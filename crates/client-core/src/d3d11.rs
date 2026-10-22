//! Zero-copy output of the D3D11VA decoder: the D3D11 video processor converts the decoded
//! NV12 picture (BT.601 limited range, like the host) into an RGBA texture on the GPU, which
//! the window shows through OpenGL interop (`WGL_NV_DX_interop2`) without the picture ever
//! coming back to memory. The textures are shared: the window opens them on a device of its
//! own, so taking one never waits for the decoder's next picture.

use std::{collections::HashMap, ffi::c_void, mem::ManuallyDrop};

use anyhow::{Context, Result};
use windows::{
    core::Interface,
    Win32::Graphics::{
        Direct3D11::{
            ID3D11Device, ID3D11DeviceContext, ID3D11Query, ID3D11Texture2D, ID3D11VideoContext, ID3D11VideoDevice,
            ID3D11VideoProcessor, ID3D11VideoProcessorEnumerator, ID3D11VideoProcessorInputView,
            ID3D11VideoProcessorOutputView, D3D11_BIND_RENDER_TARGET, D3D11_BIND_SHADER_RESOURCE, D3D11_QUERY_DESC,
            D3D11_QUERY_EVENT, D3D11_RESOURCE_MISC_SHARED, D3D11_TEX2D_VPIV, D3D11_TEX2D_VPOV, D3D11_TEXTURE2D_DESC,
            D3D11_USAGE_DEFAULT, D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE, D3D11_VIDEO_PROCESSOR_COLOR_SPACE,
            D3D11_VIDEO_PROCESSOR_CONTENT_DESC, D3D11_VIDEO_PROCESSOR_FORMAT_SUPPORT_OUTPUT,
            D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC, D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC_0,
            D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC, D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC_0,
            D3D11_VIDEO_PROCESSOR_STREAM, D3D11_VIDEO_USAGE_OPTIMAL_SPEED, D3D11_VPIV_DIMENSION_TEXTURE2D,
            D3D11_VPOV_DIMENSION_TEXTURE2D,
        },
        Dxgi::{
            Common::{DXGI_FORMAT_R8G8B8A8_UNORM, DXGI_RATIONAL, DXGI_SAMPLE_DESC},
            IDXGIResource,
        },
    },
};

/// Output textures in turn: the window may still show one while the next is written.
const RING: usize = 3;

/// A converted picture on the GPU, for the window to show. Finished by the time it is sent.
pub struct D3d11Picture {
    /// Keeps the texture alive while the window may open it.
    _texture: ID3D11Texture2D,
    shared: usize,
}

impl D3d11Picture {
    /// The shared handle of the RGBA texture holding it, for `OpenSharedResource` on another
    /// device of the same adapter. The same few textures come back in turn.
    pub fn shared_handle(&self) -> *mut c_void {
        self.shared as *mut c_void
    }
}

// SAFETY: D3D11 devices FFmpeg creates for decoding are multithread protected, and the window
// only hands these pointers to the interop, which serializes with the device itself.
unsafe impl Send for D3d11Picture {}

/// Converts decoded pictures into a ring of RGBA textures. Built for one device and size.
pub struct Converter {
    device: ID3D11Device,
    immediate: ID3D11DeviceContext,
    context: ID3D11VideoContext,
    /// Signals when the GPU has finished a conversion.
    done: ID3D11Query,
    video: ID3D11VideoDevice,
    enumerator: ID3D11VideoProcessorEnumerator,
    processor: ID3D11VideoProcessor,
    /// Textures, their shared handles and views.
    outputs: Vec<(ID3D11Texture2D, usize, ID3D11VideoProcessorOutputView)>,
    next: usize,
    /// Input views, by decoder texture and array slice: the decoder reuses a fixed pool.
    inputs: HashMap<(usize, u32), ID3D11VideoProcessorInputView>,
    size: (u32, u32),
}

// SAFETY: used on the decoder thread only; see `D3d11Picture`.
unsafe impl Send for Converter {}

impl Converter {
    /// For pictures of `width` × `height` decoded into textures of `device`.
    pub fn new(decoded: &ID3D11Texture2D, width: u32, height: u32) -> Result<Self> {
        // SAFETY: COM calls on valid interfaces with descriptors built here.
        unsafe {
            let device = decoded.GetDevice()?;
            let video: ID3D11VideoDevice = device.cast().context("no D3D11 video device")?;
            let immediate: ID3D11DeviceContext = device.GetImmediateContext()?;
            let context: ID3D11VideoContext = immediate.cast().context("no D3D11 video context")?;
            let rate = DXGI_RATIONAL { Numerator: 60, Denominator: 1 };
            let content = D3D11_VIDEO_PROCESSOR_CONTENT_DESC {
                InputFrameFormat: D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE,
                InputFrameRate: rate,
                InputWidth: width,
                InputHeight: height,
                OutputFrameRate: rate,
                OutputWidth: width,
                OutputHeight: height,
                Usage: D3D11_VIDEO_USAGE_OPTIMAL_SPEED,
            };
            let enumerator = video.CreateVideoProcessorEnumerator(&content)?;
            let support = enumerator.CheckVideoProcessorFormat(DXGI_FORMAT_R8G8B8A8_UNORM)?;
            anyhow::ensure!(
                support & D3D11_VIDEO_PROCESSOR_FORMAT_SUPPORT_OUTPUT.0 as u32 != 0,
                "the video processor cannot write RGBA"
            );
            let processor = video.CreateVideoProcessor(&enumerator, 0)?;
            // BT.601, 16-235 in; full-range RGB out. No enhancements: they cost time.
            let input_space = D3D11_VIDEO_PROCESSOR_COLOR_SPACE { _bitfield: 1 << 4 };
            context.VideoProcessorSetStreamColorSpace(&processor, 0, &input_space);
            context.VideoProcessorSetOutputColorSpace(&processor, &D3D11_VIDEO_PROCESSOR_COLOR_SPACE { _bitfield: 0 });
            context.VideoProcessorSetStreamAutoProcessingMode(&processor, 0, false);

            let mut outputs = Vec::with_capacity(RING);
            for _ in 0..RING {
                let desc = D3D11_TEXTURE2D_DESC {
                    Width: width,
                    Height: height,
                    MipLevels: 1,
                    ArraySize: 1,
                    Format: DXGI_FORMAT_R8G8B8A8_UNORM,
                    SampleDesc: DXGI_SAMPLE_DESC { Count: 1, Quality: 0 },
                    Usage: D3D11_USAGE_DEFAULT,
                    BindFlags: (D3D11_BIND_RENDER_TARGET.0 | D3D11_BIND_SHADER_RESOURCE.0) as u32,
                    CPUAccessFlags: 0,
                    MiscFlags: D3D11_RESOURCE_MISC_SHARED.0 as u32,
                };
                let mut texture = None;
                device.CreateTexture2D(&desc, None, Some(&mut texture))?;
                let texture = texture.context("no output texture")?;
                let view_desc = D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC {
                    ViewDimension: D3D11_VPOV_DIMENSION_TEXTURE2D,
                    Anonymous: D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC_0 { Texture2D: D3D11_TEX2D_VPOV { MipSlice: 0 } },
                };
                let mut view = None;
                video.CreateVideoProcessorOutputView(&texture, &enumerator, &view_desc, Some(&mut view))?;
                let shared = texture.cast::<IDXGIResource>()?.GetSharedHandle()?.0 as usize;
                outputs.push((texture, shared, view.context("no output view")?));
            }
            let mut done = None;
            device.CreateQuery(&D3D11_QUERY_DESC { Query: D3D11_QUERY_EVENT, MiscFlags: 0 }, Some(&mut done))?;
            Ok(Self {
                device,
                immediate,
                context,
                done: done.context("no D3D11 query")?,
                video,
                enumerator,
                processor,
                outputs,
                next: 0,
                inputs: HashMap::new(),
                size: (width, height),
            })
        }
    }

    /// Whether this converter fits pictures decoded into `decoded` at this size.
    pub fn fits(&self, decoded: &ID3D11Texture2D, width: u32, height: u32) -> bool {
        // SAFETY: plain query on a valid texture.
        let same_device = unsafe { decoded.GetDevice() }.is_ok_and(|d| d == self.device);
        same_device && self.size == (width, height)
    }

    /// Converts slice `index` of the decoder texture `decoded` into the next output texture.
    pub fn convert(&mut self, decoded: &ID3D11Texture2D, index: u32) -> Result<D3d11Picture> {
        let key = (decoded.as_raw() as usize, index);
        if !self.inputs.contains_key(&key) {
            let desc = D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC {
                FourCC: 0,
                ViewDimension: D3D11_VPIV_DIMENSION_TEXTURE2D,
                Anonymous: D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC_0 {
                    Texture2D: D3D11_TEX2D_VPIV { MipSlice: 0, ArraySlice: index },
                },
            };
            let mut view = None;
            // SAFETY: COM call with a descriptor for a slice of a valid texture.
            unsafe { self.video.CreateVideoProcessorInputView(decoded, &self.enumerator, &desc, Some(&mut view))? };
            self.inputs.insert(key, view.context("no input view")?);
        }
        let (texture, shared, output) = &self.outputs[self.next];
        self.next = (self.next + 1) % RING;
        let stream = D3D11_VIDEO_PROCESSOR_STREAM {
            Enable: true.into(),
            pInputSurface: ManuallyDrop::new(self.inputs.get(&key).cloned()),
            ..Default::default()
        };
        let streams = [stream];
        // SAFETY: the processor, views and textures belong to this device.
        let result = unsafe { self.context.VideoProcessorBlt(&self.processor, output, 0, &streams) };
        // The stream held a reference to the input view for the call.
        let [mut stream] = streams;
        // SAFETY: taken once, released once.
        unsafe { ManuallyDrop::drop(&mut stream.pInputSurface) };
        result.context("converting the picture on the GPU")?;
        self.wait();
        Ok(D3d11Picture { _texture: texture.clone(), shared: *shared })
    }

    /// Waits, sleeping, until the GPU has decoded and converted the picture. Otherwise the
    /// window waits for it when it takes the texture, and the driver spins a core meanwhile
    /// (measured: 7 ms per frame on an Intel UHD 750).
    fn wait(&self) {
        const LIMIT: std::time::Duration = std::time::Duration::from_millis(100);
        let start = std::time::Instant::now();
        // SAFETY: a query of this device, ended after the work it marks.
        unsafe {
            self.immediate.End(&self.done);
            self.immediate.Flush();
            loop {
                let mut finished = windows::core::BOOL(0);
                let polled = self.immediate.GetData(
                    &self.done,
                    Some(&mut finished as *mut _ as *mut c_void),
                    std::mem::size_of_val(&finished) as u32,
                    0,
                );
                if polled.is_err() || finished.as_bool() || start.elapsed() > LIMIT {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_micros(200));
            }
        }
    }
}
