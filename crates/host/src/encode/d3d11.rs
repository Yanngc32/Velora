//! Zero-copy input of the hardware encoders: the D3D11 video processor converts the captured
//! BGRA desktop into NV12 (BT.601, 16-235, like the CPU path) on the GPU that captured it, and
//! the result is copied into the encoder's texture pool. The picture never comes back to memory.
//!
//! The video processor writes into an NV12 texture of its own: drivers make NV12 render
//! targets only as single textures, while encoders take their pool as one array texture.

use std::{collections::HashMap, ffi::c_void, mem::ManuallyDrop};

use anyhow::{Context, Result};
use windows::{
    core::Interface,
    Win32::Graphics::{
        Direct3D11::{
            ID3D11Device, ID3D11DeviceContext, ID3D11Query, ID3D11Texture2D, ID3D11VideoContext, ID3D11VideoDevice,
            ID3D11VideoProcessor, ID3D11VideoProcessorEnumerator, ID3D11VideoProcessorInputView,
            ID3D11VideoProcessorOutputView, D3D11_BIND_RENDER_TARGET, D3D11_QUERY_DESC, D3D11_QUERY_EVENT,
            D3D11_TEX2D_VPIV, D3D11_TEX2D_VPOV, D3D11_TEXTURE2D_DESC, D3D11_USAGE_DEFAULT,
            D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE, D3D11_VIDEO_PROCESSOR_COLOR_SPACE,
            D3D11_VIDEO_PROCESSOR_CONTENT_DESC, D3D11_VIDEO_PROCESSOR_FORMAT_SUPPORT_INPUT,
            D3D11_VIDEO_PROCESSOR_FORMAT_SUPPORT_OUTPUT, D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC,
            D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC_0, D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC,
            D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC_0, D3D11_VIDEO_PROCESSOR_STREAM, D3D11_VIDEO_USAGE_OPTIMAL_SPEED,
            D3D11_VPIV_DIMENSION_TEXTURE2D, D3D11_VPOV_DIMENSION_TEXTURE2D,
        },
        Dxgi::Common::{DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_FORMAT_NV12, DXGI_RATIONAL, DXGI_SAMPLE_DESC},
    },
};

/// Converts desktop frames into slices of the encoder's NV12 texture array. Built for one
/// device and size.
pub struct Converter {
    immediate: ID3D11DeviceContext,
    context: ID3D11VideoContext,
    /// Signals when the GPU has finished a conversion.
    done: ID3D11Query,
    video: ID3D11VideoDevice,
    enumerator: ID3D11VideoProcessorEnumerator,
    processor: ID3D11VideoProcessor,
    /// By desktop copy texture: the capture reuses one.
    inputs: HashMap<usize, ID3D11VideoProcessorInputView>,
    /// Where the video processor writes, before the copy into the pool.
    nv12: ID3D11Texture2D,
    output: ID3D11VideoProcessorOutputView,
}

// SAFETY: used on the capture thread only; FFmpeg makes the device multithread protected.
unsafe impl Send for Converter {}

impl Converter {
    pub fn new(device: &ID3D11Device, width: u32, height: u32) -> Result<Self> {
        // SAFETY: COM calls on valid interfaces with descriptors built here.
        unsafe {
            let video: ID3D11VideoDevice = device.cast().context("no D3D11 video device")?;
            let immediate = device.GetImmediateContext()?;
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
            let input = enumerator.CheckVideoProcessorFormat(DXGI_FORMAT_B8G8R8A8_UNORM)?;
            let output = enumerator.CheckVideoProcessorFormat(DXGI_FORMAT_NV12)?;
            anyhow::ensure!(
                input & D3D11_VIDEO_PROCESSOR_FORMAT_SUPPORT_INPUT.0 as u32 != 0
                    && output & D3D11_VIDEO_PROCESSOR_FORMAT_SUPPORT_OUTPUT.0 as u32 != 0,
                "the video processor cannot convert BGRA to NV12"
            );
            let processor = video.CreateVideoProcessor(&enumerator, 0)?;
            // Full-range RGB in; BT.601, 16-235 out. No enhancements: they cost time.
            context.VideoProcessorSetStreamColorSpace(
                &processor,
                0,
                &D3D11_VIDEO_PROCESSOR_COLOR_SPACE { _bitfield: 0 },
            );
            let output_space = D3D11_VIDEO_PROCESSOR_COLOR_SPACE { _bitfield: 1 << 4 };
            context.VideoProcessorSetOutputColorSpace(&processor, &output_space);
            context.VideoProcessorSetStreamAutoProcessingMode(&processor, 0, false);

            let desc = D3D11_TEXTURE2D_DESC {
                Width: width,
                Height: height,
                MipLevels: 1,
                ArraySize: 1,
                Format: DXGI_FORMAT_NV12,
                SampleDesc: DXGI_SAMPLE_DESC { Count: 1, Quality: 0 },
                Usage: D3D11_USAGE_DEFAULT,
                BindFlags: D3D11_BIND_RENDER_TARGET.0 as u32,
                CPUAccessFlags: 0,
                MiscFlags: 0,
            };
            let mut nv12 = None;
            device.CreateTexture2D(&desc, None, Some(&mut nv12))?;
            let nv12 = nv12.context("no NV12 texture")?;
            let view_desc = D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC {
                ViewDimension: D3D11_VPOV_DIMENSION_TEXTURE2D,
                Anonymous: D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC_0 { Texture2D: D3D11_TEX2D_VPOV { MipSlice: 0 } },
            };
            let mut output = None;
            video.CreateVideoProcessorOutputView(&nv12, &enumerator, &view_desc, Some(&mut output))?;

            let mut done = None;
            device.CreateQuery(&D3D11_QUERY_DESC { Query: D3D11_QUERY_EVENT, MiscFlags: 0 }, Some(&mut done))?;
            Ok(Self {
                immediate,
                context,
                done: done.context("no D3D11 query")?,
                video,
                enumerator,
                processor,
                inputs: HashMap::new(),
                nv12,
                output: output.context("no output view")?,
            })
        }
    }

    /// Converts the desktop frame `src` into slice `index` of the pool texture `dst`, and waits
    /// for the GPU: the encoder may read it from another queue.
    pub fn convert(&mut self, src: &ID3D11Texture2D, dst: &ID3D11Texture2D, index: u32) -> Result<()> {
        let key = src.as_raw() as usize;
        if !self.inputs.contains_key(&key) {
            let desc = D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC {
                FourCC: 0,
                ViewDimension: D3D11_VPIV_DIMENSION_TEXTURE2D,
                Anonymous: D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC_0 {
                    Texture2D: D3D11_TEX2D_VPIV { MipSlice: 0, ArraySlice: 0 },
                },
            };
            let mut view = None;
            // SAFETY: COM call with a descriptor for a valid texture.
            unsafe { self.video.CreateVideoProcessorInputView(src, &self.enumerator, &desc, Some(&mut view))? };
            self.inputs.insert(key, view.context("no input view")?);
        }
        let stream = D3D11_VIDEO_PROCESSOR_STREAM {
            Enable: true.into(),
            pInputSurface: ManuallyDrop::new(self.inputs.get(&key).cloned()),
            ..Default::default()
        };
        let streams = [stream];
        // SAFETY: the processor, views and textures belong to this device.
        let result = unsafe { self.context.VideoProcessorBlt(&self.processor, &self.output, 0, &streams) };
        // The stream held a reference to the input view for the call.
        let [mut stream] = streams;
        // SAFETY: taken once, released once.
        unsafe { ManuallyDrop::drop(&mut stream.pInputSurface) };
        result.context("converting the frame on the GPU")?;
        // SAFETY: same format and size; with one mip level, slice `index` is subresource `index`.
        unsafe { self.immediate.CopySubresourceRegion(dst, index, 0, 0, 0, &self.nv12, 0, None) };
        self.wait();
        Ok(())
    }

    /// Waits, sleeping, until the GPU has converted the frame. Spinning on it would cost a core.
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
