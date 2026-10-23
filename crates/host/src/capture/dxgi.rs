//! Windows capture through DXGI Desktop Duplication: the compositor hands us the desktop
//! texture only when it changes.
//!
//! The frame is copied to a CPU staging texture for the software encoder. A GPU encoder
//! (NVENC/QSV/AMF) should consume the texture directly instead.

use std::time::Duration;

use anyhow::{Context, Result};
use windows::{
    core::Interface,
    Win32::{
        Foundation::{E_INVALIDARG, HMODULE},
        Graphics::{
            Direct3D::D3D_DRIVER_TYPE_UNKNOWN,
            Direct3D11::{
                D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D, D3D11_BIND_RENDER_TARGET,
                D3D11_BIND_SHADER_RESOURCE, D3D11_CPU_ACCESS_READ, D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                D3D11_CREATE_DEVICE_FLAG, D3D11_CREATE_DEVICE_VIDEO_SUPPORT, D3D11_MAPPED_SUBRESOURCE, D3D11_MAP_READ,
                D3D11_SDK_VERSION, D3D11_TEXTURE2D_DESC, D3D11_USAGE_DEFAULT, D3D11_USAGE_STAGING,
            },
            Dxgi::{
                CreateDXGIFactory1, IDXGIAdapter1, IDXGIFactory1, IDXGIOutput1, IDXGIOutputDuplication, IDXGIResource,
                DXGI_ERROR_ACCESS_LOST, DXGI_ERROR_WAIT_TIMEOUT, DXGI_OUTDUPL_FRAME_INFO,
            },
        },
    },
};

use super::{Capturer, Display, DisplayRect, Frame};

/// How long a new capture waits for the previous one in this process to release the output.
const RELEASE_WAIT: Duration = Duration::from_secs(2);

pub struct DxgiCapturer {
    device: ID3D11Device,
    context: ID3D11DeviceContext,
    output: IDXGIOutput1,
    duplication: Option<IDXGIOutputDuplication>,
    staging: Option<(ID3D11Texture2D, u32, u32)>,
    /// Leave frames on the GPU, in `copy`, for an encoder there.
    gpu: bool,
    /// The last frame on the GPU: the desktop texture is only ours until it is released.
    copy: Option<(ID3D11Texture2D, u32, u32)>,
    rect: DisplayRect,
    buf: Vec<u8>,
    width: u32,
    height: u32,
}

/// A display attached to the desktop, and the GPU that drives it.
struct Output {
    adapter: IDXGIAdapter1,
    output: IDXGIOutput1,
    display: Display,
}

/// Displays attached to the desktop, on every GPU, left to right.
fn outputs() -> Result<Vec<Output>> {
    // SAFETY: COM enumeration; each call returns an owned interface or an error that ends it.
    unsafe {
        let factory: IDXGIFactory1 = CreateDXGIFactory1()?;
        let mut found = Vec::new();
        for a in 0.. {
            let Ok(adapter) = factory.EnumAdapters1(a) else { break };
            for o in 0.. {
                let Ok(output) = adapter.EnumOutputs(o) else { break };
                let desc = output.GetDesc()?;
                if !desc.AttachedToDesktop.as_bool() {
                    continue;
                }
                let name = desc.DeviceName.split(|&c| c == 0).next().unwrap_or_default();
                // `\\.\DISPLAY1` -> `DISPLAY1`.
                let name = String::from_utf16_lossy(name).trim_start_matches(r"\\.\").to_string();
                let r = desc.DesktopCoordinates;
                let rect = DisplayRect {
                    x: r.left,
                    y: r.top,
                    width: (r.right - r.left) as u32,
                    height: (r.bottom - r.top) as u32,
                };
                let display = Display { name, rect, primary: r.left == 0 && r.top == 0 };
                found.push(Output { adapter: adapter.clone(), output: output.cast()?, display });
            }
        }
        found.sort_by_key(|o| (o.display.rect.x, o.display.rect.y));
        Ok(found)
    }
}

pub fn list() -> Vec<Display> {
    match outputs() {
        Ok(outputs) => outputs.into_iter().map(|o| o.display).collect(),
        Err(e) => {
            tracing::warn!("cannot list displays: {e:#}");
            Vec::new()
        }
    }
}

fn create_device(
    adapter: &IDXGIAdapter1,
    extra: D3D11_CREATE_DEVICE_FLAG,
) -> Result<(ID3D11Device, ID3D11DeviceContext)> {
    let mut device = None;
    let mut context = None;
    // SAFETY: standard D3D11 device creation with out-pointers to locals.
    unsafe {
        D3D11CreateDevice(
            adapter,
            D3D_DRIVER_TYPE_UNKNOWN,
            HMODULE::default(),
            D3D11_CREATE_DEVICE_BGRA_SUPPORT | extra,
            None,
            D3D11_SDK_VERSION,
            Some(&mut device),
            None,
            Some(&mut context),
        )
        .context("D3D11CreateDevice failed")?;
    }
    Ok((device.context("no D3D11 device")?, context.context("no D3D11 context")?))
}

impl DxgiCapturer {
    /// Captures display `index` of [`list`], on the GPU that drives it: duplication only works
    /// from a device on that GPU.
    pub fn new(index: usize) -> Result<Self> {
        let chosen = outputs()?.into_iter().nth(index).context("that display is no longer attached")?;
        // Video support lets the encoder convert colors with this device's video processor;
        // adapters without it (basic display drivers) still capture.
        let (device, context) = create_device(&chosen.adapter, D3D11_CREATE_DEVICE_VIDEO_SUPPORT)
            .or_else(|_| create_device(&chosen.adapter, Default::default()))?;
        tracing::info!("capturing {}", chosen.display.name);
        let mut capturer = Self {
            device,
            context,
            output: chosen.output,
            duplication: None,
            staging: None,
            gpu: false,
            copy: None,
            rect: DisplayRect::default(),
            buf: Vec::new(),
            width: 0,
            height: 0,
        };
        capturer.duplicate()?;
        Ok(capturer)
    }

    /// (Re)creates the duplication and refreshes the output position, which changes after a
    /// resolution or layout change.
    fn duplicate(&mut self) -> Result<()> {
        // Duplication shows the calling thread's desktop: after a switch to the lock screen or
        // a UAC prompt (ACCESS_LOST), move to the new one first.
        crate::win::follow_input_desktop();
        // A process may duplicate an output only once at a time (E_INVALIDARG otherwise). When a
        // device takes over, the previous session's capture is still letting go: wait for it.
        let deadline = std::time::Instant::now() + RELEASE_WAIT;
        // SAFETY: COM calls on valid interfaces.
        let dup = loop {
            match unsafe { self.output.DuplicateOutput(&self.device) } {
                Err(e) if e.code() == E_INVALIDARG && std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                result => {
                    break result
                        .context("DuplicateOutput failed (another app duplicating, or secure desktop active)")?
                }
            }
        };
        // SAFETY: as above.
        let desc = unsafe { self.output.GetDesc()? };
        let r = desc.DesktopCoordinates;
        let rect =
            DisplayRect { x: r.left, y: r.top, width: (r.right - r.left) as u32, height: (r.bottom - r.top) as u32 };
        if rect != self.rect {
            tracing::info!("DXGI capture {}x{} at ({}, {})", rect.width, rect.height, rect.x, rect.y);
            self.rect = rect;
        }
        self.duplication = Some(dup);
        Ok(())
    }

    /// A texture like the desktop's, for the CPU to read (`staging`) or to stay on the GPU.
    fn texture_like(&self, src: &D3D11_TEXTURE2D_DESC, staging: bool) -> Result<ID3D11Texture2D> {
        let desc = D3D11_TEXTURE2D_DESC {
            Width: src.Width,
            Height: src.Height,
            MipLevels: 1,
            ArraySize: 1,
            Format: src.Format,
            SampleDesc: src.SampleDesc,
            Usage: if staging { D3D11_USAGE_STAGING } else { D3D11_USAGE_DEFAULT },
            // The encoder's video processor reads the GPU copy.
            BindFlags: if staging { 0 } else { (D3D11_BIND_SHADER_RESOURCE.0 | D3D11_BIND_RENDER_TARGET.0) as u32 },
            CPUAccessFlags: if staging { D3D11_CPU_ACCESS_READ.0 as u32 } else { 0 },
            MiscFlags: 0,
        };
        let mut tex = None;
        // SAFETY: valid descriptor and out-pointer.
        unsafe { self.device.CreateTexture2D(&desc, None, Some(&mut tex))? };
        tex.context("CreateTexture2D returned nothing")
    }

    fn staging_for(&mut self, src: &D3D11_TEXTURE2D_DESC) -> Result<ID3D11Texture2D> {
        if let Some((tex, w, h)) = &self.staging {
            if (*w, *h) == (src.Width, src.Height) {
                return Ok(tex.clone());
            }
        }
        let tex = self.texture_like(src, true)?;
        self.staging = Some((tex.clone(), src.Width, src.Height));
        Ok(tex)
    }

    fn copy_for(&mut self, src: &D3D11_TEXTURE2D_DESC) -> Result<ID3D11Texture2D> {
        if let Some((tex, w, h)) = &self.copy {
            if (*w, *h) == (src.Width, src.Height) {
                return Ok(tex.clone());
            }
        }
        let tex = self.texture_like(src, false)?;
        self.copy = Some((tex.clone(), src.Width, src.Height));
        Ok(tex)
    }
}

impl Capturer for DxgiCapturer {
    fn rect(&self) -> DisplayRect {
        self.rect
    }

    fn device(&self) -> Option<ID3D11Device> {
        Some(self.device.clone())
    }

    fn set_gpu_frames(&mut self, on: bool) {
        self.gpu = on;
    }

    fn capture(&mut self, timeout: Duration) -> Result<Option<Frame<'_>>> {
        if self.duplication.is_none() {
            // Lost after a mode change or while the secure desktop (UAC, lock screen) is up.
            if self.duplicate().is_err() {
                std::thread::sleep(timeout);
                return Ok(None);
            }
        }
        let dup = self.duplication.clone().unwrap();

        let mut info = DXGI_OUTDUPL_FRAME_INFO::default();
        let mut resource: Option<IDXGIResource> = None;
        // SAFETY: out-pointers to locals.
        match unsafe { dup.AcquireNextFrame(timeout.as_millis() as u32, &mut info, &mut resource) } {
            Ok(()) => {}
            Err(e) if e.code() == DXGI_ERROR_WAIT_TIMEOUT => return Ok(None),
            Err(e) if e.code() == DXGI_ERROR_ACCESS_LOST => {
                self.duplication = None;
                return Ok(None);
            }
            Err(e) => return Err(e.into()),
        }

        let result = (|| -> Result<bool> {
            // Only the pointer moved; the image is unchanged.
            if info.LastPresentTime == 0 {
                return Ok(false);
            }
            let texture: ID3D11Texture2D = resource.context("no desktop resource")?.cast()?;
            let mut desc = D3D11_TEXTURE2D_DESC::default();
            // SAFETY: COM calls on valid interfaces; the mapped region is read within
            // `RowPitch * Height` bytes before Unmap.
            unsafe {
                texture.GetDesc(&mut desc);
                self.width = desc.Width;
                self.height = desc.Height;
                if self.gpu {
                    // GPU to GPU: queued before the release below, done before the next frame.
                    let copy = self.copy_for(&desc)?;
                    self.context.CopyResource(&copy, &texture);
                    return Ok(true);
                }
                let staging = self.staging_for(&desc)?;
                self.context.CopyResource(&staging, &texture);

                let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
                self.context.Map(&staging, 0, D3D11_MAP_READ, 0, Some(&mut mapped))?;
                let row = desc.Width as usize * 4;
                let pitch = mapped.RowPitch as usize;
                self.buf.resize(row * desc.Height as usize, 0);
                let src = std::slice::from_raw_parts(mapped.pData as *const u8, pitch * desc.Height as usize);
                for (dst, src) in self.buf.chunks_exact_mut(row).zip(src.chunks(pitch)) {
                    dst.copy_from_slice(&src[..row]);
                }
                self.context.Unmap(&staging, 0);
            }
            Ok(true)
        })();
        // SAFETY: the frame was acquired above.
        unsafe {
            let _ = dup.ReleaseFrame();
        }

        if !result? {
            return Ok(None);
        }
        if self.gpu {
            let mut frame = Frame::new(self.width, self.height, 0, &[]);
            frame.texture = self.copy.as_ref().map(|(tex, _, _)| tex);
            return Ok(Some(frame));
        }
        Ok(Some(Frame::new(self.width, self.height, self.width as usize * 4, &self.buf)))
    }
}
