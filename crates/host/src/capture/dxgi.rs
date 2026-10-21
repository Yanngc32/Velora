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
        Foundation::HMODULE,
        Graphics::{
            Direct3D::D3D_DRIVER_TYPE_HARDWARE,
            Direct3D11::{
                D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D, D3D11_CPU_ACCESS_READ,
                D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_MAPPED_SUBRESOURCE, D3D11_MAP_READ, D3D11_SDK_VERSION,
                D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING,
            },
            Dxgi::{
                IDXGIDevice, IDXGIOutput1, IDXGIOutputDuplication, IDXGIResource, DXGI_ERROR_ACCESS_LOST,
                DXGI_ERROR_WAIT_TIMEOUT, DXGI_OUTDUPL_FRAME_INFO,
            },
        },
    },
};

use super::{Capturer, DisplayRect, Frame};

pub struct DxgiCapturer {
    device: ID3D11Device,
    context: ID3D11DeviceContext,
    output: IDXGIOutput1,
    duplication: Option<IDXGIOutputDuplication>,
    staging: Option<(ID3D11Texture2D, u32, u32)>,
    rect: DisplayRect,
    buf: Vec<u8>,
    width: u32,
    height: u32,
}

impl DxgiCapturer {
    pub fn new() -> Result<Self> {
        let mut device = None;
        let mut context = None;
        // SAFETY: standard D3D11 device creation with out-pointers to locals.
        unsafe {
            D3D11CreateDevice(
                None,
                D3D_DRIVER_TYPE_HARDWARE,
                HMODULE::default(),
                D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                None,
                D3D11_SDK_VERSION,
                Some(&mut device),
                None,
                Some(&mut context),
            )
            .context("D3D11CreateDevice failed")?;
        }
        let device = device.context("no D3D11 device")?;
        let context = context.context("no D3D11 context")?;

        // SAFETY: COM calls on valid interfaces.
        let output: IDXGIOutput1 = unsafe {
            let dxgi: IDXGIDevice = device.cast()?;
            let adapter = dxgi.GetAdapter()?;
            adapter.EnumOutputs(0).context("no display attached to the primary GPU")?.cast()?
        };
        let mut capturer = Self {
            device,
            context,
            output,
            duplication: None,
            staging: None,
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
        // SAFETY: COM calls on valid interfaces.
        let (dup, desc) = unsafe {
            let dup = self
                .output
                .DuplicateOutput(&self.device)
                .context("DuplicateOutput failed (another app duplicating, or secure desktop active)")?;
            (dup, self.output.GetDesc()?)
        };
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

    fn staging_for(&mut self, src: &D3D11_TEXTURE2D_DESC) -> Result<ID3D11Texture2D> {
        if let Some((tex, w, h)) = &self.staging {
            if (*w, *h) == (src.Width, src.Height) {
                return Ok(tex.clone());
            }
        }
        let desc = D3D11_TEXTURE2D_DESC {
            Width: src.Width,
            Height: src.Height,
            MipLevels: 1,
            ArraySize: 1,
            Format: src.Format,
            SampleDesc: src.SampleDesc,
            Usage: D3D11_USAGE_STAGING,
            BindFlags: 0,
            CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
            MiscFlags: 0,
        };
        let mut tex = None;
        // SAFETY: valid descriptor and out-pointer.
        unsafe { self.device.CreateTexture2D(&desc, None, Some(&mut tex))? };
        let tex = tex.context("CreateTexture2D returned nothing")?;
        self.staging = Some((tex.clone(), src.Width, src.Height));
        Ok(tex)
    }
}

impl Capturer for DxgiCapturer {
    fn rect(&self) -> DisplayRect {
        self.rect
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
            self.width = desc.Width;
            self.height = desc.Height;
            Ok(true)
        })();
        // SAFETY: the frame was acquired above.
        unsafe {
            let _ = dup.ReleaseFrame();
        }

        if !result? {
            return Ok(None);
        }
        Ok(Some(Frame { width: self.width, height: self.height, stride: self.width as usize * 4, data: &self.buf }))
    }
}
