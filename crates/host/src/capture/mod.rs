//! Screen capture backends. All of them produce 32-bit BGRX/BGRA frames.

use std::time::Duration;

use anyhow::Result;

#[cfg(windows)]
mod dxgi;
#[cfg(target_os = "linux")]
mod x11;

/// Desktop area covered by the capture, in the OS's virtual-screen coordinates. Input
/// injection uses it to map normalized pointer coordinates to the captured display.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DisplayRect {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

pub struct Frame<'a> {
    pub width: u32,
    pub height: u32,
    /// Bytes per row.
    pub stride: usize,
    /// BGRX pixels, `stride * height` bytes. Empty when the frame stays on the GPU.
    pub data: &'a [u8],
    /// The frame on the GPU (BGRA), when the capture was asked to leave it there.
    #[cfg(windows)]
    pub texture: Option<&'a windows::Win32::Graphics::Direct3D11::ID3D11Texture2D>,
}

impl<'a> Frame<'a> {
    /// A frame in memory.
    pub fn new(width: u32, height: u32, stride: usize, data: &'a [u8]) -> Self {
        Self {
            width,
            height,
            stride,
            data,
            #[cfg(windows)]
            texture: None,
        }
    }
}

pub trait Capturer {
    fn rect(&self) -> DisplayRect;

    /// The GPU device frames are captured on, for an encoder there to take them directly.
    #[cfg(windows)]
    fn device(&self) -> Option<windows::Win32::Graphics::Direct3D11::ID3D11Device> {
        None
    }

    /// Leave frames on the GPU ([`Frame::texture`]) instead of copying them to memory.
    fn set_gpu_frames(&mut self, _on: bool) {}

    /// Returns the next frame as soon as the screen changes, waiting at most `timeout`.
    /// `Ok(None)` means nothing changed within the timeout.
    fn capture(&mut self, timeout: Duration) -> Result<Option<Frame<'_>>>;
}

/// A display that can be captured on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Display {
    pub name: String,
    pub rect: DisplayRect,
    pub primary: bool,
}

/// The displays that can be captured one at a time, left to right. Empty where the whole
/// desktop is captured at once (X11: one image across every monitor).
pub fn list() -> Vec<Display> {
    #[cfg(windows)]
    return dxgi::list();
    #[cfg(not(windows))]
    Vec::new()
}

/// Opens a capture of display `index` in [`list`] (ignored where there is no choice).
#[allow(unused_variables)]
pub fn open(index: usize) -> Result<Box<dyn Capturer>> {
    #[cfg(target_os = "linux")]
    return Ok(Box::new(x11::X11Capturer::new()?));
    #[cfg(windows)]
    return Ok(Box::new(dxgi::DxgiCapturer::new(index)?));
    #[cfg(not(any(target_os = "linux", windows)))]
    anyhow::bail!("screen capture is not implemented for this platform");
}
