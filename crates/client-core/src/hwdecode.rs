//! Hardware H.264 decoding through FFmpeg: D3D11VA on Windows, VA-API on Linux. The GPU
//! decodes; the picture comes back to memory as NV12 for the window to upload. Any failure,
//! opening or later, sends the decoder back to OpenH264 (see `video`).

use std::{
    ffi::{c_int, CStr},
    ptr,
    sync::Once,
};

use anyhow::{bail, Context, Result};
use ffmpeg_sys_next as ff;

use crate::video::{Chroma, Planes, VideoFrame};

#[cfg(windows)]
const DEVICE: (ff::AVHWDeviceType, ff::AVPixelFormat, &str) =
    (ff::AVHWDeviceType::AV_HWDEVICE_TYPE_D3D11VA, ff::AVPixelFormat::AV_PIX_FMT_D3D11, "D3D11VA");
#[cfg(not(windows))]
const DEVICE: (ff::AVHWDeviceType, ff::AVPixelFormat, &str) =
    (ff::AVHWDeviceType::AV_HWDEVICE_TYPE_VAAPI, ff::AVPixelFormat::AV_PIX_FMT_VAAPI, "VA-API");

/// FFmpeg logs to stderr on its own; keep only errors.
fn init_logging() {
    static INIT: Once = Once::new();
    // SAFETY: global log level setter.
    INIT.call_once(|| unsafe { ff::av_log_set_level(ff::AV_LOG_ERROR) });
}

fn av_error(code: i32) -> String {
    let mut buf = [0 as std::ffi::c_char; 256];
    // SAFETY: buffer and length are valid; av_strerror always NUL-terminates.
    unsafe {
        ff::av_strerror(code, buf.as_mut_ptr(), buf.len());
        CStr::from_ptr(buf.as_ptr()).to_string_lossy().into_owned()
    }
}

fn check(code: i32, what: &str) -> Result<i32> {
    if code < 0 {
        bail!("{what}: {}", av_error(code));
    }
    Ok(code)
}

/// Picks the GPU format from what the decoder offers; without it, decoding fails and the
/// caller falls back to software.
unsafe extern "C" fn pick_format(
    _ctx: *mut ff::AVCodecContext,
    offered: *const ff::AVPixelFormat,
) -> ff::AVPixelFormat {
    let mut at = offered;
    // SAFETY: FFmpeg passes a list ended by AV_PIX_FMT_NONE.
    unsafe {
        while *at != ff::AVPixelFormat::AV_PIX_FMT_NONE {
            if *at == DEVICE.1 {
                return *at;
            }
            at = at.add(1);
        }
    }
    ff::AVPixelFormat::AV_PIX_FMT_NONE
}

pub struct HwDecoder {
    /// Turns pictures into textures the window shows directly, while it takes them.
    #[cfg(windows)]
    converter: Option<crate::d3d11::Converter>,
    ctx: *mut ff::AVCodecContext,
    device: *mut ff::AVBufferRef,
    packet: *mut ff::AVPacket,
    frame: *mut ff::AVFrame,
    /// The GPU picture copied back to memory.
    download: *mut ff::AVFrame,
}

// SAFETY: the decoder is created and used on the decoder thread only; the pointers are owned.
unsafe impl Send for HwDecoder {}

impl HwDecoder {
    pub const NAME: &'static str = DEVICE.2;

    pub fn open() -> Result<Self> {
        init_logging();
        let mut this = Self {
            #[cfg(windows)]
            converter: None,
            ctx: ptr::null_mut(),
            device: ptr::null_mut(),
            packet: ptr::null_mut(),
            frame: ptr::null_mut(),
            download: ptr::null_mut(),
        };
        // SAFETY: FFmpeg allocation and setup; `this` frees whatever was made on failure.
        unsafe {
            check(
                ff::av_hwdevice_ctx_create(&mut this.device, DEVICE.0, ptr::null(), ptr::null_mut(), 0),
                "opening the GPU decoder device",
            )?;
            let codec = ff::avcodec_find_decoder(ff::AVCodecID::AV_CODEC_ID_H264);
            if codec.is_null() {
                bail!("FFmpeg has no H.264 decoder");
            }
            this.ctx = ff::avcodec_alloc_context3(codec);
            this.packet = ff::av_packet_alloc();
            this.frame = ff::av_frame_alloc();
            this.download = ff::av_frame_alloc();
            if this.ctx.is_null() || this.packet.is_null() || this.frame.is_null() || this.download.is_null() {
                bail!("out of memory");
            }
            let ctx = &mut *this.ctx;
            ctx.hw_device_ctx = ff::av_buffer_ref(this.device);
            ctx.get_format = Some(pick_format);
            // Every frame out as soon as it is in: no reordering delay, no frame threads.
            ctx.flags |= ff::AV_CODEC_FLAG_LOW_DELAY as c_int;
            ctx.flags2 |= ff::AV_CODEC_FLAG2_FAST as c_int;
            ctx.thread_count = 1;
            check(ff::avcodec_open2(this.ctx, codec, ptr::null_mut()), "opening the H.264 decoder")?;
        }
        Ok(this)
    }

    /// Decodes one access unit into `planes`, or with `zero_copy`, into a texture left on the
    /// GPU when it can (then the planes stay empty). `None` while there is no picture yet.
    pub fn decode(&mut self, data: &[u8], planes: Planes, zero_copy: bool) -> Result<Option<VideoFrame>> {
        // SAFETY: owned FFmpeg objects; the packet gets its own copy of `data`.
        unsafe {
            check(ff::av_new_packet(self.packet, data.len() as c_int), "allocating a packet")?;
            ptr::copy_nonoverlapping(data.as_ptr(), (*self.packet).data, data.len());
            let sent = ff::avcodec_send_packet(self.ctx, self.packet);
            ff::av_packet_unref(self.packet);
            check(sent, "decoding")?;
            let mut out = None;
            let mut planes = Some(planes);
            loop {
                let ret = ff::avcodec_receive_frame(self.ctx, self.frame);
                if ret == ff::AVERROR(ff::EAGAIN) || ret == ff::AVERROR_EOF {
                    break;
                }
                check(ret, "decoding")?;
                if (*self.frame).format != DEVICE.1 as c_int {
                    ff::av_frame_unref(self.frame);
                    bail!("the GPU did not decode this stream");
                }
                #[cfg(windows)]
                if zero_copy {
                    match self.on_gpu() {
                        Ok(picture) => {
                            ff::av_frame_unref(self.frame);
                            out = Some(picture);
                            continue;
                        }
                        // Copied back below, from now on.
                        Err(e) => {
                            tracing::warn!("cannot keep pictures on the GPU: {e:#}");
                            self.converter = None;
                        }
                    }
                }
                let _ = zero_copy;
                ff::av_frame_unref(self.download);
                let copied = ff::av_hwframe_transfer_data(self.download, self.frame, 0);
                ff::av_frame_unref(self.frame);
                check(copied, "copying the picture from the GPU")?;
                // Only the newest picture matters; earlier ones in the same call are dropped.
                let buffers = planes.take().or_else(|| out.take().map(|f: VideoFrame| (f.y, f.u, f.v)));
                out = Some(self.nv12(buffers.unwrap_or_default())?);
            }
            Ok(out)
        }
    }

    /// The decoded picture converted into a texture of `d3d11::Converter`, left on the GPU.
    #[cfg(windows)]
    unsafe fn on_gpu(&mut self) -> Result<VideoFrame> {
        use windows::{core::Interface, Win32::Graphics::Direct3D11::ID3D11Texture2D};
        // SAFETY: a D3D11VA frame holds its texture in data[0] and the array slice in data[1].
        unsafe {
            let f = &*self.frame;
            let raw = f.data[0] as *mut std::ffi::c_void;
            let texture = ID3D11Texture2D::from_raw_borrowed(&raw).context("no texture in the picture")?;
            let (w, h) = (f.width as u32, f.height as u32);
            if !self.converter.as_ref().is_some_and(|c| c.fits(texture, w, h)) {
                self.converter = Some(crate::d3d11::Converter::new(texture, w, h)?);
            }
            let converter = self.converter.as_mut().expect("just made");
            let picture = converter.convert(texture, f.data[1] as usize as u32)?;
            Ok(VideoFrame {
                frame_id: 0,
                width: w,
                height: h,
                chroma: Chroma::Planar,
                gpu: Some(picture),
                y: Vec::new(),
                u: Vec::new(),
                v: Vec::new(),
            })
        }
    }

    /// The downloaded picture, packed: luma, then interleaved chroma.
    unsafe fn nv12(&self, (mut y, mut uv, v): Planes) -> Result<VideoFrame> {
        // SAFETY: `download` holds a picture FFmpeg just filled.
        unsafe {
            let f = &*self.download;
            if f.format != ff::AVPixelFormat::AV_PIX_FMT_NV12 as c_int {
                bail!("unexpected picture format {} from the GPU", f.format);
            }
            let (w, h) = (f.width as usize, f.height as usize);
            let (cw, ch) = (w.div_ceil(2), h.div_ceil(2));
            copy_plane(f.data[0], f.linesize[0] as usize, w, h, &mut y);
            copy_plane(f.data[1], f.linesize[1] as usize, cw * 2, ch, &mut uv);
            Ok(VideoFrame {
                frame_id: 0,
                width: w as u32,
                height: h as u32,
                chroma: Chroma::Interleaved,
                gpu: None,
                y,
                u: uv,
                v,
            })
        }
    }
}

/// Copies `height` rows of `width` bytes, `stride` apart, back to back into `out`.
///
/// # Safety
/// `src` must point to `height` rows of at least `width` bytes, `stride` apart.
unsafe fn copy_plane(src: *const u8, stride: usize, width: usize, height: usize, out: &mut Vec<u8>) {
    out.clear();
    out.reserve(width * height);
    for row in 0..height {
        // SAFETY: guaranteed by the caller.
        out.extend_from_slice(unsafe { std::slice::from_raw_parts(src.add(row * stride), width) });
    }
}

impl Drop for HwDecoder {
    fn drop(&mut self) {
        // SAFETY: frees what `open` allocated; FFmpeg accepts null pointers here.
        unsafe {
            ff::avcodec_free_context(&mut self.ctx);
            ff::av_frame_free(&mut self.frame);
            ff::av_frame_free(&mut self.download);
            ff::av_packet_free(&mut self.packet);
            ff::av_buffer_unref(&mut self.device);
        }
    }
}
