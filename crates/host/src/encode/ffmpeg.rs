//! Hardware encoders through libavcodec: NVENC, Quick Sync, AMF and VA-API share this code
//! and differ only in their options. Frames are converted to NV12 on the CPU (straight into
//! the encoder's frame, no extra copy) and uploaded by the driver; VA-API needs an explicit
//! upload to a GPU surface.

use std::{
    ffi::{CStr, CString},
    ptr,
    sync::Once,
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use ffmpeg_sys_next as ff;

use super::{
    bitstream::ParameterSets,
    convert::{bgrx_to_yuv420, even_dims, Chroma},
    Encoded, EncodedFrame, EncoderSettings, GpuDevice, VideoEncoder,
};
use crate::capture::Frame;

/// Longest we wait for a pipelined encoder to return the frame just submitted.
const MAX_OUTPUT_WAIT: Duration = Duration::from_millis(8);
/// Encoders that take frames on the capture's GPU (Windows).
#[cfg(windows)]
const ZERO_COPY: &[&str] = &["h264_nvenc", "h264_amf", "h264_qsv"];
/// GPU frames in the encoder's pool: those it holds while encoding, the last picture, and one
/// being converted.
#[cfg(windows)]
const GPU_POOL: i32 = 8;

/// Low-latency options per encoder. Unknown keys are ignored by libavcodec, so options that
/// only newer FFmpeg versions understand are harmless on older ones.
fn options(name: &str) -> &'static [(&'static str, &'static str)] {
    match name {
        "h264_nvenc" => &[
            ("preset", "p1"),
            ("tune", "ull"),
            ("rc", "cbr"),
            ("zerolatency", "1"),
            ("delay", "0"),
            ("forced-idr", "1"),
            ("profile", "high"),
        ],
        "h264_qsv" => &[
            ("preset", "veryfast"),
            ("async_depth", "1"),
            ("low_delay_brc", "1"),
            ("forced_idr", "1"),
            ("profile", "high"),
        ],
        "h264_amf" => &[
            ("usage", "ultralowlatency"),
            ("quality", "speed"),
            ("rc", "cbr"),
            ("profile", "high"),
            ("header_spacing", "1"),
        ],
        "h264_vaapi" => &[("rc_mode", "CBR"), ("async_depth", "1"), ("profile", "high")],
        "libx264" => &[("preset", "ultrafast"), ("tune", "zerolatency"), ("forced-idr", "1")],
        _ => &[],
    }
}

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

pub struct Ffmpeg {
    name: String,
    settings: EncoderSettings,
    width: usize,
    height: usize,
    ctx: *mut ff::AVCodecContext,
    /// NV12 picture in system memory; kept so a keyframe of an unchanged screen can be re-sent.
    picture: *mut ff::AVFrame,
    has_picture: bool,
    /// VA-API, and zero copy on Windows: device and pool of GPU surfaces.
    hw_device: *mut ff::AVBufferRef,
    hw_frames: *mut ff::AVBufferRef,
    /// Zero copy (Windows): frames converted on the capture's GPU.
    #[cfg(windows)]
    gpu: Option<Gpu>,
    packet: *mut ff::AVPacket,
    pts: i64,
    /// Frames submitted whose packets have not come out yet.
    pending: usize,
    parameter_sets: ParameterSets,
}

/// Zero copy on Windows: the capture's device, the converter into the pool, and for Quick
/// Sync the same pool seen as its own frames.
#[cfg(windows)]
struct Gpu {
    device: GpuDevice,
    converter: super::d3d11::Converter,
    qsv_device: *mut ff::AVBufferRef,
    qsv_frames: *mut ff::AVBufferRef,
    /// The last picture, in the pool: sent again for a keyframe of an unchanged screen.
    last: *mut ff::AVFrame,
}

#[cfg(windows)]
impl Drop for Gpu {
    fn drop(&mut self) {
        // SAFETY: owned references, freed once; the functions accept null.
        unsafe {
            ff::av_frame_free(&mut self.last);
            ff::av_buffer_unref(&mut self.qsv_frames);
            ff::av_buffer_unref(&mut self.qsv_device);
        }
    }
}

impl Ffmpeg {
    /// Like [`Self::open`] but silences FFmpeg's own error output, for trying encoders that
    /// are expected to be missing.
    pub fn probe(
        name: &str,
        settings: EncoderSettings,
        width: u32,
        height: u32,
        gpu: Option<&GpuDevice>,
    ) -> Result<Self> {
        init_logging();
        // SAFETY: global log level getter/setter; probing only happens on the capture thread.
        unsafe {
            let level = ff::av_log_get_level();
            ff::av_log_set_level(ff::AV_LOG_QUIET);
            let result = Self::open(name, settings, width, height, gpu);
            ff::av_log_set_level(level);
            result
        }
    }

    /// Opens `name`, taking frames on `gpu` (the capture's device) when it can, else from memory.
    pub fn open(
        name: &str,
        settings: EncoderSettings,
        width: u32,
        height: u32,
        gpu: Option<&GpuDevice>,
    ) -> Result<Self> {
        #[cfg(windows)]
        if let Some(device) = gpu.filter(|_| ZERO_COPY.contains(&name)) {
            match Self::with(name, settings, width, height, Some(device)) {
                Ok(enc) => return Ok(enc),
                Err(e) => tracing::debug!("{name} cannot take frames on the GPU: {e:#}"),
            }
        }
        #[cfg(not(windows))]
        let _ = gpu;
        Self::with(name, settings, width, height, None)
    }

    fn with(
        name: &str,
        settings: EncoderSettings,
        width: u32,
        height: u32,
        #[allow(unused_variables)] gpu: Option<&GpuDevice>,
    ) -> Result<Self> {
        init_logging();
        let mut enc = Self {
            name: name.to_string(),
            settings,
            width: (width & !1) as usize,
            height: (height & !1) as usize,
            ctx: ptr::null_mut(),
            picture: ptr::null_mut(),
            has_picture: false,
            hw_device: ptr::null_mut(),
            hw_frames: ptr::null_mut(),
            #[cfg(windows)]
            gpu: None,
            packet: ptr::null_mut(),
            pts: 0,
            pending: 0,
            parameter_sets: ParameterSets::default(),
        };
        // On error `enc` is dropped, which frees whatever was allocated.
        // SAFETY: every pointer is checked after allocation and owned by `enc`.
        unsafe { enc.init(gpu)? };
        let input = if enc.on_gpu() { ", frames on the GPU" } else { "" };
        tracing::info!("using encoder {name} ({}x{}{input})", enc.width, enc.height);
        Ok(enc)
    }

    unsafe fn init(&mut self, #[allow(unused_variables)] gpu: Option<&GpuDevice>) -> Result<()> {
        unsafe {
            let cname = CString::new(self.name.as_str())?;
            let codec = ff::avcodec_find_encoder_by_name(cname.as_ptr());
            if codec.is_null() {
                bail!("{} is not available in this FFmpeg build", self.name);
            }
            self.ctx = ff::avcodec_alloc_context3(codec);
            self.packet = ff::av_packet_alloc();
            self.picture = ff::av_frame_alloc();
            if self.ctx.is_null() || self.packet.is_null() || self.picture.is_null() {
                bail!("out of memory");
            }

            let fps = self.settings.fps.max(1) as i32;
            let bitrate = self.settings.bitrate_kbps as i64 * 1000;
            let c = &mut *self.ctx;
            c.width = self.width as i32;
            c.height = self.height as i32;
            c.time_base = ff::AVRational { num: 1, den: fps };
            c.framerate = ff::AVRational { num: fps, den: 1 };
            c.bit_rate = bitrate;
            c.rc_max_rate = bitrate;
            // No B-frames (they add a frame of delay) and no periodic keyframes: the client
            // asks for one when it needs it.
            c.max_b_frames = 0;
            c.gop_size = fps.saturating_mul(3600);
            c.flags |= ff::AV_CODEC_FLAG_LOW_DELAY as i32;
            c.color_range = ff::AVColorRange::AVCOL_RANGE_MPEG;
            c.colorspace = ff::AVColorSpace::AVCOL_SPC_SMPTE170M;
            c.color_primaries = ff::AVColorPrimaries::AVCOL_PRI_SMPTE170M;
            c.color_trc = ff::AVColorTransferCharacteristic::AVCOL_TRC_SMPTE170M;
            c.pix_fmt = ff::AVPixelFormat::AV_PIX_FMT_NV12;

            #[cfg(windows)]
            if let Some(device) = gpu {
                self.init_gpu(device)?;
            }
            if self.name.ends_with("_vaapi") {
                check(
                    ff::av_hwdevice_ctx_create(
                        &mut self.hw_device,
                        ff::AVHWDeviceType::AV_HWDEVICE_TYPE_VAAPI,
                        ptr::null(),
                        ptr::null_mut(),
                        0,
                    ),
                    "opening VA-API device",
                )?;
                self.hw_frames = ff::av_hwframe_ctx_alloc(self.hw_device);
                if self.hw_frames.is_null() {
                    bail!("av_hwframe_ctx_alloc failed");
                }
                let frames = &mut *((*self.hw_frames).data as *mut ff::AVHWFramesContext);
                frames.format = ff::AVPixelFormat::AV_PIX_FMT_VAAPI;
                frames.sw_format = ff::AVPixelFormat::AV_PIX_FMT_NV12;
                frames.width = c.width;
                frames.height = c.height;
                frames.initial_pool_size = 4;
                check(ff::av_hwframe_ctx_init(self.hw_frames), "creating VA-API surfaces")?;
                c.pix_fmt = ff::AVPixelFormat::AV_PIX_FMT_VAAPI;
                c.hw_frames_ctx = ff::av_buffer_ref(self.hw_frames);
            }

            let mut dict: *mut ff::AVDictionary = ptr::null_mut();
            for (k, v) in options(&self.name) {
                let (k, v) = (CString::new(*k)?, CString::new(*v)?);
                ff::av_dict_set(&mut dict, k.as_ptr(), v.as_ptr(), 0);
            }
            let opened = ff::avcodec_open2(self.ctx, codec, &mut dict);
            ff::av_dict_free(&mut dict);
            check(opened, &format!("opening {}", self.name))?;

            #[cfg(windows)]
            if self.gpu.is_some() {
                return Ok(());
            }
            let p = &mut *self.picture;
            p.format = ff::AVPixelFormat::AV_PIX_FMT_NV12 as i32;
            p.width = self.width as i32;
            p.height = self.height as i32;
            check(ff::av_frame_get_buffer(self.picture, 0), "allocating frame")?;
        }
        Ok(())
    }

    /// Zero copy: a pool of NV12 textures on the capture's device for the encoder (one array,
    /// as decoders make them), which converted frames are copied into. Quick Sync takes them as
    /// frames of its own, derived from the pool; NVENC and AMF take them as they are.
    #[cfg(windows)]
    unsafe fn init_gpu(&mut self, device: &GpuDevice) -> Result<()> {
        use windows::{
            core::Interface,
            Win32::Graphics::Direct3D11::{ID3D11Multithread, D3D11_BIND_DECODER},
        };
        unsafe {
            // Encoders use the device from threads of their own; Quick Sync refuses it otherwise.
            if let Ok(multithread) = device.cast::<ID3D11Multithread>() {
                let _ = multithread.SetMultithreadProtected(true);
            }
            self.hw_device = ff::av_hwdevice_ctx_alloc(ff::AVHWDeviceType::AV_HWDEVICE_TYPE_D3D11VA);
            if self.hw_device.is_null() {
                bail!("av_hwdevice_ctx_alloc failed");
            }
            let hw = &mut *((*self.hw_device).data as *mut ff::AVHWDeviceContext);
            // FFmpeg releases the reference it is given.
            (*(hw.hwctx as *mut ff::AVD3D11VADeviceContext)).device =
                device.clone().into_raw() as *mut ff::ID3D11Device;
            check(ff::av_hwdevice_ctx_init(self.hw_device), "using the capture's GPU")?;

            self.hw_frames = ff::av_hwframe_ctx_alloc(self.hw_device);
            if self.hw_frames.is_null() {
                bail!("av_hwframe_ctx_alloc failed");
            }
            let frames = &mut *((*self.hw_frames).data as *mut ff::AVHWFramesContext);
            frames.format = ff::AVPixelFormat::AV_PIX_FMT_D3D11;
            frames.sw_format = ff::AVPixelFormat::AV_PIX_FMT_NV12;
            frames.width = self.width as i32;
            frames.height = self.height as i32;
            frames.initial_pool_size = GPU_POOL;
            (*(frames.hwctx as *mut ff::AVD3D11VAFramesContext)).BindFlags = D3D11_BIND_DECODER.0 as u32;
            check(ff::av_hwframe_ctx_init(self.hw_frames), "creating frames on the GPU")?;

            let mut gpu = Gpu {
                device: device.clone(),
                converter: super::d3d11::Converter::new(device, self.width as u32, self.height as u32)?,
                qsv_device: ptr::null_mut(),
                qsv_frames: ptr::null_mut(),
                last: ptr::null_mut(),
            };
            let c = &mut *self.ctx;
            if self.name == "h264_qsv" {
                check(
                    ff::av_hwdevice_ctx_create_derived(
                        &mut gpu.qsv_device,
                        ff::AVHWDeviceType::AV_HWDEVICE_TYPE_QSV,
                        self.hw_device,
                        0,
                    ),
                    "opening Quick Sync on the capture's GPU",
                )?;
                check(
                    ff::av_hwframe_ctx_create_derived(
                        &mut gpu.qsv_frames,
                        ff::AVPixelFormat::AV_PIX_FMT_QSV,
                        gpu.qsv_device,
                        self.hw_frames,
                        0,
                    ),
                    "sharing frames with Quick Sync",
                )?;
                c.pix_fmt = ff::AVPixelFormat::AV_PIX_FMT_QSV;
                c.hw_frames_ctx = ff::av_buffer_ref(gpu.qsv_frames);
            } else {
                c.pix_fmt = ff::AVPixelFormat::AV_PIX_FMT_D3D11;
                c.hw_frames_ctx = ff::av_buffer_ref(self.hw_frames);
            }
            self.gpu = Some(gpu);
        }
        Ok(())
    }

    /// Zero copy: converts the frame on the GPU into a new picture of the pool.
    #[cfg(windows)]
    unsafe fn fill_gpu(&mut self, frame: &Frame) -> Result<()> {
        use windows::{core::Interface, Win32::Graphics::Direct3D11::ID3D11Texture2D};
        let texture = frame.texture.context("the captured frame is not on the GPU")?;
        let gpu = self.gpu.as_mut().context("not encoding on the GPU")?;
        unsafe {
            let mut picture = ff::av_frame_alloc();
            if picture.is_null() {
                bail!("out of memory");
            }
            let got = ff::av_hwframe_get_buffer(self.hw_frames, picture, 0);
            if got < 0 {
                ff::av_frame_free(&mut picture);
                check(got, "getting a GPU frame")?;
            }
            // The pool: one array texture, a slice per picture.
            let pool = (*picture).data[0] as *mut std::ffi::c_void;
            let index = (*picture).data[1] as usize as u32;
            let converted = match ID3D11Texture2D::from_raw_borrowed(&pool) {
                Some(pool) => gpu.converter.convert(texture, pool, index),
                None => Err(anyhow::anyhow!("the GPU frame has no texture")),
            };
            if let Err(e) = converted {
                ff::av_frame_free(&mut picture);
                return Err(e);
            }
            ff::av_frame_free(&mut gpu.last);
            gpu.last = picture;
        }
        Ok(())
    }

    /// Whether frames come in on the GPU (zero copy).
    pub fn on_gpu(&self) -> bool {
        #[cfg(windows)]
        return self.gpu.is_some();
        #[cfg(not(windows))]
        false
    }

    unsafe fn free(&mut self) {
        unsafe {
            #[cfg(windows)]
            {
                self.gpu = None;
            }
            ff::avcodec_free_context(&mut self.ctx);
            ff::av_frame_free(&mut self.picture);
            ff::av_packet_free(&mut self.packet);
            ff::av_buffer_unref(&mut self.hw_frames);
            ff::av_buffer_unref(&mut self.hw_device);
        }
    }

    /// Converts into the encoder-owned NV12 frame.
    unsafe fn fill(&mut self, frame: &Frame) -> Result<()> {
        unsafe {
            check(ff::av_frame_make_writable(self.picture), "making frame writable")?;
            let p = &*self.picture;
            let (y_stride, uv_stride) = (p.linesize[0] as usize, p.linesize[1] as usize);
            let y = std::slice::from_raw_parts_mut(p.data[0], y_stride * self.height);
            let uv = std::slice::from_raw_parts_mut(p.data[1], uv_stride * self.height / 2);
            bgrx_to_yuv420(frame, y, y_stride, Chroma::Interleaved { uv, stride: uv_stride });
        }
        Ok(())
    }

    unsafe fn submit(&mut self, keyframe: bool, out: &mut Vec<EncodedFrame>) -> Result<()> {
        unsafe {
            let mut hw: *mut ff::AVFrame = ptr::null_mut();
            #[cfg(windows)]
            let gpu = self.gpu.as_ref().map(|g| (g.last, g.qsv_frames));
            #[cfg(not(windows))]
            let gpu: Option<(*mut ff::AVFrame, *mut ff::AVBufferRef)> = None;
            let input = if let Some((last, qsv_frames)) = gpu {
                if qsv_frames.is_null() {
                    last
                } else {
                    // Quick Sync sees the same texture slice as one of its frames, of the
                    // frames context derived from the pool.
                    hw = ff::av_frame_alloc();
                    if hw.is_null() {
                        bail!("out of memory");
                    }
                    (*hw).format = ff::AVPixelFormat::AV_PIX_FMT_QSV as i32;
                    (*hw).hw_frames_ctx = ff::av_buffer_ref(qsv_frames);
                    let mapped = ff::av_hwframe_map(hw, last, ff::AV_HWFRAME_MAP_DIRECT as i32);
                    if mapped < 0 {
                        ff::av_frame_free(&mut hw);
                        check(mapped, "handing the frame to Quick Sync")?;
                    }
                    hw
                }
            } else if self.hw_frames.is_null() {
                self.picture
            } else {
                hw = ff::av_frame_alloc();
                if hw.is_null() {
                    bail!("out of memory");
                }
                let uploaded = check(ff::av_hwframe_get_buffer(self.hw_frames, hw, 0), "getting GPU surface")
                    .and_then(|_| check(ff::av_hwframe_transfer_data(hw, self.picture, 0), "uploading frame"));
                if let Err(e) = uploaded {
                    ff::av_frame_free(&mut hw);
                    return Err(e);
                }
                hw
            };
            (*input).pts = self.pts;
            (*input).pict_type =
                if keyframe { ff::AVPictureType::AV_PICTURE_TYPE_I } else { ff::AVPictureType::AV_PICTURE_TYPE_NONE };
            self.pts += 1;
            let mut sent = ff::avcodec_send_frame(self.ctx, input);
            if sent == ff::AVERROR(ff::EAGAIN) {
                // Output queue full (an earlier wait timed out): drain, then resubmit.
                if let Err(e) = self.drain(out, false) {
                    ff::av_frame_free(&mut hw);
                    return Err(e);
                }
                sent = ff::avcodec_send_frame(self.ctx, input);
            }
            if !hw.is_null() {
                ff::av_frame_free(&mut hw);
            }
            check(sent, "submitting frame")?;
            self.pending += 1;
        }
        Ok(())
    }

    /// Collects finished packets; with `wait`, waits briefly for the one just submitted.
    unsafe fn drain(&mut self, out: &mut Vec<EncodedFrame>, wait: bool) -> Result<()> {
        let deadline = Instant::now() + MAX_OUTPUT_WAIT;
        unsafe {
            loop {
                let ret = ff::avcodec_receive_packet(self.ctx, self.packet);
                if ret == ff::AVERROR(ff::EAGAIN) {
                    if !wait || self.pending == 0 || Instant::now() >= deadline {
                        return Ok(());
                    }
                    std::thread::sleep(Duration::from_micros(250));
                    continue;
                }
                check(ret, "receiving packet")?;
                let pkt = &*self.packet;
                let data = std::slice::from_raw_parts(pkt.data, pkt.size as usize).to_vec();
                ff::av_packet_unref(self.packet);
                self.pending = self.pending.saturating_sub(1);
                let (data, keyframe) = self.parameter_sets.process(data);
                out.push(EncodedFrame { keyframe, width: self.width as u16, height: self.height as u16, data });
            }
        }
    }
}

impl VideoEncoder for Ffmpeg {
    fn name(&self) -> &str {
        &self.name
    }

    fn on_gpu(&self) -> bool {
        Ffmpeg::on_gpu(self)
    }

    /// NVENC and Quick Sync pick up a changed bitrate on the next frame.
    fn set_bitrate(&mut self, kbps: u32) -> bool {
        if self.ctx.is_null() {
            return false;
        }
        let bitrate = kbps as i64 * 1000;
        // SAFETY: the context is open and only used from this thread.
        unsafe {
            (*self.ctx).bit_rate = bitrate;
            (*self.ctx).rc_max_rate = bitrate;
        }
        self.settings.bitrate_kbps = kbps;
        true
    }

    fn encode(&mut self, frame: Option<&Frame>, keyframe: bool) -> Result<Encoded> {
        let mut out = Encoded::default();
        let mut keyframe = keyframe;
        if let Some(frame) = frame {
            let (w, h) = even_dims(frame);
            if (w, h) != (self.width, self.height) {
                // Encoders cannot change resolution in place.
                tracing::info!("resolution changed to {w}x{h}, reopening {}", self.name);
                #[cfg(windows)]
                let gpu = self.gpu.as_ref().map(|g| g.device.clone());
                #[cfg(not(windows))]
                let gpu: Option<GpuDevice> = None;
                *self = Self::open(&self.name, self.settings, w as u32, h as u32, gpu.as_ref())?;
                keyframe = true;
            }
            let start = Instant::now();
            // SAFETY: the frame (or the GPU pool) was allocated with the current dimensions.
            #[cfg(windows)]
            if self.gpu.is_some() {
                unsafe { self.fill_gpu(frame)? };
            } else {
                unsafe { self.fill(frame)? };
            }
            #[cfg(not(windows))]
            unsafe {
                self.fill(frame)?
            };
            self.has_picture = true;
            out.convert_time = start.elapsed();
        }
        if !self.has_picture {
            return Ok(out);
        }
        // SAFETY: context and frames are valid for the lifetime of `self`.
        unsafe {
            self.submit(keyframe, &mut out.frames).with_context(|| self.name.clone())?;
            self.drain(&mut out.frames, true).with_context(|| self.name.clone())?;
        }
        Ok(out)
    }
}

impl Drop for Ffmpeg {
    fn drop(&mut self) {
        // SAFETY: all pointers are either null or owned by `self`; the free functions accept
        // null and reset the pointers.
        unsafe { self.free() };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::bitstream::nal_types;

    /// Exercises the whole libavcodec path with a software encoder; hardware encoders differ
    /// only in their options. Skipped when FFmpeg was built without libx264.
    #[test]
    fn encodes_through_libavcodec() {
        let settings = EncoderSettings { fps: 60, bitrate_kbps: 2000 };
        let Ok(mut enc) = Ffmpeg::probe("libx264", settings, 64, 48, None) else {
            eprintln!("libx264 unavailable, skipping");
            return;
        };
        let picture = |w: u32, h: u32, shade: u8| -> Vec<u8> {
            (0..w * h).flat_map(|i| [shade, (i % 251) as u8, 255 - shade, 255]).collect()
        };
        let mut encode = |w: u32, h: u32, shade: Option<u8>, key: bool| {
            let data = shade.map(|s| picture(w, h, s));
            let frame = data.as_ref().map(|d| Frame::new(w, h, w as usize * 4, d));
            enc.encode(frame.as_ref(), key).unwrap().frames
        };

        let first = encode(64, 48, Some(10), true);
        assert_eq!(first.len(), 1, "low-latency settings must not buffer frames");
        assert!(first[0].keyframe);
        assert!(nal_types(&first[0].data).contains(&7), "first keyframe carries SPS");

        let delta = encode(64, 48, Some(40), false);
        assert!(!delta[0].keyframe);

        let forced = encode(64, 48, None, true);
        assert!(forced[0].keyframe, "re-encoding the last picture as a keyframe");
        assert!(nal_types(&forced[0].data).contains(&7), "every keyframe is self-contained");

        let resized = encode(81, 31, Some(90), false);
        assert!(resized[0].keyframe, "a new resolution starts with a keyframe");
        assert_eq!((resized[0].width, resized[0].height), (80, 30));
    }
}
