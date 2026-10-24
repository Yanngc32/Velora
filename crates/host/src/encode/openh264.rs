//! Software H.264 (OpenH264): always available, CPU bound.

use std::time::Instant;

use anyhow::Result;
use openh264::{
    encoder::{
        BitRate, Complexity, Encoder, EncoderConfig, FrameRate, FrameType, IntraFramePeriod, RateControlMode,
        UsageType, VuiConfig,
    },
    formats::YUVSource,
    OpenH264API,
};

use super::{
    convert::{bgrx_to_yuv420, even_dims, Chroma},
    Encoded, EncodedFrame, EncoderSettings, VideoEncoder,
};
use crate::capture::Frame;

/// Planar I420 image with even dimensions.
#[derive(Default)]
struct Yuv420 {
    width: usize,
    height: usize,
    data: Vec<u8>,
}

impl Yuv420 {
    fn convert_from(&mut self, frame: &Frame) {
        let (w, h) = even_dims(frame);
        if (w, h) != (self.width, self.height) {
            *self = Self { width: w, height: h, data: vec![0; w * h * 3 / 2] };
        }
        let (y, chroma) = self.data.split_at_mut(w * h);
        let (u, v) = chroma.split_at_mut(w * h / 4);
        bgrx_to_yuv420(frame, y, w, Chroma::Planar { u, u_stride: w / 2, v, v_stride: w / 2 });
    }
}

impl YUVSource for Yuv420 {
    fn dimensions(&self) -> (usize, usize) {
        (self.width, self.height)
    }

    fn strides(&self) -> (usize, usize, usize) {
        (self.width, self.width / 2, self.width / 2)
    }

    fn y(&self) -> &[u8] {
        &self.data[..self.width * self.height]
    }

    fn u(&self) -> &[u8] {
        let y_len = self.width * self.height;
        &self.data[y_len..y_len + y_len / 4]
    }

    fn v(&self) -> &[u8] {
        let y_len = self.width * self.height;
        &self.data[y_len + y_len / 4..]
    }
}

pub struct Software {
    encoder: Encoder,
    picture: Yuv420,
}

impl Software {
    pub fn new(settings: EncoderSettings) -> Result<Self> {
        let config = EncoderConfig::new()
            // Measured on 1080p desktop content: ~2.6x faster than ScreenContentRealTime with
            // indistinguishable text once the picture settles. Latency wins.
            .usage_type(UsageType::CameraVideoRealTime)
            .rate_control_mode(RateControlMode::Bitrate)
            .bitrate(BitRate::from_bps(settings.bitrate_kbps.saturating_mul(1000)))
            .max_frame_rate(FrameRate::from_hz(settings.fps as f32))
            // Dropping frames inside the encoder adds jitter; pacing is done upstream.
            .skip_frames(false)
            .complexity(Complexity::Low)
            // No periodic keyframes: the transport is reliable, the client asks when needed.
            .intra_frame_period(IntraFramePeriod::from_num_frames(0))
            .vui(VuiConfig::bt601());
        Ok(Self { encoder: Encoder::with_api_config(OpenH264API::from_source(), config)?, picture: Yuv420::default() })
    }
}

impl VideoEncoder for Software {
    fn name(&self) -> &str {
        "openh264 (software)"
    }

    fn set_bitrate(&mut self, kbps: u32) -> bool {
        /// `SBitrateInfo` of the OpenH264 API.
        #[repr(C)]
        struct BitrateInfo {
            layer: std::ffi::c_int,
            bitrate: std::ffi::c_int,
        }
        const ENCODER_OPTION_BITRATE: std::ffi::c_int = 5;
        const SPATIAL_LAYER_ALL: std::ffi::c_int = 4;
        let mut info = BitrateInfo { layer: SPATIAL_LAYER_ALL, bitrate: kbps.saturating_mul(1000) as std::ffi::c_int };
        // SAFETY: the documented option with the struct it takes, on a live encoder.
        unsafe {
            self.encoder.raw_api().set_option(ENCODER_OPTION_BITRATE, &mut info as *mut _ as *mut std::ffi::c_void) == 0
        }
    }

    fn encode(&mut self, frame: Option<&Frame>, keyframe: bool) -> Result<Encoded> {
        let mut out = Encoded::default();
        if let Some(frame) = frame {
            let start = Instant::now();
            self.picture.convert_from(frame);
            out.convert_time = start.elapsed();
        }
        if self.picture.width == 0 {
            return Ok(out);
        }
        if keyframe {
            self.encoder.force_intra_frame();
        }
        let bitstream = self.encoder.encode(&self.picture)?;
        let keyframe = match bitstream.frame_type() {
            FrameType::IDR | FrameType::I => true,
            FrameType::P | FrameType::IPMixed => false,
            FrameType::Skip | FrameType::Invalid => return Ok(out),
        };
        let data = bitstream.to_vec();
        if !data.is_empty() {
            out.frames.push(EncodedFrame {
                keyframe,
                width: self.picture.width as u16,
                height: self.picture.height as u16,
                data,
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_frame_is_a_keyframe_and_reencode_works() {
        let data: Vec<u8> = (0..64 * 64).flat_map(|_| [10, 200, 30, 255]).collect();
        let frame = Frame::new(64, 64, 256, &data);
        let mut enc = Software::new(EncoderSettings { fps: 60, bitrate_kbps: 4000 }).unwrap();
        assert!(enc.encode(None, true).unwrap().frames.is_empty(), "nothing to encode yet");
        let first = enc.encode(Some(&frame), true).unwrap().frames.remove(0);
        assert!(first.keyframe);
        assert_eq!((first.width, first.height), (64, 64));
        assert_eq!(&first.data[..4], &[0, 0, 0, 1]);
        let again = enc.encode(None, true).unwrap().frames.remove(0);
        assert!(again.keyframe);
    }

    /// What refining a still picture (`crate::refine`) relies on: encoding the same picture
    /// again spends each frame's budget on what it lacks, until there is nothing to add.
    #[test]
    fn encoding_a_still_picture_again_sharpens_it() {
        // Lines of text-like marks on a gradient, at a bitrate that blurs the keyframe.
        let (w, h) = (640u32, 360u32);
        let data: Vec<u8> = (0..w * h)
            .flat_map(|i| {
                let (x, y) = (i % w, i / w);
                let ink = y % 16 < 10 && x % 9 < 6 && (x * 31 + y * 17) % 7 < 3 && (x / 9 + y / 16) % 5 != 0;
                let v = if ink { 30 } else { 235 - (x / 8) as u8 };
                [v, v, v, 255]
            })
            .collect();
        let frame = Frame::new(w, h, w as usize * 4, &data);
        let mut enc = Software::new(EncoderSettings { fps: 60, bitrate_kbps: 300 }).unwrap();
        let mut decoder = openh264::decoder::Decoder::new().unwrap();
        // Mean squared luma error of the decoded picture after `packet`.
        let mut error = |packet: &[u8], source: &Yuv420| {
            let decoded = decoder.decode(packet).unwrap().expect("a picture per packet");
            let (stride, _, _) = decoded.strides();
            let mut sum = 0.0;
            for row in 0..source.height {
                for col in 0..source.width {
                    let d = decoded.y()[row * stride + col] as f64 - source.y()[row * source.width + col] as f64;
                    sum += d * d;
                }
            }
            sum / (source.width * source.height) as f64
        };

        let key = enc.encode(Some(&frame), true).unwrap().frames.remove(0);
        let blurry = error(&key.data, &enc.picture);
        let mut last = (blurry, key.data.len());
        for _ in 0..60 {
            let frames = enc.encode(None, false).unwrap().frames;
            let Some(frame) = frames.first() else { break };
            last = (error(&frame.data, &enc.picture), frame.data.len());
        }
        let (sharp, settled_bytes) = last;
        assert!(sharp < blurry / 4.0, "squared error {blurry:.1} -> {sharp:.1}");
        assert!(settled_bytes < 100, "nothing left to add: {settled_bytes} bytes");
    }
}
