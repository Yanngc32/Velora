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
        let frame = Frame { width: 64, height: 64, stride: 256, data: &data };
        let mut enc = Software::new(EncoderSettings { fps: 60, bitrate_kbps: 4000 }).unwrap();
        assert!(enc.encode(None, true).unwrap().frames.is_empty(), "nothing to encode yet");
        let first = enc.encode(Some(&frame), true).unwrap().frames.remove(0);
        assert!(first.keyframe);
        assert_eq!((first.width, first.height), (64, 64));
        assert_eq!(&first.data[..4], &[0, 0, 0, 1]);
        let again = enc.encode(None, true).unwrap().frames.remove(0);
        assert!(again.keyframe);
    }
}
