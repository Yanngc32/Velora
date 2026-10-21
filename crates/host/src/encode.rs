//! Color conversion and H.264 encoding (OpenH264, software).

use anyhow::Result;
use openh264::{
    encoder::{
        BitRate, Complexity, Encoder, EncoderConfig, FrameRate, FrameType, IntraFramePeriod, RateControlMode,
        UsageType, VuiConfig,
    },
    formats::YUVSource,
    OpenH264API,
};

use crate::capture::Frame;

/// Planar I420 image. Dimensions are always even.
#[derive(Default)]
pub struct Yuv420 {
    width: usize,
    height: usize,
    data: Vec<u8>,
}

impl Yuv420 {
    pub fn width(&self) -> usize {
        self.width
    }

    pub fn height(&self) -> usize {
        self.height
    }

    fn planes_mut(&mut self) -> (&mut [u8], &mut [u8], &mut [u8]) {
        let y_len = self.width * self.height;
        let c_len = y_len / 4;
        let (y, rest) = self.data.split_at_mut(y_len);
        let (u, v) = rest.split_at_mut(c_len);
        (y, u, &mut v[..c_len])
    }

    /// Converts a BGRX frame using BT.601 limited range (signalled in the stream's VUI).
    /// Odd dimensions are cropped by one pixel, as 4:2:0 needs even sizes.
    pub fn convert_from(&mut self, frame: &Frame) {
        let (w, h) = ((frame.width & !1) as usize, (frame.height & !1) as usize);
        if (w, h) != (self.width, self.height) {
            self.width = w;
            self.height = h;
            self.data = vec![0; w * h * 3 / 2];
        }
        let stride = frame.stride;
        let src = frame.data;
        let (y_plane, u_plane, v_plane) = self.planes_mut();
        let cw = w / 2;

        for cy in 0..h / 2 {
            let row0 = &src[2 * cy * stride..][..w * 4];
            let row1 = &src[(2 * cy + 1) * stride..][..w * 4];
            let (y0, y1) = y_plane[2 * cy * w..][..2 * w].split_at_mut(w);
            let u_row = &mut u_plane[cy * cw..][..cw];
            let v_row = &mut v_plane[cy * cw..][..cw];

            for cx in 0..cw {
                let mut sr = 0i32;
                let mut sg = 0i32;
                let mut sb = 0i32;
                for (row, yrow) in [(row0, &mut *y0), (row1, &mut *y1)] {
                    for dx in 0..2 {
                        let px = &row[(2 * cx + dx) * 4..][..3];
                        let (b, g, r) = (px[0] as i32, px[1] as i32, px[2] as i32);
                        yrow[2 * cx + dx] = (((66 * r + 129 * g + 25 * b + 128) >> 8) + 16) as u8;
                        sr += r;
                        sg += g;
                        sb += b;
                    }
                }
                let (r, g, b) = ((sr + 2) >> 2, (sg + 2) >> 2, (sb + 2) >> 2);
                u_row[cx] = (((-38 * r - 74 * g + 112 * b + 128) >> 8) + 128) as u8;
                v_row[cx] = (((112 * r - 94 * g - 18 * b + 128) >> 8) + 128) as u8;
            }
        }
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

pub struct EncodedFrame {
    pub keyframe: bool,
    /// Annex-B bitstream.
    pub data: Vec<u8>,
}

pub struct VideoEncoder {
    encoder: Encoder,
}

impl VideoEncoder {
    pub fn new(fps: u32, bitrate_kbps: u32) -> Result<Self> {
        let config = EncoderConfig::new()
            // Measured on 1080p desktop content: ~2.6x faster than ScreenContentRealTime with
            // indistinguishable text once the picture settles. Latency wins.
            .usage_type(UsageType::CameraVideoRealTime)
            .rate_control_mode(RateControlMode::Bitrate)
            .bitrate(BitRate::from_bps(bitrate_kbps.saturating_mul(1000)))
            .max_frame_rate(FrameRate::from_hz(fps as f32))
            // Dropping frames inside the encoder adds jitter; pacing is done upstream.
            .skip_frames(false)
            .complexity(Complexity::Low)
            // No periodic keyframes: the transport is reliable, the client asks when needed.
            .intra_frame_period(IntraFramePeriod::from_num_frames(0))
            .vui(VuiConfig::bt601());
        Ok(Self { encoder: Encoder::with_api_config(OpenH264API::from_source(), config)? })
    }

    /// Returns `None` when the encoder produced no output for this picture.
    pub fn encode(&mut self, yuv: &Yuv420, force_keyframe: bool) -> Result<Option<EncodedFrame>> {
        if force_keyframe {
            self.encoder.force_intra_frame();
        }
        let bitstream = self.encoder.encode(yuv)?;
        let keyframe = match bitstream.frame_type() {
            FrameType::IDR | FrameType::I => true,
            FrameType::P | FrameType::IPMixed => false,
            FrameType::Skip | FrameType::Invalid => return Ok(None),
        };
        let data = bitstream.to_vec();
        if data.is_empty() {
            return Ok(None);
        }
        Ok(Some(EncodedFrame { keyframe, data }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn solid(w: u32, h: u32, bgr: [u8; 3]) -> Vec<u8> {
        (0..w * h).flat_map(|_| [bgr[0], bgr[1], bgr[2], 255]).collect()
    }

    #[test]
    fn converts_reference_colors() {
        // BT.601 limited range reference values.
        for (bgr, yuv) in [
            ([0, 0, 0], (16, 128, 128)),
            ([255, 255, 255], (235, 128, 128)),
            ([0, 0, 255], (82, 90, 240)),  // red
            ([255, 0, 0], (41, 240, 110)), // blue
        ] {
            let data = solid(4, 2, bgr);
            let frame = Frame { width: 4, height: 2, stride: 16, data: &data };
            let mut out = Yuv420::default();
            out.convert_from(&frame);
            let (y, u, v) = (out.y()[0] as i32, out.u()[0] as i32, out.v()[0] as i32);
            assert!(
                (y - yuv.0).abs() <= 1 && (u - yuv.1).abs() <= 1 && (v - yuv.2).abs() <= 1,
                "{bgr:?} -> {y} {u} {v}"
            );
        }
    }

    #[test]
    fn crops_odd_dimensions_and_honors_stride() {
        let (w, h, stride) = (5u32, 3u32, 32usize);
        let data = vec![128u8; stride * h as usize];
        let frame = Frame { width: w, height: h, stride, data: &data };
        let mut out = Yuv420::default();
        out.convert_from(&frame);
        assert_eq!(out.dimensions(), (4, 2));
        assert_eq!(out.y().len(), 8);
        assert_eq!(out.u().len(), 2);
        assert_eq!(out.v().len(), 2);
    }

    #[test]
    fn first_frame_is_a_keyframe() {
        let data = solid(64, 64, [10, 200, 30]);
        let frame = Frame { width: 64, height: 64, stride: 256, data: &data };
        let mut yuv = Yuv420::default();
        yuv.convert_from(&frame);
        let mut enc = VideoEncoder::new(60, 4000).unwrap();
        let first = enc.encode(&yuv, true).unwrap().unwrap();
        assert!(first.keyframe);
        assert_eq!(&first.data[..4], &[0, 0, 0, 1]);
        if let Some(second) = enc.encode(&yuv, false).unwrap() {
            assert!(!second.keyframe);
        }
    }
}
