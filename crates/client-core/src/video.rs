//! Software video decoding thread and the frame hand-off to the UI.
//!
//! Each frame is acknowledged only after it has been decoded, so the host's in-flight limit
//! also throttles to the client's decode speed and no queue can build up anywhere between
//! capture and display. Frames stay YUV: the window converts them on the GPU, or with
//! [`VideoFrame::to_xrgb`] when it draws in software.

use std::{
    sync::{mpsc, Arc, Mutex},
    time::{Duration, Instant},
};

use openh264::{decoder::Decoder, formats::YUVSource, OpenH264API};
use tokio::sync::mpsc::UnboundedSender;
use velora_protocol::wire::ClientMsg;

use crate::reorder::{Packet, Reorder};

const STATS_INTERVAL: Duration = Duration::from_secs(5);

/// A decoded picture, I420: full-size luma, then the two chroma planes at half width and height
/// (rounded up), each packed without padding.
pub struct VideoFrame {
    pub frame_id: u32,
    pub width: u32,
    pub height: u32,
    pub y: Vec<u8>,
    pub u: Vec<u8>,
    pub v: Vec<u8>,
}

impl VideoFrame {
    /// Width and height of the chroma planes.
    pub fn chroma_size(&self) -> (u32, u32) {
        (self.width.div_ceil(2), self.height.div_ceil(2))
    }

    /// The picture as `0x00RRGGBB` pixels, for drawing without a GPU.
    pub fn to_xrgb(&self, out: &mut Vec<u32>) {
        let (w, h) = (self.width as usize, self.height as usize);
        let cw = self.chroma_size().0 as usize;
        i420_to_xrgb((&self.y, &self.u, &self.v), (w, cw, cw), (w, h), out);
    }
}

/// Planes of a frame, kept for reuse.
type Planes = (Vec<u8>, Vec<u8>, Vec<u8>);

/// Single-slot mailbox: the UI always gets the most recent picture; older undisplayed ones are
/// dropped instead of queued.
#[derive(Default)]
pub struct FrameSlot {
    latest: Mutex<Option<VideoFrame>>,
    spare: Mutex<Vec<Planes>>,
}

impl FrameSlot {
    pub fn take(&self) -> Option<VideoFrame> {
        self.latest.lock().unwrap().take()
    }

    /// Returns a displayed frame's buffers for reuse, avoiding large allocations per frame.
    pub fn recycle(&self, frame: VideoFrame) {
        let mut spare = self.spare.lock().unwrap();
        if spare.len() < 2 {
            spare.push((frame.y, frame.u, frame.v));
        }
    }

    fn buffers(&self) -> Planes {
        self.spare.lock().unwrap().pop().unwrap_or_default()
    }

    fn publish(&self, frame: VideoFrame) {
        if let Some(old) = self.latest.lock().unwrap().replace(frame) {
            self.recycle(old);
        }
    }
}

pub(crate) fn spawn_decoder(
    slot: Arc<FrameSlot>,
    control: UnboundedSender<ClientMsg>,
    on_frame: Arc<dyn Fn() + Send + Sync>,
) -> mpsc::Sender<Packet> {
    let (tx, rx) = mpsc::channel::<Packet>();
    std::thread::Builder::new()
        .name("decoder".into())
        .spawn(move || {
            if let Err(e) = decode_loop(rx, &slot, &control, &*on_frame) {
                tracing::error!("decoder stopped: {e:#}");
            }
        })
        .expect("spawning decoder thread");
    tx
}

fn decode_loop(
    rx: mpsc::Receiver<Packet>,
    slot: &FrameSlot,
    control: &UnboundedSender<ClientMsg>,
    on_frame: &(dyn Fn() + Send + Sync),
) -> anyhow::Result<()> {
    let mut decoder = Decoder::with_api_config(OpenH264API::from_source(), Default::default())?;
    let mut reorder = Reorder::default();
    let mut need_keyframe = false;
    let mut stats = Stats::new();

    for packet in rx {
        let (ready, resynced) = reorder.push(packet);
        need_keyframe |= resynced;

        for packet in ready {
            let id = packet.header.frame_id;

            if need_keyframe && !packet.header.keyframe {
                let _ = control.send(ClientMsg::FrameAck { frame_id: id });
                continue;
            }

            let start = Instant::now();
            match decoder.decode(&packet.data) {
                Ok(Some(yuv)) => {
                    need_keyframe = false;
                    let (w, h) = yuv.dimensions();
                    let decoded = start.elapsed();
                    let (mut y, mut u, mut v) = slot.buffers();
                    let (sy, su, sv) = yuv.strides();
                    let (cw, ch) = (w.div_ceil(2), h.div_ceil(2));
                    pack(yuv.y(), sy, w, h, &mut y);
                    pack(yuv.u(), su, cw, ch, &mut u);
                    pack(yuv.v(), sv, cw, ch, &mut v);
                    stats.convert += start.elapsed() - decoded;
                    slot.publish(VideoFrame { frame_id: id, width: w as u32, height: h as u32, y, u, v });
                    stats.decoded(start.elapsed(), packet.data.len());
                    on_frame();
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!("decode error on frame {id}: {e}; requesting keyframe");
                    need_keyframe = true;
                    let _ = control.send(ClientMsg::RequestKeyframe);
                }
            }
            let _ = control.send(ClientMsg::FrameAck { frame_id: id });
        }
        stats.maybe_log();
    }
    Ok(())
}

/// Copies a `width` × `height` plane with rows `stride` apart into `out`, rows back to back.
fn pack(plane: &[u8], stride: usize, width: usize, height: usize, out: &mut Vec<u8>) {
    out.clear();
    out.reserve(width * height);
    for row in plane.chunks(stride).take(height) {
        out.extend_from_slice(&row[..width]);
    }
}

/// BT.601 limited-range I420 to `0x00RRGGBB`, matching the host's conversion.
fn i420_to_xrgb(
    (yp, up, vp): (&[u8], &[u8], &[u8]),
    (sy, su, sv): (usize, usize, usize),
    (w, h): (usize, usize),
    out: &mut Vec<u32>,
) {
    out.resize(w * h, 0);

    // Per-pixel chroma contributions for the current pair of rows; expanding them first keeps
    // the main loop branch-free so it auto-vectorizes.
    let mut rd = vec![0i32; w];
    let mut gd = vec![0i32; w];
    let mut bd = vec![0i32; w];
    for row in 0..h {
        if row % 2 == 0 {
            let u_row = &up[(row / 2) * su..][..w.div_ceil(2)];
            let v_row = &vp[(row / 2) * sv..][..w.div_ceil(2)];
            for x in 0..w {
                let (d, e) = (u_row[x / 2] as i32 - 128, v_row[x / 2] as i32 - 128);
                rd[x] = 409 * e + 128;
                gd[x] = -100 * d - 208 * e + 128;
                bd[x] = 516 * d + 128;
            }
        }
        let y_row = &yp[row * sy..][..w];
        let dst = &mut out[row * w..][..w];
        for ((((px, &y), &rd), &gd), &bd) in dst.iter_mut().zip(y_row).zip(&rd).zip(&gd).zip(&bd) {
            let c = 298 * (y as i32 - 16);
            let r = ((c + rd) >> 8).clamp(0, 255) as u32;
            let g = ((c + gd) >> 8).clamp(0, 255) as u32;
            let b = ((c + bd) >> 8).clamp(0, 255) as u32;
            *px = (r << 16) | (g << 8) | b;
        }
    }
}

struct Stats {
    since: Instant,
    frames: u32,
    bytes: usize,
    decode: Duration,
    convert: Duration,
}

impl Stats {
    fn new() -> Self {
        Self { since: Instant::now(), frames: 0, bytes: 0, decode: Duration::ZERO, convert: Duration::ZERO }
    }

    fn decoded(&mut self, took: Duration, bytes: usize) {
        self.frames += 1;
        self.bytes += bytes;
        self.decode += took;
    }

    fn maybe_log(&mut self) {
        let elapsed = self.since.elapsed();
        if elapsed < STATS_INTERVAL {
            return;
        }
        let secs = elapsed.as_secs_f64();
        let ms = |d: Duration| if self.frames == 0 { 0.0 } else { d.as_secs_f64() * 1000.0 / self.frames as f64 };
        tracing::info!(
            "decoded {:.1} fps, {:.2} Mbit/s, decode {:.1} ms, copy {:.1} ms",
            self.frames as f64 / secs,
            self.bytes as f64 * 8.0 / secs / 1e6,
            ms(self.decode - self.convert),
            ms(self.convert)
        );
        *self = Self::new();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_reference_colors() {
        for ((y, u, v), rgb) in
            [((16u8, 128u8, 128u8), 0x000000u32), ((235, 128, 128), 0xFFFFFF), ((82, 90, 240), 0xFF0000)]
        {
            let frame = VideoFrame { frame_id: 0, width: 2, height: 2, y: vec![y; 4], u: vec![u], v: vec![v] };
            let mut out = Vec::new();
            frame.to_xrgb(&mut out);
            for px in out {
                for shift in [0, 8, 16] {
                    let (a, b) = ((px >> shift) & 0xFF, (rgb >> shift) & 0xFF);
                    assert!(a.abs_diff(b) <= 2, "{px:06X} vs {rgb:06X}");
                }
            }
        }
    }

    #[test]
    fn packs_strided_planes() {
        let plane = [1, 2, 9, 9, 3, 4, 9, 9];
        let mut out = vec![7; 10];
        pack(&plane, 4, 2, 2, &mut out);
        assert_eq!(out, [1, 2, 3, 4]);
    }
}
