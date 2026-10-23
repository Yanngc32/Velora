//! The host's sound in a session. What the host plays is captured (WASAPI loopback), encoded
//! to Opus 20 ms at a time and sent in QUIC datagrams; the client decodes it and plays it
//! through a short buffer that absorbs the network's jitter. A lost packet is a 20 ms gap,
//! never a delay for the ones after it.
//!
//! Windows only for now, and only in builds with FFmpeg, which brings Opus.

// Elsewhere the player and its buffer exist but are never started.
#![cfg_attr(not(all(windows, feature = "ffmpeg")), allow(dead_code))]

use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

use anyhow::Result;

#[cfg(all(windows, feature = "ffmpeg"))]
mod opus;
#[cfg(windows)]
mod wasapi;

pub const SAMPLE_RATE: u32 = 48_000;
pub const CHANNELS: usize = 2;
/// Samples per channel in one packet: 20 ms.
pub const FRAME: usize = 960;
/// Opus bitrate: clean music for a fraction of the video's.
#[cfg(all(windows, feature = "ffmpeg"))]
const BITRATE: i64 = 96_000;

/// Whether this build can capture and play sound.
pub const SUPPORTED: bool = cfg!(all(windows, feature = "ffmpeg"));

/// 20 ms frames of near silence sent before going quiet: enough for Opus to fade out.
#[cfg(all(windows, feature = "ffmpeg"))]
const QUIET_FRAMES: usize = 5;

/// Captures what this computer plays and passes each Opus packet to `send`, until `running`
/// turns false or `send` does. Blocks: run it on a thread of its own. Silence is not sent.
#[allow(unused_variables, unused_mut)]
pub fn stream_loopback(running: impl Fn() -> bool, mut send: impl FnMut(&[u8]) -> bool) -> Result<()> {
    #[cfg(all(windows, feature = "ffmpeg"))]
    {
        let mut encoder = opus::Encoder::new(BITRATE)?;
        let mut pending: Vec<f32> = Vec::with_capacity(FRAME * CHANNELS * 4);
        let mut packets = Vec::new();
        let mut quiet = 0;
        wasapi::capture(&running, |samples| {
            pending.extend_from_slice(samples);
            while pending.len() >= FRAME * CHANNELS {
                let frame: Vec<f32> = pending.drain(..FRAME * CHANNELS).collect();
                quiet = if frame.iter().all(|s| s.abs() < 1e-4) { quiet + 1 } else { 0 };
                if quiet > QUIET_FRAMES {
                    continue;
                }
                encoder.encode(&frame, &mut packets)?;
                for packet in packets.drain(..) {
                    if !send(&packet) {
                        return Ok(false);
                    }
                }
            }
            Ok(true)
        })
    }
    #[cfg(not(all(windows, feature = "ffmpeg")))]
    anyhow::bail!("this build of Velora can't capture sound")
}

/// Plays a host's sound on this computer's default output, from packets as they arrive.
pub struct Player {
    packets: std::sync::mpsc::Sender<Vec<u8>>,
    ring: Arc<Mutex<Ring>>,
    muted: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
}

impl Player {
    /// Starts a decoder thread and the output device's thread.
    pub fn start() -> Result<Self> {
        #[cfg(all(windows, feature = "ffmpeg"))]
        {
            let (packets, rx) = std::sync::mpsc::channel::<Vec<u8>>();
            let ring = Arc::new(Mutex::new(Ring::default()));
            let (muted, stop) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicBool::new(false)));
            let mut decoder = opus::Decoder::new()?;
            {
                let (ring, muted) = (ring.clone(), muted.clone());
                std::thread::Builder::new().name("audio-decode".into()).spawn(move || {
                    let mut pcm = Vec::new();
                    for packet in rx {
                        if muted.load(Ordering::Relaxed) {
                            continue;
                        }
                        pcm.clear();
                        match decoder.decode(&packet, &mut pcm) {
                            Ok(()) => ring.lock().unwrap().push(&pcm),
                            Err(e) => tracing::debug!("audio packet dropped: {e:#}"),
                        }
                    }
                })?;
            }
            {
                let (ring, stop) = (ring.clone(), stop.clone());
                std::thread::Builder::new()
                    .name("audio-out".into())
                    .spawn(move || wasapi::play(&|| !stop.load(Ordering::Relaxed), &ring))?;
            }
            Ok(Self { packets, ring, muted, stop })
        }
        #[cfg(not(all(windows, feature = "ffmpeg")))]
        anyhow::bail!("this build of Velora can't play sound")
    }

    pub fn push(&self, packet: Vec<u8>) {
        let _ = self.packets.send(packet);
    }

    /// Muting also drops what is buffered, so the sound stops at once.
    pub fn set_muted(&self, muted: bool) {
        self.muted.store(muted, Ordering::Relaxed);
        if muted {
            self.ring.lock().unwrap().samples.clear();
        }
    }
}

impl Drop for Player {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Samples between the decoder and the output device.
#[derive(Default)]
struct Ring {
    samples: VecDeque<f32>,
    /// Playing; after running dry it waits for `PREFILL` again, so one late packet doesn't
    /// turn into many short gaps.
    playing: bool,
}

/// Buffered before playing starts: covers the network's usual jitter.
const PREFILL: usize = SAMPLE_RATE as usize * CHANNELS * 40 / 1000;
/// Above this the buffer only adds delay: drop back to `PREFILL`.
const MAX_BUFFERED: usize = SAMPLE_RATE as usize * CHANNELS * 200 / 1000;

impl Ring {
    fn push(&mut self, samples: &[f32]) {
        self.samples.extend(samples);
        if self.samples.len() > MAX_BUFFERED {
            let excess = self.samples.len() - PREFILL;
            self.samples.drain(..excess - excess % CHANNELS);
        }
    }

    /// Fills `out` with what is buffered, then silence.
    fn fill(&mut self, out: &mut [f32]) {
        if !self.playing && self.samples.len() >= PREFILL {
            self.playing = true;
        }
        let mut n = 0;
        if self.playing {
            n = out.len().min(self.samples.len());
            for (slot, sample) in out.iter_mut().zip(self.samples.drain(..n)) {
                *slot = sample;
            }
            if self.samples.is_empty() {
                self.playing = false;
            }
        }
        out[n..].fill(0.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_waits_for_prefill_then_plays_and_caps_delay() {
        let mut ring = Ring::default();
        let mut out = vec![1.0; 8];
        ring.push(&[0.5; 8]);
        ring.fill(&mut out);
        assert!(out.iter().all(|&s| s == 0.0), "not enough buffered yet");

        ring.push(&vec![0.5; PREFILL]);
        ring.fill(&mut out);
        assert!(out.iter().all(|&s| s == 0.5));

        ring.push(&vec![0.25; MAX_BUFFERED * 2]);
        assert!(ring.samples.len() <= PREFILL, "delay is capped");
        assert_eq!(ring.samples.len() % CHANNELS, 0, "channels stay aligned");
    }
}
