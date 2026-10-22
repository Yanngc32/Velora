//! Adaptive bitrate: lowers the video bitrate when the network falls behind and raises it again
//! once it keeps up, between a floor and the configured bitrate.
//!
//! Frames go over reliable streams, so a congested path shows up as frames taking longer to be
//! acknowledged, and as the host holding frames back (in-flight limit reached), not as loss.
//! Once a second, the delivery time is compared with the lowest one of the last ten seconds
//! (what the path does when it is not queueing): well above it, or many frames held back, and
//! the bitrate is cut (multiplicatively); calm for a while, and it grows back (additively).

use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

/// How often a decision is made.
pub const PERIOD: Duration = Duration::from_secs(1);
/// Seconds of delivery times the baseline is the minimum of.
const BASELINE_SECONDS: usize = 10;
/// Delivery time over the baseline that counts as queueing: this much, or half the baseline.
const QUEUEING: Duration = Duration::from_millis(25);
/// Share of a period spent holding frames back that counts as congestion.
const HELD_BACK: f64 = 0.25;
/// Cut on congestion, and growth per calm step as a share of the maximum.
const DECREASE: f64 = 0.7;
const INCREASE: f64 = 0.08;
/// Calm needed after a change before growing.
const SETTLE: Duration = Duration::from_secs(2);
/// Changes smaller than this share are not worth reconfiguring the encoder for.
const MIN_STEP: f64 = 0.03;

/// What a period looked like.
#[derive(Debug, Clone, Copy, Default)]
pub struct Sample {
    /// Mean capture-to-acknowledgement time of the frames acknowledged, if any.
    pub delivery: Option<Duration>,
    /// Time the capture waited because too many frames were unacknowledged.
    pub held_back: Duration,
}

pub struct RateControl {
    max: u32,
    min: u32,
    current: u32,
    history: VecDeque<Duration>,
    last_change: Instant,
}

impl RateControl {
    /// Starts at `max_kbps`, the configured bitrate.
    pub fn new(max_kbps: u32, now: Instant) -> Self {
        let max = max_kbps.max(100);
        Self { max, min: (max / 10).max(500).min(max), current: max, history: VecDeque::new(), last_change: now }
    }

    #[cfg(test)]
    fn current(&self) -> u32 {
        self.current
    }

    /// Takes a period's sample; returns the new bitrate when it changes.
    pub fn update(&mut self, sample: Sample, now: Instant) -> Option<u32> {
        let baseline = self.history.iter().min().copied();
        if let Some(delivery) = sample.delivery {
            self.history.push_back(delivery);
            if self.history.len() > BASELINE_SECONDS {
                self.history.pop_front();
            }
        }
        let queueing = match (sample.delivery, baseline) {
            (Some(delivery), Some(base)) => delivery > base + QUEUEING.max(base / 2),
            _ => false,
        };
        let held_back = sample.held_back.as_secs_f64() > PERIOD.as_secs_f64() * HELD_BACK;
        let next = if queueing || held_back {
            (self.current as f64 * DECREASE) as u32
        } else if now.duration_since(self.last_change) >= SETTLE {
            self.current + (self.max as f64 * INCREASE) as u32
        } else {
            self.current
        }
        .clamp(self.min, self.max);
        let step = (next as f64 - self.current as f64).abs() / self.current as f64;
        if next == self.current || (step < MIN_STEP && next != self.max && next != self.min) {
            return None;
        }
        self.current = next;
        self.last_change = now;
        Some(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(ms: u64, held_back_ms: u64) -> Sample {
        Sample { delivery: Some(Duration::from_millis(ms)), held_back: Duration::from_millis(held_back_ms) }
    }

    #[test]
    fn cuts_on_queueing_and_recovers_when_calm() {
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        let mut rc = RateControl::new(12_000, t0);
        // A calm path at full rate stays put.
        for s in 1..=5 {
            assert_eq!(rc.update(sample(20, 0), at(s)), None);
        }
        // Delivery time climbs well above the 20 ms baseline: cut.
        assert_eq!(rc.update(sample(80, 0), at(6)), Some(8_400));
        assert_eq!(rc.update(sample(70, 0), at(7)), Some(5_880));
        // Calm again: no growth before it settles, then step by step back to the maximum.
        assert_eq!(rc.update(sample(22, 0), at(8)), None);
        assert_eq!(rc.update(sample(21, 0), at(9)), Some(6_840));
        let mut s = 10;
        while rc.current() < 12_000 {
            s += 2;
            rc.update(sample(20, 0), at(s));
        }
        assert_eq!(rc.current(), 12_000);
    }

    #[test]
    fn frames_held_back_count_as_congestion_and_the_floor_holds() {
        let t0 = Instant::now();
        let mut rc = RateControl::new(12_000, t0);
        let mut last = 12_000;
        for s in 1..=20 {
            if let Some(next) = rc.update(sample(20, 600), t0 + Duration::from_secs(s)) {
                assert!(next < last);
                last = next;
            }
        }
        assert_eq!(rc.current(), 1_200, "a tenth of the maximum, at least 500 kbit/s");
    }
}
