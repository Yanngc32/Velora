//! Sharpening a still picture.
//!
//! Frames are encoded only when the screen changes, each within the frame budget of the current
//! bitrate (bitrate / frame rate). A change the budget cut down (a keyframe, a window switch
//! at a low bitrate) would stay blurry for as long as the screen stays still: nothing is
//! encoded again. So once the screen stops changing after such a frame, the unchanged picture
//! is encoded again, frame after frame at the frame rate: each frame spends its budget on what
//! the picture still lacks, until the encoder has nothing left to add (its frames become tiny)
//! or a bound is reached. The rate control keeps that within the bitrate, like motion.
//!
//! Small changes (a blinking caret, a clock) fit their budget and leave the rest of the picture
//! as sharp as it was, so they do not call for refining. A bitrate well above the one the
//! picture was refined at does: the larger budget sharpens it further.

/// A frame that used this share of its budget was cut down by the rate control.
const BUDGET_USED: f64 = 0.5;
/// A refining frame under this share of its budget means the picture is as sharp as the
/// encoder makes it.
const SETTLED: f64 = 0.05;
/// Most refining frames after a change: two seconds at 60 fps.
const MAX_FRAMES: u32 = 120;
/// A bitrate this many times the one the picture was refined at is worth refining again.
const RISE: f64 = 1.5;

pub struct Refine {
    fps: u32,
    /// Refining frames still to encode.
    left: u32,
    /// Bitrate the still picture was last refined at.
    refined_kbps: Option<u32>,
}

impl Refine {
    pub fn new(fps: u32) -> Self {
        Self { fps: fps.max(1), left: 0, refined_kbps: None }
    }

    fn budget_bits(&self, kbps: u32) -> f64 {
        kbps as f64 * 1000.0 / self.fps as f64
    }

    /// A frame of `bytes` was encoded at `kbps` for a change of the screen.
    pub fn changed(&mut self, bytes: usize, kbps: u32) {
        if bytes as f64 * 8.0 >= self.budget_bits(kbps) * BUDGET_USED {
            self.left = MAX_FRAMES;
            self.refined_kbps = None;
        }
    }

    /// The screen is unchanged: whether to encode it again now, at `kbps`.
    pub fn due(&mut self, kbps: u32) -> bool {
        if self.left == 0 && self.refined_kbps.is_some_and(|k| kbps as f64 >= k as f64 * RISE) {
            self.left = MAX_FRAMES;
        }
        self.left > 0
    }

    /// A refining frame of `bytes` was encoded at `kbps`.
    pub fn refined(&mut self, bytes: usize, kbps: u32) {
        self.left = self.left.saturating_sub(1);
        if (bytes as f64 * 8.0) < self.budget_bits(kbps) * SETTLED {
            self.left = 0;
        }
        if self.left == 0 {
            self.refined_kbps = Some(kbps);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FPS: u32 = 60;
    /// Frame budget at 1200 kbit/s and 60 fps: 20 kbit, 2500 bytes.
    const KBPS: u32 = 1200;

    #[test]
    fn a_change_cut_by_its_budget_is_refined_until_the_encoder_settles() {
        let mut r = Refine::new(FPS);
        assert!(!r.due(KBPS), "nothing encoded yet");
        r.changed(2_400, KBPS);
        for _ in 0..10 {
            assert!(r.due(KBPS));
            r.refined(1_500, KBPS);
        }
        assert!(r.due(KBPS));
        r.refined(13, KBPS);
        assert!(!r.due(KBPS), "settled");
    }

    #[test]
    fn refining_stops_after_a_bound() {
        let mut r = Refine::new(FPS);
        r.changed(2_500, KBPS);
        let mut frames = 0;
        while r.due(KBPS) {
            r.refined(2_000, KBPS);
            frames += 1;
        }
        assert_eq!(frames, MAX_FRAMES);
    }

    #[test]
    fn small_changes_leave_a_sharp_picture_alone() {
        let mut r = Refine::new(FPS);
        r.changed(2_500, KBPS);
        r.refined(13, KBPS);
        // A blinking caret: a few hundred bytes now and then.
        for _ in 0..10 {
            r.changed(300, KBPS);
            assert!(!r.due(KBPS));
        }
        // A caret blinking while a big change is being refined does not stop it.
        r.changed(2_500, KBPS);
        r.refined(1_500, KBPS);
        r.changed(300, KBPS);
        assert!(r.due(KBPS));
    }

    #[test]
    fn a_higher_bitrate_refines_the_still_picture_again() {
        let mut r = Refine::new(FPS);
        r.changed(2_500, KBPS);
        r.refined(13, KBPS);
        assert!(!r.due(1_700), "not worth it");
        assert!(r.due(1_800));
        r.refined(10, 1_800);
        assert!(!r.due(1_800));
        assert!(!r.due(2_000), "refined at 1800 now");
        assert!(r.due(2_700));
    }
}
