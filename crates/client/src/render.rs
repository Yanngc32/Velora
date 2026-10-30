//! Software presentation, when OpenGL is not available (see `gpu`): letterboxed
//! nearest-neighbour scaling into the window buffer.

/// Where the remote picture sits inside the window, for mapping pointer coordinates. Zoomed in,
/// it is larger than the window and starts left of or above it.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Viewport {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

/// Zoom steps of the session window, 1 being the picture fitted to it.
pub const ZOOMS: [f64; 6] = [1.0, 1.5, 2.0, 3.0, 4.0, 6.0];

impl Viewport {
    pub fn fit(src_w: u32, src_h: u32, dst_w: u32, dst_h: u32) -> Self {
        if src_w == 0 || src_h == 0 {
            return Self::default();
        }
        let scale = f64::min(dst_w as f64 / src_w as f64, dst_h as f64 / src_h as f64);
        let width = ((src_w as f64 * scale).round() as u32).clamp(1, dst_w.max(1));
        let height = ((src_h as f64 * scale).round() as u32).clamp(1, dst_h.max(1));
        Self { x: ((dst_w - width) / 2) as i32, y: ((dst_h - height) / 2) as i32, width, height }
    }

    /// This fitted picture enlarged `zoom` times in a `dst_w` × `dst_h` window. Along an axis
    /// where it overflows, it slides with the pointer at `focus`: at the window's left edge the
    /// picture's left edge shows, at its right edge the right one. So the pointer always lands
    /// where it is drawn and every part of the picture is in reach.
    pub fn zoomed(self, zoom: f64, focus: (f64, f64), dst_w: u32, dst_h: u32) -> Self {
        if zoom <= 1.0 || self.width == 0 || self.height == 0 {
            return self;
        }
        let place = |size: u32, dst: u32, at: f64| {
            let size = (size as f64 * zoom).round() as u32;
            if size <= dst {
                return (((dst - size) / 2) as i32, size);
            }
            let t = if dst > 1 { (at / (dst - 1) as f64).clamp(0.0, 1.0) } else { 0.0 };
            (-((size - dst) as f64 * t).round() as i32, size)
        };
        let (x, width) = place(self.width, dst_w, focus.0);
        let (y, height) = place(self.height, dst_h, focus.1);
        Self { x, y, width, height }
    }

    /// Window position -> normalized remote coordinates, clamped to the picture.
    pub fn normalize(&self, px: f64, py: f64) -> (u16, u16) {
        let n = |p: f64, origin: i32, size: u32| {
            if size <= 1 {
                return 0;
            }
            let t = ((p - origin as f64) / (size - 1) as f64).clamp(0.0, 1.0);
            (t * 65535.0).round() as u16
        };
        (n(px, self.x, self.width), n(py, self.y, self.height))
    }
}

/// Draws the picture at `vp` (from `Viewport::fit`, maybe `zoomed`), black around it.
pub fn draw(src: &[u32], src_w: u32, src_h: u32, dst: &mut [u32], dst_w: u32, dst_h: u32, vp: Viewport) {
    let (sw, dw) = (src_w as usize, dst_w as usize);
    // The rows and columns of the window the picture covers.
    let span =
        |origin: i32, size: u32, dst: u32| (origin.max(0) as u32, (origin + size as i32).clamp(0, dst as i32) as u32);
    let (left, right) = span(vp.x, vp.width, dst_w);
    let (top, bottom) = span(vp.y, vp.height, dst_h);

    if vp.width == src_w && vp.height == src_h && vp.x >= 0 && vp.y >= 0 {
        for (row, line) in dst.chunks_exact_mut(dw).enumerate() {
            let r = row as u32;
            if r < top || r >= bottom {
                line.fill(0);
                continue;
            }
            let src_row = &src[(r as i32 - vp.y) as usize * sw..][..sw];
            line[..left as usize].fill(0);
            line[left as usize..][..sw].copy_from_slice(src_row);
            line[left as usize + sw..].fill(0);
        }
        return;
    }

    let x_map: Vec<usize> = (left..right).map(|x| (x as i64 - vp.x as i64) as usize * sw / vp.width as usize).collect();
    for (row, line) in dst.chunks_exact_mut(dw).enumerate() {
        let r = row as u32;
        if r < top || r >= bottom {
            line.fill(0);
            continue;
        }
        let sy = (r as i64 - vp.y as i64) as usize * src_h as usize / vp.height as usize;
        let src_row = &src[sy * sw..][..sw];
        let (before, rest) = line.split_at_mut(left as usize);
        before.fill(0);
        let (mid, after) = rest.split_at_mut((right - left) as usize);
        for (d, &sx) in mid.iter_mut().zip(&x_map) {
            *d = src_row[sx];
        }
        after.fill(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn letterboxes_and_normalizes() {
        let vp = Viewport::fit(1920, 1080, 1000, 1000);
        assert_eq!((vp.width, vp.height), (1000, 563));
        assert_eq!(vp.y, (1000 - 563) / 2);
        assert_eq!(vp.normalize(0.0, 0.0), (0, 0));
        assert_eq!(vp.normalize(999.0, 999.0), (65535, 65535));
        assert_eq!(vp.normalize(499.5, (vp.y as f64) + 281.0).0, 32768);
    }

    #[test]
    fn draws_native_and_scaled() {
        let src: Vec<u32> = (0..4 * 2).collect();
        let mut dst = vec![9; 4 * 2];
        draw(&src, 4, 2, &mut dst, 4, 2, Viewport::fit(4, 2, 4, 2));
        assert_eq!(dst, src);

        let mut dst = vec![9; 8 * 8];
        let vp = Viewport::fit(4, 2, 8, 8);
        draw(&src, 4, 2, &mut dst, 8, 8, vp);
        assert_eq!(vp, Viewport { x: 0, y: 2, width: 8, height: 4 });
        assert!(dst[..16].iter().all(|&p| p == 0));
        assert_eq!(&dst[16..24], &[0, 0, 1, 1, 2, 2, 3, 3]);
        assert_eq!(&dst[32..40], &[4, 4, 5, 5, 6, 6, 7, 7]);
        assert!(dst[48..].iter().all(|&p| p == 0));
    }

    #[test]
    fn zoomed_in_the_picture_follows_the_pointer_and_stays_under_it() {
        let fit = Viewport::fit(1920, 1080, 1000, 1000);
        assert_eq!(fit.zoomed(1.0, (300.0, 300.0), 1000, 1000), fit);
        // Twice as wide as the window; only 1126 px high, so it overflows that way too.
        let left = fit.zoomed(2.0, (0.0, 0.0), 1000, 1000);
        assert_eq!((left.x, left.y, left.width, left.height), (0, 0, 2000, 1126));
        let right = fit.zoomed(2.0, (999.0, 999.0), 1000, 1000);
        assert_eq!((right.x, right.y), (-1000, -126));
        // Wherever the pointer is, it points at the same place of the picture as unzoomed.
        for p in [0.0, 250.0, 500.0, 999.0] {
            let vp = fit.zoomed(2.0, (p, 500.0), 1000, 1000);
            let full = Viewport { x: 0, y: 0, width: 1000, height: 1000 };
            let (a, b) = (vp.normalize(p, 0.0).0 as i32, full.normalize(p, 0.0).0 as i32);
            assert!((a - b).abs() <= 40, "{p}: {a} vs {b}");
        }
        // Not overflowing across: centred, as when fitted. Overflowing down, with the pointer at
        // the top: the top shows.
        let small = Viewport::fit(100, 100, 1000, 500).zoomed(1.5, (0.0, 0.0), 1000, 500);
        assert_eq!((small.x, small.width), (500 - 375, 750));
        assert_eq!((small.y, small.height), (0, 750));
    }

    #[test]
    fn draws_zoomed_in() {
        let src: Vec<u32> = (0..4 * 2).collect();
        let mut dst = vec![9; 4 * 2];
        // Twice the size, pointer at the top left: the top-left quarter of the picture.
        let fit = Viewport::fit(4, 2, 4, 2);
        draw(&src, 4, 2, &mut dst, 4, 2, fit.zoomed(2.0, (0.0, 0.0), 4, 2));
        assert_eq!(dst, [0, 0, 1, 1, 0, 0, 1, 1]);
        // At the bottom right: the bottom-right quarter.
        draw(&src, 4, 2, &mut dst, 4, 2, fit.zoomed(2.0, (3.0, 1.0), 4, 2));
        assert_eq!(dst, [6, 6, 7, 7, 6, 6, 7, 7]);
    }
}
