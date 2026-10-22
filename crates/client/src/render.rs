//! Software presentation, when OpenGL is not available (see `gpu`): letterboxed
//! nearest-neighbour scaling into the window buffer.

/// Where the remote picture sits inside the window, for mapping pointer coordinates.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Viewport {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

impl Viewport {
    pub fn fit(src_w: u32, src_h: u32, dst_w: u32, dst_h: u32) -> Self {
        if src_w == 0 || src_h == 0 {
            return Self::default();
        }
        let scale = f64::min(dst_w as f64 / src_w as f64, dst_h as f64 / src_h as f64);
        let width = ((src_w as f64 * scale).round() as u32).clamp(1, dst_w.max(1));
        let height = ((src_h as f64 * scale).round() as u32).clamp(1, dst_h.max(1));
        Self { x: (dst_w - width) / 2, y: (dst_h - height) / 2, width, height }
    }

    /// Window position -> normalized remote coordinates, clamped to the picture.
    pub fn normalize(&self, px: f64, py: f64) -> (u16, u16) {
        let n = |p: f64, origin: u32, size: u32| {
            if size <= 1 {
                return 0;
            }
            let t = ((p - origin as f64) / (size - 1) as f64).clamp(0.0, 1.0);
            (t * 65535.0).round() as u16
        };
        (n(px, self.x, self.width), n(py, self.y, self.height))
    }
}

pub fn draw(src: &[u32], src_w: u32, src_h: u32, dst: &mut [u32], dst_w: u32, dst_h: u32) -> Viewport {
    let vp = Viewport::fit(src_w, src_h, dst_w, dst_h);
    let (sw, dw) = (src_w as usize, dst_w as usize);

    if vp.width == src_w && vp.height == src_h {
        for (row, line) in dst.chunks_exact_mut(dw).enumerate() {
            let r = row as u32;
            if r < vp.y || r >= vp.y + vp.height {
                line.fill(0);
                continue;
            }
            let src_row = &src[(r - vp.y) as usize * sw..][..sw];
            line[..vp.x as usize].fill(0);
            line[vp.x as usize..][..sw].copy_from_slice(src_row);
            line[vp.x as usize + sw..].fill(0);
        }
        return vp;
    }

    let x_map: Vec<usize> = (0..vp.width as usize).map(|x| x * sw / vp.width as usize).collect();
    for (row, line) in dst.chunks_exact_mut(dw).enumerate() {
        let r = row as u32;
        if r < vp.y || r >= vp.y + vp.height {
            line.fill(0);
            continue;
        }
        let sy = (r - vp.y) as usize * src_h as usize / vp.height as usize;
        let src_row = &src[sy * sw..][..sw];
        let (left, rest) = line.split_at_mut(vp.x as usize);
        left.fill(0);
        let (mid, right) = rest.split_at_mut(vp.width as usize);
        for (d, &sx) in mid.iter_mut().zip(&x_map) {
            *d = src_row[sx];
        }
        right.fill(0);
    }
    vp
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
        draw(&src, 4, 2, &mut dst, 4, 2);
        assert_eq!(dst, src);

        let mut dst = vec![9; 8 * 8];
        let vp = draw(&src, 4, 2, &mut dst, 8, 8);
        assert_eq!(vp, Viewport { x: 0, y: 2, width: 8, height: 4 });
        assert!(dst[..16].iter().all(|&p| p == 0));
        assert_eq!(&dst[16..24], &[0, 0, 1, 1, 2, 2, 3, 3]);
        assert_eq!(&dst[32..40], &[4, 4, 5, 5, 6, 6, 7, 7]);
        assert!(dst[48..].iter().all(|&p| p == 0));
    }
}
