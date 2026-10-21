//! BGRX -> YUV 4:2:0 (BT.601 limited range, signalled in the stream's VUI) on the CPU.

use crate::capture::Frame;

/// Destination chroma layout.
pub enum Chroma<'a> {
    /// I420: separate U and V planes.
    Planar { u: &'a mut [u8], u_stride: usize, v: &'a mut [u8], v_stride: usize },
    /// NV12: one plane of interleaved U/V pairs.
    #[cfg_attr(not(feature = "ffmpeg"), allow(dead_code))]
    Interleaved { uv: &'a mut [u8], stride: usize },
}

/// 4:2:0 needs even dimensions; odd ones are cropped by one pixel.
pub fn even_dims(frame: &Frame) -> (usize, usize) {
    ((frame.width & !1) as usize, (frame.height & !1) as usize)
}

/// Converts the even-cropped frame into the given planes in a single pass over the source
/// (each 2x2 block yields four luma samples and one chroma pair).
pub fn bgrx_to_yuv420(frame: &Frame, y: &mut [u8], y_stride: usize, mut chroma: Chroma) {
    let (w, h) = even_dims(frame);
    let cw = w / 2;
    let (mut u_buf, mut v_buf) = (vec![0u8; cw], vec![0u8; cw]);

    for cy in 0..h / 2 {
        let row0 = &frame.data[2 * cy * frame.stride..][..w * 4];
        let row1 = &frame.data[(2 * cy + 1) * frame.stride..][..w * 4];
        let (y0, y1) = y[2 * cy * y_stride..][..y_stride + w].split_at_mut(y_stride);
        // Exact-length slices let the compiler drop bounds checks in the hot loop.
        let (y0, y1) = (&mut y0[..w], &mut y1[..w]);
        let (u_row, v_row) = (&mut u_buf[..cw], &mut v_buf[..cw]);

        for cx in 0..cw {
            let (mut sr, mut sg, mut sb) = (0i32, 0i32, 0i32);
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

        match &mut chroma {
            Chroma::Planar { u, u_stride, v, v_stride } => {
                u[cy * *u_stride..][..cw].copy_from_slice(u_row);
                v[cy * *v_stride..][..cw].copy_from_slice(v_row);
            }
            Chroma::Interleaved { uv, stride } => {
                for (pair, (&u, &v)) in
                    uv[cy * *stride..][..2 * cw].as_chunks_mut::<2>().0.iter_mut().zip(u_row.iter().zip(v_row.iter()))
                {
                    *pair = [u, v];
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn solid(w: u32, h: u32, bgr: [u8; 3]) -> Vec<u8> {
        (0..w * h).flat_map(|_| [bgr[0], bgr[1], bgr[2], 255]).collect()
    }

    fn convert_planar(frame: &Frame) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let (w, h) = even_dims(frame);
        let (mut y, mut u, mut v) = (vec![0; w * h], vec![0; w * h / 4], vec![0; w * h / 4]);
        bgrx_to_yuv420(frame, &mut y, w, Chroma::Planar { u: &mut u, u_stride: w / 2, v: &mut v, v_stride: w / 2 });
        (y, u, v)
    }

    #[test]
    fn converts_reference_colors() {
        for (bgr, yuv) in [
            ([0, 0, 0], (16, 128, 128)),
            ([255, 255, 255], (235, 128, 128)),
            ([0, 0, 255], (82, 90, 240)),  // red
            ([255, 0, 0], (41, 240, 110)), // blue
        ] {
            let data = solid(4, 2, bgr);
            let (y, u, v) = convert_planar(&Frame { width: 4, height: 2, stride: 16, data: &data });
            let (y, u, v) = (y[0] as i32, u[0] as i32, v[0] as i32);
            assert!(
                (y - yuv.0).abs() <= 1 && (u - yuv.1).abs() <= 1 && (v - yuv.2).abs() <= 1,
                "{bgr:?} -> {y} {u} {v}"
            );
        }
    }

    #[test]
    fn crops_odd_dimensions_and_honors_stride() {
        let data = vec![128u8; 32 * 3];
        let frame = Frame { width: 5, height: 3, stride: 32, data: &data };
        assert_eq!(even_dims(&frame), (4, 2));
        let (y, u, v) = convert_planar(&frame);
        assert_eq!((y.len(), u.len(), v.len()), (8, 2, 2));
    }

    #[test]
    fn nv12_matches_planar() {
        let data: Vec<u8> = (0..8 * 4 * 4).map(|i| (i * 37 % 256) as u8).collect();
        let frame = Frame { width: 8, height: 4, stride: 32, data: &data };
        let (y, u, v) = convert_planar(&frame);
        let (mut y2, mut uv) = (vec![0; 32], vec![0; 16]);
        bgrx_to_yuv420(&frame, &mut y2, 8, Chroma::Interleaved { uv: &mut uv, stride: 8 });
        assert_eq!(y, y2);
        let interleaved: Vec<u8> = u.iter().zip(&v).flat_map(|(&a, &b)| [a, b]).collect();
        assert_eq!(uv, interleaved);
    }
}
