//! Annex-B bitstream helpers for encoders that do not repeat SPS/PPS on every keyframe.

/// H.264 NAL unit types we care about.
const NAL_IDR: u8 = 5;
const NAL_SPS: u8 = 7;
const NAL_PPS: u8 = 8;

/// Splits an Annex-B stream into NAL units (each including its start code).
fn nal_units(data: &[u8]) -> Vec<&[u8]> {
    let mut starts = Vec::new();
    let mut i = 0;
    while i + 3 <= data.len() {
        if data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 1 {
            // Include the leading zero of a 4-byte start code.
            starts.push(if i > 0 && data[i - 1] == 0 { i - 1 } else { i });
            i += 3;
        } else {
            i += 1;
        }
    }
    starts.iter().enumerate().map(|(n, &s)| &data[s..starts.get(n + 1).copied().unwrap_or(data.len())]).collect()
}

fn nal_type(unit: &[u8]) -> Option<u8> {
    let header = unit.iter().position(|&b| b == 1).and_then(|p| unit.get(p + 1))?;
    Some(header & 0x1F)
}

#[cfg(all(test, feature = "ffmpeg"))]
pub fn nal_types(data: &[u8]) -> Vec<u8> {
    nal_units(data).iter().filter_map(|u| nal_type(u)).collect()
}

/// Makes every keyframe self-contained: hardware encoders often emit SPS/PPS only once, but
/// the client must be able to (re)start decoding on any keyframe.
#[derive(Default)]
pub struct ParameterSets(Vec<u8>);

impl ParameterSets {
    /// Returns the frame (with parameter sets prepended when needed) and whether it is an IDR.
    pub fn process(&mut self, data: Vec<u8>) -> (Vec<u8>, bool) {
        let units = nal_units(&data);
        let types: Vec<u8> = units.iter().filter_map(|u| nal_type(u)).collect();
        let idr = types.contains(&NAL_IDR);
        if types.contains(&NAL_SPS) {
            self.0 = units
                .iter()
                .filter(|u| matches!(nal_type(u), Some(NAL_SPS | NAL_PPS)))
                .flat_map(|u| u.iter().copied())
                .collect();
            return (data, idr);
        }
        if idr && !self.0.is_empty() {
            let mut out = self.0.clone();
            out.extend_from_slice(&data);
            return (out, true);
        }
        (data, idr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPS: &[u8] = &[0, 0, 0, 1, 0x67, 1, 2];
    const PPS: &[u8] = &[0, 0, 0, 1, 0x68, 3];
    const IDR: &[u8] = &[0, 0, 1, 0x65, 9, 9];
    const P: &[u8] = &[0, 0, 0, 1, 0x41, 7];

    #[test]
    fn splits_nal_units() {
        let stream = [SPS, PPS, IDR].concat();
        let units = nal_units(&stream);
        assert_eq!(units, vec![SPS, PPS, IDR]);
        assert_eq!(units.iter().map(|u| nal_type(u).unwrap()).collect::<Vec<_>>(), vec![7, 8, 5]);
    }

    #[test]
    fn prepends_parameter_sets_to_bare_keyframes() {
        let mut ps = ParameterSets::default();
        let first = [SPS, PPS, IDR].concat();
        assert_eq!(ps.process(first.clone()), (first.clone(), true));
        assert_eq!(ps.process(P.to_vec()), (P.to_vec(), false));
        assert_eq!(ps.process(IDR.to_vec()), (first, true));
    }
}
