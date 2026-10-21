//! Frames arrive on independent QUIC streams and may complete out of order; consumers need
//! them strictly in `frame_id` order.

use std::collections::BTreeMap;

use sm_protocol::wire::FrameHeader;

/// Frames buffered while waiting for a missing earlier frame before giving up on it.
const MAX_REORDER: usize = 64;

pub struct Packet {
    pub header: FrameHeader,
    pub data: Vec<u8>,
}

#[derive(Default)]
pub struct Reorder {
    pending: BTreeMap<u32, Packet>,
    next_id: u32,
}

impl Reorder {
    /// Adds a packet and returns every packet that is now next in order. `resynced` is set
    /// when frames had to be skipped, so the consumer must wait for a keyframe.
    pub fn push(&mut self, packet: Packet) -> (Vec<Packet>, bool) {
        let mut resynced = false;
        self.pending.insert(packet.header.frame_id, packet);
        if self.pending.len() > MAX_REORDER {
            // Should not happen on a reliable transport; resynchronize on the oldest frame.
            self.next_id = *self.pending.keys().next().unwrap();
            resynced = true;
        }
        let mut ready = Vec::new();
        while let Some(packet) = self.pending.remove(&self.next_id) {
            self.next_id = self.next_id.wrapping_add(1);
            ready.push(packet);
        }
        (ready, resynced)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(id: u32) -> Packet {
        Packet { header: FrameHeader { frame_id: id, keyframe: id == 0, width: 2, height: 2 }, data: vec![] }
    }

    fn ids(packets: &[Packet]) -> Vec<u32> {
        packets.iter().map(|p| p.header.frame_id).collect()
    }

    #[test]
    fn releases_frames_in_order() {
        let mut r = Reorder::default();
        assert_eq!(ids(&r.push(packet(1)).0), Vec::<u32>::new());
        assert_eq!(ids(&r.push(packet(0)).0), vec![0, 1]);
        assert_eq!(ids(&r.push(packet(3)).0), Vec::<u32>::new());
        assert_eq!(ids(&r.push(packet(2)).0), vec![2, 3]);
    }

    #[test]
    fn resynchronizes_when_a_frame_never_arrives() {
        let mut r = Reorder::default();
        for id in 1..=MAX_REORDER as u32 {
            assert!(r.push(packet(id)).0.is_empty());
        }
        let (ready, resynced) = r.push(packet(MAX_REORDER as u32 + 1));
        assert!(resynced);
        assert_eq!(ready.len(), MAX_REORDER + 1);
    }
}
