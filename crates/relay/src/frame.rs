//! Splitting an inner QUIC packet into relay datagrams and putting it back together.
//!
//! A relayed packet travels as a datagram of the outer QUIC connection to the relay. Inner packets
//! are up to about 1250 bytes (a client's first Initial is exactly 1200) while an outer datagram
//! holds about 1150 until the outer path's MTU discovery raises it, so a packet that does not fit
//! goes out as two chunks. Every datagram, whole packet or chunk, starts with three bytes:
//!
//! - the packet id, a `u16` in big endian that goes up by one per packet and wraps;
//! - one byte with the chunk index in the high nibble and the chunk count (1 or 2) in the low one.
//!
//! A count of 1 is a whole packet and needs no table on the receiving side. The id has 16 bits
//! because the first chunk of a packet waits up to [`REASSEMBLY_TIMEOUT`] for the second: with 8
//! bits the id would come round within a fraction of a second at video rates and glue chunks of
//! different packets together, with 16 it takes over 2 s even at 30 000 packets per second.
//!
//! Losing a chunk loses the packet, silently: the inner QUIC recovers it like any other loss.
//!
//! ```
//! use std::time::Instant;
//! use velora_relay::frame::{Reassembler, Splitter};
//!
//! let packet = vec![7u8; 1200];
//! let mut splitter = Splitter::new();
//! let mut reassembler = Reassembler::new();
//! // 1150 is what an outer connection allows at first, so this packet goes out as two chunks.
//! let datagrams = splitter.split(&packet, 1150)?;
//! assert_eq!(datagrams.len(), 2);
//! let mut received = None;
//! for datagram in datagrams {
//!     received = reassembler.push(datagram, Instant::now());
//! }
//! assert_eq!(received.as_deref(), Some(&packet[..]));
//! # Ok::<(), velora_relay::frame::SplitError>(())
//! ```

use std::{
    collections::VecDeque,
    fmt,
    ops::Deref,
    time::{Duration, Instant},
};

use bytes::{BufMut, Bytes, BytesMut};

/// Bytes in front of every datagram: the packet id, then the chunk index and count.
pub const HEADER_LEN: usize = 3;
/// Most chunks a packet is split into. Inner packets stay under about 1450 bytes and an outer
/// datagram never holds less than about 1150, so two always do.
pub const MAX_CHUNKS: usize = 2;
/// How long the first chunk of a packet waits for the second before the packet is given up on. A
/// healthy path reorders by milliseconds, so only a lost chunk gets here.
pub const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(2);
/// Packets that may wait for their second chunk at once. Past it the oldest is dropped, so a peer
/// that only sends first chunks cannot make the table grow.
pub const MAX_PARTIAL: usize = 64;

/// Why a packet could not be framed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SplitError {
    #[error("empty packet")]
    Empty,
    #[error("datagrams of {max} bytes leave no room for payload after the {HEADER_LEN}-byte header")]
    DatagramTooSmall { max: usize },
    #[error("a packet of {len} bytes needs more than {MAX_CHUNKS} datagrams of {max} bytes")]
    PacketTooLarge { len: usize, max: usize },
}

/// What one packet became: one datagram when it fits, two when it does not, in chunk order.
/// Derefs to the slice of datagrams; iterating by value hands them over one by one, which is what
/// `send_datagram` wants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagrams {
    parts: [Bytes; MAX_CHUNKS],
    len: usize,
}

impl Datagrams {
    fn whole(datagram: Bytes) -> Self {
        Self { parts: [datagram, Bytes::new()], len: 1 }
    }

    fn halves(first: Bytes, second: Bytes) -> Self {
        Self { parts: [first, second], len: 2 }
    }
}

impl Deref for Datagrams {
    type Target = [Bytes];

    fn deref(&self) -> &[Bytes] {
        &self.parts[..self.len]
    }
}

impl IntoIterator for Datagrams {
    type Item = Bytes;
    type IntoIter = std::iter::Take<std::array::IntoIter<Bytes, MAX_CHUNKS>>;

    fn into_iter(self) -> Self::IntoIter {
        self.parts.into_iter().take(self.len)
    }
}

/// Frames the packets of one direction of one outer connection. Ids only mean something to the
/// [`Reassembler`] at the other end of that connection, so keep one `Splitter` per connection and
/// direction (for a relay, one per leg).
#[derive(Debug, Default)]
pub struct Splitter {
    next_id: u16,
}

impl Splitter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Frames `packet` for an outer connection whose datagrams hold `max_datagram` bytes: pass
    /// `quinn::Connection::max_datagram_size()` as it is when sending, since it grows as the outer
    /// path's MTU is discovered.
    ///
    /// The packet goes out whole when [`HEADER_LEN`] plus its length fits, otherwise as two chunks
    /// of about half each (not one full and one runt). A call can therefore take up to
    /// `2 * (max_datagram - HEADER_LEN)` bytes. Send the datagrams in order; if a send fails after
    /// the first one the packet is lost, which the inner QUIC treats like any loss.
    ///
    /// Fails for an empty packet (a QUIC endpoint never sends one, and the other side has nothing
    /// to deliver for it), for a `max_datagram` with no room for payload, and for a packet that
    /// would need more than [`MAX_CHUNKS`] datagrams. A failed call does not use up an id.
    pub fn split(&mut self, packet: &[u8], max_datagram: usize) -> Result<Datagrams, SplitError> {
        if packet.is_empty() {
            return Err(SplitError::Empty);
        }
        let len = packet.len();
        let room = match max_datagram.checked_sub(HEADER_LEN) {
            Some(room) if room > 0 => room,
            _ => return Err(SplitError::DatagramTooSmall { max: max_datagram }),
        };
        // `len - room` rather than `2 * room`, which could overflow for a silly `max_datagram`.
        if len > room && len - room > room {
            return Err(SplitError::PacketTooLarge { len, max: max_datagram });
        }
        let id = self.next_id;
        self.next_id = id.wrapping_add(1);
        if len <= room {
            return Ok(Datagrams::whole(frame(id, 0, 1, packet)));
        }
        let (first, second) = packet.split_at(len.div_ceil(2));
        Ok(Datagrams::halves(frame(id, 0, 2, first), frame(id, 1, 2, second)))
    }
}

fn frame(id: u16, index: u8, count: u8, payload: &[u8]) -> Bytes {
    let mut datagram = BytesMut::with_capacity(HEADER_LEN + payload.len());
    datagram.put_u16(id);
    datagram.put_u8((index << 4) | count);
    datagram.put_slice(payload);
    datagram.freeze()
}

/// What the three header bytes say.
struct Header {
    id: u16,
    index: u8,
    count: u8,
}

impl Header {
    /// `None` for anything the [`Splitter`] never produces: too short, no payload, a count other
    /// than 1 or 2, an index not below the count.
    fn parse(datagram: &[u8]) -> Option<Self> {
        let &[high, low, shape] = datagram.first_chunk::<HEADER_LEN>()?;
        if datagram.len() == HEADER_LEN {
            return None;
        }
        let (index, count) = (shape >> 4, shape & 0x0f);
        if !(1..=MAX_CHUNKS as u8).contains(&count) || index >= count {
            return None;
        }
        Some(Self { id: u16::from_be_bytes([high, low]), index, count })
    }
}

/// A packet of which one chunk has arrived.
struct Partial {
    id: u16,
    index: u8,
    chunk: Bytes,
    since: Instant,
}

/// Puts packets back together on the receiving side of one outer connection; one per connection
/// and direction, fed with every datagram that arrives on it.
///
/// Whole packets pass straight through. The first chunk of a split packet is held until its partner
/// arrives, in either order, for at most [`REASSEMBLY_TIMEOUT`]; at most [`MAX_PARTIAL`] are held,
/// the oldest dropped first. A packet that never gets its second chunk is dropped silently and
/// counted ([`Reassembler::dropped`]); a datagram that is not a frame is dropped and counted too
/// ([`Reassembler::malformed`]). Whatever the peer sends, nothing here panics, and what is held is
/// at most [`MAX_PARTIAL`] chunks, each no bigger than a datagram the outer connection accepts.
#[derive(Default)]
pub struct Reassembler {
    /// Oldest first.
    partial: VecDeque<Partial>,
    dropped: u64,
    malformed: u64,
}

// By hand so that logging a struct that holds one does not dump the chunks it is holding.
impl fmt::Debug for Reassembler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Reassembler")
            .field("pending", &self.partial.len())
            .field("dropped", &self.dropped)
            .field("malformed", &self.malformed)
            .finish()
    }
}

impl Reassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes a datagram received at `now` and returns the packet it completes, if any.
    ///
    /// - A whole packet comes back at once, as a slice of `datagram` (no copy, no table work).
    /// - A chunk whose partner is held returns the two joined; otherwise it is held.
    /// - The same chunk again while it is held is ignored and does not refresh its clock. A chunk
    ///   with the same id and half but other bytes means the id came round again (65 536 packets
    ///   later) while the old packet was still waiting: the old one is dropped and the new held.
    /// - Anything that is not a frame is dropped and counted.
    ///
    /// Packets held longer than [`REASSEMBLY_TIMEOUT`] are dropped before a chunk is looked at, so
    /// a late partner never completes a stale packet, whether or not [`Reassembler::expire`] ran.
    #[must_use = "the completed packet is the return value"]
    pub fn push(&mut self, datagram: Bytes, now: Instant) -> Option<Bytes> {
        let Some(Header { id, index, count }) = Header::parse(&datagram) else {
            self.malformed += 1;
            // The first and then every 1024th: a misbehaving peer must not flood the log.
            if self.malformed % 1024 == 1 {
                tracing::debug!(
                    "relay datagram of {} bytes is not a frame ({} so far)",
                    datagram.len(),
                    self.malformed
                );
            }
            return None;
        };
        let chunk = datagram.slice(HEADER_LEN..);
        if count == 1 {
            return Some(chunk);
        }
        self.expire(now);
        let Some(at) = self.partial.iter().position(|p| p.id == id) else {
            self.hold(Partial { id, index, chunk, since: now });
            return None;
        };
        if self.partial[at].index != index {
            let held = self.partial.remove(at)?;
            let (first, second) = if index == 0 { (&chunk, &held.chunk) } else { (&held.chunk, &chunk) };
            let mut packet = BytesMut::with_capacity(first.len() + second.len());
            packet.put_slice(first);
            packet.put_slice(second);
            return Some(packet.freeze());
        }
        if self.partial[at].chunk != chunk {
            self.partial.remove(at);
            self.dropped += 1;
            tracing::trace!("packet {id} dropped: its id came round again");
            self.hold(Partial { id, index, chunk, since: now });
        }
        None
    }

    /// Drops the packets whose first chunk arrived more than [`REASSEMBLY_TIMEOUT`] before `now`.
    /// `push` already does this when a split chunk arrives; call it from a timer too (once a
    /// second is plenty) so that memory and the dropped counter settle when the traffic stops.
    pub fn expire(&mut self, now: Instant) {
        let before = self.partial.len();
        self.partial.retain(|p| now.saturating_duration_since(p.since) <= REASSEMBLY_TIMEOUT);
        let expired = before - self.partial.len();
        if expired > 0 {
            self.dropped += expired as u64;
            tracing::trace!("{expired} packet(s) dropped: the second chunk never came");
        }
    }

    /// Packets now waiting for their second chunk.
    pub fn pending(&self) -> usize {
        self.partial.len()
    }

    /// Split packets given up on since the start: the second chunk never came in time, the table
    /// was full, or the id was taken by a newer packet. Whole packets never count here.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Datagrams dropped since the start for not being a frame at all.
    pub fn malformed(&self) -> u64 {
        self.malformed
    }

    fn hold(&mut self, partial: Partial) {
        if self.partial.len() >= MAX_PARTIAL {
            if let Some(oldest) = self.partial.pop_front() {
                self.dropped += 1;
                tracing::trace!("packet {} dropped: {MAX_PARTIAL} packets are already waiting", oldest.id);
            }
        }
        self.partial.push_back(partial);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Milliseconds after a fixed start, so no test sleeps.
    fn clock() -> impl Fn(u64) -> Instant {
        let start = Instant::now();
        move |ms| start + Duration::from_millis(ms)
    }

    /// Content that differs per `seed` and per position, so packets glued together wrongly never
    /// compare equal to the original.
    fn packet(len: usize, seed: u32) -> Vec<u8> {
        let mut x = seed.wrapping_mul(2_654_435_761) | 1;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                (x >> 24) as u8
            })
            .collect()
    }

    struct Rng(u64);

    impl Rng {
        fn next_u64(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }

        fn below(&mut self, n: u64) -> u64 {
            self.next_u64() % n
        }
    }

    /// Pushes the datagrams in the order given, all at `now`, and returns what the last one completed.
    fn feed<'a>(r: &mut Reassembler, datagrams: impl Iterator<Item = &'a Bytes>, now: Instant) -> Option<Bytes> {
        let mut received = None;
        for datagram in datagrams {
            received = r.push(datagram.clone(), now);
        }
        received
    }

    fn permutations<T: Clone>(items: &[T]) -> Vec<Vec<T>> {
        if items.len() <= 1 {
            return vec![items.to_vec()];
        }
        let mut all = Vec::new();
        for i in 0..items.len() {
            let mut rest = items.to_vec();
            let head = rest.remove(i);
            for mut tail in permutations(&rest) {
                tail.insert(0, head.clone());
                all.push(tail);
            }
        }
        all
    }

    #[test]
    fn a_packet_that_fits_goes_out_whole() {
        let at = clock();
        let p = packet(1000, 1);
        let datagrams = Splitter::new().split(&p, 1150).unwrap();
        assert_eq!(datagrams.len(), 1);
        assert_eq!(datagrams[0].len(), HEADER_LEN + 1000);
        assert_eq!(&datagrams[0][..HEADER_LEN], [0, 0, 0x01]);
        let mut r = Reassembler::new();
        assert_eq!(r.push(datagrams[0].clone(), at(0)).unwrap(), p);
        assert_eq!(r.pending(), 0, "a whole packet needs no table");
        assert_eq!((r.dropped(), r.malformed()), (0, 0));
    }

    #[test]
    fn a_client_initial_does_not_fit_an_outer_datagram_and_goes_out_as_two_chunks() {
        let at = clock();
        let initial = packet(1200, 2);
        let datagrams = Splitter::new().split(&initial, 1150).unwrap();
        assert_eq!(datagrams.len(), 2);
        assert!(datagrams.iter().all(|d| d.len() <= 1150));
        assert_eq!(&datagrams[0][..HEADER_LEN], [0, 0, 0x02]);
        assert_eq!(&datagrams[1][..HEADER_LEN], [0, 0, 0x12]);
        let mut r = Reassembler::new();
        assert!(r.push(datagrams[0].clone(), at(0)).is_none());
        assert_eq!(r.pending(), 1);
        assert_eq!(r.push(datagrams[1].clone(), at(1)).unwrap(), initial);
        assert_eq!(r.pending(), 0);
        assert_eq!(r.dropped(), 0);
    }

    #[test]
    fn the_wire_format_is_pinned() {
        // Peers of different versions have to agree on these bytes, so a change here is a protocol change.
        let mut s = Splitter { next_id: 0x1234 };
        let whole = s.split(&[0xaa, 0xbb, 0xcc], 100).unwrap();
        assert_eq!(&whole[0][..], [0x12, 0x34, 0x01, 0xaa, 0xbb, 0xcc]);
        let split = s.split(&[1, 2, 3], 5).unwrap();
        assert_eq!(&split[0][..], [0x12, 0x35, 0x02, 1, 2]);
        assert_eq!(&split[1][..], [0x12, 0x35, 0x12, 3]);
    }

    #[test]
    fn splits_exactly_when_header_and_payload_no_longer_fit() {
        for max in [4, 5, 1150, 1235, 1452] {
            let room = max - HEADER_LEN;
            let mut s = Splitter::new();
            assert_eq!(s.split(&packet(room, 3), max).unwrap().len(), 1);
            assert_eq!(s.split(&packet(room + 1, 3), max).unwrap().len(), 2);
            assert_eq!(s.split(&packet(2 * room, 3), max).unwrap().len(), 2);
            let len = 2 * room + 1;
            assert_eq!(s.split(&packet(len, 3), max), Err(SplitError::PacketTooLarge { len, max }));
        }
    }

    #[test]
    fn refuses_what_it_cannot_frame_and_keeps_its_id() {
        let mut s = Splitter::new();
        assert_eq!(s.split(&[], 1150), Err(SplitError::Empty));
        for max in 0..=HEADER_LEN {
            assert_eq!(s.split(&[1], max), Err(SplitError::DatagramTooSmall { max }));
        }
        assert_eq!(s.split(&[0; 2400], 1150), Err(SplitError::PacketTooLarge { len: 2400, max: 1150 }));
        // None of the failures used an id.
        assert_eq!(&s.split(&[7], 1150).unwrap()[0][..HEADER_LEN], [0, 0, 0x01]);
        // A datagram size that cannot be real must not overflow anything.
        assert_eq!(&s.split(&[0; 5000], usize::MAX).unwrap()[0][..HEADER_LEN], [0, 1, 0x01]);
        // The errors say what is wrong, since callers log them.
        assert!(SplitError::Empty.to_string().contains("empty"));
        assert!(SplitError::DatagramTooSmall { max: 2 }.to_string().contains("2 bytes"));
        assert!(SplitError::PacketTooLarge { len: 2400, max: 1150 }.to_string().contains("2400"));
    }

    #[test]
    fn chunks_may_arrive_in_either_order() {
        let at = clock();
        let p = packet(1200, 4);
        let d = Splitter::new().split(&p, 1150).unwrap();
        let mut r = Reassembler::new();
        assert!(r.push(d[1].clone(), at(0)).is_none());
        assert_eq!(r.push(d[0].clone(), at(1)).unwrap(), p);
        assert_eq!(r.pending(), 0);
    }

    #[test]
    fn a_lost_chunk_drops_the_packet_after_the_timeout() {
        let at = clock();
        let d = Splitter::new().split(&packet(1200, 5), 1150).unwrap();
        let mut r = Reassembler::new();
        assert!(r.push(d[0].clone(), at(0)).is_none());
        r.expire(at(1999));
        r.expire(at(2000));
        assert_eq!((r.pending(), r.dropped()), (1, 0), "still inside the window");
        r.expire(at(2001));
        assert_eq!((r.pending(), r.dropped()), (0, 1));
        // The straggler delivers nothing and waits out the timeout itself.
        assert!(r.push(d[1].clone(), at(2500)).is_none());
        assert_eq!(r.pending(), 1);
        r.expire(at(5000));
        r.expire(at(9000));
        assert_eq!((r.pending(), r.dropped()), (0, 2));
    }

    #[test]
    fn a_late_chunk_does_not_complete_a_packet_that_timed_out() {
        // Nobody calls `expire` here: `push` has to notice by itself.
        let at = clock();
        let d = Splitter::new().split(&packet(1200, 5), 1150).unwrap();
        let mut r = Reassembler::new();
        assert!(r.push(d[0].clone(), at(0)).is_none());
        assert!(r.push(d[1].clone(), at(3000)).is_none());
        assert_eq!(r.dropped(), 1);
        assert_eq!(r.pending(), 1, "the straggler waits for a partner that will not come");
    }

    #[test]
    fn a_repeated_chunk_is_ignored_and_does_not_extend_the_wait() {
        let at = clock();
        let p = packet(1200, 6);
        let d = Splitter::new().split(&p, 1150).unwrap();

        let mut r = Reassembler::new();
        assert!(r.push(d[0].clone(), at(0)).is_none());
        assert!(r.push(d[0].clone(), at(1500)).is_none());
        assert_eq!((r.pending(), r.dropped()), (1, 0));
        // 2.5 s after the first copy but 1 s after the repeat: the first copy's clock rules.
        assert!(r.push(d[1].clone(), at(2500)).is_none());
        assert_eq!(r.dropped(), 1);

        // Repeats before completion never deliver the packet twice.
        let mut r = Reassembler::new();
        assert!(r.push(d[1].clone(), at(0)).is_none());
        assert!(r.push(d[1].clone(), at(1)).is_none());
        assert_eq!(r.push(d[0].clone(), at(2)).unwrap(), p);
        // After delivery a repeat is just a chunk without a partner; it times out like one.
        assert!(r.push(d[0].clone(), at(3)).is_none());
        assert_eq!(r.pending(), 1);
        r.expire(at(5000));
        assert_eq!((r.pending(), r.dropped()), (0, 1));
    }

    #[test]
    fn ids_wrap_around() {
        let at = clock();
        let mut s = Splitter { next_id: u16::MAX - 1 };
        let mut r = Reassembler::new();
        let mut ids = Vec::new();
        for i in 0..4u32 {
            let p = packet(if i % 2 == 0 { 1200 } else { 100 }, i);
            let datagrams = s.split(&p, 1150).unwrap();
            ids.push(u16::from_be_bytes([datagrams[0][0], datagrams[0][1]]));
            let mut received = None;
            for datagram in datagrams {
                received = r.push(datagram, at(i as u64));
            }
            assert_eq!(received.unwrap(), p);
        }
        assert_eq!(ids, [0xfffe, 0xffff, 0, 1]);
        assert_eq!((r.pending(), r.dropped()), (0, 0));
    }

    #[test]
    fn a_reused_id_replaces_the_packet_still_waiting_under_it() {
        let at = clock();
        let new = packet(1200, 8);
        let old_chunks = Splitter { next_id: 9 }.split(&packet(1200, 7), 1150).unwrap();
        let new_chunks = Splitter { next_id: 9 }.split(&new, 1150).unwrap();
        let mut r = Reassembler::new();
        assert!(r.push(old_chunks[0].clone(), at(0)).is_none());
        // The id came round while the old packet was waiting for a chunk that was lost.
        assert!(r.push(new_chunks[0].clone(), at(10)).is_none());
        assert_eq!((r.pending(), r.dropped()), (1, 1));
        // The new packet's second chunk joins its own first chunk, not the old one.
        assert_eq!(r.push(new_chunks[1].clone(), at(11)).unwrap(), new);
        assert_eq!(r.pending(), 0);
    }

    #[test]
    fn a_reused_id_after_the_old_packet_finished_or_timed_out_is_a_new_packet() {
        let at = clock();
        let mut r = Reassembler::new();
        // Delivered, then the id comes round.
        for (i, seed) in [(0, 10), (1, 11)] {
            let p = packet(1200, seed);
            let d = Splitter { next_id: 77 }.split(&p, 1150).unwrap();
            assert!(r.push(d[0].clone(), at(i)).is_none());
            assert_eq!(r.push(d[1].clone(), at(i)).unwrap(), p);
        }
        // Timed out, then the id comes round.
        let lost = Splitter { next_id: 77 }.split(&packet(1200, 12), 1150).unwrap();
        assert!(r.push(lost[0].clone(), at(100)).is_none());
        let p = packet(1200, 13);
        let d = Splitter { next_id: 77 }.split(&p, 1150).unwrap();
        assert!(r.push(d[1].clone(), at(100 + 5000)).is_none());
        assert_eq!(r.push(d[0].clone(), at(100 + 5001)).unwrap(), p);
        assert_eq!((r.pending(), r.dropped()), (0, 1));
    }

    #[test]
    fn datagrams_that_are_not_frames_are_dropped_and_counted() {
        let at = clock();
        let garbage: [&[u8]; 14] = [
            &[],
            &[0],
            &[0, 0],
            &[0, 0, 0x01],
            &[0, 0, 0x02],
            &[0, 0, 0x00, 9],
            &[0, 0, 0x10, 9],
            &[0, 0, 0x03, 9],
            &[0, 0, 0x13, 9],
            &[0, 0, 0x0f, 9],
            &[0, 0, 0xff, 9],
            &[0, 0, 0x11, 9],
            &[0, 0, 0x22, 9],
            &[0, 0, 0xf2, 9],
        ];
        let mut r = Reassembler::new();
        for (n, datagram) in garbage.iter().enumerate() {
            assert!(r.push(Bytes::copy_from_slice(datagram), at(0)).is_none(), "{datagram:?}");
            assert_eq!(r.malformed(), n as u64 + 1);
        }
        assert_eq!((r.pending(), r.dropped()), (0, 0));

        // Of the 256 possible third bytes, only a count of 1 or 2 with a lower index is a frame.
        for shape in 0..=255u8 {
            let mut r = Reassembler::new();
            let _ = r.push(Bytes::from(vec![0, 0, shape, 9]), at(0));
            let valid = matches!(shape, 0x01 | 0x02 | 0x12);
            assert_eq!(r.malformed(), u64::from(!valid), "shape {shape:#04x}");
        }

        // Garbage did not disturb a packet in progress.
        let p = packet(1200, 14);
        let d = Splitter::new().split(&p, 1150).unwrap();
        assert!(r.push(d[0].clone(), at(1)).is_none());
        assert!(r.push(Bytes::from_static(&[0, 0, 0x12]), at(2)).is_none());
        assert_eq!(r.push(d[1].clone(), at(3)).unwrap(), p);
    }

    #[test]
    fn random_datagrams_never_panic_and_the_table_stays_bounded() {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let start = Instant::now();
        let mut elapsed = 0u64;
        let mut r = Reassembler::new();
        let (mut dropped, mut malformed, mut peak) = (0, 0, 0);
        for _ in 0..200_000 {
            let len = match rng.below(10) {
                0 => rng.below(3000) as usize,
                _ => rng.below(12) as usize,
            };
            let mut bytes: Vec<u8> = (0..len).map(|_| rng.next_u64() as u8).collect();
            if bytes.len() >= HEADER_LEN {
                // Valid headers over-represented and ids few enough that chunks meet, clash and fill the table.
                bytes[..2].copy_from_slice(&(rng.below(300) as u16).to_be_bytes());
                bytes[2] = [0x01, 0x02, 0x12, 0x02, 0x12, rng.next_u64() as u8][rng.below(6) as usize];
            }
            // Mostly milliseconds apart, now and then long enough for everything held to expire.
            elapsed += if rng.below(1000) == 0 { 3000 } else { rng.below(20) };
            let now = start + Duration::from_millis(elapsed);
            if let Some(packet) = r.push(Bytes::from(bytes), now) {
                assert!(!packet.is_empty());
            }
            if rng.below(50) == 0 {
                r.expire(now);
            }
            assert!(r.pending() <= MAX_PARTIAL);
            assert!(r.dropped() >= dropped && r.malformed() >= malformed);
            (dropped, malformed, peak) = (r.dropped(), r.malformed(), peak.max(r.pending()));
        }
        assert!(malformed > 0 && dropped > 0, "the loop should have hit both paths");
        assert_eq!(peak, MAX_PARTIAL, "the loop should have filled the table");
    }

    #[test]
    fn a_flood_of_first_chunks_cannot_grow_the_table() {
        let at = clock();
        let mut s = Splitter::new();
        let mut r = Reassembler::new();
        let flood = 10 * MAX_PARTIAL;
        let mut seconds = Vec::new();
        for i in 0..flood {
            let d = s.split(&packet(1200, i as u32), 1150).unwrap();
            assert!(r.push(d[0].clone(), at(0)).is_none());
            seconds.push(d[1].clone());
            assert!(r.pending() <= MAX_PARTIAL);
        }
        assert_eq!(r.pending(), MAX_PARTIAL);
        assert_eq!(r.dropped(), (flood - MAX_PARTIAL) as u64);
        let shown = format!("{r:?}");
        assert!(shown.len() < 100 && shown.contains("pending: 64"), "{shown}");

        // Whole packets go through a full table without costing anyone their place.
        let whole = packet(500, 99);
        let d = s.split(&whole, 1150).unwrap();
        assert_eq!(r.push(d[0].clone(), at(1)).unwrap(), whole);
        assert_eq!((r.pending(), r.dropped()), (MAX_PARTIAL, (flood - MAX_PARTIAL) as u64));

        // The newest are still waiting and complete; the oldest were evicted.
        for (i, second) in seconds.iter().enumerate().skip(flood - MAX_PARTIAL) {
            assert_eq!(r.push(second.clone(), at(2)).unwrap(), packet(1200, i as u32));
        }
        assert_eq!(r.pending(), 0);
        assert!(r.push(seconds[0].clone(), at(3)).is_none());
    }

    #[test]
    fn every_size_round_trips_in_both_orders() {
        let at = clock();
        for max in [4, 5, 64, 1150, 1200, 1235, 1252, 1452, 9000] {
            let room = max - HEADER_LEN;
            let mut s = Splitter::new();
            let mut r = Reassembler::new();
            for len in 1..=2400 {
                let p = packet(len, len as u32);
                let datagrams = match s.split(&p, max) {
                    Ok(datagrams) => datagrams,
                    Err(e) => {
                        assert_eq!(e, SplitError::PacketTooLarge { len, max });
                        assert!(len > 2 * room, "len {len} max {max}");
                        continue;
                    }
                };
                assert!(len <= 2 * room, "len {len} max {max}");
                assert_eq!(datagrams.len(), if len <= room { 1 } else { 2 }, "len {len} max {max}");
                assert!(datagrams.iter().all(|d| d.len() <= max && d.len() > HEADER_LEN));
                let payload: usize = datagrams.iter().map(|d| d.len() - HEADER_LEN).sum();
                assert_eq!(payload, len);

                assert_eq!(feed(&mut r, datagrams.iter(), at(0)).unwrap(), p, "len {len} max {max}, in order");
                assert_eq!(feed(&mut r, datagrams.iter().rev(), at(0)).unwrap(), p, "len {len} max {max}, reversed");
                assert_eq!(r.pending(), 0);
            }
            assert_eq!((r.dropped(), r.malformed()), (0, 0));
        }
    }

    #[test]
    fn two_packets_in_flight_come_out_whole_in_every_order() {
        let at = clock();
        let orders: Vec<_> = (0..=4).map(|n| permutations(&(0..n).collect::<Vec<usize>>())).collect();
        for max in [1150, 1235, 1452] {
            let top = 2400.min(2 * (max - HEADER_LEN));
            for len in 1..=top {
                let (a, b) = (packet(len, 1), packet(top + 1 - len, 2));
                let mut s = Splitter::new();
                let mut datagrams: Vec<Bytes> = s.split(&a, max).unwrap().into_iter().collect();
                datagrams.extend(s.split(&b, max).unwrap());
                let mut want = vec![Bytes::from(a), Bytes::from(b)];
                want.sort();
                for order in &orders[datagrams.len()] {
                    let mut r = Reassembler::new();
                    let mut got: Vec<Bytes> = Vec::new();
                    for (step, &i) in order.iter().enumerate() {
                        got.extend(r.push(datagrams[i].clone(), at(step as u64)));
                    }
                    got.sort();
                    assert_eq!(got, want, "lengths {len} and {} at {max}, order {order:?}", top + 1 - len);
                    assert_eq!(r.pending(), 0);
                }
            }
        }
    }

    #[test]
    fn survives_loss_duplication_and_reordering() {
        const PACKETS: usize = 20_000;
        /// How far a datagram may be moved: blocks of this many are shuffled among themselves.
        const SHUFFLE: usize = 7;
        struct Sent {
            packet: Vec<u8>,
            /// Every datagram of it arrived.
            intact: bool,
            /// Some datagram of it arrived twice.
            duplicated: bool,
        }

        let mut rng = Rng(0x0123_4567_89ab_cdef);
        // The ids wrap during the run.
        let mut s = Splitter { next_id: u16::MAX - 500 };
        let mut sent = Vec::new();
        let mut timeline: Vec<Bytes> = Vec::new();
        let mut half_lost = 0;
        for seq in 0..PACKETS {
            // The first four bytes say which packet it is, to find it again when it comes out.
            let mut packet = packet(4 + rng.below(2291) as usize, seq as u32);
            packet[..4].copy_from_slice(&(seq as u32).to_be_bytes());
            let datagrams = s.split(&packet, 1150).unwrap();
            let mut entry = Sent { packet, intact: true, duplicated: false };
            let mut arrived = 0;
            for d in datagrams.iter() {
                if rng.below(100) < 8 {
                    entry.intact = false;
                    continue;
                }
                arrived += 1;
                timeline.push(d.clone());
                if rng.below(100) < 5 {
                    entry.duplicated = true;
                    timeline.push(d.clone());
                }
            }
            half_lost += u64::from(!entry.intact && arrived > 0);
            sent.push(entry);
        }
        for block in timeline.chunks_mut(SHUFFLE) {
            for i in (1..block.len()).rev() {
                block.swap(i, rng.below(i as u64 + 1) as usize);
            }
        }

        // One datagram per millisecond: the longest a chunk waits for its partner is a few of them.
        let start = Instant::now();
        let mut r = Reassembler::new();
        let mut delivered = vec![0u32; PACKETS];
        for (step, datagram) in timeline.into_iter().enumerate() {
            let now = start + Duration::from_millis(step as u64);
            if let Some(received) = r.push(datagram, now) {
                let seq = u32::from_be_bytes(received[..4].try_into().unwrap()) as usize;
                assert_eq!(received, sent[seq].packet, "packet {seq} came out damaged");
                delivered[seq] += 1;
            }
            assert!(r.pending() <= MAX_PARTIAL);
        }
        r.expire(start + Duration::from_secs(86_400));
        assert_eq!(r.pending(), 0);

        for (seq, entry) in sent.iter().enumerate() {
            let times = delivered[seq];
            if !entry.intact {
                assert_eq!(times, 0, "packet {seq} lost a chunk and still came out");
            } else if entry.duplicated {
                // A repeat of both halves after delivery is a second delivery; QUIC drops the second packet.
                assert!((1..=2).contains(&times), "packet {seq} delivered {times} times");
            } else {
                assert_eq!(times, 1, "packet {seq} delivered {times} times");
            }
        }
        // Every packet left with one chunk was given up on and counted (repeats leave some more behind).
        assert!(r.dropped() >= half_lost, "{} dropped, {half_lost} packets lost a chunk", r.dropped());
    }
}
