# D1 relay framing: hand-over for D2 and F3

Branch `claude/reach-d1-relay-framing-6d4f97`, commit 487b363, file `crates/relay/src/frame.rs` (nothing else touched).
18 unit tests + 1 doctest; also checked by hand with 18 deliberate bugs (timeout edge, cap, join order, id, nibbles...),
every one made a test fail.
Pure module: `bytes` in and out, std `Instant` injected, no quinn or tokio types.

## Wire format (pinned by a test, so changing it is a protocol change)

Every outer datagram, whole packet or chunk, is `[id_hi, id_lo, shape, payload...]`.
`id` is a big-endian u16 that goes up by one per packet (whole ones too) and wraps.
`shape = (chunk_index << 4) | chunk_count`; the only valid values are `0x01` (whole), `0x02` and `0x12`
(first and second of two). A datagram with no payload after the header is not a frame.

## API

```rust
pub const HEADER_LEN: usize = 3;
pub const MAX_CHUNKS: usize = 2;
pub const REASSEMBLY_TIMEOUT: Duration = 2 s;
pub const MAX_PARTIAL: usize = 64;

pub enum SplitError { Empty, DatagramTooSmall { max }, PacketTooLarge { len, max } }  // thiserror, Display

pub struct Datagrams;  // Deref<Target = [Bytes]> (1 or 2, in chunk order); IntoIterator<Item = Bytes> by value

pub struct Splitter;   // new() / Default; one per outer connection and direction
impl Splitter { pub fn split(&mut self, packet: &[u8], max_datagram: usize) -> Result<Datagrams, SplitError>; }

pub struct Reassembler; // new() / Default; one per outer connection and direction
impl Reassembler {
    pub fn push(&mut self, datagram: Bytes, now: Instant) -> Option<Bytes>;  // #[must_use]
    pub fn expire(&mut self, now: Instant);
    pub fn pending(&self) -> usize;   // half packets waiting
    pub fn dropped(&self) -> u64;     // split packets given up on (timeout, table full, id taken)
    pub fn malformed(&self) -> u64;   // datagrams that were not frames
}
```

`split` takes `&[u8]` (a `&Bytes` coerces), so F3 can pass `Transmit::contents` without a copy into `Bytes` first.
A packet of up to `2 * (max_datagram - 3)` bytes is accepted (2294 at 1150).
Two chunks are halves (`len.div_ceil(2)` first), never one full and one runt.

## Using it

F3 (client `RelaySocket`):
- send: `splitter.split(transmit.contents, conn.max_datagram_size().ok_or(..)?)`, then `conn.send_datagram(d)` for each
  `d` in order. `try_send` takes `&self`, so keep the `Splitter` in a `Mutex`. Read `max_datagram_size()` at each send:
  it grows as the outer path's MTU is discovered. Log and drop on `SplitError` (an inner packet over the limit is a bug).
- receive: `conn.read_datagram().await` then `reassembler.push(d, Instant::now())`; a `Some` is the inner packet for
  quinn. Also call `reassembler.expire(Instant::now())` from a timer (about once a second) so memory and `dropped()`
  settle when traffic stops (`push` already sweeps when a split chunk arrives).

D2 (relay): the two legs have different `max_datagram_size()` values and they change over time, so do not forward a
datagram verbatim. Per inbound leg one `Reassembler`, per outbound leg one `Splitter`:
`reassembler_in.push(d, now)` then `splitter_out.split(&packet, out_conn.max_datagram_size()?)`. A whole packet costs
one copy (header strip then header write); a lost chunk drops the packet, like any loss.

## Behaviour worth knowing

- A chunk that repeats while held is ignored and does not refresh the 2 s clock. The same id and half with other
  bytes means the id came round while the old packet waited: the old one is dropped, the new held.
- A chunk repeated after its packet was delivered waits as an orphan until it times out (counted in `dropped()`); if
  both halves repeat the packet is delivered twice, which the inner QUIC drops by packet number.
- Mixing is possible only if a packet id repeats within 2 s, i.e. above about 32 000 packets per second on one
  connection (the inner AEAD would reject the glued packet anyway).
- Memory held: at most `MAX_PARTIAL` chunks, each at most the datagram the outer connection accepts.
- Logging: per-drop events at `trace`; the first not-a-frame datagram and every 1024th at `debug`.
