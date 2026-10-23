# E5 host hole punching: hand-over for E3, E4, F4 (and F2, I4, the review)

Branch `reach-e5-punch-responder` (from `integration-wave2`, 0fc65e2), commit 74a159b. Files: `crates/host/src/reach/punch.rs` and
`poll.rs`, nothing else. 48 new tests (31 and 17); `cargo fmt --all --check`, `clippy -p velora-host --all-targets -D warnings` and
`cargo test -p velora-host` are green on Windows (134 pass, 2 `#[ignore]`d that need a desktop; the new tests ran ten times in a
row, single-threaded, and two copies at once, with no flake). Linux not compiled here (the musl target is installed but `ring` needs a
Linux C compiler this PC lacks). Checked by hand with 16 planted bugs (the port the Initial goes to, the paired check, the nonce, the
arrival check, the address policy, the rate, the private-endpoint test, the network signature, the clearing rules, the burst, the
remembered `seq`, the relay test, the minimum gap, the shared secret, the dropped device): each made a test fail. No traffic left the
loopback: the DHT nodes of the tests are sockets of the tests, the NATs are the simulator below.

## What it does

- **`punch::run`** finds the `ip:port` the NAT shows for the QUIC socket and whether it shows the same one to everybody, and writes
  `ReachState::observed` and `nat`. E1's `record_addresses()` turns that into a `Public` entry of the DHT record when the NAT is a cone
  (or open) and no mapped address is advertised: that is how a client learns where to punch to.
- **`punch::respond`** is the host's half of the simultaneous open. On a request it sends one QUIC Initial toward the client's endpoint
  from the listening port (`Endpoint::connect_with`), which makes the host's NAT expect the client's packets; the client, which keeps
  dialing, gets through. The attempt lasts 12 s and ends at once when the client's own connection arrives.
- **`poll::run`** looks the requests up in the DHT for hosts that have no relay, and hands each fresh one to `respond`.

## API

```rust
// punch.rs (the two signatures E1 froze)
pub async fn run(ctx: ReachContext) -> Result<()>                              // task while standalone is on
pub async fn respond(ctx: &ReachContext, request: PunchRequest) -> Result<()>  // E4 and poll.rs call it; an Err downcasts to Refusal
pub enum Refusal { Off, BadFingerprint, BadEndpoint, NotPaired, Destination(&'static str), RateLimited, Busy, Cannot(String) }  // Display = plain words
ctx.ext::<punch::Punching>().stats() -> PunchStats { started, refused, repeated, arrived, expired };  .attempts() -> usize
// poll.rs
pub async fn run(ctx: ReachContext) -> Result<()>                              // task while standalone is on
pub fn set_source(ctx: &ReachContext, source: Option<Arc<dyn PunchSource>>)    // E3: the DHT node, or None when it goes
pub trait PunchSource { fn resolve(&self, key: [u8; 32], newer_than: Option<i64>, deadline: Duration)
                            -> BoxFuture<'_, Result<Option<Found>, LookupError>>; }
pub struct Found { value: Vec<u8>, seq: i64 };  pub enum LookupError { NoNetwork, Failed(String) };  pub struct Schedule { .. }
```

## How each ticket uses it

### E3 (DHT)

- Give the poller your node: `poll::set_source(ctx, Some(Arc::new(node.clone())))` once it is up, `set_source(ctx, None)` when `dht::run`
  ends. Until then, and for a host whose DHT switch is off, the poller does nothing at all: the DHT switch is the user's consent to
  DHT traffic, so no switch, no node, no polling. (Consequence: standalone on, DHT off and no relay leaves no way to hear a punch
  request; G2 may want a line for it.)
- The adapter for C2's `Node` is the one in the doc comment of `PunchSource` (about ten lines, in your `dht.rs`: the trait is E5's,
  the node is C2's, `dht.rs` is yours): `node.resolve_with(&key, punch_item::SALT, &ResolveOptions { newer_than, deadline })`, with
  `Error::NoNetwork` as `LookupError::NoNetwork`. `newer_than` is what makes an unchanged item cost nothing; lookups are made one
  at a time, never with a lower `newer_than` than one still running, as C2 asks.
- `ReachState::observed` changes only when a measurement gives another answer (the same answer writes nothing and wakes nobody), and a
  change of the host's addresses re-measures without clearing it first, so your record is not rebuilt for nothing at start-up.

### E4 (relay)

- For each `HostMsg::PunchRequest { from, endpoint, nonce }` that D2 puts on a unidirectional stream of the registration connection
  (read with `wire::read_msg` + `HostMsg::decode`), call `punch::respond(ctx, PunchRequest { from, endpoint, nonce })`. It returns as soon
  as the attempt is under way. `Ok` also means "a repeat of one already served, nothing to do". An `Err` is a `Refusal`: log
  `NotPaired`, `BadEndpoint`, `BadFingerprint` and `Destination` at `info` (a paired device sent something odd), `RateLimited`/`Busy`
  at `debug`.
- `respond` needs standalone reach on (`Refusal::Off`), which is always true for a registering host. The attempt runs on a task of its
  own and ends early if `ctx.stop` of the context you passed fires, so pass the context of a task that lives longer than 12 s.

### F4 (client punch dialer) and F2 (the record)

- What the host does, in order: it checks the request (below), sends a QUIC Initial (1200 bytes or more, ALPN `velora/1`, SNI
  `velora-host`) from its listening port to the endpoint in the request, and lets QUIC retransmit it for 12 s. A client-only quinn
  endpoint drops it, which is all that is wanted; what matters is that the host's NAT now expects packets from that endpoint.
- The client must keep dialing the host's observed endpoint while it waits, and must send from the socket whose endpoint it put in the
  request. **How long to wait**: on the relay path a round trip (the host punches when the stream arrives), so the plan's 10 s fits. On
  the DHT path the host answers after half a poll interval on average, 22 s (45 s at worst), plus about 3 s for its lookup; in the burst after
  its last connection ended, about 4 s on average for 3 minutes. A quinn handshake that has been retrying for 20 s retransmits seconds
  apart, so dial anew every second or two rather than rely on one connection's backoff; the NAT keeps the hole for as long as it keeps
  the mapping the host's packet made (typically 30 s or more), not only for the 12 s the host sends.
- The endpoint in the request must be a unicast address on the internet with a port, IPv4 or IPv6, as the DHT or STUN shows it (never
  loopback, private, link-local, shared, multicast or unspecified: `Refusal::Destination`). The nonce must be random and new for each
  request: the host serves a nonce once for 10 minutes.
- The host's endpoint reaches the client only in the DHT record (E1's `record_addresses()`), so `Candidate::Punch` comes from
  F2's `resolve_record`, as F1 says, and needs the host's DHT switch on. A request over a relay without the record has nowhere to dial.
- Test helper for F4: `punch::nat_sim` (below).

### I4 (field tests)

The numbers worth tuning, each in one place: `Timing` in `punch.rs` (round 3 s, refresh 10 min, retry 30 s to 5 min), `Settings`
(attempt 12 s, 4 at once, device 4 then one per 10 s, overall 8 then one per 2 s, nonces 10 minutes), `Schedule::default()` in `poll.rs`
(45 s, 3 s, burst 8 s for 3 minutes, lookup 6 s).

## The NAT simulator (`punch::nat_sim`, `crates/host/src/reach/punch.rs`, `#[cfg(test)]`)

For F4 to copy: the module needs only `std` and `tokio` (`net`, `rt`, `sync`) and has no host types. Nothing on one machine routes through a
NAT, so a device behind a `SimNat` sends not to a peer's public address but to a *gateway port* the NAT makes for that peer
(`gateway_to(peer_public)`); the gateway sends from the NAT's public socket (so the peer sees the NAT's endpoint) and remembers the peer; what
arrives on the public socket is let in or dropped by the filtering and comes to the device from the gateway of its sender. The device
thus sees each peer at the address it sends to, and whatever it does with that address (dial it, put it in a punch request) works.

```rust
let host_nat = SimNat::new(host_socket_addr, Mapping::EndpointIndependent, Filtering::PortRestricted)?;   // also Mapping::Dependent, Filtering::Open
let client_nat = SimNat::new(client_socket_addr, ..)?;
let (host_public, client_public) = (host_nat.public_endpoint(), client_nat.public_endpoint());   // what a DHT node would have seen
let client_dials = client_nat.gateway_to(host_public)?;                // dial this
let host_punches = host_nat.gateway_to(client_public)?;                // the host sends to this (the request's endpoint)
host_nat.public_endpoint_toward(some_dht_node)?                        // what a symmetric NAT shows a particular peer
host_nat.stats() -> NatStats { sent, delivered, filtered }
```

`World` in the tests of `punch.rs` is the whole setup for the host side (a real `ReachContext`, a server loop that does Retry and notes the
device as `server.rs` does, a client quinn endpoint, both NATs); F4's test can keep the host half as it is and put its own dialer where
`World::dial` is, or build a quinn server behind a `SimNat` and "punch" with one datagram from the host socket to
`host_nat.gateway_to(client_public)`, which is all `respond` amounts to for the NAT. Not simulated: address-only filtering (all loopback
addresses are one address; use `127.0.0.x` aliases for that), mapping timeouts, hairpinning, port preservation or prediction, IPv6.

## Decisions to review

1. **The observation is DHT only and IPv4 only.** STUN has no sans-IO form (it needs a std socket) and the QUIC socket belongs to the
   multiplexer, so there is no STUN fallback; the DHT is IPv4. The nodes are the public bootstrap names (B2 measured that two of the four
   send `ip` at all); C2 does not expose its saved routing table, so those are not used.
2. **`observed` is published only when it is an internet address** (B2's `is_global`: a private one is the inner side of a second NAT); `nat`
   is always published. The old values stay until a new measurement replaces them, and go if the host's addresses changed and the new
   network teaches nothing.
3. **`respond` does not look at the NAT type.** A symmetric host still sends the packet (it is cheap, and the measurement may be wrong);
   the client's handshake then simply fails, as the simulator's symmetric test shows.
4. **`Endpoint::connect_with`, as the ticket says, not raw datagrams** through the probe path, although the multiplexer could send those:
   QUIC's own timers retransmit it, and a client that is also a server completes a real handshake (the connection is then closed).
5. **Limits** (all in `Settings`): the request is served at most once per device and nonce for 10 minutes (512 nonces), each device gets 4
   requests and then one per 10 s, all devices together 8 then one per 2 s, at most 4 attempts at once, 12 s each. A paired device can
   therefore make the host send at most about 8 KB (7 packets) per request and a few KB a second; nothing from an unpaired device costs an allowance.
6. **The poller: 45 s per device, spread, 3 s apart; 8 s for 3 minutes for the device that connected last once nobody is connected.**
   A lookup is about 110 datagrams (70 sent, 40 received, S0 §8): one device costs 2.4 a second, about 210 thousand a day; three, 630
   thousand. Only while standalone and the DHT are on and no relay is registered. A slower rate when the host has seen nobody for hours
   would cost a late client more waiting; say if you want it.
7. **A shared secret is polled once and the first device by fingerprint stands for the group** (C1's shared mode makes the sender
   unknowable); the burst for a device in such a group looks the group up.
8. **The paired list is read from the file at each request** (so a removed device counts at once), in `spawn_blocking`. The checks that
   cost nothing for an unpaired device come first so that none can use up the overall allowance.
9. **Duplicates are `Ok`, other refusals `Err(Refusal)`** inside an `anyhow::Error`; the type is public so a caller can match.
10. **No setter outside the tests**: `Settings::allow_local` (a request may name the loopback or a private address) exists so that tests
    can run on the loopback; nothing outside the test modules can change it.

## Gotchas

- `ClientActivity::last_connect` is noted by `server.rs` after the device authenticated, a few round trips after its first packet, so an
  attempt outlives the client's first packets by a moment. Harmless; the test shows it ends long before its 12 s.
- The probe handler sees every datagram of the real socket during the 3 s of a round (a lookup of a few node addresses each); the
  DHT's late replies go to quinn, which drops them.
- The tests use `127.0.0.2` to `127.0.0.4` for fake DHT nodes (different "servers" for the NAT classification): fine on Windows and Linux, not on a
  macOS without loopback aliases.
- On Windows a send to a closed loopback port makes the next receive on that socket fail with `ConnectionReset`; the simulator and the fake
  nodes step over it.
- A request over a relay and one from the DHT meet in `respond`, so the nonce is shared: a request that arrives by both is served once.

## Not tested

The real DHT and a real NAT (everything is fake nodes and the simulator); C2's `Node` behind `PunchSource` (not merged; the adapter is
in the doc comment and uncompiled) and E3's `secrets::all` (a stub; the poller takes the device list as a parameter in its tests); a
symmetric NAT on the client's side; port prediction; hairpinning; an IPv6 hole (the socket-level test is there, a NAT is not); Linux and
Android compile; the 12 s window and the 45 s interval against a real home router's mapping timeouts.
