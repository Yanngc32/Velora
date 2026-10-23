# D2 relay forwarding core: hand-over for E4 and F3 (and E1, E5, E6, G2)

Branch `claude/reach-d2-relay-core-39f5b2` (from `integration-wave1`, 35081ec), commit 65e6246, file `crates/relay/src/forward.rs`,
nothing else touched. 36 new tests next to D1's 18 and its doctest; `cargo fmt --all --check`, `clippy -p velora-relay --all-targets -D warnings`
and `cargo test -p velora-relay` are green on Windows (ten runs in a row and three single-threaded, no flake). Linux not compiled
here (the musl target is installed but `ring` needs a Linux C compiler this PC lacks); nothing in the file is Windows-only. Every test runs on loopback: no traffic left this
PC, no magic packet was sent.

What it does: a table of hosts that registered over an authenticated `quinn::Connection`, pairs a client connection with one of
them, and copies the inner QUIC packets between the two connections' datagrams through D1 (a `Reassembler` per leg for what
arrives, a `Splitter` per leg for what leaves, sized by `max_datagram_size()` at every send). It also wakes, passes punch requests
on, rate-limits, and lists what it holds. No pairing, TLS, paired list or control-stream reading: those stay with E4.

## Public API (`velora_relay::forward`)

```rust
pub struct Relay;  // Clone (clones share the table), Send + Sync, Debug, Default; no global state
impl Relay {
    pub fn new(config: Config) -> Relay;                          // wakes through LanWaker
    pub fn with_waker(config: Config, waker: Arc<dyn Waker>) -> Relay;
    // The caller's connection says who is asking (its certificate), so a device cannot act as another.
    pub fn register(&self, conn: &quinn::Connection, mac: Option<Mac>) -> Result<(), Refused>;
    pub fn relay_to(&self, conn: &quinn::Connection, target: &str) -> Result<(), Refused>;   // target = base64url fingerprint
    pub async fn wake(&self, from: &quinn::Connection, target: &str) -> Result<usize, Refused>;
    pub async fn punch(&self, from: &quinn::Connection, to: &str, endpoint: &str, nonce: u64) -> Result<(), Refused>;
    // The four above for a decoded ClientMsg, answered as the HostMsg::RelayStatus to write back; None for any other message.
    pub async fn handle(&self, conn: &quinn::Connection, msg: &ClientMsg) -> Option<HostMsg>;
    pub fn registered(&self) -> Vec<Registered>;   // live hosts: addr, mac, connected_for, client, to_host / to_client Traffic
    pub fn known(&self) -> Vec<Known>;             // every host seen, live or not: fingerprint, mac, last addr (for wake; save it)
    pub fn remember(&self, known: Known);          // load saved entries on start; never overwrites an existing one
    pub fn remove(&self, device: &Fingerprint);    // a paired device was removed: drops its registration, pairing and memory
    pub fn shutdown(&self);                        // relay switched off: disconnects everyone
}
pub struct Config { burst: u32 = 6, refill: Duration = 5 s, max_hosts: usize = 256, max_known: usize = 256 }
pub enum Refused { .. }   // Display = the RelayStatus reason, plain words; match on it in tests, never on the text
pub trait Waker { fn wake(&self, mac: &Mac, host: Ipv4Addr) -> Result<usize, WakeError> }  // LanWaker is the real one
pub const CLOSE_REPLACED / CLOSE_HOST_GONE / CLOSE_TAKEN_OVER / CLOSE_REMOVED / CLOSE_SHUTDOWN: u32   // 0x20..=0x24
```

`register` and `relay_to` spawn tasks: call them inside a tokio runtime. `Refused` variants: `NoIdentity`, `BadFingerprint`,
`ToSelf`, `ConnectionInUse`, `NoDatagrams`, `RateLimited { retry_secs }`, `Full`, `UnknownHost` (never registered here),
`NotRegistered` (registered before, not connected now), `NoMac`, `NotOnNetwork`, `WakeFailed`, `BadEndpoint`, `HostNotAccepting`.

### E4 (relay serving)

- After your Hello, authorization and paired-list check, call `relay.handle(&conn, &msg)` for every control message and write the
  `Some(answer)` back on the stream it came from. That is the whole mapping; the four calls are public if you prefer them.
- Keep the table's connection open: D2 holds a clone of `conn`, so your handler ending (the control stream finishing) closes
  nothing, and you must not call `conn.close` when it ends. The peer closes it, or D2 does, with one of the `CLOSE_*` codes.
- Call `remove(&fingerprint)` when the user removes a device, `shutdown()` when "let my other PCs connect" goes off, and
  persist `known()` (every change of `registered()` is a chance) and `remember()` it on start, or a relay PC that reboots can no
  longer wake a host that was asleep when it did. Handle `Reach.relays_for_others`, the paired list and handshake rate limiting
  yourself: the limiter here only slows devices that are already authenticated.
- Open point for E1/E4: a host that registers sends the same Hello a session client does, and `server.rs` lets a newly connected
  device take over the desktop session. A registering host's connection must not become a session of the relay PC (and must not
  displace the one in progress); D2 does not see the Hello, so that rule has to live in the code that reads it.
- Registering side: dial with `tls::client_config(identity, relay_fingerprint)` (its transport config lets the relay open the
  unidirectional streams punch requests need), send `RelayRegister { mac }`, then treat the connection as the host's tunnel:
  its datagrams are D1 frames of inner packets from whoever is paired (one peer: one synthetic address per registration).
  Accept unidirectional streams on it and read one message from each with `wire::read_msg` + `HostMsg::decode`: a
  `PunchRequest { from, endpoint, nonce }` for E5. A close with `CLOSE_REPLACED` means another connection of this device took the
  entry: do not reconnect at once or two instances will replace each other forever.

### F3 (client dialer)

- Dial, Hello, send `RelayTo { fingerprint }`, wait for the `RelayStatus`; only after `ok` build the tunnel and start the inner
  handshake. The relay starts forwarding the moment it answers, so anything the host sent in between would arrive before the
  reply on the datagram path; ignore datagrams until the status is read.
- Read `max_datagram_size()` at every send. An inner packet may be up to `2 * (max - 3)` bytes (about 2300 at the start). The inner
  endpoint can probe MTU (`may_fragment() == false`) and does: in the tests the inner packets grow to 1452 bytes and a third of the
  packets toward the host are then split on the relay leg.
- Close codes tell why the relay path ended: `CLOSE_TAKEN_OVER` (another device took the host over: do not fight it),
  `CLOSE_HOST_GONE` (the host left the relay or registered again: try the next candidate), `CLOSE_REMOVED`, `CLOSE_SHUTDOWN`.
- Wake: `Wake { fingerprint }` works for a host that is asleep (see decision 3). Then poll `RelayTo`, no faster than one try
  per 5 s: the allowance is 6 new flows per device at once and one more every 5 s, shared by register, relay_to, wake and punch.
  `RateLimited` carries the seconds to wait in its text.
- One client per host (decision 2): several inner connections to one host from one device must share one inner endpoint over one
  outer connection; a second `RelayTo` to the same host from the same device takes the first over.

## Decisions to review

1. **The fingerprint is not a parameter.** The ticket had `register(conn, fingerprint, mac)`; every call here takes the connection
   and reads the fingerprint from its certificate (`tls::peer_fingerprint`). A caller cannot pass a fingerprint that is not the
   connection's, which would let one device take over another's entry. Targets are `&str` as they are on the wire; the parse and
   its answer (`BadFingerprint`) live here.
2. **One client per host, newest wins.** The datagrams carry no flow id (D1's header is pinned), so the host's registration
   connection can serve one client: the host's replies go to whoever is paired. A newer `relay_to` closes the older client with
   `CLOSE_TAKEN_OVER`, like the host's own "another device took over". The alternatives (refuse while busy; several clients with a
   flow id) are a refusal that outlasts a dead client by up to 15 s, or a D1 format change.
3. **Wake works from memory.** A sleeping PC has no connection, so "the entry goes away when the connection closes" would leave
   nothing to wake it with. The relay keeps `(mac, last address, last seen)` for every host that registered (bounded, longest
   gone out first) and `wake` uses that; `known()`/`remember()` let the caller persist it. E6's "handle `Wake` for registered
   hosts on the same LAN" is therefore already done here: what is left for E6 is `local_mac` and, if wanted, the persistence.
4. **`LanWaker` is `wake_lan_of` taken apart** (`wake_networks` + `network_of` + `wake_on`), the same three steps, so that "not on
   a network of this relay" (`NotOnNetwork`) and "sending failed" (`WakeFailed`) are different answers. IPv6 addresses have no
   IPv4 broadcast and answer `NotOnNetwork`; IPv4 written the IPv6 way (what E1's dual-stack socket reports) is read as IPv4.
5. **Punch requests travel on a unidirectional stream** the relay opens on the host's registration connection, one
   `HostMsg::PunchRequest` per stream (length prefix included, as `encode()` writes it), finished at once. Not a datagram (every
   datagram there belongs to the inner connection, and a lost one would lose the request silently); not the control stream (that
   one is E4's, and sharing its send half would couple the two). It needs the host to accept unidirectional streams; a host that
   does not takes the answer `HostNotAccepting` after 2 s. The relay checks the endpoint is a unicast `ip:port` and passes the
   certificate's fingerprint as `from`; whether the host may send to that endpoint is E5's policy.
6. **Rate limit per device, not per address.** Keyed by certificate fingerprint, with a token bucket (burst 6, one more every 5 s)
   shared by register, relay_to, wake and punch; devices behind one NAT do not share it and one cannot dodge its own by moving. It
   is a second line: only authenticated devices reach it, and a flood of unauthenticated handshakes is E4's/E1's to stop.
7. **A pairing ends with either connection, no grace period.** A host that registers again takes the old entry's client away
   (`CLOSE_HOST_GONE`), so a host reconnect costs the client a reconnect. Carrying the pairing over to the new connection (and
   waiting a few seconds for a host that dropped) would keep the inner session alive across a host blip; it was left out for
   simplicity and fits in `register`/`end_registration`.
8. **Counters** (`Traffic`: packets, datagrams, bytes, dropped) are per registration and cost an atomic add per packet. `datagrams >
   packets` is how a leg too small for whole packets shows. `dropped` is nobody paired, a closed leg, or a failed send.

## Gotchas

- When a client is taken over, the host's last packets for it can reach the new client (the host cannot tell them apart); they carry
  the old connection's IDs, so the new inner endpoint ignores them or answers with a stateless reset that dies at the host.
- Datagrams that reach a registered host while nobody is paired are dropped (not queued), so the next client never sees an
  earlier client's packets. Datagrams sent before `relay_to` returns wait in the outer connection's 64 KiB datagram buffer and
  are forwarded once the pairing exists (harmless; F3 sends nothing before the reply).
- `tls::transport_config` gives each side a 64 KiB datagram receive buffer: about 55 outer datagrams. A tunnel whose reader is
  slow loses packets there, silently.
- A connection that does not advertise datagrams (`max_datagram_size() == None`) is refused with `NoDatagrams` rather than
  accepted and starved.
- Locks are std mutexes ignoring poison, never held across an await; table lock first, then a registration's pairing lock.
- One test binds 127.0.0.2 and 127.0.0.3 to have two connections of one device come from different addresses: fine on Windows and
  Linux, not on a macOS without loopback aliases.

## The test tunnel (`#[cfg(test)]` in `forward.rs`), for E1's multiplexer and F3's `RelaySocket`

`TunnelSocket` is the inner endpoint's `AsyncUdpSocket` (`quinn::Endpoint::new_with_abstract_socket`, `TokioRuntime`):

- `local_addr` and the peer are made-up v6 addresses (`fd00:7e1a::1`, `::2`); the endpoint dials the peer's address and every
  received packet is reported with `RecvMeta { addr: peer, len, stride: len, ecn: None, dst_ip: None }`.
- `try_send` ignores `transmit.destination`: `conn.max_datagram_size()` (read now), `Splitter::split(transmit.contents, max)`,
  `conn.send_datagram` for each; never `WouldBlock`, so `create_io_poller` is a poller that is always ready; `max_transmit_segments`
  stays 1.
- A task owns the receive side: `conn.read_datagram()` into a `Reassembler` (`expire` once a second), complete packets into a
  bounded `mpsc`; `poll_recv` drains it (`Receiver::poll_recv` registers the waker) and a full queue drops, as a socket buffer would.
- `may_fragment() == false`, so quinn probes the path MTU through the tunnel.
- The tests also lose 1% of the outer datagrams in each direction on both ends (a seeded xorshift), which makes the relay leg lose
  about 1% per hop.

The ticket's test (`a_velora_connection_and_a_megabyte_cross_a_relay_with_one_percent_loss`): relay, host and client are three
quinn endpoints on loopback. Both dial out (`RelayRegister`, `RelayTo`); inner endpoints over tunnels then run the real handshake
(mutual TLS 1.3 with `tls::server_config`/`client_config`: the host sees the client's fingerprint, the client the pinned host's),
Velora's hello and welcome on a control stream, 1,000,000 bytes on a stream echoed back (identical), and 1000 datagrams of 1000 bytes
that nothing recovers: 978 or 979 arrive, none damaged, about 95 outer datagrams are lost, the relay drops none itself. The inner
connection ends with 1414-byte datagrams, so its path MTU discovery worked through the tunnel. It takes about 1.2 s.
`the_same_across_legs_of_different_sizes` repeats it with the client's leg held at 1200-byte packets and the host's wide open.
A raw test (`packets_cross_both_ways_framed_for_the_leg_they_leave_on`) pins the re-framing with exact datagram counts: packets of 1,
80, 1000, 1300 and 2000 bytes cost 6 datagrams toward the wide host and 7 toward the narrow client.

The tests were also checked against planted bugs (datagram size capped, old registration kept, takeover not closing, pairing not
cleared, limiter never refusing, host-gone not closing the client, stale address coming back, IPv4-mapped not read as IPv4): each
one made a test fail.

## Not tested

Linux/Android compile; a real router or network (every address is loopback or a documentation range); `LanWaker`'s success path
(it would broadcast on the LAN; B3 checked that by hand); IPv6 outer connections; a relay under sustained video load; a host
registering over a dual-stack socket (the address reaches `wake` through `wake_address`, which is unit-tested, not through a live one).
