# B2 (public addresses and endpoint observation): hand-over for E2, E5, F4, E6/B3 (and the review)

Branch `claude/reach-b2-addresses-33da42` (from 2c25df3), commits 8332949 (addresses), d98cddb (observe), de5b20e (fast
fail). Files: `crates/nat/src/addresses.rs` and `crates/nat/src/observe.rs`, nothing else touched. fmt, clippy
`-D warnings` and `cargo test -p velora-nat` green on Windows (53 pass, 2 `#[ignore]` manual). Linux not compiled here
(only the Windows target is installed); the Windows-only code is behind `cfg(windows)`.

## Warning for every lane that builds `velora-nat` in the shared target dir

The worktrees of B1, B2 (and later B3, E*, F*) compile the same crate path relative to the workspace, so cargo gives
them the same artifact hash (`velora_nat-659b4705d1b948dd.exe`) and its mtime check treats the other lane's build as
fresh. My `cargo test -p velora-nat` once printed 52 tests, B1's `mapping::` ones among them, without recompiling.
Run `touch crates/nat/src/*.rs` right before each cargo command and check that the test names are yours. (Told B1.)

## Public API

```rust
// velora_nat::addresses  (std types only; sync)
pub enum AddressClass { Public, Private, Shared, LinkLocal, Loopback, UniqueLocal, GlobalV6, Other }
impl AddressClass { pub fn is_global(self) -> bool }          // Public | GlobalV6
pub fn classify(ip: IpAddr) -> AddressClass                   // ::ffff:a.b.c.d is classified as a.b.c.d
pub struct GlobalV6 { pub addr: Ipv6Addr, pub interface: u32, pub valid_for: Option<Duration> }
pub fn global_ipv6() -> Vec<GlobalV6>                         // best first; first entry of each `interface` = design's pick
pub struct Ipv4Network { pub addr: Ipv4Addr, pub prefix_len: u8 }   // contains(ip), broadcast()
pub struct LocalMac { pub mac: [u8; 6], pub name: String, pub networks: Vec<Ipv4Network>, pub virtual_adapter: bool }
pub fn local_macs() -> Vec<LocalMac>                          // blocking-ish (netdev ARPs the gateways on Windows)

// velora_nat::observe  (blocking ones: async callers use spawn_blocking)
pub const DEFAULT_DHT_NODES: [&str; 4]; pub const DEFAULT_STUN_SERVERS: [&str; 2]; pub const DEFAULT_WAIT: Duration (3 s)
pub fn resolve<S: AsRef<str>>(names: &[S]) -> Vec<SocketAddr>          // blocking DNS, bad names skipped
pub fn default_dht_nodes() -> Vec<SocketAddr>                          // IPv4 only
pub fn default_stun_servers() -> Vec<SocketAddr>
pub struct Observation { pub from: SocketAddr, pub endpoint: SocketAddr }   // who answered, what it saw
pub enum NatType { Open, EndpointIndependent, Dependent, Unknown }          // Display / as_str(): "open" "endpoint-independent" ...
pub struct Observed { pub endpoint: SocketAddr, pub nat: NatType, pub observations: Vec<Observation> }
impl Observed { pub fn new(local: SocketAddr, observations: Vec<Observation>) -> Option<Observed> }
pub enum ObserveError { Io(io::Error), NoAnswer { asked: usize } }
pub fn observe(socket: &UdpSocket, dht_nodes: &[SocketAddr], stun_servers: &[SocketAddr], wait: Duration) -> Result<Observed, ObserveError>
pub fn observe_dht(socket: &UdpSocket, nodes: &[SocketAddr], wait: Duration) -> Result<Vec<Observation>, ObserveError>
pub fn observe_stun(socket: &UdpSocket, servers: &[SocketAddr], wait: Duration) -> Result<Vec<Observation>, ObserveError>
pub fn classify_nat(local: SocketAddr, observations: &[Observation]) -> NatType   // pure given the observations
pub struct DhtProbe  // no I/O: new(&nodes), pending() -> (node, datagram), handle(from, datagram) -> bool, observations()
pub fn reply_to_ping(ping: &[u8], requester: SocketAddr) -> Option<Vec<u8>>        // what a BEP 42 node answers, for fakes
```

### How each ticket uses it

- **F4 (client punch):** bind the candidate socket (IPv4: the DHT is IPv4-only), then in `spawn_blocking`
  `observe(&socket, &nodes, &velora_nat::observe::default_stun_servers(), DEFAULT_WAIT)` (nodes = saved routing-table nodes,
  else `default_dht_nodes()`; resolve once and cache). `Observed.endpoint` goes in the punch request, `nat` says whether to try.
  The socket comes back blocking with its read timeout as it was; `quinn::Endpoint::new` sets non-blocking itself,
  `tokio::net::UdpSocket::from_std` needs `set_nonblocking(true)` first. Call before the socket carries traffic: datagrams
  that arrive during the call are dropped.
- **E5 (host punch responder):** the QUIC socket is E1's multiplexer, so use `DhtProbe`: send `pending()` through the raw-probe path
  (to the IPv4-mapped form on the dual-stack socket), offer every datagram received from a node to `handle(from, data)` and keep
  it away from quinn when it returns true (`from` may be mapped; it is matched by source address and 4-byte transaction id, so
  a QUIC packet from elsewhere returns false), resend `pending()` every ~750 ms, stop after 3 observations or ~3 s, then
  `Observed::new(socket.local_addr(), probe.observations().to_vec())`. STUN has no sans-IO form (it needs a std socket).
- **E2 (host mapping):** `classify(mapping.external_ip)`: `Private`/`Shared` = CGNAT or double NAT, not advertised;
  `is_global()` says it is worth advertising; `global_ipv6()` for the `V6` entries (first of each `interface`).
- **E6 / B3 (wake):** `local_macs().first()` is the MAC to wake this PC with; `networks[].contains(peer_ip)` for "same LAN",
  `networks[].broadcast()` for the directed broadcast; skip adapters with `virtual_adapter` (Hyper-V, VMware, VPNs, a random MAC).
- **E3/C1:** `NatType` -> record `Nat`: Open -> Open, EndpointIndependent -> Cone, Dependent -> Symmetric, Unknown -> Unknown.

## Decisions to review

1. **`global_ipv6()` leaves out addresses configured by hand** (Windows `PrefixOrigin == Manual`) as well as deprecated and
   tentative ones. On this PC the only global-looking IPv6 address is Hamachi's `2620:9b::...`, a manual address that
   only Hamachi peers can reach, and Hamachi even installs a `::/0` route on its interface, so a "has an IPv6 gateway" test
   would not have caught it. Cost: a user who types a static global IPv6 by hand on a real NIC gets none advertised. Change
   `best_first` (the `!c.manual` filter) if you want it back. Tunnel interfaces (Teredo, 6to4, ISATAP) are skipped too. Elsewhere
   (netdev) there are no lifetimes or origins, so every global address of an up interface is listed in OS order.
2. **A DHT observation returns 400 ms after the second distinct answer** (or at 3 answers / all answered / `wait`). Of the four
   default bootstrap names measured today only `dht.libtorrent.org` and `relay.pkarr.org` send BEP 42's `ip`;
   `dht.transmissionbt.com` (two IPs) answers without it, `router.bittorrent.com` did not answer at all (raw pings, with and
   without `ro`, and with 2- and 4-byte transaction ids). Waiting for all would cost the full 3 s every time. Saved
   routing-table nodes (mostly libtorrent/other clients) should do better than the defaults: prefer them.
3. **NAT classification** needs two servers on different IPs to say anything but `Open`/`Unknown`, and any disagreement (even one
   of four) is `Dependent`: a conservative reading that sends the caller to the relay rather than to a punch that fails.
   `Open` means the observed endpoint is one of this PC's own addresses on the socket's port (for a wildcard-bound socket the OS
   decides: a socket can bind to the observed IP only if it is local; nothing is sent). On Linux with `ip_nonlocal_bind=1` that
   test would say yes to anything.
4. The ping carries `ro: 1` (BEP 43, "do not add me to your routing table") and a 4-byte transaction id: `mainline` nodes answer
   with exactly four bytes (a 2-byte one came back padded, so it would not match). Node id is random per probe.
5. `observe_*` set the socket to blocking mode and leave it so (std cannot read the previous mode); a non-blocking socket would make
   the loops spin. They also drop whatever else arrives meanwhile and drain stale errors first (Windows reports an earlier ICMP
   "port unreachable" on the next receive).
6. If not one ping can be sent (no route, an IPv4 node on an IPv6-only socket) the I/O error returns at once instead of after `wait`.
7. A random source without a dependency: `RandomState` + clock for ids (they only need to be hard to guess off-path). No `rand`.

## Not tested

Linux/Android compile; a real dual-stack socket; a network with a symmetric NAT or a real `Open` socket (covered with fake nodes
on loopback only); `global_ipv6()` on a PC with native IPv6 (the walker is verified against `Get-NetIPAddress`, but this PC has
no native global address to list).
