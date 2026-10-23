# Standalone reach: implementation tickets

Companion to [nat-traversal.md](nat-traversal.md) (revision 2). Status: proposal. Nothing is
implemented.

## 0. Rules that make the tickets conflict-free

1. **Every shared file has exactly one owner ticket.** `wire.rs`, `pairing.rs`, `control.rs`,
   `identity.rs`, `host/server.rs`, `host/main.rs`, `client-core/lib.rs`, `client-core/hosts.rs`,
   `gui/this_pc.rs`, `gui/strings.rs`, the workspace `Cargo.toml` and each crate's `Cargo.toml`
   are each edited by one "plumbing" ticket and then frozen for this work. Every other ticket
   adds or edits only files it owns (see §2).
2. **The protocol is defined once, up front (T0)**, with every message and field of the whole
   plan, so no feature ticket touches `wire.rs`.
3. **New crates are scaffolded first (W0)** with all their external dependencies declared and
   one empty module per owning ticket, so `Cargo.toml`/`Cargo.lock` settle before the parallel
   work starts. If `Cargo.lock` still conflicts, regenerate it (`cargo update -w`), never merge
   it by hand.
4. **Plumbing tickets expose hooks** (a state struct, stub functions in files the feature
   ticket owns), so a feature lands by filling its own files, with no edit elsewhere.
5. One branch and one worktree per ticket, named after the ticket (`reach/T0-protocol`), all
   branched from the integration branch `standalone-reach`; merged in wave order; a ticket
   rebases only onto that branch, never onto a sibling.
6. Every ticket keeps `cargo clippy --workspace --all-targets -- -D warnings` and
   `cargo test --workspace` green on Windows and Linux, and keeps older peers working.

## 1. Lanes and waves

```
Wave 0  W0 scaffolding (serial, half a day)
Wave 1  T0 protocol │ S0 DHT spike │ B1 B2 B3 velora-nat │ C1 velora-dht record │ D1 relay framing
Wave 2  E1 host plumbing │ F1 client-core plumbing │ G1 launcher plumbing │ C2 C3 DHT node │ D2 relay core
Wave 3  E2 E3 E4 E5 E6 host features │ F2 F3 F4 F5 client features │ G2 G3 launcher and CLI
Wave 4  I1 I2 I3 I4 field tests │ H1 docs │ H2 release
```

Critical path: W0 → T0 → E1 → E4 → I3 → H2, about 12 working days. With four lanes in
flight that is roughly three weeks of wall clock; the sum of all tickets is about 54
person-days, more than the plan's five weeks because plumbing, UI, mobile, field tests and
docs are now counted.

## 2. File ownership map

| Area | Files | Owner |
|---|---|---|
| Workspace | `Cargo.toml`, `Cargo.lock`, the three new crates' `Cargo.toml` and `src/lib.rs`, `.github/workflows/*` | W0 |
| Protocol | `crates/protocol/src/{wire,pairing,control,identity}.rs` | T0 |
| velora-nat | `src/mapping.rs` | B1 |
| velora-nat | `src/addresses.rs`, `src/observe.rs` | B2 |
| velora-nat | `src/wake.rs` | B3 |
| velora-dht | `src/record.rs`, `src/seal.rs`, `src/keys.rs` | C1 |
| velora-dht | `src/node.rs` | C2 |
| velora-dht | `src/punch_item.rs` | C3 |
| velora-dht | `docs/dht-spike.md` | S0 |
| velora-relay | `src/frame.rs` | D1 |
| velora-relay | `src/forward.rs` | D2 |
| Host | `src/server.rs`, `src/main.rs`, `src/control.rs`, `src/reach/mod.rs`, `src/reach/socket.rs`, `Cargo.toml` | E1 |
| Host | `src/reach/mapping.rs` | E2 |
| Host | `src/reach/dht.rs`, `src/reach/secrets.rs` | E3 |
| Host | `src/reach/relay.rs` | E4 |
| Host | `src/reach/punch.rs`, `src/reach/poll.rs` | E5 |
| Host | `src/reach/wake.rs` | E6 |
| client-core | `src/lib.rs`, `src/hosts.rs`, `src/reach/mod.rs`, `Cargo.toml` | F1 |
| client-core | `src/reach/dht.rs` | F2 |
| client-core | `src/reach/relay.rs` | F3 |
| client-core | `src/reach/punch.rs` | F4 |
| mobile | `crates/mobile/src/lib.rs` | F5 |
| Launcher | `gui/strings.rs`, `gui/this_pc.rs` (one call), `gui/mod.rs` (one call), `gui/reach.rs` (skeleton) | G1 |
| Launcher | `gui/reach.rs` (body) | G2, after G1 |
| Launcher | `crates/client/src/main.rs` | G3 |
| Docs | `README.md`, `docs/*.md` | H1 |
| Release | workspace version, release notes | H2 |

`gui/reach.rs` is created by G1 and filled by G2, which depends on G1, so the two never run
at the same time: that is the only file with two owners, in sequence.

## 3. Tickets

Format: lane · wave · estimate · depends on · runs in parallel with.

### W0 — Scaffold the crates and settle the dependencies
Workspace · wave 0 · 0.5 d · depends on nothing · serial.
- Create `crates/nat` (`velora-nat`), `crates/dht` (`velora-dht`), `crates/relay`
  (`velora-relay`, library only), add them to the workspace, and declare their dependencies
  now: `natpmp 0.5`, `igd-next 0.18`, `stunclient 0.4` (nat); `mainline 8` pinned with its
  `ed25519-dalek 3.0.0-pre.1`, `postcard 1` (dht); `quinn`, `bytes` (relay); `ring` is
  already a workspace dependency.
- Each `lib.rs` declares the modules of §2 as empty files, so later tickets never edit it.
- CI already runs clippy and tests for the whole workspace on Ubuntu and Windows; add the
  Android check for `velora-mobile` with the new transitive crates (`cargo check -p
  velora-mobile --target aarch64-linux-android`) if the Android workflow does not cover it.
- Done when: the workspace builds and lints on both OSes with the empty crates; `Cargo.lock`
  contains every new dependency.

### T0 — Protocol: every new message and field, once
Protocol · wave 1 · 2 d · after W0 · parallel with S0, B1-B3, C1, D1.
Owns `wire.rs`, `pairing.rs`, `control.rs`, `identity.rs`.
- `HelloExt.reach` (bit 5); bit 7 reserved as "another flags byte follows" (documented, not
  used).
- `HostMsg::Reach { addresses: Vec<(AddressKind, String)>, key: [u8; 32], secret: [u8; 16],
  relays: Vec<(String fingerprint, Vec<String>)>, mac: Option<[u8; 6]>, relays_for_others:
  bool }`, sent only after the welcome to clients that set the bit. `AddressKind`: `Lan`,
  `Vpn`, `Public`, `V6`, `Relay(fingerprint)`; unknown kinds decode as `Other(u8)`.
- `HostMsg::RelayStatus { ok, reason }`, `HostMsg::PunchRequest { from: fingerprint, endpoint,
  nonce }` (a relay forwarding a client's request to a registered host).
- `ClientMsg::Reached { address }`, `RelayRegister { mac }`, `RelayTo { fingerprint }`,
  `Wake { fingerprint }`, `PunchRequest { to: fingerprint, endpoint, nonce }`. Old hosts
  decode them as `Unsupported` and ignore them (already true).
- `MAX_ADDRESSES` 8 → 16.
- `pairing.rs`: `key=` and `secret=` emitted by `pairing_uri_with` and parsed; link length
  test (must stay under 300 characters with 8 addresses).
- `identity.rs`: `KnownHost` gains `kinds`, `key`, `secret`, `relays`, `mac`, all
  `#[serde(default)]`.
- `control.rs`: `Status.reach: Option<ReachStatus { standalone, relay_for_others, dht,
  mapping: Option<MappingStatus>, public: Vec<String>, v6: Vec<String>, last_reached:
  Option<(kind, address)>, registered_with: Vec<String> }>`, `Request::SetReach { standalone,
  relay_for_others, dht }`.
- Done when: round-trip tests for every message, the older-status/older-link tests, and a
  test that a hello with bit 7 is still decoded by this version.
- Risk: getting a field wrong here costs a second protocol ticket; review this one carefully.

### S0 — Spike: `mainline` on real networks
velora-dht · wave 1 · 1 d · after W0 · parallel with everything in wave 1.
Owns `docs/dht-spike.md`.
- A throwaway binary (not committed) that joins the DHT, prints `info().public_address()`
  and `firewalled()`, publishes a mutable item, resolves it from a second machine, measures
  put/get latency cold and warm, measures start time with and without a saved routing table,
  and checks after 1 h, 2 h, 3 h whether the item is still there.
- Done when: `docs/dht-spike.md` records the numbers and any surprise (e.g. the observed port
  under this router), and C2's design is confirmed or amended.

### B1 — Router port mapping
velora-nat · wave 1 · 2 d · after W0 · parallel with T0, B2, B3, C1, D1.
Owns `src/mapping.rs`.
- `map_udp(local_port, wanted_external, lease) -> Mapping { protocol, external_ip,
  external_port, lease }`: NAT-PMP first, then UPnP IGD (`AddAnyPortMapping` on IGDv2, else
  `AddPortMapping` and the next port on conflict 718); `renew`, `remove`; gateway discovery
  (default route on Windows and Linux).
- Done when: unit tests with a mocked gateway for the conflict and renewal paths; a manual
  run on this network logs a mapping and removes it; both OSes compile.
- Risk: router quirks; keep every failure as a logged `Err`, never a panic.

### B2 — Public addresses and endpoint observation
velora-nat · wave 1 · 2 d · after W0 · parallel with T0, B1, B3, C1, D1.
Owns `src/addresses.rs`, `src/observe.rs`.
- `addresses.rs`: classify an IP (public / private / shared 100.64/10 / link-local / ULA);
  list global IPv6 addresses per interface, preferring the longest valid lifetime
  (`GetAdaptersAddresses` on Windows, first global on Linux); local MACs for B3/E6.
- `observe.rs`: from a caller-provided `std::net::UdpSocket`, send a KRPC `ping` to given DHT
  nodes and read the BEP 42 `ip` field; STUN binding (`stunclient`) as fallback; from several
  observations classify the NAT as open / endpoint-independent / dependent.
- Done when: unit tests for classification and the bencode of ping/response; a manual run
  prints this PC's observed endpoint and NAT type.

### B3 — Wake-on-LAN
velora-nat · wave 1 · 0.5 d · after W0 · parallel with everything in wave 1.
Owns `src/wake.rs`.
- Build and send a magic packet to the subnet broadcast (and 255.255.255.255) on UDP 9 and 7.
- Done when: a unit test checks the packet bytes; a manual run wakes a PC on this LAN.

### C1 — DHT record format, keys and per-device sealing
velora-dht · wave 1 · 2 d · after W0 · parallel with T0, S0, B*, D1.
Owns `src/record.rs`, `src/seal.rs`, `src/keys.rs`.
- `keys.rs`: Ed25519 key pair (through `mainline`'s signing key type, to keep one dalek),
  serialized as a file beside the identity; `public_key()`.
- `record.rs`: `Record { fingerprint, addresses: Vec<(kind, addr)>, nat, relays, mac, ts }`,
  `postcard` encoding.
- `seal.rs`: `seal(record, &[(device_id, secret)]) -> Vec<u8>` with a random content key
  wrapped per device (ChaCha20-Poly1305 from `ring`), falling back to one shared secret when
  the devices don't fit; `open(bytes, device_id, secret)`; the 1000-byte BEP 44 limit
  enforced with a clear error.
- Done when: tests cover round trip, a revoked device failing to open, the size limit, and
  the fallback.

### C2 — DHT node wrapper
velora-dht · wave 2 · 2.5 d · after S0, C1 · parallel with E1, F1, G1, D2, C3.
Owns `src/node.rs`.
- `Node::open(cache_path, client_mode)` bootstrapping from the saved routing table when there
  is one; `publish(keys, salt, bytes, seq)`; `resolve(public_key, salt) -> Option<(bytes,
  seq)>`; `observed_address()`; `save_cache()`; sequence number = unix time.
- Done when: an integration test (ignored in CI, run by hand) publishes from one process and
  resolves from another; the warm start is under a second with a cache.

### C3 — Punch request item
velora-dht · wave 2 · 0.5 d · after C1 · parallel with everything in wave 2.
Owns `src/punch_item.rs`.
- Salt `velora/punch/<host key prefix>`, value `{ endpoint, nonce, ts }` sealed for the host
  only; `seq` = unix time.
- Done when: round-trip test; a stale item (older than 60 s) is rejected on open.

### D1 — Relay framing
velora-relay · wave 1 · 1 d · after W0 · parallel with everything in wave 1.
Owns `src/frame.rs`.
- Split an inner packet into one or two datagrams with a 3-byte header (packet id, chunk
  index, chunk count); reassembly table with a 2 s timeout; drop on a missing chunk.
- Done when: tests cover single, split, reordered, lost-chunk and timeout cases.

### D2 — Relay forwarding core
velora-relay · wave 2 · 3 d · after D1 · parallel with E1, F1, G1, C2, C3.
Owns `src/forward.rs`.
- Given already-authenticated `quinn::Connection`s and their fingerprints (the caller does
  pairing and TLS): `register(conn, fingerprint, mac)`; `relay_to(conn, target)` pairing a
  client connection with a registered one; copy datagrams both ways through D1 framing; per
  source rate limit on new flows; `RelayStatus` replies; `wake(target)` by MAC through the
  registered host's LAN (calls `velora-nat::wake`); a `registered()` list for status.
- Done when: an in-process test with three quinn endpoints (relay, host, client) runs a
  whole Velora handshake and 1 MB of datagrams through the relay with 1% synthetic loss.

### E1 — Host plumbing: hooks and the multiplexed socket
Host · wave 2 · 3 d · after T0 · parallel with F1, G1, C2, C3, D2.
Owns `src/server.rs`, `src/main.rs`, `src/control.rs`, `src/reach/mod.rs`,
`src/reach/socket.rs`, `crates/host/Cargo.toml`. After this ticket these files are frozen.
- `reach/mod.rs`: `ReachState` (switches, addresses with kinds, mapping status, relays
  registered with, last reached, device secrets accessor) behind `Arc<RwLock>`; stub
  functions the feature tickets fill in their own files: `mapping::run`, `dht::run`,
  `dht::reach_message(fingerprint)`, `relay::serve`, `relay::register_with`, `punch::run`,
  `wake::local_mac`, `on_paired(fingerprint)`, `handle_client_msg(msg, conn)`.
- `reach/socket.rs`: an `AsyncUdpSocket` that multiplexes the real dual-stack socket, raw
  probe sends with their replies kept out of quinn, and relay tunnels that appear as peers
  with synthetic ULA addresses (`fd00:7e1a::/32` derived from the relay's fingerprint). This
  is the one piece E4 and E5 both need, so it is written here, fully tested, once.
- `server.rs`: bind through `reach::bind` (dual-stack); `Incoming::retry` when the address is
  not validated and standalone reach is on; `reachable_addresses` merges `ReachState`; send
  `HostMsg::Reach` after the welcome to clients with the bit; dispatch the new client
  messages to `reach::handle_client_msg`; call `on_paired` after a pairing; `--relay-only`
  (no capture, no sessions, relay serving only) parsed in `main.rs`.
- `control.rs`: `Request::SetReach` → `ReachState`; `Status.reach` filled from it.
- Done when: all existing tests pass; a test proves that a client without the bit gets no
  `Reach`; the socket multiplexer has unit tests for the three sources.

### E2 — Host: mapping and public addresses
Host · wave 3 · 2 d · after B1, B2, E1 · parallel with E3-E6, F2-F5, G2, G3.
Owns `src/reach/mapping.rs`.
- Every 30 min and on start: map through B1, classify the external IP through B2 (private or
  shared → not advertised, logged as CGNAT/double NAT), compare with the observed address
  when one is known, select global v6 addresses, write `Public`/`V6` entries and the
  mapping status into `ReachState`; remove the mapping on shutdown.
- Done when: on this network the host logs `reachable at pub:…`; an integration test with
  a fake mapping result shows the right addresses in `Reach` and in `Status`.

### E3 — Host: DHT record and device secrets
Host · wave 3 · 2 d · after C2, E1 · parallel with E2, E4-E6, F2-F5, G2, G3.
Owns `src/reach/dht.rs`, `src/reach/secrets.rs`.
- Key file in the host state dir (C1); device secret generated at `on_paired` and stored per
  fingerprint; revoked devices dropped; `reach_message(fingerprint)` returns key and secret;
  publish loop (30 min and on `ReachState` change) sealing the record for every paired device
  (C1) through the node (C2) with the saved routing table in the state dir.
- Done when: a test seals and opens the record for two devices and fails for a revoked one;
  by hand, the record resolves from another machine within a minute of a change.

### E4 — Host: relay serving and registration
Host · wave 3 · 3 d · after D2, E1 · parallel with E2, E3, E5, E6, F2-F5, G2, G3.
Owns `src/reach/relay.rs`.
- Serving: when `relay_for_others` is on (or `--relay-only`), feed authenticated connections
  that send `RelayRegister`/`RelayTo` to D2; forward `Wake` to D2; answer `RelayStatus`.
- Registering: when standalone reach is on and no public address exists (or the user asks),
  keep a connection to each reachable paired device that announced `relays_for_others`,
  send `RelayRegister` with the MAC, and expose the tunnel to the main endpoint through the
  socket multiplexer (E1) so relayed clients are ordinary incoming connections; reconnect
  with backoff; list the relays in `ReachState`.
- Done when: an in-process test runs client → host-as-relay → registered host through the
  real server code; `velora-host run --relay-only` serves relays and nothing else.

### E5 — Host: hole punching responder
Host · wave 3 · 3 d · after B2, C3, E1 · parallel with E2-E4, E6, F2-F5, G2, G3.
Owns `src/reach/punch.rs`, `src/reach/poll.rs`.
- Observe the host's own endpoint through the multiplexer's probe sends (B2) and keep the
  NAT type in `ReachState`; on a `PunchRequest` (from a relay connection, or from the DHT
  poller) send toward the client's endpoint with `Endpoint::connect_with` and drop the
  attempt when the client's connection arrives; `poll.rs`: when standalone reach is on and no
  relay is registered, resolve paired clients' punch items every 10 s, and every 2 s for five
  minutes after a client disconnects.
- Done when: a loopback test with a simulated endpoint-independent NAT (a small UDP proxy in
  the test) completes a handshake through the punch; the poller is tested with a fake node.

### E6 — Host: wake support
Host · wave 3 · 1 d · after B3, E1 · parallel with everything in wave 3.
Owns `src/reach/wake.rs`.
- `local_mac` for the registration and the record; when this host serves as a relay, handle
  `Wake` for registered hosts whose connection came from the same LAN.
- Done when: a unit test checks the LAN check; by hand a relay PC wakes a sleeping host.

### F1 — client-core plumbing
client-core · wave 2 · 3 d · after T0 · parallel with E1, G1, C2, C3, D2.
Owns `src/lib.rs`, `src/hosts.rs`, `src/reach/mod.rs`, `crates/client-core/Cargo.toml`.
- Set the `reach` bit; read `HostMsg::Reach` after the welcome into `Session.reach` and
  persist it into `KnownHost` (`hosts.rs`), without changing any exported function
  signature (the Android app must keep compiling untouched).
- `establish` becomes a race over a stream of candidates: `Candidate::Direct(addr, kind)`,
  `Relay { relay_addr, relay_fingerprint, target }`, `Punch { ... }`; the first batch comes
  from the stored addresses, later ones from `reach::resolve_record` (F2 stub) as they
  arrive; `Relay` and `Punch` dial through `reach::dial_relay` and `reach::dial_punch` (F3,
  F4 stubs that return "not available" until filled); the stagger stays 250 ms; relay
  candidates start 2 s after the first direct one.
- Send `Reached` after the handshake; `hosts::wake(state, name)` public function calling
  `reach::wake` (stub).
- Done when: existing tests pass; a test shows late candidates joining a race; a test shows a
  host without `Reach` behaving exactly as before.

### F2 — client-core: DHT resolve
client-core · wave 3 · 1.5 d · after C2, F1 · parallel with E2-E6, F3-F5, G2, G3.
Owns `src/reach/dht.rs`.
- `resolve_record(known_host)`: open the node with the client's cache, resolve, open the
  record with the device secret, return its addresses (and relays) as candidates; cap the
  cold start at 5 s so it never holds the race.
- Done when: a test with a fake node returns candidates; by hand a client reaches a host
  whose IP changed.

### F3 — client-core: relay dialer
client-core · wave 3 · 2.5 d · after D1, F1 · parallel with E2-E6, F2, F4, F5, G2, G3.
Owns `src/reach/relay.rs`.
- Connect to the relay, send `RelayTo`, wait for `RelayStatus`; `RelaySocket: AsyncUdpSocket`
  that tunnels the inner endpoint's packets through the outer connection's datagrams with D1
  framing; the inner `quinn::Endpoint::new_with_abstract_socket` on it; the inner handshake
  is the normal Velora one.
- Done when: an in-process test runs the full client handshake through D2's forwarder.

### F4 — client-core: punch dialer
client-core · wave 3 · 3 d · after B2, C3, F1 · parallel with E2-E6, F2, F3, F5, G2, G3.
Owns `src/reach/punch.rs`.
- Bind the candidate's socket, observe its endpoint (B2), send the `PunchRequest` through
  the relay connection when one exists, else publish the punch item (C3) through the node;
  hand the socket to quinn and dial the host's observed endpoint for 10 s; give up to the
  relay candidate.
- Done when: the loopback test from E5 runs end to end with this dialer.

### F5 — Mobile surface
client-core/mobile · wave 3 · 0.5 d · after F1 · parallel with everything in wave 3.
Owns `crates/mobile/src/lib.rs`.
- Export `wake(host)` and the address kinds in `HostEntry`; nothing else changes.
- Done when: the Android build passes; `wake` works from the phone on the home Wi-Fi.

### G1 — Launcher plumbing
Launcher · wave 2 · 1.5 d · after T0 · parallel with E1, F1, C2, C3, D2.
Owns `gui/strings.rs`, one call in `gui/this_pc.rs`, one call in `gui/mod.rs` (device card),
`gui/reach.rs` skeleton.
- All new strings in both languages; `reach.rs` with `reach_card()` on This PC showing
  `Status.reach` (switches for standalone, relay for others, DHT; mapping state; public and
  v6 addresses; last reached; registered relays) sending `Request::SetReach`; a `wake_button`
  placeholder on the device card.
- Done when: the card renders against a fake status; strings are all used.

### G2 — Launcher: relay and wake UI
Launcher · wave 3 · 1.5 d · after G1 · parallel with everything in wave 3.
Owns `gui/reach.rs` body.
- Relay status lines, the "Let my other PCs connect through this one" switch with the
  bandwidth note, the Wake button calling `hosts::wake` with its states (sent / no relay on
  that LAN / unsupported), the public address shown next to the QR code.
- Done when: the launcher drives a real host through every switch.

### G3 — Command line
Launcher · wave 3 · 1 d · after F1 · parallel with everything in wave 3.
Owns `crates/client/src/main.rs`.
- `velora wake <host>`; `velora connect` prints which address kind won; `velora-host reach`
  status is covered by `Status`, so no host CLI change.
- Done when: both commands work against a real host.

### I1 — Field test: phase 1 on real routers
wave 4 · 1 d · after E2, F1, G1.
- Three routers (this one, one with NAT-PMP only, one with UPnP off), the client on 4G/5G:
  record which address kind reached, log lines, and the CGNAT detection on a CGNAT line.

### I2 — Field test: DHT across networks
wave 4 · 1 d · after E3, F2.
- Change the host's public IP (reconnect the ONT) with the client away; measure time to
  reach; verify a revoked device cannot open the record.

### I3 — Field test: relay across networks
wave 4 · 2 d · after E4, F3, G2, E6.
- Host behind CGNAT, relay PC on another connection, client on 4G/5G: session quality and
  settled bitrate; wake through the relay PC; `--relay-only` on a VPS.

### I4 — Field test: hole punching
wave 4 · 3 d · after E5, F4.
- Three networks with different NATs plus a phone on 4G/5G: success rate per NAT pair, time
  to first picture, fallback to the relay; fix what the field finds.

### H1 — Docs
wave 4 · 1 d · after I1-I3 · parallel with I4.
Owns `README.md`, `docs/*.md`.
- README section "Reaching this PC from anywhere" with the three options (Tailscale, standalone,
  relay PC), the switches, what each needs from the router and from Windows, the Wake
  requirements; the plan documents marked as implemented.

### H2 — Release
wave 4 · 0.5 d · after everything.
Owns the workspace version and the release notes.
- Version bump; `velora-host run --relay-only` documented for VPS users; no new binary in the
  release workflow.

## 4. Merge order

W0 → T0 → {E1, F1, G1} → feature tickets as they finish, each rebased on `standalone-reach`
→ I tickets → H1 → H2 → PR from `standalone-reach` to `main`. Feature tickets of wave 3 can
merge in any order because they share no files; the integration branch stays green after
every merge because each ticket's stubs compile without the others.

## 5. Running the lanes with parallel agents

One Claude session per ticket, each in its own worktree on `reach/<ticket>` from
`standalone-reach`; the brief is the ticket text plus §0 and §2 of this file. A session that
needs a change outside its files stops and asks, rather than editing: that is how a conflict
would start. Plumbing tickets (T0, E1, F1, G1) are reviewed with extra care, since every
later ticket builds on their interfaces.
