# F1 client-core plumbing: hand-over for F2, F3, F4, F5, G2, G3 (and the review)

Branch `claude/reach-f1-client-plumbing-fff4e6` (from 35081ec). Files: `crates/client-core/src/{lib,hosts}.rs`, `src/reach/{mod,dht,relay,punch}.rs`,
`crates/client-core/Cargo.toml` and, as its consequence, three lines of `Cargo.lock`. `dht.rs`, `relay.rs` and `punch.rs` are stubs:
`reach/mod.rs` can only declare them if the files exist, so F1 creates them and F2, F3, F4 own them from the merge on. No exported
function changed its signature. 47 tests (5 before, 42 new), fmt, clippy `-D warnings` and `cargo test -p velora-client-core` green on
Windows; `cargo check -p velora-mobile` compiles. Linux and Android were not compiled here. I also broke the code on purpose 14 ways
(stagger, relay delay, dedupe, the hello bit, `Reached` never sent, `remember` dropping reach data, `store_reach` erasing the key, two addresses of one relay dialed together, ...)
and each made at least one test fail.

## Public surface (what the other tickets and the UIs can use)

```rust
// lib.rs
pub struct ConnectParams { ..., pub reach: Option<reach::ReachParams> }   // and #[derive(Clone)]: the one struct change
Session::reach() -> Option<ReachInfo>      // what the host said right after the welcome; None for a host that predates reach
Session::on_reach(ReachListener)           // called at once if known and again if the host says more; listeners add up
Session::route() -> &Route                 // how the connection was made: Route { kind: AddressKind, address: String }
pub use reach::{ReachInfo, Route, WakeOutcome};   // and `pub mod reach`
// hosts.rs
hosts::wake(state: &StateDir, host: &str) -> Result<WakeOutcome>   // host = name or main address, like connect
// reach/mod.rs
enum Candidate { Direct(SocketAddr, AddressKind), Relay { relay_addr, relay_fingerprint: Fingerprint, target: Fingerprint },
                 Punch { endpoint: SocketAddr, via: Vec<RelayRef> } }          // RelayRef { addr, fingerprint }
struct ReachParams { host: KnownHost, state_dir: PathBuf }   // host's stored entry + this device's state directory
struct ReachInfo { addresses: Vec<(AddressKind, String)>, key: Option<[u8; 32]>, secret: Option<[u8; 16]>,
                   relays: Vec<(String, Vec<String>)>, mac: Option<[u8; 6]>, relays_for_others: bool }
enum WakeOutcome { Sent, Unsupported, NoRelay }   // Unsupported: no MAC known. NoRelay: not on the host's LAN and no relay did it
reach::kind_label(&AddressKind) -> &str           // "lan" "vpn" "public" "v6" "relay" "other"; Route has Display: "lan 192.0.2.1:7420"
```

`Debug` of `ReachInfo` and `ReachParams` leaves the key, the secret and the MAC out (a test pins it); `KnownHost` still prints its secret, so do not
`{:?}` one into a log.

## The hooks (signatures are frozen; each doc comment says what it receives, returns and the timing)

| hook | file | signature |
|---|---|---|
| `resolve_record` | `dht.rs` (F2) | `async fn(params: &ConnectParams) -> Result<Vec<Candidate>>` |
| `dial_relay` | `relay.rs` (F3) | `async fn(params: &ConnectParams, relay_addr: SocketAddr, relay_fingerprint: Fingerprint, target: Fingerprint) -> Result<(quinn::Endpoint, quinn::Connection)>` |
| `wake_through_relay` | `relay.rs` (F3) | `async fn(identity: &Identity, host: &KnownHost) -> Result<WakeOutcome>` |
| `dial_punch` | `punch.rs` (F4) | `async fn(params: &ConnectParams, endpoint: SocketAddr, via: &[RelayRef]) -> Result<(quinn::Endpoint, quinn::Connection)>` |

- `params.reach` is `Some` for a host connected to before (hosts.rs fills it from the known-hosts entry) and `None` while pairing. The race asks
  `resolve_record` only when it holds both `host.key` and `host.secret`. `params.host_fingerprint` is what every inner handshake pins.
- The two dialers return what a direct dial returns, the endpoint and connection *to the host*; `handshake` then sends the ordinary hello on it. The
  endpoint must own whatever carries the tunnel, because the session keeps only the endpoint and the connection.
- The race spawns the lookup and the dialers and aborts them when something else wins, so they must be `Send` and cancel-safe, and give up by themselves
  (the race has no per-attempt timeout; it cuts the lookup at `LOOKUP_LIMIT`, 10 s). A panic in one costs that candidate only (tested). A test in
  `lib.rs` (`the_futures_that_hold_the_hooks_are_send`) stops the build if a hook makes `connect` or `hosts::wake` `!Send`.
- **`Candidate::Punch` is proposed by `resolve_record` (F2) only**: nothing stored says a host's NAT type or observed endpoint. `Candidate::Relay` comes from
  the stored data (`KnownHost.relays` and the `Relay(fp)` entries of `kinds`) and from the record. Add the F4 sentence to F2's brief.
- `stored_candidates`, `race` and `dial` are `pub(crate)`; the constants are public and live in one place, `reach/mod.rs`.

## The race (`reach::race`, called by `establish`)

First batch: `addr`, `also`, then the rest of the host's last `Reach` list (`Direct`, kind from the list or guessed from the address: public, global v6,
100.64/10 and Tailscale's v6 range = vpn, everything else lan), then the relays. Later batches: whatever `resolve_record` returns.

- Direct candidates start `ADDRESS_STAGGER` (250 ms) apart, counted from when they arrive, so a late one never jumps the queue.
- Relays and punches start `RELAY_DELAY` / `PUNCH_DELAY` (2 s each) after the first direct one, 250 ms apart among themselves; with no direct candidate
  they start at once; one that arrives with a direct candidate in the same batch counts from it.
- Two addresses of the same relay for the same host start `RELAY_ADDRESS_STAGGER` (2 s) apart (other relays are not held up): D2 serves one client per
  host and a second `RelayTo` from the same device takes the first over, so a relay reachable at both its IPv4 and IPv6 address gets one dial, not two
  that cancel each other. There is one candidate per relay address, so a dial that is still running when the next address starts can be taken over
  (`CLOSE_TAKEN_OVER`): it should fail at once.
- `resolve_record` is asked `LOOKUP_DELAY` (500 ms) after the start, or at once when nothing is running or waiting: a LAN address that answers in
  milliseconds never touches the DHT.
- A way of reaching the host runs once (same address, or same relay and target), however often it is proposed; at most `MAX_CANDIDATES` (32) run.
- The first handshake wins, the rest are dropped. When none wins, the error is the failure of the earliest candidate accepted (the main address), with
  the old context message.
- `Candidate::route()`: `Direct` gives its kind and address, `Relay` gives `Relay(<relay fingerprint>)` and *the relay's address*, `Punch` gives `Public` and
  the endpoint. `ClientMsg::Reached { address }` carries `route.address`, so a host can match it to the entry it listed.

## After the welcome and in the known-hosts file

- The hello sets the `reach` bit in `connect` (not in `connect_files`: a files-only connection neither asks for nor reads `Reach`; a host paired with
  `pair_quietly` gets its key and secret at the first `connect`).
- `read_control` (the old displays reader) also handles `HostMsg::Reach`: all-zero `key` / `secret` become `None`, the info goes into the `Session`, the
  listeners are called, and `Reached` is sent once, only now (an older host never sends `Reach`, so never hears `Reached`).
- `hosts::connect` and `hosts::pair` register a listener that calls `store_reach`. Address list (`kinds`) and relay list are replaced whole; `key`,
  `secret` and `mac` only when the host sent one. Nothing is written when nothing changed. `remember` (re-pair) carries the reach fields over when the
  fingerprint is the same, and drops them for another host with the same name.
- Every read-edit-write of the file in `hosts.rs` takes a process-wide lock now, since `Reach` is saved while the session runs.

## Decisions to review

1. **Wake is real for the LAN.** `reach::wake` does what a stub could not leave undone: it sends the magic packet on the first network of this device that
   holds a LAN IPv4 address of the host (B3's `wake_networks` / `network_of` / `wake_on`), which is what the phone on the home Wi-Fi needs (F5), and
   calls `wake_through_relay` (stub, F3) only when none does. The ticket said stub; F5 owns no file where this could live. Caveat for F3 and G2: another LAN
   with the same subnet (192.168.1.0/24 at a hotel) reads as "sent" and wakes nothing.
2. **The DHT is touched late** (500 ms) so that a connection on the LAN or VPN never starts a node or tells the bootstrap nodes anything. A host whose
   IP changed pays that half second; tell me if you want it at zero.
3. **`PUNCH_DELAY` equals `RELAY_DELAY`**, so the relay (sure) and the punch (saves a hop) race and the relay will usually win. I4 tunes this; it is
   one constant.
4. **Zeros mean "no key / no secret".** `Reach.key` and `.secret` are not optional on the wire; a host with the DHT off can send zeros and the client
   stores nothing (and keeps an older real key). E1 and E3 must either do that or always send real values.
5. **`ConnectParams` gained a public field and `Clone`.** Only `hosts.rs` builds it in this repo (the mobile crate and the egui client do not), so nothing
   else changed; an external user with a struct literal would have to add `reach: None`.
6. **`reopen(StateDir)`.** The listener that saves `Reach` outlives the `&StateDir` that `connect` gets, and `StateDir` is not `Clone`; `hosts.rs`
   rebuilds one from `dir()` (parent + file name, which is how `StateDir::open` made it). `#[derive(Clone)]` on `StateDir` (T0's `identity.rs`) would
   remove it.
7. **Listeners add up** (`on_reach`), unlike `on_displays`, which has one: the file-saving listener must not be replaced by a UI's.
8. **`RELAY_ADDRESS_STAGGER` = 2 s** (added after reading D2's note): the alternative, one candidate per relay with all its addresses, would have changed the
   ticket's `Relay { relay_addr, .. }` and made `Route.address` ambiguous.
9. **`MAX_CANDIDATES` = 32.** A hostile or buggy host could list 8 relays of 16 addresses; each candidate is a socket and a handshake.
10. **Not consumed:** the pairing link's `key=` / `secret=` (T0 added them to `PairingLink`). `hosts::pair` takes address and code, so using them would
   need a new function; the `Reach` that follows the first welcome gives the same values, so nothing is lost but the DHT before the first connection.

## Gotchas

- Tests that need a host: `#[cfg(test)] crate::testing::{FakeHost, Script, TempDir, reach_msg, sink, within, eventually}` (in `lib.rs`). `FakeHost` is a
  loopback QUIC host that welcomes any client, sends `Script.reach` after the welcome to a client that set the bit, can behave like a host that predates
  hello extensions (`legacy`), and records the hellos and control messages it receives. F3 and F4 can use it as the inner host.
- Do not use tokio's paused clock with real QUIC sockets: the virtual clock jumps whenever the runtime waits on I/O. The race tests use fake dials for that.
- Several lanes that build `velora-client-core` into one `CARGO_TARGET_DIR` collide on the artifact hash (see the B2 note): `touch crates/client-core/src/*.rs`
  before each cargo command and check the test names.
- D2 serves one client per host and device: a files window (`connect_files`) and a session through the same relay, or two `velora` processes, take each
  other over. Nothing in F1 prevents it (they are separate connections, usually separate processes); F3 and G2 should know.
- `ReachInfo` hands over `relays_for_others`, but `KnownHost` has no field for it (T0): F3 cannot tell from the stored entry whether a listed relay still
  accepts `RelayTo`. A relay in `KnownHost.relays` is one the *host* is registered with, so it did at that time.

## Not tested

Linux and Android compile; the real DHT, relays and punching (stubs); a host from the E1 branch (the fake host stands in for it); `wake_on_lan`'s
send path (a unit test would broadcast on the real network; the choice of targets and the "not on any network" path are tested).
