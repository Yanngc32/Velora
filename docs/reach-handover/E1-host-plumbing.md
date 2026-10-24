# E1 host plumbing: hand-over for E2-E6 (and F1, F3, D2, G1 where they meet the host)

Branch `claude/reach-e1-host-plumbing-a15e76`, from `integration-wave1`: `798f8f1` (the code), `c8a3ba7` (what an independent read of
it found) and the commit of this note. Files: `crates/host/src/{server,main}.rs`,
`crates/host/src/reach/{mod,socket}.rs`, the seven stubs `reach/{mapping,dht,secrets,relay,punch,poll,wake}.rs`,
`crates/host/Cargo.toml` and the mechanical `Cargo.lock` lines that go with it. `control.rs` needed no change (the dispatch of
`Request::SetReach` is `Shared::control` in `server.rs`). fmt, `clippy -p velora-host --all-targets -D warnings` and `cargo test
-p velora-host` green on Windows (86 pass, 2 `#[ignore]`d, both run by hand: a real session over IPv4 and IPv6 to one dual-stack
socket, with Welcome, Reach and video, and 32 MB each way through a tunnel). Linux was not compiled here (only the Windows target
builds this crate).

## The rule for E2-E6

Each edits its own file and nothing else. Everything below `reach/mod.rs` is read-only for you; if you think you need a field or a
hook that is not there, look at `ReachContext::ext::<YourState>()` first (one value per type per host, made with `Default`), then ask.
`reach/mod.rs` has `#![allow(dead_code)]` because this is a binary crate and most of the API is unused until you use it.

| you | file | you fill | runs |
|---|---|---|---|
| E2 | `mapping.rs` | `run(ctx)` | task while `standalone` is on |
| E3 | `dht.rs`, `secrets.rs` | `dht::run(ctx)`, `dht::reach_message(ctx, fp)`, `secrets::{get, all, on_paired, on_revoked}` | task while `dht` is on; the rest called by the host |
| E4 | `relay.rs` | `serve(ctx)`, `register_with(ctx)`, `handle_message(ctx, from, msg)`, `on_revoked(ctx, fp)`, `busy(ctx)` | tasks; the rest called by the host |
| E5 | `punch.rs`, `poll.rs` | `punch::run(ctx)`, `punch::respond(ctx, request)`, `poll::run(ctx)` | tasks while `standalone` is on; `respond` is called by E4 and by `poll` |
| E6 | `wake.rs` | `local_mac()` | called by the host (every 5 min; was 30 until E6); D2 already does the LAN check for a relayed wake |

Contracts are in the doc comments of each stub. Tasks end by **returning** after `ctx.stop` fires (`ctx.stop.stopped().await`,
`ctx.stop.sleep(d).await -> bool`); the host waits 4 s for them, then aborts. An `Err` is logged and the task is not restarted until its
switch is turned off and on, so retry inside. Tasks of switches that go off and on again are not overlapped: the new run starts after the
old one returned (or was aborted and dropped: what it gave to `spawn_blocking` still runs, so keep such calls short, and await in the
task whatever must finish before the next run, such as the removal of a mapping).

## `ReachState` (read `ctx.reach.read()`, write `ctx.reach.update(|s| ..)`, wake-ups `ctx.reach.subscribe()`)

`update` tells subscribers only if the state changed, and the signal fires for *any* field (also `last_reached`, `clients`): compare what
you would publish with what you last did. Never hold a guard across an `.await` or a hook call. Fields and their writer:
`switches`, `relay_only`, `last_reached`, `mac`, `clients` (E1) · `addresses` (E1 keeps `Lan`/`Vpn`; E2 `Public`/`V6` through
`set_addresses(kind, vec)`; E4 `Relay(fp)` through `set_relays`, which also fills `relays`) · `mapping` (E2) · `nat`, `observed` (E5) ·
`dht_key` (E3: setting it is what puts `key=`/`secret=` in pairing links and the key in `Reach`). `addresses` is always in order of
usefulness (LAN, VPN, public, IPv6, relays); a welcome takes the first 8 that are not relays, a `Reach` the first 16. **The DHT record
is built from `record_addresses()`, not from `addresses`**: it adds `observed` as a `Public` address when the NAT is `Open` or
`EndpointIndependent` and no public address is advertised, which is how a client learns where to punch to (E5 sets `observed`, E2 owns
`Public`, E3 builds the record; nobody else puts `observed` anywhere). `exposed()` is "standalone, or relays for others".

`ReachContext`: `reach`, `state_dir` (`Arc<StateDir>`, the host's), `identity`, `fingerprint`, `bind` (with the real port),
`endpoint` (`connect_with` from the listening port), `socket` (probes and tunnels), `stop`, `ext()`, `port()`, `device_secret(fp)`,
`client_state_dir()` (where `known_hosts.json` of this computer's *client* side is, for E4 to find relays; not created, and elsewhere
under the Windows service). `ClientConn` (what a message handler gets): `conn`, `fingerprint`, `name`, `control` (`try_send(HostMsg)`
queues a message on that device's control stream; clone it to keep), `via_relay`, `link`, `remote_addr()`.

## Connections: sessions, file managers and links (E4, D2, F1, F3 must know this)

A relay request (`RelayRegister`, `RelayTo`, `Wake`, `PunchRequest`) must **not** arrive on a session: opening one captures the screen
and sends the active device away, and its datagrams are eaten by the mouse reader. So the host treats a hello with `files_only` **and**
`reach` as a *link* (and every connection of a `--relay-only` host): Welcome with `width = height = 0` and `features = Some(0)`, then
`Reach` (if asked), then control messages only, nothing else. Whoever dials a relay (the registering host in E4, the client in F3) sets
those two bits and nothing that starts a session (the host refuses `RelayRegister` and `RelayTo` that arrive on a session, since the
session's mouse reader and the relay would both read its datagrams; `Wake` and `PunchRequest` take nothing from the connection and are
accepted anywhere). Against a host from before this version the same hello is a plain file connection
that never answers with `Reach`, so "no `Reach` within a few seconds" means "cannot relay". Links go through the same `authorize` as
any connection, access password included.

D2's open point (a registering host must not become a session of the relay PC nor displace the one in progress) is this: the host
never starts a session for a link. `velora_relay::forward::Relay::handle(&from.conn, &msg)` takes the four relay messages as they come to
`relay::handle_message`; write its answer with `from.control.try_send`. D2 keeps its own handle on a registered connection, so the
control stream ending closes nothing, and a removed device must be dropped with `Relay::remove` in `relay::on_revoked`.

Update logic: a link is not "busy" for the auto-update (`relay::busy(ctx)` is, for relayed traffic that is flowing). A removed device's
links are closed (`revoke` in the launcher); `velora-host revoke` while running is not seen, so reconcile with
`authorized_clients.json` when you use per-device data.

## `HostMsg::Reach` as sent

Right after the Welcome (before `Displays`), only to clients with the hello bit. Key and secret are **all zeros when there is none** (DHT
off, key not loaded): F1 must read an all-zero key as "no record". `relays_for_others` is true under `--relay-only`. `mac` is the cached
`wake::local_mac()`. Old welcomes keep 8 plain addresses, relays excluded. `ClientMsg::Reached` is logged once per change and stored in
`last_reached` with a kind (the host's own list first, else judged by the address, else the relay when the connection came through a
tunnel).

## The socket (`reach/socket.rs`), for E4 and E5

```rust
// E5: a probe. The handler sees every datagram from the real socket before quinn; return true to keep it away.
let dht = Arc::new(Mutex::new(DhtProbe::new(&nodes)));
let probe = ctx.socket.probe({ let dht = dht.clone(); move |from, data| dht.lock().unwrap().handle(from, data) });
for (node, ping) in pings { probe.send_to(node, ping).await?; }      // async: waits for the send buffer; plain IPv4 is fine
// observations: dht.lock().unwrap().observations(); drop `probe` to stop. `from` is the plain IPv4 form of a mapped source.

// E4: a tunnel. quinn sees the peers behind the relay at `tunnel.addr()` (fd00:7e1a:<hash of fp>, port = flow).
let mut tunnel = ctx.socket.open_tunnel(relay_fp_bytes, NonZeroU16::MIN)?;   // Err if open already / 64 open
let inbound = tunnel.inbound();                                              // Clone; feed from the task that reads the relay
loop { select! {
    d = conn.read_datagram() => { if let Some(p) = reassembler.push(d?, now) { let _ = inbound.deliver(p); } }  // never blocks
    p = tunnel.next_outbound() => { /* split with conn.max_datagram_size() (read at each send), then conn.send_datagram(each) */ }
}}
// Dropping the Tunnel closes it. Open it again at the same relay and flow and the inner connections carry on.
```
Behaviour to rely on: a full or closed tunnel **drops** the packet and counts it (`ctx.socket.stats()`), it never returns `WouldBlock` or an
error to quinn (a connection that got an error from a send would end, and a closed relay link may come back); inbound is bounded (256 per
tunnel, 1024 in all) and `deliver` says `Full`/`Closed` instead of waiting; the real socket and the tunnels are served in turns. quinn shows
IPv4 peers of the dual-stack socket as `::ffff:a.b.c.d` (`Connection::remote_address()`; use `ClientConn::remote_addr()` or
`to_canonical()`); datagrams from the real network with a tunnel address as source are dropped. A connection through a tunnel is not asked
to prove its address (Retry); everything else is, while the host is `exposed()`.

## How to test a hook

`reach::testing` (cfg(test)): `context(tag) -> (ReachContext, Scratch)` (loopback socket, endpoint, scratch state dir),
`connect(&ctx) -> Link` (a real connection to `ctx.endpoint`), `client_conn(&link, name) -> (ClientConn, outbox)`, `Calls` (what the host
called in `on_paired`/`on_revoked`, in `ctx.ext::<Calls>()`). `server.rs`'s tests show a whole in-process host with clients speaking the
protocol (`TestHost`); sessions need a screen, so use links or file managers there.

## Decisions to review

1. **Links** as above (`files_only` + `reach`). A hello bit of their own (bit 6 is free) would be cleaner, but is a T0 change.
2. **`SetReach` stays privileged** under the service (not in `harmless`): it opens a port on the router, publishes the host and lets others
   use its bandwidth.
3. **Switches default to off**, saved in `reach.json` (`standalone`, `relay_for_others`, `dht`); a headless `--relay-only` host has no
   launcher, so H1 should document editing that file (or `Request::SetReach` over the control socket).
4. **Retry** (the ticket: "only while standalone reach is on") also applies while the host relays for others, `--relay-only` included:
   a relay-only VPS faces the internet by design and its switches are off by default, so it would answer spoofed Initials with
   amplification. A DHT record alone opens nothing and does not turn it on.
5. **The default bind is `[::]:7420`**, dual-stack; `--bind 0.0.0.0:7420` stays IPv4 only; an address already in use is an error, not a
   fall-back (the IPv4 half can be had beside a dual-stack socket on Windows, which would hide a second host).
6. **The pairing link** carries LAN + VPN (IPv4 first) + the public address, and with key and secret it is cut to 300 characters by
   dropping IPv6 VPN addresses first. Without a DHT key it is what it was plus the public address.
7. **Ctrl-C (and SIGTERM on Unix) end the host cleanly** (neither was handled before) so the mapping is removed; the Windows service still
   ends it hard. The SIGTERM branch is `cfg(unix)`: not compiled here.
8. A receive error of the real socket (other than the ICMP kinds) is logged and stepped over, never returned: quinn ends the whole
   endpoint on one (its own socket never returns any), and an ICMP error can be provoked from outside.
9. Tunnel and probe API shapes (`flow` as the port so a relay with several clients can have several tunnels; `send_to` async because
   tokio's cached write readiness is empty on a fresh socket).
10. `Cargo.lock` changed only by the host's new dependencies (`velora-nat`, `velora-dht`, `velora-relay`, `bytes`, `socket2`, tokio's
   `signal`); regenerate with `cargo update -w` if it conflicts.

## Gotchas

- Every host-ticket lane builds the crate `velora-host` from a worktree: same artifact hash in a shared target dir. Use your own
  `CARGO_TARGET_DIR` or `touch crates/host/src/*.rs` before each cargo command.
- `Probe` handlers run on quinn's receive path: quick, no blocking, no opening or closing probes from inside.
- The DHT node (C2) has its own socket: its `observed_address()` carries the wrong port for QUIC. Only E5's probe on this socket may set
  `ReachState::observed`.
- A host started on `127.0.0.1:0` advertises its real port (`ReachContext::bind` has it).
- `ReachState::mac` is E1's cache of `wake::local_mac()`; read it, do not call the hook.
- A device that opens an ordinary session on a `--relay-only` host (pairing it, say) gets a Welcome with no screen and then nothing:
  the pairing works, the picture never comes. G2/F1 may want to say "this computer only relays" when the Welcome is 0x0.
- The one test that runs a real session needs a screen: `cargo test -p velora-host -- --ignored session` on a machine with a desktop.

## Not tested

Linux/Android compile (including the `cfg(unix)` SIGTERM branch of `server::run`); the real DHT or a real NAT through the probe (fake
DHT nodes with B2's `DhtProbe` only); the Windows service path; `Ctrl-C` by hand.
