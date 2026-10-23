# E4 host relay: hand-over for I3 and H1 (and G2, F3, the review)

Branch `reach-e4-host-relay`, from `integration-wave2` (`0fc65e2`): `f0586b9` (two assertions of E1's dispatch test that checked the
stub's answer, see "Outside `relay.rs`"), `fa0069a` (the code and its tests: `crates/host/src/reach/relay.rs`), `560914e` (what an
independent read of it found), `09f5d41` and `467d1f7` (two tests for those fixes) and the commit of this note. fmt,
`clippy -p velora-host --all-targets -D warnings` and `cargo test -p velora-host` green on Windows (115 pass, 29 of them in `relay.rs`,
2 `#[ignore]`d by E1). Linux was not compiled here. I broke the code on purpose 12 ways (answers waited for, the close code lost to the
control stream, no shutdown on abort, a state file that cannot be read taken for empty, an unreadable list taken for empty, a status
wait with a deadline per message, a MAC address not told, listed relays taking a slot, remembered hosts not pruned, a revoke before the
file is read, the snapshot taken before the lock); each made a test fail.

## What it does

**Serving** (a host that relays for others: the switch, or `--relay-only`). `serve(ctx)` loads `relay_known.json` into D2's forwarder
(one `Relay` per host, in `ctx.ext::<RelayState>()`), then every 30 s drops what is no longer allowed (devices removed with `velora-host
revoke`, which the running host is not told about, and hosts it only remembers) and saves what the forwarder remembers if it changed;
when stopped, or aborted, it calls `Relay::shutdown()` (a drop guard) and saves. `handle_message` gives `RelayRegister`/`RelayTo` to
`Relay::handle` and queues the `RelayStatus` on the sender's control stream; `Wake` and `PunchRequest` do the same from a task of
their own (the first sends a magic packet, the second waits up to 2 s for the registered host's connection), and the answer is dropped,
not waited for, when the device does not read its control stream. A successful `RelayRegister` also saves `relay_known.json` (a relay PC
that reboots can still wake a host that was asleep when it did). `on_revoked` calls `Relay::remove` (connections end with
`CLOSE_REMOVED`/`CLOSE_HOST_GONE`) and saves. `busy` is true while a client is paired with a registered host; a registration alone does
not count.

**Registering** (`register_with`, a task while `standalone` is on and the host is not `--relay-only`). Every 30 s it reads its
candidates and keeps one supervisor task for each (at most 16): the relays the user listed in `relays.json`, and, while the host
advertises **no `Public` address** (10 s after start, so the router mapping gets its chance), the paired computers of this PC's client
side (`known_hosts.json` beside the host's state directory). A list that cannot be read (half written, say) changes nothing: the
registrations that exist stay. A supervisor does, until told to stop:

1. dial the relay's addresses a little apart (300 ms), from the listening port, with `tls::client_config(&ctx.identity, relay_fp)`:
   the host's **host** identity (see "Who may register");
2. open the control stream and say hello as a **link** (`files_only` + `reach`, the name is the computer's name), read the welcome and
   the `Reach`; no `Reach` within 3 s, or `relays_for_others == false`: not a relay, leave it alone (a minute for a relay the user
   listed, ten for a paired computer, most of which say no);
3. a paired computer needs one of 4 registration slots (and is not even dialed while they are all taken); a relay the user listed
   takes none. **Open the tunnel** (`ctx.socket.open_tunnel(relay_fp, flow 1)`) and only then send `RelayRegister { mac:
   ReachState.mac }`; wait for the `RelayStatus` (8 s in all);
4. list the relay in `ReachState` (`set_relays`; so `Reach.relays` and the `Relay(fp)` addresses follow) while the connection lasts;
5. pump: datagrams from the relay are reassembled (D1) and delivered to the tunnel's inbound side; what the endpoint sends to the
   tunnel is split to the connection's `max_datagram_size()` **read at every send** and sent as datagrams; the reassembly table is
   swept every second; unidirectional streams the relay opens carry one `HostMsg::PunchRequest` each and go to `punch::respond`
   (8 readers at a time, 5 s to arrive, and they end with the pump). A MAC address that becomes known or changes is sent again on
   the same connection with `RelayRegister`, and asked again every 10 s until the relay says yes;
6. when the connection ends, wait and start over (backoff 5 s doubling to 5 min, up to 20 % longer by chance, starting over after a
   registration that lasted a minute). A close with `CLOSE_REPLACED` waits 90 s (two copies of this host would otherwise replace each
   other for ever), `CLOSE_REMOVED` or the host's "device removed" code 10 min, `CLOSE_SHUTDOWN` 2 min; the pump is given a second to
   report the close when only the control stream broke, so that code is not lost to which of them is read first.

A registration that is established is **not** cut off when a public address turns up later; only new attempts are gated by it.
The tunnel's inner connections are ordinary incoming connections of the endpoint, from a synthetic address; E1 skips Retry for them
and `ClientConn::via_relay` says which relay.

## Files in the host's state directory

| file | written by | content |
|---|---|---|
| `reach.json` | E1 (`SetReach`) | the three switches; a headless host edits it |
| `relay_known.json` | E4 | `[{fingerprint, mac?, addr}]`: hosts this relay can wake, written when it changes; read once, before any write |
| `relays.json` | the user (G2 may write it) | relays to register with, **same shape as `known_hosts.json`** |

`relays.json` is wanted whether or not the host has a public address, and is the only source for a host run as the Windows service
(its state is not under the user's folder, so `ctx.client_state_dir()` finds no client side). An entry is a copy of one from
`known_hosts.json`, or by hand:

```json
[ { "name": "office PC", "address": "203.0.113.10:7420", "fingerprint": "<the relay's host fingerprint, base64url>",
    "also": ["198.51.100.20:7420"] } ]
```

Addresses may be `ip:port` or `name:port`; `kinds` (as `known_hosts.json` keeps them) are used when present and a `Relay(..)` kind is
never dialled. The file is read again every 30 s.

## Who may register (decision 1 — needs a change outside `relay.rs`)

D2 keys a registration by the connection's certificate, and a client asks `RelayTo` for the host by the fingerprint it pinned: the
host's **host** identity. So the registering host must dial under its host identity. But the relay's `server::authorize` lets in
the **client** identities of `authorized_clients.json`, which the user's pairing of the host PC with the relay PC fills with the host
PC's *client* identity. A host registering under its host identity is therefore `Denied` ("not paired") unless its host fingerprint
was put in the relay's `authorized_clients.json` by hand — the tests do exactly that. Nothing in `relay.rs` can fix it.

`relay::trusts(ctx, &fingerprint)` is the hook for it: true for a host in the *client side's* `known_hosts.json` of the relay PC (a
two-way pairing, `OfferPairing`). The patch that uses it is in E1's `server.rs`, so it is **not applied**; it is tested (a relay PC
with an access password, a host it only trusts, a client that is only paired; the test fails without the `server.rs` half) and saved as
`E4-trusted-links.patch` in the notes folder of the sessions (`git apply` it on this branch; 124 lines: `server.rs` and the test in
`relay.rs`). It does two things in `authorize`, which now takes `link: bool` (decided in `handle_connection` before authorizing):

```rust
// A link reaches no screen, which is what the access password protects, so a paired device gets in without it.
// So does a computer this one's user paired with as a client: it registers under its host identity,
// which is not in the list of client devices.
if link && secret.is_none() && (known || reach::relay::trusts(shared.reach.context(), &fingerprint)) {
    return Ok(Auth::Known);
}
```

The second half (`known` links skip the access password) answers F3's decision 1 as well: a relay PC with an access password cannot be
used today, by a client or by a registering host, because a link has no password to give. Take only the first half
(`!known && link && ... trusts(..)`) if the password should stay for known devices.

Without the patch a relay PC needs the host's host fingerprint in its `authorized_clients.json` (as a client entry; the full fingerprint
is the `fingerprint` field of the host's entry in any paired client's `known_hosts.json`). I3 should expect this to be the first thing
that fails in the field: the host logs `relay '<name>' (<fp>): it refused this host: this device is not paired with the host`.

## Using it

**I3 (field test).** Relay PC: turn "relay for others" on (`reach.json` `{"relay_for_others": true}`, or `velora-host run --relay-only`
on a VPS) and make its UDP port reachable. Pair the client with the relay PC and with the host PC as usual; pair the host PC's client
side with the relay PC; give the relay the host's host fingerprint (decision 1). Host PC: `standalone` on; with no public address
(CGNAT) it registers by itself 10 s after start, or at once if the relay is in `relays.json`. Log lines (info) to look for:

- relay: `this computer relays for the user's other devices`; `<fp> registered with the relay from <addr>` (D2); `<fp> is relayed to <fp>`;
- host: `registered with the relay '<name>' (<fp>) at <addr>`; `relay '<name>' (<fp>): <why>; trying again in N s` (the first
  occurrence of a reason is info, repeats are debug); `punch request of <fp> not taken: <why>` (E5 refused it); `client '<name>' (<fp>)
  connected from [fd00:7e1a:...]:1` for the relayed client (the tunnel's synthetic address).

`ReachState.relays` / `Status.reach.registered_with` list a relay only while its registration is up. The relayed client's inner
connection reports `via_relay` and a `Reached` message is recorded with the relay's kind. `Relay::registered()` (D2) has the per-
direction counters (`packets`, `datagrams`, `dropped`): `datagrams` well above `packets` is the MTU effect below.

**H1 (docs).** What a relay user must know: the relay PC forwards every picture of a relayed session (as much upload as the video
bitrate, and the same in download), only one client at a time per registered host (D2 decision 2); the host and the client both
need to be paired with it, and the host's PC must be one the relay's user paired with too (decision 1); a relay with an access
password refuses both until `authorize` changes (above); a computer switched to relay is found by hosts within ten minutes at most
(they ask the paired computers that do not relay only that often) or at once when it is listed in `relays.json`.
Headless relay: `velora-host run --relay-only` serves relays and nothing else (no capture, no input, every connection is a link).

## Decisions to review

1. **Host identity at registration, and the authorization gap** above. Alternatives: register under the client identity and let D2
   key by something else (a D2 change), or have the pairing flow also store the host identity at the relay (pairing code, E1/G).
2. **`relays.json`** as the "user asks" source and the only one under the service; **the paired computers as candidates** come from the
   client side's `known_hosts.json`. `KnownHost` has no field for "this host relays for others", so every candidate is asked.
3. **Slots and caps:** 4 registrations for paired computers (listed relays are outside the cap), 16 supervisors, 8 addresses per relay,
   4 addresses advertised per relay (public, IPv6, VPN, then LAN; the address that worked from here always included); the relay's own
   `Reach` addresses are preferred to the stored ones.
4. **One tunnel per relay, flow 1**, because D2 pairs one client with a host at a time.
5. **Waits:** see "What it does". `REFUSED_WAIT`/`NOT_A_RELAY_WAIT` (60 s / 10 min) are the cost of not knowing which paired
   computers relay; a user who just switched one on may wait up to 10 minutes or restart the host.
6. **The MAC address** is sent with the registration and again when it becomes known or changes (each costs one token of the relay's
   per-device limiter: burst 6, one more every 5 s). `None` is sent as `None`; D2 keeps an older one.
7. **`relay_known.json`** is read once, before any save, and not written at all while it cannot be read (a damaged one reads as empty
   and the next save repairs it); `reconcile` also forgets remembered hosts that are no longer paired.
8. **Punch requests** are read from the relay's unidirectional streams only (D2's way); a `PunchRequest` on the control stream is ignored.
   `punch::respond` refusals are logged at info (E5 asked for that for the odd ones; its `Refusal` type is not in this branch yet, so
   they are not told apart).
9. **`MAX_REGISTRATIONS`** is `pub` so a UI can show "n of 4".
10. **Not done: the inner MTU** (F3's "Video packet size" gotcha). The host's endpoint discovers the path MTU up to 1452 bytes and sends
    video packets of that size to a relayed client, but an outer datagram carries about 1400, so every full-size packet becomes two
    datagrams (D1 handles it, at about 1.6 times the datagrams per megabyte and twice the loss for those packets). The cure is a
    `MtuDiscoveryConfig` upper bound near 1350 for connections that come in through a tunnel, which needs `Incoming::accept_with` in
    `server.rs` (or `tls::transport_config`): not mine. Dropping the oversize packets in the pump would also work but can stall a
    handshake that starts at 1200. I3 should measure before anyone changes it.

## Outside `relay.rs`

`f0586b9` changes two assertions of `reach::tests::relay_requests_are_refused_unless_the_host_relays_for_others` in `reach/mod.rs`
(test only): they compared the hook's answer to the stub's "this build cannot relay yet". They now check that the request got past
the dispatch (it was not answered with the dispatch's own refusals). Drop the commit if you prefer to do this at the merge.

## Gotchas

- The tests start whole hosts with `server::run`, on the loopback and in scratch directories. `run` also opens the launcher's control
  channel (`\\.\pipe\velora-host` on Windows): a host that already runs on the machine keeps it and the test hosts log a warning.
  Tests that switch `standalone` on start E2's and E5's tasks as well: once they are real they must not touch the router or the DHT
  for a host bound to the loopback.
- The inner endpoint of a *client* needs a dual-stack socket: the tunnel's address is IPv6 (`fd00:7e1a::/32`), and quinn refuses to
  connect to an IPv6 address from an IPv4-only endpoint.
- `Link`, `pump` and `advertised` are private but written to be reused: F3's dialer has the same two jobs (link hello, framed pump).
- `crate::hostname()` is the name in the hello; it is the computer's name and shows in the relay's logs.
- Under `--relay-only` `register_with` is not started (E1), so a relay-only host never registers anywhere.
- A MutexGuard from `ctx.reach.read()` kept in an `if let` scrutinee lives through its body: bind the value first (the compiler
  caught one across an `.await`).

## Not tested

Linux compile; a real NAT, CGNAT or a relay on another network; `name:port` addresses (the resolver path is compiled, not run); a
relay with an access password (only with the patch, in the patch's test); an old host as relay (the 3 s wait for a `Reach` that never
comes); the 30 s serving tick, the 30 s rescan and the 5 s "does the host need a relay" check (their bodies are tested, the timers
are not); waking a real PC through the relay; an outer path whose MTU changes during a session (framing is tested at the sizes
loopback gives); the pre-dial skip when every slot is taken (the cap itself is).
