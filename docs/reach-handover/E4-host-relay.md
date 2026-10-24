# E4 host relay: hand-over for I3 and H1 (and G2, F3, the review)

Branch `reach-e4-host-relay`, from `integration-wave2` (`0fc65e2`). Commits, in order: `f0586b9` (two assertions of E1's dispatch
test that checked the stub's answer, see "Outside `relay.rs`"), `fa0069a` (the code and its tests: `crates/host/src/reach/relay.rs`),
`560914e` (what an independent read of it found), `09f5d41` and `467d1f7` (two tests for those fixes), `82fe545` and `da9ad38` (the
first version of this note), `eb13294` (the first change in `server.rs`, approved: a link from a host the relay's user paired with),
`8a0631f` (the relay tests on the real pairing flow), `e2f1450` (such a host may register and ask for nothing else), `780c557` (the
second version of this note), `cfed785` (a link of a device the host knows needs no access password) and `26a4ebb` (connections through
a tunnel keep their packets to one relay datagram), then the commit of this version of the note. fmt, `clippy -p velora-host
--all-targets -D warnings` and `cargo test -p velora-host` green on Windows (122 pass, 30 of them in `relay.rs` and 6 new in
`server.rs`, 2 `#[ignore]`d by E1); the relay tests and the server tests were repeated in parallel and the whole suite once on one
thread, with no flake. Linux was not compiled here. I broke the code on purpose 19 ways (answers waited for, the close code lost to the
control stream, no shutdown on abort, a state file that cannot be read taken for empty, an unreadable list taken for empty, a status
wait with a deadline per message, a MAC address not told, listed relays taking a slot, remembered hosts not pruned, a revoke before the
file is read, the snapshot taken before the lock; in `server.rs`: any hello of a trusted host let in, any link let in, the password
asked of a trusted host, a known device's link asked for the password, the password skipped for any hello of a known device, the MTU cap
not applied, the MTU cap applied to every connection; and the pairing check on a trusted host's requests removed); each made a test fail.

## The pairing triangle (H1, I3, G2: this is what a user has to do)

Three computers. **C** is the client you watch from (phone, laptop). **H** is the host you want to reach, which no one can reach
directly (behind a CGNAT, say). **R** is the relay: a PC or a VPS that others can reach. A relayed connection needs three pairings:

1. **C is paired with R, as a client of R.** R lists C among its paired devices. C opens a link to R and asks it to pass the
   connection on; R serves only devices it knows.
2. **R is paired with H, as a client of H.** H is one of the computers R's own user connects to: it is in the `known_hosts.json` of R's
   *client side* (what `velora list` shows on R). H registers with R under its host identity, and R lets it in only because R itself
   pinned that identity when its user paired R with H. R also needs H's pairing to be *this* way round: R being paired with C, or C with
   H, does not make H trusted at R. H must also know where R is: H is paired with R the same way (R is in H's known hosts), or R is
   listed in H's `relays.json`.
3. **C is paired with H, as a client of H**, as always. Once R passes the packets on, C and H run the ordinary handshake and H checks C
   like any client (its access password included).

In one sentence for the docs: *pair your phone with both PCs as usual, and pair the two PCs with each other, each as a client of the
other.*

When one is missing the log says which: no (1): the client's link to R is refused, "this device is not paired with the host"; no (2):
H's log has `relay '<name>' (<fp>): it refused this host: this device is not paired with the host` and R's side logs the refusal, and
the client's `RelayTo` gets "this relay does not know that device; it has never registered here"; no (3): the connection through the
relay fails at the inner hello with "this device is not paired with the host".

**Doing it with what exists today.** Pairing (2) in both directions is what the pairing *offer* does (`velora pair <R address> <code>
--offer <H's pairing link>`, or the launcher's pair-back): H pairs with R, and R's side pairs back with H. But pairing back means R
**connects to H**, and a host that is behind a CGNAT cannot be connected to: it works if H and R are on the same network (or a VPN, or H
has a public address) at that moment, and not otherwise. Without that, R's side can be given H by hand: add an entry for H to
`known_hosts.json` of R's client side (`<config>/client/known_hosts.json`, beside R's `<config>/host`):

```json
[ { "name": "home PC", "address": "any:0", "fingerprint": "<H's host fingerprint, base64url>" } ]
```

(the address is not dialed for this; H's full fingerprint is the `fingerprint` field of H's entry in any client's `known_hosts.json`).
On a VPS that runs only `velora-host run --relay-only` there is no `velora` client to pair with, so this is how it is done.

**For G2 (a simpler way to guide it).** Today's offer already carries what R needs: the pairing link contains H's host fingerprint. So
the launcher can make (2) one step on H and one tap on R, and it works for a host nobody can reach:

- On H, one action "Use a PC as my relay": pick R among H's paired PCs (or pair with it), and H sends its offer. H then registers by
  itself (the switch is E1's `standalone`; nothing else to set).
- On R, the offer shows as "H wants to use this PC as a relay: allow?". Allowing it records H in R's client-side `known_hosts.json`
  from the fingerprint in the offer, **without dialing H** (`pair_back` today dials H and fails for a hidden host). That one entry is
  all `relay::trusts` reads.
- On R, a list "Computers allowed to use this PC as a relay" (the known hosts that have registered, with a Remove: removing the entry
  drops the registration within 30 s, `reconcile`), the "Let my other PCs connect through this one" switch with the bandwidth note,
  and the registered hosts / relayed clients count (D2's `Relay::registered()`, which `Status` does not carry yet).
- On H, "Registered with <name>" from `Status.reach.registered_with` (the relay is listed only while the registration is up), and,
  when it is not, the reason: the host logs it (`relay '<name>' (<fp>): <why>`) but `Status` has no field for it.

## What it does

**Serving** (a host that relays for others: the switch, or `--relay-only`). `serve(ctx)` loads `relay_known.json` into D2's forwarder
(one `Relay` per host, in `ctx.ext::<RelayState>()`), then every 30 s drops what is no longer allowed (devices removed with `velora-host
revoke`, which the running host is not told about, hosts removed from the client side's `known_hosts.json`, and hosts it only
remembers) and saves what the forwarder remembers if it changed; when stopped, or aborted, it calls `Relay::shutdown()` (a drop guard)
and saves. `handle_message` gives `RelayRegister`/`RelayTo` to `Relay::handle` and queues the `RelayStatus` on the sender's control
stream; `Wake` and `PunchRequest` do the same from a task of their own (the first sends a magic packet, the second waits up to 2 s for
the registered host's connection), and the answer is dropped, not waited for, when the device does not read its control stream. Only
`RelayRegister` is answered for a host that is merely trusted (below); the other three need a sender in `authorized_clients.json`. A
successful `RelayRegister` also saves `relay_known.json` (a relay PC that reboots can still wake a host that was asleep when it did).
`on_revoked` calls `Relay::remove` (connections end with `CLOSE_REMOVED`/`CLOSE_HOST_GONE`) and saves. `busy` is true while a client
is paired with a registered host; a registration alone does not count.

**Registering** (`register_with`, a task while `standalone` is on and the host is not `--relay-only`). Every 30 s it reads its
candidates and keeps one supervisor task for each (at most 16): the relays the user listed in `relays.json`, and, while the host
advertises **no `Public` address** (10 s after start, so the router mapping gets its chance), the paired computers of this PC's client
side (`known_hosts.json` beside the host's state directory). A list that cannot be read (half written, say) changes nothing: the
registrations that exist stay. A supervisor does, until told to stop:

1. dial the relay's addresses a little apart (300 ms), from the listening port, with `tls::client_config(&ctx.identity, relay_fp)`:
   the host's **host** identity;
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

## Who may register: `server::authorize` and `relay::trusts` (decision 1, approved)

D2 keys a registration by the connection's certificate, and a client asks `RelayTo` for the host by the fingerprint it pinned: the
host's **host** identity, which is not one of the client identities in the relay's `authorized_clients.json`. `authorize(.., link_hello)`
(in `server.rs`, `eb13294` and `cfed785`) therefore lets in a **link hello** (`files_only` and `reach`, with no pairing secret) from a
device the host *knows*, and a link hello only:

- a **paired client** (in `authorized_clients.json`), or
- a **trusted host**: the fingerprint is in `known_hosts.json` of the client side of the relay's own computer (`relay::trusts`; the relay
  pinned it itself when its user paired with that host: nothing a connecting device says is believed).

What either gets is a link, served as one because the same hello decides both: no session and nobody sent away, no file stream, no
clipboard, and **no access-password question**: a link reaches no screen, which is what the password protects, and a client that dials a
relay holds only the password of the host it wants to reach, so the question could not be answered and a wrong guess counted toward the
relay's lockout (F3's report). A trusted host is answered for `RelayRegister` only in `relay.rs`: a request to be relayed to a host, to
wake one or to punch toward one is refused unless the sender is in `authorized_clients.json`. The acceptance of a trusted host is logged
once at info with the short fingerprint (`accepted a link from the paired computer <fp>`), no address. Every other hello of these
devices (a session, files, a pairing) and every link from an unknown fingerprint is judged exactly as before: a session and a file
manager still ask for the password, and an unknown device is refused ("this device is not paired with the host") and learns nothing about
the password. Tests in `server.rs`: an unknown fingerprint is refused a link; a trusted host gets a link and registers, with an access
password set, and writes nothing to `authorized_clients.json`; the same host is refused a session (before and after extensions) and a
file manager, on a relay-only host and on an ordinary one; a paired client, also a known host, gets in as before; with a password set, a
paired client's link works while its session and file-manager hellos are asked for the password, and an unknown device is refused.

Limit to know (H1/G2): under the Windows service the relay's state is `C:\ProgramData\Velora\host`, so its "client side" is
`...\Velora\client`, not the user's `%APPDATA%` one that the launcher and `velora pair` write: `trusts` finds nobody there, and a
service relay needs H's host fingerprint as an entry of `authorized_clients.json` (a client entry, by hand) until the launcher can hand the
service the hosts its user allowed (for example a control request that stores them in the service's own state; I did not add a second
source because the brief said trust comes only from the client side's `known_hosts.json`). A relay run by the user (`velora-host run`,
including `--relay-only` on a VPS) has the same config folder for both sides and works.

**E4b removes this limit** (`E4b-relay-management.md`): the launcher hands the service the computers its user allowed with
`Request::AllowRelayHost` (kept in `relay_hosts.json`, which `relay::trusts` reads too), and a host service learns its relays from
`Request::AddRelay`, so neither needs a hand-written file.

## Packet size through a relay (`26a4ebb`)

The host's path MTU discovery grows packets to 1452 bytes, but an inner packet travels as a datagram of the connection to the relay,
which holds about 1400 (less 3 bytes of relay framing), so each full-size video packet went out as two datagrams: about 40% more
datagrams, and a lost half lost the packet. A connection that arrives from a tunnel address (`is_tunnel_addr`) is now accepted with
`Incoming::accept_with(shared.tunnel_config)`: the host's own server config with `mtu_discovery_config` stopping at `TUNNEL_MTU` =
1350 (`server.rs`). Ordinary connections and the retries keep the endpoint's config. The test (`a_connection_through_a_relay_tunnel_keeps_
its_packets_to_one_relay_datagram`) measures `current_mtu` of both kinds of connection after their discovery has settled: an ordinary
loopback connection ends at 1452, one through a tunnel at or below 1350; without the cap the tunnel one ends at 1452 too. If the outer
path is narrower than 1400 (some mobile paths), a 1350 packet still splits; I3 should read D2's counters (`Relay::registered()` has
`packets` and `datagrams` for each direction): `datagrams` close to `packets` toward the client means the cap does its job.

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

## Using it

**I3 (field test).** Relay PC R: turn "relay for others" on (`reach.json` `{"relay_for_others": true}`, or `velora-host run --relay-only`
on a VPS) and make its UDP port reachable. Make the triangle above (on a VPS, with the hand-written entry for H). Host PC H: `standalone`
on; with no public address (CGNAT) it registers by itself 10 s after start, or at once if R is in `relays.json`. Log lines (info) to
look for:

- relay: `this computer relays for the user's other devices`; `accepted a link from the paired computer <fp>` (H was let in as a known
  host); `<fp> registered with the relay from <addr>` (D2); `<fp> is relayed to <fp>`;
- host: `registered with the relay '<name>' (<fp>) at <addr>`; `relay '<name>' (<fp>): <why>; trying again in N s` (the first
  occurrence of a reason is info, repeats are debug); `punch request of <fp> not taken: <why>` (E5 refused it); `client '<name>' (<fp>)
  connected from [fd00:7e1a:...]:1` for the relayed client (the tunnel's synthetic address).

`ReachState.relays` / `Status.reach.registered_with` list a relay only while its registration is up. The relayed client's inner
connection reports `via_relay` and a `Reached` message is recorded with the relay's kind. `Relay::registered()` (D2) has the per-
direction counters (`packets`, `datagrams`, `dropped`): `datagrams` well above `packets` is the MTU effect below.

**H1 (docs).** What a relay user must know: the three pairings above (in the one sentence); the relay PC forwards every picture of a
relayed session (as much upload as the video bitrate, and the same in download), only one client at a time per registered host (D2
decision 2); an access password on the relay PC protects its screen and is not asked of the links that clients and hosts make to it; a
Windows service relay needs the hand-written entry of H for now; a computer switched to relay is found by hosts within ten minutes at most (they
ask the paired computers that do not relay only that often) or at once when it is listed in `relays.json`. Headless relay: `velora-host
run --relay-only` serves relays and nothing else (no capture, no input, every connection is a link).

## Decisions to review

1. **Host identity at registration** and the one change in `server.rs` that follows from it (above). Alternatives: register under the
   client identity and let D2 key by something else (a D2 change), or have the pairing flow also store the host identity at the relay.
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
9. **A host that is only trusted may register and nothing else** (an addition of mine inside the brief's "a link only"): `RelayTo`,
   `Wake` and `PunchRequest` from it are refused in `relay.rs`.
10. **The inner MTU is capped at 1350 for connections through a tunnel** (F3's "Video packet size" gotcha, done in `26a4ebb`; see "Packet
    size through a relay"). `TUNNEL_MTU` in `server.rs` is the one number to tune. Dropping the oversize packets in the pump would also
    have worked but can stall a handshake that starts at 1200, so the cap is in the connection's config instead.
11. **A link of a known device needs no access password** (F3's decision 1, done in `cfed785`). Only the link hello is exempt; the same
    devices' session, file-manager and pairing hellos ask as before. On a `--relay-only` host a plain hello is still judged as a plain
    hello (it is served as a link, but a password is asked if one is set).
12. **`MAX_REGISTRATIONS`** is `pub` so a UI can show "n of 4".

## Outside `relay.rs`

- `server.rs`, all approved and each a commit of its own, named for E4's need:
  - `eb13294`: `authorize` takes `link_hello`; `handle_connection` decides `link_hello` before authorizing and uses it for `link` as
    well. About 25 lines of code and four tests in `server.rs`'s test module; the two test calls of `authorize` got `, false`.
  - `cfed785`: a link hello from a paired client skips the password question too (the branch is five lines inside the same `if`); one test.
  - `26a4ebb`: `Shared::tunnel_config` (built in `open` from the same identity) and `accept_with` for tunnel sources in
    `handle_connection` (where `await incoming` became `incoming.accept()?` for the rest, which is the same thing); one test.
- `f0586b9` changes two assertions of `reach::tests::relay_requests_are_refused_unless_the_host_relays_for_others` in `reach/mod.rs`
  (test only): they compared the hook's answer to the stub's "this build cannot relay yet". They now check that the request got past
  the dispatch (it was not answered with the dispatch's own refusals). Drop the commit if you prefer to do this at the merge.

## Gotchas

- The tests start whole hosts with `server::run`, on the loopback and in scratch directories. `run` also opens the launcher's control
  channel (`\\.\pipe\velora-host` on Windows): a host that already runs on the machine keeps it and the test hosts log a warning.
  Tests that switch `standalone` on start E2's and E5's tasks as well: once they are real they must not touch the router or the DHT
  for a host bound to the loopback.
- The inner endpoint of a *client* needs a dual-stack socket: the tunnel's address is IPv6 (`fd00:7e1a::/32`), and quinn refuses to
  connect to an IPv6 address from an IPv4-only endpoint.
- `Link`, `pump` and `advertised` are private but written to be reused: F3's dialer has the same two jobs (link hello, framed pump). The
  two sides agree on the shape of a link: the `files_only` + `reach` hello with no password, a Welcome (0x0, features 0), then `Reach`,
  then the answers to requests on the same control stream, which both keep open for as long as the link lasts (the relay's `Relay` keeps
  its own handle on the connection, so the control stream ending closes nothing).
- `crate::hostname()` is the name in the hello; it is the computer's name and shows in the relay's logs.
- Under `--relay-only` `register_with` is not started (E1), so a relay-only host never registers anywhere. On a relay-only host a plain
  hello is served as a link too, but a trusted host's plain hello is still refused: the shortcut is for the link hello only.
- A MutexGuard from `ctx.reach.read()` kept in an `if let` scrutinee lives through its body: bind the value first (the compiler
  caught one across an `.await`).

## Not tested

Linux compile; a real NAT, CGNAT or a relay on another network; `name:port` addresses (the resolver path is compiled, not run); an
old host as relay (the 3 s wait for a `Reach` that never comes); the 30 s serving tick, the 30 s rescan and the 5 s "does the host
need a relay" check (their bodies are tested, the timers are not); waking a real PC through the relay; an outer path whose MTU changes
during a session (framing is tested at the sizes loopback gives); the pre-dial skip when every slot is taken (the cap itself is); the
log line of an accepted link (there is no subscriber in the tests); a link hello with a pairing secret (it falls to the old path by the
`secret.is_none()` condition, untested); the MTU cap on a real outer path, under video load (the test shows the cap is applied and that
the uncapped connection reaches 1452 on loopback; the ratio of datagrams to packets at a real relay is I3's to read).
