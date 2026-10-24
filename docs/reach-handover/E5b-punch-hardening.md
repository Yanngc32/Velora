# E5b host punch hardening: hand-over for I4, E3, G2 (and F2, F4, the review)

Branch `reach-e5b-punch-hardening` (from `integration-wave3`, 5c628d7), code in 77b52a8. One file of code,
`crates/host/src/reach/punch.rs` (E5's), and this note. 20 new tests (the module has 51, the host crate 276 and 4 `#[ignore]`d;
the 256 + 4 it had stay green); `cargo fmt --all --check`, `cargo clippy -p velora-host --all-targets -D warnings` and `cargo test
-p velora-host` are green on Windows. The module's tests ran 30 times in a row, 5 times on one thread and 5 rounds of two copies at
once, and the whole host suite 5 times, with no failure. Linux was not compiled here. I broke the code on purpose 36 times (the vote
filter and where it applies, the settle timer, each condition of the keepalive and the record rule behind it, its interval, which
node, whether it is sent, whether quinn sees the answers, when the next one is due, stop, the measure-again rule, the constants, and
seven bugs of the simulator): each made a test fail, several only after I added or strengthened one. A fresh agent read the change
cold and found, besides what is listed under "Decisions to review", two defects and four weak tests, all fixed (the last section
says which). No packet left the loopback: the DHT nodes, the NATs and the client of the tests are sockets of the tests.

Both changes answer the two risks the F4 note left for the host side ("What the others must know").

## 1. Private votes no longer decide the host's NAT type

A DHT node inside a provider's network says a private address in its reply (S0: 2 of 136 replies), and B2's classification calls any
disagreement symmetric, so one such vote made a cone NAT look symmetric and the host did not list its endpoint for 10 minutes. F4
already drops them on the client side. `counted(votes)` does it here: **while any vote names an address on the internet (`usable`,
which is `classify(ip).is_global()` as before), only those votes count; with none public they all do.** It applies to both things
decided from the votes: what `Observed::new` classifies, and when a round is done (three answers, two different servers plus the
settle time, all answered, or the time up), so a private answer and one public one do not end a round that a second public one
would have completed. The settle timer follows the votes that count: a first public vote that displaces two private ones (two
servers) leaves one, and the timer is cleared. Tested: `[private, public, public]` is a cone NAT at the public endpoint; one public
vote (with or without a private one) is an endpoint with NAT type `Unknown`, which the record does not list as `Public`; only
private votes (a host behind two NATs) still classify the NAT and leave `observed` unset, as before.

## 2. The NAT's mapping is kept alive between measurements

A NAT forgets a UDP mapping that has seen no packet *leave* for 30 s to a few minutes and makes the next one with the port it likes.
`run` measures every 10 minutes and nothing else sends from the QUIC socket while no client is connected, so the endpoint in the
record could be wrong most of the time (many carrier NATs; a router that preserves the source port, like the author's, hides it). Now:

- **`KEEPALIVE` = 20 s: one DHT ping (65 bytes, B2's `encode_ping`, `ro=1`) to one DHT node, three a minute**, about 0.3 MB a day out and
  as much back. The nodes of the list `run` resolved take turns. It leaves from the QUIC socket through a probe of the multiplexer
  (`ctx.socket.probe`), so the reply is taken by the probe and quinn never sees it (`Stats::probe_replies`). The probe stays for
  `KEEPALIVE_REPLY` (2 s) or until the answer or `ctx.stop`; a later answer reaches quinn, which drops it (the host's endpoint
  keeps quinn's default connection-id check, so a stray datagram is dropped silently, with no stateless reset).
- **Wanted while** `keepalive_wanted(state)`: standalone on, **the DHT switch on**, **no relay registered**, and **the record sends
  clients to punch toward `observed`** (`advertises_punch_endpoint`): `observed` is set, the NAT is a cone (`EndpointIndependent`:
  an `Open` host has no mapping, nobody punches through a symmetric one, `Unknown` is not listed) and no `Public` address is
  advertised (a router mapping works, clients dial that one). That is the case in which `ReachState::record_addresses` lists
  `observed`, and a test keeps the two from drifting apart. The DHT switch is the user's consent to DHT traffic and what puts the
  record in the DHT. A registered relay is a QUIC connection from the same socket with keepalives of its own every 2 s, which hold the
  mapping when it crosses the NAT.
- A measurement counts as a keepalive (its pings leave from the socket): the next datagram is due one interval after each round.
  Nothing is sent that cannot be (an IPv6 node on the IPv4 socket, no route, no nodes): a debug line, and the next try is a full interval
  away, never a loop.
- **When it becomes wanted after a time when it was not** (the DHT switch turned on, the last relay gone, a router mapping lapsed)
  **the host measures at once** (`Pause::Resumed`): nobody knows what the mapping did meanwhile, and a measurement says and renews it.
- `ctx.ext::<Observing>().keepalives()` counts the datagrams sent. `Timing` has `keepalive` and `keepalive_reply` (the two constants
  by default), for I4 and the tests.

## The NAT simulator: `SimNat::expiring(device, filtering, lifetime)` (`punch::nat_sim`, test only)

An endpoint-independent NAT whose mapping ends when the device has sent nothing for `lifetime`. What arrives for it from then on is
dropped; the next packet that leaves makes a mapping again **on another socket, so another port, with an empty filter**; the old port
stays dead even for a peer the new mapping lets in. Only packets that leave renew a mapping (what arrives does not: the harshest
of the NATs the RFC allows, so a keepalive that works here works on the others). `public_endpoint()` is the mapping of the moment.
`SimNat::new` is unchanged (it never expires), so E5's and F4's tests are untouched; one more change for everybody: **a gateway for a
peer on a loopback alias (127.0.0.2, ...) now binds that alias**, so that peers on different IPs look like different servers to the
device (B2 classifies only from two servers on different IPs; behind the old gateways, all on 127.0.0.1, a test host read its cone as
`Unknown`). `World::with(client_nat, |device| host_nat)` takes any host NAT. F4 can copy the new `nat_sim` over its own copy.

The end-to-end pair uses the real `run`, the real `respond` and the real client: a host behind an expiring NAT (lifetime 1.2 s) that
measured its endpoint (and found a cone), then 1.8 s of quiet, then a client dials what the host published while the host punches
toward it. **Without the keepalive the handshake does not complete** (the host's packet made a new mapping on another port, which is
not what the client dials, and the client's packets die at the NAT); **with the keepalive (150 ms in the test) the same sequence
completes**.

## Decisions to review

1. **No fake clock.** The ticket asked for one. The module paces itself with `std::time::Instant` and the tests use real loopback
   sockets and real NAT-simulator tasks; a paused Tokio clock jumps to the next timer while a datagram is still on its way between those
   tasks. So the tests scale time instead: every interval is a field of `Timing` (20 s by default, 80 to 150 ms in the tests, 3600 s
   where the keepalive must stay out of the way) and the simulator's lifetime is 0.6 to 1.2 s of real time. The tests count datagrams
   in windows with a tolerance (6 to 12 in 1.05 s at one every 100 ms); the stability runs above are the evidence they hold under load.
2. **The keepalive is wanted only when the record advertises the punch endpoint** (the fourth condition, beyond the three in the
   ticket). Without it every host with a working router mapping would ping a DHT node three times a minute for an endpoint the record
   does not list, and so would a host behind a symmetric NAT.
3. **The resume rule costs one measurement** (four to six datagrams) each time the keepalive begins again (the DHT switch turned on,
   the last relay gone), and not at start-up. If you would rather it just start pinging, remove the `Pause::Resumed` early return in
   `pause`; two tests name it.
4. **A registered relay stops the keepalive, as the ticket says, and does not always hold the mapping.** The host dials a relay at the
   first of its addresses that answers, LAN and IPv6 ones among them (`relay.rs` `dial`), so a relay on the same LAN, or over IPv6, may
   be the one that wins and never cross the NAT. The record then still lists `observed` and the mapping ages out. A relay on the
   internet does hold it. If that matters, drop the `relays.is_empty()` condition (three pings a minute more on hosts with a relay).
5. **Third parties see the host.** The bootstrap nodes (the public names B2 resolves) get a ping from the host's address every 20 s while
   the host is standalone, DHT on, without a relay and advertised; the measurement alone is one burst per 10 minutes. The nodes treat
   the host as a read-only one (`ro=1`, BEP 43) and do not store it. The interval is one constant; say if the cadence or the node
   choice should differ.
6. **Public votes if any, else all** is not the client's rule (F4 drops private votes and ends with none left as "another NAT is in
   the way"). The host still classifies a host behind two NATs, because the NAT type it publishes is shown to the user (G2).
7. **`Unknown` is not measured again sooner.** With two answering nodes, one of them private, the filter leaves one public vote: an
   endpoint and NAT type `Unknown`, which the record does not list, until the next measurement (10 minutes: any answer is a good
   round). B2 found that only two of the four default names send `ip` at all, so this is not rare. A retry at `retry_min` when the
   type is `Unknown` is one line in `run`; I left it, since the same private node would answer the same way and the retry costs
   packets.
8. **Not done, on purpose: noticing a changed mapping at once (proposed as a follow-up).** The pong carries the address the node saw
   (BEP 42); comparing it with `observed` would find a remapped endpoint (a router rebooted, a carrier moved the host, the computer
   woke from sleep: the monotonic clock `run`'s deadlines use may stop meanwhile, so the 10 minutes can be longer) within 20 s
   instead of at the next measurement, and the keepalive would stop holding a mapping nobody is told about. It is a few lines in
   `Keeper::keep` (answer taken, public endpoint different from `observed`, and the last measurement older than `retry_min`: return
   a `Pause` that measures), with the same vote rule (a private reply must not cause a measurement). It was not in the ticket and
   adds a state change, so it is left for you to ask for.
9. **A round that sent nothing still puts the next keepalive 20 s away** (no route, or no nodes resolved). The mapping is then moot
   (no network), and a keepalive could send nothing either; the worst case is a gap of up to about 40 s once the network is back.

## What the others must know

- **I4**: measure what a real router and a real carrier do. The one number that matters is the shortest time a mapping survives with no
  packet leaving (`KEEPALIVE` must stay below it; Linux conntrack's default for a flow nobody answered is 30 s, and 120 s for one both
  sides sent on, which the pong makes of it). `Observing::keepalives()` and a debug line per failed send are what there is to read. If
  a mapping outlives 20 s with room to spare the interval can grow: it is one constant.
- **F4 / F2**: nothing changes in the API or the record. The host's endpoint is now kept, not guaranteed: a sleep, a router reboot or a
  carrier that moves the host still leave the record wrong until the next measurement (at most 10 minutes, or 2 s after the host's own
  addresses change). See decision 8.
- **E3 / G2**: no new state and no new setting. `observed` and `nat` change as before (and are not rewritten when a measurement gives
  the same answer). The DHT switch now also decides whether the host pings the DHT nodes between measurements.

## Gotchas

- The tests use `127.0.0.2` to `127.0.0.5` for the fake nodes, as E5's do (not on a macOS without loopback aliases: the simulator then
  binds `127.0.0.1` for them and a test that needs two servers cannot tell them apart).
- The keepalive is sent from inside `pause`, so a network change is seen after the datagram's reply wait (2 s at most); `ctx.stop` ends
  the wait at once.
- A keepalive that cannot be sent (an IPv6 node on the IPv4 socket) is not tried again with the next node: the tick is lost, the next
  one is a full interval away.

## What changed after the review

A fresh agent read the change cold (no conclusions given). No crash, spin, lost wake-up or shutdown bug; it found (1) the keepalive ran
for an endpoint the record never lists (symmetric, unknown or open NAT; a router mapping advertised): now `advertises_punch_endpoint`;
this also showed that my end-to-end world classified its cone as `Unknown` (all fake nodes behind gateways on one IP), so the
simulator's gateways keep the peer's loopback alias; (2) the settle timer stayed set when a first public vote displaced two private
ones, ending the round with one vote: now it follows the votes that count; (3) tests: the check that the old port of an expired mapping
is dead was hidden by the filter (a mutant survived: it sends from a peer the new mapping lets in now), nothing pinned that a packet
that arrives does not renew a mapping, nothing pinned the host measuring again when the last relay goes (the `was_wanted` update in
`pause`), the 400 ms lifetime of the simulator tests was a fragile margin (now 600 to 1000 ms), a tick window was one tick too tight,
and one test asserted nothing about the next keepalive; (4) comments: "only a packet that leaves renews", "for logs", "ten minutes".
It also named what stays, above: relays that do not cross the NAT (4), `Unknown` not retried (7), the reply not compared (8), a
round that sent nothing (9).

## Not tested

A real NAT or router (all of it is the simulator, whose only timeout is the one `expiring` makes); the real DHT nodes and what they do
with a ping every 20 s; a NAT that refreshes a mapping on inbound packets too (it would keep the mapping longer, never shorter); sleep
and wake of the computer; IPv6 (the DHT is IPv4); Linux and Android compile.
