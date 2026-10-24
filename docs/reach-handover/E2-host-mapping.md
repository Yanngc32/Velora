# E2 host mapping and public addresses: hand-over for I1, H1, G2 (and E3, E4, E5, the review)

Branch `reach-e2-host-mapping` (from `integration-wave3`, 5c628d7). One source file: `crates/host/src/reach/mapping.rs` (E1's stub
`mapping::run`); no manifest or lock change. `cargo fmt --all --check`, `cargo clippy -p velora-host --all-targets -- -D warnings` and
`cargo test -p velora-host` are green on Windows (309 passed, 0 failed; 5 `#[ignore]`d: two of E1's that need a desktop, two of E3's and
one of E2's that use the network, all run by hand). Linux and Android were not compiled here. The module has 54 tests: 41 on a paused
clock with a fake router and fake network cards, 11 pure ones (the verdicts, `Opinion` with explicit instants, the numbers), 1 in real
time (a stuck thread) and 1 by hand (`on_this_network`, ignored). How it was checked is at the end of this note.

## What it does

While standalone reach is on, `mapping::run` asks the router to forward the UDP port of the QUIC socket (`ctx.port()`, the same external
port when the router allows, so the addresses stored in paired devices stay valid) with `velora_nat::mapping` (NAT-PMP, then UPnP; 3 s to
find the gateway and 5 s per protocol, 10 s at the worst), keeps the mapping and writes three things into `ReachState`, which is all
it touches:

- **`mapping`** (`MappingStatus { protocol: "natpmp" | "upnp", external: "ip:port", public, lease_secs }`): the mapping the router granted.
  The launcher's router line reads it: `public: true` is "port open", `public: false` is "shared address (CGNAT)", and no mapping with
  standalone on is "the router has not opened a port" (G1's reading; there is no field for a reason, the reason is in the log).
- **`Public`** (`set_addresses`): the mapped `ip:port`, and only when it is public. E3 puts it in the DHT record, E1 in `HostMsg::Reach`, E4
  stops looking for a relay once there is one (after its 10 s of grace), and E5 re-measures when it changes.
- **`V6`**: the first global IPv6 address of each interface (`global_ipv6`) with the socket's port, when the socket is bound to `[::]` (the
  dual-stack default; a socket bound to `0.0.0.0` or to one address lists none). Looked at every minute, no router needed, so a PC behind
  a CGNAT with native IPv6 still lists them.

The rules:

- **No router is a state.** The attempt fails after 6 s, `mapping` and `Public` stay empty, and the reason is logged once at info ("no
  router opened UDP port N (NAT-PMP: no answer within 3s; UPnP: no UPnP router answered within 3s): this PC is not reachable from outside
  through the router; asking again in 60s"); the next tries come after 1, 2, 4, 8, 16, 30, 30... minutes, so a tight loop is not
  possible. A router that answers later is found then. A mapping is renewed at half its lease, never more often than every 10 s (a router
  that grants a lease of a second or two is not asked every second), never less often than every 30 minutes.
- **A public address is one that is public.** The router's external address is judged by its class (`classify`) and by the address the DHT
  nodes saw this PC at (`ReachState::observed`, E5's, always a global address). A private address or one from 100.64.0.0/10 is `Shared` (a
  second router, a CGNAT); a public-looking address while the nodes see this PC at another one is `Elsewhere` (a carrier that uses
  public-looking addresses internally is the usual case, a full-tunnel VPN another). Both are the CGNAT or double-NAT case: logged once at
  info, shown with `public: false`, kept and renewed (the user can still forward the port on the outer router), **not advertised**. Only
  IPs are compared (the observation's port is the NAT's choice for the outgoing flow), and an IPv4-mapped IPv6 address is the IPv4 one.
  The nodes' word is weighed, not just obeyed, because E5 writes it on its own schedule and every change of `Public` makes E5 measure again:
  - when they stop saying anything (E5 drops its measurement when a round learns nothing) the verdict stays as it was, also for the same
    external address after the mapping was lost and made again (the memory is cleared only by a change of LAN address): a withdrawn
    address does not come back because one round was silent;
  - when they start to disagree with an address that was public, it is withdrawn at once and the router is asked at once what its address
    is now (a renewal): the provider may have given this PC another one, and the answer is judged anew;
  - the address comes back a minute after it was withdrawn, not before, whatever the nodes say, so that nodes whose answers keep changing
    cannot make `Public` go back and forth faster than once a minute (each change makes E5 measure again, E3 publish again, E4 reconsider
    the relay); the router is asked at most once in that minute too. This holds for a renewal's answer as well as for the nodes' word. A
    different external address (the provider's new one) is judged anew, at once;
  - for the few seconds after a move to another network `observed` can still be the word about the network that was left (E5 measures after
    a 2 s debounce and a round of up to 3 s): a mapping granted then can be taken for "another NAT in front" (not advertised, one info
    line) until E5's new measurement judges it again. If that round is silent and E5 drops the word, a verdict made of the old word does
    not survive the drop; this holds only within 20 s of the move and only while the word has not been measured again (a different word, or
    none): later, and after a new measurement, the word is taken for what it says and silence changes nothing. E2 cannot tell a stale word
    from a fresh one, so it does not ignore it: a first version that ignored an unchanged word could pin a wrong address for as long as E5
    kept getting the same answer, so it was taken out.
- **Renewal** that gives another address or port moves the advertised one. A renewal that gets no answer (30 s at most) or is refused
  withdraws `mapping` and `Public` at once (the router probably restarted or the PC is elsewhere) and a new mapping is asked for after a
  minute, with the backoff above. A grant of port 0 is a failure, not an address.
- **A move to another network** (the LAN address E1's housekeeping keeps changed, within its 30 s): the old address is withdrawn at once and
  a new mapping is asked for without waiting, with the backoff reset. The old mapping is **not** given back: the request would go to the
  router of the network this PC is on now, which may hold a port of the same number for another computer (UPnP names no owner); the old
  router drops it when the lease ends. A LAN address that goes away withdraws everything and nothing is asked until one comes back.
- **A machine that slept** (the monotonic clock stops in a suspend; each look compares it with the wall clock) renews at once, or asks
  again at once with the pauses reset when there was no mapping.
- **Stop** (switch off, shutdown): `mapping` and `Public` are withdrawn first; then the task looks at the network again (E1 looks every
  30 s, so a move in the last half minute is not in the state yet) and, if this PC is where the mapping was made, gives it back, for at most
  3.8 s (the host waits 4). If the network changed it gives nothing back, for the reason a move does not. Everything the task wrote, `V6`
  too, is taken out of the state whether the task returns or is aborted. A router that does not answer the removal in time, or a stop
  that comes while a mapping is being asked for, leaves the mapping to its lease (an hour; a router that keeps only permanent mappings
  keeps it until the next run asks for the same port again).
- **A host that is not bound to every address maps nothing and lists nothing** (logged once at info). B1 forwards to this PC's address
  towards the router, which a socket bound to one address (the loopback, a Hamachi or Tailscale address, a second card, one IPv6
  address) may not take packets for, and an advertised address nobody listens at would keep E4 from looking for a relay. This is also what
  keeps the `Runtime` tests of other modules, which switch standalone reach on with a loopback host, off the router of whoever runs them.
- **The IPv6 walk through the network cards** runs off the async threads and never twice at once. A look that gives up on it after 30 s
  leaves it running; the next looks return "not known" at once (what is listed stays) until it ends, and the first one after that takes
  its answer. A walk that never comes back costs one thread, not one a minute, and holds up nothing but its first look (30 s).

## What the other tickets must know

- **I1 (field test).** "Reachable at pub:..." on a real network is left to it. By hand: `cargo test -p velora-host -- --ignored
  --nocapture on_this_network` asks the real router for the port of a throwaway socket for 15 s, prints what the task found with the
  library's and the task's log lines, and gives the mapping back. On the author's line (CGNAT, neither UPnP nor NAT-PMP): "no router
  opened UDP port N" after 6 s, `mapping None`, no public address, no IPv6 (the only global-looking address is Hamachi's, a manual one that
  `global_ipv6` leaves out), and the task ends at once when told to. What I1 must try: a line with a UPnP or NAT-PMP router that has a
  public address (expected: `public: true`, the address in the DHT record and in `Status.reach.public`); a router that answers and sits
  behind a CGNAT (expected: `public: false`, shared address, nothing advertised); a router whose external address is public-looking but
  differs from what the DHT nodes see (expected: `public: false` once E5 has measured, and the relay registration of E4 after that); a
  laptop carried between two networks with routers that answer (expected: the new address within seconds, `public: true` once E5 has
  measured the new network).
- **G2 / the launcher.** Nothing to change: `mapping`, `public` and `v6` of `Status.reach` are filled as G1 reads them.
- **E3.** The `Public` entry reaches the record when the mapping is public. A mapping that is not public leaves `Public` empty, so the
  record lists E5's observed endpoint as `Public` when the NAT is a cone, as before.
- **E4.** `needs_relay` sees `Public` empty both while the first mapping is being asked for (up to 10 s, its grace) and when no router
  answers: a PC with no router goes to a relay. A `--bind <one address>` host never has `Public`, so it goes to a relay as well.
- **E5.** E2 reads `observed` (to demote a mapping, see above) and never writes it. E5's `network_signature` includes `Public`, which only
  ever repeats `mapping.external`: E2's verdict changes (the mapping stays, `Public` goes) make E5 measure again, and a round that learns
  nothing drops the observation. E2 is built to be steady under that: a silent round changes nothing, and nodes that keep changing their
  answer move `Public` once a minute at most. Dropping `Public` from the signature would remove the feedback; see the findings.

## Decisions to review

1. **The loopback gate became a bind gate.** `run_on` maps only for a socket bound to the unspecified address (`0.0.0.0` or `[::]`); the loop
   (`serve`) is tested directly, with the socket's address as a parameter, so the IPv6 cases need no dual-stack machine. A host the user
   bound to one LAN address on purpose loses the automatic mapping (bind to every address, or forward the port by hand): B1 cannot be
   told which address to forward to, and E1's `Lan` for a specific bind is that address, not the one facing the router.
2. **A move does not give the old port back**, and withdraws the old address first: a laptop that changes network must not keep
   advertising the old public address while the new mapping is asked for. The stop looks at the network again for the same reason.
3. **`observed` decides both ways, with the guards above.** The false negative is a router with two uplinks whose mapped address is not
   the one the PC's own traffic leaves from: the mapping would work and is not advertised; the PC falls back to punch and relay, the safe
   side (a stale public address costs every client a failed attempt and keeps E4 from registering with a relay). The observation is
   DHT-only and IPv4-only, so a PC with no DHT, or none measured yet, is judged by class alone.
4. **Withdrawn at once, back after a minute.** Demoting is the safe direction and is never delayed; promoting waits a minute after the
   last demotion. A legitimate recovery (a VPN switched off) is therefore up to a minute late; the price of not flipping in step with E5.
5. **The transient after a move is accepted** (see above) rather than guessed at: the ways to guess (ignore the old word for a while,
   ignore it while it does not change, ask E5) are either wrong for same-network address changes (a dock, a new DHCP lease, a VPN that
   reconnects keep the exit address, and the old word is then true) or need E5's cooperation. The one guess kept is the 20 s rule above,
   which only decides what a silent round means, and whose worst case is one wrongly advertised address until E5 next answers.
6. **Withdrawn on a renewal that fails**, even though the lease may still run: a stale public address costs every client a failed attempt, a
   withdrawn one costs a minute.
7. **IPv6 is listed only for a socket bound to `[::]`.**
8. **No limit on how often the LAN address may change**; each change costs one request (and no removal), and E1's housekeeping looks every
   30 s.
9. **The stop waits 3.8 s for the removal**, not 3: B1 finds the router again for every removal (SSDP with a 3 s timeout, and
   `igd-next` asks routers to delay their answer up to 3 s), and the host gives tasks 4 s. A task that is still waiting then is aborted,
   which is harmless (the state is cleared by a guard).

## Not done, not tested

- A real router (UPnP or NAT-PMP) and a real CGNAT with a router that answers: fake routers only (B1 tested its own side with fake routers
  on loopback). That is I1.
- A move to a network that gives this PC the **same LAN address** (two home networks on 192.168.0.x with the same host number) is not seen
  until the next renewal, at most 30 minutes, and a stop in that time gives the port back to the new router (see the B1 finding). E5's
  next measurement, when it differs from what the old mapping says, withdraws the address and asks the router again at once.
- Nodes whose answers keep alternating (a router with two uplinks balanced per flow): `Public` still goes and comes about once a minute,
  with two info lines each time, until E5's signature stops including `Public` (the damping bounds it, it does not end it).
- Residuals of the nodes' word that were seen and left: (a) after the provider re-assigns the address, a renewal that returns the new
  one before E5 has measured again can be called "another NAT" (the old word names the old address) until E5 answers: withheld, the safe
  side; (b) an agreement seen during the quiet minute is forgotten if E5 drops its word before the minute ends, and comes back at E5's
  next answer; (c) a silent E5 round within 20 s of a LAN change on the same network (a dock, a new lease) can un-stick a true
  "another NAT" once: the address is advertised until E5 next answers; (d) if `observed` was empty when a move was noticed and a round
  that straddled the move writes the old network's word afterwards, that word is not doubted.
- A stop that comes while a mapping is being asked for (the mapping, if the router made it, stays until its lease ends), and a router that
  does not answer the removal in time.
- A real suspend (the detection is tested with a wall clock that jumps); Linux and Android compile; the wording of the logs is not asserted
  (that each thing is logged once is, by a process-wide capture).

## Findings outside E2's file (for the coordinator)

- **E5, `punch.rs::network_signature`** includes `Public` along with `mapping.external`. `Public` only repeats the mapping's address, so
  it adds nothing, and every time E2 changes its mind about a mapping E5 measures again (and drops its result if the round is silent).
  Dropping `Public` from the signature (keeping Lan, V6 and `mapping.external`) removes that feedback. Optionally E5 could also publish
  when its `observed` was measured (a counter or an instant): then E2 could tell a word about the old network from a fresh one after a
  move, and the transient above would go.
- **B1, `mapping::remove`** finds the router again for every removal (a stop may time out), and UPnP deletes by external port only, so a
  stale removal on another network can delete another host's forwarding of the same port. Keeping the router's address and the internal
  client in the `Mapping`, and checking `GetSpecificPortMappingEntry` before `DeletePortMapping`, would settle both. Also: an
  `AddAnyPortMapping` answer of port 0 is not rejected (E2 treats it as a failure).
- **E3, `dht::run`** opens a real DHT node in every `Runtime` test that switches `dht` on, with no gate (the bind gate of E2 is the model:
  when the socket is not bound to every address, set `dht_key`, wait for stop and open nothing), so those tests join the real mainline DHT
  from the machine that runs them.
- **E1, `reach/mod.rs`**: the test `setting_the_switches_saves_them_and_starts_the_tasks` still says "The hooks are still stubs". Its
  shared `testing::context()` binds with `expect`: one run of 30 failed there with Windows error 10055 (no buffer space) while other
  sessions were building.
- **E1, `service.rs::migrate_state`** does not copy `dht_key.bin`, `reach_secrets.json` or `reach.json` (already in the E3 note).

## How it was checked

- `cargo fmt --all --check`, `cargo clippy -p velora-host --all-targets -- -D warnings` and `cargo test -p velora-host` (309 passed, 0 failed,
  5 ignored); no line of code over 120 columns.
- 30 runs in a row of the 267 `reach::` tests with the final test binary: no failure. (An earlier run of 30, on older code, lost one run to
  Windows error 10055 in E1's `testing::context()`, see the findings.)
- 66 mutations, each a defect put back into the code one at a time (the verdicts, the pauses, the lease arithmetic, the bind gate, the stop
  path, the single-flight walk, the quiet minute, the memory of verdicts and of the old word, the sleep detection...): every one makes
  some test fail. Two of them (a renewal whose answer is not used, a PC with no network) make the tests hang, which is how a tight loop
  shows. The one that first survived (the sleep noticed again at every look) led to two assertions being added.
- Five independent read-only reviews by separate agents, each asked to find defects and not to confirm; every finding was checked against
  the code before anything changed. In order they found: (1) the DHT nodes' word could not withdraw a public-looking address, the old mapping
  was given back to the router of the new network after a move, and the address was advertised while the removal was awaited; (2) the
  nodes' word was not sticky (one silent E5 round brought a withdrawn address back) and the stop could remove a port on the wrong network,
  a host bound to one address was given a port nobody listens at, a stuck adapter walk leaked a thread a minute, a lease of a second was
  renewed every second, and the IPv6 tests passed vacuously where there is no dual-stack socket; (3) the first guard against the old
  network's word could pin a wrong address for good, the verdict was forgotten when a mapping was lost, and nodes that alternate made
  `Public` flip in step with E5; (4) a verdict made of the old word could stick after a failed round, the one-minute damping did not apply
  to a renewal's answer, and a finished walk's answer was thrown away; (5) the old word was doubted for ever and by its address alone.
  The decisions and residuals above are what is left of them.
