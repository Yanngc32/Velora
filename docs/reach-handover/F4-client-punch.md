# F4 client punch dialer: hand-over for I4, H1 (and F2, G2, E5, the review)

Branch `reach-f4-punch-dialer` (from `integration-wave3`, cf92511), commit c72410b. One file:
`crates/client-core/src/reach/punch.rs`, which F1 left as a stub; the frozen signature `dial_punch(&ConnectParams, SocketAddr,
&[RelayRef])` is unchanged. 36 new tests in that file (104 in the crate); `cargo fmt --all --check`, `cargo clippy -p
velora-client-core --all-targets -D warnings` and `cargo test -p velora-client-core` are green on Windows, `cargo check -p
velora-mobile` compiles. The new tests ran 30 times in a row, 5 times on one thread and 5 rounds of two copies at once, with no
failure. Linux and Android were not compiled here. I broke the code on purpose 57 times, in two rounds (22 before the review
below, 35 after it) (the redial and the cap on attempts, the NAT type, the votes, the waits and what they count from, the endpoint
told, the nonce, the socket observed, the certificate pinned, the relay asked and how many and how soon, the seq raised, the
republish, STUN asked or not...): each made a test fail (several needed a test added first). No packet left the loopback: the DHT
nodes, the STUN server, the relay (D2's `Relay` core behind the link protocol of E1), the host and both NATs of the tests are
sockets of the tests. A fresh agent read the module cold after the first version and found seven defects, all fixed (the last
section says which).

## What a dial does (`dial_punch`, called by the race for a `Candidate::Punch`)

1. **Refuses what can never work, before touching the network**: an endpoint that is not IPv4, or no relay in `via` and no secret in
   `params.reach.host.secret` (nobody could be asked).
2. **Observes**: binds one UDP socket and asks DHT nodes (B2's `observe_dht`) which endpoint the NAT shows *for that socket*, in
   `spawn_blocking`; the whole observation, names included, ends after 10 s. Votes that say a private address are dropped at once
   (S0 saw 2 in 136; one would make a cone NAT read as symmetric); STUN is asked only when fewer than two servers *on the internet*
   told; with no vote left the NAT sits behind another one ("another NAT is in the way"). `Dependent` (symmetric) ends the dial;
   `Unknown` (fewer than two servers told) goes on.
3. **Asks the host to open its NAT** toward that endpoint, and dials the host's endpoint from the same socket at the same time:
   - `via` not empty: `ClientMsg::PunchRequest { to: host, endpoint, nonce }` through the relays, each relay `RELAY_STAGGER` after the one
     before and a second address of the same relay `RELAY_ADDRESS_STAGGER` (F1's, 2 s) after its first, at most `MAX_RELAYS` addresses;
     the first `RelayStatus` ok ends the asking. A relay that does not answer, does not know the host or refuses is skipped. The `Link`
     is dropped as soon as the relay says ok (it has queued the message on the host's connection).
   - `via` empty: a punch item in the DHT (C3's `build_after`, signed with the key derived from the secret) through a `Node` of this
     device's own (`Mode::Client`, cache `dht_cache.txt` in `ReachParams::state_dir`), published again every 30 s with a fresh `ts`
     and the same nonce (the host ignores a request a minute old; a nonce it served is served once, so a repeat costs it nothing).
     The `seq` is above every one this process published for that key (a process-wide table: two dials in one second, or a retry
     while the item of a dropped dial is still being stored, must not share one) and above what the DHT says it holds. A failure that
     may pass (`NoNetwork`, `Refused`, `TimedOut`, `Stopped`, `Socket`) is tried again after 2 s, at most 3 tries; anything else ends it.
4. **Dials**: a new connection attempt every second (`REDIAL`), at most 4 alive (the oldest is dropped). One attempt retransmits its
   Initial at 0, 0.15, 0.45, 1.05, 2.25, 4.65 and 9.45 s (`initial_rtt` is 50 ms in `tls::transport_config`), so a hole that opens at
   5 s would wait until 9.45 s for it; fresh attempts keep a packet leaving every second, which also keeps the client NAT's mapping
   alive. The first handshake wins and the endpoint and connection are returned. A transport error found locally (in practice a
   certificate that is not the pinned one: the peer is not the host, a stale record) ends the dial at once; a refusal by the host
   arrives as a close and is retried.
5. **Ends** `RELAY_WAIT` (10 s) after a relay passed the request on, `DHT_WAIT` (60 s) after the item is in the DHT, `GRACE` (3 s)
   after the request could not be delivered (an open NAT still answers within a round trip, nothing else can), and `ASK_LIMIT` (30 s)
   after it began if the asking itself does not end. The error says which: "the request was delivered in the DHT, and the host did not
   open its NAT within 60 s" / "could not be delivered through a relay: the relay at ...: the relay refused: ..." / "was still on its way".

Dropping the future ends everything but two things, soon: a blocking observation in progress (within its waits and the resolver's)
and a publish the node already has under way on its own task, which may still land (the host then punches toward an endpoint this
device no longer listens at, and its attempt ends by itself in 12 s).

## Constants (I4: each in one place, `Timing::DEFAULT` and the `const`s above it)

| | value | why |
|---|---|---|
| `RELAY_WAIT` | 10 s after delivery | the host punches when the relay's message reaches it (its attempt lasts 12 s) |
| `DHT_WAIT` | 60 s after delivery | the host looks every 45 s per device and a look may take 6 s (E5), then the handshake |
| `ASK_LIMIT` / `GRACE` | 30 s / 3 s | see 5. above |
| `REDIAL` / `MAX_LIVE` | 1 s / 4 | see 4. above |
| `REPUBLISH` | 30 s | the host drops a request older than 60 s, and a publish takes seconds to be found |
| observation | 3 s per phase, 10 s in all | `observe::DEFAULT_WAIT`; it returns early on 3 answers or 400 ms after the second server |
| relay waits | connect 3 s, welcome 3 s, `Reach` 2 s, answer 3 s | tighter than `Waits::DEFAULT` |
| `RELAY_STAGGER` / `MAX_RELAYS` | 250 ms / 4 | as F3's wake |
| `MAX_PUBLISHES` / `PUBLISH_RETRY` | 3 / 2 s | |

## Decisions to review

1. **A connect that nothing else reaches reports its failure late** when a punch is in the race: F1's race ends only when every
   candidate has ended and has no timeout of its own for a dial. Through the DHT that is the time to publish (a few seconds) plus
   60 s, and up to 90 s when the publish is slow (`ASK_LIMIT` + 60 s). 60 s after delivery is what the host's polling needs; a request the
   host would have served at its next look fails if it is cut shorter. G2 may want a line for a long wait.
2. **Relays or the DHT, never both.** A host registered with a relay does not poll the DHT (E5), so a request published there is
   not read; and a relay that fails is not followed by a publish. A record that lists a relay the host has left costs the dial.
3. **Symmetric is not tried, unknown is.** The ticket says to skip symmetric; with fewer than two servers' answers nothing says it
   cannot work, and a try costs one request and some packets. `Open` (no NAT in front) goes on too.
4. **Private votes are dropped before anything is decided from them.** B2's classification calls any disagreement symmetric and its
   `observe` decides about STUN on what it was given, and S0 found private addresses among the votes (nodes inside a provider's
   network). E5's host side classifies what B2 gives it, so it has the exposure the client had: a private vote makes a cone NAT read as
   symmetric and the host does not list its endpoint until the next measurement (10 minutes). Filtering the votes before
   `Observed::new` (as `observe_votes` here does) is the fix there too, if you want it.
5. **IPv4 only**: the DHT that tells this device its endpoint is. An IPv6 `endpoint` ends the dial at once (`Candidate::Punch` should
   not carry one; a global IPv6 host is a `Direct` candidate).
6. **The STUN fallback is on**: when fewer than two DHT nodes on the internet answer, B2's STUN code asks Google's and Cloudflare's
   servers (its defaults), and their names are resolved only then. The host side cannot (no sans-IO STUN). `Env::stun = Some(vec![])`
   turns it off, if a third party must not see the device.
7. **One DHT node per dial, with its cache in `dht_cache.txt`** beside `identity.json`: the name F2's and E3's work in progress use too
   (read in their worktrees, not merged yet), so the nodes of one device share a cache; C2 keeps two nodes on one file apart (it
   reads before it writes). The name is one `const`.
8. **The nonce comes from rustls's random generator** (`quinn::rustls::crypto::ring`): client-core has no `ring` and the ticket does not
   own its `Cargo.toml`.
9. **The test seam is `dial` and `Env`** (nodes, STUN, the DHT, the table of seqs, the waits, whether a loopback endpoint is fine).
   `dial_punch` itself is `dial` with the real `Env`; what it does before the network (the IPv6 and no-way-to-ask refusals) is tested
   through it, the rest needs the internet.
10. **One punch per host at a time through the DHT**: the item lives in one slot per (host, device), so a second dial to the same host
    (a session and a files window at once) replaces the first one's request, and the host punches toward the endpoint of whichever
    it reads. The seqs make the newer one win; the older dial then waits in vain. A relay path has no such limit.

## What the others must know

- **F2** (`resolve_record`) proposes the punch: `Candidate::Punch { endpoint, via }` only for a host whose record says `Open` or `Cone`
  and lists a public endpoint, with `via` the relays the record lists (empty: the DHT path, which needs `host.secret`; without it and
  without a relay the dial ends at once). The race starts it `PUNCH_DELAY` (2 s) after the first direct address.
- **E5 / I4: the host's endpoint may be stale.** The host measures the endpoint of its QUIC socket every 10 minutes (E5, `Timing::refresh`)
  and, with no session and no relay, sends nothing from that socket in between; the DHT node and the host's other sockets map
  differently. A NAT that gives the socket another external port when it makes the mapping again (many carrier NATs; a router that keeps
  the source port, like the author's, does not) leaves the record's endpoint wrong by the time a client punches, and the dial then
  fails after its wait with "the request was delivered ... and the host did not open its NAT". A keepalive from the QUIC socket while
  an endpoint is advertised would hold the mapping; I4 should measure how long the mapping of a real router lasts.
- **I4**: what a failed punch says is in the debug log, one line each: `the NAT shows this device at <endpoint> (<type>)`, `the host could
  not be asked ...`, `an attempt toward <host> failed`. `the request was delivered in the DHT, and the host did not open its NAT` means
  the host's side is where to look (its log says `opening a hole toward ...` when it heard); check the clocks of both when the host log
  says a request was dated ahead (`FromTheFuture`, more than 10 s) or old (more than 60 s). End to end against a real host needs E3
  (the host's secret and record) and E4 (a relay that relays): both were stubs in this branch.
- **H1**: a connection that can only be made by punching through the DHT takes between a few seconds and about a minute; with a relay
  the host is registered with, a few seconds. Networks with a symmetric NAT (some mobile carriers and company networks) cannot be
  punched and need a relay. When fewer than two DHT nodes on the internet answer, two public STUN servers are asked.

## Gotchas

- **Several handshakes can complete** when the hole opens (each live attempt's Initial gets through): the client keeps the first and
  drops the others, so the host sees up to 4 connections from the device and all but one end at once without a hello (the host takes a
  session over only after the hello).
- **The host's punch Initial meets a client-only endpoint**, which quinn-proto answers with a stateless reset instead of silently
  dropping it (E5's note says dropped). The host's connection-id check discards that reset, so nothing loops.
- **Shared mode** (C1: more devices than fit in a record): every device holds the same secret and so the same punch slot; a request
  replaces another's, and the host stands the first device by fingerprint for the group (E5, decision 7), so its own attempt ends when
  its time is up (12 s) and not when this device arrives.
- **Relay flows** (D2: 6 at once, then one per 5 s per device, shared with `RelayTo`, `Wake` and `RelayRegister`): a dial takes one for
  each relay it asks, so up to `MAX_RELAYS` when the first ones are slow or refuse (a second address of one relay is asked only 2 s
  after its first), and the host takes one `PunchRequest` per device every 10 s after the fourth (E5).
- **The first DHT node of a process may bring a Windows firewall prompt** (C2).
- **Client and host behind the same NAT** (hairpin) are not handled: the observed endpoint is the NAT's own.
- **The DNS lookups of the observation block** in the system resolver, which has no limit of its own: the dial gives up on the
  observation after 10 s, the lookup ends in its thread later and takes the socket with it.

## What changed after the review

A fresh agent read the module cold (no conclusions given) and found, besides risks outside it (the stale host endpoint above, the
reset, E3 and E4 being stubs) and wrong comments (fixed): (1) on the DHT path 60 s counted from the start of the dial, not from the
moment the item was in, and the item was never refreshed, so a slow publish (a cold node, a second put round, a retry) made the
host's next look fall after the dial or past the item's 60 s, silently: the wait now counts from the delivery, and the request is
published again every 30 s; (2) a request that could not be delivered still dialed for the whole wait: now 3 s of grace; (3) two dials in
the same second published the same `seq`, and the nodes keep the first: the process-wide table; (4) the waits of one relay (11 s) were
longer than the 10 s window, and a slow relay could deliver too late to matter: the window counts from the delivery now; (5) the
observation resolved the STUN names every time, decided about STUN before dropping private votes, and had no overall limit; (6) several
addresses of one relay each took a relay flow: a relay's addresses are asked 2 s apart now.

## Not tested

A real NAT and the real DHT (`OwnNode` is `Node::open` and `Node::publish`, tested in C2); IPv6; Linux and Android compile; `dial_punch`
against the public network (what it does before touching it is tested); a NAT that keeps the mapping of a socket for a short time only
(the simulator has no mapping timeouts) or rewrites ports in other ways than the two it knows; the system resolver.
