# Reaching a PC from anywhere without a server: plan and feasibility study

Status: proposal, October 2026. Nothing here is implemented yet.

## 1. Goal

A client should reach a paired host from any network, the way it does over Tailscale today,
without installing a mesh VPN and without anyone running a server for Velora: not the
project, not the user.

Out of scope: a general-purpose VPN. Velora only needs one thing, that a QUIC packet reaches
the host's UDP port. Everything else (authentication, encryption, sessions, files, sound)
already works end to end over any path.

## 2. The constraint that shapes everything

Two computers behind different NATs cannot find each other with nothing in between: neither
knows the other's public address, and neither NAT lets a packet in that it did not see go
out. Every "serverless" system (BitTorrent, Hyperswarm, Yggdrasil, Tailscale's own direct
connections) relies on a third party that both sides can reach. The question is only who that
third party is. The options, from least to most dependent:

| Third party | Who runs it | Cost to the user | Availability |
|---|---|---|---|
| The user's own router (UPnP / NAT-PMP / PCP) | nobody | none | most home routers; not CGNAT |
| Public STUN servers | Google, Cloudflare, Twilio... | none, no account | reliable, but a dependency on a stranger |
| The BitTorrent Mainline DHT (millions of nodes) | nobody | none, no account | reliable for ~20 years; any node can read what you store unless it is encrypted |
| Another of the user's own paired PCs | the user | none | only if that PC is itself reachable |
| A self-hosted relay (`velora-relay`) | the user | a VPS | optional, last resort |
| A Velora-run coordination server | the project | none | **rejected**: the thing we want to avoid |

The plan uses the first four, in that order, and leaves the fifth as an opt-in.

## 3. What exists today

- Transport is QUIC (quinn 0.11) over UDP 7420, mutual TLS 1.3, the host's certificate pinned
  by fingerprint. Any path that delivers UDP works; nothing on the path can read or alter
  anything.
- The host already advertises several addresses (LAN, Tailscale, Netbird) in the pairing link
  and in every welcome; the client stores them and, on connect, races them all, the first to
  answer wins (`client-core::hosts::connect`, `host::server::reachable_addresses`).
- Identity is an rcgen self-signed certificate; there is no separate signing key.
- Clients that predate a field in the link or the welcome skip it. New address kinds can be
  added without breaking old clients.

Everything below is "more addresses in the race" plus, for the hard cases, a way to make an
address work.

## 4. Options evaluated and rejected

**Embed WireGuard (a Tailscale-like mesh).** Would need a TUN device (driver install on
Windows: Wintun, admin rights), IP allocation, routing, and the same coordination problem on
top. Velora doesn't need an IP network; it needs one UDP flow. Rejected.

**libp2p / iroh.** Both solve exactly this (hole punching, relays, DHT discovery) and are
Rust. iroh in particular is excellent, but its discovery and relays run on n0's servers by
default; running without them means self-hosting, which is the thing we are avoiding. Both
also bring a large dependency tree and their own transport, replacing quinn. Rejected for now;
iroh's design (ALPN over QUIC, relay as fallback) is the model to copy.

**WebRTC ICE (`webrtc-ice`).** Mature hole punching, but assumes a signaling channel that the
application provides, i.e. a server. The ICE logic itself is small enough to reimplement for
one UDP flow. Rejected as a dependency; its ideas are used in phase 3.

**IPv6 only.** Where both sides have public IPv6 (common on fibre in Brazil), no NAT exists
and a direct connection just works, after the firewall allows it. Not sufficient alone (many
networks are v4-only, phones on carriers vary), but free to add: phase 1 advertises IPv6.

## 5. Architecture

```
 client                                             host
 ┌──────────────────────────┐                      ┌──────────────────────────┐
 │ resolve: stored addrs    │   1. LAN / VPN       │ advertise:               │
 │ + DHT item of the host   │ ───────────────────▶ │  LAN, VPN (today)        │
 │                          │   2. public:7420     │  public IP + port (ph 1) │
 │ race every address;      │ ───────────────────▶ │  router mapping (ph 1)   │
 │ first handshake wins     │   3. hole punch      │  DHT item (ph 2)         │
 │                          │ ◀───────────────────▶│  punch on request (ph 3) │
 │                          │   4. via relay PC    │                          │
 │                          │ ──────▶ relay ──────▶│  (ph 4)                  │
 └──────────────────────────┘                      └──────────────────────────┘
```

Paths 1-2 are plain addresses. Path 3 needs both sides to act at the same moment, so it needs
a signal; the DHT carries it. Path 4 needs a third machine; another paired PC that path 1 or 2
reaches plays it.

## 6. Phases

### Phase 1: the router opens the port, and the host says its public address

What: at start, and every 30 minutes, the host asks the gateway to map UDP 7420 to itself
(PCP first, then NAT-PMP, then UPnP IGD; `pcp-client`, `natpmp`, `igd-next`), and learns its
public IPv4 (the mapping reply gives it; STUN as fallback) and global IPv6 addresses. Those go
into `reachable_addresses`, so into the link and every welcome. The mapping is removed on exit.

Covers: a laptop away from home when the home router supports any of the three protocols
and the ISP gives a public IPv4 or IPv6. In Brazil, fibre providers increasingly use CGNAT
for v4 but give public v6; both cases are handled when the client's network has v6 too.

Does not cover: CGNAT without v6, routers with UPnP off (common in company networks), an IP
that changes while the client is away (the client only learns addresses when it connects).

Cost: small. One PR in the host (~400 lines), a `public` entry in "This PC" so the user sees
it worked, a line in the README. No protocol change: addresses are strings already.

Risks: UPnP implementations vary; some routers accept the mapping and drop it. Mitigation: the
host checks its own mapping from outside once (a STUN-observed send to itself is not possible;
instead rely on the first client connection and log it) and re-requests on failure.

### Phase 2: finding the host when its address changed, without a server

What: the host publishes a signed, encrypted record in the Mainline DHT (BEP 44 mutable item,
crate `mainline` 8.x, which also implements BEP 42 and reports the node's observed public
address, so STUN becomes unnecessary):

```
key   = ed25519 public key of the host (new, stored next to the identity)
salt  = "velora/1"
value = encrypt(mesh_secret, { seq, addresses: [...], nat: cone|symmetric|open, ts })
```

The client learns the host's public key and the `mesh_secret` from the pairing link (two new
query parameters, ignored by old clients) and, on connect, fetches the item (1-3 s on a warm
DHT) and adds its addresses to the race. The host republishes every 30 minutes (items expire
in about 2 hours on most nodes) and whenever an address changes.

Why a new key: the TLS identity is an rcgen certificate; BEP 44 needs an ed25519 key to sign
items. The public key is derived into the DHT target, so only someone who knows it can even
find the record, and only someone with the `mesh_secret` can read it. The host's certificate
fingerprint is included in the value, binding record to identity.

Covers: dynamic IPs, and later phases' signaling.

Does not cover: reaching the host when no mapping exists; that is phase 3.

Cost: medium. New dependency (`mainline`, ~1 MB, pure Rust, tokio), ~30 lines in the pairing
link format, a `dht.rs` in the host and in client-core, identity gains a key pair (`ed25519-
dalek` or ring's Ed25519, which the workspace already has). One or two PRs.

Risks:
- The DHT is public: a record's existence leaks that "some Velora host" exists at that key; its
  content does not. Acceptable; documented.
- Some networks block UDP to random ports (the DHT uses 6881 and friends); then discovery
  falls back to stored addresses. Corporate networks will often block it.
- `mainline` runs a DHT node: a few hundred UDP packets per minute, ~2 MB of routing state.
  Run it in client mode (read-only, BEP 43) to keep that small.

### Phase 3: hole punching

What: when the host has no working mapping (CGNAT, UPnP off), both sides still have a public
endpoint through their NAT; the trick is to make both NATs see outgoing packets to the other
before the incoming ones arrive. ICE calls it simultaneous open.

Signaling without a server: the client publishes its own BEP 44 item ("I want to connect to
host H from endpoint E, nonce N", encrypted with the same mesh secret). A sharing host polls
the items of its paired clients: every 10 s while sharing, every 2 s for five minutes after a
client was last connected. On seeing a request, the host sends packets to E and the client to
the host's endpoint; the first QUIC Initial to get through completes the handshake.

Sending the punch from the host's listening socket needs no raw access: `Endpoint::connect`
to the client's endpoint sends an Initial from the same port, which is enough to open the
NAT mapping (the connection attempt is dropped once the client's own connection arrives).
Alternatively quinn's `AsyncUdpSocket` lets the host send arbitrary datagrams from the
socket; both paths are available in quinn 0.11.

NAT types (RFC 4787): endpoint-independent mapping (most home routers, phones on many
carriers) punches reliably. Address-dependent mapping (symmetric NAT: some corporate and
carrier NATs) does not: the port the other side sees differs from the one it should send to.
Port prediction helps on some; otherwise phase 4.

Covers: most home-to-home and phone-to-home cases without any router setting.

Cost: medium to large. A `punch.rs` on both sides, NAT type probing (two STUN/DHT
observations from one socket), the polling schedule, timeouts (give up after 8 s and move to
the relay). Latency from "connect" to picture: 3-15 s cold, 2-4 s warm. One PR plus a fixes
PR after real-world testing.

Risks: the hardest part to test; needs at least three networks (two different NATs and a
phone on 4G/5G). Each failure mode needs a clear message in the client ("the PC's network
doesn't let connections in; set up a relay").

### Phase 4: relay through a machine the user already has

What: any paired device that is itself reachable (phase 1 or 3 succeeded for it) can forward
UDP between two others. The relay sees only QUIC ciphertext and accepts traffic only between
devices on its paired list. It costs that machine upload bandwidth (a 1080p session is 6-12
Mbit/s), so it is off by default and a switch on "This PC" ("Let my other PCs connect through
this one").

How the client learns about relays: each host's DHT record (phase 2) lists the devices that
offered to relay for it, with their addresses. The client connects to the relay with a
"relay to H" hello; the relay opens a UDP flow to H and copies datagrams both ways. QUIC's
own retransmission handles loss; no reliability is added at the relay.

Optional `velora-relay`: the same code as a standalone binary for people with a VPS, with a
paired list and nothing else. No accounts, no registry, not run by the project.

Covers: symmetric NATs and double CGNAT, as long as one of the user's PCs is reachable.

Cost: medium. A relay task in the host (~300 lines), a hello variant, address kind "relay" in
the race, the switch. One PR.

Risks: the relay PC's upload link becomes the bottleneck; a laptop on Wi-Fi may relay at 2
Mbit/s. The adaptive bitrate already handles that, at the cost of picture quality.

## 7. Protocol and compatibility

- Pairing link: `velora://pair?address=..&code=..&also=..` gains `key=<ed25519 pub>` and
  `mesh=<secret>`; old clients ignore unknown parameters (already true).
- Welcome: addresses already carry strings; a kind prefix is added (`lan:`, `vpn:`, `pub:`,
  `relay:<device>`) so clients can order and explain them. Old clients see unknown prefixes as
  plain addresses; they must still parse as `ip:port`, so the prefix goes in a new field
  rather than the string: `HostMsg::Welcome.addresses` stays, a new optional `kinds` follows
  it, like `addresses` followed `features`.
- Hello: a `relay_to` variant for phase 4. Hosts that predate it reject the hello, which the
  client reads as "no relay here".
- Nothing in the DHT or on a relay is trusted: the client still pins the host's certificate
  and the host still checks the client's. A fake DHT record can only point a client at a
  wrong address, where the TLS handshake fails.

## 8. Security and privacy

- End-to-end security is unchanged: mutual TLS 1.3 with pinned certificates over any path.
- The host accepts UDP from the whole internet once a mapping exists. It already does when a
  user forwards the port by hand; quinn drops anything that is not a valid handshake for its
  certificate before any application code runs. The access password remains available for
  defence in depth.
- DHT records are signed (nobody can replace a host's record) and encrypted with a per-host
  secret shared at pairing (nobody can read the host's addresses). Revoking a device cannot
  take the secret back; rotating it means re-pairing. Document that.
- The relay must verify both devices against its paired list before copying a byte, and rate
  limit new flows, or it becomes an amplifier.
- No telemetry: nothing is reported to anyone. The DHT sees a key and a blob.

## 9. Feasibility verdict

| Phase | Feasible | Confidence | Why |
|---|---|---|---|
| 1 Router mapping + public address | yes | high | mature crates, no protocol change, the address race already exists |
| 2 DHT record | yes | high | `mainline` implements BEP 44/42 today, used in production by pkarr/pubky |
| 3 Hole punching | yes, for cone NATs | medium | standard technique; signaling through the DHT is unusual but sound; testing is the cost |
| 4 Relay via own PC | yes | high | plain UDP forwarding; the hard part is UX (bandwidth, the switch) |
| Symmetric NAT on both sides, no reachable PC | no | — | needs a relay someone runs; `velora-relay` on a VPS is the answer |

Expected coverage for the user's own case (laptop away, Windows PC at home on a residential
fibre connection): phase 1 alone very likely solves it (UPnP on the home router, or public
IPv6 on both ends). Phases 2-3 make it survive IP changes and routers with UPnP off. Phase 4
covers whatever is left, as long as one of their machines is reachable.

Tailscale stays supported and stays the better choice where it is already installed: it has
relays worldwide and handles every NAT. This plan removes the requirement, not the option.

## 10. Order of work and effort

| Step | Deliverable | Estimate |
|---|---|---|
| 1 | Router mapping, public v4/v6 in the race, "This PC" shows the public address | 2-3 days |
| 2 | ed25519 key in identity, link parameters, DHT publish/resolve, encrypted record | 4-5 days |
| 3 | NAT probe, punch request/poll, simultaneous open, timeouts and messages | 6-8 days + field testing |
| 4 | Relay flows in the host, the switch, relay addresses in records, `velora-relay` binary | 4-5 days |

Each step is a PR that works on its own and keeps older peers working. Step 1 can ship in
the next release.

## 11. What to measure

- Phase 1: share of hosts that obtain a mapping (log line "reachable at pub:…"), per protocol.
- Phase 2: DHT resolve time, cold and warm; publish failures.
- Phase 3: punch success rate by NAT type pair; time to first picture.
- Phase 4: relay throughput and the bitrate the session settles at.

All of it stays in the local logs; the user reads it under "This PC" and in `host.log`.
