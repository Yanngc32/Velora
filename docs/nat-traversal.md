# Reaching a PC from anywhere without a server: plan and feasibility study

Status: proposal, revision 2, October 2026. Nothing here is implemented. Revision 2 went
through the first draft line by line against the code and the crates; §13 lists what it
changed.

## 1. Goal

A client should reach a paired host from any network, the way it does over Tailscale today,
without installing a mesh VPN and without anyone running a server for Velora: not the
project, not the user.

Everything here is optional and off the critical path. Tailscale and Netbird keep working as
they do today, and a user who has them needs none of this. "Standalone reach" is a switch on
This PC, and each piece below (router mapping, DHT record, relaying for others) has its own.

Out of scope: a general-purpose VPN. Velora needs one thing, that a QUIC packet reaches the
host's UDP port. Authentication, encryption, sessions, files and sound already work end to
end over any path.

## 2. The constraint that shapes everything

Two computers behind different NATs cannot find each other with nothing in between: neither
knows the other's public address, and neither NAT lets a packet in that it did not see go
out. Every "serverless" system (BitTorrent, Hyperswarm, Yggdrasil, Tailscale's own direct
connections) relies on a third party both sides can reach. The question is only who that is.

| Third party | Who runs it | Cost to the user | Availability |
|---|---|---|---|
| The user's own router (NAT-PMP / UPnP / PCP) | nobody | none | most home routers; not CGNAT (unless the carrier runs PCP, which is rare) |
| The BitTorrent Mainline DHT (millions of nodes) | nobody, once joined; joining uses a few well-known bootstrap nodes (BitTorrent Inc, Transmission, libtorrent) and then cached peers | none, no account | running since 2005; IPv4 only; any node can read what you store unless it is encrypted |
| Public STUN servers | Google, Cloudflare, Twilio... | none, no account | reliable, but a dependency on a stranger; the DHT can replace it (BEP 42) |
| Another of the user's own paired PCs | the user | none | only while that PC is itself reachable and on |
| A self-hosted relay (`velora-relay`) | the user | a VPS | optional, last resort |
| A Velora-run coordination server | the project | none | **rejected**: the thing we want to avoid |

The plan uses the first four, in that order, STUN only as a configurable fallback, and leaves
the fifth as an opt-in.

## 3. What exists today (verified)

- Transport is QUIC (quinn 0.11.12) over UDP, mutual TLS 1.3, the host's certificate pinned
  by fingerprint. Any path that delivers UDP works; nothing on the path can read or alter
  anything. Keepalive every 2 s and a 15 s idle timeout are already set (`protocol::tls`),
  so any NAT mapping a connection uses stays alive by itself.
- QUIC datagrams are already enabled (pointer moves, sound). MTU discovery is quinn's default.
  The server does not use address validation (Retry): an exposed port could be used for
  amplification; `Incoming::retry()` exists in quinn 0.11 to fix that.
- The host binds `0.0.0.0:7420` by default: **IPv4 only**. It accepts no IPv6 today.
- The host advertises its LAN and VPN-mesh addresses in the pairing link and in the welcome
  (at most `MAX_ADDRESSES = 8`); the client stores them and races them all on connect, 250 ms
  apart, one socket per address, first handshake wins (`client-core::establish`).
- Identity is an rcgen 0.14 self-signed certificate; rcgen's default key is **ECDSA P-256**.
  There is no Ed25519 key, which BEP 44 needs.
- The pairing link parser ignores unknown query parameters: new ones are safe.
- The hello's extension flags are one byte; bits 0-4 are used (files only, clipboard,
  addresses, displays, audio). **Three bits are left.** A second byte would be rejected by
  every host that exists today, which makes the client fall back to a hello without
  extensions and lose files, clipboard and sound with those hosts.
- Welcome fields are appended in order and gated by a hello bit; a client that knows the
  previous fields but not a new one rejects the trailing bytes. A new host message sent after
  the welcome, only to clients that asked for it with a hello bit, is the safe way to add
  information (the pattern `HostMsg::Displays` uses).

Everything below is "more addresses in the race" plus, for the hard cases, a way to make an
address work.

## 4. Options evaluated and rejected

**Embed WireGuard (a Tailscale-like mesh).** Needs a TUN driver (Wintun, administrator
rights), IP allocation, routing, and the same coordination problem on top. Velora doesn't
need an IP network; it needs one UDP flow. Rejected.

**libp2p / iroh.** Both solve exactly this and are Rust. iroh can even discover peers through
the Mainline DHT (pkarr), the same idea as phase 2, but its hole punching is coordinated
through its relay servers, which n0 runs; running without them means self-hosting. Both also
replace quinn with their own transport and bring a large dependency tree. Rejected for now;
iroh's design (relay as fallback and as the signaling channel for punching) is the model this
plan copies with the user's own PC as the relay.

**WebRTC ICE (`webrtc-ice`).** Mature hole punching, but it assumes a signaling channel the
application provides, i.e. a server. The part we need is small enough to write for one UDP
flow. Rejected as a dependency; its ideas are used in phase 3.

**IPv6 only.** Where both sides have global IPv6 there is no NAT, but there usually is a
router firewall that drops unsolicited inbound v6 (common on ISP-provided routers), and
opening it needs IGDv2 pinholes or PCP, which few routers implement. So IPv6 is cheap to add
and worth measuring, not a solution on its own. Phase 1 includes it.

## 5. Architecture

```
 client                                                 host
 ┌───────────────────────────┐                         ┌───────────────────────────┐
 │ resolve: stored addrs     │  1. LAN / VPN           │ advertise:                │
 │ + DHT record of the host  │ ──────────────────────▶ │  LAN, VPN (today)         │
 │                           │  2. public v4 / v6      │  mapped port, public v4,  │
 │ race every address;       │ ──────────────────────▶ │  global v6 (phase 1)      │
 │ first handshake wins      │  3. hole punch          │  DHT record (phase 2)     │
 │                           │ ◀─────────────────────▶ │  punch on signal (ph 3)   │
 │                           │  4. through relay R     │  dials out to R (ph 4)    │
 └───────────────────────────┘                         └───────────────────────────┘

 relay (phase 4):  client ──▶ R ◀── host   both ends dial out; R copies the datagrams
```

Paths 1 and 2 are plain addresses. Path 4 needs a third machine that both ends can reach:
another paired PC that path 1 or 2 reaches; **both the client and the host connect outward
to it**, so neither needs to be reachable. Path 3 needs both sides to act at the same moment:
the signal travels through the relay when one is connected, and through the DHT otherwise.

## 6. Phases

### Phase 1: the router opens the port, and the host says its public addresses

What the host does at start and every 30 minutes:

1. Binds dual-stack (`[::]:7420` with `IPV6_V6ONLY` off), so IPv6 is accepted at all. quinn
   handles v4-mapped addresses on such a socket. The client already binds a v6 socket for a
   v6 address.
2. Asks the gateway to map UDP 7420 to itself: NAT-PMP first (`natpmp` 0.5), then UPnP IGD
   (`igd-next` 0.18, `AddAnyPortMapping` where IGDv2 is there, else `AddPortMapping` and, on
   conflict 718, the next port). PCP later: the only crate (`pcp-client` 0.1.0) is unproven
   and PCP is rare on home routers. The reply carries the external port actually assigned
   (two hosts behind one router get 7420 and 7421) and the router's external IP.
3. Decides whether that external IP is public. Private (RFC 1918) or shared (100.64/10,
   RFC 6598) means double NAT or CGNAT: the mapping only reaches the next NAT and is not
   advertised. The observed address from the DHT (phase 2) or STUN (fallback) is compared
   with it for the same reason.
4. Picks one global IPv6 address per interface, preferring the one with the longest valid
   lifetime (`GetAdaptersAddresses` on Windows; the first global one on Linux). Windows
   prefers temporary addresses for outbound, but inbound works on any of the host's addresses
   while it is valid, and the record of phase 2 refreshes the list anyway.
5. Puts `pub:` v4 and `v6:` addresses into `reachable_addresses`, so into the link and every
   welcome, and shows them on This PC. The mapping is removed on exit; a crash leaves it to
   expire (1 h lease).

Hardening that comes with exposing the port: the host calls `Incoming::retry()` for
connections whose address is not validated yet, so a spoofed Initial cannot make it send
more than it received. Costs one round trip on the first connection from a new address.

Verification: a mapping cannot be checked from inside (hairpin NAT is unreliable), so the
client reports which address won the race (`ClientMsg::Reached`, optional, old hosts ignore
unknown tags), and the host logs and shows it: "last reached at pub:…".

Covers: a laptop away from home when the home router supports NAT-PMP or UPnP and the ISP
gives a public IPv4; and v6-to-v6 where the home router's v6 firewall allows it.

Does not cover: CGNAT without usable v6, routers with UPnP off (company networks), an IP that
changes while the client is away (the client learns addresses only when it connects).

Cost: 3-4 days. One PR in the host plus `MAX_ADDRESSES` raised (old clients truncate to 8,
which is safe) and a kind per address in the new `HostMsg::Reach` (§8). Ships in the next
release.

### Phase 2: finding the host when its address changed, without a server

Spike first (1 day): confirm with `mainline` 8 on this network the observed address and port
(`Dht::info().public_address()`), put/get latency warm and cold, and how long items survive.

What: the host publishes a signed, encrypted record in the Mainline DHT (BEP 44 mutable
item). `mainline` 8.0.1 implements BEP 44 (`MutableItem::new(signing_key, value, seq, salt)`,
`put_mutable`, `get_mutable_most_recent`) and BEP 42 (observed public address), and can save
its routing table (`to_bootstrap()`) so the next start joins in well under a second without
touching the bootstrap nodes.

```
key    = Ed25519 public key of the device (new; stored next to the identity)
salt   = "velora/1"
seq    = unix time at publish (monotonic across restarts without a counter file)
value  = { fingerprint, addresses: [kind:ip:port...], nat: open|cone|symmetric, relays: [...],
           mac } encrypted as below. BEP 44 allows 1000 bytes; this is ~300 with 8 addresses.
```

Encryption, so a revoked device stops being able to read it: the record carries one copy of a
fresh content key wrapped for each paired device under that device's own secret (given to it
at pairing or over `HostMsg::Reach`), 48 bytes each, so up to about 12 devices fit beside
the content. Beyond that the host falls back to one shared secret. Revoking a device then
means leaving its wrapped key out at the next publish. AEAD: ChaCha20-Poly1305 from `ring`,
already a dependency.

The client learns the host's public key and its device secret from the pairing link (two new
parameters; the link grows by ~70 characters with a 16-byte secret, the QR stays scannable)
or, for devices paired before this version, from `HostMsg::Reach` on their next connection.
On connect, the client fetches the record (about a second warm, a few seconds cold) and
adds its addresses to the race. The host republishes every 30 minutes (nodes keep items for
about two hours) and whenever an address changes.

Why a new key: BEP 44 signs with Ed25519 and the TLS identity is ECDSA P-256. Changing the
certificate's key would change every fingerprint and break every pairing, so the Ed25519 key
is a second key beside the identity, created on first use. Every device gets one, since every
device is a host too and phase 3 needs the client's.

Covers: dynamic IPs; the signaling of phases 3 and 4.

Does not cover: reaching a host that has no mapping (phases 3 and 4).

Cost: 5-6 days after the spike. New dependencies: `mainline` (pure Rust, pinned to 8.0.1)
and, through it, `ed25519-dalek 3`: the final release, since mainline asks for
`^3.0.0-pre.1` (forcing the pre-release itself does not build against the current
RustCrypto crates, which the scaffold found). A `dht.rs` in the host and in client-core
(so the Android app resolves too), the link parameters, `HostMsg::Reach`.

Risks:
- The DHT is public and IPv4-only: a record's existence leaks that some Velora device exists
  at that key; its content does not. No record can be published or read from a v6-only or
  UDP-blocked network (corporate networks often block it): then the stored addresses are all
  the client has.
- The session process (`velora connect`) starts a DHT client each time: with the saved
  routing table it is fast; without it (first run, long offline) a few seconds.
- A DHT client sends a few hundred small UDP packets per minute while running. The host keeps
  one running; the client only during connect.

### Phase 4: relay through a machine the user already has (before phase 3)

Model: the relay R is any paired device that is reachable (phase 1 reached it) and has the
switch "Let my other PCs connect through this one" on. **Both ends connect outward to R**, so
neither the host nor the client needs to be reachable; this is how Tailscale's DERP and
iroh's relays work, and it is why the relay also carries the signaling for phase 3.

- The host H, when it has no mapping of its own (or always, when the user says so), keeps a
  QUIC connection open to R ("register", a new message after the hello) and keeps it alive
  with the existing 2 s keepalive. R learns H's fingerprint from the TLS handshake and H's
  LAN address from the connection, which is what the Wake needs.
- The client connects to R, says "relay to H" (by fingerprint), and from then on sends the
  QUIC packets meant for H as **QUIC datagrams** on its connection to R; R copies each
  datagram's payload to H's connection and back. The inner connection is Velora's normal
  client-host QUIC, so end-to-end security is unchanged and R sees ciphertext only.
- MTU: a client's QUIC Initial is 1200 bytes and must stay so, and an outer datagram carries
  about 1150 until MTU discovery raises the outer path (typically to ~1450 after a few round
  trips), and only ~1235 on 1280-MTU mobile links. So the relay leg frames each inner packet
  as one or two datagrams with a 3-byte header (packet id, chunk index); a lost chunk drops the
  packet, which the inner QUIC recovers like any loss. About 45 bytes of overhead per packet
  (4% at video sizes) and one more encryption, which is nothing next to the encoder.
- R forwards only between devices on its own paired list; whether A may reach B is decided by
  B's TLS handshake as always. New flows are rate-limited.
- How the client finds R: H's `HostMsg::Reach` (phase 1) and DHT record (phase 2) list the
  relays H is registered with and their addresses; those go into the race as `relay:R`
  addresses, tried last, after the direct ones fail. R's own public address can change too,
  which is why phase 2 comes first.
- Bandwidth: R receives the video from H and sends it to the client, so it needs both
  download and upload of the session's bitrate (6-12 Mbit/s at 1080p). The adaptive bitrate
  already follows whatever R's link gives.
- `velora-relay`: the same relay code as a standalone binary for people with a VPS, with a
  paired list and nothing else. Optional, not run by the project.

Wake through R: H tells R its MAC when registering; "Wake STUDIO-PC" in the client is a
request to R, which sends the magic packet on its LAN. The Android app on the home Wi-Fi can
send it directly too. Requirements on H are Windows' and the firmware's, not ours: Wake on
Magic Packet enabled on the adapter, fast startup off, a wired link (Wi-Fi wake depends on
the adapter), and for a PC that is off rather than asleep, the BIOS "deep sleep"/ErP setting
off; Modern Standby machines vary. After waking, the host redoes mapping, addresses and the
DHT record at once; the keep-awake added in 0.5 stays as the alternative for people who
would rather not sleep the PC.

Covers: symmetric NATs and double CGNAT, as long as one of the user's machines is reachable
and on. Also gives phase 3 its fast signaling channel.

Cost: 7-9 days. Relay task and registration in the host, the `relay to` and `wake` messages,
chunking, the switch, relay addresses in Reach and in the record, the standalone binary.

### Phase 3: hole punching (last)

What: when H has no mapping and R exists only as a fallback, both sides still have a public
endpoint through their NAT; the trick is to make both NATs see an outgoing packet to the
other before the incoming one arrives (ICE's simultaneous open), then run the normal QUIC
handshake through the hole. Where it works, it removes the relay's extra hop and bandwidth.

The endpoint must be observed **from the very socket that will carry the QUIC connection**,
because a NAT mapping is per source port. On the client that is easy: the race already gives
each address its own socket; the punch candidate binds its socket, sends a tiny KRPC `ping`
to three DHT nodes from the saved routing table (or a STUN binding as fallback), reads the
observed `ip:port` from the replies, then hands the socket to `quinn::Endpoint::new`. On the
host the socket already belongs to quinn, so the host's endpoint uses a small
`AsyncUdpSocket` wrapper that sends the same pings and keeps their replies out of quinn.
Comparing the observed port across several nodes also tells the NAT type for free.

Signaling: through R when the host is registered with one (sub-second, the normal case once
phase 4 exists); otherwise the client publishes a punch request as its own DHT item
("to H, from endpoint E, nonce") encrypted for H, and a sharing host without a relay polls
the items of its paired clients every 10 s, and every 2 s for five minutes after a client was
last connected. Either way the host then sends to E, which it can do without raw socket
access: `Endpoint::connect_with` toward E sends an Initial from the listening port, which is
enough to open the mapping; the attempt is dropped when the client's own connection arrives.
The client keeps dialing the host's observed endpoint; its Initial retransmissions ride the
hole as soon as it opens. Give up after 10 s and use the relay.

NAT types (RFC 4787): endpoint-independent mapping (most home routers, many carriers)
punches reliably. Address- or port-dependent mapping (symmetric NAT: some corporate and
carrier NATs) does not, since the port the other side sees is not the one it should send to;
port prediction helps on some; otherwise the relay stays.

Cost: 6-8 days plus field testing on at least three networks (two different NATs and a phone
on 4G/5G). Every failure needs a clear message in the client.

## 7. Effects on what Velora already does

**Security.** End to end nothing changes: mutual TLS 1.3 with pinned certificates over any
path; relays and the DHT see ciphertext only. What changes is exposure: with a mapping, the
host accepts UDP from the whole internet on its port, as it already does when a user forwards
the port by hand; quinn drops anything that is not a valid handshake for the host's
certificate before any application code runs, and Retry (phase 1) keeps the port from being
used for amplification. The access password stays as a second layer. The new secrets are the
per-device secrets of the record: whoever has a pairing link can read the host's addresses
in the DHT until that device is revoked, not connect. A relay must check its paired list
before copying a byte and rate-limit new flows.

**Smoothness.** Direct paths (mapping, IPv6, a successful punch) add nothing: it is the same
packet a hand-made port forward would carry, equal to or better than a direct Tailscale link.
A punch costs a few seconds to open the first time, nothing after. The relay adds one hop,
5-40 ms plus the relaying PC's jitter, and 45 bytes per packet; like Tailscale over DERP when
it finds no direct path. NAT mappings stay open by the 2 s keepalive already in place. The
client's own network changes (Wi-Fi to 4G) are handled by QUIC migration, as today.

**Picture quality.** Unchanged on direct paths. Through a relay the ceiling is the relaying
PC's link: residential fibre in Brazil carries 1080p at 12 Mbit/s easily; a laptop on weak
Wi-Fi relays at a few Mbit/s and the adaptive bitrate settles there, softer picture, nothing
broken.

**Wake.** Covered in phase 4: a sleeping host publishes nothing and cannot answer a punch, so
waking comes first and goes through the relay PC or the phone on the home Wi-Fi, never
through the router directly (a forwarded magic packet dies when the router forgets the
sleeping PC's ARP entry, and most routers refuse to forward to the broadcast address).

## 8. Protocol and compatibility

- Hello: one new extension bit, `reach` (bit 5). Bit 7 is reserved now as "another flags byte
  follows", so a future version can extend the flags without being dropped by hosts that
  know bit 7. Hosts that predate bit 7 would still drop such a hello, so that extension is
  for after they are gone.
- `HostMsg::Reach`, sent after the welcome only to clients that set the bit, like
  `HostMsg::Displays`: every advertised address with its kind (`lan`, `vpn`, `pub`, `v6`,
  `relay:<fingerprint>`), the host's Ed25519 key, the client's device secret, the relays the
  host is registered with, the host's MAC, and whether this host relays. Old clients never
  see it; the welcome's `addresses` field stays as it is.
- Pairing link: `velora://pair?address=..&code=..&also=..` gains `key=` and `secret=`;
  old clients ignore them (verified).
- New client messages after the hello (`Reached`, `RelayRegister`, `RelayTo`, `Wake`,
  `PunchRequest` where sent over a relay): old hosts decode them as `Unsupported` and ignore
  them, so the client only sends them to hosts whose `Reach` announced the capability, and
  times out otherwise.
- `MAX_ADDRESSES` goes from 8 to 16; old clients truncate the list, which is harmless.
- Nothing in the DHT or on a relay is trusted: the client still pins the host's certificate
  and the host still checks the client's. A fake record can only point a client at a wrong
  address, where the TLS handshake fails.

## 9. Security and privacy

- End-to-end security unchanged: mutual TLS 1.3 with pinned certificates over any path.
- Exposed port: quinn rejects anything that is not a valid handshake before application
  code; Retry prevents amplification; the access password remains for defence in depth.
- DHT records are signed (nobody can replace a device's record) and encrypted per paired
  device (nobody else can read the addresses; revoking a device stops it at the next
  publish). The DHT learns that a device exists at a public key, nothing more.
- A relay copies only between devices on its paired list, rate-limits new flows, and cannot
  read what it copies.
- IPv6 addresses and the public IP appear in the pairing link and on This PC, as the LAN
  address does today; the user controls who sees the link.
- No telemetry: nothing is reported to anyone.

## 10. Feasibility verdict

| Piece | Feasible | Confidence | Why |
|---|---|---|---|
| Router mapping, public v4, Retry | yes | high | mature crates (`natpmp`, `igd-next`), the address race exists, no welcome change |
| IPv6 | yes to advertise; reaching depends on the router | medium | needs the dual-stack bind; home routers' v6 firewalls often block inbound; cheap to try and to measure |
| DHT record | yes | high after the spike | `mainline` implements BEP 44/42 and is used in production (pkarr/pubky); pinned to 8.0.1 |
| Relay via own PC | yes | high | plain datagram forwarding with both ends connecting out; the chunking is the only subtle part |
| Hole punching | yes, for cone NATs | medium | standard technique; observing from the right socket is the subtle part; testing is the cost |
| Symmetric NAT on both sides, no reachable PC | no | — | needs a relay someone runs: `velora-relay` on a VPS |

Expected coverage for the user's own case (laptop away, Windows PC at home on residential
fibre): phase 1 very likely solves it where the router does NAT-PMP or UPnP and the ISP gives
a public IPv4; with CGNAT it depends on the router's IPv6 firewall; phases 2 and 4 then cover
it in every case as long as one of their machines is reachable, and phase 3 removes the relay
hop where the NATs allow.

Tailscale stays supported and stays the better choice where it is already installed: it has
relays worldwide and handles every NAT. This plan removes the requirement, not the option.

## 11. Order of work and effort

Recommended order is 1, 2, 4, 3: the relay is simpler than hole punching, guarantees a path,
gives punching its signaling channel, and is the machine the Wake needs.

| Step | Deliverable | Estimate |
|---|---|---|
| 1 (phase 1) | Dual-stack bind, NAT-PMP/UPnP mapping, public v4 and v6 in the race, CGNAT detection, Retry, `Reach` message, This PC shows what worked, the standalone switch | 3-4 days |
| spike | `mainline` on real networks: observed address, latencies, item lifetime | 1 day |
| 2 (phase 2) | Ed25519 key beside the identity, link parameters, per-device record encryption, publish/resolve, routing-table cache | 5-6 days |
| 3 (phase 4) | Relay registration and forwarding with chunking, the switch, relay addresses in Reach and in the record, Wake through the relay PC and the phone, `velora-relay` | 7-9 days |
| 4 (phase 3) | Endpoint observation from the QUIC socket on both sides, signaling over the relay and over the DHT, simultaneous open, timeouts and messages | 6-8 days + field testing |

About five weeks of feature work in all; counted as conflict-free tickets with plumbing,
UI, mobile, field tests and docs it comes to about 54 person-days, or roughly three weeks of
wall clock with four lanes in parallel (see [nat-traversal-tickets.md](nat-traversal-tickets.md)).
Each step is a PR that works on its own and keeps older peers working. Step 1 can ship in the
next release.

## 12. What to measure

- Phase 1: share of hosts that obtain a mapping, per protocol; which address kind clients
  report reaching (`Reached`), so IPv6's real coverage is known.
- Phase 2: DHT resolve time, cold and warm; publish failures.
- Phase 4: relay throughput and the bitrate sessions settle at; wake success.
- Phase 3: punch success rate by NAT type pair; time to first picture.

All of it stays in the local logs; the user reads it under This PC and in `host.log`.

## 13. What revision 2 changed, and why

1. The host accepts no IPv6 today (`0.0.0.0:7420`): phase 1 now starts with a dual-stack
   bind. The first draft advertised v6 addresses nobody could reach.
2. Home routers commonly firewall inbound IPv6: v6 is now "cheap, measure it", not a solution.
3. The relay model was wrong: the relay cannot "open a flow to H" when H is the unreachable
   side. Both ends now connect outward to the relay, as DERP and iroh do.
4. Relaying QUIC inside QUIC datagrams hits the 1200-byte Initial against a ~1150-byte outer
   datagram: chunking is required.
5. The relay also becomes the signaling channel for hole punching, making punching sub-second
   in the normal case and the DHT polling only a fallback.
6. New welcome fields would be rejected by clients that know the previous ones; everything new
   goes in `HostMsg::Reach`, gated by a hello bit. The hello has three bits left, so one bit
   covers the whole plan and bit 7 is reserved for extension.
7. The identity key is ECDSA P-256, not Ed25519: the Ed25519 key is a second key beside it,
   and devices paired before this version get it over `Reach`.
8. The public endpoint for punching must be observed from the QUIC socket itself (mapping
   is per port): the client observes before handing its socket to quinn; the host needs an
   `AsyncUdpSocket` wrapper.
9. CGNAT and double NAT are detected by checking the router's external IP against private
   and shared ranges and against the observed address, instead of advertising a dead mapping.
10. Two hosts behind one router: the mapping's assigned external port is advertised, not 7420.
11. Record encryption is per paired device, so revocation works without re-pairing everyone;
    the 1000-byte BEP 44 limit bounds it at about 12 devices before falling back.
12. Retry (address validation) is added with the exposed port, against amplification.
13. The DHT's bootstrap nodes are named as the third party they are, and the saved routing
    table keeps later starts off them.
14. `mainline` 8.0.1 is pinned (`=8.0.1`). It signs with `ed25519-dalek 3`, which is final by
    now: the pre-release concern of the first reading is gone (found while scaffolding).
15. `MAX_ADDRESSES = 8` would overflow with public and v6 addresses: raised to 16, which old
    clients truncate harmlessly.
16. Estimates went up where the design got more concrete: about five weeks in all.
