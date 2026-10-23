# The Mainline DHT on real networks: spike results

Ticket S0 of [nat-traversal-tickets.md](nat-traversal-tickets.md). Measured on 23 October 2026 with `mainline` 8.0.1 (the
pinned version) against the public BitTorrent DHT, from one PC on one home network. It answers what C2 (the DHT node
wrapper) is designed on, amends that design where the numbers disagree with it (§10), and lists in §11 what could not be
measured from here. Design context: phase 2 and §12 of [nat-traversal.md](nat-traversal.md).

## 1. Answers in one table

Times are medians with the range in brackets. Where a cell says "pending", §11 says what is missing.

| # | Question | Answer |
|---|---|---|
| 1 | Does `Dht::client()` bootstrap here? How fast, cold and warm? How many nodes? | Yes: all 6 cold and all 19 warm-start runs of §3.1 ended with a routing table (25-139 nodes). **Cold**: first routing-table node after 124 ms (76-290), 8 nodes after 0.58 s (0.54-1.12), 86 nodes at 5 s (25-115) and no more at 30 s. **Warm** (16 saved nodes + the 4 default names): first node 82 ms (35-98), 8 nodes 154 ms, 102 nodes at 5 s. `bootstrapped()` and `public_address()` need 2.8-4.3 s from any start (§3.1). |
| 2 | What do `public_address()` and `firewalled()` report? Is the observed port the bound one? | `public_address()` is the carrier's public IPv4 and **the port the node bound**: this line (a home router behind CGNAT) keeps the source port, for every port tried, and the mapping is endpoint-independent (§3.2). Behind a second NAT (WSL2) the port is rewritten (6881 became 64773) but stays endpoint-independent. `firewalled()` stays `true` and the node stays a client. |
| 3 | `put_mutable` / `get_mutable_most_recent`: latency, success rate, 1000 and 1001 bytes, republishing, seq | **Resolve**: first value after 0.54 s warm start (0.10-0.77), 1.17 s cold (0.68-1.68); the stream ends at 2.6-3.9 s; 12 of 46 cold resolves started seconds apart came back empty (the same lookup repeated on the node always worked), 0 of 20 from a saved table. **Publish**: 2.1 s for the host's real pattern (same key, higher seq) up to 5.8 s for a new key from a cold node; 20 of 20 `Ok`. **Limit: 996 bytes**, not 1000: 997-1001 were refused by every node, and the library reports it as `Timeout`. Higher seq replaces the value; lower seq is `NotMostRecent`; **an equal seq is acknowledged and ignored** (§4). |
| 4 | Resolve from a second node | Second process on this PC: found. A static Linux build behind WSL2's extra NAT layer: found. Both 2 of 3 tries (the third was an empty cold start). Another network: **pending: needs another network** (§5). |
| 5 | How long does a published item live? | **At least 4.5 hours.** Both readers found the exact value at every one of 20 checks, the last 270 minutes after a single publish (8 of 30 asked nodes for the node that had run since before the publish, 14 of 143 for a new one); the watcher was stopped then, with the item still there. The plan assumed about two hours, so the 30-minute republish has a wide margin (§6). |
| 6 | Is `mainline::Testnet` usable for C2's integration tests? | Yes: `Testnet::builder(n)` plus two `Dht` on 127.0.0.1; put from one, get from the other. Set `request_timeout(300 ms)`: 0.4 s per operation instead of 2.1 s (§7). |
| 7 | Cost of a running client node | Idle: 0.085% of one core (609 ms of CPU in 12 minutes), 9 MB, 20 wakeups a second, about 50 datagrams a minute while the table is full. A lookup from a fresh node is about 500 datagrams in 3 s, a repeat from a running node about 110, a publish from a fresh node about 1,000 (§8). |
| 8 | Anything surprising? | Yes, 13 items (§9). The ones that change the plan: a **log flood on Windows** (17 warnings a second per idle node), the **996-byte limit**, **equal seq ignored**, `extra_bootstrap` **drops the default nodes**, the blocking API is **deprecated**, the routing table **rots in 15-20 minutes**, DNS is resolved **once**. |

## 2. How it was measured

**Machine and network.** The author's line: a desktop PC (8-core, 16-thread Intel CPU, 16 GB of RAM, Windows 11 Pro, Rust 1.99.1,
release builds) wired by Gigabit Ethernet to a home router behind CGNAT on a residential fibre line. The DHT sees the carrier's
public IPv4 address (not written here); the hops after the router are private ISP addresses; and a few replies, from nodes that are
probably inside the ISP, saw a private `10.x` endpoint for the same source port (§3.2), which is what a private WAN address
behind a carrier NAT looks like. The router's own WAN address was not read (B1/E2 will compare it with the observed one). Other
sessions were building on the PC during the runs (1.4-2.2 GB of RAM free), which does not show in network numbers. Several mesh-VPN
adapters are installed, but their default routes have far worse metrics than the wired one, so the DHT traffic left through the
router and not through a VPN.

**The program.** `velora-spike`, throwaway, outside the repository (§12): Rust on `mainline = "=8.0.1"` with the async API,
one mode per question. It counts the datagrams the library sends and receives by listening to its TRACE events
(`mainline::rpc::socket`), reads the BEP 42 `ip` field of the replies the same way, and uses a new Ed25519 key and random
bytes for every run: nothing but random test records was published, and nothing was left running except the lifetime watcher, which was stopped after 4.5 hours.

**Terms.**

- *cold*: a new `Dht` with the default bootstrap names and an empty table.
- *warm start*: a new `Dht` whose bootstrap list is the saved table of an earlier node (`to_bootstrap()`) plus the four default
  names; the saved table was 20-35 minutes old unless said otherwise.
- *warm node*: a `Dht` that has been running for at least 30 s.
- *first value*: time from the call until the first valid item arrives on the `get_mutable` stream; *complete*: until the stream
  ends because the query ended. `get_mutable_most_recent` returns at *complete*.
- Times from a fresh node include `Dht::build()` (socket and DNS) and are measured from before it.

**Limits of this evidence.** One network, one afternoon (about 17:00-18:30 UTC, 23 October 2026), one operating system. The
DHT's state differs from run to run (a cold start ended with between 25 and 115 nodes), and several hundred node starts and
lookups from one address in a few hours may have made the bootstrap nodes less generous than usual (§9.10). These are
measurements, not a statistical study.

## 3. Joining the DHT

### 3.1 Start-up time and node counts

`Dht::build()` returns as soon as the socket is bound and the four default names are resolved; the node then bootstraps on its own
thread. Polled every 50 ms (cold: 6 runs of 30 s; each warm variant: 4 runs of 12 s):

| Start | `Dht::build()` | First node | 8 nodes | `bootstrapped()` = `public_address()` known | Nodes at 5 s | Datagrams sent / received |
|---|---|---|---|---|---|---|
| Cold | 14-234 ms | 76-290 ms (median 124) | 0.54-1.12 s (0.58) | 3.1-4.3 s (3.7) | 25-115 (86) | 97-325 / 54-225 |
| Warm, 20 entries (16 saved + 4 names) | 8-67 ms | 35-98 ms (82) | 100-170 ms (154) | 2.9-3.1 s (2.9) | 88-107 (102) | 231-287 / 174-208 |
| Warm, 12 entries (8 saved + 4 names) | 15-332 ms | 77-390 ms (110) | 208-576 ms (296) | 2.8-4.1 s (3.4) | 82-123 (112) | 227-309 / 162-242 |
| Warm, 103 entries (99 saved + 4 names) | 14-101 ms | 48-124 ms (100) | 102-185 ms (158) | 2.7-3.2 s (2.8) | 95-139 (122) | 429-529 / 328-421 |
| Warm, 99 saved, no names | 1-2 ms | 25-28 ms | 85-87 ms | 2.7-3.2 s (2.8) | 113-133 | 447-507 / 359-397 |

- "First node" is the first entry of `to_bootstrap()`; "8 nodes" is enough for a lookup to start from the table.
- `bootstrapped()` (the library's own readiness call) and `public_address()` both depend on the self-lookup the node starts, which
  ends when its last request has been answered or has timed out (2 s), so they take 2.7-4.3 s from any start. They are not a
  good readiness test; a lookup does not wait for them (§4.1).
- The table stops growing after 2-3 s: the counts at 30 s are the counts at 5 s.
- The node counts of a cold start vary much more than the times (25 to 115): the bootstrap nodes do not always answer fully.

### 3.2 What the network says about this node

- `info().public_address()` is set from the BEP 42 `ip` field of the replies, by majority, **when the first lookup ends**, so it
  is `None` for 2.7-4.3 s after start whatever the start (§3.1). It is then the carrier's public IPv4 address and **the port
  the node bound**: the line (home router plus carrier NAT) kept the source port for every local port tried (6881 and four others: 53927, 61546, 41234,
  55555, five of five). One endpoint was reported by 134 to 211 replies per 15 s run, so for those destinations the mapping is
  endpoint-independent and port-preserving, the friendliest NAT type for hole punching (phase 3).
- In one run 2 of 136 replies reported a **private** endpoint (`10.x.x.x:55555`) for the same local port. They came from
  nodes that are probably inside the ISP's own network, which fits a line behind CGNAT: the carrier does not translate what
  stays inside it. The majority vote ignores them; B2, which reads the same field from
  its own pings, has to vote and to drop non-public answers too.
- `firewalled()` stayed `true` and `server_mode()` stayed `false` in every run, including the reader of the lifetime run, which ran for 4.5 hours. The
  library clears the flag only when a ping it sends to its own public address comes back, and that never happened here: the
  carrier NAT or the router does not loop the packet back (no hairpin), or Windows Firewall drops it (no inbound rule exists for the
  program).
  Either way the node never left client mode on this network.
- Windows Firewall showed no prompt and created no rule for the program; outbound-initiated UDP and its replies work without one.

### 3.3 The routing table does not survive being idle

A node that is left alone loses its table. The persistent reader of the lifetime run (§6) had 78 nodes after 1 minute, 95-96
after 5 and 10 minutes (each check is a lookup that refreshes the nodes it touches), **18 after 15 minutes and 4 after 20**,
and its traffic fell from about 25 datagrams a minute to about 1. The cause is in the library: a node counts as stale 15
minutes after the last *query response* from it, the maintenance ping every 5 minutes does not refresh it (its reply matches
no query, so `handle_response` does not re-add the node), and `to_bootstrap()` leaves stale nodes out. Lookups keep working
with a nearly empty table because every query starts from the bootstrap list while the table is smaller than that list. For the
next four hours the reader held between 0 and 27 nodes at each check.

Consequence for the saved cache: take it right after a lookup or a publish, not at shutdown, and never replace a good cache
with a small one.

A **long bootstrap list makes every later lookup dearer**: while the closest nodes the table can offer are fewer than the
bootstrap entries, each lookup visits all of them again, query plus ping, so two datagrams each.

| Bootstrap entries | Datagrams sent per lookup of a random key (4 lookups) | Sent for the whole start |
|---|---|---|
| default, 4 names | 272-364 | 207 |
| 20 (16 saved + 4 names) | 260-304 | 269 |
| 103 (99 saved + 4 names) | 460-552 | 495 |

A lookup costs about 300 datagrams sent and 200 received (roughly 30 kB) and ends after 2.9-3.4 s even for a key nobody
published, because it only ends when the last request has been answered or has timed out.

### 3.4 When the network is not there

Simulated with bootstrap lists that cannot work (nothing was blocked on the PC):

| Bootstrap | `bootstrapped()` | get | put | Datagrams in the next 20 s |
|---|---|---|---|---|
| a node that never answers (TEST-NET 192.0.2.1) | `false` after 2.1 s | nothing after 2.2 s | `Err(Query(NoClosestNodes))` after 2.2 s | 18 (it retries by itself, about one per second) |
| a name that does not resolve | `false` after 0.19 s | nothing after 0.13 s | `Err(Query(NoClosestNodes))` after 0.12 s | **0: it never retries** |
| a closed local port (ICMP unreachable) | `false` after 2.0 s | nothing after 2.2 s | `Err(Query(NoClosestNodes))` after 2.2 s | 18 |

The second row is what happens when DNS is down while `Dht::build()` runs: the four default names are resolved once, inside
`build()` (14-234 ms here, blocking, no timeout of its own), failures are dropped silently, and an empty bootstrap list is
never refilled. A node built before the network came back (after a resume from sleep, say) is dead for good and must be
re-created.

## 4. Publishing and resolving

### 4.1 Latency and success rate

Twenty tries per scenario, 6 s apart (ten for the last two), a new throwaway key for every put, one random 300-byte value (a
realistic sealed record). Times of a fresh node include `Dht::build()`. Every put was read back at once by a separate node
that had been running for minutes. Medians, with min-max in brackets.

| Scenario | Tries | Outcome | First value / put returns | Query complete | Other |
|---|---|---|---|---|---|
| Resolve, cold node | 20 | **18 found, 2 empty** | 1.17 s (0.68-1.68) | 3.9 s (2.4-4.6) | 123 nodes asked (8-154), 20 held the item |
| Resolve, warm start (16 saved + 4 names, list 29 min old) | 20 | 20 found | 0.54 s (0.10-0.77) | 3.1 s (2.8-3.6) | 139 asked |
| Resolve, warm node (running, same key again) | 20 | 20 found | 0.16 s (0.07-0.20) | 2.6 s (2.5-2.8) | 36 asked: it reuses the nodes of the last lookup |
| Publish, cold node, new key | 20 | 20 `Ok`, **18 of 20 read back** | 5.8 s (2.6-7.1) | `stored_at` 57 (1-86) | read back after 0.48 s (0.17-0.70) |
| Publish, warm node, new key | 20 | 20 `Ok`, 20 of 20 read back | 4.9 s (3.3-6.3) | `stored_at` 21 (18-34) | read back after 0.31 s (0.15-0.69) |
| Publish, warm node, same key, higher seq | 10 | 10 `Ok`, 10 of 10 read back | 2.1 s (0.46-3.5) | `stored_at` 18 (16-20) | read back after 0.11 s (0.08-0.34) |
| Publish, warm start, new key | 10 | 10 `Ok`, 10 of 10 read back | 5.1 s (3.7-5.3) | `stored_at` 38 (23-92) | read back after 0.29 s (0.12-0.38) |

- **Resolving.** The first value arrives long before the lookup ends: 0.16 s on a running node, 0.54 s from a saved table, about
  1.1 s cold, against 2.6-3.9 s for the stream to end. `get_mutable_most_recent` waits for the end.
- **Publishing.** A publish is a lookup (2.5-3 s) plus the stores, and it ends when the slowest of the stores has answered or
  timed out (2 s): 2.6-7.1 s for a new key, about 2.1 s when the same key was just used (the node keeps the closest nodes and
  their tokens for 5 minutes; 0.46 s when every store answered at once). A published item was found by another node 0.1-0.7 s
  after the put returned.
- **`stored_at` follows the state of the publishing node, not the size of the value** (§4.2). A fresh node stored at 57 nodes
  (median over 20 publishes; 20 to 103 when the start was good), a node that had done a few lookups at about 20 (16-34 in 30
  publishes). All of those resolved from another node.

**Cold starts are the weak spot.** The first lookup of a fresh node sometimes asks exactly the 8 addresses of the four default
names, hears from none of them within 2 s, and ends 2.3 s after the call (`queried=8`). A resolve then returns nothing, and a
publish that starts from that lookup stores the item at the one or two nodes that did answer, which nobody finds again: in
`sizecmp` (two runs, 30 publishes) all 8 publishes with `stored_at` 1 or 2 failed the read-back and all 22 with 20 or more succeeded. Repeating the lookup
on the same node, which asks the same 8 addresses again, found the item every time (8 of 8, 5.3-5.9 s in all).

| Test | Starts apart | Starts | Bad starts |
|---|---|---|---|
| `boot`, the first 20 minutes | 30 s or more | 6 | 0 (one ended with only 25 nodes) |
| Lifetime watcher, a fresh node at each check | 5-15 minutes | 8 | 0 |
| Resolve, `get/cold` | 6 s | 20 | 2 |
| Resolve, second-node reads (§5) | 5 s | 6 | 2 |
| Resolve, `coldretry` | 6 s | 20 | 8 |
| Publish, `put/cold` | 6 s | 20 | 2 (not found again; the lowest `stored_at` was 1) |
| Publish, `sizecmp`, sizes 100, 600, 996 bytes in turn | 8 s | 15 | 6 |
| Publish, `sizecmp`, sizes 996, 600, 100 bytes in turn (partly alongside another test) | 8 s | 15 | 2 |
| Resolve, `coldretry` slowed down | 60 s | 8 | 2 of 8 |
| From a saved table: resolves / publishes | 6-8 s | 20 / 22 | 0 / 0 |

The bad starts came in runs with starts 5-8 s apart; the 8 starts of the lifetime watcher, 5-15 minutes apart, and the first six
`boot` runs had none. Whether the spacing is the cause was not settled (a run with starts a minute apart overlapped with other
tests and is not reported). A limit on new UDP flows (a lookup opens about 150 of them in 2 s) on the router, the ISP or the
bootstrap nodes is a candidate, triggered by this test's own bursts; the cause was not identified, and a user connecting once is not
this PC at 6-second intervals. A start from a saved table, which has 20 entries to ask instead of 8, did not suffer from it in 42 tries.

### 4.2 Value size and salt

Puts of random values with an 8-byte salt, from a node that had been running a few minutes, then read back from another node:

| Value | Result | Nodes that acknowledged (`stored_at`) |
|---|---|---|
| 300, 900, 980, 990, 994, 995, **996 bytes** | stored, read back identical | 71, 48, 44, 28, 26, 24, 19 |
| **997, 998, 999, 1000, 1001 bytes** | **every node refused it** | 0 |

The refusal is KRPC error 205 ("message too big", "Message exceeds maximum size.", "message (v field) too big", all three
wordings seen) from every node that answered, and one 203. So the usable limit is **996 bytes, not 1000**: BEP 44 caps the
bencoded value, and a byte string of 100 to 999 bytes carries a four-byte `NNN:` prefix (`996:` + 996 bytes = 1000). A salt of 64
bytes was accepted and 65 refused (error 207, "salt too big"), as the BEP says.

What the library returns for a refused put is `Err(Query(PutQueryError::Timeout))`, "timed out with no responses", after the
nodes answered in 3-5 s. `PutQueryError::ErrorResponse` exists but 8.0.1 never builds it, and the codes are visible only in
DEBUG logs (`mainline::rpc::put_query`). Sizes must therefore be checked before publishing; the error cannot tell them from a
dead network.

(`stored_at` fell from 71 to 19 along that list, but the list was run back to back from one node and 100-byte values later in the
same run gave 24 and 19 too: the fall follows the age of the publishing node, not the size (§4.1). From fresh nodes, `sizecmp` stored
values of 100, 600 and 996 bytes at 20 to 99 nodes whenever the start was good. Its bad starts (1 or 2 nodes, §4.1) hit the 600- and
996-byte puts 3 times in 5 each and the 100-byte put never when the order was 100, 600, 996, and the 600- and 100-byte puts once
each and the 996-byte put never when it was reversed: the start that opened each round was good in 10 of 10 cases whatever its
size, so the position, not the size, explains it better, and no size effect on the publishing side is claimed.)

### 4.3 Republishing and `seq`

One key, one 8-byte salt, one writer node and one reader node, 6 steps (each put is followed by a read from the other node):

| Step | Result |
|---|---|
| First publish, seq = unix time | stored at 75 nodes in 5.1 s; read back by 23 nodes |
| Higher seq (+1), new value | stored at 77 nodes in 0.6 s (same target, cached nodes); **the old value is gone**: all 12 answering nodes returned the new seq |
| Lower seq (-1) | `Err(Concurrency(NotMostRecent))` after 0.26 s; the stored item is unchanged |
| **Equal seq, other value** (three times: a smaller value, a larger one, the smaller again) | **`Ok`, `stored_at` 72-74, but the nodes keep the first value**: an equal seq is acknowledged and ignored |
| CAS equal to the stored seq / different from it | stored / `Err(Concurrency(CasFailed))` after 0.26 s |
| seq set 1,000,000 ahead, then back to "now" | the first is stored, the second is `NotMostRecent`: a seq that ran ahead once blocks the key. Reading the current seq and publishing `seen + 1` (with CAS) works |

So `seq` must strictly grow with every publish, even two within the same second. `seq = max(unix seconds, last seq + 1)`
is enough, and `NotMostRecent` is handled by one read and a retry.

## 5. Resolving from a second node

The same item (random 64 bytes, published once by one process) was read by a node that shares nothing with the publisher:

| Reader | Result |
|---|---|
| A second process on this PC, another UDP port | found in 2 of 3 tries (UDP ports 65506, 64991 and 52574): first value after 1.13 and 1.30 s, query complete after 4.0 and 4.3 s, 22-24 nodes returned it, value and seq identical to what was published. The third try found nothing: its lookup asked 5 nodes (a bad cold start, §9.10) |
| A static Linux build of the same program inside WSL2. The only distro installed is Docker Desktop's own: it sits behind the Windows host's NAT (interface MTU 1280), behind the router, so one more NAT layer than the Windows process | found in 2 of 3 tries (the process always bound 6881): first value after 1.02 and 1.09 s, complete after 3.7 and 4.0 s, 25-27 nodes, identical. The third asked 8 nodes and found nothing. The DHT saw this process as `<public IP>:64773` although it was bound to 6881: the NAT of Windows in front of WSL2 rewrites the port. In the `nat` mode run from there, 6881 became 64773, 53496 became 64730, 41234 became 64760 and 55555 became 64717, each seen by 183 to 264 replies and by no other endpoint: the rewriting is endpoint-independent, which is what hole punching needs |
| A node on another network (a laptop on other Wi-Fi, a phone hotspot) | **pending: needs another network** (commands below) |

To run the last row, with nothing but the 1.5 MB program (no installer, no admin right, no config):

```
:: on the author's PC, left running (it republishes every 20 minutes for 2 hours):
velora-spike.exe publish --hold 7200 --every 1200
:: it prints KEY=.. SALT=.. VALUE=.. and the exact line to run on the other network:
velora-spike.exe resolve --key <KEY> --salt <SALT> --expect <VALUE> --tries 3
```

The reader prints `found in N of 3 tries`, the time to the first value, and "our public endpoint as the DHT sees it", which is
that network's NAT behaviour for free: the same port as the node bound means port preservation, as at home. A phone hotspot is
the interesting case, since mobile carriers usually put several customers behind one address and rewrite the ports.

## 6. How long an item lives

The plan assumes about two hours ("nodes keep items for about two hours") and republishes every 30 minutes. One item of 300
bytes was published once (stored at 71 nodes), the publisher was dropped, and nothing republished it. Two nodes looked for it at
growing ages: one that had been running since before the publish (*persistent*) and a brand-new cold one (*fresh*). A miss would
have been repeated 30 s later; none was ever needed. "Nodes" is how many answered with the item, out of how many were asked. The
watcher was stopped after the 270-minute check, with the item still there.

| Age | Persistent reader | Fresh cold node | Attempts |
|---|---|---|---|
| 1 min (checked at 1.1) | found (18 of 169 nodes) | found (20 of 166 nodes) | 1 |
| 5 min (checked at 5.1) | found (13 of 39 nodes) | found (15 of 107 nodes) | 1 |
| 10 min (checked at 10.1) | found (13 of 40 nodes) | found (20 of 110 nodes) | 1 |
| 15 min (checked at 15.1) | found (10 of 36 nodes) | found (17 of 115 nodes) | 1 |
| 20 min (checked at 20.1) | found (11 of 40 nodes) | found (16 of 120 nodes) | 1 |
| 30 min (checked at 30.1) | found (9 of 35 nodes) | found (17 of 145 nodes) | 1 |
| 45 min (checked at 45.1) | found (7 of 36 nodes) | found (15 of 94 nodes) | 1 |
| 60 min (checked at 60.1) | found (7 of 36 nodes) | found (16 of 134 nodes) | 1 |
| 75 min (checked at 75.1) | found (7 of 38 nodes) | found (17 of 137 nodes) | 1 |
| 90 min (checked at 90.1) | found (7 of 40 nodes) | found (7 of 87 nodes) | 1 |
| 105 min (checked at 105.1) | found (7 of 37 nodes) | found (12 of 96 nodes) | 1 |
| 120 min (checked at 120.1) | found (7 of 41 nodes) | found (16 of 84 nodes) | 1 |
| 135 min (checked at 135.1) | found (7 of 36 nodes) | found (15 of 131 nodes) | 1 |
| 150 min (checked at 150.1) | found (7 of 38 nodes) | found (15 of 116 nodes) | 1 |
| 165 min (checked at 165.1) | found (7 of 34 nodes) | found (17 of 155 nodes) | 1 |
| 180 min (checked at 180.1) | found (7 of 31 nodes) | found (14 of 172 nodes) | 1 |
| 195 min (checked at 195.1) | found (7 of 32 nodes) | found (15 of 101 nodes) | 1 |
| 210 min (checked at 210.1) | found (8 of 35 nodes) | found (18 of 128 nodes) | 1 |
| 240 min (checked at 240.1) | found (8 of 30 nodes) | found (16 of 108 nodes) | 1 |
| 270 min (checked at 270.1) | found (8 of 30 nodes) | found (14 of 143 nodes) | 1 |

**What it means for the design.**

- **An item published once survives at least 4.5 hours.** Both readers found the exact value at all 20 checks, from 1 to 270
  minutes. The plan assumed about two hours, so the **30-minute republish has a wide margin**: eight rounds in a row could be lost
  (a host asleep, a network down) and the record would still be there when the host comes back. The periodic republish is not what
  keeps the record alive; what has to happen at once is the publish after an address change. Its interval is a free choice: an
  hour would still sit well inside the measured lifetime (four rounds could be lost) at half the traffic (about 1,000 datagrams a
  publish from a fresh node, §8).
- **The number of nodes holding the item did not run down.** The fresh node found it at 7 to 20 of the 84-172 nodes it asked at
  every age (20 at 1 minute, 14 at 270), and the persistent reader, which keeps asking about the same 35 nodes, found it at 7 or 8
  of them at every check from 45 minutes on. There is no sign of an approaching cliff in the window measured.
- **What this does not show**: when the item would have expired, since the run was stopped with it still there, and whether
  other days and other keys behave the same: the lifetime belongs to the nodes that hold the item and their software, and this is one
  item on one afternoon.

## 7. Testing without the internet: `Testnet`

`Testnet` works for C2's integration tests. The exact calls:

```rust
let testnet = Testnet::builder(3).build()?;               // 3 server nodes on 127.0.0.1, routing tables seeded
let node = |_| Dht::builder()
    .bootstrap(&testnet.bootstrap)                          // Vec<String> of "127.0.0.1:port"
    .bind_address(Ipv4Addr::LOCALHOST)
    .request_timeout(Duration::from_millis(300))            // see below
    .build().map(Dht::as_async);
let (a, b) = (node(0)?, node(1)?);
a.put_mutable(MutableItem::new(key, &value, seq, Some(salt)), None).await?;   // PutOutcome { stored_at: 3, .. }
b.get_mutable_most_recent(&public_key, Some(salt)).await                       // Some(item), identical
```

Measured: it works from a testnet of one node (`stored_at` = number of nodes) up to ten; the testnet builds in 0.13 s for one
node and 1.2 s for ten. With the default 2 s request timeout a put or a get takes **2.1 s even on loopback**, because the
testnet nodes put the two client nodes into their routing tables and clients never answer, so every lookup waits out a
timeout; with `request_timeout(300 ms)` a put takes 0.37 s and a get 0.40 s, and with 100 ms 0.19 s and 0.25 s. The first value
arrives in 1-64 ms either way. `Testnet::new(n)` (without `builder`) binds `0.0.0.0` and invites a firewall prompt; the
builder binds `127.0.0.1`. Dropping the `Testnet` shuts the nodes down.

## 8. What a running node costs

A client node on this PC (`firewalled` stayed `true`, so it never became a server).

| | Measured |
|---|---|
| CPU, idle | **609 ms in 12 minutes: 0.85 ms a second, 0.085% of one core** (118 nodes in the table, no log subscriber) |
| CPU, idle, with a subscriber that formats the 17 warnings a second of §9.2 | 92 ms a minute averaged over 4.4 hours (73-96 in every window), 0.15% of a core, before any I/O to a log file |
| Memory | 9 MB working set |
| Threads, wakeups | one thread per `Dht`, woken every 50 ms (20 a second) when nothing happens |
| Datagrams, idle, table full | about **25 sent and 24 received a minute** (a ping to every node every 5 minutes, and the replies) |
| Datagrams, idle, table rotted (§3.3) | 5 sent and 3 received a minute on average over 4 hours, nearly all of it one self-lookup every 15 minutes of 54-96 sent and 22-69 received |
| Start-up | cold: 97-325 sent, 54-225 received, in 2-3 s; from 16 saved nodes: 231-287 sent, 174-208 received |
| One lookup | **about 300 sent and 200 received** (260-364 / 193-281), 2.9-3.4 s, whether or not the key exists; the same key again from a running node: **about 70 sent and 40 received**, 2.5-2.8 s, because it only asks the 35 nodes it already knows (10 polls) |
| One publish from a fresh node | 204-645 datagrams sent and 132-476 received over the node start, the lookup and 20-90 stores with their acknowledgements, in 2.6-6.2 s (a good start: about 600 sent and 450 received, 4-6 s; a bad start stops after 2.6 s with 200-380 sent and nothing stored) |
| Bytes | not measured: a packet trace needs administrator rights on the PC. The datagram counts are exact; by the protocol a query is about 100 bytes and a reply 100-600, so a fresh lookup is roughly 100 kB (an estimate) |

So the plan's estimate of "a few hundred small UDP packets per minute while running" (phase 2, risks) is too high for an idle node,
about 50 a minute, and too low for a lookup, which is about 500 datagrams in 3 s. Neither matters for a host that publishes every
30 minutes or a client that resolves once per connection. It does matter for anything that looks things up in a loop (E5's
punch-request poller, §10).

## 9. Surprises

Each one cost, or would cost, something in C2 or around it; §10 says what to do.

1. **The blocking API is deprecated.** In 8.x `Dht::info`, `to_bootstrap`, `put_mutable`, `get_mutable*` and the rest are
   `#[deprecated]` ("use the async API via `Dht::as_async()`"). `AsyncDht` is plain `flume` channels, so it runs under any
   executor, tokio included. Every `Dht` is one OS thread ("Mainline Dht actor thread") that reads its socket with a 50 ms
   timeout and ends within 50 ms of the last handle being dropped.
2. **On Windows a quiet node floods the log.** The library prints `WARN IO error ... (os error 10060)` from
   `mainline::rpc::socket` every time its 50 ms read times out: about **17 lines a second** per node (49,503 events in the
   25 minutes of the put/get run, 263,000 in the 4.5 hours of the lifetime run), because Windows reports a read timeout as `TimedOut` and the code only expects `WouldBlock`.
   ICMP replies add `10054` and `10052` lines. Both binaries default their filter to `info` (`crates/host/src/main.rs:240`,
   `crates/client/src/main.rs:124`) and the host's log file is created fresh and never rotated, so `host.log` would take
   4-5 kB a second, about 400 MB a day. The filter needs `mainline=error`. (Linux and Android report `WouldBlock`: no flood
   there.) The one ERROR worth keeping is "Could not bootstrap the routing table".
3. **`extra_bootstrap` does not keep the default nodes.** Its documentation says it adds to them, but `extra_bootstrap(&[dead])`
   alone left the table empty for 10 s, exactly like `bootstrap(&[dead])`, while the default builder had 65 nodes. Use
   `bootstrap(&[saved.., DEFAULT_BOOTSTRAP_NODES..])` (the constant is public).
4. **A long bootstrap list makes every lookup dearer** (§3.3), and **the routing table rots in 15-20 minutes** without lookups.
5. **DNS is resolved once, in `build()`**, and a node whose list ended up empty never recovers (§3.4).
6. **A refused put looks like a timeout** (§4.2), and **an `Ok` put can be worth nothing**: `put_mutable` succeeds as soon as one
   node acknowledges, and a fresh node whose lookup went badly stored the item at 1 or 2 nodes, which nobody could find again
   (§4.1: 10 of 50 cold publishes). `stored_at` is the only warning.
7. **The limit is 996 bytes** (§4.2) and **an equal seq is ignored without an error** (§4.3).
8. **`public_address()` arrives with the first completed lookup**, 2.7-4.3 s after start, never earlier, and a few votes can
   be private addresses (§3.2). Behind another NAT layer the observed port is not the bound one (§3.2, §5).
9. **`get_mutable_most_recent` waits for the whole query**, 2.4-4.6 s; the first value is there after 0.1-1.7 s. Dropping
   the stream does not cancel the query: the traffic (about 500 datagrams) goes on.
10. **A cold start can be a bad start.** The first lookup of a fresh node sometimes asks only the 8 bootstrap addresses and hears
    from none of them, 2.3 s in: a resolve then returns nothing and a publish stores at 1 or 2 nodes. It happened in 12 of 46
    cold resolves and 10 of 50 cold publishes when starts were a few seconds apart, in none of 8 started minutes apart, and
    from a saved table in 0 of 20 resolves and 0 of 22 publishes. The same lookup repeated on the same node worked 8 of 8
    times (§4.1).
11. **Adaptive mode cannot be switched off.** `Config::server_mode` is only "start as a server now"; the default is "become a
    server after 15 minutes if the node believes it is not firewalled", and it believes that when a ping to its own public
    address comes back. Here it never did (§3.2), so the node stayed a client, but on a network with hairpin NAT or an open port a
    Velora node would start answering the DHT's queries and storing other people's items after 15 minutes.
12. **IPv4 only.** The socket is `0.0.0.0` UDP; IPv6 datagrams are ignored and bootstrap names are filtered to their A records.
    A network with no IPv4 at all (some mobile carriers, unless 464XLAT gives the app a v4 socket) cannot use the DHT.
13. No firewall prompt, no firewall rule and no administrator right were needed, and the working set of a running node is 9 MB.

## 10. What C2 should do

The design in [nat-traversal-tickets.md](nat-traversal-tickets.md) (`Node::open(cache_path, client_mode)`, `publish`,
`resolve`, `observed_address`, `save_cache`, seq = unix time) **stands, with these amendments**. The calls, as they were used here:

```rust
// open: saved nodes first, the default names behind them; never extra_bootstrap
let mut list: Vec<String> = saved.iter().take(16).cloned().collect();
list.extend(DEFAULT_BOOTSTRAP_NODES.iter().map(|s| s.to_string()));
let dht = Dht::builder().bootstrap(&list).build()?.as_async();       // blocks 10-250 ms for the DNS of the 4 names

// resolve: the first valid item, not get_mutable_most_recent
let mut items = dht.get_mutable(&public_key, Some(salt), None);
let first = items.next().await;                                      // None: the query ended empty

// publish
let item = MutableItem::new(signing_key.clone(), &sealed, seq, Some(salt));
match dht.put_mutable(item, None).await {
    Ok(outcome) if outcome.stored_at >= 8 => { /* stored */ }
    Ok(_) => { /* acknowledged by 1 or 2 nodes: not findable, publish again */ }
    Err(PutMutableError::Concurrency(_)) => { /* read the current seq, publish seq + 1 */ }
    Err(PutMutableError::Query(e)) => { /* NoClosestNodes: no network. Timeout: refused or unanswered */ }
}

// cache, right after a lookup or a publish
let nodes: Vec<String> = dht.to_bootstrap().await;                   // "ip:port"; stale nodes are left out
```

**Opening the node**
- Build on `Dht::as_async()`; never call the deprecated blocking methods. A start is cheap (below), so the host may open a
  node for each publish round and drop it, instead of holding a thread that wakes 20 times a second all day. A node that is
  kept has an empty table after 20 idle minutes (§3.3) and publishes like a cold one.
- Bootstrap list = **at most 16 saved nodes** (spread over the table, not the first 16) **plus `DEFAULT_BOOTSTRAP_NODES`**,
  passed to `bootstrap()`. Never `extra_bootstrap`, never the whole table. (Saved nodes alone work too, 25 ms to the first
  node, but a dead cache would then leave a dead node.)
- `Node::open` takes a small config instead of only `(cache_path, client_mode)`: bootstrap list, bind address, port, request
  timeout. The integration test of §7 needs `bind_address(127.0.0.1)`, a Testnet bootstrap and a 300 ms timeout. Do not pass
  `.port(..)` in production: a busy port is an error, while the default tries 6881 and falls back to a random one.
- `client_mode` cannot be enforced in 8.0.1 (§9.11). Keep the parameter, document that it is best effort, and let E3 decide
  whether it matters.
- Check the node after building it: if `to_bootstrap()` is empty after a few seconds, drop it and build another from the saved
  IP:ports (no DNS), a minute later from the names. Re-create the node after a resume from sleep.

**The warm start is under a second, but not the way the ticket measures it**
- `bootstrapped()` and `observed_address()` need 2.7-4.3 s whatever the start (§3.1): do not wait for them before a `resolve` or
  a `publish`. A warm start has its first nodes after 25-124 ms and 8 nodes after 85-185 ms (cold: 76-290 ms, 0.5-1.1 s), and
  the **first value of a resolve arrives after a median 0.54 s (0.10-0.77 s)** from a saved table, 1.17 s (0.68-1.68 s) cold.
  `observed_address()` is `None` until the first lookup ends.
- Done-when for C2: "warm start under a second" should read "the first value of a resolve under a second from a saved table".

**`resolve`**
- Use the `get_mutable` stream, not `get_mutable_most_recent`: return the first valid item, or the highest seq seen within
  about 300 ms of it. Pass `more_recent_than` when polling, so unchanged items come back as `NoMoreRecentValue`.
- One automatic retry on the same node when the stream ends empty (8 of 20 cold lookups came back empty in the `coldretry` run and the repeat found the item 8 of 8 times, 5.3-5.9 s after
  the start in all). F2's cap of 5 s fits one attempt (a successful cold
  resolve is done by 1.7 s, an empty one is known after 2.3 s) but not the retry (5.3-5.9 s in all): give a cold resolve about 6 s,
  or start from the saved table, which never needed one.
- Return `None` for "no record", and a typed error only for "no network" (empty table, `NoClosestNodes`).

**`publish`**
- Refuse before the network: a value over **996 bytes**, a salt over 64. The network's refusal arrives as `Timeout` and cannot be
  told from a dead network (§4.2).
- `seq = max(unix seconds, last seq + 1)`, last seq kept beside the cache. On `Concurrency(NotMostRecent)` or `CasFailed`: one
  `get_mutable`, take its seq, publish `seq + 1` (§4.3). Do not publish twice for one change inside the same second.
- **`Ok` is not enough: require `stored_at >= 8`** (every publish that was found again had 16 or more, every one with 1 or 2 was
  lost; nothing in between was seen) and otherwise publish again, on the same node, which by then has a better table.
  Prefer a node that has already done a lookup: publishes from a running node had `stored_at` of 16 or more in 30 of 30 tries,
  from a saved table 23 or more in 22 of 22, from a fresh node with the default names 10 of 50 failed (§4.1).
- Expect 3.3-5.7 s for a publish to a key the node has not touched in the last 5 minutes (a lookup, then the stores) and
  0.5-2.2 s when it has; it ends when the slowest of the stores answered or timed out (2 s).

**Cache**
- `save_cache` right after a publish or a lookup, never at shutdown; keep the best of the last saves; do not replace a cache with
  a table of fewer than 8 nodes (§3.3). A cache 22 minutes old worked as well as a fresh one, and one 51 minutes old as well
  (first node 74-137 ms, 85-123 nodes at 5 s); one five hours old as well (first node 55-242 ms, 8 nodes after 121-319 ms, 101-115 nodes at 5 s, 3 runs).

**Corrections to the design documents** (H1 owns the edit; this file only records them)
- [nat-traversal.md](nat-traversal.md) phase 2: "BEP 44 allows 1000 bytes" is **996 bytes** of value; "joins in well under a
  second without touching the bootstrap nodes" is "usable after about 0.1 s, finished after 3 s, and the default names stay in
  the list as a fallback"; "seq = unix time (monotonic across restarts without a counter file)" is `max(now, last + 1)` with the
  recovery above; "A DHT client sends a few hundred small UDP packets per minute" is about 50 a minute idle and about 500 per
  lookup (§8); "nodes keep items for about two hours" is **at least 4.5 hours** here (§6), so the 30-minute republish has a wide margin.

**For other tickets** (the short version was handed over earlier in `docs/reach-handover/S0-early-findings.md`; where that note and
this document differ, this one is right)
- **C1**: 996 is right and confirmed on the network. The 12-device record of 922 bytes was not tested as such, but 900 and 996
  bytes resolved from another node.
- **E1 and G3**: add `mainline=error` to the default filters (`"info"` becomes `"info,mainline=error"`) in `host/src/main.rs`
  and `client/src/main.rs` before C2 lands, or `host.log` fills with the 10060 warning (§9.2).
- **E3**: a publish from a fresh node is about 600 datagrams sent and 450 received and 4-6 s; once every 30 minutes that is
  nothing. Check `stored_at` (above).
- **E5**: polling is not free. A lookup of a key nobody published costs about 300 datagrams from a fresh node, but a running node that repeats it asks
  only the ~35 nodes it already knows: about 70 sent and 40 received, 2.5-2.8 s each, and a new poll started before the
  last one ended joins it. Polling one client every 10 s is therefore about 10 datagrams a second, close to a million a
  day; polling every 2 s is back-to-back lookups, 24 a second as tested (the test waited for each lookup) and up to
  about 40. With several paired devices the 10 s poll of E5 is the most expensive thing in the plan; make it 30-60 s,
  with a short burst after a disconnect.
- **B2**: take the `ip` votes by majority and drop non-public ones (§3.2); the replies carry the endpoint but the library only
  uses it after a completed lookup, so for punching, B2's own ping to a few nodes is the faster source.
- **F2**: see `resolve` above; the 5 s cap holds.

## 11. Still pending

- **Pending: another network** (§5). One run on a laptop on other Wi-Fi or a phone hotspot, which needs the author's laptop or a
  phone. Nothing here can stand in for it: WSL2 adds a NAT layer but shares the router and the ISP with the PC. The commands are
  in §5.
- **Not measured, and not measurable from here**: whether the DHT port can ever be seen as reachable (hairpin NAT, an inbound rule,
  a router mapping), which decides if the adaptive switch to server mode can happen; the router's own WAN address (carrier NAT
  check, B1 and E2); IPv6-only and mobile networks, Android included (a v4 socket through 464XLAT); a network that really blocks UDP
  (only simulated, §3.4); a saved table a day or a week old (the oldest tried: five hours); `request_timeout` below its 2 s default
  on the real network (it would shorten publishes and lookups at the price of missed answers); the bytes on the wire (no
  administrator right on the PC for a packet trace, so byte counts are estimates from the protocol).

## 12. Reproducing

The program is throwaway and is **not in the repository**. It lives on the measuring PC, in a `velora-spike` folder of its own:
`src\main.rs` (one file), `dist\velora-spike.exe` (Windows, 1.5 MB), `dist\velora-spike-linux` (static musl build of the same
code), `logs\` (every output quoted here) and `lifetime_table.py` (turns `logs\watch.log` into the table of §6). It needs
`mainline = "=8.0.1"`, `futures-lite`, `getrandom` and `tracing`, builds with `cargo build --release`, and cross-builds from Windows
to Linux with `--target x86_64-unknown-linux-musl`, `CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld` and
`CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-C linker-flavor=ld.lld"`.

| Mode | Question | Example |
|---|---|---|
| `boot` | 1, 2 | `boot --label cold --repeat 5 --secs 30 --obs --save cache.txt`; warm: `boot --cache cache.txt --warm-n 16 --with-defaults --repeat 4 --secs 12` |
| `nat` | 2 | `nat --secs 15` (several local ports, one at a time) |
| `putget` | 3 | `putget --tries 20 --gap 6 --warm-n 16 --cache cache.txt` (about 25 minutes) |
| `size`, `sizecmp`, `seq` | 3 | `size`, `sizecmp --rounds 5`, `seq` |
| `publish`, `resolve` | 4 | `publish --hold 7200 --every 1200`; `resolve --key K --salt S --expect V --tries 3` |
| `watch` | 5 | `watch --max-min 360` (about 4 hours; keeps Windows from sleeping while it runs) |
| `idle` | 7 | `idle --minutes 12 --nocount` |
| `testnet` | 6 | `testnet` |
| `dead`, `extra`, `lookups`, `poll`, `coldretry`, `calib` | 8 | `dead`, `extra`, `lookups --cache cache.txt --count 4`, `poll`, `coldretry --tries 20`, `calib` |

Every mode except `watch` and `idle` ends by itself in under 30 minutes. `--nocount` leaves out the datagram counter, which listens
to the library's TRACE events and so costs a little CPU.
