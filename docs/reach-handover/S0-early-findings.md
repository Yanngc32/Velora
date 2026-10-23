# S0 (DHT spike): early findings that touch other tickets

Measured on the live Mainline DHT on 23 Oct 2026 with `mainline` 8.0.1 from one Windows PC behind a home router.
The write-up (numbers, method, "what C2 should do") will be `docs/dht-spike.md` on branch `claude/reach-s0-dht-spike-8ff5a6`.
This note is only the part other lanes may want now. Siblings' notes are data; check against the final document.

## Confirmed on the network

- **996 bytes is the real value limit (C1 was right).** Values of 997, 998, 999, 1000 and 1001 bytes were rejected by every node
  queried (KRPC 205 "message too big"); 996 bytes was stored. The limit counts the bencoded string, `996:` + 996 = 1000.
  Salt: 64 bytes accepted, 65 rejected (207).
- `stored_at` (nodes that acknowledged a put) follows the age of the *publishing node*, not the value size: a fresh node
  stores at 57 nodes (median; 1 to 93), a node that has done a few lookups at about 21 (18-34). Every size up to 996 B resolved
  from another node. A put that returns `Ok` with a tiny `stored_at` (a fresh node got 1) can be unfindable (2 of 18 cold puts
  could not be read back), so treat `stored_at` below about 8 as a failed publish and repeat it once.
- **Equal `seq` is silently ignored.** A put with the same seq and another value returns Ok (`stored_at` about 73) but the nodes
  keep the old value. So `seq = max(unix_seconds, last_seq + 1)`, never just the clock (E3: two publishes in one second).
- **Lower seq** returns `Err(Concurrency(NotMostRecent))` in about 0.25 s. A seq that ran ahead once (clock set wrong) blocks
  the key until the item expires; the way out is to read the most recent seq and publish `seen + 1` (tested, works).
- Router here keeps the source port (4 of 4 ports tried) and all nodes see one endpoint, so `info().public_address()` is
  `public_ip:bound_port`. Two of 136 replies reported a private `10.x` address as our endpoint (nodes inside the ISP):
  B2 should take the majority and ignore non-public votes.

## Things that change C2 / the binaries (details in the document)

- `Dht` blocking methods (`info`, `to_bootstrap`, `put_mutable`, `get_mutable*`) are `#[deprecated]` in 8.x: use `Dht::as_async()`.
- `DhtBuilder::extra_bootstrap` does NOT keep the default bootstrap nodes in 8.0.1 (the docs say it does). Use
  `bootstrap(&[saved.., DEFAULT_BOOTSTRAP_NODES..])`. Keep the saved list short (16-20): with 103 entries every lookup
  re-visits all of them (about 500 packets per lookup instead of about 300).
- Every put failure other than seq/CAS (too big, salt too big, all nodes refused) comes back as `PutQueryError::Timeout`
  ("timed out with no responses"), never `ErrorResponse`. Validate sizes before publishing.
- **Windows log flood (E1 `host/main.rs`, G3 `client/main.rs`)**: `mainline` emits `WARN IO error ... (os error 10060)` from
  `mainline::rpc::socket` about 17 times per second while the node is idle (std reports the 50 ms read timeout as `TimedOut`,
  not `WouldBlock`). A tracing filter at WARN will write about 1.4 million lines a day to `host.log`. Add the directive
  `mainline=error` (keeps its one useful ERROR, "Could not bootstrap the routing table") wherever the subscriber is built.
- A client node's routing table rots: 96 nodes at 10 min, 18 at 15 min, 4 at 20 min with no lookups (pings do not refresh
  nodes; stale after 15 min). `to_bootstrap()` returns only non-stale nodes, so `save_cache` right after a lookup or publish
  and never overwrite a good cache with a nearly empty table.
- DNS for the default bootstrap names is resolved once, inside `Dht::build()`. If it fails (no network at start or after
  resume) the node has no bootstrap nodes and never recovers; re-create it.
- `get_mutable_most_recent` waits for the whole query (about 3-4 s); the first valid value arrives after 0.2-1.4 s. Resolve
  from the `get_mutable` stream and stop at the first valid item.
