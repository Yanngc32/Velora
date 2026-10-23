# C2 DHT node: hand-over for E3, F2, E5/F4, C3, E2 (and the review)

Branch `claude/reach-c2-dht-node-f27e6c` (from 35081ec). Files: `crates/dht/src/node.rs`, this note, and the one
dependency the coordinator allowed: `futures-lite = { version = "2", default-features = false }` in
`crates/dht/Cargo.toml` (mainline's `get_mutable` stream implements only that crate's `Stream` and has no method of
its own) with the matching line in `Cargo.lock` (only the name in the `velora-dht` entry). fmt, clippy `-D warnings` and
`cargo test -p velora-dht` green on Windows (84 tests, 1 `#[ignore]` against the public DHT); Linux not compiled here.
`node.rs` carries `#![cfg_attr(not(test), deny(clippy::unwrap_used, expect_used, indexing_slicing, panic))]` like `seal.rs`.

## API

```rust
pub const MAX_VALUE_LEN: usize = 996;   pub const MAX_SALT_LEN: usize = 64;
enum Mode { Client, Host }
Node::open(cache_path: impl AsRef<Path>, mode: Mode) -> Node        // async, never fails: errors come with the first call
Node::open_with(Config) -> Node
Node::next_seq(&impl Signer, salt: &[u8]) -> i64                     // max(clock, last used or seen + 1), kept in the cache file
Node::publish(&impl Signer, salt, blob: &[u8], seq: i64) -> Result<Published { seq, stored_at }, Error>
Node::publish_with(&impl Signer, salt, |seq| -> Result<Vec<u8>, E>) -> Result<Published, Error>   // seals again on SeqTooLow
Node::resolve(&[u8; 32], salt) -> Result<Option<Resolved { value: Vec<u8>, seq: i64 }>, Error>
Node::resolve_with(key, salt, &ResolveOptions { newer_than: Option<i64>, deadline: Option<Duration> })
Node::observed_address() -> Option<SocketAddrV4>
Node::save_cache() -> Result<bool, Error>                            // Ok(false): nothing to write
trait Signer { fn signing_key(&self) -> &SigningKey; fn public_key(&self) -> [u8; 32] }   // for Keys and mainline::SigningKey
Config::new(mode)   // #[non_exhaustive]: set cache_path, resolve_deadline 6 s, settle 200 ms, publish_deadline 25 s,
                    // recycle_after (Host: 10 min); for tests default_nodes, bind_address, port, request_timeout, quorum
enum Error { NoNetwork, TooBig { len }, SaltTooBig { len }, Refused { acknowledged }, SeqTooLow { seq, seen },
             TimedOut, Stopped, Socket(io), Cache(io), Blob(Box<dyn Error>) }   // #[non_exhaustive], thiserror
```

"No record" is `Ok(None)`, not an error. `NoNetwork` is "nobody answered" (offline, UDP blocked, no node to start from);
`Refused` is "the nodes were there and did not keep it" (refused, silent, or fewer than a quorum acknowledged);
`TooBig`/`SaltTooBig` are checked before anything is sent (the nodes report both as a timeout).

## What it does

- **Start.** The bootstrap list is up to 16 saved nodes (spread over the table, not the first 16) and then the default
  names, resolved here with a limit (300 ms with saved nodes, 2 s without; the last good answer is the fallback). Never
  `extra_bootstrap`. A list that ends up empty is `NoNetwork` and builds nothing (mainline never refills it), so a node
  that started with no network is built on the next call. No saved nodes: the first call waits up to 1.5 s for 8 nodes in
  the table (a lookup from the four names alone sometimes hears from none). Saved nodes: nothing is waited for.
- **Resolve.** First record from the `get_mutable` stream, plus any with a higher `seq` within `settle`; the lookup keeps
  going in the background. A lookup that found nothing and heard from fewer than a quorum is repeated once on the same
  node if a second is left; nothing and nobody answering is `NoNetwork`; out of time with nodes in the table is `Ok(None)`.
- **Publish.** Reads first (a whole lookup, which also leaves the nodes and tokens the put goes to): a stored record with a
  higher `seq`, or the same one and another value, is `SeqTooLow` before anything is sent. Then the put; fewer than a
  quorum of acknowledgements means a second round (new lookup, new put), then `Refused`. The `seq` counts as spent from the
  put on, even if it fails. One publish at a time per node.
- **Cache.** Text file (`velora-dht-cache 1`, `node ip:port` lines, `seq <key> <salt> <seq> <time>` lines), written
  atomically right after a publish and 3 s after a resolve (when its lookup has ended; at most every 5 minutes), never
  from a table smaller than a quorum (the old nodes stay, only the `seq` lines change). A file that is not ours, too big or
  unreadable is an empty cache; a saved `seq` more than 7 days ahead of the clock is dropped.
- **Host mode** replaces a node left alone for 10 minutes before the next use (its table rotted in 15; a night asleep counts,
  the clock is the wall clock). `Client` never does.
- **Never serves.** `mainline` cannot be told to stay a client (it becomes a server after 15 minutes if it thinks it is
  reachable), so every node gets a request filter that answers nobody (tested with a node forced into server mode).
- **Panics.** Every call runs on its own task: `mainline` panics when its thread is gone, and that becomes
  `Error::Stopped` and a node built again on the next call.

## Measured on the public DHT (the `#[ignore]` test, run twice by hand, 23 Oct 2026, one home line)

Throwaway key and random bytes, nothing of the product; the records expire by themselves in about two hours.

| | run 1 | run 2 |
|---|---|---|
| host: open, no cache | 245 ms | 86 ms |
| host: publish (cold node, new key) | 4.98 s, 78 nodes acknowledged | 5.95 s, 55 nodes |
| host: publish again (same key, higher `seq`) | | 3.16 s, 22 nodes |
| client, no cache: open + record | 46 ms + 1.74 s | 16 ms + 0.77 s |
| client from the host's cache: open + record | 10-45 ms + 0.555-0.565 s (3 runs) | 65-76 ms + 0.43-0.46 s (2 runs), 58 ms + 0.47 s after the republish |

So the first record from a saved table comes in 0.49-0.60 s from `Node::open` to the value, with the 200 ms `settle` in it
(the ticket's "warm start under a second" in the form S0 gave it). In run 2 the lower and the equal `seq` with another value
were refused as `SeqTooLow` by the read, and a client read the newer record after the republish.

## Decisions to review

1. **No wait for `bootstrapped()`.** The brief said to wait for it (bounded); S0's final document (§10) and the coordinator
   say not to (2.7-4.3 s from any start). Waiting for 8 table nodes on a cold start, and nothing on a warm one, is what
   is done instead.
2. **`SeqTooLow` is returned, not mended inside.** The brief said to publish `seen + 1` on `NotMostRecent`. `seal` binds the
   `seq` in the AAD of the blob, so a blob cannot be sent under another `seq`: only the caller can seal again.
   `publish_with` does that (up to twice); E3 should use it.
3. **One quorum number:** `min(8, size of the start list)`, for the table before a cold lookup, the answers that make a
   lookup trustworthy and the acknowledgements a put needs (S0's "8"). `Config::quorum` overrides it; the tests use 1.
4. `resolve` returns a struct, not a tuple; `Ok(None)` also covers "out of time with nodes in the table".
5. `Mode` only changes `recycle_after`. Both modes serve nobody (decision above), which makes `client_mode` enforced and
   not best effort. If a host should ever serve the DHT, change `Silent`.
6. **Dependency:** `futures-lite` (see the top); `tokio::spawn`/`spawn_blocking`/`time`/`sync` are used, all in the workspace features.
7. `settle` 200 ms costs every resolve up to 200 ms after the first value. `Config::settle = 0` takes it away (F2 may want to).

## What the other tickets must know

- **E3 (host).** Keep one `Node` (it is `Clone`, `Send`, `Sync`) and share it with E5's poller. Publish with
  `node.publish_with(&keys, record::SALT, |seq| Ok::<_, SealError>(seal::seal(&record, SALT, seq, &secrets, Some(&shared))?.blob))`;
  log `stored_at`. `NoNetwork`, `Refused`, `TimedOut`, `Stopped` and `Socket`: keep the old record and try again in a
  minute (the node mends itself); `TooBig` and `Blob` are bugs in the record. Do not call `save_cache` at shutdown: the
  table is saved right after each publish, which is when it is full. The cache path wants a file in the state dir.
- **F2 (client).** `Node::open(cache, Mode::Client)` as soon as the connect starts, then
  `resolve_with(&host_key, SALT, &ResolveOptions { deadline: Some(5 s), newer_than: None })`; `Ok(Some(r))` ->
  `seal::open(&r.value, SALT, r.seq, &secret)`; `Ok(None)` and every error: no candidates, `debug!` it. The cache is
  written 3 s after the resolve by a task the node keeps, so a process that ends sooner skips it.
- **E5/F4 (punch items).** `resolve_with` with `newer_than: Some(last seq)` is the poll: an unchanged item is `Ok(None)`.
  Every call is a lookup (about 70 datagrams from a running node, 2.5-2.8 s), so poll slowly. `Signer` is also
  implemented for a bare `mainline::SigningKey`: C3's derived key goes straight into `publish_with`.
- **E2.** `observed_address()` is `None` until a lookup has ended (about 3 s after the node started; a publish or a resolve
  gets there) and is the raw BEP 42 vote: it can be a private address, and its port is the DHT socket's, not QUIC's. Ask E3's
  node; do not open a second one.
- **E1/G3.** `mainline=error` in the tracing filters is still needed (the 10060 warning, 17 a second, S0 §9.2).
- **Everyone.** A node is one OS thread and one UDP socket (6881 when free, else any port). The first bind may bring a
  Windows firewall prompt for an executable without a rule. `Config` is `non_exhaustive`: `Config::new(mode)` and set fields.

## Not tested

Another network, a phone hotspot, a table days old, and long uptimes; Linux and Android builds; the default-names path with
a real DNS failure (covered through the `DefaultNodes::With` closure only); the retry of a lookup that heard from too few
(never seen in six starts on the public DHT, so only the decision is unit-tested); a stale holder of an older record on the
public DHT; a NAT that rewrites the port. The tests run on `mainline::Testnet`, and on Windows about one loopback datagram
in a hundred is lost there (plain `mainline` too: one put in 150 reached one server of three), and the PC they ran on stalls
now and then. So they use a quorum of 1 and a `settle` that lasts to the end of the lookup, and a publish that must succeed or a
record that must be found is asked again up to six times before a test fails (`stored`, `found` in the test module); what a test
is about (a refusal, a conflict, an empty answer) is asked once. Without that, 1 full run in 40 failed at default parallelism.
