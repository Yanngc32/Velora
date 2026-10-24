# F2 client DHT resolve: hand-over for I2 (and E3, F4, the review)

Branch `reach-f2-dht-resolve` (from `integration-wave2`, 8539011). One file: `crates/client-core/src/reach/dht.rs`, which F1 left as a stub; the frozen
signature `resolve_record(&ConnectParams) -> Result<Vec<Candidate>>` is unchanged. 17 tests in that file (64 in the crate); fmt, clippy `-D warnings` and
`cargo test -p velora-client-core` green on Windows, `cargo check -p velora-mobile` compiles. The tests ran five more times in a row without a flake. I broke the
code on purpose 18 ways (the salt and the key asked, the `seq` the record is opened with, the host check, the age check, which NATs are punched, the filter on
private endpoints, the host as its own relay, a relay address dialed as the host's, the `via` list, the limits, the order, the deadline passed to the node, the
outer timeout): each made a test fail except one that changes nothing observable (the separate log line for a wrong secret). `dht.rs` carries `deny(unwrap_used,
expect_used, indexing_slicing, panic)` outside its tests, like `seal.rs` and `node.rs`. **No traffic left this PC**: the tests use a stand-in for the node, and the one
test that opens a real `Node` gives it no bootstrap nodes. Linux and Android were not compiled here.

## What it does

1. Nothing to do (no stored entry, no `key`, no `secret`, or either all zeros): `Ok(vec![])` before anything is opened. F1's race asks only when it has both.
2. Opens a `Node` in `Mode::Client` on `<client state dir>/dht_cache.txt` (`dht::cache_path`), looks up `host.key` under `record::SALT` with what is left of a **6 s cap**
   (`RESOLVE_CAP`, the opening of the node included), and saves the routing table when the lookup ends (1 s at most; the node saves by itself 3 s after a resolve, later than
   the client lives).
3. Opens the value with `seal::open(blob, SALT, seq, &Secret::new(host.secret))`, requires the record's fingerprint to be the host's and its `ts` to be within a day of
   the clock, and lists the ways in. Anything that does not open, is damaged, names another host or is out of date is `Ok(vec![])` and a line at debug level
   (`NotRecipient` says the device was removed or its secret is stale). Only a lookup that could not run (`NoNetwork`, `TimedOut`, `Stopped`, `Socket`) or did not finish is an
   `Err`. A record that gave candidates is one line at info level (counts, no addresses).

## From the record to the candidates (`from_record`, in this order)

| the record | the candidate |
|---|---|
| each address of kind Lan, Vpn, Public, V6, Other(c) that parses | `Direct(addr, kind)`, in the record's order |
| each `Public` address that is global (B2's `classify(..).is_global()`), when `nat` is `Open` or `Cone`; at most 2 | `Punch { endpoint, via }`, `via` = the first 4 addresses of the record's relays (empty: signal through the DHT) |
| each address of each entry of `relays` that parses, except the host itself | `Relay { relay_addr, relay_fingerprint, target: host }` |
| an address of kind `Relay` | left out: a record holds no fingerprint for it; its relay is in `relays` |

## Decisions to review

1. **6 s, not the ticket's 5.** C2/S0 measured the first value at 0.3-1 s warm and 1-2 s cold, but a cold lookup that heard from too few nodes is repeated once and then needs
   5.3-5.9 s: 5 s cuts exactly the lookups that need the retry. Nothing waits for this (the race has the stored addresses meanwhile, and ends it as soon as one connects),
   so a lookup is not made shorter than the ones that can succeed. The race's limit (`LOOKUP_LIMIT`, 10 s) is a compile-time-checked margin behind it.
2. **`settle` stays at C2's 200 ms.** The ticket allowed 0. A host whose IP changed has an old record on some nodes and the new one on others; the first value can be the old
   one, and the 200 ms is what lets a newer `seq` replace it. It costs every resolve up to 200 ms, in a path that only runs when the stored addresses did not answer.
3. **A punch for `Open` as well as `Cone`**, and only toward a `Public` address that is global. The ticket said cone; an `Open` host has no NAT, but its firewall may drop
   what it did not expect, which the punch is for as well. A host with a mapped port lists the mapped address as `Public` too: the direct candidate wins before the punch
   would start (F1 starts it 2 s after the first direct one). Symmetric, unknown and future NAT codes: no punch.
4. **Records a day from the clock are not read** (both ways). The host republishes every 30 minutes and the nodes drop an item after about two hours, so an older one is
   not from a running host; the bound is a day so that an ordinary clock error does not silence the DHT for a device. A device whose clock is wrong by days gets no candidates
   from the DHT and a debug line saying so.
5. **A removed device learns nothing.** `NotRecipient` (removed, or a stale secret) is "no candidates" at debug level, like a missing record. G2/H1 may want to say it in words
   when a connection fails and the stored entry has a key; nothing in this file can: the race reports only the main address's failure.
6. **Relays come from `Record.relays` only.** E3: the record's `addresses` should not carry the host's relay entries (`AddressKind::Relay(fp)` has no place in a record's `Kind`), and
   `relays` must hold each relay's fingerprint and addresses, or clients get no relay candidate from the DHT.
7. **Nothing is persisted** from the record: the stored entry is refreshed by the `Reach` of the next connection, as before.
8. The node is opened per call and dropped with the call. F4 opens its own to publish its request, after this one has finished (it dials a `Punch` this returned), from the file
   `dht::cache_path(state_dir)` names (`pub(super)`): the node supports two nodes on one file.

## For I2 (field test across networks)

- Watch with `RUST_LOG=velora_client_core=debug,mainline=error`: "no DHT key or secret" (nothing stored yet, so connect once at home first), "the host has no record in the DHT",
  "does not open with this device's secret" (removed, or stale secret), "is another host's", "hours from the clock", and at info "the host's record in the DHT lists N addresses and M relays, K ways in", then the
  race's own "connected through public 203.0.113.7:51820".
- The DHT is touched only 500 ms after the connect starts (or at once when nothing else is running); a connection that wins earlier never opens a node.
- Revoking a device: after the host's next publish its secret no longer opens the record; until then it can read the last one (the nodes keep it ~2 hours).

## Gotchas

- The first bind of the node's UDP socket may bring a Windows firewall prompt for an executable without a rule (C2).
- The tests never touch the network: `Fake` stands in for the node (`Source`), and the one real-node test uses `DefaultNodes::fixed(vec![])`.
- The 6 s cap is checked in two places: the node's own deadline is what is left of it after the opening, and `find` cuts a source that ignores its deadline one second later.

## Not tested

The real DHT with a record the host published (E3 does not exist yet: the by-hand check of the ticket, "a client reaches a host whose IP changed", needs it); the node path with a real
network; a record from a future version of the host (only a record version this build cannot read, which is "no candidates"); Linux and Android compile.
