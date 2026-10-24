# E3 host DHT record and device secrets: hand-over for F2, I2, H1 (and E1, E5, G2, the review)

Branch `reach-e3-host-dht` (from `integration-wave3`, cf92511): `3264806` (the manifest stanza), `c896795` (the code) and the commit of
this note. Files: `crates/host/src/reach/dht.rs` and `secrets.rs`, and one stanza in `crates/host/Cargo.toml` that the ticket's paused
clock needs (decision 6). fmt, `clippy -p velora-host --all-targets
-D warnings` and `cargo test -p velora-host` green on Windows (203 pass; 4 `#[ignore]`d: two from E1 that need a desktop, two of E3 that use
the public DHT, run by hand); Linux not compiled here. The new tests (69 that run, 2 by hand) ran 40 times in a row with the rest of
`reach::`, and 30 more on the final build, without a failure. Two independent reads (fresh agents, read-only, the first given no
conclusions) found 7 and 2 defects and a handful of tests that proved nothing; each defect was checked against the code and fixed or
documented, and each fix has a test. Checked by hand with 47 planted bugs: 44 make a test fail, 3 change nothing a test can see (a guard
that another one makes redundant, a blob that comes out the same either way, a branch nothing reaches).

## What it does

- **Files in the host state dir.** `dht_key.bin` (the host's Ed25519 seed, C1's `Keys`, made the first time and never replaced: every
  paired device holds its public half), `reach_secrets.json` (one secret per paired device and the shared one, text, written like
  `identity.json`), `dht_cache.txt` (C2's routing table and last `seq` numbers).
- **`dht::run`** (task while the DHT switch is on): loads the key (a file system that fails for the moment is waited out, 30 s and up;
  a file that is there and is not a key ends the task with an error, since replacing it would orphan every pairing), sets
  `ReachState::dht_key` (so pairing links carry `key=`/`secret=` and `Reach` carries the key), opens one `Node` (`Mode::Host`), gives it to
  E5's poller (`poll::set_source`), publishes. When it ends, however it ends (told to stop, aborted), `dht_key` is cleared and the poller's
  source is taken away: the host asks nothing more of the DHT. A put that was under way is not cancelled (C2's operations run to their end,
  25 s at most), so a record can still land after the switch went off.
- **When it publishes.** The first time once the state has been quiet for 3 s (at most 20 s after the first change); then whenever what the
  record shows or who can read it changes (same wait); never closer than 15 s; every 30 minutes anyway; and again after the machine slept
  (the monotonic clock stops in a suspend, so each look compares it with the wall clock, and two minutes of difference mean the record may
  be gone from the DHT). A failure is retried after 30 s, 1, 2, 4... up to 10 minutes. `ReachState` changes that the record does not show
  (clients, `last_reached`, the mapping status, the switches) publish nothing. A host with nothing to say (no address and no relay), with no
  device that holds a secret, or whose list of paired devices cannot be read, publishes nothing: what the DHT has says more, and a list that
  cannot be read must not be published for from memory.
- **What the record holds** (`Body::from_state`): `ctx.fingerprint`; `ReachState::record_addresses()` cut to 1 LAN, 2 VPN, 1 public (the
  mapped one, or the endpoint a cone NAT shows), 2 IPv6, and only texts that are socket addresses; `nat` from E5's `NatType`
  (`Open`, `EndpointIndependent` = `Cone`, `Dependent` = `Symmetric`, else `Unknown`); the first relay the host is registered with, with
  its first address, in `Record::relays` and **not** among the addresses (a `Kind::Relay` entry has no fingerprint, so no client could use
  it); the MAC; the time. The cut is what keeps the largest possible record (428 bytes, with the longest strings) small enough for
  `device_capacity()` = 11 devices.
- **Who can read it.** Each paired device that was given a secret, up to 11 paired devices. With more paired devices **everybody holds one
  shared secret** and the record has one wrap (`Sealed::per_device == false`). The mode is a function of the number of paired devices, so it
  cannot flip as addresses change. `reach_message` (so `HostMsg::Reach.secret`) always carries the secret the device must hold *now*, own or
  shared.
- **Secrets** (`secrets.rs`): `get`/`all` read, `on_paired` stores the link's secret (or forgets an old one when the link had none),
  `on_revoked` forgets, `dht::reach_message` makes one for a paired device that has none, and tells it only once the file holds it (zeros
  otherwise, which a client reads as "keep what you have"). Every answer is reconciled with `authorized_clients.json` first, so
  `velora-host revoke` while the host runs counts too (the publisher looks again every minute); a list that is not there, in a directory that
  is, is "nobody", one that cannot be read (or a directory that is gone: on Windows a share that dropped says "not found") is an error and
  drops nothing. A device that is given a secret has an entry; removing an entry, for any reason (revoked, paired anew with the old entry
  still there, an entry that could not be read), also drops the shared secret (the device may have held it), and a new one is made when it
  is next needed.

## What the other tickets must know

- **F2 (client).** Key = `KnownHost.key`, salt `record::SALT`, `seal::open(&blob, SALT, item.seq, &Secret::new(known_host.secret))`.
  `NotRecipient` is "revoked, or this device's secret is stale" (the host rotated the shared secret, or the device is one of more than 11):
  treat it as no record; the device learns the new secret with its next `Reach` over any other route. The record's `fingerprint` is the
  host's. `Public` may be the mapped address or the endpoint the NAT shows for the QUIC socket (`nat` says which kind of NAT: `Open` or
  `Cone` means a punch to it can work). Relays are in `relays` (fingerprint + address), never in `addresses`. At most 1 LAN, 2 VPN,
  1 public, 2 IPv6, 1 relay with 1 address. The device's secret changes only when it is told: F1 replaces it with every non-zero `Reach`.
- **E5 (poller).** `poll::set_source` gets a `NodeSource` (the ten lines of your doc comment) when the node is up and `None` when `dht::run`
  ends. `secrets::all` gives the poller `(fingerprint, secret)` for every paired device that holds one, and in the shared mode the same
  secret for all of them, which your `Poller` already groups. A host with a relay registered does not poll (your rule): the by-hand
  chain test clears the relays for that reason.
- **E1.** `service.rs::migrate_state` copies only `identity.json`, `authorized_clients.json` and `access_password.json` when the host moves
  to the Windows service: `dht_key.bin`, `reach_secrets.json` and `reach.json` stay behind, so the service's host would make a new key and
  new secrets while every pairing holds the old ones. Add the three files there (E1 owns it).
- **G2.** The record does not appear in `Status.reach` (T0 froze it): publishing, failing and the number of devices are in the log
  (`published the host's record ...` at info when something changed, a warn on the first failure of a streak, debug after).
- **H1 (docs).** The files above and what they hold. Revoking: a device removed in the launcher is left out of the next record (within
  about 15 s), one removed with `velora-host revoke` within a minute; it can still read what it fetched, and the nodes keep a record for
  hours. With more than 11 paired devices revoking one changes the shared secret, so the others cannot read the record until they connect
  once by another route; so does pairing the 12th. A pairing link carries a secret that the client does not use (F1 takes key and secret
  from the first `Reach`).
- **I2 (field test).** The check by hand is "the record resolves from another machine within a minute of a change", left to I2. On this PC,
  from a second node on the same line (`cargo test -p velora-host -- --ignored --nocapture public_dht`, throwaway key, documentation
  addresses, about a minute): the first record 10.7 and 15.4 s after the task started (cold node, two devices, 324 bytes), a change
  readable 17.9 s after it was made (twice: the 15 s gap, a put of a few seconds, a lookup). The same test has a device leave a punch item
  and finds it through the poller's `NodeSource`; the second by-hand test runs the chain to the end (a device leaves a request, E5's poller
  finds it through the node of `dht::run`, the responder sends a 1200-byte Initial to the endpoint named): 0.6 s from the poller's start.
  From another network: not tried.

## Decisions to review

1. **Capacity 11 and the caps on the record** (1 LAN, 2 VPN, 1 public, 2 IPv6, 1 relay with 1 address) are one decision: the caps give the
   largest record, `max_devices` of that is 11, and the shared mode starts at the 12th paired device. More devices or richer records are
   one constant each (`LIST_*` in `dht.rs`; a test pins the 11).
2. **The paired list is the truth, read at every use.** A device removed behind the host's back is noticed within a minute and its secret
   is dropped from the file; `on_revoked` only makes that quicker.
3. **The cliff of the shared mode.** The device that pairs as the 12th, and the revocation (or the pairing anew) of any device in the shared
   mode, change the secret every device must hold; a device that is away cannot read the record until it connects some other way. C1 says
   so; there is no way around it with one wrap. Going back to 11 devices makes each device's own secret current again, which it also
   learns only by connecting.
4. **Nothing is published without a recipient, and nothing from a list that cannot be read.** A last device removed leaves the old record
   in the DHT until it expires (hours); publishing an unreadable record over it would need a throwaway secret and a put for nobody.
5. **15 s between puts, 3 s of quiet, 30 s to 10 min of backoff**: the ticket's "never twice in one second" is a floor far below what a
   flapping relay link would cost (about 600 datagrams a put). All in `Timing`.
6. **The test-util stanza.** `crates/host/Cargo.toml` is E1's frozen file; the ticket's "paused clock" needs `tokio` with `test-util` as a
   dev-dependency (F1 has the same in client-core). One line in a new `[dev-dependencies]` block at the end of the manifest's dependencies,
   tests only, no `Cargo.lock` change, in a commit of its own (`3264806`); the coordinator approved it. Without it the 15 loop tests would
   need millisecond-scaled intervals on the real clock.
7. **A secret is told to a device only once it is saved,** so a host that restarts never has lost what a device holds. The price: while
   the state directory cannot be written no device is given a new secret (the ones that have one go on).
8. **The write happens under the lock,** with its `fsync`, the first time a device is given a secret (`reach_message` is a sync hook called
   from an async task, as the host's own state files are). The other callers (E5's poller every 10 s, the publisher) wait a moment then.
9. **"Not found" is "nobody" only in a directory that is there.** `Path::exists` and `StateDir::load` say "nobody" for any failure to look at
   the file, and std maps the errors of a share that is gone to `NotFound`; dropping every secret and writing the empty set over the real
   file is the one mistake that cannot be undone, so both reads (the paired list, the secrets) check the directory.

## Gotchas

- `secrets::on_paired` must come after `authorized_clients.json` was written (it does, in `server::authorize`): an entry for a device that
  is not on the list is dropped by the next call.
- The first `Reach` a device asks for creates its secret and wakes the publisher, so a device paired before the DHT was switched on is in
  the record about 20 s after it first connects, and can find the host by DHT from then on. A host whose paired devices have not connected
  since the switch was turned on publishes nothing (nobody holds a secret).
- `mainline=error` in the log filter is still needed (E1 did it).

## Not tested

Another network (the record read from outside this line), a table days old, long uptimes, a real NAT that changes the endpoint; Linux
and Android builds; the file permissions on Unix (`StateDir::save` sets them, no test here); a failing disk beyond the cases of the
tests (a directory in the way of the temporary file, of the file itself, of the key; a state directory that is renamed away and back);
an actual suspend (the detection is tested with a wall clock that jumps); the shared mode on the public DHT (one wrap of the same
layout, tested with sealing and opening only); that a put under way at stop finishes (C2's behaviour, read in its code).
