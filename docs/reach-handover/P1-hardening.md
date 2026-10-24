# P1 hardening: the service keeps the reach files, B1 removes only what is this PC's, host tests stay offline

Branch `reach-p1-hardening` (from `integration-wave3`, 410e8d8). Four small fixes that the E2 report found outside its file. Files:
`crates/host/src/service.rs`, `crates/host/src/reach/{mod.rs, dht.rs, secrets.rs, relay.rs}`, `crates/nat/src/mapping.rs` and this note.
No manifest or lock change. `cargo fmt --all --check`, `cargo clippy -p velora-host -p velora-nat --all-targets -- -D warnings` and
`cargo test -p velora-host -p velora-nat` are green on Windows (host: 335 passed, 0 failed, 5 ignored; nat: 122 passed, 0 failed, 4 ignored, and
its doc test). Linux and Android were not compiled here.

## 1. The service brings the reach files over (`service.rs`, `reach/mod.rs`)

`migrate_state` copied the identity, the authorized clients and the access password into the Windows service's state, and nothing else. The
service then started with a new DHT key and new device secrets (`dht_key.bin`, `reach_secrets.json`), no switches (`reach.json`) and no
relays (`relays.json`, `relay_hosts.json`, `relay_known.json`), and every paired device held a secret that opens nothing.

- `reach::STATE_FILES` (in `reach/mod.rs`, beside `SWITCHES_FILE`) lists the six names, and each name is defined once, where the file is
  kept: `velora_dht::keys::FILE_NAME`, `SWITCHES_FILE`, `secrets::FILE`, `relay::KNOWN_FILE`, `relay::RELAYS_FILE`, `relay::HOSTS_FILE`. The
  last four were private; they are `pub(super)` now (one word each, nothing else changed in `secrets.rs` and `relay.rs`: the coordinator
  agreed, and it is its own commit).
- `migrate_state` is split in two so that it can be tested without the Windows security calls: `copy_user_state(user_config, &to)` does the
  copying and returns `None` when the service has an identity already (the early return stays: nothing is copied over a service that has its
  own state); `migrate_state` then restricts the folder's access list and prints, as before. A file the user's host does not have is not
  invented.
- Tests (temp folders, `service::tests`): every file of the three that were copied and of `STATE_FILES` is copied; a user's host that has only an
  identity gives the service only an identity; a service with an identity keeps everything it has and receives nothing. In `reach::tests`, the
  list has no name twice, no path separators, and holds the six names the code gives itself.
- Not covered: a file the reach code starts to keep later and does not list (the list is kept by hand next to the names; the doc comment says
  so); `dht_cache` (the DHT routing table, rebuilt by itself); the `restrict_tree` step (it changes access lists, so no test runs it).

## 2. B1's UPnP removal deletes only what is this PC's (`crates/nat/src/mapping.rs`)

`DeletePortMapping` names the external port and nothing else, so on the router of another network (or any router that holds that number for
another computer) the old `remove` deleted someone else's forwarding.

- `Igd::entry_at(external_port)` reads what the router holds for UDP at that port. `igd-next` 0.18 has no `GetSpecificPortMappingEntry`, only
  `GetGenericPortMappingEntry` by index, so it reads the table entry by entry until the entry (or its end, error 713), at most 256 entries.
- The entry is this PC's when its internal client is the address this PC has towards that router (the one `AddPortMapping` was given) and its
  internal port is `mapping.local_port`. Only then is `DeletePortMapping` sent. The answers:
  nothing there: done (as before); something else there: nothing is deleted and the error says whose it is
  ("the router holds UDP 7420 for 192.0.2.99:7420, not for this PC's port 7420: left alone"); the table cannot be read (the router refuses, does
  not have the action, answers nonsense, or the entry is not among the first 256): nothing is deleted and the error says so. All of them are
  `Failure::Refused`, so `mapping::remove` returns `RemoveFailed` and E2 logs it at info; the mapping then ends with its lease.
- `upnp_map` no longer takes port 0 from `AddAnyPortMapping`: it counts as a router whose `AddAnyPortMapping` does not work and the explicit
  ports are tried (NAT-PMP already refused port 0).
- Tests: the fake at the level of calls (`FakeIgd`: this PC's mapping is deleted after one lookup; another computer's is left alone; the same
  address with another internal port is left alone; nothing there is done; an unreadable table deletes nothing; port 0 falls back) and the fake
  router that speaks SSDP and SOAP on loopback (now with `GetGenericPortMappingEntry`: the entry is read and then deleted among others'; another
  computer's stays; a TCP entry at the number is not this mapping; a router that refuses to list or answers a fault deletes nothing; a table
  longer than 256 is given up on; `AddAnyPortMapping` answering port 0 falls back to `AddPortMapping`).
- NAT-PMP is unchanged: its mappings belong to the address that asks.

## 3. The host's unit tests stay off the public DHT (`reach/dht.rs`)

The `Runtime` tests switch the DHT on (`SetReach { dht: true }`, `Switches { dht: true, .. }`), which starts `dht::run`, which opened a node with
the public bootstrap names on every interface.

- `dht::run` now opens `node_config(&ctx)`: `public_config(&ctx)` (what it always did) and, in a test build only, `offline(..)`: one bootstrap
  address nobody answers at (192.0.2.1, documentation range) and the loopback as the only interface, the same node E3's own tests use
  (`lonely_node` now calls it).
- Tests: `public_config` is the public DHT on every interface with the cache beside the key; `node_config` in a test build has nobody to ask and
  the loopback only; `dht::run` itself starts, announces the key and ends when told to with that node.
- Not covered: that `run` calls `node_config` and not `public_config` (it is one line; a unit test cannot see which sockets a node bound).
- **Left for P3 / the E5 author:** `punch::run` (E5) does the same kind of thing in the `Runtime` tests that switch `standalone` on: with
  `Observing.nodes` unset it resolves the public bootstrap names (`default_dht_nodes`, `punch.rs:204`) and pings those nodes. The same
  pattern fits (a test default of no nodes).

## 4. The stale comment (`reach/mod.rs`)

"The hooks are still stubs" in `setting_the_switches_saves_them_and_starts_the_tasks` now says that the tasks are the real ones and keep running.

## How it was checked

- `cargo fmt --all --check`, `cargo clippy -p velora-host -p velora-nat --all-targets -- -D warnings`, `cargo test -p velora-host -p velora-nat`
  (numbers at the top). No line of the new code is over 120 columns (the two over-long lines in `nat/src/mapping.rs` were there before).
- 17 mutations, each a defect put back into the code one at a time: the ownership check dropped; the internal port, or the address, not compared;
  a table that cannot be read taken for an empty one; the end of the table taken for an error; an entry of another protocol counted; the table
  read without a limit; a router that refuses to list believed to have nothing; port 0 accepted; the reach files not copied; a service's own
  state overwritten; a file missing from `STATE_FILES` (two ways); the node a test opens made the public one; the offline node with the public
  bootstrap nodes, and on every interface; the production node bound to the loopback. Every one makes some test fail. One survived at first
  (a table that cannot be read for a reason other than "not authorized" taken for an empty one), and the test now tries 606, 401 and 501.
- 25 runs in a row of the 48 tests of `reach::dht` and 25 of the 3 tests of `service`, with the final test binary: no failure.

## Decisions to review

1. **A router that will not let this PC read its table never gets the delete** (some hide it; `GetGenericPortMappingEntry` is allowed to be
   disabled). The mapping then ends with its lease: an hour as E2 asks, or never for a router that keeps only permanent mappings, until the
   next run asks for the same port again. The other choice, deleting anyway when the table is unreadable, brings the bug back on exactly
   those routers; the coordinator's wording ("delete only when its internal client and port are ours") was followed.
2. **A table scan instead of a lookup**, because of the library; it costs one SOAP call per entry up to the one wanted (a few milliseconds each
   on a LAN; most tables hold a handful). E2's stop waits 3.8 s for the removal, search for the router included.
3. **`cfg(test)` in the production function that builds the DHT node's settings.** The alternatives (an injection through the context) cannot
   reach the tests that start the `Runtime` with the switches already on.
4. **`STATE_FILES` is a hand-kept list** next to the names.
5. **E2's docs say UPnP "names no owner"** as one reason a move does not give the old port back. B1 checks the owner now, so that reason is
   weaker, but the rule stays: after a move the request would go to another router than the one that has the mapping, and there is nothing
   to give back there. E2's file was not touched in this ticket.
