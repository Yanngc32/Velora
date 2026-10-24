# G3 command line: hand-over for H1, I3 and the review

Branch `reach-g3-cli`, from `integration-wave3` (`5c628d7`, which has G1 and G2). Commits: `d13072d` (the code and its tests), `a993622` (a warning
when a window loses the race for the lock) and the commit of this note. File: `crates/client/src/main.rs`, and nothing else. fmt, `clippy -p velora --all-targets -D warnings` and `cargo test -p velora` green on
Windows (51 pass; G2 left 38, so 13 are new). Linux was not compiled here. **No real host was run**: the commands were driven through their pure
parts (argument parsing, outcome to text, route to words, the lock) and through the real `hosts::wake` against scratch paired lists. I broke the code
on purpose 12 ways (an unsupported host counted as success, the relay not named, the DHT library quieted even when `RUST_LOG` names it, one missing side
of the welcome still counting as a screen, the claim file name keeping the fingerprint's characters, a lock never seen, a host found by name only,
every session holding the relay, the refusal not saying what to do, a shared lock instead of an exclusive one, the relay's address left out of the
line, other words for the LAN) and each made a test fail.

## What a user sees (H1, I3)

- **`velora wake <host>`** (a name or an address, as for `connect`): calls `hosts::wake` and prints one of the launcher's texts. *Sent* goes to
  stdout with exit status 0 ("Wake-up signal sent. The PC can take a minute to start..."). The others go to stderr as `Error: ...` with status 1: *no
  relay* ("You are not on this PC's network, and none of your PCs there could send the signal. A PC of yours that stays on there can, if "Let my other PCs
  connect through this one" is on."), *unsupported* ("This PC has not told Velora how to wake it. Connect to it once while it is on, with a recent
  Velora on both sides.") and a failure (`wake_failed`: "Could not send the wake-up signal: <why>", for example `'x' is not paired yet`). The words
  are the launcher's (`wake_*`, `reach_relay` in `strings.rs`) and follow the system language as the launcher does, Portuguese or English.
- **`velora connect <host>`** prints, before the window opens and on stdout (the launcher throws away the stdout of its sessions): `Connected to
  'Office PC' through the local network (192.0.2.10:7420).` The words after *through*: `the local network`, `the VPN`, `the public address`, `its IPv6
  address`, `another PC of yours (relay) 'Laptop' at <the relay's address>` and `another route`, each with the address that won in brackets. They are the
  launcher's English labels (`reach_kind_*`, `reach_public`, `reach_v6`) in running text; a test fails if one of those is reworded. The relay is named
  after the paired computer with that fingerprint, else by the short fingerprint (`09:09:09:09:09:09`). `velora bench` says the same on its first line.
- **A host that only relays** (`velora-host --relay-only`: a welcome of 0 by 0 and nothing else, E1 decision 11): `connect` and `bench` end with `Error:
  This PC only relays connections: there is no screen to show.` and status 1, instead of an empty window (the launcher shows a failed session's last
  error line, so it shows this). `velora pair` pairs all the same and prints `Paired with 'X'. This PC only relays connections: there is no screen to
  show.` with status 0: pairing with a relay is how a device gets to use it.
- **A second window through the same relay** (D2, F3: a relay carries one connection to a host from a device at a time and the second takes the first
  over): a window whose session came through a relay holds a lock; any other `connect` or `bench` for that host on this computer refuses before it
  dials: `Error: 'Office PC' is already open on this computer through a relay, which carries one connection to a host at a time: close that window
  first.` Closing the window, or killing it, frees the lock.
- **The log**: the client's tracing filter is the host's: `RUST_LOG`, else `info`, plus `mainline=error` (docs/dht-spike.md, 9.2 and 10) unless
  `RUST_LOG` mentions `mainline` anywhere (`RUST_LOG=mainline=debug` brings the DHT library's warnings back).

## What could not be done inside main.rs

1. **A hole punch is not told apart.** `Candidate::route()` reports a punched connection as `AddressKind::Public` with the endpoint, and `Route` is
   only a kind and an address, so `connect` says *through the public address* for it. That is true (the connection is direct to that endpoint) but it
   is not the "hole punch" the ticket lists. It needs a field on `Route` in client-core (`punched: bool`, say); then `route_words` gets one more arm.
2. **The file window does not take part.** The Files button opens its window inside the launcher (`gui/files.rs` through `hosts::connect_files`) and
   `FilesSession` has no `route()`, so the launcher cannot tell that its file connection went through a relay, and a session cannot tell that a file
   window did. What is in place is the session side and the lock itself, which is the operating system's and so works between processes. To finish:
   client-core gets `FilesSession::route()`; the launcher calls, before it opens a file window, `crate::free_relay(&state, host)?` (the same refusal
   in the same words), and after `connect_files` returns, `crate::hold_relay(&state, Some(&fingerprint), files.route())` and keeps the value for as
   long as the window lives. Those four functions (`claim_relay`, `relay_busy`, `free_relay`, `hold_relay`) are private items of the crate root, which
   every module of the crate can call as `crate::...`; nothing had to be made `pub`.
3. **Portuguese.** `strings.rs` is not G3's, so the route words, the relay-only message and the relay refusal are English literals, like the other lines
   of the command line. The launcher shows the last error line of a failed session as it is, so a Portuguese user sees the last two in English in the
   device card. Entries in `strings.rs` (and `main.rs` reading them with `strings::current()`) would fix that; the texts are in `main.rs` as constants and
   one `bail!`.
4. **The README** lists the commands (lines 231 to 234: `pair`, `connect`, `list`, `bench`) and not `velora wake <host-name>`, nor that `connect`
   says its route. It is not G3's file; whoever writes the standalone-reach documentation should add both.

## For H1 and I3 (field test)

On a real network, with a recent host paired:
`velora wake H` on H's LAN while H sleeps (status 0 and the PC starts) and from another network with a relay registered (status 0); with H never having
reported a MAC (*unsupported*, status 1); and with no relay (*no relay*, status 1). `velora connect H` on the LAN says *the local network*; from outside
through a relay it says *another PC of yours (relay) 'R'*, and the host's "last reached" (`ClientMsg::Reached` carries the same `Route`) must agree. Pair
with a `--relay-only` host and connect to it for the two relay-only lines. In two terminals, `velora connect H` through a relay in one and the same in
the other: the second is refused at once and the first is not dropped. Check the stderr of a client with standalone reach on Windows: no flood of
`mainline` warnings (about 17 a second before).

## Decisions to review

1. **The refusal does not wait to learn the route.** The route is known only after dialing, and dialing is what drops the first window, so the check is
   made before, for any route: while a window of H holds a relay, a second `connect H` is refused even if it would have gone over the LAN. The lock is per
   host, not per relay; two windows through two different relays would be fine and are refused too. Telling the relay beforehand is not possible: the race
   picks it.
2. **The lock is taken after the connection**, when the route is known, and only for a relay route. Two windows started at the same moment both pass the
   check, the second takes the first over (as it always did) and fails to take the lock, which is logged as a warning ("another window of this computer
   held the relay to this host; this connection took it over"): it carries on.
3. **A lock that cannot be made stops nobody**: no file, no state directory or a read-only one only means the check does not see that window.
4. **The lock files stay.** `relay-<fingerprint>.lock` is created empty in `<config>/client/` the first time a host is reached through a relay and never
   removed: removing it while another process waits to open it would give two holders. One per such host.
5. **Wake in the launcher's words, localized; the rest English.** On a Portuguese PC the wake texts are Portuguese and the other lines of the command
   line English. Alternatives: all English (copy the three texts into `main.rs`), or Portuguese for the new lines too (item 3 above).
6. **Exit status of `wake`**: 0 only for *sent*; every other outcome is 1, the text tells which. Distinct codes (like `EXIT_PASSWORD_REQUIRED`) are an
   addition away if a script needs them.
7. **`bench` says the route and checks the relay too**, which the ticket did not list: it is `connect` without a window, and where the time goes depends
   on the route.
8. **`pair` with a relay-only host exits 0** (it did pair). `connect` and `bench` with one exit 1.
9. **`File::try_lock` and `try_lock_shared`** (stable since Rust 1.89, the MSRV is 1.95) are the lock: `LockFileEx` on Windows, `flock` elsewhere.

## Gotchas

- Hold the guard in a **named binding** (`let _claim = ...`): `let _ = ...` would drop it, and the lock, at once. `std::process::exit(0)` at a
  disconnect skips destructors; the operating system frees the lock.
- Two handles on the same file conflict on both systems even in one process (`LockFileEx` per handle, `flock` per open file description), which is what
  lets the tests hold and look at a claim without a second process.
- `strings::all()` lists Portuguese first, English second; the test of the route words reads index 1.
- `hosts::wake` in the tests runs against a scratch paired list: a host with no MAC (*unsupported* at once) and one whose only LAN address is in
  203.0.113.0/24 (no adapter of this PC has it, so *no relay* with no packet sent, the stored relays being empty). Addresses are documentation ranges and
  fingerprints and MACs are made up. Keep it so, the repo is public.
- `rustfmt` rewrote `main.rs` with LF line endings (the working tree had CRLF from `core.autocrlf`); git sees no change from that.

## Not tested

A real host: the route line of `connect` and `bench` (it needs a `Session`, and the client crate has no QUIC dependency to fake a host with), the
*sent* outcome of `wake` on a real LAN or through a relay, the welcome of a `--relay-only` host reaching `require_screen` (the host's own test shows
the 0 by 0 and client-core passes it on), a session through a real relay holding the lock, two real processes, the lock freed by a killed process
(an operating system guarantee), a Linux build.
