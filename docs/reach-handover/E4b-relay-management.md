# T1 + E4b + E6: relay management from the launcher, and the MAC address to wake through (hand-over for G2, H1, I3 and the review)

Branch `reach-t1-relay-management`, from `integration-wave3` (`c9c83a1`, which the coordinator has since merged there). Commits, in order:
`c9c83a1` (the protocol alone, for G2 to build on), `8016c4c` (the host's handlers and their tests), `c289bfb` (a reason does not outlive
the task that said it; the server test also reads `relays.json`), `25f56c9` (tests of the edges of what a list accepts), `40beca6` (E6),
`8ab1cc8` (two more tests, from the mutation checks), then the commit of this note. fmt, `clippy -p velora-protocol -p velora-host
--all-targets -D warnings` and `cargo test -p velora-protocol -p velora-host` green on Windows (host: 187 pass and 2 `#[ignore]`d by E1,
of them 10 new in `relay.rs`, 3 in `server.rs` and 4 in `wake.rs`; protocol: 53, 4 new). The relay tests ran five more times, the server
tests and the wake tests three, and the whole host suite once on one thread: no flake. Linux was not compiled here, and neither was the
client crate. I broke the new code on purpose 51 ways, one at a time (7 in `server.rs`, 40 in `relay.rs`, 4 in `wake.rs`: the requests
left open to everyone, the other addresses dropped, either list missing from the status, either source of trust ignored or the allow-list
missing from the 30 s tick, a removal that keeps the registration or does not save, a request that does not wake the registering task, the
caps off by one or applied to a replacement, a duplicate that is added instead of replacing, every rule of a name and of an address
loosened by one case, a damaged list written over, a computer allowed to be its own relay, a reason shown beside a registration, a
reason that outlives the task, a virtual or the wrong adapter chosen for the MAC): 49 made a test fail at once, and two got through, a
reason shown next to a registered relay and a fingerprint pasted with spaces; both have a test now (`8ab1cc8`) that fails them.

## Why

E4's note found the gap: a relay PC installed as the Windows service cannot see the user's client-side `known_hosts.json` (it is under
`%APPDATA%`, and the service's state is `C:\ProgramData\Velora\host`), and a host service cannot see the relay its user paired with. That is
the normal install here, so both lists are now edited through the control channel, which the launcher already uses for the switches.

## For G2: the names to build on (`velora_protocol::control`)

Every new field has `#[serde(default)]`: a status from a host that predates them reads with the two lists empty, and a request with a field
left out reads it as empty (the host then refuses what it cannot use, in words). A host that predates the requests answers them with
`malformed request: unknown variant ...`; there is no capability flag, so the launcher can show that error, or look at `Status.version`.

| request (`op`) | send it to | does |
|---|---|---|
| `AddRelay { name, address, also, fingerprint }` (`add_relay`) | **H**, the computer behind the CGNAT | H will register with the relay `fingerprint` (its full host fingerprint, base64url), dialed at `address` and then `also`. Same fingerprint again replaces the entry |
| `RemoveRelay { fingerprint }` | H | H stops registering with it and drops the registration. Unknown fingerprint: no error, nothing changes |
| `AllowRelayHost { name, fingerprint }` (`allow_relay_host`) | **R**, the relay | the computer with this *host* fingerprint may register here (a link and nothing else). Same fingerprint again replaces the entry |
| `RemoveRelayHost { fingerprint }` | R | it may not any more, and its registration is dropped. Unknown fingerprint: no error |

The reply to each is the usual `Status`, taken after the change, so the lists below are already updated in it. In `ReachStatus` (both
default empty; `registered_with` is unchanged):

```rust
pub relays: Vec<RelayEntry>,            // H: what it is set to register with. { name, fingerprint, address, registered: bool, reason: Option<String> }
pub relay_hosts: Vec<RelayHostEntry>,   // R: the computers allowed.            { name, fingerprint, registered: bool }
```

```json
{"op":"add_relay","name":"Office PC","address":"203.0.113.10:7420","also":["198.51.100.20:7420"],"fingerprint":"<R's host fingerprint>"}
{"op":"allow_relay_host","name":"Home PC","fingerprint":"<H's host fingerprint>"}
```

**Where the fingerprints come from.** For `AddRelay`, from H's own paired-computer entry for R (`KnownHost`: `name`, `address`, `also`,
`fingerprint` map onto the request one for one). For `AllowRelayHost`, from the pairing offer that H sent (its pairing link carries H's host
fingerprint: E4's "For G2" paragraph), so R needs neither to dial H nor to be paired with it as a client. A fingerprint that does not
decode to 32 bytes is refused by the host (`Fingerprint::from_base64`), so a typo cannot be saved.

**The pairing triangle, revised** (E4's note has the full text). (1) C is paired with R as a client of R, and (3) C is paired with H, as
before. (2) is now either of two things on R: R's user paired R's client side with H (`known_hosts.json`, as before, which still works for a
relay the user runs themself), or R's host was told `AllowRelayHost` for H. The second needs nobody to dial H, so the limit that pairing
back has (H and R on the same network at that moment, E4's note) is gone: R needs only H's host fingerprint, which H's offer carries. And H
must know where R is: R in H's `known_hosts.json` (not seen by a service) or `AddRelay`.

**What the status says.**

- `relays[i].registered` is "H holds a registration with that relay now". When it is not, `reason` is, in this order: `"this computer only
  relays"` (`--relay-only` hosts never register), `"standalone reach is off"` (the switch; the entry waits for it), else what the
  registering task last said about that relay (`"it refused this host: this device is not paired with the host"`, `"it does not relay for
  other devices"`, `"the relay removed this host"`, a connection error...), or `None` while the first try has not ended. The text is the
  host's English; it is not localized and not a code. If G2 wants to translate the common ones it has to match the text, which breaks
  silently: ask for codes in `RelayEntry` if that matters.
- `relays` lists the relays in `relays.json` only. A relay H found through a paired computer (the CGNAT fallback) is in `registered_with`
  when it is up, and is not in `relays` (the user never asked for it). `RemoveRelay` edits `relays.json` only: a computer that is also one
  of this PC's paired ones keeps being used as one while this PC has no public address, exactly as before the entry existed.
- `relay_hosts[i].registered` is "that computer has a registration here now" (D2's `Relay::registered()`). `relay_hosts` lists the entries
  of `relay_hosts.json` only: a computer R trusts through `known_hosts.json` is not listed, and `RemoveRelayHost` does not undo that trust.
- Registering is quick: `AddRelay` and `RemoveRelay` wake the registering task at once (a `Notify`), so the next status shows the result
  in seconds, not at the 30 s rescan. The task runs only while `standalone` is on and the host is not `--relay-only`; with the switch off
  the entry is stored and waits.

**Privileges.** Under the Windows service all four need an administrator, like `SetReach`: they are out of `harmless` in `Shared::control`,
and the refusal is the same sentence ("only an administrator can change this computer's access"). A host the user runs themself has no
such check, as for every request.

## Host side (`reach/relay.rs`, `server.rs`)

| file in the host's state dir | written by | read by |
|---|---|---|
| `relays.json` | `AddRelay` / `RemoveRelay` (or by hand: `known_hosts.json`'s shape, E4's note) | the registering task, every 30 s or when woken |
| `relay_hosts.json` (new) | `AllowRelayHost` / `RemoveRelayHost` | `relay::trusts` at each link, the serving task's 30 s `reconcile`, `Status` |

`[ { "name": "Home PC", "fingerprint": "<base64url>" } ]`. `relay::trusts` is now `relay_hosts.json` **or** the client-side
`known_hosts.json`; `server::authorize` calls it as before (a link hello from a fingerprint it trusts is let in as a link only, E4's
rules). `reconcile` keeps a registration while its host is in `authorized_clients.json`, `relay_hosts.json` or the client-side list, and
drops it when it is in none. `RemoveRelayHost` saves the list and then does what a revoke does (`on_revoked`): `Relay::remove` (the
connection ends with `CLOSE_REMOVED`) and the host is forgotten in `relay_known.json`.

What the host checks (a refusal is words in the reply, and changes nothing):

- the fingerprint decodes to 32 bytes (surrounding spaces are ignored), and is not this computer's own (`a computer cannot be its own relay`
  / `cannot register with itself`);
- `address` and each of `also` are `ip:port` (IPv6 in brackets) or `name:port` with a DNS name (labels of letters, digits and hyphens,
  none starting or ending with one, 63 characters at most, 253 in all), port 1 to 65535, no scheme; `also` has 8 at most;
- `name`: control characters out, at most 64 characters, the short fingerprint when nothing is left (empty or only spaces);
- 16 relays and 64 allowed computers at most (`MAX_LISTED_RELAYS`, `MAX_ALLOWED_HOSTS`, `pub`), checked only for a new entry: replacing
  one in a full list works;
- a list file that cannot be read (damaged by hand, say) is **refused**, not overwritten: the reply says `<file> cannot be read; fix or
  remove it`, and the file is left as it is. Edits take a lock, so two requests at once cannot undo each other.

`ReachState::status()` (`reach/mod.rs`, E1's file) builds `ReachStatus` field by field: it gets the two lists empty and `Shared::status`
(`server.rs`) fills them in from the files, because the reach state does not read them. That is the only change in `mod.rs` for T1.

## E6: the MAC address (`reach/wake.rs`)

`wake::local_mac()` = the first adapter of `velora_nat::addresses::local_macs()` that is not `virtual_adapter`, `None` when there is none
(a MAC that a VM switch, a container or a VPN made up wakes nothing; `local_macs` already puts real adapters first and the one with the
default route first among them, so this is "the adapter the PC is on the network through, unless that one is virtual"). The choice is
`choose(&[LocalMac])`, tested on made-up lists in any order. A computer with only virtual adapters has no MAC to give: none is registered
with a relay or published, and a client asked to wake it is told it never said how (`WakeOutcome::Unsupported`, F1). A `debug` line says so.

The plumbing is E1's and was not touched except for one number: housekeeping calls `local_mac` from a blocking thread when the host
starts and every `MAC_REFRESH`, keeps it in `ReachState::mac`, and E4 (registration, and again when it changes) and E3 (the record) follow
the state. **`MAC_REFRESH` went from 30 minutes to 5** (`reach/mod.rs`, one constant; E1's note said 30) because the ticket asks for a
few minutes: a laptop that moves to another adapter should not wait half an hour to tell the relays. A write that leaves the state as it
was wakes nobody, so asking more often costs one blocking interface listing and no traffic; a computer with no real adapter asks less
and less often, up to every 5 minutes. Revert the constant if `mod.rs` should stay frozen.

## Decisions to review

1. **`relay_hosts.json` as a second source of trust**, beside the client side's `known_hosts.json` (E4's decision 1 said trust comes only
   from there; the brief for this ticket asked for the file). It is written only by an administrator under the service (or the user for
   a host they run), and it grants a link: no session, no files, no password question, `RelayRegister` only.
2. **`relays` lists only `relays.json`, `relay_hosts` only `relay_hosts.json`.** The launcher's lists are what the user asked for; the
   derived ones stay in `registered_with`, and the trust from `known_hosts.json` is removed by forgetting the computer, not by this request.
3. **`reason` is free text** in English, and `None` before the first attempt ends (not "trying"): the launcher can say "connecting" for
   `registered == false && reason == None && the switch is on`. A reason is kept until the relay registers, is removed from the list, or
   the registering task restarts (it clears them when it starts, so turning the switch on again does not show hours-old words).
4. **Damaged lists are refused, not repaired.** `relays.json` is the user's hand work in E4's note; overwriting a file that does not parse
   would lose it. The cost: a launcher user with a broken file gets an error until someone fixes it. (The registering task, on a
   `relays.json` it cannot read, leaves the registrations as they are: E4.)
5. **A duplicate `also` or an `also` equal to `address` is stored as given**; the dialer drops duplicates.
6. **An address with a name is checked for form, not resolved**: `AddRelay` does not dial, so a wrong but well-formed address is saved and
   shows up as a `reason` after the first try.
7. **`MAC_REFRESH` 30 → 5 minutes** (above).

## Outside my files

- `crates/host/src/reach/mod.rs`: the two lines in `ReachState::status()` (`relays: Vec::new(), relay_hosts: Vec::new()`) so it compiles,
  and `MAC_REFRESH`. `docs/reach-handover/E1-host-plumbing.md`: the cell that said "every 30 min". `docs/reach-handover/E4-host-relay.md`:
  a paragraph under "Limit to know" that says this removes it.
- **`crates/client/src/gui/reach.rs` (G2's) has a test helper** `reach()` that builds a `ReachStatus` field by field and breaks with the
  two new fields unless it ends with `..Default::default()`; G2's note says its branch already does (`3fbe8ff`). I did not edit that file
  and did not compile the client crate.
- **Not in the status:** how many clients are relayed through this computer right now, and which of the registered computers has one
  (D2's `Relay::registered()` has both; G2's note asks for it for the field test). A field for it would be another protocol change.

## Not tested

Linux compile; a Windows service relay with a real administrator (the pipe's privilege flag is faked in the tests, as E1's are); a relay
reached by `name:port` (the resolver path is E4's and untested); the 30 s timers (the rescan by hand is tested, the periodic one is not);
`local_mac()` against a real set of adapters beyond "it is the choice from the list this computer reports" (no VM or VPN adapter to hand).
