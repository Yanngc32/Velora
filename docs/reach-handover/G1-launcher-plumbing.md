# G1 launcher plumbing: hand-over for G2 and G3 (and the review)

Branch `claude/reach-g1-launcher-plumbing-7e1a0f` (from 35081ec). Files: `crates/client/src/gui/{reach,strings,mod,this_pc}.rs`;
`reach.rs` is new. fmt, `clippy -p velora --all-targets -D warnings` and `cargo test -p velora` (25 pass, 15 of them new) green on Windows.
Linux was not compiled here. After this ticket `strings.rs`, `mod.rs` and `this_pc.rs` are frozen; G2 edits `reach.rs` and nothing else.
I also broke `reach.rs` seven ways on purpose (the request swapping two switches, a switch flipping another, a card for `None`, a Wake button
without a MAC, the router's open and shared swapped, the relay hint always on, the last connection never shown) and each made a test fail.

## What is there

```rust
// gui/reach.rs
pub(super) fn reach_card(ui, s: &Strings, reach: Option<&ReachStatus>) -> Option<Request>   // the card on This PC
pub(super) fn wake_button(ui, s, host: &KnownHost, card: Rect, config_dir: Option<&Path>)    // the device card's Wake button
pub(super) enum WakeState { Idle, Sending, Sent, NoRelay, Unsupported, Failed(String) }
pub(super) fn wake_state(ctx, host: &str) -> WakeState;  pub(super) fn set_wake_state(ctx, host: &str, WakeState)
```

- **The card** (`this_pc.rs`, one call after the stay-awake card): `Status.reach == None` draws nothing, not even the 16 pt under it. Otherwise one
  card: three switches (standalone, DHT, relay for others), each with a plain title and a note under it; under the standalone switch, while it is on,
  the router line (port open / shared address / no port), the public addresses and the IPv6 addresses; under the relay switch the names in
  `registered_with` (or, when no port is open and there are none, a hint to turn the switch on in another PC); at the bottom the kind and address
  the last device came in by. A click on a switch comes back from `reach_card` as `Request::SetReach` with the other two switches as the host
  reports them, and `this_pc.rs` sends it with `self.host.send`. The card sends nothing else and keeps no state.
- **The Wake button** (`mod.rs`, in `DeviceCard::show`, called only while no session is open): a small outlined chip in the card's top right corner,
  where a connected computer says "Connected", shown only for a computer whose `KnownHost.mac` is known. It is **inert**: a click does nothing yet.
  Its label (`Sending`) and tooltip (the other states, or what the button does) already follow `WakeState`, which is kept in egui's memory under the
  host's name, so the launcher needs no field for it.
- **Strings** (`strings.rs`): 30 new ones, `reach_*` and `wake_*`, in both languages. The compiler keeps them honest: one struct with two values, and a
  string nothing reads is a `dead_code` error under `-D warnings`. A test also draws every state and checks that each string is on screen in one of
  them (the `wake_*` ones in the tooltip), and another that PT and EN keep the same number of `{}`. G2 needs no new string for the states
  `hosts::wake` answers (`WakeOutcome::{Sent, Unsupported, NoRelay}`, F1; `wake_failed` takes an error text), nor for the relay lines: the switch
  carries the bandwidth note and `registered_with` is listed by name.

## For G2: what to fill in (all in `reach.rs`)

1. **The click of `wake_button`** (a comment marks the place): set `Sending` with `set_wake_state`, then on a thread (as `pair_back` in `this_pc.rs`
   does, with its own current-thread runtime) open the state with `StateDir::open(config_dir.map(PathBuf::from), "client")` and call
   `velora_client_core::hosts::wake(&state, &host.name)`; turn the outcome into a `WakeState` (`Sent -> Sent`, `Unsupported -> Unsupported`,
   `NoRelay -> NoRelay`, `Err(e) -> Failed(format!("{e:#}"))`) and give it to `set_wake_state(&ctx, &name, state)` with a clone of `ui.ctx()` taken
   before the thread starts (it also repaints). Do not start a second wake while the state is `Sending`. `WakeState` and `set_wake_state` carry
   `#[allow(dead_code)]` only because nothing builds those states yet: remove it.
2. **Where the outcome shows.** For now only in the tooltip (and `Sending` in the label): the card has no free line. `wake_button` receives the
   card's whole `Rect` (the area of `DeviceCard`) and draws into a child `Ui` at its top right, as `DeviceCard::show` does for "Connected": it can
   draw anywhere on the card the same way, and `config_dir` is there for the thread. The corner holds 160 pt, a 28 pt tall chip fits.
3. **The relay lines.** Already in the card; `ReachStatus` has nothing more to say about relays. Rewording is a `strings.rs` edit, which G2 cannot
   make: ask the coordinator.

## For G3

Nothing in `strings.rs` or the launcher is meant for the command line; `velora wake` and `velora connect` print their own English like the other
commands. F1's `Session::route()` (`Route` has `Display`) and `WakeOutcome` are what they print.

## Decisions to review

1. **`DeviceCard` gained a field**, `config_dir: Option<&Path>`, set from `Launcher.config_dir` where the card is built: three lines more in
   `mod.rs` than the one call (the field, its value, the `Path` import). The thread that wakes a computer must open the paired list
   (`hosts::wake(&StateDir, ..)`) and G2 cannot edit `mod.rs`. `wake_button` also takes the card's `Rect`. The signature is the contract.
2. **The Wake button is in the corner, not in the row of buttons.** Measured on a drawn frame: at the narrowest window a card is 432 pt wide and
   its row 396. In Portuguese Connect (110), Files (87) and Forget (157, as wide as its longer label "Segure para esquecer") take about 370; a fourth
   button of 81 pt overlapped Forget's area. In English it would have fitted (about 364). The row only has room at a card width of 495 pt and up.
3. **No Wake button without a MAC.** F1's `WakeOutcome::Unsupported` ("no MAC known") would be the answer to every click on a computer that
   predates reach, so those get no button; the first connection to a host that sends `Reach` teaches the MAC and the chip appears. The text for
   `Unsupported` stays for a MAC that vanishes in between.
4. **The three switches are independent.** The card forbids no combination (DHT without standalone, say) and sends what the user chose; E1's
   `set_switches` saves it and starts or stops each task on its own. If a combination should be refused, the host must do it, and the card shows
   what the host then reports.
5. **`SetReach` under the Windows service** needs an administrator (E1 keeps it out of `harmless`). A user without it flips a switch, the host answers
   "only an administrator can change this computer's access", the red banner of This PC shows that and the switch snaps back at the next status.
   The card does not warn beforehand (it cannot know whether the launcher is elevated). G2 may want a line under the title when `Status.service`.
6. **"The public address next to the QR code" (G2's ticket) cannot be done from `reach.rs`**: the QR code is drawn by `pair_card` in `this_pc.rs`,
   frozen, and the ticket allows one call there. The reach card lists the public and IPv6 addresses, and E1 already puts the public address in the
   pairing link, so the QR code carries it. If a line under the QR code is still wanted it needs a second call in `pair_card`: decide before G2.
7. **The router line** says "port open" only when the host reports a mapping with `public: true`; `public: false` is the CGNAT/double-NAT line,
   and standalone on with no mapping is "the router has not opened a port", which is also what shows in the first seconds, before the host has
   asked. CGNAT and UPnP appear only in the secondary line.
8. **`#[allow(dead_code)]` on `WakeState` and `set_wake_state`**, until G2 builds the states (see above).

## Gotchas

- `Status.reach.relay_for_others` is `switches.relay_for_others || relay_only` (E1): a `--relay-only` host reports true whatever was saved, and
  the card sends that true back with any other switch. Such a host has no launcher, so nothing is lost.
- A host from before standalone reach sends no `reach` (it reads as `None`): nothing is drawn and no `SetReach` is ever sent to it.
- The status poll is once a second and `SetReach` is answered with the new status at once (E1's handler saves and spawns, it does not wait for the
  router), so a switch can snap back for a frame or two while the reply arrives. `stay_awake_card` behaves the same.
- **The tests draw the card without a window.** `Frames` in `reach.rs`'s tests runs `egui::Context::run_ui` with the launcher's fonts and look
  (`theme::apply`), collects every `Shape::Text` and the 40 by 22 rectangles that are switch tracks, and clicks by feeding a first frame, then a
  frame with `PointerMoved`, press and release. `hover` rests the pointer long enough for a tooltip (`tooltip_delay` 0). Anything made of the
  launcher's widgets can be tested that way. After `run_ui` call `drop_without_applying_deltas` on the output or its textures panic when dropped.
  `strings::all()` (test only) gives both languages. `egui::Id::new` is deprecated in egui 0.37: `Id::unique`.
- To *look* at a frame, a throwaway test of mine tessellated it (`ctx.tessellate`) and filled the triangles into a PNG (about 90 lines, not
  committed: it would break on the next egui upgrade for no gain at runtime). It found the overflow above; the coordinator has it and the pictures
  (`G1-screens/` in the shared notes folder), ask for them before changing the layout.
- Addresses in the tests are documentation ranges (RFC 5737, RFC 3849); keep it so, the repo is public.

## Not tested

Linux compile; a window on screen (the egui frames are real, but nothing here ran inside `eframe`); a real host (E1's is on its own branch).
