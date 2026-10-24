# G2 launcher relay and wake UI: hand-over for G3, H1 and I3 (and the review)

Branch `reach-g2-relay-wake-ui` (from `integration-wave2`, 8539011, which `standalone-reach` has since taken in). Commits: `c7706db` (the Wake chip and the card), `9cd3844` (the address
under the QR code), `55e55bb` (the administrator message), `8ade60f` (a shorter label), `2f31ec3` (this note) and `3fbe8ff` (a test fixture that tolerates new fields). Files:
`crates/client/src/gui/{reach,strings,this_pc}.rs`. fmt, `clippy -p velora --all-targets -D warnings` and `cargo test -p velora` green on
Windows (33 pass, 8 more than G1 left). Linux was not compiled here. **No real host and no window were run**: the launcher was driven with fake
statuses in headless egui frames, and drawn to PNG with the throwaway rasterizer of G1 (pictures in `G2-screens/` of the shared notes folder).
I broke the code on purpose 15 ways (the rest after an outcome, advice swapped, "no relay" told as "sent", a request never given up, an outcome
that never fades, the QR note shown with standalone off or with only one address, the administrator refusal not recognised, not tied to the card's
own request, not expiring, not worded) and each made a test fail.

## What a user sees (H1, I3)

- **Wake** (device card, top right, while no session is open): a small chip on every paired computer. A click runs `hosts::wake` on a thread
  (its own runtime, the launcher's own `--config-dir`, as `pair_back` does) and the answer comes back as a bubble under the card for 12 s, in plain
  words: *sent* ("the PC can take a minute; if it never does, Wake-on-LAN may be off in its network adapter settings or the BIOS"), *no relay* (you are
  not on its network and none of your PCs there could send it; one that stays on there can if "Let my other PCs connect through this one" is on)
  and *unsupported* (it never told Velora how to wake it; connect once while it is on, with a recent Velora on both sides). Any other error is shown
  as it is (`wake_failed`). "Sent" only says that the packet left. The chip reads "Waking…" while it works and is dimmed and deaf for 5 s after an
  outcome (D2's limiter lets a device start 6 requests and then one every 5 s, and each wake-up is one). Hovering it says what it does.
- **This PC, the card** (top to bottom): the three switches; under *Reach this PC from other networks without a VPN*, while it is on, the router
  line (port open / shared address (CGNAT) / no port), the public and IPv6 addresses, **Reachable through** (the relays this PC is registered with, by
  name) and, when no port is open and no relay is registered, what is missing: with the DHT off and no IPv6 address "no way in yet: turn on *Find this
  PC...* or set up a relay PC" (E5: with no DHT and no relay the host cannot hear a punch request); with either of those, "no relay yet: turn on *Let my
  other PCs connect through this one* on another PC and pair the two". Under the relay switch: what a session costs (6 to 12 Mbit/s of this PC's
  internet each way) and **the pairing triangle in one paragraph**: pair your other devices with this PC as usual, then pair this PC and the PC you want to
  reach with each other, in both directions (on the Connect page keep *Also let it access this PC* on), with both PCs on the same network (a PC behind a
  CGNAT cannot be dialed back otherwise, E4). At the bottom, how the last connection came in.
- **Under the QR code**: "Reachable from other networks at <public address>" when standalone reach is on and the router gave a public address
  (E1 puts it in the link, so the code carries it).
- **Administrator rights**: under the Windows service a user without them gets "only an administrator can change this computer's access" from the
  host. The banner of This PC now says it in plain words with what to do, and when the refusal answers a switch the card itself flipped, the card keeps
  a red notice at its top for 30 s (the banner is gone with the next status, a second later). Refusals to other requests only get the plain banner.

## For I3 (field test)

Nothing in `Status.reach` counts relayed clients or registered hosts (E4's `Relay::registered()` is not in it): on the relay PC look at the log lines
E4's note lists; on the host, **Reachable through** lists a relay only while its registration is up, and the "no way in yet" / "no relay yet" lines
should disappear when one registers. A Wake from a client away from the host's network goes through a relay registered by that host (F3) and
answers *no relay* when there is none: that line is the test that the relay PC's own switch and pairings are right. Everything above can be checked
with the launcher alone; nothing here sends traffic but `hosts::wake` and the `SetReach` request.

## For G3

- `velora wake <host>` can say the same three things in the same words: `wake_sent`, `wake_no_relay` (a template: fill it with `reach_relay`),
  `wake_unsupported` and `wake_failed` are in `strings.rs` (`gui::strings::current()` is already used from `main.rs`). `velora_client_core::hosts::wake`
  returns `WakeOutcome::{Sent, Unsupported, NoRelay}` or an error.
- **"This PC only relays"** (E1's note: a `--relay-only` host answers an ordinary session with a Welcome of 0 by 0 and nothing else) is **not
  done, and cannot be from `reach.rs`**: the launcher never sees the Welcome (the session is a child process) and `Status.reach` does not say that a
  host is relay-only (it reports `relay_for_others` true for a relay-only host and for one with the switch on). The place is the session setup in
  `main.rs`: when the Welcome has `width == 0 || height == 0`, fail with a plain message; the launcher already shows a failed session's last error
  line. Suggested words: "This PC only relays for your other PCs: it has no screen to show." / "Este PC só retransmite para os seus outros PCs: ele
  não tem tela para mostrar." (needs a string in `strings.rs`, which G3 may add since `main.rs` will read it).

## What is not here, and why

1. **The relay-only message** (above).
2. **One client per host per relay** (D2, F3): a file window and a session for the same host through the same relay take each other over. The
   launcher cannot tell which route a session took (it is another process), and the Files button is in `DeviceCard`, which this ticket may not change.
   H1 should say it; a fix would need the session to report its route.
3. **A relay PC with an access password refuses paired clients' links** (F3 decision 1, E4): they have no password to give on a link, so the relay switch
   does nothing for them. Either E4 exempts paired clients (`link_hello && known` in `authorize`, one condition) or the card should warn when
   `Status.password_set` and the relay switch is on; I did neither (the card does not receive `password_set`).
4. **E4's "simpler way to guide" the triangle** (an offer from the host that the relay PC allows with one tap, recording the host's fingerprint
   without dialing it; a list of the computers allowed to use this PC as a relay; why a registration failed) needs `pair_back` and the offers (in the
   frozen `this_pc.rs`/`mod.rs`) and `Status` fields that do not exist. The paragraph above is what could be done in `reach.rs`.
5. **A relay under the Windows service does not see the PCs paired in the launcher** (E4 "Limits to know"): H1 must say that a service relay needs the
   host's fingerprint added by hand for now.
6. **T1 (relay management)** was merged into `integration-wave3` after this branch was cut, so none of it is used here: `ReachStatus.relays` (each
   relay this host is set to register with, `registered` or not, and the `reason` when it is not) and `relay_hosts` (the computers allowed to register
   here), with `AddRelay`, `RemoveRelay`, `AllowRelayHost` and `RemoveRelayHost`. A launcher ticket for it would replace the one line **Reachable
   through** in `standalone_details` with a line per relay (`status_line` already draws a dot, a sentence and a detail that wraps: the reason is the
   detail) and add the lists and the buttons; `labelled` and `switch_row` are reusable. The test fixture `reach()` ends with `..Default::default()` so that
   the two new fields do not break it.

## Decisions to review

1. **`strings.rs` was edited**, which G1's note called frozen: the coordinator allowed "what the ticket needs" and the ticket needs text. 4 strings
   added, 4 reworded (`reach_relay_text`, `reach_relays_none`, `wake_sent`, `wake_no_relay`).
2. **Every computer gets the Wake chip**, G1's gate on a known MAC is gone: the third outcome (*unsupported*) is only ever seen by someone who clicks on a
   computer that never reported one, and it is the message that tells them to update Velora there.
3. **The outcome is a tooltip kept open under the card**, not over it: over the card it hid Files and Connect (a tooltip with only text lets clicks
   through, but it is not seen). It covers a little of the card below for 12 s.
4. **`this_pc.rs` has three small edits**, each in its own commit with its strings and `reach.rs` side: the call under the QR code (`pair_card`), the
   `reach_card` call (it passes `view.error`) and the banner (it words the error). The ticket allowed the first.
5. **The notice on the card only answers the card's own request**: the refusal must arrive within 5 s of a request that `reach_card` returned. A
   refusal to a removal, say, is only worded by the banner.
6. **"Reachable through" moved** from under the relay switch (G1) to the standalone section: it is how this PC is reached, not what it lets others do.
7. **The advice rules** (`advice`): "no way in yet" needs standalone on, no open port, no registered relay, the DHT off and no IPv6 address (IPv6 may
   work); with the DHT or IPv6 it is the softer "no relay yet". An open port or a registered relay needs none.
8. **The numbers**: bubble 12 s, rest 5 s (D2's limiter), a request given up after 30 s (so a thread that died cannot leave "Waking…" up), the
   refusal notice 30 s. All constants at the top of the wake code and of `Asked`.

## Gotchas

- egui decides a click from the widgets of the **previous** frame: a button that becomes clickable in a frame cannot take a click in that same frame.
  The tests give it one frame (`frames.run(Vec::new(), ..)`) after `advance`.
- `Tooltip::always_open(ctx, layer, id, anchor_rect)` plus `popup.align(RectAlign::BOTTOM_END)` is how to keep a tooltip open without a hover. It needs two
  or three frames to size itself, so tests look at a few frames.
- `egui::Id::new` is deprecated in egui 0.37: `Id::unique`.
- The wake test runs the real `hosts::wake` against a scratch paired list (`Scratch`): a host with no MAC (answers *unsupported* at once) and one whose
  only address is in 203.0.113.0/24 (no adapter of this PC has it, so *no relay*, with no packet sent: the stored relays are empty). When F3 merges,
  `wake_through_relay` is real; with no stored relays it must still answer *no relay* without traffic, and the fingerprint of that host must parse (it is made
  up in the test). If F3 changes that, change the test's host, not the product.
- The wake thread writes the outcome into egui's memory with the clock of the last frame (`ctx.input(|i| i.time)`), from outside the frame: fine, but a
  frame that never comes (the window hidden in the tray) shows it late, not wrongly.
- `Frames::until` sleeps 20 ms between frames and gives up after 10 s: a thread that hangs shows as that panic.
- Addresses in the tests are documentation ranges and the MAC is a made-up locally administered one. Keep it so, the repo is public.

## Not tested

Linux compile; a window on screen; a real host (E1's reach state, E4's registrations), a real relay or wake-up on a network; the Windows service's
refusal (the host's text is copied into the test, `REFUSAL`: if E1 rewords it, `is_admin_refusal` stops matching and the raw text shows).
