# G2 launcher relay and wake UI: hand-over for G3, H1 and I3 (and the review)

Branch `reach-g2-relay-wake-ui`, from `integration-wave2` (8539011, which `standalone-reach` has taken in since) plus **one merge of
`integration-wave3`** (`618e8ee`, allowed by the coordinator for this, to build on T1's control requests). Commits: `c7706db` (the Wake chip, the
card, the advice), `9cd3844` (the address under the QR code), `55e55bb` (the administrator message), `8ade60f` (a shorter label), `2f31ec3` and
`ffcaa71` (an earlier version of this note), `3fbe8ff` (a test fixture that tolerates new fields), `618e8ee` (the merge), `b970e2f` (the relay card)
and the commit of this version of the note. Files: `crates/client/src/gui/{reach,strings,this_pc}.rs`. fmt, `clippy -p velora --all-targets -D
warnings` and `cargo test -p velora` green on Windows (38 pass; G1 left 25). Linux was not compiled here. **No real host and no window were run**:
the launcher was driven with fake statuses in headless egui frames, and drawn to PNG with the throwaway rasterizer of G1 (pictures in `G2-screens/`
of the shared notes folder). I broke the code on purpose 24 ways and each made a test fail (rest and fading of the wake-up, the advice, the wake
outcomes, the QR note, the administrator refusal, and for the relay card: the code travelling instead of the fingerprint, a bare code not taken, the
reason left out, Remove asking for the wrong forget, the failure under the wrong form, the error already on screen taken as the answer, what was
typed kept after the request, the card skipped in the frame of a click).

## What a user sees (H1, I3)

- **Wake** (device card, top right, while no session is open): a small chip on every paired computer. A click runs `hosts::wake` on a thread
  (its own runtime, the launcher's own `--config-dir`, as `pair_back` does) and the answer comes back as a bubble under the card for 12 s, in plain
  words: *sent* ("the PC can take a minute; if it never does, Wake-on-LAN may be off in its network adapter settings or the BIOS"), *no relay* (you are
  not on its network and none of your PCs there could send it; one that stays on there can if "Let my other PCs connect through this one" is on)
  and *unsupported* (it never told Velora how to wake it; connect once while it is on, with a recent Velora on both sides). Any other error is shown
  as it is (`wake_failed`). "Sent" only says that the packet left. The chip reads "Waking…" while it works and is dimmed and deaf for 5 s after an
  outcome (D2's limiter lets a device start 6 requests and then one every 5 s, and each wake-up is one). Hovering it says what it does.
- **This PC, the first card** (top to bottom): the three switches; under *Reach this PC from other networks without a VPN*, while it is on, the router
  line (port open / shared address (CGNAT) / no port), the public and IPv6 addresses, **Reachable through** (the relays this PC is registered with, by
  name) and, when no port is open and no relay is registered, what is missing: with the DHT off and no IPv6 address "no way in yet: turn on *Find this
  PC...* or set up a relay PC" (E5: with no DHT and no relay the host cannot hear a punch request); with either of those, "no relay yet: set one up under
  *Relay PCs*". Under the relay switch: what a session costs (6 to 12 Mbit/s of this PC's internet each way) and a pointer to the second card. At the
  bottom, how the last connection came in.
- **This PC, the second card, *Relay PCs*** (T1's requests): the three steps of a relay in plain words, then two lists, each with its own form.
  *Relays this PC uses*: one line per relay with its name, a green dot and "Registered: your devices can reach this PC through it", or a grey dot and
  "Not registered: <the host's reason>", and a Remove chip (`RemoveRelay`); below, a box for a pairing link, a name (optional) and "Use as my relay"
  (`AddRelay`). *Computers allowed to use this PC as a relay*: the same for `relay_hosts` ("Registered here now." / "Not registered yet."), Remove
  (`RemoveRelayHost`), "Let it use this PC" (`AllowRelayHost`), and a line saying "turn on *Let my other PCs connect through this one* above" while some
  computer is allowed and that switch is off. The button waits for a link that can be read; a link that cannot gets "that is not a pairing link, click
  Show QR code, then Copy link on the other PC".
- **Under the QR code**: "Reachable from other networks at <public address>" when standalone reach is on and the router gave a public address
  (E1 puts it in the link, so the code carries it).
- **When the host says no**: whatever it answers a request of the cards with an error is said under the form or the switch that sent it, for 30 s
  (the launcher's own banner for an error is gone with the next status, a second later): "only an administrator can change this computer's access"
  (the Windows service, a user without rights) as "Only an administrator can change this, because Velora runs as a Windows service on this PC. Open
  Velora as administrator..."; the answer of a host that cannot read the new requests ("malformed request: ...") as "This PC's Velora is too old for
  this. Update it"; anything else (a computer cannot be its own relay, at most 16 relays...) as "Could not do that: <the host's words>". The banner
  words the first two as well, for any request.

## Setting up a relay (H1)

Three computers: **C** (phone or laptop you watch from), **H** (the host nobody can reach) and **R** (the relay PC, reachable from outside). What the
user does, and what it sends (none of it needs H and R to see each other):

1. Pair C with R, as usual (R: *Show QR code*; C: *Connect*).
2. **On H**, *Relays this PC uses*: paste R's pairing link (on R: *Show QR code*, *Copy link*), name it if wanted, *Use as my relay*. `AddRelay` carries R's
   addresses (`address` and `also`) and R's **host fingerprint**, taken from the link. H keeps it in `relays.json` and registers with R from then on (with
   standalone reach on). **On R**, *Computers allowed to use this PC as a relay*: paste H's pairing link, *Let it use this PC*. `AllowRelayHost` carries H's
   host fingerprint only; R never dials H, which is why it works for a host behind a CGNAT, and under the Windows service (R's client-side known hosts,
   which the service cannot see, are not used). R's switch *Let my other PCs connect through this one* must be on.
3. Pair C with H, as usual.

The one-time code of a link and its `key=` and `secret=` never leave the launcher: the requests have no field for them (a test checks what is sent). H's
link exists only while H's pairing window is open (10 minutes): copy it, paste it on R, and the window can be closed. The allowed-computer box also takes
a bare code (`VL1-...`), which carries the same fingerprint.

## For I3 (field test)

On H, *Relays this PC uses* shows R green when its registration is up and, when not, E4's reason in the host's words (it does not relay for other
devices, this device is not paired with the host...); on R, *Computers allowed...* shows H green while H is registered. Nothing in `Status.reach` counts
relayed clients (E4's `Relay::registered()` is not in it): on R look at the log lines E4's note lists. A Wake from a client away from H's network goes
through a relay H is registered with (F3) and answers *no relay* when there is none: that is the test that R's switch and the two steps above are right.
**At the time of writing the host's handlers for the four requests were still being written** (branch `reach-t1-relay-management`): until they land a host
answers them with "this build does not manage relays yet", which the cards show as "Could not do that: ...". Nothing here sends traffic but
`hosts::wake` and the control requests.

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
3. **No list of relayed clients on R**, only which allowed computers are registered: `Status` has nothing more.
4. **No picker of the paired computers** in place of pasting a link: where H already has R among its paired computers (or the other way round), a button
   per computer would do what the paste does with what the launcher knows (`KnownHost` has address, `also` and fingerprint). It needs the known hosts
   passed to `reach_card` (one more argument at its call in `this_pc.rs`).

## Decisions to review

1. **I ran `git merge integration-wave3` once**, as allowed, and nothing else of the kind. The branch now holds E4, E5, F2, F3 and T1's protocol.
2. **`strings.rs` was edited**, which G1's note called frozen: the coordinator allowed "what the ticket needs" and the ticket needs text. 26 strings
   added in all, 4 of G1's reworded. `reach_relay_help` is a pointer to the new card, not the paragraph about pairing the two PCs in both directions
   that it was in the first commits: `AddRelay` and `AllowRelayHost` replace that.
3. **Every computer gets the Wake chip**, G1's gate on a known MAC is gone: the third outcome (*unsupported*) is only ever seen by someone who clicks on a
   computer that never reported one, and it is the message that tells them to update Velora there.
4. **The Wake outcome is a tooltip kept open under the card**, not over it: over the card it hid Files and Connect. It covers a little of the card below
   for 12 s (a tooltip with only text lets clicks through).
5. **`this_pc.rs` has three small edits**, each with its strings and `reach.rs` side in its own commit: the call under the QR code (`pair_card`), the
   `reach_card` call (it passes `view.error`) and the banner (it words the error). The relay card needed none: `reach_card` draws both cards and returns
   the one request that was asked.
6. **An error is the answer to the cards' request only if it comes within 5 s of it and is not the one that was on screen when it went out**
   (`Asked`). An error to something else (a device removed, say) is left to the banner.
7. **"Reachable through" stayed** in the first card next to the router line (what works now), while the second card lists what is configured and why not.
   They overlap when a configured relay is registered. E4 may also register this host with a paired computer that is not in `relays`, which only the first shows.
8. **The advice rules** (`advice`): "no way in yet" needs standalone on, no open port, no registered relay, the DHT off and no IPv6 address (IPv6 may
   work); with the DHT or IPv6 it is the softer "no relay yet". An open port or a registered relay needs none.
9. **The numbers**: bubble 12 s, rest 5 s (D2's limiter), a wake request given up after 30 s (so a thread that died cannot leave "Waking…" up), a
   failure note 30 s, a request's answer within 5 s. Constants at the top of the wake code and of `Asked`.

## Gotchas

- egui decides a click from the widgets of the **previous** frame: a button that becomes clickable in a frame cannot take a click in that same frame.
  The tests give it one frame (`frames.run(Vec::new(), ..)`) after `advance` or after typing into a form.
- The text typed into the two forms lives in egui's memory under `Id::unique(("relay-link" | "relay-name", "use" | "allow"))`; the tests type with
  `type_into` and click on the text of a button (`Painted::rect`), found by where it was painted.
- `Tooltip::always_open(ctx, layer, id, anchor_rect)` plus `popup.align(RectAlign::BOTTOM_END)` is how to keep a tooltip open without a hover. It needs two
  or three frames to size itself, so tests look at a few frames.
- `egui::Id::new` is deprecated in egui 0.37: `Id::unique`.
- `is_old_host` matches the host's "malformed request" (`handle` in the host's `control.rs`) and `is_admin_refusal` its "only an administrator" (`Shared::control`
  in `server.rs`): the tests copy both texts, so if E1 rewords one the launcher shows the host's own words, which is still readable.
- The wake test runs the real `hosts::wake` against a scratch paired list (`Scratch`): a host with no MAC (answers *unsupported* at once) and one whose
  only address is in 203.0.113.0/24 (no adapter of this PC has it, so *no relay*, with no packet sent: the stored relays are empty). With F3 merged
  (it is in this branch) `wake_through_relay` is real and still answers *no relay* without traffic when no relay is stored; the fingerprint of that
  host must parse (it is made up in the test).
- The wake thread writes the outcome into egui's memory with the clock of the last frame (`ctx.input(|i| i.time)`), from outside the frame: fine, but a
  frame that never comes (the window hidden in the tray) shows it late, not wrongly.
- `Frames::until` sleeps 20 ms between frames and gives up after 10 s: a thread that hangs shows as that panic.
- Addresses in the tests are documentation ranges and the MAC and fingerprints are made up. Keep it so, the repo is public.
- The test fixture `reach()` ends with `..Default::default()` so that fields added to `ReachStatus` later do not break it.

## Not tested

Linux compile; a window on screen; a real host (E1's reach state, E4's registrations, T1's handlers), a real relay or wake-up on a network; the Windows
service's refusal (the host's text is copied into the test); typing into the link box with a keyboard (the tests put text into the box's memory).
