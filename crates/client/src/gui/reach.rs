//! Standalone reach in the launcher (`docs/nat-traversal.md`): the card on This PC that shows how
//! this computer is reached from other networks and switches its parts, and the Wake button of a
//! device card.
//!
//! What the host reports (`Status.reach`) becomes text in plain functions, which the tests check
//! without a window; the tests also draw the card in a headless egui frame.

use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use eframe::egui::{self, Align, Layout, RichText, Sense};
use velora_client_core::WakeOutcome;
use velora_protocol::{
    control::{MappingStatus, ReachStatus, Request},
    identity::{KnownHost, StateDir},
    wire::AddressKind,
};

use super::{
    divider,
    strings::{fill, Strings},
    theme::*,
    widgets::*,
};

/// The three switches of standalone reach. `Request::SetReach` carries all of them, so a card that
/// flips one starts from what the host reports for the other two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Switches {
    standalone: bool,
    relay_for_others: bool,
    dht: bool,
}

impl Switches {
    fn of(reach: &ReachStatus) -> Self {
        Self { standalone: reach.standalone, relay_for_others: reach.relay_for_others, dht: reach.dht }
    }

    fn request(self) -> Request {
        Request::SetReach { standalone: self.standalone, relay_for_others: self.relay_for_others, dht: self.dht }
    }
}

/// What the router did about this computer's port, as the host reports it.
#[derive(Debug, PartialEq, Eq)]
enum Mapping<'a> {
    /// Standalone reach is off: the router is not asked for anything.
    Off,
    /// On, and no port is open: the router did not answer, or the host has not asked yet.
    Closed,
    /// A port is open and the router's address is public.
    Open(&'a MappingStatus),
    /// A port is open, but the router's address is shared or private (CGNAT, a second router): the
    /// port reaches no further than the next router.
    Shared(&'a MappingStatus),
}

fn mapping_of(reach: &ReachStatus) -> Mapping<'_> {
    match (&reach.mapping, reach.standalone) {
        (_, false) => Mapping::Off,
        (None, true) => Mapping::Closed,
        (Some(mapping), true) if mapping.public => Mapping::Open(mapping),
        (Some(mapping), true) => Mapping::Shared(mapping),
    }
}

/// A line of status: whether it is good news, what it says and the technical detail under it.
#[derive(Debug, PartialEq, Eq)]
struct Line {
    good: bool,
    text: String,
    detail: String,
}

fn mapping_line(mapping: &Mapping, s: &Strings) -> Option<Line> {
    let (good, text, detail) = match mapping {
        Mapping::Off => return None,
        Mapping::Closed => (false, s.reach_mapping_closed, s.reach_mapping_closed_detail.to_string()),
        Mapping::Open(mapping) => {
            (true, s.reach_mapping_open, fill(s.reach_mapping_open_detail, &[&protocol_name(&mapping.protocol)]))
        }
        Mapping::Shared(mapping) => {
            (false, s.reach_mapping_shared, fill(s.reach_mapping_shared_detail, &[&mapping.external]))
        }
    };
    Some(Line { good, text: text.to_string(), detail })
}

/// The router protocol as people write it.
fn protocol_name(protocol: &str) -> String {
    match protocol {
        "natpmp" => "NAT-PMP".into(),
        "upnp" => "UPnP".into(),
        other => other.into(),
    }
}

fn kind_label(kind: &AddressKind, s: &Strings) -> &'static str {
    match kind {
        AddressKind::Lan => s.reach_kind_lan,
        AddressKind::Vpn => s.reach_kind_vpn,
        AddressKind::Public => s.reach_public,
        AddressKind::V6 => s.reach_v6,
        AddressKind::Relay(_) => s.reach_kind_relay,
        AddressKind::Other(_) => s.reach_kind_other,
    }
}

fn last_reached_text(last: &(AddressKind, String), s: &Strings) -> String {
    format!("{} · {}", kind_label(&last.0, s), last.1)
}

/// The relays this computer is registered with, by name.
fn registered_names(reach: &ReachStatus) -> Option<String> {
    (!reach.registered_with.is_empty()).then(|| reach.registered_with.join(", "))
}

/// What this computer still lacks to be reached from other networks, said only where it matters: no
/// port is open and no relay is registered.
#[derive(Debug, PartialEq, Eq)]
enum Advice {
    /// The DHT is off too (and there is no IPv6 address to try): nothing even tells this PC that a
    /// device wants in, so a hole cannot be punched either.
    Blind,
    /// A device can still find this PC (the DHT or IPv6), but a relay would be the sure way.
    NoRelay,
}

fn advice(reach: &ReachStatus) -> Option<Advice> {
    let no_port = matches!(mapping_of(reach), Mapping::Closed | Mapping::Shared(_));
    if !no_port || !reach.registered_with.is_empty() {
        return None;
    }
    Some(if reach.dht || !reach.v6.is_empty() { Advice::NoRelay } else { Advice::Blind })
}

fn advice_text(advice: &Advice, s: &Strings) -> String {
    match advice {
        Advice::Blind => fill(s.reach_advice_blind, &[s.reach_dht]),
        Advice::NoRelay => fill(s.reach_relays_none, &[s.reach_relay]),
    }
}

/// What the host says to a change that only an administrator may make: it runs as the Windows
/// service, and the launcher's user is no administrator.
fn is_admin_refusal(error: &str) -> bool {
    error.contains("only an administrator")
}

/// The words for an error from the host: plain for the one that a person can do something about,
/// the host's own for the rest.
pub(super) fn friendly_error(s: &Strings, error: &str) -> String {
    if is_admin_refusal(error) {
        s.reach_admin_needed.to_string()
    } else {
        error.to_string()
    }
}

/// How soon after the card sent a request a refusal counts as the answer to it.
const ASKED_SECONDS: f64 = 5.0;
/// How long the card keeps saying that its change was refused. The launcher's own banner for an
/// error goes with the next status, a second later.
const REFUSED_SECONDS: f64 = 30.0;

/// What the card remembers between frames, on egui's clock: when it last sent a request, and when
/// the host last refused one of its requests.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
struct Asked {
    sent: Option<f64>,
    refused: Option<f64>,
}

impl Asked {
    /// The memory after a frame at `now`, in which the card sent a request or not (`sent`) and the
    /// host's last error was `error`. A refusal to a request that the card did not send, a
    /// device removed by a user without rights, say, is not this card's to explain.
    fn after(self, now: f64, sent: bool, error: Option<&str>) -> Self {
        let sent = if sent { Some(now) } else { self.sent };
        let answered = error.is_some_and(is_admin_refusal) && sent.is_some_and(|at| now - at <= ASKED_SECONDS);
        Self { sent, refused: if answered { Some(now) } else { self.refused } }
    }

    fn refused(&self, now: f64) -> bool {
        self.refused.is_some_and(|at| now - at < REFUSED_SECONDS)
    }

    /// Seconds from `now` until the card stops saying so.
    fn next_change(&self, now: f64) -> Option<f64> {
        self.refused.map(|at| REFUSED_SECONDS - (now - at)).filter(|left| *left > 0.0)
    }
}

fn asked_id() -> egui::Id {
    egui::Id::unique("reach-asked")
}

/// The card on This PC. A host that predates standalone reach (`None`) gets nothing, not even the
/// space under it. A flipped switch comes back as the request to send; `error` is the host's answer
/// to the last request that failed, which the card explains when it is a refusal of its own.
pub(super) fn reach_card(
    ui: &mut egui::Ui,
    s: &Strings,
    reach: Option<&ReachStatus>,
    error: Option<&str>,
) -> Option<Request> {
    let reach = reach?;
    let ctx = ui.ctx().clone();
    let now = ui.input(|input| input.time);
    let asked = ctx.data(|data| data.get_temp::<Asked>(asked_id())).unwrap_or_default().after(now, false, error);
    let current = Switches::of(reach);
    let mut next = current;
    card(ui, |ui| {
        card_title(ui, s.reach_title);
        ui.add_space(4.0);
        ui.add(egui::Label::new(RichText::new(s.reach_text).color(WEAK)).wrap());
        ui.add_space(16.0);
        if asked.refused(now) {
            banner(ui, s.reach_admin_needed, ERROR);
            ui.add_space(16.0);
        }

        switch_row(ui, s.reach_standalone, s.reach_standalone_text, &mut next.standalone);
        if reach.standalone {
            standalone_details(ui, s, reach);
        }
        section_break(ui);
        switch_row(ui, s.reach_dht, s.reach_dht_text, &mut next.dht);
        section_break(ui);
        switch_row(ui, s.reach_relay, s.reach_relay_text, &mut next.relay_for_others);
        ui.add_space(10.0);
        let help = fill(s.reach_relay_help, &[s.offer_back]);
        ui.add(egui::Label::new(RichText::new(help).small().color(WEAK)).wrap());
        if let Some(last) = &reach.last_reached {
            section_break(ui);
            labelled(ui, s.reach_last, &[last_reached_text(last, s)], false);
        }
    });
    ui.add_space(16.0);
    let request = (next != current).then(|| next.request());
    let asked = asked.after(now, request.is_some(), None);
    ctx.data_mut(|data| data.insert_temp(asked_id(), asked));
    if let Some(left) = asked.next_change(now) {
        ctx.request_repaint_after(Duration::from_secs_f64(left));
    }
    request
}

/// Under the QR code of This PC: where its link also reaches this computer from other networks,
/// when the router gave it a public address. Nothing otherwise, not even the space for it.
pub(super) fn pair_note(ui: &mut egui::Ui, s: &Strings, reach: Option<&ReachStatus>) {
    let Some(reach) = reach.filter(|reach| reach.standalone && !reach.public.is_empty()) else { return };
    ui.add_space(10.0);
    labelled(ui, s.reach_pair_public, &reach.public, true);
}

/// Under the standalone switch, while it is on: what the router did, the addresses it gave and the
/// relays this computer is registered with, or what would help it to have one.
fn standalone_details(ui: &mut egui::Ui, s: &Strings, reach: &ReachStatus) {
    if let Some(line) = mapping_line(&mapping_of(reach), s) {
        ui.add_space(12.0);
        status_line(ui, &line);
    }
    for (label, addresses) in [(s.reach_public, &reach.public), (s.reach_v6, &reach.v6)] {
        if !addresses.is_empty() {
            ui.add_space(12.0);
            labelled(ui, label, addresses, true);
        }
    }
    if let Some(names) = registered_names(reach) {
        ui.add_space(12.0);
        labelled(ui, s.reach_relays, &[names], false);
    } else if let Some(advice) = advice(reach) {
        ui.add_space(12.0);
        ui.add(egui::Label::new(RichText::new(advice_text(&advice, s)).small().color(WEAK)).wrap());
    }
}

/// A switch with its title and a note under it. `on` is flipped by a click.
fn switch_row(ui: &mut egui::Ui, title: &str, note: &str, on: &mut bool) {
    ui.horizontal(|ui| {
        // Leave room for the switch so the note wraps before it.
        let text_width = ui.available_width() - 64.0;
        ui.allocate_ui_with_layout(egui::vec2(text_width, 0.0), Layout::top_down(Align::Min), |ui| {
            ui.spacing_mut().item_spacing.y = 3.0;
            ui.label(RichText::new(title).font(font(14.0, medium())));
            ui.add(egui::Label::new(RichText::new(note).color(WEAK)).wrap());
        });
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| toggle(ui, on, true));
    });
}

/// A dot, a sentence beside it and its detail under the sentence. Unlike `status`, it wraps.
fn status_line(ui: &mut egui::Ui, line: &Line) {
    let color = if line.good { LIVE } else { WEAK };
    ui.horizontal_top(|ui| {
        ui.spacing_mut().item_spacing.x = 6.0;
        let (dot, _) = ui.allocate_exact_size(egui::vec2(8.0, 18.0), Sense::hover());
        ui.painter().circle_filled(dot.center(), 3.5, color);
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            ui.add(egui::Label::new(RichText::new(&line.text).font(font(13.0, medium())).color(color)).wrap());
            ui.add(egui::Label::new(RichText::new(&line.detail).small().color(WEAK)).wrap());
        });
    });
}

/// A small label with its values under it, one to a line; `technical` sets them in monospace.
fn labelled(ui: &mut egui::Ui, label: &str, values: &[String], technical: bool) {
    ui.scope(|ui| {
        ui.spacing_mut().item_spacing.y = 3.0;
        field_label(ui, label);
        for value in values {
            let text = RichText::new(value);
            ui.add(egui::Label::new(if technical { text.font(mono(12.5)) } else { text }).wrap());
        }
    });
}

fn section_break(ui: &mut egui::Ui) {
    ui.add_space(14.0);
    divider(ui);
    ui.add_space(14.0);
}

/// Where the wake-up of one computer stands, for its button. The states are what `hosts::wake`
/// answers, plus the time while it works.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
enum WakeState {
    #[default]
    Idle,
    /// The request is on its way.
    Sending,
    /// The signal left, from this device's network or through a relay.
    Sent,
    /// This device is not on the computer's network and no relay there sent it.
    NoRelay,
    /// The computer never said how it can be woken (no MAC address known).
    Unsupported,
    /// Anything else, with the reason.
    Failed(String),
}

/// How long an outcome stays beside the button.
const OUTCOME_SECONDS: f64 = 12.0;
/// How soon after an outcome the button takes another click: a relay lets a device start six things
/// at once and then one every five seconds, and each wake-up is one of them.
const COOLDOWN_SECONDS: f64 = 5.0;
/// How long a request may take before the button stops waiting for it, so that a thread that died
/// cannot leave "Waking…" up for ever.
const SENDING_SECONDS: f64 = 30.0;

/// A wake-up and when it last changed, on egui's clock.
#[derive(Debug, Clone, Default, PartialEq)]
struct Wake {
    state: WakeState,
    at: f64,
}

impl Wake {
    /// What the card shows at `now`: an outcome fades, and a request that never answered is given up.
    fn shown(&self, now: f64) -> WakeState {
        let age = now - self.at;
        match &self.state {
            WakeState::Sending if age >= SENDING_SECONDS => WakeState::Idle,
            WakeState::Idle | WakeState::Sending => self.state.clone(),
            _ if age >= OUTCOME_SECONDS => WakeState::Idle,
            outcome => outcome.clone(),
        }
    }

    /// Whether a click starts a wake-up at `now`.
    fn ready(&self, now: f64) -> bool {
        match self.shown(now) {
            WakeState::Idle => true,
            WakeState::Sending => false,
            _ => now - self.at >= COOLDOWN_SECONDS,
        }
    }

    /// Seconds from `now` until what is shown, or whether a click is taken, changes by itself.
    fn next_change(&self, now: f64) -> Option<f64> {
        let limits: &[f64] = match self.shown(now) {
            WakeState::Idle => &[],
            WakeState::Sending => &[SENDING_SECONDS],
            _ => &[COOLDOWN_SECONDS, OUTCOME_SECONDS],
        };
        limits.iter().map(|limit| limit - (now - self.at)).filter(|left| *left > 0.0).reduce(f64::min)
    }
}

/// What to tell about a wake-up, if anything; `Idle` has nothing to tell.
fn wake_text(state: &WakeState, s: &Strings) -> Option<String> {
    match state {
        WakeState::Idle => None,
        WakeState::Sending => Some(s.wake_sending.to_string()),
        WakeState::Sent => Some(s.wake_sent.to_string()),
        WakeState::NoRelay => Some(fill(s.wake_no_relay, &[s.reach_relay])),
        WakeState::Unsupported => Some(s.wake_unsupported.to_string()),
        WakeState::Failed(reason) => Some(fill(s.wake_failed, &[reason])),
    }
}

/// What `hosts::wake` made of it, as the button tells it.
fn outcome_state(result: anyhow::Result<WakeOutcome>) -> WakeState {
    match result {
        Ok(WakeOutcome::Sent) => WakeState::Sent,
        Ok(WakeOutcome::NoRelay) => WakeState::NoRelay,
        Ok(WakeOutcome::Unsupported) => WakeState::Unsupported,
        Err(e) => WakeState::Failed(format!("{e:#}")),
    }
}

fn wake_id(host: &str) -> egui::Id {
    egui::Id::unique(("wake", host))
}

/// The wake-up of `host`, kept in egui's memory so that the launcher needs no field for it.
fn wake_of(ctx: &egui::Context, host: &str) -> Wake {
    ctx.data(|data| data.get_temp(wake_id(host))).unwrap_or_default()
}

/// Called when the wake-up of `host` changes, from the window or from the thread that does it.
fn set_wake(ctx: &egui::Context, host: &str, state: WakeState) {
    let at = ctx.input(|input| input.time);
    ctx.data_mut(|data| data.insert_temp(wake_id(host), Wake { state, at }));
    ctx.request_repaint();
}

/// Wakes `host` and waits for the answer. The paired list is the launcher's own, as in `pair_back`.
fn wake_up(config_dir: Option<PathBuf>, host: &str) -> WakeState {
    let result = (|| -> anyhow::Result<WakeOutcome> {
        let state = StateDir::open(config_dir, "client")?;
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        runtime.block_on(velora_client_core::hosts::wake(&state, host))
    })();
    outcome_state(result)
}

/// Starts waking `host` on a thread of its own: the window never waits for the network.
fn start_wake(ctx: &egui::Context, host: &str, config_dir: Option<&Path>) {
    set_wake(ctx, host, WakeState::Sending);
    let (ctx, host, config_dir) = (ctx.clone(), host.to_string(), config_dir.map(Path::to_path_buf));
    std::thread::spawn(move || {
        let state = wake_up(config_dir, &host);
        set_wake(&ctx, &host, state);
    });
}

const CHIP_HEIGHT: f32 = 28.0;

/// The Wake button of a device card; the card calls it for a computer that has no session open.
/// `card` is the card's area and `config_dir` the launcher's `--config-dir`, which the thread that
/// wakes the computer needs to open the paired list.
///
/// It sits in the card's top right corner, where a connected computer says so. The row of buttons
/// below has no room for it: in Portuguese at the narrowest window, Connect, Files and Forget take
/// about 370 of its 396 points and a fourth button would cover Forget.
///
/// Every computer gets one, also one that never said how it can be woken: the click then tells why
/// it cannot, which is what that computer's owner has to hear. What came of a wake-up shows in a
/// bubble under the card for a few seconds, and the button rests for part of them, because the
/// relay a wake-up may go through allows a device only so many requests.
pub(super) fn wake_button(
    ui: &mut egui::Ui,
    s: &Strings,
    host: &KnownHost,
    card: egui::Rect,
    config_dir: Option<&Path>,
) {
    let ctx = ui.ctx().clone();
    let now = ui.input(|input| input.time);
    let wake = wake_of(&ctx, &host.name);
    let (state, ready) = (wake.shown(now), wake.ready(now));
    let label = if state == WakeState::Sending { s.wake_sending } else { s.wake };
    let corner = egui::Rect::from_min_size(card.right_top() + egui::vec2(-178.0, 18.0), egui::vec2(160.0, CHIP_HEIGHT));
    let layout = Layout::right_to_left(Align::Min);
    let mut corner = ui.new_child(egui::UiBuilder::new().max_rect(corner).layout(layout));
    let chip = small_button(&mut corner, label, ready);
    match wake_text(&state, s).filter(|_| state != WakeState::Sending) {
        Some(outcome) => outcome_bubble(ui, chip.id, card, &outcome),
        None => {
            chip.clone().on_hover_text(s.wake_tip);
        }
    }
    if chip.clicked() && ready {
        start_wake(&ctx, &host.name, config_dir);
    }
    if let Some(left) = wake.next_change(now) {
        ctx.request_repaint_after(Duration::from_secs_f64(left));
    }
}

/// A tooltip that stays open without a hover, just under `card` and level with its right edge: over
/// the card it would hide the buttons. A tooltip with only text lets the pointer through, so what
/// it covers of the next card can still be clicked.
fn outcome_bubble(ui: &egui::Ui, id: egui::Id, card: egui::Rect, text: &str) {
    let under = egui::Rect::from_min_max(card.left_bottom(), card.right_bottom());
    let mut tooltip = egui::Tooltip::always_open(ui.ctx().clone(), ui.layer_id(), id, under).width(300.0);
    tooltip.popup = tooltip.popup.align(egui::RectAlign::BOTTOM_END);
    tooltip.show(|ui| ui.add(egui::Label::new(text).wrap()));
}

/// An outlined button as small as a chip, for a corner of a card: `secondary_button` is a whole
/// control tall. Dimmed, and deaf to clicks, while `enabled` is false.
fn small_button(ui: &mut egui::Ui, text: &str, enabled: bool) -> egui::Response {
    let color = if enabled { TEXT } else { FAINT };
    let galley = ui.painter().layout_no_wrap(text.to_string(), font(12.5, medium()), color);
    let size = egui::vec2(galley.size().x + 24.0, CHIP_HEIGHT);
    let (rect, response) = ui.allocate_exact_size(size, if enabled { Sense::click() } else { Sense::hover() });
    let hover =
        ui.ctx().animate_bool_with_time(response.id.with("hover"), enabled && response.hovered(), HOVER_SECONDS);
    let fill = egui::Color32::TRANSPARENT.lerp_to_gamma(HOVER, hover);
    let edge = BORDER_STRONG.lerp_to_gamma(FAINT, hover * 0.5);
    ui.painter().rect(rect, RADIUS, fill, egui::Stroke::new(1.0, edge), egui::StrokeKind::Inside);
    ui.painter().galley(rect.center() - galley.size() / 2.0, galley, color);
    if enabled {
        response.on_hover_cursor(egui::CursorIcon::PointingHand)
    } else {
        response
    }
}

#[cfg(test)]
mod tests {
    use eframe::egui::{epaint::Shape, vec2, Event, Modifiers, PointerButton, Pos2, Rect};
    use velora_protocol::tls::Fingerprint;

    use super::*;
    use crate::gui::{strings, theme};

    /// A MAC address of the locally administered kind: made up.
    const MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];

    /// Documentation addresses (RFC 5737, RFC 3849): nothing here is anyone's real network. Later
    /// tickets add fields to the status (relay management does); the update keeps this building.
    #[allow(clippy::needless_update)]
    fn reach() -> ReachStatus {
        ReachStatus {
            standalone: true,
            relay_for_others: false,
            dht: true,
            mapping: Some(MappingStatus {
                protocol: "natpmp".into(),
                external: "203.0.113.7:51820".into(),
                public: true,
                lease_secs: 3600,
            }),
            public: vec!["203.0.113.7:51820".into()],
            v6: vec!["[2001:db8::7]:7420".into()],
            last_reached: Some((AddressKind::Public, "198.51.100.9:50000".into())),
            registered_with: vec!["Office PC".into(), "Laptop".into()],
            ..Default::default()
        }
    }

    /// A paired computer, with or without the MAC address it reports.
    fn host(mac: Option<[u8; 6]>) -> KnownHost {
        KnownHost { name: "Desk".into(), address: "192.0.2.10:7420".into(), mac, ..Default::default() }
    }

    /// The area of a device card, and the middle of the Wake button in its top right corner.
    fn card_area() -> Rect {
        Rect::from_min_size(Pos2::ZERO, vec2(400.0, 150.0))
    }

    fn chip() -> Pos2 {
        card_area().right_top() + vec2(-30.0, 32.0)
    }

    /// What one frame painted.
    struct Painted {
        /// Every text, in the order it was painted.
        texts: Vec<String>,
        /// The track of every switch, which are the only 40 by 22 rectangles.
        switches: Vec<Rect>,
    }

    impl Painted {
        fn has(&self, text: &str) -> bool {
            self.texts.iter().any(|t| t == text)
        }

        fn mentions(&self, part: &str) -> bool {
            self.texts.iter().any(|t| t.contains(part))
        }
    }

    /// Frames of a headless egui, with the launcher's fonts and look and no window.
    struct Frames {
        ctx: egui::Context,
        time: f64,
    }

    impl Frames {
        fn new() -> Self {
            let ctx = egui::Context::default();
            theme::apply(&ctx);
            Self { ctx, time: 0.0 }
        }

        /// One frame, as wide as the narrowest window's page, with `events` arriving in it.
        fn run(&mut self, events: Vec<Event>, mut add: impl FnMut(&mut egui::Ui)) -> Painted {
            self.time += 0.1;
            let input = egui::RawInput {
                screen_rect: Some(Rect::from_min_size(Pos2::ZERO, vec2(440.0, 2400.0))),
                time: Some(self.time),
                events,
                ..Default::default()
            };
            let output = self.ctx.run_ui(input, |ui| add(ui));
            let mut painted = Painted { texts: Vec::new(), switches: Vec::new() };
            for clipped in &output.shapes {
                collect(&clipped.shape, &mut painted);
            }
            output.drop_without_applying_deltas();
            painted
        }

        /// The clock moves on without frames: the wake-up of a card fades by it.
        fn advance(&mut self, seconds: f64) {
            self.time += seconds;
        }

        /// Frames, pausing between them, until one paints what `done` wants: a wake-up runs on a
        /// thread of its own.
        fn until(&mut self, mut add: impl FnMut(&mut egui::Ui), done: impl Fn(&Painted) -> bool) -> Painted {
            for _ in 0..500 {
                let painted = self.run(Vec::new(), &mut add);
                if done(&painted) {
                    return painted;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            panic!("nothing came of it in ten seconds");
        }
    }

    fn collect(shape: &Shape, painted: &mut Painted) {
        match shape {
            Shape::Vec(shapes) => shapes.iter().for_each(|shape| collect(shape, painted)),
            Shape::Text(text) => painted.texts.push(text.galley.text().to_string()),
            Shape::Rect(rect) if rect.rect.size() == vec2(40.0, 22.0) => painted.switches.push(rect.rect),
            _ => {}
        }
    }

    fn click(at: Pos2) -> Vec<Event> {
        let button = |pressed| Event::PointerButton {
            pos: at,
            button: PointerButton::Primary,
            pressed,
            modifiers: Modifiers::NONE,
        };
        vec![Event::PointerMoved(at), button(true), button(false)]
    }

    /// Frames with the pointer resting on `at`, long enough for a tooltip: everything they painted.
    fn hover(frames: &mut Frames, at: Pos2, mut add: impl FnMut(&mut egui::Ui)) -> Vec<String> {
        frames.ctx.global_style_mut(|style| style.interaction.tooltip_delay = 0.0);
        frames.run(vec![Event::PointerMoved(at)], &mut add);
        (0..4).flat_map(|_| frames.run(Vec::new(), &mut add).texts).collect()
    }

    /// A scratch folder for the launcher's client state, removed when dropped.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("velora-g2-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        /// Pairs `host`: it goes into the known hosts of the client side, as pairing writes it.
        fn pair(&self, host: &KnownHost) {
            let state = StateDir::open(Some(self.0.clone()), "client").unwrap();
            state.save(StateDir::KNOWN_HOSTS, &vec![host.clone()]).unwrap();
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn the_switches_send_all_three_together() {
        let all = Switches { standalone: true, relay_for_others: false, dht: true };
        assert_eq!(all.request(), Request::SetReach { standalone: true, relay_for_others: false, dht: true });
        assert_eq!(Switches::of(&reach()), all);
        // Nothing reported is all off, which is also what a host that never used reach says.
        assert_eq!(
            Switches::of(&ReachStatus::default()).request(),
            Request::SetReach { standalone: false, relay_for_others: false, dht: false }
        );
    }

    #[test]
    fn the_router_is_told_apart_by_what_it_did() {
        let open = reach();
        let mapping = open.mapping.clone().unwrap();
        assert_eq!(mapping_of(&open), Mapping::Open(&mapping));
        let shared = ReachStatus { mapping: Some(MappingStatus { public: false, ..mapping.clone() }), ..reach() };
        assert!(matches!(mapping_of(&shared), Mapping::Shared(_)));
        assert_eq!(mapping_of(&ReachStatus { mapping: None, ..reach() }), Mapping::Closed);
        // Off says nothing about the router, even if a mapping lingers in the report.
        assert_eq!(mapping_of(&ReachStatus { standalone: false, ..reach() }), Mapping::Off);
    }

    #[test]
    fn each_state_of_the_router_has_its_own_line_in_both_languages() {
        for s in strings::all() {
            let open = reach();
            let line = mapping_line(&mapping_of(&open), s).unwrap();
            assert_eq!(line.text, s.reach_mapping_open);
            assert!(line.good && line.detail.contains("NAT-PMP"), "{line:?}");

            let mapping =
                MappingStatus { protocol: "upnp".into(), external: "100.64.1.2:7420".into(), ..Default::default() };
            let shared = ReachStatus { mapping: Some(mapping), ..reach() };
            let line = mapping_line(&mapping_of(&shared), s).unwrap();
            assert_eq!(line.text, s.reach_mapping_shared);
            assert!(!line.good && line.detail.contains("100.64.1.2:7420"), "{line:?}");

            let closed = ReachStatus { mapping: None, ..reach() };
            let line = mapping_line(&mapping_of(&closed), s).unwrap();
            assert_eq!((line.text.as_str(), line.good), (s.reach_mapping_closed, false));

            assert_eq!(mapping_line(&Mapping::Off, s), None);
        }
        assert_eq!(protocol_name("natpmp"), "NAT-PMP");
        assert_eq!(protocol_name("upnp"), "UPnP");
        assert_eq!(protocol_name("pcp"), "pcp");
    }

    #[test]
    fn the_last_connection_names_the_way_it_came() {
        let s = strings::current();
        for (kind, label) in [
            (AddressKind::Lan, s.reach_kind_lan),
            (AddressKind::Vpn, s.reach_kind_vpn),
            (AddressKind::Public, s.reach_public),
            (AddressKind::V6, s.reach_v6),
            (AddressKind::Relay("fp".into()), s.reach_kind_relay),
            (AddressKind::Other(9), s.reach_kind_other),
        ] {
            assert_eq!(last_reached_text(&(kind, "192.0.2.5:7420".into()), s), format!("{label} · 192.0.2.5:7420"));
        }
    }

    #[test]
    fn relays_are_listed_by_name() {
        assert_eq!(registered_names(&reach()).as_deref(), Some("Office PC, Laptop"));
        assert_eq!(registered_names(&ReachStatus::default()), None);
    }

    #[test]
    fn advice_comes_only_where_a_port_and_a_relay_would_help() {
        let bare = ReachStatus { registered_with: Vec::new(), v6: Vec::new(), ..reach() };
        // An open port needs no advice.
        assert_eq!(advice(&bare), None);
        let no_port = ReachStatus { mapping: None, ..bare.clone() };
        // With the DHT on, or an IPv6 address to try, a device can still find this PC: a relay is the
        // sure way.
        assert_eq!(advice(&no_port), Some(Advice::NoRelay));
        let v6 = vec!["[2001:db8::7]:7420".to_string()];
        assert_eq!(advice(&ReachStatus { dht: false, v6, ..no_port.clone() }), Some(Advice::NoRelay));
        // With the DHT off and nothing else, nothing tells this PC that a device wants in.
        assert_eq!(advice(&ReachStatus { dht: false, ..no_port.clone() }), Some(Advice::Blind));
        let shared = Some(MappingStatus { public: false, ..reach().mapping.unwrap() });
        assert_eq!(advice(&ReachStatus { mapping: shared, dht: false, ..bare }), Some(Advice::Blind));
        // A relay already registered needs no advice, nor does standalone reach being off.
        assert_eq!(advice(&ReachStatus { registered_with: vec!["Office PC".into()], ..no_port.clone() }), None);
        assert_eq!(advice(&ReachStatus { standalone: false, ..no_port }), None);
    }

    #[test]
    fn a_wake_up_fades_and_rests_by_the_clock() {
        let at = 100.0;
        let wake = |state| Wake { state, at };
        // While it works the button waits, and gives up on a request that never answers.
        let sending = wake(WakeState::Sending);
        assert_eq!((sending.shown(at + 1.0), sending.ready(at + 1.0)), (WakeState::Sending, false));
        assert_eq!((sending.shown(at + SENDING_SECONDS), sending.ready(at + SENDING_SECONDS)), (WakeState::Idle, true));
        // An outcome shows for a while, and the button rests for part of it.
        for outcome in [WakeState::Sent, WakeState::NoRelay, WakeState::Unsupported, WakeState::Failed("x".into())] {
            let wake = wake(outcome.clone());
            assert_eq!((wake.shown(at + 1.0), wake.ready(at + 1.0)), (outcome.clone(), false));
            let rested = at + COOLDOWN_SECONDS;
            assert_eq!((wake.shown(rested), wake.ready(rested)), (outcome.clone(), true));
            let gone = at + OUTCOME_SECONDS;
            assert_eq!((wake.shown(gone), wake.ready(gone)), (WakeState::Idle, true));
        }
        // Nothing to wait for before the first one.
        let none = Wake::default();
        assert_eq!((none.shown(5.0), none.ready(5.0), none.next_change(5.0)), (WakeState::Idle, true, None));
        // When the card has to look again.
        assert_eq!(wake(WakeState::Sending).next_change(at + 1.0), Some(SENDING_SECONDS - 1.0));
        assert_eq!(wake(WakeState::Sent).next_change(at + 1.0), Some(COOLDOWN_SECONDS - 1.0));
        assert_eq!(wake(WakeState::Sent).next_change(at + 6.0), Some(OUTCOME_SECONDS - 6.0));
        assert_eq!(wake(WakeState::Sent).next_change(at + 20.0), None);
    }

    #[test]
    fn what_hosts_wake_answers_becomes_what_the_button_says() {
        assert_eq!(outcome_state(Ok(WakeOutcome::Sent)), WakeState::Sent);
        assert_eq!(outcome_state(Ok(WakeOutcome::NoRelay)), WakeState::NoRelay);
        assert_eq!(outcome_state(Ok(WakeOutcome::Unsupported)), WakeState::Unsupported);
        let failed = outcome_state(Err(anyhow::anyhow!("'Desk' is not paired yet")));
        assert_eq!(failed, WakeState::Failed("'Desk' is not paired yet".into()));
    }

    #[test]
    fn a_wake_up_says_where_it_stands() {
        for s in strings::all() {
            assert_eq!(wake_text(&WakeState::Idle, s), None);
            assert_eq!(wake_text(&WakeState::Sending, s).as_deref(), Some(s.wake_sending));
            assert_eq!(wake_text(&WakeState::Sent, s).as_deref(), Some(s.wake_sent));
            assert_eq!(wake_text(&WakeState::NoRelay, s), Some(fill(s.wake_no_relay, &[s.reach_relay])));
            assert_eq!(wake_text(&WakeState::Unsupported, s).as_deref(), Some(s.wake_unsupported));
            let failed = wake_text(&WakeState::Failed("timed out".into()), s).unwrap();
            assert_eq!(failed, fill(s.wake_failed, &["timed out"]));
            assert!(failed.contains("timed out"));
        }
    }

    #[test]
    fn a_host_that_predates_reach_gets_no_card() {
        for s in strings::all() {
            let mut frames = Frames::new();
            let painted = frames.run(Vec::new(), |ui| {
                let top = ui.cursor().min;
                assert_eq!(reach_card(ui, s, None, None), None);
                // Not even the space the card leaves under it.
                assert_eq!(ui.cursor().min, top);
            });
            assert!(painted.texts.is_empty() && painted.switches.is_empty());
        }
    }

    #[test]
    fn the_card_shows_what_the_host_reports() {
        for s in strings::all() {
            let mut frames = Frames::new();
            let status = reach();
            let painted = frames.run(Vec::new(), |ui| assert_eq!(reach_card(ui, s, Some(&status), None), None));
            for text in [
                s.reach_title,
                s.reach_text,
                s.reach_standalone,
                s.reach_standalone_text,
                s.reach_dht,
                s.reach_dht_text,
                s.reach_relay,
                s.reach_relay_text,
                s.reach_mapping_open,
                s.reach_public,
                s.reach_v6,
                s.reach_relays,
                s.reach_last,
                "203.0.113.7:51820",
                "[2001:db8::7]:7420",
                "Office PC, Laptop",
            ] {
                assert!(painted.has(text), "{text:?} was not painted, only {:#?}", painted.texts);
            }
            assert!(painted.mentions("NAT-PMP"));
            assert!(painted.has(&last_reached_text(status.last_reached.as_ref().unwrap(), s)));
            assert_eq!(painted.switches.len(), 3);
            assert!(!painted.mentions(s.reach_mapping_closed));
            // Relaying costs bandwidth, and needs pairings that the card tells how to make.
            assert!(painted.has(&fill(s.reach_relay_help, &[s.offer_back])));
            assert!(s.reach_relay_text.contains("6") && s.reach_relay_text.contains("12 Mbit/s"));
            // Registered relays make advice unnecessary.
            assert!(!painted.mentions(s.reach_advice_blind.split("{}").next().unwrap()));
        }
    }

    #[test]
    fn what_the_router_did_not_do_is_said_plainly() {
        let s = strings::current();
        let closed = ReachStatus { mapping: None, registered_with: Vec::new(), last_reached: None, ..reach() };
        let blind = ReachStatus { dht: false, v6: Vec::new(), ..closed.clone() };
        for (status, advice) in
            [(closed, fill(s.reach_relays_none, &[s.reach_relay])), (blind, fill(s.reach_advice_blind, &[s.reach_dht]))]
        {
            let mut frames = Frames::new();
            let painted = frames.run(Vec::new(), |ui| {
                reach_card(ui, s, Some(&status), None);
            });
            assert!(painted.has(s.reach_mapping_closed) && painted.has(s.reach_mapping_closed_detail));
            assert!(painted.has(&advice), "{advice:?} was not painted, only {:#?}", painted.texts);
            assert!(!painted.has(s.reach_relays) && !painted.has(s.reach_last));
        }
    }

    #[test]
    fn with_standalone_off_the_router_and_its_addresses_stay_out_of_sight() {
        let s = strings::current();
        let mut frames = Frames::new();
        let status = ReachStatus { standalone: false, ..reach() };
        let painted = frames.run(Vec::new(), |ui| {
            reach_card(ui, s, Some(&status), None);
        });
        assert!(painted.has(s.reach_standalone) && painted.has(s.reach_dht) && painted.has(s.reach_relay));
        for gone in [s.reach_mapping_open, s.reach_public, s.reach_v6, s.reach_relays, "203.0.113.7:51820"] {
            assert!(!painted.has(gone), "{gone:?} should be hidden");
        }
        // The last connection was true whatever the switches say now.
        assert!(painted.has(s.reach_last));
    }

    #[test]
    fn the_public_address_goes_under_the_qr_code() {
        for s in strings::all() {
            // What the note painted, and the height it took.
            let note = |status: Option<&ReachStatus>| {
                let mut used = 0.0;
                let painted = Frames::new().run(Vec::new(), |ui| {
                    let top = ui.cursor().min.y;
                    pair_note(ui, s, status);
                    used = ui.cursor().min.y - top;
                });
                (painted.texts, used)
            };
            let (texts, used) = note(Some(&reach()));
            assert_eq!(texts, [s.reach_pair_public, "203.0.113.7:51820"]);
            assert!(used > 0.0);
            // Several addresses, one to a line.
            let two = ReachStatus { public: vec!["203.0.113.7:51820".into(), "203.0.113.8:51820".into()], ..reach() };
            assert_eq!(note(Some(&two)).0, [s.reach_pair_public, "203.0.113.7:51820", "203.0.113.8:51820"]);
            // Nothing to say, and no room taken: an older host, standalone reach off, or no public address
            // (a shared one is not advertised).
            let off = ReachStatus { standalone: false, ..reach() };
            let shared = ReachStatus { public: Vec::new(), ..reach() };
            for status in [None, Some(&off), Some(&shared)] {
                assert_eq!(note(status), (Vec::new(), 0.0));
            }
        }
    }

    #[test]
    fn flipping_a_switch_sends_all_three_with_that_one_changed() {
        let s = strings::current();
        let status = reach();
        let reported = Switches::of(&status);
        let mut frames = Frames::new();
        let first = frames.run(Vec::new(), |ui| {
            reach_card(ui, s, Some(&status), None);
        });
        // In the order they are drawn: standalone, DHT, relay for others.
        let flipped = [
            Switches { standalone: !reported.standalone, ..reported },
            Switches { dht: !reported.dht, ..reported },
            Switches { relay_for_others: !reported.relay_for_others, ..reported },
        ];
        assert_eq!(first.switches.len(), flipped.len());
        for (track, want) in first.switches.iter().zip(flipped) {
            let mut sent = None;
            frames.run(click(track.center()), |ui| sent = reach_card(ui, s, Some(&status), None));
            assert_eq!(sent, Some(want.request()), "clicking the switch at {track:?}");
        }
        // A frame with no click asks for nothing.
        let mut sent = None;
        frames.run(Vec::new(), |ui| sent = reach_card(ui, s, Some(&status), None));
        assert_eq!(sent, None);
    }

    /// What the host answers a change that a user without rights makes under the service
    /// (`Shared::control` in the host's `server.rs`).
    const REFUSAL: &str = "only an administrator can change this computer's access";

    #[test]
    fn a_refusal_for_lack_of_rights_is_told_in_plain_words() {
        assert!(is_admin_refusal(REFUSAL) && !is_admin_refusal("saving the standalone reach switches: disk full"));
        for s in strings::all() {
            assert_eq!(friendly_error(s, REFUSAL), s.reach_admin_needed);
            // Any other error stays as the host worded it.
            assert_eq!(friendly_error(s, "this device is not paired"), "this device is not paired");
        }
    }

    #[test]
    fn the_card_explains_a_refused_change_where_it_was_made() {
        let s = strings::current();
        let status = reach();
        let mut frames = Frames::new();
        let run = |frames: &mut Frames, events: Vec<Event>, error: Option<&str>| {
            let mut sent = None;
            let painted = frames.run(events, |ui| sent = reach_card(ui, s, Some(&status), error));
            (painted.has(s.reach_admin_needed), sent)
        };
        let first = frames.run(Vec::new(), |ui| _ = reach_card(ui, s, Some(&status), None));
        // A refusal of something else that the user did, such as removing a device, is not for this card.
        assert!(!run(&mut frames, Vec::new(), Some(REFUSAL)).0);
        // A switch is flipped, and the host refuses: the card says why, in the same frame the error
        // arrives and for as long afterwards as the launcher's own banner is gone.
        let (_, sent) = run(&mut frames, click(first.switches[1].center()), None);
        assert!(sent.is_some());
        assert!(run(&mut frames, Vec::new(), Some(REFUSAL)).0);
        assert!(run(&mut frames, Vec::new(), None).0);
        frames.advance(REFUSED_SECONDS - 1.0);
        assert!(run(&mut frames, Vec::new(), None).0);
        // Then it lets go.
        frames.advance(2.0);
        assert!(!run(&mut frames, Vec::new(), None).0);
        // A refusal long after the card's last request is not an answer to it, and neither is
        // another kind of error right after one.
        run(&mut frames, click(first.switches[1].center()), None);
        assert!(!run(&mut frames, Vec::new(), Some("this device is not paired")).0);
        frames.advance(ASKED_SECONDS + 1.0);
        assert!(!run(&mut frames, Vec::new(), Some(REFUSAL)).0);
    }

    #[test]
    fn what_the_card_remembers_of_its_requests_follows_the_clock() {
        let asked = Asked::default();
        // A request, then the refusal in time: refused; a refusal alone: not.
        assert_eq!(asked.after(10.0, false, Some(REFUSAL)).refused, None);
        let sent = asked.after(10.0, true, None);
        assert_eq!(sent, Asked { sent: Some(10.0), refused: None });
        let refused = sent.after(12.0, false, Some(REFUSAL));
        assert_eq!(refused, Asked { sent: Some(10.0), refused: Some(12.0) });
        // Refused while it lasts, and its end is known.
        assert!(refused.refused(12.0) && refused.refused(12.0 + REFUSED_SECONDS - 0.1));
        assert!(!refused.refused(12.0 + REFUSED_SECONDS));
        assert_eq!(refused.next_change(13.0), Some(REFUSED_SECONDS - 1.0));
        assert_eq!(refused.next_change(12.0 + REFUSED_SECONDS), None);
        assert_eq!(Asked::default().next_change(1.0), None);
        // Too late to be an answer.
        assert_eq!(sent.after(10.0 + ASKED_SECONDS + 0.1, false, Some(REFUSAL)).refused, None);
    }

    #[test]
    fn every_computer_gets_a_wake_button() {
        let s = strings::current();
        let mut frames = Frames::new();
        // One that reported its MAC address, and one that never did: the click tells why it cannot.
        for known in [host(Some(MAC)), host(None)] {
            let painted = frames.run(Vec::new(), |ui| wake_button(ui, s, &known, card_area(), None));
            assert_eq!(painted.texts, [s.wake]);
        }
        // While the request is on its way the button says so.
        set_wake(&frames.ctx, "Desk", WakeState::Sending);
        let painted = frames.run(Vec::new(), |ui| wake_button(ui, s, &host(None), card_area(), None));
        assert_eq!(painted.texts, [s.wake_sending]);
        // Each computer has its own state.
        assert_eq!(wake_of(&frames.ctx, "Laptop"), Wake::default());
    }

    #[test]
    fn the_button_tells_what_it_does_and_what_came_of_it() {
        for s in strings::all() {
            let known = host(Some(MAC));
            let mut button = |ui: &mut egui::Ui| wake_button(ui, s, &known, card_area(), None);
            // Resting on the button says what it does.
            let mut frames = Frames::new();
            assert!(hover(&mut frames, chip(), &mut button).contains(&s.wake_tip.to_string()));
            // Every outcome stays beside the button, with no hover, and the button keeps its name.
            for state in [WakeState::Sent, WakeState::NoRelay, WakeState::Unsupported, WakeState::Failed("x".into())] {
                let mut frames = Frames::new();
                set_wake(&frames.ctx, "Desk", state.clone());
                let shown: Vec<String> = (0..4).flat_map(|_| frames.run(Vec::new(), &mut button).texts).collect();
                let told = wake_text(&state, s).unwrap();
                assert!(shown.contains(&told), "{state:?}: {told:?} was not shown, only {shown:#?}");
                assert!(shown.contains(&s.wake.to_string()));
                assert!(!shown.contains(&s.wake_tip.to_string()));
            }
            // After a while it is gone and the button is as before.
            let mut frames = Frames::new();
            set_wake(&frames.ctx, "Desk", WakeState::Sent);
            frames.advance(OUTCOME_SECONDS);
            let shown: Vec<String> = (0..4).flat_map(|_| frames.run(Vec::new(), &mut button).texts).collect();
            assert!(shown.len() == 4 && shown.iter().all(|text| text == s.wake), "{shown:#?}");
        }
    }

    #[test]
    fn a_click_wakes_the_computer_and_the_button_says_what_came_of_it() {
        let s = strings::current();
        // Neither wake-up touches the network: the first computer never told its MAC address, the
        // second is on a network (RFC 5737) that no adapter of this PC has, and no relay is stored.
        let silent = host(None);
        let away = KnownHost {
            kinds: vec![(AddressKind::Lan, "203.0.113.9:7420".into())],
            fingerprint: Fingerprint([7; 32]).to_base64(),
            ..host(Some(MAC))
        };
        for (known, tag, outcome) in [(silent, "silent", WakeState::Unsupported), (away, "away", WakeState::NoRelay)] {
            let scratch = Scratch::new(tag);
            scratch.pair(&known);
            let mut frames = Frames::new();
            let ctx = frames.ctx.clone();
            let mut button = |ui: &mut egui::Ui| wake_button(ui, s, &known, card_area(), Some(scratch.path()));
            let told = wake_text(&outcome, s).unwrap();
            // Nothing is under way before the click.
            assert!(frames.run(Vec::new(), &mut button).has(s.wake));
            assert_eq!(wake_of(&ctx, "Desk").state, WakeState::Idle);
            // The click starts it, and what came of it appears beside the button.
            frames.run(click(chip()), &mut button);
            let painted = frames.until(&mut button, |painted| painted.has(&told));
            assert!(painted.has(s.wake), "{:#?}", painted.texts);
            let first = wake_of(&ctx, "Desk");
            assert_eq!(first.state, outcome);
            // The relay lets a device start only so many things: no click for a few seconds.
            frames.run(click(chip()), &mut button);
            assert_eq!(wake_of(&ctx, "Desk"), first);
            // After them a click starts another wake-up. (egui judges a click by the widgets of the
            // frame before, so the button gets one frame to wake from its rest.)
            frames.advance(COOLDOWN_SECONDS);
            frames.run(Vec::new(), &mut button);
            frames.run(click(chip()), &mut button);
            assert!(wake_of(&ctx, "Desk").at > first.at);
            frames.until(&mut button, |_| wake_of(&ctx, "Desk").state == outcome);
        }
    }

    /// A string that nothing shows is dead weight in a file that is frozen after this ticket.
    #[test]
    fn every_text_of_standalone_reach_is_shown_in_some_state() {
        for s in strings::all() {
            let mut frames = Frames::new();
            let mut shown = Vec::new();
            let shared = MappingStatus { public: false, ..reach().mapping.unwrap() };
            let closed = ReachStatus { mapping: None, registered_with: Vec::new(), last_reached: None, ..reach() };
            let mut statuses = vec![
                reach(),
                ReachStatus { mapping: Some(shared), registered_with: Vec::new(), ..reach() },
                ReachStatus { dht: false, v6: Vec::new(), ..closed.clone() },
                closed,
            ];
            for kind in [AddressKind::Lan, AddressKind::Vpn, AddressKind::Relay("fp".into()), AddressKind::Other(9)] {
                statuses.push(ReachStatus { last_reached: Some((kind, "192.0.2.5:7420".into())), ..reach() });
            }
            for status in &statuses {
                shown.extend(frames.run(Vec::new(), |ui| _ = reach_card(ui, s, Some(status), None)).texts);
            }
            shown.extend(frames.run(Vec::new(), |ui| pair_note(ui, s, Some(&reach()))).texts);
            // The refusal of a change by a user without rights: a switch is flipped, the host says no.
            let status = reach();
            let flip = frames.run(Vec::new(), |ui| _ = reach_card(ui, s, Some(&status), None)).switches[1].center();
            frames.run(click(flip), |ui| _ = reach_card(ui, s, Some(&status), None));
            let refused = |ui: &mut egui::Ui| _ = reach_card(ui, s, Some(&status), Some(REFUSAL));
            shown.extend(frames.run(Vec::new(), refused).texts);
            // The button: under way, then each outcome, then at rest with a hover.
            let known = host(Some(MAC));
            let mut button = |ui: &mut egui::Ui| wake_button(ui, s, &known, card_area(), None);
            let states = [
                WakeState::Sending,
                WakeState::Sent,
                WakeState::NoRelay,
                WakeState::Unsupported,
                WakeState::Failed("x".into()),
                WakeState::Idle,
            ];
            for state in states {
                set_wake(&frames.ctx, "Desk", state);
                shown.extend((0..4).flat_map(|_| frames.run(Vec::new(), &mut button).texts));
            }
            shown.extend(hover(&mut frames, chip(), &mut button));
            // What a template says around its `{}` is what the filled text starts with.
            let is_shown = |text: &str| shown.iter().any(|t| t.contains(text.split("{}").next().unwrap()));
            for (name, text) in [
                ("reach_title", s.reach_title),
                ("reach_text", s.reach_text),
                ("reach_standalone", s.reach_standalone),
                ("reach_standalone_text", s.reach_standalone_text),
                ("reach_mapping_open", s.reach_mapping_open),
                ("reach_mapping_open_detail", s.reach_mapping_open_detail),
                ("reach_mapping_shared", s.reach_mapping_shared),
                ("reach_mapping_shared_detail", s.reach_mapping_shared_detail),
                ("reach_mapping_closed", s.reach_mapping_closed),
                ("reach_mapping_closed_detail", s.reach_mapping_closed_detail),
                ("reach_public", s.reach_public),
                ("reach_pair_public", s.reach_pair_public),
                ("reach_v6", s.reach_v6),
                ("reach_dht", s.reach_dht),
                ("reach_dht_text", s.reach_dht_text),
                ("reach_relay", s.reach_relay),
                ("reach_relay_text", s.reach_relay_text),
                ("reach_relay_help", s.reach_relay_help),
                ("reach_relays", s.reach_relays),
                ("reach_relays_none", s.reach_relays_none),
                ("reach_advice_blind", s.reach_advice_blind),
                ("reach_admin_needed", s.reach_admin_needed),
                ("reach_last", s.reach_last),
                ("reach_kind_lan", s.reach_kind_lan),
                ("reach_kind_vpn", s.reach_kind_vpn),
                ("reach_kind_relay", s.reach_kind_relay),
                ("reach_kind_other", s.reach_kind_other),
                ("wake", s.wake),
                ("wake_tip", s.wake_tip),
                ("wake_sending", s.wake_sending),
                ("wake_sent", s.wake_sent),
                ("wake_no_relay", s.wake_no_relay),
                ("wake_unsupported", s.wake_unsupported),
                ("wake_failed", s.wake_failed),
            ] {
                assert!(is_shown(text), "{name} ({text:?}) is not shown in any state");
            }
        }
    }
}
