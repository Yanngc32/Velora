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
    control::{MappingStatus, ReachStatus, RelayEntry, RelayHostEntry, Request},
    identity::{KnownHost, StateDir},
    pairing::{parse_pairing_link, PairingCode},
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

/// What a host says to a request it cannot read, such as those that manage relays when it is older
/// than this launcher.
fn is_old_host(error: &str) -> bool {
    error.contains("malformed request")
}

/// The words for an error from the host: plain for the ones that a person can do something about,
/// the host's own for the rest.
pub(super) fn friendly_error(s: &Strings, error: &str) -> String {
    if is_admin_refusal(error) {
        s.reach_admin_needed.to_string()
    } else if is_old_host(error) {
        s.relay_too_old.to_string()
    } else {
        error.to_string()
    }
}

/// What the card says when the host answers one of its requests with an error.
fn failure_text(s: &Strings, error: &str) -> String {
    if is_admin_refusal(error) || is_old_host(error) {
        friendly_error(s, error)
    } else {
        fill(s.relay_failed, &[error])
    }
}

/// How soon after the card sent a request an error counts as the answer to it.
const ASKED_SECONDS: f64 = 5.0;
/// How long the card keeps saying what went wrong. The launcher's own banner for an error goes
/// with the next status, a second later.
const FAILED_SECONDS: f64 = 30.0;

/// Which part of the card sent a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Origin {
    Switches,
    /// "Use as my relay", and the Remove beside a relay.
    UseRelay,
    /// "Let it use this PC", and the Remove beside an allowed computer.
    AllowHost,
}

/// An error the host answered to a request of the card, from where it was sent and when.
#[derive(Debug, Clone, PartialEq)]
struct Failure {
    at: f64,
    origin: Origin,
    error: String,
}

/// What the card remembers between frames, on egui's clock: its last request, and the error the
/// host answered to it, if it did.
#[derive(Debug, Clone, Default, PartialEq)]
struct Asked {
    sent: Option<(f64, Origin)>,
    /// The error on the screen when that request went out: it is not the answer to it.
    stale: Option<String>,
    failed: Option<Failure>,
}

impl Asked {
    /// A request goes out at `now`, with the host's last error `error` still showing. What failed
    /// before is forgotten: this one starts over.
    fn sent(self, now: f64, origin: Origin, error: Option<&str>) -> Self {
        Self { sent: Some((now, origin)), stale: error.map(str::to_string), failed: None }
    }

    /// The host's last error `error` seen at `now`. Soon after a request of the card, and not the
    /// one that was showing when it went out, it is the answer. An error to a request the card did
    /// not send, a device removed by a user without rights, say, is not its to explain.
    fn answered(mut self, now: f64, error: Option<&str>) -> Self {
        let (Some(error), Some((sent, origin))) = (error, self.sent) else { return self };
        if now - sent <= ASKED_SECONDS && self.stale.as_deref() != Some(error) {
            self.failed = Some(Failure { at: now, origin, error: error.to_string() });
        }
        self
    }

    /// What to say about the last change made from `origin`, while it is not old news.
    fn failure(&self, now: f64, origin: Origin) -> Option<&str> {
        let failed = self.failed.as_ref().filter(|failed| failed.origin == origin);
        failed.filter(|failed| now - failed.at < FAILED_SECONDS).map(|failed| failed.error.as_str())
    }

    /// Seconds from `now` until the card stops saying it.
    fn next_change(&self, now: f64) -> Option<f64> {
        self.failed.as_ref().map(|failed| FAILED_SECONDS - (now - failed.at)).filter(|left| *left > 0.0)
    }
}

fn asked_id() -> egui::Id {
    egui::Id::unique("reach-asked")
}

/// The cards on This PC: how it is reached from other networks, and the relays it uses or lends. A
/// host that predates standalone reach (`None`) gets nothing, not even the space under them. What
/// is clicked comes back as the request to send; `error` is the host's answer to the last request
/// that failed, which the cards explain where it was made when it answers one of theirs.
pub(super) fn reach_card(
    ui: &mut egui::Ui,
    s: &Strings,
    reach: Option<&ReachStatus>,
    error: Option<&str>,
) -> Option<Request> {
    let reach = reach?;
    let ctx = ui.ctx().clone();
    let now = ui.input(|input| input.time);
    let asked = ctx.data(|data| data.get_temp::<Asked>(asked_id())).unwrap_or_default().answered(now, error);
    let current = Switches::of(reach);
    let mut next = current;
    card(ui, |ui| {
        card_title(ui, s.reach_title);
        ui.add_space(4.0);
        ui.add(egui::Label::new(RichText::new(s.reach_text).color(WEAK)).wrap());
        ui.add_space(16.0);
        failure_note(ui, s, asked.failure(now, Origin::Switches));

        switch_row(ui, s.reach_standalone, s.reach_standalone_text, &mut next.standalone);
        if reach.standalone {
            standalone_details(ui, s, reach);
        }
        section_break(ui);
        switch_row(ui, s.reach_dht, s.reach_dht_text, &mut next.dht);
        section_break(ui);
        switch_row(ui, s.reach_relay, s.reach_relay_text, &mut next.relay_for_others);
        ui.add_space(10.0);
        let help = fill(s.reach_relay_help, &[s.relay_title]);
        ui.add(egui::Label::new(RichText::new(help).small().color(WEAK)).wrap());
        if let Some(last) = &reach.last_reached {
            section_break(ui);
            labelled(ui, s.reach_last, &[last_reached_text(last, s)], false);
        }
    });
    ui.add_space(16.0);
    let switches = (next != current).then(|| (next.request(), Origin::Switches));
    let relays = relay_card(ui, s, reach, &asked, now);
    let sent = switches.or(relays);
    let asked = match &sent {
        Some((_, origin)) => asked.sent(now, *origin, error),
        None => asked,
    };
    ctx.data_mut(|data| data.insert_temp(asked_id(), asked.clone()));
    if let Some(left) = asked.next_change(now) {
        ctx.request_repaint_after(Duration::from_secs_f64(left));
    }
    sent.map(|(request, _)| request)
}

/// What went wrong with the last change made here, in a banner, until it is old news.
fn failure_note(ui: &mut egui::Ui, s: &Strings, error: Option<&str>) {
    if let Some(error) = error {
        banner(ui, &failure_text(s, error), ERROR);
        ui.add_space(12.0);
    }
}

/// The request that makes this PC register with the relay whose pairing link was pasted: the
/// relay's addresses and its host fingerprint, which the link carries, and the name given. The
/// one-time code and the secrets in the link stay here.
fn use_request(link: &str, name: &str) -> Option<Request> {
    let link = parse_pairing_link(link)?;
    Some(Request::AddRelay {
        name: short_name(name),
        address: link.address,
        also: link.also,
        fingerprint: link.code.host.to_base64(),
    })
}

/// The request that lets the computer whose pairing link (or code) was pasted register with this
/// PC as its relay. Only its host fingerprint is taken: this PC never connects to it.
fn allow_request(link: &str, name: &str) -> Option<Request> {
    let host = parse_pairing_link(link)
        .map(|link| link.code.host)
        .or_else(|| PairingCode::parse(link).ok().map(|code| code.host))?;
    Some(Request::AllowRelayHost { name: short_name(name), fingerprint: host.to_base64() })
}

/// A name as typed: trimmed, and not longer than anyone needs.
fn short_name(name: &str) -> String {
    name.trim().chars().take(64).collect()
}

/// A line for a relay this host is set to register with: whether it is, or why not.
fn relay_line(entry: &RelayEntry, s: &Strings) -> Line {
    let detail = match (entry.registered, entry.reason.as_deref().filter(|reason| !reason.is_empty())) {
        (true, _) => s.relay_up_use.to_string(),
        (false, Some(reason)) => fill(s.relay_down_why, &[reason]),
        (false, None) => s.relay_down.to_string(),
    };
    Line { good: entry.registered, text: entry_name(&entry.name, &entry.fingerprint), detail }
}

/// A line for a computer allowed to register here.
fn host_line(entry: &RelayHostEntry, s: &Strings) -> Line {
    let detail = if entry.registered { s.relay_up_allow } else { s.relay_down };
    Line { good: entry.registered, text: entry_name(&entry.name, &entry.fingerprint), detail: detail.to_string() }
}

/// What an entry is called, or the start of its fingerprint when it has no name.
fn entry_name(name: &str, fingerprint: &str) -> String {
    if name.is_empty() {
        fingerprint.chars().take(8).collect()
    } else {
        name.to_string()
    }
}

/// The second card of This PC: the relays this PC uses and the computers allowed to use it as one,
/// each with a way to add and to remove. What is asked comes back with the part that asked.
fn relay_card(
    ui: &mut egui::Ui,
    s: &Strings,
    reach: &ReachStatus,
    asked: &Asked,
    now: f64,
) -> Option<(Request, Origin)> {
    let mut sent = None;
    card(ui, |ui| {
        card_title(ui, s.relay_title);
        ui.add_space(4.0);
        ui.add(egui::Label::new(RichText::new(s.relay_intro).color(WEAK)).wrap());
        ui.add_space(14.0);
        steps(ui, s);

        section_break(ui);
        section_heading(ui, s.relay_use_title, s.relay_use_text);
        ui.add_space(10.0);
        if reach.relays.is_empty() {
            none_yet(ui, s);
        }
        for entry in &reach.relays {
            if entry_row(ui, s, &relay_line(entry, s)) {
                sent = Some((Request::RemoveRelay { fingerprint: entry.fingerprint.clone() }, Origin::UseRelay));
            }
            ui.add_space(8.0);
        }
        failure_note(ui, s, asked.failure(now, Origin::UseRelay));
        if let Some(request) = relay_form(ui, s, "use", s.relay_use_button, use_request) {
            sent = Some((request, Origin::UseRelay));
        }

        section_break(ui);
        section_heading(ui, s.relay_allow_title, s.relay_allow_text);
        ui.add_space(10.0);
        if reach.relay_hosts.is_empty() {
            none_yet(ui, s);
        }
        for entry in &reach.relay_hosts {
            if entry_row(ui, s, &host_line(entry, s)) {
                sent = Some((Request::RemoveRelayHost { fingerprint: entry.fingerprint.clone() }, Origin::AllowHost));
            }
            ui.add_space(8.0);
        }
        // Allowed, but this PC does not relay: nobody can use it yet.
        if !reach.relay_hosts.is_empty() && !reach.relay_for_others {
            let off = fill(s.relay_allow_off, &[s.reach_relay]);
            ui.add(egui::Label::new(RichText::new(off).small().color(WEAK)).wrap());
            ui.add_space(8.0);
        }
        failure_note(ui, s, asked.failure(now, Origin::AllowHost));
        if let Some(request) = relay_form(ui, s, "allow", s.relay_allow_button, allow_request) {
            sent = Some((request, Origin::AllowHost));
        }
    });
    ui.add_space(16.0);
    sent
}

/// The three steps of setting up a relay, numbered.
fn steps(ui: &mut egui::Ui, s: &Strings) {
    let second = fill(s.relay_step2, &[s.relay_use_title, s.relay_allow_title, s.show_qr, s.copy_link]);
    for (number, text) in [(1, s.relay_step1.to_string()), (2, second), (3, s.relay_step3.to_string())] {
        ui.horizontal_top(|ui| {
            ui.spacing_mut().item_spacing.x = 8.0;
            ui.label(RichText::new(format!("{number}.")).font(font(13.0, semibold())).color(ACCENT_TEXT));
            ui.add(egui::Label::new(RichText::new(text).color(WEAK)).wrap());
        });
        ui.add_space(4.0);
    }
}

/// A title with a note under it, above a list.
fn section_heading(ui: &mut egui::Ui, title: &str, note: &str) {
    ui.label(RichText::new(title).font(font(14.0, medium())));
    ui.add_space(2.0);
    ui.add(egui::Label::new(RichText::new(note).color(WEAK)).wrap());
}

fn none_yet(ui: &mut egui::Ui, s: &Strings) {
    ui.label(RichText::new(s.relay_none).color(FAINT));
    ui.add_space(8.0);
}

/// A line of a list with a Remove chip at its right end: true once Remove is clicked.
fn entry_row(ui: &mut egui::Ui, s: &Strings, line: &Line) -> bool {
    let mut remove = false;
    ui.horizontal_top(|ui| {
        // Leave room for the chip so the detail wraps before it.
        let text_width = ui.available_width() - 100.0;
        ui.allocate_ui_with_layout(egui::vec2(text_width, 0.0), Layout::top_down(Align::Min), |ui| {
            status_line(ui, line)
        });
        ui.with_layout(Layout::right_to_left(Align::Min), |ui| remove = small_button(ui, s.remove, true).clicked());
    });
    remove
}

/// A pasted pairing link, an optional name and the button that turns them into a request with
/// `make`; the button waits for a link that `make` can read. What is typed stays in egui's memory
/// while the card is on screen, and goes with the request.
fn relay_form(
    ui: &mut egui::Ui,
    s: &Strings,
    which: &str,
    button: &str,
    make: fn(&str, &str) -> Option<Request>,
) -> Option<Request> {
    let ctx = ui.ctx().clone();
    let (link_id, name_id) = (egui::Id::unique(("relay-link", which)), egui::Id::unique(("relay-name", which)));
    let mut link: String = ctx.data(|data| data.get_temp(link_id)).unwrap_or_default();
    let mut name: String = ctx.data(|data| data.get_temp(name_id)).unwrap_or_default();
    ui.add(field(&mut link, s.relay_link_hint, true).id(link_id));
    let request = make(&link, &name);
    if !link.trim().is_empty() && request.is_none() {
        let text = fill(s.relay_bad_link, &[s.show_qr, s.copy_link]);
        ui.add(egui::Label::new(RichText::new(text).small().color(ERROR)).wrap());
    }
    ui.add_space(6.0);
    let mut clicked = false;
    ui.horizontal(|ui| {
        ui.add_sized([150.0, CONTROL_HEIGHT], field(&mut name, s.relay_name_hint, false).id(name_id));
        clicked = primary_button(ui, button, ui.available_width(), request.is_some()).clicked();
    });
    ctx.data_mut(|data| {
        if clicked {
            data.remove::<String>(link_id);
            data.remove::<String>(name_id);
        } else {
            data.insert_temp(link_id, link);
            data.insert_temp(name_id, name);
        }
    });
    request.filter(|_| clicked)
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
    use velora_protocol::{pairing::pairing_uri_with, tls::Fingerprint};

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
        /// Where each text was painted.
        rects: Vec<(String, Rect)>,
    }

    impl Painted {
        fn has(&self, text: &str) -> bool {
            self.texts.iter().any(|t| t == text)
        }

        fn mentions(&self, part: &str) -> bool {
            self.texts.iter().any(|t| t.contains(part))
        }

        /// How many times `text` was painted.
        fn count(&self, text: &str) -> usize {
            self.texts.iter().filter(|t| *t == text).count()
        }

        /// Where `text` was painted, each time, in the order it was.
        fn rects(&self, text: &str) -> Vec<Rect> {
            self.rects.iter().filter(|(t, _)| t == text).map(|(_, rect)| *rect).collect()
        }

        fn rect(&self, text: &str) -> Option<Rect> {
            self.rects(text).first().copied()
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
                screen_rect: Some(Rect::from_min_size(Pos2::ZERO, vec2(440.0, 3600.0))),
                time: Some(self.time),
                events,
                ..Default::default()
            };
            let output = self.ctx.run_ui(input, |ui| add(ui));
            let mut painted = Painted { texts: Vec::new(), switches: Vec::new(), rects: Vec::new() };
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
            Shape::Text(text) => {
                painted.texts.push(text.galley.text().to_string());
                painted.rects.push((text.galley.text().to_string(), Rect::from_min_size(text.pos, text.galley.size())));
            }
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
            assert!(painted.has(&fill(s.reach_relay_help, &[s.relay_title])));
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
            let painted = frames.run(click(track.center()), |ui| sent = reach_card(ui, s, Some(&status), None));
            assert_eq!(sent, Some(want.request()), "clicking the switch at {track:?}");
            // The card of the relays is still there in the frame of the click, not skipped for it.
            assert!(painted.has(s.relay_title));
        }
        // A frame with no click asks for nothing.
        let mut sent = None;
        frames.run(Vec::new(), |ui| sent = reach_card(ui, s, Some(&status), None));
        assert_eq!(sent, None);
    }

    /// What the host answers a change that a user without rights makes under the service
    /// (`Shared::control` in the host's `server.rs`).
    const REFUSAL: &str = "only an administrator can change this computer's access";
    /// What a host that predates the relay requests answers them (`handle` in the host's `control.rs`).
    const OLD_HOST: &str = "malformed request: unknown variant `add_relay`, expected one of `status`, `start_pairing`";

    #[test]
    fn what_the_host_answers_is_told_in_plain_words() {
        assert!(is_admin_refusal(REFUSAL) && !is_admin_refusal("saving the standalone reach switches: disk full"));
        assert!(is_old_host(OLD_HOST) && !is_old_host(REFUSAL));
        let other = "a computer cannot be its own relay";
        for s in strings::all() {
            assert_eq!(friendly_error(s, REFUSAL), s.reach_admin_needed);
            assert_eq!(friendly_error(s, OLD_HOST), s.relay_too_old);
            // The banner leaves any other error as the host worded it; the cards put a sentence before it.
            assert_eq!(friendly_error(s, other), other);
            assert_eq!(failure_text(s, other), fill(s.relay_failed, &[other]));
            assert_eq!(
                (failure_text(s, REFUSAL), failure_text(s, OLD_HOST)),
                (s.reach_admin_needed.into(), s.relay_too_old.into())
            );
        }
    }

    #[test]
    fn what_the_cards_remember_of_their_requests_follows_the_clock() {
        // An error with no request of the cards before it is nobody's answer.
        let asked = Asked::default().answered(10.0, Some(REFUSAL));
        assert_eq!(asked.failure(10.0, Origin::Switches), None);
        // A request, then an error in time: its answer, for the part that sent it only.
        let sent = Asked::default().sent(10.0, Origin::UseRelay, None);
        let failed = sent.clone().answered(12.0, Some("no"));
        assert_eq!(failed.failure(12.0, Origin::UseRelay), Some("no"));
        assert_eq!((failed.failure(12.0, Origin::Switches), failed.failure(12.0, Origin::AllowHost)), (None, None));
        // It lasts, and its end is known.
        assert_eq!(failed.failure(12.0 + FAILED_SECONDS - 0.1, Origin::UseRelay), Some("no"));
        assert_eq!(failed.failure(12.0 + FAILED_SECONDS, Origin::UseRelay), None);
        assert_eq!(failed.next_change(13.0), Some(FAILED_SECONDS - 1.0));
        assert_eq!((failed.next_change(12.0 + FAILED_SECONDS), Asked::default().next_change(1.0)), (None, None));
        // Too late to be an answer, and the error that was showing when the request went out is not
        // its answer either.
        let late = sent.answered(10.0 + ASKED_SECONDS + 0.1, Some("no"));
        assert_eq!(late.failure(10.0 + ASKED_SECONDS + 0.1, Origin::UseRelay), None);
        let stale = Asked::default().sent(10.0, Origin::Switches, Some("old"));
        assert_eq!(stale.clone().answered(10.5, Some("old")).failure(10.5, Origin::Switches), None);
        assert_eq!(stale.answered(10.5, Some("new")).failure(10.5, Origin::Switches), Some("new"));
        // The next request starts over.
        assert_eq!(failed.sent(20.0, Origin::UseRelay, None).failure(20.0, Origin::UseRelay), None);
    }

    #[test]
    fn the_cards_explain_a_failed_change_where_it_was_made() {
        let s = strings::current();
        let status = reach();
        let mut frames = Frames::new();
        let run = |frames: &mut Frames, events: Vec<Event>, error: Option<&str>| {
            let mut sent = None;
            let painted = frames.run(events, |ui| sent = reach_card(ui, s, Some(&status), error));
            (painted, sent)
        };
        let (first, _) = run(&mut frames, Vec::new(), None);
        // A refusal of something else that the user did, such as removing a device, is not for the cards.
        assert!(!run(&mut frames, Vec::new(), Some(REFUSAL)).0.has(s.reach_admin_needed));
        // A switch is flipped, and the host refuses: the card says why, in the frame the error arrives
        // and for as long afterwards as the launcher's own banner is gone, and only there.
        let (_, sent) = run(&mut frames, click(first.switches[1].center()), None);
        assert!(sent.is_some());
        let (painted, _) = run(&mut frames, Vec::new(), Some(REFUSAL));
        assert_eq!(painted.count(s.reach_admin_needed), 1);
        assert_eq!(run(&mut frames, Vec::new(), None).0.count(s.reach_admin_needed), 1);
        frames.advance(FAILED_SECONDS - 1.0);
        assert_eq!(run(&mut frames, Vec::new(), None).0.count(s.reach_admin_needed), 1);
        // Then it lets go.
        frames.advance(2.0);
        assert_eq!(run(&mut frames, Vec::new(), None).0.count(s.reach_admin_needed), 0);
        // Another kind of error gets a sentence of its own.
        run(&mut frames, click(first.switches[1].center()), None);
        let other = "saving the standalone reach switches: disk full";
        let (painted, _) = run(&mut frames, Vec::new(), Some(other));
        assert!(painted.has(&fill(s.relay_failed, &[other])), "{:#?}", painted.texts);
        // A refusal long after the last request is not an answer to it.
        frames.advance(FAILED_SECONDS + ASKED_SECONDS);
        assert!(!run(&mut frames, Vec::new(), Some(REFUSAL)).0.has(s.reach_admin_needed));
    }

    /// The pairing link of a made-up computer, with a code and secrets that must not travel on.
    fn link(host: u8, address: &str, also: &[&str]) -> (String, PairingCode) {
        let code = PairingCode::generate(Fingerprint([host; 32])).unwrap();
        let also: Vec<String> = also.iter().map(|a| a.to_string()).collect();
        (pairing_uri_with(address, &also, &code, Some(&[1; 32]), Some(&[2; 16])), code)
    }

    #[test]
    fn a_pairing_link_gives_the_host_only_what_it_needs_of_it() {
        let (text, code) = link(7, "203.0.113.10:7420", &["198.51.100.20:7420"]);
        let fingerprint = Fingerprint([7; 32]).to_base64();
        // A relay: its addresses and its host fingerprint, and the name as given, trimmed.
        let want = Request::AddRelay {
            name: "Office PC".into(),
            address: "203.0.113.10:7420".into(),
            also: vec!["198.51.100.20:7420".into()],
            fingerprint: fingerprint.clone(),
        };
        assert_eq!(use_request(&format!("  {text}\n"), "  Office PC "), Some(want));
        // The names are cut and the fingerprint is the host's, not the one-time code.
        let Some(Request::AddRelay { name, fingerprint: sent, .. }) = use_request(&text, &"x".repeat(100)) else {
            panic!("a link is a relay")
        };
        assert_eq!((name.len(), sent), (64, fingerprint.clone()));
        assert!(!format!("{:?}", use_request(&text, "")).contains(&code.encode()));
        // A relay needs an address, which a bare code lacks; a computer that may register needs only
        // the fingerprint, so a link or a code will do.
        assert_eq!(use_request(&code.encode(), ""), None);
        let allowed = Request::AllowRelayHost { name: "Home PC".into(), fingerprint };
        assert_eq!(allow_request(&text, "Home PC"), Some(allowed.clone()));
        assert_eq!(allow_request(&code.encode(), " Home PC"), Some(allowed));
        for nonsense in ["", "   ", "hello", "velora://pair?address=x", "VL1-short"] {
            assert_eq!((use_request(nonsense, ""), allow_request(nonsense, "")), (None, None), "{nonsense:?}");
        }
    }

    /// Fingerprints of made-up relays and computers.
    fn fp(host: u8) -> String {
        Fingerprint([host; 32]).to_base64()
    }

    /// A status with relays and allowed computers, one of each of both kinds of state.
    fn relays() -> ReachStatus {
        ReachStatus {
            relays: vec![
                RelayEntry {
                    name: "Office PC".into(),
                    fingerprint: fp(1),
                    address: "203.0.113.10:7420".into(),
                    registered: true,
                    reason: None,
                },
                RelayEntry {
                    name: String::new(),
                    fingerprint: fp(2),
                    address: "198.51.100.20:7420".into(),
                    registered: false,
                    reason: Some("it does not relay for other devices".into()),
                },
            ],
            relay_hosts: vec![
                RelayHostEntry { name: "Home PC".into(), fingerprint: fp(3), registered: true },
                RelayHostEntry { name: "Studio".into(), fingerprint: fp(4), registered: false },
            ],
            ..reach()
        }
    }

    #[test]
    fn the_relay_card_lists_both_sides_with_their_state() {
        for s in strings::all() {
            let mut frames = Frames::new();
            let status = relays();
            let painted = frames.run(Vec::new(), |ui| _ = reach_card(ui, s, Some(&status), None));
            let steps = fill(s.relay_step2, &[s.relay_use_title, s.relay_allow_title, s.show_qr, s.copy_link]);
            let why = fill(s.relay_down_why, &["it does not relay for other devices"]);
            for text in [
                s.relay_title,
                s.relay_intro,
                s.relay_step1,
                &steps,
                s.relay_step3,
                s.relay_use_title,
                s.relay_use_text,
                s.relay_allow_title,
                s.relay_allow_text,
                // A relay: its name and how it stands; one without a name is told by its fingerprint.
                "Office PC",
                s.relay_up_use,
                &fp(2)[..8],
                &why,
                // An allowed computer.
                "Home PC",
                s.relay_up_allow,
                "Studio",
                s.relay_down,
                s.relay_use_button,
                s.relay_allow_button,
            ] {
                assert!(painted.has(text), "{text:?} was not painted, only {:#?}", painted.texts);
            }
            assert_eq!(painted.count(s.remove), 4);
            assert!(!painted.has(s.relay_none));
            // The computers may register, but this PC does not relay yet: nobody can use it.
            let off = fill(s.relay_allow_off, &[s.reach_relay]);
            assert!(painted.has(&off));
            let on = ReachStatus { relay_for_others: true, ..relays() };
            assert!(!frames.run(Vec::new(), |ui| _ = reach_card(ui, s, Some(&on), None)).has(&off));
            // With none, each list says so, and the hint has nothing to say.
            let none = ReachStatus { relays: Vec::new(), relay_hosts: Vec::new(), ..reach() };
            let painted = frames.run(Vec::new(), |ui| _ = reach_card(ui, s, Some(&none), None));
            assert_eq!((painted.count(s.relay_none), painted.count(s.remove)), (2, 0));
            assert!(!painted.has(&off));
        }
    }

    #[test]
    fn remove_asks_the_host_to_forget_that_one_entry() {
        let s = strings::current();
        let status = relays();
        let mut frames = Frames::new();
        let first = frames.run(Vec::new(), |ui| _ = reach_card(ui, s, Some(&status), None));
        // In the order they are drawn: the relays, then the computers.
        let wanted = [
            Request::RemoveRelay { fingerprint: fp(1) },
            Request::RemoveRelay { fingerprint: fp(2) },
            Request::RemoveRelayHost { fingerprint: fp(3) },
            Request::RemoveRelayHost { fingerprint: fp(4) },
        ];
        let chips = first.rects(s.remove);
        assert_eq!(chips.len(), wanted.len());
        for (chip, want) in chips.iter().zip(wanted) {
            let mut sent = None;
            frames.run(click(chip.center()), |ui| sent = reach_card(ui, s, Some(&status), None));
            assert_eq!(sent, Some(want), "clicking Remove at {chip:?}");
        }
    }

    /// Types into a form of the relay card, as far as egui's memory is concerned.
    fn type_into(ctx: &egui::Context, which: &str, link: &str, name: &str) {
        ctx.data_mut(|data| {
            data.insert_temp(egui::Id::unique(("relay-link", which)), link.to_string());
            data.insert_temp(egui::Id::unique(("relay-name", which)), name.to_string());
        });
    }

    #[test]
    fn a_form_sends_what_was_pasted_when_it_is_a_link_and_forgets_it() {
        let s = strings::current();
        let status = reach();
        let mut frames = Frames::new();
        let (text, _) = link(7, "203.0.113.10:7420", &[]);
        let run = |frames: &mut Frames, events: Vec<Event>| {
            let mut sent = None;
            let painted = frames.run(events, |ui| sent = reach_card(ui, s, Some(&status), None));
            (painted, sent)
        };
        let bad = fill(s.relay_bad_link, &[s.show_qr, s.copy_link]);
        // Nothing pasted: no complaint, and the button is deaf.
        let (painted, _) = run(&mut frames, Vec::new());
        assert!(!painted.has(&bad));
        let button = painted.rect(s.relay_use_button).unwrap().center();
        assert_eq!(run(&mut frames, click(button)).1, None);
        // Something that is not a link: the card says what a link is, and the button stays deaf.
        type_into(&frames.ctx, "use", "hello", "");
        let (painted, _) = run(&mut frames, Vec::new());
        assert!(painted.has(&bad));
        assert_eq!(run(&mut frames, click(button)).1, None);
        // A link: the complaint is gone and a click sends it, with the name typed beside it.
        type_into(&frames.ctx, "use", &text, "Office PC");
        let (painted, _) = run(&mut frames, Vec::new());
        assert!(!painted.has(&bad));
        let button = painted.rect(s.relay_use_button).unwrap().center();
        let want = Request::AddRelay {
            name: "Office PC".into(),
            address: "203.0.113.10:7420".into(),
            also: Vec::new(),
            fingerprint: fp(7),
        };
        assert_eq!(run(&mut frames, click(button)).1, Some(want));
        // What was typed goes with it.
        let again = frames.ctx.data(|data| data.get_temp::<String>(egui::Id::unique(("relay-link", "use"))));
        assert_eq!(again, None);
        assert_eq!(run(&mut frames, click(button)).1, None);
        // The other form takes a link too, and asks the host to let that computer register.
        type_into(&frames.ctx, "allow", &text, "");
        let (painted, _) = run(&mut frames, Vec::new());
        let button = painted.rect(s.relay_allow_button).unwrap().center();
        let want = Request::AllowRelayHost { name: String::new(), fingerprint: fp(7) };
        assert_eq!(run(&mut frames, click(button)).1, Some(want));
    }

    #[test]
    fn a_failed_relay_request_is_explained_under_its_own_form() {
        let s = strings::current();
        let status = reach();
        let mut frames = Frames::new();
        let (text, _) = link(7, "203.0.113.10:7420", &[]);
        let run = |frames: &mut Frames, events: Vec<Event>, error: Option<&str>| {
            let mut sent = None;
            let painted = frames.run(events, |ui| sent = reach_card(ui, s, Some(&status), error));
            (painted, sent)
        };
        // "Let it use this PC" is clicked, and the host says no.
        type_into(&frames.ctx, "allow", &text, "");
        let (painted, _) = run(&mut frames, Vec::new(), None);
        let button = painted.rect(s.relay_allow_button).unwrap().center();
        assert!(run(&mut frames, click(button), None).1.is_some());
        let no = "a computer cannot register with itself";
        let (painted, _) = run(&mut frames, Vec::new(), Some(no));
        let said = fill(s.relay_failed, &[no]);
        assert_eq!(painted.count(&said), 1);
        // It sits above the form that sent the request, below the list of that part, not elsewhere.
        let (said_at, allow_at, use_at) = (
            painted.rect(&said).unwrap(),
            painted.rect(s.relay_allow_button).unwrap(),
            painted.rect(s.relay_use_button).unwrap(),
        );
        assert!(said_at.top() < allow_at.top() && said_at.top() > use_at.bottom());
        // A host that is too old says so in plain words.
        type_into(&frames.ctx, "use", &text, "");
        run(&mut frames, Vec::new(), None);
        frames.advance(ASKED_SECONDS);
        let (painted, _) = run(&mut frames, Vec::new(), None);
        let button = painted.rect(s.relay_use_button).unwrap().center();
        assert!(run(&mut frames, click(button), None).1.is_some());
        assert!(run(&mut frames, Vec::new(), Some(OLD_HOST)).0.has(s.relay_too_old));
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
            // The relay card: its lists, a link that is none, and what went wrong with a request.
            let listed = relays();
            shown.extend(frames.run(Vec::new(), |ui| _ = reach_card(ui, s, Some(&listed), None)).texts);
            type_into(&frames.ctx, "use", "hello", "");
            shown.extend(frames.run(Vec::new(), |ui| _ = reach_card(ui, s, Some(&listed), None)).texts);
            for (origin, error) in
                [(Origin::UseRelay, "a computer cannot be its own relay"), (Origin::AllowHost, OLD_HOST)]
            {
                let asked = Asked::default().sent(frames.time, origin, None).answered(frames.time, Some(error));
                frames.ctx.data_mut(|data| data.insert_temp(asked_id(), asked));
                shown.extend(frames.run(Vec::new(), |ui| _ = reach_card(ui, s, Some(&listed), None)).texts);
            }
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
                ("relay_title", s.relay_title),
                ("relay_intro", s.relay_intro),
                ("relay_step1", s.relay_step1),
                ("relay_step2", s.relay_step2),
                ("relay_step3", s.relay_step3),
                ("relay_use_title", s.relay_use_title),
                ("relay_use_text", s.relay_use_text),
                ("relay_use_button", s.relay_use_button),
                ("relay_allow_title", s.relay_allow_title),
                ("relay_allow_text", s.relay_allow_text),
                ("relay_allow_button", s.relay_allow_button),
                ("relay_allow_off", s.relay_allow_off),
                ("relay_link_hint", s.relay_link_hint),
                ("relay_name_hint", s.relay_name_hint),
                ("relay_bad_link", s.relay_bad_link),
                ("relay_none", s.relay_none),
                ("relay_up_use", s.relay_up_use),
                ("relay_up_allow", s.relay_up_allow),
                ("relay_down", s.relay_down),
                ("relay_down_why", s.relay_down_why),
                ("relay_failed", s.relay_failed),
                ("relay_too_old", s.relay_too_old),
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
