//! Standalone reach in the launcher (`docs/nat-traversal.md`): the card on This PC that shows how
//! this computer is reached from other networks and switches its parts, and the Wake button of a
//! device card.
//!
//! What the host reports (`Status.reach`) becomes text in plain functions, which the tests check
//! without a window; the tests also draw the card in a headless egui frame.

use std::path::Path;

use eframe::egui::{self, Align, Layout, RichText, Sense};
use velora_protocol::{
    control::{MappingStatus, ReachStatus, Request},
    identity::KnownHost,
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

/// With no relay, say how to get one, but only where it matters: when no port is open to reach the
/// computer by.
fn relay_hint_wanted(reach: &ReachStatus) -> bool {
    reach.registered_with.is_empty() && matches!(mapping_of(reach), Mapping::Closed | Mapping::Shared(_))
}

/// The card on This PC. A host that predates standalone reach (`None`) gets nothing, not even the
/// space under it. A flipped switch comes back as the request to send.
pub(super) fn reach_card(ui: &mut egui::Ui, s: &Strings, reach: Option<&ReachStatus>) -> Option<Request> {
    let reach = reach?;
    let current = Switches::of(reach);
    let mut next = current;
    card(ui, |ui| {
        card_title(ui, s.reach_title);
        ui.add_space(4.0);
        ui.add(egui::Label::new(RichText::new(s.reach_text).color(WEAK)).wrap());
        ui.add_space(16.0);

        switch_row(ui, s.reach_standalone, s.reach_standalone_text, &mut next.standalone);
        if reach.standalone {
            standalone_details(ui, s, reach);
        }
        section_break(ui);
        switch_row(ui, s.reach_dht, s.reach_dht_text, &mut next.dht);
        section_break(ui);
        switch_row(ui, s.reach_relay, s.reach_relay_text, &mut next.relay_for_others);
        if let Some(names) = registered_names(reach) {
            ui.add_space(12.0);
            labelled(ui, s.reach_relays, &[names], false);
        } else if relay_hint_wanted(reach) {
            ui.add_space(12.0);
            let hint = fill(s.reach_relays_none, &[s.reach_relay]);
            ui.add(egui::Label::new(RichText::new(hint).small().color(WEAK)).wrap());
        }
        if let Some(last) = &reach.last_reached {
            section_break(ui);
            labelled(ui, s.reach_last, &[last_reached_text(last, s)], false);
        }
    });
    ui.add_space(16.0);
    (next != current).then(|| next.request())
}

/// Under the standalone switch, while it is on: what the router did and the addresses it gave.
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

/// Where the wake-up of one computer stands, for its button. The states are what `hosts::wake` can
/// answer, plus the time while it works.
// reach: G2 builds every state but `Idle` from the outcome of `hosts::wake`.
#[allow(dead_code)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) enum WakeState {
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

/// What to tell about a wake-up, if anything; `Idle` has nothing to tell.
fn wake_text(state: &WakeState, s: &Strings) -> Option<String> {
    match state {
        WakeState::Idle => None,
        WakeState::Sending => Some(s.wake_sending.to_string()),
        WakeState::Sent => Some(s.wake_sent.to_string()),
        WakeState::NoRelay => Some(s.wake_no_relay.to_string()),
        WakeState::Unsupported => Some(s.wake_unsupported.to_string()),
        WakeState::Failed(reason) => Some(fill(s.wake_failed, &[reason])),
    }
}

/// A computer that never told its MAC address cannot be woken: it gets no button, which could only
/// say so. It learns the address the first time it is connected to with a host that sends it.
fn wake_offered(host: &KnownHost) -> bool {
    host.mac.is_some()
}

fn wake_id(host: &str) -> egui::Id {
    egui::Id::unique(("wake", host))
}

/// The wake-up of `host`, kept in egui's memory so that the launcher needs no field for it.
pub(super) fn wake_state(ctx: &egui::Context, host: &str) -> WakeState {
    ctx.data(|data| data.get_temp(wake_id(host))).unwrap_or_default()
}

/// Called by the thread that wakes `host` when its state changes.
// reach: G2 calls this.
#[allow(dead_code)]
pub(super) fn set_wake_state(ctx: &egui::Context, host: &str, state: WakeState) {
    ctx.data_mut(|data| data.insert_temp(wake_id(host), state));
    ctx.request_repaint();
}

const WAKE_HEIGHT: f32 = 28.0;

/// The Wake button of a device card; the card calls it for a computer that has no session open.
/// `card` is the card's area and `config_dir` the launcher's `--config-dir`, which the thread that
/// wakes the computer needs to open the paired list.
///
/// It sits in the card's top right corner, where a connected computer says so. The row of buttons
/// below has no room for it: in Portuguese at the narrowest window, Connect, Files and Forget take
/// about 370 of its 396 points and a fourth button would cover Forget.
pub(super) fn wake_button(
    ui: &mut egui::Ui,
    s: &Strings,
    host: &KnownHost,
    card: egui::Rect,
    _config_dir: Option<&Path>,
) {
    if !wake_offered(host) {
        return;
    }
    let state = wake_state(ui.ctx(), &host.name);
    let label = if state == WakeState::Sending { s.wake_sending } else { s.wake };
    let tip = wake_text(&state, s).unwrap_or_else(|| s.wake_tip.to_string());
    let corner = egui::Rect::from_min_size(card.right_top() + egui::vec2(-178.0, 18.0), egui::vec2(160.0, WAKE_HEIGHT));
    let layout = Layout::right_to_left(Align::Min);
    let mut corner = ui.new_child(egui::UiBuilder::new().max_rect(corner).layout(layout));
    // reach: G2 starts the wake-up when this is clicked (`hosts::wake` on a thread, as `pair_back`
    // does) and reports its outcome with `set_wake_state`.
    small_button(&mut corner, label).on_hover_text(tip);
}

/// An outlined button as small as a chip, for a corner of a card: `secondary_button` is a whole
/// control tall.
fn small_button(ui: &mut egui::Ui, text: &str) -> egui::Response {
    let galley = ui.painter().layout_no_wrap(text.to_string(), font(12.5, medium()), TEXT);
    let size = egui::vec2(galley.size().x + 24.0, WAKE_HEIGHT);
    let (rect, response) = ui.allocate_exact_size(size, Sense::click());
    let hover = ui.ctx().animate_bool_with_time(response.id.with("hover"), response.hovered(), HOVER_SECONDS);
    let fill = egui::Color32::TRANSPARENT.lerp_to_gamma(HOVER, hover);
    let edge = BORDER_STRONG.lerp_to_gamma(FAINT, hover * 0.5);
    ui.painter().rect(rect, RADIUS, fill, egui::Stroke::new(1.0, edge), egui::StrokeKind::Inside);
    ui.painter().galley(rect.center() - galley.size() / 2.0, galley, TEXT);
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

#[cfg(test)]
mod tests {
    use eframe::egui::{epaint::Shape, vec2, Event, Modifiers, PointerButton, Pos2, Rect};

    use super::*;
    use crate::gui::{strings, theme};

    /// Documentation addresses (RFC 5737, RFC 3849): nothing here is anyone's real network.
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
        }
    }

    fn host(mac: Option<[u8; 6]>) -> KnownHost {
        KnownHost { name: "Desk".into(), address: "192.0.2.10:7420".into(), mac, ..Default::default() }
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
    fn relays_are_listed_by_name_and_asked_for_only_when_a_port_is_not_enough() {
        assert_eq!(registered_names(&reach()).as_deref(), Some("Office PC, Laptop"));
        assert_eq!(registered_names(&ReachStatus::default()), None);

        let none = ReachStatus { registered_with: Vec::new(), ..reach() };
        // A port is open: nobody needs a relay.
        assert!(!relay_hint_wanted(&none));
        assert!(relay_hint_wanted(&ReachStatus { mapping: None, ..none.clone() }));
        let shared = Some(MappingStatus { public: false, ..none.mapping.clone().unwrap() });
        assert!(relay_hint_wanted(&ReachStatus { mapping: shared, ..none.clone() }));
        // Off asks for nothing, and a relay already registered needs no hint.
        assert!(!relay_hint_wanted(&ReachStatus { standalone: false, mapping: None, ..none }));
        assert!(!relay_hint_wanted(&ReachStatus { mapping: None, ..reach() }));
    }

    #[test]
    fn a_host_that_predates_reach_gets_no_card() {
        for s in strings::all() {
            let mut frames = Frames::new();
            let painted = frames.run(Vec::new(), |ui| {
                let top = ui.cursor().min;
                assert_eq!(reach_card(ui, s, None), None);
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
            let painted = frames.run(Vec::new(), |ui| assert_eq!(reach_card(ui, s, Some(&status)), None));
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
        }
    }

    #[test]
    fn what_the_router_did_not_do_is_said_plainly() {
        let s = strings::current();
        let mut frames = Frames::new();
        let status = ReachStatus { mapping: None, registered_with: Vec::new(), last_reached: None, ..reach() };
        let painted = frames.run(Vec::new(), |ui| {
            reach_card(ui, s, Some(&status));
        });
        assert!(painted.has(s.reach_mapping_closed) && painted.has(s.reach_mapping_closed_detail));
        assert!(painted.has(&fill(s.reach_relays_none, &[s.reach_relay])));
        assert!(!painted.has(s.reach_relays) && !painted.has(s.reach_last));
    }

    #[test]
    fn with_standalone_off_the_router_and_its_addresses_stay_out_of_sight() {
        let s = strings::current();
        let mut frames = Frames::new();
        let status = ReachStatus { standalone: false, ..reach() };
        let painted = frames.run(Vec::new(), |ui| {
            reach_card(ui, s, Some(&status));
        });
        assert!(painted.has(s.reach_standalone) && painted.has(s.reach_dht) && painted.has(s.reach_relay));
        for gone in [s.reach_mapping_open, s.reach_public, s.reach_v6, "203.0.113.7:51820"] {
            assert!(!painted.has(gone), "{gone:?} should be hidden");
        }
        // What was true of past connections and relays still is.
        assert!(painted.has(s.reach_last) && painted.has(s.reach_relays));
    }

    #[test]
    fn flipping_a_switch_sends_all_three_with_that_one_changed() {
        let s = strings::current();
        let status = reach();
        let reported = Switches::of(&status);
        let mut frames = Frames::new();
        let first = frames.run(Vec::new(), |ui| {
            reach_card(ui, s, Some(&status));
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
            frames.run(click(track.center()), |ui| sent = reach_card(ui, s, Some(&status)));
            assert_eq!(sent, Some(want.request()), "clicking the switch at {track:?}");
        }
        // A frame with no click asks for nothing.
        let mut sent = None;
        frames.run(Vec::new(), |ui| sent = reach_card(ui, s, Some(&status)));
        assert_eq!(sent, None);
    }

    #[test]
    fn a_wake_up_says_where_it_stands() {
        for s in strings::all() {
            assert_eq!(wake_text(&WakeState::Idle, s), None);
            assert_eq!(wake_text(&WakeState::Sending, s).as_deref(), Some(s.wake_sending));
            assert_eq!(wake_text(&WakeState::Sent, s).as_deref(), Some(s.wake_sent));
            assert_eq!(wake_text(&WakeState::NoRelay, s).as_deref(), Some(s.wake_no_relay));
            assert_eq!(wake_text(&WakeState::Unsupported, s).as_deref(), Some(s.wake_unsupported));
            let failed = wake_text(&WakeState::Failed("timed out".into()), s).unwrap();
            assert_eq!(failed, fill(s.wake_failed, &["timed out"]));
            assert!(failed.contains("timed out"));
        }
    }

    #[test]
    fn only_a_computer_with_a_known_mac_gets_a_wake_button() {
        let s = strings::current();
        let mut frames = Frames::new();
        let card = Rect::from_min_size(Pos2::ZERO, vec2(400.0, 150.0));
        let painted = frames.run(Vec::new(), |ui| wake_button(ui, s, &host(None), card, None));
        assert!(painted.texts.is_empty());
        let known = host(Some([0x02, 0, 0, 0, 0, 0x01]));
        let painted = frames.run(Vec::new(), |ui| wake_button(ui, s, &known, card, None));
        assert_eq!(painted.texts, [s.wake]);
        // While the request is on its way the button says so.
        set_wake_state(&frames.ctx, "Desk", WakeState::Sending);
        let painted = frames.run(Vec::new(), |ui| wake_button(ui, s, &known, card, None));
        assert_eq!(painted.texts, [s.wake_sending]);
        // Each computer has its own state.
        assert_eq!(wake_state(&frames.ctx, "Laptop"), WakeState::Idle);
    }

    /// Frames with the pointer resting on `at`, long enough for a tooltip: everything they painted.
    fn hover(frames: &mut Frames, at: Pos2, mut add: impl FnMut(&mut egui::Ui)) -> Vec<String> {
        frames.ctx.global_style_mut(|style| style.interaction.tooltip_delay = 0.0);
        frames.run(vec![Event::PointerMoved(at)], &mut add);
        (0..4).flat_map(|_| frames.run(Vec::new(), &mut add).texts).collect()
    }

    #[test]
    fn a_wake_up_shows_where_it_stands_on_the_button() {
        for s in strings::all() {
            let known = host(Some([0x02, 0, 0, 0, 0, 0x01]));
            let card = Rect::from_min_size(Pos2::ZERO, vec2(400.0, 150.0));
            for state in [
                WakeState::Idle,
                WakeState::Sending,
                WakeState::Sent,
                WakeState::NoRelay,
                WakeState::Unsupported,
                WakeState::Failed("timed out".into()),
            ] {
                let mut frames = Frames::new();
                set_wake_state(&frames.ctx, "Desk", state.clone());
                // The button is in the card's top right corner: the pointer rests on it.
                let on_it = card.right_top() + vec2(-30.0, 32.0);
                let shown = hover(&mut frames, on_it, |ui| wake_button(ui, s, &known, card, None));
                let tip = wake_text(&state, s).unwrap_or_else(|| s.wake_tip.to_string());
                assert!(shown.contains(&tip), "{state:?}: {tip:?} was not shown, only {shown:#?}");
            }
        }
    }

    /// A string that nothing shows is dead weight in a file that is frozen after this ticket.
    #[test]
    fn every_text_of_standalone_reach_is_shown_in_some_state() {
        for s in strings::all() {
            let mut frames = Frames::new();
            let mut shown = Vec::new();
            let shared = MappingStatus { public: false, ..reach().mapping.unwrap() };
            let mut statuses = vec![
                reach(),
                ReachStatus { mapping: Some(shared), registered_with: Vec::new(), ..reach() },
                ReachStatus { mapping: None, registered_with: Vec::new(), last_reached: None, ..reach() },
            ];
            for kind in [AddressKind::Lan, AddressKind::Vpn, AddressKind::Relay("fp".into()), AddressKind::Other(9)] {
                statuses.push(ReachStatus { last_reached: Some((kind, "192.0.2.5:7420".into())), ..reach() });
            }
            for status in &statuses {
                shown.extend(frames.run(Vec::new(), |ui| _ = reach_card(ui, s, Some(status))).texts);
            }
            let known = host(Some([0x02, 0, 0, 0, 0, 0x01]));
            let card = Rect::from_min_size(Pos2::ZERO, vec2(400.0, 150.0));
            shown.extend(frames.run(Vec::new(), |ui| wake_button(ui, s, &known, card, None)).texts);
            set_wake_state(&frames.ctx, "Desk", WakeState::Sending);
            shown.extend(frames.run(Vec::new(), |ui| wake_button(ui, s, &known, card, None)).texts);
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
                ("reach_v6", s.reach_v6),
                ("reach_dht", s.reach_dht),
                ("reach_dht_text", s.reach_dht_text),
                ("reach_relay", s.reach_relay),
                ("reach_relay_text", s.reach_relay_text),
                ("reach_relays", s.reach_relays),
                ("reach_relays_none", s.reach_relays_none),
                ("reach_last", s.reach_last),
                ("reach_kind_lan", s.reach_kind_lan),
                ("reach_kind_vpn", s.reach_kind_vpn),
                ("reach_kind_relay", s.reach_kind_relay),
                ("reach_kind_other", s.reach_kind_other),
                ("wake", s.wake),
                ("wake_sending", s.wake_sending),
            ] {
                assert!(is_shown(text), "{name} ({text:?}) is not shown in any state");
            }
        }
    }
}
