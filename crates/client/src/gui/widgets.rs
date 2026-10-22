//! Velora controls: flat fills, 1 px borders, consistent heights.

use eframe::egui::{
    self, vec2, Align2, Color32, CursorIcon, FontId, Rect, Response, RichText, Sense, Shadow, Stroke, StrokeKind, Ui,
};

use super::{
    icons::{Icon, Icons},
    theme::*,
};

pub const CONTROL_HEIGHT: f32 = 40.0;
/// Hover fades, in seconds.
pub const HOVER_SECONDS: f32 = 0.12;

/// Section label, title and optional subtitle opening each page.
pub fn page_header(ui: &mut Ui, label: &str, title: &str, subtitle: Option<&str>) {
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(vec2(16.0, 12.0), Sense::hover());
        ui.painter().rect_filled(Rect::from_center_size(rect.center(), vec2(16.0, 2.0)), 0.0, ACCENT_TEXT);
        ui.label(
            RichText::new(label.to_uppercase())
                .font(font(11.5, semibold()))
                .color(ACCENT_TEXT)
                .extra_letter_spacing(1.0),
        );
    });
    ui.add_space(4.0);
    ui.label(RichText::new(title).font(font(28.0, bold())).extra_letter_spacing(-0.4));
    if let Some(subtitle) = subtitle {
        ui.add_space(2.0);
        ui.label(RichText::new(subtitle).color(WEAK).size(15.0));
    }
    ui.add_space(24.0);
}

pub fn card<R>(ui: &mut Ui, add: impl FnOnce(&mut Ui) -> R) -> egui::InnerResponse<R> {
    egui::Frame::new()
        .fill(CARD)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(CARD_RADIUS)
        .inner_margin(24)
        .shadow(Shadow { offset: [0, 8], blur: 24, spread: 0, color: Color32::from_black_alpha(60) })
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        })
}

pub fn card_title(ui: &mut Ui, text: &str) {
    ui.label(RichText::new(text).font(font(15.0, semibold())));
}

pub fn field_label(ui: &mut Ui, text: &str) {
    ui.label(RichText::new(text).font(font(13.0, medium())).color(WEAK));
}

/// A single-line input; `technical` sets it in monospace, for codes and addresses.
pub fn field<'a>(text: &'a mut String, hint: &'a str, technical: bool) -> egui::TextEdit<'a> {
    let font = if technical { mono(13.5) } else { FontId::proportional(14.0) };
    egui::TextEdit::singleline(text)
        .hint_text(RichText::new(hint).color(FAINT).size(14.0))
        .desired_width(f32::INFINITY)
        .margin(vec2(12.0, 11.0))
        .font(font)
}

/// The page's main action: solid accent.
pub fn primary_button(ui: &mut Ui, text: &str, width: f32, enabled: bool) -> Response {
    let sense = if enabled { Sense::click() } else { Sense::hover() };
    let (rect, response) = ui.allocate_exact_size(vec2(width, CONTROL_HEIGHT), sense);
    let hover =
        ui.ctx().animate_bool_with_time(response.id.with("hover"), enabled && response.hovered(), HOVER_SECONDS);
    let press = ui.ctx().animate_bool_with_time(response.id.with("press"), response.is_pointer_button_down_on(), 0.06);
    let painter = ui.painter();
    let (fill, color) = if enabled {
        (ACCENT.lerp_to_gamma(ACCENT_HOVER, hover).lerp_to_gamma(ACCENT_PRESSED, press), Color32::WHITE)
    } else {
        (HOVER, FAINT)
    };
    painter.rect_filled(rect, RADIUS, fill);
    painter.text(rect.center(), Align2::CENTER_CENTER, text, font(14.0, semibold()), color);
    if enabled {
        response.on_hover_cursor(CursorIcon::PointingHand)
    } else {
        response
    }
}

/// A secondary action: outlined, fills on hover.
pub fn secondary_button(ui: &mut Ui, text: &str) -> Response {
    secondary_button_icon(ui, text, None)
}

/// [`secondary_button`] with a leading icon.
pub fn secondary_button_icon(ui: &mut Ui, text: &str, icon: Option<(&Icons, Icon)>) -> Response {
    const ICON: f32 = 16.0;
    let galley = ui.painter().layout_no_wrap(text.to_string(), font(14.0, medium()), TEXT);
    let lead = if icon.is_some() { ICON + 8.0 } else { 0.0 };
    let (rect, response) = ui.allocate_exact_size(vec2(galley.size().x + lead + 28.0, CONTROL_HEIGHT), Sense::click());
    let hover = ui.ctx().animate_bool_with_time(response.id.with("hover"), response.hovered(), HOVER_SECONDS);
    let press = ui.ctx().animate_bool_with_time(response.id.with("press"), response.is_pointer_button_down_on(), 0.06);
    let fill = Color32::TRANSPARENT.lerp_to_gamma(HOVER, hover).lerp_to_gamma(BORDER, press);
    let edge = BORDER_STRONG.lerp_to_gamma(FAINT, hover * 0.5);
    ui.painter().rect(rect, RADIUS, fill, Stroke::new(1.0, edge), StrokeKind::Inside);
    let left = rect.left() + 14.0;
    if let Some((icons, icon)) = icon {
        icons.paint(ui.painter(), icon, egui::pos2(left + ICON / 2.0, rect.center().y), ICON, TEXT);
    }
    ui.painter().galley(egui::pos2(left + lead, rect.center().y - galley.size().y / 2.0), galley, TEXT);
    response.on_hover_cursor(CursorIcon::PointingHand)
}

/// An on/off switch. Returns a response that is `changed()` when flipped.
pub fn toggle(ui: &mut Ui, on: &mut bool, enabled: bool) -> Response {
    let size = vec2(40.0, 22.0);
    let sense = if enabled { Sense::click() } else { Sense::hover() };
    let (rect, mut response) = ui.allocate_exact_size(size, sense);
    if response.clicked() {
        *on = !*on;
        response.mark_changed();
    }
    let t = ui.ctx().animate_bool_responsive(response.id, *on);
    let painter = ui.painter();
    let radius = size.y / 2.0;
    let track = BG.lerp_to_gamma(ACCENT, t);
    let edge = BORDER_STRONG.lerp_to_gamma(ACCENT, t);
    painter.rect(rect, radius, track, Stroke::new(1.0, edge), StrokeKind::Inside);
    let x = egui::lerp((rect.left() + radius)..=(rect.right() - radius), t);
    painter.circle_filled(egui::pos2(x, rect.center().y), radius - 4.0, WEAK.lerp_to_gamma(Color32::WHITE, t));
    if !enabled {
        painter.rect_filled(rect, radius, BG.gamma_multiply(0.6));
    }
    if enabled {
        response.on_hover_cursor(CursorIcon::PointingHand)
    } else {
        response
    }
}

/// A sidebar entry. The selection highlight is drawn by the sidebar, which slides it between
/// entries; `badge` is a count with its pulse (see [`super::motion::badge`]).
pub fn nav_item(
    ui: &mut Ui,
    icons: &Icons,
    icon: Icon,
    label: &str,
    selected: bool,
    badge: Option<(usize, f32)>,
) -> Response {
    let (rect, response) = ui.allocate_exact_size(vec2(ui.available_width(), 38.0), Sense::click());
    let t = ui.ctx().animate_bool_with_time(response.id.with("selected"), selected, 0.18);
    let hover =
        ui.ctx().animate_bool_with_time(response.id.with("hover"), response.hovered() && !selected, HOVER_SECONDS);
    let painter = ui.painter();
    if hover > 0.0 {
        painter.rect_filled(rect, RADIUS, Color32::from_white_alpha((10.0 * hover) as u8));
    }
    let color = WEAK.lerp_to_gamma(TEXT, t.max(hover));
    let icon_center = rect.left_center() + vec2(20.0, 0.0);
    icons.paint(painter, icon, icon_center, 18.0, color.lerp_to_gamma(ACCENT_TEXT, t));
    painter.text(rect.left_center() + vec2(40.0, 0.0), Align2::LEFT_CENTER, label, font(14.0, medium()), color);
    if let Some((count, pulse)) = badge {
        super::motion::badge(painter, rect.right_center() - vec2(10.0, 0.0), count, pulse);
    }
    response.on_hover_cursor(CursorIcon::PointingHand)
}

/// A notice above the page: a colored dot and a border in that color.
pub fn banner(ui: &mut Ui, text: &str, color: Color32) {
    let inner = egui::Frame::new()
        .fill(CARD)
        .stroke(Stroke::new(1.0, color.gamma_multiply(0.45)))
        .corner_radius(RADIUS)
        .inner_margin(egui::Margin { left: 30, right: 14, top: 10, bottom: 10 })
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(text);
        });
    let rect = inner.response.rect;
    ui.painter().circle_filled(egui::pos2(rect.left() + 16.0, rect.top() + 19.0), 3.5, color);
}

/// A colored dot followed by a label, e.g. "● Connected".
pub fn status(ui: &mut Ui, text: &str, color: Color32) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 6.0;
        let (rect, _) = ui.allocate_exact_size(vec2(8.0, 16.0), Sense::hover());
        ui.painter().circle_filled(rect.center(), 3.5, color);
        ui.label(RichText::new(text).font(font(13.0, medium())).color(color));
    });
}

/// A circle with the initials of `name`, like a profile picture placeholder.
pub fn avatar(ui: &mut Ui, name: &str, size: f32) {
    let initials: String = name
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .take(2)
        .filter_map(|w| w.chars().next())
        .flat_map(char::to_uppercase)
        .collect();
    let (rect, _) = ui.allocate_exact_size(vec2(size, size), Sense::hover());
    ui.painter().circle_filled(rect.center(), size / 2.0, AVATAR);
    let text = if initials.is_empty() { "?".to_string() } else { initials };
    ui.painter().text(rect.center(), Align2::CENTER_CENTER, text, font(size * 0.4, semibold()), Color32::WHITE);
}
