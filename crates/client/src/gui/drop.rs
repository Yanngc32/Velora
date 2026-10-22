//! Files dragged in from the system (Explorer, the desktop): where the pointer is while they
//! hover, so the drop goes to the target under it, and how a drop target looks.
//!
//! winit reports that files hover and where they were dropped, but not the pointer position
//! during the drag: on Windows the system owns the mouse then, so ask it.

use eframe::egui::{self, vec2, Align2, Painter, Pos2, Rect, Shape, Stroke};

use super::{file_icons, theme::*};

/// Files from the system are over the window.
pub fn hovering(ctx: &egui::Context) -> bool {
    ctx.input(|i| !i.raw.hovered_files.is_empty())
}

/// Absolute paths of files just dropped on the window.
pub fn dropped(ctx: &egui::Context) -> Vec<String> {
    ctx.input(|i| {
        i.raw
            .dropped_files
            .iter()
            .map(|f| f.path())
            .filter(|p| p.is_absolute())
            .map(|p| p.display().to_string())
            .collect()
    })
}

/// The pointer in window coordinates, also while the system drags files over the window.
#[cfg(windows)]
pub fn pointer(ctx: &egui::Context) -> Option<Pos2> {
    use windows::Win32::{Foundation::POINT, UI::WindowsAndMessaging::GetCursorPos};
    let mut point = POINT::default();
    // SAFETY: plain query into a local.
    unsafe { GetCursorPos(&mut point) }.ok()?;
    let (inner, ppp) = ctx.input(|i| (i.viewport().inner_rect, i.pixels_per_point()));
    Some(egui::pos2(point.x as f32 / ppp, point.y as f32 / ppp) - inner?.min.to_vec2())
}

#[cfg(not(windows))]
pub fn pointer(ctx: &egui::Context) -> Option<Pos2> {
    ctx.input(|i| i.pointer.latest_pos())
}

/// Highlights `rect` as the place a drop lands: a tinted fill, a dashed outline that runs
/// around it, and a bobbing arrow over `label`. `t` fades it in and out (0 to 1).
pub fn target(painter: &Painter, rect: Rect, label: &str, now: f64, t: f32) {
    if t <= 0.0 {
        return;
    }
    let rect = rect.shrink(2.0);
    painter.rect_filled(rect, CARD_RADIUS, ACCENT.gamma_multiply(0.10 * t));
    let outline = file_icons::rounded_outline(rect, CARD_RADIUS.nw as f32);
    let offset = (now as f32 * 24.0) % 14.0;
    painter.extend(Shape::dashed_line_with_offset(
        &outline,
        Stroke::new(1.6, ACCENT_TEXT.gamma_multiply(t)),
        &[8.0],
        &[6.0],
        offset,
    ));
    let bob = (now as f32 * 4.0).sin() * 3.0 * t;
    let center = rect.center() - vec2(0.0, 14.0) + vec2(0.0, bob - (1.0 - t) * 8.0);
    file_icons::arrow_badge(painter, center, 20.0, true, ACCENT_TEXT.gamma_multiply(t));
    painter.text(
        center + vec2(0.0, 34.0),
        Align2::CENTER_CENTER,
        label,
        font(14.0, semibold()),
        TEXT.gamma_multiply(t),
    );
}

/// A list row that takes the drop: covered, with a dashed outline, an arrow and `label`.
pub fn row_target(painter: &Painter, rect: Rect, label: &str, now: f64, t: f32) {
    if t <= 0.0 {
        return;
    }
    let rect = rect.shrink(3.0);
    painter.rect_filled(rect, RADIUS, CARD.gamma_multiply(0.94 * t));
    painter.rect_filled(rect, RADIUS, ACCENT.gamma_multiply(0.12 * t));
    let outline = file_icons::rounded_outline(rect, RADIUS.nw as f32);
    let offset = (now as f32 * 24.0) % 12.0;
    painter.extend(Shape::dashed_line_with_offset(
        &outline,
        Stroke::new(1.4, ACCENT_TEXT.gamma_multiply(t)),
        &[7.0],
        &[5.0],
        offset,
    ));
    let bob = (now as f32 * 4.0).sin() * 2.0 * t;
    let badge = rect.left_center() + vec2(32.0, bob);
    file_icons::arrow_badge(painter, badge, 14.0, true, ACCENT_TEXT.gamma_multiply(t));
    painter.text(badge + vec2(26.0, -bob), Align2::LEFT_CENTER, label, font(14.0, semibold()), TEXT.gamma_multiply(t));
}
