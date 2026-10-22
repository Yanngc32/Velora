//! Short, time-based transitions. Each takes the moment its subject appeared and the current
//! time (`ui.input(|i| i.time)`), so nothing animates once it has settled.

use std::f32::consts::{PI, TAU};

use eframe::egui::{self, pos2, vec2, Pos2, RichText, Stroke, Ui};

use super::theme::*;

/// Progress of a transition that started at `since` and lasts `duration` seconds, eased out.
pub fn progress(now: f64, since: f64, duration: f32) -> f32 {
    egui::emath::easing::cubic_out((((now - since) as f32) / duration).clamp(0.0, 1.0))
}

/// A one-off rise and fall over `duration` seconds after `since`: 0 → 1 → 0.
pub fn pulse(now: f64, since: f64, duration: f32) -> f32 {
    let t = (((now - since) as f32) / duration).clamp(0.0, 1.0);
    (t * PI).sin()
}

/// How long the success notice stays up, in seconds.
pub const SUCCESS_SECONDS: f64 = 6.0;

/// "Paired" notice: its ring draws itself, then the check mark is stroked in.
pub fn success_notice(ui: &mut Ui, text: &str, age: f64) {
    let age = age as f32;
    let fade_out = ((SUCCESS_SECONDS as f32 - age) / 0.4).clamp(0.0, 1.0);
    ui.scope(|ui| {
        ui.multiply_opacity(fade_out * progress(age as f64, 0.0, 0.2));
        let inner = egui::Frame::new()
            .fill(CARD)
            .stroke(Stroke::new(1.0, LIVE.gamma_multiply(0.45)))
            .corner_radius(RADIUS)
            .inner_margin(egui::Margin { left: 44, right: 14, top: 12, bottom: 12 })
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new(text).font(font(14.0, medium())));
            });
        let center = pos2(inner.response.rect.left() + 22.0, inner.response.rect.center().y);
        let ring = progress(age as f64, 0.1, 0.45);
        let check = progress(age as f64, 0.45, 0.3);
        let painter = ui.painter();
        if check > 0.0 {
            painter.circle_filled(center, 10.0, LIVE.gamma_multiply(0.16 * check));
        }
        painter.add(egui::Shape::line(arc(center, 10.0, ring), Stroke::new(1.6, LIVE)));
        let mark = [center + vec2(-4.5, 0.2), center + vec2(-1.4, 3.3), center + vec2(4.6, -3.2)];
        painter.add(egui::Shape::line(partial(&mark, check), Stroke::new(1.8, LIVE)));
    });
}

/// Points along a circle from 12 o'clock, clockwise, covering `fraction` of it.
fn arc(center: Pos2, radius: f32, fraction: f32) -> Vec<Pos2> {
    let steps = (48.0 * fraction).ceil() as usize;
    (0..=steps)
        .map(|i| {
            let a = -TAU / 4.0 + TAU * fraction * i as f32 / steps.max(1) as f32;
            center + vec2(a.cos(), a.sin()) * radius
        })
        .collect()
}

/// The first `fraction` of a polyline, by length.
fn partial(points: &[Pos2], fraction: f32) -> Vec<Pos2> {
    let total: f32 = points.windows(2).map(|w| w[0].distance(w[1])).sum();
    let mut left = total * fraction;
    let mut out = vec![points[0]];
    for w in points.windows(2) {
        let len = w[0].distance(w[1]);
        if left >= len {
            out.push(w[1]);
            left -= len;
        } else {
            if left > 0.0 {
                out.push(w[0] + (w[1] - w[0]) * (left / len));
            }
            break;
        }
    }
    out
}

/// A finished transfer: the ring draws itself, then the check mark, `age` seconds after it
/// ended.
pub fn done_mark(painter: &egui::Painter, center: Pos2, radius: f32, age: f64) {
    let ring = progress(age, 0.0, 0.35);
    let check = progress(age, 0.25, 0.25);
    painter.circle_filled(center, radius, LIVE.gamma_multiply(0.14 * ring));
    painter.add(egui::Shape::line(arc(center, radius, ring), Stroke::new(1.6, LIVE)));
    let s = radius / 10.0;
    let mark = [center + vec2(-4.5, 0.2) * s, center + vec2(-1.4, 3.3) * s, center + vec2(4.6, -3.2) * s];
    if check > 0.0 {
        painter.add(egui::Shape::line(partial(&mark, check), Stroke::new(1.8, LIVE)));
    }
}

/// A failed transfer: a red ring with a cross that pops in, `age` seconds after it ended.
pub fn failed_mark(painter: &egui::Painter, center: Pos2, radius: f32, age: f64) {
    let t = progress(age, 0.0, 0.25);
    // Overshoots a little, then settles: a small shake of the head.
    let r = radius * (1.0 + 0.15 * (1.0 - t) * (age as f32 * 30.0).sin());
    painter.circle_filled(center, r, ERROR.gamma_multiply(0.14 * t));
    painter.circle_stroke(center, r, Stroke::new(1.6, ERROR.gamma_multiply(t)));
    let d = r * 0.38;
    let stroke = Stroke::new(1.8, ERROR.gamma_multiply(t));
    painter.line_segment([center + vec2(-d, -d), center + vec2(d, d)], stroke);
    painter.line_segment([center + vec2(-d, d), center + vec2(d, -d)], stroke);
}

/// A count badge that swells and flashes teal while `pulse` rises and falls.
pub fn badge(painter: &egui::Painter, right_center: Pos2, count: usize, pulse: f32) {
    let text = count.to_string();
    let color = WEAK.lerp_to_gamma(BG, pulse);
    let scale = 1.0 + 0.25 * pulse;
    // Only the pill swells: animating the font size would rasterize a glyph set per frame.
    let galley = painter.layout_no_wrap(text, font(11.5, semibold()), color);
    let size = vec2((galley.size().x + 12.0).max(20.0), 18.0) * scale;
    let rect = egui::Rect::from_min_size(right_center - vec2(size.x, size.y / 2.0), size);
    painter.rect_filled(rect, size.y / 2.0, BORDER.lerp_to_gamma(LIVE, pulse));
    painter.galley(rect.center() - galley.size() / 2.0, galley, color);
}
