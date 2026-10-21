//! Velora look for egui: flat dark surfaces, 1 px borders, one violet accent, set in Inter with
//! JetBrains Mono for codes and addresses.

use std::sync::Arc;

use eframe::egui::{
    self, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Stroke, TextStyle, Visuals,
};

pub const BG: Color32 = Color32::from_rgb(0x0F, 0x10, 0x14);
pub const SIDEBAR: Color32 = Color32::from_rgb(0x14, 0x15, 0x1B);
pub const CARD: Color32 = Color32::from_rgb(0x1A, 0x1B, 0x22);
pub const HOVER: Color32 = Color32::from_rgb(0x21, 0x22, 0x2B);
pub const BORDER: Color32 = Color32::from_rgb(0x2B, 0x2D, 0x38);
pub const BORDER_STRONG: Color32 = Color32::from_rgb(0x3A, 0x3C, 0x4A);
pub const TEXT: Color32 = Color32::from_rgb(0xE6, 0xE7, 0xEE);
pub const WEAK: Color32 = Color32::from_rgb(0x98, 0x9A, 0xAB);
pub const FAINT: Color32 = Color32::from_rgb(0x6B, 0x6D, 0x7E);
/// Brand violet, for the primary action and the current selection.
pub const ACCENT: Color32 = Color32::from_rgb(0x7B, 0x4D, 0xFF);
pub const ACCENT_HOVER: Color32 = Color32::from_rgb(0x8C, 0x63, 0xFF);
pub const ACCENT_PRESSED: Color32 = Color32::from_rgb(0x69, 0x3C, 0xE8);
/// Brand lavender, for accent text on dark surfaces (the violet is too dark to read there).
pub const ACCENT_TEXT: Color32 = Color32::from_rgb(0xB3, 0x88, 0xFF);
/// Brand teal, for live status and commands.
pub const LIVE: Color32 = Color32::from_rgb(0x4E, 0xE1, 0xC3);
pub const ERROR: Color32 = Color32::from_rgb(0xF2, 0x6D, 0x7D);
pub const AVATAR: Color32 = Color32::from_rgb(0x47, 0x4B, 0x5C);

pub const RADIUS: CornerRadius = CornerRadius::same(6);
pub const CARD_RADIUS: CornerRadius = CornerRadius::same(10);

pub fn medium() -> FontFamily {
    FontFamily::Name("medium".into())
}

pub fn semibold() -> FontFamily {
    FontFamily::Name("semibold".into())
}

pub fn bold() -> FontFamily {
    FontFamily::Name("bold".into())
}

pub fn font(size: f32, family: FontFamily) -> FontId {
    FontId::new(size, family)
}

pub fn mono(size: f32) -> FontId {
    FontId::monospace(size)
}

fn fonts() -> FontDefinitions {
    let mut fonts = FontDefinitions::default();
    for (name, data) in [
        ("inter", &include_bytes!("../../assets/fonts/Inter-Regular.ttf")[..]),
        ("inter-medium", include_bytes!("../../assets/fonts/Inter-Medium.ttf")),
        ("inter-semibold", include_bytes!("../../assets/fonts/Inter-SemiBold.ttf")),
        ("inter-bold", include_bytes!("../../assets/fonts/Inter-Bold.ttf")),
        ("jetbrains-mono", include_bytes!("../../assets/fonts/JetBrainsMono-Regular.ttf")),
    ] {
        fonts.font_data.insert(name.into(), Arc::new(FontData::from_static(data)));
    }
    // egui's bundled fonts stay as fallbacks for scripts and symbols outside the subset.
    let fallbacks = fonts.families[&FontFamily::Proportional].clone();
    fonts.families.get_mut(&FontFamily::Proportional).unwrap().insert(0, "inter".into());
    fonts.families.get_mut(&FontFamily::Monospace).unwrap().insert(0, "jetbrains-mono".into());
    for (family, face) in [(medium(), "inter-medium"), (semibold(), "inter-semibold"), (bold(), "inter-bold")] {
        let mut list = vec![face.to_string()];
        list.extend(fallbacks.iter().cloned());
        fonts.families.insert(family, list);
    }
    fonts
}

pub fn apply(ctx: &egui::Context) {
    ctx.set_fonts(fonts());

    let mut v = Visuals::dark();
    v.panel_fill = BG;
    v.window_fill = CARD;
    v.extreme_bg_color = BG;
    v.faint_bg_color = CARD;
    v.code_bg_color = BG;
    v.override_text_color = Some(TEXT);
    v.hyperlink_color = ACCENT_TEXT;
    v.selection.bg_fill = ACCENT.gamma_multiply(0.45);
    v.selection.stroke = Stroke::new(1.0, ACCENT_TEXT);
    v.text_cursor.stroke = Stroke::new(1.5, TEXT);
    for w in [&mut v.widgets.noninteractive, &mut v.widgets.inactive, &mut v.widgets.hovered, &mut v.widgets.active] {
        w.corner_radius = RADIUS;
        w.expansion = 0.0;
    }
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, BORDER);
    v.widgets.inactive.bg_fill = BG;
    v.widgets.inactive.weak_bg_fill = BG;
    v.widgets.inactive.bg_stroke = Stroke::new(1.0, BORDER);
    v.widgets.hovered.bg_fill = BG;
    v.widgets.hovered.weak_bg_fill = HOVER;
    v.widgets.hovered.bg_stroke = Stroke::new(1.0, BORDER_STRONG);
    v.widgets.active.bg_fill = BG;
    v.widgets.active.weak_bg_fill = HOVER;
    v.widgets.active.bg_stroke = Stroke::new(1.0, ACCENT);
    ctx.set_visuals(v);

    ctx.global_style_mut(|style| {
        style.spacing.item_spacing = egui::vec2(8.0, 8.0);
        style.spacing.button_padding = egui::vec2(14.0, 8.0);
        style.spacing.interact_size.y = 36.0;
        style.text_styles.insert(TextStyle::Heading, font(28.0, bold()));
        style.text_styles.insert(TextStyle::Body, FontId::proportional(14.0));
        style.text_styles.insert(TextStyle::Button, font(14.0, semibold()));
        style.text_styles.insert(TextStyle::Small, FontId::proportional(12.0));
        style.text_styles.insert(TextStyle::Monospace, mono(13.0));
    });
}
