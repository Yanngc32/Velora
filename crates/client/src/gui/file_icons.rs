//! File glyphs drawn in code: a page with a folded corner in its type's color and a mark for
//! the type (lines, grid, play, note…), a folder, or a drive.

use eframe::egui::{pos2, vec2, Color32, Painter, Pos2, Rect, Shape, Stroke, StrokeKind};
use velora_client_core::files::EntryKind;

use super::theme::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Folder,
    Drive,
    Document,
    Sheet,
    Slides,
    Pdf,
    Image,
    Video,
    Audio,
    Archive,
    Code,
    App,
    Other,
}

impl FileType {
    pub fn of(kind: EntryKind, name: &str) -> Self {
        match kind {
            EntryKind::Dir => return Self::Folder,
            // Drives are named like `C:` or `/`; other places are folders (Downloads, Home).
            EntryKind::Place if name.ends_with(':') || name.starts_with('/') => return Self::Drive,
            EntryKind::Place => return Self::Folder,
            EntryKind::File => {}
        }
        let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default();
        match ext.as_str() {
            "doc" | "docx" | "odt" | "rtf" | "txt" | "md" | "pages" => Self::Document,
            "xls" | "xlsx" | "xlsm" | "ods" | "csv" | "tsv" | "numbers" => Self::Sheet,
            "ppt" | "pptx" | "odp" | "key" => Self::Slides,
            "pdf" => Self::Pdf,
            "png" | "jpg" | "jpeg" | "gif" | "webp" | "bmp" | "svg" | "heic" | "tif" | "tiff" | "ico" | "raw" => {
                Self::Image
            }
            "mp4" | "mkv" | "mov" | "avi" | "webm" | "wmv" | "m4v" => Self::Video,
            "mp3" | "wav" | "flac" | "ogg" | "m4a" | "aac" | "opus" | "wma" => Self::Audio,
            "zip" | "rar" | "7z" | "tar" | "gz" | "xz" | "bz2" | "zst" | "iso" => Self::Archive,
            "rs" | "py" | "js" | "ts" | "tsx" | "jsx" | "json" | "toml" | "yaml" | "yml" | "html" | "css" | "c"
            | "cpp" | "h" | "cs" | "java" | "go" | "kt" | "swift" | "sh" | "ps1" | "sql" | "xml" => Self::Code,
            "exe" | "msi" | "apk" | "appx" | "msix" | "dmg" | "deb" | "rpm" | "bat" | "cmd" | "lnk" => Self::App,
            _ => Self::Other,
        }
    }

    pub fn color(self) -> Color32 {
        match self {
            Self::Folder => ACCENT_TEXT,
            Self::Drive => WEAK,
            Self::Document => Color32::from_rgb(0x6A, 0x9C, 0xFF),
            Self::Sheet => Color32::from_rgb(0x4C, 0xD0, 0x8A),
            Self::Slides => Color32::from_rgb(0xFF, 0x9F, 0x5A),
            Self::Pdf => ERROR,
            Self::Image => Color32::from_rgb(0xE0, 0x7B, 0xF0),
            Self::Video => Color32::from_rgb(0xFF, 0x7A, 0x59),
            Self::Audio => LIVE,
            Self::Archive => Color32::from_rgb(0xF5, 0xC4, 0x51),
            Self::Code => Color32::from_rgb(0x9F, 0xB4, 0xFF),
            Self::App => Color32::from_rgb(0xB8, 0xBC, 0xCC),
            Self::Other => WEAK,
        }
    }
}

/// Draws the glyph for an entry, fitted in `rect` (about 20 × 20 pt looks right in a row).
pub fn paint(painter: &Painter, rect: Rect, kind: EntryKind, name: &str) {
    paint_type(painter, rect, FileType::of(kind, name));
}

pub fn paint_type(painter: &Painter, rect: Rect, ty: FileType) {
    let color = ty.color();
    match ty {
        FileType::Folder => folder(painter, rect, color),
        FileType::Drive => drive(painter, rect, color),
        _ => page(painter, rect, ty, color),
    }
}

fn folder(painter: &Painter, rect: Rect, color: Color32) {
    let r = Rect::from_center_size(rect.center(), vec2(rect.width(), rect.height() * 0.78));
    let tab = Rect::from_min_size(r.min, vec2(r.width() * 0.42, r.height() * 0.3));
    painter.rect_filled(tab, 2.0, color.gamma_multiply(0.75));
    let body = Rect::from_min_max(pos2(r.left(), r.top() + r.height() * 0.18), r.max);
    painter.rect_filled(body, 2.5, color.gamma_multiply(0.28));
    painter.rect_stroke(body, 2.5, Stroke::new(1.3, color), StrokeKind::Inside);
    // The front flap, a shade lighter, gives the folder depth.
    let flap = Rect::from_min_max(pos2(body.left(), body.top() + body.height() * 0.3), body.max);
    painter.rect_filled(flap.shrink(1.3), 1.5, color.gamma_multiply(0.18));
}

fn drive(painter: &Painter, rect: Rect, color: Color32) {
    let body = Rect::from_center_size(rect.center(), vec2(rect.width(), rect.height() * 0.62));
    painter.rect_filled(body, 3.0, color.gamma_multiply(0.18));
    painter.rect_stroke(body, 3.0, Stroke::new(1.3, color), StrokeKind::Inside);
    let y = body.center().y;
    painter.hline(
        (body.left() + 3.5)..=(body.left() + body.width() * 0.5),
        y,
        Stroke::new(1.3, color.gamma_multiply(0.6)),
    );
    painter.circle_filled(pos2(body.right() - 4.5, y), 1.6, LIVE);
}

fn page(painter: &Painter, rect: Rect, ty: FileType, color: Color32) {
    let w = rect.height() * 0.8;
    let r = Rect::from_center_size(rect.center(), vec2(w, rect.height()));
    let fold = w * 0.34;
    let outline = vec![
        r.left_top(),
        pos2(r.right() - fold, r.top()),
        pos2(r.right(), r.top() + fold),
        r.right_bottom(),
        r.left_bottom(),
    ];
    painter.add(Shape::convex_polygon(outline.clone(), color.gamma_multiply(0.16), Stroke::NONE));
    painter.add(Shape::closed_line(outline, Stroke::new(1.3, color)));
    painter.add(Shape::convex_polygon(
        vec![pos2(r.right() - fold, r.top()), pos2(r.right(), r.top() + fold), pos2(r.right() - fold, r.top() + fold)],
        color.gamma_multiply(0.55),
        Stroke::NONE,
    ));
    // The type's mark, in the lower part of the page.
    let mark = Rect::from_min_max(pos2(r.left() + 3.0, r.top() + fold + 1.5), pos2(r.right() - 3.0, r.bottom() - 3.0));
    let thin = Stroke::new(1.2, color);
    match ty {
        FileType::Sheet => {
            painter.rect_stroke(mark, 1.0, thin, StrokeKind::Inside);
            painter.vline(mark.center().x, mark.y_range(), thin);
            painter.hline(mark.x_range(), mark.center().y, thin);
        }
        FileType::Slides => {
            let screen = Rect::from_min_max(mark.min, pos2(mark.right(), mark.bottom() - 2.5));
            painter.rect_filled(screen, 1.0, color.gamma_multiply(0.6));
            painter.vline(mark.center().x, (screen.bottom())..=mark.bottom(), thin);
        }
        FileType::Pdf => {
            let band = Rect::from_min_max(
                pos2(mark.left() - 1.0, mark.bottom() - 4.0),
                pos2(mark.right() + 1.0, mark.bottom()),
            );
            painter.rect_filled(band, 1.0, color);
            lines(painter, Rect::from_min_max(mark.min, pos2(mark.right(), band.top() - 1.0)), thin, 2);
        }
        FileType::Image => {
            painter.circle_filled(pos2(mark.right() - 2.0, mark.top() + 2.0), 1.6, color);
            painter.add(Shape::convex_polygon(
                vec![mark.left_bottom(), pos2(mark.left() + mark.width() * 0.4, mark.top() + 2.5), mark.right_bottom()],
                color.gamma_multiply(0.75),
                Stroke::NONE,
            ));
        }
        FileType::Video => {
            let c = mark.center();
            let h = mark.height().min(mark.width()) * 0.5;
            painter.add(Shape::convex_polygon(
                vec![c + vec2(-h * 0.7, -h), c + vec2(h, 0.0), c + vec2(-h * 0.7, h)],
                color,
                Stroke::NONE,
            ));
        }
        FileType::Audio => {
            let head = pos2(mark.left() + 2.5, mark.bottom() - 2.0);
            painter.circle_filled(head, 2.0, color);
            let stem = head.x + 1.8;
            painter.vline(stem, (mark.top())..=head.y, thin);
            painter.line_segment([pos2(stem, mark.top()), pos2(mark.right(), mark.top() + 2.0)], thin);
        }
        FileType::Archive => {
            let x = mark.center().x;
            let mut y = mark.top() - fold * 0.6;
            let mut left = true;
            while y < mark.bottom() - 2.0 {
                let dx = if left { -1.6 } else { 1.6 };
                painter.rect_filled(Rect::from_center_size(pos2(x + dx, y + 1.0), vec2(2.6, 1.6)), 0.5, color);
                y += 2.4;
                left = !left;
            }
        }
        FileType::Code => {
            let c = mark.center();
            let h = mark.height().min(5.0) * 0.6;
            painter.add(Shape::line(vec![c + vec2(-1.5, -h), c + vec2(-4.0, 0.0), c + vec2(-1.5, h)], thin));
            painter.add(Shape::line(vec![c + vec2(1.5, -h), c + vec2(4.0, 0.0), c + vec2(1.5, h)], thin));
        }
        FileType::App => {
            let s = mark.width().min(mark.height()) * 0.42;
            let c = mark.center();
            for (dx, dy) in [(-1.0, -1.0), (1.0, -1.0), (-1.0, 1.0), (1.0, 1.0)] {
                let center = c + vec2(dx * (s / 2.0 + 0.6), dy * (s / 2.0 + 0.6));
                painter.rect_filled(Rect::from_center_size(center, vec2(s, s)), 0.8, color.gamma_multiply(0.8));
            }
        }
        _ => lines(painter, mark, thin, 3),
    }
}

fn lines(painter: &Painter, area: Rect, stroke: Stroke, count: usize) {
    let step = area.height() / count as f32;
    for i in 0..count {
        let y = area.top() + step * (i as f32 + 0.5);
        // The last line is shorter, like the end of a paragraph.
        let right = if i + 1 == count { area.left() + area.width() * 0.6 } else { area.right() };
        painter.hline(area.left()..=right, y, stroke);
    }
}

/// A round badge with an arrow: up for sending, down for receiving. Used on drop targets.
pub fn arrow_badge(painter: &Painter, center: Pos2, radius: f32, up: bool, color: Color32) {
    painter.circle_filled(center, radius, color.gamma_multiply(0.16));
    painter.circle_stroke(center, radius, Stroke::new(1.5, color.gamma_multiply(0.7)));
    let d = if up { -1.0 } else { 1.0 };
    let len = radius * 0.5;
    let stroke = Stroke::new(2.0, color);
    painter.line_segment([center - vec2(0.0, len * d), center + vec2(0.0, len * d)], stroke);
    let tip = center + vec2(0.0, len * d);
    painter.add(Shape::line(
        vec![tip + vec2(-len * 0.6, -len * 0.6 * d), tip, tip + vec2(len * 0.6, -len * 0.6 * d)],
        stroke,
    ));
}

/// Points around a rounded rectangle, clockwise from the top left, closed: an outline that
/// a dashed stroke can follow.
pub fn rounded_outline(rect: Rect, radius: f32) -> Vec<Pos2> {
    use std::f32::consts::{FRAC_PI_2, PI};
    let r = radius.min(rect.width() / 2.0).min(rect.height() / 2.0);
    let corners = [
        (pos2(rect.right() - r, rect.top() + r), -FRAC_PI_2),
        (pos2(rect.right() - r, rect.bottom() - r), 0.0),
        (pos2(rect.left() + r, rect.bottom() - r), FRAC_PI_2),
        (pos2(rect.left() + r, rect.top() + r), PI),
    ];
    let mut points = vec![pos2(rect.left() + r, rect.top())];
    for (center, start) in corners {
        for i in 0..=8 {
            let a = start + FRAC_PI_2 * i as f32 / 8.0;
            points.push(center + vec2(a.cos(), a.sin()) * r);
        }
    }
    points.push(points[0]);
    points
}

#[cfg(test)]
mod tests {
    use super::{EntryKind, FileType};

    #[test]
    fn types_follow_the_extension() {
        let file = |name| FileType::of(EntryKind::File, name);
        assert_eq!(file("4844-Precificacao-Vitorinos (1).xlsx"), FileType::Sheet);
        assert_eq!(file("REPORT.PDF"), FileType::Pdf);
        assert_eq!(file("photo.heic"), FileType::Image);
        assert_eq!(file("velora-0.3.1-setup.exe"), FileType::App);
        assert_eq!(file("archive.tar.gz"), FileType::Archive);
        assert_eq!(file("README"), FileType::Other);
        assert_eq!(FileType::of(EntryKind::Dir, "x.pdf"), FileType::Folder);
        assert_eq!(FileType::of(EntryKind::Place, "C:"), FileType::Drive);
        assert_eq!(FileType::of(EntryKind::Place, "Downloads"), FileType::Folder);
    }
}
