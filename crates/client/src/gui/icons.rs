//! Lucide icons (ISC license, see assets/icons/LICENSE-lucide.txt), rasterized white by
//! packaging/make_ui_assets.py and tinted when drawn.

use eframe::egui::{self, pos2, Color32, Painter, Pos2, Rect, TextureHandle, Vec2};

#[derive(Clone, Copy)]
pub enum Icon {
    Connect,
    Monitor,
    Settings,
    Info,
    Plus,
    Smartphone,
}

pub struct Icons([TextureHandle; 6]);

impl Icons {
    pub fn load(ctx: &egui::Context) -> anyhow::Result<Self> {
        let files: [(&str, &[u8]); 6] = [
            ("log-in", include_bytes!("../../assets/icons/log-in.png")),
            ("monitor", include_bytes!("../../assets/icons/monitor.png")),
            ("settings", include_bytes!("../../assets/icons/settings.png")),
            ("info", include_bytes!("../../assets/icons/info.png")),
            ("plus", include_bytes!("../../assets/icons/plus.png")),
            ("smartphone", include_bytes!("../../assets/icons/smartphone.png")),
        ];
        let mut textures = Vec::with_capacity(files.len());
        for (name, png) in files {
            let image = image::load_from_memory(png)?.into_rgba8();
            let size = [image.width() as usize, image.height() as usize];
            let color = egui::ColorImage::from_rgba_unmultiplied(size, image.as_raw());
            textures.push(ctx.load_texture(name, color, egui::TextureOptions::LINEAR));
        }
        Ok(Self(textures.try_into().map_err(|_| anyhow::anyhow!("icon count"))?))
    }

    pub fn paint(&self, painter: &Painter, icon: Icon, center: Pos2, size: f32, color: Color32) {
        let texture = &self.0[icon as usize];
        let rect = Rect::from_center_size(center, Vec2::splat(size));
        painter.image(texture.id(), rect, Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0)), color);
    }
}
