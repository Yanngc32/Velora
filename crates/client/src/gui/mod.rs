//! Desktop launcher: pair and pick computers, settings, updates.
//!
//! Each remote session runs in its own process (`velora connect <host>`, the window in
//! `main.rs`). That window needs raw physical keys, which egui does not expose, and a separate
//! process keeps a misbehaving session from taking the launcher down.

mod icons;
mod strings;
mod theme;
mod widgets;

use std::{
    io::Read,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{anyhow, Result};
use eframe::egui::{self, Align, Layout, RichText, Sense, TextureHandle, Vec2};
use icons::{Icon, Icons};
use strings::{fill, Strings};
use theme::*;
use velora_client_core::hosts;
use velora_protocol::{
    identity::{KnownHost, StateDir},
    pairing::{parse_pairing_uri, PairingCode},
};
use widgets::*;

use crate::settings::Settings;

const ICON_PNG: &[u8] = include_bytes!("../../assets/velora-icon.png");
const REPO_URL: &str = "https://github.com/yanngc32/screen_mirroring";

pub fn run(state: StateDir, config_dir: Option<PathBuf>, no_update: bool) -> Result<()> {
    let icon = image::load_from_memory(ICON_PNG)?.into_rgba8();
    let (w, h) = icon.dimensions();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Velora")
            .with_app_id("velora")
            .with_inner_size([980.0, 620.0])
            .with_min_inner_size([760.0, 500.0])
            .with_icon(egui::IconData { rgba: icon.clone().into_raw(), width: w, height: h }),
        ..Default::default()
    };
    eframe::run_native(
        "Velora",
        options,
        Box::new(move |cc| {
            theme::apply(&cc.egui_ctx);
            let logo = cc.egui_ctx.load_texture(
                "logo",
                egui::ColorImage::from_rgba_unmultiplied([w as usize, h as usize], icon.as_raw()),
                egui::TextureOptions::LINEAR,
            );
            let icons = Icons::load(&cc.egui_ctx)?;
            Ok(Box::new(Launcher::new(state, config_dir, no_update, logo, icons, &cc.egui_ctx)))
        }),
    )
    .map_err(|e| anyhow!("{e}"))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Connect,
    Devices,
    Settings,
    About,
}

#[derive(Clone)]
enum UpdateState {
    Idle,
    Checking,
    UpToDate,
    Updated(String),
    Failed(String),
}

struct Session {
    label: String,
    child: Child,
    stderr: Arc<Mutex<String>>,
}

struct Launcher {
    s: &'static Strings,
    state: StateDir,
    config_dir: Option<PathBuf>,
    logo: TextureHandle,
    icons: Icons,
    page: Page,
    address: String,
    code: String,
    error: Option<String>,
    hosts: Vec<KnownHost>,
    hosts_loaded: Instant,
    settings: Settings,
    draft_name: String,
    saved: bool,
    sessions: Vec<Session>,
    update: Arc<Mutex<UpdateState>>,
}

impl Launcher {
    fn new(
        state: StateDir,
        config_dir: Option<PathBuf>,
        no_update: bool,
        logo: TextureHandle,
        icons: Icons,
        ctx: &egui::Context,
    ) -> Self {
        let settings = Settings::load(&state);
        let mut launcher = Self {
            s: strings::current(),
            hosts: hosts::list(&state).unwrap_or_default(),
            hosts_loaded: Instant::now(),
            state,
            config_dir,
            logo,
            icons,
            page: Page::Connect,
            address: String::new(),
            code: String::new(),
            error: None,
            draft_name: settings.device_name.clone(),
            settings,
            saved: false,
            sessions: Vec::new(),
            update: Arc::new(Mutex::new(UpdateState::Idle)),
        };
        if !launcher.hosts.is_empty() {
            launcher.page = Page::Devices;
        }
        if launcher.settings.auto_update && velora_update::auto_update_enabled(no_update) {
            launcher.check_updates(ctx);
        }
        launcher
    }

    fn refresh_hosts(&mut self) {
        self.hosts = hosts::list(&self.state).unwrap_or_default();
        self.hosts_loaded = Instant::now();
    }

    fn check_updates(&self, ctx: &egui::Context) {
        *self.update.lock().unwrap() = UpdateState::Checking;
        let (update, ctx) = (self.update.clone(), ctx.clone());
        std::thread::spawn(move || {
            let result = match velora_update::update_now() {
                Ok(Some(v)) => UpdateState::Updated(v.to_string()),
                Ok(None) => UpdateState::UpToDate,
                Err(e) => UpdateState::Failed(format!("{e:#}")),
            };
            *update.lock().unwrap() = result;
            ctx.request_repaint();
        });
    }

    /// Starts a session window: `velora [--config-dir ..] --no-update <args>`.
    fn spawn(&mut self, label: String, args: &[&str]) {
        let exe = match std::env::current_exe() {
            Ok(e) => e,
            Err(e) => return self.error = Some(e.to_string()),
        };
        let mut cmd = Command::new(exe);
        if let Some(dir) = &self.config_dir {
            cmd.arg("--config-dir").arg(dir);
        }
        // The launcher owns updates; sessions must not race it.
        cmd.arg("--no-update").args(args).env("NO_COLOR", "1").stdout(Stdio::null()).stderr(Stdio::piped());
        match cmd.spawn() {
            Ok(mut child) => {
                let stderr = Arc::new(Mutex::new(String::new()));
                if let Some(mut pipe) = child.stderr.take() {
                    let buf = stderr.clone();
                    std::thread::spawn(move || {
                        let mut chunk = [0u8; 4096];
                        while let Ok(n) = pipe.read(&mut chunk) {
                            if n == 0 {
                                break;
                            }
                            let mut b = buf.lock().unwrap();
                            b.push_str(&String::from_utf8_lossy(&chunk[..n]));
                            // Only the tail matters for error reporting.
                            if b.len() > 16 * 1024 {
                                let cut = b.len() - 8 * 1024;
                                let cut = (cut..b.len()).find(|&i| b.is_char_boundary(i)).unwrap_or(0);
                                b.drain(..cut);
                            }
                        }
                    });
                }
                self.error = None;
                self.sessions.push(Session { label, child, stderr });
            }
            Err(e) => self.error = Some(e.to_string()),
        }
    }

    fn poll_sessions(&mut self) {
        let mut changed = false;
        let s = self.s;
        let mut error = None;
        self.sessions.retain_mut(|session| match session.child.try_wait() {
            Ok(None) => true,
            Ok(Some(status)) => {
                changed = true;
                if !status.success() {
                    let log = session.stderr.lock().unwrap();
                    error = Some(fill(s.session_failed, &[&session.label, &last_error(&log)]));
                }
                false
            }
            Err(_) => false,
        });
        if let Some(e) = error {
            self.error = Some(e);
        }
        // A pairing session saves its host; also pick up `velora pair` run from a terminal.
        if changed || self.hosts_loaded.elapsed() > Duration::from_secs(3) {
            self.refresh_hosts();
        }
    }

    fn connect_page(&mut self, ui: &mut egui::Ui) {
        let s = self.s;
        page_header(ui, s.connect_label, s.connect_title, Some(s.connect_hint));
        const FORM_WIDTH: f32 = 360.0;
        const GAP: f32 = 40.0;
        if ui.available_width() >= FORM_WIDTH + GAP + 240.0 {
            ui.horizontal_top(|ui| {
                ui.allocate_ui_with_layout(egui::vec2(FORM_WIDTH, 0.0), Layout::top_down(Align::Min), |ui| {
                    self.connect_form(ui)
                });
                ui.add_space(GAP - ui.spacing().item_spacing.x);
                let width = ui.available_width();
                ui.allocate_ui_with_layout(egui::vec2(width, 0.0), Layout::top_down(Align::Min), |ui| {
                    connect_steps(ui, s)
                });
            });
        } else {
            self.connect_form(ui);
            ui.add_space(24.0);
            connect_steps(ui, s);
        }
    }

    fn connect_form(&mut self, ui: &mut egui::Ui) {
        let s = self.s;
        card(ui, |ui| {
            field_label(ui, s.code);
            let code = ui.add(field(&mut self.code, s.code_hint, true));
            // Pasting the whole pairing link fills in both fields.
            if code.changed() {
                if let Some((address, code)) = parse_pairing_uri(&self.code) {
                    self.address = address;
                    self.code = code.encode();
                }
            }
            ui.add_space(12.0);
            field_label(ui, s.address);
            ui.add(field(&mut self.address, s.address_hint, true));
            ui.add_space(16.0);

            let ready = !self.address.trim().is_empty() && !self.code.trim().is_empty();
            if primary_button(ui, s.connect, ui.available_width(), ready).clicked() {
                match PairingCode::parse(&self.code) {
                    Ok(_) => {
                        let (address, code, name) = (
                            self.address.trim().to_string(),
                            self.code.trim().to_string(),
                            self.settings.device_name.clone(),
                        );
                        self.spawn(address.clone(), &["pair", &address, &code, "--name", &name]);
                        self.code.clear();
                    }
                    Err(_) => self.error = Some(s.invalid_code.into()),
                }
            }
        });
    }

    fn devices(&mut self, ui: &mut egui::Ui) {
        let s = self.s;
        if self.hosts.is_empty() {
            return self.empty_devices(ui);
        }
        let count = match self.hosts.len() {
            1 => s.devices_count_one.to_string(),
            n => fill(s.devices_count, &[&n.to_string()]),
        };
        let top = ui.cursor().min;
        page_header(ui, s.devices_label, s.devices_title, Some(&count));
        // "Pair computer" sits at the right of the header, level with the title.
        // The list below leaves 14 pt for its scroll bar; line up with the list's edge.
        let right = ui.max_rect().right() - 14.0;
        let area = egui::Rect::from_min_max(
            egui::pos2(right - 320.0, top.y + 28.0),
            egui::pos2(right, top.y + 28.0 + CONTROL_HEIGHT),
        );
        // A child UI, so the button does not move the page's cursor.
        let mut corner = ui.new_child(egui::UiBuilder::new().max_rect(area).layout(Layout::right_to_left(Align::Min)));
        if secondary_button_icon(&mut corner, s.pair_computer, Some((&self.icons, Icon::Plus))).clicked() {
            self.page = Page::Connect;
        }

        let mut action = None;
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.set_max_width(ui.available_width() - 14.0);
            egui::Frame::new().fill(CARD).stroke(egui::Stroke::new(1.0, BORDER)).corner_radius(CARD_RADIUS).show(
                ui,
                |ui| {
                    ui.set_width(ui.available_width());
                    ui.spacing_mut().item_spacing.y = 0.0;
                    for (i, host) in self.hosts.iter().enumerate() {
                        if i > 0 {
                            let y = ui.cursor().min.y;
                            ui.painter().hline(ui.max_rect().x_range(), y, egui::Stroke::new(1.0, BORDER));
                        }
                        let running = self.sessions.iter().any(|x| x.label == host.name);
                        if let Some(a) = device_row(ui, s, &self.icons, host, running) {
                            action = Some((a, host.name.clone()));
                        }
                    }
                },
            );
            ui.add_space(24.0);
        });
        match action {
            Some((DeviceAction::Connect, name)) => self.spawn(name.clone(), &["connect", &name]),
            Some((DeviceAction::Forget, name)) => {
                if let Err(e) = hosts::forget(&self.state, &name) {
                    self.error = Some(format!("{e:#}"));
                }
                self.refresh_hosts();
            }
            None => {}
        }
    }

    fn empty_devices(&mut self, ui: &mut egui::Ui) {
        let s = self.s;
        page_header(ui, s.devices_label, s.devices_title, None);
        card(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(24.0);
                self.icons.paint(
                    ui.painter(),
                    Icon::Monitor,
                    ui.cursor().min + egui::vec2(ui.available_width() / 2.0, 16.0),
                    32.0,
                    FAINT,
                );
                ui.add_space(44.0);
                ui.label(RichText::new(s.no_devices_title).font(font(16.0, semibold())));
                ui.label(RichText::new(s.no_devices).color(WEAK));
                ui.add_space(12.0);
                if primary_button(ui, s.pair_computer, 200.0, true).clicked() {
                    self.page = Page::Connect;
                }
                ui.add_space(24.0);
            });
        });
    }

    fn settings_page(&mut self, ui: &mut egui::Ui) {
        let s = self.s;
        page_header(ui, s.settings_label, s.settings_title, None);
        card(ui, |ui| {
            card_title(ui, s.identity_title);
            ui.add_space(4.0);
            field_label(ui, s.device_name);
            if ui.add(field(&mut self.draft_name, s.device_name_hint, false)).changed() {
                self.saved = false;
            }
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                let name = self.draft_name.trim();
                let dirty = !name.is_empty() && name != self.settings.device_name;
                if primary_button(ui, s.save, 110.0, dirty).clicked() {
                    let mut next = self.settings.clone();
                    next.device_name = name.to_string();
                    self.store(next);
                    self.draft_name = self.settings.device_name.clone();
                }
                if self.saved {
                    status(ui, s.saved, LIVE);
                }
            });
        });
        ui.add_space(16.0);
        card(ui, |ui| {
            let release = velora_update::is_release_build();
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 4.0;
                    card_title(ui, s.auto_update);
                    let note = if release { s.auto_update_text } else { s.auto_update_source_build };
                    ui.label(RichText::new(note).color(WEAK));
                });
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let mut on = self.settings.auto_update && release;
                    if toggle(ui, &mut on, release).changed() {
                        let mut next = self.settings.clone();
                        next.auto_update = on;
                        self.store(next);
                    }
                });
            });
        });
        ui.add_space(16.0);
        card(ui, |ui| {
            card_title(ui, s.data_folder);
            ui.add_space(2.0);
            ui.add(
                egui::Label::new(RichText::new(self.state.dir().display().to_string()).font(mono(12.5)).color(WEAK))
                    .wrap(),
            );
        });
    }

    fn store(&mut self, next: Settings) {
        match next.save(&self.state) {
            Ok(()) => {
                self.settings = next;
                self.saved = true;
            }
            Err(e) => self.error = Some(format!("{e:#}")),
        }
    }

    fn about(&mut self, ui: &mut egui::Ui) {
        let s = self.s;
        page_header(ui, s.about_label, "Velora", Some(s.about_text));
        let state = self.update.lock().unwrap().clone();
        card(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            let row = |ui: &mut egui::Ui, key: &str, value: &mut dyn FnMut(&mut egui::Ui)| {
                ui.horizontal(|ui| {
                    ui.set_min_height(CONTROL_HEIGHT + 8.0);
                    ui.allocate_ui_with_layout(egui::vec2(120.0, 20.0), Layout::left_to_right(Align::Center), |ui| {
                        ui.set_min_width(120.0);
                        ui.label(RichText::new(key).color(WEAK));
                    });
                    value(ui);
                });
            };
            row(ui, s.version, &mut |ui| {
                ui.label(RichText::new(velora_update::Version::current().to_string()).font(mono(13.0)));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let checking = matches!(state, UpdateState::Checking);
                    if secondary_button(ui, s.check_updates).clicked() && !checking {
                        self.check_updates(ui.ctx());
                    }
                    match &state {
                        UpdateState::Idle => {}
                        UpdateState::Checking => {
                            ui.label(RichText::new(s.checking).color(WEAK));
                            ui.spinner();
                        }
                        UpdateState::UpToDate => status(ui, s.up_to_date, LIVE),
                        UpdateState::Updated(v) => status(ui, &fill(s.updated_restart, &[v]), LIVE),
                        UpdateState::Failed(e) => {
                            ui.add(egui::Label::new(RichText::new(e).color(ERROR).small()).truncate());
                        }
                    }
                });
            });
            divider(ui);
            row(ui, s.license, &mut |ui| {
                ui.label("MIT");
            });
            divider(ui);
            row(ui, s.source_code, &mut |ui| {
                ui.hyperlink_to(RichText::new("github.com/yanngc32/screen_mirroring").font(mono(13.0)), REPO_URL);
            });
        });
    }

    fn sidebar(&mut self, ui: &mut egui::Ui) {
        let s = self.s;
        ui.horizontal(|ui| {
            ui.add_space(6.0);
            ui.add(egui::Image::new(&self.logo).fit_to_exact_size(Vec2::splat(26.0)).corner_radius(6));
            ui.label(RichText::new("Velora").font(font(16.0, semibold())));
        });
        ui.add_space(22.0);
        ui.spacing_mut().item_spacing.y = 2.0;
        for (page, icon, label) in [
            (Page::Connect, Icon::Connect, s.nav_connect),
            (Page::Devices, Icon::Monitor, s.nav_devices),
            (Page::Settings, Icon::Settings, s.nav_settings),
            (Page::About, Icon::Info, s.nav_about),
        ] {
            if nav_item(ui, &self.icons, icon, label, self.page == page).clicked() {
                self.page = page;
                self.error = None;
                self.saved = false;
            }
        }

        // This device, pinned to the bottom.
        const FOOTER_HEIGHT: f32 = 58.0;
        ui.add_space((ui.available_height() - FOOTER_HEIGHT).max(0.0));
        egui::Frame::new()
            .fill(CARD)
            .stroke(egui::Stroke::new(1.0, BORDER))
            .corner_radius(RADIUS)
            .inner_margin(egui::Margin::symmetric(10, 10))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    avatar(ui, &self.settings.device_name, 32.0);
                    ui.vertical(|ui| {
                        ui.spacing_mut().item_spacing.y = 1.0;
                        ui.add(
                            egui::Label::new(RichText::new(&self.settings.device_name).font(font(13.5, semibold())))
                                .truncate(),
                        );
                        match self.sessions.len() {
                            0 => {
                                let line = format!("{} · v{}", s.this_device, velora_update::Version::current());
                                ui.label(RichText::new(line).color(WEAK).size(12.0));
                            }
                            n => {
                                let text = if n == 1 { s.sessions_open } else { s.sessions_open_many };
                                ui.label(RichText::new(fill(text, &[&n.to_string()])).color(LIVE).size(12.0));
                            }
                        }
                    });
                });
            });
    }
}

impl eframe::App for Launcher {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll_sessions();
        if !self.sessions.is_empty() || matches!(*self.update.lock().unwrap(), UpdateState::Checking) {
            ui.ctx().request_repaint_after(Duration::from_millis(300));
        }

        egui::Panel::left("nav")
            .exact_size(232.0)
            .resizable(false)
            .show_separator_line(false)
            .frame(egui::Frame::new().fill(SIDEBAR).inner_margin(egui::Margin::symmetric(12, 18)))
            .show(ui, |ui| {
                let edge = ui.max_rect().right() + 12.0 - 0.5;
                ui.painter().vline(edge, ui.ctx().content_rect().y_range(), egui::Stroke::new(1.0, BORDER));
                self.sidebar(ui);
            });

        egui::CentralPanel::no_frame()
            .frame(egui::Frame::new().fill(BG).inner_margin(egui::Margin { left: 48, right: 34, top: 36, bottom: 0 }))
            .show(ui, |ui| {
                ui.set_max_width(ui.available_width().min(860.0));
                if let Some(updated) = match &*self.update.lock().unwrap() {
                    UpdateState::Updated(v) => Some(fill(self.s.updated_restart, &[v])),
                    _ => None,
                } {
                    banner(ui, &updated, LIVE);
                }
                for session in &self.sessions {
                    banner(ui, &fill(self.s.session_running, &[&session.label]), LIVE);
                }
                if let Some(error) = self.error.clone() {
                    banner(ui, &error, ERROR);
                }
                if self.error.is_some() || !self.sessions.is_empty() {
                    ui.add_space(12.0);
                }
                // The device list scrolls itself, below its header.
                if self.page == Page::Devices {
                    return self.devices(ui);
                }
                egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                    // Keep clear of the floating scroll bar.
                    ui.set_max_width(ui.available_width() - 14.0);
                    match self.page {
                        Page::Connect => self.connect_page(ui),
                        Page::Settings => self.settings_page(ui),
                        _ => self.about(ui),
                    }
                    ui.add_space(24.0);
                });
            });
    }
}

enum DeviceAction {
    Connect,
    Forget,
}

fn device_row(ui: &mut egui::Ui, s: &Strings, icons: &Icons, host: &KnownHost, running: bool) -> Option<DeviceAction> {
    let mut action = None;
    egui::Frame::new().inner_margin(egui::Margin::symmetric(18, 14)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal(|ui| {
            let (tile, _) = ui.allocate_exact_size(Vec2::splat(40.0), Sense::hover());
            ui.painter().rect(tile, RADIUS, BG, egui::Stroke::new(1.0, BORDER), egui::StrokeKind::Inside);
            icons.paint(ui.painter(), Icon::Monitor, tile.center(), 20.0, WEAK);
            ui.add_space(6.0);
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 3.0;
                ui.horizontal(|ui| {
                    ui.label(RichText::new(&host.name).font(font(14.5, semibold())));
                    if running {
                        ui.add_space(4.0);
                        status(ui, s.connected, LIVE);
                    }
                });
                ui.label(RichText::new(&host.address).font(mono(12.5)).color(WEAK));
            });
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if primary_button(ui, s.connect, 110.0, true).clicked() {
                    action = Some(DeviceAction::Connect);
                }
                if secondary_button(ui, s.forget).clicked() {
                    action = Some(DeviceAction::Forget);
                }
            });
        });
    });
    action
}

fn divider(ui: &mut egui::Ui) {
    let y = ui.cursor().min.y;
    ui.painter().hline(ui.max_rect().x_range(), y, egui::Stroke::new(1.0, BORDER));
}

fn connect_steps(ui: &mut egui::Ui, s: &Strings) {
    ui.label(RichText::new(s.steps_title).font(font(14.0, semibold())));
    ui.add_space(14.0);
    let steps = [(s.step1_title, s.step1_text), (s.step2_title, s.step2_text), (s.step3_title, s.step3_text)];
    const DOT: f32 = 24.0;
    let mut previous: Option<egui::Rect> = None;
    for (i, (title, text)) in steps.into_iter().enumerate() {
        let first = i == 0;
        let row = ui.horizontal_top(|ui| {
            let (dot, _) = ui.allocate_exact_size(Vec2::splat(DOT), Sense::hover());
            let (edge, number) = if first { (ACCENT_TEXT, ACCENT_TEXT) } else { (BORDER_STRONG, WEAK) };
            ui.painter().circle(dot.center(), DOT / 2.0 - 0.5, BG, egui::Stroke::new(1.0, edge));
            ui.painter().text(
                dot.center(),
                egui::Align2::CENTER_CENTER,
                (i + 1).to_string(),
                font(12.0, semibold()),
                number,
            );
            ui.add_space(8.0);
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 4.0;
                ui.add_space(3.0);
                ui.label(RichText::new(title).font(font(14.0, semibold())));
                ui.add(egui::Label::new(RichText::new(text).color(WEAK)).wrap());
                if first {
                    ui.add_space(2.0);
                    command(ui, "velora-host run --pair");
                }
            });
            dot
        });
        let dot = row.inner;
        // A line joins each step's circle to the next one.
        if let Some(above) = previous {
            ui.painter().vline(
                above.center().x,
                (above.bottom() + 4.0)..=(dot.top() - 4.0),
                egui::Stroke::new(1.0, BORDER_STRONG),
            );
        }
        previous = Some(dot);
        ui.add_space(20.0);
    }
}

/// What went wrong in a failed session, from its stderr: anyhow's `Error:` line plus the root
/// cause listed under `Caused by:`, or else the last line.
fn last_error(log: &str) -> String {
    let lines: Vec<&str> = log.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    let Some(at) = lines.iter().rposition(|l| l.starts_with("Error: ")) else {
        return lines.last().copied().unwrap_or("?").to_string();
    };
    let error = &lines[at]["Error: ".len()..];
    // anyhow prints a backtrace after the causes when RUST_BACKTRACE is set.
    let tail = &lines[at + 1..];
    let tail = &tail[..tail.iter().position(|l| l.starts_with("Stack backtrace:")).unwrap_or(tail.len())];
    let root = match tail.first() {
        Some(&"Caused by:") => tail.last().filter(|_| tail.len() > 1),
        _ => None,
    };
    match root {
        // Several causes are numbered "0: ..", "1: ..".
        Some(cause) => {
            let cause = cause.split_once(": ").filter(|(n, _)| n.parse::<u32>().is_ok()).map_or(*cause, |(_, c)| c);
            format!("{error}: {cause}")
        }
        None => error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn picks_the_error_and_root_cause() {
        let log = "INFO something\nError: host rejected the connection: not paired\n";
        assert_eq!(super::last_error(log), "host rejected the connection: not paired");
        let log = "Error: resolving x:1\n\nCaused by:\n    failed to lookup address\n";
        assert_eq!(super::last_error(log), "resolving x:1: failed to lookup address");
        let log = "Error: connecting\n\nCaused by:\n    0: handshake\n    1: timed out\n";
        assert_eq!(super::last_error(log), "connecting: timed out");
        let log =
            "Error: resolving x:1\n\nCaused by:\n    no such host\n\nStack backtrace:\n   0: main\n   1: _start\n";
        assert_eq!(super::last_error(log), "resolving x:1: no such host");
        assert_eq!(super::last_error("just a line\n"), "just a line");
    }
}
