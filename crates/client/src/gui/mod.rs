//! Desktop launcher: pair and pick computers, settings, updates.
//!
//! Each remote session runs in its own process (`velora connect <host>`, the window in
//! `main.rs`). That window needs raw physical keys, which egui does not expose, and a separate
//! process keeps a misbehaving session from taking the launcher down.

mod drop;
mod file_icons;
mod files;
mod icons;
mod motion;
pub(crate) mod strings;
mod theme;
mod this_pc;
mod widgets;

use std::{
    io::{Read, Write},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{anyhow, Result};
use eframe::egui::{self, Align, Color32, Layout, RichText, Sense, TextureHandle, Vec2};
use icons::{Icon, Icons};
use motion::success_notice;
use strings::{fill, Strings};
use theme::*;
pub use this_pc::spawn_host;
use this_pc::{HostLink, ServiceJob};
use velora_client_core::hosts;
use velora_protocol::{
    identity::{KnownHost, StateDir},
    pairing::{parse_pairing_uri, PairingCode},
};
use widgets::*;

use crate::settings::Settings;

const ICON_PNG: &[u8] = include_bytes!("../../assets/velora-icon.png");
const REPO_URL: &str = "https://github.com/Yanngc32/Velora";

/// Opens the launcher; `minimized` when started at sign-in.
pub fn run(state: StateDir, config_dir: Option<PathBuf>, no_update: bool, minimized: bool) -> Result<()> {
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
            if minimized {
                cc.egui_ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
            }
            Ok(Box::new(Launcher::new(state, config_dir, no_update, logo, icons, &cc.egui_ctx)))
        }),
    )
    .map_err(|e| anyhow!("{e}"))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Connect,
    Devices,
    ThisPc,
    Settings,
    About,
    /// The file manager, reached from a device; the sidebar shows it under Devices.
    Files,
}

#[derive(Clone)]
enum UpdateState {
    Idle,
    Checking,
    UpToDate,
    /// A newer release, and how many bytes it takes to download.
    Available(String, u64),
    /// Downloading a release: bytes so far and in total.
    Downloading(String, u64, u64),
    /// Installed on disk; the running processes are still the old version.
    Updated(String),
    Failed(String),
}

enum UpdateAction {
    Check,
    Install,
    Restart,
}

struct Session {
    label: String,
    /// Its command line, to start it again with a password.
    args: Vec<String>,
    child: Child,
    stderr: Arc<Mutex<String>>,
    /// Copies the session's stderr into `stderr`; done shortly after the session exits.
    reader: Option<std::thread::JoinHandle<()>>,
}

/// A session that stopped because its host asks for an access password.
struct PasswordPrompt {
    label: String,
    args: Vec<String>,
    /// The previous attempt had a password and it was wrong.
    wrong: bool,
    input: String,
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
    /// This executable, located before an update renames it, to start the new version.
    exe: Option<PathBuf>,
    /// `ui.input` time of the current frame.
    now: f64,
    /// When the current page was opened, and where the sidebar highlight was at that moment.
    page_since: f64,
    nav_from: Option<f32>,
    nav_y: Option<f32>,
    /// A host that just appeared in the list, and when.
    new_host: Option<(String, f64)>,
    /// When each notice now on screen first appeared, to fade it in.
    notices_seen: Vec<(String, f64)>,
    /// The host on this computer.
    host: HostLink,
    /// Pairing link and its QR code texture.
    qr: Option<(String, TextureHandle)>,
    /// Devices paired with this computer at the last poll, to notice new ones.
    clients_seen: Option<Vec<String>>,
    /// A device that just paired with this computer, and when.
    new_client: Option<(String, f64)>,
    /// The host view at the last poll that changed something.
    host_view: Option<Arc<this_pc::HostView>>,
    /// A host started from here that has not answered yet.
    host_child: Option<this_pc::StartedHost>,
    /// Pairing a new computer also lets it reach this one.
    offer_back: bool,
    /// File requests already answered or announced, by id, and those to always accept.
    requests_answered: Vec<u64>,
    requests_seen: Vec<u64>,
    requests_always: Vec<u64>,
    /// Offers from paired devices already being acted on, by link.
    offers_taken: Vec<String>,
    /// Pairing back with offered computers, once done: link, and host name or error.
    offers_done: this_pc::PairedBack,
    /// Another copy of the host holding the port, which "This PC" offers to stop.
    port_blocker: Option<crate::port_owner::PortOwner>,
    /// Installing or removing the Windows service.
    service_job: Arc<Mutex<ServiceJob>>,
    /// The access password being typed on "This PC".
    draft_password: String,
    password_prompt: Option<PasswordPrompt>,
    /// The file manager of one paired computer, kept while you look elsewhere.
    files: Option<files::FileManager>,
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
            exe: std::env::current_exe().ok(),
            now: 0.0,
            page_since: f64::NEG_INFINITY,
            nav_from: None,
            nav_y: None,
            new_host: None,
            notices_seen: Vec::new(),
            host: HostLink::start(ctx.clone()),
            qr: None,
            clients_seen: None,
            new_client: None,
            host_child: None,
            offer_back: true,
            requests_answered: Vec::new(),
            requests_seen: Vec::new(),
            requests_always: Vec::new(),
            offers_taken: Vec::new(),
            offers_done: Arc::default(),
            port_blocker: None,
            host_view: None,
            service_job: Arc::default(),
            draft_password: String::new(),
            password_prompt: None,
            files: None,
        };
        if !launcher.hosts.is_empty() {
            launcher.page = Page::Devices;
        }
        if launcher.settings.auto_update && velora_update::auto_update_enabled(no_update) {
            launcher.check_updates(ctx, true);
        }
        launcher
    }

    fn refresh_hosts(&mut self) {
        let hosts = hosts::list(&self.state).unwrap_or_default();
        if let Some(added) = hosts.iter().find(|h| !self.hosts.iter().any(|old| old.name == h.name)) {
            self.new_host = Some((added.name.clone(), self.now));
            // Just paired from this page: show where the computer landed.
            if self.page == Page::Connect {
                self.go(Page::Devices);
            }
        }
        self.hosts = hosts;
        self.hosts_loaded = Instant::now();
    }

    fn go(&mut self, page: Page) {
        if page != self.page {
            self.page = page;
            self.page_since = self.now;
            self.nav_from = self.nav_y;
        }
    }

    /// Looks for a newer release in the background; with `install`, also downloads and
    /// installs it, reporting progress.
    fn check_updates(&self, ctx: &egui::Context, install: bool) {
        *self.update.lock().unwrap() = UpdateState::Checking;
        let (state, ctx) = (self.update.clone(), ctx.clone());
        std::thread::spawn(move || {
            let result = (|| -> Result<UpdateState> {
                let updater = velora_update::Updater::for_current_exe()?;
                let Some(update) = updater.check()? else { return Ok(UpdateState::UpToDate) };
                let version = update.version.to_string();
                // Nothing to fetch: the host sharing this folder installed it already.
                if update.files.is_empty() {
                    return Ok(UpdateState::Updated(version));
                }
                if !install {
                    return Ok(UpdateState::Available(version, update.size()));
                }
                let mut progress = |done: u64, total: u64| {
                    *state.lock().unwrap() = UpdateState::Downloading(version.clone(), done, total);
                    ctx.request_repaint();
                };
                updater.install_with_progress(&update, &mut progress)?;
                Ok(UpdateState::Updated(version))
            })();
            *state.lock().unwrap() = result.unwrap_or_else(|e| UpdateState::Failed(format!("{e:#}")));
            ctx.request_repaint();
        });
    }

    /// Starts the installed version: the host first when it runs from this folder (not as the
    /// service, which updates itself), then the launcher, which exits.
    fn restart_updated(&mut self) {
        let Some(exe) = self.exe.clone() else { return };
        if self.host.view().status.as_ref().is_some_and(|st| !st.service) {
            let _ = velora_protocol::control::request(&velora_protocol::control::Request::Shutdown);
            // The new host can only bind once the old one let go of the port.
            let deadline = Instant::now() + Duration::from_secs(5);
            while crate::port_owner::udp_owner(velora_protocol::wire::DEFAULT_PORT).is_some()
                && Instant::now() < deadline
            {
                std::thread::sleep(Duration::from_millis(100));
            }
            if let Err(e) = spawn_host(self.config_dir.as_deref(), self.s.host_missing) {
                self.error = Some(format!("{e:#}"));
                return;
            }
        }
        velora_update::restart(&exe);
    }

    /// Starts a session window: `velora [--config-dir ..] --no-update <args>`. A password
    /// goes through standard input, never the command line, which other processes can read.
    fn spawn(&mut self, label: String, args: &[&str], password: Option<String>) {
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
        if password.is_some() {
            cmd.arg("--password-stdin").stdin(Stdio::piped());
        }
        match cmd.spawn() {
            Ok(mut child) => {
                if let (Some(mut stdin), Some(password)) = (child.stdin.take(), password) {
                    // Dropped right after: the session reads one line.
                    let _ = writeln!(stdin, "{password}");
                }
                let stderr = Arc::new(Mutex::new(String::new()));
                let mut reader = None;
                if let Some(mut pipe) = child.stderr.take() {
                    let buf = stderr.clone();
                    reader = Some(std::thread::spawn(move || {
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
                    }));
                }
                self.error = None;
                let args = args.iter().map(|a| a.to_string()).collect();
                self.sessions.push(Session { label, args, child, stderr, reader });
            }
            Err(e) => self.error = Some(e.to_string()),
        }
    }

    fn poll_sessions(&mut self) {
        let mut changed = false;
        let s = self.s;
        let mut error = None;
        let mut prompt = None;
        self.sessions.retain_mut(|session| match session.child.try_wait() {
            Ok(None) => true,
            Ok(Some(status)) => {
                changed = true;
                // Its last lines (the error) may still be on their way through the pipe.
                if let Some(reader) = session.reader.take() {
                    let _ = reader.join();
                }
                let log = session.stderr.lock().unwrap();
                if status.code() == Some(crate::EXIT_PASSWORD_REQUIRED) {
                    prompt = Some(PasswordPrompt {
                        label: session.label.clone(),
                        args: std::mem::take(&mut session.args),
                        wrong: log.contains("wrong password"),
                        input: String::new(),
                    });
                } else if !status.success() {
                    error = Some(fill(s.session_failed, &[&session.label, &last_error(&log)]));
                }
                false
            }
            Err(_) => false,
        });
        if let Some(e) = error {
            self.error = Some(e);
        }
        // One question at a time; another session that needs one can be started again.
        if self.password_prompt.is_none() {
            self.password_prompt = prompt;
        }
        // A pairing session saves its host; also pick up `velora pair` run from a terminal.
        // Poll faster while a session runs: a pairing session saves its host once paired.
        let every = Duration::from_secs(if self.sessions.is_empty() { 3 } else { 1 });
        if changed || self.hosts_loaded.elapsed() > every {
            self.refresh_hosts();
        }
    }

    fn connect_page(&mut self, ui: &mut egui::Ui) {
        const FORM_WIDTH: f32 = 360.0;
        const GAP: f32 = 48.0;
        const STEPS_WIDTH: f32 = 420.0;
        // Header, form and steps as one block, centered in the window, a little above the
        // middle (measured on the previous frame).
        let width = (FORM_WIDTH + GAP + STEPS_WIDTH).min(ui.available_width());
        let id = ui.scope_id().with("connect-height");
        let height = ui.ctx().data(|d| d.get_temp::<f32>(id)).unwrap_or(0.0);
        let left = ((ui.available_width() - width) / 2.0).max(0.0);
        // The visible height: inside the page's scroll area the available one has no end.
        let visible = ui.clip_rect().bottom() - ui.cursor().min.y;
        let top = ((visible - height) * 0.4).max(0.0);
        let rect =
            egui::Rect::from_min_size(ui.cursor().min + egui::vec2(left, top), egui::vec2(width, height.max(1.0)));
        let block =
            ui.scope_builder(egui::UiBuilder::new().max_rect(rect).layout(Layout::top_down(Align::Min)), |ui| {
                self.connect_block(ui, FORM_WIDTH, GAP);
            });
        let measured = block.response.rect.height();
        if (measured - height).abs() > 0.5 {
            ui.ctx().data_mut(|d| d.insert_temp(id, measured));
            ui.ctx().request_repaint();
        }
    }

    fn connect_block(&mut self, ui: &mut egui::Ui, form_width: f32, gap: f32) {
        let s = self.s;
        page_header(ui, s.connect_label, s.connect_title, Some(s.connect_hint));
        if ui.available_width() >= form_width + gap + 240.0 {
            ui.horizontal_top(|ui| {
                ui.allocate_ui_with_layout(egui::vec2(form_width, 0.0), Layout::top_down(Align::Min), |ui| {
                    self.connect_form(ui)
                });
                ui.add_space(gap - ui.spacing().item_spacing.x);
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
            // Only a running host can hand out a code for the other computer.
            let sharing = self.host.view().status.is_some();
            ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                let mut on = self.offer_back && sharing;
                if toggle(ui, &mut on, sharing).changed() {
                    self.offer_back = on;
                }
                ui.add_space(4.0);
                ui.add(egui::Label::new(RichText::new(s.offer_back).font(font(13.5, medium()))).wrap());
            });
            if !sharing {
                ui.add_space(2.0);
                ui.add(egui::Label::new(RichText::new(s.offer_back_off).small().color(WEAK)).wrap());
            }
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
                        let mut args = vec!["pair".to_string(), address.clone(), code, "--name".into(), name];
                        let mut offer_error = None;
                        if self.offer_back && sharing {
                            // A fresh code from this computer's host, for the other one to pair back.
                            // Without one (a service host refuses non-administrators), pair one way.
                            let request = velora_protocol::control::Request::StartPairing;
                            let link = velora_protocol::control::request(&request)
                                .and_then(|st| st.pairing.map(|p| p.uri).ok_or_else(|| anyhow!("no pairing code")));
                            match link {
                                Ok(link) => args.extend(["--offer".to_string(), link]),
                                Err(e) => offer_error = Some(fill(s.offer_failed, &[&format!("{e:#}")])),
                            }
                        }
                        let args: Vec<&str> = args.iter().map(String::as_str).collect();
                        self.spawn(address.clone(), &args, None);
                        if offer_error.is_some() {
                            self.error = offer_error;
                        }
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
            self.go(Page::Connect);
        }

        let mut action = None;
        // Files dragged in from the system go to the computer they are dropped on.
        let ctx = ui.ctx().clone();
        let (hovering, pointer, dropped) = (drop::hovering(&ctx), drop::pointer(&ctx), drop::dropped(&ctx));
        let mut drop_on = None;
        if hovering {
            ctx.request_repaint();
        }
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.set_max_width(ui.available_width() - 14.0);
            // Room above the first row: a card lifts under the pointer and must not be clipped.
            ui.add_space(6.0);
            // Cards in as many columns as fit.
            const MIN_CARD: f32 = 340.0;
            const GAP: f32 = 16.0;
            let width = ui.available_width();
            let columns = (((width + GAP) / (MIN_CARD + GAP)).floor() as usize).max(1);
            let card_width = (width - GAP * (columns - 1) as f32) / columns as f32;
            for row in self.hosts.chunks(columns) {
                ui.horizontal_top(|ui| {
                    ui.spacing_mut().item_spacing.x = GAP;
                    for host in row {
                        let fresh = match &self.new_host {
                            Some((name, since)) if *name == host.name => Some(*since),
                            _ => None,
                        };
                        // A pairing session is labelled with the address it dialed.
                        let running = self.sessions.iter().any(|x| x.label == host.name || x.label == host.address);
                        let card = DeviceCard { host, running, fresh, now: self.now, width: card_width };
                        let (picked, rect) = card.show(ui, s, &self.icons);
                        if let Some(a) = picked {
                            action = Some((a, host.name.clone()));
                        }
                        let over = pointer.is_some_and(|p| rect.contains(p));
                        let id = ui.scope_id().with(("device-drop", &host.name));
                        let t = ctx.animate_bool_with_time(id, hovering && over, 0.15);
                        drop::row_target(ui.painter(), rect, &fill(s.devices_drop, &[&host.name]), self.now, t);
                        if over && !dropped.is_empty() {
                            drop_on = Some(host.name.clone());
                        }
                    }
                });
                ui.add_space(GAP);
            }
            ui.add_space(24.0);
        });
        if let Some(name) = drop_on {
            self.open_files(name.clone(), &ctx);
            if let Some(manager) = &mut self.files {
                manager.send_when_ready(name, dropped, &ctx);
            }
        }
        match action {
            Some((DeviceAction::Connect, name)) => self.spawn(name.clone(), &["connect", &name], None),
            Some((DeviceAction::Files, name)) => self.open_files(name, ui.ctx()),
            Some((DeviceAction::Forget, name)) => {
                if let Err(e) = hosts::forget(&self.state, &name) {
                    self.error = Some(format!("{e:#}"));
                }
                self.refresh_hosts();
            }
            None => {}
        }
    }

    fn open_files(&mut self, host: String, ctx: &egui::Context) {
        match &mut self.files {
            // Keeps its transfers: the computer just shows on the right.
            Some(manager) => manager.show_host(host, ctx),
            None => {
                let manager =
                    files::FileManager::open(host, self.config_dir.clone(), self.settings.device_name.clone(), ctx);
                match manager {
                    Ok(manager) => self.files = Some(manager),
                    Err(e) => return self.error = Some(format!("{e:#}")),
                }
            }
        }
        self.go(Page::Files);
    }

    fn files_page(&mut self, ui: &mut egui::Ui) {
        let s = self.s;
        let Some(manager) = &mut self.files else { return self.go(Page::Devices) };
        let top = ui.cursor().min;
        page_header(ui, s.files_label, s.files_title, Some(s.files_hint));
        // Back to Devices sits at the right of the header, level with the title, as "Pair
        // computer" does there.
        let right = ui.max_rect().right();
        let area = egui::Rect::from_min_max(
            egui::pos2(right - 320.0, top.y + 28.0),
            egui::pos2(right, top.y + 28.0 + CONTROL_HEIGHT),
        );
        let mut corner = ui.new_child(egui::UiBuilder::new().max_rect(area).layout(Layout::right_to_left(Align::Min)));
        let back = secondary_button(&mut corner, s.files_to_devices).clicked();
        let hosts: Vec<String> = self.hosts.iter().map(|h| h.name.clone()).collect();
        manager.ui(ui, s, &hosts);
        if back {
            self.go(Page::Devices);
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
                    self.go(Page::Connect);
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
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 4.0;
                    card_title(ui, s.clipboard_title);
                    ui.add(egui::Label::new(RichText::new(s.clipboard_text).color(WEAK)).wrap());
                });
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let mut on = self.settings.share_clipboard;
                    if toggle(ui, &mut on, true).changed() {
                        let mut next = self.settings.clone();
                        next.share_clipboard = on;
                        self.store(next);
                    }
                });
            });
        });
        ui.add_space(16.0);
        self.startup_card(ui);
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

    /// Starting with the user's session: open the launcher, turn sharing on.
    fn startup_card(&mut self, ui: &mut egui::Ui) {
        let s = self.s;
        // The service already starts the host with the computer.
        let service = self.host_view.as_ref().and_then(|v| v.status.as_ref()).is_some_and(|st| st.service);
        let mut next = self.settings.clone();
        card(ui, |ui| {
            card_title(ui, s.startup_title);
            ui.add_space(6.0);
            let row = |ui: &mut egui::Ui, title: &str, note: &str, on: &mut bool, enabled: bool| {
                ui.horizontal(|ui| {
                    // Leave room for the switch so a long note wraps before it.
                    let text_width = ui.available_width() - 64.0;
                    ui.allocate_ui_with_layout(egui::vec2(text_width, 0.0), Layout::top_down(Align::Min), |ui| {
                        ui.spacing_mut().item_spacing.y = 2.0;
                        ui.label(RichText::new(title).font(font(14.0, medium())));
                        ui.add(egui::Label::new(RichText::new(note).color(WEAK)).wrap());
                    });
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| toggle(ui, on, enabled).changed()).inner
                })
                .inner
            };
            row(ui, s.open_at_login, s.open_at_login_text, &mut next.open_at_login, true);
            ui.add_space(10.0);
            let note = if service { s.share_at_login_service } else { s.share_at_login_text };
            let mut share = next.share_at_login && !service;
            if row(ui, s.share_at_login, note, &mut share, !service) {
                next.share_at_login = share;
            }
        });
        if next != self.settings {
            let enabled = next.open_at_login || next.share_at_login;
            match crate::autostart::apply(enabled, self.config_dir.as_deref()) {
                Ok(()) => self.store(next),
                Err(e) => self.error = Some(format!("{e:#}")),
            }
        }
    }

    /// Asks for the access password of a host whose session stopped for it, then starts the
    /// session again with it.
    fn password_modal(&mut self, ctx: &egui::Context) {
        let s = self.s;
        let Some(prompt) = &mut self.password_prompt else { return };
        let mut submit = false;
        let mut cancel = false;
        let modal = egui::Modal::new(egui::Id::unique("password-prompt")).show(ctx, |ui| {
            ui.set_width(340.0);
            card_title(ui, &fill(s.password_prompt_title, &[&prompt.label]));
            ui.add_space(4.0);
            let (text, color) = if prompt.wrong { (s.password_wrong, ERROR) } else { (s.password_prompt_text, WEAK) };
            ui.label(RichText::new(text).color(color));
            ui.add_space(12.0);
            let field = ui.add(field(&mut prompt.input, s.password_field, false).password(true));
            field.request_focus();
            if field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                submit = true;
            }
            ui.add_space(14.0);
            ui.horizontal(|ui| {
                if primary_button(ui, s.connect_short, 140.0, !prompt.input.is_empty()).clicked() {
                    submit = true;
                }
                if secondary_button(ui, s.cancel_short).clicked() {
                    cancel = true;
                }
            });
        });
        if modal.should_close() || cancel {
            self.password_prompt = None;
        } else if submit && !prompt.input.is_empty() {
            let prompt = self.password_prompt.take().unwrap();
            let args: Vec<&str> = prompt.args.iter().map(String::as_str).collect();
            self.spawn(prompt.label.clone(), &args, Some(prompt.input));
        }
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
        let mut action = None;
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
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| match &state {
                    UpdateState::Idle | UpdateState::UpToDate | UpdateState::Failed(_) => {
                        if secondary_button(ui, s.check_updates).clicked() {
                            action = Some(UpdateAction::Check);
                        }
                        match &state {
                            UpdateState::UpToDate => status(ui, s.up_to_date, LIVE),
                            UpdateState::Failed(e) => {
                                ui.add(egui::Label::new(RichText::new(e).color(ERROR).small()).truncate());
                            }
                            _ => {}
                        }
                    }
                    UpdateState::Checking => {
                        ui.label(RichText::new(s.checking).color(WEAK));
                        ui.spinner();
                    }
                    UpdateState::Available(v, size) => {
                        if primary_button(ui, s.download_install, 180.0, true).clicked() {
                            action = Some(UpdateAction::Install);
                        }
                        status(ui, &fill(s.update_available, &[v, &files::human_size(*size)]), LIVE);
                    }
                    UpdateState::Downloading(_, done, total) => {
                        let percent = if *total > 0 { done * 100 / total } else { 0 };
                        ui.label(RichText::new(format!("{percent}%")).font(mono(13.0)).color(WEAK));
                    }
                    UpdateState::Updated(v) => {
                        if primary_button(ui, s.restart_now, 160.0, true).clicked() {
                            action = Some(UpdateAction::Restart);
                        }
                        status(ui, &fill(s.updated_restart, &[v]), LIVE);
                    }
                });
            });
            if let UpdateState::Downloading(v, done, total) = &state {
                ui.add_space(4.0);
                let fraction = if *total > 0 { *done as f32 / *total as f32 } else { 0.0 };
                progress_bar(ui, fraction, ui.available_width());
                ui.add_space(8.0);
                let line = fill(s.downloading, &[v, &files::human_size(*done), &files::human_size(*total)]);
                ui.label(RichText::new(line).small().color(WEAK));
                ui.add_space(8.0);
            }
            divider(ui);
            row(ui, s.license, &mut |ui| {
                ui.label("MIT");
            });
            divider(ui);
            row(ui, s.source_code, &mut |ui| {
                ui.hyperlink_to(RichText::new("github.com/Yanngc32/Velora").font(mono(13.0)), REPO_URL);
            });
        });
        match action {
            Some(UpdateAction::Check) => self.check_updates(ui.ctx(), false),
            Some(UpdateAction::Install) => self.check_updates(ui.ctx(), true),
            Some(UpdateAction::Restart) => self.restart_updated(),
            None => {}
        }
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
        // The selection highlight goes under the entries and slides to the selected one.
        let highlight = ui.painter().add(egui::Shape::Noop);
        let mut selected = None;
        for (page, icon, label) in [
            (Page::Connect, Icon::Connect, s.nav_connect),
            (Page::Devices, Icon::Monitor, s.nav_devices),
            (Page::ThisPc, Icon::Smartphone, s.nav_this_pc),
            (Page::Settings, Icon::Settings, s.nav_settings),
            (Page::About, Icon::Info, s.nav_about),
        ] {
            let badge = (page == Page::Devices && !self.hosts.is_empty()).then(|| {
                let pulse = self.new_host.as_ref().map_or(0.0, |(_, since)| motion::pulse(self.now, *since, 0.8));
                (self.hosts.len(), pulse)
            });
            let current = if self.page == Page::Files { Page::Devices } else { self.page };
            let response = nav_item(ui, &self.icons, icon, label, current == page, badge);
            if current == page {
                selected = Some(response.rect);
            }
            if response.clicked() {
                self.go(page);
                self.error = None;
                self.saved = false;
            }
        }
        if let Some(rect) = selected {
            let t = motion::progress(self.now, self.page_since, 0.22);
            let y = egui::lerp(self.nav_from.unwrap_or(rect.top())..=rect.top(), t);
            self.nav_y = Some(y);
            let pill = egui::Rect::from_min_size(egui::pos2(rect.left(), y), rect.size());
            ui.painter().set(highlight, egui::epaint::RectShape::filled(pill, RADIUS, ACCENT.gamma_multiply(0.16)));
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
        self.now = ui.input(|i| i.time);
        self.poll_sessions();
        if !self.sessions.is_empty() || matches!(*self.update.lock().unwrap(), UpdateState::Checking) {
            ui.ctx().request_repaint_after(Duration::from_millis(300));
        }
        if let Some((_, since)) = &self.new_host {
            if self.now - since > motion::SUCCESS_SECONDS {
                self.new_host = None;
            }
        }
        let host = self.host.view();
        self.track_clients(&host);
        self.pair_back(&host);
        if self.new_client.as_ref().is_some_and(|(_, since)| self.now - since > motion::SUCCESS_SECONDS) {
            self.new_client = None;
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
                // Pages read best in a column; pairing centers its own.
                if self.page != Page::Connect {
                    ui.set_max_width(ui.available_width().min(860.0));
                }
                let mut notices = Vec::new();
                if let UpdateState::Updated(v) = &*self.update.lock().unwrap() {
                    notices.push((fill(self.s.updated_restart, &[v]), LIVE));
                }
                for session in &self.sessions {
                    notices.push((fill(self.s.session_running, &[&session.label]), LIVE));
                }
                if let Some(error) = &self.error {
                    notices.push((error.clone(), ERROR));
                }
                let now = self.now;
                self.notices_seen.retain(|(text, _)| notices.iter().any(|(t, _)| t == text));
                if let Some((name, since)) = &self.new_host {
                    success_notice(ui, &fill(self.s.paired_success, &[name]), now - since);
                }
                if let Some((name, since)) = &self.new_client {
                    success_notice(ui, &fill(self.s.client_paired, &[name]), now - since);
                }
                for (text, color) in &notices {
                    let since = match self.notices_seen.iter().find(|(t, _)| t == text) {
                        Some((_, since)) => *since,
                        None => {
                            self.notices_seen.push((text.clone(), now));
                            now
                        }
                    };
                    ui.scope(|ui| {
                        ui.multiply_opacity(motion::progress(now, since, 0.2));
                        banner(ui, text, *color);
                    });
                }
                if !notices.is_empty() || self.new_host.is_some() || self.new_client.is_some() {
                    ui.add_space(12.0);
                }
                self.file_requests(ui, &host);

                // New pages fade in while rising a few points.
                let t = motion::progress(now, self.page_since, 0.18);
                ui.multiply_opacity(t);
                ui.add_space((1.0 - t) * 8.0);
                let settling = t < 1.0
                    || self.new_host.is_some()
                    || self.new_client.is_some()
                    || self.notices_seen.iter().any(|(_, since)| now - since < 0.2);
                if settling {
                    ui.ctx().request_repaint();
                }
                // The device list and the file manager scroll themselves, below their header.
                if self.page == Page::Devices {
                    return self.devices(ui);
                }
                if self.page == Page::Files {
                    return self.files_page(ui);
                }
                // One scroll position per page: a long page must not leave the next one scrolled.
                let scroll = egui::ScrollArea::vertical().id_salt(self.page as u8).auto_shrink([false, false]);
                scroll.show(ui, |ui| {
                    // Keep clear of the floating scroll bar.
                    ui.set_max_width(ui.available_width() - 14.0);
                    match self.page {
                        Page::Connect => self.connect_page(ui),
                        Page::ThisPc => self.this_pc_page(ui),
                        Page::Settings => self.settings_page(ui),
                        _ => self.about(ui),
                    }
                    ui.add_space(24.0);
                });
            });
        self.password_modal(ui.ctx());
    }
}

enum DeviceAction {
    Connect,
    Files,
    Forget,
}

/// A button that removes something only when held: grey at rest, red under the pointer
/// (where it says to hold), and a red fill sweeps across while it is held. Letting go early
/// cancels. True once held to the end.
fn hold_to_forget(ui: &mut egui::Ui, s: &Strings) -> bool {
    const HOLD: f64 = 1.2;
    let font_id = font(12.5, semibold());
    let rest = ui.painter().layout_no_wrap(s.forget.to_string(), font_id.clone(), FAINT);
    let hint = ui.painter().layout_no_wrap(s.hold_to_forget.to_string(), font_id, ERROR);
    // As wide as the longer label, so nothing moves when it changes.
    let size = egui::vec2(rest.size().x.max(hint.size().x) + 24.0, CONTROL_HEIGHT - 6.0);
    let (rect, response) = ui.allocate_exact_size(size, Sense::click());
    let id = response.id.with("held-since");
    let now = ui.input(|i| i.time);
    let held = response.is_pointer_button_down_on();
    let since = ui.ctx().data_mut(|d| {
        let since = d.get_temp_mut_or_default::<Option<f64>>(id);
        *since = if held { Some(since.unwrap_or(now)) } else { None };
        *since
    });
    let progress = since.map_or(0.0, |t| ((now - t) / HOLD).clamp(0.0, 1.0)) as f32;
    let hover = ui.ctx().animate_bool_with_time(response.id.with("hover"), response.hovered() || held, HOVER_SECONDS);

    let painter = ui.painter();
    painter.rect_filled(rect, RADIUS, ERROR.gamma_multiply(0.16 * hover));
    painter.rect_stroke(
        rect,
        RADIUS,
        egui::Stroke::new(1.0, ERROR.gamma_multiply(0.55 * hover)),
        egui::StrokeKind::Inside,
    );
    if progress > 0.0 {
        let fill = egui::Rect::from_min_size(rect.min, egui::vec2(rect.width() * progress, rect.height()));
        painter.with_clip_rect(fill).rect_filled(rect, RADIUS, ERROR.gamma_multiply(0.55));
    }
    let galley = if hover > 0.5 { hint } else { rest };
    let color = FAINT.lerp_to_gamma(ERROR, hover).lerp_to_gamma(TEXT, progress);
    painter.galley(rect.center() - galley.size() / 2.0, galley, color);
    response.on_hover_cursor(egui::CursorIcon::PointingHand);

    if held {
        ui.ctx().request_repaint();
    }
    if progress >= 1.0 {
        ui.ctx().data_mut(|d| d.remove::<Option<f64>>(id));
        return true;
    }
    false
}

/// A paired computer as a card: its name and address, whether a session is open, and its
/// actions. The card lifts a little under the pointer; a `fresh` one (just paired, at that
/// time) grows in and keeps a teal edge that fades over a few seconds.
struct DeviceCard<'a> {
    host: &'a KnownHost,
    running: bool,
    fresh: Option<f64>,
    now: f64,
    width: f32,
}

impl DeviceCard<'_> {
    const HEIGHT: f32 = 150.0;

    fn show(self, ui: &mut egui::Ui, s: &Strings, icons: &Icons) -> (Option<DeviceAction>, egui::Rect) {
        let (slot, _) = ui.allocate_exact_size(egui::vec2(self.width, Self::HEIGHT), Sense::hover());
        let id = ui.scope_id().with(("device", &self.host.name));
        let hover = ui.ctx().animate_bool_with_time(id.with("hover"), ui.rect_contains_pointer(slot), HOVER_SECONDS);
        let (grow, wash) = match self.fresh {
            Some(since) => {
                (motion::progress(self.now, since, 0.35), 1.0 - motion::progress(self.now, since + 0.6, 2.5))
            }
            None => (1.0, 0.0),
        };
        let rect = egui::Rect::from_center_size(slot.center(), slot.size() * (0.94 + 0.06 * grow))
            .translate(egui::vec2(0.0, -2.0 * hover));
        let painter = ui.painter();
        painter.add(
            egui::Shadow {
                offset: [0, (4.0 + 6.0 * hover) as i8],
                blur: (12.0 + 12.0 * hover) as u8,
                spread: 0,
                color: Color32::from_black_alpha((40.0 + 40.0 * hover) as u8),
            }
            .as_shape(rect, CARD_RADIUS),
        );
        painter.rect_filled(rect, CARD_RADIUS, CARD);
        let edge = BORDER.lerp_to_gamma(BORDER_STRONG, hover).lerp_to_gamma(LIVE, wash);
        painter.rect_stroke(rect, CARD_RADIUS, egui::Stroke::new(1.0, edge), egui::StrokeKind::Inside);

        let mut action = None;
        let mut card =
            ui.new_child(egui::UiBuilder::new().max_rect(rect.shrink(18.0)).layout(Layout::top_down(Align::Min)));
        card.multiply_opacity(grow);
        card.horizontal(|ui| {
            let (tile, _) = ui.allocate_exact_size(Vec2::splat(44.0), Sense::hover());
            let tint = if self.running { LIVE } else { WEAK.lerp_to_gamma(ACCENT_TEXT, hover) };
            ui.painter().rect(tile, RADIUS, BG, egui::Stroke::new(1.0, BORDER), egui::StrokeKind::Inside);
            icons.paint(ui.painter(), Icon::Monitor, tile.center(), 22.0, tint);
            ui.add_space(6.0);
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 4.0;
                ui.add(egui::Label::new(RichText::new(&self.host.name).font(font(15.0, semibold()))).truncate());
                ui.label(RichText::new(&self.host.address).font(mono(12.5)).color(WEAK));
            });
        });
        if self.running {
            let mut corner = ui.new_child(
                egui::UiBuilder::new()
                    .max_rect(egui::Rect::from_min_max(
                        rect.right_top() + egui::vec2(-160.0, 18.0),
                        rect.right_top() + egui::vec2(-18.0, 40.0),
                    ))
                    .layout(Layout::right_to_left(Align::Center)),
            );
            status(&mut corner, s.connected, LIVE);
        }
        let bar = egui::Rect::from_min_max(
            rect.left_bottom() + egui::vec2(18.0, -18.0 - CONTROL_HEIGHT),
            rect.right_bottom() - egui::vec2(18.0, 18.0),
        );
        let mut buttons =
            ui.new_child(egui::UiBuilder::new().max_rect(bar).layout(Layout::right_to_left(Align::Center)));
        buttons.multiply_opacity(grow);
        if primary_button(&mut buttons, s.connect, 110.0, true).clicked() {
            action = Some(DeviceAction::Connect);
        }
        if secondary_button(&mut buttons, s.files).clicked() {
            action = Some(DeviceAction::Files);
        }
        buttons.with_layout(Layout::left_to_right(Align::Center), |ui| {
            if hold_to_forget(ui, s) {
                action = Some(DeviceAction::Forget);
            }
        });
        if self.fresh.is_some() && wash > 0.0 {
            ui.ctx().request_repaint();
        }
        (action, rect)
    }
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
