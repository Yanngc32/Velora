//! "This PC": the host running on this computer, seen through its local control channel.
//! Turn sharing on and off, pair a phone with a QR code, see and remove paired devices.

use std::{
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{mpsc, Arc, Mutex},
    time::Duration,
};

use eframe::egui::{self, Align, Color32, Layout, RichText, Sense, TextureHandle, Vec2};
use velora_protocol::{
    control::{self, Device, Request, Status},
    identity::StateDir,
};

use super::{icons::Icon, strings::fill, theme::*, widgets::*, Launcher};

const POLL: Duration = Duration::from_secs(1);
/// Output of a host started by the launcher, in the host's state directory.
const HOST_LOG: &str = "host.log";
const QR_SIZE: f32 = 232.0;

/// What the launcher knows about the local host, refreshed by a background thread.
#[derive(Clone, Default, PartialEq)]
pub struct HostView {
    /// `None` while no host answers.
    pub status: Option<Status>,
    /// The last request other than a status poll failed.
    pub error: Option<String>,
    /// At least one poll finished, so `status: None` means "not running".
    pub checked: bool,
}

pub struct HostLink {
    /// Replaced (never mutated) when something changes, so frames share it cheaply.
    view: Arc<Mutex<Arc<HostView>>>,
    requests: mpsc::Sender<Request>,
}

impl HostLink {
    pub fn start(ctx: egui::Context) -> Self {
        let view = Arc::new(Mutex::new(Arc::new(HostView::default())));
        let (requests, rx) = mpsc::channel::<Request>();
        let shared = view.clone();
        std::thread::Builder::new()
            .name("host-link".into())
            .spawn(move || loop {
                let request = match rx.recv_timeout(POLL) {
                    Ok(r) => r,
                    Err(mpsc::RecvTimeoutError::Timeout) => Request::Status,
                    Err(mpsc::RecvTimeoutError::Disconnected) => return,
                };
                let polling = request == Request::Status;
                let result = control::request(&request);
                let mut next = HostView::clone(&shared.lock().unwrap());
                next.checked = true;
                match result {
                    Ok(status) => {
                        next.status = Some(status);
                        next.error = None;
                    }
                    Err(_) if polling => next.status = None,
                    Err(e) => next.error = Some(format!("{e:#}")),
                }
                let mut current = shared.lock().unwrap();
                // Most polls change nothing: no new frame for those.
                if **current != next {
                    *current = Arc::new(next);
                    ctx.request_repaint();
                }
            })
            .expect("spawning host link thread");
        Self { view, requests }
    }

    pub fn view(&self) -> Arc<HostView> {
        self.view.lock().unwrap().clone()
    }

    pub fn send(&self, request: Request) {
        let _ = self.requests.send(request);
    }
}

/// `velora-host`, installed next to this executable.
fn host_exe() -> Option<PathBuf> {
    let name = if cfg!(windows) { "velora-host.exe" } else { "velora-host" };
    let exe = std::env::current_exe().ok()?.with_file_name(name);
    exe.exists().then_some(exe)
}

enum Action {
    Start,
    Stop,
    Pair,
    CancelPairing,
    Copy(String),
    Remove(String),
    /// Install (`true`) or remove the Windows service.
    Service(bool),
    /// Set (`Some`) or remove the access password.
    SetPassword(Option<String>),
}

/// An elevated `velora-host service install|uninstall` in progress, or its outcome.
#[derive(Clone, Default)]
pub enum ServiceJob {
    #[default]
    Idle,
    Running,
    Failed(String),
}

/// Runs `velora-host service <action>` as administrator (a UAC prompt) and waits for it.
#[cfg(windows)]
fn run_elevated_service(action: &str, config_dir: &std::path::Path) -> anyhow::Result<()> {
    use anyhow::{bail, Context};
    use windows::{
        core::HSTRING,
        Win32::{
            Foundation::CloseHandle,
            System::Threading::{GetExitCodeProcess, WaitForSingleObject, INFINITE},
            UI::{
                Shell::{ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW},
                WindowsAndMessaging::SW_HIDE,
            },
        },
    };

    let exe = host_exe().context("velora-host.exe not found next to Velora")?;
    let report = std::env::temp_dir().join(format!("velora-service-{}.txt", std::process::id()));
    let _ = std::fs::remove_file(&report);
    let (verb, file) = (HSTRING::from("runas"), HSTRING::from(exe.as_os_str()));
    let params = HSTRING::from(format!(
        "--config-dir \"{}\" service {action} --report \"{}\"",
        config_dir.display(),
        report.display()
    ));
    let mut info = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
        lpVerb: windows::core::PCWSTR(verb.as_ptr()),
        lpFile: windows::core::PCWSTR(file.as_ptr()),
        lpParameters: windows::core::PCWSTR(params.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };
    // SAFETY: the strings outlive the call; the process handle is closed below.
    let code = unsafe {
        // Fails with ERROR_CANCELLED when the UAC prompt is declined.
        ShellExecuteExW(&mut info).context("administrator permission was not granted")?;
        let mut code = 1u32;
        WaitForSingleObject(info.hProcess, INFINITE);
        let _ = GetExitCodeProcess(info.hProcess, &mut code);
        let _ = CloseHandle(info.hProcess);
        code
    };
    let message = std::fs::read_to_string(&report).unwrap_or_default();
    let _ = std::fs::remove_file(&report);
    if code != 0 {
        bail!("{}", if message.trim().is_empty() { format!("exit code {code}") } else { message });
    }
    Ok(())
}

/// Starts `velora-host run` in the background, without a window, logging to `host.log` in
/// the host's state directory. It outlives the launcher. Returns the process and its log.
pub fn spawn_host(config_dir: Option<&std::path::Path>, missing: &str) -> anyhow::Result<(Child, PathBuf)> {
    let exe = host_exe().ok_or_else(|| anyhow::anyhow!("{missing}"))?;
    let log = StateDir::open(config_dir.map(PathBuf::from), "host")?.path(HOST_LOG);
    let mut cmd = Command::new(exe);
    if let Some(dir) = config_dir {
        cmd.arg("--config-dir").arg(dir);
    }
    cmd.arg("run").env("NO_COLOR", "1").stdin(Stdio::null()).stdout(Stdio::null()).stderr(std::fs::File::create(&log)?);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        cmd.creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS);
    }
    Ok((cmd.spawn()?, log))
}

impl Launcher {
    fn start_host(&mut self) {
        match spawn_host(self.config_dir.as_deref(), self.s.host_missing) {
            Ok(started) => {
                self.error = None;
                self.host_child = Some(started);
            }
            Err(e) => self.error = Some(format!("{e:#}")),
        }
    }

    /// Reports a host started from here that exits before it answers (port in use, ...).
    fn watch_started_host(&mut self, view: &HostView) {
        let Some((child, log)) = &mut self.host_child else { return };
        if view.status.is_some() {
            self.host_child = None;
            return;
        }
        if let Ok(Some(status)) = child.try_wait() {
            if !status.success() {
                let log = std::fs::read_to_string(log).unwrap_or_default();
                self.error = Some(fill(self.s.host_failed, &[&super::last_error(&log)]));
            }
            self.host_child = None;
        }
    }

    /// Notices devices that appear while the page is open (a phone just scanned the code).
    pub(super) fn track_clients(&mut self, view: &Arc<HostView>) {
        // Only when a poll changed something, not on every frame.
        if self.host_view.as_ref().is_some_and(|seen| Arc::ptr_eq(seen, view)) {
            return;
        }
        self.host_view = Some(view.clone());
        let Some(status) = &view.status else { return };
        let known: Vec<String> = status.devices.iter().map(|d| d.fingerprint.clone()).collect();
        if let Some(previous) = &self.clients_seen {
            if let Some(added) = status.devices.iter().find(|d| !previous.contains(&d.fingerprint)) {
                self.new_client = Some((added.name.clone(), self.now));
            }
        }
        self.clients_seen = Some(known);
    }

    pub(super) fn this_pc_page(&mut self, ui: &mut egui::Ui) {
        let s = self.s;
        let view = self.host.view();
        self.watch_started_host(&view);
        let subtitle = match &view.status {
            Some(st) => {
                let mut line = format!("{} · {}", s.share_on, st.name);
                if let Some(address) = &st.address {
                    line.push_str(&format!(" · {address}"));
                }
                line
            }
            None if view.checked => s.share_off.to_string(),
            None => String::new(),
        };
        page_header(ui, s.share_label, s.this_pc_title, Some(&subtitle));
        if let Some(e) = &view.error {
            banner(ui, e, ERROR);
            ui.add_space(12.0);
        }

        let mut action = None;
        match &view.status {
            None if !view.checked => {
                ui.spinner();
            }
            None => {
                card(ui, |ui| {
                    card_title(ui, s.share_off_title);
                    ui.add(egui::Label::new(RichText::new(s.share_off_text).color(WEAK)).wrap());
                    ui.add_space(14.0);
                    // Not twice while a host just started has not answered yet.
                    let starting = self.host_child.is_some();
                    if primary_button(ui, s.share_start, 200.0, !starting).clicked() {
                        action = Some(Action::Start);
                    }
                })
                .inner
            }
            Some(status) => {
                const PAIR_WIDTH: f32 = QR_SIZE + 48.0;
                const GAP: f32 = 24.0;
                let pair = |ui: &mut egui::Ui, this: &mut Launcher, action: &mut Option<Action>| {
                    this.pair_card(ui, status, action)
                };
                if ui.available_width() >= PAIR_WIDTH + GAP + 320.0 {
                    ui.horizontal_top(|ui| {
                        ui.allocate_ui_with_layout(egui::vec2(PAIR_WIDTH, 0.0), Layout::top_down(Align::Min), |ui| {
                            pair(ui, self, &mut action)
                        });
                        ui.add_space(GAP - ui.spacing().item_spacing.x);
                        let width = ui.available_width();
                        ui.allocate_ui_with_layout(egui::vec2(width, 0.0), Layout::top_down(Align::Min), |ui| {
                            self.clients_card(ui, &status.devices, &mut action)
                        });
                    });
                } else {
                    pair(ui, self, &mut action);
                    ui.add_space(16.0);
                    self.clients_card(ui, &status.devices, &mut action);
                }
                ui.add_space(16.0);
                self.password_card(ui, status.password_set, &mut action);
                ui.add_space(16.0);
                ui.horizontal(|ui| {
                    // The service would only start the host again.
                    if !status.service && secondary_button(ui, s.share_stop).clicked() {
                        action = Some(Action::Stop);
                    }
                    let note = fill(s.host_fingerprint, &[&status.fingerprint, &status.version]);
                    ui.add_space(8.0);
                    ui.label(RichText::new(note).font(mono(12.0)).color(FAINT));
                });
            }
        }
        if cfg!(windows) && view.checked {
            ui.add_space(16.0);
            let service = view.status.as_ref().is_some_and(|st| st.service);
            self.service_card(ui, service, &mut action);
        }

        match action {
            Some(Action::Start) => self.start_host(),
            Some(Action::Stop) => self.host.send(Request::Shutdown),
            Some(Action::Pair) => self.host.send(Request::StartPairing),
            Some(Action::CancelPairing) => self.host.send(Request::CancelPairing),
            Some(Action::Copy(text)) => ui.ctx().copy_text(text),
            Some(Action::Remove(fingerprint)) => self.host.send(Request::Revoke { fingerprint }),
            Some(Action::Service(install)) => self.change_service(ui.ctx(), install),
            Some(Action::SetPassword(password)) => {
                self.draft_password.clear();
                self.host.send(Request::SetPassword { password });
            }
            None => {}
        }
    }

    /// The access password paired devices must also give.
    fn password_card(&mut self, ui: &mut egui::Ui, set: bool, action: &mut Option<Action>) {
        let s = self.s;
        card(ui, |ui| {
            card_title(ui, s.password_title);
            ui.add_space(2.0);
            if set {
                status(ui, s.password_on, LIVE);
            } else {
                ui.add(egui::Label::new(RichText::new(s.password_text).color(WEAK)).wrap());
            }
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                let hint = if set { s.password_new } else { s.password_hint };
                let field =
                    ui.add_sized([240.0, CONTROL_HEIGHT], field(&mut self.draft_password, hint, false).password(true));
                let ready = !self.draft_password.is_empty();
                let label = if set { s.password_change } else { s.password_set };
                let submit = field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                if (primary_button(ui, label, 120.0, ready).clicked() || submit) && ready {
                    *action = Some(Action::SetPassword(Some(self.draft_password.clone())));
                }
                if set && secondary_button(ui, s.password_remove).clicked() {
                    *action = Some(Action::SetPassword(None));
                }
            });
        });
    }

    /// Lock screen access: the host as a Windows service.
    fn service_card(&self, ui: &mut egui::Ui, active: bool, action: &mut Option<Action>) {
        let s = self.s;
        let job = self.service_job.lock().unwrap().clone();
        card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 4.0;
                    card_title(ui, s.service_title);
                    if active {
                        status(ui, s.service_on, LIVE);
                    } else {
                        ui.add(egui::Label::new(RichText::new(s.service_text).color(WEAK)).wrap());
                    }
                });
            });
            ui.add_space(12.0);
            ui.horizontal(|ui| match &job {
                ServiceJob::Running => {
                    ui.spinner();
                    ui.label(RichText::new(s.service_waiting).color(WEAK));
                }
                _ if active => {
                    if secondary_button(ui, s.service_disable).clicked() {
                        *action = Some(Action::Service(false));
                    }
                }
                _ => {
                    if primary_button(ui, s.service_enable, 200.0, true).clicked() {
                        *action = Some(Action::Service(true));
                    }
                }
            });
            if let ServiceJob::Failed(e) = &job {
                ui.add_space(8.0);
                ui.add(egui::Label::new(RichText::new(e).color(ERROR)).wrap());
            }
        });
    }

    fn change_service(&self, ctx: &egui::Context, install: bool) {
        // The base configuration folder (its `host` subfolder holds the paired devices).
        let config_dir = match StateDir::open(self.config_dir.clone(), "host") {
            Ok(state) => state.dir().parent().map(PathBuf::from).unwrap_or_default(),
            Err(e) => return *self.service_job.lock().unwrap() = ServiceJob::Failed(format!("{e:#}")),
        };
        let job = self.service_job.clone();
        *job.lock().unwrap() = ServiceJob::Running;
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            #[cfg(windows)]
            let result = run_elevated_service(if install { "install" } else { "uninstall" }, &config_dir);
            #[cfg(not(windows))]
            let result: anyhow::Result<()> =
                Err(anyhow::anyhow!("the service is only available on Windows ({install}, {})", config_dir.display()));
            *job.lock().unwrap() = match result {
                Ok(()) => ServiceJob::Idle,
                Err(e) => ServiceJob::Failed(format!("{e:#}")),
            };
            ctx.request_repaint();
        });
    }

    fn pair_card(&mut self, ui: &mut egui::Ui, status: &Status, action: &mut Option<Action>) {
        let s = self.s;
        card(ui, |ui| {
            card_title(ui, s.pair_device_title);
            ui.add_space(4.0);
            let Some(pairing) = &status.pairing else {
                ui.add(egui::Label::new(RichText::new(s.pair_device_text).color(WEAK)).wrap());
                ui.add_space(14.0);
                if primary_button(ui, s.show_qr, ui.available_width(), true).clicked() {
                    *action = Some(Action::Pair);
                }
                return;
            };
            ui.add(egui::Label::new(RichText::new(s.scan_hint).color(WEAK)).wrap());
            ui.add_space(12.0);
            let texture = self.qr_texture(ui.ctx(), &pairing.uri);
            ui.vertical_centered(|ui| {
                let (rect, _) = ui.allocate_exact_size(Vec2::splat(QR_SIZE), Sense::hover());
                // White with a quiet zone, as scanners expect, whatever the theme.
                ui.painter().rect_filled(rect, RADIUS, Color32::WHITE);
                if let Some(texture) = texture {
                    let uv = egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0));
                    ui.painter().image(texture.id(), rect.shrink(12.0), uv, Color32::WHITE);
                }
            });
            ui.add_space(12.0);
            let left = pairing.expires_in_secs;
            let expires = fill(s.expires_in, &[&format!("{}:{:02}", left / 60, left % 60)]);
            ui.label(RichText::new(expires).color(FAINT).size(12.5));
            ui.add_space(10.0);
            field_label(ui, s.code_other_pc);
            ui.add(egui::Label::new(RichText::new(&pairing.code).font(mono(11.5)).color(TEXT)).wrap());
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if secondary_button(ui, s.copy_link).clicked() {
                    *action = Some(Action::Copy(pairing.uri.clone()));
                }
                if secondary_button(ui, s.cancel).clicked() {
                    *action = Some(Action::CancelPairing);
                }
            });
        });
    }

    fn clients_card(&self, ui: &mut egui::Ui, devices: &[Device], action: &mut Option<Action>) {
        let s = self.s;
        card(ui, |ui| {
            card_title(ui, s.clients_title);
            ui.add_space(4.0);
            if devices.is_empty() {
                ui.label(RichText::new(s.no_clients).color(WEAK));
                return;
            }
            for (i, device) in devices.iter().enumerate() {
                if i > 0 {
                    let y = ui.cursor().min.y;
                    ui.painter().hline(ui.max_rect().x_range(), y, egui::Stroke::new(1.0, BORDER));
                }
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    let (tile, _) = ui.allocate_exact_size(Vec2::splat(36.0), Sense::hover());
                    ui.painter().rect(tile, RADIUS, BG, egui::Stroke::new(1.0, BORDER), egui::StrokeKind::Inside);
                    self.icons.paint(ui.painter(), Icon::Smartphone, tile.center(), 18.0, WEAK);
                    ui.add_space(4.0);
                    ui.vertical(|ui| {
                        ui.spacing_mut().item_spacing.y = 2.0;
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(&device.name).font(font(14.0, semibold())));
                            if device.connected {
                                status(ui, s.connected, LIVE);
                            }
                        });
                        ui.label(RichText::new(&device.short).font(mono(12.0)).color(WEAK));
                    });
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if secondary_button(ui, s.remove).clicked() {
                            *action = Some(Action::Remove(device.fingerprint.clone()));
                        }
                    });
                });
                ui.add_space(10.0);
            }
        });
    }

    /// The pairing link as a QR code texture, one pixel per module, cached per link.
    fn qr_texture(&mut self, ctx: &egui::Context, uri: &str) -> Option<TextureHandle> {
        if let Some((cached, texture)) = &self.qr {
            if cached == uri {
                return Some(texture.clone());
            }
        }
        let code = qrcode::QrCode::new(uri.as_bytes()).ok()?;
        let width = code.width();
        let pixels = code
            .to_colors()
            .into_iter()
            .map(|c| if c == qrcode::Color::Dark { Color32::BLACK } else { Color32::WHITE })
            .collect();
        let image = egui::ColorImage::new([width, width], pixels);
        // Nearest filtering keeps module edges sharp at any scale.
        let texture = ctx.load_texture("pairing-qr", image, egui::TextureOptions::NEAREST);
        self.qr = Some((uri.to_string(), texture.clone()));
        Some(texture)
    }
}
