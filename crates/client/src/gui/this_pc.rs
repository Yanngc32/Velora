//! "This PC": the host running on this computer, seen through its local control channel.
//! Turn sharing on and off, pair a phone with a QR code, see and remove paired devices.

use std::{
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{mpsc, Arc, Mutex},
    time::{Duration, Instant},
};

use eframe::egui::{self, Align, Color32, Layout, RichText, Sense, TextureHandle, Vec2};
use velora_protocol::{
    control::{self, Device, Request, Status},
    identity::StateDir,
    wire::DEFAULT_PORT,
};

use super::{icons::Icon, strings::fill, theme::*, widgets::*, Launcher};
use crate::port_owner;

const POLL: Duration = Duration::from_secs(1);
/// Output of a host started by the launcher, in the host's state directory.
const HOST_LOG: &str = "host.log";
const QR_SIZE: f32 = 232.0;
/// How long a host started from here may take to answer before the launcher says so.
const START_TIMEOUT: Duration = Duration::from_secs(15);

/// Offers acted on: the offered link, and the computer's name or why pairing back failed.
pub type PairedBack = Arc<Mutex<Vec<(String, Result<String, String>)>>>;

/// A host started from here that has not answered yet.
pub struct StartedHost {
    child: Child,
    log: PathBuf,
    since: Instant,
}

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

    /// The same link, for another thread (the tray icon's).
    #[cfg(windows)]
    pub fn handle(&self) -> HostHandle {
        HostHandle { view: self.view.clone(), requests: self.requests.clone() }
    }
}

/// A [`HostLink`] seen from another thread.
#[cfg(windows)]
#[derive(Clone)]
pub struct HostHandle {
    view: Arc<Mutex<Arc<HostView>>>,
    requests: mpsc::Sender<Request>,
}

#[cfg(windows)]
impl HostHandle {
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
    /// Stop the other copy of the host holding the port, then start this one.
    StopBlockerAndStart(u32),
    Stop,
    Pair,
    CancelPairing,
    Copy(String),
    Remove(String),
    /// Install (`true`) or remove the Windows service.
    Service(bool),
    /// Set (`Some`) or remove the access password.
    SetPassword(Option<String>),
    StayAwake(bool),
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
        self.port_blocker = None;
        // Starting a host that cannot bind only ends in an error: say who holds the port now.
        if let Some(owner) = port_owner::udp_owner(DEFAULT_PORT) {
            return self.port_in_use(owner);
        }
        match spawn_host(self.config_dir.as_deref(), self.s.host_missing) {
            Ok((child, log)) => {
                self.error = None;
                self.host_child = Some(StartedHost { child, log, since: Instant::now() });
            }
            Err(e) => self.error = Some(format!("{e:#}")),
        }
    }

    fn port_in_use(&mut self, owner: port_owner::PortOwner) {
        let (pid, port) = (owner.pid.to_string(), DEFAULT_PORT.to_string());
        if owner.is_host() {
            self.error = Some(fill(self.s.port_in_use_host, &[&owner.name, &pid, &port]));
            self.port_blocker = Some(owner);
        } else {
            self.error = Some(fill(self.s.port_in_use, &[&port, &owner.name, &pid]));
        }
    }

    fn stop_blocker_and_start(&mut self, pid: u32) {
        match port_owner::stop(pid) {
            Ok(()) => self.start_host(),
            Err(e) => self.error = Some(format!("{e:#}")),
        }
    }

    /// Reports a host started from here that exits before it answers (port in use, ...), or
    /// that runs without answering.
    fn watch_started_host(&mut self, view: &HostView) {
        let Some(started) = &mut self.host_child else { return };
        if view.status.is_some() {
            self.host_child = None;
            self.port_blocker = None;
            return;
        }
        if let Ok(Some(status)) = started.child.try_wait() {
            let log = std::fs::read_to_string(&started.log).unwrap_or_default();
            self.host_child = None;
            if status.success() {
                return;
            }
            // Something took the port in between: name it rather than show the OS error.
            if log.contains("binding") {
                if let Some(owner) = port_owner::udp_owner(DEFAULT_PORT) {
                    return self.port_in_use(owner);
                }
            }
            self.error = Some(fill(self.s.host_failed, &[&super::last_error(&log)]));
        } else if started.since.elapsed() > START_TIMEOUT {
            self.error = Some(fill(self.s.host_no_answer, &[&started.log.display().to_string()]));
            self.host_child = None;
        }
    }

    /// Pairs with computers that paired with this one and offered to be reached from here too.
    /// Quietly, over a file connection; the result shows like any new computer in Devices.
    pub(super) fn pair_back(&mut self, view: &HostView) {
        let done: Vec<_> = std::mem::take(&mut *self.offers_done.lock().unwrap());
        for (uri, result) in done {
            self.host.send(Request::DismissOffer { uri });
            match result {
                Ok(_) => self.refresh_hosts(),
                Err(e) => self.error = Some(e),
            }
        }
        let Some(status) = &view.status else { return };
        for offer in &status.offers {
            if self.offers_taken.contains(&offer.uri) {
                continue;
            }
            self.offers_taken.push(offer.uri.clone());
            let Some(link) = velora_protocol::pairing::parse_pairing_link(&offer.uri) else { continue };
            let (name, done, uri) = (self.settings.device_name.clone(), self.offers_done.clone(), offer.uri.clone());
            let (from, s, config_dir) = (offer.name.clone(), self.s, self.config_dir.clone());
            std::thread::spawn(move || {
                let result = (|| -> anyhow::Result<String> {
                    // The launcher's own paired list, as in `run`.
                    let state = StateDir::open(config_dir, "client")?;
                    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
                    runtime.block_on(velora_client_core::hosts::pair_quietly(
                        &state,
                        &link.address,
                        &link.also,
                        &link.code.encode(),
                        &name,
                        None,
                    ))
                })();
                let result = result.map_err(|e| {
                    let why = match e.downcast_ref::<velora_client_core::PasswordRequired>() {
                        Some(_) => s.offer_needs_password.to_string(),
                        None => format!("{e:#}"),
                    };
                    fill(s.pair_back_failed, &[&from, &why])
                });
                done.lock().unwrap().push((uri, result));
            });
        }
    }

    /// Devices asking to send files here, on top of every page: accept or decline, and
    /// optionally always accept that device. A new request also flashes the window.
    pub(super) fn file_requests(&mut self, ui: &mut egui::Ui, view: &HostView) {
        let s = self.s;
        let Some(status) = &view.status else { return };
        let open: Vec<_> = status.requests.iter().filter(|r| !self.requests_answered.contains(&r.id)).collect();
        if open.iter().any(|r| !self.requests_seen.contains(&r.id)) {
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::RequestUserAttention(egui::UserAttentionType::Critical));
            self.requests_seen.extend(open.iter().map(|r| r.id));
        }
        let now = ui.input(|i| i.time);
        let mut answers = Vec::new();
        for request in &open {
            let id = ui.scope_id().with(("request", request.id));
            let since = ui.ctx().data_mut(|d| *d.get_temp_mut_or_insert_with(id, || now));
            ui.scope(|ui| {
                let t = super::motion::progress(now, since, 0.25);
                ui.multiply_opacity(t);
                ui.add_space((1.0 - t) * 8.0);
                let frame = egui::Frame::new()
                    .fill(CARD)
                    .stroke(egui::Stroke::new(1.0, ACCENT.gamma_multiply(0.6)))
                    .corner_radius(CARD_RADIUS)
                    .inner_margin(egui::Margin::symmetric(18, 14));
                frame.show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        let (badge, _) = ui.allocate_exact_size(Vec2::splat(40.0), Sense::hover());
                        let bob = (now as f32 * 3.0).sin() * 1.5;
                        super::file_icons::arrow_badge(
                            ui.painter(),
                            badge.center() + egui::vec2(0.0, bob),
                            18.0,
                            false,
                            ACCENT_TEXT,
                        );
                        ui.add_space(6.0);
                        ui.vertical(|ui| {
                            ui.spacing_mut().item_spacing.y = 3.0;
                            let title = fill(s.request_title, &[&request.name]);
                            ui.label(RichText::new(title).font(font(14.5, semibold())));
                            let size = super::files::human_size(request.bytes);
                            ui.label(RichText::new(fill(s.request_text, &[&size, &request.folder])).color(WEAK));
                            ui.horizontal(|ui| {
                                let mut always = self.requests_always.contains(&request.id);
                                if toggle(ui, &mut always, true).changed() {
                                    self.requests_always.retain(|id| *id != request.id);
                                    if always {
                                        self.requests_always.push(request.id);
                                    }
                                }
                                ui.label(RichText::new(fill(s.request_always, &[&request.name])).small().color(WEAK));
                            });
                        });
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if primary_button(ui, s.request_accept, 120.0, true).clicked() {
                                answers.push((request.id, true));
                            }
                            if secondary_button(ui, s.request_decline).clicked() {
                                answers.push((request.id, false));
                            }
                        });
                    });
                });
            });
            ui.add_space(12.0);
        }
        if !open.is_empty() {
            // The badge bobs while a request waits.
            ui.ctx().request_repaint_after(Duration::from_millis(33));
        }
        for (id, accept) in answers {
            let always = accept && self.requests_always.contains(&id);
            self.host.send(Request::AnswerFiles { id, accept, always });
            self.requests_answered.push(id);
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
                // Reachable from anywhere on the VPN mesh too.
                if let Some(vpn) = st.also.first() {
                    line.push_str(&format!(" · VPN {vpn}"));
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
                    if let Some(blocker) = &self.port_blocker {
                        if primary_button(ui, s.stop_and_start, 200.0, !starting).clicked() {
                            action = Some(Action::StopBlockerAndStart(blocker.pid));
                        }
                    } else {
                        let label = if starting { s.share_starting } else { s.share_start };
                        if primary_button(ui, label, 200.0, !starting).clicked() {
                            action = Some(Action::Start);
                        }
                    }
                    if starting {
                        // Keep polling the child even when nothing else repaints.
                        ui.ctx().request_repaint_after(Duration::from_millis(250));
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
                if let Some(on) = status.stay_awake {
                    self.stay_awake_card(ui, on, &mut action);
                    ui.add_space(16.0);
                }
                // Nothing from a host that predates standalone reach.
                if let Some(request) = super::reach::reach_card(ui, s, status.reach.as_ref()) {
                    self.host.send(request);
                }
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
            Some(Action::StopBlockerAndStart(pid)) => self.stop_blocker_and_start(pid),
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
            Some(Action::StayAwake(on)) => self.host.send(Request::SetStayAwake { on }),
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

    /// Keeping the computer awake while it is shared.
    fn stay_awake_card(&self, ui: &mut egui::Ui, on: bool, action: &mut Option<Action>) {
        let s = self.s;
        card(ui, |ui| {
            ui.horizontal(|ui| {
                // Leave room for the switch so the note wraps before it.
                let text_width = ui.available_width() - 64.0;
                ui.allocate_ui_with_layout(egui::vec2(text_width, 0.0), Layout::top_down(Align::Min), |ui| {
                    ui.spacing_mut().item_spacing.y = 4.0;
                    card_title(ui, s.stay_awake_title);
                    ui.add(egui::Label::new(RichText::new(s.stay_awake_text).color(WEAK)).wrap());
                });
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let mut next = on;
                    if toggle(ui, &mut next, true).changed() {
                        *action = Some(Action::StayAwake(next));
                    }
                });
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
