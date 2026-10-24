//! File manager: two computers side by side, this one or any paired one on either side. It
//! connects for files only, so an open remote session carries on, and every transfer is its
//! own stream. Between two remote computers, files pass through this one.

use std::{
    collections::{BTreeSet, HashMap},
    path::PathBuf,
    sync::{Arc, Mutex},
};

use eframe::egui::{self, Align, Color32, CursorIcon, Layout, RichText, Sense, Stroke, StrokeKind, Vec2};
use velora_client_core::{
    files::{EntryKind, RemoteEntry as Entry},
    hosts, FilesSession, PasswordRequired, RemoteFiles,
};
use velora_protocol::{files as fs, identity::StateDir};

use super::{drop, file_icons, motion, strings::fill, theme::*, widgets::*, Strings};

const ROW_HEIGHT: f32 = 34.0;
/// One transfer: icon, name, details and its progress bar.
const TRANSFER_HEIGHT: f32 = 52.0;
/// How long a hint about where to drop stays up, in seconds.
const HINT_SECONDS: f64 = 4.0;
/// Space kept below the transfers card, so it never touches the window's bottom edge.
const BOTTOM_GAP: f32 = 16.0;

/// A pane's position.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Side {
    Left,
    Right,
}

impl Side {
    fn other(self) -> Self {
        match self {
            Self::Left => Self::Right,
            Self::Right => Self::Left,
        }
    }
}

/// The computer a pane shows.
#[derive(Clone, PartialEq, Eq)]
enum Machine {
    Local,
    /// A paired computer, by name.
    Remote(String),
}

/// What a pane shows. `path: None` is the list of drives and well-known folders.
#[derive(Default)]
struct Listing {
    path: Option<String>,
    entries: Vec<Entry>,
    loading: bool,
    error: Option<String>,
    /// Counts completed listings, so the pane notices new entries and lets them come in.
    version: u64,
}

struct Pane {
    machine: Machine,
    listing: Arc<Mutex<Listing>>,
    /// Folders opened before this one, for Back.
    history: Vec<Option<String>>,
    /// Selected entries, by full path.
    selected: BTreeSet<String>,
    /// The listing version on screen, and when it appeared.
    shown: (u64, f64),
    /// Where the pane was last drawn, to tell which one files from the system hover.
    rect: egui::Rect,
}

impl Pane {
    fn new(machine: Machine) -> Self {
        Self {
            machine,
            listing: Arc::default(),
            history: Vec::new(),
            selected: BTreeSet::new(),
            shown: (0, 0.0),
            rect: egui::Rect::NOTHING,
        }
    }
}

enum Link {
    Connecting,
    Ready(Arc<FilesSession>),
    Password { wrong: bool },
    Failed(String),
}

#[derive(Clone)]
enum TransferState {
    Running,
    Done,
    Failed(String),
}

struct Transfer {
    id: u64,
    label: String,
    /// Where it goes, by name, and whether that is another computer (whose user may be asked).
    to: String,
    to_remote: bool,
    /// Between two remote computers: the one it is first fetched from, while it is.
    fetching_from: Option<String>,
    done: u64,
    total: u64,
    state: TransferState,
    task: Option<tokio::task::AbortHandle>,
    /// When it started and, once over, ended (UI time, seconds).
    started: f64,
    ended: Option<f64>,
    /// Smoothed bytes per second, and the sample it was last measured from.
    speed: f64,
    sample: (f64, u64),
}

/// Dragged rows: where they come from and their paths.
#[derive(Clone)]
struct DragItems {
    from: Side,
    paths: Vec<String>,
}

type Update = Arc<dyn Fn(&mut dyn FnMut(&mut Transfer)) + Send + Sync>;

pub struct FileManager {
    config_dir: Option<PathBuf>,
    device_name: String,
    runtime: tokio::runtime::Runtime,
    /// File connections to paired computers, by name, opened as panes show them.
    links: HashMap<String, Arc<Mutex<Link>>>,
    /// Passwords being typed, by computer.
    passwords: HashMap<String, String>,
    left: Pane,
    right: Pane,
    transfers: Arc<Mutex<Vec<Transfer>>>,
    /// Height of the transfers card when last drawn, to leave room for it below the panes.
    transfers_drawn: f32,
    next_transfer: u64,
    /// Files dropped on a computer in Devices, sent to its Downloads once connected.
    pending: Vec<(String, Vec<String>)>,
    /// A word about where to drop, and when it was shown.
    hint: Option<(String, f64)>,
}

impl FileManager {
    /// This computer on the left, `host` on the right.
    pub fn open(
        host: String,
        config_dir: Option<PathBuf>,
        device_name: String,
        ctx: &egui::Context,
    ) -> anyhow::Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?;
        let mut manager = Self {
            config_dir,
            device_name,
            runtime,
            links: HashMap::new(),
            passwords: HashMap::new(),
            left: Pane::new(Machine::Local),
            right: Pane::new(Machine::Local),
            transfers: Arc::default(),
            transfers_drawn: 0.0,
            next_transfer: 0,
            pending: Vec::new(),
            hint: None,
        };
        manager.load(Side::Left, None, ctx);
        manager.show(Side::Right, Machine::Remote(host), ctx);
        Ok(manager)
    }

    /// Shows `host` on the right, unless a pane shows it already.
    pub fn show_host(&mut self, host: String, ctx: &egui::Context) {
        let machine = Machine::Remote(host);
        if self.left.machine != machine && self.right.machine != machine {
            self.show(Side::Right, machine, ctx);
        }
    }

    /// Sends `paths` from this computer to `host`'s Downloads, as soon as it is connected.
    pub fn send_when_ready(&mut self, host: String, paths: Vec<String>, ctx: &egui::Context) {
        self.link(&host, ctx);
        self.pending.push((host, paths));
    }

    /// The name shown for a computer.
    fn name(machine: &Machine, s: &Strings) -> String {
        match machine {
            Machine::Local => s.files_this_pc.to_string(),
            Machine::Remote(host) => host.clone(),
        }
    }

    /// The connection to `host`, opened if needed.
    fn link(&mut self, host: &str, ctx: &egui::Context) -> Arc<Mutex<Link>> {
        if let Some(link) = self.links.get(host) {
            return link.clone();
        }
        let link = Arc::new(Mutex::new(Link::Connecting));
        self.links.insert(host.to_string(), link.clone());
        self.connect(host, None, ctx);
        link
    }

    fn connect(&mut self, host: &str, password: Option<String>, ctx: &egui::Context) {
        let Some(link) = self.links.get(host).cloned() else { return };
        *link.lock().unwrap() = Link::Connecting;
        let ctx = ctx.clone();
        let (config_dir, host, name) = (self.config_dir.clone(), host.to_string(), self.device_name.clone());
        // Panes showing this computer list its places once connected.
        let panes: Vec<_> = [&self.left, &self.right]
            .into_iter()
            .filter(|p| p.machine == Machine::Remote(host.clone()))
            .map(|p| p.listing.clone())
            .collect();
        self.runtime.spawn(async move {
            let result = async {
                let state = StateDir::open(config_dir, "client")?;
                // A session of this computer through a relay to `host` keeps it: this connection would take it over.
                crate::free_relay(&state, &host, super::strings::current())?;
                hosts::connect_files(&state, &host, &name, password.as_deref()).await
            }
            .await;
            let next = match result {
                Ok(session) => {
                    let files = session.files.clone();
                    *link.lock().unwrap() = Link::Ready(Arc::new(session));
                    for listing in panes {
                        list_into(listing, Some(files.clone()), None, ctx.clone()).await;
                    }
                    return;
                }
                Err(e) => match e.downcast_ref::<PasswordRequired>() {
                    Some(p) => Link::Password { wrong: p.wrong },
                    None => Link::Failed(format!("{e:#}")),
                },
            };
            *link.lock().unwrap() = next;
            ctx.request_repaint();
        });
    }

    /// The file connection for a computer: `Ok(None)` for this one, `Err` while a remote one
    /// is not connected.
    fn files(&self, machine: &Machine) -> Result<Option<RemoteFiles>, ()> {
        match machine {
            Machine::Local => Ok(None),
            Machine::Remote(host) => match self.links.get(host).map(|l| l.lock().unwrap()).as_deref() {
                Some(Link::Ready(session)) => Ok(Some(session.files.clone())),
                _ => Err(()),
            },
        }
    }

    fn pane(&mut self, side: Side) -> &mut Pane {
        match side {
            Side::Left => &mut self.left,
            Side::Right => &mut self.right,
        }
    }

    /// Switches a pane to another computer, at its places.
    fn show(&mut self, side: Side, machine: Machine, ctx: &egui::Context) {
        if let Machine::Remote(host) = &machine {
            self.link(host, ctx);
        }
        let pane = self.pane(side);
        *pane = Pane::new(machine);
        self.load(side, None, ctx);
    }

    /// Shows `path` in a pane, listed in the background.
    fn load(&mut self, side: Side, path: Option<String>, ctx: &egui::Context) {
        let machine = self.pane(side).machine.clone();
        let Ok(files) = self.files(&machine) else { return };
        let pane = self.pane(side);
        pane.selected.clear();
        let listing = pane.listing.clone();
        let ctx = ctx.clone();
        self.runtime.spawn(list_into(listing, files, path, ctx));
    }

    fn navigate(&mut self, side: Side, path: Option<String>, ctx: &egui::Context) {
        let pane = self.pane(side);
        let current = pane.listing.lock().unwrap().path.clone();
        pane.history.push(current);
        self.load(side, path, ctx);
    }

    fn back(&mut self, side: Side, ctx: &egui::Context) {
        if let Some(previous) = self.pane(side).history.pop() {
            self.load(side, previous, ctx);
        }
    }

    /// Copies `paths` from one pane to the folder shown on the other.
    fn transfer(&mut self, from: Side, paths: Vec<String>, s: &Strings, ctx: &egui::Context) {
        let to = from.other();
        let (src, dst) = (self.pane(from).machine.clone(), self.pane(to).machine.clone());
        let dir = self.pane(to).listing.lock().unwrap().path.clone();
        self.copy(src, paths, dst, dir, s, ctx);
    }

    /// Copies `paths` from `src` into `dir` on `dst` (its Downloads when `None`), one transfer
    /// each. Between two remote computers, each goes through a temporary folder here.
    fn copy(
        &mut self,
        src: Machine,
        paths: Vec<String>,
        dst: Machine,
        dir: Option<String>,
        s: &Strings,
        ctx: &egui::Context,
    ) {
        let now = ctx.input(|i| i.time);
        if src == dst {
            self.hint = Some((s.files_same_machine.to_string(), now));
            return;
        }
        let (Ok(from), Ok(into)) = (self.files(&src), self.files(&dst)) else { return };
        for path in paths {
            let label = std::path::Path::new(&path)
                .file_name()
                .map_or_else(|| path.clone(), |n| n.to_string_lossy().into_owned());
            let id = self.next_transfer;
            self.next_transfer += 1;
            let relay = from.is_some() && into.is_some();
            self.transfers.lock().unwrap().push(Transfer {
                id,
                label,
                to: Self::name(&dst, s),
                to_remote: into.is_some(),
                fetching_from: relay.then(|| Self::name(&src, s)),
                done: 0,
                total: 0,
                state: TransferState::Running,
                task: None,
                started: now,
                ended: None,
                speed: 0.0,
                sample: (now, 0),
            });
            // Rows can be cleared while others run: find this one by id.
            let update: Update = {
                let transfers = self.transfers.clone();
                Arc::new(move |f: &mut dyn FnMut(&mut Transfer)| {
                    if let Some(t) = transfers.lock().unwrap().iter_mut().find(|t| t.id == id) {
                        f(t);
                    }
                })
            };
            let (ctx, from, into, dir) = (ctx.clone(), from.clone(), into.clone(), dir.clone());
            // Panes to refresh once it arrived, if they still show that folder.
            let shown: Vec<_> =
                [&self.left, &self.right].into_iter().filter(|p| p.machine == dst).map(|p| p.listing.clone()).collect();
            let task_update = update.clone();
            let handle = self.runtime.spawn(async move {
                let update = task_update;
                let result = copy_one(&from, &into, &path, dir.as_deref(), id, &update, &ctx).await;
                let state = match result {
                    Ok(()) => TransferState::Done,
                    Err(e) => TransferState::Failed(format!("{e:#}")),
                };
                update(&mut |t| t.state = state.clone());
                for listing in shown {
                    if listing.lock().unwrap().path == dir {
                        list_into(listing, into.clone(), dir.clone(), ctx.clone()).await;
                    }
                }
                ctx.request_repaint();
            });
            let task = handle.abort_handle();
            update(&mut |t| t.task = Some(task.clone()));
        }
    }

    /// `hosts`: the paired computers a pane can switch to.
    pub fn ui(&mut self, ui: &mut egui::Ui, s: &Strings, hosts: &[String]) {
        let ctx = ui.ctx().clone();
        let now = ctx.input(|i| i.time);

        // Drops from Devices go out once their computer is connected.
        let ready: Vec<_> = self
            .pending
            .iter()
            .enumerate()
            .filter(|(_, (host, _))| self.files(&Machine::Remote(host.clone())).is_ok())
            .map(|(i, _)| i)
            .collect();
        for i in ready.into_iter().rev() {
            let (host, paths) = self.pending.remove(i);
            self.copy(Machine::Local, paths, Machine::Remote(host), None, s, &ctx);
        }

        // Files from the system go to the pane under the pointer, when it shows another
        // computer; one showing this computer has them already, so it says where to drop.
        let hovering = drop::hovering(&ctx);
        let over = drop::pointer(&ctx)
            .and_then(|p| [Side::Left, Side::Right].into_iter().find(|side| self.pane(*side).rect.contains(p)));
        let dropped = drop::dropped(&ctx);
        if !dropped.is_empty() {
            let target = over.filter(|side| self.pane(*side).machine != Machine::Local).or_else(|| {
                // Dropped elsewhere on the page: the one remote pane, if there is just one.
                let remote: Vec<_> = [Side::Left, Side::Right]
                    .into_iter()
                    .filter(|side| self.pane(*side).machine != Machine::Local)
                    .collect();
                (over.is_none() && remote.len() == 1).then(|| remote[0])
            });
            match target {
                Some(side) => {
                    let (machine, dir) = {
                        let pane = self.pane(side);
                        (pane.machine.clone(), pane.listing.lock().unwrap().path.clone())
                    };
                    self.copy(Machine::Local, dropped, machine, dir, s, &ctx);
                }
                None => self.hint = Some((s.files_drop_remote_side.to_string(), now)),
            }
        }
        if hovering {
            ctx.request_repaint();
        }
        if let Some((hint, since)) = &self.hint {
            if now - since < HINT_SECONDS {
                ui.scope(|ui| {
                    ui.multiply_opacity(motion::progress(now, *since, 0.2));
                    banner(ui, hint, ACCENT_TEXT);
                });
                ui.add_space(12.0);
                ctx.request_repaint_after(std::time::Duration::from_millis(200));
            } else {
                self.hint = None;
            }
        }

        let transfers_height = self.transfers_height();
        let height = (ui.available_height() - transfers_height - 12.0 - BOTTOM_GAP).max(240.0);
        let gap = 16.0;
        let width = (ui.available_width() - gap) / 2.0;
        let mut drops = Vec::new();
        ui.horizontal_top(|ui| {
            for side in [Side::Left, Side::Right] {
                ui.allocate_ui_with_layout(Vec2::new(width, height), Layout::top_down(Align::Min), |ui| {
                    let os_over = hovering && over == Some(side);
                    if let Some(drop) = self.pane_ui(ui, s, side, height, os_over, hosts) {
                        drops.push(drop);
                    }
                });
                if side == Side::Left {
                    ui.add_space(gap - ui.spacing().item_spacing.x);
                }
            }
        });
        for items in drops {
            self.transfer(items.from, items.paths, s, &ctx);
        }
        if transfers_height > 0.0 {
            ui.add_space(12.0);
            self.transfers_ui(ui, s);
        }
        if self.transfers.lock().unwrap().iter().any(|t| matches!(t.state, TransferState::Running)) {
            ctx.request_repaint_after(std::time::Duration::from_millis(250));
        }
    }

    /// Picks the computer a pane shows: this one or a paired one.
    fn machine_menu(&mut self, ui: &mut egui::Ui, s: &Strings, side: Side, hosts: &[String]) {
        let current = self.pane(side).machine.clone();
        // Each computer keeps a color: teal for this one, violet for the others.
        let color = if current == Machine::Local { LIVE } else { ACCENT_TEXT };
        // A dot, the name and a chevron, on a tint under the pointer; a click lists the choices.
        let name = ui.painter().layout_no_wrap(Self::name(&current, s), font(14.5, semibold()), TEXT);
        let size = Vec2::new(10.0 + 8.0 + name.size().x + 22.0 + 12.0, 30.0);
        let (rect, button) = ui.allocate_exact_size(size, Sense::click());
        let hover = ui.ctx().animate_bool_with_time(button.id.with("hover"), button.hovered(), HOVER_SECONDS);
        let painter = ui.painter();
        painter.rect_filled(rect, RADIUS, HOVER.gamma_multiply(hover));
        let dot = egui::pos2(rect.left() + 11.0, rect.center().y);
        painter.circle_filled(dot, 4.0, color.gamma_multiply(0.25));
        painter.circle_filled(dot, 2.5, color);
        painter.galley(egui::pos2(rect.left() + 22.0, rect.center().y - name.size().y / 2.0), name, TEXT);
        let c = egui::pos2(rect.right() - 14.0, rect.center().y + 1.0);
        let chevron = vec![c + Vec2::new(-4.0, -2.0), c + Vec2::new(0.0, 2.0), c + Vec2::new(4.0, -2.0)];
        painter.add(egui::Shape::line(chevron, Stroke::new(1.5, WEAK.lerp_to_gamma(TEXT, hover))));
        let button = button.on_hover_cursor(CursorIcon::PointingHand);
        let mut pick = None;
        egui::Popup::menu(&button).show(|ui| {
            ui.set_min_width(rect.width().max(180.0));
            let mut choices = vec![Machine::Local];
            choices.extend(hosts.iter().map(|h| Machine::Remote(h.clone())));
            for machine in choices {
                let chosen = machine == current;
                let text = RichText::new(Self::name(&machine, s)).font(font(13.5, medium()));
                if ui.selectable_label(chosen, text).clicked() {
                    pick = Some(machine);
                    ui.close();
                }
            }
        });
        if let Some(machine) = pick.filter(|m| *m != current) {
            self.show(side, machine, ui.ctx());
        }
    }

    /// A remote pane before its computer is connected: connecting, its password, or why not.
    fn link_ui(&mut self, ui: &mut egui::Ui, s: &Strings, host: &str) {
        let ctx = ui.ctx().clone();
        let state = match self.links.get(host).map(|l| l.lock().unwrap()).as_deref() {
            Some(Link::Password { wrong }) => Err(Some(*wrong)),
            Some(Link::Failed(e)) => Ok(Some(e.clone())),
            _ => Ok(None),
        };
        egui::Frame::new().inner_margin(egui::Margin::symmetric(18, 18)).show(ui, |ui| match state {
            Ok(None) => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(RichText::new(fill(s.files_connecting, &[host])).color(WEAK));
                });
            }
            Ok(Some(error)) => {
                ui.add(egui::Label::new(RichText::new(error).color(ERROR)).wrap());
                ui.add_space(10.0);
                if small_button(ui, s.files_retry, true).clicked() {
                    self.connect(host, None, &ctx);
                }
            }
            Err(wrong) => {
                ui.set_max_width(320.0);
                card_title(ui, &fill(s.password_prompt_title, &[host]));
                ui.add_space(4.0);
                let wrong = wrong.unwrap_or(false);
                let (text, color) = if wrong { (s.password_wrong, ERROR) } else { (s.password_prompt_text, WEAK) };
                ui.add(egui::Label::new(RichText::new(text).color(color)).wrap());
                ui.add_space(10.0);
                let draft = self.passwords.entry(host.to_string()).or_default();
                let field = ui.add(field(draft, s.password_field, false).password(true));
                let enter = field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                ui.add_space(12.0);
                let ready = !draft.is_empty();
                if (primary_button(ui, s.connect_short, 140.0, ready).clicked() || enter) && ready {
                    let password = std::mem::take(draft);
                    self.connect(host, Some(password), &ctx);
                }
            }
        });
    }

    /// One side: which computer, path and actions, then the entries. Returns rows dropped on
    /// it from the other side. `os_over`: files from the system hover this pane.
    fn pane_ui(
        &mut self,
        ui: &mut egui::Ui,
        s: &Strings,
        side: Side,
        height: f32,
        os_over: bool,
        hosts: &[String],
    ) -> Option<DragItems> {
        let ctx = ui.ctx().clone();
        let now = ctx.input(|i| i.time);
        let machine = self.pane(side).machine.clone();
        let other = self.pane(side.other()).machine.clone();
        let connected = self.files(&machine).is_ok();
        let (path, loading, error, entries, version) = {
            let l = self.pane(side).listing.lock().unwrap();
            (l.path.clone(), l.loading, l.error.clone(), l.entries.clone(), l.version)
        };
        // A new listing comes in row after row.
        let pane = self.pane(side);
        if pane.shown.0 != version {
            pane.shown = (version, now);
        }
        let shown_at = pane.shown.1;
        if now - shown_at < 0.6 {
            ctx.request_repaint();
        }
        let mut open = None;
        let mut send = false;
        let frame = egui::Frame::new().fill(CARD).stroke(Stroke::new(1.0, BORDER)).corner_radius(CARD_RADIUS);
        let response = frame
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.set_height(height);
                egui::Frame::new().inner_margin(egui::Margin::symmetric(14, 12)).show(ui, |ui| {
                    // The computer on its own line; under it the folder, with the actions at its
                    // right, so a narrow pane cuts the path rather than overlapping.
                    ui.horizontal(|ui| self.machine_menu(ui, s, side, hosts));
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            let selected = !copyable(&entries, &self.pane(side).selected).is_empty();
                            let label = match side {
                                Side::Left => fill(s.files_send_to, &[&Self::name(&other, s)]),
                                Side::Right => fill(s.files_send_back, &[&Self::name(&other, s)]),
                            };
                            if small_button(ui, &label, selected && connected).clicked() {
                                send = true;
                            }
                            if small_button(ui, s.files_places, path.is_some()).clicked() {
                                open = Some(None);
                            }
                            if small_button(ui, s.files_back, !self.pane(side).history.is_empty()).clicked() {
                                self.back(side, &ctx);
                            }
                            ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                                let shown = path.clone().unwrap_or_else(|| s.files_places.to_string());
                                ui.add(egui::Label::new(RichText::new(shown).font(mono(12.0)).color(WEAK)).truncate());
                            });
                        });
                    });
                });
                let top = ui.cursor().min.y;
                ui.painter().hline(ui.max_rect().x_range(), top, Stroke::new(1.0, BORDER));
                if let (false, Machine::Remote(host)) = (connected, &machine) {
                    self.link_ui(ui, s, host);
                } else if let Some(error) = &error {
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        ui.add_space(14.0);
                        ui.add(egui::Label::new(RichText::new(error).color(ERROR)).wrap());
                    });
                } else if loading && entries.is_empty() {
                    ui.add_space(14.0);
                    ui.vertical_centered(|ui| ui.spinner());
                } else if entries.is_empty() {
                    ui.add_space(14.0);
                    ui.vertical_centered(|ui| ui.label(RichText::new(s.files_empty).color(FAINT)));
                } else {
                    egui::ScrollArea::vertical().id_salt(side as u8).auto_shrink([false, false]).show_rows(
                        ui,
                        ROW_HEIGHT,
                        entries.len(),
                        |ui, range| {
                            let first = range.start;
                            for (i, entry) in entries[range].iter().enumerate() {
                                let delay = ((first + i) as f64 * 0.018).min(0.3);
                                let appear = motion::progress(now, shown_at + delay, 0.22);
                                if let Some(action) = self.row(ui, side, entry, &entries, appear) {
                                    open = Some(Some(action));
                                }
                            }
                        },
                    );
                }
            })
            .response;
        if let Some(target) = open {
            self.navigate(side, target, &ctx);
        }
        if send {
            let paths = copyable(&entries, &self.pane(side).selected);
            return Some(DragItems { from: side, paths });
        }
        self.pane(side).rect = response.rect;
        // Rows dragged from the other pane, or files from the system.
        let dropped = response.dnd_release_payload::<DragItems>().filter(|d| d.from != side);
        let rows_over = response.dnd_hover_payload::<DragItems>().is_some_and(|d| d.from != side);
        let label = match &machine {
            Machine::Local if os_over => s.files_drop_remote_side.to_string(),
            Machine::Local => s.files_drop_download.to_string(),
            Machine::Remote(host) => fill(s.files_drop_send, &[host]),
        };
        let t = ctx.animate_bool_with_time(response.id.with("drop"), rows_over || os_over, 0.15);
        if t > 0.0 {
            drop::target(ui.painter(), response.rect, &label, now, t);
            ctx.request_repaint();
        }
        dropped.map(|d| (*d).clone())
    }

    /// One entry. Click selects (Ctrl adds, Shift extends), double click opens folders, and
    /// selected rows can be dragged to the other pane. Returns a folder to open.
    /// `appear` (0 to 1) fades the row in and slides it into place.
    fn row(&mut self, ui: &mut egui::Ui, side: Side, entry: &Entry, entries: &[Entry], appear: f32) -> Option<String> {
        let (slot, response) =
            ui.allocate_exact_size(Vec2::new(ui.available_width(), ROW_HEIGHT), Sense::click_and_drag());
        let rect = slot.translate(Vec2::new((1.0 - appear) * 12.0, 0.0));
        let ui = &mut ui.new_child(egui::UiBuilder::new().max_rect(slot));
        ui.multiply_opacity(appear);
        let pane = self.pane(side);
        let selected = pane.selected.contains(&entry.path);
        let hover = ui.ctx().animate_bool_with_time(response.id.with("hover"), response.hovered(), HOVER_SECONDS);
        let fill = if selected { ACCENT.gamma_multiply(0.18) } else { Color32::from_white_alpha((5.0 * hover) as u8) };
        ui.painter().rect_filled(rect.shrink2(Vec2::new(6.0, 1.0)), RADIUS, fill);
        let icon = egui::Rect::from_center_size(egui::pos2(rect.left() + 26.0, rect.center().y), Vec2::splat(20.0));
        file_icons::paint(ui.painter(), icon, entry.kind, &entry.name);
        let size = match entry.kind {
            EntryKind::File => human_size(entry.size),
            _ => String::new(),
        };
        let size_galley = ui.painter().layout_no_wrap(size, font(12.0, medium()), FAINT);
        let name_width = rect.width() - 56.0 - size_galley.size().x - 16.0;
        let name = ui.painter().layout_no_wrap(entry.name.clone(), font(13.5, medium()), TEXT);
        // One line: cut long names rather than wrapping.
        let clip =
            egui::Rect::from_min_size(egui::pos2(rect.left() + 44.0, rect.top()), Vec2::new(name_width, rect.height()));
        ui.painter().with_clip_rect(clip).galley(
            egui::pos2(clip.left(), rect.center().y - name.size().y / 2.0),
            name,
            TEXT,
        );
        ui.painter().galley(
            egui::pos2(rect.right() - 16.0 - size_galley.size().x, rect.center().y - size_galley.size().y / 2.0),
            size_galley,
            FAINT,
        );

        let folder = entry.kind != EntryKind::File;
        if response.double_clicked() && folder {
            return Some(entry.path.clone());
        }
        if response.clicked() {
            let modifiers = ui.input(|i| i.modifiers);
            if modifiers.command {
                if !pane.selected.remove(&entry.path) {
                    pane.selected.insert(entry.path.clone());
                }
            } else if modifiers.shift && !pane.selected.is_empty() {
                let anchor = entries.iter().position(|e| pane.selected.contains(&e.path)).unwrap_or(0);
                let here = entries.iter().position(|e| e.path == entry.path).unwrap_or(anchor);
                let (a, b) = (anchor.min(here), anchor.max(here));
                pane.selected.extend(entries[a..=b].iter().map(|e| e.path.clone()));
            } else {
                pane.selected = BTreeSet::from([entry.path.clone()]);
            }
        }
        // Places are not files: they can be opened, not copied.
        if entry.kind != EntryKind::Place && response.drag_started() {
            if !pane.selected.contains(&entry.path) {
                pane.selected = BTreeSet::from([entry.path.clone()]);
            }
            response.dnd_set_drag_payload(DragItems { from: side, paths: copyable(entries, &pane.selected) });
        }
        if response.hovered() {
            ui.ctx().set_cursor_icon(if folder { CursorIcon::PointingHand } else { CursorIcon::Default });
        }
        None
    }

    /// Room the transfers card takes: as last drawn, or an estimate before its first frame.
    fn transfers_height(&self) -> f32 {
        let n = self.transfers.lock().unwrap().len().min(4);
        if n == 0 {
            0.0
        } else if self.transfers_drawn > 0.0 {
            self.transfers_drawn
        } else {
            90.0 + n as f32 * TRANSFER_HEIGHT
        }
    }

    fn transfers_ui(&mut self, ui: &mut egui::Ui, s: &Strings) {
        let now = ui.input(|i| i.time);
        let mut clear = false;
        let drawn = card(ui, |ui| {
            ui.horizontal(|ui| {
                card_title(ui, s.files_transfers);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let finished =
                        self.transfers.lock().unwrap().iter().any(|t| !matches!(t.state, TransferState::Running));
                    if small_button(ui, s.files_clear, finished).clicked() {
                        clear = true;
                    }
                });
            });
            ui.add_space(4.0);
            let mut transfers = self.transfers.lock().unwrap();
            // Scroll within what is left of the window rather than run past its bottom.
            let rows = (4.0 * TRANSFER_HEIGHT).min(ui.available_height() - BOTTOM_GAP).max(TRANSFER_HEIGHT);
            egui::ScrollArea::vertical().id_salt("transfers").max_height(rows).show(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 0.0;
                for transfer in transfers.iter_mut().rev() {
                    track(transfer, now);
                    transfer_row(ui, s, transfer, now);
                }
            });
            if transfers.iter().any(|t| t.ended.is_none_or(|end| now - end < 1.0)) {
                ui.ctx().request_repaint();
            }
        });
        self.transfers_drawn = drawn.response.rect.height();
        if clear {
            self.transfers.lock().unwrap().retain(|t| matches!(t.state, TransferState::Running));
            self.transfers_drawn = 0.0;
        }
    }
}

/// Measures speed every half second, smoothed, and notes when a transfer ends.
fn track(t: &mut Transfer, now: f64) {
    if !matches!(t.state, TransferState::Running) {
        t.ended.get_or_insert(now);
        return;
    }
    let (at, bytes) = t.sample;
    let dt = now - at;
    if dt >= 0.5 {
        let rate = t.done.saturating_sub(bytes) as f64 / dt;
        t.speed = if t.speed == 0.0 { rate } else { 0.7 * t.speed + 0.3 * rate };
        t.sample = (now, t.done);
    }
}

/// One transfer: the file's icon, its name, where it goes with size, speed and time left, and
/// a progress bar with a sheen running along it. Ends with a check mark or a cross.
fn transfer_row(ui: &mut egui::Ui, s: &Strings, t: &mut Transfer, now: f64) {
    let appear = motion::progress(now, t.started, 0.25);
    let (slot, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), TRANSFER_HEIGHT), Sense::hover());
    let rect = slot.translate(Vec2::new(0.0, (1.0 - appear) * 8.0));
    let ui = &mut ui.new_child(egui::UiBuilder::new().max_rect(slot));
    ui.multiply_opacity(appear);
    let painter = ui.painter().clone();

    let icon = egui::Rect::from_center_size(egui::pos2(rect.left() + 12.0, rect.top() + 20.0), Vec2::splat(22.0));
    file_icons::paint(&painter, icon, EntryKind::File, &t.label);
    let left = rect.left() + 36.0;
    let right_room = 120.0;

    let name = painter.layout_no_wrap(t.label.clone(), font(13.5, medium()), TEXT);
    let clip =
        egui::Rect::from_min_max(egui::pos2(left, rect.top()), egui::pos2(rect.right() - right_room, rect.bottom()));
    painter.with_clip_rect(clip).galley(egui::pos2(left, rect.top() + 4.0), name, TEXT);

    let mut details = vec![match &t.fetching_from {
        Some(from) => fill(s.files_fetching, &[from, &t.to]),
        None => fill(s.files_to, &[&t.to]),
    }];
    let (detail_color, bar_color) = match &t.state {
        // Everything sent, but the other computer has not said it saved it: its user is asked.
        TransferState::Running if t.to_remote && t.fetching_from.is_none() && t.total > 0 && t.done >= t.total => {
            details.push(fill(s.files_waiting, &[&t.to]));
            (ACCENT_TEXT, ACCENT)
        }
        TransferState::Running => {
            if t.total > 0 {
                details.push(fill(s.files_of, &[&human_size(t.done), &human_size(t.total)]));
            }
            if t.speed > 0.0 {
                details.push(format!("{}/s", human_size(t.speed as u64)));
                if t.total > t.done {
                    let left = (t.total - t.done) as f64 / t.speed;
                    details.push(fill(s.files_left, &[&duration(left)]));
                }
            }
            (WEAK, ACCENT)
        }
        TransferState::Done => {
            details.push(human_size(t.total));
            details.push(s.files_done.to_string());
            (WEAK, LIVE)
        }
        TransferState::Failed(e) => {
            details = vec![fill(s.files_failed, &[e])];
            (ERROR, ERROR)
        }
    };
    let line = painter.layout_no_wrap(details.join(" · "), font(12.0, medium()), detail_color);
    painter.with_clip_rect(clip).galley(egui::pos2(left, rect.top() + 23.0), line, detail_color);

    // Progress: full while running, then it fades as the mark takes over.
    let fraction = match t.state {
        TransferState::Done => 1.0,
        _ if t.total == 0 => 0.0,
        _ => t.done as f32 / t.total as f32,
    };
    let fade = t.ended.map_or(1.0, |end| 1.0 - motion::progress(now, end + 0.4, 0.5));
    if fade > 0.0 {
        let bar = egui::Rect::from_min_max(
            egui::pos2(left, rect.bottom() - 10.0),
            egui::pos2(rect.right() - 12.0, rect.bottom() - 6.0),
        );
        painter.rect_filled(bar, 2.0, BORDER.gamma_multiply(fade));
        let done = egui::Rect::from_min_size(bar.min, Vec2::new(bar.width() * fraction.clamp(0.0, 1.0), bar.height()));
        painter.rect_filled(done, 2.0, bar_color.gamma_multiply(fade));
        if matches!(t.state, TransferState::Running) && done.width() > 4.0 {
            sheen(&painter.with_clip_rect(done), done, now);
        }
    }

    let mark = egui::pos2(rect.right() - 24.0, rect.top() + 18.0);
    match &t.state {
        TransferState::Running => {
            let percent = (fraction * 100.0).round() as u32;
            let text = painter.layout_no_wrap(format!("{percent}%"), font(12.5, semibold()), ACCENT_TEXT);
            let cancel_rect = egui::Rect::from_min_max(
                egui::pos2(rect.right() - right_room + 8.0, rect.top() + 4.0),
                egui::pos2(rect.right() - 4.0, rect.top() + 32.0),
            );
            let mut child =
                ui.new_child(egui::UiBuilder::new().max_rect(cancel_rect).layout(Layout::right_to_left(Align::Center)));
            if small_button(&mut child, s.cancel_short, true).clicked() {
                if let Some(task) = t.task.take() {
                    task.abort();
                }
                t.state = TransferState::Failed(s.files_cancelled.into());
            }
            let x = child.min_rect().left() - 8.0 - text.size().x;
            painter.galley(egui::pos2(x, rect.top() + 18.0 - text.size().y / 2.0), text, ACCENT_TEXT);
        }
        TransferState::Done => motion::done_mark(&painter, mark, 10.0, now - t.ended.unwrap_or(now)),
        TransferState::Failed(_) => motion::failed_mark(&painter, mark, 10.0, now - t.ended.unwrap_or(now)),
    }
}

/// A soft light band sweeping along a progress bar, so a slow transfer still looks alive.
fn sheen(painter: &egui::Painter, bar: egui::Rect, now: f64) {
    let width = 48.0;
    let travel = bar.width() + width * 2.0;
    let x = bar.left() - width + ((now as f32 * 120.0) % travel);
    let clear = Color32::TRANSPARENT;
    let light = Color32::from_white_alpha(70);
    let mut mesh = egui::Mesh::default();
    for (dx, color) in [(0.0, clear), (width / 2.0, light), (width, clear)] {
        mesh.colored_vertex(egui::pos2(x + dx, bar.top()), color);
        mesh.colored_vertex(egui::pos2(x + dx, bar.bottom()), color);
    }
    for i in 0..2u32 {
        let a = i * 2;
        mesh.add_triangle(a, a + 1, a + 2);
        mesh.add_triangle(a + 1, a + 3, a + 2);
    }
    painter.add(egui::Shape::mesh(mesh));
}

/// `12 s`, `3 min 5 s`, `1 h 20 min`.
fn duration(seconds: f64) -> String {
    let s = seconds.max(0.0).round() as u64;
    match s {
        0..60 => format!("{s} s"),
        60..3600 => format!("{} min {} s", s / 60, s % 60),
        _ => format!("{} h {} min", s / 3600, s % 3600 / 60),
    }
}

impl Drop for FileManager {
    fn drop(&mut self) {
        for link in self.links.values() {
            if let Link::Ready(session) = &*link.lock().unwrap() {
                session.close();
            }
        }
    }
}

/// The selected entries that can be copied: files and folders, not drives or places.
fn copyable(entries: &[Entry], selected: &BTreeSet<String>) -> Vec<String> {
    entries
        .iter()
        .filter(|e| e.kind != EntryKind::Place && selected.contains(&e.path))
        .map(|e| e.path.clone())
        .collect()
}

/// Copies one file or folder for [`FileManager::copy`]; `from` and `into` are `None` for this
/// computer. Between two remote computers it is fetched into a temporary folder here, then
/// sent on, and the folder is removed either way.
async fn copy_one(
    from: &Option<RemoteFiles>,
    into: &Option<RemoteFiles>,
    path: &str,
    dir: Option<&str>,
    id: u64,
    update: &Update,
    ctx: &egui::Context,
) -> anyhow::Result<()> {
    let mut progress = |done: u64, total: u64| {
        update(&mut |t| (t.done, t.total) = (done, total));
        ctx.request_repaint();
    };
    match (from, into) {
        (None, Some(into)) => into.upload(vec![PathBuf::from(path)], dir.unwrap_or(""), &mut progress).await.map(drop),
        (Some(from), None) => {
            let dest = match dir {
                Some(dir) => PathBuf::from(dir),
                None => fs::downloads_dir()?,
            };
            from.download(path, &dest, &mut progress).await.map(drop)
        }
        (Some(from), Some(into)) => {
            let temp = std::env::temp_dir().join(format!("velora-relay-{}-{id}", std::process::id()));
            tokio::fs::create_dir_all(&temp).await?;
            let result = async {
                let names = from.download(path, &temp, &mut progress).await?;
                update(&mut |t| {
                    t.fetching_from = None;
                    (t.done, t.speed, t.sample.1) = (0, 0.0, 0);
                });
                let sources = names.iter().map(|n| temp.join(n)).collect();
                into.upload(sources, dir.unwrap_or(""), &mut progress).await.map(drop)
            }
            .await;
            let _ = tokio::fs::remove_dir_all(&temp).await;
            result
        }
        (None, None) => anyhow::bail!("both sides are this computer"),
    }
}

/// Lists `path` (or the places) into `listing`: on the computer of `files`, or this one.
async fn list_into(listing: Arc<Mutex<Listing>>, files: Option<RemoteFiles>, path: Option<String>, ctx: egui::Context) {
    {
        let mut l = listing.lock().unwrap();
        l.loading = true;
        l.error = None;
    }
    ctx.request_repaint();
    let result = match files {
        Some(files) => match &path {
            Some(path) => files.list(path).await,
            None => files.roots().await,
        },
        _ => {
            let path = path.clone();
            tokio::task::spawn_blocking(move || match path {
                Some(path) => fs::list(std::path::Path::new(&path)),
                None => Ok(fs::roots()),
            })
            .await
            .unwrap_or_else(|e| Err(e.into()))
        }
    };
    let mut l = listing.lock().unwrap();
    l.loading = false;
    l.version += 1;
    l.path = path;
    match result {
        Ok(entries) => l.entries = entries,
        Err(e) => {
            l.entries.clear();
            l.error = Some(format!("{e:#}"));
        }
    }
    ctx.request_repaint();
}

/// A compact outlined button for pane headers.
fn small_button(ui: &mut egui::Ui, text: &str, enabled: bool) -> egui::Response {
    let galley = ui.painter().layout_no_wrap(text.to_string(), font(12.5, medium()), TEXT);
    let size = Vec2::new(galley.size().x + 20.0, 28.0);
    let sense = if enabled { Sense::click() } else { Sense::hover() };
    let (rect, response) = ui.allocate_exact_size(size, sense);
    let hover =
        ui.ctx().animate_bool_with_time(response.id.with("hover"), enabled && response.hovered(), HOVER_SECONDS);
    let fill = Color32::TRANSPARENT.lerp_to_gamma(HOVER, hover);
    let edge = if enabled { BORDER_STRONG } else { BORDER };
    ui.painter().rect(rect, RADIUS, fill, Stroke::new(1.0, edge), StrokeKind::Inside);
    let color = if enabled { TEXT } else { FAINT };
    ui.painter().galley(rect.center() - galley.size() / 2.0, galley, color);
    if enabled {
        response.on_hover_cursor(CursorIcon::PointingHand)
    } else {
        response
    }
}

/// `1.5 MB`, in powers of 1000 as file managers show them.
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1000.0 && unit < UNITS.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use velora_protocol::{identity::KnownHost, tls::Fingerprint};

    use super::*;

    /// Whichever way a pane asks for a computer (opening, switching, Retry), a session that holds the relay to it is
    /// not displaced: the pane says so in the user's language and nothing is dialed (the address is a documentation one).
    #[test]
    fn a_pane_for_a_computer_that_a_session_holds_the_relay_to_says_so_and_dials_nothing() {
        let dir = std::env::temp_dir().join(format!("velora-p2-files-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let state = StateDir::open(Some(dir.clone()), "client").unwrap();
        let office = KnownHost {
            name: "Office PC".into(),
            address: "192.0.2.10:7420".into(),
            fingerprint: Fingerprint([1; 32]).to_base64(),
            ..Default::default()
        };
        state.save(StateDir::KNOWN_HOSTS, &vec![office.clone()]).unwrap();
        let _session = crate::claim_relay(&state, &office.fingerprint).expect("a session takes the relay");

        let manager =
            FileManager::open("Office PC".into(), Some(dir.clone()), "Test PC".into(), &egui::Context::default())
                .unwrap();
        let expected = fill(super::super::strings::current().relay_busy, &["Office PC"]);
        let began = Instant::now();
        let shown = loop {
            let link = manager.links.get("Office PC").unwrap().clone();
            if let Link::Failed(error) = &*link.lock().unwrap() {
                break error.clone();
            }
            assert!(began.elapsed() < Duration::from_secs(10), "the pane never said why it did not connect");
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(shown, expected);
        drop(manager);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sizes_read_like_a_file_manager() {
        assert_eq!(super::human_size(0), "0 B");
        assert_eq!(super::human_size(999), "999 B");
        assert_eq!(super::human_size(1_500_000), "1.5 MB");
        assert_eq!(super::human_size(3_000_000_000), "3.0 GB");
    }

    #[test]
    fn durations_read_naturally() {
        assert_eq!(super::duration(12.4), "12 s");
        assert_eq!(super::duration(185.0), "3 min 5 s");
        assert_eq!(super::duration(4800.0), "1 h 20 min");
    }
}
