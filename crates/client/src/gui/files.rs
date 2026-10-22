//! File manager: this computer and a paired one side by side. It connects for files only, so
//! an open remote session carries on, and every transfer is its own stream.

use std::{
    collections::BTreeSet,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use eframe::egui::{self, Align, Color32, CursorIcon, Layout, RichText, Sense, Stroke, StrokeKind, Vec2};
use velora_client_core::{
    files::{EntryKind, RemoteEntry as Entry},
    hosts, FilesSession, PasswordRequired, RemoteFiles,
};
use velora_protocol::{files as fs, identity::StateDir};

use super::{strings::fill, theme::*, widgets::*, Strings};

const ROW_HEIGHT: f32 = 34.0;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Side {
    Local,
    Remote,
}

/// What a pane shows. `path: None` is the list of drives and well-known folders.
#[derive(Default)]
struct Listing {
    path: Option<String>,
    entries: Vec<Entry>,
    loading: bool,
    error: Option<String>,
}

struct Pane {
    listing: Arc<Mutex<Listing>>,
    /// Folders opened before this one, for Back.
    history: Vec<Option<String>>,
    /// Selected entries, by full path.
    selected: BTreeSet<String>,
}

impl Pane {
    fn new() -> Self {
        Self { listing: Arc::default(), history: Vec::new(), selected: BTreeSet::new() }
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
    upload: bool,
    done: u64,
    total: u64,
    state: TransferState,
    task: Option<tokio::task::AbortHandle>,
}

/// Dragged rows: where they come from and their paths.
#[derive(Clone)]
struct DragItems {
    from: Side,
    paths: Vec<String>,
}

pub struct FileManager {
    pub host: String,
    config_dir: Option<PathBuf>,
    device_name: String,
    runtime: tokio::runtime::Runtime,
    link: Arc<Mutex<Link>>,
    local: Pane,
    remote: Pane,
    transfers: Arc<Mutex<Vec<Transfer>>>,
    next_transfer: u64,
    password: String,
}

impl FileManager {
    pub fn open(
        host: String,
        config_dir: Option<PathBuf>,
        device_name: String,
        ctx: &egui::Context,
    ) -> anyhow::Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?;
        let mut manager = Self {
            host,
            config_dir,
            device_name,
            runtime,
            link: Arc::new(Mutex::new(Link::Connecting)),
            local: Pane::new(),
            remote: Pane::new(),
            transfers: Arc::default(),
            next_transfer: 0,
            password: String::new(),
        };
        manager.connect(None, ctx);
        manager.load(Side::Local, None, ctx);
        Ok(manager)
    }

    fn connect(&mut self, password: Option<String>, ctx: &egui::Context) {
        *self.link.lock().unwrap() = Link::Connecting;
        let (link, ctx) = (self.link.clone(), ctx.clone());
        let (config_dir, host, name) = (self.config_dir.clone(), self.host.clone(), self.device_name.clone());
        let remote = self.remote.listing.clone();
        self.runtime.spawn(async move {
            let result = async {
                let state = StateDir::open(config_dir, "client")?;
                hosts::connect_files(&state, &host, &name, password.as_deref()).await
            }
            .await;
            let next = match result {
                Ok(session) => {
                    let files = session.files.clone();
                    *link.lock().unwrap() = Link::Ready(Arc::new(session));
                    list_into(remote, Side::Remote, Some(files), None, ctx.clone()).await;
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

    fn files(&self) -> Option<RemoteFiles> {
        match &*self.link.lock().unwrap() {
            Link::Ready(session) => Some(session.files.clone()),
            _ => None,
        }
    }

    fn pane(&mut self, side: Side) -> &mut Pane {
        match side {
            Side::Local => &mut self.local,
            Side::Remote => &mut self.remote,
        }
    }

    /// Shows `path` in a pane, listed in the background.
    fn load(&mut self, side: Side, path: Option<String>, ctx: &egui::Context) {
        let files = self.files();
        if side == Side::Remote && files.is_none() {
            return;
        }
        let pane = self.pane(side);
        pane.selected.clear();
        let listing = pane.listing.clone();
        let ctx = ctx.clone();
        self.runtime.spawn(list_into(listing, side, files, path, ctx));
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

    /// Copies `paths` from one side to the folder shown on the other (Downloads when it shows
    /// the list of places), one transfer each.
    fn transfer(&mut self, from: Side, paths: Vec<String>, ctx: &egui::Context) {
        let Some(files) = self.files() else { return };
        let target = match from {
            Side::Local => self.remote.listing.lock().unwrap().path.clone(),
            Side::Remote => self.local.listing.lock().unwrap().path.clone(),
        };
        for path in paths {
            let label = std::path::Path::new(&path)
                .file_name()
                .map_or_else(|| path.clone(), |n| n.to_string_lossy().into_owned());
            let upload = from == Side::Local;
            let id = self.next_transfer;
            self.next_transfer += 1;
            let row = Transfer { id, label, upload, done: 0, total: 0, state: TransferState::Running, task: None };
            self.transfers.lock().unwrap().push(row);
            // Rows can be cleared while others run: find this one by id.
            let update = {
                let transfers = self.transfers.clone();
                move |f: &mut dyn FnMut(&mut Transfer)| {
                    if let Some(t) = transfers.lock().unwrap().iter_mut().find(|t| t.id == id) {
                        f(t);
                    }
                }
            };
            let (ctx, files, target) = (ctx.clone(), files.clone(), target.clone());
            let (local, remote) = (self.local.listing.clone(), self.remote.listing.clone());
            let task_update = update.clone();
            let handle = self.runtime.spawn(async move {
                let update = task_update;
                let mut progress = |done: u64, total: u64| {
                    update(&mut |t| (t.done, t.total) = (done, total));
                    ctx.request_repaint();
                };
                let result = if upload {
                    files.upload(vec![PathBuf::from(&path)], target.as_deref().unwrap_or(""), &mut progress).await
                } else {
                    let dest = match &target {
                        Some(dir) => Ok(PathBuf::from(dir)),
                        None => fs::downloads_dir(),
                    };
                    match dest {
                        Ok(dest) => files.download(&path, &dest, &mut progress).await,
                        Err(e) => Err(e),
                    }
                };
                let state = match result {
                    Ok(_) => TransferState::Done,
                    Err(e) => TransferState::Failed(format!("{e:#}")),
                };
                update(&mut |t| t.state = state.clone());
                // Show what arrived, if that folder is still on screen.
                let (listing, side, files) =
                    if upload { (remote, Side::Remote, Some(files)) } else { (local, Side::Local, None) };
                if listing.lock().unwrap().path == target {
                    list_into(listing, side, files, target, ctx.clone()).await;
                }
                ctx.request_repaint();
            });
            let task = handle.abort_handle();
            update(&mut |t| t.task = Some(task.clone()));
        }
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, s: &Strings) {
        let ctx = ui.ctx().clone();
        enum View {
            Connecting,
            Ready,
            Password(bool),
            Failed(String),
        }
        let view = match &*self.link.lock().unwrap() {
            Link::Connecting => View::Connecting,
            Link::Ready(_) => View::Ready,
            Link::Password { wrong } => View::Password(*wrong),
            Link::Failed(e) => View::Failed(e.clone()),
        };
        match view {
            View::Connecting => {
                card(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(RichText::new(fill(s.files_connecting, &[&self.host])).color(WEAK));
                    });
                });
                return;
            }
            View::Password(wrong) => return self.password_card(ui, s, wrong),
            View::Failed(error) => {
                banner(ui, &error, ERROR);
                ui.add_space(12.0);
                if secondary_button(ui, s.files_retry).clicked() {
                    self.connect(None, &ctx);
                }
                return;
            }
            View::Ready => {}
        }

        // Files dropped from the system onto the window go to the remote folder.
        let dropped: Vec<String> = ui.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .map(|f| f.path())
                .filter(|p| p.is_absolute())
                .map(|p| p.display().to_string())
                .collect()
        });
        if !dropped.is_empty() {
            self.transfer(Side::Local, dropped, &ctx);
        }

        let transfers_height = self.transfers_height();
        let height = (ui.available_height() - transfers_height - 12.0).max(240.0);
        let gap = 16.0;
        let width = (ui.available_width() - gap) / 2.0;
        let mut drops = Vec::new();
        ui.horizontal_top(|ui| {
            for side in [Side::Local, Side::Remote] {
                ui.allocate_ui_with_layout(Vec2::new(width, height), Layout::top_down(Align::Min), |ui| {
                    if let Some(drop) = self.pane_ui(ui, s, side, height) {
                        drops.push(drop);
                    }
                });
                if side == Side::Local {
                    ui.add_space(gap - ui.spacing().item_spacing.x);
                }
            }
        });
        for items in drops {
            self.transfer(items.from, items.paths, &ctx);
        }
        if transfers_height > 0.0 {
            ui.add_space(12.0);
            self.transfers_ui(ui, s);
        }
        if self.transfers.lock().unwrap().iter().any(|t| matches!(t.state, TransferState::Running)) {
            ctx.request_repaint_after(std::time::Duration::from_millis(250));
        }
    }

    fn password_card(&mut self, ui: &mut egui::Ui, s: &Strings, wrong: bool) {
        let ctx = ui.ctx().clone();
        card(ui, |ui| {
            ui.set_max_width(380.0);
            card_title(ui, &fill(s.password_prompt_title, &[&self.host]));
            ui.add_space(4.0);
            let (text, color) = if wrong { (s.password_wrong, ERROR) } else { (s.password_prompt_text, WEAK) };
            ui.label(RichText::new(text).color(color));
            ui.add_space(12.0);
            let field = ui.add(field(&mut self.password, s.password_field, false).password(true));
            let enter = field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            ui.add_space(14.0);
            if (primary_button(ui, s.connect_short, 140.0, !self.password.is_empty()).clicked() || enter)
                && !self.password.is_empty()
            {
                let password = std::mem::take(&mut self.password);
                self.connect(Some(password), &ctx);
            }
        });
    }

    /// One side: title, path and actions, then the entries. Returns rows dropped on it from
    /// the other side.
    fn pane_ui(&mut self, ui: &mut egui::Ui, s: &Strings, side: Side, height: f32) -> Option<DragItems> {
        let ctx = ui.ctx().clone();
        let title = match side {
            Side::Local => s.files_this_pc.to_string(),
            Side::Remote => self.host.clone(),
        };
        let (path, loading, error, entries) = {
            let l = self.pane(side).listing.lock().unwrap();
            (l.path.clone(), l.loading, l.error.clone(), l.entries.clone())
        };
        let mut open = None;
        let mut send = false;
        let frame = egui::Frame::new().fill(CARD).stroke(Stroke::new(1.0, BORDER)).corner_radius(CARD_RADIUS);
        let response = frame
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.set_height(height);
                egui::Frame::new().inner_margin(egui::Margin::symmetric(14, 12)).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(&title).font(font(14.5, semibold())));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            let selected = !copyable(&entries, &self.pane(side).selected).is_empty();
                            let label = if side == Side::Local { s.files_send } else { s.files_download };
                            if small_button(ui, label, selected).clicked() {
                                send = true;
                            }
                            if small_button(ui, s.files_places, path.is_some()).clicked() {
                                open = Some(None);
                            }
                            if small_button(ui, s.files_back, !self.pane(side).history.is_empty()).clicked() {
                                self.back(side, &ctx);
                            }
                        });
                    });
                    ui.add_space(4.0);
                    let shown = path.clone().unwrap_or_else(|| s.files_places.to_string());
                    ui.add(egui::Label::new(RichText::new(shown).font(mono(12.0)).color(WEAK)).truncate());
                });
                let top = ui.cursor().min.y;
                ui.painter().hline(ui.max_rect().x_range(), top, Stroke::new(1.0, BORDER));
                if let Some(error) = &error {
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
                            for entry in &entries[range] {
                                if let Some(action) = self.row(ui, side, entry, &entries) {
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
        // Rows dragged from the other pane.
        let dropped = response.dnd_release_payload::<DragItems>().filter(|d| d.from != side);
        if response.dnd_hover_payload::<DragItems>().is_some_and(|d| d.from != side) {
            ui.painter().rect_stroke(response.rect, CARD_RADIUS, Stroke::new(1.5, ACCENT), StrokeKind::Inside);
        }
        dropped.map(|d| (*d).clone())
    }

    /// One entry. Click selects (Ctrl adds, Shift extends), double click opens folders, and
    /// selected rows can be dragged to the other pane. Returns a folder to open.
    fn row(&mut self, ui: &mut egui::Ui, side: Side, entry: &Entry, entries: &[Entry]) -> Option<String> {
        let (rect, response) =
            ui.allocate_exact_size(Vec2::new(ui.available_width(), ROW_HEIGHT), Sense::click_and_drag());
        let pane = self.pane(side);
        let selected = pane.selected.contains(&entry.path);
        let hover = ui.ctx().animate_bool_with_time(response.id.with("hover"), response.hovered(), HOVER_SECONDS);
        let fill = if selected { ACCENT.gamma_multiply(0.18) } else { Color32::from_white_alpha((5.0 * hover) as u8) };
        ui.painter().rect_filled(rect.shrink2(Vec2::new(6.0, 1.0)), RADIUS, fill);
        let icon = egui::Rect::from_center_size(egui::pos2(rect.left() + 26.0, rect.center().y), Vec2::splat(16.0));
        paint_kind(ui.painter(), icon, entry.kind);
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

    fn transfers_height(&self) -> f32 {
        let n = self.transfers.lock().unwrap().len().min(4);
        if n == 0 {
            0.0
        } else {
            50.0 + n as f32 * 36.0
        }
    }

    fn transfers_ui(&mut self, ui: &mut egui::Ui, s: &Strings) {
        let mut clear = false;
        card(ui, |ui| {
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
            let mut transfers = self.transfers.lock().unwrap();
            egui::ScrollArea::vertical().id_salt("transfers").max_height(4.0 * 36.0).show(ui, |ui| {
                for transfer in transfers.iter_mut().rev() {
                    ui.horizontal(|ui| {
                        ui.set_min_height(30.0);
                        let arrow = if transfer.upload { "→" } else { "←" };
                        ui.label(RichText::new(arrow).color(ACCENT_TEXT));
                        ui.add_sized(
                            Vec2::new(220.0, 20.0),
                            egui::Label::new(RichText::new(&transfer.label).font(font(13.5, medium()))).truncate(),
                        );
                        match transfer.state.clone() {
                            TransferState::Running => {
                                let fraction = if transfer.total == 0 {
                                    0.0
                                } else {
                                    transfer.done as f32 / transfer.total as f32
                                };
                                let bar_width = (ui.available_width() - 160.0).max(60.0);
                                progress_bar(ui, fraction, bar_width);
                                ui.label(
                                    RichText::new(format!(
                                        "{} / {}",
                                        human_size(transfer.done),
                                        human_size(transfer.total)
                                    ))
                                    .font(font(12.0, medium()))
                                    .color(WEAK),
                                );
                                if small_button(ui, s.cancel_short, true).clicked() {
                                    if let Some(task) = transfer.task.take() {
                                        task.abort();
                                    }
                                    transfer.state = TransferState::Failed(s.files_cancelled.into());
                                }
                            }
                            TransferState::Done => status(ui, s.files_done, LIVE),
                            TransferState::Failed(e) => {
                                ui.add(
                                    egui::Label::new(RichText::new(fill(s.files_failed, &[&e])).color(ERROR))
                                        .truncate(),
                                );
                            }
                        }
                    });
                }
            });
        });
        if clear {
            self.transfers.lock().unwrap().retain(|t| matches!(t.state, TransferState::Running));
        }
    }
}

impl Drop for FileManager {
    fn drop(&mut self) {
        if let Link::Ready(session) = &*self.link.lock().unwrap() {
            session.close();
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

/// Lists `path` (or the places) on one side into `listing`.
async fn list_into(
    listing: Arc<Mutex<Listing>>,
    side: Side,
    files: Option<RemoteFiles>,
    path: Option<String>,
    ctx: egui::Context,
) {
    {
        let mut l = listing.lock().unwrap();
        l.loading = true;
        l.error = None;
    }
    ctx.request_repaint();
    let result = match (side, files) {
        (Side::Remote, Some(files)) => match &path {
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

fn progress_bar(ui: &mut egui::Ui, fraction: f32, width: f32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width, 6.0), Sense::hover());
    ui.painter().rect_filled(rect, 3.0, BORDER);
    let done = egui::Rect::from_min_size(rect.min, Vec2::new(rect.width() * fraction.clamp(0.0, 1.0), rect.height()));
    ui.painter().rect_filled(done, 3.0, ACCENT);
}

/// Small outline glyphs: a folder, a page, or a drive.
fn paint_kind(painter: &egui::Painter, rect: egui::Rect, kind: EntryKind) {
    let stroke = Stroke::new(1.4, WEAK);
    match kind {
        EntryKind::Dir => {
            let body = egui::Rect::from_min_max(rect.min + Vec2::new(0.0, 3.5), rect.max - Vec2::new(0.0, 1.5));
            painter.rect_stroke(body, 2.0, stroke, StrokeKind::Middle);
            let tab = egui::Rect::from_min_size(rect.min + Vec2::new(0.0, 1.0), Vec2::new(6.5, 3.0));
            painter.rect_filled(tab, 1.0, WEAK);
        }
        EntryKind::File => {
            let body = rect.shrink2(Vec2::new(2.5, 0.5));
            painter.rect_stroke(body, 2.0, stroke, StrokeKind::Middle);
            for i in 0..2 {
                let y = body.top() + 6.0 + i as f32 * 3.5;
                painter.hline((body.left() + 2.5)..=(body.right() - 2.5), y, Stroke::new(1.2, FAINT));
            }
        }
        EntryKind::Place => {
            let body = rect.shrink2(Vec2::new(0.5, 3.0));
            painter.rect_stroke(body, 2.5, stroke, StrokeKind::Middle);
            painter.circle_filled(egui::pos2(body.right() - 3.5, body.center().y), 1.3, ACCENT_TEXT);
        }
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
    #[test]
    fn sizes_read_like_a_file_manager() {
        assert_eq!(super::human_size(0), "0 B");
        assert_eq!(super::human_size(999), "999 B");
        assert_eq!(super::human_size(1_500_000), "1.5 MB");
        assert_eq!(super::human_size(3_000_000_000), "3.0 GB");
    }
}
