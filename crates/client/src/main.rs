// The launcher is a GUI app: no console window on Windows (see `attach_console`).
#![cfg_attr(windows, windows_subsystem = "windows")]

mod autostart;
mod gpu;
mod gui;
#[cfg(all(windows, feature = "ffmpeg"))]
mod interop;
mod keymap;
mod port_owner;
mod render;
mod send_to;
mod settings;

use std::{
    collections::BTreeMap,
    fs::TryLockError,
    num::NonZeroU32,
    path::PathBuf,
    rc::Rc,
    sync::{
        atomic::{AtomicU32, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use gui::strings::{fill, Strings};
use settings::Settings;
use velora_client_core::{
    hosts, FrameSlot, InputSender, OfferEvent, Route, RouteKind, Session, VideoFrame, VideoOutput, WakeOutcome,
};
use velora_protocol::{
    identity::{KnownHost, StateDir},
    tls::Fingerprint,
    wire::{AddressKind, DisplayList, KeyState, MouseButton},
};
use winit::{
    application::ApplicationHandler,
    dpi::PhysicalSize,
    event::{ElementState, MouseScrollDelta, WindowEvent},
    event_loop::{ActiveEventLoop, EventLoop, EventLoopProxy},
    keyboard::{KeyCode, ModifiersState, PhysicalKey},
    window::{Fullscreen, Window, WindowId},
};

#[derive(Parser)]
#[command(
    name = "velora",
    version,
    about = "Control a remote computer running velora-host. Without a command, opens the Velora app."
)]
struct Cli {
    /// Directory for identity and known hosts (defaults to the OS config directory).
    #[arg(long, global = true)]
    config_dir: Option<PathBuf>,
    /// Don't install updates in the background (release builds update themselves by default).
    #[arg(long, global = true)]
    no_update: bool,
    /// Read the host's access password from the first line of standard input.
    #[arg(long, global = true)]
    password_stdin: bool,
    /// Started at sign-in: turn sharing on and/or open the launcher minimized, as the
    /// settings say.
    #[arg(long, hide = true)]
    autostart: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

/// Exit status when the host asks for its access password (missing or wrong), so the
/// launcher can ask the user and start the session again.
pub const EXIT_PASSWORD_REQUIRED: i32 = 3;

#[derive(Subcommand)]
enum Command {
    /// Pair with a host using the code printed by `velora-host run --pair`, then connect.
    Pair {
        /// Host address, `ip[:port]` or `hostname[:port]`.
        address: String,
        code: String,
        /// Name this device is registered under on the host.
        #[arg(long)]
        name: Option<String>,
        /// Pairing link to this computer's own host, offered so the host's computer pairs back.
        #[arg(long)]
        offer: Option<String>,
        /// Another address of the host (say, on Tailscale or Netbird), tried along with
        /// `address`. May be given several times.
        #[arg(long)]
        also: Vec<String>,
    },
    /// Connect to a paired host by name or address, and say which way in it took.
    Connect { host: String },
    /// Wake a sleeping paired host by Wake-on-LAN: from this computer's own network when it is the host's, else through a
    /// relay on the host's network. Exits with 0 only when the signal was sent.
    Wake { host: String },
    /// List paired hosts.
    List,
    /// Connect without a window and report streaming statistics.
    Bench {
        host: String,
        #[arg(long, default_value_t = 10)]
        seconds: u64,
    },
    /// Install the latest release now.
    Update,
    /// Send files and folders to the device connected to this computer, into its Downloads
    /// folder (what Explorer's Send To → Velora runs).
    Send {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
    },
}

fn main() -> Result<()> {
    match run() {
        Err(e) if e.downcast_ref::<velora_client_core::PasswordRequired>().is_some() => {
            eprintln!("Error: {e:#}");
            std::process::exit(EXIT_PASSWORD_REQUIRED);
        }
        result => result,
    }
}

fn run() -> Result<()> {
    #[cfg(windows)]
    attach_console();
    tracing_subscriber::fmt().with_env_filter(log_filter()).with_writer(std::io::stderr).init();

    let cli = Cli::parse();
    let state = StateDir::open(cli.config_dir.clone(), "client")?;
    velora_update::cleanup_current_exe();
    let settings = Settings::load(&state);
    let no_update = cli.no_update || !settings.auto_update;
    let Some(command) = cli.command else {
        if cli.autostart {
            if settings.share_at_login
                && velora_protocol::control::request(&velora_protocol::control::Request::Status).is_err()
            {
                if let Err(e) = gui::spawn_host(cli.config_dir.as_deref(), "velora-host not found") {
                    tracing::warn!("cannot turn sharing on: {e:#}");
                }
            }
            // On Windows the launcher then waits in the tray, to announce devices asking to
            // send files; elsewhere only when asked to open.
            if !settings.open_at_login && !(cfg!(windows) && settings.share_at_login) {
                return Ok(());
            }
        }
        if let Err(e) = send_to::install() {
            tracing::warn!("cannot add Velora to Send To: {e:#}");
        }
        return gui::run(state, cli.config_dir, no_update, cli.autostart);
    };
    if let Command::Send { paths } = command {
        return send_to::send(paths);
    }
    let runtime = tokio::runtime::Runtime::new()?;
    if matches!(command, Command::Pair { .. } | Command::Connect { .. })
        && velora_update::auto_update_enabled(no_update)
    {
        // A session runs for a long time: update in the background, effective next start.
        std::thread::spawn(|| match velora_update::update_now() {
            Ok(Some(v)) => eprintln!("Updated to {v}; it takes effect the next time velora starts."),
            Ok(None) => {}
            Err(e) => tracing::warn!("update check failed: {e:#}"),
        });
    }

    let share_clipboard = settings.share_clipboard;
    let device_name = settings.device_name;
    let password = if cli.password_stdin { Some(read_password()?).filter(|p| !p.is_empty()) } else { None };
    let password = password.as_deref();
    let s = gui::strings::current();
    match command {
        Command::Send { .. } => unreachable!("handled above"),
        Command::Update => {
            match velora_update::update_now()? {
                Some(v) => println!("Updated to {v}."),
                None => println!("Already up to date ({}).", velora_update::Version::current()),
            }
            Ok(())
        }
        Command::List => {
            let hosts = hosts::list(&state)?;
            if hosts.is_empty() {
                println!("No paired hosts. Use `velora pair <address> <code>`.");
            }
            for h in hosts {
                println!("{:<24} {}", h.name, h.address);
            }
            Ok(())
        }
        Command::Wake { host } => {
            println!("{}", runtime.block_on(wake(&state, &host, s))?);
            Ok(())
        }
        Command::Pair { address, code, name, offer, also } => {
            let (proxy, event_loop) = new_event_loop()?;
            let slot = Arc::new(FrameSlot::default());
            let output = VideoOutput::Decoded { slot: slot.clone(), on_frame: redraw_callback(proxy) };
            let name = name.unwrap_or(device_name);
            let session = runtime.block_on(hosts::pair(&state, &address, &also, &code, &name, password, output))?;
            if shows_nothing(session.width, session.height) {
                // Paired all the same: the point of pairing with a relay is that this device can use it.
                session.close();
                println!("{}", paired_without_screen(s, &session.host_name));
                return Ok(());
            }
            println!("Paired with '{}'. Next time: velora connect {}", session.host_name, session.host_name);
            if let Some(link) = offer {
                session.input.offer_pairing(&link);
            }
            run_window(&runtime, event_loop, session, slot, share_clipboard)
        }
        Command::Connect { host } => {
            let paired = free_relay(&state, &host, s)?;
            let (proxy, event_loop) = new_event_loop()?;
            let slot = Arc::new(FrameSlot::default());
            let output = VideoOutput::Decoded { slot: slot.clone(), on_frame: redraw_callback(proxy) };
            let session = runtime.block_on(hosts::connect(&state, &host, &device_name, password, output))?;
            require_screen(&session, s)?;
            println!("{}", connected_line(s, &session.host_name, &way_in(&state, &session, s)));
            // Held for as long as the window lives: the operating system frees it when the process ends, however it does.
            let _claim = hold_relay(&state, paired.as_deref(), session.route());
            run_window(&runtime, event_loop, session, slot, share_clipboard)
        }
        Command::Bench { host, seconds } => runtime.block_on(async {
            let paired = free_relay(&state, &host, s)?;
            let frames = Arc::new(AtomicU32::new(0));
            let counter = frames.clone();
            let on_frame = Arc::new(move || {
                counter.fetch_add(1, Ordering::Relaxed);
            });
            let output = VideoOutput::Decoded { slot: Arc::new(FrameSlot::default()), on_frame };
            let session = hosts::connect(&state, &host, &device_name, password, output).await?;
            require_screen(&session, s)?;
            let _claim = hold_relay(&state, paired.as_deref(), session.route());
            println!(
                "{} ({}x{})",
                connected_line(s, &session.host_name, &way_in(&state, &session, s)),
                session.width,
                session.height
            );
            tokio::time::sleep(Duration::from_secs(seconds)).await;
            let n = frames.load(Ordering::Relaxed);
            println!(
                "{n} frames in {seconds}s ({:.1} fps), rtt {:.1} ms",
                n as f64 / seconds as f64,
                session.rtt().as_secs_f64() * 1000.0
            );
            session.close();
            Ok(())
        }),
    }
}

/// The first line of standard input, without its line ending.
fn read_password() -> Result<String> {
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

/// What the log shows: `RUST_LOG`, else info. The DHT library (`mainline`) is kept to its errors unless `RUST_LOG` names
/// it: on Windows it logs a warning about 17 times a second while idle (docs/dht-spike.md, 9.2), which buries the rest.
fn log_filter() -> tracing_subscriber::EnvFilter {
    log_filter_for(std::env::var("RUST_LOG").ok().as_deref())
}

fn log_filter_for(rust_log: Option<&str>) -> tracing_subscriber::EnvFilter {
    use tracing_subscriber::EnvFilter;
    let spec = rust_log.map(str::trim).filter(|spec| !spec.is_empty());
    let filter = spec.and_then(|spec| EnvFilter::try_new(spec).ok()).unwrap_or_else(|| "info".into());
    match "mainline=error".parse() {
        Ok(directive) if !spec.is_some_and(|spec| spec.contains("mainline")) => filter.add_directive(directive),
        _ => filter,
    }
}

/// `velora wake`: what to print when the signal went out, else an error that says why not.
async fn wake(state: &StateDir, host: &str, s: &Strings) -> Result<String> {
    wake_report(hosts::wake(state, host).await, s)
}

/// What `velora wake` says, in the launcher's words (`wake_*` in `strings.rs`). Only a sent signal is a success: the
/// other outcomes are errors, so that the exit status tells a script whether the signal went out.
fn wake_report(outcome: Result<WakeOutcome>, s: &Strings) -> Result<String> {
    match outcome {
        Ok(WakeOutcome::Sent) => Ok(s.wake_sent.to_string()),
        Ok(WakeOutcome::NoRelay) => bail!(fill(s.wake_no_relay, &[s.reach_relay])),
        Ok(WakeOutcome::Unsupported) => bail!(s.wake_unsupported),
        Err(e) => bail!(fill(s.wake_failed, &[&format!("{e:#}")])),
    }
}

/// Which way in a connection took, in the launcher's words (`reach_kind_*` and the like in `strings.rs`) and in its form
/// (`last_reached_text` there): the label, a middle dot and the address, with the relay's name between them for a relay.
fn route_words(route: &Route, known: &[KnownHost], s: &Strings) -> String {
    let (label, relay) = match &route.kind {
        RouteKind::Punch => (s.reach_kind_punch, None),
        RouteKind::Address(AddressKind::Lan) => (s.reach_kind_lan, None),
        RouteKind::Address(AddressKind::Vpn) => (s.reach_kind_vpn, None),
        RouteKind::Address(AddressKind::Public) => (s.reach_public, None),
        RouteKind::Address(AddressKind::V6) => (s.reach_v6, None),
        RouteKind::Address(AddressKind::Relay(fingerprint)) => {
            (s.reach_kind_relay, Some(relay_name(fingerprint, known)))
        }
        RouteKind::Address(AddressKind::Other(_)) => (s.reach_kind_other, None),
    };
    match relay {
        Some(name) => format!("{label} · {name} · {}", route.address),
        None => format!("{label} · {}", route.address),
    }
}

/// The name of the paired computer that is the relay with `fingerprint`, else its short form: a relay is a computer of the
/// user's, but not always one this device has paired with.
fn relay_name(fingerprint: &str, known: &[KnownHost]) -> String {
    match known.iter().find(|h| h.fingerprint == fingerprint) {
        Some(host) => host.name.clone(),
        None => Fingerprint::from_base64(fingerprint).map_or_else(|_| fingerprint.to_string(), |f| f.short()),
    }
}

/// How `session` reached its host, in words (see [`route_words`]).
fn way_in(state: &StateDir, session: &Session, s: &Strings) -> String {
    route_words(session.route(), &hosts::list(state).unwrap_or_default(), s)
}

/// The line `velora connect` prints once the session is up, and `velora bench` starts with.
fn connected_line(s: &Strings, host: &str, way: &str) -> String {
    fill(s.cli_connected, &[host, way])
}

/// What `velora pair` says when the host only relays: it is paired, and there is nothing more to do with it here.
fn paired_without_screen(s: &Strings, host: &str) -> String {
    format!("{} {}", fill(s.cli_paired, &[host]), s.relay_only)
}

/// Whether a welcome of this size has nothing to show: what a host that only relays (`velora-host --relay-only`) sends,
/// and a window for it would stay empty.
fn shows_nothing(width: u16, height: u16) -> bool {
    width == 0 || height == 0
}

/// Ends a session that has no screen, with `relay_only` for the error: the launcher shows the last error line of a failed
/// session.
fn require_screen(session: &Session, s: &Strings) -> Result<()> {
    if shows_nothing(session.width, session.height) {
        session.close();
        bail!(s.relay_only);
    }
    Ok(())
}

// A relay carries one connection to a host from this device at a time: a second one takes the first over (D2, F3). A window
// that reached its host through a relay therefore holds a lock on a file in the state directory for as long as it lives,
// and any other window of this computer looks at that file before it connects. The operating system owns the lock, so a
// window that crashes or is killed frees it too. The file is left behind, empty.

/// The lock held by a window that reached its host through a relay; it ends with this value.
struct RelayClaim {
    _lock: std::fs::File,
}

/// The lock file of the host with `fingerprint` (base64url, so it is already a name that files can have).
fn claim_path(state: &StateDir, fingerprint: &str) -> PathBuf {
    let name: String = fingerprint.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_')).collect();
    state.dir().join(format!("relay-{name}.lock"))
}

/// Takes the relay to the host with `fingerprint`, or `None` when another window already holds it (or the file cannot be
/// used: a lock that cannot be taken is no reason to stop anyone).
fn claim_relay(state: &StateDir, fingerprint: &str) -> Option<RelayClaim> {
    let path = claim_path(state, fingerprint);
    let file = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).open(&path);
    match file.map_err(TryLockError::Error).and_then(|file| file.try_lock().map(|()| file)) {
        Ok(file) => Some(RelayClaim { _lock: file }),
        Err(TryLockError::WouldBlock) => {
            tracing::warn!("another window of this computer held the relay to this host; this connection took it over");
            None
        }
        Err(TryLockError::Error(e)) => {
            tracing::debug!("cannot claim the relay ({}): {e}", path.display());
            None
        }
    }
}

/// Whether a window holds the relay to the host with `fingerprint`.
fn relay_busy(state: &StateDir, fingerprint: &str) -> bool {
    let Ok(file) = std::fs::File::open(claim_path(state, fingerprint)) else { return false };
    matches!(file.try_lock_shared(), Err(TryLockError::WouldBlock))
}

/// The fingerprint of the paired host called `host` (a name or an address, as `hosts::connect` takes it) once no other
/// window of this computer holds a relay to it, else an error saying so. Before the connection: afterwards the relay would
/// already have dropped the other window. A host that is not paired is left for `hosts::connect` to complain about.
fn free_relay(state: &StateDir, host: &str, s: &Strings) -> Result<Option<String>> {
    let known = hosts::list(state).unwrap_or_default();
    let Some(paired) = known.iter().find(|h| h.name == host || h.address == host) else { return Ok(None) };
    if relay_busy(state, &paired.fingerprint) {
        bail!(fill(s.relay_busy, &[&paired.name]));
    }
    Ok(Some(paired.fingerprint.clone()))
}

/// Takes the relay for a session that came through one (`route`), else nothing.
fn hold_relay(state: &StateDir, paired: Option<&str>, route: &Route) -> Option<RelayClaim> {
    let fingerprint = paired.filter(|_| matches!(route.kind, RouteKind::Address(AddressKind::Relay(_))))?;
    claim_relay(state, fingerprint)
}

/// A GUI-subsystem program has no console; reuse the terminal it was started from, if any,
/// so the command line still prints.
#[cfg(windows)]
fn attach_console() {
    use windows::Win32::System::Console::{AttachConsole, ATTACH_PARENT_PROCESS};
    // SAFETY: no preconditions; fails harmlessly when there is no parent console.
    unsafe {
        let _ = AttachConsole(ATTACH_PARENT_PROCESS);
    }
}

fn new_event_loop() -> Result<(EventLoopProxy<()>, EventLoop<()>)> {
    let event_loop = EventLoop::<()>::with_user_event().build()?;
    Ok((event_loop.create_proxy(), event_loop))
}

fn redraw_callback(proxy: EventLoopProxy<()>) -> Arc<dyn Fn() + Send + Sync> {
    Arc::new(move || {
        let _ = proxy.send_event(());
    })
}

fn run_window(
    runtime: &tokio::runtime::Runtime,
    event_loop: EventLoop<()>,
    session: Session,
    frames: Arc<FrameSlot>,
    share_clipboard: bool,
) -> Result<()> {
    let session = Arc::new(session);
    let transfers = Arc::new(Mutex::new(Transfers::default()));
    let proxy = event_loop.create_proxy();
    // The clipboard goes both ways: copied here, it goes to the host; copied there, it lands
    // here (see `velora-clipboard`).
    let clipboard = share_clipboard.then(|| {
        let session = session.clone();
        velora_clipboard::spawn(move |clip| match clip.encode() {
            Ok((kind, data)) => session.send_clipboard(kind, data),
            Err(e) => tracing::warn!("cannot share the clipboard: {e:#}"),
        })
    });
    let paste = Arc::new(move |kind: u8, data: Vec<u8>| {
        let Some(Some(clipboard)) = &clipboard else { return };
        tracing::debug!("clipboard received from the host ({} bytes)", data.len());
        match velora_clipboard::Clip::decode(kind, &data) {
            Ok(clip) => {
                let _ = clipboard.send(clip);
            }
            Err(e) => tracing::warn!("clipboard from the host: {e:#}"),
        }
    });
    // What the host sends (Send To there) lands in this user's Downloads folder.
    match velora_protocol::files::downloads_dir() {
        Ok(dest) => {
            let (transfers, proxy) = (transfers.clone(), proxy.clone());
            session.receive_files(
                dest,
                Arc::new(move |event| {
                    transfers.lock().unwrap().offer(event);
                    let _ = proxy.send_event(());
                }),
                paste,
            );
        }
        Err(e) => tracing::warn!("cannot receive files: {e:#}"),
    }
    {
        // Exit the UI when the host goes away.
        let session = session.clone();
        runtime.spawn(async move {
            let reason = session.closed().await;
            eprintln!("disconnected: {reason}");
            std::process::exit(0);
        });
    }
    // The host's displays, when it has several: shown in the title, picked with shortcuts.
    let displays = Arc::new(Mutex::new(None));
    {
        let (displays, proxy) = (displays.clone(), proxy.clone());
        session.on_displays(Arc::new(move |list| {
            *displays.lock().unwrap() = Some(list.clone());
            let _ = proxy.send_event(());
        }));
    }
    println!("Shortcuts, with Ctrl+Alt+Shift: F fullscreen, M next display, 1-9 a display, A sound on/off, Q quit");
    let mut app = App {
        input: session.input.clone(),
        frames,
        runtime: runtime.handle().clone(),
        proxy,
        transfers,
        displays,
        muted: false,
        title: format!("{} — Velora", session.host_name),
        shown_title: String::new(),
        remote_size: (session.width as u32, session.height as u32),
        session,
        window: None,
        renderer: None,
        current: None,
        viewport: render::Viewport::default(),
        cursor: (0.0, 0.0),
        modifiers: ModifiersState::empty(),
    };
    event_loop.run_app(&mut app)?;
    Ok(())
}

type Surface = softbuffer::Surface<Rc<Window>, Rc<Window>>;

/// How the session window draws: on the GPU, or in software (with the converted picture).
enum Renderer {
    Gpu(Box<gpu::Gpu>),
    Cpu(Surface, Vec<u32>),
}

impl Renderer {
    /// The GPU unless it fails or `VELORA_RENDERER=cpu` asks for software.
    fn new(window: &Rc<Window>) -> Result<Self> {
        if std::env::var("VELORA_RENDERER").is_ok_and(|v| v.eq_ignore_ascii_case("cpu")) {
            return Self::software(window);
        }
        match gpu::Gpu::new(window) {
            Ok(gpu) => Ok(Self::Gpu(Box::new(gpu))),
            Err(e) => {
                tracing::warn!("drawing in software, OpenGL is not available: {e:#}");
                Self::software(window)
            }
        }
    }

    fn software(window: &Rc<Window>) -> Result<Self> {
        let surface = softbuffer::Context::new(window.clone())
            .and_then(|ctx| Surface::new(&ctx, window.clone()))
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(Self::Cpu(surface, Vec::new()))
    }
}

/// File transfers of a session, shown in its window title.
#[derive(Default)]
struct Transfers {
    /// Running ones by (sending, id): name, bytes done and total.
    running: BTreeMap<(bool, u64), (String, u64, u64)>,
    /// The last one to finish, and when.
    last: Option<(String, Instant)>,
}

/// How long the outcome of a transfer stays in the title.
const TRANSFER_NOTICE: Duration = Duration::from_secs(8);

impl Transfers {
    fn offer(&mut self, event: OfferEvent) {
        let s = gui::strings::current();
        match event {
            OfferEvent::Progress { id, done, total } => {
                self.running.insert((false, id), (s.files.to_lowercase(), done, total));
            }
            OfferEvent::Saved { id, names } => {
                self.running.remove(&(false, id));
                self.last = Some((gui::strings::fill(s.files_saved, &[&names.join(", ")]), Instant::now()));
            }
            OfferEvent::Failed { id, error } => {
                self.running.remove(&(false, id));
                self.last = Some((gui::strings::fill(s.files_failed, &[&error]), Instant::now()));
            }
        }
    }

    /// The title's suffix: the first running transfer, or the last outcome for a while.
    fn summary(&self) -> Option<String> {
        let s = gui::strings::current();
        if let Some(((sending, _), (name, done, total))) = self.running.iter().next() {
            let percent = if *total == 0 { 0 } else { done * 100 / total };
            let template = if *sending { s.files_sending } else { s.files_receiving };
            let mut text = gui::strings::fill(template, &[name, &percent.to_string()]);
            if self.running.len() > 1 {
                text.push_str(&format!(" (+{})", self.running.len() - 1));
            }
            return Some(text);
        }
        self.last.as_ref().filter(|(_, at)| at.elapsed() < TRANSFER_NOTICE).map(|(text, _)| text.clone())
    }
}

struct App {
    session: Arc<Session>,
    input: InputSender,
    frames: Arc<FrameSlot>,
    runtime: tokio::runtime::Handle,
    proxy: EventLoopProxy<()>,
    transfers: Arc<Mutex<Transfers>>,
    displays: Arc<Mutex<Option<DisplayList>>>,
    /// The host's sound is muted here.
    muted: bool,
    /// Base title, and the one on screen (with the display, sound and transfers).
    title: String,
    shown_title: String,
    remote_size: (u32, u32),
    window: Option<Rc<Window>>,
    renderer: Option<Renderer>,
    current: Option<VideoFrame>,
    viewport: render::Viewport,
    cursor: (f64, f64),
    modifiers: ModifiersState,
}

impl App {
    fn pointer(&self) -> (u16, u16) {
        self.viewport.normalize(self.cursor.0, self.cursor.1)
    }

    /// Sends a file or folder dropped on the window to the host's Downloads folder.
    fn send_dropped(&mut self, path: PathBuf) {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let s = gui::strings::current();
        let Some(files) = self.session.files() else {
            self.transfers.lock().unwrap().last = Some((s.files_unsupported.to_string(), Instant::now()));
            self.refresh_title();
            return;
        };
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let name = path.file_name().map_or_else(|| path.display().to_string(), |n| n.to_string_lossy().into_owned());
        let (transfers, proxy) = (self.transfers.clone(), self.proxy.clone());
        transfers.lock().unwrap().running.insert((true, id), (name.clone(), 0, 0));
        self.refresh_title();
        self.runtime.spawn(async move {
            let mut progress = |done: u64, total: u64| {
                transfers.lock().unwrap().running.insert((true, id), (name.clone(), done, total));
                let _ = proxy.send_event(());
            };
            let result = files.upload(vec![path], "", &mut progress).await;
            let mut t = transfers.lock().unwrap();
            t.running.remove(&(true, id));
            let text = match result {
                Ok(names) => gui::strings::fill(s.files_sent, &[&names.join(", ")]),
                Err(e) => gui::strings::fill(s.files_failed, &[&format!("{e:#}")]),
            };
            t.last = Some((text, Instant::now()));
            drop(t);
            let _ = proxy.send_event(());
        });
    }

    fn refresh_title(&mut self) {
        let mut title = self.title.clone();
        if let Some(d) = self.displays.lock().unwrap().as_ref().filter(|d| d.list.len() > 1) {
            let s = gui::strings::current();
            let (n, of) = ((d.current as usize + 1).to_string(), d.list.len().to_string());
            title = format!("{title} · {}", gui::strings::fill(s.session_display, &[&n, &of]));
        }
        if self.muted {
            title = format!("{title} · {}", gui::strings::current().session_muted);
        }
        if let Some(summary) = self.transfers.lock().unwrap().summary() {
            title = format!("{title} · {summary}");
        }
        if title != self.shown_title {
            if let Some(w) = &self.window {
                w.set_title(&title);
            }
            self.shown_title = title;
        }
    }

    fn redraw(&mut self) -> Result<()> {
        let (Some(window), Some(renderer)) = (&self.window, &mut self.renderer) else { return Ok(()) };
        let fresh = self.frames.take();
        let size = window.inner_size();
        let (Some(w), Some(h)) = (NonZeroU32::new(size.width), NonZeroU32::new(size.height)) else { return Ok(()) };
        match renderer {
            Renderer::Gpu(gpu) => {
                // The textures hold the picture now: its buffers can go back to the decoder.
                if let Some(frame) = fresh {
                    if let Err(e) = gpu.upload(&frame) {
                        tracing::warn!("showing pictures from the GPU decoder failed: {e:#}; copying them instead");
                        self.frames.set_zero_copy(false);
                    }
                    self.frames.recycle(frame);
                }
                self.viewport = gpu.draw(w.get(), h.get())?;
            }
            Renderer::Cpu(surface, rgb) => {
                if let Some(frame) = fresh {
                    frame.to_xrgb(rgb);
                    if let Some(old) = self.current.replace(frame) {
                        self.frames.recycle(old);
                    }
                }
                surface.resize(w, h).map_err(|e| anyhow::anyhow!("{e}"))?;
                let mut buffer = surface.buffer_mut().map_err(|e| anyhow::anyhow!("{e}"))?;
                match &self.current {
                    Some(f) => self.viewport = render::draw(rgb, f.width, f.height, &mut buffer, w.get(), h.get()),
                    None => buffer.fill(0),
                }
                buffer.present().map_err(|e| anyhow::anyhow!("{e}"))?;
            }
        }
        Ok(())
    }

    /// Client-side shortcuts; returns true when the key was consumed.
    fn shortcut(&mut self, event_loop: &ActiveEventLoop, key: KeyCode) -> bool {
        let m = self.modifiers;
        if !(m.control_key() && m.alt_key() && m.shift_key()) {
            return false;
        }
        match key {
            KeyCode::KeyF => {
                if let Some(w) = &self.window {
                    let fs = if w.fullscreen().is_some() { None } else { Some(Fullscreen::Borderless(None)) };
                    w.set_fullscreen(fs);
                }
            }
            KeyCode::KeyQ => {
                self.session.close();
                event_loop.exit();
            }
            KeyCode::KeyA if self.session.has_audio() => {
                self.muted = !self.muted;
                self.session.set_muted(self.muted);
                self.refresh_title();
            }
            // The host's next display, or one by its number.
            KeyCode::KeyM => {
                let displays = self.displays.lock().unwrap().clone();
                if let Some(d) = displays.filter(|d| d.list.len() > 1) {
                    self.input.select_display(((d.current as usize + 1) % d.list.len()) as u8);
                }
            }
            _ => {
                let Some(index) = digit(key) else { return false };
                let count = self.displays.lock().unwrap().as_ref().map_or(0, |d| d.list.len());
                if index < count {
                    self.input.select_display(index as u8);
                }
            }
        }
        // The modifiers already reached the host; don't leave them held there.
        self.input.release_all();
        true
    }
}

/// 0 for the 1 key up to 8 for the 9 key.
fn digit(key: KeyCode) -> Option<usize> {
    const DIGITS: [KeyCode; 9] = [
        KeyCode::Digit1,
        KeyCode::Digit2,
        KeyCode::Digit3,
        KeyCode::Digit4,
        KeyCode::Digit5,
        KeyCode::Digit6,
        KeyCode::Digit7,
        KeyCode::Digit8,
        KeyCode::Digit9,
    ];
    DIGITS.iter().position(|&d| d == key)
}

impl ApplicationHandler for App {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        if self.window.is_some() {
            return;
        }
        let (rw, rh) = self.remote_size;
        // Native remote resolution, shrunk to fit the monitor when needed.
        let (mut w, mut h) = (rw.max(320), rh.max(240));
        if let Some(monitor) = event_loop.primary_monitor() {
            let m = monitor.size();
            let scale = f64::min(1.0, f64::min(m.width as f64 * 0.9 / w as f64, m.height as f64 * 0.9 / h as f64));
            w = (w as f64 * scale) as u32;
            h = (h as f64 * scale) as u32;
        }
        let attrs = Window::default_attributes().with_title(&self.title).with_inner_size(PhysicalSize::new(w, h));
        let window = match event_loop.create_window(attrs) {
            Ok(w) => Rc::new(w),
            Err(e) => {
                eprintln!("cannot create window: {e}");
                event_loop.exit();
                return;
            }
        };
        match Renderer::new(&window) {
            Ok(renderer) => {
                // The decoder may leave pictures on the GPU when the window can show them there.
                if let Renderer::Gpu(gpu) = &renderer {
                    self.frames.set_zero_copy(gpu.zero_copy());
                }
                self.renderer = Some(renderer);
            }
            Err(e) => {
                eprintln!("cannot create drawing surface: {e:#}");
                event_loop.exit();
                return;
            }
        }
        self.window = Some(window);
    }

    fn user_event(&mut self, _event_loop: &ActiveEventLoop, _event: ()) {
        self.refresh_title();
        if let Some(w) = &self.window {
            w.request_redraw();
        }
    }

    fn window_event(&mut self, event_loop: &ActiveEventLoop, _id: WindowId, event: WindowEvent) {
        match event {
            WindowEvent::CloseRequested => {
                self.session.close();
                event_loop.exit();
            }
            WindowEvent::RedrawRequested => {
                if let Err(e) = self.redraw() {
                    tracing::warn!("redraw failed: {e:#}");
                }
            }
            WindowEvent::Resized(_) => {
                if let Some(w) = &self.window {
                    w.request_redraw();
                }
            }
            WindowEvent::Focused(false) => self.input.release_all(),
            WindowEvent::DroppedFile(path) => self.send_dropped(path),
            WindowEvent::ModifiersChanged(m) => self.modifiers = m.state(),
            WindowEvent::CursorMoved { position, .. } => {
                self.cursor = (position.x, position.y);
                let (x, y) = self.pointer();
                self.input.mouse_move(x, y);
            }
            WindowEvent::MouseInput { state, button, .. } => {
                let button = match button {
                    winit::event::MouseButton::Left => MouseButton::Left,
                    winit::event::MouseButton::Right => MouseButton::Right,
                    winit::event::MouseButton::Middle => MouseButton::Middle,
                    winit::event::MouseButton::Back => MouseButton::Back,
                    winit::event::MouseButton::Forward => MouseButton::Forward,
                    winit::event::MouseButton::Other(_) => return,
                };
                let (x, y) = self.pointer();
                self.input.mouse_button(button, state == ElementState::Pressed, x, y);
            }
            WindowEvent::MouseWheel { delta, .. } => {
                // winit: positive x = content moves right (scroll left), positive y = scroll up.
                let (dx, dy) = match delta {
                    MouseScrollDelta::LineDelta(x, y) => (-x as f64 * 120.0, y as f64 * 120.0),
                    // Touchpads: roughly one notch per 40 px.
                    MouseScrollDelta::PixelDelta(p) => (-p.x * 3.0, p.y * 3.0),
                };
                let clamp = |v: f64| v.round().clamp(i16::MIN as f64, i16::MAX as f64) as i16;
                self.input.scroll(clamp(dx), clamp(dy));
            }
            WindowEvent::KeyboardInput { event, .. } => {
                let PhysicalKey::Code(code) = event.physical_key else { return };
                if event.state == ElementState::Pressed && self.shortcut(event_loop, code) {
                    return;
                }
                let Some(evdev) = keymap::to_evdev(code) else { return };
                let state = match (event.state, event.repeat) {
                    (ElementState::Released, _) => KeyState::Up,
                    (ElementState::Pressed, false) => KeyState::Down,
                    (ElementState::Pressed, true) => KeyState::Repeat,
                };
                self.input.key(evdev, state);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::anyhow;
    use clap::CommandFactory;

    use super::*;
    use crate::gui::strings;

    /// A scratch folder for the client's state, removed when dropped.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("velora-g3-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            Self(dir)
        }

        fn state(&self) -> StateDir {
            StateDir::open(Some(self.0.clone()), "client").unwrap()
        }

        /// Pairs `hosts`: they go into the known hosts, as pairing writes them.
        fn pair(&self, hosts: &[KnownHost]) {
            self.state().save(StateDir::KNOWN_HOSTS, &hosts.to_vec()).unwrap();
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A paired computer. Addresses are documentation ones (RFC 5737, RFC 3849) and fingerprints are made up: nothing
    /// here is anyone's network.
    fn host(name: &str, address: &str, tag: u8) -> KnownHost {
        KnownHost {
            name: name.into(),
            address: address.into(),
            fingerprint: Fingerprint([tag; 32]).to_base64(),
            ..Default::default()
        }
    }

    fn route(kind: impl Into<RouteKind>, address: &str) -> Route {
        Route { kind: kind.into(), address: address.into() }
    }

    fn relay(tag: u8) -> AddressKind {
        AddressKind::Relay(Fingerprint([tag; 32]).to_base64())
    }

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("velora").chain(args.iter().copied()))
    }

    #[test]
    fn the_command_line_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn wake_takes_one_host() {
        let Some(Command::Wake { host }) = parse(&["wake", "Office PC"]).unwrap().command else { panic!("not wake") };
        assert_eq!(host, "Office PC");
        // By address too, and with the global options before or after, as for the other commands.
        let cli = parse(&["--config-dir", "state", "wake", "192.0.2.10:7420", "--no-update"]).unwrap();
        assert_eq!(cli.config_dir, Some(PathBuf::from("state")));
        assert!(cli.no_update);
        assert!(matches!(cli.command, Some(Command::Wake { host }) if host == "192.0.2.10:7420"));
        assert!(parse(&["wake"]).is_err(), "which host?");
        assert!(parse(&["wake", "Office PC", "Laptop"]).is_err(), "one at a time");
        // The others are as they were.
        assert!(matches!(parse(&["connect", "x"]).unwrap().command, Some(Command::Connect { .. })));
        assert!(matches!(
            parse(&["bench", "x", "--seconds", "3"]).unwrap().command,
            Some(Command::Bench { seconds: 3, .. })
        ));
    }

    #[test]
    fn wake_says_each_outcome_in_the_launchers_words_and_succeeds_only_when_it_sent() {
        for s in strings::all() {
            assert_eq!(wake_report(Ok(WakeOutcome::Sent), s).unwrap(), s.wake_sent);
            let refused = |outcome| wake_report(outcome, s).unwrap_err().to_string();
            assert_eq!(refused(Ok(WakeOutcome::NoRelay)), fill(s.wake_no_relay, &[s.reach_relay]));
            assert_eq!(refused(Ok(WakeOutcome::Unsupported)), s.wake_unsupported);
            // A failure shows what went wrong, all of it.
            let failed = Err(anyhow!("no route").context("cannot ask the relay"));
            assert_eq!(refused(failed), fill(s.wake_failed, &["cannot ask the relay: no route"]));
        }
    }

    /// The real `hosts::wake` against paired computers that cannot be woken, so that no packet leaves this PC.
    #[test]
    fn wake_asks_the_paired_computers_and_tells_what_came_of_it() {
        // A made-up MAC address of the locally administered kind.
        const MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];
        let scratch = Scratch::new("wake");
        // The first never told its MAC address. The second is on a network that no adapter of this PC has, and has no
        // relay stored.
        let silent = host("Silent", "192.0.2.10:7420", 1);
        let away = KnownHost {
            mac: Some(MAC),
            kinds: vec![(AddressKind::Lan, "203.0.113.9:7420".into())],
            ..host("Away", "198.51.100.10:7420", 2)
        };
        scratch.pair(&[silent, away]);
        let state = scratch.state();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        for s in strings::all() {
            let told = |name: &str| runtime.block_on(wake(&state, name, s)).unwrap_err().to_string();
            assert_eq!(told("Silent"), s.wake_unsupported);
            assert_eq!(told("Away"), fill(s.wake_no_relay, &[s.reach_relay]));
            // By address, as `connect` takes it.
            assert_eq!(told("192.0.2.10:7420"), s.wake_unsupported);
            let unknown = told("Nowhere");
            assert!(unknown.starts_with(&fill(s.wake_failed, &[""])), "{unknown}");
            assert!(unknown.contains("'Nowhere' is not paired yet"), "{unknown}");
        }
    }

    /// The launcher words a route as its label, a middle dot and the address (`last_reached_text`): so does the command
    /// line, in the same language, with the relay's name between the two for a relay.
    #[test]
    fn the_route_is_told_in_the_launchers_words() {
        let known = [host("Office PC", "192.0.2.10:7420", 1), host("Laptop", "192.0.2.20:7420", 9)];
        for s in strings::all() {
            let words = |kind: RouteKind, address| route_words(&route(kind, address), &known, s);
            for (kind, label, address) in [
                (AddressKind::Lan, s.reach_kind_lan, "192.0.2.10:7420"),
                (AddressKind::Vpn, s.reach_kind_vpn, "198.51.100.5:7420"),
                (AddressKind::Public, s.reach_public, "203.0.113.5:7420"),
                (AddressKind::V6, s.reach_v6, "[2001:db8::5]:7420"),
                (AddressKind::Other(7), s.reach_kind_other, "192.0.2.77:7420"),
            ] {
                assert_eq!(words(kind.into(), address), format!("{label} · {address}"));
            }
            // A hole punch is told apart from the public address it ends at.
            let punched = words(RouteKind::Punch, "203.0.113.5:7420");
            assert_eq!(punched, format!("{} · 203.0.113.5:7420", s.reach_kind_punch));
            assert_ne!(punched, words(AddressKind::Public.into(), "203.0.113.5:7420"));
            // A relay is named when this device has paired with it, and else by its fingerprint.
            let relayed = |name: &str| format!("{} · {name} · 198.51.100.4:7420", s.reach_kind_relay);
            assert_eq!(words(relay(9).into(), "198.51.100.4:7420"), relayed("Laptop"));
            assert_eq!(words(relay(5).into(), "198.51.100.4:7420"), relayed(&Fingerprint([5; 32]).short()));
            // A relay that is not even a fingerprint is shown as it came.
            let garbled = words(AddressKind::Relay("not a fingerprint".into()).into(), "198.51.100.4:7420");
            assert_eq!(garbled, relayed("not a fingerprint"));
        }
    }

    #[test]
    fn the_lines_of_the_command_line_come_from_the_strings_in_both_languages() {
        for s in strings::all() {
            let way = route_words(&route(AddressKind::Lan, "192.0.2.10:7420"), &[], s);
            let line = connected_line(s, "Office PC", &way);
            assert_eq!(line, fill(s.cli_connected, &["Office PC", &way]));
            assert!(line.contains("Office PC") && line.ends_with(&way), "{line}");
            // A host that only relays is paired, and told why there is nothing to see.
            let paired = paired_without_screen(s, "Relay PC");
            assert_eq!(paired, format!("{} {}", fill(s.cli_paired, &["Relay PC"]), s.relay_only));
            assert!(paired.contains("Relay PC") && paired.ends_with(s.relay_only), "{paired}");
        }
        // Each language has its own words for them.
        let [pt, en] = strings::all();
        for (pt, en) in [
            (pt.cli_connected, en.cli_connected),
            (pt.cli_paired, en.cli_paired),
            (pt.relay_only, en.relay_only),
            (pt.relay_busy, en.relay_busy),
            (pt.reach_kind_punch, en.reach_kind_punch),
        ] {
            assert_ne!(pt, en);
        }
    }

    #[test]
    fn a_host_with_no_screen_is_one_that_only_relays() {
        assert!(shows_nothing(0, 0));
        // Either side being nothing leaves nothing to draw.
        assert!(shows_nothing(0, 1080) && shows_nothing(1920, 0));
        assert!(!shows_nothing(1920, 1080) && !shows_nothing(1, 1));
    }

    #[test]
    fn the_claim_file_is_in_the_state_directory_whatever_the_fingerprint_looks_like() {
        let scratch = Scratch::new("path");
        let state = scratch.state();
        let real = claim_path(&state, &Fingerprint([3; 32]).to_base64());
        assert_eq!(real.parent(), Some(state.dir()));
        assert!(real.file_name().unwrap().to_str().unwrap().starts_with("relay-"));
        // What a hand-edited known-hosts file may hold must not lead out of the folder.
        let odd = claim_path(&state, "../../x\\y/z");
        assert_eq!(odd.parent(), Some(state.dir()));
        assert_eq!(odd.file_name().unwrap(), "relay-xyz.lock");
    }

    #[test]
    fn a_relay_is_held_by_one_window_at_a_time() {
        let scratch = Scratch::new("claim");
        let state = scratch.state();
        let (office, desk) = (Fingerprint([1; 32]).to_base64(), Fingerprint([2; 32]).to_base64());
        assert!(!relay_busy(&state, &office), "nothing was claimed yet");
        let claim = claim_relay(&state, &office).expect("the first window takes it");
        assert!(relay_busy(&state, &office));
        assert!(claim_relay(&state, &office).is_none(), "a second one cannot");
        assert!(!relay_busy(&state, &desk), "another host is another connection through the relay");
        let other = claim_relay(&state, &desk);
        assert!(other.is_some() && relay_busy(&state, &desk));
        // Closing the window frees it.
        drop(claim);
        assert!(!relay_busy(&state, &office) && relay_busy(&state, &desk));
        assert!(claim_relay(&state, &office).is_some());
    }

    #[test]
    fn a_claim_that_cannot_be_made_stops_nobody() {
        let scratch = Scratch::new("nofile");
        let state = scratch.state();
        std::fs::remove_dir_all(state.dir()).unwrap();
        let office = Fingerprint([1; 32]).to_base64();
        assert!(claim_relay(&state, &office).is_none(), "the file cannot be made");
        assert!(!relay_busy(&state, &office), "and without it nothing is held");
    }

    #[test]
    fn a_second_window_through_the_same_relay_is_refused_before_it_connects() {
        let scratch = Scratch::new("free");
        let office = host("Office PC", "192.0.2.10:7420", 1);
        scratch.pair(&[office.clone(), host("Laptop", "192.0.2.20:7420", 9)]);
        let state = scratch.state();
        let relayed = route(relay(9), "198.51.100.4:7420");
        for s in strings::all() {
            // Nothing is held: it may connect, by name or by address.
            for name in ["Office PC", "192.0.2.10:7420"] {
                assert_eq!(free_relay(&state, name, s).unwrap().as_deref(), Some(office.fingerprint.as_str()));
            }
            // A host that is not paired is left for the connection to complain about.
            assert_eq!(free_relay(&state, "Nowhere", s).unwrap(), None);
        }
        // The first window came through a relay and holds it.
        let first = hold_relay(&state, Some(&office.fingerprint), &relayed).expect("a relayed session claims");
        for s in strings::all() {
            for name in ["Office PC", "192.0.2.10:7420"] {
                let refused = free_relay(&state, name, s).unwrap_err().to_string();
                assert_eq!(refused, fill(s.relay_busy, &["Office PC"]));
            }
            // Another computer is not in the way.
            assert!(free_relay(&state, "Laptop", s).is_ok());
        }
        // Once that window is closed, the next one may.
        drop(first);
        assert!(free_relay(&state, "Office PC", strings::current()).is_ok());
    }

    #[test]
    fn only_a_session_that_came_through_a_relay_holds_one() {
        let scratch = Scratch::new("hold");
        let state = scratch.state();
        let office = Fingerprint([1; 32]).to_base64();
        let direct: [RouteKind; 6] = [
            AddressKind::Lan.into(),
            AddressKind::Vpn.into(),
            AddressKind::Public.into(),
            AddressKind::V6.into(),
            AddressKind::Other(4).into(),
            RouteKind::Punch,
        ];
        for kind in direct {
            let direct = route(kind, "192.0.2.10:7420");
            assert!(hold_relay(&state, Some(&office), &direct).is_none() && !relay_busy(&state, &office));
        }
        // A host that is not paired has no fingerprint to hold it under.
        assert!(hold_relay(&state, None, &route(relay(9), "198.51.100.4:7420")).is_none());
        assert!(hold_relay(&state, Some(&office), &route(relay(9), "198.51.100.4:7420")).is_some());
    }

    #[test]
    fn the_dht_library_is_kept_to_errors_unless_the_user_names_it() {
        let shown = |rust_log: Option<&str>| log_filter_for(rust_log).to_string();
        assert!(shown(None).contains("mainline=error") && shown(None).contains("info"));
        assert!(shown(Some("")).contains("mainline=error"));
        assert!(shown(Some("debug")).contains("mainline=error") && shown(Some("debug")).contains("debug"));
        assert!(shown(Some("velora_client=debug")).contains("mainline=error"));
        // Not a filter at all: the default, which is not allowed to be noisy either.
        assert!(shown(Some("=== not a filter")).contains("mainline=error"));
        // Someone debugging the DHT gets what they asked for.
        assert!(!shown(Some("mainline=debug")).contains("mainline=error"));
        assert!(shown(Some("info,mainline=trace")).contains("mainline=trace"));
    }
}
