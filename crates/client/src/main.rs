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
    num::NonZeroU32,
    path::PathBuf,
    rc::Rc,
    sync::{
        atomic::{AtomicU32, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use anyhow::Result;
use clap::{Parser, Subcommand};
use settings::Settings;
use velora_client_core::{hosts, FrameSlot, InputSender, OfferEvent, Session, VideoFrame, VideoOutput};
use velora_protocol::{
    identity::StateDir,
    wire::{KeyState, MouseButton},
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
    },
    /// Connect to a paired host by name or address.
    Connect { host: String },
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
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with_writer(std::io::stderr)
        .init();

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
            if !settings.open_at_login {
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

    let device_name = settings.device_name;
    let password = if cli.password_stdin { Some(read_password()?).filter(|p| !p.is_empty()) } else { None };
    let password = password.as_deref();
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
        Command::Pair { address, code, name } => {
            let (proxy, event_loop) = new_event_loop()?;
            let slot = Arc::new(FrameSlot::default());
            let output = VideoOutput::Decoded { slot: slot.clone(), on_frame: redraw_callback(proxy) };
            let name = name.unwrap_or(device_name);
            let session = runtime.block_on(hosts::pair(&state, &address, &code, &name, password, output))?;
            println!("Paired with '{}'. Next time: velora connect {}", session.host_name, session.host_name);
            run_window(&runtime, event_loop, session, slot)
        }
        Command::Connect { host } => {
            let (proxy, event_loop) = new_event_loop()?;
            let slot = Arc::new(FrameSlot::default());
            let output = VideoOutput::Decoded { slot: slot.clone(), on_frame: redraw_callback(proxy) };
            let session = runtime.block_on(hosts::connect(&state, &host, &device_name, password, output))?;
            run_window(&runtime, event_loop, session, slot)
        }
        Command::Bench { host, seconds } => runtime.block_on(async {
            let frames = Arc::new(AtomicU32::new(0));
            let counter = frames.clone();
            let on_frame = Arc::new(move || {
                counter.fetch_add(1, Ordering::Relaxed);
            });
            let output = VideoOutput::Decoded { slot: Arc::new(FrameSlot::default()), on_frame };
            let session = hosts::connect(&state, &host, &device_name, password, output).await?;
            println!("connected to '{}' ({}x{})", session.host_name, session.width, session.height);
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
) -> Result<()> {
    let session = Arc::new(session);
    let transfers = Arc::new(Mutex::new(Transfers::default()));
    let proxy = event_loop.create_proxy();
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
    println!("Shortcuts: Ctrl+Alt+Shift+F fullscreen, Ctrl+Alt+Shift+Q quit");
    let mut app = App {
        input: session.input.clone(),
        frames,
        runtime: runtime.handle().clone(),
        proxy,
        transfers,
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
    /// Base title, and the one on screen (with transfers).
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
        let title = match self.transfers.lock().unwrap().summary() {
            Some(summary) => format!("{} · {summary}", self.title),
            None => self.title.clone(),
        };
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
            _ => return false,
        }
        // The modifiers already reached the host; don't leave them held there.
        self.input.release_all();
        true
    }
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
