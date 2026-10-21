// The launcher is a GUI app: no console window on Windows (see `attach_console`).
#![cfg_attr(windows, windows_subsystem = "windows")]

mod gui;
mod keymap;
mod render;
mod settings;

use std::{
    num::NonZeroU32,
    path::PathBuf,
    rc::Rc,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::Result;
use clap::{Parser, Subcommand};
use settings::Settings;
use velora_client_core::{hosts, FrameSlot, InputSender, Session, VideoFrame, VideoOutput};
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
    #[command(subcommand)]
    command: Option<Command>,
}

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
}

fn main() -> Result<()> {
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
        return gui::run(state, cli.config_dir, no_update);
    };
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
    match command {
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
            let session = runtime.block_on(hosts::pair(&state, &address, &code, &name, output))?;
            println!("Paired with '{}'. Next time: velora connect {}", session.host_name, session.host_name);
            run_window(&runtime, event_loop, session, slot)
        }
        Command::Connect { host } => {
            let (proxy, event_loop) = new_event_loop()?;
            let slot = Arc::new(FrameSlot::default());
            let output = VideoOutput::Decoded { slot: slot.clone(), on_frame: redraw_callback(proxy) };
            let session = runtime.block_on(hosts::connect(&state, &host, &device_name, output))?;
            run_window(&runtime, event_loop, session, slot)
        }
        Command::Bench { host, seconds } => runtime.block_on(async {
            let frames = Arc::new(AtomicU32::new(0));
            let counter = frames.clone();
            let on_frame = Arc::new(move || {
                counter.fetch_add(1, Ordering::Relaxed);
            });
            let output = VideoOutput::Decoded { slot: Arc::new(FrameSlot::default()), on_frame };
            let session = hosts::connect(&state, &host, &device_name, output).await?;
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
        title: format!("{} — Velora", session.host_name),
        remote_size: (session.width as u32, session.height as u32),
        session,
        window: None,
        surface: None,
        current: None,
        viewport: render::Viewport::default(),
        cursor: (0.0, 0.0),
        modifiers: ModifiersState::empty(),
    };
    event_loop.run_app(&mut app)?;
    Ok(())
}

type Surface = softbuffer::Surface<Rc<Window>, Rc<Window>>;

struct App {
    session: Arc<Session>,
    input: InputSender,
    frames: Arc<FrameSlot>,
    title: String,
    remote_size: (u32, u32),
    window: Option<Rc<Window>>,
    surface: Option<Surface>,
    current: Option<VideoFrame>,
    viewport: render::Viewport,
    cursor: (f64, f64),
    modifiers: ModifiersState,
}

impl App {
    fn pointer(&self) -> (u16, u16) {
        self.viewport.normalize(self.cursor.0, self.cursor.1)
    }

    fn redraw(&mut self) -> Result<()> {
        let (Some(window), Some(surface)) = (&self.window, &mut self.surface) else { return Ok(()) };
        if let Some(frame) = self.frames.take() {
            if let Some(old) = self.current.replace(frame) {
                self.frames.recycle(old);
            }
        }
        let size = window.inner_size();
        let (Some(w), Some(h)) = (NonZeroU32::new(size.width), NonZeroU32::new(size.height)) else { return Ok(()) };
        surface.resize(w, h).map_err(|e| anyhow::anyhow!("{e}"))?;
        let mut buffer = surface.buffer_mut().map_err(|e| anyhow::anyhow!("{e}"))?;
        match &self.current {
            Some(f) => self.viewport = render::draw(&f.pixels, f.width, f.height, &mut buffer, w.get(), h.get()),
            None => buffer.fill(0),
        }
        buffer.present().map_err(|e| anyhow::anyhow!("{e}"))?;
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
        let surface = softbuffer::Context::new(window.clone()).and_then(|ctx| Surface::new(&ctx, window.clone()));
        match surface {
            Ok(s) => self.surface = Some(s),
            Err(e) => {
                eprintln!("cannot create drawing surface: {e}");
                event_loop.exit();
                return;
            }
        }
        self.window = Some(window);
    }

    fn user_event(&mut self, _event_loop: &ActiveEventLoop, _event: ()) {
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
