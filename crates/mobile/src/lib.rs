//! The client exported to the mobile apps through UniFFI.
//!
//! Calls that touch the network block and must run off the UI thread. After connecting, the
//! app calls [`Session::start`] with its listener; video is then delivered as encoded H.264
//! access units, in order, for the platform's hardware decoder, and the app reports each
//! frame back with [`Session::frame_done`] once it is on screen, which paces the host.

use std::sync::{Arc, Mutex, OnceLock};

use velora_client_core::{hosts, EncodedFrame, VideoOutput};
use velora_protocol::{
    identity::StateDir,
    wire::{KeyState, MouseButton as WireButton},
};

uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum MobileError {
    #[error("{0}")]
    Failed(String),
    /// The host has an access password: ask for it and call again with it.
    #[error("this computer asks for a password")]
    PasswordRequired,
    #[error("wrong password")]
    WrongPassword,
}

impl From<anyhow::Error> for MobileError {
    fn from(e: anyhow::Error) -> Self {
        match e.downcast_ref::<velora_client_core::PasswordRequired>() {
            Some(p) if p.wrong => Self::WrongPassword,
            Some(_) => Self::PasswordRequired,
            None => Self::Failed(format!("{e:#}")),
        }
    }
}

type Result<T> = std::result::Result<T, MobileError>;

fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("velora-net")
            .enable_all()
            .build()
            .expect("starting the network runtime")
    })
}

fn init_logging() {
    #[cfg(target_os = "android")]
    {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            use tracing_subscriber::layer::SubscriberExt;
            let subscriber = tracing_subscriber::registry().with(paranoid_android::layer("Velora"));
            let _ = tracing::subscriber::set_global_default(subscriber);
        });
    }
}

#[derive(uniffi::Record)]
pub struct HostEntry {
    pub name: String,
    pub address: String,
}

#[derive(uniffi::Record)]
pub struct VideoFrame {
    pub frame_id: u32,
    pub keyframe: bool,
    pub width: u16,
    pub height: u16,
    /// H.264 Annex-B access unit.
    pub data: Vec<u8>,
}

#[derive(uniffi::Enum)]
pub enum Button {
    Left,
    Right,
    Middle,
}

/// Implemented by the app. Called from background threads.
#[uniffi::export(with_foreign)]
pub trait SessionListener: Send + Sync {
    fn on_video_frame(&self, frame: VideoFrame);
    fn on_closed(&self, reason: String);
}

#[derive(uniffi::Object)]
pub struct Client {
    state: StateDir,
    device_name: String,
}

#[uniffi::export]
impl Client {
    /// `config_dir` holds this device's identity and paired hosts (the app's private files).
    #[uniffi::constructor]
    pub fn new(config_dir: String, device_name: String) -> Result<Arc<Self>> {
        init_logging();
        Ok(Arc::new(Self { state: StateDir::open(Some(config_dir.into()), "client")?, device_name }))
    }

    pub fn hosts(&self) -> Result<Vec<HostEntry>> {
        Ok(hosts::list(&self.state)?.into_iter().map(|h| HostEntry { name: h.name, address: h.address }).collect())
    }

    pub fn forget(&self, name: String) -> Result<()> {
        Ok(hosts::forget(&self.state, &name)?)
    }

    /// Pairs with the code printed by `velora-host run --pair`. Blocking. Fails with
    /// `PasswordRequired` / `WrongPassword` when the host has an access password; the code
    /// stays valid, so call again with the password.
    pub fn pair(&self, address: String, code: String, password: Option<String>) -> Result<Arc<Session>> {
        let gate = Arc::new(Gate::default());
        let output = gate.output();
        let session = runtime().block_on(hosts::pair(
            &self.state,
            address.trim(),
            &[],
            code.trim(),
            &self.device_name,
            password.as_deref(),
            output,
        ))?;
        Ok(Arc::new(Session { inner: Arc::new(session), gate }))
    }

    /// Connects to a paired host by name. Blocking. Fails like [`Client::pair`] when a
    /// password is needed.
    pub fn connect(&self, host: String, password: Option<String>) -> Result<Arc<Session>> {
        let gate = Arc::new(Gate::default());
        let output = gate.output();
        let session =
            runtime().block_on(hosts::connect(&self.state, &host, &self.device_name, password.as_deref(), output))?;
        Ok(Arc::new(Session { inner: Arc::new(session), gate }))
    }
}

/// Holds frames that arrive before the app has attached its listener.
#[derive(Default)]
struct Gate {
    state: Mutex<GateState>,
}

#[derive(Default)]
struct GateState {
    listener: Option<Arc<dyn SessionListener>>,
    pending: Vec<VideoFrame>,
}

impl Gate {
    // Delivery happens under the lock so frames held back before `attach` can never be
    // overtaken by newer ones; the listener only queues frames, so the hold is short.
    fn output(self: &Arc<Self>) -> VideoOutput {
        let gate = self.clone();
        VideoOutput::Encoded(Arc::new(move |f: EncodedFrame| {
            let frame = VideoFrame {
                frame_id: f.frame_id,
                keyframe: f.keyframe,
                width: f.width,
                height: f.height,
                data: f.data,
            };
            let mut state = gate.state.lock().unwrap();
            match &state.listener {
                Some(l) => l.on_video_frame(frame),
                None => state.pending.push(frame),
            }
        }))
    }

    fn attach(&self, listener: Arc<dyn SessionListener>) {
        let mut state = self.state.lock().unwrap();
        for frame in std::mem::take(&mut state.pending) {
            listener.on_video_frame(frame);
        }
        state.listener = Some(listener);
    }
}

/// An active connection. Input methods are cheap and non-blocking.
#[derive(uniffi::Object)]
pub struct Session {
    inner: Arc<velora_client_core::Session>,
    gate: Arc<Gate>,
}

#[uniffi::export]
impl Session {
    /// Starts delivering video and the close notification to `listener`.
    pub fn start(&self, listener: Arc<dyn SessionListener>) {
        let watch = self.inner.clone();
        let on_close = listener.clone();
        runtime().spawn(async move {
            let reason = watch.closed().await;
            on_close.on_closed(reason);
        });
        self.gate.attach(listener);
    }

    pub fn host_name(&self) -> String {
        self.inner.host_name.clone()
    }

    /// Remote display size; frames carry their own size if it changes.
    pub fn width(&self) -> u16 {
        self.inner.width
    }

    pub fn height(&self) -> u16 {
        self.inner.height
    }

    pub fn rtt_ms(&self) -> f64 {
        self.inner.rtt().as_secs_f64() * 1000.0
    }

    /// Absolute pointer position, `0..=65535` on each axis of the remote display.
    pub fn mouse_move(&self, x: u16, y: u16) {
        self.inner.input.mouse_move(x, y);
    }

    pub fn mouse_button(&self, button: Button, down: bool, x: u16, y: u16) {
        let button = match button {
            Button::Left => WireButton::Left,
            Button::Right => WireButton::Right,
            Button::Middle => WireButton::Middle,
        };
        self.inner.input.mouse_button(button, down, x, y);
    }

    /// 120 units per wheel notch; positive `dy` scrolls up, positive `dx` scrolls right.
    pub fn scroll(&self, dx: i16, dy: i16) {
        self.inner.input.scroll(dx, dy);
    }

    /// Physical key by Linux evdev code (e.g. 1 = Esc, 15 = Tab, 29 = left Ctrl).
    pub fn key(&self, code: u16, down: bool) {
        self.inner.input.key(code, if down { KeyState::Down } else { KeyState::Up });
    }

    /// Types text on the host, whatever its keyboard layout.
    pub fn text(&self, text: String) {
        self.inner.input.text(&text);
    }

    pub fn release_all(&self) {
        self.inner.input.release_all();
    }

    pub fn request_keyframe(&self) {
        self.inner.input.request_keyframe();
    }

    /// Call once a delivered frame has been rendered (or dropped).
    pub fn frame_done(&self, frame_id: u32) {
        self.inner.input.frame_done(frame_id);
    }

    /// Ends the session. (`close()` on the Kotlin object only frees the handle.)
    pub fn disconnect(&self) {
        self.inner.close();
    }
}
