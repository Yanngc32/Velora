//! The client exported to the mobile apps through UniFFI.
//!
//! Calls that touch the network block and must run off the UI thread. After connecting, the
//! app calls [`Session::start`] with its listener; video is then delivered as encoded H.264
//! access units, in order, for the platform's hardware decoder, and the app reports each
//! frame back with [`Session::frame_done`] once it is on screen, which paces the host.

use std::sync::{Arc, Mutex, OnceLock};

use velora_client_core::{
    hosts, ConnectMode as CoreMode, EncodedFrame, LinkState, Route, RouteKind, VideoOutput, WakeOutcome as CoreWake,
};
use velora_protocol::{
    identity::{KnownHost, StateDir},
    wire::{AddressKind as WireKind, KeyState, MouseButton as WireButton},
};

uniffi::setup_scaffolding!();

mod files;

pub use files::{FileEntry, FileKind, Files, OfferListener, TransferListener};

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
    /// The kinds of address the computer said it has the last time it was connected to, most useful first and each
    /// once: on its local network, on a VPN mesh, public on the internet, IPv6, behind a relay. Empty until it has
    /// said (it was paired before this version, or its Velora is older), which is no statement about it. The app can
    /// tell from them whether the computer is likely to answer from other networks. Extra data: it has a default,
    /// so code that builds a `HostEntry` by hand, or ignores this, keeps working.
    #[uniffi(default = [])]
    pub kinds: Vec<AddressKind>,
}

/// How one of a computer's addresses is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum AddressKind {
    /// On the computer's local network.
    Lan,
    /// On a VPN mesh such as Tailscale or Netbird.
    Vpn,
    /// The router's public IPv4 address and the port it maps to the computer.
    Public,
    /// A global IPv6 address.
    V6,
    /// Through another paired computer that relays.
    Relay,
    /// A kind this version does not know.
    Other,
}

impl From<&WireKind> for AddressKind {
    fn from(kind: &WireKind) -> Self {
        match kind {
            WireKind::Lan => Self::Lan,
            WireKind::Vpn => Self::Vpn,
            WireKind::Public => Self::Public,
            WireKind::V6 => Self::V6,
            WireKind::Relay(_) => Self::Relay,
            WireKind::Other(_) => Self::Other,
        }
    }
}

/// What `Client.wake` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum WakeOutcome {
    /// The wake-up packet was sent, from this device's own network or by a relay. Whether the computer wakes depends on
    /// its firmware and Windows settings, which nothing here can see.
    Sent,
    /// The computer never told its network adapter's address (it has not connected since it learned to), so there is
    /// nothing to wake it by. Connect to it once while it is awake.
    Unsupported,
    /// This device is not on the computer's network, and no relay it is registered with could send the packet.
    NoRelay,
}

impl From<CoreWake> for WakeOutcome {
    fn from(outcome: CoreWake) -> Self {
        match outcome {
            CoreWake::Sent => Self::Sent,
            CoreWake::Unsupported => Self::Unsupported,
            CoreWake::NoRelay => Self::NoRelay,
        }
    }
}

/// Which ways of reaching a computer a connection may take: the user's choice, kept per computer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ConnectionMode {
    /// Whichever answers first, and a better one when it appears during the session.
    Auto,
    /// Only the computer's addresses on the local network.
    Lan,
    /// Only its addresses on a VPN mesh (Tailscale, Netbird).
    Vpn,
    /// Only Velora's own ways from other networks: public address, IPv6, hole punching, relays.
    Velora,
}

impl From<CoreMode> for ConnectionMode {
    fn from(mode: CoreMode) -> Self {
        match mode {
            CoreMode::Auto => Self::Auto,
            CoreMode::Lan => Self::Lan,
            CoreMode::Vpn => Self::Vpn,
            CoreMode::Velora => Self::Velora,
        }
    }
}

impl From<ConnectionMode> for CoreMode {
    fn from(mode: ConnectionMode) -> Self {
        match mode {
            ConnectionMode::Auto => Self::Auto,
            ConnectionMode::Lan => Self::Lan,
            ConnectionMode::Vpn => Self::Vpn,
            ConnectionMode::Velora => Self::Velora,
        }
    }
}

/// The way a connection reached the computer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum Way {
    Lan,
    Vpn,
    Public,
    V6,
    /// A hole punched through the NATs on both sides.
    Punch,
    /// Through another paired computer that relays.
    Relay,
    Other,
}

impl From<&Route> for Way {
    fn from(route: &Route) -> Self {
        match &route.kind {
            RouteKind::Punch => Self::Punch,
            RouteKind::Address(kind) => match AddressKind::from(kind) {
                AddressKind::Lan => Self::Lan,
                AddressKind::Vpn => Self::Vpn,
                AddressKind::Public => Self::Public,
                AddressKind::V6 => Self::V6,
                AddressKind::Relay => Self::Relay,
                AddressKind::Other => Self::Other,
            },
        }
    }
}

/// How a session's connection stands.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum LinkStatus {
    /// Connected that way: at first, after reconnecting, or after moving to a better way during the session.
    Up { way: Way, address: String },
    /// The connection was lost and the session is getting it back (for about a minute and a half; then `on_closed`).
    Reconnecting,
}

impl From<&LinkState> for LinkStatus {
    fn from(state: &LinkState) -> Self {
        match state {
            LinkState::Up(route) => Self::Up { way: route.into(), address: route.address.clone() },
            LinkState::Reconnecting => Self::Reconnecting,
        }
    }
}

/// Implemented by the app to follow a session's connection. Called from background threads.
#[uniffi::export(with_foreign)]
pub trait LinkListener: Send + Sync {
    fn on_link(&self, status: LinkStatus);
}

/// The distinct kinds of address a paired computer last listed, in the order it listed them.
fn kinds_of(host: &KnownHost) -> Vec<AddressKind> {
    let mut kinds = Vec::new();
    for kind in host.kinds.iter().map(|(kind, _)| AddressKind::from(kind)) {
        if !kinds.contains(&kind) {
            kinds.push(kind);
        }
    }
    kinds
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
        let list = hosts::list(&self.state)?;
        Ok(list.into_iter().map(|h| HostEntry { kinds: kinds_of(&h), name: h.name, address: h.address }).collect())
    }

    pub fn forget(&self, name: String) -> Result<()> {
        Ok(hosts::forget(&self.state, &name)?)
    }

    /// The connection mode chosen for the paired computer `name`.
    pub fn connection_mode(&self, name: String) -> Result<ConnectionMode> {
        let host = hosts::list(&self.state)?.into_iter().find(|h| h.name == name);
        Ok(host.map_or(ConnectionMode::Auto, |h| h.mode.into()))
    }

    /// Sets which ways connections to the paired computer `name` may take; from the next connection on.
    pub fn set_connection_mode(&self, name: String, mode: ConnectionMode) -> Result<()> {
        Ok(hosts::set_mode(&self.state, &name, mode.into())?)
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

    /// Wakes a paired computer that is asleep, by Wake-on-LAN: the packet goes out of this device's own network when
    /// the computer is on it (the phone on the home Wi-Fi), and otherwise a relay on the computer's network is asked
    /// to send it. `host` is a name from `hosts()`. Blocking: at once when the computer is on this device's network,
    /// and up to about 25 seconds when relays are asked and do not answer, so call it off the UI thread. It does not
    /// wait for the computer to wake: connect to it a little later. Fails when the computer is not paired (or this
    /// device's own files cannot be read); "nothing could be done" is a `WakeOutcome`, not a failure.
    pub fn wake(&self, host: String) -> Result<WakeOutcome> {
        Ok(runtime().block_on(hosts::wake(&self.state, &host))?.into())
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

    /// How the current connection reached the computer.
    pub fn link(&self) -> LinkStatus {
        let route = self.inner.route();
        LinkStatus::Up { way: (&route).into(), address: route.address }
    }

    /// Calls `listener` with how the connection stands: right away, and whenever it is lost, regained or moved to a
    /// better way.
    pub fn watch_link(&self, listener: Arc<dyn LinkListener>) {
        self.inner.on_link(Arc::new(move |state: &LinkState| listener.on_link(state.into())));
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

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU32, Ordering},
    };

    use super::*;

    /// A directory under the system's temporary one, removed when dropped.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static COUNT: AtomicU32 = AtomicU32::new(0);
            let name = format!("velora-mobile-{}-{}", std::process::id(), COUNT.fetch_add(1, Ordering::Relaxed));
            let path = std::env::temp_dir().join(name);
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        /// The app's private directory, as `Client::new` takes it.
        fn path(&self) -> String {
            self.0.to_str().unwrap().to_string()
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn host(name: &str, address: &str, kinds: Vec<(WireKind, &str)>) -> KnownHost {
        KnownHost {
            name: name.into(),
            address: address.into(),
            fingerprint: "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM".into(),
            kinds: kinds.into_iter().map(|(kind, address)| (kind, address.to_string())).collect(),
            ..Default::default()
        }
    }

    /// A client whose paired computers are `hosts`.
    fn client_with(dir: &TempDir, hosts: &[KnownHost]) -> Arc<Client> {
        StateDir::open(Some(dir.path().into()), "client").unwrap().save(StateDir::KNOWN_HOSTS, &hosts).unwrap();
        Client::new(dir.path(), "test phone".into()).unwrap()
    }

    #[test]
    fn every_kind_of_address_has_a_name_for_the_app() {
        for (wire, expected) in [
            (WireKind::Lan, AddressKind::Lan),
            (WireKind::Vpn, AddressKind::Vpn),
            (WireKind::Public, AddressKind::Public),
            (WireKind::V6, AddressKind::V6),
            // The relay's fingerprint is for the connection code, not for a screen.
            (WireKind::Relay("fingerprint".into()), AddressKind::Relay),
            (WireKind::Other(9), AddressKind::Other),
        ] {
            assert_eq!(AddressKind::from(&wire), expected, "{wire:?}");
        }
    }

    #[test]
    fn what_a_computer_listed_is_told_once_per_kind_in_its_order() {
        let listed = host(
            "pc",
            "192.0.2.10:7420",
            vec![
                (WireKind::Lan, "192.0.2.10:7420"),
                (WireKind::Vpn, "100.64.0.5:7420"),
                (WireKind::Lan, "192.0.2.11:7420"),
                (WireKind::V6, "[2001:db8::10]:7420"),
                (WireKind::Vpn, "[fd00::5]:7420"),
                (WireKind::Relay("one".into()), "203.0.113.9:7420"),
                (WireKind::Relay("two".into()), "203.0.113.10:7420"),
            ],
        );
        assert_eq!(kinds_of(&listed), vec![AddressKind::Lan, AddressKind::Vpn, AddressKind::V6, AddressKind::Relay]);
        // A computer that has not said, as one paired before this version: no kinds, not a guess.
        assert!(kinds_of(&host("old", "192.0.2.12:7420", Vec::new())).is_empty());
    }

    #[test]
    fn the_connection_mode_is_kept_per_computer_and_every_way_has_a_name() {
        let dir = TempDir::new();
        let client = client_with(&dir, &[host("desk", "192.0.2.10:7420", Vec::new())]);
        assert_eq!(client.connection_mode("desk".into()).unwrap(), ConnectionMode::Auto);
        client.set_connection_mode("desk".into(), ConnectionMode::Vpn).unwrap();
        assert_eq!(client.connection_mode("desk".into()).unwrap(), ConnectionMode::Vpn);
        assert!(client.set_connection_mode("nobody".into(), ConnectionMode::Lan).is_err());
        for mode in CoreMode::ALL {
            assert_eq!(CoreMode::from(ConnectionMode::from(mode)), mode);
        }
        let route = |kind: RouteKind| Route { kind, address: "192.0.2.10:7420".into() };
        assert_eq!(Way::from(&route(RouteKind::Punch)), Way::Punch);
        assert_eq!(Way::from(&route(WireKind::Relay("one".into()).into())), Way::Relay);
        assert_eq!(Way::from(&route(WireKind::Vpn.into())), Way::Vpn);
        assert_eq!(
            LinkStatus::from(&LinkState::Up(route(WireKind::Lan.into()))),
            LinkStatus::Up { way: Way::Lan, address: "192.0.2.10:7420".into() }
        );
        assert_eq!(LinkStatus::from(&LinkState::Reconnecting), LinkStatus::Reconnecting);
    }

    #[test]
    fn the_wake_outcomes_are_the_clients_one_for_one() {
        assert_eq!(WakeOutcome::from(CoreWake::Sent), WakeOutcome::Sent);
        assert_eq!(WakeOutcome::from(CoreWake::Unsupported), WakeOutcome::Unsupported);
        assert_eq!(WakeOutcome::from(CoreWake::NoRelay), WakeOutcome::NoRelay);
    }

    #[test]
    fn the_hosts_keep_their_name_and_address_and_carry_the_kinds() {
        let dir = TempDir::new();
        let client = client_with(
            &dir,
            &[
                host(
                    "desk",
                    "192.0.2.10:7420",
                    vec![(WireKind::Lan, "192.0.2.10:7420"), (WireKind::Public, "203.0.113.7:51820")],
                ),
                host("laptop", "192.0.2.20:7420", Vec::new()),
            ],
        );
        let hosts = client.hosts().unwrap();
        let seen: Vec<(&str, &str)> = hosts.iter().map(|h| (h.name.as_str(), h.address.as_str())).collect();
        assert_eq!(seen, vec![("desk", "192.0.2.10:7420"), ("laptop", "192.0.2.20:7420")]);
        assert_eq!(hosts[0].kinds, vec![AddressKind::Lan, AddressKind::Public]);
        assert!(hosts[1].kinds.is_empty());
    }

    #[test]
    fn wake_says_what_it_could_do_and_fails_only_for_a_computer_that_is_not_paired() {
        let dir = TempDir::new();
        let mut asleep = host("asleep", "192.0.2.30:7420", vec![(WireKind::Lan, "192.0.2.30:7420")]);
        let silent = host("silent", "192.0.2.31:7420", Vec::new());
        // On a documentation network that no network of this device holds, and with no relay to ask.
        asleep.mac = Some([0x02, 1, 2, 3, 4, 5]);
        let client = client_with(&dir, &[asleep, silent]);

        // It never told its adapter's address: nothing to wake it by.
        assert_eq!(client.wake("silent".into()).unwrap(), WakeOutcome::Unsupported);
        // Not on this device's network, and nobody to ask.
        assert_eq!(client.wake("asleep".into()).unwrap(), WakeOutcome::NoRelay);
        // The name is the one `hosts()` gives, or the main address, like `connect`.
        assert_eq!(client.wake("192.0.2.30:7420".into()).unwrap(), WakeOutcome::NoRelay);
        let err = client.wake("nobody".into()).unwrap_err();
        assert!(matches!(&err, MobileError::Failed(why) if why.contains("is not paired yet")), "{err}");
    }
}
