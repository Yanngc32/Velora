//! Platform-independent client: connection, authentication, input sending and video
//! delivery. UIs only draw frames and feed input: the desktop gets decoded RGB pictures,
//! mobile apps get the H.264 stream in order and decode it in hardware.

#[cfg(all(windows, feature = "ffmpeg"))]
mod d3d11;
pub mod files;
pub mod hosts;
#[cfg(feature = "ffmpeg")]
mod hwdecode;
pub mod reach;
mod reorder;
#[cfg(feature = "decode")]
mod video;

use std::{
    future::Future,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Mutex,
    },
};

use anyhow::{bail, Result};
use tokio::sync::mpsc;
use velora_protocol::{
    identity::Identity,
    tls::{self, Fingerprint},
    wire::{
        self, AudioPacket, ClientMsg, DisplayList, FrameHeader, HelloExt, HostMsg, KeyState, MouseButton, MouseMove,
        FEATURE_AUDIO, FEATURE_CLIPBOARD, FEATURE_FILES, PROTOCOL_VERSION,
    },
};

pub use files::{OfferEvent, RemoteFiles};
pub use reach::{ReachInfo, Route, RouteKind, WakeOutcome};

#[cfg(feature = "decode")]
pub use video::{Chroma, FrameSlot, GpuPicture, VideoFrame};

/// An encoded frame, delivered in order. Acknowledge it with [`InputSender::frame_done`] once
/// it has been displayed: that is what paces the host.
pub struct EncodedFrame {
    pub frame_id: u32,
    pub keyframe: bool,
    pub width: u16,
    pub height: u16,
    /// H.264 Annex-B access unit.
    pub data: Vec<u8>,
}

pub enum VideoOutput {
    /// Decode in software into `slot`; `on_frame` runs (on the decoder thread) after each new
    /// picture, e.g. to request a redraw. Frames are acknowledged automatically.
    #[cfg(feature = "decode")]
    Decoded { slot: Arc<FrameSlot>, on_frame: Arc<dyn Fn() + Send + Sync> },
    /// Hand encoded frames, in order, to the caller's decoder.
    Encoded(Arc<dyn Fn(EncodedFrame) + Send + Sync>),
}

#[derive(Clone)]
pub struct ConnectParams {
    pub addr: SocketAddr,
    /// Other addresses of the host (LAN, VPN mesh): tried at once, a little after `addr`, and
    /// the first to answer is used.
    pub also: Vec<SocketAddr>,
    pub host_fingerprint: Fingerprint,
    pub identity: Identity,
    pub device_name: String,
    /// Set when pairing for the first time.
    pub pairing_secret: Option<[u8; wire::PAIRING_SECRET_LEN]>,
    /// The host's access password, when the user gave one.
    pub password: Option<String>,
    /// What this device remembers about reaching the host from other networks (see [`reach`]):
    /// more addresses with their kinds, relays, the DHT key. `None` for a host never connected
    /// to, as when pairing; the race then has `addr` and `also` and nothing else.
    pub reach: Option<reach::ReachParams>,
}

/// The host has an access password: ask the user for it and connect again with
/// [`ConnectParams::password`]. Find it in a connection error with `downcast_ref`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordRequired {
    /// A password was sent and it was wrong.
    pub wrong: bool,
}

impl std::fmt::Display for PasswordRequired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.wrong { "wrong password" } else { "this computer asks for a password" })
    }
}

impl std::error::Error for PasswordRequired {}

/// The host ended the connection without a word: what hosts that predate hello extensions do
/// with a hello that has them.
#[derive(Debug)]
struct NoReply;

impl std::fmt::Display for NoReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the host closed the connection")
    }
}

impl std::error::Error for NoReply {}

/// A connection the host accepted.
struct Handshake {
    endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    host_name: String,
    newly_paired: bool,
    width: u16,
    height: u16,
    features: u32,
    addresses: Vec<String>,
    route: Route,
}

/// A connection to the host whose TLS handshake is done, and the way it was made.
struct Established {
    endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    route: Route,
}

/// Sets up the secure connection to the host, racing the ways of reaching it (see [`reach`]):
/// the addresses stored for it, then more that the DHT lookup finds while the race runs, the
/// relays it is registered with, a hole punch. Only the TLS handshake races: the host opens
/// nothing before the hello, which goes on the winner alone, so the others never become a
/// session that would take over.
async fn establish(params: &ConnectParams) -> Result<Established> {
    let shared = Arc::new(params.clone());
    // Only with the host's key and this device's secret, which come with its `Reach`.
    let lookup = reach::can_resolve(params).then(|| {
        let shared = shared.clone();
        async move { reach::resolve_record(&shared).await }
    });
    establish_with(shared, lookup).await
}

/// [`establish`] with the lookup given, so that tests can bring candidates in late.
async fn establish_with<L>(params: Arc<ConnectParams>, lookup: Option<L>) -> Result<Established>
where
    L: Future<Output = Result<Vec<reach::Candidate>>> + Send + 'static,
{
    let config = tls::client_config(&params.identity, params.host_fingerprint)?;
    let first = reach::stored_candidates(&params);
    let dial = move |candidate: reach::Candidate| {
        let (params, config) = (params.clone(), config.clone());
        async move { reach::dial(&params, config, &candidate).await }
    };
    let (candidate, (endpoint, conn)) = reach::race(first, lookup, dial).await.map_err(|e| {
        e.context("could not establish a secure connection (wrong address or host fingerprint changed?)")
    })?;
    Ok(Established { endpoint, conn, route: candidate.route() })
}

async fn handshake(params: &ConnectParams, ext: Option<HelloExt>) -> Result<Handshake> {
    let Established { endpoint, conn, route } = establish(params).await?;

    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(
        &ClientMsg::Hello {
            version: PROTOCOL_VERSION,
            name: params.device_name.clone(),
            pairing_secret: params.pairing_secret,
            password: params.password.clone(),
            ext,
        }
        .encode(),
    )
    .await?;

    let mut newly_paired = false;
    loop {
        let body = match wire::read_msg(&mut recv).await {
            Ok(Some(body)) => body,
            Ok(None) | Err(_) if !newly_paired => return Err(NoReply.into()),
            Ok(None) => bail!("host closed the connection"),
            Err(e) => return Err(e),
        };
        match HostMsg::decode(&body)? {
            HostMsg::Paired => newly_paired = true,
            HostMsg::Welcome { version, host_name, width, height, features, addresses, .. } => {
                if version != PROTOCOL_VERSION {
                    bail!("host uses protocol version {version}, expected {PROTOCOL_VERSION}");
                }
                return Ok(Handshake {
                    endpoint,
                    conn,
                    send,
                    recv,
                    host_name,
                    newly_paired,
                    width,
                    height,
                    features: features.unwrap_or(0),
                    addresses,
                    route,
                });
            }
            HostMsg::Rejected { reason } => bail!("host rejected the connection: {reason}"),
            HostMsg::PasswordRequired { wrong } => return Err(PasswordRequired { wrong }.into()),
            // Only follows the welcome.
            HostMsg::Displays(_) => bail!("displays before the welcome"),
            // `Reach` follows the welcome too (see `read_control`); the other two are what a relay says to the dialer
            // that asked it, on a connection of its own, never to the hello of a host.
            HostMsg::Reach { .. } | HostMsg::RelayStatus { .. } | HostMsg::PunchRequest { .. } => {
                bail!("unexpected message before the welcome")
            }
        }
    }
}

/// Called with the host's displays (see [`Session::on_displays`]).
pub type DisplaysListener = Arc<dyn Fn(&DisplayList) + Send + Sync>;

/// The host's displays as last announced, and who to tell when they change.
#[derive(Default)]
struct Displays {
    list: Option<DisplayList>,
    listener: Option<DisplaysListener>,
}

/// Called with what the host said about reaching it from elsewhere (see [`Session::on_reach`]).
pub type ReachListener = Arc<dyn Fn(&ReachInfo) + Send + Sync>;

/// What the host last said about reaching it, and who to tell when it says it.
#[derive(Default)]
struct ReachSlot {
    info: Option<ReachInfo>,
    listeners: Vec<ReachListener>,
}

pub struct Session {
    pub host_name: String,
    /// Where else the host answers (see `HostMsg::Welcome`).
    pub addresses: Vec<String>,
    /// The host accepted the pairing secret and stored this device.
    pub newly_paired: bool,
    pub width: u16,
    pub height: u16,
    pub input: InputSender,
    features: u32,
    displays: Arc<Mutex<Displays>>,
    reach: Arc<Mutex<ReachSlot>>,
    route: Route,
    /// Plays the host's sound, when it sends it.
    audio: Option<Arc<velora_audio::Player>>,
    conn: quinn::Connection,
    runtime: tokio::runtime::Handle,
    _endpoint: quinn::Endpoint,
}

impl Session {
    /// Resolves when the connection ends, with the reason.
    pub async fn closed(&self) -> String {
        match self.conn.closed().await {
            quinn::ConnectionError::ApplicationClosed(c) => String::from_utf8_lossy(&c.reason).into_owned(),
            e => e.to_string(),
        }
    }

    pub fn rtt(&self) -> std::time::Duration {
        self.conn.rtt()
    }

    pub fn close(&self) {
        self.conn.close(0u32.into(), b"client closed");
    }

    /// The host's files, when it serves them (hosts before file transfers don't).
    pub fn files(&self) -> Option<RemoteFiles> {
        (self.features & FEATURE_FILES != 0).then(|| RemoteFiles { conn: self.conn.clone() })
    }

    /// Saves files the host sends (Send To on the host) into `dest`, reporting each transfer.
    /// Hosts without file transfers never send any.
    /// Accepts what the host sends: files into `dest`, reported to `on_event`, and its
    /// clipboard content (kind and bytes, see `velora-clipboard`), passed to `on_clip`.
    pub fn receive_files(
        &self,
        dest: PathBuf,
        on_event: Arc<dyn Fn(OfferEvent) + Send + Sync>,
        on_clip: Arc<dyn Fn(u8, Vec<u8>) + Send + Sync>,
    ) {
        self.runtime.spawn(files::receive_offers(self.conn.clone(), dest, on_event, on_clip));
    }

    /// The host's displays, when it has more than one to choose from (hosts that predate the
    /// choice never say).
    pub fn displays(&self) -> Option<DisplayList> {
        self.displays.lock().unwrap().list.clone()
    }

    /// Calls `listener` with the host's displays: right away if they are known, and whenever
    /// they change (another one is streamed).
    pub fn on_displays(&self, listener: DisplaysListener) {
        let now = {
            let mut displays = self.displays.lock().unwrap();
            displays.listener = Some(listener.clone());
            displays.list.clone()
        };
        if let Some(list) = now {
            listener(&list);
        }
    }

    /// What the host said about reaching it from other networks, once it has said it (hosts that
    /// predate standalone reach never do). Arrives just after the welcome.
    pub fn reach(&self) -> Option<ReachInfo> {
        self.reach.lock().unwrap().info.clone()
    }

    /// Calls `listener` with what the host says about reaching it: right away if it has said,
    /// and again if it says more. Listeners add up; none replaces another, since `hosts` keeps
    /// the known-hosts file up to date through one of them.
    pub fn on_reach(&self, listener: ReachListener) {
        let now = {
            let mut slot = self.reach.lock().unwrap();
            slot.listeners.push(listener.clone());
            slot.info.clone()
        };
        if let Some(info) = now {
            listener(&info);
        }
    }

    /// How this connection was made: the kind of the address that won the race and that address.
    pub fn route(&self) -> &Route {
        &self.route
    }

    /// The host's sound plays here.
    pub fn has_audio(&self) -> bool {
        self.audio.is_some()
    }

    /// Mutes or unmutes the host's sound.
    pub fn set_muted(&self, muted: bool) {
        if let Some(audio) = &self.audio {
            audio.set_muted(muted);
        }
    }

    /// Sends this computer's clipboard content to the host, when it shares its clipboard.
    pub fn send_clipboard(&self, kind: u8, data: Vec<u8>) {
        if self.features & FEATURE_CLIPBOARD == 0 {
            return;
        }
        let conn = self.conn.clone();
        self.runtime.spawn(async move {
            let sent = async {
                let (mut send, _recv) = conn.open_bi().await?;
                velora_protocol::files::send_clipboard(&mut send, kind, &data).await
            };
            match sent.await {
                Ok(()) => tracing::debug!("clipboard sent to the host ({} bytes)", data.len()),
                Err(e) => tracing::debug!("clipboard not sent: {e:#}"),
            }
        });
    }
}

/// A connection for file transfers only: no video or input, and the host's current session,
/// if any, carries on.
pub struct FilesSession {
    pub host_name: String,
    /// Where else the host answers (see `HostMsg::Welcome`).
    pub addresses: Vec<String>,
    pub files: RemoteFiles,
    route: Route,
    conn: quinn::Connection,
    _endpoint: quinn::Endpoint,
}

impl FilesSession {
    pub fn close(&self) {
        self.conn.close(0u32.into(), b"client closed");
    }

    /// How this connection was made, as for [`Session::route`]. A relay carries one connection to a host from a device at
    /// a time, so a caller that sees a relay here has taken the place of any other connection through it.
    pub fn route(&self) -> &Route {
        &self.route
    }
}

impl Drop for FilesSession {
    fn drop(&mut self) {
        self.close();
    }
}

/// Connects for file transfers only.
pub async fn connect_files(params: ConnectParams) -> Result<FilesSession> {
    const TOO_OLD: &str = "this computer's Velora is too old for file transfers; update it";
    let ext = HelloExt { files_only: true, addresses: true, ..Default::default() };
    let hs = match handshake(&params, Some(ext)).await {
        Err(e) if e.is::<NoReply>() => bail!(TOO_OLD),
        hs => hs?,
    };
    if hs.features & FEATURE_FILES == 0 {
        bail!(TOO_OLD);
    }
    // Nothing more is said on the control stream; keep it open for the connection's lifetime.
    let Handshake { endpoint, conn, send, recv, host_name, addresses, route, .. } = hs;
    tokio::spawn(async move {
        let _keep = (send, recv);
        std::future::pending::<()>().await
    });
    Ok(FilesSession {
        host_name,
        addresses,
        files: RemoteFiles { conn: conn.clone() },
        route,
        conn,
        _endpoint: endpoint,
    })
}

/// Connects, authenticates and starts delivering video to `output`.
pub async fn connect(params: ConnectParams, output: VideoOutput) -> Result<Session> {
    let ext = HelloExt {
        files_only: false,
        clipboard: true,
        addresses: true,
        displays: true,
        audio: velora_audio::SUPPORTED,
        // Hosts that predate standalone reach ignore the bit and send nothing more.
        reach: true,
    };
    let hs = match handshake(&params, Some(ext)).await {
        // Hosts that predate hello extensions drop the connection: ask again as they expect.
        Err(e) if e.is::<NoReply>() => handshake(&params, None).await?,
        hs => hs?,
    };
    let Handshake {
        endpoint,
        conn,
        mut send,
        recv,
        host_name,
        newly_paired,
        width,
        height,
        features,
        addresses,
        route,
    } = hs;

    let (control_tx, mut control_rx) = mpsc::unbounded_channel::<ClientMsg>();
    tokio::spawn(async move {
        while let Some(msg) = control_rx.recv().await {
            if send.write_all(&msg.encode()).await.is_err() {
                break;
            }
        }
    });
    // Keep reading: the host announces its displays and how else it can be reached here, and a
    // host-side close is noticed.
    let displays = Arc::new(Mutex::new(Displays::default()));
    let reach = Arc::new(Mutex::new(ReachSlot::default()));
    tokio::spawn(read_control(recv, displays.clone(), reach.clone(), control_tx.clone(), route.clone()));

    // The host's sound arrives in datagrams; newer ones only, a lost one is a short gap.
    let audio = (features & FEATURE_AUDIO != 0).then(velora_audio::Player::start).and_then(|player| match player {
        Ok(player) => Some(Arc::new(player)),
        Err(e) => {
            tracing::warn!("cannot play the host's sound: {e:#}");
            None
        }
    });
    if let Some(player) = audio.clone() {
        let conn = conn.clone();
        tokio::spawn(async move {
            let mut last = 0;
            while let Ok(datagram) = conn.read_datagram().await {
                let Ok(packet) = AudioPacket::decode(&datagram) else { continue };
                if packet.is_newer_than(last) {
                    if last == 0 {
                        tracing::info!("playing the host's sound");
                    }
                    last = packet.seq;
                    player.push(packet.data);
                }
            }
        });
    }

    let decoder = match output {
        #[cfg(feature = "decode")]
        VideoOutput::Decoded { slot, on_frame } => video::spawn_decoder(slot, control_tx.clone(), on_frame),
        VideoOutput::Encoded(sink) => spawn_encoded(sink, control_tx.clone()),
    };
    {
        let conn = conn.clone();
        tokio::spawn(async move {
            while let Ok(mut stream) = conn.accept_uni().await {
                let decoder = decoder.clone();
                tokio::spawn(async move {
                    let mut header = [0u8; FrameHeader::LEN];
                    if stream.read_exact(&mut header).await.is_err() {
                        return;
                    }
                    let Ok(data) = stream.read_to_end(wire::MAX_FRAME_BYTES).await else { return };
                    let _ = decoder.send(reorder::Packet { header: FrameHeader::decode(&header), data });
                });
            }
        });
    }

    Ok(Session {
        host_name,
        addresses,
        newly_paired,
        width,
        height,
        input: InputSender { conn: conn.clone(), control: control_tx, seq: Arc::new(AtomicU32::new(0)) },
        features,
        displays,
        reach,
        route,
        audio,
        conn,
        runtime: tokio::runtime::Handle::current(),
        _endpoint: endpoint,
    })
}

/// Reads what the host says on the control stream after the welcome: its displays, and how else
/// it can be reached. Ends with the stream.
async fn read_control(
    mut recv: quinn::RecvStream,
    displays: Arc<Mutex<Displays>>,
    reach: Arc<Mutex<ReachSlot>>,
    control: mpsc::UnboundedSender<ClientMsg>,
    route: Route,
) {
    let mut reported = false;
    while let Ok(Some(body)) = wire::read_msg(&mut recv).await {
        // What this version does not know, or is not for this end, is skipped.
        match HostMsg::decode(&body) {
            Ok(HostMsg::Displays(list)) => {
                let listener = {
                    let mut displays = displays.lock().unwrap();
                    displays.list = Some(list.clone());
                    displays.listener.clone()
                };
                if let Some(listener) = listener {
                    listener(&list);
                }
            }
            Ok(HostMsg::Reach { addresses, key, secret, relays, mac, relays_for_others }) => {
                let info = ReachInfo {
                    addresses,
                    key: reach::non_zero(key),
                    secret: reach::non_zero(secret),
                    relays,
                    mac,
                    relays_for_others,
                };
                tracing::debug!("the host told how else it can be reached: {info:?}");
                let listeners = {
                    let mut slot = reach.lock().unwrap();
                    slot.info = Some(info.clone());
                    slot.listeners.clone()
                };
                for listener in listeners {
                    listener(&info);
                }
                // Only a host that sent `Reach` knows this message, and it wants to hear it once.
                if !std::mem::replace(&mut reported, true) {
                    let _ = control.send(ClientMsg::Reached { address: route.address.clone() });
                }
            }
            _ => {}
        }
    }
}

/// Thread-safe, non-blocking input sink. Coordinates are normalized to `0..=65535` over the
/// remote display.
#[derive(Clone)]
pub struct InputSender {
    conn: quinn::Connection,
    control: mpsc::UnboundedSender<ClientMsg>,
    seq: Arc<AtomicU32>,
}

impl InputSender {
    /// Sent as an unreliable datagram: a lost position is superseded by the next one.
    pub fn mouse_move(&self, x: u16, y: u16) {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        let datagram = MouseMove { seq, x, y }.encode();
        let _ = self.conn.send_datagram(bytes::Bytes::copy_from_slice(&datagram));
    }

    pub fn mouse_button(&self, button: MouseButton, down: bool, x: u16, y: u16) {
        self.send(ClientMsg::MouseButton { button, down, x, y });
    }

    /// `code` is a Linux evdev key code.
    pub fn key(&self, code: u16, state: KeyState) {
        self.send(ClientMsg::Key { code, state });
    }

    /// 120 units per wheel notch; positive `dy` scrolls up, positive `dx` scrolls right.
    pub fn scroll(&self, dx: i16, dy: i16) {
        self.send(ClientMsg::Scroll { dx, dy });
    }

    pub fn release_all(&self) {
        self.send(ClientMsg::ReleaseAll);
    }

    /// Streams the host's display at `index` in [`Session::displays`].
    pub fn select_display(&self, index: u8) {
        self.send(ClientMsg::SelectDisplay { index });
    }

    pub fn request_keyframe(&self) {
        self.send(ClientMsg::RequestKeyframe);
    }

    /// Offers the host a `velora://pair?..` link to this computer's own host, so the other
    /// computer can pair back. Hosts that predate offers ignore it.
    pub fn offer_pairing(&self, link: &str) {
        self.send(ClientMsg::OfferPairing { link: link.to_string() });
    }

    /// Types text on the host (layout-independent), for soft keyboards that produce
    /// characters rather than key presses.
    pub fn text(&self, text: &str) {
        for chunk in wire::split_text(text) {
            self.send(ClientMsg::Text { text: chunk.to_string() });
        }
    }

    /// Acknowledges a frame delivered through [`VideoOutput::Encoded`] once it is on screen.
    pub fn frame_done(&self, frame_id: u32) {
        self.send(ClientMsg::FrameAck { frame_id });
    }

    fn send(&self, msg: ClientMsg) {
        let _ = self.control.send(msg);
    }
}

/// Delivers encoded frames in order. After a gap (only possible if frames were lost), frames
/// are dropped and acknowledged until the next keyframe, which is requested.
fn spawn_encoded(
    sink: Arc<dyn Fn(EncodedFrame) + Send + Sync>,
    control: mpsc::UnboundedSender<ClientMsg>,
) -> std::sync::mpsc::Sender<reorder::Packet> {
    let (tx, rx) = std::sync::mpsc::channel::<reorder::Packet>();
    std::thread::Builder::new()
        .name("video".into())
        .spawn(move || {
            let mut reorder = reorder::Reorder::default();
            let mut need_keyframe = false;
            for packet in rx {
                let (ready, resynced) = reorder.push(packet);
                if resynced {
                    need_keyframe = true;
                    let _ = control.send(ClientMsg::RequestKeyframe);
                }
                for p in ready {
                    let h = p.header;
                    if need_keyframe && !h.keyframe {
                        let _ = control.send(ClientMsg::FrameAck { frame_id: h.frame_id });
                        continue;
                    }
                    need_keyframe = false;
                    sink(EncodedFrame {
                        frame_id: h.frame_id,
                        keyframe: h.keyframe,
                        width: h.width,
                        height: h.height,
                        data: p.data,
                    });
                }
            }
        })
        .expect("spawning video thread");
    tx
}

/// What the tests that need a host share: a temporary directory and a fake host that speaks just enough protocol.
#[cfg(test)]
pub(crate) mod testing {
    use std::{
        net::SocketAddr,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU32, Ordering},
        time::Duration,
    };

    use anyhow::{anyhow, bail};
    use velora_protocol::{
        identity::KnownHost,
        wire::{AddressKind, Codec, FEATURE_CLIPBOARD, FEATURE_FILES},
    };

    use super::*;

    /// A directory under the system's temporary one, removed when dropped.
    pub struct TempDir(PathBuf);

    impl TempDir {
        pub fn new() -> Self {
            static COUNT: AtomicU32 = AtomicU32::new(0);
            let name = format!("velora-client-core-{}-{}", std::process::id(), COUNT.fetch_add(1, Ordering::Relaxed));
            let path = std::env::temp_dir().join(name);
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        pub fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// What a fake host does besides welcoming the client.
    #[derive(Clone, Default)]
    pub struct Script {
        /// Sent right after the welcome, to a client that set the hello's reach bit.
        pub reach: Option<HostMsg>,
        /// Drops the connection on a hello that has extensions, as the hosts that predate them do.
        pub legacy: bool,
    }

    /// A host that accepts any client, answers its hello with a welcome, says what the script says and records what the
    /// client sends. It listens on loopback.
    pub struct FakeHost {
        pub identity: Identity,
        pub addr: SocketAddr,
        /// The extensions of each hello received.
        pub hellos: mpsc::UnboundedReceiver<Option<HelloExt>>,
        /// The control messages that follow a hello.
        pub messages: mpsc::UnboundedReceiver<ClientMsg>,
        _endpoint: quinn::Endpoint,
    }

    impl FakeHost {
        pub fn start(script: Script) -> Self {
            let identity = Identity::generate().unwrap();
            let endpoint =
                quinn::Endpoint::server(tls::server_config(&identity).unwrap(), "127.0.0.1:0".parse().unwrap())
                    .unwrap();
            let addr = endpoint.local_addr().unwrap();
            let (hello_tx, hellos) = mpsc::unbounded_channel();
            let (message_tx, messages) = mpsc::unbounded_channel();
            let accepting = endpoint.clone();
            tokio::spawn(async move {
                while let Some(incoming) = accepting.accept().await {
                    let (script, hello_tx, message_tx) = (script.clone(), hello_tx.clone(), message_tx.clone());
                    tokio::spawn(async move {
                        if let Err(e) = serve(incoming, script, hello_tx, message_tx).await {
                            tracing::debug!("fake host: {e:#}");
                        }
                    });
                }
            });
            Self { identity, addr, hellos, messages, _endpoint: endpoint }
        }

        /// The entry a client that paired with this host holds for it.
        pub fn entry(&self) -> KnownHost {
            KnownHost {
                name: "fake-pc".into(),
                address: self.addr.to_string(),
                fingerprint: self.identity.fingerprint().to_base64(),
                ..Default::default()
            }
        }
    }

    async fn serve(
        incoming: quinn::Incoming,
        script: Script,
        hellos: mpsc::UnboundedSender<Option<HelloExt>>,
        messages: mpsc::UnboundedSender<ClientMsg>,
    ) -> Result<()> {
        let conn = incoming.await?;
        let (mut send, mut recv) = conn.accept_bi().await?;
        let body = wire::read_msg(&mut recv).await?.ok_or_else(|| anyhow!("closed before the hello"))?;
        let ClientMsg::Hello { ext, .. } = ClientMsg::decode(&body)? else { bail!("expected a hello") };
        let _ = hellos.send(ext);
        if script.legacy && ext.is_some() {
            conn.close(0u32.into(), b"");
            return Ok(());
        }
        let welcome = HostMsg::Welcome {
            version: PROTOCOL_VERSION,
            host_name: "fake-pc".into(),
            codec: Codec::H264,
            width: 1280,
            height: 720,
            features: ext.map(|_| FEATURE_FILES | FEATURE_CLIPBOARD),
            addresses: if ext.is_some_and(|e| e.addresses) { vec!["192.0.2.10:7420".into()] } else { Vec::new() },
        };
        send.write_all(&welcome.encode()).await?;
        // Like a real host: `Reach` goes only to a client that asked for it.
        if let Some(reach) = script.reach.filter(|_| ext.is_some_and(|e| e.reach)) {
            send.write_all(&reach.encode()).await?;
        }
        while let Some(body) = wire::read_msg(&mut recv).await? {
            let _ = messages.send(ClientMsg::decode(&body)?);
        }
        Ok(())
    }

    /// A `Reach` such as a host with a mapped port and one relay would send.
    pub fn reach_msg() -> HostMsg {
        HostMsg::Reach {
            addresses: vec![
                (AddressKind::Lan, "192.0.2.10:7420".into()),
                (AddressKind::Public, "198.51.100.7:51820".into()),
            ],
            key: [7; 32],
            secret: [9; 16],
            relays: vec![(Fingerprint([5; 32]).to_base64(), vec!["203.0.113.9:7420".into()])],
            mac: Some([0x02, 1, 2, 3, 4, 5]),
            relays_for_others: true,
        }
    }

    /// Discards the video.
    pub fn sink() -> VideoOutput {
        VideoOutput::Encoded(Arc::new(|_| {}))
    }

    /// A test that waits for something that never comes should fail, not hang.
    pub async fn within<T>(what: &str, future: impl Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(10), future).await.unwrap_or_else(|_| panic!("timed out: {what}"))
    }

    /// Polls `check` until it gives something.
    pub async fn eventually<T>(what: &str, mut check: impl FnMut() -> Option<T>) -> T {
        within(what, async {
            loop {
                if let Some(found) = check() {
                    return found;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use velora_protocol::{
        identity::{KnownHost, StateDir},
        wire::AddressKind,
    };

    use super::{testing::*, *};

    fn params(host: &FakeHost, addr: SocketAddr) -> ConnectParams {
        ConnectParams {
            addr,
            also: Vec::new(),
            host_fingerprint: host.identity.fingerprint(),
            identity: Identity::generate().unwrap(),
            device_name: "test device".into(),
            pairing_secret: None,
            password: None,
            reach: None,
        }
    }

    #[tokio::test]
    async fn a_host_without_reach_is_connected_to_as_before() {
        let mut host = FakeHost::start(Script::default());
        let session = within("connect", connect(params(&host, host.addr), sink())).await.unwrap();

        // The hello asks for `Reach` (a host that predates it ignores the bit), and nothing of the kind comes back.
        assert!(within("hello", host.hellos.recv()).await.unwrap().unwrap().reach);
        assert_eq!(session.host_name, "fake-pc");
        assert_eq!(session.addresses, vec!["192.0.2.10:7420".to_string()]);
        assert_eq!(session.route(), &Route { kind: AddressKind::Lan.into(), address: host.addr.to_string() });
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(session.reach(), None);

        // So nothing about it is said to the host either: the first message it hears is the user's.
        session.input.release_all();
        assert_eq!(within("message", host.messages.recv()).await, Some(ClientMsg::ReleaseAll));
    }

    #[tokio::test]
    async fn a_host_with_reach_is_heard_and_told_where_it_was_reached() {
        let mut host = FakeHost::start(Script { reach: Some(reach_msg()), ..Default::default() });
        let session = within("connect", connect(params(&host, host.addr), sink())).await.unwrap();

        let info = eventually("the reach information", || session.reach()).await;
        assert_eq!(
            info,
            ReachInfo {
                addresses: vec![
                    (AddressKind::Lan, "192.0.2.10:7420".into()),
                    (AddressKind::Public, "198.51.100.7:51820".into())
                ],
                key: Some([7; 32]),
                secret: Some([9; 16]),
                relays: vec![(Fingerprint([5; 32]).to_base64(), vec!["203.0.113.9:7420".into()])],
                mac: Some([0x02, 1, 2, 3, 4, 5]),
                relays_for_others: true,
            }
        );
        // The host hears once which of its addresses this connection was made to.
        let reached = ClientMsg::Reached { address: host.addr.to_string() };
        assert_eq!(within("message", host.messages.recv()).await, Some(reached));
        session.input.release_all();
        assert_eq!(within("message", host.messages.recv()).await, Some(ClientMsg::ReleaseAll));
    }

    #[tokio::test]
    async fn listeners_add_up_and_the_late_one_is_called_at_once() {
        let host = FakeHost::start(Script { reach: Some(reach_msg()), ..Default::default() });
        let session = within("connect", connect(params(&host, host.addr), sink())).await.unwrap();
        let early = Arc::new(Mutex::new(Vec::new()));
        let late = Arc::new(Mutex::new(Vec::new()));
        let keep = |into: &Arc<Mutex<Vec<ReachInfo>>>| {
            let into = into.clone();
            Arc::new(move |info: &ReachInfo| into.lock().unwrap().push(info.clone())) as ReachListener
        };
        session.on_reach(keep(&early));
        eventually("the reach information", || session.reach()).await;
        eventually("the early listener", || (early.lock().unwrap().len() == 1).then_some(())).await;
        session.on_reach(keep(&late));
        assert_eq!(late.lock().unwrap().len(), 1);
        assert_eq!(early.lock().unwrap().len(), 1, "the first listener was not replaced, and was not called again");
    }

    #[tokio::test]
    async fn a_host_with_nothing_to_publish_sends_zeros_and_they_mean_none() {
        let HostMsg::Reach { addresses, relays, mac, relays_for_others, .. } = reach_msg() else { unreachable!() };
        let zeros = HostMsg::Reach { addresses, key: [0; 32], secret: [0; 16], relays, mac, relays_for_others };
        let host = FakeHost::start(Script { reach: Some(zeros), ..Default::default() });
        let session = within("connect", connect(params(&host, host.addr), sink())).await.unwrap();
        let info = eventually("the reach information", || session.reach()).await;
        assert_eq!((info.key, info.secret), (None, None));
        assert_eq!(info.mac, Some([0x02, 1, 2, 3, 4, 5]));
    }

    #[tokio::test]
    async fn a_host_that_predates_hello_extensions_is_asked_again_without_them() {
        let mut host = FakeHost::start(Script { legacy: true, ..Default::default() });
        let session = within("connect", connect(params(&host, host.addr), sink())).await.unwrap();
        // The first hello had extensions and was dropped; the second had none, and its welcome has no addresses.
        assert!(within("hello", host.hellos.recv()).await.unwrap().is_some());
        assert_eq!(within("hello", host.hellos.recv()).await.unwrap(), None);
        assert_eq!(session.addresses, Vec::<String>::new());
        assert_eq!(session.reach(), None);
    }

    #[tokio::test]
    async fn a_late_candidate_wins_over_an_address_that_never_answers() {
        let host = FakeHost::start(Script::default());
        // Bound and silent: what a stored address looks like once the host has moved away from it.
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        // The lookup finds the host's real address a little after it was asked.
        let real = host.addr;
        let lookup = async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            Ok(vec![reach::Candidate::Direct(real, AddressKind::Public)])
        };
        let began = std::time::Instant::now();
        let stale = Arc::new(params(&host, silent.local_addr().unwrap()));
        let established = within("race", establish_with(stale, Some(lookup))).await.unwrap();
        assert_eq!(established.route, Route { kind: AddressKind::Public.into(), address: host.addr.to_string() });
        assert!(began.elapsed() >= reach::LOOKUP_DELAY, "the DHT is not asked before its delay");
        established.conn.close(0u32.into(), b"");
    }

    #[tokio::test]
    async fn a_files_connection_says_how_it_was_made_like_a_session() {
        let mut host = FakeHost::start(Script::default());
        let files = within("connect", connect_files(params(&host, host.addr))).await.unwrap();
        // The hello is the files-only one, and the route is that of the address dialed.
        assert!(within("hello", host.hellos.recv()).await.unwrap().unwrap().files_only);
        assert_eq!(files.route(), &Route { kind: AddressKind::Lan.into(), address: host.addr.to_string() });
        assert_eq!(files.host_name, "fake-pc");
    }

    /// Never called: it only has to compile. Callers spawn these futures on a multi-threaded runtime, and the hooks of
    /// F2-F4 sit inside them, so a hook that is not `Send` would stop the clients from building.
    #[allow(dead_code)]
    fn the_futures_that_hold_the_hooks_are_send(params: ConnectParams, state: &StateDir, host: &KnownHost) {
        fn send<T: Send>(_: T) {}
        send(connect(params.clone(), sink()));
        send(connect_files(params.clone()));
        send(establish(&params));
        send(hosts::connect(state, "pc", "me", None, sink()));
        send(hosts::wake(state, "pc"));
        send(reach::wake(&params.identity, host));
    }
}
