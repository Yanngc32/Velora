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
    time::Duration,
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
pub use velora_protocol::identity::ConnectMode;

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

#[derive(Clone)]
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

impl ConnectParams {
    /// The ways in the user allows for this host ([`KnownHost::mode`]); any for a host being paired.
    pub fn mode(&self) -> ConnectMode {
        self.reach.as_ref().map_or_else(ConnectMode::default, |reach| reach.host.mode)
    }
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

/// The connection mode chosen for the host allows none of the ways in this device knows for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoWayIn(pub ConnectMode);

impl std::fmt::Display for NoWayIn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "no address of this computer fits the connection mode '{}'", self.0.as_str())
    }
}

impl std::error::Error for NoWayIn {}

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
///
/// Only the ways in that `filter` admits are tried. A filter that wants the local network alone (looking for a better way
/// in than a direct one) does not ask the DHT: the host's LAN addresses are stored.
async fn establish(params: &ConnectParams, filter: reach::Filter) -> Result<Established> {
    let shared = Arc::new(params.clone());
    // Only with the host's key and this device's secret, which come with its `Reach`.
    let lookup = (reach::can_resolve(params) && filter.below.is_none_or(|below| below > 1)).then(|| {
        let shared = shared.clone();
        async move { reach::resolve_record(&shared).await }
    });
    establish_with(shared, lookup, filter).await
}

/// [`establish`] with the lookup given, so that tests can bring candidates in late.
async fn establish_with<L>(params: Arc<ConnectParams>, lookup: Option<L>, filter: reach::Filter) -> Result<Established>
where
    L: Future<Output = Result<Vec<reach::Candidate>>> + Send + 'static,
{
    let config = tls::client_config(&params.identity, params.host_fingerprint)?;
    let first: Vec<_> = reach::stored_candidates(&params).into_iter().filter(|c| filter.admits(c)).collect();
    if first.is_empty() && lookup.is_none() {
        bail!(NoWayIn(filter.mode));
    }
    let lookup = lookup.map(|lookup| async move {
        lookup.await.map(|found| found.into_iter().filter(|c| filter.admits(c)).collect::<Vec<_>>())
    });
    let dial = move |candidate: reach::Candidate| {
        let (params, config) = (params.clone(), config.clone());
        async move { reach::dial(&params, config, &candidate).await }
    };
    let (candidate, (endpoint, conn)) = reach::race(first, lookup, dial).await.map_err(|e| {
        e.context("could not establish a secure connection (wrong address or host fingerprint changed?)")
    })?;
    Ok(Established { endpoint, conn, route: candidate.route() })
}

async fn handshake(params: &ConnectParams, ext: Option<HelloExt>, filter: reach::Filter) -> Result<Handshake> {
    let Established { endpoint, conn, route } = establish(params, filter).await?;

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

/// How the connection to the host stands, for a session that keeps it up (see [`Session::on_link`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkState {
    /// Connected through `Route`: at first, after a reconnection, or after moving to a better way in.
    Up(Route),
    /// The connection was lost and the session is trying to get it back.
    Reconnecting,
}

/// Called when the connection to the host changes (see [`Session::on_link`]).
pub type LinkListener = Arc<dyn Fn(&LinkState) + Send + Sync>;

/// The current state of the link and who to tell when it changes.
#[derive(Default)]
struct LinkSlot {
    state: Option<LinkState>,
    listeners: Vec<LinkListener>,
}

/// Where files the host sends go, once a caller asked for them ([`Session::receive_files`]): every connection of the
/// session gets the same.
#[derive(Clone)]
struct Offers {
    dest: PathBuf,
    on_event: Arc<dyn Fn(OfferEvent) + Send + Sync>,
    on_clip: Arc<dyn Fn(u8, Vec<u8>) + Send + Sync>,
}

/// One connection to the host and what goes with it. A session has one at a time; reconnecting, or moving to a better
/// way in, replaces it.
#[derive(Clone)]
struct Link {
    conn: quinn::Connection,
    /// Writes to this connection's control stream.
    control: mpsc::UnboundedSender<ClientMsg>,
    route: Route,
    features: u32,
    _endpoint: quinn::Endpoint,
}

/// What a session and its input sender share: the current connection, and what outlives connections.
struct Shared {
    link: Mutex<Link>,
    states: Mutex<LinkSlot>,
    offers: Mutex<Option<Offers>>,
    /// Set by [`Session::close`]: the end of the connection is the end of the session.
    closing: std::sync::atomic::AtomicBool,
    /// Why the session ended, once it has.
    ended: tokio::sync::watch::Sender<Option<String>>,
}

impl Shared {
    fn link(&self) -> Link {
        self.link.lock().unwrap().clone()
    }

    fn set_state(&self, state: LinkState) {
        let listeners = {
            let mut slot = self.states.lock().unwrap();
            if slot.state.as_ref() == Some(&state) {
                return;
            }
            slot.state = Some(state.clone());
            slot.listeners.clone()
        };
        for listener in listeners {
            listener(&state);
        }
    }

    fn end(&self, reason: String) {
        self.ended.send_if_modified(|ended| ended.is_none() && ended.replace(reason).is_none());
    }
}

/// A session with a host: video, input, sound, files. It keeps its connection up: when it is lost, the session connects
/// again (for [`RECONNECT_LIMIT`]); when a better way in appears (the local network, or anything direct when a relay
/// carries it), the session moves to it. The host gives the screen to the newest connection of a device, so a new one
/// takes over from the old without a gap beyond a keyframe. [`Session::on_link`] tells about both.
pub struct Session {
    pub host_name: String,
    /// Where else the host answers (see `HostMsg::Welcome`).
    pub addresses: Vec<String>,
    /// The host accepted the pairing secret and stored this device.
    pub newly_paired: bool,
    pub width: u16,
    pub height: u16,
    pub input: InputSender,
    shared: Arc<Shared>,
    displays: Arc<Mutex<Displays>>,
    reach: Arc<Mutex<ReachSlot>>,
    /// Plays the host's sound, when it sends it.
    audio: Option<Arc<velora_audio::Player>>,
    runtime: tokio::runtime::Handle,
}

impl Session {
    /// Resolves when the session ends, with the reason: closed here, ended by the host, or lost and not regained.
    pub async fn closed(&self) -> String {
        let mut ended = self.shared.ended.subscribe();
        let reason = match ended.wait_for(Option::is_some).await {
            Ok(reason) => reason.clone().unwrap_or_default(),
            Err(_) => "the session ended".into(),
        };
        reason
    }

    pub fn rtt(&self) -> std::time::Duration {
        self.shared.link().conn.rtt()
    }

    pub fn close(&self) {
        self.shared.closing.store(true, Ordering::Relaxed);
        self.shared.link().conn.close(0u32.into(), b"client closed");
        self.shared.end("client closed".into());
    }

    /// The host's files, when it serves them (hosts before file transfers don't), over the current connection.
    pub fn files(&self) -> Option<RemoteFiles> {
        let link = self.shared.link();
        (link.features & FEATURE_FILES != 0).then(|| RemoteFiles { conn: link.conn })
    }

    /// Accepts what the host sends: files into `dest`, reported to `on_event`, and its
    /// clipboard content (kind and bytes, see `velora-clipboard`), passed to `on_clip`.
    /// Hosts without file transfers never send any. Holds for the connections that follow too.
    pub fn receive_files(
        &self,
        dest: PathBuf,
        on_event: Arc<dyn Fn(OfferEvent) + Send + Sync>,
        on_clip: Arc<dyn Fn(u8, Vec<u8>) + Send + Sync>,
    ) {
        let offers = Offers { dest, on_event, on_clip };
        *self.shared.offers.lock().unwrap() = Some(offers.clone());
        self.runtime.spawn(files::receive_offers(
            self.shared.link().conn,
            offers.dest,
            offers.on_event,
            offers.on_clip,
        ));
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

    /// How the current connection was made: the kind of the address that won the race and that address.
    pub fn route(&self) -> Route {
        self.shared.link().route
    }

    /// Calls `listener` with the state of the connection: right away, and whenever it is lost, regained or moved to
    /// another way in. Listeners add up.
    pub fn on_link(&self, listener: LinkListener) {
        let now = {
            let mut slot = self.shared.states.lock().unwrap();
            slot.listeners.push(listener.clone());
            slot.state.clone()
        };
        if let Some(state) = now {
            listener(&state);
        }
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
        let link = self.shared.link();
        if link.features & FEATURE_CLIPBOARD == 0 {
            return;
        }
        let conn = link.conn;
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

impl Drop for Session {
    /// The connection is kept up by a task of its own: it ends with the session.
    fn drop(&mut self) {
        self.close();
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
    let filter = reach::Filter { mode: params.mode(), below: None };
    let hs = match handshake(&params, Some(ext), filter).await {
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

/// How long a lost session keeps trying to connect again before it ends.
pub const RECONNECT_LIMIT: Duration = Duration::from_secs(90);
/// The longest wait between two attempts to connect again (they start sooner and back off).
const RECONNECT_BACKOFF: Duration = Duration::from_secs(8);
/// Most one attempt to connect again, or to move to a better way in, may take.
const ATTEMPT_LIMIT: Duration = Duration::from_secs(20);
/// How often a session that could have a better way in looks for one, and how soon after it began.
pub const UPGRADE_EVERY: Duration = Duration::from_secs(30);
#[cfg(not(test))]
const FIRST_UPGRADE: Duration = Duration::from_secs(10);
#[cfg(test)]
const FIRST_UPGRADE: Duration = Duration::from_millis(500);

/// The hello of a session: everything this version takes.
fn session_hello() -> HelloExt {
    HelloExt {
        files_only: false,
        clipboard: true,
        addresses: true,
        displays: true,
        audio: velora_audio::SUPPORTED,
        // Hosts that predate standalone reach ignore the bit and send nothing more.
        reach: true,
    }
}

/// Connects, authenticates and starts delivering video to `output`. The session then keeps its connection up (see
/// [`Session`]).
pub async fn connect(params: ConnectParams, output: VideoOutput) -> Result<Session> {
    let filter = reach::Filter { mode: params.mode(), below: None };
    let ext = Some(session_hello());
    let (hs, ext) = match handshake(&params, ext, filter).await {
        // Hosts that predate hello extensions drop the connection: ask again as they expect.
        Err(e) if e.is::<NoReply>() => (handshake(&params, None, filter).await?, None),
        hs => (hs?, ext),
    };
    let (host_name, newly_paired, width, height, addresses) =
        (hs.host_name.clone(), hs.newly_paired, hs.width, hs.height, hs.addresses.clone());

    // The host's sound plays through one player whatever the connection.
    let audio = (hs.features & FEATURE_AUDIO != 0).then(velora_audio::Player::start).and_then(|player| match player {
        Ok(player) => Some(Arc::new(player)),
        Err(e) => {
            tracing::warn!("cannot play the host's sound: {e:#}");
            None
        }
    });
    let parts = Parts {
        displays: Arc::new(Mutex::new(Displays::default())),
        reach: Arc::new(Mutex::new(ReachSlot::default())),
        audio: audio.clone(),
        output,
    };
    let link = parts.attach(hs, None);
    let route = link.route.clone();
    let shared = Arc::new(Shared {
        link: Mutex::new(link),
        states: Mutex::new(LinkSlot { state: Some(LinkState::Up(route)), listeners: Vec::new() }),
        offers: Mutex::new(None),
        closing: false.into(),
        ended: tokio::sync::watch::channel(None).0,
    });
    // Once paired, the next connections are those of a paired device.
    let params = ConnectParams { pairing_secret: None, ..params };
    tokio::spawn(keep_up(shared.clone(), parts.clone(), params, ext));

    Ok(Session {
        host_name,
        addresses,
        newly_paired,
        width,
        height,
        input: InputSender { shared: shared.clone(), seq: Arc::new(AtomicU32::new(0)) },
        shared,
        displays: parts.displays,
        reach: parts.reach,
        audio,
        runtime: tokio::runtime::Handle::current(),
    })
}

/// What every connection of a session feeds: the displays and reach slots, the sound player and the video output.
#[derive(Clone)]
struct Parts {
    displays: Arc<Mutex<Displays>>,
    reach: Arc<Mutex<ReachSlot>>,
    audio: Option<Arc<velora_audio::Player>>,
    output: VideoOutput,
}

impl Parts {
    /// Starts reading a connection the host accepted: its control stream, sound, video and offered files.
    fn attach(&self, hs: Handshake, offers: Option<Offers>) -> Link {
        let Handshake { endpoint, conn, mut send, recv, features, route, .. } = hs;
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
        tokio::spawn(read_control(recv, self.displays.clone(), self.reach.clone(), control_tx.clone(), route.clone()));

        // The host's sound arrives in datagrams; newer ones only, a lost one is a short gap.
        if let Some(player) = self.audio.clone().filter(|_| features & FEATURE_AUDIO != 0) {
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

        // Each connection numbers its frames from the start: a decoder of its own.
        let decoder = match &self.output {
            #[cfg(feature = "decode")]
            VideoOutput::Decoded { slot, on_frame } => {
                video::spawn_decoder(slot.clone(), control_tx.clone(), on_frame.clone())
            }
            VideoOutput::Encoded(sink) => spawn_encoded(sink.clone(), control_tx.clone()),
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
        if let Some(offers) = offers {
            tokio::spawn(files::receive_offers(conn.clone(), offers.dest, offers.on_event, offers.on_clip));
        }
        Link { conn, control: control_tx, route, features, _endpoint: endpoint }
    }
}

/// Whether a session in `mode`, connected through a way in of `rank`, could find a better one.
fn could_improve(mode: ConnectMode, rank: u8) -> bool {
    match mode {
        ConnectMode::Auto => rank > 0,
        // Velora's own ways in: a relay can give way to a direct one.
        ConnectMode::Velora => rank > 1,
        ConnectMode::Lan | ConnectMode::Vpn => false,
    }
}

/// Whether a connection that ended this way is worth connecting again: it was lost, not ended by either side.
fn lost(error: &quinn::ConnectionError) -> bool {
    !matches!(error, quinn::ConnectionError::ApplicationClosed(_) | quinn::ConnectionError::LocallyClosed)
}

fn reason(error: &quinn::ConnectionError) -> String {
    match error {
        quinn::ConnectionError::ApplicationClosed(c) => String::from_utf8_lossy(&c.reason).into_owned(),
        e => e.to_string(),
    }
}

/// Connects once more, for a session: a full handshake through a way in that `filter` admits, bounded in time.
async fn reopen(params: &ConnectParams, ext: Option<HelloExt>, filter: reach::Filter) -> Result<Handshake> {
    tokio::time::timeout(ATTEMPT_LIMIT, handshake(params, ext, filter))
        .await
        .map_err(|_| anyhow::anyhow!("no answer within {ATTEMPT_LIMIT:?}"))?
}

/// Keeps a session's connection up until the session ends: connects again when it is lost, and moves to a better way in
/// when one answers.
async fn keep_up(shared: Arc<Shared>, parts: Parts, params: ConnectParams, ext: Option<HelloExt>) {
    let mode = params.mode();
    let mut next_look = tokio::time::Instant::now() + FIRST_UPGRADE;
    let mut upgrade: Option<tokio::task::JoinHandle<Result<Handshake>>> = None;
    loop {
        let link = shared.link();
        let rank = reach::rank(&link.route.kind);
        let looking = upgrade.is_none() && could_improve(mode, rank);
        tokio::select! {
            error = link.conn.closed() => {
                if shared.closing.load(Ordering::Relaxed) {
                    shared.end("client closed".into());
                    return;
                }
                // Moving to a better way in: the host sends the old connection away as soon as the new one says hello.
                if let Some(task) = upgrade.take() {
                    if let Ok(Ok(hs)) = task.await {
                        move_to(&shared, &parts, hs, "moved to a better way in");
                        continue;
                    }
                }
                if !lost(&error) {
                    shared.end(reason(&error));
                    return;
                }
                tracing::info!("connection lost ({error}); connecting again");
                shared.set_state(LinkState::Reconnecting);
                match regain(&shared, &params, ext, mode).await {
                    Some(hs) => {
                        let link = parts.attach(hs, shared.offers.lock().unwrap().clone());
                        tracing::info!("connected again through {}", link.route);
                        let route = link.route.clone();
                        *shared.link.lock().unwrap() = link;
                        shared.set_state(LinkState::Up(route));
                    }
                    None => {
                        shared.end(reason(&error));
                        return;
                    }
                }
            }
            done = async { upgrade.as_mut().expect("guarded").await }, if upgrade.is_some() => {
                upgrade = None;
                next_look = tokio::time::Instant::now() + UPGRADE_EVERY;
                match done {
                    Ok(Ok(hs)) => {
                        let old = shared.link();
                        move_to(&shared, &parts, hs, "moved to a better way in");
                        old.conn.close(0u32.into(), b"moved to a better way in");
                    }
                    Ok(Err(e)) => tracing::debug!("no better way in: {e:#}"),
                    Err(e) => tracing::debug!("looking for a better way in failed: {e}"),
                }
            }
            _ = tokio::time::sleep_until(next_look), if looking => {
                let filter = reach::Filter { mode, below: Some(rank) };
                let params = params.clone();
                upgrade = Some(tokio::spawn(async move { reopen(&params, ext, filter).await }));
            }
        }
    }
}

/// Switches the session to a new connection.
fn move_to(shared: &Shared, parts: &Parts, hs: Handshake, why: &str) {
    let link = parts.attach(hs, shared.offers.lock().unwrap().clone());
    tracing::info!("{why}: {}", link.route);
    let route = link.route.clone();
    *shared.link.lock().unwrap() = link;
    shared.set_state(LinkState::Up(route));
}

/// Connects again after a loss, backing off between attempts, until [`RECONNECT_LIMIT`] or the session is closed. A host
/// that now asks for a password, or turns the device away, is not asked again.
async fn regain(
    shared: &Shared,
    params: &ConnectParams,
    ext: Option<HelloExt>,
    mode: ConnectMode,
) -> Option<Handshake> {
    let began = tokio::time::Instant::now();
    let mut wait = Duration::from_millis(500);
    let filter = reach::Filter { mode, below: None };
    loop {
        if shared.closing.load(Ordering::Relaxed) {
            return None;
        }
        match reopen(params, ext, filter).await {
            Ok(hs) => return Some(hs),
            Err(e) if e.is::<PasswordRequired>() || format!("{e:#}").contains("rejected") => {
                tracing::warn!("cannot connect again: {e:#}");
                return None;
            }
            Err(e) => tracing::debug!("connecting again failed: {e:#}"),
        }
        if began.elapsed() + wait > RECONNECT_LIMIT {
            return None;
        }
        tokio::time::sleep(wait).await;
        wait = (wait * 2).min(RECONNECT_BACKOFF);
    }
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
    /// Input goes to the session's current connection.
    shared: Arc<Shared>,
    seq: Arc<AtomicU32>,
}

impl InputSender {
    /// Sent as an unreliable datagram: a lost position is superseded by the next one.
    pub fn mouse_move(&self, x: u16, y: u16) {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        let datagram = MouseMove { seq, x, y }.encode();
        let _ = self.shared.link().conn.send_datagram(bytes::Bytes::copy_from_slice(&datagram));
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
        let _ = self.shared.link().control.send(msg);
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
        /// Ends the session with this reason right after the welcome, as a host does when another device takes over.
        pub end_with: Option<&'static str>,
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
        if let Some(reason) = script.end_with {
            tokio::time::sleep(Duration::from_millis(200)).await;
            conn.close(1u32.into(), reason.as_bytes());
            return Ok(());
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

    /// A UDP relay in front of a host, for one client, that can stop passing packets: a path that is lost, or not there
    /// yet.
    pub struct Hop {
        pub addr: SocketAddr,
        blocked: Arc<std::sync::atomic::AtomicBool>,
    }

    impl Hop {
        pub async fn to(host: SocketAddr, blocked: bool) -> Self {
            let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let addr = socket.local_addr().unwrap();
            let blocked = Arc::new(std::sync::atomic::AtomicBool::new(blocked));
            let flag = blocked.clone();
            tokio::spawn(async move {
                let mut client: Option<SocketAddr> = None;
                let mut buf = vec![0u8; 65536];
                while let Ok((n, from)) = socket.recv_from(&mut buf).await {
                    if flag.load(Ordering::Relaxed) {
                        continue;
                    }
                    let to = if from == host {
                        match client {
                            Some(client) => client,
                            None => continue,
                        }
                    } else {
                        client = Some(from);
                        host
                    };
                    let _ = socket.send_to(&buf[..n], to).await;
                }
            });
            Self { addr, blocked }
        }

        pub fn block(&self, blocked: bool) {
            self.blocked.store(blocked, Ordering::Relaxed);
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
        assert_eq!(session.route(), Route { kind: AddressKind::Lan.into(), address: host.addr.to_string() });
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
        let established = within("race", establish_with(stale, Some(lookup), reach::Filter::default())).await.unwrap();
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

    /// Records the states a session goes through.
    fn states(session: &Session) -> Arc<Mutex<Vec<LinkState>>> {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let into = seen.clone();
        session.on_link(Arc::new(move |state: &LinkState| into.lock().unwrap().push(state.clone())));
        seen
    }

    /// Params whose stored entry gives each address its kind, as a host's `Reach` does.
    fn params_with_kinds(host: &FakeHost, kinds: Vec<(AddressKind, SocketAddr)>, dir: &TempDir) -> ConnectParams {
        let entry = KnownHost {
            kinds: kinds.iter().map(|(kind, addr)| (kind.clone(), addr.to_string())).collect(),
            ..host.entry()
        };
        ConnectParams {
            reach: Some(reach::ReachParams { host: entry, state_dir: dir.path().to_path_buf() }),
            ..params(host, kinds[0].1)
        }
    }

    #[tokio::test]
    async fn a_lost_connection_is_regained_and_input_goes_to_the_new_one() {
        let mut host = FakeHost::start(Script::default());
        let path = Hop::to(host.addr, false).await;
        let session = within("connect", connect(params(&host, path.addr), sink())).await.unwrap();
        let seen = states(&session);
        within("hello", host.hellos.recv()).await;

        // The path goes quiet: once the connection times out, the session says so and tries again.
        path.block(true);
        tokio::time::timeout(Duration::from_secs(30), async {
            while !seen.lock().unwrap().contains(&LinkState::Reconnecting) {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the loss is noticed");
        path.block(false);
        within("the second hello", host.hellos.recv()).await;
        eventually("up again", || matches!(seen.lock().unwrap().last(), Some(LinkState::Up(_))).then_some(())).await;
        assert_eq!(session.route().address, path.addr.to_string());

        session.input.release_all();
        assert_eq!(within("message", host.messages.recv()).await, Some(ClientMsg::ReleaseAll));
    }

    #[tokio::test]
    async fn a_session_the_host_ends_is_not_connected_again() {
        let mut host = FakeHost::start(Script { end_with: Some("another device took over"), ..Default::default() });
        let session = within("connect", connect(params(&host, host.addr), sink())).await.unwrap();
        assert_eq!(within("the end", session.closed()).await, "another device took over");
        within("hello", host.hellos.recv()).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(host.hellos.try_recv().is_err(), "no second hello");
    }

    #[tokio::test]
    async fn a_session_moves_to_the_local_network_when_it_answers() {
        let mut host = FakeHost::start(Script::default());
        let dir = TempDir::new();
        let vpn = Hop::to(host.addr, false).await;
        let lan = Hop::to(host.addr, true).await;
        let params = params_with_kinds(&host, vec![(AddressKind::Vpn, vpn.addr), (AddressKind::Lan, lan.addr)], &dir);
        let session = within("connect", connect(params, sink())).await.unwrap();
        assert_eq!(session.route().kind, RouteKind::Address(AddressKind::Vpn), "the LAN does not answer yet");
        let seen = states(&session);
        within("hello", host.hellos.recv()).await;

        lan.block(false);
        let lan_route = Route { kind: AddressKind::Lan.into(), address: lan.addr.to_string() };
        eventually("moved to the LAN", || {
            seen.lock().unwrap().contains(&LinkState::Up(lan_route.clone())).then_some(())
        })
        .await;
        within("the new hello", host.hellos.recv()).await;
        assert_eq!(session.route(), lan_route);
        assert!(!seen.lock().unwrap().contains(&LinkState::Reconnecting), "moved without a loss");
        session.input.release_all();
        assert_eq!(within("message", host.messages.recv()).await, Some(ClientMsg::ReleaseAll));
    }

    #[tokio::test]
    async fn a_mode_keeps_to_its_ways_in() {
        let host = FakeHost::start(Script::default());
        let dir = TempDir::new();
        let lan = Hop::to(host.addr, false).await;
        let vpn = Hop::to(host.addr, false).await;
        let kinds = vec![(AddressKind::Lan, lan.addr), (AddressKind::Vpn, vpn.addr)];
        let mut params = params_with_kinds(&host, kinds, &dir);
        params.reach.as_mut().unwrap().host.mode = ConnectMode::Vpn;
        let session = within("connect", connect(params.clone(), sink())).await.unwrap();
        assert_eq!(session.route(), Route { kind: AddressKind::Vpn.into(), address: vpn.addr.to_string() });
        drop(session);

        // A mode none of the stored addresses fits fails at once, and says why.
        params.reach.as_mut().unwrap().host.mode = ConnectMode::Velora;
        let error = within("connect", connect(params, sink())).await.err().expect("no way in");
        assert_eq!(error.downcast_ref::<NoWayIn>(), Some(&NoWayIn(ConnectMode::Velora)));
    }

    /// Never called: it only has to compile. Callers spawn these futures on a multi-threaded runtime, and the hooks of
    /// F2-F4 sit inside them, so a hook that is not `Send` would stop the clients from building.
    #[allow(dead_code)]
    fn the_futures_that_hold_the_hooks_are_send(params: ConnectParams, state: &StateDir, host: &KnownHost) {
        fn send<T: Send>(_: T) {}
        send(connect(params.clone(), sink()));
        send(connect_files(params.clone()));
        send(establish(&params, reach::Filter::default()));
        send(hosts::connect(state, "pc", "me", None, sink()));
        send(hosts::wake(state, "pc"));
        send(reach::wake(&params.identity, host));
    }
}
