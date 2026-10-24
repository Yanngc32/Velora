//! Connection handling, authorization and the per-session capture/encode/send pipeline.
//!
//! Latency control: the host keeps at most `ceil(RTT / frame interval) + 2` frames in flight
//! (encoded but not yet acknowledged by the client). When the link or the client cannot keep
//! up, new frames are simply not captured, so queues never build up and the picture on the
//! client is always recent, at the cost of frame rate.

use std::{
    collections::VecDeque,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, ensure, Context, Result};
use tokio::sync::{mpsc, oneshot};
use velora_protocol::{
    control::{self, Reply, Request},
    files as wire_files,
    identity::{AuthorizedClient, Identity, StateDir},
    pairing::{pairing_uri_with, parse_pairing_uri, PairingCode},
    tls::{self, Fingerprint},
    wire::{
        self, AddressKind, AudioPacket, ClientMsg, Codec, DisplayInfo, DisplayList, FrameHeader, HelloExt, HostMsg,
        MouseMove, DEVICE_SECRET_LEN, FEATURE_AUDIO, FEATURE_CLIPBOARD, FEATURE_FILES, PROTOCOL_VERSION, REACH_KEY_LEN,
    },
};

use crate::{
    capture::{self, DisplayRect},
    encode::{self, EncoderChoice, EncoderSettings},
    input::{InputCmd, InputHandle},
    password::Check,
    rate::{self, RateControl},
    reach::{self, socket::Multiplexer, ClientConn, ControlSender, ReachContext, ReachState, Runtime, Switches},
    transfer::Peer,
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MIN_IN_FLIGHT: u32 = 2;
const MAX_IN_FLIGHT: u32 = 16;
/// If no ack arrives for this long, assume the counter is out of sync and resume sending.
const ACK_STALL_RESET: Duration = Duration::from_secs(2);
const STATS_INTERVAL: Duration = Duration::from_secs(5);
const UPDATE_FIRST_CHECK: Duration = Duration::from_secs(60);
const UPDATE_INTERVAL: Duration = Duration::from_secs(6 * 3600);
const UPDATE_IDLE_POLL: Duration = Duration::from_secs(30);
const PAIRING_TTL: Duration = Duration::from_secs(10 * 60);
/// Longest pairing link, in characters, that still makes a QR code a phone reads without trouble.
const MAX_LINK_LEN: usize = 300;
/// The largest packet, in bytes, a connection that arrives through a relay tunnel may grow to. Its
/// packets travel as datagrams of the connection to the relay, which hold about 1400 bytes less
/// the 3 of the relay framing: a packet up to this is one datagram, a longer one is two.
const TUNNEL_MTU: u16 = 1350;

pub struct HostOptions {
    pub bind: SocketAddr,
    pub name: String,
    pub fps: u32,
    pub bitrate_kbps: u32,
    pub encoder: EncoderChoice,
    /// Running as the system service, which the launcher shows.
    pub service: bool,
    /// Lower the bitrate when the network falls behind (see `rate`); `bitrate_kbps` is the most.
    pub adaptive_bitrate: bool,
    /// Serve relays and nothing else: no screen is captured and no session starts. For a machine
    /// with no screen to share (a VPS) that other paired devices connect through.
    pub relay_only: bool,
}

#[derive(Clone)]
pub struct PendingPairing {
    pub code: PairingCode,
    /// Address advertised in the pairing link.
    pub address: String,
    /// Addresses on a VPN mesh, and the public one, in the link too.
    pub also: Vec<String>,
    /// The host's DHT key, in the link when the host has one (it then carries `secret` too).
    key: Option<[u8; REACH_KEY_LEN]>,
    /// The secret that opens the host's DHT record for the device this link pairs; the device
    /// gets it as part of pairing, and `reach::on_paired` stores it under the device's fingerprint.
    secret: Option<[u8; DEVICE_SECRET_LEN]>,
    expires: Instant,
}

impl PendingPairing {
    /// The `velora://pair?..` link, with the DHT key and device secret when there are some.
    pub fn uri(&self) -> String {
        pairing_uri_with(&self.address, &self.also, &self.code, self.key.as_ref(), self.secret.as_ref())
    }
}

struct Active {
    conn: quinn::Connection,
    fingerprint: Fingerprint,
    /// The device takes files (Send To); older ones don't know about them.
    files: bool,
}

/// A connection for file transfers only (the desktop's file manager).
struct FilesConn {
    conn: quinn::Connection,
    fingerprint: Fingerprint,
}

/// A connection that carries control messages and nothing else: a relay link (see
/// `serve_link`). Not file transfers, not a session, and not counted as the host being busy.
struct LinkConn {
    conn: quinn::Connection,
    fingerprint: Fingerprint,
}

pub struct Shared {
    options: HostOptions,
    state: Arc<StateDir>,
    fingerprint: Fingerprint,
    /// `None` under `--relay-only`, which starts no sessions.
    input: Option<InputHandle>,
    /// Standalone reach: its state, switches and tasks.
    reach: Runtime,
    /// Connections asked to prove their address with Retry since the host started.
    retries: AtomicU64,
    pairing: Mutex<Option<PendingPairing>>,
    /// Paired devices that offered to be reached from here too, for the launcher to act on.
    offers: Mutex<Vec<PendingOffer>>,
    /// Devices waiting for the user here to accept their files.
    requests: Mutex<Vec<PendingRequest>>,
    next_request: AtomicU64,
    /// Held across every read-modify-write of the paired list, so pairing and removing a
    /// device at the same moment cannot undo each other.
    clients: Mutex<()>,
    password: crate::password::Gate,
    active: Mutex<Option<Active>>,
    files: Mutex<Vec<FilesConn>>,
    links: Mutex<Vec<LinkConn>>,
    /// What connections that arrive through a relay tunnel are accepted with: see [`tunnel_config`].
    tunnel_config: Arc<quinn::ServerConfig>,
    shutdown: tokio::sync::Notify,
    awake: crate::awake::Awake,
}

/// The server config for connections that arrive through a relay tunnel: the host's own, with path
/// MTU discovery stopping at [`TUNNEL_MTU`] where the endpoint's would go on to 1452. Ordinary
/// connections keep the endpoint's config, and so do the retries.
fn tunnel_config(identity: &Identity) -> Result<Arc<quinn::ServerConfig>> {
    let mut config = tls::server_config(identity)?;
    let transport = Arc::get_mut(&mut config.transport).context("the transport config is shared")?;
    let mut discovery = quinn::MtuDiscoveryConfig::default();
    discovery.upper_bound(TUNNEL_MTU);
    transport.mtu_discovery_config(Some(discovery));
    Ok(Arc::new(config))
}

/// Binds the socket, opens the endpoint on it and builds the host around both. Needs a Tokio
/// runtime, since the socket registers with it.
fn open(mut options: HostOptions, state: StateDir) -> Result<(Arc<Shared>, quinn::Endpoint)> {
    let identity = state.load_or_create_identity()?;
    let socket = reach::bind(options.bind).with_context(|| format!("binding {}", options.bind))?;
    let socket = Arc::new(Multiplexer::new(socket)?);
    // The port the socket really has: what the addresses the host advertises must say, whatever
    // was asked for (port 0 lets the system pick one).
    options.bind.set_port(socket.local_addr().port());
    let endpoint = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(tls::server_config(&identity)?),
        socket.clone(),
        Arc::new(quinn::TokioRuntime),
    )?;
    tracing::info!(
        "host '{}' {} listening on {} (fingerprint {})",
        options.name,
        velora_update::Version::current(),
        endpoint.local_addr()?,
        identity.fingerprint()
    );

    let tunnel_config = tunnel_config(&identity)?;
    let state = Arc::new(state);
    let fingerprint = identity.fingerprint();
    let reach = reach::Reach::new(ReachState {
        switches: Switches::load(&state),
        relay_only: options.relay_only,
        ..Default::default()
    });
    let reach = Runtime::new(ReachContext::new(reach, state.clone(), identity, options.bind, endpoint.clone(), socket));
    let awake = crate::awake::Awake::start(&state);
    let shared = Arc::new(Shared {
        awake,
        input: (!options.relay_only).then(crate::input::spawn),
        options,
        state,
        reach,
        retries: AtomicU64::new(0),
        password: crate::password::Gate::default(),
        fingerprint,
        pairing: Mutex::new(None),
        offers: Mutex::new(Vec::new()),
        requests: Mutex::new(Vec::new()),
        next_request: AtomicU64::new(1),
        clients: Mutex::new(()),
        active: Mutex::new(None),
        files: Mutex::new(Vec::new()),
        links: Mutex::new(Vec::new()),
        tunnel_config,
        shutdown: tokio::sync::Notify::new(),
    });
    // The first welcome must not go out with no address in it.
    shared.refresh_local();
    shared.reach.start();
    Ok((shared, endpoint))
}

/// Runs until the endpoint fails or the launcher stops the host, or until an update was
/// installed and the host is idle; then returns `true` so the caller restarts into the new
/// version. With `pair`, a pairing window opens right away and is printed.
pub async fn run(options: HostOptions, state: StateDir, pair: bool, auto_update: bool) -> Result<bool> {
    let (shared, endpoint) = open(options, state)?;
    if pair {
        let pairing = shared.start_pairing()?;
        crate::print_pairing(&pairing);
    }
    // The launcher's view of this host. Without it the host still works from the command line.
    {
        let shared = shared.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::control::serve(shared.clone()).await {
                // Under the service another process could have taken the pipe's name: exit
                // and let the service start the host again rather than run unreachable.
                if shared.is_service() {
                    tracing::error!("local control channel failed: {e:#}");
                    std::process::exit(1);
                }
                tracing::warn!("local control channel unavailable: {e:#}");
            }
        });
    }

    let updated = async {
        if auto_update {
            update_loop(&shared).await
        } else {
            std::future::pending().await
        }
    };
    tokio::pin!(updated);
    // Ctrl-C (and, where there is such a thing, SIGTERM) ends the host the same way the launcher
    // does, so the router mapping is removed. A process with no console cannot get Ctrl-C, and
    // then this never fires.
    let interrupted = async {
        #[cfg(unix)]
        let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
        #[cfg(unix)]
        let terminated = async {
            match terminate.as_mut() {
                Some(signal) => signal.recv().await,
                None => std::future::pending().await,
            }
        };
        #[cfg(not(unix))]
        let terminated = std::future::pending::<Option<()>>();
        tokio::select! {
            ended = tokio::signal::ctrl_c() => {
                if ended.is_err() {
                    std::future::pending::<()>().await
                }
            }
            _ = terminated => {}
        }
    };
    tokio::pin!(interrupted);

    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    shared.reach.stop().await;
                    return Ok(false);
                };
                on_incoming(&shared, incoming);
            }
            () = &mut updated => {
                // Release the UDP port before the new version binds it.
                shutdown(&shared, &endpoint, b"host is updating").await;
                return Ok(true);
            }
            () = shared.shutdown.notified() => {
                tracing::info!("stopping at the launcher's request");
                shutdown(&shared, &endpoint, b"host stopped").await;
                return Ok(false);
            }
            () = &mut interrupted => {
                tracing::info!("stopping on Ctrl-C or SIGTERM");
                shutdown(&shared, &endpoint, b"host stopped").await;
                return Ok(false);
            }
        }
    }
}

/// Closes the endpoint and waits for its connections to end, while the standalone reach tasks
/// clean up (the router mapping is removed).
async fn shutdown(shared: &Shared, endpoint: &quinn::Endpoint, reason: &[u8]) {
    endpoint.close(0u32.into(), reason);
    tokio::join!(endpoint.wait_idle(), shared.reach.stop());
}

/// Whether a connection attempt must prove its address before the host spends anything on it: a
/// host that means to be reached from the internet (`exposed`: standalone reach is on, or it
/// relays for others, as a `--relay-only` machine does by definition) would otherwise answer a
/// spoofed first packet with more bytes than it received. Attempts that came through a relay
/// tunnel are exempt: the relay's own connection is authenticated, and a round trip through it
/// would cost more than it protects.
fn wants_retry(exposed: bool, validated: bool, may_retry: bool, remote: SocketAddr) -> bool {
    exposed && !validated && may_retry && !reach::socket::is_tunnel_addr(remote)
}

/// Starts handling a connection attempt, or asks it to prove its address first.
fn on_incoming(shared: &Arc<Shared>, incoming: quinn::Incoming) {
    let exposed = shared.reach.reach().read().exposed();
    let remote = incoming.remote_address();
    let incoming = if wants_retry(exposed, incoming.remote_address_validated(), incoming.may_retry(), remote) {
        match incoming.retry() {
            Ok(()) => {
                shared.retries.fetch_add(1, Ordering::Relaxed);
                tracing::debug!("asked {} to prove its address", peer_addr(remote));
                return;
            }
            Err(refused) => refused.into_incoming(),
        }
    } else {
        incoming
    };
    let shared = shared.clone();
    tokio::spawn(async move {
        if let Err(e) = handle_connection(incoming, shared).await {
            tracing::info!("connection from {} ended: {e:#}", peer_addr(remote));
        }
    });
}

/// `addr` for logs: an IPv4 peer of the dual-stack socket reads as the IPv4 address it is.
fn peer_addr(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

/// Periodically installs new releases; resolves once one is installed and nobody is using
/// the host (no session, file connection or relayed traffic, no open pairing window).
async fn update_loop(shared: &Shared) {
    let mut delay = UPDATE_FIRST_CHECK;
    loop {
        tokio::time::sleep(delay).await;
        delay = UPDATE_INTERVAL;
        match tokio::task::spawn_blocking(velora_update::update_now).await {
            Ok(Ok(Some(version))) => {
                tracing::info!("installed version {version}; restarting when idle");
                break;
            }
            Ok(Ok(None)) => tracing::debug!("up to date"),
            Ok(Err(e)) => tracing::warn!("update check failed: {e:#}"),
            Err(e) => tracing::warn!("update task failed: {e}"),
        }
    }
    loop {
        let pairing_open = shared.pairing.lock().unwrap().as_ref().is_some_and(|p| p.expires > Instant::now());
        let busy = shared.active.lock().unwrap().is_some()
            || !shared.files.lock().unwrap().is_empty()
            || reach::relay::busy(shared.reach.context());
        if !busy && !pairing_open {
            return;
        }
        tokio::time::sleep(UPDATE_IDLE_POLL).await;
    }
}

async fn handle_connection(incoming: quinn::Incoming, shared: Arc<Shared>) -> Result<()> {
    // What arrives through a relay tunnel is held to packets that fit one datagram of the relay's.
    let connecting = if reach::socket::is_tunnel_addr(incoming.remote_address()) {
        incoming.accept_with(shared.tunnel_config.clone())?
    } else {
        incoming.accept()?
    };
    let conn = tokio::time::timeout(HANDSHAKE_TIMEOUT, connecting).await.context("handshake timeout")??;
    let fingerprint = tls::peer_fingerprint(&conn)?;

    let (mut send, mut recv) =
        tokio::time::timeout(HANDSHAKE_TIMEOUT, conn.accept_bi()).await.context("no control stream")??;
    let body = tokio::time::timeout(HANDSHAKE_TIMEOUT, wire::read_msg(&mut recv))
        .await
        .context("no hello")??
        .context("closed before hello")?;
    let ClientMsg::Hello { version, name, pairing_secret, password, ext } = ClientMsg::decode(&body)? else {
        bail!("expected hello");
    };
    // Shown in logs and stored in the paired list: strip control characters.
    let name: String = name.chars().filter(|c| !c.is_control()).collect();

    let reject = |reason: &str| HostMsg::Rejected { reason: reason.into() }.encode();
    if version != PROTOCOL_VERSION {
        send.write_all(&reject("incompatible protocol version")).await?;
        let _ = send.finish();
        let _ = send.stopped().await;
        bail!("client '{name}' uses protocol {version}");
    }

    // The hello of a relay link (files only, and it asks for `Reach`), which no session and no file
    // manager sends. A host this computer's user paired with may open one without being a paired
    // device: see `authorize`.
    let link_hello = ext.is_some_and(|e| e.files_only && e.reach);
    let auth = {
        let shared = shared.clone();
        let name = name.clone();
        // Checking a password is deliberately slow (key stretching): off the async workers.
        tokio::task::spawn_blocking(move || {
            authorize(&shared, fingerprint, &name, pairing_secret, password.as_deref(), link_hello)
        })
        .await??
    };
    let refusal = match auth {
        Auth::Known => None,
        Auth::Paired => {
            send.write_all(&HostMsg::Paired.encode()).await?;
            None
        }
        Auth::Denied => Some((reject("this device is not paired with the host"), "not paired")),
        Auth::Password { wrong } => {
            Some((HostMsg::PasswordRequired { wrong }.encode(), if wrong { "wrong password" } else { "no password" }))
        }
        Auth::LockedOut(left) => {
            let reason = format!("too many wrong passwords; try again in {} s", left.as_secs().max(1));
            Some((reject(&reason), "password locked out"))
        }
    };
    if let Some((message, why)) = refusal {
        send.write_all(&message).await?;
        let _ = send.finish();
        let _ = send.stopped().await;
        bail!("refused client '{name}' ({fingerprint}): {why}");
    }
    // Where else this host answers, for clients that ask: tried along with this address later.
    let addresses = if ext.is_some_and(|e| e.addresses) { shared.welcome_addresses() } else { Vec::new() };
    let remote = peer_addr(conn.remote_address());
    // For the rest of the connection: standalone reach looks at who is connected.
    let _connected = shared.reach.reach().client_connected(fingerprint);
    let (control, outbox) = ControlSender::channel();
    // A relay link: the device only talks to the relay service. Under `--relay-only` that is
    // every connection.
    let link = shared.options.relay_only || link_hello;
    let client = ClientConn {
        conn: conn.clone(),
        fingerprint,
        name: name.clone(),
        control,
        via_relay: shared.reach.context().socket.tunnel_relay(conn.remote_address()),
        link,
    };
    if link {
        tracing::info!("client '{name}' ({fingerprint}) linked from {remote}");
        return serve_link(client, send, recv, outbox, &shared, ext, addresses).await;
    }
    // Only clients that know about extensions understand the features field. Sessions share
    // the clipboard; a connection for files alone does not.
    let features = ext.map(|e| FEATURE_FILES | if e.files_only { 0 } else { FEATURE_CLIPBOARD });
    if ext.is_some_and(|e| e.files_only) {
        tracing::info!("client '{name}' ({fingerprint}) connected for files from {remote}");
        return serve_files_only(conn, send, fingerprint, &name, &shared, features, addresses).await;
    }
    tracing::info!("client '{name}' ({fingerprint}) connected from {remote}");

    // A newly connected device takes over: switching from the phone to a PC should just work.
    let active = Active { conn: conn.clone(), fingerprint, files: ext.is_some() };
    if let Some(old) = shared.active.lock().unwrap().replace(active) {
        old.conn.close(1u32.into(), b"another device took over");
    }

    let clipboard = ext.is_some_and(|e| e.clipboard).then(|| share_clipboard(&conn)).flatten();
    let peer = Peer { shared: shared.clone(), name: name.clone(), fingerprint, clipboard };
    // The screen stays on while the device watches it.
    let _screen = shared.awake.screen_on();
    let result = run_session(send, recv, &shared, ext, addresses, peer, SessionLink { client, outbox }).await;

    if let Some(input) = &shared.input {
        input.send(InputCmd::ReleaseAll);
    }
    let mut active = shared.active.lock().unwrap();
    if active.as_ref().is_some_and(|a| a.conn.stable_id() == conn.stable_id()) {
        *active = None;
    }
    result
}

/// A connection that carries control messages and nothing else, for the relay service: the
/// welcome, `Reach` for clients that ask, and then whatever the device sends, which goes to the
/// reach hooks. No screen is captured, no file stream is served and no other device is sent
/// away; the connection's datagrams are left to whoever relays them.
async fn serve_link(
    client: ClientConn,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    mut outbox: mpsc::Receiver<HostMsg>,
    shared: &Arc<Shared>,
    ext: Option<HelloExt>,
    addresses: Vec<String>,
) -> Result<()> {
    let ctx = shared.reach.context();
    let welcome = HostMsg::Welcome {
        version: PROTOCOL_VERSION,
        host_name: shared.options.name.clone(),
        codec: Codec::H264,
        width: 0,
        height: 0,
        // It shares no files and no clipboard.
        features: ext.map(|_| 0),
        addresses,
    };
    send.write_all(&welcome.encode()).await?;
    if ext.is_some_and(|e| e.reach) {
        send.write_all(&reach::reach_message(ctx, &client.fingerprint).encode()).await?;
    }
    let conn = client.conn.clone();
    shared.links.lock().unwrap().push(LinkConn { conn: conn.clone(), fingerprint: client.fingerprint });

    let reading = async {
        while let Some(body) = wire::read_msg(&mut recv).await? {
            match ClientMsg::decode(&body)? {
                ClientMsg::Hello { .. } => bail!("unexpected hello"),
                ClientMsg::Unsupported { tag } => tracing::debug!("ignoring unsupported message {tag}"),
                msg => dispatch_reach(ctx, &client, msg).await,
            }
        }
        anyhow::Ok(())
    };
    let writing = async {
        while let Some(msg) = outbox.recv().await {
            send.write_all(&msg.encode()).await?;
        }
        anyhow::Ok(())
    };
    let result = tokio::select! {
        r = reading => r,
        r = writing => r,
        e = conn.closed() => Err(e.into()),
    };
    shared.links.lock().unwrap().retain(|l| l.conn.stable_id() != conn.stable_id());
    result
}

/// Hands a client message that only the reach hooks understand to them. A hook that fails costs
/// the message, not the connection.
async fn dispatch_reach(ctx: &ReachContext, client: &ClientConn, msg: ClientMsg) {
    if let Err(e) = reach::handle_client_msg(ctx, client, msg).await {
        tracing::warn!("reach: message from '{}' failed: {e:#}", client.name);
    }
}

/// What a session's control stream shares with the reach hooks: the device they can talk to, and
/// what they queued to say.
struct SessionLink {
    client: ClientConn,
    outbox: mpsc::Receiver<HostMsg>,
}

/// Shares this computer's clipboard with the device on `conn` for the session: what is copied
/// here goes to it on a stream of its own; what it sends goes through the returned sender.
fn share_clipboard(conn: &quinn::Connection) -> Option<std::sync::mpsc::Sender<velora_clipboard::Clip>> {
    let (conn, runtime) = (conn.clone(), tokio::runtime::Handle::current());
    velora_clipboard::spawn(move |clip| {
        let encoded = match clip.encode() {
            Ok(encoded) => encoded,
            Err(e) => return tracing::warn!("cannot share the clipboard: {e:#}"),
        };
        let conn = conn.clone();
        runtime.spawn(async move {
            let sent = async {
                let (mut send, _recv) = conn.open_bi().await?;
                wire_files::send_clipboard(&mut send, encoded.0, &encoded.1).await
            };
            match sent.await {
                Ok(()) => tracing::debug!("clipboard sent to the device ({} bytes)", encoded.1.len()),
                Err(e) => tracing::debug!("clipboard not sent: {e:#}"),
            }
        });
    })
}

/// A connection for file transfers only: nothing is captured, and the current session stays.
async fn serve_files_only(
    conn: quinn::Connection,
    mut send: quinn::SendStream,
    fingerprint: Fingerprint,
    name: &str,
    shared: &Arc<Shared>,
    features: Option<u32>,
    addresses: Vec<String>,
) -> Result<()> {
    let welcome = HostMsg::Welcome {
        version: PROTOCOL_VERSION,
        host_name: shared.options.name.clone(),
        codec: Codec::H264,
        width: 0,
        height: 0,
        features,
        addresses,
    };
    send.write_all(&welcome.encode()).await?;
    shared.files.lock().unwrap().push(FilesConn { conn: conn.clone(), fingerprint });
    let result = tokio::select! {
        r = crate::transfer::accept(conn.clone(), Peer { shared: shared.clone(), name: name.into(), fingerprint, clipboard: None }) => r,
        e = conn.closed() => Err(e.into()),
    };
    shared.files.lock().unwrap().retain(|c| c.conn.stable_id() != conn.stable_id());
    result
}

impl Shared {
    pub fn is_service(&self) -> bool {
        self.options.service
    }

    /// Looks at this computer's LAN and VPN addresses again and records them in the reach state,
    /// where everything that advertises the host's addresses reads them. Returns them.
    fn refresh_local(&self) -> (String, Vec<String>) {
        let bind = self.options.bind;
        let address = advertised_address(bind);
        let vpn = vpn_addresses(bind.port());
        self.reach.reach().update(|state| {
            state.set_addresses(
                AddressKind::Lan,
                (!address.starts_with('<')).then(|| address.clone()).into_iter().collect(),
            );
            state.set_addresses(AddressKind::Vpn, vpn.clone());
        });
        (address, vpn)
    }

    /// The addresses a welcome lists for clients without `HostMsg::Reach`: the host's own, at most
    /// eight, the most useful first.
    fn welcome_addresses(&self) -> Vec<String> {
        self.refresh_local();
        self.reach.reach().read().welcome_addresses()
    }

    /// Opens a pairing window, replacing any open one.
    fn start_pairing(&self) -> Result<PendingPairing> {
        let (address, vpn) = self.refresh_local();
        let (key, public) = {
            let state = self.reach.reach().read();
            (state.dht_key, state.addresses_of(&AddressKind::Public))
        };
        // The device secret goes in the link along with the key, and nowhere else: it opens the
        // host's record in the DHT for this device until the device is removed.
        let secret = key.map(|_| new_device_secret()).transpose()?;
        let pairing = PendingPairing {
            code: PairingCode::generate(self.fingerprint)?,
            also: link_addresses(&address, &vpn, &public, key.as_ref(), secret.as_ref()),
            address,
            key,
            secret,
            expires: Instant::now() + PAIRING_TTL,
        };
        *self.pairing.lock().unwrap() = Some(pairing.clone());
        Ok(pairing)
    }

    /// Handles a request from the launcher on this computer. Under the service, the host is
    /// shared by everyone who logs on: only administrators may change who has access, and
    /// nobody stops it this way (the service would only start it again).
    pub fn control(&self, request: Request, privileged: bool) -> Reply {
        if self.options.service && request == Request::Shutdown {
            return Err("this host runs as the Velora service; turn the service off instead".into());
        }
        // Sending files changes nothing about access, and reads them as the user at the console.
        // Dismissing an offer only forgets it: access to this computer stays as it was. Answering
        // a device's files is the user's call: it can reach their screen already. Staying awake
        // decides only whether the computer sleeps. The standalone reach switches are not here:
        // they decide whether this computer opens a port on the router, is listed in the DHT and
        // carries other devices' traffic, which is access in the sense that matters.
        let harmless = matches!(
            request,
            Request::Status
                | Request::SendFiles { .. }
                | Request::DismissOffer { .. }
                | Request::AnswerFiles { .. }
                | Request::SetStayAwake { .. }
        );
        if self.options.service && !privileged && !harmless {
            return Err("only an administrator can change this computer's access".into());
        }
        let result = match request {
            Request::Status => Ok(()),
            Request::StartPairing => self.start_pairing().map(drop),
            Request::CancelPairing => {
                *self.pairing.lock().unwrap() = None;
                Ok(())
            }
            Request::Revoke { fingerprint } => self.revoke(&fingerprint),
            Request::DismissOffer { uri } => {
                self.offers.lock().unwrap().retain(|o| o.uri != uri);
                Ok(())
            }
            Request::AnswerFiles { id, accept, always } => self.answer_files(id, accept, always),
            Request::SetPassword { password } => {
                crate::password::set(&self.state, password.as_deref()).map(|()| self.password.reset())
            }
            Request::Shutdown => {
                self.shutdown.notify_one();
                Ok(())
            }
            Request::SendFiles { paths } => self.send_files(paths),
            Request::SetStayAwake { on } => self.awake.set(&self.state, on),
            Request::SetReach { standalone, relay_for_others, dht } => {
                self.reach.set_switches(Switches { standalone, relay_for_others, dht })
            }
            // The protocol has them; the host answers them in the next commit.
            Request::AddRelay { .. }
            | Request::RemoveRelay { .. }
            | Request::AllowRelayHost { .. }
            | Request::RemoveRelayHost { .. } => Err(anyhow::anyhow!("this build does not manage relays yet")),
        };
        result.and_then(|()| self.status()).map_err(|e| format!("{e:#}"))
    }

    /// Starts sending `paths` to the connected device; the transfer goes on in the background.
    /// Called from a blocking thread of the runtime.
    fn send_files(&self, paths: Vec<PathBuf>) -> Result<()> {
        ensure!(!paths.is_empty(), "nothing to send");
        ensure!(paths.iter().all(|p| p.is_absolute()), "paths must be absolute");
        let conn = {
            let active = self.active.lock().unwrap();
            let active = active.as_ref().context("no device is connected")?;
            ensure!(active.files, "the connected device can't receive files; update Velora on it");
            active.conn.clone()
        };
        let service = self.options.service;
        tokio::runtime::Handle::current().spawn(async move {
            let count = paths.len();
            match crate::transfer::offer(conn, paths, service).await {
                Ok(_) => tracing::info!("sent {count} item(s) to the connected device"),
                Err(e) => tracing::warn!("sending files failed: {e:#}"),
            }
        });
        Ok(())
    }

    fn revoke(&self, fingerprint: &str) -> Result<()> {
        let fingerprint = Fingerprint::from_base64(fingerprint)?;
        let clients = self.clients.lock().unwrap();
        if revoke(&self.state, &fingerprint.to_base64())? == 0 {
            bail!("this device is not paired");
        }
        drop(clients);
        if let Some(active) = self.active.lock().unwrap().as_ref().filter(|a| a.fingerprint == fingerprint) {
            active.conn.close(2u32.into(), b"device removed on the host");
        }
        for files in self.files.lock().unwrap().iter().filter(|c| c.fingerprint == fingerprint) {
            files.conn.close(2u32.into(), b"device removed on the host");
        }
        for link in self.links.lock().unwrap().iter().filter(|c| c.fingerprint == fingerprint) {
            link.conn.close(2u32.into(), b"device removed on the host");
        }
        reach::on_revoked(self.reach.context(), &fingerprint);
        Ok(())
    }

    fn status(&self) -> Result<control::Status> {
        let clients: Vec<AuthorizedClient> = self.state.load(StateDir::AUTHORIZED_CLIENTS)?;
        let connected = self.active.lock().unwrap().as_ref().map(|a| a.fingerprint.to_base64());
        let devices = clients
            .into_iter()
            .map(|c| control::Device {
                short: Fingerprint::from_base64(&c.fingerprint).map(|f| f.short()).unwrap_or_default(),
                connected: connected.as_deref() == Some(c.fingerprint.as_str()),
                name: c.name,
                fingerprint: c.fingerprint,
                added_unix: c.added_unix,
            })
            .collect();
        let pairing = self.pairing.lock().unwrap().as_ref().and_then(|p| {
            let left = p.expires.checked_duration_since(Instant::now())?;
            Some(control::Pairing {
                uri: p.uri(),
                code: p.code.encode(),
                address: p.address.clone(),
                expires_in_secs: left.as_secs(),
            })
        });
        let (address, also) = self.refresh_local();
        Ok(control::Status {
            name: self.options.name.clone(),
            version: velora_update::Version::current().to_string(),
            fingerprint: self.fingerprint.short(),
            address: (!address.starts_with('<')).then_some(address),
            also,
            service: self.options.service,
            password_set: crate::password::is_set(&self.state)?,
            devices,
            pairing,
            offers: self.current_offers(),
            requests: self
                .requests
                .lock()
                .unwrap()
                .iter()
                .map(|r| control::FileRequest {
                    id: r.id,
                    name: r.name.clone(),
                    bytes: r.bytes,
                    folder: r.folder.clone(),
                })
                .collect(),
            stay_awake: self.awake.setting(&self.state),
            reach: Some(self.reach.reach().read().status()),
        })
    }

    /// Asks the user here, through the launcher, before files from a device are saved; devices
    /// marked "always accept" skip the question. Fails with the reason to give the device.
    pub async fn ask_to_receive(
        &self,
        name: &str,
        fingerprint: &Fingerprint,
        bytes: u64,
        folder: String,
    ) -> std::result::Result<(), &'static str> {
        let fp = fingerprint.to_base64();
        let trusted = self
            .state
            .load::<Vec<AuthorizedClient>>(StateDir::AUTHORIZED_CLIENTS)
            .is_ok_and(|clients| clients.iter().any(|c| c.fingerprint == fp && c.trust_files));
        if trusted {
            return Ok(());
        }
        let (answer, answered) = oneshot::channel();
        let id = self.next_request.fetch_add(1, Ordering::Relaxed);
        tracing::info!("client '{name}' asks to send {bytes} bytes to {folder}");
        self.requests.lock().unwrap().push(PendingRequest {
            id,
            name: name.to_string(),
            fingerprint: fp,
            bytes,
            folder,
            answer: Some(answer),
        });
        let result = tokio::time::timeout(REQUEST_TTL, answered).await;
        self.requests.lock().unwrap().retain(|r| r.id != id);
        match result {
            Ok(Ok(true)) => Ok(()),
            Ok(Ok(false)) => Err("the other computer declined the files"),
            _ => Err("nobody accepted the files on the other computer in time"),
        }
    }

    fn answer_files(&self, id: u64, accept: bool, always: bool) -> Result<()> {
        let mut requests = self.requests.lock().unwrap();
        let request = requests.iter_mut().find(|r| r.id == id).context("this request is no longer open")?;
        if accept && always {
            let _clients = self.clients.lock().unwrap();
            let mut clients: Vec<AuthorizedClient> = self.state.load(StateDir::AUTHORIZED_CLIENTS)?;
            for client in clients.iter_mut().filter(|c| c.fingerprint == request.fingerprint) {
                client.trust_files = true;
            }
            self.state.save(StateDir::AUTHORIZED_CLIENTS, &clients)?;
        }
        if let Some(answer) = request.answer.take() {
            let _ = answer.send(accept);
        }
        Ok(())
    }

    /// Keeps a paired device's offer to be reached from here too, replacing its earlier one.
    /// It lives as long as the pairing code it carries.
    fn offer(&self, name: &str, link: String) {
        if parse_pairing_uri(&link).is_none() {
            tracing::warn!("client '{name}' offered an invalid pairing link");
            return;
        }
        tracing::info!("client '{name}' offered to pair back");
        let mut offers = self.offers.lock().unwrap();
        offers.retain(|o| o.name != name && o.expires > Instant::now());
        offers.truncate(MAX_OFFERS - 1);
        offers.push(PendingOffer { name: name.to_string(), uri: link, expires: Instant::now() + PAIRING_TTL });
    }

    fn current_offers(&self) -> Vec<control::Offer> {
        let mut offers = self.offers.lock().unwrap();
        offers.retain(|o| o.expires > Instant::now());
        offers.iter().map(|o| control::Offer { name: o.name.clone(), uri: o.uri.clone() }).collect()
    }
}

/// See [`Shared::ask_to_receive`].
struct PendingRequest {
    id: u64,
    name: String,
    fingerprint: String,
    bytes: u64,
    folder: String,
    answer: Option<oneshot::Sender<bool>>,
}

/// How long a device's files wait for an answer before they are declined.
const REQUEST_TTL: Duration = Duration::from_secs(120);

/// See [`Shared::offer`].
struct PendingOffer {
    name: String,
    uri: String,
    expires: Instant,
}

/// Offers kept at once; a device has at most one.
const MAX_OFFERS: usize = 8;

/// Removes the paired devices matching `device` (name, or full or short fingerprint) and
/// returns how many. Every handshake re-reads the list, so this applies without a restart.
pub fn revoke(state: &StateDir, device: &str) -> Result<usize> {
    let mut clients: Vec<AuthorizedClient> = state.load(StateDir::AUTHORIZED_CLIENTS)?;
    let before = clients.len();
    clients.retain(|c| {
        let short = Fingerprint::from_base64(&c.fingerprint).map(|f| f.short()).unwrap_or_default();
        c.name != device && c.fingerprint != device && short != device
    });
    let removed = before - clients.len();
    if removed > 0 {
        state.save(StateDir::AUTHORIZED_CLIENTS, &clients)?;
    }
    Ok(removed)
}

/// The address clients can actually reach: the bound one, or the LAN address when listening
/// on every interface.
pub fn advertised_address(bind: SocketAddr) -> String {
    let ip = if bind.ip().is_unspecified() { local_ip() } else { Some(bind.ip()) };
    match ip {
        Some(ip) => SocketAddr::new(ip, bind.port()).to_string(),
        None => format!("<this-pc-address>:{}", bind.port()),
    }
}

/// `ip:port` addresses on a VPN mesh: Tailscale and Netbird both hand out addresses from the
/// shared address space 100.64.0.0/10, and Tailscale IPv6 ones from fd7a:115c:a1e0::/48. Other
/// devices of the mesh reach this computer there from anywhere.
pub fn vpn_addresses(port: u16) -> Vec<String> {
    let Ok(interfaces) = if_addrs::get_if_addrs() else { return Vec::new() };
    let mut out: Vec<String> = interfaces
        .into_iter()
        .map(|i| i.ip())
        .filter(is_vpn_mesh)
        .map(|ip| SocketAddr::new(ip, port).to_string())
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Whether `ip` is in the ranges Tailscale and Netbird assign (see [`vpn_addresses`]).
pub(crate) fn is_vpn_mesh(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            a == 100 && (64..128).contains(&b)
        }
        std::net::IpAddr::V6(v6) => v6.segments()[..3] == [0xfd7a, 0x115c, 0xa1e0],
    }
}

/// This computer's LAN address (when it could be determined) and those on a VPN mesh: the two
/// kinds that depend on the network it is on right now.
pub(crate) fn local_addresses(bind: SocketAddr) -> (Option<String>, Vec<String>) {
    let lan = advertised_address(bind);
    ((!lan.starts_with('<')).then_some(lan), vpn_addresses(bind.port()))
}

/// A new random secret for a device to open the host's DHT record with.
fn new_device_secret() -> Result<[u8; DEVICE_SECRET_LEN]> {
    use ring::rand::SecureRandom;
    let mut secret = [0u8; DEVICE_SECRET_LEN];
    ring::rand::SystemRandom::new().fill(&mut secret).map_err(|_| anyhow::anyhow!("system RNG failure"))?;
    Ok(secret)
}

/// The addresses a pairing link carries besides the first one. Without the DHT key (and the
/// device secret) it carries the VPN addresses, as it always has, and the public one: whoever
/// scans it away from home needs that. With them the link has 78 more characters, and a QR code
/// of more than [`MAX_LINK_LEN`] gets hard to scan, so only what a first connection needs is
/// kept, the public address first, then the VPN ones, IPv6 last (each costs about 72 characters
/// against 25). The rest of the host's addresses reach the device in `HostMsg::Reach`.
fn link_addresses(
    address: &str,
    vpn: &[String],
    public: &[String],
    key: Option<&[u8; REACH_KEY_LEN]>,
    secret: Option<&[u8; DEVICE_SECRET_LEN]>,
) -> Vec<String> {
    let is_v6 = |address: &&String| address.starts_with('[');
    let by_priority = public.iter().chain(vpn.iter().filter(|a| !is_v6(a))).chain(vpn.iter().filter(is_v6));
    let unlimited = key.is_none() && secret.is_none();
    // The code is as long whatever its value.
    let code = PairingCode { host: Fingerprint([0; 32]), secret: [0; wire::PAIRING_SECRET_LEN] };
    let mut kept: Vec<String> = Vec::new();
    for candidate in by_priority {
        kept.push(candidate.clone());
        if !unlimited && pairing_uri_with(address, &kept, &code, key, secret).len() > MAX_LINK_LEN {
            kept.pop();
        }
    }
    // In the order a link has always listed them: the VPN addresses, then the public one.
    vpn.iter().chain(public).filter(|address| kept.contains(address)).cloned().collect()
}

/// Primary LAN address, found by asking the OS which interface would route to a public IP
/// (no packet is sent).
fn local_ip() -> Option<std::net::IpAddr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("192.0.2.1:9").ok()?;
    Some(socket.local_addr().ok()?.ip())
}

enum Auth {
    Known,
    Paired,
    Denied,
    /// Paired (or holding a valid pairing code), but the access password is missing or wrong.
    Password {
        wrong: bool,
    },
    LockedOut(Duration),
}

/// Decides whether a connecting device may open a session. The pairing code is consumed only
/// once the password (if any) was right too, so a device asked for the password can retry
/// with the same code. Unpaired devices learn nothing about the password.
///
/// `link_hello` is whether the hello is the one of a relay link, which reaches no screen. A link from
/// a device this host knows needs no password (the password protects the screen, and a client that
/// dials a relay holds only the password of the host it wants to reach, not this one's). Known means
/// a paired client, or a computer whose *host* this one's user paired with (it is in
/// `known_hosts.json` of the client side, see `reach::relay::trusts`): that registers with a relay
/// under its host identity, which is not in the list of client devices, and may open a link and
/// nothing else. Any other hello of such a device, and any link from one nobody knows, is judged
/// as it always was.
fn authorize(
    shared: &Shared,
    fingerprint: Fingerprint,
    name: &str,
    secret: Option<[u8; wire::PAIRING_SECRET_LEN]>,
    password: Option<&str>,
    link_hello: bool,
) -> Result<Auth> {
    let fp = fingerprint.to_base64();
    let pairing_valid = |secret: &[u8; wire::PAIRING_SECRET_LEN]| {
        let pairing = shared.pairing.lock().unwrap();
        pairing.as_ref().is_some_and(|p| p.expires > Instant::now() && p.code.secret_matches(secret))
    };
    // Re-read on every connection so `velora-host revoke` applies without a restart.
    let known = {
        let _clients = shared.clients.lock().unwrap();
        shared.state.load::<Vec<AuthorizedClient>>(StateDir::AUTHORIZED_CLIENTS)?.iter().any(|c| c.fingerprint == fp)
    };
    // What is let in here is served as a link, because the same hello decides both. A link reaches
    // no screen, which is what the access password protects, so none is asked. Any other hello of
    // the same device, a session or files, is judged below, as it always was.
    if link_hello && secret.is_none() {
        if known {
            return Ok(Auth::Known);
        }
        if reach::relay::trusts(shared.reach.context(), &fingerprint) {
            tracing::info!("accepted a link from the paired computer {fingerprint}");
            return Ok(Auth::Known);
        }
    }
    if !known && !secret.as_ref().is_some_and(pairing_valid) {
        return Ok(Auth::Denied);
    }
    match shared.password.check(&shared.state, fingerprint, password) {
        Check::Ok => {}
        Check::Required { wrong } => return Ok(Auth::Password { wrong }),
        Check::LockedOut(left) => return Ok(Auth::LockedOut(left)),
    }
    if known {
        // The check takes a moment: the device may have been removed meanwhile.
        let _clients = shared.clients.lock().unwrap();
        let clients: Vec<AuthorizedClient> = shared.state.load(StateDir::AUTHORIZED_CLIENTS)?;
        return Ok(if clients.iter().any(|c| c.fingerprint == fp) { Auth::Known } else { Auth::Denied });
    }

    let clients_lock = shared.clients.lock().unwrap();
    let mut clients: Vec<AuthorizedClient> = shared.state.load(StateDir::AUTHORIZED_CLIENTS)?;
    let mut pairing = shared.pairing.lock().unwrap();
    // Another device may have used the code meanwhile.
    let valid = secret
        .is_some_and(|s| pairing.as_ref().is_some_and(|p| p.expires > Instant::now() && p.code.secret_matches(&s)));
    if !valid {
        return Ok(Auth::Denied);
    }
    // Single use.
    let device_secret = pairing.take().and_then(|p| p.secret);
    clients.push(AuthorizedClient {
        name: name.to_string(),
        fingerprint: fp,
        added_unix: SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
        trust_files: false,
    });
    shared.state.save(StateDir::AUTHORIZED_CLIENTS, &clients)?;
    tracing::info!("paired new client '{name}' ({fingerprint})");
    // The hook gets no lock to hold.
    drop((pairing, clients_lock));
    reach::on_paired(shared.reach.context(), &fingerprint, name, device_secret);
    Ok(Auth::Paired)
}

/// State shared between the capture thread and the network tasks of one session.
struct Session {
    running: AtomicBool,
    keyframe_requested: AtomicBool,
    /// Bitrate the encoder should use, set by the rate control.
    bitrate_kbps: AtomicU32,
    /// What the rate control looks at, since its last decision.
    window: Mutex<RateWindow>,
    in_flight: AtomicU32,
    max_in_flight: AtomicU32,
    last_ack: Mutex<Instant>,
    stats: Mutex<Stats>,
    /// The display the client asked for, by index in `capture::list()`.
    display: AtomicUsize,
    /// The display being captured, once the capture thread switched to it.
    shown: AtomicUsize,
    /// The capture thread switched displays (or could not): tell the client.
    display_changed: tokio::sync::Notify,
}

/// Deliveries and waits of the current rate control period.
#[derive(Default)]
struct RateWindow {
    delivery: Duration,
    delivered: u32,
    held_back: Duration,
}

struct OutFrame {
    id: u32,
    keyframe: bool,
    width: u16,
    height: u16,
    captured: Instant,
    data: Vec<u8>,
}

impl Session {
    /// Saturating decrement: the counter may have been reset by the stall guard.
    fn ack_frame(&self) {
        let mut n = self.in_flight.load(Ordering::Acquire);
        while n > 0 {
            match self.in_flight.compare_exchange_weak(n, n - 1, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => break,
                Err(actual) => n = actual,
            }
        }
    }
}

async fn run_session(
    mut control_send: quinn::SendStream,
    mut control_recv: quinn::RecvStream,
    shared: &Arc<Shared>,
    ext: Option<HelloExt>,
    addresses: Vec<String>,
    peer: Peer,
    link: SessionLink,
) -> Result<()> {
    let SessionLink { client, mut outbox } = link;
    let conn = &client.conn;
    let client_name = peer.name.clone();
    let opts = &shared.options;
    let input = shared.input.clone().context("this host serves relays only")?;
    let ctx = shared.reach.context();
    // The host's sound goes to clients that play it, from builds that can capture it.
    let audio = ext.is_some_and(|e| e.audio) && velora_audio::SUPPORTED;
    let features = ext.map(|_| FEATURE_FILES | FEATURE_CLIPBOARD | if audio { FEATURE_AUDIO } else { 0 });
    // Sessions start on the primary display.
    let displays = capture::list();
    let first = displays.iter().position(|d| d.primary).unwrap_or(0);
    let session = Arc::new(Session {
        running: AtomicBool::new(true),
        keyframe_requested: AtomicBool::new(true),
        bitrate_kbps: AtomicU32::new(opts.bitrate_kbps),
        window: Mutex::new(RateWindow::default()),
        in_flight: AtomicU32::new(0),
        max_in_flight: AtomicU32::new(MIN_IN_FLIGHT + 1),
        last_ack: Mutex::new(Instant::now()),
        stats: Mutex::new(Stats::default()),
        display: AtomicUsize::new(first),
        shown: AtomicUsize::new(first),
        display_changed: tokio::sync::Notify::new(),
    });

    let (frame_tx, mut frame_rx) = mpsc::channel::<OutFrame>(4);
    let (ready_tx, ready_rx) = oneshot::channel();
    {
        let session = session.clone();
        let input = input.clone();
        let settings = EncoderSettings { fps: opts.fps, bitrate_kbps: opts.bitrate_kbps };
        let choice = opts.encoder.clone();
        std::thread::Builder::new().name("capture".into()).spawn(move || {
            if let Err(e) = capture_loop(&session, &choice, settings, frame_tx, ready_tx, &input) {
                tracing::error!("capture stopped: {e:#}");
            }
            session.running.store(false, Ordering::Relaxed);
        })?;
    }
    let rect = match ready_rx.await.context("capture thread exited")? {
        Ok(rect) => rect,
        Err(e) => {
            // Tell the client why instead of just dropping the connection.
            let reason = format!("host cannot stream: {e:#}");
            control_send.write_all(&HostMsg::Rejected { reason }.encode()).await?;
            let _ = control_send.finish();
            let _ = control_send.stopped().await;
            return Err(e);
        }
    };

    control_send
        .write_all(
            &HostMsg::Welcome {
                version: PROTOCOL_VERSION,
                host_name: opts.name.clone(),
                codec: Codec::H264,
                width: (rect.width & !1) as u16,
                height: (rect.height & !1) as u16,
                features,
                addresses,
            }
            .encode(),
        )
        .await?;
    // How to reach the host from elsewhere, for clients that ask and only for them.
    if ext.is_some_and(|e| e.reach) {
        control_send.write_all(&reach::reach_message(ctx, &client.fingerprint).encode()).await?;
    }

    if audio {
        let (conn, session) = (conn.clone(), session.clone());
        std::thread::Builder::new().name("audio".into()).spawn(move || {
            let mut seq = 0u32;
            let sent = velora_audio::stream_loopback(
                || session.running.load(Ordering::Relaxed),
                |data| {
                    seq = seq.wrapping_add(1);
                    // Fails only once the connection is gone.
                    conn.send_datagram(AudioPacket { seq, data: data.to_vec() }.encode().into()).is_ok()
                },
            );
            if let Err(e) = sent {
                tracing::warn!("sound not shared: {e:#}");
            }
        })?;
    }

    // Clients that can pick a display hear which there are, now and after every switch.
    let offer_displays = ext.is_some_and(|e| e.displays) && displays.len() > 1;
    let display_list = |current: usize| {
        let list = displays
            .iter()
            .map(|d| DisplayInfo {
                name: d.name.clone(),
                width: d.rect.width.min(u16::MAX as u32) as u16,
                height: d.rect.height.min(u16::MAX as u32) as u16,
                primary: d.primary,
            })
            .collect();
        HostMsg::Displays(DisplayList { current: current as u8, list })
    };
    if offer_displays {
        control_send.write_all(&display_list(first).encode()).await?;
    }
    // Everything written to the control stream after the welcome goes through here, one message
    // at a time: display changes, and what the reach hooks queued for this device.
    let announce = async {
        loop {
            tokio::select! {
                () = session.display_changed.notified(), if offer_displays => {
                    control_send.write_all(&display_list(session.shown.load(Ordering::Relaxed)).encode()).await?;
                }
                Some(msg) = outbox.recv() => control_send.write_all(&msg.encode()).await?,
                else => std::future::pending::<()>().await,
            }
        }
        #[allow(unreachable_code)]
        anyhow::Ok(())
    };

    let video = async {
        while let Some(frame) = frame_rx.recv().await {
            let header =
                FrameHeader { frame_id: frame.id, keyframe: frame.keyframe, width: frame.width, height: frame.height };
            session.stats.lock().unwrap().sent(frame.id, frame.captured, frame.data.len());
            let mut stream = conn.open_uni().await?;
            stream.write_all(&header.encode()).await?;
            stream.write_all(&frame.data).await?;
            stream.finish()?;
        }
        anyhow::Ok(())
    };

    let control = async {
        while let Some(body) = wire::read_msg(&mut control_recv).await? {
            match ClientMsg::decode(&body)? {
                ClientMsg::Key { code, state } => input.send(InputCmd::Key { code, state }),
                ClientMsg::MouseButton { button, down, x, y } => input.send(InputCmd::Button { button, down, x, y }),
                ClientMsg::Scroll { dx, dy } => input.send(InputCmd::Scroll { dx, dy }),
                ClientMsg::ReleaseAll => input.send(InputCmd::ReleaseAll),
                ClientMsg::RequestKeyframe => session.keyframe_requested.store(true, Ordering::Relaxed),
                ClientMsg::FrameAck { frame_id } => {
                    session.ack_frame();
                    *session.last_ack.lock().unwrap() = Instant::now();
                    if let Some(delivery) = session.stats.lock().unwrap().acked(frame_id) {
                        let mut window = session.window.lock().unwrap();
                        window.delivery += delivery;
                        window.delivered += 1;
                    }
                }
                ClientMsg::Text { text } => input.send(InputCmd::Text(text)),
                ClientMsg::OfferPairing { link } => shared.offer(&client_name, link),
                ClientMsg::SelectDisplay { index } if (index as usize) < displays.len() => {
                    session.display.store(index as usize, Ordering::Relaxed)
                }
                ClientMsg::SelectDisplay { index } => tracing::debug!("no display {index}"),
                ClientMsg::Unsupported { tag } => tracing::debug!("ignoring unsupported message {tag}"),
                msg @ (ClientMsg::Reached { .. }
                | ClientMsg::RelayRegister { .. }
                | ClientMsg::RelayTo { .. }
                | ClientMsg::Wake { .. }
                | ClientMsg::PunchRequest { .. }) => dispatch_reach(ctx, &client, msg).await,
                ClientMsg::Hello { .. } => bail!("unexpected hello"),
            }
        }
        anyhow::Ok(())
    };

    let pointer = async {
        let mut last_seq = 0u32;
        loop {
            let datagram = conn.read_datagram().await?;
            let Ok(m) = MouseMove::decode(&datagram) else { continue };
            if m.is_newer_than(last_seq) {
                last_seq = m.seq;
                input.send(InputCmd::Move { x: m.x, y: m.y });
            }
        }
        #[allow(unreachable_code)]
        anyhow::Ok(())
    };

    let monitor = async {
        let frame_interval = Duration::from_secs_f64(1.0 / opts.fps as f64);
        let mut tick = tokio::time::interval(Duration::from_millis(250));
        let mut last_log = Instant::now();
        let mut rate = RateControl::new(opts.bitrate_kbps, Instant::now());
        let mut last_rate = Instant::now();
        while session.running.load(Ordering::Relaxed) {
            tick.tick().await;
            if opts.adaptive_bitrate && last_rate.elapsed() >= rate::PERIOD {
                last_rate = Instant::now();
                let window = std::mem::take(&mut *session.window.lock().unwrap());
                let sample = rate::Sample {
                    delivery: (window.delivered > 0).then(|| window.delivery / window.delivered),
                    held_back: window.held_back,
                };
                if let Some(kbps) = rate.update(sample, Instant::now()) {
                    tracing::info!(
                        "bitrate {kbps} kbit/s (delivery {:.0} ms, held back {:.0} ms)",
                        sample.delivery.unwrap_or_default().as_secs_f64() * 1000.0,
                        sample.held_back.as_secs_f64() * 1000.0
                    );
                    session.bitrate_kbps.store(kbps, Ordering::Relaxed);
                }
            }
            let rtt = conn.rtt();
            let budget = (rtt.as_secs_f64() / frame_interval.as_secs_f64()).ceil() as u32 + MIN_IN_FLIGHT;
            session.max_in_flight.store(budget.clamp(MIN_IN_FLIGHT, MAX_IN_FLIGHT), Ordering::Relaxed);
            if last_log.elapsed() >= STATS_INTERVAL {
                let elapsed = last_log.elapsed();
                last_log = Instant::now();
                session.stats.lock().unwrap().log(elapsed, rtt, session.bitrate_kbps.load(Ordering::Relaxed));
            }
        }
        anyhow::Ok(())
    };

    let result = tokio::select! {
        r = video => r,
        r = control => r,
        r = pointer => r,
        r = monitor => r,
        r = announce => r,
        r = crate::transfer::accept(conn.clone(), peer) => r,
        e = conn.closed() => Err(e.into()),
    };
    session.running.store(false, Ordering::Relaxed);
    result
}

/// Opens the encoder for `capturer`'s frames: on its GPU when `gpu` allows and the encoder can
/// take them there, else from memory. The capture follows the encoder's choice.
fn open_encoder(
    choice: &EncoderChoice,
    settings: EncoderSettings,
    rect: DisplayRect,
    capturer: &mut dyn capture::Capturer,
    gpu: bool,
) -> Result<Box<dyn encode::VideoEncoder>> {
    #[cfg(windows)]
    let device = if gpu { capturer.device() } else { None };
    #[cfg(not(windows))]
    let device: Option<encode::GpuDevice> = {
        let _ = gpu;
        None
    };
    let encoder = encode::open(choice, settings, rect.width, rect.height, device.as_ref())?;
    capturer.set_gpu_frames(encoder.on_gpu());
    Ok(encoder)
}

fn capture_loop(
    session: &Session,
    choice: &EncoderChoice,
    settings: EncoderSettings,
    frames: mpsc::Sender<OutFrame>,
    ready: oneshot::Sender<Result<DisplayRect>>,
    input: &InputHandle,
) -> Result<()> {
    let mut shown = session.display.load(Ordering::Relaxed);
    // Frames stay on the GPU for encoders that take them there, until that fails once.
    let mut gpu = encode::zero_copy();
    let setup = || -> Result<_> {
        let mut capturer = capture::open(shown)?;
        let rect = capturer.rect();
        let encoder = open_encoder(choice, settings, rect, capturer.as_mut(), gpu)?;
        tracing::info!("encoder: {}", encoder.name());
        Ok((capturer, encoder))
    };
    let (mut capturer, mut encoder) = match setup() {
        Ok(v) => v,
        Err(e) => {
            let _ = ready.send(Err(anyhow::anyhow!("{e:#}")));
            return Err(e);
        }
    };
    let mut rect = capturer.rect();
    input.send(InputCmd::SetDisplay(rect));
    let _ = ready.send(Ok(rect));

    let interval = Duration::from_secs_f64(1.0 / settings.fps.max(1) as f64);
    let mut bitrate = settings.bitrate_kbps;
    let mut have_picture = false;
    let mut next_id = 0u32;
    let mut last_capture = Instant::now() - interval;

    while session.running.load(Ordering::Relaxed) {
        // The client picked another display: capture it instead, at its size.
        let wanted = session.display.load(Ordering::Relaxed);
        if wanted != shown {
            match capture::open(wanted) {
                Ok(next) => {
                    capturer = next;
                    rect = capturer.rect();
                    input.send(InputCmd::SetDisplay(rect));
                    let settings = EncoderSettings { bitrate_kbps: bitrate, ..settings };
                    encoder = open_encoder(choice, settings, rect, capturer.as_mut(), gpu)?;
                    session.keyframe_requested.store(true, Ordering::Relaxed);
                    have_picture = false;
                    shown = wanted;
                    tracing::info!("streaming display {}", wanted + 1);
                }
                Err(e) => {
                    tracing::warn!("cannot capture display {}: {e:#}", wanted + 1);
                    session.display.store(shown, Ordering::Relaxed);
                }
            }
            session.shown.store(shown, Ordering::Relaxed);
            session.display_changed.notify_one();
        }

        // Never capture faster than the target frame rate.
        let since = last_capture.elapsed();
        if since < interval {
            std::thread::sleep(interval - since);
        }

        let in_flight = session.in_flight.load(Ordering::Acquire);
        if in_flight >= session.max_in_flight.load(Ordering::Relaxed) {
            if session.last_ack.lock().unwrap().elapsed() > ACK_STALL_RESET {
                tracing::warn!("no frame acks for {ACK_STALL_RESET:?}, resetting flow control");
                session.in_flight.store(0, Ordering::Release);
                *session.last_ack.lock().unwrap() = Instant::now();
            } else {
                session.stats.lock().unwrap().throttled += 1;
                let waited = Instant::now();
                std::thread::sleep(Duration::from_millis(1));
                session.window.lock().unwrap().held_back += waited.elapsed();
                continue;
            }
        }

        let keyframe = session.keyframe_requested.load(Ordering::Relaxed);
        // Block until the screen changes (bounded so shutdown and keyframe requests are
        // noticed), but return immediately when a keyframe of an unchanged screen is due.
        let timeout = if keyframe && have_picture { Duration::ZERO } else { Duration::from_millis(100) };
        let frame = capturer.capture(timeout)?;
        let changed = frame.is_some();
        let captured_at = Instant::now();
        last_capture = captured_at;
        if !changed && !(keyframe && have_picture) {
            continue;
        }
        have_picture = true;

        // The rate control asked for another bitrate: in place, or by opening the encoder again
        // (which then starts with a keyframe).
        let target = session.bitrate_kbps.load(Ordering::Relaxed);
        if target != bitrate {
            bitrate = target;
            if !encoder.set_bitrate(target) {
                let settings = EncoderSettings { bitrate_kbps: target, ..settings };
                encoder = open_encoder(choice, settings, rect, capturer.as_mut(), gpu)?;
                session.keyframe_requested.store(true, Ordering::Relaxed);
                continue;
            }
        }
        // Captured before the encoder switched between the GPU and memory: wait for the next.
        #[cfg(windows)]
        if frame.as_ref().is_some_and(|f| f.texture.is_some() != encoder.on_gpu()) {
            session.keyframe_requested.store(true, Ordering::Relaxed);
            continue;
        }
        let keyframe = keyframe || session.keyframe_requested.load(Ordering::Relaxed);
        session.keyframe_requested.store(false, Ordering::Relaxed);
        let encode_start = Instant::now();
        let encoded = match encoder.encode(frame.as_ref(), keyframe) {
            Ok(encoded) => encoded,
            // Encoding on the GPU is the newer path: if it fails, copy frames to memory instead.
            Err(e) if encoder.on_gpu() => {
                tracing::warn!("encoding frames on the GPU failed: {e:#}; copying them to memory instead");
                gpu = false;
                let settings = EncoderSettings { bitrate_kbps: bitrate, ..settings };
                encoder = open_encoder(choice, settings, rect, capturer.as_mut(), gpu)?;
                session.keyframe_requested.store(true, Ordering::Relaxed);
                have_picture = false;
                continue;
            }
            Err(e) => return Err(e),
        };
        {
            let mut stats = session.stats.lock().unwrap();
            stats.convert_time += encoded.convert_time;
            stats.encode_time += encode_start.elapsed() - encoded.convert_time;
        }

        if capturer.rect() != rect {
            rect = capturer.rect();
            input.send(InputCmd::SetDisplay(rect));
        }

        for encoded in encoded.frames {
            session.in_flight.fetch_add(1, Ordering::AcqRel);
            let frame = OutFrame {
                id: next_id,
                keyframe: encoded.keyframe,
                width: encoded.width,
                height: encoded.height,
                captured: captured_at,
                data: encoded.data,
            };
            next_id = next_id.wrapping_add(1);
            if frames.blocking_send(frame).is_err() {
                return Ok(());
            }
        }
    }
    Ok(())
}

#[derive(Default)]
struct Stats {
    pending: VecDeque<(u32, Instant)>,
    frames: u32,
    bytes: u64,
    throttled: u32,
    convert_time: Duration,
    encode_time: Duration,
    latency_sum: Duration,
    latency_max: Duration,
    acked: u32,
}

impl Stats {
    fn sent(&mut self, id: u32, captured: Instant, bytes: usize) {
        self.frames += 1;
        self.bytes += bytes as u64;
        self.pending.push_back((id, captured));
        if self.pending.len() > 256 {
            self.pending.pop_front();
        }
    }

    /// Notes a frame's acknowledgement; returns its capture-to-acknowledgement time.
    fn acked(&mut self, id: u32) -> Option<Duration> {
        while let Some(&(pending, captured)) = self.pending.front() {
            self.pending.pop_front();
            if pending == id {
                let latency = captured.elapsed();
                self.latency_sum += latency;
                self.latency_max = self.latency_max.max(latency);
                self.acked += 1;
                return Some(latency);
            }
        }
        None
    }

    fn log(&mut self, elapsed: Duration, rtt: Duration, bitrate_kbps: u32) {
        let secs = elapsed.as_secs_f64();
        let per_frame = |d: Duration, n: u32| if n == 0 { 0.0 } else { d.as_secs_f64() * 1000.0 / n as f64 };
        tracing::info!(
            "video: {:.1} fps, {:.2} Mbit/s (target {:.1}), convert {:.1} ms, encode {:.1} ms, capture->client {:.1} ms (max {:.1}), rtt {:.1} ms, throttled {}",
            self.frames as f64 / secs,
            self.bytes as f64 * 8.0 / secs / 1e6,
            bitrate_kbps as f64 / 1000.0,
            per_frame(self.convert_time, self.frames),
            per_frame(self.encode_time, self.frames),
            per_frame(self.latency_sum, self.acked),
            self.latency_max.as_secs_f64() * 1000.0,
            rtt.as_secs_f64() * 1000.0,
            self.throttled,
        );
        let pending = std::mem::take(&mut self.pending);
        *self = Self { pending, ..Self::default() };
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use velora_protocol::{
        control::ReachStatus,
        identity::{Identity, KnownHost},
        pairing::{parse_pairing_link, URI_PREFIX},
    };

    use super::*;

    #[test]
    fn recognizes_vpn_mesh_addresses() {
        let vpn = |s: &str| is_vpn_mesh(&s.parse().unwrap());
        assert!(vpn("100.101.102.103"), "Tailscale / Netbird");
        assert!(vpn("100.64.0.1") && vpn("100.127.255.254"));
        assert!(!vpn("100.63.0.1") && !vpn("100.128.0.1"), "outside 100.64.0.0/10");
        assert!(!vpn("192.168.1.9") && !vpn("10.0.0.2"));
        assert!(vpn("fd7a:115c:a1e0::1234"));
        assert!(!vpn("fe80::1"));
    }

    // The host, in process, on the loopback, with clients that speak the protocol to it. Sessions
    // need a screen, which a test cannot count on, so these go through the connections that do not:
    // links (what the relay service uses) and file managers.

    /// A host in a scratch state directory, accepting connections the way `run` does.
    struct TestHost {
        shared: Arc<Shared>,
        endpoint: quinn::Endpoint,
        dir: PathBuf,
        accepting: tokio::task::JoinHandle<()>,
    }

    impl Drop for TestHost {
        fn drop(&mut self) {
            self.accepting.abort();
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    async fn host(tag: &str, relay_only: bool) -> TestHost {
        host_as(tag, relay_only, false).await
    }

    async fn host_as(tag: &str, relay_only: bool, service: bool) -> TestHost {
        host_on(tag, "127.0.0.1:0".parse().unwrap(), relay_only, service).await
    }

    async fn host_on(tag: &str, bind: SocketAddr, relay_only: bool, service: bool) -> TestHost {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("velora-server-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let state = StateDir::open(Some(dir.clone()), "host").unwrap();
        // A test host must not hold the computer awake.
        std::fs::write(state.path("power.json"), r#"{"stay_awake":false}"#).unwrap();
        let options = HostOptions {
            bind,
            name: "test host".into(),
            fps: 30,
            bitrate_kbps: 1000,
            encoder: EncoderChoice::Software,
            service,
            adaptive_bitrate: false,
            relay_only,
        };
        let (shared, endpoint) = open(options, state).unwrap();
        let accepting = tokio::spawn({
            let (shared, endpoint) = (shared.clone(), endpoint.clone());
            async move {
                while let Some(incoming) = endpoint.accept().await {
                    on_incoming(&shared, incoming);
                }
            }
        });
        TestHost { shared, endpoint, dir, accepting }
    }

    /// A client's end of a connection to a [`TestHost`].
    struct Client {
        conn: quinn::Connection,
        send: quinn::SendStream,
        recv: quinn::RecvStream,
        _endpoint: quinn::Endpoint,
    }

    impl Client {
        async fn send(&mut self, msg: ClientMsg) {
            self.send.write_all(&msg.encode()).await.unwrap();
        }

        /// The next message from the host.
        async fn next(&mut self) -> HostMsg {
            let body = tokio::time::timeout(Duration::from_secs(5), wire::read_msg(&mut self.recv))
                .await
                .expect("the host answers")
                .unwrap()
                .expect("the stream is open");
            HostMsg::decode(&body).unwrap()
        }

        /// Whether the host sends nothing for a moment.
        async fn silent(&mut self) -> bool {
            tokio::time::timeout(Duration::from_millis(400), wire::read_msg(&mut self.recv)).await.is_err()
        }
    }

    impl TestHost {
        fn pair(&self, identity: &Identity, name: &str) {
            let _clients = self.shared.clients.lock().unwrap();
            let mut clients: Vec<AuthorizedClient> = self.shared.state.load(StateDir::AUTHORIZED_CLIENTS).unwrap();
            clients.push(AuthorizedClient {
                name: name.into(),
                fingerprint: identity.fingerprint().to_base64(),
                added_unix: 0,
                trust_files: false,
            });
            self.shared.state.save(StateDir::AUTHORIZED_CLIENTS, &clients).unwrap();
        }

        /// Connects as `identity` and sends the hello.
        async fn connect(&self, identity: &Identity, ext: Option<HelloExt>) -> Client {
            self.connect_to(self.endpoint.local_addr().unwrap(), identity, ext).await
        }

        async fn connect_to(&self, to: SocketAddr, identity: &Identity, ext: Option<HelloExt>) -> Client {
            let from = if to.is_ipv6() { "[::]:0" } else { "127.0.0.1:0" };
            let endpoint = quinn::Endpoint::client(from.parse().unwrap()).unwrap();
            let config = tls::client_config(identity, self.shared.fingerprint).unwrap();
            let conn = endpoint.connect_with(config, to, tls::SERVER_NAME).unwrap().await.unwrap();
            let (mut send, recv) = conn.open_bi().await.unwrap();
            let hello = ClientMsg::Hello {
                version: PROTOCOL_VERSION,
                name: "test client".into(),
                pairing_secret: None,
                password: None,
                ext,
            };
            send.write_all(&hello.encode()).await.unwrap();
            Client { conn, send, recv, _endpoint: endpoint }
        }

        fn reach(&self) -> &reach::Reach {
            self.shared.reach.reach()
        }
    }

    /// What a client sends to talk to the relay service: no session, and the Reach message.
    fn link_hello() -> HelloExt {
        HelloExt { files_only: true, reach: true, addresses: true, ..Default::default() }
    }

    async fn until(mut condition: impl FnMut() -> bool) {
        for _ in 0..200 {
            if condition() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the condition did not come true");
    }

    #[tokio::test]
    async fn reach_follows_the_welcome_for_a_client_that_asks_and_only_for_it() {
        let host = host("reach", false).await;
        let (asking, plain) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        host.pair(&asking, "asking");
        host.pair(&plain, "plain");
        host.reach().update(|state| {
            state.set_addresses(AddressKind::Public, vec!["198.51.100.4:51820".into()]);
            state.set_relays(vec![reach::RelayEntry {
                fingerprint: Fingerprint([4; 32]),
                name: "relay".into(),
                addresses: vec!["203.0.113.9:7420".into()],
            }]);
        });

        let mut client = host.connect(&asking, Some(link_hello())).await;
        let HostMsg::Welcome { addresses, features, width, height, .. } = client.next().await else {
            panic!("the welcome comes first")
        };
        assert_eq!((width, height, features), (0, 0, Some(0)), "a link shares no screen and no files");
        let local = host.endpoint.local_addr().unwrap().to_string();
        assert_eq!(addresses.first(), Some(&local));
        assert!(addresses.contains(&"198.51.100.4:51820".to_string()));
        assert!(!addresses.contains(&"203.0.113.9:7420".to_string()), "no relay in a welcome");
        let HostMsg::Reach { addresses, key, secret, relays, relays_for_others, .. } = client.next().await else {
            panic!("Reach follows the welcome")
        };
        assert_eq!(addresses[0], (AddressKind::Lan, local));
        assert!(addresses.contains(&(AddressKind::Public, "198.51.100.4:51820".to_string())));
        let relay_kind = AddressKind::Relay(Fingerprint([4; 32]).to_base64());
        assert_eq!(addresses.last(), Some(&(relay_kind, "203.0.113.9:7420".to_string())), "relays come last");
        assert_eq!((key, secret, relays_for_others), ([0; REACH_KEY_LEN], [0; DEVICE_SECRET_LEN], false));
        assert_eq!(relays.len(), 1);

        // The same hello without the bit: a file manager's. Welcome, and nothing after it.
        let ext = HelloExt { files_only: true, addresses: true, ..Default::default() };
        let mut client = host.connect(&plain, Some(ext)).await;
        let HostMsg::Welcome { features, .. } = client.next().await else { panic!("a welcome") };
        assert_eq!(features, Some(FEATURE_FILES), "files are served on this one");
        assert!(client.silent().await, "a client that did not set the bit gets no Reach");
    }

    #[tokio::test]
    async fn a_relay_only_host_starts_no_session_whatever_the_hello_asks_for() {
        let host = host("relay-only", true).await;
        let (old, new) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        host.pair(&old, "old client");
        host.pair(&new, "new client");

        // A hello from before extensions existed: a session, to any other host. Here, a welcome
        // with no screen, and no Reach, since it did not ask.
        let mut client = host.connect(&old, None).await;
        let HostMsg::Welcome { width, height, features, addresses, .. } = client.next().await else { panic!() };
        assert_eq!((width, height, features, addresses), (0, 0, None, Vec::new()));
        assert!(client.silent().await);

        // A session hello that asks for Reach gets it.
        let ext = HelloExt { clipboard: true, reach: true, ..Default::default() };
        let mut client = host.connect(&new, Some(ext)).await;
        assert!(matches!(client.next().await, HostMsg::Welcome { width: 0, height: 0, features: Some(0), .. }));
        let HostMsg::Reach { relays_for_others, .. } = client.next().await else { panic!("Reach") };
        assert!(relays_for_others, "a relay-only host relays");
        assert!(host.shared.active.lock().unwrap().is_none(), "no session was started and nobody was sent away");
        assert!(host.shared.input.is_none(), "and nothing listens for input");

        // Devices that are not paired are refused, here as anywhere.
        let stranger = Identity::generate().unwrap();
        let mut client = host.connect(&stranger, None).await;
        assert!(matches!(client.next().await, HostMsg::Rejected { .. }));
    }

    // A host behind a NAT registers with a relay under its *host* identity, which is not in the
    // relay's list of client devices. The relay lets in a link from a host its own user paired with:
    // one in `known_hosts.json` of the client side of the relay's computer, beside the host's state.

    /// The client side of the host's computer has paired with `device`'s host.
    fn pair_back(host: &TestHost, device: &Identity) {
        let client_dir = host.dir.join("client");
        std::fs::create_dir_all(&client_dir).unwrap();
        let paired = [KnownHost {
            name: "home PC".into(),
            address: "198.51.100.8:7420".into(),
            fingerprint: device.fingerprint().to_base64(),
            ..Default::default()
        }];
        std::fs::write(client_dir.join(StateDir::KNOWN_HOSTS), serde_json::to_vec(&paired).unwrap()).unwrap();
    }

    #[tokio::test]
    async fn a_link_is_refused_to_a_device_nobody_paired_exactly_as_before() {
        let host = host("trust-stranger", true).await;
        let (computer, stranger) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        pair_back(&host, &computer);
        let mut client = host.connect(&stranger, Some(link_hello())).await;
        let HostMsg::Rejected { reason } = client.next().await else { panic!("refused") };
        assert_eq!(reason, "this device is not paired with the host");
        assert!(host.shared.links.lock().unwrap().is_empty());
        // And with no list at all, which is how most computers are.
        let host = self::host("trust-none", true).await;
        let mut client = host.connect(&stranger, Some(link_hello())).await;
        assert!(matches!(client.next().await, HostMsg::Rejected { .. }));
    }

    #[tokio::test]
    async fn a_host_this_computers_user_paired_with_gets_a_link_and_can_register() {
        let host = host("trust-link", true).await;
        let (computer, client) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        pair_back(&host, &computer);
        host.pair(&client, "phone");
        // An access password protects the screen, and a link reaches none: it does not stand in the way
        // of the host's link.
        crate::password::set(&host.shared.state, Some("a password")).unwrap();

        let mut link = host.connect(&computer, Some(link_hello())).await;
        let HostMsg::Welcome { width, height, features, .. } = link.next().await else { panic!("a welcome") };
        assert_eq!((width, height, features), (0, 0, Some(0)), "a link: no screen and no files");
        let HostMsg::Reach { relays_for_others, .. } = link.next().await else { panic!("Reach") };
        assert!(relays_for_others, "the host relays for others");
        link.send(ClientMsg::RelayRegister { mac: None }).await;
        assert_eq!(link.next().await, HostMsg::RelayStatus { ok: true, reason: String::new() });
        until(|| host.shared.links.lock().unwrap().len() == 1).await;

        // A link and nothing more: no session, nobody sent away, no file stream; and the host is not
        // a paired device now, so no other hello of it is let in because of this one.
        assert!(host.shared.active.lock().unwrap().is_none());
        assert!(host.shared.files.lock().unwrap().is_empty());
        let paired: Vec<AuthorizedClient> = host.shared.state.load(StateDir::AUTHORIZED_CLIENTS).unwrap();
        assert!(paired.iter().all(|c| c.fingerprint != computer.fingerprint().to_base64()));
    }

    #[tokio::test]
    async fn a_link_of_a_paired_device_needs_no_password_but_a_session_and_files_do() {
        let host = host("password-links", false).await;
        let (client, stranger) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        host.pair(&client, "phone");
        crate::password::set(&host.shared.state, Some("a password")).unwrap();

        // A link reaches no screen, and the client that dials a relay has no password of this
        // computer to send: it gets in.
        let mut link = host.connect(&client, Some(link_hello())).await;
        assert!(matches!(link.next().await, HostMsg::Welcome { width: 0, height: 0, features: Some(0), .. }));
        assert!(matches!(link.next().await, HostMsg::Reach { .. }));

        // Its other hellos still ask for the password: a session (before and after extensions) and a
        // file manager.
        let session = HelloExt { clipboard: true, reach: true, ..Default::default() };
        let files = HelloExt { files_only: true, addresses: true, ..Default::default() };
        for ext in [None, Some(session), Some(files)] {
            let mut asked = host.connect(&client, ext).await;
            assert!(matches!(asked.next().await, HostMsg::PasswordRequired { wrong: false }), "hello: {ext:?}");
        }
        assert!(host.shared.active.lock().unwrap().is_none());

        // A device nobody knows is refused as before, and learns nothing about the password.
        let mut unknown = host.connect(&stranger, Some(link_hello())).await;
        let HostMsg::Rejected { reason } = unknown.next().await else { panic!("refused") };
        assert_eq!(reason, "this device is not paired with the host");
    }

    #[tokio::test]
    async fn the_same_host_is_still_refused_a_session_files_and_a_pairing() {
        for relay_only in [false, true] {
            let host = host("trust-session", relay_only).await;
            let computer = Identity::generate().unwrap();
            pair_back(&host, &computer);
            // The hellos that are not a link's: a session (before and after extensions) and a file manager.
            let session = HelloExt { clipboard: true, reach: true, ..Default::default() };
            let files = HelloExt { files_only: true, addresses: true, ..Default::default() };
            for ext in [None, Some(session), Some(files)] {
                let mut client = host.connect(&computer, ext).await;
                let HostMsg::Rejected { reason } = client.next().await else {
                    panic!("refused (relay only: {relay_only}, hello: {ext:?})")
                };
                assert_eq!(reason, "this device is not paired with the host");
            }
            assert!(host.shared.active.lock().unwrap().is_none());
            assert!(host.shared.files.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn a_paired_client_gets_in_as_before_whether_or_not_it_is_a_known_host_too() {
        let host = host("trust-client", false).await;
        let (client, both) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        host.pair(&client, "phone");
        host.pair(&both, "laptop");
        pair_back(&host, &both);
        for identity in [&client, &both] {
            // A link, as for any paired device.
            let mut link = host.connect(identity, Some(link_hello())).await;
            assert!(matches!(link.next().await, HostMsg::Welcome { width: 0, height: 0, features: Some(0), .. }));
            assert!(matches!(link.next().await, HostMsg::Reach { .. }));
            // A file manager, which serves files: the rights of a paired client are its own.
            let files = HelloExt { files_only: true, addresses: true, ..Default::default() };
            let mut manager = host.connect(identity, Some(files)).await;
            let HostMsg::Welcome { features, .. } = manager.next().await else { panic!("a welcome") };
            assert_eq!(features, Some(FEATURE_FILES));
        }
    }

    #[tokio::test]
    async fn messages_on_a_link_go_to_the_reach_hooks() {
        let host = host("link", false).await;
        let identity = Identity::generate().unwrap();
        host.pair(&identity, "phone");
        let mut client = host.connect(&identity, Some(link_hello())).await;
        client.next().await;
        client.next().await;

        client.send(ClientMsg::Reached { address: "192.168.1.20:7420".into() }).await;
        until(|| host.reach().read().last_reached.is_some()).await;
        assert_eq!(host.reach().read().last_reached, Some((AddressKind::Lan, "192.168.1.20:7420".to_string())));

        // The host does not relay for others: told so.
        client.send(ClientMsg::RelayTo { fingerprint: "someone".into() }).await;
        let HostMsg::RelayStatus { ok, reason } = client.next().await else { panic!("a status") };
        assert!(!ok);
        assert_eq!(reason, "this computer does not relay for other devices");

        // With the switch on the request reaches the relay hook (a stub that says it cannot yet).
        host.reach().update(|state| state.switches.relay_for_others = true);
        client.send(ClientMsg::RelayTo { fingerprint: "someone".into() }).await;
        let HostMsg::RelayStatus { ok, reason } = client.next().await else { panic!("a status") };
        assert!(!ok && reason != "this computer does not relay for other devices", "{reason}");

        // A message that is not for a link is ignored, and the link goes on.
        client.send(ClientMsg::RequestKeyframe).await;
        client.send(ClientMsg::Reached { address: "100.101.102.103:7420".into() }).await;
        until(|| host.reach().read().last_reached.as_ref().is_some_and(|(kind, _)| *kind == AddressKind::Vpn)).await;
        // A second hello is an error that ends the connection.
        client
            .send(ClientMsg::Hello {
                version: 1,
                name: "again".into(),
                pairing_secret: None,
                password: None,
                ext: None,
            })
            .await;
        tokio::time::timeout(Duration::from_secs(5), client.conn.closed()).await.expect("the host ends it");
    }

    #[tokio::test]
    async fn links_count_as_connected_clients_but_not_as_a_busy_host() {
        let host = host("busy", false).await;
        let identity = Identity::generate().unwrap();
        host.pair(&identity, "phone");
        assert_eq!(host.reach().read().clients.connected, 0);
        let mut client = host.connect(&identity, Some(link_hello())).await;
        client.next().await;
        until(|| host.reach().read().clients.connected == 1).await;
        until(|| host.shared.links.lock().unwrap().len() == 1).await;
        assert!(host.shared.active.lock().unwrap().is_none());
        assert!(host.shared.files.lock().unwrap().is_empty(), "an update need not wait for a link");
        client.conn.close(0u32.into(), b"done");
        until(|| host.reach().read().clients.connected == 0).await;
        until(|| host.shared.links.lock().unwrap().is_empty()).await;
        assert!(host.reach().read().clients.last_disconnect.is_some());
    }

    #[tokio::test]
    async fn removing_a_device_ends_its_links_and_tells_reach() {
        let host = host("revoke", false).await;
        let identity = Identity::generate().unwrap();
        host.pair(&identity, "phone");
        let mut client = host.connect(&identity, Some(link_hello())).await;
        client.next().await;
        until(|| host.shared.links.lock().unwrap().len() == 1).await;

        let fingerprint = identity.fingerprint();
        host.shared.control(Request::Revoke { fingerprint: fingerprint.to_base64() }, true).unwrap();
        tokio::time::timeout(Duration::from_secs(5), client.conn.closed()).await.expect("the link is closed");
        let calls = host.shared.reach.context().ext::<reach::testing::Calls>();
        assert_eq!(*calls.revoked.lock().unwrap(), vec![fingerprint]);
    }

    #[tokio::test]
    async fn new_addresses_prove_themselves_only_while_the_host_means_to_be_reached_from_outside() {
        let host = host("retry", false).await;
        let identity = Identity::generate().unwrap();
        host.pair(&identity, "phone");
        let retries = || host.shared.retries.load(Ordering::Relaxed);
        let set = |standalone, relay_for_others| {
            host.shared.control(Request::SetReach { standalone, relay_for_others, dht: false }, true).unwrap();
        };
        // Links stand in for sessions, which need a screen. A new client socket is a new address.
        let connect = || async {
            let mut client = host.connect(&identity, Some(link_hello())).await;
            assert!(matches!(client.next().await, HostMsg::Welcome { .. }));
            client
        };

        let _first = connect().await;
        assert_eq!(retries(), 0, "everything is off: the host behaves as it always has");
        set(true, false);
        let _second = connect().await;
        assert_eq!(retries(), 1, "asked to prove itself, and then connected");
        set(false, false);
        let _third = connect().await;
        assert_eq!(retries(), 1);
        set(false, true);
        let _fourth = connect().await;
        assert_eq!(retries(), 2, "a host that relays for others is reached from outside too");
    }

    #[tokio::test]
    async fn a_relay_only_host_asks_for_proof_with_every_switch_off() {
        let host = host("retry-relay", true).await;
        let identity = Identity::generate().unwrap();
        host.pair(&identity, "phone");
        let mut client = host.connect(&identity, None).await;
        assert!(matches!(client.next().await, HostMsg::Welcome { .. }));
        assert_eq!(host.shared.retries.load(Ordering::Relaxed), 1, "it faces the internet by definition");
    }

    /// A real session, which needs a screen to capture: run it by hand with `--ignored` on a
    /// machine with a desktop. It goes over IPv4 and IPv6 to the one dual-stack socket.
    #[tokio::test]
    #[ignore = "needs a screen to capture"]
    async fn a_session_gets_the_welcome_then_reach_then_video_over_both_ip_families() {
        let host = host_on("session", "[::]:0".parse().unwrap(), false, false).await;
        let port = host.endpoint.local_addr().unwrap().port();
        let identity = Identity::generate().unwrap();
        host.pair(&identity, "viewer");
        for to in [
            SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port)),
            SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port)),
        ] {
            let ext = HelloExt { addresses: true, reach: true, ..Default::default() };
            let mut client = host.connect_to(to, &identity, Some(ext)).await;
            let HostMsg::Welcome { width, height, features, .. } = client.next().await else { panic!("a welcome") };
            assert!(width > 0 && height > 0, "{width}x{height}");
            assert!(features.is_some_and(|f| f & FEATURE_FILES != 0));
            assert!(matches!(client.next().await, HostMsg::Reach { .. }), "Reach follows the welcome of a session too");
            // The picture follows: a frame on a stream of its own.
            let mut frame =
                tokio::time::timeout(Duration::from_secs(10), client.conn.accept_uni()).await.unwrap().unwrap();
            let mut header = [0u8; wire::FrameHeader::LEN];
            frame.read_exact(&mut header).await.unwrap();
            assert!(wire::FrameHeader::decode(&header).width > 0);
            client.send(ClientMsg::Reached { address: to.to_string() }).await;
            until(|| host.reach().read().last_reached.is_some()).await;
            client.conn.close(0u32.into(), b"done");
            until(|| host.shared.active.lock().unwrap().is_none()).await;
            host.reach().update(|state| state.last_reached = None);
        }

        // A session that did not set the bit gets the welcome and no Reach.
        let to = SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port));
        let mut client = host.connect_to(to, &identity, Some(HelloExt { addresses: true, ..Default::default() })).await;
        assert!(matches!(client.next().await, HostMsg::Welcome { .. }));
        assert!(client.silent().await, "no Reach for a client that did not ask");
    }

    /// Stands in for the relay between a client and a tunnel of the host: what arrives on the
    /// returned address goes into the tunnel, what the tunnel sends goes back to the client.
    async fn relay_for(host: &TestHost, relay: [u8; 32]) -> (SocketAddr, SocketAddr, tokio::task::JoinHandle<()>) {
        let mut tunnel = host.shared.reach.context().socket.open_tunnel(relay, std::num::NonZeroU16::MIN).unwrap();
        let peer = tunnel.addr();
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let pump = tokio::spawn(async move {
            let inbound = tunnel.inbound();
            let (mut client, mut buf) = (None, vec![0u8; 2048]);
            loop {
                tokio::select! {
                    received = socket.recv_from(&mut buf) => {
                        let Ok((n, from)) = received else { break };
                        client = Some(from);
                        let _ = inbound.deliver(bytes::Bytes::copy_from_slice(&buf[..n]));
                    }
                    packet = tunnel.next_outbound() => {
                        let (Some(packet), Some(client)) = (packet, client) else { continue };
                        let _ = socket.send_to(&packet, client).await;
                    }
                }
            }
        });
        (address, peer, pump)
    }

    #[tokio::test]
    async fn a_device_that_comes_through_a_relay_is_a_link_like_any_other_and_is_known_to_have_come_through_it() {
        let host = host("relayed", true).await;
        let identity = Identity::generate().unwrap();
        host.pair(&identity, "laptop");
        // A host reached from outside makes every ordinary address prove itself: this one need not.
        host.shared.control(Request::SetReach { standalone: true, relay_for_others: true, dht: false }, true).unwrap();
        let (relay_address, tunnel_peer, _pump) = relay_for(&host, [3; 32]).await;

        let mut client = host.connect_to(relay_address, &identity, Some(link_hello())).await;
        assert!(matches!(client.next().await, HostMsg::Welcome { .. }));
        assert!(matches!(client.next().await, HostMsg::Reach { .. }));
        assert_eq!(
            host.shared.retries.load(Ordering::Relaxed),
            0,
            "a relayed connection is not asked to prove its address"
        );

        client.send(ClientMsg::Reached { address: "198.51.100.77:7420".into() }).await;
        until(|| host.reach().read().last_reached.is_some()).await;
        let relay_kind = AddressKind::Relay(Fingerprint([3; 32]).to_base64());
        assert_eq!(host.reach().read().last_reached, Some((relay_kind, "198.51.100.77:7420".to_string())));
        assert!(reach::socket::is_tunnel_addr(tunnel_peer));
        assert!(host.shared.reach.context().socket.stats().tunnel_in > 0);
    }

    #[tokio::test]
    async fn a_connection_through_a_relay_tunnel_keeps_its_packets_to_one_relay_datagram() {
        let host = host("tunnel-mtu", true).await;
        let identity = Identity::generate().unwrap();
        host.pair(&identity, "laptop");
        let (relay_address, _peer, _pump) = relay_for(&host, [4; 32]).await;
        let mut direct = host.connect(&identity, Some(link_hello())).await;
        assert!(matches!(direct.next().await, HostMsg::Welcome { .. }));
        let mut relayed = host.connect_to(relay_address, &identity, Some(link_hello())).await;
        assert!(matches!(relayed.next().await, HostMsg::Welcome { .. }));

        // The host finds out by itself, after the handshake, how big its packets can be. An ordinary
        // connection goes on to quinn's own limit; the one through a tunnel stops where the datagrams
        // of the relay hold its packets.
        let mtu = |through_tunnel: bool| {
            let links = host.shared.links.lock().unwrap();
            let link = links
                .iter()
                .find(|link| reach::socket::is_tunnel_addr(link.conn.remote_address()) == through_tunnel)?;
            Some(link.conn.stats().path.current_mtu)
        };
        // Wait until neither has moved for half a second, so that what is measured is where each ended.
        let (mut last, mut steady) = ((0, 0), 0);
        for _ in 0..500 {
            let now = (mtu(false).unwrap_or(0), mtu(true).unwrap_or(0));
            steady = if now == last { steady + 1 } else { 0 };
            last = now;
            if steady >= 25 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let (direct_mtu, relayed_mtu) = last;
        assert!(direct_mtu > TUNNEL_MTU, "an ordinary connection grows past it: {direct_mtu}");
        assert!(relayed_mtu > 1200 && relayed_mtu <= TUNNEL_MTU, "and one through a tunnel stops there: {relayed_mtu}");
    }

    #[test]
    fn retry_is_for_unvalidated_addresses_of_a_host_reached_from_outside() {
        let direct: SocketAddr = "203.0.113.5:40000".parse().unwrap();
        let relayed = reach::socket::tunnel_addr(&[1; 32], std::num::NonZeroU16::MIN);
        assert!(wants_retry(true, false, true, direct));
        assert!(!wants_retry(false, false, true, direct), "not exposed: the host behaves as it always has");
        assert!(!wants_retry(true, true, true, direct), "already validated");
        assert!(!wants_retry(true, false, false, direct), "quinn cannot retry this one");
        assert!(!wants_retry(true, false, true, relayed), "the relay's own connection is authenticated");
    }

    #[test]
    fn peers_are_logged_in_their_plain_form() {
        assert_eq!(peer_addr("[::ffff:192.168.1.9]:51000".parse().unwrap()), "192.168.1.9:51000".parse().unwrap());
        assert_eq!(peer_addr("[2001:db8::1]:7420".parse().unwrap()), "[2001:db8::1]:7420".parse().unwrap());
    }

    #[tokio::test]
    async fn set_reach_is_saved_applied_and_shown() {
        let host = host("set-reach", true).await;
        let status = host.shared.control(Request::Status, false).unwrap();
        assert_eq!(
            status.reach,
            Some(ReachStatus { relay_for_others: true, ..Default::default() }),
            "relay-only relays"
        );

        let status = host
            .shared
            .control(Request::SetReach { standalone: true, relay_for_others: false, dht: true }, true)
            .unwrap();
        let shown = status.reach.unwrap();
        assert_eq!((shown.standalone, shown.dht), (true, true));
        assert!(shown.relay_for_others, "--relay-only is not a switch to turn off");
        // Saved, so the next start has them.
        let saved = Switches::load(&host.shared.state);
        assert_eq!(saved, Switches { standalone: true, relay_for_others: false, dht: true });
        assert_eq!(host.reach().read().switches, saved);
    }

    #[tokio::test]
    async fn the_status_lists_what_reach_found() {
        let host = host("status", false).await;
        host.reach().update(|state| {
            state.set_addresses(AddressKind::Public, vec!["198.51.100.4:51820".into()]);
            state.set_addresses(AddressKind::V6, vec!["[2001:db8::1]:7420".into()]);
        });
        let status = host.shared.control(Request::Status, false).unwrap();
        let reach = status.reach.unwrap();
        assert_eq!(reach.public, ["198.51.100.4:51820"]);
        assert_eq!(reach.v6, ["[2001:db8::1]:7420"]);
        let local = host.endpoint.local_addr().unwrap().to_string();
        assert_eq!(status.address, Some(local), "the address the host has always shown");
    }

    #[tokio::test]
    async fn only_an_administrator_changes_the_switches_of_a_service() {
        let host = host_as("service", true, true).await;
        let set = Request::SetReach { standalone: true, relay_for_others: true, dht: true };
        let error = host.shared.control(set.clone(), false).unwrap_err();
        assert!(error.contains("administrator"), "{error}");
        assert_eq!(host.reach().read().switches, Switches::default());
        host.shared.control(Request::Status, false).unwrap();
        host.shared.control(set, true).unwrap();
        assert!(host.reach().read().switches.dht);
    }

    #[tokio::test]
    async fn the_pairing_link_carries_the_dht_key_and_device_secret_only_when_there_is_a_key() {
        let host = host("link-keys", false).await;
        let without = host.shared.start_pairing().unwrap();
        assert!(!without.uri().contains("key=") && !without.uri().contains("secret="));
        let parsed = parse_pairing_link(&without.uri()).unwrap();
        assert_eq!((parsed.key, parsed.secret), (None, None));

        host.reach().update(|state| {
            state.dht_key = Some([0xAB; REACH_KEY_LEN]);
            state.set_addresses(AddressKind::Public, vec!["198.51.100.4:51820".into()]);
        });
        let with = host.shared.start_pairing().unwrap();
        let uri = with.uri();
        assert!(uri.starts_with(URI_PREFIX) && uri.len() <= MAX_LINK_LEN, "{} characters", uri.len());
        let link = parse_pairing_link(&uri).unwrap();
        assert_eq!(link.key, Some([0xAB; REACH_KEY_LEN]));
        assert!(link.secret.is_some() && link.secret == with.secret);
        assert!(link.also.contains(&"198.51.100.4:51820".to_string()), "the public address is in the link");

        // The link in the status is the same one.
        let status = host.shared.control(Request::Status, false).unwrap();
        assert_eq!(status.pairing.unwrap().uri, uri);
    }

    #[tokio::test]
    async fn pairing_hands_the_device_secret_to_reach() {
        let host = host("on-paired", false).await;
        host.reach().update(|state| state.dht_key = Some([1; REACH_KEY_LEN]));
        let pairing = host.shared.start_pairing().unwrap();
        let device = Identity::generate().unwrap().fingerprint();

        let auth = authorize(&host.shared, device, "new phone", Some(pairing.code.secret), None, false).unwrap();
        assert!(matches!(auth, Auth::Paired));
        let paired: Vec<AuthorizedClient> = host.shared.state.load(StateDir::AUTHORIZED_CLIENTS).unwrap();
        assert_eq!(paired.len(), 1);
        let calls = host.shared.reach.context().ext::<reach::testing::Calls>();
        assert_eq!(*calls.paired.lock().unwrap(), vec![(device, pairing.secret)], "the secret the link carried");
        assert!(host.shared.pairing.lock().unwrap().is_none(), "the code works once");

        // A link made while the host had no key carries no secret: reach makes one when it needs it.
        host.reach().update(|state| state.dht_key = None);
        let pairing = host.shared.start_pairing().unwrap();
        let other = Identity::generate().unwrap().fingerprint();
        authorize(&host.shared, other, "tablet", Some(pairing.code.secret), None, false).unwrap();
        assert_eq!(calls.paired.lock().unwrap()[1], (other, None));
    }

    #[test]
    fn the_link_keeps_what_a_first_connection_needs() {
        let lan = "192.168.1.9:7420";
        let vpn: Vec<String> =
            vec!["100.101.102.103:7420".into(), "[fd7a:115c:a1e0:ab12:4843:cd96:6265:2a31]:7420".into()];
        let public: Vec<String> = vec!["198.51.100.4:51820".into()];
        let (key, secret) = ([0xAB; REACH_KEY_LEN], [0xCD; DEVICE_SECRET_LEN]);
        let code = PairingCode { host: Fingerprint([0; 32]), secret: [0; wire::PAIRING_SECRET_LEN] };
        let length = |also: &[String], with_keys: bool| {
            let keys = with_keys.then_some((&key, &secret));
            pairing_uri_with(lan, also, &code, keys.map(|k| k.0), keys.map(|k| k.1)).len()
        };

        // Without the key the link is what it has always been, with the public address added.
        let also = link_addresses(lan, &vpn, &public, None, None);
        assert_eq!(also, [vpn[0].clone(), vpn[1].clone(), public[0].clone()]);

        // With it, LAN + VPN + public fit; the IPv6 mesh address does not, and goes first.
        let also = link_addresses(lan, &vpn, &public, Some(&key), Some(&secret));
        assert!(length(&also, true) <= MAX_LINK_LEN);
        assert_eq!(also, [vpn[0].clone(), public[0].clone()]);

        // Eight IPv4 addresses do not fit either: the public one is kept, then VPN ones in order.
        let many: Vec<String> = (1..=8).map(|n| format!("100.64.0.{n}:7420")).collect();
        let also = link_addresses(lan, &many, &public, Some(&key), Some(&secret));
        assert!(length(&also, true) <= MAX_LINK_LEN);
        assert!(also.contains(&public[0]) && also.starts_with(&many[..2]), "{also:?}");
        assert!(also.len() < 9);
    }
}
