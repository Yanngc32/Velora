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
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, ensure, Context, Result};
use tokio::sync::{mpsc, oneshot};
use velora_protocol::{
    control::{self, Reply, Request},
    files as wire_files,
    identity::{AuthorizedClient, StateDir},
    pairing::{pairing_uri, parse_pairing_uri, PairingCode},
    tls::{self, Fingerprint},
    wire::{
        self, ClientMsg, Codec, FrameHeader, HostMsg, MouseMove, FEATURE_CLIPBOARD, FEATURE_FILES, PROTOCOL_VERSION,
    },
};

use crate::{
    capture::{self, DisplayRect},
    encode::{self, EncoderChoice, EncoderSettings},
    input::{InputCmd, InputHandle},
    password::Check,
    rate::{self, RateControl},
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
}

#[derive(Clone)]
pub struct PendingPairing {
    pub code: PairingCode,
    /// Address advertised in the pairing link.
    pub address: String,
    expires: Instant,
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

pub struct Shared {
    options: HostOptions,
    state: StateDir,
    fingerprint: Fingerprint,
    input: InputHandle,
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
    shutdown: tokio::sync::Notify,
}

/// Runs until the endpoint fails or the launcher stops the host, or until an update was
/// installed and the host is idle; then returns `true` so the caller restarts into the new
/// version. With `pair`, a pairing window opens right away and is printed.
pub async fn run(options: HostOptions, state: StateDir, pair: bool, auto_update: bool) -> Result<bool> {
    let identity = state.load_or_create_identity()?;
    let endpoint = quinn::Endpoint::server(tls::server_config(&identity)?, options.bind)
        .with_context(|| format!("binding {}", options.bind))?;
    tracing::info!(
        "host '{}' {} listening on {} (fingerprint {})",
        options.name,
        velora_update::Version::current(),
        endpoint.local_addr()?,
        identity.fingerprint()
    );

    let shared = Arc::new(Shared {
        options,
        state,
        password: crate::password::Gate::default(),
        fingerprint: identity.fingerprint(),
        input: crate::input::spawn(),
        pairing: Mutex::new(None),
        offers: Mutex::new(Vec::new()),
        requests: Mutex::new(Vec::new()),
        next_request: AtomicU64::new(1),
        clients: Mutex::new(()),
        active: Mutex::new(None),
        files: Mutex::new(Vec::new()),
        shutdown: tokio::sync::Notify::new(),
    });
    if pair {
        let pairing = shared.start_pairing()?;
        crate::print_pairing(&pairing.code, &pairing.address);
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

    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { return Ok(false) };
                let shared = shared.clone();
                tokio::spawn(async move {
                    let remote = incoming.remote_address();
                    if let Err(e) = handle_connection(incoming, shared).await {
                        tracing::info!("connection from {remote} ended: {e:#}");
                    }
                });
            }
            () = &mut updated => {
                // Release the UDP port before the new version binds it.
                endpoint.close(0u32.into(), b"host is updating");
                endpoint.wait_idle().await;
                return Ok(true);
            }
            () = shared.shutdown.notified() => {
                tracing::info!("stopping at the launcher's request");
                endpoint.close(0u32.into(), b"host stopped");
                endpoint.wait_idle().await;
                return Ok(false);
            }
        }
    }
}

/// Periodically installs new releases; resolves once one is installed and nobody is using
/// the host (no session or file connection, no open pairing window).
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
        let busy = shared.active.lock().unwrap().is_some() || !shared.files.lock().unwrap().is_empty();
        if !busy && !pairing_open {
            return;
        }
        tokio::time::sleep(UPDATE_IDLE_POLL).await;
    }
}

async fn handle_connection(incoming: quinn::Incoming, shared: Arc<Shared>) -> Result<()> {
    let conn = tokio::time::timeout(HANDSHAKE_TIMEOUT, incoming).await.context("handshake timeout")??;
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

    let auth = {
        let shared = shared.clone();
        let name = name.clone();
        // Checking a password is deliberately slow (key stretching): off the async workers.
        tokio::task::spawn_blocking(move || authorize(&shared, fingerprint, &name, pairing_secret, password.as_deref()))
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
    // Only clients that know about extensions understand the features field. Sessions share
    // the clipboard; a connection for files alone does not.
    let features = ext.map(|e| FEATURE_FILES | if e.files_only { 0 } else { FEATURE_CLIPBOARD });
    if ext.is_some_and(|e| e.files_only) {
        tracing::info!("client '{name}' ({fingerprint}) connected for files from {}", conn.remote_address());
        return serve_files_only(conn, send, fingerprint, &name, &shared, features).await;
    }
    tracing::info!("client '{name}' ({fingerprint}) connected from {}", conn.remote_address());

    // A newly connected device takes over: switching from the phone to a PC should just work.
    let active = Active { conn: conn.clone(), fingerprint, files: ext.is_some() };
    if let Some(old) = shared.active.lock().unwrap().replace(active) {
        old.conn.close(1u32.into(), b"another device took over");
    }

    let clipboard = ext.is_some_and(|e| e.clipboard).then(|| share_clipboard(&conn)).flatten();
    let peer = Peer { shared: shared.clone(), name: name.clone(), fingerprint, clipboard };
    let result = run_session(&conn, send, recv, &shared, features, peer).await;

    shared.input.send(InputCmd::ReleaseAll);
    let mut active = shared.active.lock().unwrap();
    if active.as_ref().is_some_and(|a| a.conn.stable_id() == conn.stable_id()) {
        *active = None;
    }
    result
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
) -> Result<()> {
    let welcome = HostMsg::Welcome {
        version: PROTOCOL_VERSION,
        host_name: shared.options.name.clone(),
        codec: Codec::H264,
        width: 0,
        height: 0,
        features,
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

    /// Opens a pairing window, replacing any open one.
    fn start_pairing(&self) -> Result<PendingPairing> {
        let pairing = PendingPairing {
            code: PairingCode::generate(self.fingerprint)?,
            address: advertised_address(self.options.bind),
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
        // a device's files is the user's call: it can reach their screen already.
        let harmless = matches!(
            request,
            Request::Status | Request::SendFiles { .. } | Request::DismissOffer { .. } | Request::AnswerFiles { .. }
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
        let _clients = self.clients.lock().unwrap();
        if revoke(&self.state, &fingerprint.to_base64())? == 0 {
            bail!("this device is not paired");
        }
        if let Some(active) = self.active.lock().unwrap().as_ref().filter(|a| a.fingerprint == fingerprint) {
            active.conn.close(2u32.into(), b"device removed on the host");
        }
        for files in self.files.lock().unwrap().iter().filter(|c| c.fingerprint == fingerprint) {
            files.conn.close(2u32.into(), b"device removed on the host");
        }
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
                uri: pairing_uri(&p.address, &p.code),
                code: p.code.encode(),
                address: p.address.clone(),
                expires_in_secs: left.as_secs(),
            })
        });
        let address = advertised_address(self.options.bind);
        Ok(control::Status {
            name: self.options.name.clone(),
            version: velora_update::Version::current().to_string(),
            fingerprint: self.fingerprint.short(),
            address: (!address.starts_with('<')).then_some(address),
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
fn authorize(
    shared: &Shared,
    fingerprint: Fingerprint,
    name: &str,
    secret: Option<[u8; wire::PAIRING_SECRET_LEN]>,
    password: Option<&str>,
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

    let _clients = shared.clients.lock().unwrap();
    let mut clients: Vec<AuthorizedClient> = shared.state.load(StateDir::AUTHORIZED_CLIENTS)?;
    let mut pairing = shared.pairing.lock().unwrap();
    // Another device may have used the code meanwhile.
    let valid = secret
        .is_some_and(|s| pairing.as_ref().is_some_and(|p| p.expires > Instant::now() && p.code.secret_matches(&s)));
    if !valid {
        return Ok(Auth::Denied);
    }
    // Single use.
    *pairing = None;
    clients.push(AuthorizedClient {
        name: name.to_string(),
        fingerprint: fp,
        added_unix: SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
        trust_files: false,
    });
    shared.state.save(StateDir::AUTHORIZED_CLIENTS, &clients)?;
    tracing::info!("paired new client '{name}' ({fingerprint})");
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
    conn: &quinn::Connection,
    mut control_send: quinn::SendStream,
    mut control_recv: quinn::RecvStream,
    shared: &Arc<Shared>,
    features: Option<u32>,
    peer: Peer,
) -> Result<()> {
    let client_name = peer.name.clone();
    let opts = &shared.options;
    let session = Arc::new(Session {
        running: AtomicBool::new(true),
        keyframe_requested: AtomicBool::new(true),
        bitrate_kbps: AtomicU32::new(opts.bitrate_kbps),
        window: Mutex::new(RateWindow::default()),
        in_flight: AtomicU32::new(0),
        max_in_flight: AtomicU32::new(MIN_IN_FLIGHT + 1),
        last_ack: Mutex::new(Instant::now()),
        stats: Mutex::new(Stats::default()),
    });

    let (frame_tx, mut frame_rx) = mpsc::channel::<OutFrame>(4);
    let (ready_tx, ready_rx) = oneshot::channel();
    {
        let session = session.clone();
        let input = shared.input.clone();
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
            }
            .encode(),
        )
        .await?;

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
                ClientMsg::Key { code, state } => shared.input.send(InputCmd::Key { code, state }),
                ClientMsg::MouseButton { button, down, x, y } => {
                    shared.input.send(InputCmd::Button { button, down, x, y })
                }
                ClientMsg::Scroll { dx, dy } => shared.input.send(InputCmd::Scroll { dx, dy }),
                ClientMsg::ReleaseAll => shared.input.send(InputCmd::ReleaseAll),
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
                ClientMsg::Text { text } => shared.input.send(InputCmd::Text(text)),
                ClientMsg::OfferPairing { link } => shared.offer(&client_name, link),
                ClientMsg::Unsupported { tag } => tracing::debug!("ignoring unsupported message {tag}"),
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
                shared.input.send(InputCmd::Move { x: m.x, y: m.y });
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
        r = crate::transfer::accept(conn.clone(), peer) => r,
        e = conn.closed() => Err(e.into()),
    };
    session.running.store(false, Ordering::Relaxed);
    result
}

fn capture_loop(
    session: &Session,
    choice: &EncoderChoice,
    settings: EncoderSettings,
    frames: mpsc::Sender<OutFrame>,
    ready: oneshot::Sender<Result<DisplayRect>>,
    input: &InputHandle,
) -> Result<()> {
    let setup = || -> Result<_> {
        let capturer = capture::open()?;
        let rect = capturer.rect();
        let encoder = encode::open(choice, settings, rect.width, rect.height)?;
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
                encoder = encode::open(choice, settings, rect.width, rect.height)?;
                session.keyframe_requested.store(true, Ordering::Relaxed);
            }
        }
        let keyframe = keyframe || session.keyframe_requested.load(Ordering::Relaxed);
        session.keyframe_requested.store(false, Ordering::Relaxed);
        let encode_start = Instant::now();
        let encoded = encoder.encode(frame.as_ref(), keyframe)?;
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
