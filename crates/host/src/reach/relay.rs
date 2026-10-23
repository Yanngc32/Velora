//! Relaying through a paired PC: serving relays for other devices, and registering this host with
//! one (ticket E4; the plumbing it plugs into is `reach/mod.rs`, which it does not edit).
//!
//! A host that cannot be reached directly (behind CGNAT, say) dials *out* to a PC that can, and
//! keeps the connection; a client that wants the host dials out to the same PC. Both connections
//! are *links*: a hello with `files_only` and `reach`, which the host answers with a welcome of no
//! screen, `Reach`, and then control messages only, so nothing is captured and no desktop session
//! is taken over (`docs/reach-handover/E1-host-plumbing.md`). The relay copies the datagrams of
//! one connection to the other (`velora_relay::forward`, ticket D2) and sees ciphertext only: the
//! two ends run the ordinary Velora handshake through it.
//!
//! ## Serving (the relay PC)
//!
//! [`serve`] runs while the host relays for others (the switch, or `--relay-only`). It owns the
//! forwarder (a `velora_relay::forward::Relay`, one per host, in [`ReachContext::ext`]) and keeps
//! what the forwarder remembers for waking sleeping hosts in `relay_known.json` of the state
//! directory, so a restart does not forget a host that was asleep. [`handle_message`] gives the
//! forwarder the four relay messages as they arrive and queues its `RelayStatus` answers;
//! [`on_revoked`] drops a removed device from it.
//!
//! ## Registering (the host behind the NAT)
//!
//! [`register_with`] runs while standalone reach is on. It wants a relay when the host advertises
//! no public address, or when the user listed relays by hand in `relays.json` of the state
//! directory (entries shaped like those of `known_hosts.json`; this also serves a host running as
//! the Windows service, whose state is not in the user's folder). The candidates are those entries
//! and the hosts of the client side of this computer (`known_hosts.json` beside the host's state
//! directory). For each, up to [`MAX_REGISTRATIONS`], a task dials the relay with the host's own
//! identity, checks in its `Reach` that it relays for others, sends `RelayRegister` with the MAC
//! address, and exposes the connection to the endpoint as a tunnel
//! ([`crate::reach::socket::Multiplexer::open_tunnel`]): what clients send through the relay
//! reaches the endpoint as an ordinary incoming connection, at the tunnel's address. The relay is
//! listed in [`crate::reach::ReachState::relays`] while it is registered; the task reconnects
//! with a growing delay when the connection is lost. Punch requests the relay passes on arrive
//! on unidirectional streams of the same connection and go to [`punch::respond`].
//!
//! ## Who may register
//!
//! The host registers under its *host* identity, because clients ask the relay for the host by
//! the fingerprint they pinned, and the forwarder keys its table by the connection's
//! certificate. The relay's `authorize` (`server.rs`) lets in the client identities of
//! `authorized_clients.json`, which a host's identity is not unless it was put there by hand; it
//! is meant to ask [`trusts`] too, for a link from a host the relay's own user paired with. See
//! `docs/reach-handover/E4-host-relay.md`.

use std::{
    collections::{hash_map::RandomState, BTreeMap, HashMap, HashSet},
    hash::BuildHasher,
    net::SocketAddr,
    num::NonZeroU16,
    path::Path,
    sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError},
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context as _, Result};
use serde::{Deserialize, Serialize};
use tokio::{
    sync::{mpsc, watch, Semaphore},
    task::{JoinHandle, JoinSet},
    time::{sleep, timeout, timeout_at},
};
use velora_nat::wake::{format_mac, parse_mac, Mac};
use velora_protocol::{
    identity::{AuthorizedClient, KnownHost, StateDir},
    tls::{self, Fingerprint},
    wire::{self, AddressKind, ClientMsg, HelloExt, HostMsg, MAX_NAME_LEN, PROTOCOL_VERSION},
};
use velora_relay::{
    forward::{Known, Relay, CLOSE_REMOVED, CLOSE_REPLACED, CLOSE_SHUTDOWN},
    frame::{Reassembler, Splitter},
};

use super::{
    punch,
    socket::{Tunnel, Undelivered},
    ClientConn, PunchRequest, ReachContext, RelayEntry,
};

/// What the forwarder remembers for waking hosts, in the host's state directory.
const KNOWN_FILE: &str = "relay_known.json";
/// Relays to register with whether or not the host has a public address, shaped like `known_hosts.json`.
const RELAYS_FILE: &str = "relays.json";
/// How often the serving task saves what the forwarder remembers and drops what is no longer allowed.
const SAVE_EVERY: Duration = Duration::from_secs(30);

/// Relays one host holds a registration with at once. Each costs a connection and its keepalive.
pub const MAX_REGISTRATIONS: usize = 4;
/// Relays one host keeps a supervisor for: the user's and the paired computers that may relay.
const MAX_CANDIDATES: usize = 16;
/// Addresses of one relay tried (and resolved).
const MAX_DIAL_ADDRESSES: usize = 8;
/// Addresses of a relay listed in `Reach`, for clients to dial it at.
const MAX_ADVERTISED: usize = 4;
/// How long after start the paired computers are left alone, so that a public address that is about
/// to appear (the router mapping) is not answered with relays that are dropped again.
const STARTUP_GRACE: Duration = Duration::from_secs(10);
/// How often the registering task reads its lists of relays again, and how often a supervisor of a
/// paired computer looks at whether the host needs a relay.
const RESCAN_EVERY: Duration = Duration::from_secs(30);
const RECHECK_EVERY: Duration = Duration::from_secs(5);
/// How long the supervisors get to end when the task is told to.
const SUPERVISORS_GRACE: Duration = Duration::from_millis(2500);

/// How long a connection attempt may take, how far apart the addresses of one relay are tried, and
/// how long a name may take to resolve.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const DIAL_STAGGER: Duration = Duration::from_millis(300);
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(4);
/// How long the relay may take to answer on the link, and how long to wait for `Reach` after its
/// welcome before concluding that it sends none (a host from before standalone reach).
const LINK_TIMEOUT: Duration = Duration::from_secs(8);
const REACH_WAIT: Duration = Duration::from_secs(3);
/// Messages of a relay waiting to be read.
const INBOX_QUEUE: usize = 16;

/// The wait before the first retry, the longest wait, and how long a registration must have lasted
/// for the wait to start over.
const BACKOFF_MIN: Duration = Duration::from_secs(5);
const BACKOFF_MAX: Duration = Duration::from_secs(300);
const STABLE_AFTER: Duration = Duration::from_secs(60);
/// How long to stay away from a relay: after another registration of this host replaced this one
/// (two copies of the host would otherwise replace each other for ever), after the relay removed the
/// host or stopped relaying, and when this host is registered with as many relays as it allows.
const REPLACED_WAIT: Duration = Duration::from_secs(90);
const REMOVED_WAIT: Duration = Duration::from_secs(600);
const SHUTDOWN_WAIT: Duration = Duration::from_secs(120);
const FULL_WAIT: Duration = Duration::from_secs(60);
/// How long to stay away from a relay that does not relay, does not know this host or asks for an
/// access password: a minute when the user listed it, ten when it is one of the paired computers
/// (most of which say no, and each try shows in their logs).
const REFUSED_WAIT: Duration = Duration::from_secs(60);
const NOT_A_RELAY_WAIT: Duration = Duration::from_secs(600);
/// The code a host closes the links of a device with when the user removes it (`server.rs`).
const CLOSE_DEVICE_REMOVED: u32 = 2;

/// Punch requests read at once, and how long one may take to arrive.
const MAX_PUNCH_STREAMS: usize = 8;
const PUNCH_READ_TIMEOUT: Duration = Duration::from_secs(5);
/// How often the pump gives up the pieces of packets whose other piece never came.
const SWEEP_EVERY: Duration = Duration::from_secs(1);
/// How often a host with a MAC address the relay has not accepted yet tries to tell it again, and
/// how long the end of the control stream waits for the connection to say why it ended.
const MAC_RETRY: Duration = Duration::from_secs(10);
const CLOSE_GRACE: Duration = Duration::from_secs(1);
/// Longest text from a peer that goes in a log line.
const MAX_LOGGED: usize = 200;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

// ---------------------------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------------------------

/// What the serving and the registering halves keep for the host, in [`ReachContext::ext`].
#[derive(Default)]
struct RelayState {
    /// The forwarder of the serving half.
    relay: Relay,
    /// Whether the state file was read into the forwarder. Held while it is read, so that whoever
    /// asks first reads it and the others wait for that: a save never writes over entries that were
    /// not loaded yet.
    loaded: Mutex<bool>,
    /// The computer's name for the hello, found once and off the async workers.
    name: OnceLock<String>,
    /// What the state file holds now, so that it is written only when something changed.
    saved: Mutex<Vec<KnownRecord>>,
    /// The relays this host is registered with now, by the relay's raw fingerprint.
    live: Mutex<BTreeMap<[u8; 32], RelayEntry>>,
}

/// One host the forwarder remembers, as the state file writes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct KnownRecord {
    /// The host's fingerprint (base64url).
    fingerprint: String,
    /// The MAC address it said, as `aa:bb:cc:dd:ee:ff`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mac: Option<String>,
    /// The address its connection came from the last time.
    addr: String,
}

impl KnownRecord {
    fn of(known: &Known) -> KnownRecord {
        KnownRecord {
            fingerprint: known.fingerprint.to_base64(),
            mac: known.mac.as_ref().map(format_mac),
            addr: known.addr.to_string(),
        }
    }

    /// `None` for a record that does not read: it is dropped, not a reason to lose the others.
    fn known(&self) -> Option<Known> {
        let mac = match &self.mac {
            Some(text) => Some(parse_mac(text).ok()?),
            None => None,
        };
        Some(Known {
            fingerprint: Fingerprint::from_base64(&self.fingerprint).ok()?,
            mac,
            addr: self.addr.parse().ok()?,
        })
    }
}

impl RelayState {
    /// Reads the state file into the forwarder, once. Blocking. Returns whether it has been read: a
    /// file that is missing or damaged reads as empty (the next save writes it afresh), but one that
    /// cannot be read at all is left for the next try, and nothing is saved until then, or the
    /// sleeping hosts it holds would be lost.
    fn load_known(&self, ctx: &ReachContext) -> bool {
        let mut loaded = lock(&self.loaded);
        if *loaded {
            return true;
        }
        let records: Vec<KnownRecord> = match std::fs::read(ctx.state_dir.path(KNOWN_FILE)) {
            Ok(data) => serde_json::from_slice(&data).unwrap_or_else(|e| {
                tracing::warn!("ignoring {KNOWN_FILE}: {e}");
                Vec::new()
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => {
                tracing::warn!("cannot read {KNOWN_FILE} yet: {e}");
                return false;
            }
        };
        let mut remembered = 0;
        for record in &records {
            match record.known() {
                Some(known) => {
                    self.relay.remember(known);
                    remembered += 1;
                }
                None => tracing::debug!("{KNOWN_FILE}: skipping an entry that does not read"),
            }
        }
        if remembered > 0 {
            tracing::info!("relay: remembering {remembered} host(s) to wake from {KNOWN_FILE}");
        }
        *lock(&self.saved) = records;
        *loaded = true;
        true
    }

    /// Writes what the forwarder remembers, if it differs from what the file holds. Blocking.
    fn save_known(&self, ctx: &ReachContext) {
        if !self.load_known(ctx) {
            return;
        }
        // The snapshot is taken under the lock, so that the later of two saves is the later state.
        let mut saved = lock(&self.saved);
        let mut records: Vec<KnownRecord> = self.relay.known().iter().map(KnownRecord::of).collect();
        records.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
        if *saved == records {
            return;
        }
        match ctx.state_dir.save(KNOWN_FILE, &records) {
            Ok(()) => *saved = records,
            Err(e) => tracing::warn!("could not save {KNOWN_FILE}: {e:#}"),
        }
    }
}

/// Shuts the forwarder down when dropped, so that the hosts and clients it holds are let go however
/// the serving task ends, an abort included.
struct ShutdownOnDrop(Arc<RelayState>);

impl Drop for ShutdownOnDrop {
    fn drop(&mut self) {
        self.0.relay.shutdown();
    }
}

/// Text a peer sent, fit for a log line: control characters removed, cut short.
fn clean(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).take(MAX_LOGGED).collect()
}

// ---------------------------------------------------------------------------------------------
// Serving
// ---------------------------------------------------------------------------------------------

/// The serving task. Started when the host relays for others (the switch, or `--relay-only`); it
/// ends when `ctx.stop` fires, and everything the relay holds is then disconnected (also when the
/// task is aborted instead).
///
/// It loads what the forwarder remembers for waking hosts, and every half minute drops devices
/// that are no longer allowed (removed from `authorized_clients.json`, which `velora-host revoke`
/// does without telling the running host) and saves what the forwarder remembers.
pub async fn serve(ctx: ReachContext) -> Result<()> {
    let state = ctx.ext::<RelayState>();
    let loading = (ctx.clone(), state.clone());
    let _ = tokio::task::spawn_blocking(move || loading.1.load_known(&loading.0)).await;
    let relaying = ShutdownOnDrop(state.clone());
    tracing::info!("this computer relays for the user's other devices");
    while !ctx.stop.sleep(SAVE_EVERY).await {
        let tick = (ctx.clone(), state.clone());
        let _ = tokio::task::spawn_blocking(move || {
            reconcile(&tick.0, &tick.1);
            tick.1.save_known(&tick.0);
        })
        .await;
    }
    // What the forwarder remembers of the hosts it lets go is saved after that.
    drop(relaying);
    let last = (ctx.clone(), state.clone());
    let _ = tokio::task::spawn_blocking(move || last.1.save_known(&last.0)).await;
    tracing::info!("this computer no longer relays");
    Ok(())
}

/// Drops from the forwarder the devices that are not allowed any more: hosts and clients that were
/// removed, and hosts it only remembers to wake. A list that cannot be read changes nothing.
fn reconcile(ctx: &ReachContext, state: &RelayState) {
    let Some(allowed) = allowed(ctx) else { return };
    for known in state.relay.known() {
        if !allowed.contains(&known.fingerprint.to_base64()) {
            state.relay.remove(&known.fingerprint);
        }
    }
    for host in state.relay.registered() {
        if !allowed.contains(&host.fingerprint.to_base64()) {
            tracing::info!("relay: {} is not paired any more; dropping it", host.fingerprint);
            state.relay.remove(&host.fingerprint);
        }
        if let Some(client) = host.client.filter(|client| !allowed.contains(&client.to_base64())) {
            tracing::info!("relay: {client} is not paired any more; dropping it");
            state.relay.remove(&client);
        }
    }
}

/// The fingerprints (base64url) of the devices this host relays for: those paired with it, and the
/// hosts its user paired with from here (see [`trusts`]). `None` when either list cannot be read.
fn allowed(ctx: &ReachContext) -> Option<HashSet<String>> {
    let clients: Vec<AuthorizedClient> = ctx.state_dir.load(StateDir::AUTHORIZED_CLIENTS).ok()?;
    let mut allowed: HashSet<String> = clients.into_iter().map(|client| client.fingerprint).collect();
    allowed.extend(client_side_hosts(ctx)?.into_iter().map(|host| host.fingerprint));
    Some(allowed)
}

/// A relay request arrived from a paired device (`RelayRegister`, `RelayTo`, `Wake` or
/// `PunchRequest`) and this host relays for others (otherwise `reach::handle_client_msg` already
/// answered no, and `RelayRegister` and `RelayTo` came from a session, which has no business
/// handing over its datagrams). The forwarder answers; the answer is queued on the control stream
/// the request came from.
///
/// `RelayRegister` and `RelayTo` are quick and answered here. `Wake` (the magic packet goes out on
/// the blocking pool) and `PunchRequest` (the relay opens a stream on the host's connection, which
/// may take two seconds) are answered from a task of their own, so that the device's control
/// stream is read meanwhile.
pub async fn handle_message(ctx: &ReachContext, from: &ClientConn, msg: ClientMsg) -> Result<()> {
    let state = ctx.ext::<RelayState>();
    let relay = state.relay.clone();
    match msg {
        ClientMsg::RelayRegister { .. } | ClientMsg::RelayTo { .. } => {
            let registering = matches!(msg, ClientMsg::RelayRegister { .. });
            let answer = relay.handle(&from.conn, &msg).await;
            let registered = matches!(answer, Some(HostMsg::RelayStatus { ok: true, .. }));
            if let Some(answer) = answer {
                from.control.try_send(answer)?;
            }
            if registering && registered {
                // A host that registers is a host to wake later: keep that across a restart.
                let saving = (ctx.clone(), state);
                drop(tokio::task::spawn_blocking(move || saving.1.save_known(&saving.0)));
            }
        }
        ClientMsg::Wake { .. } | ClientMsg::PunchRequest { .. } => {
            let (conn, control) = (from.conn.clone(), from.control.clone());
            tokio::spawn(async move {
                if let Some(answer) = relay.handle(&conn, &msg).await {
                    // A device that does not read its answers is not waited for: its tasks would pile up.
                    let _ = control.try_send(answer);
                }
            });
        }
        _ => {}
    }
    Ok(())
}

/// A paired device was removed in the launcher (called through `reach::on_revoked`, from a
/// blocking thread, with no lock held). Drops it from the forwarder (`Relay::remove`): its
/// registration and any flow it is part of end. The forwarder holds its own handle on a device's
/// connection, so the host closing the device's link is not enough. Removals made with
/// `velora-host revoke` while the host runs do not come here; the serving task finds them within
/// half a minute.
pub fn on_revoked(ctx: &ReachContext, fingerprint: &Fingerprint) {
    let state = ctx.ext::<RelayState>();
    // The file first: read later it would put the device back.
    state.load_known(ctx);
    state.relay.remove(fingerprint);
    state.save_known(ctx);
}

/// Whether relayed traffic is flowing through this host right now: a client is paired with a
/// registered host. The host does not install an update (which restarts it) while this is true;
/// links that are only registered do not count.
pub fn busy(ctx: &ReachContext) -> bool {
    ctx.ext::<RelayState>().relay.registered().iter().any(|host| host.client.is_some())
}

/// Whether the host `fingerprint` is one this computer's user paired with as a client (it is in
/// `known_hosts.json` of the client side, beside the host's state directory). Such a host may open
/// a *link* to this relay without being in `authorized_clients.json`: it registers under its host
/// identity, which only a pairing in this direction can have put there. A blocking file read.
///
/// The host's `authorize` is meant to ask this for a link hello (`files_only` and `reach`) from a
/// fingerprint it does not know, and to let it in as a link only: no session, and no access
/// password, since a link reaches no screen.
pub fn trusts(ctx: &ReachContext, fingerprint: &Fingerprint) -> bool {
    let wanted = fingerprint.to_base64();
    client_side_hosts(ctx).is_some_and(|hosts| hosts.iter().any(|host| host.fingerprint == wanted))
}

/// The hosts the client side of this computer is paired with: none if it has no list, `None` if it
/// has one that cannot be read (callers that act on what is missing from a list must not act then).
fn client_side_hosts(ctx: &ReachContext) -> Option<Vec<KnownHost>> {
    match ctx.client_state_dir() {
        Some(dir) => read_hosts(&dir.join(StateDir::KNOWN_HOSTS)),
        None => Some(Vec::new()),
    }
}

/// Reads a list of hosts: empty when there is no file, `None` when there is one that cannot be read.
fn read_hosts(path: &Path) -> Option<Vec<KnownHost>> {
    match std::fs::read(path) {
        Ok(data) => match serde_json::from_slice(&data) {
            Ok(hosts) => Some(hosts),
            Err(e) => {
                tracing::debug!("cannot read {}: {e}", path.display());
                None
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(Vec::new()),
        Err(e) => {
            tracing::debug!("cannot read {}: {e}", path.display());
            None
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Registering
// ---------------------------------------------------------------------------------------------

/// A relay to register with.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Candidate {
    fingerprint: Fingerprint,
    /// How the launcher shows it.
    name: String,
    /// `ip:port` (or `name:port`) to dial, in the order to try them.
    addresses: Vec<String>,
    /// The user listed it in `relays.json`: wanted even when the host can be reached directly.
    explicit: bool,
}

impl Candidate {
    /// `None` for an entry that cannot be dialed: a fingerprint that does not read, or no address.
    fn of(host: &KnownHost, explicit: bool) -> Option<Candidate> {
        let fingerprint = Fingerprint::from_base64(&host.fingerprint).ok()?;
        let mut addresses: Vec<String> = Vec::new();
        let mut add = |address: &str| {
            let address = address.trim();
            if !address.is_empty() && !addresses.iter().any(|known| known == address) {
                addresses.push(address.to_string());
            }
        };
        // The kinds are what the host last said about itself. A relay's own relays are no way to it.
        for (kind, address) in &host.kinds {
            if !matches!(kind, AddressKind::Relay(_)) {
                add(address);
            }
        }
        add(&host.address);
        for address in &host.also {
            add(address);
        }
        addresses.truncate(MAX_DIAL_ADDRESSES);
        if addresses.is_empty() {
            return None;
        }
        let name: String = host.name.chars().filter(|c| !c.is_control()).take(MAX_NAME_LEN).collect();
        let name = if name.trim().is_empty() { fingerprint.short() } else { name };
        Some(Candidate { fingerprint, name, addresses, explicit })
    }
}

/// The relays to register with out of the user's list and the paired computers of the client side:
/// the user's first, then the others in the order the client side keeps them; each relay once,
/// never this host itself, at most [`MAX_CANDIDATES`].
fn select(explicit: &[KnownHost], paired: &[KnownHost], own: &Fingerprint) -> Vec<Candidate> {
    let mut found: Vec<Candidate> = Vec::new();
    let listed = explicit.iter().map(|host| (host, true)).chain(paired.iter().map(|host| (host, false)));
    for (host, explicit) in listed {
        let Some(candidate) = Candidate::of(host, explicit) else { continue };
        if candidate.fingerprint == *own || found.iter().any(|known| known.fingerprint == candidate.fingerprint) {
            continue;
        }
        found.push(candidate);
        if found.len() == MAX_CANDIDATES {
            break;
        }
    }
    found
}

/// Reads the lists the candidates come from. Blocking. `None` when one of them cannot be read (a
/// file half written, say): the registrations that exist stay as they are until it can.
fn gather(ctx: &ReachContext) -> Option<Vec<Candidate>> {
    let explicit: Vec<KnownHost> = match ctx.state_dir.load(RELAYS_FILE) {
        Ok(list) => list,
        Err(e) => {
            tracing::debug!("cannot read {RELAYS_FILE}: {e:#}");
            return None;
        }
    };
    Some(select(&explicit, &client_side_hosts(ctx)?, &ctx.fingerprint))
}

/// Whether the paired computers are worth asking for a relay: the host advertises no public address
/// (a router mapping that works would be one) and has had a moment to get one.
fn needs_relay(ctx: &ReachContext, started: Instant) -> bool {
    started.elapsed() >= STARTUP_GRACE && ctx.reach.read().addresses_of(&AddressKind::Public).is_empty()
}

/// Aborts the task when dropped, so that the tasks a task started do not outlive it if it is aborted.
struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A supervisor the registering task has started, and the means to tell it things.
struct Running {
    cancel: watch::Sender<bool>,
    update: watch::Sender<Candidate>,
    handle: AbortOnDrop,
}

/// The registering task. Started while standalone reach is on (and the host is not `--relay-only`);
/// it ends when `ctx.stop` fires.
///
/// It looks at the relays it could use every half minute and keeps one supervisor task for each (at
/// most [`MAX_CANDIDATES`]); the supervisors dial, register and reconnect, and at most
/// [`MAX_REGISTRATIONS`] of them hold a registration at a time. A paired computer that does not relay
/// for others costs a short connection every ten minutes, no more.
pub async fn register_with(ctx: ReachContext) -> Result<()> {
    run_registration(ctx, Instant::now()).await
}

/// [`register_with`], told when the host started (the paired computers are left alone for a moment
/// after that).
async fn run_registration(ctx: ReachContext, started: Instant) -> Result<()> {
    let slots = Arc::new(Semaphore::new(MAX_REGISTRATIONS));
    let mut running: HashMap<Fingerprint, Running> = HashMap::new();
    let mut leaving: Vec<AbortOnDrop> = Vec::new();
    // The computer's name goes in the hello; finding it may read a file.
    let named = ctx.ext::<RelayState>();
    let _ = tokio::task::spawn_blocking(move || named.name.get_or_init(crate::hostname).len()).await;
    loop {
        let scanning = ctx.clone();
        match tokio::task::spawn_blocking(move || gather(&scanning)).await {
            Ok(Some(wanted)) => supervise_all(&ctx, &slots, started, &mut running, &mut leaving, wanted),
            Ok(None) => {}
            Err(e) => tracing::warn!("relay registration: could not read the lists of relays: {e}"),
        }
        if ctx.stop.sleep(RESCAN_EVERY).await {
            break;
        }
    }
    for supervisor in running.values() {
        let _ = supervisor.cancel.send(true);
    }
    // Those that do not end in time are aborted when their handles drop.
    let deadline = tokio::time::Instant::now() + SUPERVISORS_GRACE;
    for mut handle in running.into_values().map(|supervisor| supervisor.handle).chain(leaving) {
        let _ = timeout_at(deadline, &mut handle.0).await;
    }
    Ok(())
}

/// Starts a supervisor for every candidate that has none, tells the others about changes in their
/// addresses, and ends those whose relay is no longer listed.
fn supervise_all(
    ctx: &ReachContext,
    slots: &Arc<Semaphore>,
    started: Instant,
    running: &mut HashMap<Fingerprint, Running>,
    leaving: &mut Vec<AbortOnDrop>,
    wanted: Vec<Candidate>,
) {
    running.retain(|_, supervisor| !supervisor.handle.0.is_finished());
    leaving.retain(|handle| !handle.0.is_finished());
    let keep: HashSet<Fingerprint> = wanted.iter().map(|candidate| candidate.fingerprint).collect();
    let gone: Vec<Fingerprint> = running.keys().filter(|fingerprint| !keep.contains(fingerprint)).copied().collect();
    for fingerprint in gone {
        if let Some(supervisor) = running.remove(&fingerprint) {
            tracing::info!("relay {fingerprint} is not listed any more; leaving it");
            let _ = supervisor.cancel.send(true);
            leaving.push(supervisor.handle);
        }
    }
    for candidate in wanted {
        match running.get(&candidate.fingerprint) {
            Some(supervisor) => {
                supervisor.update.send_if_modified(|current| {
                    let changed = *current != candidate;
                    if changed {
                        *current = candidate.clone();
                    }
                    changed
                });
            }
            None => {
                let (cancel, cancelled) = Cancel::new();
                let (update, changes) = watch::channel(candidate.clone());
                let handle =
                    AbortOnDrop(tokio::spawn(supervise(ctx.clone(), changes, cancelled, slots.clone(), started)));
                running.insert(candidate.fingerprint, Running { cancel, update, handle });
            }
        }
    }
}

/// Keeps this host registered with one relay: dials it, registers, carries the tunnel until the
/// connection ends, and tries again after a wait that grows while it keeps failing.
async fn supervise(
    ctx: ReachContext,
    candidate: watch::Receiver<Candidate>,
    mut cancel: Cancel,
    slots: Arc<Semaphore>,
    started: Instant,
) {
    let mut backoff = Backoff::new();
    // The last reason said aloud, so that a relay that stays away is not complained about at every try.
    let mut told: Option<String> = None;
    loop {
        let current = candidate.borrow().clone();
        if !current.explicit && !needs_relay(&ctx, started) {
            if cancel.sleep(RECHECK_EVERY).await {
                return;
            }
            continue;
        }
        // A paired computer is not worth a handshake when this host's own cap would turn it away.
        if !current.explicit && slots.available_permits() == 0 {
            if cancel.sleep(FULL_WAIT).await {
                return;
            }
            continue;
        }
        let ended = tokio::select! {
            ended = attempt(&ctx, &current, &slots) => ended,
            () = cancel.wait() => return,
        };
        let (why, wait, registered) = match ended {
            Ended::Lost { why, registered_for } => {
                if registered_for.is_some_and(|lived| lived >= STABLE_AFTER) {
                    backoff.reset();
                }
                (why, backoff.wait(), registered_for.is_some())
            }
            Ended::Wait { why, wait } => (why, wait, false),
        };
        if registered {
            told = None;
        }
        let message =
            format!("relay '{}' ({}): {why}; trying again in {} s", current.name, current.fingerprint, wait.as_secs());
        if told.as_deref() == Some(why.as_str()) {
            tracing::debug!("{message}");
        } else {
            tracing::info!("{message}");
            told = Some(why);
        }
        if cancel.sleep(wait).await {
            return;
        }
    }
}

/// How an attempt at registering ended.
enum Ended {
    /// It failed, or the registration was lost after `registered_for`.
    Lost { why: String, registered_for: Option<Duration> },
    /// Leave the relay alone this long: it said no, or asked for something this host cannot give.
    Wait { why: String, wait: Duration },
}

/// One try: dial the relay, open a link, register, and carry the tunnel until the connection ends.
/// Everything it holds (the connection, the tunnel, the entry in the state) goes when it is dropped.
async fn attempt(ctx: &ReachContext, candidate: &Candidate, slots: &Arc<Semaphore>) -> Ended {
    let lost = |why: String| Ended::Lost { why, registered_for: None };
    let state = ctx.ext::<RelayState>();
    let (conn, via) = match dial(ctx, candidate).await {
        Ok(dialed) => dialed,
        Err(e) => return lost(format!("{e:#}")),
    };
    let _closing = CloseOnDrop(conn.clone());
    // A relay the user listed is being set up, and is asked again soon; the paired computers that
    // may relay are many, and the ones that say no are left alone for longer.
    let turned_away = if candidate.explicit { REFUSED_WAIT } else { NOT_A_RELAY_WAIT };
    let name = state.name.get().map_or("host", String::as_str);
    let mut link = match Link::open(&conn, name).await {
        Ok(link) => link,
        Err(LinkError::Refused(reason)) => {
            return Ended::Wait { why: format!("it refused this host: {reason}"), wait: turned_away };
        }
        Err(LinkError::PasswordRequired) => {
            let why = "it asks for an access password, which a link cannot give".to_string();
            return Ended::Wait { why, wait: turned_away };
        }
        Err(LinkError::Other(e)) => return lost(format!("{e:#}")),
    };
    if !link.reach.as_ref().is_some_and(|reach| reach.relays_for_others) {
        return Ended::Wait { why: "it does not relay for other devices".into(), wait: turned_away };
    }
    // The relays the user listed do not count against the cap: they asked for them.
    let permit = if candidate.explicit {
        None
    } else {
        match slots.clone().try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => {
                let why = "this host is registered with as many relays as it allows".to_string();
                return Ended::Wait { why, wait: FULL_WAIT };
            }
        }
    };
    // Open before registering: clients are passed through as soon as the relay has said yes.
    let mut tunnel = match ctx.socket.open_tunnel(candidate.fingerprint.0, NonZeroU16::MIN) {
        Ok(tunnel) => tunnel,
        Err(e) => return lost(e.to_string()),
    };
    let mac = ctx.reach.read().mac;
    if let Err(e) = link.send(&ClientMsg::RelayRegister { mac }).await {
        return lost(format!("{e:#}"));
    }
    if let Err(reason) = link.status().await {
        return lost(format!("registering failed: {reason}"));
    }
    let registered = Instant::now();
    let addresses = advertised(link.reach.as_ref(), &candidate.addresses, &via);
    let entry = RelayEntry { fingerprint: candidate.fingerprint, name: candidate.name.clone(), addresses };
    let _listed = Listed::new(ctx, &state, entry);
    tracing::info!("registered with the relay '{}' ({}) at {via}", candidate.name, candidate.fingerprint);

    let carried = carry(ctx, &conn, &mut link, &mut tunnel, mac).await;
    drop(permit);
    ended_by(carried, registered.elapsed())
}

/// How carrying a registration ended.
enum Carried {
    /// The connection ended; the error says how.
    Closed(quinn::ConnectionError),
    /// This side gave it up: the endpoint's socket is gone, or the control stream broke.
    Broken(String),
}

/// What the end of a registration that lasted `registered_for` says about when to try again: a
/// relay that closed the connection to say something (another registration replaced this one, the
/// user removed the host, the relay stopped) is left alone for longer than one that just went away.
fn ended_by(carried: Carried, registered_for: Duration) -> Ended {
    let registered_for = Some(registered_for);
    match carried {
        Carried::Closed(quinn::ConnectionError::ApplicationClosed(close)) => {
            let code = u64::from(close.error_code);
            let reason = clean(&String::from_utf8_lossy(&close.reason));
            let said = |text: &str| if reason.is_empty() { text.to_string() } else { format!("{text} ({reason})") };
            if code == u64::from(CLOSE_REPLACED) {
                let why = said("another registration of this host replaced this one");
                Ended::Wait { why, wait: REPLACED_WAIT }
            } else if code == u64::from(CLOSE_REMOVED) || code == u64::from(CLOSE_DEVICE_REMOVED) {
                Ended::Wait { why: said("the relay removed this host"), wait: REMOVED_WAIT }
            } else if code == u64::from(CLOSE_SHUTDOWN) {
                Ended::Wait { why: said("the relay stopped relaying"), wait: SHUTDOWN_WAIT }
            } else {
                Ended::Lost { why: said("the relay closed the connection"), registered_for }
            }
        }
        Carried::Closed(e) => Ended::Lost { why: e.to_string(), registered_for },
        Carried::Broken(why) => Ended::Lost { why, registered_for },
    }
}

/// Which MAC address the relay has accepted, so that one that turns up after the registration (the
/// host looks for it once it runs) or changes is told to the relay too, which lets it wake this host.
#[derive(Debug)]
struct MacTold {
    /// What the relay accepted.
    confirmed: Option<Mac>,
    /// What was sent and not answered yet.
    asked: Option<Mac>,
}

impl MacTold {
    /// `sent` is what the registration carried, and the relay accepted.
    fn new(sent: Option<Mac>) -> MacTold {
        MacTold { confirmed: sent, asked: None }
    }

    /// The address to tell the relay now: one it did not accept yet, when no question is open.
    fn to_tell(&self, current: Option<Mac>) -> Option<Mac> {
        current.filter(|mac| self.asked.is_none() && Some(*mac) != self.confirmed)
    }

    fn asked(&mut self, mac: Mac) {
        self.asked = Some(mac);
    }

    /// The relay answered the open question. A no leaves the address to be told again.
    fn answered(&mut self, ok: bool) {
        if let Some(mac) = self.asked.take().filter(|_| ok) {
            self.confirmed = Some(mac);
        }
    }
}

/// Carries inner packets between the tunnel and the relay and listens on the control stream, until
/// the connection ends. `sent` is the MAC address the registration carried.
async fn carry(
    ctx: &ReachContext,
    conn: &quinn::Connection,
    link: &mut Link,
    tunnel: &mut Tunnel,
    sent: Option<Mac>,
) -> Carried {
    let mut changes = ctx.reach.subscribe();
    let mut mac = MacTold::new(sent);
    let mut retry = tokio::time::interval(MAC_RETRY);
    retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let pumping = pump(conn, tunnel, Some(ctx));
    tokio::pin!(pumping);
    let why = loop {
        let current = ctx.reach.read().mac;
        if let Some(wanted) = mac.to_tell(current) {
            match link.send(&ClientMsg::RelayRegister { mac: Some(wanted) }).await {
                Ok(()) => mac.asked(wanted),
                Err(e) => break format!("{e:#}"),
            }
        }
        tokio::select! {
            ended = &mut pumping => return ended,
            message = link.inbox.recv() => match message {
                Some(Ok(HostMsg::RelayStatus { ok, reason })) => {
                    mac.answered(ok);
                    if !ok {
                        tracing::warn!("the relay did not take this host's last request: {}", clean(&reason));
                    }
                }
                Some(Ok(_)) => {}
                Some(Err(why)) => break why,
                None => break "the relay ended the control stream".to_string(),
            },
            changed = changes.changed() => {
                if changed.is_err() {
                    break "the host is shutting down".to_string();
                }
            }
            _ = retry.tick() => {}
        }
    };
    // A relay that ends the control stream is usually closing the connection, and the pump knows
    // with what code (which says how long to stay away): give it a moment to say.
    match timeout(CLOSE_GRACE, &mut pumping).await {
        Ok(ended) => ended,
        Err(_) => Carried::Broken(why),
    }
}

/// The addresses a client can dial the relay at, for `Reach`: what the relay said about itself on
/// the link (the freshest), else what the lists have. Those a client elsewhere can use come first
/// (public, IPv6, VPN) and LAN ones last. The address that worked from here is always among them.
fn advertised(reach: Option<&RelayReach>, listed: &[String], worked: &str) -> Vec<String> {
    let mut found: Vec<(u8, String)> = Vec::new();
    for (kind, address) in reach.map(|reach| reach.addresses.as_slice()).unwrap_or_default() {
        let rank = match kind {
            AddressKind::Public => 0,
            AddressKind::V6 => 1,
            AddressKind::Vpn => 2,
            AddressKind::Lan => 3,
            // A relay's relay is no way to it, and a kind this version does not know is no address to dial.
            AddressKind::Relay(_) | AddressKind::Other(_) => continue,
        };
        found.push((rank, address.clone()));
    }
    if found.is_empty() {
        found = listed.iter().map(|address| (4, address.clone())).collect();
    }
    found.sort_by_key(|(rank, _)| *rank);
    let mut addresses: Vec<String> = Vec::new();
    for (_, address) in found {
        if !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    addresses.truncate(MAX_ADVERTISED);
    if !addresses.iter().any(|address| address == worked) {
        if addresses.len() == MAX_ADVERTISED {
            addresses.pop();
        }
        addresses.push(worked.to_string());
    }
    addresses
}

/// Lists a relay in the state (and so in `Reach`) while the registration lasts.
struct Listed {
    ctx: ReachContext,
    state: Arc<RelayState>,
    key: [u8; 32],
}

impl Listed {
    fn new(ctx: &ReachContext, state: &Arc<RelayState>, entry: RelayEntry) -> Listed {
        let key = entry.fingerprint.0;
        let mut live = lock(&state.live);
        live.insert(key, entry);
        ctx.reach.update(|reach| reach.set_relays(live.values().cloned().collect()));
        Listed { ctx: ctx.clone(), state: state.clone(), key }
    }
}

impl Drop for Listed {
    fn drop(&mut self) {
        let mut live = lock(&self.state.live);
        live.remove(&self.key);
        self.ctx.reach.update(|reach| reach.set_relays(live.values().cloned().collect()));
    }
}

/// Connects to the relay at its first address to answer, trying the addresses a little apart (the
/// first connection that is made wins, the rest are dropped). The connection is made from the
/// listening port, so the NAT keeps one mapping for it and for the clients that come in. Returns
/// the connection and the address that worked.
async fn dial(ctx: &ReachContext, candidate: &Candidate) -> Result<(quinn::Connection, String)> {
    let addresses = resolve(&candidate.addresses).await;
    if addresses.is_empty() {
        bail!("none of its addresses can be dialed");
    }
    let config = tls::client_config(&ctx.identity, candidate.fingerprint)?;
    let mut attempts = JoinSet::new();
    for (index, addr) in addresses.into_iter().enumerate() {
        let (endpoint, config) = (ctx.endpoint.clone(), config.clone());
        let stagger = DIAL_STAGGER * u32::try_from(index).unwrap_or(u32::MAX);
        attempts.spawn(async move {
            sleep(stagger).await;
            let connecting =
                endpoint.connect_with(config, addr, tls::SERVER_NAME).map_err(|e| anyhow!("{addr}: {e}"))?;
            let conn = timeout(CONNECT_TIMEOUT, connecting)
                .await
                .map_err(|_| anyhow!("{addr}: no answer"))?
                .map_err(|e| anyhow!("{addr}: {e}"))?;
            anyhow::Ok((conn, addr))
        });
    }
    let mut last = anyhow!("none of its addresses answered");
    while let Some(joined) = attempts.join_next().await {
        match joined {
            Ok(Ok((conn, addr))) => return Ok((conn, addr.to_string())),
            Ok(Err(e)) => last = e,
            Err(e) => last = anyhow!("a connection attempt failed: {e}"),
        }
    }
    Err(last)
}

/// The socket addresses of `addresses`: `ip:port` as it is, `name:port` through the resolver. Those
/// that do not resolve, or are no place to dial, are skipped.
async fn resolve(addresses: &[String]) -> Vec<SocketAddr> {
    let mut found: Vec<SocketAddr> = Vec::new();
    for text in addresses {
        let resolved: Vec<SocketAddr> = match text.parse::<SocketAddr>() {
            Ok(addr) => vec![addr],
            Err(_) => match timeout(RESOLVE_TIMEOUT, tokio::net::lookup_host(text.as_str())).await {
                Ok(Ok(addrs)) => addrs.collect(),
                Ok(Err(e)) => {
                    tracing::debug!("cannot resolve {text}: {e}");
                    Vec::new()
                }
                Err(_) => {
                    tracing::debug!("resolving {text} took too long");
                    Vec::new()
                }
            },
        };
        for addr in resolved {
            let dialable = addr.port() != 0 && !addr.ip().is_unspecified() && !addr.ip().is_multicast();
            if dialable && !found.contains(&addr) {
                found.push(addr);
            }
        }
    }
    found.truncate(MAX_DIAL_ADDRESSES);
    found
}

// ---------------------------------------------------------------------------------------------
// The link
// ---------------------------------------------------------------------------------------------

/// What a relay said about itself right after its welcome (`HostMsg::Reach`).
#[derive(Debug, Clone)]
struct RelayReach {
    addresses: Vec<(AddressKind, String)>,
    relays_for_others: bool,
}

/// Why opening a link failed.
#[derive(Debug)]
enum LinkError {
    /// The host said no (`Rejected`): this device is not paired with it.
    Refused(String),
    /// The host has an access password, and a link has none to give.
    PasswordRequired,
    Other(anyhow::Error),
}

impl From<anyhow::Error> for LinkError {
    fn from(e: anyhow::Error) -> LinkError {
        LinkError::Other(e)
    }
}

/// The control stream of a connection to a host, after the hello of a *link*: `files_only` and
/// `reach`, which the host answers with a welcome for no screen, a `Reach`, and then control
/// messages only (see the module docs).
struct Link {
    send: quinn::SendStream,
    /// What the host says, in order. `Err` is a stream that broke; the channel closing is a clean end.
    inbox: mpsc::Receiver<Result<HostMsg, String>>,
    reader: JoinHandle<()>,
    /// `None` for a host that sent none: one from before standalone reach, which cannot relay.
    reach: Option<RelayReach>,
}

impl Drop for Link {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

impl Link {
    /// Opens the control stream on `conn`, says hello as `name` and reads the welcome and, if one
    /// follows within [`REACH_WAIT`], the `Reach`.
    async fn open(conn: &quinn::Connection, name: &str) -> Result<Link, LinkError> {
        let (mut send, recv) = timeout(LINK_TIMEOUT, conn.open_bi())
            .await
            .map_err(|_| anyhow!("opening the control stream took too long"))?
            .map_err(|e| anyhow!("opening the control stream: {e}"))?;
        let hello = ClientMsg::Hello {
            version: PROTOCOL_VERSION,
            name: name.chars().filter(|c| !c.is_control()).take(MAX_NAME_LEN).collect(),
            pairing_secret: None,
            password: None,
            ext: Some(HelloExt { files_only: true, reach: true, ..Default::default() }),
        };
        timeout(LINK_TIMEOUT, send.write_all(&hello.encode()))
            .await
            .map_err(|_| anyhow!("sending the hello took too long"))?
            .map_err(|e| anyhow!("sending the hello: {e}"))?;
        let (messages, inbox) = mpsc::channel(INBOX_QUEUE);
        let reader = tokio::spawn(read_host_messages(recv, messages));
        let mut link = Link { send, inbox, reader, reach: None };
        // The whole welcome has this long, however much the host says meanwhile.
        let deadline = tokio::time::Instant::now() + LINK_TIMEOUT;
        loop {
            match link.next_until(deadline).await? {
                HostMsg::Welcome { version, .. } if version == PROTOCOL_VERSION => break,
                HostMsg::Welcome { version, .. } => {
                    return Err(anyhow!("the host speaks protocol {version}, not {PROTOCOL_VERSION}").into());
                }
                HostMsg::Rejected { reason } => return Err(LinkError::Refused(clean(&reason))),
                HostMsg::PasswordRequired { .. } => return Err(LinkError::PasswordRequired),
                // This device offered no pairing secret.
                HostMsg::Paired => {}
                _ => return Err(anyhow!("the host sent something before its welcome").into()),
            }
        }
        // A host from before standalone reach ignores the bit and sends none; one whose stream
        // breaks instead has no connection worth keeping.
        let deadline = tokio::time::Instant::now() + REACH_WAIT;
        loop {
            match timeout_at(deadline, link.inbox.recv()).await {
                Ok(Some(Ok(HostMsg::Reach { addresses, relays_for_others, .. }))) => {
                    link.reach = Some(RelayReach { addresses, relays_for_others });
                    break;
                }
                Ok(Some(Ok(_))) => {}
                Ok(Some(Err(why))) => return Err(anyhow!("{}", clean(&why)).into()),
                Ok(None) => return Err(anyhow!("the host closed the control stream").into()),
                Err(_) => break,
            }
        }
        Ok(link)
    }

    /// The next message from the host; an error when it does not come by `deadline` or the stream ends.
    async fn next_until(&mut self, deadline: tokio::time::Instant) -> Result<HostMsg> {
        match timeout_at(deadline, self.inbox.recv()).await {
            Ok(Some(Ok(msg))) => Ok(msg),
            Ok(Some(Err(why))) => bail!("{}", clean(&why)),
            Ok(None) => bail!("the host closed the control stream"),
            Err(_) => bail!("the host took too long to answer"),
        }
    }

    async fn send(&mut self, msg: &ClientMsg) -> Result<()> {
        timeout(LINK_TIMEOUT, self.send.write_all(&msg.encode()))
            .await
            .map_err(|_| anyhow!("sending to the host took too long"))?
            .context("sending to the host")
    }

    /// Waits for the answer to a relay request: `Ok` when the relay did it, the reason when it did not.
    async fn status(&mut self) -> Result<(), String> {
        self.status_within(LINK_TIMEOUT).await
    }

    /// [`Link::status`], with `wait` for the whole answer however much else the host says meanwhile.
    async fn status_within(&mut self, wait: Duration) -> Result<(), String> {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            match self.next_until(deadline).await.map_err(|e| format!("{e:#}"))? {
                HostMsg::RelayStatus { ok: true, .. } => return Ok(()),
                HostMsg::RelayStatus { ok: false, reason } => return Err(clean(&reason)),
                _ => {}
            }
        }
    }
}

/// Reads the messages of the control stream into a channel (reading is not safe to cancel, so it
/// gets a task of its own). A message that does not read is skipped: a newer host may say more than
/// this version knows, and the framing says where the next one starts.
async fn read_host_messages(mut recv: quinn::RecvStream, out: mpsc::Sender<Result<HostMsg, String>>) {
    loop {
        let body = match wire::read_msg(&mut recv).await {
            Ok(Some(body)) => body,
            Ok(None) => return,
            Err(e) => {
                let _ = out.send(Err(format!("{e:#}"))).await;
                return;
            }
        };
        match HostMsg::decode(&body) {
            Ok(msg) => {
                if out.send(Ok(msg)).await.is_err() {
                    return;
                }
            }
            Err(e) => tracing::debug!("a message of the host does not read: {e:#}"),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The pump
// ---------------------------------------------------------------------------------------------

/// Carries inner packets between `tunnel` (the endpoint's side of a relay) and `conn` (the outer
/// connection to the relay) until `conn` ends: what the relay sends is put back together and
/// handed to the endpoint, what the endpoint sends is cut to the outer datagram size, which is
/// read at every send because it grows as the outer path's MTU is found, and sent. The packets of
/// a connection that is slower than the endpoint are dropped, like a full socket's: the inner QUIC
/// recovers them. With `punch`, the punch requests the relay passes on (one stream each) go to the
/// hole punching code.
async fn pump(conn: &quinn::Connection, tunnel: &mut Tunnel, punch: Option<&ReachContext>) -> Carried {
    let (inbound, mut splitter, mut reassembler) = (tunnel.inbound(), Splitter::new(), Reassembler::new());
    // The readers of punch requests end with the pump, however it ends.
    let mut readers = JoinSet::new();
    let mut sweep = tokio::time::interval(SWEEP_EVERY);
    sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut dropped = 0u64;
    loop {
        tokio::select! {
            datagram = conn.read_datagram() => {
                let datagram = match datagram {
                    Ok(datagram) => datagram,
                    Err(e) => return Carried::Closed(e),
                };
                if let Some(packet) = reassembler.push(datagram, Instant::now()) {
                    match inbound.deliver(packet) {
                        Ok(()) | Err(Undelivered::Full) => {}
                        Err(Undelivered::Closed) => return Carried::Broken("the tunnel was closed".into()),
                    }
                }
            }
            packet = tunnel.next_outbound() => {
                let Some(packet) = packet else { return Carried::Broken("the endpoint's socket is gone".into()) };
                if let Err(e) = send_framed(conn, &mut splitter, &packet, &mut dropped) {
                    return Carried::Closed(e);
                }
            }
            stream = conn.accept_uni() => {
                let recv = match stream {
                    Ok(recv) => recv,
                    Err(e) => return Carried::Closed(e),
                };
                // Streams nobody takes (too many at once, or no one to give them to) are dropped, which
                // tells the relay to stop sending.
                while readers.try_join_next().is_some() {}
                if let (Some(ctx), true) = (punch, readers.len() < MAX_PUNCH_STREAMS) {
                    let ctx = ctx.clone();
                    readers.spawn(async move { read_punch(&ctx, recv).await });
                }
            }
            _ = sweep.tick() => reassembler.expire(Instant::now()),
        }
    }
}

/// Frames `packet` and sends it. A packet that cannot go (the outer datagrams do not fit it, the
/// relay takes none) is dropped and counted; only a connection that is gone is an error.
fn send_framed(
    conn: &quinn::Connection,
    splitter: &mut Splitter,
    packet: &[u8],
    dropped: &mut u64,
) -> Result<(), quinn::ConnectionError> {
    let mut drop_packet = |why: &str| {
        *dropped += 1;
        if *dropped == 1 || dropped.is_multiple_of(1024) {
            tracing::debug!("relay: dropped a packet of the tunnel: {why} ({dropped} so far)");
        }
    };
    let Some(max) = conn.max_datagram_size() else {
        drop_packet("the relay connection takes no datagrams");
        return Ok(());
    };
    match splitter.split(packet, max) {
        Ok(datagrams) => {
            for datagram in datagrams {
                match conn.send_datagram(datagram) {
                    Ok(()) => {}
                    Err(quinn::SendDatagramError::ConnectionLost(e)) => return Err(e),
                    Err(e) => {
                        drop_packet(&e.to_string());
                        break;
                    }
                }
            }
        }
        Err(e) => drop_packet(&e.to_string()),
    }
    Ok(())
}

/// Reads the punch request a relay passes on (one message on a stream of its own, which the relay
/// then finishes) and gives it to the hole punching code. What does not read is dropped.
async fn read_punch(ctx: &ReachContext, mut recv: quinn::RecvStream) {
    let body = match timeout(PUNCH_READ_TIMEOUT, wire::read_msg(&mut recv)).await {
        Ok(Ok(Some(body))) => body,
        Ok(Ok(None)) => return,
        Ok(Err(e)) => return tracing::debug!("a punch request did not arrive: {e:#}"),
        Err(_) => return tracing::debug!("a punch request took too long to arrive"),
    };
    if let Some(request) = parse_punch(&body) {
        respond(ctx, request).await;
    }
}

/// The punch request in a message body, if that is what it is.
fn parse_punch(body: &[u8]) -> Option<PunchRequest> {
    match HostMsg::decode(body) {
        Ok(HostMsg::PunchRequest { from, endpoint, nonce }) => Some(PunchRequest { from, endpoint, nonce }),
        Ok(_) => {
            tracing::debug!("a relay sent something else than a punch request on a stream");
            None
        }
        Err(e) => {
            tracing::debug!("a punch request does not read: {e:#}");
            None
        }
    }
}

/// Gives a punch request to the hole punching code (E5); what it fails with is only logged. A
/// refusal is news: a paired device asked for something the host will not do.
async fn respond(ctx: &ReachContext, request: PunchRequest) {
    let from = clean(&request.from);
    if let Err(e) = punch::respond(ctx, request).await {
        tracing::info!("punch request of {from} not taken: {e:#}");
    }
}

// ---------------------------------------------------------------------------------------------
// Small things
// ---------------------------------------------------------------------------------------------

/// Tells a supervisor to end. (`Stop` is the host's own; only the host can make one.)
#[derive(Clone)]
struct Cancel(watch::Receiver<bool>);

impl Cancel {
    fn new() -> (watch::Sender<bool>, Cancel) {
        let (tx, rx) = watch::channel(false);
        (tx, Cancel(rx))
    }

    /// Resolves when told to end, or when whoever could tell is gone.
    async fn wait(&mut self) {
        let _ = self.0.wait_for(|cancelled| *cancelled).await;
    }

    /// Sleeps `duration` or until told to end; returns whether it was told.
    async fn sleep(&mut self, duration: Duration) -> bool {
        tokio::select! {
            () = tokio::time::sleep(duration) => {}
            () = self.wait() => return true,
        }
        *self.0.borrow()
    }
}

/// The wait between attempts at one relay: it doubles up to [`BACKOFF_MAX`] while attempts keep
/// failing, and starts over after a registration that lasted.
#[derive(Debug)]
struct Backoff {
    next: Duration,
}

impl Backoff {
    fn new() -> Backoff {
        Backoff { next: BACKOFF_MIN }
    }

    /// The wait before the next attempt, up to a fifth longer by chance, so that hosts that lost the
    /// same relay at the same moment do not come back at the same moment.
    fn wait(&mut self) -> Duration {
        let wait = self.next;
        self.next = (self.next * 2).min(BACKOFF_MAX);
        wait + wait / 5 * jitter() / 100
    }

    fn reset(&mut self) {
        self.next = BACKOFF_MIN;
    }
}

/// A number from 0 to 99 that is different every time.
fn jitter() -> u32 {
    u32::try_from(RandomState::new().hash_one(0u8) % 100).unwrap_or(0)
}

/// Closes the connection when dropped, so that a registration that ends in any way is not left to
/// time out at the relay.
struct CloseOnDrop(quinn::Connection);

impl Drop for CloseOnDrop {
    fn drop(&mut self) {
        self.0.close(0u32.into(), b"registration ended");
    }
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use velora_protocol::{identity::Identity, wire::Codec};
    use velora_relay::forward::CLOSE_HOST_GONE;

    use super::*;
    use crate::{
        encode::EncoderChoice,
        reach::{
            bind, handle_client_msg, reach_message,
            socket::{tunnel_addr, Multiplexer},
            testing, ControlSender, Switches,
        },
        server::{self, HostOptions},
    };

    const MAC: [u8; 6] = [1, 2, 3, 4, 5, 6];

    fn known(n: u8) -> Known {
        Known { fingerprint: Fingerprint([n; 32]), mac: Some([n; 6]), addr: "192.0.2.7".parse().unwrap() }
    }

    fn entry(name: &str, fingerprint: Fingerprint, address: &str) -> KnownHost {
        KnownHost {
            name: name.into(),
            address: address.into(),
            fingerprint: fingerprint.to_base64(),
            ..Default::default()
        }
    }

    fn clients(devices: &[Fingerprint]) -> Vec<AuthorizedClient> {
        devices
            .iter()
            .map(|device| AuthorizedClient {
                name: "device".into(),
                fingerprint: device.to_base64(),
                added_unix: 0,
                trust_files: false,
            })
            .collect()
    }

    async fn until(what: &str, mut condition: impl FnMut() -> bool) {
        for _ in 0..400 {
            if condition() {
                return;
            }
            sleep(Duration::from_millis(50)).await;
        }
        panic!("gave up waiting for {what}");
    }

    // What the host remembers and how it picks relays -----------------------------------------

    #[test]
    fn what_the_relay_remembers_survives_its_file_form_and_a_bad_entry_costs_only_itself() {
        let record = KnownRecord::of(&known(3));
        assert_eq!(record.known(), Some(known(3)));
        let json = serde_json::to_string(&record).unwrap();
        assert_eq!(serde_json::from_str::<KnownRecord>(&json).unwrap(), record);

        // A host that said no MAC address has no field for it.
        let without = Known { mac: None, ..known(3) };
        let record_without = KnownRecord::of(&without);
        assert!(!serde_json::to_string(&record_without).unwrap().contains("mac"));
        assert_eq!(record_without.known(), Some(without));

        let bad = [
            KnownRecord { fingerprint: "nope".into(), ..record.clone() },
            KnownRecord { mac: Some("zz:zz".into()), ..record.clone() },
            KnownRecord { addr: "not an address".into(), ..record.clone() },
        ];
        assert!(bad.iter().all(|record| record.known().is_none()));
    }

    #[tokio::test]
    async fn the_relay_saves_what_it_remembers_only_when_it_changes_and_loads_it_after_a_restart() {
        let (ctx, _scratch) = testing::context("relay-known");
        let file = ctx.state_dir.path(KNOWN_FILE);
        let state = ctx.ext::<RelayState>();
        state.load_known(&ctx);
        state.save_known(&ctx);
        assert!(!file.exists(), "nothing to save yet");

        state.relay.remember(known(1));
        state.relay.remember(known(2));
        state.save_known(&ctx);
        let saved: Vec<KnownRecord> = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        assert_eq!(saved.len(), 2);

        // What has not changed is not written again.
        std::fs::remove_file(&file).unwrap();
        state.save_known(&ctx);
        assert!(!file.exists());

        // A new forwarder (the host restarted) learns it from the file, once.
        std::fs::write(&file, serde_json::to_vec(&saved).unwrap()).unwrap();
        let restarted = RelayState::default();
        restarted.load_known(&ctx);
        let mut remembered = restarted.relay.known();
        remembered.sort_by_key(|known| known.fingerprint.0);
        assert_eq!(remembered, vec![known(1), known(2)]);
        restarted.relay.remove(&Fingerprint([1; 32]));
        restarted.load_known(&ctx);
        assert_eq!(restarted.relay.known().len(), 1, "the file is read once");

        // A file that does not read is no reason to stop: the forwarder starts empty.
        std::fs::write(&file, b"{ not json").unwrap();
        let damaged = RelayState::default();
        damaged.load_known(&ctx);
        assert!(damaged.relay.known().is_empty());
        damaged.relay.remember(known(5));
        damaged.save_known(&ctx);
        let rewritten: Vec<KnownRecord> = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        assert_eq!(rewritten.len(), 1, "and the next save repairs the file");
    }

    #[test]
    fn the_users_relays_come_first_and_each_relay_counts_once() {
        let own = Fingerprint([9; 32]);
        let mine = [entry("mine", Fingerprint([1; 32]), "198.51.100.1:7420")];
        let paired = [
            entry("same", Fingerprint([1; 32]), "198.51.100.99:7420"),
            entry("laptop", Fingerprint([2; 32]), "192.0.2.2:7420"),
            entry("this one", own, "192.0.2.9:7420"),
            KnownHost {
                fingerprint: "not a fingerprint".into(),
                ..entry("broken", Fingerprint([3; 32]), "192.0.2.3:7420")
            },
            entry("no address", Fingerprint([4; 32]), ""),
        ];
        let found = select(&mine, &paired, &own);
        let listed: Vec<(&str, bool)> = found.iter().map(|c| (c.name.as_str(), c.explicit)).collect();
        assert_eq!(listed, [("mine", true), ("laptop", false)]);
        assert_eq!(found[0].addresses, ["198.51.100.1:7420"], "the user's entry wins");

        let many: Vec<KnownHost> =
            (0..40).map(|n| entry("relay", Fingerprint([100 + n; 32]), "192.0.2.50:7420")).collect();
        assert_eq!(select(&[], &many, &own).len(), MAX_CANDIDATES);
    }

    #[test]
    fn a_relays_addresses_leave_out_its_own_relays_and_keep_the_order_it_gave() {
        let mut relay = entry("relay", Fingerprint([5; 32]), "192.0.2.5:7420");
        relay.also = vec!["192.0.2.6:7420".into(), "192.0.2.5:7420".into()];
        relay.kinds = vec![
            (AddressKind::Relay(Fingerprint([6; 32]).to_base64()), "203.0.113.6:7420".into()),
            (AddressKind::Public, "198.51.100.5:7420".into()),
            (AddressKind::Lan, "192.0.2.5:7420".into()),
        ];
        let candidate = Candidate::of(&relay, false).unwrap();
        assert_eq!(candidate.addresses, ["198.51.100.5:7420", "192.0.2.5:7420", "192.0.2.6:7420"]);
        assert_eq!(candidate.name, "relay");

        // A name with control characters is cleaned, an empty one is the fingerprint.
        relay.name = "re\u{7}lay\n".into();
        assert_eq!(Candidate::of(&relay, false).unwrap().name, "relay");
        relay.name = "  ".into();
        assert_eq!(Candidate::of(&relay, false).unwrap().name, Fingerprint([5; 32]).short());
    }

    #[test]
    fn clients_are_given_the_addresses_of_a_relay_that_work_from_outside_first() {
        let reach = RelayReach {
            relays_for_others: true,
            addresses: vec![
                (AddressKind::Lan, "192.0.2.5:7420".into()),
                (AddressKind::Vpn, "100.64.0.5:7420".into()),
                (AddressKind::Public, "198.51.100.5:7420".into()),
                (AddressKind::V6, "[2001:db8::5]:7420".into()),
                (AddressKind::Relay("someone".into()), "203.0.113.1:7420".into()),
                (AddressKind::Other(9), "203.0.113.2:7420".into()),
            ],
        };
        let listed = vec!["192.0.2.77:7420".to_string()];
        assert_eq!(
            advertised(Some(&reach), &listed, "192.0.2.5:7420"),
            ["198.51.100.5:7420", "[2001:db8::5]:7420", "100.64.0.5:7420", "192.0.2.5:7420"]
        );
        // The one that worked from here is always among them, in place of the last when they are full.
        let got = advertised(Some(&reach), &listed, "203.0.113.77:7420");
        assert_eq!(got.len(), MAX_ADVERTISED);
        assert_eq!(got.first().map(String::as_str), Some("198.51.100.5:7420"));
        assert_eq!(got.last().map(String::as_str), Some("203.0.113.77:7420"));
        // A relay that said nothing useful is dialed at what the lists have.
        let silent =
            RelayReach { relays_for_others: true, addresses: vec![(AddressKind::Relay("x".into()), "a:1".into())] };
        let lists = vec!["192.0.2.1:7420".to_string(), "192.0.2.2:7420".to_string()];
        assert_eq!(advertised(Some(&silent), &lists, "192.0.2.2:7420"), lists);
        assert_eq!(advertised(None, &lists, "192.0.2.3:7420"), ["192.0.2.1:7420", "192.0.2.2:7420", "192.0.2.3:7420"]);
    }

    #[test]
    fn the_wait_between_attempts_doubles_up_to_five_minutes_and_starts_over() {
        let mut backoff = Backoff::new();
        let mut base = BACKOFF_MIN;
        for _ in 0..10 {
            let wait = backoff.wait();
            assert!(wait >= base && wait <= base + base / 5, "{wait:?} for a base of {base:?}");
            base = (base * 2).min(BACKOFF_MAX);
        }
        assert_eq!(base, BACKOFF_MAX);
        backoff.reset();
        assert!(backoff.wait() < BACKOFF_MIN * 2);
    }

    #[test]
    fn a_relay_that_closes_the_connection_to_say_something_is_left_alone_for_longer() {
        let closed = |code: u32, reason: &str| {
            Carried::Closed(quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
                error_code: code.into(),
                reason: reason.to_string().into(),
            }))
        };
        let lived = Duration::from_secs(7);
        let wait = |code: u32| match ended_by(closed(code, ""), lived) {
            Ended::Wait { wait, .. } => Some(wait),
            _ => None,
        };
        assert_eq!(wait(CLOSE_REPLACED), Some(REPLACED_WAIT));
        assert_eq!(wait(CLOSE_REMOVED), Some(REMOVED_WAIT));
        assert_eq!(wait(CLOSE_DEVICE_REMOVED), Some(REMOVED_WAIT));
        assert_eq!(wait(CLOSE_SHUTDOWN), Some(SHUTDOWN_WAIT));

        // Any other code, or none at all, is a relay that went away: the usual wait, and how long it lasted.
        assert_eq!(wait(0x99), None);
        let Ended::Lost { why, registered_for } = ended_by(closed(0x99, "restart"), lived) else { panic!("lost") };
        assert_eq!((why.as_str(), registered_for), ("the relay closed the connection (restart)", Some(lived)));
        let broken = ended_by(Carried::Broken("it broke".into()), lived);
        assert!(matches!(broken, Ended::Lost { registered_for: Some(_), .. }));
        let timed_out = ended_by(Carried::Closed(quinn::ConnectionError::TimedOut), lived);
        assert!(matches!(timed_out, Ended::Lost { registered_for: Some(_), .. }));
    }

    #[test]
    fn only_a_punch_request_is_taken_from_a_stream() {
        let request = HostMsg::PunchRequest { from: "client".into(), endpoint: "198.51.100.7:4000".into(), nonce: 9 };
        let parsed = parse_punch(&request.encode()[4..]).expect("a punch request");
        assert_eq!(parsed, PunchRequest { from: "client".into(), endpoint: "198.51.100.7:4000".into(), nonce: 9 });
        assert!(parse_punch(&HostMsg::RelayStatus { ok: true, reason: String::new() }.encode()[4..]).is_none());
        assert!(parse_punch(&[0xff, 1, 2, 3]).is_none());
        assert!(parse_punch(&[]).is_none());
    }

    #[tokio::test]
    async fn a_host_the_user_paired_with_from_here_is_trusted_and_nobody_else() {
        let (ctx, _scratch) = testing::context("relay-trust");
        let (paired, stranger) = (Fingerprint([7; 32]), Fingerprint([8; 32]));
        assert!(!trusts(&ctx, &paired), "there is no client side at all");
        let client_dir = ctx.client_state_dir().unwrap();
        std::fs::create_dir_all(&client_dir).unwrap();
        let hosts = [entry("laptop", paired, "192.0.2.7:7420")];
        std::fs::write(client_dir.join(StateDir::KNOWN_HOSTS), serde_json::to_vec(&hosts).unwrap()).unwrap();
        assert!(trusts(&ctx, &paired));
        assert!(!trusts(&ctx, &stranger));
        std::fs::write(client_dir.join(StateDir::KNOWN_HOSTS), b"damaged").unwrap();
        assert!(!trusts(&ctx, &paired), "a list that does not read trusts nobody");
    }

    // Serving ----------------------------------------------------------------------------------

    /// A throwaway device connected to the host of `ctx`, and what the hooks are given for it.
    async fn device(ctx: &ReachContext, name: &str) -> (testing::Link, ClientConn, mpsc::Receiver<HostMsg>) {
        let link = testing::connect(ctx).await;
        let (from, outbox) = testing::client_conn(&link, name);
        (link, from, outbox)
    }

    /// The `RelayStatus` the hooks queued for a device.
    async fn answer(outbox: &mut mpsc::Receiver<HostMsg>) -> (bool, String) {
        match timeout(Duration::from_secs(5), outbox.recv()).await {
            Ok(Some(HostMsg::RelayStatus { ok, reason })) => (ok, reason),
            other => panic!("expected a relay status, got {other:?}"),
        }
    }

    /// The application code a connection was closed with.
    async fn closed_with(conn: &quinn::Connection) -> u64 {
        match timeout(Duration::from_secs(5), conn.closed()).await.expect("the connection ends") {
            quinn::ConnectionError::ApplicationClosed(close) => u64::from(close.error_code),
            other => panic!("closed in some other way: {other}"),
        }
    }

    #[tokio::test]
    async fn a_host_registers_is_remembered_across_restarts_and_dropped_when_removed() {
        let (ctx, _scratch) = testing::context("relay-register");
        let state = ctx.ext::<RelayState>();
        let (host_link, host, mut host_outbox) = device(&ctx, "sleeping host").await;
        let host_fp = tls::peer_fingerprint(&host_link.server).unwrap();

        handle_message(&ctx, &host, ClientMsg::RelayRegister { mac: Some(MAC) }).await.unwrap();
        assert_eq!(answer(&mut host_outbox).await, (true, String::new()));
        let registered = state.relay.registered();
        assert_eq!((registered.len(), registered[0].fingerprint, registered[0].mac), (1, host_fp, Some(MAC)));

        // It can be woken after a restart because the file has it.
        let file = ctx.state_dir.path(KNOWN_FILE);
        until("the state file", || file.exists()).await;
        let saved: Vec<KnownRecord> = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].fingerprint, host_fp.to_base64());
        assert_eq!(parse_mac(saved[0].mac.as_deref().unwrap()).unwrap(), MAC);

        // A client is passed to it; relayed traffic makes the host busy, a registration alone does not.
        assert!(!busy(&ctx));
        let (client_link, client, mut client_outbox) = device(&ctx, "phone").await;
        handle_message(&ctx, &client, ClientMsg::RelayTo { fingerprint: host_fp.to_base64() }).await.unwrap();
        assert_eq!(answer(&mut client_outbox).await, (true, String::new()));
        assert!(busy(&ctx));

        // A host nobody registered is refused with the reason.
        let (_stray_link, stray, mut stray_outbox) = device(&ctx, "stray").await;
        let unknown = Fingerprint([42; 32]).to_base64();
        handle_message(&ctx, &stray, ClientMsg::RelayTo { fingerprint: unknown }).await.unwrap();
        let (ok, reason) = answer(&mut stray_outbox).await;
        assert!(!ok && reason.contains("never registered"), "{reason}");

        // The user removes the host: its connection and the client's end, and the file forgets it.
        on_revoked(&ctx, &host_fp);
        assert_eq!(closed_with(host_link.client()).await, u64::from(CLOSE_REMOVED));
        assert_eq!(closed_with(client_link.client()).await, u64::from(CLOSE_HOST_GONE));
        assert!(state.relay.registered().is_empty() && !busy(&ctx));
        let saved: Vec<KnownRecord> = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        assert!(saved.is_empty());
    }

    #[tokio::test]
    async fn a_punch_request_reaches_the_registered_host_on_a_stream_of_its_own() {
        let (ctx, _scratch) = testing::context("relay-punch");
        let (host_link, host, mut host_outbox) = device(&ctx, "host").await;
        let host_fp = tls::peer_fingerprint(&host_link.server).unwrap();
        handle_message(&ctx, &host, ClientMsg::RelayRegister { mac: None }).await.unwrap();
        assert!(answer(&mut host_outbox).await.0);

        let (client_link, client, mut client_outbox) = device(&ctx, "phone").await;
        let client_fp = tls::peer_fingerprint(&client_link.server).unwrap();
        let request =
            ClientMsg::PunchRequest { to: host_fp.to_base64(), endpoint: "198.51.100.7:4000".into(), nonce: 9 };
        handle_message(&ctx, &client, request).await.unwrap();
        assert_eq!(answer(&mut client_outbox).await, (true, String::new()));

        // The host's end of the registration connection receives it on a stream.
        let mut stream = timeout(Duration::from_secs(5), host_link.client().accept_uni()).await.unwrap().unwrap();
        let body = wire::read_msg(&mut stream).await.unwrap().unwrap();
        let parsed = parse_punch(&body).expect("a punch request");
        assert_eq!(parsed.from, client_fp.to_base64());
        assert_eq!((parsed.endpoint.as_str(), parsed.nonce), ("198.51.100.7:4000", 9));

        // A host that told no MAC address cannot be woken, and the answer says why.
        handle_message(&ctx, &client, ClientMsg::Wake { fingerprint: host_fp.to_base64() }).await.unwrap();
        let (ok, reason) = answer(&mut client_outbox).await;
        assert!(!ok && reason.contains("MAC"), "{reason}");
    }

    #[tokio::test]
    async fn devices_removed_behind_the_hosts_back_are_dropped_by_the_serving_task() {
        let (ctx, _scratch) = testing::context("relay-reconcile");
        let state = ctx.ext::<RelayState>();
        let (host_link, host, mut host_outbox) = device(&ctx, "host").await;
        let host_fp = tls::peer_fingerprint(&host_link.server).unwrap();
        handle_message(&ctx, &host, ClientMsg::RelayRegister { mac: None }).await.unwrap();
        assert!(answer(&mut host_outbox).await.0);

        // Paired devices stay, and a host that is only remembered (asleep) goes if it is not one of
        // them; everything stays when the list cannot be read.
        state.relay.remember(known(7));
        std::fs::write(ctx.state_dir.path(StateDir::AUTHORIZED_CLIENTS), b"damaged").unwrap();
        reconcile(&ctx, &state);
        assert_eq!((state.relay.registered().len(), state.relay.known().len()), (1, 2));
        ctx.state_dir.save(StateDir::AUTHORIZED_CLIENTS, &clients(&[host_fp])).unwrap();
        reconcile(&ctx, &state);
        assert_eq!(state.relay.registered().len(), 1);
        let remembered: Vec<Fingerprint> = state.relay.known().iter().map(|known| known.fingerprint).collect();
        assert_eq!(remembered, [host_fp]);

        // `velora-host revoke` took it out of the list: it goes at the next look.
        ctx.state_dir.save(StateDir::AUTHORIZED_CLIENTS, &clients(&[])).unwrap();
        reconcile(&ctx, &state);
        assert!(state.relay.registered().is_empty());
        assert_eq!(closed_with(host_link.client()).await, u64::from(CLOSE_REMOVED));
    }

    #[tokio::test]
    async fn packets_are_cut_to_the_datagram_size_of_the_connection_and_put_back_together() {
        let (ctx, _scratch) = testing::context("relay-frame");
        let link = testing::connect(&ctx).await;
        let (mut splitter, mut reassembler, mut dropped) = (Splitter::new(), Reassembler::new(), 0u64);
        let max = link.server.max_datagram_size().expect("datagrams are on");
        // One that fits whole, one that needs two datagrams, and the most two datagrams hold.
        for len in [100, max, 2 * (max - 3)] {
            let packet: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            send_framed(&link.server, &mut splitter, &packet, &mut dropped).unwrap();
            let mut put_back = None;
            while put_back.is_none() {
                let datagram = timeout(Duration::from_secs(5), link.client().read_datagram()).await;
                put_back = reassembler.push(datagram.expect("a datagram").unwrap(), Instant::now());
            }
            assert_eq!(put_back.unwrap().as_ref(), &packet[..]);
        }
        assert_eq!(dropped, 0);
        // One that no two datagrams hold is dropped and counted; the connection goes on.
        let too_big = vec![0u8; 3 * link.server.max_datagram_size().unwrap()];
        send_framed(&link.server, &mut splitter, &too_big, &mut dropped).unwrap();
        assert_eq!(dropped, 1);
    }

    // Whole hosts, in process, on the loopback ----------------------------------------------------

    /// Removes the state directory of a test host.
    struct TempDir(std::path::PathBuf);

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A host's state directory, ready to be filled in and started.
    struct Prepared {
        dir: TempDir,
        state: StateDir,
        fingerprint: Fingerprint,
    }

    fn prepare(tag: &str) -> Prepared {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "velora-relay-{tag}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let state = StateDir::open(Some(dir.clone()), "host").unwrap();
        // A test host must not hold the computer awake.
        std::fs::write(state.path("power.json"), r#"{"stay_awake":false}"#).unwrap();
        let fingerprint = state.load_or_create_identity().unwrap().fingerprint();
        Prepared { dir: TempDir(dir), state, fingerprint }
    }

    /// Addresses on the loopback with nothing bound to them now (and different from each other).
    fn free_addrs<const N: usize>() -> [SocketAddr; N] {
        let sockets: Vec<std::net::UdpSocket> =
            (0..N).map(|_| std::net::UdpSocket::bind("127.0.0.1:0").unwrap()).collect();
        let addrs: Vec<SocketAddr> = sockets.iter().map(|socket| socket.local_addr().unwrap()).collect();
        addrs.try_into().unwrap()
    }

    /// A whole host, started the way `velora-host run` starts it.
    struct Machine {
        _dir: TempDir,
        fingerprint: Fingerprint,
        addr: SocketAddr,
        /// Its state directory.
        state: std::path::PathBuf,
        task: tokio::task::JoinHandle<Result<bool>>,
    }

    impl Drop for Machine {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    impl Prepared {
        /// Lists the client devices (`authorized_clients.json`) this host serves.
        fn pair(&self, devices: &[Fingerprint]) {
            self.state.save(StateDir::AUTHORIZED_CLIENTS, &clients(devices)).unwrap();
        }

        async fn start(self, addr: SocketAddr, relay_only: bool) -> Machine {
            let Prepared { dir, state, fingerprint } = self;
            let path = state.dir().to_path_buf();
            let options = HostOptions {
                bind: addr,
                name: "test host".into(),
                fps: 30,
                bitrate_kbps: 1000,
                encoder: EncoderChoice::Software,
                service: false,
                adaptive_bitrate: false,
                relay_only,
            };
            let task = tokio::spawn(server::run(options, state, false, false));
            for _ in 0..400 {
                assert!(!task.is_finished(), "the host stopped at start");
                if std::net::UdpSocket::bind(addr).is_err() {
                    break;
                }
                sleep(Duration::from_millis(25)).await;
            }
            assert!(std::net::UdpSocket::bind(addr).is_err(), "the host never bound its port");
            Machine { _dir: dir, fingerprint, addr, state: path, task }
        }
    }

    /// A device's connection to a host (or through a relay to one), after the hello of a link.
    struct Device {
        conn: quinn::Connection,
        link: Link,
        _endpoint: quinn::Endpoint,
    }

    async fn link_to(identity: &Identity, addr: SocketAddr, host: Fingerprint) -> Device {
        let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let config = tls::client_config(identity, host).unwrap();
        let conn = endpoint.connect_with(config, addr, tls::SERVER_NAME).unwrap().await.expect("connected");
        let link = Link::open(&conn, "test device").await.map_err(|e| format!("{e:?}")).expect("a link");
        Device { conn, link, _endpoint: endpoint }
    }

    /// What a client does to reach a host through a relay it is already relayed on (`relay`): an
    /// endpoint whose socket is the relay connection, and a connection to the host over it.
    async fn through(identity: &Identity, relay: &quinn::Connection, host: Fingerprint) -> (Device, AbortOnDrop) {
        let socket = Arc::new(Multiplexer::new(bind("[::]:0".parse().unwrap()).unwrap()).unwrap());
        assert!(socket.local_addr().is_ipv6(), "the addresses of tunnels are IPv6");
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            socket.clone(),
            Arc::new(quinn::TokioRuntime),
        )
        .unwrap();
        let mut tunnel = socket.open_tunnel(host.0, NonZeroU16::MIN).unwrap();
        let addr = tunnel.addr();
        let outer = relay.clone();
        let pumping = AbortOnDrop(tokio::spawn(async move {
            let _ = pump(&outer, &mut tunnel, None).await;
        }));
        let config = tls::client_config(identity, host).unwrap();
        let conn = endpoint.connect_with(config, addr, tls::SERVER_NAME).unwrap().await.expect("connected through");
        let link = Link::open(&conn, "test device").await.map_err(|e| format!("{e:?}")).expect("a link");
        (Device { conn, link, _endpoint: endpoint }, pumping)
    }

    #[tokio::test]
    async fn a_client_reaches_a_host_behind_a_nat_through_a_relay_that_is_a_host_too() {
        let client = Identity::generate().unwrap();
        let client_fp = client.fingerprint();
        let (relay, host) = (prepare("relay"), prepare("host"));
        let [relay_addr, host_addr] = free_addrs();
        // The registering host presents its own (host) identity, which the relay must let in.
        relay.pair(&[client_fp, host.fingerprint]);
        host.pair(&[client_fp]);
        Switches { standalone: true, ..Default::default() }.save(&host.state).unwrap();
        host.state.save(RELAYS_FILE, &[entry("relay", relay.fingerprint, &relay_addr.to_string())]).unwrap();
        let relay = relay.start(relay_addr, true).await;
        let host = host.start(host_addr, false).await;

        // The host dials the relay on its own and says so in its Reach.
        let via_relay = AddressKind::Relay(relay.fingerprint.to_base64());
        let mut listed = Vec::new();
        for _ in 0..100 {
            let device = link_to(&client, host.addr, host.fingerprint).await;
            let reach = device.link.reach.as_ref().expect("the host sends Reach");
            listed = reach.addresses.iter().filter(|(kind, _)| *kind == via_relay).map(|(_, a)| a.clone()).collect();
            if !listed.is_empty() {
                break;
            }
            drop(device);
            sleep(Duration::from_millis(200)).await;
        }
        assert!(listed.contains(&relay_addr.to_string()), "the host lists the relay it registered with: {listed:?}");

        // The client asks the relay for the host and speaks to it through the relay.
        let mut at_relay = link_to(&client, relay.addr, relay.fingerprint).await;
        assert!(at_relay.link.reach.as_ref().unwrap().relays_for_others);
        at_relay.link.send(&ClientMsg::RelayTo { fingerprint: host.fingerprint.to_base64() }).await.unwrap();
        at_relay.link.status().await.expect("the relay passes the client to the host");
        let (mut at_host, _pumping) = through(&client, &at_relay.conn, host.fingerprint).await;
        let reach = at_host.link.reach.as_ref().expect("the host answers a link with Reach");
        assert!(!reach.relays_for_others, "that is the host, not the relay");
        assert!(reach.addresses.contains(&(via_relay, relay_addr.to_string())));
        at_host.link.send(&ClientMsg::RelayTo { fingerprint: "someone".into() }).await.unwrap();
        let refused = at_host.link.status().await.unwrap_err();
        assert_eq!(refused, "this computer does not relay for other devices");

        // The relay kept the host's MAC address for waking it after a restart.
        let file = relay.state.join(KNOWN_FILE);
        until("the relay to save what it remembers", || {
            std::fs::read(&file)
                .ok()
                .and_then(|data| serde_json::from_slice::<Vec<KnownRecord>>(&data).ok())
                .is_some_and(|records| records.iter().any(|r| r.fingerprint == host.fingerprint.to_base64()))
        })
        .await;
    }

    #[tokio::test]
    async fn a_host_is_turned_away_by_a_relay_that_does_not_know_it_or_does_not_relay() {
        let (ctx, _scratch) = testing::context("relay-attempt");
        let slots = Arc::new(Semaphore::new(MAX_REGISTRATIONS));
        let candidate = |machine: &Machine| Candidate {
            fingerprint: machine.fingerprint,
            name: "relay".into(),
            addresses: vec![machine.addr.to_string()],
            explicit: true,
        };

        // A relay that has never heard of this host.
        let relay = prepare("attempt-relay");
        let [relay_addr, plain_addr] = free_addrs();
        let relay_state = relay.state.dir().to_path_buf();
        let relay = relay.start(relay_addr, true).await;
        let Ended::Wait { why, .. } = attempt(&ctx, &candidate(&relay), &slots).await else { panic!("turned away") };
        assert!(why.contains("not paired"), "{why}");

        // A computer that is paired but does not relay for others.
        let plain = prepare("attempt-plain");
        plain.pair(&[ctx.fingerprint]);
        let plain = plain.start(plain_addr, false).await;
        let Ended::Wait { why, .. } = attempt(&ctx, &candidate(&plain), &slots).await else { panic!("left alone") };
        assert!(why.contains("does not relay"), "{why}");

        // Once the relay's user pairs it, a paired computer is still turned away when this host is
        // registered with as many relays as it allows.
        std::fs::write(
            relay_state.join(StateDir::AUTHORIZED_CLIENTS),
            serde_json::to_vec(&clients(&[ctx.fingerprint])).unwrap(),
        )
        .unwrap();
        let derived = Candidate { explicit: false, ..candidate(&relay) };
        let full = Arc::new(Semaphore::new(0));
        let Ended::Wait { why, wait } = attempt(&ctx, &derived, &full).await else { panic!("turned away by the cap") };
        assert!(why.contains("as many relays"), "{why}");
        assert_eq!(wait, FULL_WAIT);

        // A relay the user listed is not counted: the host registers, and is listed while the
        // connection lasts.
        let attempting = {
            let (ctx, candidate, slots) = (ctx.clone(), candidate(&relay), slots.clone());
            AbortOnDrop(tokio::spawn(async move {
                let _ = attempt(&ctx, &candidate, &slots).await;
            }))
        };
        until("the registration", || !ctx.reach.read().relays.is_empty()).await;
        let listed = ctx.reach.read().relays.clone();
        assert_eq!((listed.len(), listed[0].fingerprint), (1, relay.fingerprint));
        assert!(listed[0].addresses.contains(&relay_addr.to_string()));
        let tunnel = tunnel_addr(&relay.fingerprint.0, NonZeroU16::MIN);
        assert_eq!(ctx.socket.tunnel_relay(tunnel), Some(relay.fingerprint.0), "clients come in at the tunnel");
        assert_eq!(slots.available_permits(), MAX_REGISTRATIONS, "a listed relay takes no slot");

        // The registration ends: the relay is no longer listed and the tunnel is closed.
        drop(attempting);
        until("the registration to end", || ctx.reach.read().relays.is_empty()).await;
        assert_eq!(ctx.socket.tunnel_relay(tunnel), None);

        // A paired computer holds a slot for as long as it holds the registration.
        let attempting = {
            let (ctx, slots) = (ctx.clone(), slots.clone());
            AbortOnDrop(tokio::spawn(async move {
                let _ = attempt(&ctx, &derived, &slots).await;
            }))
        };
        until("the slot to be taken", || slots.available_permits() == MAX_REGISTRATIONS - 1).await;
        drop(attempting);
        until("the slot to be given back", || slots.available_permits() == MAX_REGISTRATIONS).await;
    }

    #[tokio::test]
    async fn paired_computers_are_tried_as_relays_only_while_the_host_has_no_public_address() {
        let (ctx, _scratch) = testing::context("relay-derived");
        let relay = prepare("derived-relay");
        let [relay_addr] = free_addrs();
        relay.pair(&[ctx.fingerprint]);
        let relay = relay.start(relay_addr, true).await;
        // The client side of this computer is paired with it; the user listed nothing.
        let client_dir = ctx.client_state_dir().unwrap();
        std::fs::create_dir_all(&client_dir).unwrap();
        let hosts = [entry("desktop", relay.fingerprint, &relay_addr.to_string())];
        std::fs::write(client_dir.join(StateDir::KNOWN_HOSTS), serde_json::to_vec(&hosts).unwrap()).unwrap();

        // With a public address nobody needs a relay.
        ctx.reach.update(|state| state.set_addresses(AddressKind::Public, vec!["198.51.100.4:51820".into()]));
        let long_ago = Instant::now().checked_sub(Duration::from_secs(3600)).unwrap_or_else(Instant::now);
        let registering = AbortOnDrop(tokio::spawn({
            let ctx = ctx.clone();
            async move {
                let _ = run_registration(ctx, long_ago).await;
            }
        }));
        sleep(Duration::from_millis(1500)).await;
        assert!(ctx.reach.read().relays.is_empty());

        // Without one the paired computer is asked, and it relays.
        ctx.reach.update(|state| state.set_addresses(AddressKind::Public, Vec::new()));
        until("the registration", || !ctx.reach.read().relays.is_empty()).await;

        // An address that turns up later does not cut off what is already established.
        ctx.reach.update(|state| state.set_addresses(AddressKind::Public, vec!["198.51.100.4:51820".into()]));
        sleep(Duration::from_millis(1000)).await;
        assert_eq!(ctx.reach.read().relays.len(), 1);

        // The registering task is aborted: nothing it started goes on.
        drop(registering);
        until("everything to be given up", || ctx.reach.read().relays.is_empty()).await;

        // A relay the user listed is used whether or not the host has a public address.
        let (listed_ctx, _listed_scratch) = testing::context("relay-listed");
        let listed = prepare("listed-relay");
        let [listed_addr] = free_addrs();
        listed.pair(&[listed_ctx.fingerprint]);
        let listed = listed.start(listed_addr, true).await;
        listed_ctx.reach.update(|state| state.set_addresses(AddressKind::Public, vec!["198.51.100.4:51820".into()]));
        listed_ctx.state_dir.save(RELAYS_FILE, &[entry("mine", listed.fingerprint, &listed_addr.to_string())]).unwrap();
        let _registering = AbortOnDrop(tokio::spawn({
            let ctx = listed_ctx.clone();
            async move {
                let _ = run_registration(ctx, Instant::now()).await;
            }
        }));
        until("the registration with the listed relay", || !listed_ctx.reach.read().relays.is_empty()).await;
    }

    // A relay that is not a whole host --------------------------------------------------------

    /// Accepts links the way `server::serve_link` does with nothing but the reach hooks behind
    /// them, and hands the connections to the test so that it can end them from the relay's side.
    async fn serve_links(ctx: ReachContext, accepted: mpsc::UnboundedSender<quinn::Connection>) {
        while let Some(incoming) = ctx.endpoint.accept().await {
            let (ctx, accepted) = (ctx.clone(), accepted.clone());
            tokio::spawn(async move {
                let _ = serve_link(&ctx, incoming, accepted).await;
            });
        }
    }

    async fn serve_link(
        ctx: &ReachContext,
        incoming: quinn::Incoming,
        accepted: mpsc::UnboundedSender<quinn::Connection>,
    ) -> Result<()> {
        let conn = incoming.await?;
        let fingerprint = tls::peer_fingerprint(&conn)?;
        let (mut send, mut recv) = conn.accept_bi().await?;
        wire::read_msg(&mut recv).await?.context("no hello")?;
        let welcome = HostMsg::Welcome {
            version: PROTOCOL_VERSION,
            host_name: "relay".into(),
            codec: Codec::H264,
            width: 0,
            height: 0,
            features: Some(0),
            addresses: Vec::new(),
        };
        send.write_all(&welcome.encode()).await?;
        send.write_all(&reach_message(ctx, &fingerprint).encode()).await?;
        let (control, mut outbox) = ControlSender::channel();
        let client =
            ClientConn { conn: conn.clone(), fingerprint, name: "host".into(), control, via_relay: None, link: true };
        let _ = accepted.send(conn);
        loop {
            tokio::select! {
                body = wire::read_msg(&mut recv) => {
                    let Some(body) = body? else { return Ok(()) };
                    handle_client_msg(ctx, &client, ClientMsg::decode(&body)?).await?;
                }
                message = outbox.recv() => {
                    let Some(message) = message else { return Ok(()) };
                    send.write_all(&message.encode()).await?;
                }
            }
        }
    }

    #[tokio::test]
    async fn a_lost_registration_is_made_again_and_a_mac_address_that_turns_up_is_told() {
        let (relay_ctx, _relay_scratch) = testing::context("relay-restarts");
        relay_ctx.reach.update(|state| state.relay_only = true);
        let (accepted_tx, mut accepted) = mpsc::unbounded_channel();
        let _serving = AbortOnDrop(tokio::spawn(serve_links(relay_ctx.clone(), accepted_tx)));

        let (ctx, _scratch) = testing::context("reconnects");
        let relay_addr = relay_ctx.socket.local_addr().to_string();
        ctx.state_dir.save(RELAYS_FILE, &[entry("relay", relay_ctx.fingerprint, &relay_addr)]).unwrap();
        let _registering = AbortOnDrop(tokio::spawn({
            let ctx = ctx.clone();
            async move {
                let _ = run_registration(ctx, Instant::now()).await;
            }
        }));
        let first = timeout(Duration::from_secs(10), accepted.recv()).await.expect("dialed").unwrap();
        until("the registration", || !ctx.reach.read().relays.is_empty()).await;
        let forwarder = relay_ctx.ext::<RelayState>();
        let registered = forwarder.relay.registered();
        assert_eq!((registered.len(), registered[0].fingerprint, registered[0].mac), (1, ctx.fingerprint, None));

        // The MAC address turns up (the host looks for it after it starts): the relay is told.
        ctx.reach.update(|state| state.mac = Some(MAC));
        until("the relay to know the MAC address", || {
            forwarder.relay.registered().first().is_some_and(|host| host.mac == Some(MAC))
        })
        .await;

        // The relay drops the connection (it restarted, say): the host registers again after a wait.
        first.close(0x99u32.into(), b"restart");
        until("the registration to be lost", || ctx.reach.read().relays.is_empty()).await;
        let second = timeout(Duration::from_secs(20), accepted.recv()).await.expect("dialed again").unwrap();
        assert_ne!(first.stable_id(), second.stable_id());
        until("the registration again", || !ctx.reach.read().relays.is_empty()).await;
        until("the relay to hear the MAC address again", || {
            forwarder.relay.registered().first().is_some_and(|host| host.mac == Some(MAC))
        })
        .await;
    }

    #[tokio::test]
    async fn the_code_a_relay_closes_with_says_how_long_to_stay_away_every_time() {
        let (relay_ctx, _relay_scratch) = testing::context("relay-codes");
        relay_ctx.reach.update(|state| state.relay_only = true);
        let (accepted_tx, mut accepted) = mpsc::unbounded_channel();
        let _serving = AbortOnDrop(tokio::spawn(serve_links(relay_ctx.clone(), accepted_tx)));
        let (ctx, _scratch) = testing::context("codes");
        let candidate = Candidate {
            fingerprint: relay_ctx.fingerprint,
            name: "relay".into(),
            addresses: vec![relay_ctx.socket.local_addr().to_string()],
            explicit: true,
        };
        let slots = Arc::new(Semaphore::new(MAX_REGISTRATIONS));

        // The connection and its control stream end together and are read by different tasks, so
        // which of them tells the host first is chance: five rounds (the relay's allowance of new
        // flows is six) make it very likely that both orders are tried.
        for round in 0..5 {
            let attempting = {
                let (ctx, candidate, slots) = (ctx.clone(), candidate.clone(), slots.clone());
                tokio::spawn(async move { attempt(&ctx, &candidate, &slots).await })
            };
            let conn = timeout(Duration::from_secs(10), accepted.recv()).await.expect("dialed").unwrap();
            until("the registration", || !ctx.reach.read().relays.is_empty()).await;
            conn.close(CLOSE_REPLACED.into(), b"another copy");
            let ended = timeout(Duration::from_secs(10), attempting).await.expect("the attempt ends").unwrap();
            let Ended::Wait { wait, .. } = ended else { panic!("round {round}: the host should stay away") };
            assert_eq!(wait, REPLACED_WAIT);
        }
    }

    #[tokio::test]
    async fn a_control_stream_that_breaks_with_the_connection_does_not_hide_why_it_closed() {
        let (ctx, _scratch) = testing::context("relay-carry");
        // At the end of a registration the control stream has broken and the connection is closed
        // with a code, both ready when `carry` looks. Which it looks at first is chance, so repeat it.
        for round in 0..20u8 {
            let pair = testing::connect(&ctx).await;
            let (send, _recv) = pair.client().open_bi().await.unwrap();
            let (messages, inbox) = mpsc::channel(INBOX_QUEUE);
            messages.send(Err("connection lost".into())).await.unwrap();
            let mut link = Link { send, inbox, reader: tokio::spawn(async {}), reach: None };
            let mut tunnel = ctx.socket.open_tunnel([round + 1; 32], NonZeroU16::MIN).unwrap();
            pair.server.close(CLOSE_REPLACED.into(), b"another copy");
            let _ = pair.client().closed().await;
            let carried = carry(&ctx, pair.client(), &mut link, &mut tunnel, None).await;
            let Ended::Wait { wait, .. } = ended_by(carried, Duration::from_secs(1)) else {
                panic!("round {round}: the close code was lost")
            };
            assert_eq!(wait, REPLACED_WAIT);
        }
    }

    #[tokio::test]
    async fn answers_to_a_device_that_does_not_read_are_dropped_and_no_task_waits_for_it() {
        let (ctx, _scratch) = testing::context("relay-flood");
        let (_link, from, outbox) = device(&ctx, "phone").await;
        // Far more requests than the queue of a control stream holds, and the device reads none of
        // the answers.
        for _ in 0..200 {
            let wake = ClientMsg::Wake { fingerprint: Fingerprint([1; 32]).to_base64() };
            handle_message(&ctx, &from, wake).await.unwrap();
        }
        // Each is answered from a task of its own, and none of them stays to wait: only `from` still
        // holds a way to write to the device's queue.
        until("the tasks to end", || outbox.sender_strong_count() == 1).await;
    }

    #[test]
    fn a_mac_address_is_told_to_the_relay_until_it_accepts_it() {
        let (a, b) = ([1; 6], [2; 6]);
        let mut told = MacTold::new(None);
        assert_eq!(told.to_tell(None), None, "there is nothing to tell");
        assert_eq!(told.to_tell(Some(a)), Some(a), "one that turned up after the registration");
        told.asked(a);
        assert_eq!(told.to_tell(Some(a)), None, "one question at a time");
        told.answered(false);
        assert_eq!(told.to_tell(Some(a)), Some(a), "a no is asked again");
        told.asked(a);
        told.answered(true);
        assert_eq!(told.to_tell(Some(a)), None);
        assert_eq!(told.to_tell(Some(b)), Some(b), "and a change is told");
        assert_eq!(MacTold::new(Some(a)).to_tell(Some(a)), None, "the registration carried it");
    }

    #[tokio::test]
    async fn a_relay_that_talks_without_answering_does_not_hold_the_host_up() {
        let (ctx, _scratch) = testing::context("relay-chatty");
        let link = testing::connect(&ctx).await;
        let server = link.server.clone();
        let _talking = AbortOnDrop(tokio::spawn(async move {
            let Ok((mut send, mut recv)) = server.accept_bi().await else { return };
            let _ = wire::read_msg(&mut recv).await;
            let welcome = HostMsg::Welcome {
                version: PROTOCOL_VERSION,
                host_name: "chatty".into(),
                codec: Codec::H264,
                width: 0,
                height: 0,
                features: Some(0),
                addresses: Vec::new(),
            };
            let reach = HostMsg::Reach {
                addresses: Vec::new(),
                key: [0; 32],
                secret: [0; 16],
                relays: Vec::new(),
                mac: None,
                relays_for_others: true,
            };
            let _ = send.write_all(&welcome.encode()).await;
            let _ = send.write_all(&reach.encode()).await;
            // For ever, and never the answer that was asked for.
            while send.write_all(&HostMsg::Paired.encode()).await.is_ok() {
                sleep(Duration::from_millis(10)).await;
            }
        }));
        let mut opened = Link::open(link.client(), "test device").await.map_err(|e| format!("{e:?}")).expect("a link");
        let began = Instant::now();
        let status = timeout(Duration::from_secs(5), opened.status_within(Duration::from_millis(300))).await;
        let status = status.expect("the wait has a deadline of its own");
        assert!(status.is_err(), "no answer came");
        assert!(began.elapsed() < Duration::from_secs(2), "and the wait ended at its deadline: {:?}", began.elapsed());
    }

    #[tokio::test]
    async fn removing_a_device_is_not_undone_by_a_file_read_afterwards() {
        let (ctx, _scratch) = testing::context("relay-revoke-first");
        let file = ctx.state_dir.path(KNOWN_FILE);
        let records = [KnownRecord::of(&known(1)), KnownRecord::of(&known(2))];
        std::fs::write(&file, serde_json::to_vec(&records).unwrap()).unwrap();
        // The relay switch has been off, so the file was never read when the user removes a device.
        on_revoked(&ctx, &Fingerprint([1; 32]));
        let state = ctx.ext::<RelayState>();
        let remembered: Vec<Fingerprint> = state.relay.known().iter().map(|known| known.fingerprint).collect();
        assert_eq!(remembered, [Fingerprint([2; 32])]);
        let saved: Vec<KnownRecord> = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        assert_eq!(saved, [KnownRecord::of(&known(2))]);
    }

    #[tokio::test]
    async fn a_state_file_that_cannot_be_read_is_not_written_over() {
        let (ctx, _scratch) = testing::context("relay-unreadable");
        let file = ctx.state_dir.path(KNOWN_FILE);
        // Not missing, not damaged: reading it fails (it is a directory).
        std::fs::create_dir(&file).unwrap();
        let state = RelayState::default();
        assert!(!state.load_known(&ctx));
        state.relay.remember(known(1));
        state.save_known(&ctx);
        std::fs::remove_dir(&file).unwrap();
        std::fs::write(&file, serde_json::to_vec(&[KnownRecord::of(&known(9))]).unwrap()).unwrap();

        // Readable at last: what it holds is loaded before anything is written, so nothing is lost.
        state.save_known(&ctx);
        let saved: Vec<KnownRecord> = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        let mut fingerprints: Vec<String> = saved.iter().map(|record| record.fingerprint.clone()).collect();
        fingerprints.sort();
        let mut both = vec![Fingerprint([1; 32]).to_base64(), Fingerprint([9; 32]).to_base64()];
        both.sort();
        assert_eq!(fingerprints, both);
    }

    #[test]
    fn saves_from_several_threads_leave_the_file_with_everything_remembered() {
        let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap();
        let (ctx, _scratch) = runtime.block_on(async { testing::context("relay-saves") });
        let state = ctx.ext::<RelayState>();
        std::thread::scope(|scope| {
            for thread in 0..6u8 {
                let (ctx, state) = (&ctx, &state);
                scope.spawn(move || {
                    for n in 0..10u8 {
                        state.relay.remember(known(thread * 10 + n + 1));
                        state.save_known(ctx);
                    }
                });
            }
        });
        let saved: Vec<KnownRecord> =
            serde_json::from_slice(&std::fs::read(ctx.state_dir.path(KNOWN_FILE)).unwrap()).unwrap();
        assert_eq!(saved.len(), 60, "the last save held the latest state");
    }

    #[tokio::test]
    async fn a_list_that_cannot_be_read_changes_nothing() {
        let (ctx, _scratch) = testing::context("relay-lists");
        assert_eq!(gather(&ctx).map(|found| found.len()), Some(0), "no lists, no relays");
        assert!(allowed(&ctx).is_some());

        // `relays.json` half written: the registrations that exist stay.
        std::fs::write(ctx.state_dir.path(RELAYS_FILE), b"[{\"name\":").unwrap();
        assert!(gather(&ctx).is_none());
        std::fs::remove_file(ctx.state_dir.path(RELAYS_FILE)).unwrap();

        // `known_hosts.json` of the client side that does not read: nobody is dropped for it either.
        let client_dir = ctx.client_state_dir().unwrap();
        std::fs::create_dir_all(&client_dir).unwrap();
        let hosts = client_dir.join(StateDir::KNOWN_HOSTS);
        std::fs::write(&hosts, b"damaged").unwrap();
        assert!(gather(&ctx).is_none());
        assert!(allowed(&ctx).is_none());
        std::fs::write(&hosts, b"[]").unwrap();
        assert!(gather(&ctx).is_some() && allowed(&ctx).is_some());
    }

    #[tokio::test]
    async fn the_forwarder_is_shut_down_when_the_serving_task_is_aborted() {
        let (ctx, _scratch) = testing::context("relay-abort");
        let state = ctx.ext::<RelayState>();
        let (host_link, host, mut outbox) = device(&ctx, "host").await;
        handle_message(&ctx, &host, ClientMsg::RelayRegister { mac: None }).await.unwrap();
        assert!(answer(&mut outbox).await.0);
        let serving = tokio::spawn(serve(ctx.clone()));
        // It has started relaying once it has read its file (and a moment more to take hold).
        until("the serving task to read its file", || *lock(&state.loaded)).await;
        sleep(Duration::from_millis(100)).await;
        serving.abort();
        assert_eq!(closed_with(host_link.client()).await, u64::from(CLOSE_SHUTDOWN));
        assert!(state.relay.registered().is_empty());
    }

    #[test]
    fn text_from_a_peer_is_cleaned_before_it_is_logged() {
        assert_eq!(clean("two\nlines\u{7}\u{1b}[31m"), "twolines[31m");
        assert_eq!(clean(&"x".repeat(1000)).len(), MAX_LOGGED);
        assert_eq!(clean("plain"), "plain");
    }
}
