//! Standalone reach, host side: being reachable from other networks with no mesh VPN and no
//! server anyone runs (`docs/nat-traversal.md`, tickets in `docs/nat-traversal-tickets.md`).
//!
//! This file is the plumbing, written once (ticket E1): the shared [`ReachState`], the
//! [`ReachContext`] every hook receives, the switches and the tasks they start, the dispatch of
//! the new client messages, and the dual-stack [`bind`]. Each feature fills in a file of its own
//! and never touches this one:
//!
//! | file | ticket | hooks |
//! |---|---|---|
//! | `mapping.rs` | E2 | [`mapping::run`] |
//! | `dht.rs`, `secrets.rs` | E3 | [`dht::run`], [`dht::reach_message`], [`secrets::get`], [`secrets::all`], [`secrets::on_paired`], [`secrets::on_revoked`] |
//! | `relay.rs` | E4 | [`relay::serve`], [`relay::register_with`], [`relay::handle_message`], [`relay::busy`] |
//! | `punch.rs`, `poll.rs` | E5 | [`punch::run`], [`punch::respond`], [`poll::run`] |
//! | `wake.rs` | E6 | [`wake::local_mac`], [`wake::same_lan`] |
//!
//! Each of those has its contract in its doc comment (when it runs, what it gets, what it must
//! return). The rules they share:
//!
//! - **Tasks** (`run`, `serve`, `register_with`) are started by [`Runtime`] when their switch is
//!   on and told to end through [`Stop`] when it goes off or the host shuts down. They end by
//!   returning, after their own clean-up (the mapping is removed there). An `Err` is logged and
//!   the task is not restarted until its switch is turned off and on; a task that fails
//!   routinely (no network yet) retries inside itself.
//! - **State** is [`ReachContext::reach`]: read it with `read()`, change it with `update()`, which
//!   tells everyone who `subscribe`d. Never hold a guard across an `.await` or a call into another
//!   hook.
//! - **Nothing may panic on network input**, or on a router, DHT or relay that misbehaves: return
//!   an error, log it with `tracing`.
//! - Per-feature runtime objects that two hooks of one feature share (a task and the handler it
//!   serves) live in [`ReachContext::ext`], one per host, not in statics.
//!
//! Three kinds of connection reach the host (`server::handle_connection` tells them apart by the
//! hello): a *session* (a device watching the screen), a *file manager* (`files_only`) and a
//! *link* (`files_only` and `reach`, or any connection to a `--relay-only` host). Only a session
//! starts a capture or sends another device away; a link carries control messages and nothing
//! else, and its datagrams belong to whoever relays them. The relay service speaks on links.
//! The socket the QUIC endpoint runs on is [`socket::Multiplexer`]: besides ordinary QUIC it
//! carries probes (E5) and relay tunnels (E4).

// This is a binary, where an unused `pub` item is dead code. Most of what is here is for the
// feature tickets to use, so until they have, the lint would only say so.
#![allow(dead_code)]

use std::{
    any::{Any, TypeId},
    collections::HashMap,
    future::Future,
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV6, UdpSocket},
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard},
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};
use tokio::{sync::mpsc, sync::watch, task::JoinHandle};
use velora_nat::{
    addresses::{classify, AddressClass},
    observe::NatType,
};
use velora_protocol::{
    control::{MappingStatus, ReachStatus},
    identity::{Identity, StateDir},
    tls::Fingerprint,
    wire::{
        AddressKind, ClientMsg, HostMsg, DEVICE_SECRET_LEN, MAX_ADDRESSES, MAX_RELAYS, MAX_WELCOME_ADDRESSES,
        REACH_KEY_LEN,
    },
};

pub mod dht;
pub mod mapping;
pub mod poll;
pub mod punch;
pub mod relay;
pub mod secrets;
pub mod socket;
pub mod wake;

use socket::Multiplexer;

/// File in the host's state directory that holds the three switches.
const SWITCHES_FILE: &str = "reach.json";
/// How long a task gets to clean up after it is told to stop (the router mapping is removed there).
const STOP_GRACE: Duration = Duration::from_secs(4);
/// How often the host looks at its own LAN and VPN addresses again.
const HOUSEKEEPING_INTERVAL: Duration = Duration::from_secs(30);
/// How often it looks for its MAC address again once it has one. While it has none it asks after
/// `MAC_RETRY`, then twice as long each time, up to this.
const MAC_REFRESH: Duration = Duration::from_secs(30 * 60);
const MAC_RETRY: Duration = Duration::from_secs(30);
/// The kind code for an address this version cannot place (`AddressKind::Other`).
const UNKNOWN_KIND: u8 = 255;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

// ---------------------------------------------------------------------------------------------
// Switches
// ---------------------------------------------------------------------------------------------

/// The three switches on This PC (`Request::SetReach`), all off until the user turns them on.
/// Kept in `reach.json` in the host's state directory.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Switches {
    /// Ask the router to map the port, tell devices the public and IPv6 addresses, make new
    /// addresses prove themselves with Retry, find a way in through a relay or a punched hole.
    pub standalone: bool,
    /// Other paired devices may connect through this computer to reach their own host.
    pub relay_for_others: bool,
    /// Publish the host's addresses in the BitTorrent Mainline DHT for its paired devices.
    pub dht: bool,
}

impl Switches {
    /// The saved switches; off when nothing was saved or the file is damaged (the host must start
    /// either way).
    pub fn load(state: &StateDir) -> Switches {
        state.load(SWITCHES_FILE).unwrap_or_else(|e| {
            tracing::warn!("ignoring {SWITCHES_FILE}: {e:#}");
            Switches::default()
        })
    }

    pub fn save(&self, state: &StateDir) -> Result<()> {
        state.save(SWITCHES_FILE, self)
    }
}

// ---------------------------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------------------------

/// A relay this host is registered with (E4 writes these).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayEntry {
    pub fingerprint: Fingerprint,
    /// How the launcher shows it: the name the paired device has.
    pub name: String,
    /// `ip:port` addresses the relay answers at, for clients to dial it.
    pub addresses: Vec<String>,
}

/// Who is connected, for E5's poller ("every 2 s for a while after a client was last connected").
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientActivity {
    /// Authenticated connections open now: sessions, file managers and relay links.
    pub connected: usize,
    /// The device that connected last and when: how E5 notices that the client it opened a hole
    /// for has arrived.
    pub last_connect: Option<(Fingerprint, Instant)>,
    /// When the last of them ended.
    pub last_disconnect: Option<Instant>,
}

/// Everything standalone reach knows about this host, behind [`Reach`]. Each field says who
/// writes it; anyone may read it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ReachState {
    /// E1: from `reach.json` and `Request::SetReach`.
    pub switches: Switches,
    /// E1: `velora-host run --relay-only`. Not saved.
    pub relay_only: bool,
    /// Every address the host advertises, with its kind, most useful first (see
    /// [`ReachState::set_addresses`]): E1 keeps the `Lan` and `Vpn` ones, E2 the `Public` and
    /// `V6` ones, E4 the `Relay` ones (through [`ReachState::set_relays`]).
    pub addresses: Vec<(AddressKind, String)>,
    /// E2: the router's port mapping, when there is one.
    pub mapping: Option<MappingStatus>,
    /// E5: how this host's NAT maps ports, once measured.
    pub nat: Option<NatType>,
    /// E5: the endpoint the NAT shows for the QUIC socket (`ip:port` as peers see it), once seen.
    pub observed: Option<SocketAddr>,
    /// E4: the relays this host is registered with.
    pub relays: Vec<RelayEntry>,
    /// E1: where the last device that said so reached the host.
    pub last_reached: Option<(AddressKind, String)>,
    /// E3: the host's DHT public key, once it has one. A pairing link carries it only when set.
    pub dht_key: Option<[u8; REACH_KEY_LEN]>,
    /// E1, from [`wake::local_mac`]: the MAC address of the adapter to wake this PC through.
    pub mac: Option<[u8; 6]>,
    /// E1.
    pub clients: ClientActivity,
}

/// Where a kind of address goes in the list: the most useful for a client first.
fn rank(kind: &AddressKind) -> u8 {
    match kind {
        AddressKind::Lan => 0,
        AddressKind::Vpn => 1,
        AddressKind::Public => 2,
        AddressKind::V6 => 3,
        AddressKind::Relay(_) => 4,
        AddressKind::Other(_) => 5,
    }
}

impl ReachState {
    /// Other devices may connect through this computer: the switch, or `--relay-only`.
    pub fn relays_for_others(&self) -> bool {
        self.switches.relay_for_others || self.relay_only
    }

    /// Replaces every address of `kind` (for `Relay(fingerprint)`, only that relay's) with
    /// `addresses`, and keeps the list in the order of usefulness: LAN, VPN, public, IPv6,
    /// relays. Within a kind the order given is kept.
    pub fn set_addresses(&mut self, kind: AddressKind, addresses: Vec<String>) {
        self.addresses.retain(|(other, _)| *other != kind);
        self.addresses.extend(addresses.into_iter().map(|address| (kind.clone(), address)));
        self.addresses.sort_by_key(|(kind, _)| rank(kind));
    }

    /// The addresses of `kind` (for `Relay(fingerprint)`, that relay's).
    pub fn addresses_of(&self, kind: &AddressKind) -> Vec<String> {
        self.addresses.iter().filter(|(other, _)| other == kind).map(|(_, address)| address.clone()).collect()
    }

    /// Replaces the relays the host is registered with, and their `Relay` addresses.
    pub fn set_relays(&mut self, relays: Vec<RelayEntry>) {
        self.addresses.retain(|(kind, _)| !matches!(kind, AddressKind::Relay(_)));
        for relay in &relays {
            let kind = AddressKind::Relay(relay.fingerprint.to_base64());
            self.addresses.extend(relay.addresses.iter().map(|address| (kind.clone(), address.clone())));
        }
        self.relays = relays;
        self.addresses.sort_by_key(|(kind, _)| rank(kind));
    }

    /// What a welcome lists, for devices without `HostMsg::Reach` (clients before this version
    /// read exactly eight and plain `ip:port`s): the most useful eight, relays left out since a
    /// relay's address is no way to the host without the relay protocol.
    pub fn welcome_addresses(&self) -> Vec<String> {
        let direct = self.addresses.iter().filter(|(kind, _)| !matches!(kind, AddressKind::Relay(_)));
        direct.take(MAX_WELCOME_ADDRESSES).map(|(_, address)| address.clone()).collect()
    }

    /// What `HostMsg::Reach` lists: all of them with their kinds, up to the most the message holds.
    pub fn reach_addresses(&self) -> Vec<(AddressKind, String)> {
        self.addresses.iter().take(MAX_ADDRESSES).cloned().collect()
    }

    /// What This PC shows.
    pub fn status(&self) -> ReachStatus {
        ReachStatus {
            standalone: self.switches.standalone,
            relay_for_others: self.relays_for_others(),
            dht: self.switches.dht,
            mapping: self.mapping.clone(),
            public: self.addresses_of(&AddressKind::Public),
            v6: self.addresses_of(&AddressKind::V6),
            last_reached: self.last_reached.clone(),
            registered_with: self.relays.iter().map(|relay| relay.name.clone()).collect(),
        }
    }
}

/// The shared [`ReachState`]: a cheap handle, clone it freely.
#[derive(Clone)]
pub struct Reach {
    state: Arc<RwLock<ReachState>>,
    changed: Arc<watch::Sender<u64>>,
}

impl Reach {
    pub fn new(state: ReachState) -> Reach {
        Reach { state: Arc::new(RwLock::new(state)), changed: Arc::new(watch::channel(0).0) }
    }

    /// Reads the state. Keep the guard short, and never across an `.await`.
    pub fn read(&self) -> RwLockReadGuard<'_, ReachState> {
        self.state.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// Changes the state. Subscribers are told when `f` changed something, so call it freely
    /// (a write that leaves the state as it was wakes nobody). Same rules as [`Reach::read`].
    pub fn update<R>(&self, f: impl FnOnce(&mut ReachState) -> R) -> R {
        let mut state = self.state.write().unwrap_or_else(PoisonError::into_inner);
        let before = state.clone();
        let result = f(&mut state);
        let changed = *state != before;
        drop(state);
        if changed {
            self.changed.send_modify(|version| *version += 1);
        }
        result
    }

    /// Resolves (`changed().await`) every time the state changes. Several changes close together
    /// may show up as one wake-up. The value counts the changes.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.changed.subscribe()
    }

    /// Notes a device connected; the returned guard notes it left when dropped.
    pub fn client_connected(&self, fingerprint: Fingerprint) -> ClientGuard {
        self.update(|state| {
            state.clients.connected += 1;
            state.clients.last_connect = Some((fingerprint, Instant::now()));
        });
        ClientGuard(self.clone())
    }
}

/// See [`Reach::client_connected`].
pub struct ClientGuard(Reach);

impl Drop for ClientGuard {
    fn drop(&mut self) {
        self.0.update(|state| {
            state.clients.connected = state.clients.connected.saturating_sub(1);
            state.clients.last_disconnect = Some(Instant::now());
        });
    }
}

// ---------------------------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------------------------

/// Tells a task to end. Cloning shares the signal.
#[derive(Clone)]
pub struct Stop {
    stopped: watch::Receiver<bool>,
    /// Keeps the sender of a signal that never fires alive, so it does not read as "gone".
    _keep: Option<Arc<watch::Sender<bool>>>,
}

impl Stop {
    fn new(stopped: watch::Receiver<bool>) -> Stop {
        Stop { stopped, _keep: None }
    }

    /// A signal that never fires, for code that is not a task.
    pub fn never() -> Stop {
        let (tx, rx) = watch::channel(false);
        Stop { stopped: rx, _keep: Some(Arc::new(tx)) }
    }

    pub fn is_stopped(&self) -> bool {
        *self.stopped.borrow()
    }

    /// Resolves when the task must end.
    pub async fn stopped(&self) {
        let mut stopped = self.stopped.clone();
        // An error means the sender is gone, which is as good as being told.
        let _ = stopped.wait_for(|stopped| *stopped).await;
    }

    /// Sleeps `duration` or until stopped, whichever is first; returns whether it was stopped.
    pub async fn sleep(&self, duration: Duration) -> bool {
        tokio::select! {
            () = tokio::time::sleep(duration) => self.is_stopped(),
            () = self.stopped() => true,
        }
    }
}

#[derive(Default)]
struct Ext(Mutex<HashMap<TypeId, Arc<dyn Any + Send + Sync>>>);

/// Everything a hook may use. Cloning is cheap and every clone is the same host.
#[derive(Clone)]
pub struct ReachContext {
    /// The shared state: read it, update it, subscribe to its changes.
    pub reach: Reach,
    /// The host's state directory (`<config>/host`): the identity, the paired devices, and the
    /// files each feature keeps. Its parent holds the client's (`<config>/client`).
    pub state_dir: Arc<StateDir>,
    /// This host's TLS identity: what `velora_protocol::tls::client_config` needs to dial out as
    /// a paired device (E4 does, to a relay).
    pub identity: Arc<Identity>,
    pub fingerprint: Fingerprint,
    /// The address the host was asked to bind (`--bind`), for the addresses it advertises.
    pub bind: SocketAddr,
    /// The QUIC endpoint. E4 and E5 dial out with `connect_with` (from the listening port, which
    /// is the point); nobody else needs it.
    pub endpoint: quinn::Endpoint,
    /// The socket under the endpoint: probes and relay tunnels are opened through it.
    pub socket: Arc<Multiplexer>,
    /// Ends the task this context was given to; never fires outside tasks.
    pub stop: Stop,
    ext: Arc<Ext>,
}

impl ReachContext {
    /// The context of a host; its tasks get clones with their own [`Stop`].
    pub fn new(
        reach: Reach,
        state_dir: Arc<StateDir>,
        identity: Identity,
        bind: SocketAddr,
        endpoint: quinn::Endpoint,
        socket: Arc<Multiplexer>,
    ) -> ReachContext {
        ReachContext {
            reach,
            state_dir,
            fingerprint: identity.fingerprint(),
            identity: Arc::new(identity),
            bind,
            endpoint,
            socket,
            stop: Stop::never(),
            ext: Arc::default(),
        }
    }

    /// The one `T` of this host, made with `T::default()` the first time anyone asks. How a task
    /// and the handler that serves with it share what they build, without a static.
    pub fn ext<T: Default + Send + Sync + 'static>(&self) -> Arc<T> {
        let mut map = lock(&self.ext.0);
        let stored = map.entry(TypeId::of::<T>()).or_insert_with(|| Arc::new(T::default()));
        stored.clone().downcast::<T>().unwrap_or_default()
    }

    /// The port the endpoint listens on.
    pub fn port(&self) -> u16 {
        self.socket.local_addr().port()
    }

    /// The secret that opens the host's DHT record for a paired device (see [`secrets::get`]).
    pub fn device_secret(&self, fingerprint: &Fingerprint) -> Option<[u8; DEVICE_SECRET_LEN]> {
        secrets::get(self, fingerprint)
    }

    /// Where the client side of this computer keeps its state (`known_hosts.json`: the paired
    /// devices this one can dial, relays among them), beside the host's. Not created, and not
    /// necessarily there: under the Windows service the host's state is not in the user's folder.
    pub fn client_state_dir(&self) -> Option<std::path::PathBuf> {
        self.state_dir.dir().parent().map(|config| config.join("client"))
    }
}

impl std::fmt::Debug for ReachContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReachContext").field("fingerprint", &self.fingerprint).field("socket", &self.socket).finish()
    }
}

/// Queues messages for the control stream of one connection, from any task. The connection's own
/// task writes them in order after what it is writing already.
#[derive(Clone)]
pub struct ControlSender(mpsc::Sender<HostMsg>);

/// Messages waiting for one connection's control stream.
const CONTROL_QUEUE: usize = 32;

impl ControlSender {
    pub fn channel() -> (ControlSender, mpsc::Receiver<HostMsg>) {
        let (tx, rx) = mpsc::channel(CONTROL_QUEUE);
        (ControlSender(tx), rx)
    }

    /// Queues `msg`; fails when the connection has ended or [`CONTROL_QUEUE`] messages are
    /// waiting (a peer that does not read).
    pub fn try_send(&self, msg: HostMsg) -> Result<()> {
        self.0.try_send(msg).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => anyhow::anyhow!("the control stream is not being read"),
            mpsc::error::TrySendError::Closed(_) => anyhow::anyhow!("the connection has ended"),
        })
    }

    /// Like [`ControlSender::try_send`], waiting for room instead of failing when the queue is full.
    pub async fn send(&self, msg: HostMsg) -> Result<()> {
        self.0.send(msg).await.map_err(|_| anyhow::anyhow!("the connection has ended"))
    }
}

/// The paired device on the other end of a connection a hook is called for.
#[derive(Clone)]
pub struct ClientConn {
    pub conn: quinn::Connection,
    pub fingerprint: Fingerprint,
    /// The name the device gave itself, control characters removed.
    pub name: String,
    /// Where replies to the device go: its control stream.
    pub control: ControlSender,
    /// The relay (raw fingerprint) the connection came through, when it did; see
    /// [`socket::Multiplexer::open_tunnel`].
    pub via_relay: Option<[u8; 32]>,
}

impl ClientConn {
    /// The device's address, with an IPv4-mapped one in its IPv4 form. Inside the tunnel range
    /// when the device came through a relay (see [`ClientConn::via_relay`]).
    pub fn remote_addr(&self) -> SocketAddr {
        let remote = self.conn.remote_address();
        SocketAddr::new(remote.ip().to_canonical(), remote.port())
    }
}

/// A host's DHT key and the secret that opens its record for one device, as `Reach` carries them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceKeys {
    pub key: [u8; REACH_KEY_LEN],
    pub secret: [u8; DEVICE_SECRET_LEN],
}

/// A client's request that the host open a hole in its NAT toward the client, as a relay passes it
/// on (`HostMsg::PunchRequest`) or the DHT carries it. Fields as on the wire: the receiver
/// parses them and drops what does not parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PunchRequest {
    /// The client's fingerprint (base64url).
    pub from: String,
    /// The client's public `ip:port`.
    pub endpoint: String,
    pub nonce: u64,
}

// ---------------------------------------------------------------------------------------------
// Hooks the host calls
// ---------------------------------------------------------------------------------------------

/// A device was just paired. Called once, right after it was added to the paired list, from a
/// blocking thread with no lock held.
///
/// `secret` is the device secret the pairing link carried, when it carried one (the link holds it
/// only while the host has a DHT key): E3 stores it for the device. When it is `None`, E3 makes
/// one when it first needs it (`dht::reach_message`).
pub fn on_paired(ctx: &ReachContext, fingerprint: &Fingerprint, name: &str, secret: Option<[u8; DEVICE_SECRET_LEN]>) {
    tracing::debug!("reach: '{name}' ({fingerprint}) paired");
    #[cfg(test)]
    ctx.ext::<testing::Calls>().paired.lock().unwrap().push((*fingerprint, secret));
    secrets::on_paired(ctx, fingerprint, secret);
}

/// A device was removed from the paired list through the launcher. Devices removed with
/// `velora-host revoke` while the host runs are not announced: hooks that keep per-device data
/// reconcile it with `authorized_clients.json` when they use it.
pub fn on_revoked(ctx: &ReachContext, fingerprint: &Fingerprint) {
    #[cfg(test)]
    ctx.ext::<testing::Calls>().revoked.lock().unwrap().push(*fingerprint);
    secrets::on_revoked(ctx, fingerprint);
}

/// The `HostMsg::Reach` for the device `fingerprint`, sent right after the welcome to clients that
/// asked for it. The key and secret are all zeros when there is none for this device (the DHT
/// switch is off, or the host has no key yet): readers treat an all-zero key as "no record".
pub fn reach_message(ctx: &ReachContext, fingerprint: &Fingerprint) -> HostMsg {
    // Before the state is read: the hook may use it.
    let keys = dht::reach_message(ctx, fingerprint);
    let state = ctx.reach.read();
    HostMsg::Reach {
        addresses: state.reach_addresses(),
        key: keys.map_or([0; REACH_KEY_LEN], |keys| keys.key),
        secret: keys.map_or([0; DEVICE_SECRET_LEN], |keys| keys.secret),
        relays: state
            .relays
            .iter()
            .take(MAX_RELAYS)
            .map(|relay| (relay.fingerprint.to_base64(), relay.addresses.iter().take(MAX_ADDRESSES).cloned().collect()))
            .collect(),
        mac: state.mac,
        relays_for_others: state.relays_for_others(),
    }
}

/// A client message that only this feature understands arrived on the control stream of a paired
/// device's connection (`Reached`, `RelayRegister`, `RelayTo`, `Wake`, `PunchRequest`). Called
/// from the task that reads that stream, one message at a time: return promptly and spawn
/// anything that takes long. An `Err` is logged; the connection goes on.
///
/// `Reached` is handled here. The other four are for the relay (E4): refused with a
/// `RelayStatus` here while the host does not relay for others, handed to
/// [`relay::handle_message`] when it does.
pub async fn handle_client_msg(ctx: &ReachContext, from: &ClientConn, msg: ClientMsg) -> Result<()> {
    match msg {
        ClientMsg::Reached { address } => {
            let address: String = address.chars().filter(|c| !c.is_control()).collect();
            let kind = from.via_relay.map_or_else(
                || kind_of(&ctx.reach.read(), &address),
                |relay| AddressKind::Relay(Fingerprint(relay).to_base64()),
            );
            let reached = Some((kind, address));
            let level =
                if ctx.reach.read().last_reached == reached { tracing::Level::DEBUG } else { tracing::Level::INFO };
            if let Some((kind, address)) = &reached {
                // A device that connects over and over from the same place is not news.
                match level {
                    tracing::Level::INFO => {
                        tracing::info!("'{}' reached this computer at {} ({address})", from.name, kind_name(kind))
                    }
                    _ => tracing::debug!("'{}' reached this computer again at {address}", from.name),
                }
            }
            ctx.reach.update(|state| state.last_reached = reached);
            Ok(())
        }
        ClientMsg::RelayRegister { .. }
        | ClientMsg::RelayTo { .. }
        | ClientMsg::Wake { .. }
        | ClientMsg::PunchRequest { .. } => {
            if !ctx.reach.read().relays_for_others() {
                let reason = "this computer does not relay for other devices".to_string();
                return from.control.try_send(HostMsg::RelayStatus { ok: false, reason });
            }
            relay::handle_message(ctx, from, msg).await
        }
        // Not ours (a hello can carry the access password: it is never printed).
        _ => {
            tracing::debug!("reach: ignoring a message that is not about reach");
            Ok(())
        }
    }
}

/// The kind of `address` as a device wrote it in `Reached`: the host's own list says when it
/// has the address, else the kind is judged from the address.
fn kind_of(state: &ReachState, address: &str) -> AddressKind {
    if let Some((kind, _)) = state.addresses.iter().find(|(_, own)| own == address) {
        return kind.clone();
    }
    let Ok(addr) = address.parse::<SocketAddr>() else { return AddressKind::Other(UNKNOWN_KIND) };
    let ip = addr.ip().to_canonical();
    if crate::server::is_vpn_mesh(&ip) {
        return AddressKind::Vpn;
    }
    match classify(ip) {
        AddressClass::Public => AddressKind::Public,
        AddressClass::GlobalV6 => AddressKind::V6,
        AddressClass::Private | AddressClass::LinkLocal | AddressClass::Loopback | AddressClass::UniqueLocal => {
            AddressKind::Lan
        }
        AddressClass::Shared | AddressClass::Other => AddressKind::Other(UNKNOWN_KIND),
    }
}

fn kind_name(kind: &AddressKind) -> &'static str {
    match kind {
        AddressKind::Lan => "a LAN address",
        AddressKind::Vpn => "a VPN address",
        AddressKind::Public => "its public address",
        AddressKind::V6 => "an IPv6 address",
        AddressKind::Relay(_) => "a relay",
        AddressKind::Other(_) => "an address of an unknown kind",
    }
}

// ---------------------------------------------------------------------------------------------
// The socket
// ---------------------------------------------------------------------------------------------

/// Binds the host's UDP socket. `[::]` gets a dual-stack socket (`IPV6_V6ONLY` off), so IPv6
/// peers are accepted along with IPv4 ones (reported as IPv4-mapped IPv6, see [`socket`]); where
/// the machine cannot do that, the same port on `0.0.0.0`. Any other address is bound as given,
/// so `--bind 0.0.0.0:7420` and `--bind 192.168.1.5:7420` stay IPv4 only.
pub fn bind(addr: SocketAddr) -> io::Result<UdpSocket> {
    match addr {
        SocketAddr::V6(v6) if v6.ip().is_unspecified() => match bind_dual_stack(v6) {
            // Something else has the port: listening on half of it would hide that, and on Windows
            // the IPv4 half can be had beside a dual-stack socket that holds the whole.
            Err(e) if e.kind() == io::ErrorKind::AddrInUse => Err(e),
            Err(e) => {
                tracing::info!("no dual-stack socket ({e}): listening on IPv4 only");
                UdpSocket::bind(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), addr.port()))
            }
            socket => socket,
        },
        _ => UdpSocket::bind(addr),
    }
}

fn bind_dual_stack(addr: SocketAddrV6) -> io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_only_v6(false)?;
    socket.bind(&SocketAddr::V6(addr).into())?;
    Ok(socket.into())
}

// ---------------------------------------------------------------------------------------------
// Tasks
// ---------------------------------------------------------------------------------------------

/// The long-running parts, each started and stopped by the switches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Task {
    /// E1: keeps the LAN and VPN addresses and the MAC in the state.
    Housekeeping,
    Mapping,
    Punch,
    Poll,
    RelayRegister,
    RelayServe,
    Dht,
}

type TaskFuture = Pin<Box<dyn Future<Output = Result<()>> + Send>>;

impl Task {
    const ALL: [Task; 7] =
        [Task::Housekeeping, Task::Mapping, Task::Punch, Task::Poll, Task::RelayRegister, Task::RelayServe, Task::Dht];

    fn name(self) -> &'static str {
        match self {
            Task::Housekeeping => "housekeeping",
            Task::Mapping => "port mapping",
            Task::Punch => "hole punching",
            Task::Poll => "punch requests",
            Task::RelayRegister => "relay registration",
            Task::RelayServe => "relay service",
            Task::Dht => "DHT record",
        }
    }

    /// Whether the task runs with the state as it is.
    fn wanted(self, state: &ReachState) -> bool {
        let standalone = state.switches.standalone;
        match self {
            Task::Housekeeping => true,
            Task::Mapping | Task::Punch | Task::Poll => standalone,
            // A relay serves; it does not look for one to hide behind.
            Task::RelayRegister => standalone && !state.relay_only,
            Task::RelayServe => state.relays_for_others(),
            Task::Dht => state.switches.dht,
        }
    }

    fn run(self, ctx: ReachContext) -> TaskFuture {
        match self {
            Task::Housekeeping => Box::pin(housekeeping(ctx)),
            Task::Mapping => Box::pin(mapping::run(ctx)),
            Task::Punch => Box::pin(punch::run(ctx)),
            Task::Poll => Box::pin(poll::run(ctx)),
            Task::RelayRegister => Box::pin(relay::register_with(ctx)),
            Task::RelayServe => Box::pin(relay::serve(ctx)),
            Task::Dht => Box::pin(dht::run(ctx)),
        }
    }
}

/// Keeps what the host knows about its own network current: the LAN and VPN addresses (they
/// change when a laptop moves) and the MAC address.
async fn housekeeping(ctx: ReachContext) -> Result<()> {
    let (mut next_mac, mut retry) = (Instant::now(), MAC_RETRY);
    loop {
        refresh_addresses(&ctx).await;
        if Instant::now() >= next_mac {
            // Finding the adapters can take a moment, and a machine with none to wake would ask
            // for ever: ask less and less often.
            let wait = if refresh_mac(&ctx, wake::local_mac).await {
                retry = MAC_RETRY;
                MAC_REFRESH
            } else {
                retry = (retry * 2).min(MAC_REFRESH);
                retry
            };
            next_mac = Instant::now() + wait;
        }
        if ctx.stop.sleep(HOUSEKEEPING_INTERVAL).await {
            return Ok(());
        }
    }
}

/// Looks at the LAN and VPN addresses again and records them (telling subscribers when they changed).
pub async fn refresh_addresses(ctx: &ReachContext) {
    let bind = ctx.bind;
    // The interface list is a system call that can take a moment.
    match tokio::task::spawn_blocking(move || crate::server::local_addresses(bind)).await {
        Ok((lan, vpn)) => ctx.reach.update(|state| {
            state.set_addresses(AddressKind::Lan, lan.into_iter().collect());
            state.set_addresses(AddressKind::Vpn, vpn);
        }),
        Err(e) => tracing::warn!("could not list this computer's addresses: {e}"),
    }
}

/// Asks `lookup` ([`wake::local_mac`]) again; a failure keeps the MAC already known. Returns whether
/// there is one.
async fn refresh_mac(ctx: &ReachContext, lookup: fn() -> Option<[u8; 6]>) -> bool {
    match tokio::task::spawn_blocking(lookup).await {
        Ok(Some(mac)) => ctx.reach.update(|state| state.mac = Some(mac)),
        Ok(None) => {}
        Err(e) => tracing::warn!("could not read this computer's MAC address: {e}"),
    }
    ctx.reach.read().mac.is_some()
}

struct Running {
    stop: watch::Sender<bool>,
    handle: JoinHandle<()>,
}

struct Slot {
    task: Task,
    running: Option<Running>,
    /// The earlier run that is still cleaning up; the next run waits for it.
    stopping: Option<JoinHandle<()>>,
}

struct Tasks {
    slots: Vec<Slot>,
    /// How long a task gets to end after it is told to.
    grace: Duration,
}

impl Tasks {
    fn new() -> Tasks {
        Tasks { slots: Task::ALL.map(|task| Slot { task, running: None, stopping: None }).into(), grace: STOP_GRACE }
    }

    /// Starts the tasks `wanted` and `launch`es them with a [`Stop`] and the earlier run of the
    /// same task to wait for; tells those no longer wanted to stop.
    fn apply(
        &mut self,
        wanted: impl Fn(Task) -> bool,
        launch: impl Fn(Task, Stop, Option<JoinHandle<()>>) -> JoinHandle<()>,
    ) {
        for slot in &mut self.slots {
            match (wanted(slot.task), slot.running.is_some()) {
                (true, false) => {
                    let (stop, stopped) = watch::channel(false);
                    let handle = launch(slot.task, Stop::new(stopped), slot.stopping.take());
                    slot.running = Some(Running { stop, handle });
                }
                (false, true) => {
                    if let Some(running) = slot.running.take() {
                        slot.stopping = Some(stop_in_background(slot.task, running, self.grace));
                    }
                }
                _ => {}
            }
        }
    }

    /// Tells every task to stop and waits for them, up to the grace period in all.
    async fn stop_all(mut self) {
        let mut waiting = Vec::new();
        for slot in &mut self.slots {
            if let Some(running) = slot.running.take() {
                let _ = running.stop.send(true);
                waiting.push((slot.task, running.handle));
            }
            if let Some(stopping) = slot.stopping.take() {
                waiting.push((slot.task, stopping));
            }
        }
        let deadline = tokio::time::Instant::now() + self.grace;
        for (task, mut handle) in waiting {
            if tokio::time::timeout_at(deadline, &mut handle).await.is_err() {
                tracing::warn!("reach: {} did not stop in time", task.name());
                handle.abort();
            }
        }
    }
}

fn stop_in_background(task: Task, mut running: Running, grace: Duration) -> JoinHandle<()> {
    let _ = running.stop.send(true);
    tokio::spawn(async move {
        if tokio::time::timeout(grace, &mut running.handle).await.is_err() {
            tracing::warn!("reach: {} did not stop in time", task.name());
            running.handle.abort();
        }
    })
}

/// Owns the switches and the tasks they start. One per host, in `server::Shared`.
pub struct Runtime {
    ctx: ReachContext,
    tasks: Mutex<Tasks>,
    runtime: tokio::runtime::Handle,
}

impl Runtime {
    /// Needs a Tokio runtime. Starts nothing yet: see [`Runtime::start`].
    pub fn new(ctx: ReachContext) -> Runtime {
        Runtime { ctx, tasks: Mutex::new(Tasks::new()), runtime: tokio::runtime::Handle::current() }
    }

    pub fn context(&self) -> &ReachContext {
        &self.ctx
    }

    pub fn reach(&self) -> &Reach {
        &self.ctx.reach
    }

    /// Starts what the saved switches ask for.
    pub fn start(&self) {
        let switches = self.ctx.reach.read().switches;
        if switches != Switches::default() {
            tracing::info!(
                "standalone reach: {} (relay for others {}, DHT record {})",
                if switches.standalone { "on" } else { "off" },
                if switches.relay_for_others { "on" } else { "off" },
                if switches.dht { "on" } else { "off" },
            );
        }
        self.apply();
    }

    /// Saves and applies new switches: the tasks of those turned on start, those turned off are
    /// told to stop (and finish in the background). Nothing changes when saving fails.
    pub fn set_switches(&self, switches: Switches) -> Result<()> {
        switches.save(&self.ctx.state_dir).context("saving the standalone reach switches")?;
        self.ctx.reach.update(|state| state.switches = switches);
        self.apply();
        Ok(())
    }

    /// Starts and stops tasks to match the state.
    pub fn apply(&self) {
        let state = self.ctx.reach.read().clone();
        lock(&self.tasks).apply(|task| task.wanted(&state), |task, stop, after| self.launch(task, stop, after));
    }

    fn launch(&self, task: Task, stop: Stop, after: Option<JoinHandle<()>>) -> JoinHandle<()> {
        let ctx = ReachContext { stop, ..self.ctx.clone() };
        self.runtime.spawn(async move {
            if let Some(earlier) = after {
                let _ = earlier.await;
            }
            tracing::debug!("reach: {} starts", task.name());
            match task.run(ctx).await {
                Ok(()) => tracing::debug!("reach: {} ended", task.name()),
                Err(e) => tracing::warn!("reach: {} stopped: {e:#}", task.name()),
            }
        })
    }

    /// Tells every task to stop and waits for them (a few seconds at most): the router mapping
    /// is removed here.
    pub async fn stop(&self) {
        let tasks = std::mem::replace(&mut *lock(&self.tasks), Tasks { slots: Vec::new(), grace: STOP_GRACE });
        tasks.stop_all().await;
    }
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

/// A context for tests of the plumbing and of the hooks: a host's pieces on the loopback, with
/// a state directory in the system's temporary folder that goes away when the guard drops.
#[cfg(test)]
pub(crate) mod testing {
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use super::*;

    /// Removes the state directory of a test context when dropped.
    pub struct Scratch(PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    impl Scratch {
        /// The directory the state directory (`host`) is in.
        pub fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    /// What the host called in the hooks of `reach::on_paired` and `reach::on_revoked`, which the
    /// feature tickets fill in, so tests can see the host made the calls: kept in
    /// `ctx.ext::<Calls>()`.
    #[derive(Default)]
    pub struct Calls {
        pub paired: Mutex<Vec<(Fingerprint, Option<[u8; DEVICE_SECRET_LEN]>)>>,
        pub revoked: Mutex<Vec<Fingerprint>>,
    }

    /// A context on `127.0.0.1` with an endpoint that accepts connections but nobody serves.
    /// Needs a Tokio runtime.
    pub fn context(tag: &str) -> (ReachContext, Scratch) {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "velora-reach-{tag}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let state = StateDir::open(Some(dir.clone()), "host").expect("a state directory");
        let identity = Identity::generate().expect("an identity");
        let socket =
            Arc::new(Multiplexer::new(UdpSocket::bind("127.0.0.1:0").expect("a socket")).expect("a multiplexer"));
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(velora_protocol::tls::server_config(&identity).expect("a server config")),
            socket.clone(),
            Arc::new(quinn::TokioRuntime),
        )
        .expect("an endpoint");
        let bind = socket.local_addr();
        let ctx =
            ReachContext::new(Reach::new(ReachState::default()), Arc::new(state), identity, bind, endpoint, socket);
        (ctx, Scratch(dir))
    }

    /// A connection to the context's endpoint, from a throwaway client.
    pub struct Link {
        /// The host's side of it.
        pub server: quinn::Connection,
        /// What keeps the client's side up.
        client: (quinn::Endpoint, quinn::Connection),
    }

    impl Link {
        /// The client's end of the connection.
        pub fn client(&self) -> &quinn::Connection {
            &self.client.1
        }
    }

    /// Connects a throwaway client to `ctx.endpoint` and accepts it.
    pub async fn connect(ctx: &ReachContext) -> Link {
        let identity = Identity::generate().expect("an identity");
        let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().expect("an address")).expect("an endpoint");
        let config = velora_protocol::tls::client_config(&identity, ctx.fingerprint).expect("a client config");
        let connecting = endpoint
            .connect_with(config, ctx.socket.local_addr(), velora_protocol::tls::SERVER_NAME)
            .expect("a connection attempt");
        let accepting = async { ctx.endpoint.accept().await.expect("the endpoint is open").await };
        let (client, server) = tokio::join!(connecting, accepting);
        Link { server: server.expect("accepted"), client: (endpoint, client.expect("connected")) }
    }

    /// The device `link` stands for, as the hooks are given it, and the queue its control stream
    /// would write from.
    pub fn client_conn(link: &Link, name: &str) -> (ClientConn, mpsc::Receiver<HostMsg>) {
        let (control, outbox) = ControlSender::channel();
        let client = ClientConn {
            conn: link.server.clone(),
            fingerprint: Fingerprint([9; 32]),
            name: name.into(),
            control,
            via_relay: None,
        };
        (client, outbox)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use super::*;

    fn addr(kind: AddressKind, text: &str) -> (AddressKind, String) {
        (kind, text.to_string())
    }

    fn texts(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn relay(n: u8, addresses: &[&str]) -> RelayEntry {
        RelayEntry { fingerprint: Fingerprint([n; 32]), name: format!("relay {n}"), addresses: texts(addresses) }
    }

    #[test]
    fn addresses_are_kept_in_order_of_usefulness_and_replaced_by_kind() {
        let mut state = ReachState::default();
        state.set_addresses(AddressKind::V6, texts(&["[2001:db8::1]:7420"]));
        state.set_addresses(AddressKind::Public, texts(&["198.51.100.4:51820"]));
        state.set_addresses(AddressKind::Vpn, texts(&["100.64.0.2:7420", "100.64.0.3:7420"]));
        state.set_addresses(AddressKind::Lan, texts(&["192.168.1.9:7420"]));
        let listed: Vec<&str> = state.addresses.iter().map(|(_, a)| a.as_str()).collect();
        assert_eq!(
            listed,
            ["192.168.1.9:7420", "100.64.0.2:7420", "100.64.0.3:7420", "198.51.100.4:51820", "[2001:db8::1]:7420"]
        );
        // A kind is replaced whole, and withdrawn with an empty list.
        state.set_addresses(AddressKind::Vpn, texts(&["100.64.0.9:7420"]));
        state.set_addresses(AddressKind::Public, Vec::new());
        assert_eq!(state.addresses_of(&AddressKind::Vpn), texts(&["100.64.0.9:7420"]));
        assert!(state.addresses_of(&AddressKind::Public).is_empty());
        assert_eq!(state.addresses.len(), 3);
    }

    #[test]
    fn the_welcome_leaves_relays_out_and_holds_eight_and_reach_holds_sixteen() {
        let mut state = ReachState::default();
        let many: Vec<String> = (1..=12).map(|n| format!("100.64.0.{n}:7420")).collect();
        state.set_addresses(AddressKind::Vpn, many);
        state.set_relays(vec![relay(1, &["198.51.100.20:7420"]), relay(2, &["198.51.100.21:7420"])]);
        let welcome = state.welcome_addresses();
        assert_eq!(welcome.len(), MAX_WELCOME_ADDRESSES);
        assert!(welcome.iter().all(|a| a.starts_with("100.64.0.")), "no relay address in a welcome: {welcome:?}");
        assert_eq!(state.reach_addresses().len(), 14, "everything fits in a Reach");
        state.set_addresses(AddressKind::Public, vec!["198.51.100.4:51820".to_string(); 5]);
        let listed = state.reach_addresses();
        assert_eq!(listed.len(), MAX_ADDRESSES);
        assert!(listed.iter().all(|(kind, _)| !matches!(kind, AddressKind::Relay(_))), "relays are cut first");
    }

    #[test]
    fn relay_addresses_follow_the_relays_the_host_is_registered_with() {
        let mut state = ReachState::default();
        state.set_addresses(AddressKind::Lan, texts(&["192.168.1.9:7420"]));
        state
            .set_relays(vec![relay(1, &["198.51.100.20:7420", "198.51.100.21:7420"]), relay(2, &["203.0.113.5:7420"])]);
        let first = AddressKind::Relay(Fingerprint([1; 32]).to_base64());
        assert_eq!(state.addresses_of(&first), texts(&["198.51.100.20:7420", "198.51.100.21:7420"]));
        assert_eq!(state.addresses.len(), 4);
        state.set_relays(vec![relay(2, &["203.0.113.5:7420"])]);
        assert!(state.addresses_of(&first).is_empty());
        assert_eq!(state.addresses.len(), 2);
        assert_eq!(state.status().registered_with, texts(&["relay 2"]));
    }

    #[test]
    fn the_status_shows_the_state() {
        let mut state = ReachState {
            switches: Switches { standalone: true, relay_for_others: false, dht: true },
            mapping: Some(MappingStatus {
                protocol: "upnp".into(),
                external: "198.51.100.4:51820".into(),
                public: true,
                lease_secs: 3600,
            }),
            last_reached: Some(addr(AddressKind::Public, "198.51.100.4:51820")),
            ..Default::default()
        };
        state.set_addresses(AddressKind::Public, texts(&["198.51.100.4:51820"]));
        state.set_addresses(AddressKind::V6, texts(&["[2001:db8::1]:7420"]));
        let status = state.status();
        assert_eq!((status.standalone, status.relay_for_others, status.dht), (true, false, true));
        assert_eq!((status.public, status.v6), (texts(&["198.51.100.4:51820"]), texts(&["[2001:db8::1]:7420"])));
        assert_eq!(status.mapping, state.mapping);
        assert_eq!(status.last_reached, state.last_reached);
        // A relay-only host relays whatever the switch says.
        state.relay_only = true;
        assert!(state.status().relay_for_others);
    }

    #[tokio::test]
    async fn an_update_wakes_subscribers_only_when_something_changed() {
        let reach = Reach::new(ReachState::default());
        let mut changes = reach.subscribe();
        reach.update(|state| state.mac = None);
        assert!(!changes.has_changed().unwrap(), "writing what is already there is no change");
        reach.update(|state| state.mac = Some([1, 2, 3, 4, 5, 6]));
        assert!(changes.has_changed().unwrap());
        changes.changed().await.unwrap();
        let guard = reach.client_connected(Fingerprint([1; 32]));
        assert_eq!(reach.read().clients.connected, 1);
        assert_eq!(reach.read().clients.last_connect.map(|(who, _)| who), Some(Fingerprint([1; 32])));
        drop(guard);
        let clients = reach.read().clients.clone();
        assert_eq!(clients.connected, 0);
        assert!(clients.last_disconnect.is_some());
    }

    #[tokio::test]
    async fn the_switches_are_saved_and_a_damaged_file_means_off() {
        let (ctx, scratch) = testing::context("switches");
        let state = &ctx.state_dir;
        assert_eq!(Switches::load(state), Switches::default());
        let on = Switches { standalone: true, relay_for_others: true, dht: false };
        on.save(state).unwrap();
        assert_eq!(Switches::load(state), on);
        let file = scratch.path().join("host").join(SWITCHES_FILE);
        std::fs::write(&file, "not json").unwrap();
        assert_eq!(Switches::load(state), Switches::default());
        // Fields a later version added do not stop an earlier one reading the rest.
        std::fs::write(&file, r#"{"standalone":true,"future":1}"#).unwrap();
        assert_eq!(Switches::load(state), Switches { standalone: true, ..Default::default() });
    }

    #[tokio::test]
    async fn stop_ends_a_sleep_and_never_fires_for_code_that_is_not_a_task() {
        let never = Stop::never();
        assert!(!never.is_stopped());
        assert!(!never.sleep(Duration::from_millis(30)).await);
        let (tx, rx) = watch::channel(false);
        let stop = Stop::new(rx);
        let sleeper = tokio::spawn({
            let stop = stop.clone();
            async move { stop.sleep(Duration::from_secs(60)).await }
        });
        tx.send(true).unwrap();
        assert!(sleeper.await.unwrap(), "told to stop during the sleep");
        stop.stopped().await;
        // A signal whose sender went away reads as stopped.
        let (tx, rx) = watch::channel(false);
        drop(tx);
        Stop::new(rx).stopped().await;
    }

    /// What the tasks of a test did, in order.
    #[derive(Clone, Default)]
    struct Journal(Arc<Mutex<Vec<String>>>);

    impl Journal {
        fn note(&self, line: String) {
            lock(&self.0).push(line);
        }

        fn lines(&self) -> Vec<String> {
            lock(&self.0).clone()
        }

        /// The lines once there are `count` of them (or after two seconds).
        async fn until(&self, count: usize) -> Vec<String> {
            for _ in 0..200 {
                if self.lines().len() >= count {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            self.lines()
        }

        /// A launcher whose tasks note `up` when they start and `down` when they end, `slow` after
        /// being told to.
        fn launcher(&self, slow: Duration) -> impl Fn(Task, Stop, Option<JoinHandle<()>>) -> JoinHandle<()> {
            let (journal, runs) = (self.clone(), Arc::new(Mutex::new(0usize)));
            move |task, stop, after| {
                let run = {
                    let mut runs = lock(&runs);
                    *runs += 1;
                    *runs
                };
                let journal = journal.clone();
                tokio::spawn(async move {
                    if let Some(earlier) = after {
                        let _ = earlier.await;
                    }
                    journal.note(format!("{} up {run}", task.name()));
                    stop.stopped().await;
                    tokio::time::sleep(slow).await;
                    journal.note(format!("{} down {run}", task.name()));
                })
            }
        }
    }

    #[tokio::test]
    async fn tasks_start_when_wanted_and_are_told_to_stop_when_not() {
        let journal = Journal::default();
        let launch = journal.launcher(Duration::ZERO);
        let mut tasks = Tasks::new();
        tasks.apply(|task| task == Task::Mapping, &launch);
        assert_eq!(journal.until(1).await, ["port mapping up 1"]);
        // Applying again with the same wish starts nothing twice; a second task starts beside it.
        tasks.apply(|task| matches!(task, Task::Mapping | Task::Dht), &launch);
        assert_eq!(journal.until(2).await, ["port mapping up 1", "DHT record up 2"]);
        tasks.apply(|task| task == Task::Dht, &launch);
        assert_eq!(journal.until(3).await[2], "port mapping down 1");
        tasks.stop_all().await;
        let lines = journal.lines();
        assert_eq!(lines.len(), 4, "{lines:?}");
        assert_eq!(lines[3], "DHT record down 2");
    }

    #[tokio::test]
    async fn a_task_still_cleaning_up_is_waited_for_before_the_same_task_starts_again() {
        let journal = Journal::default();
        let launch = journal.launcher(Duration::from_millis(150));
        let mut tasks = Tasks::new();
        tasks.apply(|task| task == Task::Mapping, &launch);
        journal.until(1).await;
        // Off and on again at once: the new run must not begin while the old one removes its mapping.
        tasks.apply(|_| false, &launch);
        tasks.apply(|task| task == Task::Mapping, &launch);
        assert_eq!(journal.until(3).await, ["port mapping up 1", "port mapping down 1", "port mapping up 2"]);
        tasks.stop_all().await;
        assert_eq!(journal.lines().last().unwrap(), "port mapping down 2");
    }

    #[tokio::test]
    async fn a_task_that_ignores_stop_is_given_up_on_after_the_grace_period() {
        let mut tasks = Tasks { grace: Duration::from_millis(100), ..Tasks::new() };
        let launch = |_: Task, _: Stop, _: Option<JoinHandle<()>>| tokio::spawn(std::future::pending::<()>());
        tasks.apply(|task| task == Task::Punch, launch);
        let started = Instant::now();
        tasks.stop_all().await;
        assert!(started.elapsed() < Duration::from_secs(2), "stop_all must not wait for a task that never ends");
    }

    #[test]
    fn what_each_task_needs() {
        let mut state = ReachState::default();
        let wanted = |state: &ReachState| Task::ALL.into_iter().filter(|t| t.wanted(state)).collect::<Vec<_>>();
        assert_eq!(wanted(&state), [Task::Housekeeping], "everything is off until the user turns it on");
        state.switches.standalone = true;
        assert_eq!(wanted(&state), [Task::Housekeeping, Task::Mapping, Task::Punch, Task::Poll, Task::RelayRegister]);
        state.switches = Switches { dht: true, ..Default::default() };
        assert_eq!(wanted(&state), [Task::Housekeeping, Task::Dht], "the DHT record has its own switch");
        state.switches = Switches { relay_for_others: true, ..Default::default() };
        assert_eq!(wanted(&state), [Task::Housekeeping, Task::RelayServe]);
        // A relay serves; it does not look for a relay to hide behind.
        state.relay_only = true;
        state.switches = Switches { standalone: true, ..Default::default() };
        assert_eq!(wanted(&state), [Task::Housekeeping, Task::Mapping, Task::Punch, Task::Poll, Task::RelayServe]);
    }

    #[tokio::test]
    async fn setting_the_switches_saves_them_and_starts_the_tasks() {
        let (ctx, _scratch) = testing::context("runtime");
        let runtime = Runtime::new(ctx.clone());
        runtime.start();
        let on = Switches { standalone: true, relay_for_others: false, dht: true };
        runtime.set_switches(on).unwrap();
        assert_eq!(ctx.reach.read().switches, on);
        assert_eq!(Switches::load(&ctx.state_dir), on, "saved for the next start");
        // The hooks are still stubs: tasks that end at once are not started over and over.
        tokio::time::sleep(Duration::from_millis(50)).await;
        runtime.apply();
        runtime.stop().await;
    }

    #[tokio::test]
    async fn switches_that_cannot_be_saved_change_nothing() {
        let (ctx, scratch) = testing::context("unsaved");
        let runtime = Runtime::new(ctx.clone());
        // A directory where the file goes: the rename over it fails.
        std::fs::create_dir_all(scratch.path().join("host").join(SWITCHES_FILE)).unwrap();
        let result = runtime.set_switches(Switches { standalone: true, ..Default::default() });
        assert!(result.is_err());
        assert_eq!(ctx.reach.read().switches, Switches::default());
    }

    #[tokio::test]
    async fn housekeeping_records_the_hosts_own_addresses() {
        let (ctx, _scratch) = testing::context("housekeeping");
        refresh_addresses(&ctx).await;
        let lan = ctx.reach.read().addresses_of(&AddressKind::Lan);
        assert_eq!(lan, vec![ctx.bind.to_string()], "bound to one address, which is the one advertised");
    }

    #[tokio::test]
    async fn a_failed_mac_lookup_keeps_the_mac_already_known() {
        let (ctx, _scratch) = testing::context("mac");
        assert!(!refresh_mac(&ctx, || None).await, "none yet");
        assert!(refresh_mac(&ctx, || Some([1, 2, 3, 4, 5, 6])).await);
        assert_eq!(ctx.reach.read().mac, Some([1, 2, 3, 4, 5, 6]));
        assert!(refresh_mac(&ctx, || None).await, "an adapter that is briefly gone is not forgotten");
        assert_eq!(ctx.reach.read().mac, Some([1, 2, 3, 4, 5, 6]));
        assert!(refresh_mac(&ctx, || Some([6, 5, 4, 3, 2, 1])).await);
        assert_eq!(ctx.reach.read().mac, Some([6, 5, 4, 3, 2, 1]), "a changed adapter is followed");
    }

    #[tokio::test]
    async fn control_senders_queue_in_order_and_refuse_when_full_or_closed() {
        let (sender, mut queue) = ControlSender::channel();
        for n in 0..CONTROL_QUEUE {
            sender.try_send(HostMsg::RelayStatus { ok: true, reason: n.to_string() }).unwrap();
        }
        assert!(sender.try_send(HostMsg::Paired).is_err(), "a peer that does not read cannot make the host buffer");
        let first = queue.recv().await.unwrap();
        assert_eq!(first, HostMsg::RelayStatus { ok: true, reason: "0".into() });
        sender.send(HostMsg::Paired).await.unwrap();
        drop(queue);
        assert!(sender.try_send(HostMsg::Paired).is_err());
        assert!(sender.send(HostMsg::Paired).await.is_err());
    }

    #[tokio::test]
    async fn ext_gives_every_caller_one_value_per_type() {
        #[derive(Default)]
        struct Counter(Mutex<u32>);
        #[derive(Default)]
        struct Other(u8);
        let (ctx, _scratch) = testing::context("ext");
        *lock(&ctx.ext::<Counter>().0) += 1;
        *lock(&ctx.clone().ext::<Counter>().0) += 1;
        assert_eq!(*lock(&ctx.ext::<Counter>().0), 2, "a clone of the context is the same host");
        assert_eq!(ctx.ext::<Other>().0, 0);
        let (another, _other_scratch) = testing::context("ext2");
        assert_eq!(*lock(&another.ext::<Counter>().0), 0, "another host has its own");
    }

    #[tokio::test]
    async fn reached_is_recorded_with_its_kind() {
        let (ctx, _scratch) = testing::context("reached");
        let link = testing::connect(&ctx).await;
        let (from, _outbox) = testing::client_conn(&link, "phone");
        ctx.reach.update(|state| state.set_addresses(AddressKind::Public, texts(&["198.51.100.4:51820"])));
        let reached = |address: &str| ClientMsg::Reached { address: address.into() };
        let last = |ctx: &ReachContext| ctx.reach.read().last_reached.clone().unwrap();

        // An address the host lists is the kind it lists it as.
        handle_client_msg(&ctx, &from, reached("198.51.100.4:51820")).await.unwrap();
        assert_eq!(last(&ctx), addr(AddressKind::Public, "198.51.100.4:51820"));
        // One it does not is judged by what it is.
        for (written, kind) in [
            ("192.168.1.20:7420", AddressKind::Lan),
            ("100.101.102.103:7420", AddressKind::Vpn),
            ("[fd7a:115c:a1e0::1]:7420", AddressKind::Vpn),
            ("[2804:14c:5b82::1]:7420", AddressKind::V6),
            ("8.8.4.4:7420", AddressKind::Public),
            ("not an address", AddressKind::Other(UNKNOWN_KIND)),
        ] {
            handle_client_msg(&ctx, &from, reached(written)).await.unwrap();
            assert_eq!(last(&ctx), addr(kind, written));
        }
        // Control characters do not get into the log or the status.
        handle_client_msg(&ctx, &from, reached("192.168.1.20:7420\n\u{7}")).await.unwrap();
        assert_eq!(last(&ctx).1, "192.168.1.20:7420");
        // Through a relay, whatever the device calls the address.
        let relayed = ClientConn { via_relay: Some([5; 32]), ..from.clone() };
        handle_client_msg(&ctx, &relayed, reached("anything")).await.unwrap();
        assert_eq!(last(&ctx).0, AddressKind::Relay(Fingerprint([5; 32]).to_base64()));
    }

    #[tokio::test]
    async fn relay_requests_are_refused_unless_the_host_relays_for_others() {
        let (ctx, _scratch) = testing::context("refused");
        let link = testing::connect(&ctx).await;
        let (from, mut outbox) = testing::client_conn(&link, "phone");
        let requests = [
            ClientMsg::RelayRegister { mac: None },
            ClientMsg::RelayTo { fingerprint: "f".into() },
            ClientMsg::Wake { fingerprint: "f".into() },
            ClientMsg::PunchRequest { to: "f".into(), endpoint: "e".into(), nonce: 1 },
        ];
        for request in requests.clone() {
            handle_client_msg(&ctx, &from, request).await.unwrap();
            let Some(HostMsg::RelayStatus { ok: false, reason }) = outbox.recv().await else { panic!("a refusal") };
            assert_eq!(reason, "this computer does not relay for other devices");
        }
        assert!(outbox.try_recv().is_err());

        // With the switch on they reach E4's hook, which (still a stub) says it cannot yet.
        ctx.reach.update(|state| state.switches.relay_for_others = true);
        for request in requests {
            handle_client_msg(&ctx, &from, request).await.unwrap();
            let Some(HostMsg::RelayStatus { ok: false, reason }) = outbox.recv().await else { panic!("a status") };
            assert_ne!(reason, "this computer does not relay for other devices");
        }
        // Anything else is not for reach.
        handle_client_msg(&ctx, &from, ClientMsg::RequestKeyframe).await.unwrap();
        assert!(outbox.try_recv().is_err());
    }

    #[tokio::test]
    async fn the_reach_message_carries_the_state_and_zeros_where_there_are_no_keys() {
        let (ctx, _scratch) = testing::context("message");
        ctx.reach.update(|state| {
            state.set_addresses(AddressKind::Lan, texts(&["192.168.1.9:7420"]));
            state.set_addresses(AddressKind::Public, texts(&["198.51.100.4:51820"]));
            state.set_relays(vec![relay(3, &["203.0.113.5:7420"])]);
            state.mac = Some([0, 1, 2, 3, 4, 5]);
            state.switches.relay_for_others = true;
        });
        let message = reach_message(&ctx, &Fingerprint([9; 32]));
        let HostMsg::Reach { addresses, key, secret, relays, mac, relays_for_others } = message else {
            panic!("a Reach")
        };
        assert_eq!(
            addresses,
            vec![
                addr(AddressKind::Lan, "192.168.1.9:7420"),
                addr(AddressKind::Public, "198.51.100.4:51820"),
                addr(AddressKind::Relay(Fingerprint([3; 32]).to_base64()), "203.0.113.5:7420"),
            ]
        );
        assert_eq!((key, secret), ([0; REACH_KEY_LEN], [0; DEVICE_SECRET_LEN]), "no DHT record yet");
        assert_eq!(relays, vec![(Fingerprint([3; 32]).to_base64(), texts(&["203.0.113.5:7420"]))]);
        assert_eq!((mac, relays_for_others), (Some([0, 1, 2, 3, 4, 5]), true));
    }

    #[test]
    fn bind_makes_the_unspecified_ipv6_address_dual_stack_and_leaves_others_alone() {
        // IPv4 addresses stay IPv4: `--bind 0.0.0.0:..` is the way to ask for that.
        let v4 = bind("127.0.0.1:0".parse().unwrap()).unwrap();
        assert!(v4.local_addr().unwrap().is_ipv4());
        let unspecified_v4 = bind("0.0.0.0:0".parse().unwrap()).unwrap();
        assert!(unspecified_v4.local_addr().unwrap().is_ipv4());

        let any = bind(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0)).unwrap();
        let local = any.local_addr().unwrap();
        if local.is_ipv4() {
            return eprintln!("no IPv6 on this machine: the fallback to IPv4 is what was tested");
        }
        // Dual-stack: an IPv4 datagram arrives, as its IPv4-mapped form.
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        any.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        sender.send_to(b"hi", ("127.0.0.1", local.port())).unwrap();
        let mut buf = [0u8; 8];
        let (n, from) = any.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hi");
        assert_eq!(from.ip().to_canonical(), sender.local_addr().unwrap().ip());
        // The port is taken now.
        assert!(bind(local).is_err());
    }
}
