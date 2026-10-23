//! The relay itself: register a host, pair a client with it, copy datagrams both ways.
//!
//! A relay is a PC that both ends can reach: a paired PC with "let my other PCs connect through
//! this one" on, or `velora-host run --relay-only` on a VPS. A host H that cannot be reached
//! directly dials out to it and *registers*; a client C that wants H dials out to it too and asks
//! to be *relayed to* H. From then on the datagrams of C's connection and of H's carry the QUIC
//! packets of the connection C and H make with each other (the "inner" connection), framed by
//! [`crate::frame`], and the relay copies them across. It sees ciphertext only: C and H run the
//! normal Velora handshake through it, with the same pinned certificates.
//!
//! The two legs are separate QUIC connections whose datagram sizes differ and change as each
//! path's MTU is discovered, so a datagram is never forwarded as it came. Each leg has a
//! [`Reassembler`] for what arrives and a [`Splitter`] for what leaves: a packet is put back
//! together on one leg and framed again, for the size the other leg allows at that moment. A lost
//! chunk loses the packet, like any loss; the inner QUIC recovers it.
//!
//! # What the caller does
//!
//! The caller (the host's `reach/relay.rs`) owns everything before and around this module: the
//! TLS handshake, the check that the device is on the paired list, the Velora hello, and reading
//! the control stream. It hands this module an authenticated [`quinn::Connection`] together with
//! what the device asked for, and writes the answer back on the stream it read the request from.
//! [`Relay::handle`] does that mapping for the four messages that concern a relay:
//!
//! | message | call | answer |
//! |---|---|---|
//! | `RelayRegister { mac }` | [`Relay::register`] | `RelayStatus` |
//! | `RelayTo { fingerprint }` | [`Relay::relay_to`] | `RelayStatus` |
//! | `Wake { fingerprint }` | [`Relay::wake`] | `RelayStatus` |
//! | `PunchRequest { to, endpoint, nonce }` | [`Relay::punch`] | `RelayStatus` |
//!
//! Who a connection is comes from its TLS certificate, never from the message, so a device cannot
//! register or relay as another. Nothing here checks the paired list: only connections of paired
//! devices may be passed in.
//!
//! # One client per host
//!
//! The datagrams carry no flow id, so the host's registration connection can serve one client at
//! a time: replies from the host go to whoever is paired. A newer [`Relay::relay_to`] takes the
//! host over and closes the older client's connection ([`CLOSE_TAKEN_OVER`]), the way a direct
//! connection to a host takes over from the previous device. A client that wants several inner
//! connections to the same host (a session and a file transfer, say) runs them as one inner
//! endpoint over one outer connection.
//!
//! # Waking
//!
//! A sleeping PC has no connection to the relay, so the relay remembers each host's MAC address
//! and last address when it registers ([`Relay::known`]) and wakes from that memory. The magic
//! packet goes out on the relay's own network that holds the host's last address; a host that
//! registered from elsewhere cannot be woken from here ([`Refused::NotOnNetwork`]).
//!
//! # Punch requests
//!
//! [`Relay::punch`] hands a client's request to open a hole in its NAT to the registered host as
//! one `HostMsg::PunchRequest` on a unidirectional stream that the relay opens on the host's
//! registration connection. A stream, not a datagram, because every datagram on that connection
//! belongs to the inner connection and a lost one would lose the request silently. The host
//! accepts unidirectional streams on that connection, reads one length-prefixed message from each
//! (`wire::read_msg`, then `HostMsg::decode`) and passes the request on to the hole puncher.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex, MutexGuard,
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use velora_nat::wake::{self, Mac};
use velora_protocol::{
    tls::{self, Fingerprint},
    wire::{ClientMsg, HostMsg},
};

use crate::frame::{Reassembler, SplitError, Splitter};

/// Application error code of a host's connection closed because a newer connection of the same
/// device registered in its place.
pub const CLOSE_REPLACED: u32 = 0x20;
/// Application error code of a client's connection closed because the host it was relayed to
/// disconnected from the relay (or registered again).
pub const CLOSE_HOST_GONE: u32 = 0x21;
/// Application error code of a client's connection closed because another client (or the same
/// device on a newer connection) took the host over.
pub const CLOSE_TAKEN_OVER: u32 = 0x22;
/// Application error code of a connection closed because its device was removed from the relay
/// ([`Relay::remove`]).
pub const CLOSE_REMOVED: u32 = 0x23;
/// Application error code of a connection closed because the relay stopped ([`Relay::shutdown`]).
pub const CLOSE_SHUTDOWN: u32 = 0x24;

/// How often the reassembly table of a leg is swept while no datagram arrives.
const SWEEP_EVERY: Duration = Duration::from_secs(1);
/// How long a punch request may take to be handed to the host's connection.
const PUNCH_TIMEOUT: Duration = Duration::from_secs(2);
/// The longest [`Config::refill`] taken as it is.
const LONGEST_REFILL: Duration = Duration::from_secs(24 * 60 * 60);
/// Most devices the rate limiter tracks; past it, devices whose allowance has recovered are
/// forgotten (they would start with a full allowance anyway).
const MAX_TRACKED: usize = 1024;

/// What a relay may do, and how much.
#[derive(Debug, Clone)]
pub struct Config {
    /// New flows (a registration, a pairing, a wake, a punch request) one device may start at
    /// once. Its allowance is refilled by one every [`Config::refill`].
    pub burst: u32,
    /// How long a device waits for one more new flow after using up its burst. Read as at least a
    /// millisecond and at most a day.
    pub refill: Duration,
    /// Hosts registered at once. A host registering again replaces its old entry and does not
    /// count twice.
    pub max_hosts: usize,
    /// Hosts remembered for waking after they disconnect (at least [`Config::max_hosts`]).
    pub max_known: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self { burst: 6, refill: Duration::from_secs(5), max_hosts: 256, max_known: 256 }
    }
}

/// Why the relay did not do what a device asked. The `Display` text is the `reason` of the
/// `HostMsg::RelayStatus` that answers it: plain words, fit for a log or a message to the user.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refused {
    #[error("the connection has no device certificate")]
    NoIdentity,
    #[error("that is not a device fingerprint")]
    BadFingerprint,
    #[error("a device cannot be relayed to itself")]
    ToSelf,
    #[error("this connection is already registered or relaying")]
    ConnectionInUse,
    #[error("this connection does not carry datagrams, which a relay needs")]
    NoDatagrams,
    #[error("too many requests from this device; try again in {retry_secs} s")]
    RateLimited { retry_secs: u64 },
    #[error("this relay is serving as many devices as it can")]
    Full,
    /// The target never registered with this relay (as far as it remembers).
    #[error("this relay does not know that device; it has never registered here")]
    UnknownHost,
    /// The target registered before but has no connection to the relay now: it is off, asleep, or
    /// has lost its network.
    #[error("that device is not connected to this relay now")]
    NotRegistered,
    #[error("that device did not tell this relay its MAC address, so it cannot be woken from here")]
    NoMac,
    #[error("that device is not on a network of this relay, which cannot wake it")]
    NotOnNetwork,
    #[error("the wake-up packet could not be sent")]
    WakeFailed,
    #[error("that is not an address to open a hole toward")]
    BadEndpoint,
    #[error("that device did not take the request")]
    HostNotAccepting,
}

/// Why a magic packet did not go out, as a [`Waker`] reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WakeError {
    /// None of the relay's networks holds the host's address.
    NotOnNetwork,
    /// A network holds it but sending failed; the text is for the log.
    Failed(String),
}

/// Sends the magic packet. [`LanWaker`] is the real one; [`Relay::with_waker`] takes another, for
/// tests that must not touch the network.
pub trait Waker: Send + Sync + 'static {
    /// Wakes the PC with this MAC address, whose last address was `host`. Returns how many
    /// datagrams went out. Blocking.
    fn wake(&self, mac: &Mac, host: Ipv4Addr) -> Result<usize, WakeError>;
}

/// Wakes a host on the network of this PC that holds its address, through `velora_nat::wake`.
///
/// That is `wake::wake_lan_of` taken apart, so that "not on a network of this PC" and "sending
/// failed" come back as different answers.
#[derive(Debug, Clone, Copy, Default)]
pub struct LanWaker;

impl Waker for LanWaker {
    fn wake(&self, mac: &Mac, host: Ipv4Addr) -> Result<usize, WakeError> {
        let networks = wake::wake_networks();
        let network = wake::network_of(&networks, host).ok_or(WakeError::NotOnNetwork)?;
        wake::wake_on(mac, &network).map_err(|e| WakeError::Failed(format!("{e:#}")))
    }
}

/// What a relay forwarded in one direction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Traffic {
    /// Inner packets sent on.
    pub packets: u64,
    /// Outer datagrams they became (more than `packets` when the receiving leg is too small to
    /// take them whole).
    pub datagrams: u64,
    /// Bytes of inner packets sent on.
    pub bytes: u64,
    /// Inner packets that could not be sent on: nobody paired, the leg gone, a packet too big
    /// for it, or its send failing.
    pub dropped: u64,
}

/// A host registered with the relay, for the launcher's status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registered {
    pub fingerprint: Fingerprint,
    /// Where its connection comes from, as the relay sees it.
    pub addr: SocketAddr,
    /// The MAC address it can be woken with, if it said one.
    pub mac: Option<Mac>,
    /// How long ago it registered.
    pub connected_for: Duration,
    /// The device relayed to it now.
    pub client: Option<Fingerprint>,
    /// From the client to the host, since the host registered.
    pub to_host: Traffic,
    /// From the host to the client, since the host registered.
    pub to_client: Traffic,
}

/// What the relay remembers of a host after it disconnects, to wake it. [`Relay::known`] lists
/// these for the caller to keep across restarts, and [`Relay::remember`] loads them back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Known {
    pub fingerprint: Fingerprint,
    pub mac: Option<Mac>,
    /// The address its connection came from the last time it was registered.
    pub addr: IpAddr,
}

/// The relay's table of registered hosts and the clients paired with them. Cheap to clone (the
/// clones share the table); there is no global state, so tests make as many as they like.
///
/// [`Relay::register`] and [`Relay::relay_to`] start tasks and so must be called from within a
/// tokio runtime.
#[derive(Clone)]
pub struct Relay {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for Relay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = locked(&self.shared.state);
        f.debug_struct("Relay").field("hosts", &state.hosts.len()).field("known", &state.known.len()).finish()
    }
}

impl Default for Relay {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

impl Relay {
    /// A relay that wakes through the real network ([`LanWaker`]).
    pub fn new(config: Config) -> Self {
        Self::with_waker(config, Arc::new(LanWaker))
    }

    /// A relay that sends its magic packets through `waker`.
    pub fn with_waker(config: Config, waker: Arc<dyn Waker>) -> Self {
        let limiter = RateLimiter::new(config.burst, config.refill);
        let state = State { hosts: HashMap::new(), known: HashMap::new(), limiter, next_id: 0 };
        Self { shared: Arc::new(Shared { config, waker, state: Mutex::new(state) }) }
    }

    /// Registers the host on `conn` as reachable through this relay, and remembers `mac` for
    /// waking it. The host keeps `conn` open (the 2 s keepalive holds its NAT mapping) and its
    /// datagrams reach whichever client is relayed to it; the entry goes away when the
    /// connection closes.
    ///
    /// Registering again from a new connection replaces the old entry (a reconnect): the old
    /// connection is closed ([`CLOSE_REPLACED`]) and the client relayed to it, if any, is sent
    /// away ([`CLOSE_HOST_GONE`]). Registering again on the same connection only updates the MAC.
    /// A `mac` of `None` never forgets the one the host said before.
    ///
    /// Refused when the connection is a client's or takes no datagrams, when the relay is full,
    /// and when the device has started too many new flows lately.
    pub fn register(&self, conn: &quinn::Connection, mac: Option<Mac>) -> Result<(), Refused> {
        let device = identity(conn)?;
        let now = Instant::now();
        let addr = conn.remote_address();
        let (registration, replaced) = {
            let mut state = locked(&self.shared.state);
            state.limiter.take(device, now).map_err(rate_limited)?;
            if conn.max_datagram_size().is_none() {
                return Err(Refused::NoDatagrams);
            }
            let current = state.hosts.get(&device).cloned();
            let mac = mac.or_else(|| state.known.get(&device).and_then(|known| known.mac));
            if let Some(current) = current.as_ref().filter(|c| c.leg.conn.stable_id() == conn.stable_id()) {
                *locked(&current.mac) = mac;
                state.remember(device, mac, addr.ip(), now, &self.shared.config);
                return Ok(());
            }
            if state.is_client(conn) {
                return Err(Refused::ConnectionInUse);
            }
            if current.is_none() && state.hosts.len() >= self.shared.config.max_hosts {
                return Err(Refused::Full);
            }
            state.next_id += 1;
            let registration = Arc::new(Registration {
                id: state.next_id,
                fingerprint: device,
                leg: Arc::new(Leg::new(conn.clone())),
                mac: Mutex::new(mac),
                since: now,
                pairing: Mutex::new(None),
                counters: Arc::new(Counters::default()),
            });
            state.hosts.insert(device, registration.clone());
            state.remember(device, mac, addr.ip(), now, &self.shared.config);
            (registration, current)
        };
        match replaced {
            Some(old) => {
                tracing::info!("{device} registered again from {addr}; the old connection is closed");
                self.shared.end_registration(&old, CLOSE_REPLACED, CLOSE_HOST_GONE, "registered again");
            }
            None => tracing::info!("{device} registered with the relay from {addr}"),
        }
        tokio::spawn(host_pump(self.shared.clone(), registration));
        Ok(())
    }

    /// Pairs the client on `conn` with the registered host `target` (a fingerprint as it is on the
    /// wire, base64url): from now on the datagrams of `conn` are inner packets for the host and
    /// the host's come back on `conn`. Forwarding starts when this returns, so the caller sends
    /// its `RelayStatus` right away.
    ///
    /// A host serves one client at a time: pairing replaces the client paired before, whose
    /// connection is closed ([`CLOSE_TAKEN_OVER`]). The pairing ends when `conn` closes, or when
    /// the host disconnects (the client's connection is then closed with [`CLOSE_HOST_GONE`]).
    ///
    /// Refused when `target` is not a fingerprint, is the caller itself, is not registered
    /// ([`Refused::UnknownHost`] if the relay never saw it, [`Refused::NotRegistered`] if it is
    /// offline now), when `conn` is already registered or relaying or takes no datagrams, and
    /// when the device has started too many new flows lately.
    pub fn relay_to(&self, conn: &quinn::Connection, target: &str) -> Result<(), Refused> {
        let device = identity(conn)?;
        let now = Instant::now();
        let (host, pairing, previous) = {
            let mut state = locked(&self.shared.state);
            state.limiter.take(device, now).map_err(rate_limited)?;
            let target = parse_fingerprint(target)?;
            if target == device {
                return Err(Refused::ToSelf);
            }
            if conn.max_datagram_size().is_none() {
                return Err(Refused::NoDatagrams);
            }
            let registered = state.hosts.get(&device).is_some_and(|h| h.leg.conn.stable_id() == conn.stable_id());
            if registered || state.is_client(conn) {
                return Err(Refused::ConnectionInUse);
            }
            let host = state.host(&target)?;
            let pairing = Arc::new(Pairing {
                client: device,
                leg: Arc::new(Leg::new(conn.clone())),
                host: host.leg.clone(),
                counters: host.counters.clone(),
                live: AtomicBool::new(true),
            });
            let previous = locked(&host.pairing).replace(pairing.clone());
            (host, pairing, previous)
        };
        if let Some(previous) = previous {
            tracing::info!("{} takes {} over from {}", device, host.fingerprint, previous.client);
            previous.end(CLOSE_TAKEN_OVER, "another device took over this host");
        } else {
            tracing::info!("{} is relayed to {}", device, host.fingerprint);
        }
        tokio::spawn(client_pump(host, pairing));
        Ok(())
    }

    /// Wakes the host `target` (a fingerprint as it is on the wire) with the MAC address it
    /// registered with, on the network of this PC that holds its address. Works for a host that
    /// is no longer connected, which is the point: a sleeping PC has no connection. Returns how
    /// many datagrams went out. `from` is the device asking.
    ///
    /// Refused when the host is not known, said no MAC, or is not on a network of this PC (see
    /// [`Refused::NotOnNetwork`]), and when sending fails. Sending is blocking and runs on the
    /// blocking pool.
    pub async fn wake(&self, from: &quinn::Connection, target: &str) -> Result<usize, Refused> {
        let device = identity(from)?;
        let (target, mac, addr) = {
            let mut state = locked(&self.shared.state);
            state.limiter.take(device, Instant::now()).map_err(rate_limited)?;
            let target = parse_fingerprint(target)?;
            let (mac, addr) = state.wake_target(&target)?;
            (target, mac, addr)
        };
        let Some(host) = wake_address(addr) else { return Err(Refused::NotOnNetwork) };
        let waker = self.shared.waker.clone();
        match tokio::task::spawn_blocking(move || waker.wake(&mac, host)).await {
            Ok(Ok(sent)) => {
                tracing::info!("{device} woke {target} ({sent} datagrams)");
                Ok(sent)
            }
            Ok(Err(WakeError::NotOnNetwork)) => Err(Refused::NotOnNetwork),
            Ok(Err(WakeError::Failed(why))) => {
                tracing::warn!("waking {target} for {device} failed: {why}");
                Err(Refused::WakeFailed)
            }
            Err(e) => {
                tracing::warn!("waking {target} for {device} failed: {e}");
                Err(Refused::WakeFailed)
            }
        }
    }

    /// Hands the registered host `to` (a fingerprint as it is on the wire) a request from the
    /// client on `from` to open a hole in the host's NAT toward `endpoint`, the client's public
    /// `ip:port`, with the client's `nonce`. The host receives a `HostMsg::PunchRequest` whose
    /// `from` is the client's certificate fingerprint (see the module docs for how). Returns
    /// when the message is queued on the host's connection, not when the host has read it.
    ///
    /// Refused for an `endpoint` that is not a unicast `ip:port`, for a host that is not
    /// registered, and when the host's connection does not take the stream within two seconds.
    pub async fn punch(&self, from: &quinn::Connection, to: &str, endpoint: &str, nonce: u64) -> Result<(), Refused> {
        let device = identity(from)?;
        let (host, endpoint) = {
            let mut state = locked(&self.shared.state);
            state.limiter.take(device, Instant::now()).map_err(rate_limited)?;
            let to = parse_fingerprint(to)?;
            let endpoint = parse_endpoint(endpoint)?;
            (state.host(&to)?, endpoint)
        };
        let message =
            HostMsg::PunchRequest { from: device.to_base64(), endpoint: endpoint.to_string(), nonce }.encode();
        let sent = async {
            let mut stream = host.leg.conn.open_uni().await.map_err(|e| e.to_string())?;
            stream.write_all(&message).await.map_err(|e| e.to_string())?;
            stream.finish().map_err(|e| e.to_string())
        };
        match tokio::time::timeout(PUNCH_TIMEOUT, sent).await {
            Ok(Ok(())) => {
                tracing::debug!("punch request of {device} for {} passed on", host.fingerprint);
                Ok(())
            }
            Ok(Err(why)) => {
                tracing::debug!("punch request for {} not delivered: {why}", host.fingerprint);
                Err(Refused::HostNotAccepting)
            }
            Err(_) => {
                tracing::debug!("punch request for {} not delivered: timed out", host.fingerprint);
                Err(Refused::HostNotAccepting)
            }
        }
    }

    /// Answers a control message for the device on `conn`: `Some(HostMsg::RelayStatus)` for the
    /// four messages that concern a relay (see the module docs), `None` for any other, which the
    /// caller handles itself. The caller writes the answer on the stream it read the message from.
    ///
    /// ```ignore
    /// if let Some(answer) = relay.handle(&conn, &msg).await {
    ///     send.write_all(&answer.encode()).await?;
    /// }
    /// ```
    pub async fn handle(&self, conn: &quinn::Connection, msg: &ClientMsg) -> Option<HostMsg> {
        let outcome = match msg {
            ClientMsg::RelayRegister { mac } => self.register(conn, *mac),
            ClientMsg::RelayTo { fingerprint } => self.relay_to(conn, fingerprint),
            ClientMsg::Wake { fingerprint } => self.wake(conn, fingerprint).await.map(drop),
            ClientMsg::PunchRequest { to, endpoint, nonce } => self.punch(conn, to, endpoint, *nonce).await,
            _ => return None,
        };
        Some(match outcome {
            Ok(()) => HostMsg::RelayStatus { ok: true, reason: String::new() },
            Err(refused) => HostMsg::RelayStatus { ok: false, reason: refused.to_string() },
        })
    }

    /// The hosts registered now, longest connected first.
    pub fn registered(&self) -> Vec<Registered> {
        let now = Instant::now();
        let state = locked(&self.shared.state);
        let mut hosts: Vec<Registered> = state
            .hosts
            .values()
            .map(|host| Registered {
                fingerprint: host.fingerprint,
                addr: canonical(host.leg.conn.remote_address()),
                mac: *locked(&host.mac),
                connected_for: now.saturating_duration_since(host.since),
                client: locked(&host.pairing).as_ref().map(|pairing| pairing.client),
                to_host: host.counters.to_host.snapshot(),
                to_client: host.counters.to_client.snapshot(),
            })
            .collect();
        hosts.sort_by_key(|host| std::cmp::Reverse(host.connected_for));
        hosts
    }

    /// What the relay remembers for waking hosts: every host that registered with it and that
    /// the table still holds, connected or not. For the caller to keep across restarts.
    pub fn known(&self) -> Vec<Known> {
        let state = locked(&self.shared.state);
        state
            .known
            .iter()
            .map(|(&fingerprint, entry)| Known { fingerprint, mac: entry.mac, addr: entry.addr })
            .collect()
    }

    /// Loads an entry saved from an earlier run. An entry the relay already has is kept, since it
    /// is newer.
    pub fn remember(&self, known: Known) {
        let mut state = locked(&self.shared.state);
        if !state.known.contains_key(&known.fingerprint) {
            state.remember(known.fingerprint, known.mac, known.addr, Instant::now(), &self.shared.config);
        }
    }

    /// Drops everything held for `device`: its registration (the client relayed to it is sent
    /// away with [`CLOSE_HOST_GONE`]), the pairing it has as a client, and what is remembered for
    /// waking it. For when the user removes a paired device. The device's own connections are
    /// closed with [`CLOSE_REMOVED`].
    pub fn remove(&self, device: &Fingerprint) {
        let (registration, pairings) = {
            let mut state = locked(&self.shared.state);
            state.known.remove(device);
            let registration = state.hosts.remove(device);
            let pairings: Vec<Arc<Pairing>> = state
                .hosts
                .values()
                .filter_map(|host| locked(&host.pairing).take_if(|p| p.client == *device))
                .collect();
            (registration, pairings)
        };
        if let Some(registration) = registration {
            self.shared.end_registration(&registration, CLOSE_REMOVED, CLOSE_HOST_GONE, "device removed");
        }
        for pairing in pairings {
            pairing.end(CLOSE_REMOVED, "device removed");
        }
    }

    /// Stops serving: every registered host and every paired client is disconnected
    /// ([`CLOSE_SHUTDOWN`]) and the table is emptied. What is remembered for waking stays.
    pub fn shutdown(&self) {
        let hosts: Vec<Arc<Registration>> = {
            let mut state = locked(&self.shared.state);
            let hosts: Vec<_> = state.hosts.drain().map(|(_, host)| host).collect();
            for host in &hosts {
                state.last_seen(host);
            }
            hosts
        };
        for host in hosts {
            self.shared.end_registration(&host, CLOSE_SHUTDOWN, CLOSE_SHUTDOWN, "relay stopped");
        }
    }
}

/// Locks `mutex`, ignoring poison: a panic elsewhere must not stop the relay from serving.
fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The certificate fingerprint of the device on `conn`.
fn identity(conn: &quinn::Connection) -> Result<Fingerprint, Refused> {
    tls::peer_fingerprint(conn).map_err(|_| Refused::NoIdentity)
}

fn parse_fingerprint(text: &str) -> Result<Fingerprint, Refused> {
    Fingerprint::from_base64(text).map_err(|_| Refused::BadFingerprint)
}

/// `addr` with an IPv4 address written the IPv6 way (as a dual-stack socket reports one) in its IPv4 form.
fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

/// The IPv4 address a magic packet can be aimed at, if `addr` is one. That is an IPv4 address, or
/// one written the IPv6 way, as a dual-stack socket (the host's) reports the peers that connect over
/// IPv4. A magic packet is a broadcast on an IPv4 network, so an IPv6 address has none.
fn wake_address(addr: IpAddr) -> Option<Ipv4Addr> {
    match addr.to_canonical() {
        IpAddr::V4(host) => Some(host),
        IpAddr::V6(_) => None,
    }
}

/// A punch endpoint must be somewhere a packet can go: a port, and a unicast address. An IPv4
/// address in its IPv6 form comes back as plain IPv4.
fn parse_endpoint(text: &str) -> Result<SocketAddr, Refused> {
    let endpoint: SocketAddr = text.trim().parse().map_err(|_| Refused::BadEndpoint)?;
    let ip = endpoint.ip().to_canonical();
    if endpoint.port() == 0 || ip.is_unspecified() || ip.is_multicast() || ip == Ipv4Addr::BROADCAST {
        return Err(Refused::BadEndpoint);
    }
    Ok(SocketAddr::new(ip, endpoint.port()))
}

/// The refusal for a device that has to wait `retry_after`, rounded up to whole seconds.
fn rate_limited(retry_after: Duration) -> Refused {
    let secs = retry_after.as_secs() + u64::from(retry_after.subsec_nanos() > 0);
    Refused::RateLimited { retry_secs: secs.max(1) }
}

struct Shared {
    config: Config,
    waker: Arc<dyn Waker>,
    state: Mutex<State>,
}

/// Lock order: `State`, then a registration's `pairing`; never the other way round, and no lock
/// is held across an await.
struct State {
    hosts: HashMap<Fingerprint, Arc<Registration>>,
    known: HashMap<Fingerprint, KnownEntry>,
    limiter: RateLimiter,
    next_id: u64,
}

struct KnownEntry {
    mac: Option<Mac>,
    addr: IpAddr,
    seen: Instant,
}

impl State {
    /// Whether `conn` is the connection of a client that is paired with a host.
    fn is_client(&self, conn: &quinn::Connection) -> bool {
        let id = conn.stable_id();
        self.hosts.values().any(|host| locked(&host.pairing).as_ref().is_some_and(|p| p.leg.conn.stable_id() == id))
    }

    /// The registered host `target`, or why there is none.
    fn host(&self, target: &Fingerprint) -> Result<Arc<Registration>, Refused> {
        match self.hosts.get(target) {
            Some(host) => Ok(host.clone()),
            None if self.known.contains_key(target) => Err(Refused::NotRegistered),
            None => Err(Refused::UnknownHost),
        }
    }

    /// The MAC and the last address to wake `target` with.
    fn wake_target(&self, target: &Fingerprint) -> Result<(Mac, IpAddr), Refused> {
        let (mac, addr) = match (self.hosts.get(target), self.known.get(target)) {
            (Some(host), _) => (*locked(&host.mac), host.leg.conn.remote_address().ip()),
            (None, Some(entry)) => (entry.mac, entry.addr),
            (None, None) => return Err(Refused::UnknownHost),
        };
        Ok((mac.ok_or(Refused::NoMac)?, addr))
    }

    /// Notes where `host` was last seen: that address is what a wake uses once it is gone.
    fn last_seen(&mut self, host: &Registration) {
        if let Some(entry) = self.known.get_mut(&host.fingerprint) {
            entry.addr = host.leg.conn.remote_address().ip().to_canonical();
            entry.seen = Instant::now();
        }
    }

    /// Keeps what is needed to wake `device` later. When the memory is full the host that has been
    /// gone longest is forgotten.
    fn remember(&mut self, device: Fingerprint, mac: Option<Mac>, addr: IpAddr, now: Instant, config: &Config) {
        let capacity = config.max_known.max(config.max_hosts);
        if self.known.len() >= capacity && !self.known.contains_key(&device) {
            let oldest = self
                .known
                .iter()
                .filter(|(fingerprint, _)| !self.hosts.contains_key(fingerprint))
                .min_by_key(|(_, entry)| entry.seen)
                .map(|(&fingerprint, _)| fingerprint);
            if let Some(oldest) = oldest {
                self.known.remove(&oldest);
            }
        }
        self.known.insert(device, KnownEntry { mac, addr: addr.to_canonical(), seen: now });
    }
}

impl Shared {
    /// Ends a registration: it leaves the table (unless a newer one already took its place), its
    /// connection is closed with `host_code`, and the client relayed to it, if any, with
    /// `client_code`. Safe to call more than once.
    fn end_registration(&self, host: &Arc<Registration>, host_code: u32, client_code: u32, why: &str) {
        {
            let mut state = locked(&self.state);
            if state.hosts.get(&host.fingerprint).is_some_and(|current| current.id == host.id) {
                state.hosts.remove(&host.fingerprint);
                state.last_seen(host);
            }
        }
        host.leg.conn.close(host_code.into(), why.as_bytes());
        if let Some(pairing) = locked(&host.pairing).take() {
            pairing.end(client_code, "the host disconnected from the relay");
        }
    }
}

/// One side of a pairing: a connection and the framing of what is sent on it.
struct Leg {
    conn: quinn::Connection,
    /// Used by whichever pump sends on this leg, which is the other leg's.
    splitter: Mutex<Splitter>,
}

impl Leg {
    fn new(conn: quinn::Connection) -> Self {
        Self { conn, splitter: Mutex::new(Splitter::new()) }
    }

    /// Frames `packet` for the datagram size this leg allows right now and sends it. Returns how
    /// many datagrams went out. Never waits: when the leg is slow, quinn drops its oldest queued
    /// datagrams, which is what a datagram path does.
    fn forward(&self, packet: &[u8]) -> Result<usize, Undelivered> {
        let max = self.conn.max_datagram_size().ok_or(Undelivered::NoDatagrams)?;
        let datagrams = locked(&self.splitter).split(packet, max)?;
        let count = datagrams.len();
        for datagram in datagrams {
            self.conn.send_datagram(datagram)?;
        }
        Ok(count)
    }
}

/// Why a packet was not sent on.
#[derive(Debug, thiserror::Error)]
enum Undelivered {
    #[error("the connection takes no datagrams")]
    NoDatagrams,
    #[error("cannot be framed: {0}")]
    Frame(#[from] SplitError),
    #[error("the send failed: {0}")]
    Send(#[from] quinn::SendDatagramError),
}

/// A host's registration: its connection, and the client paired with it now.
struct Registration {
    /// Tells this registration from a newer one of the same host.
    id: u64,
    fingerprint: Fingerprint,
    leg: Arc<Leg>,
    mac: Mutex<Option<Mac>>,
    since: Instant,
    pairing: Mutex<Option<Arc<Pairing>>>,
    counters: Arc<Counters>,
}

/// A client paired with a host.
struct Pairing {
    client: Fingerprint,
    leg: Arc<Leg>,
    /// Where the client's packets go.
    host: Arc<Leg>,
    counters: Arc<Counters>,
    /// Cleared when the pairing ends, so a pump that is still draining stops forwarding.
    live: AtomicBool,
}

impl Pairing {
    /// Ends the pairing: nothing more is forwarded, and the client's connection is closed with
    /// `code`.
    fn end(&self, code: u32, why: &str) {
        if self.live.swap(false, Ordering::AcqRel) {
            self.leg.conn.close(code.into(), why.as_bytes());
        }
    }
}

#[derive(Default)]
struct Counters {
    to_host: Direction,
    to_client: Direction,
}

#[derive(Default)]
struct Direction {
    packets: AtomicU64,
    datagrams: AtomicU64,
    bytes: AtomicU64,
    dropped: AtomicU64,
}

impl Direction {
    fn snapshot(&self) -> Traffic {
        Traffic {
            packets: self.packets.load(Ordering::Relaxed),
            datagrams: self.datagrams.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
        }
    }

    /// Sends `packet` on through `to` and counts what happened.
    fn deliver(&self, to: &Leg, packet: &Bytes) {
        match to.forward(packet) {
            Ok(datagrams) => {
                self.packets.fetch_add(1, Ordering::Relaxed);
                self.datagrams.fetch_add(datagrams as u64, Ordering::Relaxed);
                self.bytes.fetch_add(packet.len() as u64, Ordering::Relaxed);
            }
            Err(why) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                tracing::trace!("relayed packet of {} bytes dropped: {why}", packet.len());
            }
        }
    }

    fn drop_packet(&self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
}

/// Reads a leg's datagrams until its connection ends, puts the packets back together and hands
/// each to `deliver`. One `Reassembler` per leg, as the framing needs.
async fn pump(conn: &quinn::Connection, mut deliver: impl FnMut(Bytes)) {
    let mut reassembler = Reassembler::new();
    let mut sweep = tokio::time::interval(SWEEP_EVERY);
    sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            datagram = conn.read_datagram() => match datagram {
                Ok(datagram) => {
                    if let Some(packet) = reassembler.push(datagram, Instant::now()) {
                        deliver(packet);
                    }
                }
                Err(_) => break,
            },
            _ = sweep.tick() => reassembler.expire(Instant::now()),
        }
    }
    tracing::debug!(
        "leg closed ({} split packets lost, {} datagrams that were not frames)",
        reassembler.dropped(),
        reassembler.malformed()
    );
}

/// Forwards the host's datagrams to the client paired with it, for as long as the host's
/// connection lasts; drops them while nobody is paired. Then removes the registration.
async fn host_pump(shared: Arc<Shared>, host: Arc<Registration>) {
    let to_client = &host.counters.to_client;
    pump(&host.leg.conn, |packet| {
        let pairing = locked(&host.pairing).clone();
        match pairing {
            Some(pairing) if pairing.live.load(Ordering::Acquire) => to_client.deliver(&pairing.leg, &packet),
            _ => to_client.drop_packet(),
        }
    })
    .await;
    tracing::info!("{} left the relay", host.fingerprint);
    shared.end_registration(&host, CLOSE_HOST_GONE, CLOSE_HOST_GONE, "connection closed");
}

/// Forwards a client's datagrams to the host it is paired with, for as long as the client's
/// connection lasts. Then ends the pairing, if it is still the host's.
async fn client_pump(host: Arc<Registration>, pairing: Arc<Pairing>) {
    let to_host = &pairing.counters.to_host;
    pump(&pairing.leg.conn, |packet| {
        if pairing.live.load(Ordering::Acquire) {
            to_host.deliver(&pairing.host, &packet);
        } else {
            to_host.drop_packet();
        }
    })
    .await;
    pairing.live.store(false, Ordering::Release);
    let mut slot = locked(&host.pairing);
    if slot.as_ref().is_some_and(|current| Arc::ptr_eq(current, &pairing)) {
        *slot = None;
        tracing::info!("{} is no longer relayed to {}", pairing.client, host.fingerprint);
    }
}

/// A token bucket per device: each gets [`Config::burst`] new flows at once and one more every
/// [`Config::refill`]. Keyed by the certificate fingerprint rather than the address, so devices
/// behind one NAT do not share an allowance and a device cannot dodge its own by moving.
struct RateLimiter {
    burst: f64,
    refill: Duration,
    buckets: HashMap<Fingerprint, Bucket>,
}

struct Bucket {
    tokens: f64,
    at: Instant,
}

impl RateLimiter {
    fn new(burst: u32, refill: Duration) -> Self {
        let refill = refill.clamp(Duration::from_millis(1), LONGEST_REFILL);
        Self { burst: f64::from(burst.max(1)), refill, buckets: HashMap::new() }
    }

    /// Takes one token for `device` at `now`. When there is none, says how long until there is.
    fn take(&mut self, device: Fingerprint, now: Instant) -> Result<(), Duration> {
        let (burst, refill) = (self.burst, self.refill);
        if self.buckets.len() >= MAX_TRACKED && !self.buckets.contains_key(&device) {
            self.buckets.retain(|_, bucket| tokens(bucket, now, burst, refill) < burst);
            if self.buckets.len() >= MAX_TRACKED {
                return Err(refill);
            }
        }
        let bucket = self.buckets.entry(device).or_insert(Bucket { tokens: burst, at: now });
        bucket.tokens = tokens(bucket, now, burst, refill);
        bucket.at = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(())
        } else {
            Err(refill.mul_f64(1.0 - bucket.tokens))
        }
    }
}

/// What `bucket` holds at `now`.
fn tokens(bucket: &Bucket, now: Instant, burst: f64, refill: Duration) -> f64 {
    let earned = now.saturating_duration_since(bucket.at).as_secs_f64() / refill.as_secs_f64();
    (bucket.tokens + earned).min(burst)
}

#[cfg(test)]
mod tests {
    use std::{
        io::{self, IoSliceMut},
        net::{Ipv6Addr, SocketAddrV6},
        pin::Pin,
        sync::atomic::AtomicUsize,
        task::{Context, Poll},
    };

    use quinn::{
        udp::{RecvMeta, Transmit},
        AsyncUdpSocket, UdpPoller,
    };
    use tokio::sync::mpsc;
    use velora_protocol::{
        identity::Identity,
        wire::{self, Codec, PROTOCOL_VERSION},
    };

    use super::*;

    // ---- the pieces of a relay deployment, in-process -------------------------------------------

    const MAC: Mac = [0x02, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e];

    fn ident() -> Identity {
        Identity::generate().unwrap()
    }

    /// `len` bytes that differ per `seed` and per position, so packets glued together wrongly never
    /// compare equal to the original.
    fn pattern(len: usize, seed: u32) -> Vec<u8> {
        let mut x = seed.wrapping_mul(2_654_435_761) | 1;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                (x >> 24) as u8
            })
            .collect()
    }

    /// The outer transport settings that matter to a relay (see `velora_protocol::tls`), with the
    /// two MTU knobs these tests turn to make the legs of a pairing differ.
    fn transport(initial_mtu: u16, discover: bool) -> quinn::TransportConfig {
        let mut transport = quinn::TransportConfig::default();
        transport
            .max_idle_timeout(Some(Duration::from_secs(15).try_into().unwrap()))
            .keep_alive_interval(Some(Duration::from_secs(2)))
            .datagram_receive_buffer_size(Some(64 * 1024))
            .initial_mtu(initial_mtu);
        if !discover {
            transport.mtu_discovery_config(None);
        }
        transport
    }

    /// How large the datagrams on a device's connection to the relay can get.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Path {
        /// The library's defaults: about 1160 bytes at first, more once the path's MTU is found.
        Open,
        /// Large from the start (1452-byte packets), as on a path whose MTU is known.
        Wide,
        /// Never more than the 1200-byte packets QUIC starts with: no discovery, and the relay is
        /// told not to send more.
        Narrow,
    }

    /// A relay on loopback, run the way the host's relay code will run it. Its own datagrams are
    /// large from the start, so only a `Path::Narrow` device holds the relay's leg down.
    struct Rig {
        relay: Relay,
        addr: SocketAddr,
        fingerprint: Fingerprint,
        _endpoint: quinn::Endpoint,
    }

    async fn rig() -> Rig {
        rig_with(Config::default(), Arc::new(LanWaker)).await
    }

    async fn rig_with(config: Config, waker: Arc<dyn Waker>) -> Rig {
        let identity = ident();
        let mut server = tls::server_config(&identity).unwrap();
        server.transport_config(Arc::new(transport(1452, true)));
        let endpoint = quinn::Endpoint::server(server, "127.0.0.1:0".parse().unwrap()).unwrap();
        let relay = Relay::with_waker(config, waker);
        tokio::spawn(serve(relay.clone(), endpoint.clone()));
        Rig { relay, addr: endpoint.local_addr().unwrap(), fingerprint: identity.fingerprint(), _endpoint: endpoint }
    }

    /// What the host's relay code does with each connection once the device is known to be paired:
    /// read the control messages, hand them to the relay, write its answers back.
    async fn serve(relay: Relay, endpoint: quinn::Endpoint) {
        while let Some(incoming) = endpoint.accept().await {
            let relay = relay.clone();
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                let Ok((mut send, mut recv)) = conn.accept_bi().await else { return };
                while let Ok(Some(body)) = wire::read_msg(&mut recv).await {
                    let Ok(msg) = ClientMsg::decode(&body) else { return };
                    if let Some(answer) = relay.handle(&conn, &msg).await {
                        if send.write_all(&answer.encode()).await.is_err() {
                            return;
                        }
                    }
                }
            });
        }
    }

    /// A device's connection to the relay, with its control stream open.
    struct Outer {
        _endpoint: quinn::Endpoint,
        conn: quinn::Connection,
        send: quinn::SendStream,
        recv: quinn::RecvStream,
    }

    impl Outer {
        async fn connect(identity: &Identity, rig: &Rig, path: Path) -> Outer {
            let transport = match path {
                Path::Open => transport(1200, true),
                Path::Wide => transport(1452, true),
                Path::Narrow => transport(1200, false),
            };
            Outer::connect_with(identity, rig, path, transport).await
        }

        async fn connect_with(identity: &Identity, rig: &Rig, path: Path, transport: quinn::TransportConfig) -> Outer {
            Outer::connect_from(identity, rig, path, transport, Ipv4Addr::LOCALHOST).await
        }

        /// Connects from `ip`, one of the loopback addresses, so that two connections of one device
        /// can come from different places.
        async fn connect_from(
            identity: &Identity,
            rig: &Rig,
            path: Path,
            transport: quinn::TransportConfig,
            ip: Ipv4Addr,
        ) -> Outer {
            let socket = std::net::UdpSocket::bind((ip, 0)).unwrap();
            let mut endpoint_config = quinn::EndpointConfig::default();
            if path == Path::Narrow {
                endpoint_config.max_udp_payload_size(1200).unwrap();
            }
            let endpoint = quinn::Endpoint::new(endpoint_config, None, socket, Arc::new(quinn::TokioRuntime)).unwrap();
            let mut config = tls::client_config(identity, rig.fingerprint).unwrap();
            config.transport_config(Arc::new(transport));
            let conn = endpoint.connect_with(config, rig.addr, tls::SERVER_NAME).unwrap().await.unwrap();
            let (send, recv) = conn.open_bi().await.unwrap();
            Outer { _endpoint: endpoint, conn, send, recv }
        }

        /// Sends `msg` and waits for the relay's `RelayStatus`: `Ok` when it says ok, else its reason.
        async fn ask(&mut self, msg: ClientMsg) -> Result<(), String> {
            self.send.write_all(&msg.encode()).await.unwrap();
            let body = tokio::time::timeout(Duration::from_secs(10), wire::read_msg(&mut self.recv))
                .await
                .expect("the relay did not answer")
                .unwrap()
                .expect("the control stream ended");
            match HostMsg::decode(&body).unwrap() {
                HostMsg::RelayStatus { ok: true, .. } => Ok(()),
                HostMsg::RelayStatus { ok: false, reason } => Err(reason),
                other => panic!("not a RelayStatus: {other:?}"),
            }
        }
    }

    fn register_msg(mac: Option<Mac>) -> ClientMsg {
        ClientMsg::RelayRegister { mac }
    }

    fn relay_to_msg(host: &Identity) -> ClientMsg {
        ClientMsg::RelayTo { fingerprint: host.fingerprint().to_base64() }
    }

    /// A device's connection plus the datagram framing, to play the part of the host's and the
    /// client's relay code: packets in, packets out.
    struct Peer {
        outer: Outer,
        splitter: Splitter,
        reassembler: Reassembler,
    }

    impl Peer {
        fn new(outer: Outer) -> Peer {
            Peer { outer, splitter: Splitter::new(), reassembler: Reassembler::new() }
        }

        /// A host that has registered.
        async fn host(identity: &Identity, rig: &Rig, path: Path) -> Peer {
            let mut outer = Outer::connect(identity, rig, path).await;
            outer.ask(register_msg(None)).await.unwrap();
            Peer::new(outer)
        }

        /// A client that is relayed to `host`.
        async fn client(identity: &Identity, host: &Identity, rig: &Rig, path: Path) -> Peer {
            let mut outer = Outer::connect(identity, rig, path).await;
            outer.ask(relay_to_msg(host)).await.unwrap();
            Peer::new(outer)
        }

        fn send(&mut self, packet: &[u8]) {
            let max = self.outer.conn.max_datagram_size().expect("the connection takes datagrams");
            for datagram in self.splitter.split(packet, max).unwrap() {
                self.outer.conn.send_datagram(datagram).unwrap();
            }
        }

        async fn recv(&mut self) -> Bytes {
            loop {
                let datagram = tokio::time::timeout(Duration::from_secs(10), self.outer.conn.read_datagram())
                    .await
                    .expect("no packet arrived")
                    .unwrap();
                if let Some(packet) = self.reassembler.push(datagram, Instant::now()) {
                    return packet;
                }
            }
        }

        /// Whether no packet arrives for a while.
        async fn is_silent(&mut self) -> bool {
            tokio::time::timeout(Duration::from_millis(300), self.recv()).await.is_err()
        }
    }

    /// The application error code a connection was closed with.
    async fn closed_with(conn: &quinn::Connection) -> u32 {
        match tokio::time::timeout(Duration::from_secs(10), conn.closed()).await.expect("the connection stayed open") {
            quinn::ConnectionError::ApplicationClosed(close) => u32::try_from(close.error_code.into_inner()).unwrap(),
            other => panic!("closed in another way: {other}"),
        }
    }

    async fn eventually(what: &str, mut done: impl FnMut() -> bool) {
        for _ in 0..500 {
            if done() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("timed out waiting for {what}");
    }

    /// A waker that sends nothing and says what it was asked to do.
    #[derive(Default)]
    struct FakeWaker {
        calls: Mutex<Vec<(Mac, Ipv4Addr)>>,
        fail: Mutex<Option<WakeError>>,
    }

    impl Waker for FakeWaker {
        fn wake(&self, mac: &Mac, host: Ipv4Addr) -> Result<usize, WakeError> {
            locked(&self.calls).push((*mac, host));
            match locked(&self.fail).clone() {
                Some(error) => Err(error),
                None => Ok(4),
            }
        }
    }

    // ---- the pure parts -------------------------------------------------------------------------

    fn device(n: u16) -> Fingerprint {
        let mut bytes = [0u8; 32];
        bytes[..2].copy_from_slice(&n.to_be_bytes());
        Fingerprint(bytes)
    }

    #[test]
    fn a_device_has_a_burst_then_one_new_flow_per_interval() {
        let start = Instant::now();
        let mut limiter = RateLimiter::new(3, Duration::from_secs(10));
        for _ in 0..3 {
            assert_eq!(limiter.take(device(1), start), Ok(()));
        }
        // Used up: the next one is a full interval away.
        assert_eq!(limiter.take(device(1), start), Err(Duration::from_secs(10)));
        // Half an interval later it is half an interval short.
        assert_eq!(limiter.take(device(1), start + Duration::from_secs(5)), Err(Duration::from_secs(5)));
        // Asking too early takes nothing: after the interval there is exactly one.
        let later = start + Duration::from_secs(10);
        assert_eq!(limiter.take(device(1), later), Ok(()));
        assert!(limiter.take(device(1), later).is_err());
        // The allowance never grows past the burst, however long the device was quiet.
        let much_later = start + Duration::from_secs(3600);
        for _ in 0..3 {
            assert_eq!(limiter.take(device(1), much_later), Ok(()));
        }
        assert!(limiter.take(device(1), much_later).is_err());
    }

    #[test]
    fn devices_do_not_share_an_allowance() {
        let now = Instant::now();
        let mut limiter = RateLimiter::new(1, Duration::from_secs(60));
        assert_eq!(limiter.take(device(1), now), Ok(()));
        assert!(limiter.take(device(1), now).is_err());
        assert_eq!(limiter.take(device(2), now), Ok(()));
    }

    #[test]
    fn the_limiter_forgets_devices_that_have_recovered_and_only_those() {
        let start = Instant::now();
        let mut limiter = RateLimiter::new(2, Duration::from_secs(10));
        for n in 0..MAX_TRACKED as u16 {
            assert_eq!(limiter.take(device(n), start), Ok(()));
        }
        // Every tracked device is still short of its burst: a newcomer waits instead of growing the table.
        assert_eq!(limiter.take(device(5000), start), Err(Duration::from_secs(10)));
        assert_eq!(limiter.buckets.len(), MAX_TRACKED);
        // Once they have recovered they are the same as new devices, and are dropped to make room.
        assert_eq!(limiter.take(device(5000), start + Duration::from_secs(20)), Ok(()));
        assert_eq!(limiter.buckets.len(), 1);
    }

    #[test]
    fn a_degenerate_limit_still_limits() {
        let now = Instant::now();
        let mut limiter = RateLimiter::new(0, Duration::ZERO);
        assert_eq!(limiter.take(device(1), now), Ok(()));
        assert!(limiter.take(device(1), now).is_err());

        // An interval too long to count in is cut to a day instead of overflowing.
        let mut limiter = RateLimiter::new(1, Duration::MAX);
        assert_eq!(limiter.take(device(1), now), Ok(()));
        assert_eq!(limiter.take(device(1), now), Err(LONGEST_REFILL));
    }

    #[test]
    fn refusals_are_sentences_for_a_log_or_the_user() {
        let all = [
            Refused::NoIdentity,
            Refused::BadFingerprint,
            Refused::ToSelf,
            Refused::ConnectionInUse,
            Refused::NoDatagrams,
            Refused::RateLimited { retry_secs: 7 },
            Refused::Full,
            Refused::UnknownHost,
            Refused::NotRegistered,
            Refused::NoMac,
            Refused::NotOnNetwork,
            Refused::WakeFailed,
            Refused::BadEndpoint,
            Refused::HostNotAccepting,
        ];
        for refused in all {
            let text = refused.to_string();
            assert!(text.len() > 15 && text.is_ascii() && !text.ends_with('.'), "{text:?}");
        }
        assert!(Refused::RateLimited { retry_secs: 7 }.to_string().contains("7 s"));
        assert_eq!(rate_limited(Duration::from_millis(1500)), Refused::RateLimited { retry_secs: 2 });
        assert_eq!(rate_limited(Duration::from_secs(10)), Refused::RateLimited { retry_secs: 10 });
        assert_eq!(rate_limited(Duration::from_millis(1)), Refused::RateLimited { retry_secs: 1 });
    }

    #[test]
    fn fingerprints_are_base64url_of_32_bytes() {
        let fingerprint = device(7);
        let text = fingerprint.to_base64();
        assert_eq!(parse_fingerprint(&text), Ok(fingerprint));
        for bad in ["", "abc", &text[1..], &format!("{text}A"), "not base64 !!"] {
            assert_eq!(parse_fingerprint(bad), Err(Refused::BadFingerprint), "{bad:?}");
        }
    }

    #[test]
    fn a_magic_packet_is_aimed_at_ipv4_addresses_however_they_are_written() {
        let host = Some(Ipv4Addr::new(192, 0, 2, 9));
        for text in ["192.0.2.9", "::ffff:192.0.2.9"] {
            assert_eq!(wake_address(text.parse().unwrap()), host, "{text}");
        }
        for text in ["2001:db8::5", "::1", "fe80::1"] {
            assert_eq!(wake_address(text.parse().unwrap()), None, "{text}");
        }
    }

    #[test]
    fn punch_endpoints_must_be_somewhere_a_packet_can_go() {
        for good in ["203.0.113.7:50000", "[2001:db8::1]:4000", " 203.0.113.7:1 "] {
            assert!(parse_endpoint(good).is_ok(), "{good:?}");
        }
        assert_eq!(parse_endpoint("[::ffff:203.0.113.7]:9"), Ok("203.0.113.7:9".parse().unwrap()));
        for bad in [
            "",
            "203.0.113.7",
            "203.0.113.7:0",
            "0.0.0.0:9",
            "[::]:9",
            "224.0.0.1:9",
            "255.255.255.255:9",
            "[ff02::1]:9",
            "example.com:9",
            "203.0.113.7:99999",
        ] {
            assert_eq!(parse_endpoint(bad), Err(Refused::BadEndpoint), "{bad:?}");
        }
    }

    // ---- the relay, with plain framed packets on the outer connections -----------------------------

    #[tokio::test]
    async fn targets_that_are_not_there_get_answers() {
        let rig = rig().await;
        let mut client = Outer::connect(&ident(), &rig, Path::Open).await;
        let stranger = ident().fingerprint().to_base64();
        let unknown = Err(Refused::UnknownHost.to_string());
        assert_eq!(client.ask(ClientMsg::RelayTo { fingerprint: stranger.clone() }).await, unknown);
        assert_eq!(client.ask(ClientMsg::Wake { fingerprint: stranger.clone() }).await, unknown);
        let punch = ClientMsg::PunchRequest { to: stranger, endpoint: "203.0.113.7:50000".into(), nonce: 1 };
        assert_eq!(client.ask(punch).await, unknown);
        let nonsense = ClientMsg::RelayTo { fingerprint: "nonsense".into() };
        assert_eq!(client.ask(nonsense).await, Err(Refused::BadFingerprint.to_string()));
        assert!(rig.relay.registered().is_empty());

        let me = ident();
        let mut outer = Outer::connect(&me, &rig, Path::Open).await;
        assert_eq!(outer.ask(relay_to_msg(&me)).await, Err(Refused::ToSelf.to_string()));
    }

    #[tokio::test]
    async fn a_host_that_is_gone_is_known_but_not_registered() {
        let rig = rig().await;
        let host_id = ident();
        let host = Peer::host(&host_id, &rig, Path::Open).await;
        assert_eq!(rig.relay.registered().len(), 1);

        host.outer.conn.close(0u32.into(), b"going to sleep");
        eventually("the host to leave the table", || rig.relay.registered().is_empty()).await;
        let mut client = Outer::connect(&ident(), &rig, Path::Open).await;
        assert_eq!(client.ask(relay_to_msg(&host_id)).await, Err(Refused::NotRegistered.to_string()));
        // It is not forgotten: that is how a sleeping PC is woken.
        let known = rig.relay.known();
        assert_eq!(known.len(), 1);
        assert_eq!(known[0].fingerprint, host_id.fingerprint());
    }

    #[tokio::test]
    async fn packets_cross_both_ways_framed_for_the_leg_they_leave_on() {
        let rig = rig().await;
        let (host_id, client_id) = (ident(), ident());
        // A wide leg to the host and a narrow one to the client: a packet that fits whole on one
        // does not on the other, so the relay has to frame each packet again.
        let mut host = Peer::host(&host_id, &rig, Path::Wide).await;
        let mut client = Peer::client(&client_id, &host_id, &rig, Path::Narrow).await;
        let (narrow, wide) =
            (client.outer.conn.max_datagram_size().unwrap(), host.outer.conn.max_datagram_size().unwrap());
        assert!(narrow > 1100 && narrow < 1200 && wide > 1350, "{narrow} {wide}");

        // 1, 80 and 1000 bytes fit whole on both legs; 1300 only on the wide one; 2000 on neither.
        let sizes = [1, 80, 1000, 1300, 2000];
        for (n, size) in sizes.into_iter().enumerate() {
            let up = pattern(size, n as u32);
            client.send(&up);
            assert_eq!(host.recv().await, up, "{size} bytes up");
            let down = pattern(size, 100 + n as u32);
            host.send(&down);
            assert_eq!(client.recv().await, down, "{size} bytes down");
        }
        let seen = rig.relay.registered().remove(0);
        assert_eq!(seen.client, Some(client_id.fingerprint()));
        assert_eq!((seen.to_host.packets, seen.to_host.bytes), (5, 4381));
        assert_eq!((seen.to_client.packets, seen.to_client.bytes), (5, 4381));
        assert_eq!(seen.to_host.datagrams, 4 + 2, "whole on the wide leg except the 2000 bytes");
        assert_eq!(seen.to_client.datagrams, 3 + 4, "split on the narrow leg from 1300 bytes up");
        assert_eq!((seen.to_host.dropped, seen.to_client.dropped), (0, 0));
    }

    #[tokio::test]
    async fn junk_and_half_packets_do_not_get_in_the_way() {
        let rig = rig().await;
        let (host_id, client_id) = (ident(), ident());
        let mut host = Peer::host(&host_id, &rig, Path::Open).await;
        let mut client = Peer::client(&client_id, &host_id, &rig, Path::Open).await;

        // Not frames: too short, no payload, a shape that does not exist.
        for junk in [&b"\x00"[..], b"\x00\x01\x01", b"\x00\x01\xff junk", b""] {
            client.outer.conn.send_datagram(Bytes::copy_from_slice(junk)).unwrap();
        }
        // A packet that loses its second chunk is dropped alone.
        let max = client.outer.conn.max_datagram_size().unwrap();
        let half = client.splitter.split(&pattern(max + 100, 1), max).unwrap();
        assert_eq!(half.len(), 2);
        client.outer.conn.send_datagram(half[0].clone()).unwrap();
        client.send(b"after the junk");
        assert_eq!(host.recv().await, &b"after the junk"[..]);
        assert!(host.is_silent().await);
        assert_eq!(rig.relay.registered()[0].to_host.packets, 1);
    }

    #[tokio::test]
    async fn what_a_host_sends_before_anyone_is_relayed_to_it_is_dropped() {
        let rig = rig().await;
        let (host_id, client_id) = (ident(), ident());
        let mut host = Peer::host(&host_id, &rig, Path::Open).await;
        host.send(b"for nobody");
        eventually("the packet to be dropped", || rig.relay.registered()[0].to_client.dropped == 1).await;

        let mut client = Peer::client(&client_id, &host_id, &rig, Path::Open).await;
        assert!(client.is_silent().await, "the dropped packet came back");
        host.send(b"for the client");
        assert_eq!(client.recv().await, &b"for the client"[..]);
    }

    #[tokio::test]
    async fn a_host_that_registers_again_replaces_the_old_entry() {
        let rig = rig().await;
        let (host_id, client_id) = (ident(), ident());
        let first = Peer::host(&host_id, &rig, Path::Open).await;
        let client = Peer::client(&client_id, &host_id, &rig, Path::Open).await;
        assert_eq!(rig.relay.registered()[0].client, Some(client_id.fingerprint()));

        // The reconnect: the same device from a new connection.
        let mut second = Peer::host(&host_id, &rig, Path::Open).await;
        assert_eq!(closed_with(&first.outer.conn).await, CLOSE_REPLACED);
        assert_eq!(closed_with(&client.outer.conn).await, CLOSE_HOST_GONE);
        let table = rig.relay.registered();
        assert_eq!(table.len(), 1, "one entry per host");
        assert_eq!(table[0].addr, second.outer._endpoint.local_addr().unwrap());
        assert_eq!(table[0].client, None);

        // The new entry works, and the old connection's end does not take it down.
        let mut newcomer = Peer::client(&ident(), &host_id, &rig, Path::Open).await;
        newcomer.send(b"through the new entry");
        assert_eq!(second.recv().await, &b"through the new entry"[..]);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(rig.relay.registered().len(), 1);
    }

    #[tokio::test]
    async fn a_client_that_disconnects_frees_the_host() {
        let rig = rig().await;
        let (host_id, first_id, second_id) = (ident(), ident(), ident());
        let mut host = Peer::host(&host_id, &rig, Path::Open).await;
        let first = Peer::client(&first_id, &host_id, &rig, Path::Open).await;
        assert_eq!(rig.relay.registered()[0].client, Some(first_id.fingerprint()));

        first.outer.conn.close(0u32.into(), b"bye");
        eventually("the pairing to end", || rig.relay.registered()[0].client.is_none()).await;
        assert_eq!(rig.relay.registered().len(), 1, "the host stays registered");

        let mut second = Peer::client(&second_id, &host_id, &rig, Path::Open).await;
        second.send(b"next in line");
        assert_eq!(host.recv().await, &b"next in line"[..]);
        host.send(b"and back");
        assert_eq!(second.recv().await, &b"and back"[..]);
    }

    #[tokio::test]
    async fn a_host_that_disconnects_sends_its_client_away() {
        let rig = rig().await;
        let (host_id, client_id) = (ident(), ident());
        let host = Peer::host(&host_id, &rig, Path::Open).await;
        let client = Peer::client(&client_id, &host_id, &rig, Path::Open).await;

        host.outer.conn.close(0u32.into(), b"network gone");
        assert_eq!(closed_with(&client.outer.conn).await, CLOSE_HOST_GONE);
        eventually("the host to leave the table", || rig.relay.registered().is_empty()).await;
    }

    #[tokio::test]
    async fn a_newer_client_takes_the_host_over() {
        let rig = rig().await;
        let (host_id, laptop_id, phone_id) = (ident(), ident(), ident());
        let mut host = Peer::host(&host_id, &rig, Path::Open).await;
        let mut laptop = Peer::client(&laptop_id, &host_id, &rig, Path::Open).await;
        laptop.send(b"from the laptop");
        assert_eq!(host.recv().await, &b"from the laptop"[..]);

        let mut phone = Peer::client(&phone_id, &host_id, &rig, Path::Open).await;
        assert_eq!(closed_with(&laptop.outer.conn).await, CLOSE_TAKEN_OVER);
        assert_eq!(rig.relay.registered()[0].client, Some(phone_id.fingerprint()));
        phone.send(b"from the phone");
        assert_eq!(host.recv().await, &b"from the phone"[..]);
        host.send(b"to the phone");
        assert_eq!(phone.recv().await, &b"to the phone"[..]);
        assert_eq!(rig.relay.registered().len(), 1);
    }

    #[tokio::test]
    async fn a_device_that_reconnects_takes_over_from_its_own_dead_connection() {
        let rig = rig().await;
        let (host_id, laptop_id) = (ident(), ident());
        let mut host = Peer::host(&host_id, &rig, Path::Open).await;
        let before = Peer::client(&laptop_id, &host_id, &rig, Path::Open).await;

        // Its network changed and it is back on a new connection, while the old one has not timed out yet.
        let mut after = Peer::client(&laptop_id, &host_id, &rig, Path::Open).await;
        assert_eq!(closed_with(&before.outer.conn).await, CLOSE_TAKEN_OVER);
        after.send(b"from the new connection");
        assert_eq!(host.recv().await, &b"from the new connection"[..]);
        host.send(b"to the new connection");
        assert_eq!(after.recv().await, &b"to the new connection"[..]);
        assert_eq!(rig.relay.registered()[0].client, Some(laptop_id.fingerprint()));
    }

    #[tokio::test]
    async fn a_connection_is_one_thing_at_a_time() {
        let rig = rig().await;
        let (host_id, other_id, client_id) = (ident(), ident(), ident());
        let mut host = Peer::host(&host_id, &rig, Path::Open).await;
        let mut other = Peer::host(&other_id, &rig, Path::Open).await;
        let busy = Err(Refused::ConnectionInUse.to_string());

        // A registered host cannot also be a client.
        assert_eq!(host.outer.ask(relay_to_msg(&other_id)).await, busy);
        // Registering twice on one connection is allowed: it only says the MAC again.
        host.outer.ask(register_msg(Some(MAC))).await.unwrap();
        host.outer.ask(register_msg(None)).await.unwrap();
        assert_eq!(rig.relay.registered().iter().filter(|r| r.mac == Some(MAC)).count(), 1, "the MAC is kept");
        assert_eq!(rig.relay.registered().len(), 2);

        // A client relays to one host on one connection, and cannot register.
        let mut client = Peer::client(&client_id, &host_id, &rig, Path::Open).await;
        assert_eq!(client.outer.ask(relay_to_msg(&other_id)).await, busy);
        assert_eq!(client.outer.ask(relay_to_msg(&host_id)).await, busy);
        assert_eq!(client.outer.ask(register_msg(None)).await, busy);
        client.send(b"still paired with the first");
        assert_eq!(host.recv().await, &b"still paired with the first"[..]);
        assert!(other.is_silent().await);
    }

    #[tokio::test]
    async fn a_connection_that_takes_no_datagrams_is_turned_away() {
        let rig = rig().await;
        let host_id = ident();
        let _host = Peer::host(&host_id, &rig, Path::Open).await;
        // Without a datagram buffer this device tells the relay it cannot receive any.
        let mut transport = transport(1200, true);
        transport.datagram_receive_buffer_size(None);
        let mut deaf = Outer::connect_with(&ident(), &rig, Path::Open, transport).await;
        let refused = Err(Refused::NoDatagrams.to_string());
        assert_eq!(deaf.ask(register_msg(None)).await, refused);
        assert_eq!(deaf.ask(relay_to_msg(&host_id)).await, refused);
        assert_eq!(rig.relay.registered().len(), 1);
        assert_eq!(rig.relay.registered()[0].client, None);
    }

    #[tokio::test]
    async fn a_device_that_starts_too_many_flows_is_slowed_down_alone() {
        let config = Config { burst: 2, refill: Duration::from_secs(3600), ..Config::default() };
        let rig = rig_with(config, Arc::new(LanWaker)).await;
        let target = ClientMsg::RelayTo { fingerprint: ident().fingerprint().to_base64() };
        let unknown = Err(Refused::UnknownHost.to_string());

        let mut busy = Outer::connect(&ident(), &rig, Path::Open).await;
        assert_eq!(busy.ask(target.clone()).await, unknown);
        assert_eq!(busy.ask(target.clone()).await, unknown);
        let too_many = "too many requests from this device; try again in ";
        let refused = busy.ask(target.clone()).await.unwrap_err();
        assert!(refused.starts_with(too_many), "{refused}");
        // Wakes and punch requests draw on the same allowance.
        let wake = ClientMsg::Wake { fingerprint: ident().fingerprint().to_base64() };
        assert!(busy.ask(wake).await.unwrap_err().starts_with(too_many));

        let mut calm = Outer::connect(&ident(), &rig, Path::Open).await;
        assert_eq!(calm.ask(target).await, unknown);
    }

    #[tokio::test]
    async fn a_relay_that_is_full_turns_new_hosts_away_but_not_a_reconnecting_one() {
        let rig = rig_with(Config { max_hosts: 1, ..Config::default() }, Arc::new(LanWaker)).await;
        let (first_id, second_id) = (ident(), ident());
        let _first = Peer::host(&first_id, &rig, Path::Open).await;

        let mut second = Outer::connect(&second_id, &rig, Path::Open).await;
        assert_eq!(second.ask(register_msg(None)).await, Err(Refused::Full.to_string()));
        let _reconnected = Peer::host(&first_id, &rig, Path::Open).await;
        assert_eq!(rig.relay.registered().len(), 1);
    }

    #[tokio::test]
    async fn only_the_relay_messages_are_the_relays_to_answer() {
        let rig = rig().await;
        let outer = Outer::connect(&ident(), &rig, Path::Open).await;
        for other in [
            ClientMsg::RequestKeyframe,
            ClientMsg::ReleaseAll,
            ClientMsg::Reached { address: "lan:192.0.2.1:7420".into() },
            ClientMsg::Unsupported { tag: 99 },
        ] {
            assert_eq!(rig.relay.handle(&outer.conn, &other).await, None, "{other:?}");
        }
    }

    // ---- waking, punching, removing ---------------------------------------------------------------

    #[test]
    fn the_real_waker_knows_an_address_no_network_of_this_pc_holds() {
        // 203.0.113.0/24 is reserved for documentation: no adapter is ever on it.
        assert_eq!(LanWaker.wake(&MAC, Ipv4Addr::new(203, 0, 113, 5)), Err(WakeError::NotOnNetwork));
    }

    #[tokio::test]
    async fn a_host_outside_the_relays_networks_cannot_be_woken() {
        // The real waker, and a host that registers over loopback, which is on none of this PC's networks.
        let rig = rig().await;
        let host_id = ident();
        let mut host = Outer::connect(&host_id, &rig, Path::Open).await;
        host.ask(register_msg(Some(MAC))).await.unwrap();

        let mut client = Outer::connect(&ident(), &rig, Path::Open).await;
        let wake = ClientMsg::Wake { fingerprint: host_id.fingerprint().to_base64() };
        let refused = client.ask(wake).await.unwrap_err();
        assert_eq!(refused, Refused::NotOnNetwork.to_string());
        assert!(refused.contains("not on a network of this relay"), "{refused}");
    }

    #[tokio::test]
    async fn the_magic_packet_goes_to_the_mac_and_address_the_host_registered_with() {
        let waker = Arc::new(FakeWaker::default());
        let rig = rig_with(Config::default(), waker.clone()).await;
        let host_id = ident();
        let mut host = Outer::connect(&host_id, &rig, Path::Open).await;
        host.ask(register_msg(Some(MAC))).await.unwrap();
        let mut client = Outer::connect(&ident(), &rig, Path::Open).await;
        let wake = ClientMsg::Wake { fingerprint: host_id.fingerprint().to_base64() };

        client.ask(wake.clone()).await.unwrap();
        assert_eq!(*locked(&waker.calls), [(MAC, Ipv4Addr::LOCALHOST)]);

        // Asleep: its connection is gone but the relay still knows where to knock.
        host.conn.close(0u32.into(), b"sleeping");
        eventually("the host to leave the table", || rig.relay.registered().is_empty()).await;
        client.ask(wake).await.unwrap();
        assert_eq!(*locked(&waker.calls), [(MAC, Ipv4Addr::LOCALHOST); 2]);
    }

    #[tokio::test]
    async fn a_wake_that_cannot_be_done_says_why() {
        let waker = Arc::new(FakeWaker::default());
        let rig = rig_with(Config::default(), waker.clone()).await;
        let mut client = Outer::connect(&ident(), &rig, Path::Open).await;
        let wake = |host: &Identity| ClientMsg::Wake { fingerprint: host.fingerprint().to_base64() };

        // It never said its MAC address.
        let shy_id = ident();
        let mut shy = Outer::connect(&shy_id, &rig, Path::Open).await;
        shy.ask(register_msg(None)).await.unwrap();
        assert_eq!(client.ask(wake(&shy_id)).await, Err(Refused::NoMac.to_string()));

        // None of the relay's networks holds its address, or sending fails.
        let host_id = ident();
        let mut host = Outer::connect(&host_id, &rig, Path::Open).await;
        host.ask(register_msg(Some(MAC))).await.unwrap();
        *locked(&waker.fail) = Some(WakeError::NotOnNetwork);
        assert_eq!(client.ask(wake(&host_id)).await, Err(Refused::NotOnNetwork.to_string()));
        *locked(&waker.fail) = Some(WakeError::Failed("the adapter said boom".into()));
        let failed = client.ask(wake(&host_id)).await.unwrap_err();
        assert_eq!(failed, Refused::WakeFailed.to_string());
        assert!(!failed.contains("boom"), "details stay in the log");

        // A magic packet is an IPv4 broadcast: an IPv6 address has none to wake it on, while an
        // IPv4 address written the IPv6 way is still IPv4.
        *locked(&waker.fail) = None;
        let (v6, mapped) = (ident(), ident());
        let addr = |text: &str| -> IpAddr { text.parse().unwrap() };
        rig.relay.remember(Known { fingerprint: v6.fingerprint(), mac: Some(MAC), addr: addr("2001:db8::5") });
        rig.relay.remember(Known { fingerprint: mapped.fingerprint(), mac: Some(MAC), addr: addr("::ffff:192.0.2.9") });
        let sent_so_far = locked(&waker.calls).len();
        assert_eq!(client.ask(wake(&v6)).await, Err(Refused::NotOnNetwork.to_string()));
        assert_eq!(locked(&waker.calls).len(), sent_so_far, "nothing is sent for an IPv6 address");
        client.ask(wake(&mapped)).await.unwrap();
        assert_eq!(locked(&waker.calls).last(), Some(&(MAC, Ipv4Addr::new(192, 0, 2, 9))));
        let stored = rig.relay.known().into_iter().find(|known| known.fingerprint == mapped.fingerprint());
        assert_eq!(stored.map(|known| known.addr), Some(addr("192.0.2.9")), "kept in its IPv4 form");
    }

    #[tokio::test]
    async fn what_the_relay_remembers_can_be_saved_and_loaded() {
        let rig = rig().await;
        let host_id = ident();
        let loaded = Known { fingerprint: host_id.fingerprint(), mac: Some(MAC), addr: "192.0.2.9".parse().unwrap() };
        rig.relay.remember(loaded);
        assert_eq!(rig.relay.known(), [loaded]);
        // An entry loaded later never replaces one the relay already has.
        rig.relay.remember(Known { mac: None, addr: "192.0.2.77".parse().unwrap(), ..loaded });
        assert_eq!(rig.relay.known(), [loaded]);

        // The host registers without a MAC: the one it said before is kept, the address is new.
        let mut host = Outer::connect(&host_id, &rig, Path::Open).await;
        host.ask(register_msg(None)).await.unwrap();
        assert_eq!(rig.relay.known(), [Known { addr: "127.0.0.1".parse().unwrap(), ..loaded }]);
        assert_eq!(rig.relay.registered()[0].mac, Some(MAC));
    }

    #[tokio::test]
    async fn what_is_remembered_follows_the_newest_registration() {
        let rig = rig().await;
        let host_id = ident();
        let (old_ip, new_ip) = (Ipv4Addr::new(127, 0, 0, 2), Ipv4Addr::new(127, 0, 0, 3));
        let mut old = Outer::connect_from(&host_id, &rig, Path::Open, transport(1200, true), old_ip).await;
        old.ask(register_msg(Some(MAC))).await.unwrap();
        assert_eq!(rig.relay.known()[0].addr, IpAddr::V4(old_ip));

        // The host comes back from another address. When the old connection finishes closing, that
        // must not put its address back.
        let mut new = Outer::connect_from(&host_id, &rig, Path::Open, transport(1200, true), new_ip).await;
        new.ask(register_msg(None)).await.unwrap();
        assert_eq!(closed_with(&old.conn).await, CLOSE_REPLACED);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            rig.relay.known(),
            [Known { fingerprint: host_id.fingerprint(), mac: Some(MAC), addr: IpAddr::V4(new_ip) }]
        );

        // Gone, it is remembered where it was last seen.
        new.conn.close(0u32.into(), b"sleeping");
        eventually("the host to leave the table", || rig.relay.registered().is_empty()).await;
        assert_eq!(rig.relay.known()[0].addr, IpAddr::V4(new_ip));
    }

    #[tokio::test]
    async fn the_memory_for_waking_is_bounded_and_forgets_the_longest_gone_first() {
        let config = Config { max_known: 2, max_hosts: 1, ..Config::default() };
        let rig = rig_with(config, Arc::new(LanWaker)).await;
        for n in 1..=3 {
            let addr = "192.0.2.9".parse().unwrap();
            rig.relay.remember(Known { fingerprint: device(n), mac: Some(MAC), addr });
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let mut kept: Vec<Fingerprint> = rig.relay.known().into_iter().map(|known| known.fingerprint).collect();
        kept.sort_by_key(|fingerprint| fingerprint.0);
        assert_eq!(kept, [device(2), device(3)]);
    }

    #[tokio::test]
    async fn a_punch_request_reaches_the_host_on_a_stream_of_its_own() {
        let rig = rig().await;
        let (host_id, client_id) = (ident(), ident());
        let host = Peer::host(&host_id, &rig, Path::Open).await;
        // No pairing is needed: punching is signalling, and the client may not be relayed at all.
        let mut client = Outer::connect(&client_id, &rig, Path::Open).await;
        let to = host_id.fingerprint().to_base64();
        let request =
            |endpoint: &str, nonce| ClientMsg::PunchRequest { to: to.clone(), endpoint: endpoint.into(), nonce };

        client.ask(request("203.0.113.7:50000", 42)).await.unwrap();
        client.ask(request("[::ffff:203.0.113.8]:50001", u64::MAX)).await.unwrap();
        let expected = [("203.0.113.7:50000", 42), ("203.0.113.8:50001", u64::MAX)];
        for (endpoint, nonce) in expected {
            let mut stream = tokio::time::timeout(Duration::from_secs(10), host.outer.conn.accept_uni())
                .await
                .expect("no stream arrived")
                .unwrap();
            // The way the host reads any control message.
            let body = wire::read_msg(&mut stream).await.unwrap().unwrap();
            let message = HostMsg::decode(&body).unwrap();
            let from = client_id.fingerprint().to_base64();
            assert_eq!(message, HostMsg::PunchRequest { from, endpoint: endpoint.into(), nonce });
        }

        for bad in ["not an address", "203.0.113.7:0", "224.0.0.1:9"] {
            assert_eq!(client.ask(request(bad, 1)).await, Err(Refused::BadEndpoint.to_string()), "{bad}");
        }
    }

    #[tokio::test]
    async fn a_punch_request_a_host_does_not_take_is_an_answer() {
        let rig = rig().await;
        let host_id = ident();
        // This host lets nobody open streams to it, so the request has nowhere to go.
        let mut transport = transport(1200, true);
        transport.max_concurrent_uni_streams(0u32.into());
        let mut host = Outer::connect_with(&host_id, &rig, Path::Open, transport).await;
        host.ask(register_msg(None)).await.unwrap();

        let mut client = Outer::connect(&ident(), &rig, Path::Open).await;
        let to = host_id.fingerprint().to_base64();
        let request = ClientMsg::PunchRequest { to, endpoint: "203.0.113.7:1".into(), nonce: 1 };
        assert_eq!(client.ask(request).await, Err(Refused::HostNotAccepting.to_string()));
    }

    #[tokio::test]
    async fn removing_a_device_drops_what_the_relay_holds_for_it() {
        let rig = rig().await;
        let (host_id, client_id) = (ident(), ident());
        let mut host = Peer::host(&host_id, &rig, Path::Open).await;
        let client = Peer::client(&client_id, &host_id, &rig, Path::Open).await;

        rig.relay.remove(&client_id.fingerprint());
        assert_eq!(closed_with(&client.outer.conn).await, CLOSE_REMOVED);
        assert_eq!(rig.relay.registered()[0].client, None, "the host stays, free for another client");
        host.send(b"nobody is there");

        let other = Peer::client(&ident(), &host_id, &rig, Path::Open).await;
        rig.relay.remove(&host_id.fingerprint());
        assert_eq!(closed_with(&host.outer.conn).await, CLOSE_REMOVED);
        assert_eq!(closed_with(&other.outer.conn).await, CLOSE_HOST_GONE);
        assert!(rig.relay.registered().is_empty());
        assert!(rig.relay.known().is_empty(), "and it is not remembered for waking either");
    }

    #[tokio::test]
    async fn shutting_down_disconnects_everyone() {
        let rig = rig().await;
        let (host_id, client_id) = (ident(), ident());
        let host = Peer::host(&host_id, &rig, Path::Open).await;
        let client = Peer::client(&client_id, &host_id, &rig, Path::Open).await;

        rig.relay.shutdown();
        assert_eq!(closed_with(&host.outer.conn).await, CLOSE_SHUTDOWN);
        assert_eq!(closed_with(&client.outer.conn).await, CLOSE_SHUTDOWN);
        assert!(rig.relay.registered().is_empty());
        assert_eq!(rig.relay.known().len(), 1, "waking still works from what it remembers");
    }

    // ---- the whole thing: a Velora handshake and a megabyte through the relay, with loss ------------

    /// A seeded coin that comes up "lost" `per_mille` times in a thousand.
    #[derive(Debug)]
    struct Loss {
        per_mille: u64,
        state: u64,
    }

    impl Loss {
        fn new(per_mille: u64, seed: u64) -> Loss {
            Loss { per_mille, state: seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1 }
        }

        fn lost(&mut self) -> bool {
            // xorshift64*
            self.state ^= self.state >> 12;
            self.state ^= self.state << 25;
            self.state ^= self.state >> 27;
            (self.state.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 33) % 1000 < self.per_mille
        }
    }

    /// What a tunnel socket did, to check that packets really were split and joined on the way.
    #[derive(Debug, Default)]
    struct TunnelStats {
        packets_sent: AtomicUsize,
        datagrams_sent: AtomicUsize,
        packets_received: AtomicUsize,
        datagrams_received: AtomicUsize,
        lost: AtomicUsize,
    }

    fn count(counter: &AtomicUsize) -> usize {
        counter.load(Ordering::Relaxed)
    }

    /// The UDP socket of an inner endpoint, the way the multiplexer (E1) and the client's relay
    /// socket (F3) build theirs: the endpoint believes it talks to one peer at a made-up address.
    /// What it sends is framed by a `Splitter` for the datagram size the outer connection to the
    /// relay allows at that moment (read at every send) and goes out as outer datagrams. A task
    /// reads the outer connection's datagrams, puts them through a `Reassembler` and queues the
    /// inner packets for `poll_recv`, tagged as coming from the peer's made-up address. `try_send`
    /// never blocks, so the poller is always ready; when the queue is full a packet is dropped, as
    /// a full socket buffer would. Here it also loses a share of the outer datagrams, in both
    /// directions.
    #[derive(Debug)]
    struct TunnelSocket {
        local: SocketAddr,
        peer: SocketAddr,
        conn: quinn::Connection,
        splitter: Mutex<Splitter>,
        inbound: Mutex<mpsc::Receiver<Bytes>>,
        loss: Mutex<Loss>,
        stats: Arc<TunnelStats>,
        reader: tokio::task::JoinHandle<()>,
    }

    impl TunnelSocket {
        fn new(conn: quinn::Connection, local: SocketAddr, peer: SocketAddr, per_mille: u64, seed: u64) -> Arc<Self> {
            let (to_endpoint, inbound) = mpsc::channel(512);
            let stats = Arc::new(TunnelStats::default());
            let reader =
                tokio::spawn(read_outer(conn.clone(), to_endpoint, Loss::new(per_mille, seed + 100), stats.clone()));
            Arc::new(Self {
                local,
                peer,
                conn,
                splitter: Mutex::new(Splitter::new()),
                inbound: Mutex::new(inbound),
                loss: Mutex::new(Loss::new(per_mille, seed)),
                stats,
                reader,
            })
        }
    }

    impl Drop for TunnelSocket {
        fn drop(&mut self) {
            self.reader.abort();
        }
    }

    /// Feeds a tunnel socket: the outer connection's datagrams, reassembled, minus the lost ones.
    async fn read_outer(
        conn: quinn::Connection,
        packets: mpsc::Sender<Bytes>,
        mut loss: Loss,
        stats: Arc<TunnelStats>,
    ) {
        let mut reassembler = Reassembler::new();
        let mut sweep = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                datagram = conn.read_datagram() => {
                    let Ok(datagram) = datagram else { return };
                    stats.datagrams_received.fetch_add(1, Ordering::Relaxed);
                    if loss.lost() {
                        stats.lost.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    if let Some(packet) = reassembler.push(datagram, Instant::now()) {
                        stats.packets_received.fetch_add(1, Ordering::Relaxed);
                        let _ = packets.try_send(packet);
                    }
                }
                _ = sweep.tick() => reassembler.expire(Instant::now()),
            }
        }
    }

    #[derive(Debug)]
    struct AlwaysWritable;

    impl UdpPoller for AlwaysWritable {
        fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncUdpSocket for TunnelSocket {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            Box::pin(AlwaysWritable)
        }

        fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
            let closed = || io::Error::new(io::ErrorKind::BrokenPipe, "the outer connection is closed");
            let max = self.conn.max_datagram_size().ok_or_else(closed)?;
            let datagrams = locked(&self.splitter).split(transmit.contents, max).map_err(io::Error::other)?;
            self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
            for datagram in datagrams {
                self.stats.datagrams_sent.fetch_add(1, Ordering::Relaxed);
                if locked(&self.loss).lost() {
                    self.stats.lost.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                self.conn.send_datagram(datagram).map_err(io::Error::other)?;
            }
            Ok(())
        }

        fn poll_recv(
            &self,
            cx: &mut Context,
            bufs: &mut [IoSliceMut<'_>],
            meta: &mut [RecvMeta],
        ) -> Poll<io::Result<usize>> {
            let mut inbound = locked(&self.inbound);
            let mut filled = 0;
            while filled < bufs.len().min(meta.len()) {
                match inbound.poll_recv(cx) {
                    Poll::Ready(Some(packet)) => {
                        let len = packet.len().min(bufs[filled].len());
                        bufs[filled][..len].copy_from_slice(&packet[..len]);
                        meta[filled] = RecvMeta { addr: self.peer, len, stride: len, ecn: None, dst_ip: None };
                        filled += 1;
                    }
                    Poll::Ready(None) if filled == 0 => {
                        let ended = io::Error::new(io::ErrorKind::BrokenPipe, "the outer connection ended");
                        return Poll::Ready(Err(ended));
                    }
                    Poll::Ready(None) | Poll::Pending => break,
                }
            }
            if filled > 0 {
                Poll::Ready(Ok(filled))
            } else {
                Poll::Pending
            }
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(self.local)
        }

        // Nothing is fragmented, so the endpoint may probe for larger packets than 1200 bytes.
        fn may_fragment(&self) -> bool {
            false
        }
    }

    /// An endpoint whose UDP socket is a tunnel through `conn`, losing `per_mille` in a thousand of
    /// the outer datagrams each way.
    fn tunnel(
        conn: quinn::Connection,
        local: SocketAddr,
        peer: SocketAddr,
        server: Option<quinn::ServerConfig>,
        per_mille: u64,
        seed: u64,
    ) -> (quinn::Endpoint, Arc<TunnelStats>) {
        let socket = TunnelSocket::new(conn, local, peer, per_mille, seed);
        let stats = socket.stats.clone();
        let config = quinn::EndpointConfig::default();
        let endpoint =
            quinn::Endpoint::new_with_abstract_socket(config, server, socket, Arc::new(quinn::TokioRuntime)).unwrap();
        (endpoint, stats)
    }

    /// Made-up addresses for the two inner endpoints; they never reach a network. (The multiplexer
    /// derives its own from the relay's fingerprint, in `fd00:7e1a::/32`.)
    fn synthetic(last: u16, port: u16) -> SocketAddr {
        SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::new(0xfd00, 0x7e1a, 0, 0, 0, 0, 0, last), port, 0, 0))
    }

    const PAYLOAD: usize = 1_000_000;
    const DATAGRAMS: usize = 1000;
    const DATAGRAM_LEN: usize = 1000;

    /// Datagram `n` of the second phase: its number, then bytes that depend on it.
    fn datagram(n: usize) -> Bytes {
        let mut data = pattern(DATAGRAM_LEN, n as u32 + 1000);
        data[..4].copy_from_slice(&(n as u32).to_be_bytes());
        Bytes::from(data)
    }

    /// Counts the datagrams that arrive on `conn`: those that are one of ours, whole, and the rest.
    async fn count_datagrams(conn: quinn::Connection, intact: Arc<AtomicUsize>, damaged: Arc<AtomicUsize>) {
        while let Ok(data) = conn.read_datagram().await {
            let number = data.get(..4).map(|prefix| u32::from_be_bytes(prefix.try_into().unwrap()) as usize);
            let counter = if number.is_some_and(|n| n < DATAGRAMS && data == datagram(n)) { &intact } else { &damaged };
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// What the host does with the inner connection that arrives: the Velora hello and welcome, a
    /// stream it echoes back, and a count of the datagrams. It is done when the client ends the
    /// control stream. Returns the datagrams that arrived intact and damaged.
    async fn host_side(endpoint: quinn::Endpoint, client: Fingerprint) -> (usize, usize) {
        let conn = endpoint.accept().await.expect("the endpoint closed").await.expect("the inner handshake failed");
        assert_eq!(tls::peer_fingerprint(&conn).unwrap(), client, "the host sees the client's certificate");
        let (intact, damaged) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        tokio::spawn(count_datagrams(conn.clone(), intact.clone(), damaged.clone()));

        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
        let hello = ClientMsg::decode(&wire::read_msg(&mut recv).await.unwrap().unwrap()).unwrap();
        assert!(matches!(hello, ClientMsg::Hello { version: PROTOCOL_VERSION, .. }), "{hello:?}");
        let welcome = HostMsg::Welcome {
            version: PROTOCOL_VERSION,
            host_name: "desktop".into(),
            codec: Codec::H264,
            width: 1920,
            height: 1080,
            features: None,
            addresses: Vec::new(),
        };
        send.write_all(&welcome.encode()).await.unwrap();

        let (mut echo_send, mut echo_recv) = conn.accept_bi().await.unwrap();
        let data = echo_recv.read_to_end(2 * PAYLOAD).await.unwrap();
        echo_send.write_all(&data).await.unwrap();
        echo_send.finish().unwrap();

        // The client says it is done by ending its control stream; a stream end is never lost.
        recv.read_to_end(1024).await.unwrap();
        (count(&intact), count(&damaged))
    }

    /// What a run through the relay leaves to look at.
    struct Outcome {
        relay: Registered,
        client: Arc<TunnelStats>,
        host: Arc<TunnelStats>,
        intact: usize,
    }

    /// Everything the relay is for, in one process. A host and a client that cannot reach each
    /// other dial out to a relay, the relay pairs them, and they make a normal Velora connection
    /// through it: mutual TLS with pinned certificates, then the hello and the welcome. They move a
    /// megabyte over a stream, which the host echoes back, and a megabyte of datagrams, while
    /// `per_mille` in a thousand of the outer datagrams are lost on every leg.
    async fn velora_through_the_relay(client_path: Path, host_path: Path, per_mille: u64) -> Outcome {
        let rig = rig().await;
        let (host_id, client_id) = (ident(), ident());

        // Both ends dial out; the relay pairs them.
        let mut host_outer = Outer::connect(&host_id, &rig, host_path).await;
        host_outer.ask(register_msg(None)).await.unwrap();
        let mut client_outer = Outer::connect(&client_id, &rig, client_path).await;
        client_outer.ask(relay_to_msg(&host_id)).await.unwrap();

        // An inner endpoint at each end, over a tunnel through its outer connection.
        let (host_addr, client_addr) = (synthetic(1, 7420), synthetic(2, 41000));
        let server = tls::server_config(&host_id).unwrap();
        let (host_endpoint, host_stats) =
            tunnel(host_outer.conn.clone(), host_addr, client_addr, Some(server), per_mille, 1);
        let (client_endpoint, client_stats) =
            tunnel(client_outer.conn.clone(), client_addr, host_addr, None, per_mille, 2);
        let host = tokio::spawn(host_side(host_endpoint, client_id.fingerprint()));

        // The handshake: QUIC and TLS 1.3 with both certificates checked, whose first packet is a
        // 1200-byte Initial that does not fit a datagram of the narrow leg whole.
        let config = tls::client_config(&client_id, host_id.fingerprint()).unwrap();
        let connecting = client_endpoint.connect_with(config, host_addr, tls::SERVER_NAME).unwrap();
        let conn = connecting.await.expect("the handshake through the relay failed");
        assert_eq!(tls::peer_fingerprint(&conn).unwrap(), host_id.fingerprint(), "the pinned certificate");

        // Velora's own hello and welcome, on the control stream.
        let (mut control, mut replies) = conn.open_bi().await.unwrap();
        let hello = ClientMsg::Hello {
            version: PROTOCOL_VERSION,
            name: "laptop".into(),
            pairing_secret: None,
            password: None,
            ext: None,
        };
        control.write_all(&hello.encode()).await.unwrap();
        let welcome = HostMsg::decode(&wire::read_msg(&mut replies).await.unwrap().unwrap()).unwrap();
        assert!(matches!(welcome, HostMsg::Welcome { width: 1920, height: 1080, .. }), "{welcome:?}");

        // A megabyte on a stream and back: lost packets are the inner QUIC's to recover.
        let payload = pattern(PAYLOAD, 5);
        let (mut up, mut down) = conn.open_bi().await.unwrap();
        up.write_all(&payload).await.unwrap();
        up.finish().unwrap();
        let echoed = down.read_to_end(2 * PAYLOAD).await.unwrap();
        assert!(echoed == payload, "the echo differs from what was sent ({} bytes back)", echoed.len());

        // A megabyte of datagrams, which nothing recovers: each arrives whole or not at all.
        for n in 0..DATAGRAMS {
            conn.send_datagram(datagram(n)).unwrap();
            if n % 10 == 9 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        control.finish().unwrap();
        let (intact, damaged) = host.await.unwrap();
        assert_eq!(damaged, 0, "a datagram arrived changed");
        assert!(intact >= DATAGRAMS * 9 / 10, "only {intact} of {DATAGRAMS} datagrams arrived");

        let inner_datagram_size = conn.max_datagram_size();
        let relay = rig.relay.registered().remove(0);
        assert_eq!(relay.client, Some(client_id.fingerprint()));
        assert!(relay.to_host.bytes > PAYLOAD as u64 && relay.to_client.bytes > PAYLOAD as u64, "{relay:?}");
        assert_eq!((relay.to_host.dropped, relay.to_client.dropped), (0, 0), "the relay dropped packets itself");
        let lost = count(&client_stats.lost) + count(&host_stats.lost);
        assert_eq!(lost > 0, per_mille > 0, "{lost} outer datagrams were lost");
        println!("through the relay: {intact}/{DATAGRAMS} datagrams intact, {lost} outer datagrams lost");
        println!("  inner datagrams of up to {inner_datagram_size:?} bytes; to host {:?}", relay.to_host);
        println!("  to client {:?}", relay.to_client);
        Outcome { relay, client: client_stats, host: host_stats, intact }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_velora_connection_and_a_megabyte_cross_a_relay_with_one_percent_loss() {
        let run = velora_through_the_relay(Path::Open, Path::Open, 10);
        let out = tokio::time::timeout(Duration::from_secs(120), run).await.expect("timed out");
        assert!(out.intact > 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_same_across_legs_of_different_sizes() {
        // The client's leg is held at 1200-byte packets while the host's is wide open, so a packet
        // that is whole on one leg is in two pieces on the other, in both directions.
        let run = velora_through_the_relay(Path::Narrow, Path::Wide, 10);
        let out = tokio::time::timeout(Duration::from_secs(120), run).await.expect("timed out");
        assert!(count(&out.client.datagrams_sent) > count(&out.client.packets_sent), "the client sent no split packet");
        assert!(out.relay.to_client.datagrams > out.relay.to_client.packets, "the relay split nothing for the client");
        assert!(count(&out.client.datagrams_received) > count(&out.client.packets_received));
        assert!(count(&out.host.packets_received) > 0 && count(&out.host.packets_sent) > 0);
    }
}
