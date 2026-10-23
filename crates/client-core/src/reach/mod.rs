//! Standalone reach on the client: ways of reaching a paired host besides the address the user gave, with no mesh VPN
//! and no server in the way (`docs/nat-traversal.md`). All of it is optional: a host that never sent a `HostMsg::Reach`
//! is connected to exactly as before, and Tailscale and the like keep working as plain addresses.
//!
//! This file is the plumbing (ticket F1), frozen once merged:
//!
//! - [`Candidate`]: one way of reaching the host. `stored_candidates` makes the first batch from what is remembered
//!   about the host, and [`resolve_record`] adds more while the race runs.
//! - `race`: starts the candidates on a schedule (the constants below), the first TLS handshake wins and the rest are
//!   dropped.
//! - [`ReachInfo`], [`ReachParams`], [`Route`]: what the host said, what the race may use, how a connection was made.
//! - [`wake`]: Wake-on-LAN, from this device's network or through a relay.
//!
//! The feature tickets fill in the hooks in files of their own and edit nothing here. Each hook says, where it is
//! defined, what it receives and what it returns:
//!
//! | hook | file | ticket |
//! |---|---|---|
//! | [`resolve_record`] | `dht.rs` | F2 |
//! | [`dial_relay`], [`wake_through_relay`] | `relay.rs` | F3 |
//! | [`dial_punch`] | `punch.rs` | F4 |
//!
//! The race spawns the futures of [`resolve_record`], [`dial_relay`] and [`dial_punch`] and drops them when another
//! candidate wins; [`wake_through_relay`] sits inside the future of [`hosts::wake`](crate::hosts::wake), which callers
//! spawn on a multi-threaded runtime. All of them must be `Send`, and a test in `lib.rs` fails to compile otherwise.

use std::{
    collections::HashMap,
    fmt,
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

use anyhow::{anyhow, Result};
use tokio::{
    task::JoinSet,
    time::{error::Elapsed, Instant},
};
use velora_nat::addresses::{classify, AddressClass};
use velora_protocol::{
    identity::{Identity, KnownHost},
    tls::{self, Fingerprint},
    wire::{AddressKind, DEVICE_SECRET_LEN, REACH_KEY_LEN},
};

use crate::ConnectParams;

mod dht;
mod punch;
mod relay;

pub use dht::resolve_record;
pub use punch::dial_punch;
pub use relay::{dial_relay, wake_through_relay};

/// How long each further direct address waits before it is tried: the first usually answers.
pub const ADDRESS_STAGGER: Duration = Duration::from_millis(250);
/// Relays start this long after the first direct address: a relay costs the relaying PC bandwidth and the session a hop,
/// so it is the way in when nothing direct answers, not a competitor of the direct addresses.
pub const RELAY_DELAY: Duration = Duration::from_secs(2);
/// Two addresses of the same relay, for the same host, start this far apart. A relay lets one client reach a host at a
/// time and a second `RelayTo` from the same device takes the first over (D2's decision 2), so the second address waits
/// until the first has had time to finish: a relay reachable at both its IPv4 and IPv6 address still gets one dial, not two
/// that cancel each other.
pub const RELAY_ADDRESS_STAGGER: Duration = Duration::from_secs(2);
/// Hole punching starts as late as the relays: the relay is the sure path and the punch is the one that saves its hop,
/// so the two run side by side and whichever completes first wins. Field tests (I4) tune this, here and in one place.
pub const PUNCH_DELAY: Duration = Duration::from_secs(2);
/// The DHT is asked only when the stored addresses have not answered by then (or have all failed): a LAN or VPN address
/// answers in milliseconds, and a lookup tells the whole DHT that this device is looking for the host.
pub const LOOKUP_DELAY: Duration = Duration::from_millis(500);
/// A lookup that takes longer than this is given up. [`resolve_record`] caps itself lower (the plan says 5 s for a cold
/// start); this is the plumbing's own safety net, so a hook that hangs cannot hold the race when nothing else is left.
pub const LOOKUP_LIMIT: Duration = Duration::from_secs(10);
/// Most candidates one race starts, whatever the stored data and the record say: each one is a socket and a handshake.
pub const MAX_CANDIDATES: usize = 32;

/// A relay: another paired device that both ends can dial, and the fingerprint its certificate must have.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayRef {
    pub addr: SocketAddr,
    pub fingerprint: Fingerprint,
}

/// One way of reaching the host that the race can try.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Candidate {
    /// An address of the host itself, dialed directly: its LAN or VPN address, the public address its router maps to it
    /// or a global IPv6 address. The kind says which, for logs and for [`Route`]; it does not change how it is tried.
    Direct(SocketAddr, AddressKind),
    /// Through a relay: another paired device, reachable at `relay_addr` with the certificate `relay_fingerprint`, that
    /// passes the datagrams between this device and the host `target` (the host's fingerprint). Dialed by
    /// [`dial_relay`] (F3).
    Relay { relay_addr: SocketAddr, relay_fingerprint: Fingerprint, target: Fingerprint },
    /// Hole punching toward the host's public `endpoint`, as its NAT shows it. `via` are the relays the request to open
    /// the hole can go through (empty: through the DHT). Dialed by [`dial_punch`] (F4); proposed by [`resolve_record`]
    /// (F2), since only the host's record tells its NAT type and endpoint.
    Punch { endpoint: SocketAddr, via: Vec<RelayRef> },
}

impl Candidate {
    /// How a connection made through this candidate is reported: see [`Route`].
    pub fn route(&self) -> Route {
        match self {
            Self::Direct(addr, kind) => Route { kind: kind.clone(), address: addr.to_string() },
            Self::Relay { relay_addr, relay_fingerprint, .. } => {
                Route { kind: AddressKind::Relay(relay_fingerprint.to_base64()), address: relay_addr.to_string() }
            }
            // A punched connection is a direct one to the host's public endpoint.
            Self::Punch { endpoint, .. } => Route { kind: AddressKind::Public, address: endpoint.to_string() },
        }
    }

    /// Whether `other` is the same way of reaching the host: the same address (the kind is only a label) or the same
    /// relay. A race starts each way once, whoever proposes it again.
    fn same_target(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Direct(a, _), Self::Direct(b, _)) => a == b,
            (
                Self::Relay { relay_addr: a, relay_fingerprint: fa, target: ta },
                Self::Relay { relay_addr: b, relay_fingerprint: fb, target: tb },
            ) => a == b && fa == fb && ta == tb,
            (Self::Punch { endpoint: a, .. }, Self::Punch { endpoint: b, .. }) => a == b,
            _ => false,
        }
    }
}

impl fmt::Display for Candidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct(addr, kind) => write!(f, "{} {addr}", kind_label(kind)),
            Self::Relay { relay_addr, relay_fingerprint, .. } => {
                write!(f, "relay {relay_addr} ({})", relay_fingerprint.short())
            }
            Self::Punch { endpoint, via } => write!(f, "punch {endpoint} (signalled through {} relays)", via.len()),
        }
    }
}

/// A word for an address kind, for logs and messages: `lan`, `vpn`, `public`, `v6`, `relay`, `other`.
pub fn kind_label(kind: &AddressKind) -> &'static str {
    match kind {
        AddressKind::Lan => "lan",
        AddressKind::Vpn => "vpn",
        AddressKind::Public => "public",
        AddressKind::V6 => "v6",
        AddressKind::Relay(_) => "relay",
        AddressKind::Other(_) => "other",
    }
}

/// How a connection was made: the kind of the address that won the race and that address as it was dialed (for a relay,
/// the relay's own). It is what `ClientMsg::Reached` tells the host, so the host's "last reached" can say which way in
/// worked, and what `velora connect` can print.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub kind: AddressKind,
    pub address: String,
}

impl fmt::Display for Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", kind_label(&self.kind), self.address)
    }
}

/// What a host said about reaching it from other networks (`HostMsg::Reach`), as the client keeps it. The host sends it
/// after the welcome, to clients that asked for it in their hello.
#[derive(Clone, PartialEq, Eq)]
pub struct ReachInfo {
    /// Every address of the host with its kind, most useful first (a superset of the welcome's).
    pub addresses: Vec<(AddressKind, String)>,
    /// The host's DHT key; `None` when the host sent zeros, as a host with nothing to publish may.
    pub key: Option<[u8; REACH_KEY_LEN]>,
    /// The secret that opens that record for this device; `None` when the host sent zeros.
    pub secret: Option<[u8; DEVICE_SECRET_LEN]>,
    /// The relays the host is registered with: each one's fingerprint (base64url) and its addresses.
    pub relays: Vec<(String, Vec<String>)>,
    /// The MAC address of the host's network adapter, for Wake-on-LAN.
    pub mac: Option<[u8; 6]>,
    /// The host relays for its other paired devices.
    pub relays_for_others: bool,
}

impl fmt::Debug for ReachInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The secret opens the host's record: it stays out of logs, and so does the rest of what only the code needs.
        f.debug_struct("ReachInfo")
            .field("addresses", &self.addresses)
            .field("relays", &self.relays)
            .field("has_key", &self.key.is_some())
            .field("has_secret", &self.secret.is_some())
            .field("has_mac", &self.mac.is_some())
            .field("relays_for_others", &self.relays_for_others)
            .finish()
    }
}

/// Zeros are what a host sends where it has nothing (no DHT record, so no key and no secret); no real key or secret is.
pub(crate) fn non_zero<const N: usize>(bytes: [u8; N]) -> Option<[u8; N]> {
    (bytes != [0; N]).then_some(bytes)
}

/// What a connection attempt knows about the host beyond `ConnectParams::addr` and `also`: its stored entry, and where
/// this device keeps its own reach state. Set for a host that was connected to before; the hooks read it.
#[derive(Clone)]
pub struct ReachParams {
    /// The host's entry as it was stored when the attempt began: `kinds`, `key`, `secret`, `relays` and `mac` are what
    /// its last `Reach` said.
    pub host: KnownHost,
    /// This device's state directory (`StateDir::dir`): where its DHT key (`velora_dht::keys::FILE_NAME`) and the
    /// DHT node's routing-table cache belong, beside `identity.json`.
    pub state_dir: PathBuf,
}

impl fmt::Debug for ReachParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `KnownHost` holds the device secret: show the name only.
        f.debug_struct("ReachParams").field("host", &self.host.name).field("state_dir", &self.state_dir).finish()
    }
}

/// Whether the race should ask the DHT: only with the host's key and this device's secret in hand.
pub(crate) fn can_resolve(params: &ConnectParams) -> bool {
    params.reach.as_ref().is_some_and(|reach| reach.host.key.is_some() && reach.host.secret.is_some())
}

// ---- the first batch: what is stored ----

/// A guess at what an address is from the address alone, for those stored before the host said (older entries, or the
/// address the user typed).
pub(crate) fn guess_kind(ip: IpAddr) -> AddressKind {
    match classify(ip) {
        AddressClass::Public => AddressKind::Public,
        AddressClass::GlobalV6 => AddressKind::V6,
        // 100.64/10 is what Tailscale and Netbird hand out (and carriers, which an address alone cannot tell apart).
        AddressClass::Shared => AddressKind::Vpn,
        AddressClass::UniqueLocal if is_tailscale_v6(ip) => AddressKind::Vpn,
        _ => AddressKind::Lan,
    }
}

/// Tailscale's IPv6 range, `fd7a:115c:a1e0::/48`.
fn is_tailscale_v6(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V6(ip) if ip.segments()[..3] == [0xfd7a, 0x115c, 0xa1e0])
}

/// The kind the host gave `addr` in its last `Reach`, or a guess.
fn direct_kind(addr: SocketAddr, kinds: &[(AddressKind, String)]) -> AddressKind {
    kinds
        .iter()
        .find(|(kind, text)| !matches!(kind, AddressKind::Relay(_)) && text.parse() == Ok(addr))
        .map_or_else(|| guess_kind(addr.ip()), |(kind, _)| kind.clone())
}

/// The first batch of the race: what this device remembers about the host, in the order to start it. Direct addresses
/// first: the main one and the others the user and the welcome gave, in the order they were stored, then the rest of
/// what the host's last `Reach` listed. Then the relays it is registered with. Strings that do not parse are skipped.
pub(crate) fn stored_candidates(params: &ConnectParams) -> Vec<Candidate> {
    let host = params.reach.as_ref().map(|reach| &reach.host);
    let kinds = host.map_or(&[][..], |host| &host.kinds[..]);
    let mut found: Vec<Candidate> = Vec::new();
    let mut add = |candidate: Candidate| {
        if !found.iter().any(|known| known.same_target(&candidate)) {
            found.push(candidate);
        }
    };
    for &addr in std::iter::once(&params.addr).chain(&params.also) {
        add(Candidate::Direct(addr, direct_kind(addr, kinds)));
    }
    for (kind, text) in kinds {
        // A relay's address is not the host's: dialing it as the host would fail the pinned certificate.
        if matches!(kind, AddressKind::Relay(_)) {
            continue;
        }
        match text.parse() {
            Ok(addr) => add(Candidate::Direct(addr, kind.clone())),
            Err(_) => tracing::debug!("ignoring a stored address that does not parse"),
        }
    }
    if let Some(host) = host {
        for relay in relay_candidates(host, params.host_fingerprint) {
            add(relay);
        }
    }
    found
}

/// The relays the host last said it is registered with: from its relay list and from the relay entries of its address
/// list, which name the same relays. A relay is never the host itself.
fn relay_candidates(host: &KnownHost, target: Fingerprint) -> Vec<Candidate> {
    let mut found = Vec::new();
    let mut add = |fingerprint: &str, address: &str| {
        let (Ok(relay_fingerprint), Ok(relay_addr)) =
            (Fingerprint::from_base64(fingerprint), address.parse::<SocketAddr>())
        else {
            tracing::debug!("ignoring a stored relay address that does not parse");
            return;
        };
        if relay_fingerprint != target {
            found.push(Candidate::Relay { relay_addr, relay_fingerprint, target });
        }
    };
    for (fingerprint, addresses) in &host.relays {
        for address in addresses {
            add(fingerprint, address);
        }
    }
    for (kind, address) in &host.kinds {
        if let AddressKind::Relay(fingerprint) = kind {
            add(fingerprint, address);
        }
    }
    found
}

// ---- the race ----

/// When each candidate may start. Direct addresses go one stagger apart; relays and punches wait for their delay after
/// the first direct one (at once when there is none) and go one stagger apart among themselves, except that addresses of
/// the same relay keep [`RELAY_ADDRESS_STAGGER`] between them.
#[derive(Default)]
struct Slots {
    /// When the first direct candidate starts: the others count their delay from it.
    first_direct: Option<Instant>,
    /// Earliest start of the next direct candidate: the previous one plus the stagger.
    next_direct: Option<Instant>,
    /// Earliest start of the next relay or punch.
    next_slow: Option<Instant>,
    /// Earliest start of the next candidate through each relay, for each host (the relay's fingerprint, the host's).
    same_relay: HashMap<(Fingerprint, Fingerprint), Instant>,
}

impl Slots {
    /// The time `candidate` may start if it arrives at `now`.
    fn reserve(&mut self, candidate: &Candidate, now: Instant) -> Instant {
        match candidate {
            Candidate::Direct(..) => {
                let at = self.next_direct.map_or(now, |next| next.max(now));
                self.next_direct = Some(at + ADDRESS_STAGGER);
                self.first_direct.get_or_insert(at);
                at
            }
            Candidate::Relay { .. } | Candidate::Punch { .. } => {
                let (delay, relay) = match candidate {
                    Candidate::Relay { relay_fingerprint, target, .. } => {
                        (RELAY_DELAY, Some((*relay_fingerprint, *target)))
                    }
                    _ => (PUNCH_DELAY, None),
                };
                let after_direct = self.first_direct.map_or(now, |first| first + delay);
                // The slot in the lane of relays and punches; waiting for the same relay does not hold up the others.
                let lane = after_direct.max(now).max(self.next_slow.unwrap_or(now));
                self.next_slow = Some(lane + ADDRESS_STAGGER);
                let Some(relay) = relay else { return lane };
                let at = lane.max(self.same_relay.get(&relay).copied().unwrap_or(now));
                self.same_relay.insert(relay, at + RELAY_ADDRESS_STAGGER);
                at
            }
        }
    }
}

/// A candidate that has been accepted and has not started.
struct Waiting {
    at: Instant,
    /// Its place in the order candidates were accepted; the lower, the more its failure says (see `race`).
    seq: usize,
    candidate: Candidate,
}

/// The candidates of a race: what was accepted, when each may start.
#[derive(Default)]
struct Queue {
    slots: Slots,
    waiting: Vec<Waiting>,
    /// Everything accepted so far, started or not: a way of reaching the host is tried once per race.
    accepted: Vec<Candidate>,
}

impl Queue {
    /// Accepts a batch that arrived at `now`, except what is accepted already and what goes past [`MAX_CANDIDATES`].
    fn add(&mut self, batch: Vec<Candidate>, now: Instant) {
        // Direct ones first, so that relays count their delay from the first of them even if the batch lists them first.
        let (direct, slow): (Vec<_>, Vec<_>) = batch.into_iter().partition(|c| matches!(c, Candidate::Direct(..)));
        for candidate in direct.into_iter().chain(slow) {
            if self.accepted.iter().any(|known| known.same_target(&candidate)) {
                continue;
            }
            if self.accepted.len() >= MAX_CANDIDATES {
                tracing::debug!("too many candidates: not trying {candidate}");
                continue;
            }
            let at = self.slots.reserve(&candidate, now);
            self.waiting.push(Waiting { at, seq: self.accepted.len(), candidate: candidate.clone() });
            self.accepted.push(candidate);
        }
    }

    fn is_empty(&self) -> bool {
        self.waiting.is_empty()
    }

    /// When the next waiting candidate may start.
    fn next_start(&self) -> Option<Instant> {
        self.waiting.iter().map(|w| w.at).min()
    }

    /// Removes the candidates that may start by `now`, in the order they should.
    fn take_due(&mut self, now: Instant) -> Vec<(usize, Candidate)> {
        let (mut due, later): (Vec<_>, Vec<_>) =
            std::mem::take(&mut self.waiting).into_iter().partition(|w| w.at <= now);
        self.waiting = later;
        due.sort_by_key(|w| (w.at, w.seq));
        due.into_iter().map(|w| (w.seq, w.candidate)).collect()
    }
}

/// What the lookup gave, if it gave anything before its deadline.
type Asked = std::result::Result<Result<Vec<Candidate>>, Elapsed>;

/// Tries candidates until one of them connects, and returns it with what it connected: the first handshake wins and the
/// attempts still running are dropped.
///
/// `first` is the batch known at the start. `lookup`, when there is one, is asked [`LOOKUP_DELAY`] after the start (at
/// once if nothing is running or waiting by then) for more, which join the race on the same rules however late they
/// come; it gets [`LOOKUP_LIMIT`] to answer. `dial` turns a candidate into an attempt. Attempts and lookup run in tasks
/// of their own, so they must be `Send`, and a panic in one costs that candidate (or the lookup) and nothing else.
///
/// Rules: direct candidates start [`ADDRESS_STAGGER`] apart; relays and punches wait [`RELAY_DELAY`] and
/// [`PUNCH_DELAY`] after the first direct one (when none exists they start at once), and addresses of the same relay
/// [`RELAY_ADDRESS_STAGGER`] apart; a way of reaching the host runs
/// once, however often it is proposed; at most [`MAX_CANDIDATES`] run. The error, when none connects, is the failure of
/// the earliest candidate accepted (the main address, normally): the one that says most.
pub(crate) async fn race<T, D, F, L>(first: Vec<Candidate>, lookup: Option<L>, dial: D) -> Result<(Candidate, T)>
where
    T: Send + 'static,
    D: Fn(Candidate) -> F,
    F: Future<Output = Result<T>> + Send + 'static,
    L: Future<Output = Result<Vec<Candidate>>> + Send + 'static,
{
    let begun = Instant::now();
    let mut queue = Queue::default();
    queue.add(first, begun);
    let mut running = JoinSet::new();
    let mut failure: Option<(usize, anyhow::Error)> = None;
    // The lookup waits here until it is time to ask, and then runs in a task of its own.
    let mut lookup = lookup;
    let mut lookups: JoinSet<Asked> = JoinSet::new();
    let ask = |lookup: L| async move { tokio::time::timeout(LOOKUP_LIMIT, lookup).await };

    loop {
        if running.is_empty() && queue.is_empty() {
            match lookup.take() {
                // Nothing else is trying: ask now rather than after the delay.
                Some(l) => {
                    lookups.spawn(ask(l));
                }
                None if lookups.is_empty() => break,
                None => {}
            }
        }
        let next_start = queue.next_start();
        tokio::select! {
            biased;
            Some(done) = running.join_next(), if !running.is_empty() => match done {
                Ok((_, candidate, Ok(connected))) => {
                    running.abort_all();
                    tracing::info!("connected through {candidate}");
                    return Ok((candidate, connected));
                }
                Ok((seq, candidate, Err(e))) => {
                    tracing::debug!("{candidate}: {e:#}");
                    if failure.as_ref().is_none_or(|(first, _)| seq < *first) {
                        failure = Some((seq, e));
                    }
                }
                Err(e) => tracing::debug!("a connection attempt ended abnormally: {e}"),
            },
            Some(done) = lookups.join_next(), if !lookups.is_empty() => match done {
                Ok(Ok(Ok(batch))) => {
                    tracing::debug!("the lookup found {} candidates", batch.len());
                    queue.add(batch, Instant::now());
                }
                Ok(Ok(Err(e))) => tracing::debug!("the lookup failed: {e:#}"),
                Ok(Err(_)) => tracing::debug!("the lookup took too long"),
                Err(e) => tracing::debug!("the lookup ended abnormally: {e}"),
            },
            _ = tokio::time::sleep_until(begun + LOOKUP_DELAY), if lookup.is_some() => {
                if let Some(l) = lookup.take() {
                    lookups.spawn(ask(l));
                }
            }
            _ = sleep_until_if(next_start), if next_start.is_some() => {
                for (seq, candidate) in queue.take_due(Instant::now()) {
                    tracing::debug!("trying {candidate}");
                    let attempt = dial(candidate.clone());
                    running.spawn(async move { (seq, candidate, attempt.await) });
                }
            }
        }
    }
    Err(failure.map_or_else(|| anyhow!("no address to try"), |(_, e)| e))
}

async fn sleep_until_if(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// Dials one candidate: a direct address here, the hooks for the others. `config` is the TLS configuration pinned to the
/// host's certificate.
pub(crate) async fn dial(
    params: &ConnectParams,
    config: quinn::ClientConfig,
    candidate: &Candidate,
) -> Result<(quinn::Endpoint, quinn::Connection)> {
    match candidate {
        Candidate::Direct(addr, _) => dial_direct(config, *addr).await,
        Candidate::Relay { relay_addr, relay_fingerprint, target } => {
            dial_relay(params, *relay_addr, *relay_fingerprint, *target).await
        }
        Candidate::Punch { endpoint, via } => dial_punch(params, *endpoint, via).await,
    }
}

/// One socket and one QUIC handshake to `addr`, pinned to the host's certificate.
async fn dial_direct(config: quinn::ClientConfig, addr: SocketAddr) -> Result<(quinn::Endpoint, quinn::Connection)> {
    let bind: SocketAddr = if addr.is_ipv6() { "[::]:0".parse()? } else { "0.0.0.0:0".parse()? };
    let mut endpoint = quinn::Endpoint::client(bind)?;
    endpoint.set_default_client_config(config);
    let conn = endpoint.connect(addr, tls::SERVER_NAME)?.await?;
    Ok((endpoint, conn))
}

// ---- wake ----

/// What [`wake`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeOutcome {
    /// A magic packet went out, from this device's own network or through a relay. Whether the PC wakes is up to its
    /// firmware and Windows settings, which nothing here can see.
    Sent,
    /// The host never reported a MAC address (it predates standalone reach, or has no usable adapter): nothing to wake it
    /// by.
    Unsupported,
    /// The host is not on a network of this device, and no relay it is registered with could send the packet for it.
    NoRelay,
}

/// Wakes a sleeping host by Wake-on-LAN. A magic packet only works from the host's own network, so this tries that
/// first: when one of this device's networks holds a LAN address of the host, the packet goes out there (the phone on
/// the home Wi-Fi, the laptop on the home LAN). Otherwise it asks a relay on the host's network ([`wake_through_relay`]).
///
/// Does not wait for the PC to wake: [`WakeOutcome::Sent`] says the packet left, no more.
pub async fn wake(identity: &Identity, host: &KnownHost) -> Result<WakeOutcome> {
    let Some(mac) = host.mac else { return Ok(WakeOutcome::Unsupported) };
    let targets = lan_targets(host);
    if !targets.is_empty() && tokio::task::spawn_blocking(move || wake_on_lan(&mac, &targets)).await? {
        return Ok(WakeOutcome::Sent);
    }
    wake_through_relay(identity, host).await
}

/// The host's IPv4 addresses on its LAN, in the order stored: the ones its last `Reach` called `Lan`, and the plain
/// addresses stored before that when they look like a LAN address. Names and other kinds do not say where the host's
/// network is.
fn lan_targets(host: &KnownHost) -> Vec<Ipv4Addr> {
    let listed = host.kinds.iter().map(|(kind, text)| (Some(kind), text.as_str()));
    let plain = std::iter::once(host.address.as_str()).chain(host.also.iter().map(String::as_str)).map(|t| (None, t));
    let mut targets = Vec::new();
    for (kind, text) in listed.chain(plain) {
        let Some(IpAddr::V4(ip)) = text.parse::<SocketAddr>().map(|a| a.ip()).or_else(|_| text.parse::<IpAddr>()).ok()
        else {
            continue;
        };
        let lan = match kind {
            Some(kind) => *kind == AddressKind::Lan,
            None => guess_kind(ip.into()) == AddressKind::Lan,
        };
        if lan && !targets.contains(&ip) {
            targets.push(ip);
        }
    }
    targets
}

/// Sends the packet on the first network of this device that holds one of `targets`. Blocking. `false` when no network
/// does (the device is not at the host's LAN) or nothing could be sent.
fn wake_on_lan(mac: &[u8; 6], targets: &[Ipv4Addr]) -> bool {
    let networks = velora_nat::wake::wake_networks();
    targets.iter().filter_map(|ip| velora_nat::wake::network_of(&networks, *ip)).any(|network| {
        velora_nat::wake::wake_on(mac, &network).inspect_err(|e| tracing::warn!("wake-on-LAN: {e:#}")).is_ok()
    })
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        },
    };

    use super::*;

    const HOST: Fingerprint = Fingerprint([9; 32]);

    /// Documentation addresses (RFC 5737): never a real machine.
    fn addr(n: u8) -> SocketAddr {
        SocketAddr::from(([192, 0, 2, n], 7420))
    }

    fn direct(n: u8) -> Candidate {
        Candidate::Direct(addr(n), AddressKind::Lan)
    }

    fn relay(n: u8) -> Candidate {
        Candidate::Relay { relay_addr: addr(n), relay_fingerprint: Fingerprint([n; 32]), target: HOST }
    }

    fn punch(n: u8) -> Candidate {
        Candidate::Punch { endpoint: addr(n), via: Vec::new() }
    }

    const fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    // ---- the race, on a paused clock with candidates that only wait ----

    /// What a fake candidate does once started.
    #[derive(Clone, Copy)]
    enum Answer {
        Connects(Duration),
        Fails(Duration),
        Hangs,
        Panics,
    }

    type Lookup = Pin<Box<dyn Future<Output = Result<Vec<Candidate>>> + Send>>;

    /// A lookup that answers after `delay`.
    fn lookup_after(delay: Duration, answer: std::result::Result<Vec<Candidate>, &'static str>) -> Lookup {
        Box::pin(async move {
            tokio::time::sleep(delay).await;
            answer.map_err(|e| anyhow!(e))
        })
    }

    /// Counts the attempts that exist: one while its future is alive.
    struct Alive(Arc<AtomicUsize>);

    impl Alive {
        fn new(count: &Arc<AtomicUsize>) -> Self {
            count.fetch_add(1, Ordering::SeqCst);
            Self(count.clone())
        }
    }

    impl Drop for Alive {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    struct Run {
        result: Result<(Candidate, String)>,
        /// When each candidate started, in milliseconds after the race began.
        starts: Vec<(Candidate, u64)>,
        /// When the race returned, the same way.
        ended: u64,
        /// Attempts whose future still existed after the race returned.
        left_running: usize,
    }

    async fn run(
        first: Vec<Candidate>,
        lookup: Option<Lookup>,
        answer: impl Fn(&Candidate) -> Answer + Send + Sync + 'static,
    ) -> Run {
        let begun = Instant::now();
        let starts = Arc::new(Mutex::new(Vec::new()));
        let alive = Arc::new(AtomicUsize::new(0));
        let answer = Arc::new(answer);
        let dial = {
            let (starts, alive) = (starts.clone(), alive.clone());
            move |candidate: Candidate| {
                let (starts, alive, answer) = (starts.clone(), alive.clone(), answer.clone());
                async move {
                    let _alive = Alive::new(&alive);
                    starts.lock().unwrap().push((candidate.clone(), begun.elapsed().as_millis() as u64));
                    match answer(&candidate) {
                        Answer::Connects(after) => {
                            tokio::time::sleep(after).await;
                            Ok(candidate.to_string())
                        }
                        Answer::Fails(after) => {
                            tokio::time::sleep(after).await;
                            Err(anyhow!("{candidate} did not answer"))
                        }
                        Answer::Hangs => std::future::pending().await,
                        Answer::Panics => panic!("a hook with a bug"),
                    }
                }
            }
        };
        let result = race(first, lookup, dial).await;
        let ended = begun.elapsed().as_millis() as u64;
        // The attempts that were aborted are dropped when the runtime next gets to them.
        for _ in 0..3 {
            tokio::task::yield_now().await;
        }
        let starts = starts.lock().unwrap().clone();
        Run { result, starts, ended, left_running: alive.load(Ordering::SeqCst) }
    }

    #[tokio::test(start_paused = true)]
    async fn direct_candidates_start_a_stagger_apart_and_the_first_address_tells_the_failure() {
        let run = run(vec![direct(1), direct(2), direct(3)], None, |_| Answer::Fails(ms(5000))).await;
        assert_eq!(run.starts, vec![(direct(1), 0), (direct(2), 250), (direct(3), 500)]);
        assert_eq!(run.ended, 5500);
        assert!(run.result.unwrap_err().to_string().contains(&direct(1).to_string()));
    }

    #[tokio::test(start_paused = true)]
    async fn the_failure_of_the_first_address_wins_even_when_another_failed_earlier() {
        let run =
            run(vec![direct(1), direct(2)], None, |c| Answer::Fails(if *c == direct(1) { ms(2000) } else { ms(100) }))
                .await;
        assert_eq!(run.ended, 2000);
        assert!(run.result.unwrap_err().to_string().contains(&direct(1).to_string()));
    }

    #[tokio::test(start_paused = true)]
    async fn the_first_handshake_wins_and_the_others_are_dropped() {
        let run = run(vec![direct(1), direct(2), direct(3)], None, |c| {
            if *c == direct(2) {
                Answer::Connects(ms(100))
            } else {
                Answer::Hangs
            }
        })
        .await;
        let (won, value) = run.result.unwrap();
        assert_eq!((won, value), (direct(2), direct(2).to_string()));
        // The third never started: the race was over at 350 ms, before its 500.
        assert_eq!(run.starts, vec![(direct(1), 0), (direct(2), 250)]);
        assert_eq!(run.ended, 350);
        assert_eq!(run.left_running, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_late_candidate_joins_the_race_on_the_same_rules() {
        // The stored address never answers; the lookup finds another one a second after it was asked.
        let lookup = lookup_after(ms(1000), Ok(vec![direct(2)]));
        let run =
            run(
                vec![direct(1)],
                Some(lookup),
                |c| {
                    if *c == direct(2) {
                        Answer::Connects(ms(100))
                    } else {
                        Answer::Hangs
                    }
                },
            )
            .await;
        assert_eq!(run.result.unwrap().0, direct(2));
        // Asked after LOOKUP_DELAY, answered 1000 ms later, started at once (its stagger slot is long past).
        assert_eq!(run.starts, vec![(direct(1), 0), (direct(2), 1500)]);
        assert_eq!(run.ended, 1600);
        assert_eq!(run.left_running, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn late_candidates_keep_the_stagger_with_the_ones_before_them() {
        let lookup = lookup_after(ms(100), Ok(vec![direct(4), direct(5)]));
        let run = run(vec![direct(1), direct(2), direct(3)], Some(lookup), |_| Answer::Fails(ms(5000))).await;
        // The lookup answers at 600 ms; the third address took the slot at 500, so the next free is 750, then 1000.
        let starts: Vec<u64> = run.starts.iter().map(|(_, at)| *at).collect();
        assert_eq!(starts, vec![0, 250, 500, 750, 1000]);
    }

    #[tokio::test(start_paused = true)]
    async fn the_lookup_is_left_alone_when_a_candidate_connects_before_its_delay() {
        let t0 = Instant::now();
        let asked = Arc::new(Mutex::new(None));
        let probe: Lookup = {
            let asked = asked.clone();
            Box::pin(async move {
                *asked.lock().unwrap() = Some(t0.elapsed().as_millis() as u64);
                Ok(Vec::new())
            })
        };
        let run = run(vec![direct(1)], Some(probe), |_| Answer::Connects(ms(50))).await;
        assert!(run.result.is_ok());
        assert_eq!(*asked.lock().unwrap(), None);
    }

    #[tokio::test(start_paused = true)]
    async fn the_lookup_is_asked_at_once_when_every_candidate_has_failed() {
        let t0 = Instant::now();
        let asked = Arc::new(Mutex::new(None));
        let probe: Lookup = {
            let asked = asked.clone();
            Box::pin(async move {
                *asked.lock().unwrap() = Some(t0.elapsed().as_millis() as u64);
                Ok(vec![direct(2)])
            })
        };
        let run = run(vec![direct(1)], Some(probe), |c| {
            if *c == direct(1) {
                Answer::Fails(ms(50))
            } else {
                Answer::Connects(ms(10))
            }
        })
        .await;
        assert_eq!(run.result.unwrap().0, direct(2));
        assert_eq!(*asked.lock().unwrap(), Some(50));
    }

    #[tokio::test(start_paused = true)]
    async fn a_lookup_that_fails_or_finds_nothing_is_not_fatal() {
        for lookup in [lookup_after(ms(10), Err("no network")), lookup_after(ms(10), Ok(Vec::new()))] {
            let run = run(vec![direct(1)], Some(lookup), |_| Answer::Connects(ms(1000))).await;
            assert_eq!(run.result.unwrap().0, direct(1));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_lookup_that_panics_costs_the_lookup_and_nothing_else() {
        async fn lookup_with_a_bug() -> Result<Vec<Candidate>> {
            panic!("a hook with a bug")
        }
        let run = run(vec![direct(1)], Some(Box::pin(lookup_with_a_bug())), |_| Answer::Connects(ms(1000))).await;
        assert_eq!(run.result.unwrap().0, direct(1));
    }

    #[tokio::test(start_paused = true)]
    async fn a_lookup_that_never_answers_is_given_up_when_nothing_else_is_left() {
        let hangs: Lookup = Box::pin(std::future::pending());
        let run = run(vec![direct(1)], Some(hangs), |_| Answer::Fails(ms(100))).await;
        // The candidate failed at 100 ms, the lookup started then and was cut off LOOKUP_LIMIT later.
        assert_eq!(run.ended, 100 + LOOKUP_LIMIT.as_millis() as u64);
        assert!(run.result.unwrap_err().to_string().contains(&direct(1).to_string()));
    }

    #[tokio::test(start_paused = true)]
    async fn relays_start_two_seconds_after_the_first_direct_candidate() {
        // Listed first on purpose: the batch is read direct candidates first.
        let run = run(vec![relay(7), direct(1), direct(2)], None, |_| Answer::Fails(ms(5000))).await;
        assert_eq!(run.starts, vec![(direct(1), 0), (direct(2), 250), (relay(7), 2000)]);
    }

    #[tokio::test(start_paused = true)]
    async fn relays_and_punches_go_one_stagger_apart_after_their_delay() {
        let run = run(vec![direct(1), punch(8), relay(7), relay(6)], None, |_| Answer::Fails(ms(5000))).await;
        assert_eq!(
            run.starts,
            vec![(direct(1), 0), (punch(8), 2000), (relay(7), 2250), (relay(6), 2500)],
            "in the order they were listed, since both wait the same"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn two_addresses_of_one_relay_are_not_dialed_together_but_another_relay_is_not_held_up() {
        let at_address = |relay: u8, address: u8| Candidate::Relay {
            relay_addr: addr(address),
            relay_fingerprint: Fingerprint([relay; 32]),
            target: HOST,
        };
        let (first, second, other) = (at_address(7, 10), at_address(7, 11), at_address(8, 12));
        let run =
            run(vec![direct(1), first.clone(), second.clone(), other.clone()], None, |_| Answer::Fails(ms(9000))).await;
        // The relay lane is 250 ms a candidate, and the second address of relay 7 waits 2 s after the first.
        assert_eq!(run.starts, vec![(direct(1), 0), (first, 2000), (other, 2500), (second, 4000)]);
    }

    #[tokio::test(start_paused = true)]
    async fn relays_start_at_once_when_there_is_no_direct_candidate_and_count_from_one_that_comes_late() {
        let lookup = lookup_after(ms(100), Ok(vec![direct(2), relay(8)]));
        let run = run(vec![relay(7)], Some(lookup), |_| Answer::Fails(ms(5000))).await;
        // The relay of the first batch had nothing to wait for. The lookup comes at 600 ms with a direct address, which
        // starts at once, and a relay, which waits its two seconds from that.
        assert_eq!(run.starts, vec![(relay(7), 0), (direct(2), 600), (relay(8), 2600)]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_way_of_reaching_the_host_is_tried_once_however_often_it_is_proposed() {
        // The record repeats the stored address (with another label, since a kind is only a label) and the relay.
        let again = Candidate::Direct(addr(1), AddressKind::Public);
        let lookup = lookup_after(ms(10), Ok(vec![again, direct(2), relay(7)]));
        let run = run(vec![direct(1), relay(7)], Some(lookup), |_| Answer::Fails(ms(5000))).await;
        let tried: Vec<Candidate> = run.starts.into_iter().map(|(c, _)| c).collect();
        // The relay would have started at 2000 ms; the race is still on then (nothing answers), so all three show up.
        assert_eq!(tried, vec![direct(1), direct(2), relay(7)]);
    }

    #[tokio::test(start_paused = true)]
    async fn no_more_than_the_cap_of_candidates_is_started() {
        let many: Vec<Candidate> = (0..40u16)
            .map(|i| Candidate::Direct(SocketAddr::from(([192, 0, 2, 1], 7000 + i)), AddressKind::Lan))
            .collect();
        let run = run(many, None, |_| Answer::Fails(ms(1))).await;
        assert_eq!(run.starts.len(), MAX_CANDIDATES);
        assert!(run.result.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn nothing_to_try_is_an_error() {
        let run = run(Vec::new(), None, |_| Answer::Fails(ms(1))).await;
        assert!(run.result.unwrap_err().to_string().contains("no address to try"));
    }

    #[tokio::test(start_paused = true)]
    async fn a_hook_that_panics_costs_its_candidate_and_nothing_else() {
        let run = run(vec![direct(1), direct(2)], None, |c| {
            if *c == direct(1) {
                Answer::Panics
            } else {
                Answer::Connects(ms(10))
            }
        })
        .await;
        assert_eq!(run.result.unwrap().0, direct(2));
    }

    // ---- the candidates that come from what is stored ----

    fn params(addr: SocketAddr, also: Vec<SocketAddr>, host: Option<KnownHost>) -> ConnectParams {
        ConnectParams {
            addr,
            also,
            host_fingerprint: HOST,
            identity: Identity::generate().unwrap(),
            device_name: "test device".into(),
            pairing_secret: None,
            password: None,
            reach: host.map(|host| ReachParams { host, state_dir: PathBuf::from("state") }),
        }
    }

    #[test]
    fn without_reach_data_the_candidates_are_the_stored_addresses_with_a_guessed_kind() {
        let public = SocketAddr::from(([8, 8, 8, 8], 7420));
        let vpn = SocketAddr::from(([100, 101, 102, 103], 7420));
        let found = stored_candidates(&params(addr(1), vec![vpn, addr(1), public], None));
        assert_eq!(
            found,
            vec![
                Candidate::Direct(addr(1), AddressKind::Lan),
                Candidate::Direct(vpn, AddressKind::Vpn),
                Candidate::Direct(public, AddressKind::Public),
            ]
        );
    }

    #[test]
    fn kinds_are_guessed_from_the_address() {
        let guess = |text: &str| guess_kind(text.parse().unwrap());
        for lan in ["192.168.1.20", "10.0.0.5", "172.16.4.4", "169.254.3.4", "127.0.0.1", "fd12:3456::1", "fe80::1"] {
            assert_eq!(guess(lan), AddressKind::Lan, "{lan}");
        }
        for vpn in ["100.101.102.103", "fd7a:115c:a1e0::1"] {
            assert_eq!(guess(vpn), AddressKind::Vpn, "{vpn}");
        }
        assert_eq!(guess("8.8.8.8"), AddressKind::Public);
        assert_eq!(guess("2606:4700:4700::1111"), AddressKind::V6);
    }

    #[test]
    fn the_hosts_last_reach_adds_addresses_with_their_kinds_and_its_relays() {
        let relay_fp = Fingerprint([7; 32]).to_base64();
        let vpn = SocketAddr::from(([100, 101, 102, 103], 7420));
        let host = KnownHost {
            kinds: vec![
                (AddressKind::Lan, "192.0.2.1:7420".into()),
                (AddressKind::Vpn, "100.101.102.103:7420".into()),
                (AddressKind::Public, "198.51.100.7:51820".into()),
                (AddressKind::V6, "[2606:4700:4700::1111]:7420".into()),
                // A relay's own address is not the host's: it must not be dialed as one.
                (AddressKind::Relay(relay_fp.clone()), "203.0.113.9:7420".into()),
                (AddressKind::Other(77), "192.0.2.77:7420".into()),
                (AddressKind::Lan, "not an address".into()),
            ],
            relays: vec![
                (relay_fp.clone(), vec!["203.0.113.9:7420".into(), "203.0.113.10:7420".into(), "garbage".into()]),
                ("not a fingerprint".into(), vec!["203.0.113.11:7420".into()]),
                // The host cannot be its own relay.
                (HOST.to_base64(), vec!["203.0.113.12:7420".into()]),
            ],
            ..Default::default()
        };
        let found = stored_candidates(&params(addr(1), vec![vpn], Some(host)));
        let relay_at = |ip: u8| Candidate::Relay {
            relay_addr: SocketAddr::from(([203, 0, 113, ip], 7420)),
            relay_fingerprint: Fingerprint([7; 32]),
            target: HOST,
        };
        assert_eq!(
            found,
            vec![
                Candidate::Direct(addr(1), AddressKind::Lan),
                Candidate::Direct(vpn, AddressKind::Vpn),
                Candidate::Direct(SocketAddr::from(([198, 51, 100, 7], 51820)), AddressKind::Public),
                Candidate::Direct("[2606:4700:4700::1111]:7420".parse().unwrap(), AddressKind::V6),
                Candidate::Direct(addr(77), AddressKind::Other(77)),
                relay_at(9),
                relay_at(10),
            ]
        );
    }

    #[test]
    fn the_routes_of_candidates_name_the_address_dialed() {
        assert_eq!(direct(1).route(), Route { kind: AddressKind::Lan, address: "192.0.2.1:7420".into() });
        assert_eq!(
            relay(2).route(),
            Route { kind: AddressKind::Relay(Fingerprint([2; 32]).to_base64()), address: "192.0.2.2:7420".into() }
        );
        assert_eq!(punch(3).route(), Route { kind: AddressKind::Public, address: "192.0.2.3:7420".into() });
        assert_eq!(direct(1).route().to_string(), "lan 192.0.2.1:7420");
    }

    #[test]
    fn all_zero_keys_and_secrets_are_none() {
        assert_eq!(non_zero([0u8; 32]), None);
        assert_eq!(non_zero([0u8; 16]), None);
        assert_eq!(non_zero([0, 0, 1, 0]), Some([0, 0, 1, 0]));
    }

    #[test]
    fn nothing_that_opens_the_record_reaches_a_log() {
        let info = ReachInfo {
            addresses: vec![(AddressKind::Lan, "192.0.2.1:7420".into())],
            key: Some([0xAB; 32]),
            secret: Some([0xCD; 16]),
            relays: Vec::new(),
            mac: Some([0xEF; 6]),
            relays_for_others: false,
        };
        let host = KnownHost { name: "PC".into(), key: info.key, secret: info.secret, ..Default::default() };
        let reach = ReachParams { host, state_dir: PathBuf::from("state") };
        for text in [format!("{info:?}"), format!("{reach:?}")] {
            for byte in ["171", "205", "239"] {
                assert!(!text.contains(byte), "{byte} in {text}");
            }
        }
    }

    // ---- wake ----

    #[test]
    fn the_lan_targets_of_a_host_are_its_lan_addresses_in_ipv4() {
        let host = KnownHost {
            address: "192.0.2.20:7420".into(),
            also: vec!["100.101.102.103:7420".into(), "mypc.example:7420".into(), "192.0.2.30".into()],
            kinds: vec![
                (AddressKind::Vpn, "192.0.2.50:7420".into()),
                (AddressKind::Lan, "192.0.2.21:7420".into()),
                (AddressKind::Lan, "[fd12:3456::1]:7420".into()),
                (AddressKind::Public, "198.51.100.7:51820".into()),
                (AddressKind::Lan, "192.0.2.21:7420".into()),
            ],
            ..Default::default()
        };
        let ip = |last: u8| Ipv4Addr::new(192, 0, 2, last);
        // What the host called Lan first, then the plain addresses that look like one; no repeats.
        assert_eq!(lan_targets(&host), vec![ip(21), ip(20), ip(30)]);
    }

    #[tokio::test]
    async fn a_host_that_reported_no_mac_cannot_be_woken() {
        let host = KnownHost { address: "192.0.2.20:7420".into(), ..Default::default() };
        assert_eq!(wake(&Identity::generate().unwrap(), &host).await.unwrap(), WakeOutcome::Unsupported);
    }

    #[tokio::test]
    async fn a_host_off_every_network_of_this_device_is_left_to_the_relays() {
        // 203.0.113.0/24 is a documentation range: no network of this device holds it, so nothing is sent.
        let host = KnownHost {
            mac: Some([0x02, 1, 2, 3, 4, 5]),
            kinds: vec![(AddressKind::Lan, "203.0.113.9:7420".into())],
            ..Default::default()
        };
        assert_eq!(wake(&Identity::generate().unwrap(), &host).await.unwrap(), WakeOutcome::NoRelay);
    }
}
