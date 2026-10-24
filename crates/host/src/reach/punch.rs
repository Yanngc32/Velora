//! Hole punching, host side: seeing the endpoint the NAT shows, and opening a hole toward a client
//! on request. Filled in by ticket E5 (with `poll.rs`); the plumbing it plugs into is
//! `reach/mod.rs`, which E5 does not edit.
//!
//! Two jobs, and a client needs both to reach a host that sits behind a NAT with no router mapping
//! and no relay in the way:
//!
//! 1. [`run`] finds out which `ip:port` the NAT shows the world for the QUIC socket, and whether it
//!    shows the same one to everybody. A client can only dial a host it knows that endpoint of, and
//!    only a NAT that keeps one endpoint per socket lets the client's packets in once the host has
//!    sent something out. The result goes in `ReachState::observed` and `nat`; E3 puts it in the
//!    DHT record (`ReachState::record_addresses`), which is how a client learns where to punch to.
//! 2. [`respond`] is the host's half of the simultaneous open. A client that wants in sends a
//!    request ("my endpoint is this, nonce that"), by a relay (E4 hands it over) or by the DHT
//!    (`poll.rs`), and dials the host's observed endpoint. The host sends one QUIC Initial toward
//!    the client's endpoint from the listening port, which makes its NAT expect the client's
//!    packets, and the client's own Initial, which it keeps retransmitting, gets through.
//!
//! The endpoint [`run`] measures is only good while the NAT keeps the mapping it describes. A NAT forgets a mapping
//! that has seen no packet leave for anything from 30 seconds to a few minutes, and makes the next one with the port it
//! likes, which may be another. Nothing else sends from the listening port while no client is connected, so [`run`]
//! does, while the endpoint is advertised: one DHT ping to one node every [`KEEPALIVE`] (a registered relay needs none:
//! its connection leaves from the same socket and keeps the mapping by itself). The answer says where the node sees the
//! socket: another endpoint on the internet than the one measured means the NAT made another mapping (a router
//! restarted, the computer woke up), and [`run`] measures again at once, at most once in [`REMEASURE_GAP`].
//!
//! A request is untrusted: whoever holds a paired device's secret (or a relay) can make one for any
//! endpoint, and the host would send a 1200-byte packet there, once per attempt. So [`respond`]
//! serves only paired devices, only toward unicast internet addresses, each nonce once, within a
//! rate limit per device and overall, and with a handful of attempts at a time.

use std::{
    collections::HashMap,
    fmt, io,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex, MutexGuard, PoisonError,
    },
    time::{Duration, Instant, SystemTime},
};

use anyhow::Result;
use velora_nat::{
    addresses::classify,
    observe::{default_dht_nodes, DhtProbe, NatType, Observation, Observed},
};
use velora_protocol::{
    identity::{AuthorizedClient, StateDir},
    tls::{self, Fingerprint},
};

use super::{PunchRequest, ReachContext, ReachState};

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

// ---------------------------------------------------------------------------------------------
// Seeing the endpoint the NAT shows
// ---------------------------------------------------------------------------------------------

/// Answers after which waiting longer tells nothing new (as in `velora_nat::observe`).
const ENOUGH_ANSWERS: usize = 3;

/// How often a datagram goes from the QUIC socket to a DHT node while the endpoint is advertised, so that the NAT's
/// mapping of the socket does not expire between measurements. A UDP mapping lasts from 30 seconds (Linux's default for
/// a flow nobody has answered, and many routers) to a few minutes, and a packet that leaves renews it (some NATs count
/// the ones that arrive too, which only helps): 20 seconds is inside the shortest. Three packets a minute, each a DHT
/// ping of 65 bytes that the node answers with a pong.
const KEEPALIVE: Duration = Duration::from_secs(20);

/// How long a keepalive keeps its probe on the socket for the node's answer, so that the answer never reaches quinn.
/// One that comes later reaches quinn, which drops it.
const KEEPALIVE_REPLY: Duration = Duration::from_secs(2);

/// The least time after a measurement before a keepalive that saw the socket at another endpoint may start one. A node
/// that is wrong, or a mapping that keeps changing, must not make the host measure over and over: the gap doubles for
/// each measurement a keepalive starts until one finds the endpoint as it was measured, up to the interval between
/// periodic measurements, and an endpoint a measurement did not confirm is not asked for again.
const REMEASURE_GAP: Duration = Duration::from_secs(60);

/// How the observation is paced. The defaults are the product's; tests shorten them through
/// [`Observing`].
#[derive(Debug, Clone)]
struct Timing {
    /// The most a round waits for answers.
    wait: Duration,
    /// A silent node is pinged again this often (UDP loses packets, and the first one opens the NAT).
    resend: Duration,
    /// How long the nodes still silent get to answer once two different ones have.
    settle: Duration,
    /// How long a good result is trusted before it is measured again.
    refresh: Duration,
    /// How long after a round that learnt nothing the next one starts, doubling up to `retry_max`.
    retry_min: Duration,
    retry_max: Duration,
    /// How long the host waits after its network addresses changed before measuring again, so a
    /// burst of changes (a laptop joining a Wi-Fi) costs one round.
    debounce: Duration,
    /// How long the resolved DHT node addresses are kept.
    renew_nodes: Duration,
    /// How often a datagram keeps the NAT's mapping of the QUIC socket alive between two measurements.
    keepalive: Duration,
    /// How long a keepalive waits for the node's answer, which the probe keeps away from quinn.
    keepalive_reply: Duration,
    /// The least time after a measurement before a keepalive that saw another endpoint may start one.
    remeasure_gap: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Timing {
            wait: Duration::from_secs(3),
            resend: Duration::from_millis(750),
            settle: Duration::from_millis(400),
            refresh: Duration::from_secs(10 * 60),
            retry_min: Duration::from_secs(30),
            retry_max: Duration::from_secs(5 * 60),
            debounce: Duration::from_secs(2),
            renew_nodes: Duration::from_secs(30 * 60),
            keepalive: KEEPALIVE,
            keepalive_reply: KEEPALIVE_REPLY,
            remeasure_gap: REMEASURE_GAP,
        }
    }
}

/// What [`run`] asks and how it paces itself, per host (`ctx.ext::<Observing>()`).
#[derive(Default)]
pub struct Observing {
    timing: Mutex<Timing>,
    /// The DHT nodes to ask; the public bootstrap names when unset.
    nodes: Mutex<Option<Vec<SocketAddr>>>,
    /// Keepalive datagrams sent so far (the tests count them).
    keepalives: AtomicU64,
    /// Measurement rounds begun so far (the tests count them).
    measurements: AtomicU64,
}

impl Observing {
    fn timing(&self) -> Timing {
        lock(&self.timing).clone()
    }

    fn nodes(&self) -> Option<Vec<SocketAddr>> {
        lock(&self.nodes).clone()
    }

    /// How many keepalive datagrams the host has sent from its QUIC socket.
    pub fn keepalives(&self) -> u64 {
        self.keepalives.load(Ordering::Relaxed)
    }

    /// How many measurement rounds the host has begun.
    pub fn measurements(&self) -> u64 {
        self.measurements.load(Ordering::Relaxed)
    }
}

/// What a change of network shows in the state: the LAN and IPv6 addresses of this computer and the address the router
/// mapped (`ReachState::mapping`, E2's). When it changes the endpoint the NAT shows has probably changed too. The
/// `Public` addresses are not in it: they only repeat the mapping's address, and E2 changes them as its verdict about
/// the mapping changes, a verdict it makes from what this task measured. With them in, each of the two woke the other,
/// and a round that learnt nothing dropped the endpoint, though nothing about the network had changed.
type Signature = (Vec<String>, Vec<String>, Option<String>);

fn network_signature(state: &ReachState) -> Signature {
    use velora_protocol::wire::AddressKind::{Lan, V6};
    (state.addresses_of(&Lan), state.addresses_of(&V6), state.mapping.as_ref().map(|mapping| mapping.external.clone()))
}

/// The observing task. Started when standalone reach is on; it ends when `ctx.stop` fires.
///
/// It measures the endpoint the NAT shows for the QUIC socket with a probe on the multiplexer
/// (`ctx.socket.probe(..)` and `velora_nat::observe::DhtProbe`: send its pings with
/// `Probe::send_to`, offer every datagram the probe hears to `DhtProbe::handle`) and writes
/// `state.observed` and `state.nat` (both `None` when it learnt nothing). Repeat when the network
/// may have changed, not in a tight loop. Do not add the observed endpoint to `state.addresses`:
/// `ReachState::record_addresses()` puts it in the DHT record as a `Public` address when the NAT
/// keeps one endpoint per socket and no mapped address is advertised, and nowhere else, since a
/// client dialling it straight would only fail.
///
/// This is how it does that. A round pings the DHT's bootstrap nodes (IPv4 only: the DHT is) and reads the address each
/// one saw the ping come from (BEP 42), until three have answered, or two different ones have and 400 ms went by, or 3
/// s are up. A round that learnt nothing is followed by another after 30 s, then 60, up to 5 minutes; a good one by
/// another in 10 minutes, or 2 seconds after the host's LAN or IPv6 addresses or the address its router mapped changed
/// (E2's verdict about that mapping, which comes and goes in the `Public` addresses, is no change of network). The old
/// result stays until the new one replaces it (the same answer changes nothing, so the DHT record is not published
/// again for it), and is dropped if the new network teaches nothing, since it describes a network the host has left, or
/// a mapping the NAT has replaced. Only an endpoint on the internet is published as `observed`: a private one is the
/// inner side of a second NAT. When the task ends both fields are cleared.
///
/// A node inside a provider's network says a private address (S0 saw two in 136 replies), and one such vote would make
/// a cone NAT look symmetric: while any vote names an address on the internet, only those count, for what is classified
/// and for when the round is done. With none public they all count (a host behind two NATs still gets its NAT
/// classified).
///
/// Between two measurements it keeps the mapping alive (see the module docs and [`keepalive_wanted`]): one DHT ping to
/// one node every [`KEEPALIVE`] while the record sends clients to punch toward the endpoint, the DHT switch is on and
/// no relay is registered. When that is allowed again after a pause (the DHT switch, a relay) the host measures at once
/// instead, since what the mapping did meanwhile is not known. A keepalive whose answer shows the socket at another
/// endpoint on the internet than the one measured (the NAT made another mapping: a router restarted, the computer woke
/// up) makes it measure at once as well, but not within [`REMEASURE_GAP`] of the last measurement, and less and less
/// often while what the keepalives see keeps changing, and not for an endpoint a measurement did not confirm. The
/// keepalives go to the nodes that told the host where its socket is in the last measurement.
pub async fn run(ctx: ReachContext) -> Result<()> {
    let observing = ctx.ext::<Observing>();
    let timing = observing.timing();
    let mut changes = ctx.reach.subscribe();
    let mut signature = network_signature(&ctx.reach.read());
    let mut nodes: Vec<SocketAddr> = Vec::new();
    let mut nodes_from = Instant::now();
    let mut retry = timing.retry_min;
    let mut shown: (Option<SocketAddr>, Option<NatType>) = (None, None);
    // The addresses changed since the last result was taken, or a keepalive showed that the endpoint measured is gone.
    let mut moved = false;
    let mut keeper = Keeper::new();

    while !ctx.stop.is_stopped() {
        if nodes.is_empty() || nodes_from.elapsed() >= timing.renew_nodes {
            nodes = match observing.nodes() {
                Some(nodes) => nodes,
                // The system resolver can take seconds on a network without DNS.
                None => tokio::task::spawn_blocking(default_dht_nodes).await.unwrap_or_default(),
            };
            nodes_from = Instant::now();
        }
        observing.measurements.fetch_add(1, Ordering::Relaxed);
        let learnt = observe(&ctx, &nodes, &timing).await.unwrap_or_else(|e| {
            tracing::debug!("no DHT node could be asked: {e}");
            None
        });
        let wait = match learnt {
            Some(seen) => {
                retry = timing.retry_min;
                let now = (usable(seen.endpoint).then_some(seen.endpoint), Some(seen.nat));
                if now != shown {
                    match now.0 {
                        Some(endpoint) => {
                            tracing::info!("the NAT shows this computer as {endpoint} ({} NAT)", seen.nat)
                        }
                        None => tracing::info!(
                            "the NAT shows this computer at {}, which is not an internet address ({} NAT)",
                            seen.endpoint,
                            seen.nat
                        ),
                    }
                    shown = now;
                }
                // The votes of an `Observed` are the ones that counted: these nodes told where the socket is.
                keeper.voters = seen.observations.iter().map(|vote| vote.from).collect();
                ctx.reach.update(|state| (state.observed, state.nat) = now);
                timing.refresh
            }
            None => {
                tracing::debug!("no DHT node told this computer how the NAT shows it; trying again in {retry:?}");
                if moved {
                    // The host is on another network and this one teaches nothing: the endpoint it
                    // had belongs to the one it left.
                    shown = (None, None);
                    ctx.reach.update(|state| (state.observed, state.nat) = (None, None));
                }
                let wait = retry;
                retry = (retry * 2).min(timing.retry_max);
                wait
            }
        };
        // The pings of the round left from the socket and renewed the mapping, whatever came of them (a round that
        // could send none means no network, and a keepalive could send none either).
        keeper.measured(&ctx, &timing);
        moved = false;
        match pause(&ctx, &mut changes, &mut signature, wait, &timing, &mut keeper, &nodes).await {
            Pause::Elapsed => {}
            Pause::Moved | Pause::Remapped => {
                moved = true;
                retry = timing.retry_min;
            }
            Pause::Resumed => retry = timing.retry_min,
            Pause::Stopped => break,
        }
    }
    ctx.reach.update(|state| (state.observed, state.nat) = (None, None));
    Ok(())
}

/// Whether `endpoint` is an address the internet can send to: what a client must be told to dial.
fn usable(endpoint: SocketAddr) -> bool {
    classify(endpoint.ip()).is_global()
}

enum Pause {
    /// The time passed.
    Elapsed,
    /// The network addresses changed (and the debounce passed).
    Moved,
    /// The keepalive was allowed again after a time when it was not (the DHT switch, a relay): measure again.
    Resumed,
    /// A keepalive saw the socket at another endpoint than the one measured: measure again.
    Remapped,
    Stopped,
}

/// Waits `wait`, or until the network addresses change, or the keepalive is allowed again, or a keepalive finds the
/// endpoint changed, or the task is told to stop; and sends the keepalive datagrams that fall due meanwhile.
async fn pause(
    ctx: &ReachContext,
    changes: &mut tokio::sync::watch::Receiver<u64>,
    signature: &mut Signature,
    wait: Duration,
    timing: &Timing,
    keeper: &mut Keeper,
    nodes: &[SocketAddr],
) -> Pause {
    let observing = ctx.ext::<Observing>();
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let (allowed, wanted) = {
            let state = ctx.reach.read();
            (keepalive_allowed(&state), keepalive_wanted(&state))
        };
        if allowed && !keeper.was_allowed {
            // It was off while the host went on (the DHT switch, a relay), so nobody knows what the mapping did
            // meanwhile: a measurement says, and renews it. Only these two decide: whether the record advertises the
            // endpoint is E2's verdict and this task's own result, and measuring again for a change of either would be
            // a loop.
            return Pause::Resumed;
        }
        keeper.was_allowed = allowed;
        tokio::select! {
            () = ctx.stop.stopped() => return Pause::Stopped,
            () = tokio::time::sleep_until(deadline) => return Pause::Elapsed,
            () = tokio::time::sleep_until(keeper.next), if wanted => {
                let seen = keeper.keep(ctx, nodes, timing, &observing.keepalives).await;
                if let Some(endpoint) = keeper.weigh(seen, timing) {
                    tracing::info!("a DHT node sees this computer at {endpoint} now: measuring again");
                    return Pause::Remapped;
                }
            }
            changed = changes.changed() => {
                if changed.is_err() {
                    return Pause::Stopped;
                }
                let now = network_signature(&ctx.reach.read());
                if now != *signature {
                    *signature = now;
                    return if ctx.stop.sleep(timing.debounce).await { Pause::Stopped } else { Pause::Moved };
                }
            }
        }
    }
}

/// Whether the mapping of the QUIC socket should be kept alive: [`keepalive_allowed`], and the record sends clients to
/// punch toward `observed`.
fn keepalive_wanted(state: &ReachState) -> bool {
    keepalive_allowed(state) && advertises_punch_endpoint(state)
}

/// Whether the host is in a state in which it keeps the mapping alive at all: standalone reach is on, the DHT switch is
/// on (it is what puts the record in the DHT for clients to read), and no relay is registered. A registered relay is a
/// QUIC connection from this very socket, with keepalives of its own every 2 s, which hold the mapping as well as any
/// datagram of ours when the connection crosses the NAT (the host dials a relay at the first address that answers, so
/// one on the same LAN or over IPv6 may be the one that wins, and holds nothing; the ticket's rule is kept all the
/// same). When this begins to hold after a time when it did not, the host measures at once.
fn keepalive_allowed(state: &ReachState) -> bool {
    state.switches.standalone && state.switches.dht && state.relays.is_empty()
}

/// Whether the host's record makes clients punch toward `observed` (the case `ReachState::record_addresses` adds a
/// `Public` entry for): the NAT keeps one endpoint per socket (an `Open` host has no mapping to keep, and nobody
/// punches through a symmetric one) and no `Public` address is advertised that clients would dial instead (a router's
/// mapping).
fn advertises_punch_endpoint(state: &ReachState) -> bool {
    use velora_protocol::wire::AddressKind::Public;
    state.observed.is_some()
        && state.nat == Some(NatType::EndpointIndependent)
        && state.addresses_of(&Public).is_empty()
}

/// What a keepalive learnt about where the NAT shows the socket.
#[derive(Debug, PartialEq, Eq)]
enum Seen {
    /// Nothing that counts: nothing could be sent, no answer came, the answer carried no address, or one that is not on
    /// the internet (a node inside a provider's network says a private one), or there is no measurement to compare it
    /// with.
    Nothing,
    /// The node sees the socket at the endpoint that was measured.
    Same,
    /// The node sees it at another endpoint on the internet: the NAT made another mapping (a router restarted, the
    /// computer woke up), and the endpoint in the record leads nowhere.
    Changed(SocketAddr),
}

/// What keeps the NAT's mapping of the QUIC socket alive between two measurements.
struct Keeper {
    /// When the next datagram is due.
    next: tokio::time::Instant,
    /// Whether the keepalive was allowed the last time the state was looked at.
    was_allowed: bool,
    /// Which of the nodes the next datagram goes to: they take turns.
    turn: usize,
    /// The nodes that told where the socket is in the last measurement: the ones a keepalive goes to, since a node that
    /// answers without the address (some do) says nothing about the mapping. Empty until a measurement learns some.
    voters: Vec<SocketAddr>,
    /// When the last measurement ended, on the monotonic clock and on the wall clock.
    measured_at: tokio::time::Instant,
    measured_wall: SystemTime,
    /// How many measurements keepalives have started since one last saw the endpoint as it was measured.
    steps: u32,
    /// The endpoint a keepalive saw and the measurement under way was started for.
    asked: Option<SocketAddr>,
    /// An endpoint a keepalive saw and the measurement it started did not confirm.
    declined: Option<SocketAddr>,
}

impl Keeper {
    fn new() -> Keeper {
        let now = tokio::time::Instant::now();
        Keeper {
            next: now,
            was_allowed: false,
            turn: 0,
            voters: Vec::new(),
            measured_at: now,
            measured_wall: SystemTime::now(),
            steps: 0,
            asked: None,
            declined: None,
        }
    }

    /// A measurement was made: its pings left from the socket and renewed the mapping, so the next datagram is due a
    /// full interval from now, and the keepalive is allowed or not as the state says now.
    fn measured(&mut self, ctx: &ReachContext, timing: &Timing) {
        self.measured_at = tokio::time::Instant::now();
        self.measured_wall = SystemTime::now();
        self.next = self.measured_at + timing.keepalive;
        let state = ctx.reach.read();
        self.was_allowed = keepalive_allowed(&state);
        // A measurement that a keepalive asked for either adopted what that keepalive saw or did not. A node that says
        // again what a measurement did not confirm is wrong, and the NAT is not; any other measurement starts afresh.
        self.declined = match self.asked.take() {
            Some(claimed) if state.observed != Some(claimed) => Some(claimed),
            _ => None,
        };
    }

    /// How long after the last measurement a keepalive that saw another endpoint may start one: `remeasure_gap`,
    /// doubled for each measurement a keepalive has started since one last saw the endpoint as it was measured, and
    /// never more than `refresh`. A mapping that changes between every two keepalives is not chased faster than the
    /// host measures anyway.
    fn gap(&self, timing: &Timing) -> Duration {
        timing.remeasure_gap.saturating_mul(1 << self.steps.min(16)).min(timing.refresh)
    }

    /// Whether the last measurement is a [`gap`](Keeper::gap) old. The wall clock counts too: the monotonic one may
    /// stop while the computer sleeps, and a computer that has just woken up is the case this is for.
    fn may_remeasure(&self, timing: &Timing) -> bool {
        let since = self.measured_at.elapsed().max(self.measured_wall.elapsed().unwrap_or_default());
        since >= self.gap(timing)
    }

    /// What to make of what a keepalive saw: the endpoint to measure again for, or `None`. Not for the endpoint a
    /// measurement did not confirm, and not within the gap of the last measurement, so that a node that is wrong, or a
    /// mapping that keeps changing, cannot make the host measure over and over.
    fn weigh(&mut self, seen: Seen, timing: &Timing) -> Option<SocketAddr> {
        match seen {
            Seen::Nothing => None,
            Seen::Same => {
                self.steps = 0;
                None
            }
            Seen::Changed(endpoint) if self.declined == Some(endpoint) => {
                tracing::debug!(
                    "a DHT node sees this computer at {endpoint} again, which a measurement did not confirm"
                );
                None
            }
            Seen::Changed(endpoint) if !self.may_remeasure(timing) => {
                tracing::debug!("a DHT node sees this computer at {endpoint}, but it was measured moments ago");
                None
            }
            Seen::Changed(endpoint) => {
                self.asked = Some(endpoint);
                self.steps = self.steps.saturating_add(1);
                Some(endpoint)
            }
        }
    }

    /// Sends one DHT ping to one node from the QUIC socket, and keeps the probe on the socket for the answer so that
    /// quinn never sees it. Whatever happens the next one is due a full interval from now. The answer says where the
    /// node saw the socket, which is compared with the endpoint measured.
    async fn keep(&mut self, ctx: &ReachContext, nodes: &[SocketAddr], timing: &Timing, sent: &AtomicU64) -> Seen {
        self.next = tokio::time::Instant::now() + timing.keepalive;
        let pool: &[SocketAddr] = if self.voters.is_empty() { nodes } else { &self.voters };
        let Some(node) = pool.get(self.turn % pool.len().max(1)).copied() else { return Seen::Nothing };
        self.turn = self.turn.wrapping_add(1);

        let asked = Arc::new(Mutex::new(DhtProbe::new(&[node])));
        let answered = Arc::new(tokio::sync::Notify::new());
        // The handler runs on quinn's receive path: it only looks at the datagram.
        let probe = ctx.socket.probe({
            let (asked, answered) = (asked.clone(), answered.clone());
            move |from, datagram| {
                let taken = lock(&asked).handle(from, datagram);
                if taken {
                    answered.notify_one();
                }
                taken
            }
        });
        let ping = lock(&asked).pending().next().map(|(_, ping)| ping.to_vec());
        let Some(ping) = ping else { return Seen::Nothing };
        if let Err(e) = probe.send_to(node, &ping).await {
            tracing::debug!("the keepalive toward {node} could not be sent: {e}");
            return Seen::Nothing;
        }
        sent.fetch_add(1, Ordering::Relaxed);
        let heard = tokio::select! {
            () = answered.notified() => true,
            () = tokio::time::sleep(timing.keepalive_reply) => false,
            () = ctx.stop.stopped() => false,
        };
        if !heard {
            return Seen::Nothing;
        }
        // An answer that names no address on the internet says nothing about the mapping.
        let saw = lock(&asked).observations().first().map(|vote| vote.endpoint).filter(|endpoint| usable(*endpoint));
        match (saw, ctx.reach.read().observed) {
            (Some(saw), Some(measured)) if saw == measured => Seen::Same,
            (Some(saw), Some(_)) => Seen::Changed(saw),
            _ => Seen::Nothing,
        }
    }
}

/// The votes that count: those that name an address on the internet, while there are any. A node inside a provider's
/// network says a private address (S0 saw two in 136 replies), and one such vote would make a cone NAT look symmetric
/// and end a round too soon. With no public vote they all count, so a host behind two NATs still has its NAT classified
/// (and `observed` stays unset, as [`usable`] says).
fn counted(votes: &[Observation]) -> Vec<Observation> {
    let public: Vec<Observation> = votes.iter().copied().filter(|vote| usable(vote.endpoint)).collect();
    if public.is_empty() {
        votes.to_vec()
    } else {
        public
    }
}

/// How many different servers (by IP) have answered.
fn distinct_servers(observations: &[Observation]) -> usize {
    let mut ips: Vec<_> = observations.iter().map(|observation| observation.from.ip()).collect();
    ips.sort();
    ips.dedup();
    ips.len()
}

/// One round: pings `nodes` from the QUIC socket until enough have answered, and summarises what
/// they saw. `Ok(None)` when nobody told us anything. An error only when not one ping could be
/// sent (no route, an address family the socket does not reach).
async fn observe(ctx: &ReachContext, nodes: &[SocketAddr], timing: &Timing) -> io::Result<Option<Observed>> {
    if nodes.is_empty() {
        return Ok(None);
    }
    let asked = Arc::new(Mutex::new(DhtProbe::new(nodes)));
    // The handler runs on quinn's receive path: it only looks at the datagram.
    let probe = ctx.socket.probe({
        let asked = asked.clone();
        move |from, datagram| lock(&asked).handle(from, datagram)
    });
    let started = Instant::now();
    let (mut next_round, mut second_server) = (started, None::<Instant>);
    let (mut sent_any, mut last_error) = (false, None);
    let observations = loop {
        let now = Instant::now();
        if now >= next_round {
            let pending: Vec<(SocketAddr, Vec<u8>)> =
                lock(&asked).pending().map(|(node, ping)| (node, ping.to_vec())).collect();
            for (node, ping) in pending {
                match probe.send_to(node, &ping).await {
                    Ok(()) => sent_any = true,
                    Err(e) => last_error = Some(e),
                }
            }
            next_round = Instant::now() + timing.resend;
            if !sent_any {
                // Nothing went out, so there is nothing to wait for.
                return Err(last_error.unwrap_or_else(|| io::Error::other("no ping was sent")));
            }
        }
        let (all_answered, seen) = {
            let asked = lock(&asked);
            let all_answered = asked.pending().next().is_none();
            (all_answered, counted(asked.observations()))
        };
        let now = Instant::now();
        // Two different servers among the votes that count. A first public vote can displace private ones, and then
        // there is one again.
        if distinct_servers(&seen) >= 2 {
            second_server.get_or_insert(now);
        } else {
            second_server = None;
        }
        let settled = second_server.is_some_and(|at| now >= at + timing.settle);
        if all_answered || seen.len() >= ENOUGH_ANSWERS || settled || now >= started + timing.wait {
            break seen;
        }
        let mut wake = next_round.min(started + timing.wait);
        if let Some(at) = second_server {
            wake = wake.min(at + timing.settle);
        }
        if ctx.stop.sleep(wake.saturating_duration_since(now)).await {
            return Ok(None);
        }
    };
    drop(probe);
    Ok(Observed::new(ctx.socket.local_addr(), observations))
}

// ---------------------------------------------------------------------------------------------
// Opening a hole on request
// ---------------------------------------------------------------------------------------------

/// How the responder is limited. The defaults are the product's; tests change them through
/// [`Punching::settings`].
#[derive(Debug, Clone, Copy)]
pub(super) struct Settings {
    /// How long an attempt lasts if the client does not arrive. Its own connection attempt would
    /// give up after the idle timeout (15 s); the client gives up on a relay path after 10 s, and
    /// on the DHT path later.
    attempt_for: Duration,
    /// Attempts under way at once.
    max_attempts: usize,
    /// How long a served nonce is remembered. A request older than a minute is refused as stale
    /// before it gets here (DHT) or is a replay of an old relay message (relay).
    nonce_memory: Duration,
    /// Most nonces remembered.
    max_nonces: usize,
    /// Per device: a burst, then one more request every `device_refill`.
    device_burst: f64,
    device_refill: Duration,
    /// All devices together.
    overall_burst: f64,
    overall_refill: Duration,
    /// Let a request name a loopback, private or link-local address. Only tests do.
    allow_local: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            attempt_for: Duration::from_secs(12),
            max_attempts: 4,
            nonce_memory: Duration::from_secs(10 * 60),
            max_nonces: 512,
            device_burst: 4.0,
            device_refill: Duration::from_secs(10),
            overall_burst: 8.0,
            overall_refill: Duration::from_secs(2),
            allow_local: false,
        }
    }
}

/// A token bucket: `take` is allowed while there is a token, and tokens come back at a steady pace.
#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    at: Instant,
}

impl Bucket {
    fn full(burst: f64, now: Instant) -> Bucket {
        Bucket { tokens: burst, at: now }
    }

    fn refilled(&self, burst: f64, refill: Duration, now: Instant) -> f64 {
        let earned = now.saturating_duration_since(self.at).as_secs_f64() / refill.as_secs_f64().max(f64::EPSILON);
        (self.tokens + earned).min(burst)
    }

    fn take(&mut self, burst: f64, refill: Duration, now: Instant) -> bool {
        self.tokens = self.refilled(burst, refill, now);
        self.at = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[derive(Default)]
struct Ledger {
    /// Requests served, until `nonce_memory` has passed.
    nonces: HashMap<(Fingerprint, u64), Instant>,
    devices: HashMap<Fingerprint, Bucket>,
    overall: Option<Bucket>,
    in_flight: usize,
}

/// What the responder did, for tests and logs.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PunchStats {
    /// Attempts begun: a QUIC Initial went toward a client.
    pub started: u64,
    /// Requests turned away, whatever the reason.
    pub refused: u64,
    /// Requests that were a repeat of one already served.
    pub repeated: u64,
    /// Attempts that ended because the client's own connection arrived.
    pub arrived: u64,
    /// Attempts that ended because their time was up.
    pub expired: u64,
}

/// The responder's state, one per host (`ctx.ext::<Punching>()`): the limits and what they remember.
#[derive(Default)]
pub struct Punching {
    settings: Mutex<Settings>,
    ledger: Mutex<Ledger>,
    started: AtomicU64,
    refused: AtomicU64,
    repeated: AtomicU64,
    arrived: AtomicU64,
    expired: AtomicU64,
    /// Attempts under way, for tests to wait on.
    attempts: AtomicUsize,
}

impl Punching {
    fn settings(&self) -> Settings {
        *lock(&self.settings)
    }

    /// What the responder did so far.
    pub fn stats(&self) -> PunchStats {
        PunchStats {
            started: self.started.load(Ordering::Relaxed),
            refused: self.refused.load(Ordering::Relaxed),
            repeated: self.repeated.load(Ordering::Relaxed),
            arrived: self.arrived.load(Ordering::Relaxed),
            expired: self.expired.load(Ordering::Relaxed),
        }
    }

    /// How many attempts are under way now.
    pub fn attempts(&self) -> usize {
        self.attempts.load(Ordering::Relaxed)
    }

    /// Checks a request that passed every test of its content against the nonces and the limits,
    /// and if it is to be served notes it and takes a slot.
    fn admit(&self, device: Fingerprint, nonce: u64, now: Instant) -> Result<Admission, Refusal> {
        let settings = self.settings();
        let mut ledger = lock(&self.ledger);
        ledger.nonces.retain(|_, served| now.saturating_duration_since(*served) < settings.nonce_memory);
        if ledger.nonces.contains_key(&(device, nonce)) {
            return Ok(Admission::Repeat);
        }
        if ledger.in_flight >= settings.max_attempts {
            return Err(Refusal::Busy);
        }
        // The device's allowance is spent first, so one flooding device cannot use up the overall one
        // for the others; a refused request costs the overall allowance nothing.
        let bucket = ledger.devices.entry(device).or_insert_with(|| Bucket::full(settings.device_burst, now));
        if !bucket.take(settings.device_burst, settings.device_refill, now) {
            return Err(Refusal::RateLimited);
        }
        let overall = ledger.overall.get_or_insert_with(|| Bucket::full(settings.overall_burst, now));
        if !overall.take(settings.overall_burst, settings.overall_refill, now) {
            return Err(Refusal::RateLimited);
        }
        if ledger.nonces.len() >= settings.max_nonces {
            let oldest = ledger.nonces.iter().min_by_key(|(_, served)| **served).map(|(key, _)| *key);
            if let Some(oldest) = oldest {
                ledger.nonces.remove(&oldest);
            }
        }
        // Devices that have recovered their whole allowance are as good as new ones.
        ledger.devices.retain(|_, bucket| {
            bucket.refilled(settings.device_burst, settings.device_refill, now) < settings.device_burst
        });
        ledger.nonces.insert((device, nonce), now);
        ledger.in_flight += 1;
        Ok(Admission::Serve)
    }

    fn finished(&self) {
        let mut ledger = lock(&self.ledger);
        ledger.in_flight = ledger.in_flight.saturating_sub(1);
    }
}

enum Admission {
    Serve,
    Repeat,
}

/// Gives a slot back when the attempt ends, however it ends.
struct Slot(Arc<Punching>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.finished();
        self.0.attempts.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Why a request was not served. The text is for the log of whoever passed it on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Standalone reach is off: this host did not agree to open anything.
    Off,
    /// `from` is not a fingerprint.
    BadFingerprint,
    /// `endpoint` is not an `ip:port`.
    BadEndpoint,
    /// The device is not on the paired list (it may have been removed meanwhile).
    NotPaired,
    /// The endpoint is not somewhere a packet should be sent: the text says why.
    Destination(&'static str),
    /// Too many requests, from this device or from all of them.
    RateLimited,
    /// Attempts are under way already.
    Busy,
    /// The QUIC endpoint could not start the attempt (an address family its socket does not reach).
    Cannot(String),
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::Off => f.write_str("standalone reach is off"),
            Refusal::BadFingerprint => f.write_str("the requesting device is not named by a fingerprint"),
            Refusal::BadEndpoint => f.write_str("the endpoint is not an ip:port"),
            Refusal::NotPaired => f.write_str("the requesting device is not paired with this computer"),
            Refusal::Destination(why) => write!(f, "the endpoint is not one to send to: {why}"),
            Refusal::RateLimited => f.write_str("too many punch requests"),
            Refusal::Busy => f.write_str("other punch attempts are under way"),
            Refusal::Cannot(why) => write!(f, "cannot start the attempt: {why}"),
        }
    }
}

impl std::error::Error for Refusal {}

/// Whether the host may send a packet to `endpoint` because a client asked it to: a unicast address
/// on the internet with a port. The endpoint is what the client says its NAT shows, and the host
/// takes nobody's word for more than that: it is never a loopback, private, link-local, shared
/// (carrier NAT) or multicast address, where a packet would reach something that never asked.
fn check_destination(endpoint: SocketAddr, allow_local: bool) -> Result<(), &'static str> {
    use velora_nat::addresses::AddressClass::*;
    let ip = endpoint.ip().to_canonical();
    if endpoint.port() == 0 {
        return Err("port 0");
    }
    if ip.is_unspecified() {
        return Err("the unspecified address");
    }
    if ip.is_multicast() {
        return Err("a multicast address");
    }
    if allow_local {
        return Ok(());
    }
    match classify(ip) {
        Public | GlobalV6 => Ok(()),
        Private => Err("a private address"),
        Shared => Err("a shared (carrier NAT) address"),
        LinkLocal => Err("a link-local address"),
        Loopback => Err("a loopback address"),
        UniqueLocal => Err("a unique-local address"),
        Other => Err("an address that is not for the internet"),
    }
}

/// The name the paired device `fingerprint` has, or `None` when it is not paired.
fn paired_name(state: &StateDir, fingerprint: &Fingerprint) -> Option<String> {
    let clients: Vec<AuthorizedClient> = state.load(StateDir::AUTHORIZED_CLIENTS).ok()?;
    let wanted = fingerprint.to_base64();
    clients.into_iter().find(|client| client.fingerprint == wanted).map(|client| client.name)
}

/// Whether the client's own connection has arrived since `since`: the host notes every device that
/// connects (`ClientActivity`), after it has authenticated.
fn arrived(ctx: &ReachContext, client: &Fingerprint, since: Instant) -> bool {
    ctx.reach.read().clients.last_connect.is_some_and(|(who, at)| who == *client && at >= since)
}

/// A client asked this host to open a hole toward it: from a relay (E4 passes on the
/// `HostMsg::PunchRequest` it reads on its registration connection) or from the DHT poller
/// (`poll.rs`). Parse the request (it is untrusted text), check the client is paired, and send
/// toward its endpoint from the listening port with `ctx.endpoint.connect_with`, dropping the
/// attempt when the client's own connection arrives. Return once the attempt is under way.
///
/// This is what it checks, in this order, and an `Err` (a [`Refusal`]) says which test failed:
/// standalone reach is on; `from` is a fingerprint on the paired list (re-read from the file, so a
/// removal counts at once); `endpoint` is an `ip:port` on the internet ([`check_destination`]); the
/// nonce is new for that device (a repeat of a request already served returns `Ok` and does
/// nothing); the device and all devices together are within their rates; fewer than four attempts
/// are under way. Then one QUIC connection attempt toward the endpoint begins, pinned to the
/// client's certificate (it is never expected to complete: the client's endpoint only dials). It
/// is kept for 12 s, its Initial retransmitted by QUIC's own timers, and dropped as soon as the
/// client's own connection arrives, when its time is up, or when `ctx.stop` fires.
pub async fn respond(ctx: &ReachContext, request: PunchRequest) -> Result<()> {
    let punching = ctx.ext::<Punching>();
    match serve(ctx, &punching, &request).await {
        Ok(()) => Ok(()),
        Err(refusal) => {
            punching.refused.fetch_add(1, Ordering::Relaxed);
            Err(refusal.into())
        }
    }
}

async fn serve(ctx: &ReachContext, punching: &Arc<Punching>, request: &PunchRequest) -> Result<(), Refusal> {
    if !ctx.reach.read().switches.standalone {
        return Err(Refusal::Off);
    }
    let settings = punching.settings();
    let client = Fingerprint::from_base64(&request.from).map_err(|_| Refusal::BadFingerprint)?;
    let endpoint: SocketAddr = request.endpoint.trim().parse().map_err(|_| Refusal::BadEndpoint)?;
    let endpoint = SocketAddr::new(endpoint.ip().to_canonical(), endpoint.port());
    // A small file read, in case the list is on a slow disk.
    let name = {
        let state = ctx.state_dir.clone();
        tokio::task::spawn_blocking(move || paired_name(&state, &client)).await.unwrap_or(None)
    }
    .ok_or(Refusal::NotPaired)?;
    check_destination(endpoint, settings.allow_local).map_err(Refusal::Destination)?;

    let started = Instant::now();
    match punching.admit(client, request.nonce, started)? {
        Admission::Repeat => {
            punching.repeated.fetch_add(1, Ordering::Relaxed);
            tracing::debug!("'{name}' asked again for the hole it asked for ({:08x}); not repeating it", request.nonce);
            return Ok(());
        }
        Admission::Serve => {}
    }
    let slot = Slot(punching.clone());
    punching.attempts.fetch_add(1, Ordering::Relaxed);

    let config = tls::client_config(&ctx.identity, client).map_err(|e| Refusal::Cannot(format!("{e:#}")))?;
    let connecting =
        ctx.endpoint.connect_with(config, endpoint, tls::SERVER_NAME).map_err(|e| Refusal::Cannot(e.to_string()))?;
    punching.started.fetch_add(1, Ordering::Relaxed);
    tracing::info!("opening a hole toward '{name}' at {endpoint}");

    let (ctx, punching) = (ctx.clone(), punching.clone());
    tokio::spawn(async move {
        let outcome = attempt(&ctx, client, started, connecting, settings.attempt_for).await;
        match outcome {
            Outcome::Arrived => {
                punching.arrived.fetch_add(1, Ordering::Relaxed);
                tracing::debug!("'{name}' arrived; the attempt toward {endpoint} is over");
            }
            Outcome::TimedOut => {
                punching.expired.fetch_add(1, Ordering::Relaxed);
                tracing::info!("'{name}' did not arrive through the hole toward {endpoint}");
            }
            Outcome::Ended => tracing::debug!("the attempt toward {endpoint} ended"),
        }
        drop(slot);
    });
    Ok(())
}

enum Outcome {
    Arrived,
    TimedOut,
    /// The attempt ended by itself (it completed or failed) or the task was told to stop.
    Ended,
}

/// Keeps the connection attempt alive, which keeps its Initial going out, until the client arrives
/// or `lasts` is up. Dropping `connecting` ends the attempt quietly.
async fn attempt(
    ctx: &ReachContext,
    client: Fingerprint,
    since: Instant,
    connecting: quinn::Connecting,
    lasts: Duration,
) -> Outcome {
    let mut changes = ctx.reach.subscribe();
    let end = tokio::time::sleep(lasts);
    tokio::pin!(end, connecting);
    loop {
        if arrived(ctx, &client, since) {
            return Outcome::Arrived;
        }
        tokio::select! {
            result = &mut connecting => {
                // The client's endpoint is not expected to accept; if it did there is a connection
                // nobody uses.
                if let Ok(connection) = result {
                    connection.close(0u32.into(), b"hole open");
                }
                return Outcome::Ended;
            }
            _ = changes.changed() => {}
            () = &mut end => return Outcome::TimedOut,
            () = ctx.stop.stopped() => return Outcome::Ended,
        }
    }
}

/// A NAT on the loopback, for tests of hole punching. It is written to be copied: it needs nothing
/// but `std` and `tokio` (`net`, `rt`, `sync`), so the client's tests (F4) take this module as it is.
///
/// Nothing on one machine routes through a NAT, so the simulation changes who talks to whom. A device behind a
/// [`SimNat`] does not send to a peer's public address: it sends to a *gateway port* ([`SimNat::gateway_to`]), one per
/// peer, on the NAT's private side. The gateway forwards what it gets from the NAT's public socket to the peer, as a
/// real NAT rewrites the source address, and remembers the peer so that its answers are let in. What arrives on the
/// public socket is let in or dropped by the NAT's filtering, and delivered to the device from the gateway port of its
/// sender, so the device sees every peer at the address it sends to (with the peer's own IP when that is a loopback
/// alias such as
/// 127.0.0.2, so that peers on different IPs count as different servers). The device never learns the
/// peer's real address, and everything it does with the gateway address (dial it, tell it to another
/// host as "the client's endpoint") works as it would with a public one.
///
/// ```ignore
/// let host_nat = SimNat::new(host_socket_addr, Mapping::EndpointIndependent, Filtering::PortRestricted)?;
/// let client_nat = SimNat::new(client_socket_addr, Mapping::EndpointIndependent, Filtering::PortRestricted)?;
/// // what each would learn from a DHT node: the endpoint the NAT shows
/// let (host_public, client_public) = (host_nat.public_endpoint(), client_nat.public_endpoint());
/// // what each dials or punches toward
/// let client_dials = client_nat.gateway_to(host_public)?;
/// let host_punches = host_nat.gateway_to(client_public)?;
/// ```
///
/// [`SimNat::expiring`] makes an endpoint-independent NAT that forgets its mapping when the device has sent nothing for
/// a while, and makes another, on another port, with the next packet. [`SimNat::restart`] makes one forget it at once,
/// as a router that restarted does.
#[cfg(test)]
pub(crate) mod nat_sim {
    use std::{
        collections::{HashMap, HashSet},
        io,
        net::{Ipv4Addr, SocketAddr},
        sync::{
            atomic::{AtomicU64, Ordering},
            Arc, Mutex, MutexGuard, PoisonError,
        },
        time::{Duration, Instant},
    };

    use tokio::{net::UdpSocket, task::JoinHandle};

    /// How the NAT chooses the external port of the device's flows (RFC 4787, section 4.1).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Mapping {
        /// One external endpoint for the device's socket, whoever it talks to (a "cone" NAT):
        /// the endpoint a DHT node saw is the one a peer can be told. Hole punching works.
        EndpointIndependent,
        /// A new external port for every peer (a "symmetric" NAT): the endpoint a DHT node saw is
        /// only good for that node. Hole punching fails.
        Dependent,
    }

    /// What the NAT lets in from outside (RFC 4787, section 5).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Filtering {
        /// Anyone who knows the external endpoint (a "full cone" NAT).
        Open,
        /// Only the exact address and port the device has sent to.
        PortRestricted,
    }

    /// What the NAT did with the packets, for tests to look at.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    pub struct NatStats {
        /// From the device out to a peer.
        pub sent: u64,
        /// From a peer in to the device.
        pub delivered: u64,
        /// From outside, dropped by the filtering.
        pub filtered: u64,
    }

    pub struct SimNat {
        shared: Arc<Shared>,
    }

    struct Shared {
        device: SocketAddr,
        mapping: Mapping,
        filtering: Filtering,
        /// How long a mapping lives without a packet from the device (RFC 4787, section 4.3), or `None` for one that
        /// never ends. Only an endpoint-independent NAT has one mapping to end.
        lifetime: Option<Duration>,
        state: Mutex<State>,
        sent: AtomicU64,
        delivered: AtomicU64,
        filtered: AtomicU64,
    }

    struct State {
        gateways: HashMap<SocketAddr, Arc<Gateway>>,
        /// Peers the device has sent to since the mapping was made.
        sent_to: HashSet<SocketAddr>,
        /// The public socket of an endpoint-independent NAT, shared by every flow. With dependent mapping nothing
        /// leaves from it and nothing arriving at it is let in.
        public: Arc<UdpSocket>,
        /// Which mapping `public` is: it goes up when an expired mapping is made again, on another socket and so
        /// another port.
        generation: u64,
        /// When the device last sent anything out.
        refreshed: Instant,
        tasks: Vec<JoinHandle<()>>,
    }

    struct Gateway {
        /// The private side: the device sends here and is sent from here.
        private: Arc<UdpSocket>,
        /// The public socket of this flow alone (dependent mapping); `None` when the mapping's own public socket
        /// carries it.
        own: Option<Arc<UdpSocket>>,
    }

    fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        mutex.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn bind() -> io::Result<Arc<UdpSocket>> {
        bind_on(Ipv4Addr::LOCALHOST)
    }

    /// A socket on `ip`, or on the plain loopback address where this machine has no such address (a macOS has only
    /// 127.0.0.1).
    fn bind_on(ip: Ipv4Addr) -> io::Result<Arc<UdpSocket>> {
        let socket =
            std::net::UdpSocket::bind((ip, 0)).or_else(|_| std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)))?;
        socket.set_nonblocking(true)?;
        Ok(Arc::new(UdpSocket::from_std(socket)?))
    }

    /// Errors of a receive that say nothing about the socket (Windows reports an earlier send to a
    /// closed port on the next receive).
    fn transient(e: &io::Error) -> bool {
        matches!(
            e.kind(),
            io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted | io::ErrorKind::Interrupted
        )
    }

    impl SimNat {
        /// A NAT in front of the UDP socket at `device`. Needs a Tokio runtime.
        pub fn new(device: SocketAddr, mapping: Mapping, filtering: Filtering) -> io::Result<SimNat> {
            SimNat::build(device, mapping, filtering, None)
        }

        /// An endpoint-independent NAT whose mapping ends when the device sends nothing for `lifetime`. The next packet
        /// then makes a mapping again on another port (as a NAT that picks its ports at random does) with an empty
        /// filter, and what arrives meanwhile for the old port is dropped. Only packets that leave renew a mapping.
        /// Time is the real clock: tests make `lifetime` short instead (a paused Tokio clock jumps while real sockets
        /// wait, so it cannot be used).
        pub fn expiring(device: SocketAddr, filtering: Filtering, lifetime: Duration) -> io::Result<SimNat> {
            SimNat::build(device, Mapping::EndpointIndependent, filtering, Some(lifetime))
        }

        fn build(
            device: SocketAddr,
            mapping: Mapping,
            filtering: Filtering,
            lifetime: Option<Duration>,
        ) -> io::Result<SimNat> {
            let public = bind()?;
            let shared = Arc::new(Shared {
                device,
                mapping,
                filtering,
                lifetime,
                state: Mutex::new(State {
                    gateways: HashMap::new(),
                    sent_to: HashSet::new(),
                    public: public.clone(),
                    generation: 0,
                    refreshed: Instant::now(),
                    tasks: Vec::new(),
                }),
                sent: AtomicU64::new(0),
                delivered: AtomicU64::new(0),
                filtered: AtomicU64::new(0),
            });
            let task = tokio::spawn(from_outside(shared.clone(), public, None, 0));
            lock(&shared.state).tasks.push(task);
            Ok(SimNat { shared })
        }

        /// The endpoint the NAT shows the world for the device: what a DHT node or a STUN server
        /// would report, and what a peer is told to dial. For dependent mapping it is the endpoint
        /// of no flow in particular (use [`SimNat::public_endpoint_toward`]). For an expiring NAT
        /// it is the mapping of the moment: after it expires, the next packet from the device
        /// makes another.
        pub fn public_endpoint(&self) -> SocketAddr {
            lock(&self.shared.state).public.local_addr().unwrap_or(self.shared.device)
        }

        /// The endpoint the NAT shows `peer` for the device: [`SimNat::public_endpoint`], or with
        /// dependent mapping the port of the flow toward `peer`.
        pub fn public_endpoint_toward(&self, peer: SocketAddr) -> io::Result<SocketAddr> {
            match &gateway(&self.shared, peer)?.own {
                Some(own) => own.local_addr(),
                None => Ok(self.public_endpoint()),
            }
        }

        /// Where the device sends to reach `peer` (the peer's public endpoint) through the NAT.
        pub fn gateway_to(&self, peer: SocketAddr) -> io::Result<SocketAddr> {
            gateway(&self.shared, peer)?.private.local_addr()
        }

        /// The NAT forgets its mapping now, as a router does when it restarts: what arrives for the old port is
        /// dropped, and the next packet that leaves goes out from another port, with an empty filter. For an
        /// endpoint-independent NAT.
        pub fn restart(&self) {
            remap(&self.shared, &mut lock(&self.shared.state));
        }

        pub fn stats(&self) -> NatStats {
            NatStats {
                sent: self.shared.sent.load(Ordering::Relaxed),
                delivered: self.shared.delivered.load(Ordering::Relaxed),
                filtered: self.shared.filtered.load(Ordering::Relaxed),
            }
        }
    }

    impl Drop for SimNat {
        fn drop(&mut self) {
            for task in lock(&self.shared.state).tasks.drain(..) {
                task.abort();
            }
        }
    }

    /// The gateway for `peer`, made on first use.
    fn gateway(shared: &Arc<Shared>, peer: SocketAddr) -> io::Result<Arc<Gateway>> {
        let mut state = lock(&shared.state);
        if let Some(gateway) = state.gateways.get(&peer) {
            return Ok(gateway.clone());
        }
        // A peer on a loopback alias (127.0.0.2, ...) is heard from its own IP, so that peers on different IPs look
        // like different servers to the device, as they do on the internet.
        let private = match peer {
            SocketAddr::V4(v4) if v4.ip().is_loopback() => bind_on(*v4.ip())?,
            _ => bind()?,
        };
        let own = match shared.mapping {
            Mapping::EndpointIndependent => None,
            Mapping::Dependent => {
                let own = bind()?;
                state.tasks.push(tokio::spawn(from_outside(shared.clone(), own.clone(), Some(peer), 0)));
                Some(own)
            }
        };
        let gateway = Arc::new(Gateway { private, own });
        state.tasks.push(tokio::spawn(from_device(shared.clone(), gateway.clone(), peer)));
        state.gateways.insert(peer, gateway.clone());
        Ok(gateway)
    }

    /// A packet leaves the device toward `peer`: the mapping and the filter exist before it goes, as in a real NAT, so
    /// an answer that comes back at once is let in. Returns the socket it leaves from. A mapping that lived out its
    /// lifetime without a packet is made again first, on another socket, with an empty filter.
    fn outbound(shared: &Arc<Shared>, gateway: &Gateway, peer: SocketAddr) -> Arc<UdpSocket> {
        let mut state = lock(&shared.state);
        if let Some(own) = &gateway.own {
            state.sent_to.insert(peer);
            return own.clone();
        }
        if let Some(lifetime) = shared.lifetime {
            if state.refreshed.elapsed() > lifetime {
                remap(shared, &mut state);
            }
            state.refreshed = Instant::now();
        }
        state.sent_to.insert(peer);
        state.public.clone()
    }

    /// The mapping ends and the NAT makes another: on another socket, so another port, with an empty filter. What
    /// arrives at the old socket is dropped from now on.
    fn remap(shared: &Arc<Shared>, state: &mut State) {
        if let Ok(public) = bind() {
            state.generation += 1;
            let task = tokio::spawn(from_outside(shared.clone(), public.clone(), None, state.generation));
            state.tasks.push(task);
            state.public = public;
            state.sent_to.clear();
        }
    }

    /// What the device sends to a gateway goes out to the gateway's peer from the public socket.
    async fn from_device(shared: Arc<Shared>, gateway: Arc<Gateway>, peer: SocketAddr) {
        let mut buffer = vec![0u8; 65_536];
        loop {
            let (len, from) = match gateway.private.recv_from(&mut buffer).await {
                Ok(received) => received,
                Err(e) if transient(&e) => continue,
                Err(_) => return,
            };
            // Only the device uses its gateways.
            if from != shared.device {
                continue;
            }
            let public = outbound(&shared, &gateway, peer);
            if public.send_to(&buffer[..len], peer).await.is_ok() {
                shared.sent.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// What arrives on a public socket is let in or dropped, and delivered to the device from the
    /// gateway of whoever sent it. `only` is the one peer a flow's own socket (dependent mapping)
    /// takes packets from; `generation` is the mapping the socket belongs to, which no longer
    /// takes anything once the NAT has made another.
    async fn from_outside(shared: Arc<Shared>, socket: Arc<UdpSocket>, only: Option<SocketAddr>, generation: u64) {
        let mut buffer = vec![0u8; 65_536];
        loop {
            let (len, from) = match socket.recv_from(&mut buffer).await {
                Ok(received) => received,
                Err(e) if transient(&e) => continue,
                Err(_) => return,
            };
            let allowed = match (shared.mapping, only) {
                (Mapping::Dependent, Some(peer)) => from == peer && lock(&shared.state).sent_to.contains(&from),
                (Mapping::Dependent, None) => false,
                (Mapping::EndpointIndependent, _) => {
                    let state = lock(&shared.state);
                    let alive = generation == state.generation
                        && shared.lifetime.is_none_or(|lifetime| state.refreshed.elapsed() <= lifetime);
                    alive && (shared.filtering == Filtering::Open || state.sent_to.contains(&from))
                }
            };
            if !allowed {
                shared.filtered.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let Ok(gateway) = gateway(&shared, from) else { continue };
            if gateway.private.send_to(&buffer[..len], shared.device).await.is_ok() {
                shared.delivered.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// What the tests of this file and of `poll.rs` share: a host that has standalone reach on and lets
/// requests name the loopback (which a real one does not), paired devices, and a place to send to.
#[cfg(test)]
pub(super) mod test_support {
    use std::net::Ipv4Addr;

    use tokio::net::UdpSocket;
    use velora_protocol::identity::Identity;

    use super::*;
    use crate::reach::testing;

    pub async fn eventually(what: &str, mut done: impl FnMut() -> bool) {
        for _ in 0..600 {
            if done() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("timed out waiting for {what}");
    }

    pub fn pair(ctx: &ReachContext, identity: &Identity, name: &str) {
        let mut clients: Vec<AuthorizedClient> = ctx.state_dir.load(StateDir::AUTHORIZED_CLIENTS).unwrap();
        clients.push(AuthorizedClient {
            name: name.into(),
            fingerprint: identity.fingerprint().to_base64(),
            added_unix: 0,
            trust_files: false,
        });
        ctx.state_dir.save(StateDir::AUTHORIZED_CLIENTS, &clients).unwrap();
    }

    pub fn request(client: &Identity, endpoint: impl ToString, nonce: u64) -> PunchRequest {
        PunchRequest { from: client.fingerprint().to_base64(), endpoint: endpoint.to_string(), nonce }
    }

    pub fn configure(ctx: &ReachContext, change: impl FnOnce(&mut Settings)) {
        change(&mut lock(&ctx.ext::<Punching>().settings));
    }

    /// A host with standalone reach on that lets requests name the loopback.
    pub fn host(tag: &str) -> (ReachContext, testing::Scratch) {
        let (ctx, scratch) = testing::context(tag);
        ctx.reach.update(|state| state.switches.standalone = true);
        configure(&ctx, |settings| settings.allow_local = true);
        (ctx, scratch)
    }

    /// A UDP socket that is nobody's client but takes what the host sends.
    pub async fn nobody() -> UdpSocket {
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap()
    }

    /// `ctx` with the socket the host really binds: dual-stack, where the machine can do that (check
    /// `ctx.socket.local_addr().is_ipv6()`; it is IPv4 only otherwise).
    pub fn dual_stack(ctx: ReachContext) -> ReachContext {
        use crate::reach::socket::Multiplexer;
        let socket = Arc::new(Multiplexer::new(crate::reach::bind("[::]:0".parse().unwrap()).unwrap()).unwrap());
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(tls::server_config(&ctx.identity).unwrap()),
            socket.clone(),
            Arc::new(quinn::TokioRuntime),
        )
        .unwrap();
        let bind = socket.local_addr();
        ReachContext { socket, endpoint, bind, ..ctx }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use tokio::{
        net::UdpSocket,
        sync::{mpsc, watch},
        task::JoinHandle,
    };
    use velora_nat::observe::reply_to_ping;
    use velora_protocol::{
        control::MappingStatus,
        identity::{AuthorizedClient, Identity},
        wire::AddressKind,
    };

    use super::{
        nat_sim::{Filtering, Mapping, SimNat},
        test_support::{configure, dual_stack, eventually, host, nobody, pair, request},
        *,
    };
    use crate::reach::{testing, RelayEntry, Stop};

    fn refusal(result: Result<()>) -> Refusal {
        result.expect_err("the request should have been refused").downcast::<Refusal>().expect("a Refusal")
    }

    // ---- where a packet may be sent -----------------------------------------------------------

    #[test]
    fn a_request_may_name_a_unicast_address_on_the_internet_and_nothing_else() {
        let check = |text: &str, allow_local| check_destination(text.parse().unwrap(), allow_local);
        for good in ["8.8.8.8:4000", "[2001:4860:4860::8888]:4000", "[::ffff:8.8.8.8]:4000"] {
            assert_eq!(check(good, false), Ok(()), "{good}");
        }
        for (bad, why) in [
            ("127.0.0.1:4000", "a loopback address"),
            ("[::1]:4000", "a loopback address"),
            ("10.1.2.3:4000", "a private address"),
            ("192.168.1.9:4000", "a private address"),
            ("172.16.0.1:4000", "a private address"),
            ("169.254.1.1:4000", "a link-local address"),
            ("[fe80::1]:4000", "a link-local address"),
            ("100.64.0.1:4000", "a shared (carrier NAT) address"),
            ("[fd00::1]:4000", "a unique-local address"),
            ("224.0.0.1:4000", "a multicast address"),
            ("[ff02::1]:4000", "a multicast address"),
            ("0.0.0.0:4000", "the unspecified address"),
            ("[::]:4000", "the unspecified address"),
            ("8.8.8.8:0", "port 0"),
            ("203.0.113.7:4000", "an address that is not for the internet"),
            ("255.255.255.255:4000", "an address that is not for the internet"),
        ] {
            assert_eq!(check(bad, false), Err(why), "{bad}");
        }
        // Tests may let the loopback and private addresses through; nothing else.
        for local in ["127.0.0.1:4000", "10.1.2.3:4000", "[fe80::1]:4000"] {
            assert_eq!(check(local, true), Ok(()), "{local}");
        }
        for still in ["8.8.8.8:0", "0.0.0.0:4000", "224.0.0.1:4000"] {
            assert!(check(still, true).is_err(), "{still}");
        }
    }

    #[test]
    fn a_bucket_gives_a_burst_then_refills_at_its_pace_and_never_past_the_burst() {
        let start = Instant::now();
        let (burst, refill) = (3.0, Duration::from_secs(10));
        let mut bucket = Bucket::full(burst, start);
        assert!((0..3).all(|_| bucket.take(burst, refill, start)));
        assert!(!bucket.take(burst, refill, start));
        // Half a refill later it still has half a token; a refused take takes nothing.
        assert!(!bucket.take(burst, refill, start + Duration::from_secs(5)));
        assert!(bucket.take(burst, refill, start + Duration::from_secs(10)));
        assert!(!bucket.take(burst, refill, start + Duration::from_secs(10)));
        // Left alone for an hour it holds the burst and no more.
        let later = start + Duration::from_secs(3600);
        assert!((0..3).all(|_| bucket.take(burst, refill, later)));
        assert!(!bucket.take(burst, refill, later));
    }

    // ---- the responder -------------------------------------------------------------------------

    #[tokio::test]
    async fn requests_that_are_not_to_be_served_are_refused_and_say_why() {
        let (ctx, _scratch) = testing::context("punch-refuse");
        let (laptop, stranger) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        pair(&ctx, &laptop, "laptop");
        let punching = ctx.ext::<Punching>();

        // Standalone reach is off, so the host agreed to nothing.
        assert_eq!(refusal(respond(&ctx, request(&laptop, "8.8.8.8:4000", 1)).await), Refusal::Off);
        ctx.reach.update(|state| state.switches.standalone = true);

        // The content of the request is untrusted text.
        let nonsense = PunchRequest { from: "nonsense".into(), ..request(&laptop, "8.8.8.8:4000", 1) };
        assert_eq!(refusal(respond(&ctx, nonsense).await), Refusal::BadFingerprint);
        assert_eq!(refusal(respond(&ctx, request(&laptop, "not an endpoint", 1)).await), Refusal::BadEndpoint);
        assert_eq!(refusal(respond(&ctx, request(&laptop, "8.8.8.8", 1)).await), Refusal::BadEndpoint);
        // Only paired devices are served.
        assert_eq!(refusal(respond(&ctx, request(&stranger, "8.8.8.8:4000", 1)).await), Refusal::NotPaired);
        // And only toward the internet.
        for (endpoint, why) in [
            ("127.0.0.1:4000", "a loopback address"),
            ("192.168.1.9:4000", "a private address"),
            ("8.8.8.8:0", "port 0"),
        ] {
            assert_eq!(refusal(respond(&ctx, request(&laptop, endpoint, 1)).await), Refusal::Destination(why));
        }

        // Nothing was sent, and every refusal was counted.
        assert_eq!(punching.stats(), PunchStats { refused: 8, ..Default::default() });
        assert_eq!(punching.attempts(), 0);
    }

    #[tokio::test]
    async fn a_device_removed_from_the_list_is_refused_at_once() {
        let (ctx, _scratch) = host("punch-removed");
        let laptop = Identity::generate().unwrap();
        pair(&ctx, &laptop, "laptop");
        let target = nobody().await;
        respond(&ctx, request(&laptop, target.local_addr().unwrap(), 1)).await.unwrap();

        ctx.state_dir.save(StateDir::AUTHORIZED_CLIENTS, &Vec::<AuthorizedClient>::new()).unwrap();
        let again = request(&laptop, target.local_addr().unwrap(), 2);
        assert_eq!(refusal(respond(&ctx, again).await), Refusal::NotPaired);
    }

    #[tokio::test]
    async fn the_host_sends_a_quic_initial_from_its_listening_port_and_keeps_sending() {
        let (ctx, _scratch) = host("punch-initial");
        let laptop = Identity::generate().unwrap();
        pair(&ctx, &laptop, "laptop");
        let target = nobody().await;

        respond(&ctx, request(&laptop, target.local_addr().unwrap(), 7)).await.unwrap();
        assert_eq!(ctx.ext::<Punching>().attempts(), 1, "the attempt is under way when respond returns");

        let mut buffer = vec![0u8; 4096];
        let mut seen = Vec::new();
        while seen.len() < 2 {
            let (len, from) = tokio::time::timeout(Duration::from_secs(5), target.recv_from(&mut buffer))
                .await
                .expect("the host sent nothing")
                .unwrap();
            seen.push((len, from, buffer[0]));
        }
        for (len, from, first) in seen {
            assert_eq!(from, ctx.socket.local_addr(), "from the port quinn listens on, which is the point");
            assert!(len >= 1200, "a client's first flight is padded to 1200 bytes, this one is {len}");
            assert_eq!(first & 0xc0, 0xc0, "a long-header packet");
        }
    }

    #[tokio::test]
    async fn an_attempt_ends_when_its_time_is_up() {
        let (ctx, _scratch) = host("punch-expire");
        configure(&ctx, |settings| settings.attempt_for = Duration::from_millis(300));
        let laptop = Identity::generate().unwrap();
        pair(&ctx, &laptop, "laptop");
        let target = nobody().await;
        let punching = ctx.ext::<Punching>();

        respond(&ctx, request(&laptop, target.local_addr().unwrap(), 7)).await.unwrap();
        assert_eq!(punching.attempts(), 1);
        eventually("the attempt to end", || punching.attempts() == 0).await;
        assert_eq!(punching.stats(), PunchStats { started: 1, expired: 1, ..Default::default() });
    }

    #[tokio::test]
    async fn an_attempt_ends_when_the_task_that_asked_is_told_to_stop() {
        let (ctx, _scratch) = host("punch-stop");
        let laptop = Identity::generate().unwrap();
        pair(&ctx, &laptop, "laptop");
        let target = nobody().await;
        let (stop, stopped) = watch::channel(false);
        let ctx = ReachContext { stop: Stop::new(stopped), ..ctx };
        let punching = ctx.ext::<Punching>();

        respond(&ctx, request(&laptop, target.local_addr().unwrap(), 7)).await.unwrap();
        assert_eq!(punching.attempts(), 1);
        stop.send(true).unwrap();
        eventually("the attempt to end", || punching.attempts() == 0).await;
        assert_eq!(punching.stats().expired, 0, "told to stop, not out of time");
    }

    #[tokio::test]
    async fn a_request_is_served_once_however_often_it_arrives() {
        let (ctx, _scratch) = host("punch-nonce");
        let laptop = Identity::generate().unwrap();
        pair(&ctx, &laptop, "laptop");
        let target = nobody().await.local_addr().unwrap();
        let punching = ctx.ext::<Punching>();

        respond(&ctx, request(&laptop, target, 7)).await.unwrap();
        // The relay or the DHT hands it over again: nothing happens, and it is not an error.
        respond(&ctx, request(&laptop, target, 7)).await.unwrap();
        respond(&ctx, request(&laptop, target, 7)).await.unwrap();
        assert_eq!(punching.stats(), PunchStats { started: 1, repeated: 2, ..Default::default() });
        // Another nonce is another request; the same nonce from another device is too.
        respond(&ctx, request(&laptop, target, 8)).await.unwrap();
        let phone = Identity::generate().unwrap();
        pair(&ctx, &phone, "phone");
        respond(&ctx, request(&phone, target, 7)).await.unwrap();
        assert_eq!(punching.stats().started, 3);
    }

    #[tokio::test]
    async fn a_device_has_its_own_rate_and_all_devices_share_another() {
        let (ctx, _scratch) = host("punch-rate");
        configure(&ctx, |settings| {
            settings.max_attempts = 100;
            settings.device_burst = 2.0;
            settings.device_refill = Duration::from_secs(3600);
            settings.overall_burst = 4.0;
            settings.overall_refill = Duration::from_secs(3600);
        });
        let (laptop, phone, tablet) =
            (Identity::generate().unwrap(), Identity::generate().unwrap(), Identity::generate().unwrap());
        for (identity, name) in [(&laptop, "laptop"), (&phone, "phone"), (&tablet, "tablet")] {
            pair(&ctx, identity, name);
        }
        let target = nobody().await.local_addr().unwrap();

        // The laptop has two, and a third is turned away; the phone is not affected by that.
        for nonce in 1..=2 {
            respond(&ctx, request(&laptop, target, nonce)).await.unwrap();
        }
        assert_eq!(refusal(respond(&ctx, request(&laptop, target, 3)).await), Refusal::RateLimited);
        for nonce in 1..=2 {
            respond(&ctx, request(&phone, target, nonce)).await.unwrap();
        }
        // Four were served in all, which is all the host does for everybody at this rate.
        assert_eq!(refusal(respond(&ctx, request(&tablet, target, 1)).await), Refusal::RateLimited);
        assert_eq!(ctx.ext::<Punching>().stats().started, 4);
        // A request refused for its rate may be tried again later: its nonce was not spent.
        configure(&ctx, |settings| {
            settings.overall_burst = 100.0;
            settings.overall_refill = Duration::from_millis(1);
        });
        tokio::time::sleep(Duration::from_millis(30)).await;
        respond(&ctx, request(&tablet, target, 1)).await.unwrap();
    }

    #[tokio::test]
    async fn only_so_many_attempts_run_at_once() {
        let (ctx, _scratch) = host("punch-busy");
        configure(&ctx, |settings| settings.max_attempts = 2);
        let laptop = Identity::generate().unwrap();
        pair(&ctx, &laptop, "laptop");
        let target = nobody().await.local_addr().unwrap();

        respond(&ctx, request(&laptop, target, 1)).await.unwrap();
        respond(&ctx, request(&laptop, target, 2)).await.unwrap();
        assert_eq!(refusal(respond(&ctx, request(&laptop, target, 3)).await), Refusal::Busy);
        assert_eq!(ctx.ext::<Punching>().attempts(), 2);
    }

    // ---- seeing the endpoint the NAT shows -----------------------------------------------------

    /// A DHT node on the loopback that answers each ping with the address `claim` says it saw (the `ip`
    /// field of BEP 42), or not at all.
    struct FakeNode {
        addr: SocketAddr,
        /// Where the pings it got came from.
        sources: Arc<Mutex<Vec<SocketAddr>>>,
        /// How long each of them was.
        sizes: Arc<Mutex<Vec<usize>>>,
        task: JoinHandle<()>,
    }

    impl FakeNode {
        fn spawn(ip: Ipv4Addr, claim: impl Fn(SocketAddr) -> Option<SocketAddr> + Send + 'static) -> FakeNode {
            FakeNode::spawn_slow(ip, Duration::ZERO, claim)
        }

        /// One that waits `delay` before it answers a ping.
        fn spawn_slow(
            ip: Ipv4Addr,
            delay: Duration,
            claim: impl Fn(SocketAddr) -> Option<SocketAddr> + Send + 'static,
        ) -> FakeNode {
            FakeNode::spawn_replying(ip, delay, move |from, ping| {
                claim(from).and_then(|seen| reply_to_ping(ping, seen))
            })
        }

        /// One that waits `delay` before it sends what `reply` makes of a ping and of where it came from, if anything.
        fn spawn_replying(
            ip: Ipv4Addr,
            delay: Duration,
            reply: impl Fn(SocketAddr, &[u8]) -> Option<Vec<u8>> + Send + 'static,
        ) -> FakeNode {
            let socket = std::net::UdpSocket::bind((ip, 0)).unwrap();
            socket.set_nonblocking(true).unwrap();
            let socket = UdpSocket::from_std(socket).unwrap();
            let addr = socket.local_addr().unwrap();
            let (sources, sizes) = (Arc::new(Mutex::new(Vec::new())), Arc::new(Mutex::new(Vec::new())));
            let task = tokio::spawn({
                let (sources, sizes) = (sources.clone(), sizes.clone());
                async move {
                    let mut buffer = vec![0u8; 2048];
                    loop {
                        let (len, from) = match socket.recv_from(&mut buffer).await {
                            Ok(received) => received,
                            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => continue,
                            Err(_) => return,
                        };
                        lock(&sources).push(from);
                        lock(&sizes).push(len);
                        if let Some(answer) = reply(from, &buffer[..len]) {
                            tokio::time::sleep(delay).await;
                            let _ = socket.send_to(&answer, from).await;
                        }
                    }
                }
            });
            FakeNode { addr, sources, sizes, task }
        }

        /// How many pings it has heard.
        fn heard(&self) -> usize {
            lock(&self.sources).len()
        }
    }

    impl Drop for FakeNode {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    /// Three nodes that all say the host is at `shown`.
    fn agreeing(shown: SocketAddr) -> Vec<FakeNode> {
        (2..=4).map(|n| FakeNode::spawn(Ipv4Addr::new(127, 0, 0, n), move |_| Some(shown))).collect()
    }

    fn fast() -> Timing {
        Timing {
            wait: Duration::from_millis(800),
            resend: Duration::from_millis(100),
            settle: Duration::from_millis(100),
            refresh: Duration::from_secs(60),
            retry_min: Duration::from_millis(100),
            retry_max: Duration::from_millis(400),
            debounce: Duration::from_millis(50),
            renew_nodes: Duration::from_secs(60),
            // Out of the way of every test that is not about it.
            keepalive: Duration::from_secs(3600),
            keepalive_reply: Duration::from_millis(300),
            remeasure_gap: Duration::from_secs(3600),
        }
    }

    fn ask(ctx: &ReachContext, nodes: &[FakeNode]) {
        ask_with(ctx, nodes, fast());
    }

    fn ask_with(ctx: &ReachContext, nodes: &[FakeNode], timing: Timing) {
        let observing = ctx.ext::<Observing>();
        *lock(&observing.timing) = timing;
        *lock(&observing.nodes) = Some(nodes.iter().map(|node| node.addr).collect());
    }

    /// The pings all the nodes have heard.
    fn heard(nodes: &[FakeNode]) -> usize {
        nodes.iter().map(FakeNode::heard).sum()
    }

    #[tokio::test]
    async fn a_nat_that_shows_one_endpoint_to_every_node_is_a_cone_and_the_record_lists_it() {
        let (ctx, _scratch) = host("observe-cone");
        let shown: SocketAddr = "8.8.8.8:40123".parse().unwrap();
        let nodes = agreeing(shown);
        ask(&ctx, &nodes);
        let task = tokio::spawn(run(ctx.clone()));

        eventually("the endpoint to be seen", || ctx.reach.read().observed.is_some()).await;
        let state = ctx.reach.read().clone();
        assert_eq!((state.observed, state.nat), (Some(shown), Some(NatType::EndpointIndependent)));
        // The pings left from the very port quinn listens on: a NAT maps each source port on its own.
        let port = ctx.socket.local_addr().port();
        for node in &nodes {
            let sources = lock(&node.sources);
            assert!(!sources.is_empty() && sources.iter().all(|from| from.port() == port), "{sources:?}");
        }
        // The answers were kept away from quinn.
        assert!(ctx.socket.stats().probe_replies >= 2);
        // E1's record lists the endpoint as the public address clients punch to; nothing else does.
        assert!(state.record_addresses().contains(&(AddressKind::Public, shown.to_string())));
        assert!(
            state.addresses.is_empty() && !state.reach_addresses().iter().any(|(kind, _)| *kind == AddressKind::Public)
        );
        task.abort();
    }

    #[tokio::test]
    async fn a_nat_that_shows_every_node_another_endpoint_cannot_be_punched_and_is_not_listed() {
        let (ctx, _scratch) = host("observe-symmetric");
        let nodes: Vec<FakeNode> = (2..=4u16)
            .map(|n| {
                let shown: SocketAddr = format!("8.8.8.8:{}", 40000 + n).parse().unwrap();
                FakeNode::spawn(Ipv4Addr::new(127, 0, 0, n as u8), move |_| Some(shown))
            })
            .collect();
        ask(&ctx, &nodes);
        let task = tokio::spawn(run(ctx.clone()));

        eventually("the NAT to be classified", || ctx.reach.read().nat.is_some()).await;
        let state = ctx.reach.read().clone();
        assert_eq!(state.nat, Some(NatType::Dependent));
        assert!(!state.record_addresses().iter().any(|(kind, _)| *kind == AddressKind::Public), "nobody could dial it");
        task.abort();
    }

    #[tokio::test]
    async fn an_endpoint_that_is_not_on_the_internet_is_not_published() {
        // The inner side of a second NAT, as a few DHT nodes show it.
        let (ctx, _scratch) = host("observe-private");
        let nodes = agreeing("10.9.8.7:5000".parse().unwrap());
        ask(&ctx, &nodes);
        let task = tokio::spawn(run(ctx.clone()));

        eventually("the NAT to be classified", || ctx.reach.read().nat.is_some()).await;
        let state = ctx.reach.read().clone();
        assert_eq!((state.nat, state.observed), (Some(NatType::EndpointIndependent), None));
        task.abort();
    }

    #[test]
    fn the_votes_that_count_are_the_public_ones_while_there_are_any() {
        let vote = |node: u8, shown: &str| Observation {
            from: SocketAddr::from(([127, 0, 0, node], 6881)),
            endpoint: shown.parse().unwrap(),
        };
        let (inside, a, b) = (vote(2, "10.1.2.3:4000"), vote(3, "8.8.8.8:40123"), vote(4, "8.8.8.8:40123"));
        assert_eq!(counted(&[inside, a, b]), vec![a, b], "the private vote does not count");
        assert_eq!(counted(&[a, inside]), vec![a]);
        // Nothing public: the NAT is still classified from what there is.
        assert_eq!(counted(&[inside]), vec![inside]);
        let (other, third) = (vote(5, "10.9.9.9:1"), vote(6, "192.168.7.7:2"));
        assert_eq!(counted(&[inside, other, third]), vec![inside, other, third]);
        assert!(counted(&[]).is_empty());
        // Loopback, shared (carrier) and the other kinds that are no address of the internet are private votes too.
        let (loopback, shared) = (vote(7, "127.0.0.1:9"), vote(8, "100.64.1.2:9"));
        assert_eq!(counted(&[loopback, shared, a]), vec![a]);
    }

    #[tokio::test]
    async fn one_vote_from_inside_a_providers_network_does_not_make_a_cone_nat_look_symmetric() {
        let (ctx, _scratch) = host("observe-inside");
        let (public, private): (SocketAddr, SocketAddr) =
            ("8.8.8.8:40123".parse().unwrap(), "10.1.2.3:4000".parse().unwrap());
        let nodes = vec![
            FakeNode::spawn(Ipv4Addr::new(127, 0, 0, 2), move |_| Some(private)),
            FakeNode::spawn(Ipv4Addr::new(127, 0, 0, 3), move |_| Some(public)),
            FakeNode::spawn(Ipv4Addr::new(127, 0, 0, 4), move |_| Some(public)),
        ];
        ask(&ctx, &nodes);
        let task = tokio::spawn(run(ctx.clone()));

        eventually("the NAT to be classified", || ctx.reach.read().nat.is_some()).await;
        let state = ctx.reach.read().clone();
        assert_eq!((state.observed, state.nat), (Some(public), Some(NatType::EndpointIndependent)));
        assert!(
            state.record_addresses().contains(&(AddressKind::Public, public.to_string())),
            "and the record lists it"
        );
        task.abort();
    }

    #[tokio::test]
    async fn a_round_does_not_end_on_a_private_vote_and_one_public_one() {
        // The private and the first public answer come at once, the second public one a moment later, past the time two
        // servers would have ended the round if the private vote counted as one of them.
        let (ctx, _scratch) = host("observe-slow");
        let (public, private): (SocketAddr, SocketAddr) =
            ("8.8.8.8:40123".parse().unwrap(), "10.1.2.3:4000".parse().unwrap());
        let nodes = vec![
            FakeNode::spawn(Ipv4Addr::new(127, 0, 0, 2), move |_| Some(private)),
            FakeNode::spawn(Ipv4Addr::new(127, 0, 0, 3), move |_| Some(public)),
            FakeNode::spawn_slow(Ipv4Addr::new(127, 0, 0, 4), Duration::from_millis(350), move |_| Some(public)),
        ];
        ask(&ctx, &nodes);
        let task = tokio::spawn(run(ctx.clone()));

        eventually("the NAT to be classified", || ctx.reach.read().nat.is_some()).await;
        let state = ctx.reach.read().clone();
        assert_eq!((state.observed, state.nat), (Some(public), Some(NatType::EndpointIndependent)));
        task.abort();
    }

    #[tokio::test]
    async fn a_public_vote_that_displaces_two_private_ones_does_not_leave_the_round_settled() {
        // Two private votes (two servers: the round would end once the settle time has gone by), then a public one that
        // displaces them (one server again), then a second public one long after the settle time would have gone by.
        let (ctx, _scratch) = host("observe-displaced");
        let (public, private): (SocketAddr, SocketAddr) =
            ("8.8.8.8:40123".parse().unwrap(), "10.1.2.3:4000".parse().unwrap());
        let nodes = vec![
            FakeNode::spawn(Ipv4Addr::new(127, 0, 0, 2), move |_| Some(private)),
            FakeNode::spawn(Ipv4Addr::new(127, 0, 0, 3), move |_| Some(private)),
            FakeNode::spawn_slow(Ipv4Addr::new(127, 0, 0, 4), Duration::from_millis(150), move |_| Some(public)),
            FakeNode::spawn_slow(Ipv4Addr::new(127, 0, 0, 5), Duration::from_millis(800), move |_| Some(public)),
        ];
        ask_with(&ctx, &nodes, Timing { settle: Duration::from_millis(400), wait: Duration::from_secs(2), ..fast() });
        let task = tokio::spawn(run(ctx.clone()));

        eventually("the NAT to be classified", || ctx.reach.read().nat.is_some()).await;
        let state = ctx.reach.read().clone();
        assert_eq!((state.observed, state.nat), (Some(public), Some(NatType::EndpointIndependent)));
        task.abort();
    }

    #[tokio::test]
    async fn one_public_vote_is_an_endpoint_and_no_classification() {
        let (ctx, _scratch) = host("observe-one");
        let (public, private): (SocketAddr, SocketAddr) =
            ("8.8.8.8:40123".parse().unwrap(), "10.1.2.3:4000".parse().unwrap());
        let nodes = vec![
            FakeNode::spawn(Ipv4Addr::new(127, 0, 0, 2), move |_| Some(private)),
            FakeNode::spawn(Ipv4Addr::new(127, 0, 0, 3), move |_| Some(public)),
            FakeNode::spawn(Ipv4Addr::new(127, 0, 0, 4), |_| None),
        ];
        ask(&ctx, &nodes);
        let task = tokio::spawn(run(ctx.clone()));

        eventually("the endpoint to be seen", || ctx.reach.read().observed.is_some()).await;
        // One server on the internet cannot say whether the NAT maps ports by destination: the record does not list it.
        let state = ctx.reach.read().clone();
        assert_eq!((state.observed, state.nat), (Some(public), Some(NatType::Unknown)));
        assert!(!state.record_addresses().iter().any(|(kind, _)| *kind == AddressKind::Public));
        task.abort();
    }

    #[tokio::test]
    async fn a_host_that_nothing_translates_is_open() {
        // Nodes that report the address they really saw: there is no NAT.
        let (ctx, _scratch) = host("observe-open");
        let nodes: Vec<FakeNode> = (2..=4).map(|n| FakeNode::spawn(Ipv4Addr::new(127, 0, 0, n), Some)).collect();
        ask(&ctx, &nodes);
        let task = tokio::spawn(run(ctx.clone()));

        eventually("the NAT to be classified", || ctx.reach.read().nat.is_some()).await;
        // The loopback is not an internet address, so there is no endpoint to publish.
        assert_eq!((ctx.reach.read().nat, ctx.reach.read().observed), (Some(NatType::Open), None));
        task.abort();
    }

    // ---- keeping the mapping alive -----------------------------------------------------------

    fn relay_entry() -> RelayEntry {
        RelayEntry {
            fingerprint: Fingerprint([7; 32]),
            name: "relay".into(),
            addresses: vec!["198.51.100.9:7420".into()],
        }
    }

    /// A host whose mapping should be kept: everything on, a cone NAT showing `8.8.8.8:40123`, no relay, no mapped
    /// address.
    fn keeping() -> ReachState {
        let mut state = ReachState::default();
        state.switches.standalone = true;
        state.switches.dht = true;
        state.observed = Some("8.8.8.8:40123".parse().unwrap());
        state.nat = Some(NatType::EndpointIndependent);
        state
    }

    /// What `keepalive_wanted` says once `change` has been made to the state of [`keeping`].
    fn wanted_after(change: impl FnOnce(&mut ReachState)) -> bool {
        let mut state = keeping();
        change(&mut state);
        keepalive_wanted(&state)
    }

    #[test]
    fn the_mapping_is_kept_while_the_record_sends_clients_to_punch_and_no_relay_holds_the_socket() {
        assert!(keepalive_wanted(&keeping()));
        assert!(!wanted_after(|state| state.switches.standalone = false), "standalone reach is off");
        assert!(!wanted_after(|state| state.switches.dht = false), "the DHT switch is off: nobody reads the record");
        assert!(!wanted_after(|state| state.set_relays(vec![relay_entry()])), "a registered relay holds the mapping");
        assert!(!wanted_after(|state| state.observed = None), "there is no endpoint to keep");
        // The record sends no one to punch toward it: no cone NAT to keep a mapping of...
        for nat in [None, Some(NatType::Unknown), Some(NatType::Dependent), Some(NatType::Open)] {
            assert!(!wanted_after(|state| state.nat = nat), "{nat:?}");
        }
        // ...or an address that is dialled instead (a router's mapping).
        let mapped = vec!["203.0.113.5:7420".to_string()];
        assert!(!wanted_after(|state| state.set_addresses(AddressKind::Public, mapped)), "a mapped address is dialled");
        // An address of another kind changes nothing.
        assert!(wanted_after(|state| state.set_addresses(AddressKind::Lan, vec!["192.168.1.5:7420".into()])));
    }

    #[test]
    fn the_keepalive_follows_what_the_record_says_about_the_endpoint() {
        // `advertises_punch_endpoint` and `record_addresses` must not drift apart: the record lists `observed` as a
        // `Public` address exactly when there is a mapping to keep (an `Open` host is listed too, and has none).
        let listed = (AddressKind::Public, "8.8.8.8:40123".to_string());
        for nat in [None, Some(NatType::EndpointIndependent), Some(NatType::Dependent), Some(NatType::Unknown)] {
            for mapped in [false, true] {
                let mut state = keeping();
                state.nat = nat;
                if mapped {
                    state.set_addresses(AddressKind::Public, vec!["203.0.113.5:7420".into()]);
                }
                let (kept, said) = (advertises_punch_endpoint(&state), state.record_addresses().contains(&listed));
                assert_eq!(kept, said, "{nat:?}, mapped: {mapped}");
            }
        }
    }

    /// A host with the DHT switch on and nodes that answer, measured once; the keepalive is `every`.
    async fn kept(
        tag: &str,
        every: Duration,
    ) -> (ReachContext, testing::Scratch, Vec<FakeNode>, JoinHandle<Result<()>>) {
        let (ctx, scratch) = host(tag);
        ctx.reach.update(|state| state.switches.dht = true);
        let nodes = agreeing("8.8.8.8:40123".parse().unwrap());
        ask_with(&ctx, &nodes, Timing { keepalive: every, ..fast() });
        let task = tokio::spawn(run(ctx.clone()));
        eventually("the endpoint to be seen", || ctx.reach.read().observed.is_some()).await;
        (ctx, scratch, nodes, task)
    }

    #[tokio::test]
    async fn the_keepalive_is_one_small_datagram_to_one_node_an_interval_and_quinn_never_sees_the_answers() {
        let (ctx, _scratch, nodes, task) = kept("keepalive-count", Duration::from_millis(100)).await;
        let (pings, sent, taken) =
            (heard(&nodes), ctx.ext::<Observing>().keepalives(), ctx.socket.stats().probe_replies);

        tokio::time::sleep(Duration::from_millis(1050)).await;
        let kept = ctx.ext::<Observing>().keepalives() - sent;
        assert!((6..=12).contains(&kept), "{kept} datagrams in 1.05 s at one every 100 ms");
        // Each went to one node (not to all of them), and the nodes took turns.
        let reached = (heard(&nodes) - pings) as u64;
        assert!(reached.abs_diff(kept) <= 1, "{kept} sent, {reached} heard");
        assert!(nodes.iter().all(|node| node.heard() > 1), "the same node every time");
        // Small: a DHT ping.
        assert!(nodes.iter().all(|node| lock(&node.sizes).iter().all(|len| *len <= 100)));
        // The answers were taken by the probe, and quinn never heard of them.
        let answered = ctx.socket.stats().probe_replies - taken;
        assert!(answered.abs_diff(kept) <= 1, "{kept} sent, {answered} answers kept from quinn");
        task.abort();
    }

    #[tokio::test]
    async fn the_keepalive_is_off_while_the_dht_switch_is_off_and_while_a_relay_is_registered() {
        let (ctx, _scratch) = host("keepalive-switches");
        let nodes = agreeing("8.8.8.8:40123".parse().unwrap());
        // The interval is short and the measurement long past, so only the rules keep it quiet.
        ask_with(&ctx, &nodes, Timing { keepalive: Duration::from_millis(80), ..fast() });
        let task = tokio::spawn(run(ctx.clone()));
        eventually("the endpoint to be seen", || ctx.reach.read().observed.is_some()).await;
        let observing = ctx.ext::<Observing>();

        // The DHT switch is off: nobody is told this endpoint, so nothing keeps it.
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(observing.keepalives(), 0);

        // On: the keepalive goes.
        ctx.reach.update(|state| state.switches.dht = true);
        eventually("the keepalive to go", || observing.keepalives() >= 3).await;

        // A relay registers: its connection from the socket does the job.
        ctx.reach.update(|state| state.set_relays(vec![relay_entry()]));
        tokio::time::sleep(Duration::from_millis(200)).await;
        let sent = observing.keepalives();
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(observing.keepalives(), sent, "it went on after a relay registered");

        // The relay goes: the keepalive is back.
        ctx.reach.update(|state| state.set_relays(Vec::new()));
        eventually("the keepalive to come back", || observing.keepalives() >= sent + 3).await;

        // The DHT switch goes off again.
        ctx.reach.update(|state| state.switches.dht = false);
        tokio::time::sleep(Duration::from_millis(200)).await;
        let sent = observing.keepalives();
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(observing.keepalives(), sent, "it went on after the DHT switch went off");
        task.abort();
    }

    #[tokio::test]
    async fn when_the_keepalive_begins_after_a_pause_the_host_measures_at_once() {
        // The interval is longer than the test: a burst of pings can only be a measurement.
        let (ctx, _scratch) = host("keepalive-resume");
        let nodes = agreeing("8.8.8.8:40123".parse().unwrap());
        ask_with(&ctx, &nodes, Timing { keepalive: Duration::from_secs(3600), ..fast() });
        let task = tokio::spawn(run(ctx.clone()));
        eventually("the endpoint to be seen", || ctx.reach.read().observed.is_some()).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        let before: Vec<usize> = nodes.iter().map(FakeNode::heard).collect();

        // What the mapping did while the keepalive was off is not known: the DHT switch comes on, and the host asks
        // again.
        ctx.reach.update(|state| state.switches.dht = true);
        eventually("every node to be asked again", || {
            nodes.iter().zip(&before).all(|(node, before)| node.heard() > *before)
        })
        .await;
        assert_eq!(ctx.ext::<Observing>().keepalives(), 0, "that was a measurement, not a keepalive");
        // A measurement that changes nothing leaves the state as it was.
        assert_eq!(ctx.reach.read().observed, Some("8.8.8.8:40123".parse().unwrap()));
        task.abort();
    }

    #[tokio::test]
    async fn when_the_last_relay_goes_the_host_measures_at_once() {
        // The interval is longer than the test: a burst of pings can only be a measurement.
        let (ctx, _scratch, nodes, task) = kept("keepalive-relay-gone", Duration::from_secs(3600)).await;
        ctx.reach.update(|state| state.set_relays(vec![relay_entry()]));
        tokio::time::sleep(Duration::from_millis(300)).await;
        let before: Vec<usize> = nodes.iter().map(FakeNode::heard).collect();

        // What the mapping did while the relay was there is not known: the relay goes, and the host asks again.
        ctx.reach.update(|state| state.set_relays(Vec::new()));
        eventually("every node to be asked again", || {
            nodes.iter().zip(&before).all(|(node, before)| node.heard() > *before)
        })
        .await;
        assert_eq!(ctx.ext::<Observing>().keepalives(), 0, "that was a measurement, not a keepalive");
        task.abort();
    }

    #[tokio::test]
    async fn the_keepalive_ends_with_the_task() {
        let (ctx, _scratch) = host("keepalive-stop");
        ctx.reach.update(|state| state.switches.dht = true);
        let nodes = agreeing("8.8.8.8:40123".parse().unwrap());
        ask_with(&ctx, &nodes, Timing { keepalive: Duration::from_millis(80), ..fast() });
        let (stop, stopped) = watch::channel(false);
        let task = tokio::spawn(run(ReachContext { stop: Stop::new(stopped), ..ctx.clone() }));
        let observing = ctx.ext::<Observing>();
        eventually("the keepalive to go", || observing.keepalives() >= 2).await;

        stop.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(3), task).await.expect("the task did not end").unwrap().unwrap();
        let sent = observing.keepalives();
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(observing.keepalives(), sent);
    }

    #[tokio::test]
    async fn a_keepalive_that_cannot_be_sent_is_no_error_and_the_next_one_is_a_full_interval_away() {
        // An IPv6 node and an IPv4 socket: not one datagram can be sent.
        let (ctx, _scratch) = host("keepalive-unreachable");
        let mut keeper = Keeper::new();
        let timing = Timing { keepalive: Duration::from_millis(200), ..fast() };
        let sent = AtomicU64::new(0);
        let started = tokio::time::Instant::now();
        keeper.keep(&ctx, &["[2001:db8::1]:6881".parse().unwrap()], &timing, &sent).await;
        assert_eq!(sent.load(Ordering::Relaxed), 0);
        assert!(keeper.next >= started + timing.keepalive, "the next one must not be due at once");
        // No nodes at all: nothing to send to, and the same pace.
        let started = tokio::time::Instant::now();
        keeper.keep(&ctx, &[], &timing, &sent).await;
        assert_eq!(sent.load(Ordering::Relaxed), 0);
        assert!(keeper.next >= started + timing.keepalive);
    }

    #[tokio::test]
    async fn a_keepalive_waiting_for_a_node_that_stopped_answering_ends_with_the_task() {
        // The answer is waited for much longer than the test lasts.
        let (ctx, _scratch) = host("keepalive-silent-stop");
        ctx.reach.update(|state| state.switches.dht = true);
        let answering = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let nodes = changing(&Arc::new(Mutex::new("8.8.8.8:40123".parse().unwrap())), &answering);
        let timing =
            Timing { keepalive: Duration::from_millis(80), keepalive_reply: Duration::from_secs(30), ..fast() };
        ask_with(&ctx, &nodes, timing);
        let (stop, stopped) = watch::channel(false);
        let task = tokio::spawn(run(ReachContext { stop: Stop::new(stopped), ..ctx.clone() }));
        eventually("the endpoint to be seen", || ctx.reach.read().observed.is_some()).await;

        // The nodes go quiet: the next keepalive goes out and waits.
        answering.store(false, Ordering::Relaxed);
        let observing = ctx.ext::<Observing>();
        let sent = observing.keepalives();
        eventually("a keepalive to wait for its answer", || observing.keepalives() > sent).await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        stop.send(true).unwrap();
        let ended = tokio::time::timeout(Duration::from_secs(2), task).await;
        assert!(ended.expect("the task went on waiting for the answer").unwrap().is_ok());
    }

    #[tokio::test]
    async fn a_measurement_puts_the_next_keepalive_a_full_interval_away_and_notes_whether_it_is_allowed() {
        let (ctx, _scratch) = host("keepalive-measured");
        let timing = Timing { keepalive: Duration::from_secs(20), ..fast() };
        let mut keeper = Keeper::new();
        let before = tokio::time::Instant::now();
        keeper.measured(&ctx, &timing);
        assert!(keeper.next >= before + timing.keepalive, "the pings of the round just renewed the mapping");
        assert!(!keeper.was_allowed, "the DHT switch is off");

        ctx.reach.update(|state| *state = keeping());
        keeper.measured(&ctx, &timing);
        assert!(keeper.was_allowed);
        ctx.reach.update(|state| state.switches.dht = false);
        keeper.measured(&ctx, &timing);
        assert!(!keeper.was_allowed);
        // Whether the record advertises the endpoint is not what it notes: that is E2's verdict and this task's own
        // result.
        ctx.reach.update(|state| *state = keeping());
        ctx.reach.update(|state| state.set_addresses(AddressKind::Public, vec!["203.0.113.5:7420".into()]));
        keeper.measured(&ctx, &timing);
        assert!(keeper.was_allowed, "a mapped address is advertised, and the keepalive is still allowed");
    }

    // ---- what makes the host measure again ------------------------------------------------------

    fn mapping(external: &str, public: bool) -> MappingStatus {
        MappingStatus { protocol: "upnp".into(), external: external.into(), public, lease_secs: 3600 }
    }

    fn endpoint(port: u16) -> SocketAddr {
        SocketAddr::from(([8, 8, 8, 8], port))
    }

    #[test]
    fn the_network_is_known_by_the_lan_and_ipv6_addresses_and_the_address_the_router_mapped() {
        let changes = |from: &ReachState, change: &dyn Fn(&mut ReachState)| {
            let mut state = from.clone();
            change(&mut state);
            network_signature(&state) != network_signature(from)
        };
        let nothing = ReachState::default();
        assert!(changes(&nothing, &|state| state.set_addresses(AddressKind::Lan, vec!["192.168.1.5:7420".into()])));
        assert!(changes(&nothing, &|state| state.set_addresses(AddressKind::V6, vec!["[2001:db8::5]:7420".into()])));
        assert!(changes(&nothing, &|state| state.mapping = Some(mapping("203.0.113.5:7420", true))));

        let mut mapped = nothing.clone();
        mapped.mapping = Some(mapping("203.0.113.5:7420", true));
        // E2's verdict about the mapping comes and goes in the `Public` addresses and in the flags of the mapping, and
        // it is made from what this task measured: none of that is a change of network.
        let public = vec!["203.0.113.5:7420".to_string()];
        assert!(!changes(&mapped, &|state| state.set_addresses(AddressKind::Public, public.clone())));
        assert!(!changes(&mapped, &|state| state.mapping = Some(mapping("203.0.113.5:7420", false))));
        assert!(!changes(&mapped, &|state| state.mapping.as_mut().unwrap().lease_secs = 60));
        // Another address of the router is a change, and so is a mapping that is gone.
        assert!(changes(&mapped, &|state| state.mapping = Some(mapping("203.0.113.9:7420", true))));
        assert!(changes(&mapped, &|state| state.mapping = None));
    }

    #[tokio::test]
    async fn a_change_of_e2s_verdict_makes_the_host_neither_measure_again_nor_drop_what_it_measured() {
        let (ctx, _scratch) = host("signature-verdict");
        let answering = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let nodes = changing(&Arc::new(Mutex::new(endpoint(40123))), &answering);
        ask(&ctx, &nodes);
        let task = tokio::spawn(run(ctx.clone()));
        eventually("the endpoint to be seen", || ctx.reach.read().observed == Some(endpoint(40123))).await;
        let observing = ctx.ext::<Observing>();
        let rounds = observing.measurements();

        // The DHT is blocked from now on: a round would learn nothing and, if the host thought it had moved, drop the
        // endpoint it has. E2 changes its mind about the mapped address, as it does whenever the nodes' word changes.
        answering.store(false, Ordering::Relaxed);
        for _ in 0..3 {
            ctx.reach.update(|state| state.set_addresses(AddressKind::Public, vec!["203.0.113.5:7420".into()]));
            tokio::time::sleep(Duration::from_millis(150)).await;
            ctx.reach.update(|state| state.set_addresses(AddressKind::Public, Vec::new()));
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        assert_eq!(observing.measurements(), rounds, "the host measured again for a change of E2's verdict");
        assert_eq!(ctx.reach.read().observed, Some(endpoint(40123)), "and dropped what it had");
        task.abort();
    }

    #[tokio::test]
    async fn the_host_measures_again_when_the_router_maps_another_address_and_not_when_it_only_changes_its_mind() {
        let (ctx, _scratch) = host("signature-mapping");
        let nodes = agreeing(endpoint(40123));
        ask(&ctx, &nodes);
        let task = tokio::spawn(run(ctx.clone()));
        eventually("the endpoint to be seen", || ctx.reach.read().observed.is_some()).await;
        let observing = ctx.ext::<Observing>();
        let mut rounds = observing.measurements();

        // The router maps an address: news, since the endpoint the nodes see may have changed with it.
        ctx.reach.update(|state| state.mapping = Some(mapping("203.0.113.5:7420", true)));
        eventually("a measurement for the new mapping", || observing.measurements() > rounds).await;
        rounds = observing.measurements();

        // E2 judges the mapping, flag by flag, and the router's lease is renewed: the same mapping.
        for public in [false, true, false] {
            ctx.reach.update(|state| state.mapping = Some(mapping("203.0.113.5:7420", public)));
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        ctx.reach.update(|state| state.mapping.as_mut().unwrap().lease_secs = 60);
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(observing.measurements(), rounds, "the host measured again for the same mapping");

        // Another address is news again.
        ctx.reach.update(|state| state.mapping = Some(mapping("203.0.113.9:7420", true)));
        eventually("a measurement for the other address", || observing.measurements() > rounds).await;
        task.abort();
    }

    #[tokio::test]
    async fn the_keepalive_begins_when_e2_withdraws_its_address_and_the_host_does_not_measure_for_it() {
        let (ctx, _scratch) = host("signature-resume");
        ctx.reach.update(|state| {
            state.switches.dht = true;
            state.set_addresses(AddressKind::Public, vec!["203.0.113.5:7420".into()]);
        });
        let nodes = agreeing(endpoint(40123));
        ask_with(&ctx, &nodes, Timing { keepalive: Duration::from_millis(100), ..fast() });
        let task = tokio::spawn(run(ctx.clone()));
        eventually("the endpoint to be seen", || ctx.reach.read().observed.is_some()).await;
        let observing = ctx.ext::<Observing>();

        // A mapped address is advertised: clients dial that one, and nothing is sent between measurements.
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(observing.keepalives(), 0);
        let rounds = observing.measurements();

        // E2 withdraws it, as it does when the nodes' word differs from the router's. The record sends clients to the
        // observed endpoint now, and the keepalive begins. The host does not measure for it: the endpoint was measured
        // moments ago, and the answer of a keepalive says whether it moved.
        ctx.reach.update(|state| state.set_addresses(AddressKind::Public, Vec::new()));
        eventually("the keepalive to begin", || observing.keepalives() >= 2).await;
        assert_eq!(observing.measurements(), rounds, "the host measured for a change of E2's verdict");

        // E2 puts it back: the keepalive stops.
        ctx.reach.update(|state| state.set_addresses(AddressKind::Public, vec!["203.0.113.5:7420".into()]));
        tokio::time::sleep(Duration::from_millis(200)).await;
        let sent = observing.keepalives();
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(observing.keepalives(), sent);
        assert_eq!(observing.measurements(), rounds);
        task.abort();
    }

    // ---- what a keepalive's answer says -----------------------------------------------------------

    #[tokio::test]
    async fn a_keepalive_says_whether_the_node_sees_the_socket_where_it_was_measured() {
        let (ctx, _scratch) = host("keepalive-seen");
        ctx.reach.update(|state| state.observed = Some(endpoint(40123)));
        let shown = Arc::new(Mutex::new(endpoint(40123)));
        let answering = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let nodes = changing(&shown, &answering);
        let node = [nodes[0].addr];
        // The window is long: an answer that comes late under load must not be taken for none.
        let timing = Timing { keepalive_reply: Duration::from_millis(1000), ..fast() };
        let (mut keeper, sent) = (Keeper::new(), AtomicU64::new(0));

        assert_eq!(keeper.keep(&ctx, &node, &timing, &sent).await, Seen::Same);
        // Another port of the same address: the NAT made another mapping.
        *lock(&shown) = endpoint(41000);
        assert_eq!(keeper.keep(&ctx, &node, &timing, &sent).await, Seen::Changed(endpoint(41000)));
        // Another address.
        let elsewhere: SocketAddr = "9.9.9.9:40123".parse().unwrap();
        *lock(&shown) = elsewhere;
        assert_eq!(keeper.keep(&ctx, &node, &timing, &sent).await, Seen::Changed(elsewhere));
        // An address that is not on the internet says nothing about the mapping (a node inside a provider's network).
        *lock(&shown) = "10.1.2.3:4000".parse().unwrap();
        assert_eq!(keeper.keep(&ctx, &node, &timing, &sent).await, Seen::Nothing);
        // Neither does silence.
        answering.store(false, Ordering::Relaxed);
        assert_eq!(keeper.keep(&ctx, &node, &timing, &sent).await, Seen::Nothing);
        // Nor an answer when nothing was measured.
        answering.store(true, Ordering::Relaxed);
        *lock(&shown) = endpoint(41000);
        ctx.reach.update(|state| state.observed = None);
        assert_eq!(keeper.keep(&ctx, &node, &timing, &sent).await, Seen::Nothing);
    }

    /// A pong that does not say where the pinger is, as some DHT nodes answer.
    fn pong_without_the_address(ping: &[u8]) -> Option<Vec<u8>> {
        let marker = b"1:t4:";
        let at = ping.windows(marker.len()).position(|window| window == marker)? + marker.len();
        let mut pong = b"d1:rd2:id20:".to_vec();
        pong.extend_from_slice(&[7; 20]);
        pong.extend_from_slice(b"e1:t4:");
        pong.extend_from_slice(ping.get(at..at + 4)?);
        pong.extend_from_slice(b"1:y1:re");
        Some(pong)
    }

    #[tokio::test]
    async fn a_keepalive_goes_to_the_nodes_that_told_the_host_where_it_is() {
        let (ctx, _scratch) = host("keepalive-voters");
        ctx.reach.update(|state| state.switches.dht = true);
        let shown = endpoint(40123);
        // Two nodes that say where the host is, one that answers without saying, and one inside a provider's network
        // that says a private address (its vote does not count).
        let private: SocketAddr = "10.1.2.3:4000".parse().unwrap();
        let nodes = [
            FakeNode::spawn(Ipv4Addr::new(127, 0, 0, 2), move |_| Some(shown)),
            FakeNode::spawn(Ipv4Addr::new(127, 0, 0, 3), move |_| Some(shown)),
            FakeNode::spawn_replying(Ipv4Addr::new(127, 0, 0, 4), Duration::ZERO, |_, ping| {
                pong_without_the_address(ping)
            }),
            FakeNode::spawn(Ipv4Addr::new(127, 0, 0, 5), move |_| Some(private)),
        ];
        ask_with(&ctx, &nodes, Timing { keepalive: Duration::from_millis(60), ..fast() });
        let task = tokio::spawn(run(ctx.clone()));
        eventually("the endpoint to be seen", || ctx.reach.read().observed == Some(shown)).await;
        let observing = ctx.ext::<Observing>();
        let (before, sent) = (nodes.iter().map(FakeNode::heard).collect::<Vec<_>>(), observing.keepalives());

        eventually("some keepalives", || observing.keepalives() >= sent + 8).await;
        let after: Vec<usize> = nodes.iter().map(FakeNode::heard).collect();
        // They went to the two that say where the host is, in turn, and none to the others: one that does not say, and
        // one whose answer is no use (a private address says nothing about the mapping).
        assert_eq!(after[2], before[2], "a keepalive went to a node that does not say where the host is");
        assert_eq!(after[3], before[3], "a keepalive went to a node that says a private address");
        assert!(after[0] > before[0] + 2 && after[1] > before[1] + 2, "{before:?} then {after:?}");
        task.abort();
    }

    #[tokio::test]
    async fn a_round_that_learns_nothing_after_a_remap_drops_the_endpoint_the_keepalive_showed_dead() {
        let (ctx, _scratch) = host("keepalive-remap-silent");
        ctx.reach.update(|state| state.switches.dht = true);
        // 0: the nodes say the old endpoint; 1: they say the new one once; 2: they say the new one; 3: they say
        // nothing.
        let mode = Arc::new(AtomicUsize::new(0));
        let nodes: Vec<FakeNode> = (2..=4)
            .map(|n| {
                let mode = mode.clone();
                FakeNode::spawn(Ipv4Addr::new(127, 0, 0, n), move |_| match mode.load(Ordering::SeqCst) {
                    0 => Some(endpoint(40123)),
                    1 if mode.compare_exchange(1, 3, Ordering::SeqCst, Ordering::SeqCst).is_ok() => {
                        Some(endpoint(41000))
                    }
                    2 => Some(endpoint(41000)),
                    _ => None,
                })
            })
            .collect();
        let gap = Duration::from_millis(300);
        ask_with(&ctx, &nodes, Timing { keepalive: Duration::from_millis(100), remeasure_gap: gap, ..fast() });
        let task = tokio::spawn(run(ctx.clone()));
        eventually("the endpoint to be seen", || ctx.reach.read().observed == Some(endpoint(40123))).await;
        // Past the gap, so that the next keepalive that sees another endpoint is the one that counts.
        tokio::time::sleep(gap + Duration::from_millis(150)).await;

        // The NAT made another mapping. The nodes answer the next ping, and then nothing: the measurement that follows
        // learns nothing, and the endpoint the keepalive showed to be dead is dropped, not published until a round
        // succeeds.
        mode.store(1, Ordering::SeqCst);
        eventually("the endpoint to be dropped", || ctx.reach.read().observed.is_none()).await;
        // The network answers again: the host learns the new endpoint.
        mode.store(2, Ordering::SeqCst);
        eventually("the new endpoint", || ctx.reach.read().observed == Some(endpoint(41000))).await;
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn the_host_measures_less_and_less_often_for_keepalives_that_keep_seeing_another_endpoint() {
        let (ctx, _scratch) = host("keepalive-backoff");
        let timing = Timing { remeasure_gap: Duration::from_secs(60), refresh: Duration::from_secs(600), ..fast() };
        let secs = Duration::from_secs;
        let mut keeper = Keeper::new();
        let measure_for = |keeper: &mut Keeper, endpoint: SocketAddr| {
            // The measurement a keepalive asked for adopts what it saw.
            ctx.reach.update(|state| state.observed = Some(endpoint));
            keeper.measured(&ctx, &timing);
        };
        keeper.measured(&ctx, &timing);

        // A minute after a measurement a keepalive may ask for one...
        tokio::time::advance(secs(59)).await;
        assert_eq!(keeper.weigh(Seen::Changed(endpoint(41000)), &timing), None, "within the gap");
        tokio::time::advance(secs(2)).await;
        assert_eq!(keeper.weigh(Seen::Changed(endpoint(41000)), &timing), Some(endpoint(41000)));
        measure_for(&mut keeper, endpoint(41000));
        // ...then two minutes, then four, as long as no keepalive sees the endpoint as it was measured...
        tokio::time::advance(secs(119)).await;
        assert_eq!(keeper.weigh(Seen::Changed(endpoint(41001)), &timing), None);
        tokio::time::advance(secs(2)).await;
        assert_eq!(keeper.weigh(Seen::Changed(endpoint(41001)), &timing), Some(endpoint(41001)));
        measure_for(&mut keeper, endpoint(41001));
        tokio::time::advance(secs(239)).await;
        assert_eq!(keeper.weigh(Seen::Changed(endpoint(41002)), &timing), None);
        tokio::time::advance(secs(2)).await;
        assert_eq!(keeper.weigh(Seen::Changed(endpoint(41002)), &timing), Some(endpoint(41002)));
        measure_for(&mut keeper, endpoint(41002));
        // ...and never less often than the host measures anyway.
        assert_eq!(keeper.gap(&timing), secs(480));
        tokio::time::advance(secs(481)).await;
        assert_eq!(keeper.weigh(Seen::Changed(endpoint(41003)), &timing), Some(endpoint(41003)));
        assert_eq!(keeper.gap(&timing), timing.refresh);

        // A keepalive that sees the endpoint as it was measured starts it over.
        measure_for(&mut keeper, endpoint(41003));
        assert_eq!(keeper.weigh(Seen::Same, &timing), None);
        assert_eq!(keeper.gap(&timing), secs(60));
        tokio::time::advance(secs(61)).await;
        assert_eq!(keeper.weigh(Seen::Changed(endpoint(41004)), &timing), Some(endpoint(41004)));
    }

    #[tokio::test(start_paused = true)]
    async fn an_endpoint_a_measurement_did_not_confirm_is_not_asked_for_again() {
        let (ctx, _scratch) = host("keepalive-declined");
        let timing = Timing { remeasure_gap: Duration::from_secs(60), refresh: Duration::from_secs(600), ..fast() };
        ctx.reach.update(|state| state.observed = Some(endpoint(40123)));
        let (wrong, real) = (endpoint(41000), endpoint(42000));
        let mut keeper = Keeper::new();
        keeper.measured(&ctx, &timing);

        tokio::time::advance(Duration::from_secs(61)).await;
        assert_eq!(keeper.weigh(Seen::Changed(wrong), &timing), Some(wrong));
        // The measurement found the endpoint as it was: a node that says `wrong` again is mistaken, and the NAT is not.
        keeper.measured(&ctx, &timing);
        tokio::time::advance(Duration::from_secs(3600)).await;
        assert_eq!(keeper.weigh(Seen::Changed(wrong), &timing), None, "asked for again, though it was not confirmed");
        // Another endpoint is news.
        assert_eq!(keeper.weigh(Seen::Changed(real), &timing), Some(real));
        keeper.measured(&ctx, &timing);
        // A measurement nobody asked for starts afresh.
        keeper.measured(&ctx, &timing);
        tokio::time::advance(Duration::from_secs(3600)).await;
        assert_eq!(keeper.weigh(Seen::Changed(real), &timing), Some(real));
    }

    #[tokio::test]
    async fn the_wall_clock_counts_for_the_gap_because_the_monotonic_one_may_stop_in_a_suspend() {
        let timing = Timing { remeasure_gap: Duration::from_secs(60), ..fast() };
        let mut keeper = Keeper::new();
        assert!(!keeper.may_remeasure(&timing));
        keeper.measured_wall = SystemTime::now() - Duration::from_secs(3600);
        assert!(keeper.may_remeasure(&timing), "an hour went by on the wall clock");
        // A wall clock that was set back says nothing: the monotonic one decides.
        keeper.measured_wall = SystemTime::now() + Duration::from_secs(3600);
        assert!(!keeper.may_remeasure(&timing));
    }

    #[tokio::test]
    async fn a_keepalive_may_start_a_measurement_only_a_gap_after_the_last_one() {
        let (ctx, _scratch) = host("keepalive-gap");
        let timing = Timing { remeasure_gap: Duration::from_millis(500), ..fast() };
        let mut keeper = Keeper::new();
        tokio::time::sleep(Duration::from_millis(550)).await;
        assert!(keeper.may_remeasure(&timing));
        keeper.measured(&ctx, &timing);
        assert!(!keeper.may_remeasure(&timing), "a measurement was just made");
        tokio::time::sleep(Duration::from_millis(550)).await;
        assert!(keeper.may_remeasure(&timing));
        // The next measurement holds it back again, whatever started it.
        keeper.measured(&ctx, &timing);
        assert!(!keeper.may_remeasure(&timing));
    }

    /// What the tests of a keepalive's answer run: a host with the DHT switch on whose nodes all say it is at
    /// `endpoint(40123)`, measured once, with a keepalive every 100 ms and `gap` before a keepalive may start another
    /// measurement.
    struct Measured {
        ctx: ReachContext,
        _scratch: testing::Scratch,
        shown: Arc<Mutex<SocketAddr>>,
        _nodes: Vec<FakeNode>,
        task: JoinHandle<Result<()>>,
    }

    async fn measured_host(tag: &str, gap: Duration) -> Measured {
        let (ctx, scratch) = host(tag);
        ctx.reach.update(|state| state.switches.dht = true);
        let shown = Arc::new(Mutex::new(endpoint(40123)));
        let nodes = changing(&shown, &Arc::new(std::sync::atomic::AtomicBool::new(true)));
        ask_with(&ctx, &nodes, Timing { keepalive: Duration::from_millis(100), remeasure_gap: gap, ..fast() });
        let task = tokio::spawn(run(ctx.clone()));
        eventually("the endpoint to be seen", || ctx.reach.read().observed == Some(endpoint(40123))).await;
        Measured { ctx, _scratch: scratch, shown, _nodes: nodes, task }
    }

    #[tokio::test]
    async fn a_keepalive_that_shows_another_endpoint_makes_the_host_measure_again_but_not_too_soon() {
        let host = measured_host("keepalive-remap", Duration::from_millis(500)).await;
        let observing = host.ctx.ext::<Observing>();
        let rounds = observing.measurements();

        // The NAT made another mapping (a router restarted, the computer woke up): every node sees the socket at the
        // new one.
        *lock(&host.shown) = endpoint(41000);
        // The next keepalive shows it, but a measurement was made moments ago.
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(observing.measurements(), rounds, "it measured again within the gap");
        assert_eq!(host.ctx.reach.read().observed, Some(endpoint(40123)));
        // Once the gap is over, the next one makes the host measure, and the record leads to the new endpoint.
        eventually("the new endpoint", || host.ctx.reach.read().observed == Some(endpoint(41000))).await;
        assert_eq!(observing.measurements(), rounds + 1);
        host.task.abort();
    }

    #[tokio::test]
    async fn a_keepalive_answered_with_an_address_that_is_not_on_the_internet_changes_nothing() {
        let host = measured_host("keepalive-private", Duration::from_millis(200)).await;
        let observing = host.ctx.ext::<Observing>();
        let (rounds, sent) = (observing.measurements(), observing.keepalives());

        // A node inside a provider's network says a private address, as S0 saw two in 136 replies.
        *lock(&host.shown) = "10.1.2.3:4000".parse().unwrap();
        tokio::time::sleep(Duration::from_millis(800)).await;
        assert!(observing.keepalives() >= sent + 3, "the keepalive went on");
        assert_eq!(observing.measurements(), rounds, "the host measured again for a private address");
        assert_eq!(host.ctx.reach.read().observed, Some(endpoint(40123)));
        host.task.abort();
    }

    #[test]
    fn the_keepalive_the_product_uses_is_three_datagrams_a_minute_inside_the_shortest_mapping_lifetime() {
        let product = Timing::default();
        assert_eq!((product.keepalive, product.keepalive_reply), (KEEPALIVE, KEEPALIVE_REPLY));
        assert_eq!(product.remeasure_gap, REMEASURE_GAP);
        assert_eq!(KEEPALIVE, Duration::from_secs(20));
        // A keepalive's news waits at least a minute after a measurement: a mapping that changes faster is not chased.
        assert_eq!(REMEASURE_GAP, Duration::from_secs(60));
        assert!(REMEASURE_GAP >= KEEPALIVE);
        assert_eq!(Duration::from_secs(60).as_secs() / KEEPALIVE.as_secs(), 3);
        // A UDP mapping may end after 30 seconds without a packet that leaves.
        assert!(KEEPALIVE < Duration::from_secs(30));
        assert!(KEEPALIVE_REPLY < KEEPALIVE, "an answer is waited for less than the interval");
    }

    #[tokio::test]
    async fn silent_nodes_teach_nothing_and_are_asked_again() {
        let (ctx, _scratch) = host("observe-silent");
        let shown: SocketAddr = "8.8.8.8:40123".parse().unwrap();
        let answering = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let nodes: Vec<FakeNode> = (2..=4)
            .map(|n| {
                let answering = answering.clone();
                FakeNode::spawn(Ipv4Addr::new(127, 0, 0, n), move |_| {
                    answering.load(Ordering::Relaxed).then_some(shown)
                })
            })
            .collect();
        ask(&ctx, &nodes);
        let task = tokio::spawn(run(ctx.clone()));

        // The nodes hear the pings and say nothing, and the state says nothing was learnt.
        eventually("the pings to arrive", || nodes.iter().all(|node| !lock(&node.sources).is_empty())).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!((ctx.reach.read().observed, ctx.reach.read().nat), (None, None));
        // The network comes back.
        answering.store(true, Ordering::Relaxed);
        eventually("the endpoint to be seen", || ctx.reach.read().observed == Some(shown)).await;
        task.abort();
    }

    /// Nodes that say the host is at the address in `shown`, and say nothing while `answering` is off.
    fn changing(shown: &Arc<Mutex<SocketAddr>>, answering: &Arc<std::sync::atomic::AtomicBool>) -> Vec<FakeNode> {
        (2..=4)
            .map(|n| {
                let (shown, answering) = (shown.clone(), answering.clone());
                FakeNode::spawn(Ipv4Addr::new(127, 0, 0, n), move |_| {
                    answering.load(Ordering::Relaxed).then(|| *lock(&shown))
                })
            })
            .collect()
    }

    fn moves_to_another_network(ctx: &ReachContext) {
        ctx.reach.update(|state| state.set_addresses(AddressKind::Lan, vec!["192.168.50.2:7420".into()]));
    }

    #[tokio::test]
    async fn a_change_of_network_makes_the_host_measure_again_at_once() {
        let (ctx, _scratch) = host("observe-moved");
        let shown = Arc::new(Mutex::new("8.8.8.8:40123".parse::<SocketAddr>().unwrap()));
        let nodes = changing(&shown, &Arc::new(std::sync::atomic::AtomicBool::new(true)));
        ask(&ctx, &nodes);
        let task = tokio::spawn(run(ctx.clone()));
        eventually("the first endpoint", || ctx.reach.read().observed == Some("8.8.8.8:40123".parse().unwrap())).await;

        // The laptop joins another network: another address, and the NAT there shows another endpoint.
        *lock(&shown) = "9.9.9.9:50321".parse().unwrap();
        let started = Instant::now();
        moves_to_another_network(&ctx);
        eventually("the new endpoint", || ctx.reach.read().observed == Some("9.9.9.9:50321".parse().unwrap())).await;
        assert!(started.elapsed() < Duration::from_secs(5), "it waited for the refresh instead of noticing");
        task.abort();
    }

    #[tokio::test]
    async fn the_endpoint_of_a_network_the_host_left_is_dropped_when_the_new_one_teaches_nothing() {
        let (ctx, _scratch) = host("observe-left");
        let shown = Arc::new(Mutex::new("8.8.8.8:40123".parse::<SocketAddr>().unwrap()));
        let answering = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let nodes = changing(&shown, &answering);
        ask(&ctx, &nodes);
        let task = tokio::spawn(run(ctx.clone()));
        eventually("the endpoint", || ctx.reach.read().observed.is_some()).await;

        // A network where the DHT is blocked.
        answering.store(false, Ordering::Relaxed);
        moves_to_another_network(&ctx);
        eventually("the old endpoint to go", || ctx.reach.read().observed.is_none()).await;
        assert_eq!(ctx.reach.read().nat, None);
        task.abort();
    }

    #[tokio::test]
    async fn a_change_of_address_that_measures_the_same_does_not_touch_the_result() {
        // The LAN address appears while the host starts, which is no change of network: the endpoint
        // must stay in the state throughout, or the DHT record would be published again for nothing.
        let (ctx, _scratch) = host("observe-steady");
        let shown: SocketAddr = "8.8.8.8:40123".parse().unwrap();
        let nodes = agreeing(shown);
        ask(&ctx, &nodes);
        let task = tokio::spawn(run(ctx.clone()));
        eventually("the endpoint", || ctx.reach.read().observed.is_some()).await;
        let mut changes = ctx.reach.subscribe();
        changes.borrow_and_update();

        let pings_before: usize = nodes.iter().map(|node| lock(&node.sources).len()).sum();
        moves_to_another_network(&ctx);
        // Watch for as long as the second measurement takes.
        let watch_until = Instant::now() + Duration::from_millis(900);
        while Instant::now() < watch_until {
            assert_eq!(ctx.reach.read().observed, Some(shown), "the endpoint was dropped in between");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let pings_after: usize = nodes.iter().map(|node| lock(&node.sources).len()).sum();
        assert!(pings_after > pings_before, "it should have measured again");
        task.abort();
    }

    #[tokio::test]
    async fn when_the_task_is_told_to_stop_it_ends_and_clears_what_it_measured() {
        let (ctx, _scratch) = host("observe-stop");
        let nodes = agreeing("8.8.8.8:40123".parse().unwrap());
        ask(&ctx, &nodes);
        let (stop, stopped) = watch::channel(false);
        let task = tokio::spawn(run(ReachContext { stop: Stop::new(stopped), ..ctx.clone() }));
        eventually("the endpoint to be seen", || ctx.reach.read().observed.is_some()).await;

        stop.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(3), task).await.expect("the task did not end").unwrap().unwrap();
        assert_eq!((ctx.reach.read().observed, ctx.reach.read().nat), (None, None));
    }

    #[tokio::test]
    async fn a_node_that_cannot_be_reached_at_all_is_an_error_not_a_wait() {
        // An IPv6 node and an IPv4 socket: not one ping can be sent.
        let (ctx, _scratch) = host("observe-unreachable");
        let started = Instant::now();
        let outcome =
            observe(&ctx, &["[2001:db8::1]:6881".parse().unwrap()], &Timing { wait: Duration::from_secs(5), ..fast() })
                .await;
        assert!(outcome.is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(matches!(observe(&ctx, &[], &fast()).await, Ok(None)));
    }

    #[test]
    fn the_nonces_are_remembered_for_a_while_and_the_memory_is_bounded() {
        let punching = Punching::default();
        *lock(&punching.settings) = Settings {
            nonce_memory: Duration::from_secs(60),
            max_nonces: 2,
            max_attempts: 100,
            device_burst: 100.0,
            overall_burst: 100.0,
            ..Settings::default()
        };
        let (device, t0) = (Fingerprint([1; 32]), Instant::now());
        let at = |secs| t0 + Duration::from_secs(secs);
        assert!(matches!(punching.admit(device, 1, at(0)), Ok(Admission::Serve)));
        assert!(matches!(punching.admit(device, 1, at(30)), Ok(Admission::Repeat)));
        assert!(matches!(punching.admit(device, 2, at(31)), Ok(Admission::Serve)));
        // The third makes room by forgetting the oldest, which is then new again.
        assert!(matches!(punching.admit(device, 3, at(32)), Ok(Admission::Serve)));
        assert!(matches!(punching.admit(device, 1, at(33)), Ok(Admission::Serve)));
        assert!(matches!(punching.admit(device, 3, at(34)), Ok(Admission::Repeat)));
        // A nonce is forgotten once the memory time has passed.
        assert!(matches!(punching.admit(device, 3, at(200)), Ok(Admission::Serve)));
    }

    #[tokio::test]
    async fn a_client_has_arrived_when_it_connected_after_the_attempt_began() {
        let (ctx, _scratch) = host("punch-arrived");
        let (client, other) = (Fingerprint([1; 32]), Fingerprint([2; 32]));
        assert!(!arrived(&ctx, &client, Instant::now()));
        let _guard = ctx.reach.client_connected(client);
        let connected_at = ctx.reach.read().clients.last_connect.map(|(_, at)| at).unwrap();
        assert!(arrived(&ctx, &client, connected_at));
        assert!(!arrived(&ctx, &client, connected_at + Duration::from_millis(1)), "it was here before");
        assert!(!arrived(&ctx, &other, connected_at), "another device is not the client");
    }

    // ---- address families -----------------------------------------------------------------------

    #[tokio::test]
    async fn on_a_dual_stack_socket_the_hole_is_opened_toward_ipv4_and_ipv6_clients() {
        let (ctx, _scratch) = host("punch-dual");
        let ctx = dual_stack(ctx);
        if !ctx.socket.local_addr().is_ipv6() {
            return eprintln!("no dual-stack socket on this machine: skipped");
        }
        let laptop = Identity::generate().unwrap();
        pair(&ctx, &laptop, "laptop");
        let port = ctx.socket.local_addr().port();
        let first_packet = |socket: UdpSocket| async move {
            let mut buffer = vec![0u8; 4096];
            let received = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buffer)).await;
            received.expect("the host sent nothing").map(|(len, from)| (len, from, buffer[0]))
        };

        // An IPv4 client, which the dual-stack socket reaches as an IPv4-mapped address.
        let v4 = nobody().await;
        respond(&ctx, request(&laptop, v4.local_addr().unwrap(), 1)).await.unwrap();
        let (len, from, first) = first_packet(v4).await.unwrap();
        assert_eq!(from, SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port));
        assert!(len >= 1200 && first & 0xc0 == 0xc0);

        // And an IPv6 one.
        if let Ok(v6) = UdpSocket::bind("[::1]:0").await {
            respond(&ctx, request(&laptop, v6.local_addr().unwrap(), 2)).await.unwrap();
            let (len, from, first) = first_packet(v6).await.unwrap();
            assert_eq!(from, SocketAddr::new(std::net::Ipv6Addr::LOCALHOST.into(), port));
            assert!(len >= 1200 && first & 0xc0 == 0xc0);
        }
    }

    #[tokio::test]
    async fn a_host_that_listens_on_ipv4_only_says_so_when_asked_to_punch_toward_ipv6() {
        let (ctx, _scratch) = host("punch-v4-only");
        assert!(ctx.socket.local_addr().is_ipv4());
        let laptop = Identity::generate().unwrap();
        pair(&ctx, &laptop, "laptop");
        let punching = ctx.ext::<Punching>();

        let refused = refusal(respond(&ctx, request(&laptop, "[::1]:4000", 1)).await);
        assert!(matches!(refused, Refusal::Cannot(_)), "{refused}");
        // The slot it took was given back, and nothing was started.
        assert_eq!((punching.attempts(), punching.stats().started), (0, 0));
        let target = nobody().await.local_addr().unwrap();
        respond(&ctx, request(&laptop, target, 2)).await.unwrap();
    }

    #[tokio::test]
    async fn the_nat_is_seen_from_a_dual_stack_socket_too() {
        let (ctx, _scratch) = host("observe-dual");
        let ctx = dual_stack(ctx);
        let shown: SocketAddr = "8.8.8.8:40123".parse().unwrap();
        let nodes = agreeing(shown);
        let seen = observe(&ctx, &nodes.iter().map(|node| node.addr).collect::<Vec<_>>(), &fast()).await;
        let seen = seen.unwrap().expect("the nodes answered");
        assert_eq!((seen.endpoint, seen.nat), (shown, NatType::EndpointIndependent));
    }

    // ---- the simulated NAT ----------------------------------------------------------------------

    /// A device behind a NAT: a UDP socket and the NAT in front of it.
    async fn device(mapping: Mapping, filtering: Filtering) -> (UdpSocket, SimNat) {
        let socket = nobody().await;
        let nat = SimNat::new(socket.local_addr().unwrap(), mapping, filtering).unwrap();
        (socket, nat)
    }

    async fn receive(socket: &UdpSocket) -> Option<(Vec<u8>, SocketAddr)> {
        let mut buffer = vec![0u8; 2048];
        match tokio::time::timeout(Duration::from_millis(300), socket.recv_from(&mut buffer)).await {
            Ok(Ok((len, from))) => Some((buffer[..len].to_vec(), from)),
            _ => None,
        }
    }

    #[tokio::test]
    async fn a_port_restricted_nat_lets_in_only_what_the_device_has_sent_to() {
        let ((a, nat_a), (b, nat_b)) = (
            device(Mapping::EndpointIndependent, Filtering::PortRestricted).await,
            device(Mapping::EndpointIndependent, Filtering::PortRestricted).await,
        );
        let (a_to_b, b_to_a) =
            (nat_a.gateway_to(nat_b.public_endpoint()).unwrap(), nat_b.gateway_to(nat_a.public_endpoint()).unwrap());

        // A speaks first: B's NAT has seen nothing from B toward A, so it drops it.
        a.send_to(b"knock", a_to_b).await.unwrap();
        assert!(receive(&b).await.is_none());
        assert_eq!((nat_a.stats().sent, nat_b.stats().filtered, nat_b.stats().delivered), (1, 1, 0));

        // B answers (it knows A's endpoint from a request): A's NAT lets it in, from B's gateway.
        b.send_to(b"hello", b_to_a).await.unwrap();
        let (data, from) = receive(&a).await.expect("A's NAT should let B in");
        assert_eq!((data.as_slice(), from), (&b"hello"[..], a_to_b), "the device sees the peer at its gateway");
        // Now B's NAT has seen B send to A, and lets A in.
        a.send_to(b"again", a_to_b).await.unwrap();
        let (data, from) = receive(&b).await.expect("B's NAT should let A in now");
        assert_eq!((data.as_slice(), from), (&b"again"[..], b_to_a));
    }

    #[tokio::test]
    async fn an_open_nat_lets_in_anyone_who_knows_the_endpoint() {
        let ((a, nat_a), (b, nat_b)) = (
            device(Mapping::EndpointIndependent, Filtering::PortRestricted).await,
            device(Mapping::EndpointIndependent, Filtering::Open).await,
        );
        let a_to_b = nat_a.gateway_to(nat_b.public_endpoint()).unwrap();
        a.send_to(b"hello", a_to_b).await.unwrap();
        let (data, from) = receive(&b).await.expect("an open NAT lets anyone in");
        assert_eq!(data, b"hello");
        // B can answer the address it sees, and A's NAT lets the answer in (A sent to B first).
        b.send_to(b"hi", from).await.unwrap();
        assert_eq!(receive(&a).await.map(|(data, _)| data), Some(b"hi".to_vec()));
    }

    #[tokio::test]
    async fn a_cone_shows_one_endpoint_and_a_symmetric_nat_one_per_peer() {
        let (_a, cone) = device(Mapping::EndpointIndependent, Filtering::PortRestricted).await;
        let (_b, symmetric) = device(Mapping::Dependent, Filtering::PortRestricted).await;
        let (one, two): (SocketAddr, SocketAddr) = ("127.0.0.1:9".parse().unwrap(), "127.0.0.1:10".parse().unwrap());
        assert_eq!(cone.public_endpoint_toward(one).unwrap(), cone.public_endpoint());
        assert_eq!(cone.public_endpoint_toward(two).unwrap(), cone.public_endpoint());
        let (toward_one, toward_two) =
            (symmetric.public_endpoint_toward(one).unwrap(), symmetric.public_endpoint_toward(two).unwrap());
        assert_ne!(toward_one, toward_two);
        assert!(toward_one != symmetric.public_endpoint() && toward_two != symmetric.public_endpoint());
    }

    /// Where a peer hears a device behind `nat` come from, when the device sends one datagram to `peer` through it.
    async fn source_of_one_datagram(device: &UdpSocket, nat: &SimNat, peer: &UdpSocket) -> SocketAddr {
        device.send_to(b"hello", nat.gateway_to(peer.local_addr().unwrap()).unwrap()).await.unwrap();
        receive(peer).await.expect("the peer should hear the device").1
    }

    #[tokio::test]
    async fn an_expiring_nat_forgets_a_mapping_that_saw_no_packet_leave_and_makes_another_on_another_port() {
        let lifetime = Duration::from_millis(600);
        let device = nobody().await;
        let nat = SimNat::expiring(device.local_addr().unwrap(), Filtering::PortRestricted, lifetime).unwrap();
        let peer = nobody().await;
        let first = source_of_one_datagram(&device, &nat, &peer).await;
        assert_eq!(first, nat.public_endpoint());

        // The peer can answer while the mapping lives.
        peer.send_to(b"back", first).await.unwrap();
        assert_eq!(receive(&device).await.map(|(data, _)| data), Some(b"back".to_vec()));

        // The device is quiet for longer than the mapping lives: what comes for it now is dropped...
        tokio::time::sleep(lifetime * 2).await;
        let filtered = nat.stats().filtered;
        peer.send_to(b"too late", first).await.unwrap();
        assert!(receive(&device).await.is_none(), "the old mapping let a packet in");
        assert_eq!(nat.stats().filtered, filtered + 1);
        // ...and the next packet that leaves gets a mapping again, on another port, and the old port stays dead.
        let other = nobody().await;
        let second = source_of_one_datagram(&device, &nat, &other).await;
        assert_ne!(second.port(), first.port());
        assert_eq!(second, nat.public_endpoint());
        other.send_to(b"to the new one", second).await.unwrap();
        assert_eq!(receive(&device).await.map(|(data, _)| data), Some(b"to the new one".to_vec()));
        // The new mapping starts with an empty filter: the peer of the old one is a stranger to it.
        peer.send_to(b"from the old peer", second).await.unwrap();
        assert!(receive(&device).await.is_none(), "the new mapping remembered whom the old one let in");
        // The old port stays dead even for a peer the new mapping lets in (the filter would not stop that one).
        other.send_to(b"to the old port", first).await.unwrap();
        assert!(receive(&device).await.is_none(), "the old port took a packet after the NAT made another mapping");
    }

    #[tokio::test]
    async fn packets_that_leave_keep_the_mapping_of_an_expiring_nat() {
        let lifetime = Duration::from_millis(1000);
        let device = nobody().await;
        let nat = SimNat::expiring(device.local_addr().unwrap(), Filtering::PortRestricted, lifetime).unwrap();
        let peer = nobody().await;
        let first = source_of_one_datagram(&device, &nat, &peer).await;

        // Longer than the lifetime, with a packet out every 100 ms (to the same peer; to another one is the same to a
        // cone).
        for _ in 0..12 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_eq!(source_of_one_datagram(&device, &nat, &peer).await, first);
        }
        // Only what leaves renews it. A packet that arrives half a lifetime later is let in and does not put the end
        // off...
        tokio::time::sleep(lifetime / 2).await;
        peer.send_to(b"still there", first).await.unwrap();
        assert!(receive(&device).await.is_some(), "a mapping inside its lifetime lets the peer in");
        // ...so a quarter of a lifetime after the end, counted from the last packet that left, it is gone.
        tokio::time::sleep(lifetime * 3 / 4).await;
        peer.send_to(b"gone", first).await.unwrap();
        assert!(receive(&device).await.is_none(), "a packet that arrived put the end of the mapping off");
    }

    #[tokio::test]
    async fn a_restarted_nat_forgets_its_mapping_at_once_and_makes_another_on_another_port() {
        let device = nobody().await;
        let nat =
            SimNat::new(device.local_addr().unwrap(), Mapping::EndpointIndependent, Filtering::PortRestricted).unwrap();
        let (peer, other) = (nobody().await, nobody().await);
        let first = source_of_one_datagram(&device, &nat, &peer).await;
        assert_eq!(source_of_one_datagram(&device, &nat, &other).await, first, "one mapping for every peer");
        peer.send_to(b"back", first).await.unwrap();
        assert_eq!(receive(&device).await.map(|(data, _)| data), Some(b"back".to_vec()));

        nat.restart();
        assert_ne!(nat.public_endpoint().port(), first.port());
        // What arrives for the old port is dropped, for a peer the old mapping let in as for any other.
        peer.send_to(b"too late", first).await.unwrap();
        assert!(receive(&device).await.is_none(), "the old port took a packet after the restart");
        // The next packet that leaves is seen from the new port, and the filter is empty: only its peer is let in.
        let second = source_of_one_datagram(&device, &nat, &peer).await;
        assert_ne!(second.port(), first.port());
        assert_eq!(second, nat.public_endpoint());
        other.send_to(b"a stranger to the new mapping", second).await.unwrap();
        assert!(receive(&device).await.is_none(), "the new mapping remembered whom the old one let in");
        peer.send_to(b"to the new one", second).await.unwrap();
        assert_eq!(receive(&device).await.map(|(data, _)| data), Some(b"to the new one".to_vec()));
    }

    // ---- punching through it -------------------------------------------------------------------

    const CONE: (Mapping, Filtering) = (Mapping::EndpointIndependent, Filtering::PortRestricted);

    /// What `server.rs` does with a connection attempt, as far as reach can see: make an address prove
    /// itself (Retry), note the device that is connected, and echo what it says on a stream. Hands
    /// over each connection that gets in.
    fn serve(ctx: &ReachContext) -> mpsc::UnboundedReceiver<(Fingerprint, quinn::Connection)> {
        let (arrivals, received) = mpsc::unbounded_channel();
        let ctx = ctx.clone();
        tokio::spawn(async move {
            while let Some(incoming) = ctx.endpoint.accept().await {
                if !incoming.remote_address_validated() && incoming.may_retry() {
                    let _ = incoming.retry();
                    continue;
                }
                let (ctx, arrivals) = (ctx.clone(), arrivals.clone());
                tokio::spawn(async move {
                    let Ok(connection) = incoming.await else { return };
                    let Ok(fingerprint) = tls::peer_fingerprint(&connection) else { return };
                    let _connected = ctx.reach.client_connected(fingerprint);
                    let _ = arrivals.send((fingerprint, connection.clone()));
                    while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                        let Ok(data) = recv.read_to_end(1024).await else { return };
                        let _ = send.write_all(&data).await;
                        let _ = send.finish();
                    }
                });
            }
        });
        received
    }

    /// A host and a client on the loopback, each behind a NAT of its own, and nothing else between them.
    struct World {
        ctx: ReachContext,
        _scratch: testing::Scratch,
        client: Identity,
        endpoint: quinn::Endpoint,
        client_nat: SimNat,
        host_nat: SimNat,
        arrivals: mpsc::UnboundedReceiver<(Fingerprint, quinn::Connection)>,
    }

    impl World {
        async fn new(client_nat: (Mapping, Filtering), host_nat: (Mapping, Filtering)) -> World {
            World::with(client_nat, |device| SimNat::new(device, host_nat.0, host_nat.1).unwrap()).await
        }

        /// A world whose host NAT is whatever `host_nat` makes of the address of the host's socket.
        async fn with(client_nat: (Mapping, Filtering), host_nat: impl FnOnce(SocketAddr) -> SimNat) -> World {
            let (ctx, scratch) = host("punch-world");
            configure(&ctx, |settings| settings.attempt_for = Duration::from_secs(8));
            let client = Identity::generate().unwrap();
            pair(&ctx, &client, "phone");
            let arrivals = serve(&ctx);
            let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let client_addr = socket.local_addr().unwrap();
            let endpoint =
                quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, Arc::new(quinn::TokioRuntime))
                    .unwrap();
            World {
                host_nat: host_nat(ctx.socket.local_addr()),
                client_nat: SimNat::new(client_addr, client_nat.0, client_nat.1).unwrap(),
                ctx,
                _scratch: scratch,
                client,
                endpoint,
                arrivals,
            }
        }

        /// The client dials the host at `host_public`, the endpoint it was told the host's NAT shows.
        fn dial(&self, host_public: SocketAddr) -> JoinHandle<Result<quinn::Connection, quinn::ConnectionError>> {
            let via = self.client_nat.gateway_to(host_public).unwrap();
            let config = tls::client_config(&self.client, self.ctx.fingerprint).unwrap();
            let connecting = self.endpoint.connect_with(config, via, tls::SERVER_NAME).unwrap();
            tokio::spawn(connecting)
        }

        /// The client's request reaches the host: toward the endpoint the client's NAT shows.
        async fn punch(&self, nonce: u64) -> Result<()> {
            let toward = self.host_nat.gateway_to(self.client_nat.public_endpoint()).unwrap();
            respond(&self.ctx, request(&self.client, toward, nonce)).await
        }

        fn punching(&self) -> Arc<Punching> {
            self.ctx.ext::<Punching>()
        }
    }

    #[tokio::test]
    async fn a_client_behind_a_cone_nat_gets_through_another_once_the_host_punches() {
        let mut world = World::new(CONE, CONE).await;
        let dialing = world.dial(world.host_nat.public_endpoint());

        // Without the hole the client's packets die at the host's NAT, however often it sends them.
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(!dialing.is_finished());
        assert!(world.host_nat.stats().filtered >= 1, "{:?}", world.host_nat.stats());
        assert_eq!(world.host_nat.stats().delivered, 0);

        // The request arrives and the host sends toward the client; the client's next retransmission is let in.
        world.punch(1).await.unwrap();
        let connection = tokio::time::timeout(Duration::from_secs(10), dialing)
            .await
            .expect("the handshake did not complete through the hole")
            .unwrap()
            .expect("the handshake failed");
        let (fingerprint, _server_side) = tokio::time::timeout(Duration::from_secs(5), world.arrivals.recv())
            .await
            .expect("the host saw nobody")
            .unwrap();
        assert_eq!(fingerprint, world.client.fingerprint(), "the host knows the device by its certificate");
        assert_eq!(tls::peer_fingerprint(&connection).unwrap(), world.ctx.fingerprint, "and the client the host");

        // Data goes both ways through the two holes.
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        send.write_all(b"through the hole").await.unwrap();
        send.finish().unwrap();
        assert_eq!(recv.read_to_end(1024).await.unwrap(), b"through the hole");
        assert!(world.client_nat.stats().delivered > 0 && world.host_nat.stats().delivered > 0);

        // The host dropped its own attempt as soon as the client was in, long before its time was up.
        let punching = world.punching();
        eventually("the host's attempt to end", || punching.attempts() == 0).await;
        assert_eq!(punching.stats(), PunchStats { started: 1, arrived: 1, ..Default::default() });
    }

    /// How long the host's NAT keeps a mapping nobody renews, in the tests that watch it forget.
    const LIFETIME: Duration = Duration::from_millis(1200);

    /// A host behind the NAT that `host_nat` makes, with the DHT switch on and the nodes reached through the NAT, so
    /// that what it sends is what the NAT sees. The nodes answer with what they saw come in (BEP 42): 8.8.8.8 and the
    /// port of the mapping of the moment. Returns once the endpoint is measured.
    async fn host_behind(
        timing: Timing,
        host_nat: impl FnOnce(SocketAddr) -> SimNat,
    ) -> (World, Vec<FakeNode>, JoinHandle<Result<()>>) {
        let world = World::with(CONE, host_nat).await;
        world.ctx.reach.update(|state| state.switches.dht = true);
        let nodes: Vec<FakeNode> = (2..=4)
            .map(|n| {
                FakeNode::spawn(Ipv4Addr::new(127, 0, 0, n), |from| {
                    Some(SocketAddr::new(Ipv4Addr::new(8, 8, 8, 8).into(), from.port()))
                })
            })
            .collect();
        let observing = world.ctx.ext::<Observing>();
        *lock(&observing.timing) = timing;
        *lock(&observing.nodes) =
            Some(nodes.iter().map(|node| world.host_nat.gateway_to(node.addr).unwrap()).collect());
        let task = tokio::spawn(run(world.ctx.clone()));
        eventually("the endpoint to be seen", || world.ctx.reach.read().observed.is_some()).await;
        // The nodes are on different IPs, so the host sees a cone NAT and its record sends clients to punch toward the
        // endpoint.
        assert_eq!(world.ctx.reach.read().nat, Some(NatType::EndpointIndependent));
        (world, nodes, task)
    }

    /// A host behind a NAT that forgets its mapping after `LIFETIME` (see [`host_behind`]).
    async fn forgetful_host(keepalive: Duration) -> (World, Vec<FakeNode>, JoinHandle<Result<()>>) {
        let nat = |device| SimNat::expiring(device, Filtering::PortRestricted, LIFETIME).unwrap();
        host_behind(Timing { keepalive, ..fast() }, nat).await
    }

    /// The endpoint the host published, as a client in this world dials it: the port is the mapping's, on the loopback.
    fn published_by(world: &World) -> SocketAddr {
        let observed = world.ctx.reach.read().observed.expect("the host measured its endpoint");
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), observed.port())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_mapping_that_expires_between_two_measurements_breaks_the_punch_without_a_keepalive() {
        let (world, _nodes, task) = forgetful_host(Duration::from_secs(3600)).await;
        let published = published_by(&world);
        // Nothing leaves the host's socket for longer than its mapping lives (the next measurement is a minute away).
        tokio::time::sleep(LIFETIME * 3 / 2).await;

        // A client dials what the host published, and the host, asked to, punches toward the client.
        let dialing = world.dial(published);
        world.punch(1).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(3), dialing).await.is_err(),
            "the client got through to a mapping that was gone"
        );
        // The host's NAT made another mapping for its packet, on another port, which is not what the client dials.
        assert_ne!(world.host_nat.public_endpoint().port(), published.port());
        assert!(world.host_nat.stats().filtered > 0, "the client's packets died at the host's NAT");
        task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_keepalive_holds_the_mapping_and_the_same_punch_gets_through() {
        let (mut world, nodes, task) = forgetful_host(Duration::from_millis(150)).await;
        let published = published_by(&world);
        // The same quiet time, the same punch.
        tokio::time::sleep(LIFETIME * 3 / 2).await;
        assert!(world.ctx.ext::<Observing>().keepalives() >= 5, "the keepalive did not run");
        assert!(heard(&nodes) > 3, "and the nodes heard it");

        let dialing = world.dial(published);
        world.punch(1).await.unwrap();
        let connection = tokio::time::timeout(Duration::from_secs(10), dialing)
            .await
            .expect("the handshake did not complete through the hole")
            .unwrap()
            .expect("the handshake failed");
        let (fingerprint, _server_side) = tokio::time::timeout(Duration::from_secs(5), world.arrivals.recv())
            .await
            .expect("the host saw nobody")
            .unwrap();
        assert_eq!(fingerprint, world.client.fingerprint());
        assert_eq!(tls::peer_fingerprint(&connection).unwrap(), world.ctx.fingerprint);
        // The mapping the host published is the one its NAT still shows.
        assert_eq!(world.host_nat.public_endpoint().port(), published.port());
        task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn after_the_router_restarts_the_host_notices_and_a_client_punches_to_the_new_endpoint() {
        let timing =
            Timing { keepalive: Duration::from_millis(150), remeasure_gap: Duration::from_millis(400), ..fast() };
        let nat = |device| SimNat::new(device, Mapping::EndpointIndependent, Filtering::PortRestricted).unwrap();
        let (mut world, _nodes, task) = host_behind(timing, nat).await;
        let observing = world.ctx.ext::<Observing>();
        let (old, rounds) = (published_by(&world), observing.measurements());

        // The router restarts: its mapping is gone, and the next packet from the host's socket gets another port.
        world.host_nat.restart();
        let port = world.host_nat.public_endpoint().port();
        assert_ne!(port, old.port());

        // The next keepalive shows it, and once the gap since the last measurement is over the host measures again.
        eventually("the new endpoint", || world.ctx.reach.read().observed.is_some_and(|seen| seen.port() == port))
            .await;
        assert_eq!(observing.measurements(), rounds + 1);

        // A client that dials what the host publishes now gets through.
        let dialing = world.dial(published_by(&world));
        world.punch(1).await.unwrap();
        let connection = tokio::time::timeout(Duration::from_secs(10), dialing)
            .await
            .expect("the handshake did not complete through the hole")
            .unwrap()
            .expect("the handshake failed");
        let (fingerprint, _server_side) = tokio::time::timeout(Duration::from_secs(5), world.arrivals.recv())
            .await
            .expect("the host saw nobody")
            .unwrap();
        assert_eq!(fingerprint, world.client.fingerprint());
        assert_eq!(tls::peer_fingerprint(&connection).unwrap(), world.ctx.fingerprint);
        task.abort();
    }

    #[tokio::test]
    async fn a_host_behind_an_open_nat_needs_no_punch() {
        // Sanity for the simulation: a full cone lets the client in unasked, as the plan says it does.
        let mut world = World::new(CONE, (Mapping::EndpointIndependent, Filtering::Open)).await;
        let connection = tokio::time::timeout(Duration::from_secs(10), world.dial(world.host_nat.public_endpoint()))
            .await
            .expect("the handshake did not complete")
            .unwrap()
            .expect("the handshake failed");
        let (fingerprint, _) = world.arrivals.recv().await.unwrap();
        assert_eq!(fingerprint, world.client.fingerprint());
        drop(connection);
        assert_eq!(world.punching().stats(), PunchStats::default());
    }

    #[tokio::test]
    async fn a_host_behind_a_symmetric_nat_cannot_be_punched() {
        let world = World::new(CONE, (Mapping::Dependent, Filtering::PortRestricted)).await;
        // All the client can be told is the endpoint the DHT node saw, which is good for that node only.
        let dht_node: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let dialing = world.dial(world.host_nat.public_endpoint_toward(dht_node).unwrap());

        // The host does its part, from another port of its NAT than the one the client dials.
        world.punch(1).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(3), dialing).await.is_err(),
            "a symmetric NAT should keep the client out"
        );
        assert!(world.host_nat.stats().filtered > 0, "the client's packets were dropped at the host's NAT");
        assert!(world.client_nat.stats().filtered > 0, "and the host's, at the client's");
        assert_eq!(world.punching().stats().started, 1);
    }
}
