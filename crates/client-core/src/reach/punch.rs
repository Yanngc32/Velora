//! F4: reaching a host by hole punching, for a host that nothing else reaches (`docs/nat-traversal.md`, phase 3).
//!
//! The host is behind a NAT that lets nothing in unasked, but the NAT keeps one public `ip:port` for the host's QUIC socket
//! (a "cone"), which the host's record lists, and this device's NAT does the same for it. A NAT lets a packet in only from an
//! address its own side has sent to, so each side has to send first. [`dial_punch`] arranges that:
//!
//! 1. It binds one UDP socket and asks DHT nodes (STUN servers when they cannot tell enough) which endpoint the NAT shows for
//!    *that socket*: a NAT keeps a mapping per source port, so the answer is good only for the socket that asked. A NAT that
//!    shows another endpoint to some of the nodes (B2 reads that as a symmetric one) cannot be punched, and ends the attempt.
//! 2. It tells the host where this device is. Through a relay the host is registered with, that is a
//!    `ClientMsg::PunchRequest`, which the relay passes on at once. With no relay, it is a punch item published in the DHT
//!    (`velora_dht::punch_item`, sealed with the secret this device holds for the host), which the host's poller finds within
//!    its polling interval; it is published again every [`REPUBLISH`], with a fresh `ts`, because the host ignores a request a
//!    minute old. The host answers by sending one QUIC Initial toward that endpoint from its listening port, and that opens
//!    its NAT toward this device.
//! 3. Meanwhile it dials the host's own endpoint from the same socket, starting a new connection attempt every second:
//!    an attempt's own retransmissions soon come seconds apart, and a hole that opens between them should not wait for the
//!    next one. The first handshake wins, and the rest are dropped.
//!
//! The dial ends [`RELAY_WAIT`] or [`DHT_WAIT`] after the request was delivered, [`GRACE`] after it could not be, and
//! [`ASK_LIMIT`] after it began if the asking itself does not end.
//!
//! Everything the dial needs from the outside world (the nodes it asks, the DHT, the waits) is in [`Env`], so that the
//! tests run it against simulated NATs on the loopback.

use std::{
    collections::{BTreeMap, VecDeque},
    future::Future,
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    path::PathBuf,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::{Duration, SystemTime},
};

use anyhow::{anyhow, bail, Context as _, Result};
use tokio::{
    sync::{watch, OnceCell},
    task::{AbortHandle, JoinSet},
};
use velora_dht::{
    node::{Error as DhtError, Mode, Node, Published, Signer},
    punch_item::{self, Built, PunchError},
    seal::Secret,
};
use velora_nat::{
    addresses::classify,
    observe::{self, NatType, Observation, Observed},
};
use velora_protocol::{
    tls::{self, Fingerprint},
    wire::ClientMsg,
};

use super::{
    relay::{Link, Waits},
    RelayRef, RELAY_ADDRESS_STAGGER,
};
use crate::ConnectParams;

/// How long the dial goes on after a relay has passed the request to the host. The host punches as soon as the message reaches
/// it (its own attempt lasts 12 s), so the hole is open after a few round trips: the plan's 10 s is generous.
const RELAY_WAIT: Duration = Duration::from_secs(10);
/// How long it goes on after the request is in the DHT. The host looks for requests every 45 s for each device and a look may
/// take 6 s (the host's `poll.rs`), so it may not hear of the request for 51 s; the rest is the margin for the handshake. For the
/// device that connected last, the host looks every 8 s for three minutes once nobody is connected, and the dial ends sooner.
const DHT_WAIT: Duration = Duration::from_secs(60);
/// How long the asking itself may take (relays that do not answer, a publish that does not end) before the dial gives up.
const ASK_LIMIT: Duration = Duration::from_secs(30);
/// How much longer the dial goes on once the request could not be delivered: only a host whose NAT is open still answers, and
/// it does within a round trip.
const GRACE: Duration = Duration::from_secs(3);
/// A new connection attempt starts this often...
const REDIAL: Duration = Duration::from_secs(1);
/// ...and at most this many are under way: when another starts the oldest is dropped, so that a host whose hole opens
/// answers a few attempts and not every one of the last minute.
const MAX_LIVE: usize = 4;
/// Relay addresses asked for one request, at most. Each relay is asked [`RELAY_STAGGER`] after the one before, and a second
/// address of the same relay [`RELAY_ADDRESS_STAGGER`] after its first (a relay asked twice only helps when its first address
/// does not answer, and each request takes one of the device's few new flows there). The first to pass the request on ends
/// the asking; the host serves a nonce once, however often it arrives.
const MAX_RELAYS: usize = 4;
const RELAY_STAGGER: Duration = Duration::from_millis(250);
/// While the request waits in the DHT it is published again this often, with a fresh `ts` (same nonce, higher `seq`): the host
/// ignores a request more than a minute old, and a publish can take a good part of a minute before the item is there to be found.
const REPUBLISH: Duration = Duration::from_secs(30);
/// Tries to publish the request before the dial gives up on the DHT, and the pause after a failure that may pass.
const MAX_PUBLISHES: usize = 3;
const PUBLISH_RETRY: Duration = Duration::from_secs(2);
/// The whole observation, resolving the names and waiting for the answers, ends after this: the system resolver has no limit
/// of its own.
const OBSERVE_LIMIT: Duration = Duration::from_secs(10);
/// Servers that must have told, on different addresses, for the kind of a NAT to be read (B2's rule): STUN is asked when the
/// DHT nodes did not say enough.
const MIN_SERVERS: usize = 2;
/// The routing-table cache of this device's DHT node, in its state directory (`ReachParams::state_dir`).
const CACHE_FILE: &str = "dht_cache.txt";

/// Every wait of the dial, in one place for the field tests (I4) to tune.
#[derive(Debug, Clone, Copy)]
struct Timing {
    relay_wait: Duration,
    dht_wait: Duration,
    ask_limit: Duration,
    grace: Duration,
    redial: Duration,
    republish: Duration,
    /// What each phase of the observation waits for answers, and how long the whole of it may take.
    observe: Duration,
    observe_limit: Duration,
    /// Dealing with a relay. The punch window is short, so these are tighter than a relay dial's own.
    relay: Waits,
    relay_stagger: Duration,
    address_stagger: Duration,
    publish_retry: Duration,
}

impl Timing {
    const DEFAULT: Timing = Timing {
        relay_wait: RELAY_WAIT,
        dht_wait: DHT_WAIT,
        ask_limit: ASK_LIMIT,
        grace: GRACE,
        redial: REDIAL,
        republish: REPUBLISH,
        observe: observe::DEFAULT_WAIT,
        observe_limit: OBSERVE_LIMIT,
        relay: Waits {
            connect: Duration::from_secs(3),
            welcome: Duration::from_secs(3),
            reach: Duration::from_secs(2),
            answer: Duration::from_secs(3),
            inner: Duration::from_secs(10),
        },
        relay_stagger: RELAY_STAGGER,
        address_stagger: RELAY_ADDRESS_STAGGER,
        publish_retry: PUBLISH_RETRY,
    };
}

/// What [`dial`] takes from the outside world, so that a test can put a simulation in its place. [`Env::real`] is what
/// [`dial_punch`] uses.
struct Env {
    /// The DHT nodes and the STUN servers that tell what the NAT shows. `None`: the public ones, resolved when needed.
    nodes: Option<Vec<SocketAddr>>,
    stun: Option<Vec<SocketAddr>>,
    /// Where the punch item goes. `None`: a DHT node of this device's own, opened when the item is ready.
    dht: Option<Arc<dyn Dht>>,
    /// The `seq` of each punch item this process has published.
    seqs: &'static Seqs,
    timing: Timing,
    /// An endpoint on the loopback or a private network is fine. A real NAT that shows one is behind another NAT, whose
    /// outer side cannot be told to the host; tests run on the loopback.
    allow_local: bool,
    /// Tries a NAT that shows another endpoint to every node. The test that shows why nobody does turns this on.
    try_symmetric: bool,
}

impl Env {
    fn real() -> Env {
        Env {
            nodes: None,
            stun: None,
            dht: None,
            seqs: &SEQS,
            timing: Timing::DEFAULT,
            allow_local: false,
            try_symmetric: false,
        }
    }
}

type Publishing<'a> = Pin<Box<dyn Future<Output = Result<Published, DhtError>> + Send + 'a>>;

/// The one thing a punch request asks of the DHT: to be stored.
trait Dht: Send + Sync {
    fn publish<'a>(
        &'a self,
        signer: &'a (dyn Signer + Sync),
        salt: &'a [u8],
        blob: &'a [u8],
        seq: i64,
    ) -> Publishing<'a>;
}

/// A node of this device's own, opened when the first publish needs it. `Mode::Client`: it lasts as long as the request is
/// being published, which is as long as the dial. A publish it has under way runs on a task of the node's own and can end
/// after the dial does.
struct OwnNode {
    cache: PathBuf,
    node: OnceCell<Node>,
}

impl Dht for OwnNode {
    fn publish<'a>(
        &'a self,
        signer: &'a (dyn Signer + Sync),
        salt: &'a [u8],
        blob: &'a [u8],
        seq: i64,
    ) -> Publishing<'a> {
        Box::pin(async move {
            let node = self.node.get_or_init(|| Node::open(&self.cache, Mode::Client)).await;
            node.publish(signer, salt, blob, seq).await
        })
    }
}

/// The highest `seq` this process has put under each punch key. The DHT keeps the first of two items with the same `seq`, so
/// two dials in the same second, or a retry that begins while the item of a dial that was dropped is still being stored, must
/// not share one.
struct Seqs(Mutex<BTreeMap<[u8; 32], i64>>);

static SEQS: Seqs = Seqs(Mutex::new(BTreeMap::new()));

impl Seqs {
    /// Builds the request with a `seq` above every one built before under this key, and above `floor` (what the DHT said it
    /// holds, when it turned the last one down), and notes it.
    fn build(&self, secret: &Secret, endpoint: &str, nonce: u64, floor: i64) -> Result<Built, PunchError> {
        let key = punch_item::public_key(secret);
        let mut last = locked(&self.0);
        let above = last.get(&key).copied().unwrap_or(i64::MIN).max(floor);
        let built = punch_item::build_after(secret, endpoint, nonce, SystemTime::now(), above)?;
        last.insert(key, built.2);
        Ok(built)
    }
}

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Opens a hole in both NATs toward the host's public `endpoint` and connects through it.
///
/// **Receives** `params`, the connection being made (`params.identity`, `params.host_fingerprint` and, for the request
/// through the DHT, the secret in `params.reach.host.secret` and the state directory in `params.reach.state_dir`);
/// `endpoint`, the host's public endpoint as its NAT shows it, the address to dial once the hole is open (IPv4: the DHT that
/// tells this device its own endpoint is); `via`, relays the request can be passed through (another paired device the host
/// is registered with), best first. Empty means the request goes through the DHT.
///
/// **Returns** the QUIC endpoint and connection to the host, as a direct dial would: the caller sends the ordinary Velora
/// hello on it. The endpoint's socket is the one the NAT mapping was observed from.
///
/// **Gives up** by itself. At once when this device's NAT cannot be punched (symmetric), shows no endpoint or one that is
/// not on the internet, and when there is no way to ask the host (no relay and no secret). [`GRACE`] after the request could
/// not be delivered (every relay refused, the DHT took none of its tries). [`ASK_LIMIT`] after it began, if the asking does
/// not end. Otherwise [`RELAY_WAIT`] (a relay passed the request on) or [`DHT_WAIT`] (the DHT has it) after the request was
/// delivered. The error says which of these it was. The race logs it at debug level, and a relay candidate, if any, has been
/// running next to it.
///
/// **Timing.** The race starts it [`PUNCH_DELAY`](super::PUNCH_DELAY) after the first direct address, and drops it when
/// another candidate wins: the future is `Send` and cancel-safe. Dropping it closes its socket, ends its attempts and its relay
/// links, and stops the DHT node. Two things end by themselves, soon: a blocking observation in progress (within its waits,
/// and the system resolver's), and a publish the DHT node already has under way, which may still land (the host then punches
/// toward an endpoint this device no longer listens at, and its attempt ends on its own).
pub async fn dial_punch(
    params: &ConnectParams,
    endpoint: SocketAddr,
    via: &[RelayRef],
) -> Result<(quinn::Endpoint, quinn::Connection)> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).context("could not open a UDP socket")?;
    dial(params, endpoint, via, socket, Env::real()).await
}

async fn dial(
    params: &ConnectParams,
    host: SocketAddr,
    via: &[RelayRef],
    socket: UdpSocket,
    env: Env,
) -> Result<(quinn::Endpoint, quinn::Connection)> {
    let host = SocketAddr::new(host.ip().to_canonical(), host.port());
    if !host.is_ipv4() {
        bail!("hole punching is IPv4 only, and {host} is not an IPv4 endpoint");
    }
    let secret = params.reach.as_ref().and_then(|reach| reach.host.secret);
    if via.is_empty() && secret.is_none() {
        bail!(
            "no relay is known to pass the request on, and this device holds no secret to publish it in the DHT with"
        );
    }

    let (socket, observed) = observe_endpoint(socket, &env).await?;
    let public = observed.endpoint;
    tracing::debug!("the NAT shows this device at {public} ({})", observed.nat);
    // `Unknown` (fewer than two servers told) goes on: nothing says it cannot work.
    if observed.nat == NatType::Dependent && !env.try_symmetric {
        bail!(
            "this network's NAT shows another endpoint to every server (a symmetric NAT), so the host cannot be told \
             where to punch to"
        );
    }

    let nonce = random_nonce()?;
    let config = tls::client_config(&params.identity, params.host_fingerprint)?;
    let endpoint = quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, Arc::new(quinn::TokioRuntime))
        .context("could not start the endpoint of the hole")?;

    let (wait, how) =
        if via.is_empty() { (env.timing.dht_wait, "in the DHT") } else { (env.timing.relay_wait, "through a relay") };
    let (progress, signal) = watch::channel(Signal::Asking);
    let signaling = async {
        signal_host(params, via, secret, public, nonce, &env, &progress).await;
        // The dial goes on, as its own end says, whether the request got through or not.
        std::future::pending::<Result<quinn::Connection>>().await
    };
    let connected = tokio::select! {
        connected = dial_until(&endpoint, &config, host, &env.timing, wait, signal) => connected,
        never = signaling => never,
    };
    let state = progress.borrow().clone();
    let connection =
        connected.with_context(|| format!("hole punching toward {host} failed ({})", state.describe(how, wait)))?;
    tracing::debug!("the hole to {host} is open");
    Ok((endpoint, connection))
}

/// How asking the host is going, for the dial to time its end by.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Signal {
    /// Under way: the dial goes on for up to [`ASK_LIMIT`].
    Asking,
    /// The host has been asked (a relay passed the request on, the DHT has it): the dial goes on for its wait from now.
    Delivered,
    /// Nobody could be asked, for these reasons: the dial goes on for [`GRACE`] and ends.
    Failed(String),
}

impl Signal {
    /// What became of the request, in words for the error of a dial that gives up.
    fn describe(&self, how: &str, wait: Duration) -> String {
        match self {
            Signal::Asking => format!("the request was still on its way {how}"),
            Signal::Delivered => format!(
                "the request was delivered {how}, and the host did not open its NAT within {} s",
                wait.as_secs_f32()
            ),
            Signal::Failed(words) => format!("the request could not be delivered {how}: {words}"),
        }
    }
}

/// Asks the nodes which endpoint the NAT shows for `socket`. The socket goes through a blocking call and comes back (a future
/// dropped, or out of time, leaves the call to end by itself and drop the socket then).
async fn observe_endpoint(socket: UdpSocket, env: &Env) -> Result<(UdpSocket, Observed)> {
    let (nodes, stun, wait, allow_local) = (env.nodes.clone(), env.stun.clone(), env.timing.observe, env.allow_local);
    let observing = tokio::task::spawn_blocking(move || {
        let observed = observe_votes(&socket, nodes, stun, wait, allow_local);
        (socket, observed)
    });
    let limit = env.timing.observe_limit;
    let (socket, observed) = tokio::time::timeout(limit, observing)
        .await
        .map_err(|_| anyhow!("the observation of this device's NAT did not end in {} s", limit.as_secs_f32()))?
        .context("the observation of this device's NAT did not run")?;
    Ok((socket, observed?))
}

/// The blocking part: asks the DHT nodes and, when they do not tell enough, the STUN servers, and keeps the votes of those on
/// the internet. A node inside a provider's network says a private address (S0 saw two in 136 replies), and one such vote
/// would make a cone NAT look symmetric, or keep STUN from being asked. With no vote left the NAT sits behind another one,
/// whose outer side nobody here can see, and the host cannot be told where to punch to.
fn observe_votes(
    socket: &UdpSocket,
    nodes: Option<Vec<SocketAddr>>,
    stun: Option<Vec<SocketAddr>>,
    wait: Duration,
    allow_local: bool,
) -> Result<Observed> {
    let local = socket.local_addr()?;
    let (mut heard, mut votes, mut failure) = (0, Vec::new(), None);

    let nodes = nodes.unwrap_or_else(observe::default_dht_nodes);
    match observe::observe_dht(socket, &nodes, wait) {
        Ok(found) => keep(found, allow_local, &mut heard, &mut votes),
        Err(e) => {
            tracing::debug!("DHT observation failed: {e}");
            failure = Some(e.to_string());
        }
    }
    if distinct_servers(&votes) < MIN_SERVERS {
        let stun = stun.unwrap_or_else(observe::default_stun_servers);
        match observe::observe_stun(socket, &stun, wait) {
            Ok(found) => keep(found, allow_local, &mut heard, &mut votes),
            Err(e) => {
                tracing::debug!("STUN observation failed: {e}");
                failure = Some(e.to_string());
            }
        }
    }
    Observed::new(local, votes).ok_or_else(|| {
        if heard > 0 {
            anyhow!("the endpoint the nodes show for this device is not on the internet: another NAT is in the way")
        } else {
            let why = failure.unwrap_or_else(|| "no DHT node or STUN server told".into());
            anyhow!("could not tell which endpoint this network's NAT shows ({why})")
        }
    })
}

/// Counts what was heard, and keeps the votes that name an address on the internet.
fn keep(found: Vec<Observation>, allow_local: bool, heard: &mut usize, votes: &mut Vec<Observation>) {
    *heard += found.len();
    votes.extend(found.into_iter().filter(|vote| allow_local || classify(vote.endpoint.ip()).is_global()));
}

/// How many different servers (by address, not port) have told.
fn distinct_servers(votes: &[Observation]) -> usize {
    let mut ips: Vec<_> = votes.iter().map(|vote| vote.from.ip()).collect();
    ips.sort();
    ips.dedup();
    ips.len()
}

/// Asks the host to open its NAT toward `public`, and says to the dial how that went. Through relays it returns once they
/// have been asked, whatever came of it. Through the DHT it returns only if the first publish fails: otherwise it goes on
/// publishing for as long as the dial lasts, and the dial drops it.
async fn signal_host(
    params: &ConnectParams,
    via: &[RelayRef],
    secret: Option<[u8; 16]>,
    public: SocketAddr,
    nonce: u64,
    env: &Env,
    progress: &watch::Sender<Signal>,
) {
    let outcome = if via.is_empty() {
        match secret.context("this device holds no secret for the host") {
            Ok(secret) => ask_through_dht(params, secret, public, nonce, env, progress).await,
            Err(e) => Err(e),
        }
    } else {
        signal_relays(params, via, public, nonce, &env.timing).await.map(|()| {
            progress.send_replace(Signal::Delivered);
        })
    };
    if let Err(e) = outcome {
        tracing::debug!("the host could not be asked: {e:#}");
        progress.send_replace(Signal::Failed(format!("{e:#}")));
    }
}

/// The request through the relays the host is registered with: each relay asked a little after the one before, a second
/// address of the same relay later still, and the first to pass it on ends it. A relay that cannot (it does not know the host,
/// it is busy, it does not answer) is skipped.
async fn signal_relays(
    params: &ConnectParams,
    via: &[RelayRef],
    public: SocketAddr,
    nonce: u64,
    timing: &Timing,
) -> Result<()> {
    let via = &via[..via.len().min(MAX_RELAYS)];
    let mut asking = JoinSet::new();
    for (relay, delay) in via.iter().copied().zip(relay_delays(via, timing)) {
        let (params, waits) = (params.clone(), timing.relay);
        asking.spawn(async move {
            tokio::time::sleep(delay).await;
            ask_relay(&params, relay, public, nonce, &waits)
                .await
                .with_context(|| format!("the relay at {}", relay.addr))
        });
    }
    let mut failure = None;
    while let Some(done) = asking.join_next().await {
        match done {
            Ok(Ok(())) => {
                tracing::debug!("the request is on its way through a relay");
                return Ok(());
            }
            Ok(Err(e)) => {
                tracing::debug!("{e:#}");
                failure = Some(e);
            }
            Err(e) => tracing::debug!("a request to a relay ended abnormally: {e}"),
        }
    }
    Err(failure.unwrap_or_else(|| anyhow!("no relay to ask")))
}

/// When each address of `via` is asked, from the start: the relays one `relay_stagger` apart in the order they come, and a
/// second address of a relay `address_stagger` after its first.
fn relay_delays(via: &[RelayRef], timing: &Timing) -> Vec<Duration> {
    let mut relays: Vec<(Fingerprint, u32)> = Vec::new();
    via.iter()
        .map(|relay| {
            let at =
                relays.iter().position(|(fingerprint, _)| *fingerprint == relay.fingerprint).unwrap_or_else(|| {
                    relays.push((relay.fingerprint, 0));
                    relays.len() - 1
                });
            let nth = relays[at].1;
            relays[at].1 += 1;
            timing.relay_stagger * u32::try_from(at).unwrap_or(u32::MAX) + timing.address_stagger * nth
        })
        .collect()
}

/// One relay: connect, say hello as a link, send the request and wait for the relay to say it passed it on. The link is
/// dropped when it has: the relay has queued the message on the host's connection by then.
async fn ask_relay(
    params: &ConnectParams,
    relay: RelayRef,
    public: SocketAddr,
    nonce: u64,
    waits: &Waits,
) -> Result<()> {
    let mut link = Link::open(&params.identity, &params.device_name, relay, waits).await?;
    let request =
        ClientMsg::PunchRequest { to: params.host_fingerprint.to_base64(), endpoint: public.to_string(), nonce };
    link.ask(request, waits).await
}

/// The request in the DHT: published, said delivered, and published again every [`REPUBLISH`] for as long as this is polled.
/// It returns only when the first publish fails.
async fn ask_through_dht(
    params: &ConnectParams,
    secret: [u8; 16],
    public: SocketAddr,
    nonce: u64,
    env: &Env,
    progress: &watch::Sender<Signal>,
) -> Result<()> {
    let dht: Arc<dyn Dht> = match &env.dht {
        Some(dht) => dht.clone(),
        None => {
            let reach = params.reach.as_ref().context("this device keeps no state directory for the host")?;
            Arc::new(OwnNode { cache: reach.state_dir.join(CACHE_FILE), node: OnceCell::new() })
        }
    };
    let request = Request { secret: Secret::new(secret), endpoint: public.to_string(), nonce, dht };
    request.publish(env).await?;
    progress.send_replace(Signal::Delivered);
    loop {
        tokio::time::sleep(env.timing.republish).await;
        if let Err(e) = request.publish(env).await {
            tracing::debug!("could not publish the request again: {e:#}");
        }
    }
}

/// The punch item of one dial: the same request every time it is published, made again for a fresh `ts` and a `seq` above
/// every one used.
struct Request {
    secret: Secret,
    endpoint: String,
    nonce: u64,
    dht: Arc<dyn Dht>,
}

impl Request {
    /// One publish: the DHT refuses an item whose `seq` is not above what it holds, so a refusal for that is a new item with
    /// a higher `seq` at once; a failure that may pass (nobody answered, too few nodes kept it) is tried again after a pause;
    /// anything else is ours to fix, and ends it.
    async fn publish(&self, env: &Env) -> Result<()> {
        let mut floor = i64::MIN;
        let mut attempt = 0;
        loop {
            attempt += 1;
            // Built again for each try: its `ts` is what the host measures its age by.
            let (key, salt, seq, blob) = env
                .seqs
                .build(&self.secret, &self.endpoint, self.nonce, floor)
                .context("could not make the punch request")?;
            let error = match self.dht.publish(&key, salt, &blob, seq).await {
                Ok(published) => {
                    tracing::debug!("the request is in the DHT ({} nodes kept it)", published.stored_at);
                    return Ok(());
                }
                Err(error) => error,
            };
            if attempt >= MAX_PUBLISHES {
                return Err(anyhow::Error::new(error).context(format!("not published in {attempt} tries")));
            }
            match error {
                DhtError::SeqTooLow { seen, .. } => floor = seen,
                ref e if transient(e) => {
                    tracing::debug!("publishing failed, trying again: {e}");
                    tokio::time::sleep(env.timing.publish_retry).await;
                }
                e => return Err(anyhow::Error::new(e).context("the DHT would not take the request")),
            }
        }
    }
}

/// A failure of the DHT that another try may get past.
fn transient(error: &DhtError) -> bool {
    matches!(
        error,
        DhtError::NoNetwork | DhtError::Refused { .. } | DhtError::TimedOut | DhtError::Stopped | DhtError::Socket(_)
    )
}

/// Dials `host` from `endpoint` until a handshake completes or the dial's end comes: a new attempt every `timing.redial`, at
/// most [`MAX_LIVE`] under way. Each attempt is a connection of its own, so the host's Retry and its handshake work as for any
/// client. The end is [`ASK_LIMIT`] from the start, and moves as `signal` says: `wait` from the moment the request was
/// delivered, [`GRACE`] from the moment it could not be. A transport error found here (in practice, a certificate that is
/// not the pinned one: the peer is not the host) ends it at once; a refusal by the host arrives as a close, and is retried.
async fn dial_until(
    endpoint: &quinn::Endpoint,
    config: &quinn::ClientConfig,
    host: SocketAddr,
    timing: &Timing,
    wait: Duration,
    mut signal: watch::Receiver<Signal>,
) -> Result<quinn::Connection> {
    let mut attempts: JoinSet<Result<quinn::Connection, quinn::ConnectionError>> = JoinSet::new();
    let mut live: VecDeque<AbortHandle> = VecDeque::new();
    let mut redial = tokio::time::interval(timing.redial);
    redial.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let end = tokio::time::sleep(timing.ask_limit);
    tokio::pin!(end);
    let mut watching = true;
    let mut last_failure: Option<quinn::ConnectionError> = None;
    loop {
        tokio::select! {
            _ = redial.tick() => {
                if live.len() >= MAX_LIVE {
                    if let Some(oldest) = live.pop_front() {
                        oldest.abort();
                    }
                }
                let connecting = endpoint
                    .connect_with(config.clone(), host, tls::SERVER_NAME)
                    .context("could not start a connection attempt")?;
                live.push_back(attempts.spawn(connecting));
            }
            Some(done) = attempts.join_next() => match done {
                Ok(Ok(connection)) => return Ok(connection),
                Ok(Err(e @ quinn::ConnectionError::TransportError(_))) => {
                    return Err(anyhow::Error::new(e).context(format!("the peer at {host} answered, and is not the host")));
                }
                Ok(Err(e)) => {
                    tracing::trace!("an attempt toward {host} failed: {e}");
                    last_failure = Some(e);
                }
                // An attempt dropped to make room for a newer one.
                Err(_) => {}
            },
            changed = signal.changed(), if watching => {
                if changed.is_err() {
                    watching = false;
                    continue;
                }
                let after = match &*signal.borrow_and_update() {
                    Signal::Asking => None,
                    Signal::Delivered => Some(wait),
                    Signal::Failed(_) => Some(timing.grace),
                };
                if let Some(after) = after {
                    end.as_mut().reset(tokio::time::Instant::now() + after);
                }
            }
            () = &mut end => {
                let gave_up = "the host did not answer through the hole";
                return Err(match last_failure {
                    Some(e) => anyhow::Error::new(e).context(gave_up),
                    None => anyhow!(gave_up),
                });
            }
        }
    }
}

/// A random number for the request: the host serves each one once.
fn random_nonce() -> Result<u64> {
    let mut bytes = [0u8; 8];
    quinn::rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut bytes)
        .map_err(|_| anyhow!("the system random generator failed"))?;
    Ok(u64::from_le_bytes(bytes))
}

/// A NAT on the loopback, for tests of hole punching. Copied from the host's `reach/punch.rs` (E5), where its own tests
/// are; it needs nothing but `std` and `tokio` (`net`, `rt`, `sync`).
///
/// Nothing on one machine routes through a NAT, so the simulation changes who talks to whom. A device
/// behind a [`SimNat`] does not send to a peer's public address: it sends to a *gateway port*
/// ([`SimNat::gateway_to`]), one per peer, on the NAT's private side. The gateway forwards what it
/// gets from the NAT's public socket to the peer, as a real NAT rewrites the source address, and
/// remembers the peer so that its answers are let in. What arrives on the public socket is let in
/// or dropped by the NAT's filtering, and delivered to the device from the gateway port of its
/// sender, so the device sees every peer at the address it sends to. The device never learns the
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
#[cfg(test)]
mod nat_sim {
    // Kept whole, as the host's tests have it, so that the two stay alike: these tests use less of it.
    #![allow(dead_code)]

    use std::{
        collections::{HashMap, HashSet},
        io,
        net::{Ipv4Addr, SocketAddr},
        sync::{
            atomic::{AtomicU64, Ordering},
            Arc, Mutex, MutexGuard, PoisonError,
        },
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
        /// The public socket of an endpoint-independent NAT, shared by every flow. With dependent
        /// mapping nothing leaves from it and nothing arriving at it is let in.
        public: Arc<UdpSocket>,
        state: Mutex<State>,
        sent: AtomicU64,
        delivered: AtomicU64,
        filtered: AtomicU64,
    }

    #[derive(Default)]
    struct State {
        gateways: HashMap<SocketAddr, Arc<Gateway>>,
        /// Peers the device has sent to.
        sent_to: HashSet<SocketAddr>,
        tasks: Vec<JoinHandle<()>>,
    }

    struct Gateway {
        /// The private side: the device sends here and is sent from here.
        private: Arc<UdpSocket>,
        /// The public socket this flow leaves from.
        public: Arc<UdpSocket>,
    }

    fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        mutex.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn bind() -> io::Result<Arc<UdpSocket>> {
        let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
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
            let public = bind()?;
            let shared = Arc::new(Shared {
                device,
                mapping,
                filtering,
                public: public.clone(),
                state: Mutex::default(),
                sent: AtomicU64::new(0),
                delivered: AtomicU64::new(0),
                filtered: AtomicU64::new(0),
            });
            let task = tokio::spawn(from_outside(shared.clone(), public, None));
            lock(&shared.state).tasks.push(task);
            Ok(SimNat { shared })
        }

        /// The endpoint the NAT shows the world for the device: what a DHT node or a STUN server
        /// would report, and what a peer is told to dial. For dependent mapping it is the endpoint
        /// of no flow in particular (use [`SimNat::public_endpoint_toward`]).
        pub fn public_endpoint(&self) -> SocketAddr {
            self.shared.public.local_addr().unwrap_or(self.shared.device)
        }

        /// The endpoint the NAT shows `peer` for the device: [`SimNat::public_endpoint`], or with
        /// dependent mapping the port of the flow toward `peer`.
        pub fn public_endpoint_toward(&self, peer: SocketAddr) -> io::Result<SocketAddr> {
            gateway(&self.shared, peer)?.public.local_addr()
        }

        /// Where the device sends to reach `peer` (the peer's public endpoint) through the NAT.
        pub fn gateway_to(&self, peer: SocketAddr) -> io::Result<SocketAddr> {
            gateway(&self.shared, peer)?.private.local_addr()
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
        let private = bind()?;
        let public = match shared.mapping {
            Mapping::EndpointIndependent => shared.public.clone(),
            Mapping::Dependent => {
                let own = bind()?;
                state.tasks.push(tokio::spawn(from_outside(shared.clone(), own.clone(), Some(peer))));
                own
            }
        };
        let gateway = Arc::new(Gateway { private, public });
        state.tasks.push(tokio::spawn(from_device(shared.clone(), gateway.clone(), peer)));
        state.gateways.insert(peer, gateway.clone());
        Ok(gateway)
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
            // The mapping and the filter exist before the packet leaves, as in a real NAT, so an
            // answer that comes back at once is let in.
            lock(&shared.state).sent_to.insert(peer);
            if gateway.public.send_to(&buffer[..len], peer).await.is_ok() {
                shared.sent.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// What arrives on a public socket is let in or dropped, and delivered to the device from the
    /// gateway of whoever sent it. `only` is the one peer a flow's own socket (dependent mapping)
    /// takes packets from.
    async fn from_outside(shared: Arc<Shared>, socket: Arc<UdpSocket>, only: Option<SocketAddr>) {
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
                    shared.filtering == Filtering::Open || lock(&shared.state).sent_to.contains(&from)
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

#[cfg(test)]
mod tests {
    use std::{
        io,
        net::{Ipv4Addr, SocketAddr},
        sync::atomic::{AtomicUsize, Ordering},
    };

    use tokio::{net::UdpSocket as AsyncSocket, sync::mpsc, task::JoinHandle};
    use velora_nat::{observe::reply_to_ping, wake::Mac};
    use velora_protocol::{
        identity::{Identity, KnownHost},
        tls::Fingerprint,
        wire::{self, Codec, HostMsg, PROTOCOL_VERSION},
    };
    use velora_relay::forward::{Config as RelayConfig, Relay, WakeError, Waker as MagicPacket};

    use super::{
        nat_sim::{Filtering, Mapping, NatStats, SimNat},
        *,
    };
    use crate::{
        reach::ReachParams,
        testing::{eventually, within, TempDir},
    };

    const CONE: (Mapping, Filtering) = (Mapping::EndpointIndependent, Filtering::PortRestricted);
    const OPEN: (Mapping, Filtering) = (Mapping::EndpointIndependent, Filtering::Open);
    const SECRET: [u8; 16] = [0x5E; 16];
    const HOST_NAME: &str = "punched-pc";

    /// The waits of a dial, short enough for tests, long enough for loopback.
    fn fast() -> Timing {
        Timing {
            relay_wait: Duration::from_secs(8),
            dht_wait: Duration::from_secs(8),
            ask_limit: Duration::from_secs(8),
            grace: Duration::from_millis(400),
            redial: Duration::from_millis(100),
            republish: Duration::from_secs(30),
            observe: Duration::from_millis(800),
            observe_limit: Duration::from_secs(5),
            relay: Waits {
                connect: Duration::from_millis(700),
                welcome: Duration::from_secs(2),
                reach: Duration::from_secs(1),
                answer: Duration::from_secs(2),
                inner: Duration::from_secs(1),
            },
            relay_stagger: Duration::from_millis(100),
            address_stagger: Duration::from_millis(600),
            publish_retry: Duration::from_millis(50),
        }
    }

    // ---- DHT nodes that say what the NAT shows ----

    /// A DHT node on the loopback that answers each ping with the address `claim` says it saw (the `ip` field of BEP 42),
    /// or not at all. `claim` gets the node's own address and the address the ping came from.
    struct FakeNode {
        addr: SocketAddr,
        /// Where the pings it got came from.
        sources: Arc<Mutex<Vec<SocketAddr>>>,
        task: JoinHandle<()>,
    }

    impl FakeNode {
        fn spawn(
            ip: Ipv4Addr,
            claim: impl Fn(SocketAddr, SocketAddr) -> Option<SocketAddr> + Send + 'static,
        ) -> FakeNode {
            let socket = std::net::UdpSocket::bind((ip, 0)).unwrap();
            socket.set_nonblocking(true).unwrap();
            let socket = AsyncSocket::from_std(socket).unwrap();
            let addr = socket.local_addr().unwrap();
            let sources = Arc::new(Mutex::new(Vec::new()));
            let task = tokio::spawn({
                let sources = sources.clone();
                async move {
                    let mut buffer = vec![0u8; 2048];
                    loop {
                        let (len, from) = match socket.recv_from(&mut buffer).await {
                            Ok(received) => received,
                            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => continue,
                            Err(_) => return,
                        };
                        locked(&sources).push(from);
                        let reply = claim(addr, from).and_then(|seen| reply_to_ping(&buffer[..len], seen));
                        if let Some(reply) = reply {
                            let _ = socket.send_to(&reply, from).await;
                        }
                    }
                }
            });
            FakeNode { addr, sources, task }
        }
    }

    impl Drop for FakeNode {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    /// Three nodes, on three addresses (the NAT is classified by how many servers saw it), each saying what `claim` says.
    fn nodes_claiming(
        claim: impl Fn(SocketAddr, SocketAddr) -> Option<SocketAddr> + Clone + Send + 'static,
    ) -> Vec<FakeNode> {
        (2..=4).map(|n| FakeNode::spawn(Ipv4Addr::new(127, 0, 0, n), claim.clone())).collect()
    }

    /// Three nodes that all say the device is at `shown`: what a cone NAT looks like.
    fn agreeing(shown: SocketAddr) -> Vec<FakeNode> {
        nodes_claiming(move |_, _| Some(shown))
    }

    // ---- the DHT ----

    #[derive(Clone)]
    struct Stored {
        key: [u8; 32],
        salt: Vec<u8>,
        blob: Vec<u8>,
        seq: i64,
    }

    /// A DHT that keeps what is published, after answering the errors it was given.
    #[derive(Default)]
    struct FakeDht {
        failures: Mutex<VecDeque<DhtError>>,
        stored: Mutex<Vec<Stored>>,
        tries: AtomicUsize,
        /// How long a publish takes before it stores anything.
        delay: Duration,
    }

    impl FakeDht {
        fn failing(errors: impl IntoIterator<Item = DhtError>) -> Arc<FakeDht> {
            Arc::new(FakeDht { failures: Mutex::new(errors.into_iter().collect()), ..Default::default() })
        }

        fn slow(delay: Duration) -> Arc<FakeDht> {
            Arc::new(FakeDht { delay, ..Default::default() })
        }

        fn all(&self) -> Vec<Stored> {
            locked(&self.stored).clone()
        }

        fn tries(&self) -> usize {
            self.tries.load(Ordering::Relaxed)
        }

        fn first(&self) -> Option<Stored> {
            locked(&self.stored).first().cloned()
        }
    }

    impl Dht for FakeDht {
        fn publish<'a>(
            &'a self,
            signer: &'a (dyn Signer + Sync),
            salt: &'a [u8],
            blob: &'a [u8],
            seq: i64,
        ) -> Publishing<'a> {
            Box::pin(async move {
                self.tries.fetch_add(1, Ordering::Relaxed);
                if let Some(error) = locked(&self.failures).pop_front() {
                    return Err(error);
                }
                tokio::time::sleep(self.delay).await;
                locked(&self.stored).push(Stored {
                    key: signer.public_key(),
                    salt: salt.to_vec(),
                    blob: blob.to_vec(),
                    seq,
                });
                Ok(Published { seq, stored_at: 20 })
            })
        }
    }

    // ---- a relay ----

    /// A magic packet that is never asked for.
    struct NoWaker;

    impl MagicPacket for NoWaker {
        fn wake(&self, _mac: &Mac, _host: Ipv4Addr) -> Result<usize, WakeError> {
            Err(WakeError::NotOnNetwork)
        }
    }

    /// A relay on the loopback, run the way the host's relay code runs it: Velora's hello and welcome for a link, then the
    /// control messages handed to D2's `Relay` and its answers written back.
    struct Rig {
        addr: SocketAddr,
        identity: Identity,
        _endpoint: quinn::Endpoint,
    }

    impl Rig {
        fn start() -> Rig {
            let identity = Identity::generate().unwrap();
            let endpoint =
                quinn::Endpoint::server(tls::server_config(&identity).unwrap(), "127.0.0.1:0".parse().unwrap())
                    .unwrap();
            let relay = Relay::with_waker(RelayConfig::default(), Arc::new(NoWaker));
            let accepting = endpoint.clone();
            tokio::spawn(async move {
                while let Some(incoming) = accepting.accept().await {
                    let relay = relay.clone();
                    tokio::spawn(async move {
                        if let Err(e) = serve_link(relay, incoming).await {
                            tracing::debug!("test relay: {e:#}");
                        }
                    });
                }
            });
            Rig { addr: endpoint.local_addr().unwrap(), identity, _endpoint: endpoint }
        }

        fn relay_ref(&self) -> RelayRef {
            RelayRef { addr: self.addr, fingerprint: self.identity.fingerprint() }
        }
    }

    /// What the host does with a connection of a paired device that says hello as a link (`serve_link` in its `server.rs`).
    async fn serve_link(relay: Relay, incoming: quinn::Incoming) -> Result<()> {
        let conn = incoming.await?;
        let (mut send, mut recv) = conn.accept_bi().await?;
        let body = wire::read_msg(&mut recv).await?.ok_or_else(|| anyhow!("no hello"))?;
        let ClientMsg::Hello { ext, .. } = ClientMsg::decode(&body)? else { bail!("not a hello") };
        let welcome = HostMsg::Welcome {
            version: PROTOCOL_VERSION,
            host_name: "relay".into(),
            codec: Codec::H264,
            width: 0,
            height: 0,
            features: ext.map(|_| 0),
            addresses: Vec::new(),
        };
        send.write_all(&welcome.encode()).await?;
        if ext.is_some_and(|e| e.reach) {
            let reach = HostMsg::Reach {
                addresses: Vec::new(),
                key: [0; 32],
                secret: [0; 16],
                relays: Vec::new(),
                mac: None,
                relays_for_others: true,
            };
            send.write_all(&reach.encode()).await?;
        }
        while let Some(body) = wire::read_msg(&mut recv).await? {
            let msg = ClientMsg::decode(&body)?;
            if let Some(answer) = relay.handle(&conn, &msg).await {
                send.write_all(&answer.encode()).await?;
            }
        }
        Ok(())
    }

    // ---- a host and a client, each behind a NAT ----

    /// A host behind a NAT: a QUIC server on the loopback that does what `server.rs` does with a connection attempt as far as
    /// the punch can see (Retry for an address that has not proved itself, the device noted, what it says echoed).
    struct SimHost {
        identity: Identity,
        endpoint: quinn::Endpoint,
        nat: Arc<SimNat>,
        /// Each connection that got in, with the fingerprint of the device.
        arrivals: mpsc::UnboundedReceiver<(Fingerprint, quinn::Connection)>,
    }

    impl SimHost {
        fn start(nat: (Mapping, Filtering)) -> SimHost {
            let identity = Identity::generate().unwrap();
            let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let addr = socket.local_addr().unwrap();
            let endpoint = quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                Some(tls::server_config(&identity).unwrap()),
                socket,
                Arc::new(quinn::TokioRuntime),
            )
            .unwrap();
            let (arrived, arrivals) = mpsc::unbounded_channel();
            let accepting = endpoint.clone();
            tokio::spawn(async move {
                while let Some(incoming) = accepting.accept().await {
                    if !incoming.remote_address_validated() && incoming.may_retry() {
                        let _ = incoming.retry();
                        continue;
                    }
                    let arrived = arrived.clone();
                    tokio::spawn(async move {
                        let Ok(connection) = incoming.await else { return };
                        let Ok(fingerprint) = tls::peer_fingerprint(&connection) else { return };
                        let _ = arrived.send((fingerprint, connection.clone()));
                        // The first stream is Velora's control stream: the hello and the welcome. It stays open here.
                        let Ok((mut control, mut hello)) = connection.accept_bi().await else { return };
                        let Ok(Some(body)) = wire::read_msg(&mut hello).await else { return };
                        if !matches!(ClientMsg::decode(&body), Ok(ClientMsg::Hello { .. })) {
                            return;
                        }
                        let welcome = HostMsg::Welcome {
                            version: PROTOCOL_VERSION,
                            host_name: HOST_NAME.into(),
                            codec: Codec::H264,
                            width: 1280,
                            height: 720,
                            features: None,
                            addresses: Vec::new(),
                        };
                        let _ = control.write_all(&welcome.encode()).await;
                        // The streams after it are echoed.
                        while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                            let Ok(data) = recv.read_to_end(1024).await else { return };
                            let _ = send.write_all(&data).await;
                            let _ = send.finish();
                        }
                    });
                }
            });
            SimHost { identity, endpoint, nat: Arc::new(SimNat::new(addr, nat.0, nat.1).unwrap()), arrivals }
        }

        fn fingerprint(&self) -> Fingerprint {
            self.identity.fingerprint()
        }

        fn puncher(&self) -> Puncher {
            Puncher { identity: self.identity.clone(), endpoint: self.endpoint.clone(), nat: self.nat.clone() }
        }

        /// Registers with the relay as a host does, and punches toward each client whose request the relay passes on, `delay`
        /// after it arrives. The requests are kept for the test to look at.
        async fn register_with(&self, rig: &Rig, delay: Duration) -> Registered {
            let mut link = Link::open(&self.identity, "host", rig.relay_ref(), &Waits::DEFAULT).await.unwrap();
            link.ask(ClientMsg::RelayRegister { mac: None }, &Waits::DEFAULT).await.unwrap();
            let puncher = self.puncher();
            let (seen, requests) = mpsc::unbounded_channel();
            let task = tokio::spawn(async move {
                while let Ok(mut stream) = link.conn.accept_uni().await {
                    let Ok(Some(body)) = wire::read_msg(&mut stream).await else { continue };
                    let Ok(msg) = HostMsg::decode(&body) else { continue };
                    if let HostMsg::PunchRequest { from, endpoint, .. } = &msg {
                        tokio::time::sleep(delay).await;
                        puncher.punch(Fingerprint::from_base64(from).unwrap(), endpoint.parse().unwrap());
                    }
                    let _ = seen.send(msg);
                }
            });
            Registered { requests, _task: task }
        }
    }

    /// What the request handed to a host through a relay.
    struct Registered {
        requests: mpsc::UnboundedReceiver<HostMsg>,
        _task: JoinHandle<()>,
    }

    /// What the host's `respond` does, as far as the NAT can tell: one QUIC Initial toward the client's public endpoint from
    /// the listening port (through the host's NAT), which QUIC retransmits for a few seconds.
    #[derive(Clone)]
    struct Puncher {
        identity: Identity,
        endpoint: quinn::Endpoint,
        nat: Arc<SimNat>,
    }

    impl Puncher {
        fn punch(&self, client: Fingerprint, client_public: SocketAddr) {
            let toward = self.nat.gateway_to(client_public).unwrap();
            let config = tls::client_config(&self.identity, client).unwrap();
            let connecting = self.endpoint.connect_with(config, toward, tls::SERVER_NAME).unwrap();
            tokio::spawn(async move {
                let _ = tokio::time::timeout(Duration::from_secs(8), connecting).await;
            });
        }
    }

    /// The host's poller: waits for the item to be in the DHT, `delay` later opens it as the host does and punches toward the
    /// endpoint it names.
    fn poll_dht(dht: Arc<FakeDht>, puncher: Puncher, client: Fingerprint, delay: Duration) -> JoinHandle<Stored> {
        tokio::spawn(async move {
            let stored = eventually("the item to be published", || dht.first()).await;
            tokio::time::sleep(delay).await;
            let item = punch_item::open(&stored.blob, &Secret::new(SECRET), stored.seq, SystemTime::now()).unwrap();
            puncher.punch(client, item.endpoint.parse().unwrap());
            stored
        })
    }

    /// A device behind a NAT: the socket it dials from, which the dial takes over, and the NAT in front of it.
    struct SimClient {
        identity: Identity,
        socket: Option<std::net::UdpSocket>,
        addr: SocketAddr,
        nat: Arc<SimNat>,
    }

    impl SimClient {
        fn new(nat: (Mapping, Filtering)) -> SimClient {
            let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let addr = socket.local_addr().unwrap();
            let nat = Arc::new(SimNat::new(addr, nat.0, nat.1).unwrap());
            SimClient { identity: Identity::generate().unwrap(), socket: Some(socket), addr, nat }
        }

        fn fingerprint(&self) -> Fingerprint {
            self.identity.fingerprint()
        }
    }

    fn world(nodes: &[FakeNode], dht: Option<Arc<FakeDht>>) -> Env {
        Env {
            nodes: Some(nodes.iter().map(|node| node.addr).collect()),
            stun: Some(Vec::new()),
            dht: dht.map(|dht| dht as Arc<dyn Dht>),
            seqs: Box::leak(Box::new(Seqs(Mutex::new(BTreeMap::new())))),
            timing: fast(),
            allow_local: true,
            try_symmetric: false,
        }
    }

    /// What a client that paired with `host` holds for it; `secret` is the one it got for the DHT.
    fn params(client: &Identity, host: Fingerprint, secret: Option<[u8; 16]>, dir: &TempDir) -> ConnectParams {
        ConnectParams {
            // A documentation address: nothing answers, and nothing is sent to it in these tests.
            addr: SocketAddr::from(([192, 0, 2, 1], 7420)),
            also: Vec::new(),
            host_fingerprint: host,
            identity: client.clone(),
            device_name: "test device".into(),
            pairing_secret: None,
            password: None,
            reach: Some(ReachParams {
                host: KnownHost {
                    name: "punched-pc".into(),
                    address: "192.0.2.1:7420".into(),
                    fingerprint: host.to_base64(),
                    secret,
                    ..Default::default()
                },
                state_dir: dir.path().to_path_buf(),
            }),
        }
    }

    type Dialed = Result<(quinn::Endpoint, quinn::Connection)>;

    /// Starts the dial of `client` toward `host`, as the race would: the endpoint it is given is the host's public one as the
    /// client's NAT carries packets to it.
    fn start_dial(
        client: &mut SimClient,
        host: &SimHost,
        params: ConnectParams,
        via: Vec<RelayRef>,
        env: Env,
    ) -> JoinHandle<Dialed> {
        let socket = client.socket.take().unwrap();
        let target = client.nat.gateway_to(host.nat.public_endpoint()).unwrap();
        tokio::spawn(async move { dial(&params, target, &via, socket, env).await })
    }

    /// What a connection through the hole is good for: the peer is the host, the host saw this device, Velora's hello is
    /// answered with its welcome (what `handshake` in `lib.rs` does next with the connection a dial returns), and data goes
    /// both ways.
    async fn assert_works(host: &mut SimHost, client: &SimClient, connection: &quinn::Connection) {
        assert_eq!(tls::peer_fingerprint(connection).unwrap(), host.fingerprint(), "the client pinned the host");
        let (fingerprint, _) = within("the host to see the device", host.arrivals.recv()).await.unwrap();
        assert_eq!(fingerprint, client.fingerprint(), "the host knows the device by its certificate");

        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        let hello = ClientMsg::Hello {
            version: PROTOCOL_VERSION,
            name: "test device".into(),
            pairing_secret: None,
            password: None,
            ext: None,
        };
        send.write_all(&hello.encode()).await.unwrap();
        let body = within("the welcome", wire::read_msg(&mut recv)).await.unwrap().expect("the host answered");
        let HostMsg::Welcome { version, host_name, .. } = HostMsg::decode(&body).unwrap() else {
            panic!("the host said something before its welcome")
        };
        assert_eq!((version, host_name.as_str()), (PROTOCOL_VERSION, HOST_NAME));

        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        send.write_all(b"through the hole").await.unwrap();
        send.finish().unwrap();
        assert_eq!(recv.read_to_end(1024).await.unwrap(), b"through the hole");
    }

    /// The socket of a dial is free again once the dial is over.
    async fn assert_released(addr: SocketAddr) {
        eventually("the dial's socket to be closed", || std::net::UdpSocket::bind(addr).ok()).await;
    }

    // ---- through the DHT ----

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_client_behind_a_cone_nat_gets_through_another_with_the_request_in_the_dht() {
        let mut host = SimHost::start(CONE);
        let mut client = SimClient::new(CONE);
        let nodes = agreeing(client.nat.public_endpoint());
        let (dht, dir) = (Arc::new(FakeDht::default()), TempDir::new());
        let params = params(&client.identity, host.fingerprint(), Some(SECRET), &dir);

        // The host looks for the request half a second after it is there.
        let polled = poll_dht(dht.clone(), host.puncher(), client.fingerprint(), Duration::from_millis(500));
        let dialing = start_dial(&mut client, &host, params, Vec::new(), world(&nodes, Some(dht.clone())));
        let (_endpoint, connection) = within("the dial", dialing).await.unwrap().unwrap();
        assert_works(&mut host, &client, &connection).await;

        // Until the host punched, the client's packets died at its NAT; afterwards both NATs carried them.
        assert!(host.nat.stats().filtered >= 1, "{:?}", host.nat.stats());
        assert!(host.nat.stats().delivered > 0 && client.nat.stats().delivered > 0);

        // The item is at the key and slot the host polls, and names the endpoint the NAT showed the nodes, which the nodes
        // were asked from the very socket that dialed.
        let stored = polled.await.unwrap();
        assert_eq!(stored.key, punch_item::public_key(&Secret::new(SECRET)));
        assert_eq!(stored.salt, punch_item::SALT);
        let item = punch_item::open(&stored.blob, &Secret::new(SECRET), stored.seq, SystemTime::now()).unwrap();
        assert_eq!(item.endpoint, client.nat.public_endpoint().to_string());
        for node in &nodes {
            let sources = locked(&node.sources);
            assert!(!sources.is_empty() && sources.iter().all(|from| *from == client.addr), "{sources:?}");
        }
        assert_eq!(dht.tries(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_request_the_dht_turned_down_for_its_seq_is_made_again_above_what_is_stored() {
        let mut host = SimHost::start(CONE);
        let mut client = SimClient::new(CONE);
        let nodes = agreeing(client.nat.public_endpoint());
        let seen = i64::try_from(SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()).unwrap()
            + 100_000;
        // A newer item is stored, then the network hiccups; the third try goes through.
        let dht = FakeDht::failing([DhtError::SeqTooLow { seq: 1, seen }, DhtError::TimedOut]);
        let dir = TempDir::new();
        let params = params(&client.identity, host.fingerprint(), Some(SECRET), &dir);

        let polled = poll_dht(dht.clone(), host.puncher(), client.fingerprint(), Duration::ZERO);
        let dialing = start_dial(&mut client, &host, params, Vec::new(), world(&nodes, Some(dht.clone())));
        let (_endpoint, connection) = within("the dial", dialing).await.unwrap().unwrap();
        assert_works(&mut host, &client, &connection).await;

        assert_eq!(dht.tries(), 3);
        // The seq is above the one that was in the way, and the host opens the item all the same: its `ts` is the clock's.
        assert!(polled.await.unwrap().seq > seen);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn publishing_is_given_up_after_a_few_tries_and_what_is_ours_is_not_tried_again() {
        let request = |dht: &Arc<FakeDht>| Request {
            secret: Secret::new(SECRET),
            endpoint: "198.51.100.7:4000".into(),
            nonce: 1,
            dht: dht.clone(),
        };

        let dht = FakeDht::failing([DhtError::TimedOut, DhtError::NoNetwork, DhtError::Refused { acknowledged: 1 }]);
        let env = world(&[], Some(dht.clone()));
        let started = tokio::time::Instant::now();
        let error = request(&dht).publish(&env).await.unwrap_err();
        assert_eq!(dht.tries(), MAX_PUBLISHES);
        assert!(format!("{error:#}").contains("not published in 3 tries"), "{error:#}");
        // A pause after each failure that was followed by another try, and none after the last.
        assert!(started.elapsed() >= 2 * env.timing.publish_retry, "{:?}", started.elapsed());

        let dht = FakeDht::failing([DhtError::TooBig { len: 2_000 }]);
        let env = world(&[], Some(dht.clone()));
        let error = request(&dht).publish(&env).await.unwrap_err();
        assert_eq!(dht.tries(), 1, "a request the DHT cannot hold is ours to fix, not to repeat");
        assert!(format!("{error:#}").contains("would not take the request"), "{error:#}");
    }

    #[test]
    fn the_failures_that_may_pass_are_the_ones_that_are_tried_again() {
        for error in [DhtError::NoNetwork, DhtError::Refused { acknowledged: 0 }, DhtError::TimedOut, DhtError::Stopped]
        {
            assert!(transient(&error), "{error}");
        }
        for error in
            [DhtError::TooBig { len: 1 }, DhtError::SaltTooBig { len: 1 }, DhtError::SeqTooLow { seq: 1, seen: 2 }]
        {
            assert!(!transient(&error), "{error}");
        }
    }

    // ---- through a relay ----

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_client_behind_a_cone_nat_gets_through_another_with_the_request_through_a_relay() {
        let mut host = SimHost::start(CONE);
        let mut client = SimClient::new(CONE);
        let nodes = agreeing(client.nat.public_endpoint());
        let (rig, dir, dht) = (Rig::start(), TempDir::new(), Arc::new(FakeDht::default()));
        let mut registered = host.register_with(&rig, Duration::from_millis(300)).await;
        let params = params(&client.identity, host.fingerprint(), Some(SECRET), &dir);

        let dialing = start_dial(&mut client, &host, params, vec![rig.relay_ref()], world(&nodes, Some(dht.clone())));
        let (_endpoint, connection) = within("the dial", dialing).await.unwrap().unwrap();
        assert_works(&mut host, &client, &connection).await;

        // The relay passed on what the client said: who it is (from its certificate, not its word), where it is, a nonce.
        let HostMsg::PunchRequest { from, endpoint, .. } =
            within("the request", registered.requests.recv()).await.unwrap()
        else {
            panic!("the host was sent something else")
        };
        assert_eq!(from, client.fingerprint().to_base64());
        assert_eq!(endpoint, client.nat.public_endpoint().to_string());
        assert_eq!(dht.tries(), 0, "a relay carries the request, the DHT is left alone");
        assert!(host.nat.stats().filtered >= 1, "the client's packets died at the host's NAT until it punched");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_relay_that_does_not_answer_or_does_not_know_the_host_is_skipped_for_the_next() {
        let mut host = SimHost::start(CONE);
        let mut client = SimClient::new(CONE);
        let nodes = agreeing(client.nat.public_endpoint());
        let dir = TempDir::new();
        // The first address has nothing behind it, the second is a relay the host never registered with, the third works.
        let dead = RelayRef {
            addr: std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap(),
            fingerprint: Fingerprint([9; 32]),
        };
        let (stranger, relay) = (Rig::start(), Rig::start());
        let mut registered = host.register_with(&relay, Duration::ZERO).await;
        let params = params(&client.identity, host.fingerprint(), None, &dir);

        let via = vec![dead, stranger.relay_ref(), relay.relay_ref()];
        let dialing = start_dial(&mut client, &host, params, via, world(&nodes, None));
        let (_endpoint, connection) = within("the dial", dialing).await.unwrap().unwrap();
        assert_works(&mut host, &client, &connection).await;
        assert!(matches!(registered.requests.recv().await, Some(HostMsg::PunchRequest { .. })));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_first_relay_to_pass_the_request_on_ends_the_asking() {
        let mut host = SimHost::start(CONE);
        let mut client = SimClient::new(CONE);
        let nodes = agreeing(client.nat.public_endpoint());
        let (first, second, dir) = (Rig::start(), Rig::start(), TempDir::new());
        let mut at_first = host.register_with(&first, Duration::ZERO).await;
        let mut at_second = host.register_with(&second, Duration::ZERO).await;
        let params = params(&client.identity, host.fingerprint(), None, &dir);
        // The second relay is asked 600 ms after the first, which passes the request on long before.
        let mut env = world(&nodes, None);
        env.timing.relay_stagger = Duration::from_millis(600);

        let dialing = start_dial(&mut client, &host, params, vec![first.relay_ref(), second.relay_ref()], env);
        let (_endpoint, connection) = within("the dial", dialing).await.unwrap().unwrap();
        assert_works(&mut host, &client, &connection).await;
        assert!(matches!(at_first.requests.recv().await, Some(HostMsg::PunchRequest { .. })));
        // Past the stagger, so that a request that was only held back would have gone out by now.
        tokio::time::sleep(Duration::from_millis(700)).await;
        assert!(at_second.requests.try_recv().is_err(), "the second relay was asked as well");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn only_the_first_few_relays_are_asked() {
        let host = SimHost::start(CONE);
        let mut client = SimClient::new(CONE);
        let nodes = agreeing(client.nat.public_endpoint());
        let (relay, dir) = (Rig::start(), TempDir::new());
        let mut registered = host.register_with(&relay, Duration::ZERO).await;
        let params = params(&client.identity, host.fingerprint(), None, &dir);
        let dead = |n: u8| RelayRef {
            addr: std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap(),
            fingerprint: Fingerprint([n; 32]),
        };
        // Relays that do not answer take up the allowance, and the one that works is past it.
        let mut via: Vec<RelayRef> = (0..u8::try_from(MAX_RELAYS).unwrap()).map(dead).collect();
        via.push(relay.relay_ref());
        let mut env = world(&nodes, None);
        env.timing.relay_wait = Duration::from_millis(1500);
        env.timing.relay_stagger = Duration::from_millis(10);

        let dialing = start_dial(&mut client, &host, params, via, env);
        let error = within("the dial", dialing).await.unwrap().expect_err("the relay that works was never asked");
        assert!(format!("{error:#}").contains("could not be delivered through a relay"), "{error:#}");
        assert!(registered.requests.try_recv().is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn relays_that_all_refuse_end_the_dial_after_a_short_grace_and_are_in_the_words_of_the_error() {
        let mut host = SimHost::start(CONE);
        let mut client = SimClient::new(CONE);
        let nodes = agreeing(client.nat.public_endpoint());
        let dir = TempDir::new();
        let stranger = Rig::start();
        let params = params(&client.identity, host.fingerprint(), None, &dir);
        let env = world(&nodes, None);
        assert!(env.timing.relay_wait > Duration::from_secs(5), "the wait the dial must not sit out");

        let started = tokio::time::Instant::now();
        let dialing = start_dial(&mut client, &host, params, vec![stranger.relay_ref()], env);
        let error = within("the dial", dialing).await.unwrap().expect_err("no host punched, so no connection");
        let words = format!("{error:#}");
        assert!(words.contains("could not be delivered through a relay"), "{words}");
        assert!(words.contains("the relay refused"), "{words}");
        assert!(started.elapsed() < Duration::from_secs(3), "it kept dialing for {:?}", started.elapsed());
        assert!(host.arrivals.try_recv().is_err());
    }

    // ---- what the dial refuses or gives up ----

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_symmetric_nat_is_not_tried_and_nothing_is_sent() {
        let host = SimHost::start(CONE);
        let mut client = SimClient::new((Mapping::Dependent, Filtering::PortRestricted));
        // Every node is shown another port, as a symmetric NAT does.
        let nat = client.nat.clone();
        let nodes = nodes_claiming(move |node, _| nat.public_endpoint_toward(node).ok());
        let (dht, dir) = (Arc::new(FakeDht::default()), TempDir::new());
        let params = params(&client.identity, host.fingerprint(), Some(SECRET), &dir);

        let dialing = start_dial(&mut client, &host, params, Vec::new(), world(&nodes, Some(dht.clone())));
        let error = within("the dial", dialing).await.unwrap().expect_err("a symmetric NAT cannot be punched");
        assert!(error.to_string().contains("symmetric NAT"), "{error:#}");
        assert_eq!(dht.tries(), 0, "nobody is asked to open a hole that cannot work");
        assert_eq!(host.nat.stats(), NatStats::default(), "and nothing is sent toward the host");
        assert_released(client.addr).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_symmetric_nat_would_keep_the_host_out_if_it_were_tried() {
        let host = SimHost::start(CONE);
        let mut client = SimClient::new((Mapping::Dependent, Filtering::PortRestricted));
        let nat = client.nat.clone();
        let nodes = nodes_claiming(move |node, _| nat.public_endpoint_toward(node).ok());
        let (dht, dir) = (Arc::new(FakeDht::default()), TempDir::new());
        let params = params(&client.identity, host.fingerprint(), Some(SECRET), &dir);
        let mut env = world(&nodes, Some(dht.clone()));
        env.try_symmetric = true;
        env.timing.dht_wait = Duration::from_millis(2500);

        // The host does its part, toward the endpoint the first node saw: good for that node and nobody else.
        let polled = poll_dht(dht.clone(), host.puncher(), client.fingerprint(), Duration::ZERO);
        let dialing = start_dial(&mut client, &host, params, Vec::new(), env);
        let error = within("the dial", dialing).await.unwrap().expect_err("no hole opens through a symmetric NAT");
        assert!(format!("{error:#}").contains("did not answer through the hole"), "{error:#}");
        polled.await.unwrap();
        assert!(client.nat.stats().filtered > 0, "the host's packet was dropped at the client's NAT");
        assert!(host.nat.stats().filtered > 0, "and the client's, at the host's");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_host_that_never_opens_its_nat_ends_the_dial_when_the_time_is_up_and_frees_the_socket() {
        let host = SimHost::start(CONE);
        let mut client = SimClient::new(CONE);
        let nodes = agreeing(client.nat.public_endpoint());
        let (dht, dir) = (Arc::new(FakeDht::default()), TempDir::new());
        let params = params(&client.identity, host.fingerprint(), Some(SECRET), &dir);
        let mut env = world(&nodes, Some(dht.clone()));
        env.timing.dht_wait = Duration::from_millis(1200);

        let started = tokio::time::Instant::now();
        let dialing = start_dial(&mut client, &host, params, Vec::new(), env);
        let error = within("the dial", dialing).await.unwrap().expect_err("nobody punched");
        let words = format!("{error:#}");
        assert!(words.contains("the host did not answer through the hole"), "{words}");
        assert!(words.contains("the request was delivered in the DHT"), "{words}");
        assert!(words.contains("within 1.2 s"), "{words}");
        assert!(started.elapsed() >= Duration::from_millis(1200), "{:?}", started.elapsed());
        assert_eq!(dht.tries(), 1);
        assert_released(client.addr).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_the_dial_stops_everything_it_started() {
        let host = SimHost::start(CONE);
        let mut client = SimClient::new(CONE);
        let nodes = agreeing(client.nat.public_endpoint());
        let (dht, dir) = (Arc::new(FakeDht::default()), TempDir::new());
        let params = params(&client.identity, host.fingerprint(), Some(SECRET), &dir);

        let dialing = start_dial(&mut client, &host, params, Vec::new(), world(&nodes, Some(dht)));
        eventually("the first attempts to leave", || (client.nat.stats().sent >= 3).then_some(())).await;
        dialing.abort();
        let _ = dialing.await;
        // What was in flight settles, and then the device sends nothing more.
        tokio::time::sleep(Duration::from_millis(300)).await;
        let sent = client.nat.stats().sent;
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert_eq!(client.nat.stats().sent, sent, "the dial went on sending after it was dropped");
        assert_released(client.addr).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_hole_that_opens_late_is_dialed_through_within_a_moment() {
        let mut host = SimHost::start(CONE);
        let mut client = SimClient::new(CONE);
        let nodes = agreeing(client.nat.public_endpoint());
        let (rig, dir) = (Rig::start(), TempDir::new());
        // The host punches five seconds after it hears. One connection attempt sends its Initial at 0, 0.15, 0.45, 1.05, 2.25
        // and 4.65 s and then at 9.45 s, past the end of the dial: only the attempts started since the hole opened get in.
        let _registered = host.register_with(&rig, Duration::from_secs(5)).await;
        let params = params(&client.identity, host.fingerprint(), None, &dir);

        let started = tokio::time::Instant::now();
        let dialing = start_dial(&mut client, &host, params, vec![rig.relay_ref()], world(&nodes, None));
        let (_endpoint, connection) = within("the dial", dialing).await.unwrap().unwrap();
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_secs(5), "it connected before the host punched: {elapsed:?}");
        assert!(elapsed < Duration::from_secs(7), "{elapsed:?}");
        assert_works(&mut host, &client, &connection).await;
    }

    /// The destination connection id of a QUIC long header packet: what tells one connection attempt from another.
    fn dcid(datagram: &[u8]) -> Option<Vec<u8>> {
        if datagram.first()? & 0x80 == 0 {
            return None;
        }
        let len = usize::from(*datagram.get(5)?);
        datagram.get(6..6 + len).map(<[u8]>::to_vec)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn attempts_start_every_redial_and_no_more_than_a_few_stay_alive() {
        // A peer that is only a socket: nothing answers, and each attempt shows by the connection id of its packets.
        let sink = AsyncSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let host = sink.local_addr().unwrap();
        let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let endpoint =
            quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, Arc::new(quinn::TokioRuntime))
                .unwrap();
        let config = tls::client_config(&Identity::generate().unwrap(), Fingerprint([1; 32])).unwrap();
        let mut timing = fast();
        timing.ask_limit = Duration::from_secs(60);
        // Asking never ends, so the dial does not either.
        let (_asking, signal) = watch::channel(Signal::Asking);
        let dialing = tokio::spawn({
            let endpoint = endpoint.clone();
            async move { dial_until(&endpoint, &config, host, &timing, Duration::from_secs(60), signal).await }
        });

        // For each attempt, when its packets began and when they stopped.
        let mut seen: std::collections::HashMap<Vec<u8>, (tokio::time::Instant, tokio::time::Instant)> =
            std::collections::HashMap::new();
        let end = tokio::time::Instant::now() + Duration::from_millis(2500);
        let mut buffer = vec![0u8; 2048];
        while let Ok(Ok((len, _))) = tokio::time::timeout_at(end, sink.recv_from(&mut buffer)).await {
            if let Some(id) = dcid(&buffer[..len]) {
                let now = tokio::time::Instant::now();
                seen.entry(id).and_modify(|(_, last)| *last = now).or_insert((now, now));
            }
        }
        dialing.abort();

        // One every 100 ms, the first at once.
        assert!(seen.len() >= 15, "{} attempts in 2.5 s", seen.len());
        // None outlives its place: it is dropped when the fourth after it starts, 400 ms on, while its own backoff (a packet at
        // 0, 0.15, 0.45, 1.05, 2.25 s) is still short. One that was left alone would still be sending after a second.
        let longest = seen.values().map(|(first, last)| *last - *first).max().unwrap();
        assert!(longest < Duration::from_millis(1000), "an attempt went on sending for {longest:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_wait_counts_from_the_delivery_and_not_from_the_start() {
        let mut host = SimHost::start(CONE);
        let mut client = SimClient::new(CONE);
        let nodes = agreeing(client.nat.public_endpoint());
        // The publish takes 1.5 s, longer than the wait that follows it; the host punches 0.3 s after it finds the item.
        let (dht, dir) = (FakeDht::slow(Duration::from_millis(1500)), TempDir::new());
        let params = params(&client.identity, host.fingerprint(), Some(SECRET), &dir);
        let mut env = world(&nodes, Some(dht.clone()));
        env.timing.dht_wait = Duration::from_secs(1);

        let started = tokio::time::Instant::now();
        let _polled = poll_dht(dht.clone(), host.puncher(), client.fingerprint(), Duration::from_millis(300));
        let dialing = start_dial(&mut client, &host, params, Vec::new(), env);
        let (_endpoint, connection) = within("the dial", dialing).await.unwrap().unwrap();
        assert!(started.elapsed() > Duration::from_millis(1500), "{:?}", started.elapsed());
        assert_works(&mut host, &client, &connection).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_request_that_cannot_be_delivered_ends_the_dial_after_a_short_grace() {
        let mut host = SimHost::start(CONE);
        let mut client = SimClient::new(CONE);
        let nodes = agreeing(client.nat.public_endpoint());
        let (dht, dir) = (FakeDht::failing([DhtError::TooBig { len: 2_000 }]), TempDir::new());
        let params = params(&client.identity, host.fingerprint(), Some(SECRET), &dir);
        let env = world(&nodes, Some(dht.clone()));
        assert!(env.timing.dht_wait > Duration::from_secs(5), "the wait the dial must not sit out");

        let started = tokio::time::Instant::now();
        let dialing = start_dial(&mut client, &host, params, Vec::new(), env);
        let error = within("the dial", dialing).await.unwrap().expect_err("the host was never asked");
        let words = format!("{error:#}");
        assert!(words.contains("could not be delivered in the DHT"), "{words}");
        assert!(words.contains("would not take the request"), "{words}");
        assert!(started.elapsed() < Duration::from_secs(3), "it kept dialing for {:?}", started.elapsed());
        assert_eq!(dht.tries(), 1);
        assert!(host.arrivals.try_recv().is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn asking_that_does_not_end_ends_the_dial_at_the_ask_limit() {
        let host = SimHost::start(CONE);
        let mut client = SimClient::new(CONE);
        let nodes = agreeing(client.nat.public_endpoint());
        // A publish that never ends.
        let (dht, dir) = (FakeDht::slow(Duration::from_secs(3600)), TempDir::new());
        let params = params(&client.identity, host.fingerprint(), Some(SECRET), &dir);
        let mut env = world(&nodes, Some(dht));
        env.timing.ask_limit = Duration::from_millis(700);

        let started = tokio::time::Instant::now();
        let dialing = start_dial(&mut client, &host, params, Vec::new(), env);
        let error = within("the dial", dialing).await.unwrap().expect_err("the host was never asked");
        assert!(format!("{error:#}").contains("the request was still on its way in the DHT"), "{error:#}");
        assert!(started.elapsed() >= Duration::from_millis(700), "{:?}", started.elapsed());
        assert!(started.elapsed() < Duration::from_secs(4), "{:?}", started.elapsed());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_request_is_published_again_with_a_fresh_ts_and_the_same_nonce() {
        let host = SimHost::start(CONE);
        let mut client = SimClient::new(CONE);
        let nodes = agreeing(client.nat.public_endpoint());
        let (dht, dir) = (Arc::new(FakeDht::default()), TempDir::new());
        let params = params(&client.identity, host.fingerprint(), Some(SECRET), &dir);
        let mut env = world(&nodes, Some(dht.clone()));
        env.timing.republish = Duration::from_millis(300);
        env.timing.dht_wait = Duration::from_millis(1700);

        let dialing = start_dial(&mut client, &host, params, Vec::new(), env);
        within("the dial", dialing).await.unwrap().expect_err("nobody punched");
        // The host opens each one as it finds it, and the one it finds last is the freshest.
        let items: Vec<_> = dht
            .all()
            .iter()
            .map(|stored| {
                let item = punch_item::open(&stored.blob, &Secret::new(SECRET), stored.seq, SystemTime::now()).unwrap();
                (stored.seq, item)
            })
            .collect();
        assert!(items.len() >= 3, "{} publishes in 1.7 s", items.len());
        assert!(items.windows(2).all(|pair| pair[0].0 < pair[1].0), "the seq must go up each time");
        assert!(items.iter().all(|(_, item)| item.nonce == items[0].1.nonce && item.endpoint == items[0].1.endpoint));
        assert!(items.windows(2).all(|pair| pair[0].1.ts <= pair[1].1.ts));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_addresses_of_one_relay_are_not_asked_together() {
        let mut host = SimHost::start(CONE);
        let mut client = SimClient::new(CONE);
        let nodes = agreeing(client.nat.public_endpoint());
        let (rig, dir) = (Rig::start(), TempDir::new());
        let mut registered = host.register_with(&rig, Duration::ZERO).await;
        let params = params(&client.identity, host.fingerprint(), None, &dir);
        // Two addresses of one relay, and no pause between relays: only the pause between a relay's own addresses holds the second back.
        let mut env = world(&nodes, None);
        env.timing.relay_stagger = Duration::ZERO;

        let dialing = start_dial(&mut client, &host, params, vec![rig.relay_ref(), rig.relay_ref()], env);
        let (_endpoint, connection) = within("the dial", dialing).await.unwrap().unwrap();
        assert_works(&mut host, &client, &connection).await;
        tokio::time::sleep(Duration::from_millis(800)).await;
        assert!(matches!(registered.requests.try_recv(), Ok(HostMsg::PunchRequest { .. })));
        assert!(registered.requests.try_recv().is_err(), "the relay was asked twice");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn after_a_relay_passes_the_request_on_the_dial_waits_for_the_host_and_then_ends() {
        let host = SimHost::start(CONE);
        let mut client = SimClient::new(CONE);
        let nodes = agreeing(client.nat.public_endpoint());
        let (rig, dir) = (Rig::start(), TempDir::new());
        // The host is registered with the relay and never does anything with what the relay gives it.
        let mut link = Link::open(&host.identity, "host", rig.relay_ref(), &Waits::DEFAULT).await.unwrap();
        link.ask(ClientMsg::RelayRegister { mac: None }, &Waits::DEFAULT).await.unwrap();
        let params = params(&client.identity, host.fingerprint(), None, &dir);
        let mut env = world(&nodes, None);
        env.timing.relay_wait = Duration::from_millis(700);
        assert!(env.timing.ask_limit > Duration::from_secs(5), "the end the delivery must pull in");

        let started = tokio::time::Instant::now();
        let dialing = start_dial(&mut client, &host, params, vec![rig.relay_ref()], env);
        let error = within("the dial", dialing).await.unwrap().expect_err("the host never punched");
        let words = format!("{error:#}");
        assert!(words.contains("the request was delivered through a relay"), "{words}");
        assert!(words.contains("within 0.7 s"), "{words}");
        assert!(started.elapsed() < Duration::from_secs(4), "{:?}", started.elapsed());
        drop(link);
    }

    #[test]
    fn the_delays_of_the_relays_follow_the_relay_and_not_the_address() {
        let relay = |fingerprint: u8, port: u16| RelayRef {
            addr: SocketAddr::from(([203, 0, 113, fingerprint], port)),
            fingerprint: Fingerprint([fingerprint; 32]),
        };
        let timing = Timing {
            relay_stagger: Duration::from_millis(10),
            address_stagger: Duration::from_millis(1000),
            ..Timing::DEFAULT
        };
        // Relays 1 and 2, then a second and a third address of relay 1.
        let via = [relay(1, 1), relay(2, 1), relay(1, 2), relay(1, 3)];
        let ms = |delays: Vec<Duration>| delays.iter().map(|d| d.as_millis()).collect::<Vec<_>>();
        assert_eq!(ms(relay_delays(&via, &timing)), vec![0, 10, 1000, 2000]);
        assert!(relay_delays(&[], &timing).is_empty());
    }

    #[test]
    fn seqs_only_go_up_for_a_key_and_a_floor_is_respected() {
        let seqs = Seqs(Mutex::new(BTreeMap::new()));
        let secret = Secret::new(SECRET);
        let build = |floor| seqs.build(&secret, "198.51.100.7:4000", 1, floor).unwrap().2;
        let (first, second, third) = (build(i64::MIN), build(i64::MIN), build(i64::MIN));
        assert!(first < second && second < third, "{first} {second} {third}");
        // What the DHT said it holds is a floor, and the next is above it.
        assert_eq!(build(third + 1_000), third + 1_001);
        // Another key has a count of its own.
        let other = seqs.build(&Secret::new([0x11; 16]), "198.51.100.7:4000", 1, i64::MIN).unwrap().2;
        assert!(other <= first + 1, "{other} {first}");
    }

    // ---- what the observation counts ----

    /// A STUN server on the loopback that tells every device it is at `shown`, and counts how often it was asked.
    struct FakeStun {
        addr: SocketAddr,
        asked: Arc<AtomicUsize>,
        task: JoinHandle<()>,
    }

    impl FakeStun {
        fn spawn(ip: Ipv4Addr, shown: SocketAddr) -> FakeStun {
            let SocketAddr::V4(shown) = shown else { panic!("a fake STUN server tells IPv4 endpoints") };
            let socket = std::net::UdpSocket::bind((ip, 0)).unwrap();
            socket.set_nonblocking(true).unwrap();
            let socket = AsyncSocket::from_std(socket).unwrap();
            let addr = socket.local_addr().unwrap();
            let asked = Arc::new(AtomicUsize::new(0));
            let task = tokio::spawn({
                let asked = asked.clone();
                async move {
                    let mut buffer = [0u8; 1500];
                    loop {
                        let (len, from) = match socket.recv_from(&mut buffer).await {
                            Ok(received) => received,
                            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => continue,
                            Err(_) => return,
                        };
                        // A binding request: 20 bytes of header, whose bytes 4 to 20 (magic cookie and transaction id) are echoed.
                        if len < 20 {
                            continue;
                        }
                        asked.fetch_add(1, Ordering::Relaxed);
                        let mut reply = vec![0x01, 0x01, 0x00, 0x0C];
                        reply.extend_from_slice(&buffer[4..20]);
                        // XOR-MAPPED-ADDRESS: IPv4, the port and the address xor-ed with the magic cookie.
                        reply.extend([0x00, 0x20, 0x00, 0x08, 0x00, 0x01]);
                        reply.extend((shown.port() ^ 0x2112).to_be_bytes());
                        reply.extend((u32::from(*shown.ip()) ^ 0x2112_A442).to_be_bytes());
                        let _ = socket.send_to(&reply, from).await;
                    }
                }
            });
            FakeStun { addr, asked, task }
        }

        fn asked(&self) -> usize {
            self.asked.load(Ordering::Relaxed)
        }
    }

    impl Drop for FakeStun {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stun_is_asked_when_the_nodes_on_the_internet_are_too_few_to_tell() {
        let host = SimHost::start(CONE);
        let mut client = SimClient::new(CONE);
        // One node inside a provider's network, one on the internet, one silent: counted as they come, two servers have told,
        // but only one of them on the internet.
        let (inside, outside) = (Ipv4Addr::new(127, 0, 0, 2), Ipv4Addr::new(127, 0, 0, 3));
        let nodes = nodes_claiming(move |node, _| match node.ip() {
            ip if ip == inside => Some("10.1.2.3:4000".parse().unwrap()),
            ip if ip == outside => Some("8.8.8.8:40123".parse().unwrap()),
            _ => None,
        });
        // STUN says another endpoint than the node does, so that its answer shows in the outcome: two servers that disagree.
        let stun = FakeStun::spawn(Ipv4Addr::new(127, 0, 0, 5), "9.9.9.9:50000".parse().unwrap());
        let (dht, dir) = (Arc::new(FakeDht::default()), TempDir::new());
        let params = params(&client.identity, host.fingerprint(), Some(SECRET), &dir);
        let mut env = world(&nodes, Some(dht.clone()));
        env.stun = Some(vec![stun.addr]);
        env.allow_local = false;

        let dialing = start_dial(&mut client, &host, params, Vec::new(), env);
        let error = within("the dial", dialing).await.unwrap().expect_err("two servers on the internet disagree");
        assert!(error.to_string().contains("symmetric NAT"), "{error:#}");
        assert_eq!(stun.asked(), 1);
        assert_eq!(dht.tries(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stun_is_left_alone_when_two_nodes_on_the_internet_agree() {
        let host = SimHost::start(CONE);
        let mut client = SimClient::new(CONE);
        let nodes = agreeing("8.8.8.8:40123".parse().unwrap());
        let stun = FakeStun::spawn(Ipv4Addr::new(127, 0, 0, 5), "9.9.9.9:50000".parse().unwrap());
        let (dht, dir) = (Arc::new(FakeDht::default()), TempDir::new());
        let params = params(&client.identity, host.fingerprint(), Some(SECRET), &dir);
        let mut env = world(&nodes, Some(dht.clone()));
        env.stun = Some(vec![stun.addr]);
        env.allow_local = false;
        env.timing.dht_wait = Duration::from_millis(500);

        let dialing = start_dial(&mut client, &host, params, Vec::new(), env);
        within("the dial", dialing).await.unwrap().expect_err("nobody punched");
        assert_eq!(stun.asked(), 0, "the nodes had told enough");
        assert_eq!(dht.tries(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_observation_that_takes_too_long_is_given_up() {
        let host = SimHost::start(CONE);
        let mut client = SimClient::new(CONE);
        let nodes = nodes_claiming(|_, _| None);
        let (dht, dir) = (Arc::new(FakeDht::default()), TempDir::new());
        let params = params(&client.identity, host.fingerprint(), Some(SECRET), &dir);
        let mut env = world(&nodes, Some(dht.clone()));
        // Silent nodes, waited for up to 2 s a phase, but only 300 ms allowed for the whole.
        env.timing.observe = Duration::from_secs(2);
        env.timing.observe_limit = Duration::from_millis(300);

        let started = tokio::time::Instant::now();
        let dialing = start_dial(&mut client, &host, params, Vec::new(), env);
        let error = within("the dial", dialing).await.unwrap().expect_err("nothing was observed in time");
        assert!(error.to_string().contains("did not end in 0.3 s"), "{error:#}");
        assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
        assert_eq!(dht.tries(), 0);
        // The blocking call ends by itself, and takes the socket with it.
        assert_released(client.addr).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn every_dial_asks_with_a_nonce_of_its_own() {
        let host = SimHost::start(CONE);
        let (dht, dir) = (Arc::new(FakeDht::default()), TempDir::new());
        for _ in 0..2 {
            let mut client = SimClient::new(CONE);
            let nodes = agreeing(client.nat.public_endpoint());
            let params = params(&client.identity, host.fingerprint(), Some(SECRET), &dir);
            let mut env = world(&nodes, Some(dht.clone()));
            env.timing.dht_wait = Duration::from_millis(300);
            let dialing = start_dial(&mut client, &host, params, Vec::new(), env);
            within("the dial", dialing).await.unwrap().expect_err("nobody punched");
        }
        let nonces: Vec<u64> = locked(&dht.stored)
            .iter()
            .map(|stored| {
                punch_item::open(&stored.blob, &Secret::new(SECRET), stored.seq, SystemTime::now()).unwrap().nonce
            })
            .collect();
        assert_eq!(nonces.len(), 2);
        assert_ne!(nonces[0], nonces[1]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_host_behind_an_open_nat_is_reached_without_anyone_answering_the_request() {
        let mut host = SimHost::start(OPEN);
        let mut client = SimClient::new(CONE);
        let nodes = agreeing(client.nat.public_endpoint());
        let (dht, dir) = (Arc::new(FakeDht::default()), TempDir::new());
        let params = params(&client.identity, host.fingerprint(), Some(SECRET), &dir);

        let dialing = start_dial(&mut client, &host, params, Vec::new(), world(&nodes, Some(dht)));
        let (_endpoint, connection) = within("the dial", dialing).await.unwrap().unwrap();
        assert_works(&mut host, &client, &connection).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_peer_that_is_not_the_host_ends_the_dial_at_once() {
        let host = SimHost::start(OPEN);
        let mut client = SimClient::new(CONE);
        let nodes = agreeing(client.nat.public_endpoint());
        let (dht, dir) = (Arc::new(FakeDht::default()), TempDir::new());
        // The device pinned another certificate than the one that answers (the record was stale and the endpoint is somebody else's).
        let params = params(&client.identity, Fingerprint([3; 32]), Some(SECRET), &dir);

        let started = tokio::time::Instant::now();
        let dialing = start_dial(&mut client, &host, params, Vec::new(), world(&nodes, Some(dht)));
        let error = within("the dial", dialing).await.unwrap().expect_err("the certificate is not the pinned one");
        assert!(format!("{error:#}").contains("is not the host"), "{error:#}");
        assert!(started.elapsed() < Duration::from_secs(4), "it kept dialing: {:?}", started.elapsed());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_endpoint_that_is_not_on_the_internet_is_not_told_to_the_host() {
        let host = SimHost::start(CONE);
        let mut client = SimClient::new(CONE);
        // A private address: the inner side of a second NAT.
        let nodes = agreeing("10.1.2.3:4000".parse().unwrap());
        let (dht, dir) = (Arc::new(FakeDht::default()), TempDir::new());
        let params = params(&client.identity, host.fingerprint(), Some(SECRET), &dir);
        let mut env = world(&nodes, Some(dht.clone()));
        env.allow_local = false;

        let dialing = start_dial(&mut client, &host, params, Vec::new(), env);
        let error = within("the dial", dialing).await.unwrap().expect_err("a private endpoint is no use to the host");
        assert!(error.to_string().contains("another NAT is in the way"), "{error:#}");
        assert_eq!(dht.tries(), 0);
        assert_eq!(host.nat.stats(), NatStats::default());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_vote_from_inside_a_providers_network_does_not_make_a_cone_nat_look_symmetric() {
        let host = SimHost::start(CONE);
        let mut client = SimClient::new(CONE);
        // One node says a private address (a node of the provider's own), the other two the NAT's real one.
        let inside = Ipv4Addr::new(127, 0, 0, 2);
        let nodes = nodes_claiming(move |node, _| {
            let shown: SocketAddr =
                if node.ip() == inside { "10.1.2.3:4000" } else { "8.8.8.8:40123" }.parse().unwrap();
            Some(shown)
        });
        let (dht, dir) = (Arc::new(FakeDht::default()), TempDir::new());
        let params = params(&client.identity, host.fingerprint(), Some(SECRET), &dir);
        let mut env = world(&nodes, Some(dht.clone()));
        env.allow_local = false;
        env.timing.dht_wait = Duration::from_millis(600);

        // Counted as they stand the three disagree, which is what a symmetric NAT does and the dial would give up.
        let dialing = start_dial(&mut client, &host, params, Vec::new(), env);
        let error = within("the dial", dialing).await.unwrap().expect_err("nobody punched");
        assert!(!error.to_string().contains("symmetric"), "{error:#}");
        let stored = dht.first().expect("the request was published");
        let item = punch_item::open(&stored.blob, &Secret::new(SECRET), stored.seq, SystemTime::now()).unwrap();
        assert_eq!(item.endpoint, "8.8.8.8:40123", "and the endpoint is the one the nodes on the internet agree on");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_endpoint_on_the_internet_is_what_the_host_is_told() {
        let host = SimHost::start(CONE);
        let mut client = SimClient::new(CONE);
        let nodes = agreeing("8.8.8.8:40123".parse().unwrap());
        let (dht, dir) = (Arc::new(FakeDht::default()), TempDir::new());
        let params = params(&client.identity, host.fingerprint(), Some(SECRET), &dir);
        let mut env = world(&nodes, Some(dht.clone()));
        env.allow_local = false;
        env.timing.dht_wait = Duration::from_millis(600);

        let dialing = start_dial(&mut client, &host, params, Vec::new(), env);
        within("the dial", dialing).await.unwrap().expect_err("nobody punched");
        let stored = dht.first().expect("the request was published");
        let item = punch_item::open(&stored.blob, &Secret::new(SECRET), stored.seq, SystemTime::now()).unwrap();
        assert_eq!(item.endpoint, "8.8.8.8:40123");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn when_no_node_says_what_the_nat_shows_there_is_nothing_to_tell_the_host() {
        let host = SimHost::start(CONE);
        let mut client = SimClient::new(CONE);
        let nodes = nodes_claiming(|_, _| None);
        let (dht, dir) = (Arc::new(FakeDht::default()), TempDir::new());
        let params = params(&client.identity, host.fingerprint(), Some(SECRET), &dir);
        let mut env = world(&nodes, Some(dht.clone()));
        env.timing.observe = Duration::from_millis(400);

        let dialing = start_dial(&mut client, &host, params, Vec::new(), env);
        let error = within("the dial", dialing).await.unwrap().expect_err("nothing was observed");
        assert!(format!("{error:#}").contains("could not tell which endpoint"), "{error:#}");
        assert_eq!(dht.tries(), 0);
        assert_eq!(host.nat.stats(), NatStats::default());
        assert_released(client.addr).await;
    }

    #[tokio::test]
    async fn the_hook_refuses_what_it_can_never_do_before_it_touches_the_network() {
        let dir = TempDir::new();
        let client = Identity::generate().unwrap();
        let host = Fingerprint([4; 32]);
        let endpoint: SocketAddr = "203.0.113.9:7420".parse().unwrap();
        let relay = RelayRef { addr: "203.0.113.10:7420".parse().unwrap(), fingerprint: Fingerprint([5; 32]) };

        // Not IPv4.
        let with_secret = params(&client, host, Some(SECRET), &dir);
        let v6: SocketAddr = "[2001:db8::1]:7420".parse().unwrap();
        let error = dial_punch(&with_secret, v6, &[relay]).await.expect_err("IPv6 is not punched");
        assert!(error.to_string().contains("IPv4 only"), "{error:#}");
        // No relay and no secret: nobody can be asked.
        let without_secret = params(&client, host, None, &dir);
        let error = dial_punch(&without_secret, endpoint, &[]).await.expect_err("nobody to ask");
        assert!(error.to_string().contains("no relay is known"), "{error:#}");
        let mut no_reach = params(&client, host, Some(SECRET), &dir);
        no_reach.reach = None;
        assert!(dial_punch(&no_reach, endpoint, &[]).await.is_err());
    }

    #[test]
    fn the_waits_are_the_ones_the_plan_and_the_hosts_polling_call_for() {
        assert_eq!(RELAY_WAIT, Duration::from_secs(10));
        assert_eq!(
            DHT_WAIT,
            Duration::from_secs(60),
            "the host polls every 45 s, a look takes 3, a publish a few more"
        );
        assert_eq!(Timing::DEFAULT.relay_wait, RELAY_WAIT);
        assert_eq!(Timing::DEFAULT.dht_wait, DHT_WAIT);
        assert_eq!(Timing::DEFAULT.redial, Duration::from_secs(1));
    }

    #[test]
    fn nonces_are_random() {
        let nonces: std::collections::HashSet<u64> = (0..200).map(|_| random_nonce().unwrap()).collect();
        assert_eq!(nonces.len(), 200);
    }
}
