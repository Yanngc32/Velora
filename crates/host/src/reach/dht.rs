//! The host's record in the BitTorrent Mainline DHT (ticket E3, with `secrets.rs`); the plumbing it plugs into is
//! `reach/mod.rs`, which E3 does not edit.
//!
//! While the DHT switch is on, [`run`] keeps one DHT node (`velora_dht::node`, with its routing table saved in the
//! state directory) and publishes, under the host's own Ed25519 key (`dht_key.bin`, made the first time), a record
//! that only the paired devices can read: the host's fingerprint, its addresses, the kind of NAT in front of it, the
//! relay it is registered with and its MAC (`velora_dht::record`), sealed for every device that has been given a
//! secret (`velora_dht::seal`, `secrets.rs`). A client finds it by the key, which it learns at pairing or in
//! `HostMsg::Reach`.
//!
//! - **When.** The first time once the state has stopped changing for a few seconds (a start brings the addresses,
//!   the mapping, the NAT type and the relay one after the other); again whenever what the record holds changes
//!   (after the same wait, so a burst is one record) or the devices that can read it do; never closer than 15
//!   seconds, however much changes (a relay link that flaps must not be a stream of puts, each about 600
//!   datagrams); and in any case every 30 minutes, because the nodes forget a record after a couple of hours.
//!   Nothing is sent for a change the record does not show: `ReachState` also holds who is connected and where the
//!   last device came from, and its signal fires for those too. A failure is tried again after 30 seconds, then
//!   1, 2, 4 minutes, up to 10: never in a tight loop. The monotonic clock may stand still while the machine
//!   sleeps, so every look compares it with the wall clock, and two minutes more of the second than of the first
//!   mean that the record may be gone from the DHT: it is published again as for a start.
//! - **What it holds.** The addresses are `ReachState::record_addresses()` (LAN, VPN, public, IPv6, and the
//!   endpoint a cone NAT shows, which is how a client learns where to punch to), cut to the few of each kind that
//!   matter; the relays are a list of their own with their fingerprints (a relay address is no use to a client
//!   without one). The cut keeps every record, with the longest strings there are, small enough for
//!   [`device_capacity`] devices.
//! - **Who can read it.** Each device with a secret, up to [`device_capacity`] paired devices; with more, everyone
//!   has the same secret and the record has one wrap (`secrets.rs` has the rules, and `HostMsg::Reach` carries the
//!   secret a device must hold now). The mode depends on the number of paired devices and nothing else, so it
//!   cannot flip as the addresses change. A device removed in the launcher is left out of the next record, one
//!   removed with `velora-host revoke` within a minute.
//! - **The punch requests.** While the node is up, the poller of `poll.rs` looks the clients' punch items up
//!   through it ([`NodeSource`]); when this task ends the source is taken away again, and the host asks nothing more
//!   of the DHT. A put that was under way is not cancelled (the node's operations run to their end, 25 s at most).
//!
//! Having no network is not an error: the node builds itself again on the next call, and the publisher waits.

use std::{
    net::SocketAddr,
    sync::{Arc, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Result};
use tokio::time::Instant;
use velora_dht::{
    keys::{self, Keys},
    node::{Config, Error as NodeError, Mode, Node, Published, ResolveOptions},
    punch_item,
    record::{self, Kind, Nat, Record, Relay},
    seal::{self, SealError, Secret},
};
use velora_nat::observe::NatType;
use velora_protocol::{tls::Fingerprint, wire::AddressKind};

use super::{
    poll::{self, BoxFuture, Found, LookupError, PunchSource},
    secrets::{self, Recipients},
    DeviceKeys, ReachContext, ReachState,
};

/// Where the node keeps its routing table (and the `seq` numbers it used), in the state directory.
const CACHE_FILE: &str = "dht_cache.txt";

/// Most addresses of each kind the record lists, and relays with their addresses. A host has one LAN address it
/// advertises, a VPN mesh gives it one or two, one public endpoint (mapped or observed), and a couple of global IPv6
/// ones; one relay is the way in for a host nobody can reach directly. More than this is not worth the bytes: each
/// address takes up to 49 and each device 48 of the 996 a DHT value holds.
const LIST_LAN: usize = 1;
const LIST_VPN: usize = 2;
const LIST_PUBLIC: usize = 1;
const LIST_V6: usize = 2;
const LIST_RELAYS: usize = 1;
const LIST_RELAY_ADDRESSES: usize = 1;

/// The longest text of a socket address: `[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535`.
const MAX_ADDRESS_TEXT: usize = 47;

/// How often things happen. The product's values are the `Default`; the tests of the loop use others.
#[derive(Debug, Clone, Copy)]
struct Timing {
    /// A record is published again after this long without one, changed or not.
    refresh: Duration,
    /// A change waits this long for the next one before it is published...
    quiet: Duration,
    /// ...but never longer than this since the first of them.
    patience: Duration,
    /// Two publishes are never closer than this, whatever changes.
    gap: Duration,
    /// After a failure the next try waits this long, twice as long after each further one...
    retry: Duration,
    /// ...up to this.
    retry_max: Duration,
    /// The state of the devices is looked at again at least this often (a device removed with `velora-host revoke`
    /// is noticed this way).
    recheck: Duration,
    /// The wall clock, in Unix seconds: the time written in a record, and how a sleep of the machine is noticed.
    wall: fn() -> u64,
}

impl Default for Timing {
    fn default() -> Self {
        Timing {
            refresh: Duration::from_secs(30 * 60),
            quiet: Duration::from_secs(3),
            patience: Duration::from_secs(20),
            gap: Duration::from_secs(15),
            retry: Duration::from_secs(30),
            retry_max: Duration::from_secs(10 * 60),
            recheck: Duration::from_secs(60),
            wall: unix_now,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The record
// ---------------------------------------------------------------------------------------------

/// What the record says, without the time: two records with the same body are the same record.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Body {
    addresses: Vec<(Kind, String)>,
    nat: Nat,
    relays: Vec<Relay>,
    mac: Option<[u8; 6]>,
}

/// A text a socket address can have: what the other tickets put in the state, and nothing else, so that a record is as
/// small as [`device_capacity`] says.
fn is_address(text: &str) -> bool {
    text.len() <= MAX_ADDRESS_TEXT && text.parse::<SocketAddr>().is_ok()
}

impl Body {
    fn from_state(state: &ReachState) -> Body {
        let mut listed = [0usize; 4];
        let addresses = state
            .record_addresses()
            .into_iter()
            .filter_map(|(kind, address)| {
                let (kind, limit) = match kind {
                    AddressKind::Lan => (Kind::Lan, LIST_LAN),
                    AddressKind::Vpn => (Kind::Vpn, LIST_VPN),
                    AddressKind::Public => (Kind::Public, LIST_PUBLIC),
                    AddressKind::V6 => (Kind::V6, LIST_V6),
                    // The relays have a list of their own, with the fingerprints a client needs; a kind this
                    // version cannot place is of no use to a client.
                    AddressKind::Relay(_) | AddressKind::Other(_) => return None,
                };
                let count = listed.get_mut(usize::from(u8::from(kind)))?;
                (*count < limit && is_address(&address)).then(|| {
                    *count += 1;
                    (kind, address)
                })
            })
            .collect();
        let relays = state
            .relays
            .iter()
            .filter_map(|relay| {
                let addresses: Vec<String> = relay
                    .addresses
                    .iter()
                    .filter(|address| is_address(address))
                    .take(LIST_RELAY_ADDRESSES)
                    .cloned()
                    .collect();
                (!addresses.is_empty()).then_some(Relay { fingerprint: relay.fingerprint.0, addresses })
            })
            .take(LIST_RELAYS)
            .collect();
        let nat = match state.nat {
            Some(NatType::Open) => Nat::Open,
            Some(NatType::EndpointIndependent) => Nat::Cone,
            Some(NatType::Dependent) => Nat::Symmetric,
            Some(NatType::Unknown) | None => Nat::Unknown,
        };
        Body { addresses, nat, relays, mac: state.mac }
    }

    fn record(&self, fingerprint: &Fingerprint, ts: u64) -> Record {
        Record {
            fingerprint: fingerprint.0,
            addresses: self.addresses.clone(),
            nat: self.nat,
            relays: self.relays.clone(),
            mac: self.mac,
            ts,
        }
    }
}

/// The largest record [`Body::from_state`] can make: every list full of the longest addresses there are.
fn worst_case() -> Record {
    let longest = format!("[{}]:65535", ["ffff"; 8].join(":"));
    let mut addresses = Vec::new();
    for (kind, count) in
        [(Kind::Lan, LIST_LAN), (Kind::Vpn, LIST_VPN), (Kind::Public, LIST_PUBLIC), (Kind::V6, LIST_V6)]
    {
        addresses.extend((0..count).map(|_| (kind, longest.clone())));
    }
    Record {
        fingerprint: [0xff; 32],
        addresses,
        nat: Nat::Other(0xff),
        relays: (0..LIST_RELAYS)
            .map(|_| Relay { fingerprint: [0xff; 32], addresses: vec![longest.clone(); LIST_RELAY_ADDRESSES] })
            .collect(),
        mac: Some([0xff; 6]),
        ts: u64::MAX,
    }
}

/// How many paired devices a sealed record has room for beside the largest record the host makes. Past this every
/// device gets the same secret instead (`secrets.rs`).
pub(super) fn device_capacity() -> usize {
    static CAPACITY: OnceLock<usize> = OnceLock::new();
    *CAPACITY.get_or_init(|| seal::max_devices(worst_case().encode().map_or(seal::MAX_SEALED_LEN, |bytes| bytes.len())))
}

/// Everything that makes one published record differ from the last, which is what the publisher compares.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Content {
    body: Body,
    recipients: Recipients,
}

/// What would be published now, or nothing when no device has been given a secret or the host has nothing to say (no
/// address and no relay: the record in the DHT, which says more, stays).
fn content(ctx: &ReachContext) -> Result<Option<Content>> {
    // The state is read and let go of before the secrets are asked for: they may take a moment.
    let body = Body::from_state(&ctx.reach.read());
    Ok(match secrets::recipients(ctx)? {
        _ if body.addresses.is_empty() && body.relays.is_empty() => None,
        Recipients::Nobody => None,
        recipients => Some(Content { body, recipients }),
    })
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs())
}

// ---------------------------------------------------------------------------------------------
// The DHT, as far as the publisher is concerned
// ---------------------------------------------------------------------------------------------

/// The sealing of one record, given the `seq` it is for. It may be asked again with a higher one.
type Seal<'a> = dyn FnMut(i64) -> Result<Vec<u8>, SealError> + Send + 'a;

/// What the publisher needs of the DHT: `Node` is the real one, and the tests have a fake that remembers what it got.
trait Publisher: Send + Sync + 'static {
    /// Puts the record `seal` makes under the host's key and `record::SALT`.
    fn publish<'a>(&'a self, keys: &'a Keys, seal: &'a mut Seal<'a>) -> BoxFuture<'a, Result<Published, NodeError>>;
}

impl Publisher for Node {
    fn publish<'a>(&'a self, keys: &'a Keys, seal: &'a mut Seal<'a>) -> BoxFuture<'a, Result<Published, NodeError>> {
        Box::pin(self.publish_with(keys, record::SALT, seal))
    }
}

/// The poller's way into the DHT: the node, asked for the punch items of the paired clients.
struct NodeSource(Node);

impl PunchSource for NodeSource {
    fn resolve(
        &self,
        key: [u8; 32],
        newer_than: Option<i64>,
        deadline: Duration,
    ) -> BoxFuture<'_, Result<Option<Found>, LookupError>> {
        Box::pin(async move {
            let options = ResolveOptions { newer_than, deadline: Some(deadline) };
            match self.0.resolve_with(&key, punch_item::SALT, &options).await {
                Ok(found) => Ok(found.map(|found| Found { value: found.value, seq: found.seq })),
                Err(e) => Err(lookup_error(e)),
            }
        })
    }
}

fn lookup_error(e: NodeError) -> LookupError {
    match e {
        NodeError::NoNetwork => LookupError::NoNetwork,
        other => LookupError::Failed(other.to_string()),
    }
}

// ---------------------------------------------------------------------------------------------
// When to publish
// ---------------------------------------------------------------------------------------------

/// Decides when the next publish is due. No I/O and no clock of its own: the loop tells it what it sees and when, so
/// that all of the timing can be tested with made-up instants.
struct Planner {
    timing: Timing,
    /// What the state holds now (`None`: nobody to publish for), and when that last changed.
    seen: Option<Content>,
    changed_at: Instant,
    /// Since when what is seen has differed from what was published, while it does.
    waiting_since: Option<Instant>,
    /// What was published last, and when that ended.
    published: Option<(Content, Instant)>,
    /// When the last attempt, good or bad, ended.
    last_end: Option<Instant>,
    /// Attempts that failed since the last one that worked.
    failures: u32,
}

impl Planner {
    fn new(timing: Timing, now: Instant) -> Planner {
        Planner {
            timing,
            seen: None,
            changed_at: now,
            waiting_since: None,
            published: None,
            last_end: None,
            failures: 0,
        }
    }

    /// What the state holds at `now`.
    fn observe(&mut self, now: Instant, current: Option<Content>) {
        if self.seen != current {
            self.seen = current;
            self.changed_at = now;
        }
        let differs = match (&self.seen, &self.published) {
            (None, _) => false,
            (Some(_), None) => true,
            (Some(seen), Some((published, _))) => seen != published,
        };
        if !differs {
            self.waiting_since = None;
        } else if self.waiting_since.is_none() {
            self.waiting_since = Some(now);
        }
    }

    /// What is to be published, if there is anything.
    fn content(&self) -> Option<&Content> {
        self.seen.as_ref()
    }

    /// When the next publish is due, or never (nobody to publish for).
    fn due(&self) -> Option<Instant> {
        let seen = self.seen.as_ref()?;
        let differs = self.published.as_ref().is_none_or(|(published, _)| published != seen);
        let mut at: Option<Instant> = None;
        if differs {
            let quiet = self.changed_at + self.timing.quiet;
            let limit = self.waiting_since.map_or(quiet, |since| since + self.timing.patience);
            at = Some(quiet.min(limit));
        }
        if let Some((_, ended)) = &self.published {
            let refresh = *ended + self.timing.refresh;
            at = Some(at.map_or(refresh, |at| at.min(refresh)));
        }
        let mut at = at?;
        if let Some(end) = self.last_end {
            at = at.max(end + self.timing.gap);
            if self.failures > 0 {
                at = at.max(end + self.backoff());
            }
        }
        Some(at)
    }

    /// `content` was published and the put ended at `now`.
    fn succeeded(&mut self, now: Instant, content: Content) {
        self.published = Some((content, now));
        self.last_end = Some(now);
        self.failures = 0;
        self.waiting_since = None;
    }

    /// An attempt ended at `now` with nothing published.
    fn failed(&mut self, now: Instant) {
        self.failures = self.failures.saturating_add(1);
        self.last_end = Some(now);
    }

    /// The machine slept: what was published may be gone from the DHT, and what was known of the network is out of
    /// date, so the next publish is due as for a start (when the state has settled).
    fn slept(&mut self, now: Instant) {
        self.published = None;
        self.failures = 0;
        self.changed_at = now;
        self.waiting_since = None;
    }

    /// How long the next try waits after the failures so far.
    fn backoff(&self) -> Duration {
        let doublings = self.failures.saturating_sub(1).min(16);
        self.timing.retry.saturating_mul(1 << doublings).min(self.timing.retry_max)
    }
}

/// How much more time the wall clock may count between two looks than the monotonic one before the machine is taken
/// to have slept: clocks differ by a second or so, and a step of the wall clock of a minute is not worth a put.
const SLEPT: Duration = Duration::from_secs(120);

/// Whether the machine slept between two looks, which the monotonic clock (`monotonic` long) did not count and the
/// wall clock (`wall` seconds) did.
fn slept(monotonic: Duration, wall: u64) -> bool {
    Duration::from_secs(wall) > monotonic + SLEPT
}

// ---------------------------------------------------------------------------------------------
// The task
// ---------------------------------------------------------------------------------------------

/// The publishing task. Started when the DHT switch is on (independent of standalone reach); it ends when `ctx.stop`
/// fires.
///
/// It loads or creates the Ed25519 key in `ctx.state_dir` (`velora_dht::keys`), records its public key in
/// `state.dht_key` (that is what puts `key=` and `secret=` in pairing links and fills `HostMsg::Reach`; cleared
/// when the task ends), opens the DHT node, gives it to the poller of punch requests, and publishes the sealed
/// record for every paired device that has a secret (`secrets.rs`): see the module docs for when. An error is
/// returned only when the key file is not a key; a file system that fails for the moment and everything the network
/// does are waited out.
pub async fn run(ctx: ReachContext) -> Result<()> {
    let config = node_config(&ctx);
    run_with(ctx, config, Timing::default()).await
}

/// How the host's node is set up in production: the public DHT, on every interface, with its table kept beside the key.
fn public_config(ctx: &ReachContext) -> Config {
    let mut config = Config::new(Mode::Host);
    config.cache_path = Some(ctx.state_dir.path(CACHE_FILE));
    config
}

/// What [`run`] opens. In a test build it is [`offline`]: the unit tests of the host switch the DHT on through the
/// runtime, which starts this task, and a unit test must never reach the public DHT.
fn node_config(ctx: &ReachContext) -> Config {
    let config = public_config(ctx);
    #[cfg(test)]
    let config = offline(config);
    config
}

/// `config` with a node whose only way into the DHT is an address nobody answers at, and that listens on the loopback
/// only: nothing it sends leaves the machine, and nothing from outside reaches it.
#[cfg(test)]
fn offline(mut config: Config) -> Config {
    let nobody = std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(192, 0, 2, 1), 6881);
    config.default_nodes = velora_dht::node::DefaultNodes::fixed(vec![nobody]);
    config.bind_address = Some(std::net::Ipv4Addr::LOCALHOST);
    config
}

/// What [`run`] has set up and must take down again, however the task ends (aborted included). It clears the key and
/// the source whoever set them: the runtime never runs two of a task at once, so a run's end cannot be undoing the next
/// run's start.
struct Registered<'a>(&'a ReachContext);

impl Drop for Registered<'_> {
    fn drop(&mut self) {
        poll::set_source(self.0, None);
        self.0.reach.update(|state| state.dht_key = None);
    }
}

/// The host's key, made the first time. A file system that fails for the moment (a sharing violation, a rename that an
/// antivirus holds up) is waited out; a file that is there and is not a key is an error for the user to look at,
/// since replacing it would orphan every pairing. `None` when told to stop meanwhile.
async fn load_keys(ctx: &ReachContext, timing: Timing) -> Result<Option<Keys>> {
    let (mut wait, mut said) = (timing.retry, false);
    loop {
        let path = ctx.state_dir.path(keys::FILE_NAME);
        let loaded = tokio::task::spawn_blocking(move || Keys::load_or_create(&path)).await;
        match loaded.context("reading the DHT key")? {
            Ok(keys) => return Ok(Some(keys)),
            Err(e) if e.chain().any(|cause| cause.is::<std::io::Error>()) => {
                if !said {
                    tracing::warn!("the host's DHT key cannot be read or made yet, trying again: {e:#}");
                    said = true;
                }
                if ctx.stop.sleep(wait).await {
                    return Ok(None);
                }
                wait = (wait * 2).min(timing.retry_max);
            }
            Err(e) => return Err(e.context("the host's DHT key")),
        }
    }
}

async fn run_with(ctx: ReachContext, config: Config, timing: Timing) -> Result<()> {
    let Some(keys) = load_keys(&ctx, timing).await? else { return Ok(()) };
    ctx.reach.update(|state| state.dht_key = Some(keys.public_key()));
    let _registered = Registered(&ctx);

    let node = tokio::select! {
        node = Node::open_with(config) => node,
        () = ctx.stop.stopped() => return Ok(()),
    };
    poll::set_source(&ctx, Some(Arc::new(NodeSource(node.clone()))));
    tracing::debug!("publishing the host's record in the DHT");
    publish_loop(&ctx, &keys, &node, timing).await
}

/// Publishes whenever [`Planner`] says so, until `ctx.stop` fires.
async fn publish_loop(ctx: &ReachContext, keys: &Keys, publisher: &dyn Publisher, timing: Timing) -> Result<()> {
    let mut states = ctx.reach.subscribe();
    let mut devices = secrets::changes(ctx);
    let mut planner = Planner::new(timing, Instant::now());
    let (mut looked_at, mut wall_then) = (Instant::now(), (timing.wall)());
    // Said once per streak, so a laptop with no network does not fill the log.
    let (mut failing, mut unreadable) = (false, false);
    loop {
        if ctx.stop.is_stopped() {
            return Ok(());
        }
        let now = Instant::now();
        // The monotonic clock may stand still while the machine sleeps, the wall clock does not: what was published
        // has been in the DHT for longer than the planner knows.
        let wall = (timing.wall)();
        if slept(now.saturating_duration_since(looked_at), wall.saturating_sub(wall_then)) {
            tracing::debug!("the machine slept: publishing the host's record again");
            planner.slept(now);
        }
        (looked_at, wall_then) = (now, wall);
        // What cannot be read is not published from memory: a device that was removed meanwhile would be in it.
        let current = match content(ctx) {
            Ok(current) => {
                unreadable = false;
                current
            }
            Err(e) => {
                if !unreadable {
                    tracing::warn!("the DHT record cannot be made now: {e:#}");
                }
                unreadable = true;
                None
            }
        };
        planner.observe(now, current);

        let due = planner.due();
        if due.is_some_and(|at| at <= now) {
            let Some(content) = planner.content().cloned() else { continue };
            let record = content.body.record(&ctx.fingerprint, (timing.wall)());
            let mut seal = |seq: i64| -> Result<Vec<u8>, SealError> {
                let sealed = match &content.recipients {
                    Recipients::Devices(secrets) => {
                        let secrets: Vec<Secret> = secrets.iter().map(|bytes| Secret::new(*bytes)).collect();
                        seal::seal(&record, record::SALT, seq, &secrets, None)?
                    }
                    Recipients::Shared(secret) => {
                        seal::seal(&record, record::SALT, seq, &[], Some(&Secret::new(*secret)))?
                    }
                    Recipients::Nobody => return Err(SealError::NoRecipients),
                };
                Ok(sealed.blob)
            };
            let outcome = tokio::select! {
                outcome = publisher.publish(keys, &mut seal) => outcome,
                () = ctx.stop.stopped() => return Ok(()),
            };
            let ended = Instant::now();
            match outcome {
                Ok(published) => {
                    let news = planner.published.as_ref().is_none_or(|(before, _)| *before != content);
                    let readers = match &content.recipients {
                        Recipients::Devices(secrets) => format!("{} devices", secrets.len()),
                        _ => "all devices (they share a secret)".to_string(),
                    };
                    if news || failing {
                        tracing::info!(
                            "published the host's record in the DHT for {readers} (seq {}, kept by {} nodes)",
                            published.seq,
                            published.stored_at
                        );
                    } else {
                        tracing::debug!("published the host's record in the DHT again (seq {})", published.seq);
                    }
                    failing = false;
                    planner.succeeded(ended, content);
                }
                Err(e) => {
                    planner.failed(ended);
                    let retry = planner.backoff();
                    if failing {
                        tracing::debug!("the host's record is still not in the DHT: {e}");
                    } else {
                        tracing::warn!(
                            "could not publish the host's record in the DHT ({e}); trying again in {retry:?}"
                        );
                    }
                    failing = true;
                }
            }
            continue;
        }

        let wait = due.map_or(timing.recheck, |at| at.saturating_duration_since(now).min(timing.recheck));
        tokio::select! {
            () = ctx.stop.stopped() => return Ok(()),
            () = tokio::time::sleep(wait) => {}
            changed = states.changed() => if changed.is_err() { return Ok(()) },
            changed = devices.changed() => if changed.is_err() { return Ok(()) },
        }
    }
}

/// What `HostMsg::Reach` carries for the device `fingerprint`: the host's DHT public key and the secret that opens the
/// record for that device. Called each time a client that asked for `Reach` connects, from the async task of the
/// connection: a few small files are read, and one written the first time a device is given a secret.
///
/// `None` while there is no key (the DHT switch is off, or the key is not loaded yet): the message then carries zeros,
/// which readers treat as "no record". For a paired device that has no secret yet (it paired before this version, or
/// while the host had no key) it makes one, stores it, and returns it. For a fingerprint that is not paired it returns
/// `None`. While more devices are paired than a record has room for the secret is the one they all share.
pub fn reach_message(ctx: &ReachContext, fingerprint: &Fingerprint) -> Option<DeviceKeys> {
    let key = ctx.reach.read().dht_key?;
    match secrets::secret_for(ctx, fingerprint) {
        Ok(secret) => secret.map(|secret| DeviceKeys { key, secret }),
        Err(e) => {
            tracing::warn!("no DHT secret for the device {fingerprint}: {e:#}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        fs,
        net::{Ipv4Addr, SocketAddrV4},
        sync::Mutex,
    };

    use tokio::{sync::watch, task::JoinHandle};
    use velora_dht::{node::DefaultNodes, seal::OpenError};
    use velora_protocol::{
        control::MappingStatus,
        identity::{AuthorizedClient, StateDir},
        wire::HostMsg,
    };

    use super::*;
    use crate::reach::{
        self, lock, punch,
        testing::{self, Scratch},
        RelayEntry, Stop,
    };

    fn fp(n: u8) -> Fingerprint {
        Fingerprint([n; 32])
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    /// The paired list becomes exactly these devices.
    fn pair(ctx: &ReachContext, devices: &[Fingerprint]) {
        let clients: Vec<AuthorizedClient> = devices
            .iter()
            .map(|device| AuthorizedClient {
                name: format!("device {}", device.short()),
                fingerprint: device.to_base64(),
                added_unix: 0,
                trust_files: false,
            })
            .collect();
        ctx.state_dir.save(StateDir::AUTHORIZED_CLIENTS, &clients).unwrap();
    }

    /// A host with an address of each kind, a NAT that shows one endpoint, a relay and a MAC: all in the ranges set
    /// aside for documentation (and the one of VPN meshes).
    fn busy(state: &mut ReachState) {
        state.set_addresses(AddressKind::Lan, vec!["192.0.2.10:7420".into()]);
        state.set_addresses(AddressKind::Vpn, vec!["100.64.0.5:7420".into(), "[fd7a:115c:a1e0::5]:7420".into()]);
        state.set_addresses(AddressKind::Public, vec!["198.51.100.7:51000".into()]);
        state.set_addresses(AddressKind::V6, vec!["[2001:db8::7]:7420".into()]);
        state.set_relays(vec![RelayEntry {
            fingerprint: fp(77),
            name: "a relay".into(),
            addresses: vec!["203.0.113.9:7420".into()],
        }]);
        state.nat = Some(NatType::EndpointIndependent);
        state.mac = Some([2, 0, 0, 0, 0, 1]);
    }

    fn busy_state() -> ReachState {
        let mut state = ReachState::default();
        busy(&mut state);
        state
    }

    // === what the record says ===

    #[test]
    fn the_record_lists_each_kind_in_order_and_keeps_the_relay_apart() {
        let body = Body::from_state(&busy_state());
        assert_eq!(
            body.addresses,
            vec![
                (Kind::Lan, "192.0.2.10:7420".to_string()),
                (Kind::Vpn, "100.64.0.5:7420".to_string()),
                (Kind::Vpn, "[fd7a:115c:a1e0::5]:7420".to_string()),
                (Kind::Public, "198.51.100.7:51000".to_string()),
                (Kind::V6, "[2001:db8::7]:7420".to_string()),
            ]
        );
        assert_eq!(body.relays, vec![Relay { fingerprint: [77; 32], addresses: vec!["203.0.113.9:7420".to_string()] }]);
        assert_eq!((body.nat, body.mac), (Nat::Cone, Some([2, 0, 0, 0, 0, 1])));
        let record = body.record(&fp(5), 1234);
        assert_eq!((record.fingerprint, record.ts), ([5; 32], 1234));
    }

    #[test]
    fn the_endpoint_a_cone_nat_shows_is_listed_as_public_and_the_one_of_a_symmetric_nat_is_not() {
        let mut state = ReachState::default();
        state.set_addresses(AddressKind::Lan, vec!["192.0.2.10:7420".into()]);
        state.observed = Some("198.51.100.20:40000".parse().unwrap());
        state.nat = Some(NatType::EndpointIndependent);
        let body = Body::from_state(&state);
        assert_eq!(body.addresses.last(), Some(&(Kind::Public, "198.51.100.20:40000".to_string())));

        state.nat = Some(NatType::Dependent);
        let body = Body::from_state(&state);
        assert!(body.addresses.iter().all(|(kind, _)| *kind != Kind::Public), "{:?}", body.addresses);
        assert_eq!(body.nat, Nat::Symmetric);
    }

    #[test]
    fn the_nat_types_of_the_probe_are_the_ones_of_the_record() {
        for (seen, told) in [
            (Some(NatType::Open), Nat::Open),
            (Some(NatType::EndpointIndependent), Nat::Cone),
            (Some(NatType::Dependent), Nat::Symmetric),
            (Some(NatType::Unknown), Nat::Unknown),
            (None, Nat::Unknown),
        ] {
            let state = ReachState { nat: seen, ..ReachState::default() };
            assert_eq!(Body::from_state(&state).nat, told, "{seen:?}");
        }
    }

    #[test]
    fn a_few_of_each_kind_and_only_real_addresses_are_listed() {
        let mut state = ReachState::default();
        state.set_addresses(AddressKind::Lan, vec!["192.0.2.1:1".into(), "192.0.2.2:2".into()]);
        state.set_addresses(
            AddressKind::Vpn,
            vec!["100.64.0.1:1".into(), "not an address".into(), "100.64.0.2:2".into(), "100.64.0.3:3".into()],
        );
        state.set_addresses(AddressKind::Public, vec!["x".repeat(100)]);
        state.set_addresses(AddressKind::V6, (1..=4).map(|n| format!("[2001:db8::{n}]:1")).collect());
        state.set_relays(vec![
            RelayEntry {
                fingerprint: fp(1),
                name: "first".into(),
                addresses: vec!["junk".into(), "203.0.113.1:1".into(), "203.0.113.2:2".into()],
            },
            RelayEntry { fingerprint: fp(2), name: "second".into(), addresses: vec!["203.0.113.3:3".into()] },
        ]);
        let body = Body::from_state(&state);
        let texts = |kind: Kind| -> Vec<&str> {
            body.addresses.iter().filter(|(of, _)| *of == kind).map(|(_, text)| text.as_str()).collect()
        };
        assert_eq!(texts(Kind::Lan), vec!["192.0.2.1:1"], "one");
        assert_eq!(
            texts(Kind::Vpn),
            vec!["100.64.0.1:1", "100.64.0.2:2"],
            "two of them, and what is not an address is not one"
        );
        assert_eq!(texts(Kind::Public), Vec::<&str>::new(), "a text no socket address has");
        assert_eq!(texts(Kind::V6), vec!["[2001:db8::1]:1", "[2001:db8::2]:1"]);
        assert_eq!(body.relays, vec![Relay { fingerprint: [1; 32], addresses: vec!["203.0.113.1:1".to_string()] }]);
        // The relay's addresses are not in the list of the host's own.
        assert!(body.addresses.iter().all(|(kind, _)| !matches!(kind, Kind::Relay)));
    }

    #[test]
    fn what_the_record_does_not_show_does_not_change_it() {
        let before = Body::from_state(&busy_state());
        let mut other = busy_state();
        other.clients.connected = 3;
        other.clients.last_connect = Some((fp(1), std::time::Instant::now()));
        other.last_reached = Some((AddressKind::Lan, "192.0.2.77:7420".into()));
        other.mapping = Some(MappingStatus::default());
        other.switches.standalone = true;
        other.dht_key = Some([1; 32]);
        assert_eq!(Body::from_state(&other), before);

        // What it does show does.
        let changed: [fn(&mut ReachState); 5] = [
            |state| state.set_addresses(AddressKind::Lan, vec!["192.0.2.11:7420".into()]),
            |state| state.set_addresses(AddressKind::Public, vec![]),
            |state| state.nat = Some(NatType::Dependent),
            |state| state.mac = None,
            |state| state.set_relays(vec![]),
        ];
        for change in changed {
            let mut moved = busy_state();
            change(&mut moved);
            assert_ne!(Body::from_state(&moved), before);
        }
    }

    #[test]
    fn the_largest_record_leaves_room_for_the_devices_the_capacity_says() {
        let worst = worst_case();
        let capacity = device_capacity();
        assert_eq!(capacity, 11, "the lists above and 48 bytes a device, in a value of 996");

        let secrets =
            |n: usize| -> Vec<Secret> { (0..n).map(|n| Secret::new([u8::try_from(n).unwrap(); 16])).collect() };
        let sealed = seal::seal(&worst, record::SALT, 1, &secrets(capacity), None).unwrap();
        assert!(sealed.per_device);
        assert!(sealed.blob.len() <= seal::MAX_SEALED_LEN, "{}", sealed.blob.len());
        // One more would not, which is where the shared secret takes over.
        assert!(matches!(
            seal::seal(&worst, record::SALT, 1, &secrets(capacity + 1), None),
            Err(SealError::TooLarge { .. })
        ));
        let shared = Secret::new([9; 16]);
        assert!(!seal::seal(&worst, record::SALT, 1, &secrets(capacity + 1), Some(&shared)).unwrap().per_device);

        // A state that fills every list with the longest addresses there are makes no record larger than that.
        let longest = format!("[{}]:65535", ["ffff"; 8].join(":"));
        let mut state = ReachState::default();
        state.set_addresses(AddressKind::Lan, vec![longest.clone(); 4]);
        state.set_addresses(AddressKind::Vpn, vec![longest.clone(); 6]);
        state.set_addresses(AddressKind::Public, vec![longest.clone(); 4]);
        state.set_addresses(AddressKind::V6, vec![longest.clone(); 6]);
        state.set_relays(
            (1..=8)
                .map(|n| RelayEntry { fingerprint: fp(n), name: "r".into(), addresses: vec![longest.clone(); 4] })
                .collect(),
        );
        state.mac = Some([0xff; 6]);
        let record = Body::from_state(&state).record(&fp(0xff), u64::MAX);
        assert!(record.encode().unwrap().len() <= worst.encode().unwrap().len());
    }

    // === when to publish (made-up instants) ===

    fn content_of(n: u8) -> Content {
        Content {
            body: Body {
                addresses: vec![(Kind::Lan, format!("192.0.2.{n}:7420"))],
                nat: Nat::Unknown,
                relays: vec![],
                mac: None,
            },
            recipients: Recipients::Devices(vec![[1; 16]]),
        }
    }

    /// `t` seconds after an instant all the tests of the planner share.
    fn at(t0: Instant, seconds: f64) -> Instant {
        t0 + Duration::from_secs_f64(seconds)
    }

    #[test]
    fn a_start_is_published_once_the_state_has_been_quiet_for_a_moment() {
        let t0 = Instant::now();
        let mut planner = Planner::new(Timing::default(), t0);
        assert_eq!(planner.due(), None, "nothing is known yet");
        planner.observe(t0, Some(content_of(1)));
        assert_eq!(planner.due(), Some(at(t0, 3.0)));
        // Looking again changes nothing as long as nothing changed.
        planner.observe(at(t0, 1.0), Some(content_of(1)));
        planner.observe(at(t0, 2.0), Some(content_of(1)));
        assert_eq!(planner.due(), Some(at(t0, 3.0)));

        planner.succeeded(at(t0, 9.0), content_of(1));
        planner.observe(at(t0, 10.0), Some(content_of(1)));
        assert_eq!(planner.due(), Some(at(t0, 9.0 + 1800.0)), "nothing but the refresh is left");
        planner.succeeded(at(t0, 1809.0), content_of(1));
        assert_eq!(planner.due(), Some(at(t0, 3609.0)), "and the next one is half an hour after that");
    }

    #[test]
    fn changes_in_a_burst_are_one_publish_but_a_state_that_never_settles_is_not_waited_for_forever() {
        let t0 = Instant::now();
        let mut planner = Planner::new(Timing::default(), t0);
        planner.observe(t0, Some(content_of(1)));
        planner.observe(at(t0, 2.0), Some(content_of(2)));
        planner.observe(at(t0, 4.0), Some(content_of(3)));
        assert_eq!(planner.due(), Some(at(t0, 7.0)), "three seconds after the last of them");

        for second in (6..60).step_by(2) {
            planner.observe(at(t0, f64::from(second)), Some(content_of(u8::try_from(second).unwrap())));
        }
        assert_eq!(planner.due(), Some(at(t0, 20.0)), "twenty seconds after the first, whatever happens");
    }

    #[test]
    fn two_publishes_are_never_closer_than_the_gap() {
        let t0 = Instant::now();
        let mut planner = Planner::new(Timing::default(), t0);
        planner.observe(t0, Some(content_of(1)));
        planner.succeeded(at(t0, 10.0), content_of(1));
        planner.observe(at(t0, 10.5), Some(content_of(2)));
        assert_eq!(
            planner.due(),
            Some(at(t0, 25.0)),
            "fifteen seconds after the end of the last, not three after the change"
        );
        // A change that comes later is not held back by it.
        planner.succeeded(at(t0, 25.5), content_of(2));
        planner.observe(at(t0, 100.0), Some(content_of(3)));
        assert_eq!(planner.due(), Some(at(t0, 103.0)));
    }

    #[test]
    fn a_change_during_a_publish_waits_for_its_turn() {
        let t0 = Instant::now();
        let mut planner = Planner::new(Timing::default(), t0);
        planner.observe(t0, Some(content_of(1)));
        // The put began at 3 s and ended at 9; the state changed meanwhile and is looked at when it ends.
        planner.succeeded(at(t0, 9.0), content_of(1));
        planner.observe(at(t0, 9.0), Some(content_of(2)));
        assert_eq!(planner.due(), Some(at(t0, 24.0)));
    }

    #[test]
    fn a_failure_waits_twice_as_long_each_time_up_to_a_limit_and_a_success_starts_over() {
        let t0 = Instant::now();
        let mut planner = Planner::new(Timing::default(), t0);
        planner.observe(t0, Some(content_of(1)));
        let mut now = at(t0, 3.0);
        for wait in [30, 60, 120, 240, 480, 600, 600, 600] {
            planner.failed(now);
            planner.observe(now, Some(content_of(1)));
            assert_eq!(planner.due(), Some(now + secs(wait)), "after a failure at {now:?}");
            now += secs(wait);
        }
        planner.succeeded(now, content_of(1));
        assert_eq!(planner.due(), Some(now + secs(1800)));
        planner.failed(now + secs(1800));
        assert_eq!(planner.due(), Some(now + secs(1800 + 30)), "a failure after a success is the first again");
    }

    #[test]
    fn a_change_does_not_cut_a_pause_after_a_failure_short() {
        let t0 = Instant::now();
        let mut planner = Planner::new(Timing::default(), t0);
        planner.observe(t0, Some(content_of(1)));
        planner.failed(at(t0, 3.0));
        planner.failed(at(t0, 40.0));
        // Sixty seconds from 40, however often the state changes meanwhile.
        for second in 41..60 {
            planner.observe(at(t0, f64::from(second)), Some(content_of(u8::try_from(second).unwrap())));
        }
        assert_eq!(planner.due(), Some(at(t0, 100.0)));
    }

    #[test]
    fn nobody_to_publish_for_means_never_due_until_somebody_is() {
        let t0 = Instant::now();
        let mut planner = Planner::new(Timing::default(), t0);
        planner.observe(t0, None);
        assert_eq!(planner.due(), None);
        planner.observe(at(t0, 5.0), Some(content_of(1)));
        assert_eq!(planner.due(), Some(at(t0, 8.0)));
        planner.succeeded(at(t0, 9.0), content_of(1));
        // The last device goes: nothing to publish and nothing to refresh.
        planner.observe(at(t0, 20.0), None);
        assert_eq!(planner.due(), None);
        planner.observe(at(t0, 4000.0), Some(content_of(1)));
        assert!(planner.due().is_some_and(|due| due <= at(t0, 4000.0)), "the record is old: due at once");
    }

    #[tokio::test]
    async fn a_host_with_nothing_to_say_publishes_nothing() {
        let (ctx, _scratch) = testing::context("e3-empty");
        pair(&ctx, &[fp(1)]);
        secrets::secret_for(&ctx, &fp(1)).unwrap();
        assert_eq!(content(&ctx).unwrap(), None, "no address and no relay: what the DHT has says more");

        ctx.reach.update(|state| state.set_addresses(AddressKind::Lan, vec!["192.0.2.10:7420".into()]));
        let found = content(&ctx).unwrap().expect("something to say");
        assert!(matches!(found.recipients, Recipients::Devices(secrets) if secrets.len() == 1));
        // A relay alone is something to say.
        ctx.reach.update(|state| {
            state.set_addresses(AddressKind::Lan, vec![]);
            state.set_relays(vec![RelayEntry {
                fingerprint: fp(77),
                name: "r".into(),
                addresses: vec!["203.0.113.9:7420".into()],
            }]);
        });
        assert!(content(&ctx).unwrap().is_some());
    }

    // === the loop, on a fake DHT and a paused clock ===

    #[derive(Clone)]
    struct Call {
        at: Instant,
        seq: i64,
        blob: Vec<u8>,
    }

    #[derive(Clone, Copy)]
    enum Outcome {
        Stored,
        NoNetwork,
        Refused,
        NeverEnds,
    }

    /// A DHT that keeps what it is given and answers as the plan says (a record is stored unless it says otherwise).
    struct FakeDht {
        calls: Mutex<Vec<Call>>,
        plan: Mutex<VecDeque<Outcome>>,
        count: watch::Sender<usize>,
    }

    impl FakeDht {
        fn new(plan: &[Outcome]) -> Arc<FakeDht> {
            Arc::new(FakeDht {
                calls: Mutex::default(),
                plan: Mutex::new(plan.iter().copied().collect()),
                count: watch::channel(0).0,
            })
        }

        fn calls(&self) -> Vec<Call> {
            lock(&self.calls).clone()
        }

        /// Waits until `n` records were put. On the paused clock that costs no time, and a loop that never gets there
        /// is a failure after a virtual day.
        async fn until(&self, n: usize) {
            let mut count = self.count.subscribe();
            tokio::time::timeout(secs(24 * 3600), count.wait_for(|calls| *calls >= n))
                .await
                .expect("the publisher put the record in time")
                .expect("the fake DHT is alive");
        }
    }

    impl Publisher for FakeDht {
        fn publish<'a>(
            &'a self,
            _keys: &'a Keys,
            seal: &'a mut Seal<'a>,
        ) -> BoxFuture<'a, Result<Published, NodeError>> {
            Box::pin(async move {
                let seq = 1000 + i64::try_from(lock(&self.calls).len()).unwrap();
                let blob = seal(seq).map_err(|e| NodeError::Blob(e.into()))?;
                let outcome = lock(&self.plan).pop_front().unwrap_or(Outcome::Stored);
                lock(&self.calls).push(Call { at: Instant::now(), seq, blob });
                self.count.send_modify(|calls| *calls += 1);
                match outcome {
                    Outcome::Stored => Ok(Published { seq, stored_at: 20 }),
                    Outcome::NoNetwork => Err(NodeError::NoNetwork),
                    Outcome::Refused => Err(NodeError::Refused { acknowledged: 2 }),
                    Outcome::NeverEnds => std::future::pending().await,
                }
            })
        }
    }

    /// The host, and the loop running on a fake DHT.
    struct Rig {
        ctx: ReachContext,
        _scratch: Scratch,
        fake: Arc<FakeDht>,
        stop: watch::Sender<bool>,
        task: JoinHandle<Result<()>>,
    }

    impl Rig {
        /// `paired` devices, of which `holders` have been given a secret, and the loop with the default timing.
        async fn start(paired: &[Fingerprint], holders: &[Fingerprint], plan: &[Outcome]) -> Rig {
            Rig::start_with(Timing::default(), paired, holders, plan).await
        }

        async fn start_with(timing: Timing, paired: &[Fingerprint], holders: &[Fingerprint], plan: &[Outcome]) -> Rig {
            let (ctx, scratch) = testing::context("e3-loop");
            let (stop, stopped) = watch::channel(false);
            let ctx = ReachContext { stop: Stop::new(stopped), ..ctx };
            ctx.reach.update(busy);
            pair(&ctx, paired);
            for device in holders {
                secrets::secret_for(&ctx, device).unwrap();
            }
            let keys = Keys::load_or_create(&ctx.state_dir.path(keys::FILE_NAME)).unwrap();
            let fake = FakeDht::new(plan);
            let task = tokio::spawn({
                let (ctx, fake) = (ctx.clone(), fake.clone());
                async move { publish_loop(&ctx, &keys, fake.as_ref(), timing).await }
            });
            Rig { ctx, _scratch: scratch, fake, stop, task }
        }

        /// Tells the loop to stop and waits for it.
        async fn finish(self) -> Result<()> {
            self.stop.send(true).unwrap();
            self.task.await.unwrap()
        }

        /// The secret a device holds now, as a reader of the record would use it.
        fn secret(&self, device: Fingerprint) -> Secret {
            Secret::new(secrets::get(&self.ctx, &device).expect("a secret"))
        }
    }

    fn open(call: &Call, secret: &Secret) -> Result<Record, OpenError> {
        seal::open(&call.blob, record::SALT, call.seq, secret)
    }

    /// `actual` is `expected`, give or take the millisecond a timer rounds up to.
    fn near(actual: Duration, expected: Duration) {
        assert!(actual >= expected && actual < expected + ms(100), "{actual:?}, not {expected:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn the_record_is_sealed_for_each_device_and_not_for_one_that_was_revoked() {
        let rig = Rig::start(&[fp(1), fp(2)], &[fp(1), fp(2)], &[]).await;
        rig.fake.until(1).await;
        let first = rig.fake.calls()[0].clone();
        let (a, b) = (rig.secret(fp(1)), rig.secret(fp(2)));
        let expected = Body::from_state(&rig.ctx.reach.read()).record(&rig.ctx.fingerprint, 0);
        for secret in [&a, &b] {
            let record = open(&first, secret).expect("every device opens it");
            assert_eq!(Record { ts: 0, ..record }, expected);
        }
        assert!(matches!(open(&first, &Secret::new([9; 16])), Err(OpenError::NotRecipient)), "and nobody else does");

        // The second device is removed in the launcher.
        let revoked_at = Instant::now();
        pair(&rig.ctx, &[fp(1)]);
        reach::on_revoked(&rig.ctx, &fp(2));
        rig.fake.until(2).await;
        let second = rig.fake.calls()[1].clone();
        assert!(second.at - revoked_at < secs(20), "left out of the next record, not of one a minute later");
        assert!(open(&second, &a).is_ok(), "the device that stays still reads it");
        assert!(matches!(open(&second, &b), Err(OpenError::NotRecipient)), "the one that was revoked does not");
        rig.finish().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn nothing_is_put_for_half_an_hour_and_then_the_same_record_again() {
        let rig = Rig::start(&[fp(1)], &[fp(1)], &[]).await;
        rig.fake.until(1).await;
        tokio::time::sleep(secs(29 * 60)).await;
        assert_eq!(rig.fake.calls().len(), 1, "a quiet half hour puts nothing");

        rig.fake.until(2).await;
        let calls = rig.fake.calls();
        near(calls[1].at - calls[0].at, secs(30 * 60));
        let secret = rig.secret(fp(1));
        let (first, again) = (open(&calls[0], &secret).unwrap(), open(&calls[1], &secret).unwrap());
        assert_eq!(Record { ts: first.ts, ..again }, first, "the same record, sealed again");
        rig.finish().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn what_the_record_does_not_show_puts_nothing_and_what_it_shows_puts_it_once_the_state_is_quiet() {
        let rig = Rig::start(&[fp(1)], &[fp(1)], &[]).await;
        rig.fake.until(1).await;
        tokio::time::sleep(secs(60)).await;

        // Devices connect, the place one was last reached from changes, a switch is turned: none of that is in it.
        rig.ctx.reach.update(|state| {
            state.clients.connected = 2;
            state.last_reached = Some((AddressKind::Lan, "192.0.2.50:7420".into()));
            state.mapping = Some(MappingStatus::default());
            state.switches.standalone = true;
        });
        tokio::time::sleep(secs(10 * 60)).await;
        assert_eq!(rig.fake.calls().len(), 1);

        let changed_at = Instant::now();
        rig.ctx.reach.update(|state| state.set_addresses(AddressKind::Lan, vec!["192.0.2.11:7420".into()]));
        rig.fake.until(2).await;
        near(rig.fake.calls()[1].at - changed_at, secs(3));
        let record = open(&rig.fake.calls()[1], &rig.secret(fp(1))).unwrap();
        assert_eq!(record.addresses[0], (Kind::Lan, "192.0.2.11:7420".to_string()));
        rig.finish().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_burst_of_changes_is_one_record_with_the_last_state() {
        let rig = Rig::start(&[fp(1)], &[fp(1)], &[]).await;
        rig.fake.until(1).await;
        tokio::time::sleep(secs(60)).await;

        for n in 1..=3 {
            rig.ctx.reach.update(|state| state.set_addresses(AddressKind::Lan, vec![format!("192.0.2.{n}:7420")]));
            tokio::time::sleep(secs(1)).await;
        }
        rig.fake.until(2).await;
        tokio::time::sleep(secs(60)).await;
        assert_eq!(rig.fake.calls().len(), 2, "one put for the three of them");
        let record = open(&rig.fake.calls()[1], &rig.secret(fp(1))).unwrap();
        assert_eq!(record.addresses[0], (Kind::Lan, "192.0.2.3:7420".to_string()));
        rig.finish().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_state_that_keeps_changing_is_published_every_twenty_seconds() {
        let rig = Rig::start(&[fp(1)], &[fp(1)], &[]).await;
        // A relay link that flaps: the relay's address changes every two seconds for ten minutes.
        for n in 0..300u32 {
            rig.ctx.reach.update(|state| {
                state.set_relays(vec![RelayEntry {
                    fingerprint: fp(77),
                    name: "a relay".into(),
                    addresses: vec![format!("203.0.113.9:{}", 1000 + n)],
                }])
            });
            tokio::time::sleep(secs(2)).await;
        }
        let calls = rig.fake.calls();
        assert!((27..=31).contains(&calls.len()), "{} puts in ten minutes", calls.len());
        for pair in calls.windows(2) {
            // Twenty seconds after the first change that the last put did not hold, which comes with the next update.
            let wait = pair[1].at - pair[0].at;
            assert!(wait >= secs(20) && wait <= secs(22) + ms(100), "{wait:?} between two puts");
        }
        rig.finish().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_change_just_after_a_publish_waits_for_the_gap_and_not_for_the_quiet() {
        let rig = Rig::start(&[fp(1)], &[fp(1)], &[]).await;
        rig.fake.until(1).await;
        tokio::time::sleep(secs(1)).await;
        rig.ctx.reach.update(|state| state.set_addresses(AddressKind::Lan, vec!["192.0.2.12:7420".into()]));
        rig.fake.until(2).await;
        let calls = rig.fake.calls();
        near(calls[1].at - calls[0].at, secs(15));
        rig.finish().await.unwrap();
    }

    static FAKE_WALL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1_000_000);

    fn fake_wall() -> u64 {
        FAKE_WALL.load(std::sync::atomic::Ordering::SeqCst)
    }

    #[tokio::test(start_paused = true)]
    async fn a_machine_that_slept_publishes_again_without_waiting_for_the_half_hour() {
        let timing = Timing { wall: fake_wall, ..Timing::default() };
        let rig = Rig::start_with(timing, &[fp(1)], &[fp(1)], &[]).await;
        rig.fake.until(1).await;
        tokio::time::sleep(secs(10)).await;

        // Three hours go by on the wall clock while the monotonic one stands still: a suspend.
        let woke_at = Instant::now();
        FAKE_WALL.fetch_add(3 * 3600, std::sync::atomic::Ordering::SeqCst);
        rig.fake.until(2).await;
        assert!(rig.fake.calls()[1].at - woke_at < secs(70), "{:?}", rig.fake.calls()[1].at - woke_at);
        rig.finish().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_failing_network_is_tried_again_after_longer_and_longer_and_then_all_is_well_again() {
        let plan = [Outcome::NoNetwork, Outcome::NoNetwork, Outcome::Refused];
        let rig = Rig::start(&[fp(1)], &[fp(1)], &plan).await;
        rig.fake.until(4).await;
        let calls = rig.fake.calls();
        for (n, wait) in [30, 60, 120].into_iter().enumerate() {
            near(calls[n + 1].at - calls[n].at, secs(wait));
        }
        // The record is in; the next put is the refresh, half an hour after the one that worked.
        rig.fake.until(5).await;
        near(rig.fake.calls()[4].at - calls[3].at, secs(30 * 60));
        rig.finish().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn the_loop_ends_at_once_when_told_to_even_in_a_put_that_never_ends() {
        let rig = Rig::start(&[fp(1)], &[fp(1)], &[Outcome::NeverEnds]).await;
        rig.fake.until(1).await;
        let ended = tokio::time::timeout(secs(1), rig.finish()).await.expect("it stops at once");
        assert!(ended.is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn a_device_that_is_given_a_secret_is_published_for_without_waiting_half_an_hour() {
        let rig = Rig::start(&[fp(1), fp(2)], &[fp(1)], &[]).await;
        rig.fake.until(1).await;
        assert_eq!(secrets::get(&rig.ctx, &fp(2)), None, "paired, but not told a secret yet");

        // It connects and asks for `Reach`.
        rig.ctx.reach.update(|state| state.dht_key = Some([9; 32]));
        let asked_at = Instant::now();
        let told = reach_message(&rig.ctx, &fp(2)).expect("a secret for it");
        rig.fake.until(2).await;
        let calls = rig.fake.calls();
        assert!(calls[1].at - asked_at < secs(20), "{:?}", calls[1].at - asked_at);
        assert!(open(&calls[1], &Secret::new(told.secret)).is_ok());
        assert!(open(&calls[1], &rig.secret(fp(1))).is_ok());
        rig.finish().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_device_removed_behind_the_hosts_back_is_left_out_within_a_minute() {
        let rig = Rig::start(&[fp(1), fp(2)], &[fp(1), fp(2)], &[]).await;
        rig.fake.until(1).await;
        let (a, b) = (rig.secret(fp(1)), rig.secret(fp(2)));
        tokio::time::sleep(secs(10)).await;

        // `velora-host revoke` while the host runs: the list changes and nobody says so.
        let removed_at = Instant::now();
        pair(&rig.ctx, &[fp(1)]);
        rig.fake.until(2).await;
        let second = rig.fake.calls()[1].clone();
        assert!(second.at - removed_at < secs(64), "{:?}", second.at - removed_at);
        assert!(open(&second, &a).is_ok());
        assert!(matches!(open(&second, &b), Err(OpenError::NotRecipient)));
        rig.finish().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_list_of_devices_that_cannot_be_read_is_not_published_for_from_memory() {
        let rig = Rig::start(&[fp(1), fp(2)], &[fp(1), fp(2)], &[]).await;
        rig.fake.until(1).await;
        let (a, b) = (rig.secret(fp(1)), rig.secret(fp(2)));

        fs::write(rig.ctx.state_dir.path(StateDir::AUTHORIZED_CLIENTS), "not json").unwrap();
        tokio::time::sleep(secs(45 * 60)).await;
        assert_eq!(rig.fake.calls().len(), 1, "the refresh waits for a list it can read");

        // Readable again, and the second device is gone from it.
        pair(&rig.ctx, &[fp(1)]);
        rig.fake.until(2).await;
        let second = rig.fake.calls()[1].clone();
        assert!(open(&second, &a).is_ok());
        assert!(matches!(open(&second, &b), Err(OpenError::NotRecipient)));
        rig.finish().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn with_no_device_holding_a_secret_there_is_nobody_to_publish_for() {
        let rig = Rig::start(&[fp(1)], &[], &[]).await;
        tokio::time::sleep(secs(3600)).await;
        assert!(rig.fake.calls().is_empty());

        rig.ctx.reach.update(|state| state.dht_key = Some([9; 32]));
        assert!(reach_message(&rig.ctx, &fp(1)).is_some());
        rig.fake.until(1).await;
        rig.finish().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn more_devices_than_fit_share_one_secret_and_a_revoked_one_cannot_read_what_follows() {
        let devices: Vec<Fingerprint> = (1..=u8::try_from(device_capacity() + 2).unwrap()).map(fp).collect();
        let rig = Rig::start(&devices, &devices, &[]).await;
        rig.fake.until(1).await;
        let first = rig.fake.calls()[0].clone();
        assert_eq!(first.blob.get(1), Some(&1), "one wrap, for the secret they share");
        let shared = rig.secret(devices[0]);
        for device in &devices {
            assert_eq!(rig.secret(*device).as_bytes(), shared.as_bytes(), "every device holds the same");
            assert!(open(&first, &rig.secret(*device)).is_ok());
        }

        // One of them is revoked: the secret changes, and the others have the new one with their next `Reach`.
        let revoked_at = Instant::now();
        pair(&rig.ctx, &devices[1..]);
        reach::on_revoked(&rig.ctx, &devices[0]);
        rig.fake.until(2).await;
        let second = rig.fake.calls()[1].clone();
        assert!(second.at - revoked_at < secs(20));
        assert_eq!(second.blob.get(1), Some(&1));
        assert!(matches!(open(&second, &shared), Err(OpenError::NotRecipient)), "what it holds opens nothing now");
        let renewed = rig.secret(devices[1]);
        assert!(open(&second, &renewed).is_ok());
        assert_ne!(renewed.as_bytes(), shared.as_bytes());
        rig.finish().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn when_the_devices_fit_again_each_has_a_wrap_of_its_own() {
        let capacity = device_capacity();
        let devices: Vec<Fingerprint> = (1..=u8::try_from(capacity + 1).unwrap()).map(fp).collect();
        let rig = Rig::start(&devices, &devices, &[]).await;
        rig.fake.until(1).await;
        let shared = rig.secret(devices[0]);

        pair(&rig.ctx, &devices[1..]);
        reach::on_revoked(&rig.ctx, &devices[0]);
        rig.fake.until(2).await;
        let second = rig.fake.calls()[1].clone();
        assert_eq!(usize::from(second.blob[1]), capacity, "a wrap each");
        assert!(matches!(open(&second, &shared), Err(OpenError::NotRecipient)));
        for device in &devices[1..] {
            assert!(open(&second, &rig.secret(*device)).is_ok());
        }
        rig.finish().await.unwrap();
    }

    // === what the host asks of the hooks ===

    #[tokio::test]
    async fn without_a_key_there_is_nothing_to_tell_a_device() {
        let (ctx, _scratch) = testing::context("e3-hook");
        pair(&ctx, &[fp(1)]);
        assert_eq!(reach_message(&ctx, &fp(1)), None);
        assert_eq!(secrets::get(&ctx, &fp(1)), None, "and no secret was made for the asking");
    }

    #[tokio::test]
    async fn a_paired_device_is_told_the_key_and_its_own_secret_and_a_stranger_nothing() {
        let (ctx, _scratch) = testing::context("e3-hook");
        pair(&ctx, &[fp(1), fp(2)]);
        ctx.reach.update(|state| state.dht_key = Some([5; 32]));
        let told = reach_message(&ctx, &fp(1)).expect("a key and a secret");
        assert_eq!(told.key, [5; 32]);
        assert_eq!(reach_message(&ctx, &fp(1)), Some(told), "the same the next time");
        assert_eq!(secrets::get(&ctx, &fp(1)), Some(told.secret));
        assert_ne!(reach_message(&ctx, &fp(2)).unwrap().secret, told.secret, "each has its own");
        assert_eq!(reach_message(&ctx, &fp(9)), None, "nothing for a device that is not paired");
    }

    #[tokio::test]
    async fn in_the_shared_mode_every_device_is_told_the_secret_they_share() {
        let (ctx, _scratch) = testing::context("e3-hook");
        let devices: Vec<Fingerprint> = (1..=u8::try_from(device_capacity() + 1).unwrap()).map(fp).collect();
        pair(&ctx, &devices);
        ctx.reach.update(|state| state.dht_key = Some([5; 32]));
        let told: Vec<DeviceKeys> = devices.iter().map(|device| reach_message(&ctx, device).unwrap()).collect();
        assert!(told.iter().all(|keys| keys.secret == told[0].secret && keys.key == [5; 32]));
    }

    #[tokio::test]
    async fn the_hooks_the_host_calls_reach_the_secrets() {
        let (ctx, _scratch) = testing::context("e3-hooks");
        pair(&ctx, &[fp(1)]);
        ctx.reach.update(|state| state.dht_key = Some([5; 32]));

        // The pairing link carried a secret.
        reach::on_paired(&ctx, &fp(1), "a phone", Some([4; 16]));
        let HostMsg::Reach { key, secret, .. } = reach::reach_message(&ctx, &fp(1)) else { panic!("a Reach message") };
        assert_eq!((key, secret), ([5; 32], [4; 16]));

        // Removed in the launcher: nothing for it any more.
        pair(&ctx, &[]);
        reach::on_revoked(&ctx, &fp(1));
        let HostMsg::Reach { key, secret, .. } = reach::reach_message(&ctx, &fp(1)) else { panic!("a Reach message") };
        assert_eq!((key, secret), ([0; 32], [0; 16]));
    }

    // === the task, with a real node that has nobody to talk to ===

    fn fast() -> Timing {
        Timing {
            refresh: secs(2),
            quiet: ms(50),
            patience: ms(200),
            gap: ms(50),
            retry: ms(100),
            retry_max: ms(400),
            recheck: ms(100),
            wall: unix_now,
        }
    }

    /// A host whose task can be stopped.
    fn stoppable_host(tag: &str) -> (ReachContext, Scratch, watch::Sender<bool>) {
        let (ctx, scratch) = testing::context(tag);
        let (stop, stopped) = watch::channel(false);
        (ReachContext { stop: Stop::new(stopped), ..ctx }, scratch, stop)
    }

    /// A node whose only way into the DHT is an address nobody answers at, with short waits.
    fn lonely_node(ctx: &ReachContext) -> Config {
        let mut config = offline(public_config(ctx));
        config.request_timeout = Some(ms(200));
        config.publish_deadline = secs(1);
        config.resolve_deadline = secs(1);
        config
    }

    #[tokio::test]
    async fn the_node_the_runtime_opens_reaches_the_public_dht_in_production_and_nobody_in_a_test() {
        let (ctx, _scratch) = testing::context("e3-config");
        // In production: the public DHT, on every interface, with the table beside the key.
        let public = public_config(&ctx);
        assert!(matches!(public.default_nodes, DefaultNodes::Public));
        assert_eq!(public.bind_address, None);
        assert_eq!(public.cache_path, Some(ctx.state_dir.path(CACHE_FILE)));

        // What `run` opens in this build: nobody to ask, and the loopback only.
        let config = node_config(&ctx);
        let DefaultNodes::With(nodes) = &config.default_nodes else { panic!("the public DHT, in a test") };
        assert_eq!(nodes.as_ref()(), [SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 6881)]);
        assert_eq!(config.bind_address, Some(Ipv4Addr::LOCALHOST));
        assert_eq!(config.cache_path, public.cache_path, "and the table is still kept beside the key");
    }

    #[tokio::test]
    async fn the_task_the_runtime_starts_works_offline_and_ends_when_told_to() {
        let (ctx, _scratch, stop) = stoppable_host("e3-offline");
        let task = tokio::spawn(run(ctx.clone()));
        eventually("the key", || ctx.reach.read().dht_key.is_some()).await;
        assert!(!task.is_finished());
        stop.send(true).unwrap();
        tokio::time::timeout(secs(5), task).await.expect("it ends when told to").unwrap().unwrap();
        assert_eq!(ctx.reach.read().dht_key, None);
    }

    async fn eventually(what: &str, mut done: impl FnMut() -> bool) {
        for _ in 0..600 {
            if done() {
                return;
            }
            tokio::time::sleep(ms(10)).await;
        }
        panic!("timed out waiting for {what}");
    }

    #[tokio::test]
    async fn the_task_announces_its_key_and_takes_it_away_when_it_ends() {
        let (ctx, _scratch, stop) = stoppable_host("e3-run");
        ctx.reach.update(busy);
        pair(&ctx, &[fp(1)]);
        let task = tokio::spawn(run_with(ctx.clone(), lonely_node(&ctx), fast()));
        eventually("the key", || ctx.reach.read().dht_key.is_some()).await;
        let key = Keys::load_or_create(&ctx.state_dir.path(keys::FILE_NAME)).unwrap().public_key();
        assert_eq!(ctx.reach.read().dht_key, Some(key));
        assert_eq!(reach_message(&ctx, &fp(1)).map(|told| told.key), Some(key), "the key a device is told");

        // The device has a secret now, so the task tries to publish, and cannot: that is no reason to end.
        tokio::time::sleep(ms(1500)).await;
        assert!(!task.is_finished(), "a network that does not answer does not end the task");
        stop.send(true).unwrap();
        tokio::time::timeout(secs(5), task).await.expect("it ends when told to").unwrap().unwrap();
        assert_eq!(ctx.reach.read().dht_key, None, "and the key goes with it");
    }

    #[tokio::test]
    async fn a_task_that_is_aborted_still_takes_its_key_away() {
        let (ctx, _scratch, _stop) = stoppable_host("e3-abort");
        let task = tokio::spawn(run_with(ctx.clone(), lonely_node(&ctx), fast()));
        eventually("the key", || ctx.reach.read().dht_key.is_some()).await;
        task.abort();
        let _ = task.await;
        assert_eq!(ctx.reach.read().dht_key, None);
    }

    #[tokio::test]
    async fn a_key_file_that_cannot_be_used_ends_the_task_with_an_error_and_is_left_alone() {
        let (ctx, _scratch, _stop) = stoppable_host("e3-key");
        let path = ctx.state_dir.path(keys::FILE_NAME);
        fs::write(&path, b"short").unwrap();
        let ended = tokio::time::timeout(secs(5), run_with(ctx.clone(), lonely_node(&ctx), fast())).await;
        let err = ended.expect("a key file that is wrong is not waited for").unwrap_err();
        assert!(format!("{err:#}").contains("DHT key"), "{err:#}");
        assert_eq!(ctx.reach.read().dht_key, None);
        assert_eq!(fs::read(&path).unwrap(), b"short", "never replaced: every device holds the key it replaces");
    }

    #[tokio::test]
    async fn a_node_with_nobody_to_ask_tells_the_poller_there_is_no_network() {
        let (ctx, _scratch, _stop) = stoppable_host("e3-source");
        let source = NodeSource(Node::open_with(lonely_node(&ctx)).await);
        assert_eq!(source.resolve([3; 32], None, secs(2)).await, Err(LookupError::NoNetwork));
    }

    #[test]
    fn what_the_node_reports_is_what_the_poller_understands() {
        assert_eq!(lookup_error(NodeError::NoNetwork), LookupError::NoNetwork);
        assert_eq!(lookup_error(NodeError::TimedOut), LookupError::Failed("the DHT did not finish in time".into()));
        assert!(matches!(lookup_error(NodeError::Stopped), LookupError::Failed(_)));
    }

    #[tokio::test]
    async fn a_key_that_cannot_be_had_yet_is_waited_for() {
        let (ctx, _scratch, stop) = stoppable_host("e3-key-wait");
        let path = ctx.state_dir.path(keys::FILE_NAME);
        // A directory in the way: an error of the file system, not a key file that is wrong, and it may pass.
        fs::create_dir(&path).unwrap();
        let task = tokio::spawn(run_with(ctx.clone(), lonely_node(&ctx), fast()));
        tokio::time::sleep(ms(400)).await;
        assert!(!task.is_finished(), "it waits");
        assert_eq!(ctx.reach.read().dht_key, None);

        fs::remove_dir(&path).unwrap();
        eventually("the key", || ctx.reach.read().dht_key.is_some()).await;
        stop.send(true).unwrap();
        tokio::time::timeout(secs(5), task).await.expect("it ends when told to").unwrap().unwrap();
    }

    #[tokio::test]
    async fn told_to_stop_while_it_waits_for_the_key_the_task_ends() {
        let (ctx, _scratch, stop) = stoppable_host("e3-key-stop");
        fs::create_dir(ctx.state_dir.path(keys::FILE_NAME)).unwrap();
        let task = tokio::spawn(run_with(ctx.clone(), lonely_node(&ctx), fast()));
        tokio::time::sleep(ms(150)).await;
        stop.send(true).unwrap();
        tokio::time::timeout(secs(5), task).await.expect("it ends").unwrap().unwrap();
        assert_eq!(ctx.reach.read().dht_key, None);
    }

    /// The real node, with a note of how each put ended.
    struct Spy {
        node: Node,
        ended: Mutex<Vec<String>>,
    }

    impl Publisher for Spy {
        fn publish<'a>(
            &'a self,
            keys: &'a Keys,
            seal: &'a mut Seal<'a>,
        ) -> BoxFuture<'a, Result<Published, NodeError>> {
            Box::pin(async move {
                let result = Publisher::publish(&self.node, keys, seal).await;
                lock(&self.ended).push(match &result {
                    Ok(_) => "stored".to_string(),
                    Err(e) => e.to_string(),
                });
                result
            })
        }
    }

    #[tokio::test]
    async fn a_put_on_a_node_that_has_nobody_to_ask_fails_and_is_tried_again_later() {
        let (ctx, _scratch, stop) = stoppable_host("e3-spy");
        ctx.reach.update(busy);
        pair(&ctx, &[fp(1)]);
        secrets::secret_for(&ctx, &fp(1)).unwrap();
        let keys = Keys::load_or_create(&ctx.state_dir.path(keys::FILE_NAME)).unwrap();
        let spy = Arc::new(Spy { node: Node::open_with(lonely_node(&ctx)).await, ended: Mutex::default() });
        let task = tokio::spawn({
            let (ctx, spy) = (ctx.clone(), spy.clone());
            async move { publish_loop(&ctx, &keys, spy.as_ref(), fast()).await }
        });
        eventually("two puts that failed", || lock(&spy.ended).len() >= 2).await;
        assert!(lock(&spy.ended).iter().all(|how| how != "stored"), "{:?}", lock(&spy.ended));
        assert!(!task.is_finished(), "a failed put is no reason to end");
        stop.send(true).unwrap();
        tokio::time::timeout(secs(5), task).await.expect("it ends when told to").unwrap().unwrap();
    }

    #[test]
    fn a_machine_has_slept_when_the_wall_clock_ran_far_ahead_of_the_monotonic_one() {
        assert!(!slept(secs(60), 60));
        assert!(!slept(secs(60), 61), "a second of difference is the clocks' business");
        assert!(!slept(secs(60), 60 + 120), "exactly the margin is not enough");
        assert!(slept(secs(60), 60 + 121));
        assert!(!slept(secs(60), 0), "a wall clock that was set back is no sleep");
    }

    #[test]
    fn after_a_sleep_the_record_is_due_again_once_the_state_has_settled() {
        let t0 = Instant::now();
        let mut planner = Planner::new(Timing::default(), t0);
        planner.observe(t0, Some(content_of(1)));
        planner.failed(at(t0, 5.0));
        planner.failed(at(t0, 40.0));
        planner.succeeded(at(t0, 100.0), content_of(1));
        planner.observe(at(t0, 101.0), Some(content_of(1)));
        assert_eq!(planner.due(), Some(at(t0, 1900.0)), "nothing but the refresh before");

        planner.slept(at(t0, 20_000.0));
        planner.observe(at(t0, 20_000.0), Some(content_of(1)));
        assert_eq!(planner.due(), Some(at(t0, 20_003.0)), "the same record, as for a start");
    }

    #[test]
    fn a_text_that_parses_but_is_longer_than_an_address_can_be_is_not_listed() {
        // The parser takes leading zeros in a port without limit: that is why there is a cap, which keeps every record
        // within what `device_capacity` counts on.
        let long = format!("192.0.2.1:{}80", "0".repeat(60));
        assert!(long.parse::<SocketAddr>().is_ok(), "the premise: {long}");
        assert!(!is_address(&long));
        assert!(is_address(&format!("[{}]:65535", ["ffff"; 8].join(":"))), "the longest there is");

        let mut state = ReachState::default();
        state.set_addresses(AddressKind::Lan, vec![long.clone()]);
        state.set_addresses(AddressKind::V6, vec![format!("[2001:db8::1]:{}80", "0".repeat(60))]);
        state.set_relays(vec![RelayEntry { fingerprint: fp(1), name: "r".into(), addresses: vec![long] }]);
        let body = Body::from_state(&state);
        assert_eq!((body.addresses, body.relays), (vec![], vec![]));
    }

    /// A source of punch items that only counts how often it is asked.
    struct Probe(Arc<std::sync::atomic::AtomicUsize>);

    impl PunchSource for Probe {
        fn resolve(
            &self,
            _key: [u8; 32],
            _newer_than: Option<i64>,
            _deadline: Duration,
        ) -> BoxFuture<'_, Result<Option<Found>, LookupError>> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async { Ok(None) })
        }
    }

    /// A poller (E5's, with a stop of its own) on the host `ctx`.
    fn start_poller(ctx: &ReachContext) -> (watch::Sender<bool>, JoinHandle<Result<()>>) {
        let (stop, stopped) = watch::channel(false);
        (stop, tokio::spawn(poll::run(ReachContext { stop: Stop::new(stopped), ..ctx.clone() })))
    }

    async fn stop_poller((stop, poller): (watch::Sender<bool>, JoinHandle<Result<()>>)) {
        stop.send(true).unwrap();
        tokio::time::timeout(secs(10), poller).await.expect("the poller ends").unwrap().unwrap();
    }

    fn free_port() -> u16 {
        std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap().local_addr().unwrap().port()
    }

    fn port_is_taken(port: u16) -> bool {
        std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).is_err()
    }

    #[tokio::test]
    async fn the_task_gives_the_poller_its_node_in_place_of_whatever_it_had() {
        let (ctx, _scratch, stop) = stoppable_host("e3-source");
        pair(&ctx, &[fp(1)]);
        secrets::secret_for(&ctx, &fp(1)).unwrap();
        let asked = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        poll::set_source(&ctx, Some(Arc::new(Probe(asked.clone()))));

        // The control: a poller with a device that holds a secret and a source asks the source at once.
        let poller = start_poller(&ctx);
        eventually("the poller to ask its source", || asked.load(std::sync::atomic::Ordering::SeqCst) >= 1).await;
        stop_poller(poller).await;

        // The task starts, and the source is its node: a new poller no longer asks the probe.
        let port = free_port();
        let mut config = lonely_node(&ctx);
        config.port = Some(port);
        let task = tokio::spawn(run_with(ctx.clone(), config, fast()));
        eventually("the node", || port_is_taken(port)).await;
        tokio::time::sleep(ms(200)).await;
        let before = asked.load(std::sync::atomic::Ordering::SeqCst);
        let poller = start_poller(&ctx);
        tokio::time::sleep(secs(1)).await;
        assert_eq!(asked.load(std::sync::atomic::Ordering::SeqCst), before, "the poller asks the node now");
        stop_poller(poller).await;

        stop.send(true).unwrap();
        tokio::time::timeout(secs(10), task).await.expect("the task ends").unwrap().unwrap();
    }

    #[tokio::test]
    async fn nothing_holds_the_node_once_the_task_has_ended() {
        let (ctx, _scratch, stop) = stoppable_host("e3-let-go");
        let port = free_port();
        let mut config = lonely_node(&ctx);
        config.port = Some(port);
        let task = tokio::spawn(run_with(ctx.clone(), config, fast()));
        eventually("the node", || port_is_taken(port)).await;

        // The poller held a clone of the node; with the source taken away nothing does, and its socket is closed.
        stop.send(true).unwrap();
        tokio::time::timeout(secs(10), task).await.expect("the task ends").unwrap().unwrap();
        eventually("the node to let its port go", || !port_is_taken(port)).await;
    }

    /// By hand: `cargo test -p velora-host -- --ignored --nocapture public_dht`. Uses the public DHT with a key made
    /// for the test (what it puts there goes away by itself in a few hours) and addresses of the documentation ranges.
    #[tokio::test]
    #[ignore = "uses the public DHT; run by hand"]
    async fn public_dht_a_record_the_host_publishes_is_read_by_a_device_and_follows_a_change() {
        let (ctx, scratch, stop) = stoppable_host("e3-public");
        ctx.reach.update(busy);
        pair(&ctx, &[fp(1), fp(2)]);
        let mut config = Config::new(Mode::Host);
        config.cache_path = Some(ctx.state_dir.path(CACHE_FILE));
        let started = std::time::Instant::now();
        let task = tokio::spawn(run_with(ctx.clone(), config, Timing::default()));
        eventually("the key", || ctx.reach.read().dht_key.is_some()).await;
        let key = ctx.reach.read().dht_key.unwrap();
        let secret_of = |device: Fingerprint| Secret::new(reach_message(&ctx, &device).expect("a secret").secret);
        let (first_device, second_device) = (secret_of(fp(1)), secret_of(fp(2)));

        // A device on another node, with nothing saved, looks the record up until it is there.
        let device_node = Node::open(scratch.path().join("device-cache.txt"), Mode::Client).await;
        let first = loop {
            if let Ok(Some(found)) = device_node.resolve(&key, record::SALT).await {
                break found;
            }
            assert!(started.elapsed() < secs(120), "no record after two minutes");
            tokio::time::sleep(secs(2)).await;
        };
        println!("the record was there {:?} after the task started (seq {})", started.elapsed(), first.seq);
        let expected = Body::from_state(&ctx.reach.read()).record(&ctx.fingerprint, 0);
        for secret in [&first_device, &second_device] {
            let record = seal::open(&first.value, record::SALT, first.seq, secret).expect("a device opens it");
            assert_eq!(Record { ts: 0, ..record }, expected);
        }
        println!("{} bytes sealed for two devices", first.value.len());

        // The second device is removed and the address changes: the next record follows within seconds.
        let changed = std::time::Instant::now();
        pair(&ctx, &[fp(1)]);
        reach::on_revoked(&ctx, &fp(2));
        ctx.reach.update(|state| state.set_addresses(AddressKind::Lan, vec!["192.0.2.99:7420".into()]));
        let options = ResolveOptions { newer_than: Some(first.seq), deadline: Some(secs(8)) };
        let second = loop {
            if let Ok(Some(found)) = device_node.resolve_with(&key, record::SALT, &options).await {
                break found;
            }
            assert!(changed.elapsed() < secs(120), "no newer record after two minutes");
            tokio::time::sleep(secs(2)).await;
        };
        println!("the change was there {:?} after it was made (seq {})", changed.elapsed(), second.seq);
        let record = seal::open(&second.value, record::SALT, second.seq, &first_device).expect("the device that stays");
        assert_eq!(record.addresses[0], (Kind::Lan, "192.0.2.99:7420".to_string()));
        assert!(matches!(
            seal::open(&second.value, record::SALT, second.seq, &second_device),
            Err(OpenError::NotRecipient)
        ));

        // What the poller asks the node for: a punch item that a device left for this host, found at its key.
        let punch_secret = Secret::new([7; 16]);
        let endpoint = "198.51.100.7:40000";
        let (signer, salt, seq, blob) = punch_item::build(&punch_secret, endpoint, 42, SystemTime::now()).unwrap();
        device_node.publish(&signer, salt, &blob, seq).await.expect("the device leaves its request");
        let source = NodeSource(Node::open(scratch.path().join("host-cache.txt"), Mode::Host).await);
        let found = source
            .resolve(punch_item::public_key(&punch_secret), None, secs(10))
            .await
            .expect("a lookup")
            .expect("the item");
        let item = punch_item::open(&found.value, &punch_secret, found.seq, SystemTime::now()).expect("an item");
        assert_eq!((item.endpoint.as_str(), item.nonce), (endpoint, 42));
        println!("the punch item was found through the node of the poller");

        stop.send(true).unwrap();
        tokio::time::timeout(secs(10), task).await.expect("it ends").unwrap().unwrap();
    }

    /// By hand, like the one above: what ties the three tickets together. A device leaves a punch request in the DHT,
    /// the poller of E5 asks for it through the node this task gave it, and the responder sends its packet.
    #[tokio::test]
    #[ignore = "uses the public DHT; run by hand"]
    async fn public_dht_a_punch_request_a_device_leaves_reaches_the_responder_through_the_poller() {
        // Standalone reach on, and a responder that may send to the loopback, which only its own tests can allow.
        let (ctx, scratch) = punch::test_support::host("e3-public-punch");
        let (stop, stopped) = watch::channel(false);
        let ctx = ReachContext { stop: Stop::new(stopped), ..ctx };
        ctx.reach.update(|state| {
            busy(state);
            // A host with a relay hears punch requests from the relay and does not poll the DHT for them.
            state.set_relays(vec![]);
        });
        pair(&ctx, &[fp(1)]);
        let mut config = Config::new(Mode::Host);
        config.cache_path = Some(ctx.state_dir.path(CACHE_FILE));
        let host = tokio::spawn(run_with(ctx.clone(), config, Timing::default()));
        eventually("the key", || ctx.reach.read().dht_key.is_some()).await;
        let secret = reach_message(&ctx, &fp(1)).expect("a secret").secret;

        // The device leaves a request for the responder to send a packet to a socket of the test.
        let target = punch::test_support::nobody().await;
        let endpoint = target.local_addr().unwrap().to_string();
        let device_node = Node::open(scratch.path().join("device-cache.txt"), Mode::Client).await;
        let (signer, salt, seq, blob) =
            punch_item::build(&Secret::new(secret), &endpoint, 77, SystemTime::now()).unwrap();
        device_node.publish(&signer, salt, &blob, seq).await.expect("the device leaves its request");
        let left = std::time::Instant::now();

        // The poller looks it up as soon as it starts, through the node of the task above.
        let poller = tokio::spawn(poll::run(ctx.clone()));
        let mut packet = vec![0u8; 2048];
        let (len, _) = tokio::time::timeout(secs(60), target.recv_from(&mut packet))
            .await
            .expect("the responder sends its packet")
            .unwrap();
        println!("the responder's packet ({len} bytes) came {:?} after the request was left", left.elapsed());
        assert!(len >= 1200, "a QUIC Initial");

        stop.send(true).unwrap();
        tokio::time::timeout(secs(10), poller).await.expect("the poller ends").unwrap().unwrap();
        tokio::time::timeout(secs(10), host).await.expect("the task ends").unwrap().unwrap();
    }
}
