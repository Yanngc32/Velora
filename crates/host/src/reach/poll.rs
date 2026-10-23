//! Punch requests that arrive through the DHT. Filled in by ticket E5 (with `punch.rs`); the
//! plumbing it plugs into is `reach/mod.rs`, which E5 does not edit.
//!
//! A host nobody can reach directly and that has no relay has no channel to hear "a client wants in,
//! from here". The client leaves the request in the DHT (`velora_dht::punch_item`: one item per
//! paired device, at a key derived from the secret the host gave that device) and this task looks
//! for them. A lookup is dear (about 70 datagrams and 3 s from a running node, `docs/dht-spike.md`
//! §8), so it asks rarely, one device at a time, and only while there is nobody to ask for it:
//!
//! - every paired device with a secret is looked up every 45 s, the lookups spread over that
//!   interval and never closer than 3 s (a host with 20 devices stretches the interval instead of
//!   asking in bursts);
//! - for 3 minutes after the last connection ended, the device that connected last is looked up
//!   every 8 s: a client that just lost its network is the one most likely to come back;
//! - nothing while the host is registered with a relay (the relay carries the requests), and
//!   nothing while there is no DHT node to ask (see [`set_source`]).
//!
//! Every item found goes through `punch_item::open` (sealed for that device, fresh, well formed) and
//! the request it holds to [`punch::respond`], which does the rest of the checking.

use std::{
    collections::{BTreeMap, HashSet},
    fmt,
    future::Future,
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use anyhow::Result;
use tokio::sync::watch;
use velora_dht::{
    punch_item::{self, PunchError},
    seal::{OpenError, Secret},
};
use velora_protocol::{tls::Fingerprint, wire::DEVICE_SECRET_LEN};

use super::{punch, secrets, ClientActivity, PunchRequest, ReachContext};

/// A future that can be boxed and sent between threads.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A value the DHT returned for a key, and the `seq` it was published with (the sealing binds it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub value: Vec<u8>,
    pub seq: i64,
}

/// Why a lookup gave no answer at all (an item that is not there is `Ok(None)`, not this).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupError {
    /// Nobody answered: no network, or UDP is blocked. Worth trying again later.
    NoNetwork,
    /// Anything else the node reports, as text for the log.
    Failed(String),
}

impl fmt::Display for LookupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LookupError::NoNetwork => f.write_str("no DHT node answered"),
            LookupError::Failed(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for LookupError {}

/// What the poller needs from the DHT: C2's `Node` is the real one, and E3, who keeps it, gives it
/// to [`set_source`]. A small trait so that the poller is tested with a fake node.
///
/// The adapter for `velora_dht::node::Node` is one call:
///
/// ```ignore
/// impl PunchSource for Node {
///     fn resolve(&self, key: [u8; 32], newer_than: Option<i64>, deadline: Duration)
///         -> BoxFuture<'_, Result<Option<Found>, LookupError>>
///     {
///         Box::pin(async move {
///             let options = ResolveOptions { newer_than, deadline: Some(deadline) };
///             match self.resolve_with(&key, punch_item::SALT, &options).await {
///                 Ok(found) => Ok(found.map(|r| Found { value: r.value, seq: r.seq })),
///                 Err(Error::NoNetwork) => Err(LookupError::NoNetwork),
///                 Err(e) => Err(LookupError::Failed(e.to_string())),
///             }
///         })
///     }
/// }
/// ```
pub trait PunchSource: Send + Sync + 'static {
    /// The newest item stored under `key` and `punch_item::SALT`, when its `seq` is above `newer_than`
    /// (a poll for what changed: an item that is already known is `Ok(None)`), looked for for at
    /// most `deadline`. Lookups are made one at a time.
    fn resolve(
        &self,
        key: [u8; 32],
        newer_than: Option<i64>,
        deadline: Duration,
    ) -> BoxFuture<'_, Result<Option<Found>, LookupError>>;
}

/// Where the DHT node comes from: whoever has one gives it here, and the poller picks it up.
struct Slot {
    source: watch::Sender<Option<Arc<dyn PunchSource>>>,
}

impl Default for Slot {
    fn default() -> Self {
        Slot { source: watch::channel(None).0 }
    }
}

/// Gives the poller the DHT node to look up punch items with, or takes it away (`None`: the node
/// is gone, the DHT switch went off). Without one the poller idles, which is how a host that did not
/// switch the DHT on stays away from it. E3's `dht::run` calls this when its node is up and again
/// with `None` when it ends.
pub fn set_source(ctx: &ReachContext, source: Option<Arc<dyn PunchSource>>) {
    ctx.ext::<Slot>().source.send_replace(source);
}

/// How often and how much the poller looks. The defaults are the product's (the module docs); tests
/// use much shorter ones.
#[derive(Debug, Clone, Copy)]
pub struct Schedule {
    /// Each device (each secret) is looked up this often when nobody is expected.
    pub interval: Duration,
    /// Never two lookups closer than this, however many devices there are: with N devices the
    /// interval becomes at least N times this.
    pub min_gap: Duration,
    /// After the last connection ended, the device that connected last is looked up this often...
    pub burst_interval: Duration,
    /// ...for this long.
    pub burst_window: Duration,
    /// A lookup is given up on after this long.
    pub lookup_deadline: Duration,
    /// The list of devices is read again this often.
    pub devices_every: Duration,
}

impl Default for Schedule {
    fn default() -> Self {
        Schedule {
            interval: Duration::from_secs(45),
            min_gap: Duration::from_secs(3),
            burst_interval: Duration::from_secs(8),
            burst_window: Duration::from_secs(3 * 60),
            lookup_deadline: Duration::from_secs(6),
            devices_every: Duration::from_secs(10),
        }
    }
}

/// The devices that hold one secret, which is one item in the DHT: one device, except in a shared
/// record (more devices than a record has room for), where they all share the secret and so the
/// slot, and a request cannot say which of them it is from.
struct Group {
    secret: Secret,
    key: [u8; 32],
    /// Fingerprint order.
    members: Vec<Fingerprint>,
    /// When it is next looked up, if nothing speeds it up.
    due: Instant,
    last_polled: Option<Instant>,
    /// The highest `seq` seen at this key: what was already served is not asked for again.
    newer_than: Option<i64>,
}

/// What the poller decides with: who to look up next, and what to do with an item. No I/O.
struct Poller {
    schedule: Schedule,
    /// In key order, so the schedule does not depend on the order the devices were listed in.
    groups: Vec<Group>,
    last_lookup_end: Option<Instant>,
    /// What was logged once already, so a device with a broken clock does not fill the log.
    noted: HashSet<(Fingerprint, &'static str)>,
}

impl Poller {
    fn new(schedule: Schedule) -> Poller {
        Poller { schedule, groups: Vec::new(), last_lookup_end: None, noted: HashSet::new() }
    }

    /// Takes the current list of devices: the new ones are scheduled (spread over the interval when
    /// there are several), the ones that are gone are dropped, the rest keep their place.
    fn set_devices(&mut self, devices: &[(Fingerprint, [u8; DEVICE_SECRET_LEN])], now: Instant) {
        let mut by_secret: BTreeMap<[u8; DEVICE_SECRET_LEN], Vec<Fingerprint>> = BTreeMap::new();
        for (fingerprint, secret) in devices {
            by_secret.entry(*secret).or_default().push(*fingerprint);
        }
        let total = by_secret.len();
        let mut old: Vec<Group> = std::mem::take(&mut self.groups);
        let mut new_ones = 0u32;
        for (bytes, mut members) in by_secret {
            members.sort_by_key(|fingerprint| fingerprint.0);
            let kept = old.iter().position(|group| group.secret.as_bytes() == &bytes).map(|at| old.swap_remove(at));
            let group = match kept {
                Some(mut group) => {
                    group.members = members;
                    group
                }
                None => {
                    let secret = Secret::new(bytes);
                    let key = punch_item::public_key(&secret);
                    // N new groups at once start a total-th of the interval apart.
                    let offset = self.schedule.interval * new_ones / u32::try_from(total).unwrap_or(1).max(1);
                    new_ones += 1;
                    Group { secret, key, members, due: now + offset, last_polled: None, newer_than: None }
                }
            };
            self.groups.push(group);
        }
        self.groups.sort_by_key(|group| group.key);
    }

    /// How long each group waits between two lookups when nobody is expected: the interval, or
    /// longer when there are so many groups that the lookups would crowd each other.
    fn slow_interval(&self) -> Duration {
        let groups = u32::try_from(self.groups.len()).unwrap_or(u32::MAX).max(1);
        self.schedule.interval.max(self.schedule.min_gap.saturating_mul(groups))
    }

    /// The group to look up next and when, if there is one. `burst` is the device that connected
    /// last, when the host has just become idle.
    fn next(&self, now: Instant, burst: Option<Fingerprint>) -> Option<(usize, Instant)> {
        self.groups
            .iter()
            .enumerate()
            .map(|(at, group)| {
                let mut due = group.due;
                if burst.is_some_and(|device| group.members.contains(&device)) {
                    let sooner = group.last_polled.map_or(now, |polled| polled + self.schedule.burst_interval);
                    due = due.min(sooner);
                }
                if let Some(end) = self.last_lookup_end {
                    due = due.max(end + self.schedule.min_gap);
                }
                (due, at)
            })
            .min()
            .map(|(due, at)| (at, due))
    }

    /// A lookup of group `at` that began at `started` has ended.
    fn finished(&mut self, at: usize, started: Instant, ended: Instant) {
        let slow = self.slow_interval();
        if let Some(group) = self.groups.get_mut(at) {
            group.last_polled = Some(started);
            group.due = ended + slow;
        }
        self.last_lookup_end = Some(ended);
    }

    /// What to do with the item found for group `at`: the request it holds if a host may serve it.
    fn open(&mut self, at: usize, found: &Found, now: SystemTime) -> Option<PunchRequest> {
        let group = self.groups.get_mut(at)?;
        // Whatever it turns out to be, it is not asked for again.
        group.newer_than = Some(group.newer_than.map_or(found.seq, |seen| seen.max(found.seq)));
        let from = *group.members.first()?;
        match punch_item::open(&found.value, &group.secret, found.seq, now) {
            Ok(item) => Some(PunchRequest { from: from.to_base64(), endpoint: item.endpoint, nonce: item.nonce }),
            Err(PunchError::Stale { .. } | PunchError::Open(OpenError::NotRecipient)) => {
                tracing::trace!("the punch item of {from} is old or not for it");
                None
            }
            Err(PunchError::FromTheFuture { ahead }) => {
                if self.noted.insert((from, "future")) {
                    tracing::warn!(
                        "{from} dated a punch request {ahead} s ahead of this computer's clock; ignoring it"
                    );
                }
                None
            }
            Err(e) => {
                if self.noted.insert((from, "damaged")) {
                    tracing::debug!("the punch item of {from} cannot be read: {e}");
                }
                None
            }
        }
    }
}

/// The device to look up often right now: the one that connected last, while nobody is connected and
/// the last connection ended less than the burst window ago.
fn burst_target(clients: &ClientActivity, now: Instant, schedule: &Schedule) -> Option<Fingerprint> {
    let (device, _) = clients.last_connect?;
    let left = clients.last_disconnect?;
    (clients.connected == 0 && now.saturating_duration_since(left) < schedule.burst_window).then_some(device)
}

/// The polling task. Started when standalone reach is on; it ends when `ctx.stop` fires.
///
/// While no relay is registered (`state.relays` is empty) it looks up the punch items of the
/// paired clients in the DHT and hands each fresh one to `punch::respond`. It polls more often
/// for a while after a client disconnects: `state.clients.connected` and
/// `state.clients.last_disconnect` say when that was, and `ctx.reach.subscribe()` wakes it when
/// they change.
///
/// The module docs have the pacing. The devices are those of `secrets::all` (the ones with a secret
/// that are still paired), and the DHT node is whatever was given to [`set_source`]: until there is
/// one, nothing is looked up.
pub async fn run(ctx: ReachContext) -> Result<()> {
    let devices = {
        let ctx = ctx.clone();
        move || secrets::all(&ctx)
    };
    let sink = {
        let ctx = ctx.clone();
        move |request: PunchRequest| -> BoxFuture<'static, Result<()>> {
            let ctx = ctx.clone();
            Box::pin(async move { punch::respond(&ctx, request).await })
        }
    };
    run_with(&ctx, Schedule::default(), devices, sink).await
}

/// [`run`] with its parts given: the schedule, where the devices come from and where requests go.
async fn run_with(
    ctx: &ReachContext,
    schedule: Schedule,
    devices: impl Fn() -> Vec<(Fingerprint, [u8; DEVICE_SECRET_LEN])>,
    sink: impl Fn(PunchRequest) -> BoxFuture<'static, Result<()>>,
) -> Result<()> {
    let mut sources = ctx.ext::<Slot>().source.subscribe();
    let mut changes = ctx.reach.subscribe();
    let mut poller = Poller::new(schedule);
    let mut devices_read: Option<Instant> = None;
    let mut offline = false;
    loop {
        if ctx.stop.is_stopped() {
            return Ok(());
        }
        let now = Instant::now();
        let source = sources.borrow().clone();
        let relayed = !ctx.reach.read().relays.is_empty();
        let Some(source) = source.filter(|_| !relayed) else {
            if !idle(ctx, &mut changes, &mut sources, schedule.devices_every).await {
                return Ok(());
            }
            continue;
        };
        if devices_read.is_none_or(|at| now.saturating_duration_since(at) >= schedule.devices_every) {
            poller.set_devices(&devices(), now);
            devices_read = Some(now);
        }
        let burst = burst_target(&ctx.reach.read().clients, now, &schedule);
        let Some((at, due)) = poller.next(now, burst) else {
            if !idle(ctx, &mut changes, &mut sources, schedule.devices_every).await {
                return Ok(());
            }
            continue;
        };
        if due > now {
            // Anything that changes the picture (a client leaving, a relay, the list of devices) wakes it.
            let limit = (due - now).min(schedule.devices_every);
            if !idle(ctx, &mut changes, &mut sources, limit).await {
                return Ok(());
            }
            continue;
        }

        let Some(group) = poller.groups.get(at) else { continue };
        let (key, newer_than) = (group.key, group.newer_than);
        let started = Instant::now();
        let outcome = tokio::select! {
            outcome = source.resolve(key, newer_than, schedule.lookup_deadline) => outcome,
            () = ctx.stop.stopped() => return Ok(()),
        };
        poller.finished(at, started, Instant::now());
        match outcome {
            Ok(Some(found)) => {
                offline = false;
                if let Some(request) = poller.open(at, &found, SystemTime::now()) {
                    match sink(request).await {
                        Ok(()) => {}
                        Err(e) => tracing::debug!("a punch request found in the DHT was not served: {e:#}"),
                    }
                }
            }
            Ok(None) => offline = false,
            Err(e) => {
                // Said once per outage, not once per lookup.
                if !offline {
                    tracing::debug!("looking up punch requests failed: {e}");
                }
                offline = true;
            }
        }
    }
}

/// Waits up to `limit`, or for a change of the state, of the DHT node or the order to stop; false
/// when the task must end.
async fn idle(
    ctx: &ReachContext,
    changes: &mut watch::Receiver<u64>,
    sources: &mut watch::Receiver<Option<Arc<dyn PunchSource>>>,
    limit: Duration,
) -> bool {
    tokio::select! {
        () = ctx.stop.stopped() => false,
        () = tokio::time::sleep(limit) => true,
        changed = changes.changed() => changed.is_ok(),
        changed = sources.changed() => changed.is_ok(),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{Mutex, MutexGuard},
    };

    use tokio::{sync::mpsc, task::JoinHandle};
    use velora_protocol::identity::Identity;

    use super::*;
    use crate::reach::{
        punch::test_support::{eventually, host, nobody, pair},
        testing::Scratch,
        RelayEntry, Stop,
    };

    fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        mutex.lock().unwrap()
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    fn fp(n: u8) -> Fingerprint {
        Fingerprint([n; 32])
    }

    fn device_secret(n: u8) -> ([u8; DEVICE_SECRET_LEN], Secret) {
        ([n; DEVICE_SECRET_LEN], Secret::new([n; DEVICE_SECRET_LEN]))
    }

    /// Short intervals, same shape: a device every 300 ms, a burst of 60 ms for 400 ms.
    fn fast() -> Schedule {
        Schedule {
            interval: ms(300),
            min_gap: ms(20),
            burst_interval: ms(60),
            burst_window: ms(400),
            lookup_deadline: ms(500),
            devices_every: ms(50),
        }
    }

    // ---- a DHT to ask ---------------------------------------------------------------------------

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Asked {
        key: [u8; 32],
        newer_than: Option<i64>,
        at: Instant,
    }

    /// The items that were put in it, and a record of what it was asked.
    #[derive(Default)]
    struct FakeDht {
        items: Mutex<HashMap<[u8; 32], Found>>,
        asked: Mutex<Vec<Asked>>,
        failing: Mutex<Option<LookupError>>,
        /// How long a lookup takes.
        delay: Mutex<Duration>,
    }

    impl FakeDht {
        /// What a client holding `secret` publishes.
        fn put(&self, secret: &Secret, endpoint: &str, nonce: u64, now: SystemTime) -> i64 {
            let (_, _, seq, value) = punch_item::build(secret, endpoint, nonce, now).unwrap();
            lock(&self.items).insert(punch_item::public_key(secret), Found { value, seq });
            seq
        }

        /// The same with a `seq` above the last one put, as a client does when it asks again.
        fn put_after(&self, secret: &Secret, endpoint: &str, nonce: u64, last_seq: i64) -> i64 {
            let (_, _, seq, value) =
                punch_item::build_after(secret, endpoint, nonce, SystemTime::now(), last_seq).unwrap();
            lock(&self.items).insert(punch_item::public_key(secret), Found { value, seq });
            seq
        }

        fn asked(&self) -> Vec<Asked> {
            lock(&self.asked).clone()
        }

        fn asked_for(&self, secret: &Secret) -> Vec<Asked> {
            let key = punch_item::public_key(secret);
            self.asked().into_iter().filter(|asked| asked.key == key).collect()
        }
    }

    impl PunchSource for FakeDht {
        fn resolve(
            &self,
            key: [u8; 32],
            newer_than: Option<i64>,
            _deadline: Duration,
        ) -> BoxFuture<'_, Result<Option<Found>, LookupError>> {
            Box::pin(async move {
                lock(&self.asked).push(Asked { key, newer_than, at: Instant::now() });
                let delay = *lock(&self.delay);
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                if let Some(error) = lock(&self.failing).clone() {
                    return Err(error);
                }
                let found = lock(&self.items).get(&key).cloned();
                Ok(found.filter(|found| newer_than.is_none_or(|seen| found.seq > seen)))
            })
        }
    }

    // ---- the poller around it -------------------------------------------------------------------

    type Devices = Vec<(Fingerprint, [u8; DEVICE_SECRET_LEN])>;

    /// The poller running against a fake DHT: the requests it hands on arrive in `requests`.
    struct Rig {
        ctx: ReachContext,
        _scratch: Scratch,
        dht: Arc<FakeDht>,
        devices: Arc<Mutex<Devices>>,
        stop: watch::Sender<bool>,
        requests: mpsc::UnboundedReceiver<PunchRequest>,
        sink: mpsc::UnboundedSender<PunchRequest>,
        task: Option<JoinHandle<Result<()>>>,
    }

    impl Rig {
        /// Everything in place and nothing running yet.
        fn new(devices: Devices) -> Rig {
            let (ctx, scratch) = host("poll");
            let dht = Arc::new(FakeDht::default());
            set_source(&ctx, Some(dht.clone()));
            let (stop, stopped) = watch::channel(false);
            let ctx = ReachContext { stop: Stop::new(stopped), ..ctx };
            let (sink, requests) = mpsc::unbounded_channel();
            Rig {
                ctx,
                _scratch: scratch,
                dht,
                devices: Arc::new(Mutex::new(devices)),
                stop,
                requests,
                sink,
                task: None,
            }
        }

        /// Runs the poller, handing the requests it finds to `requests`.
        fn start(&mut self, schedule: Schedule) {
            let (ctx, devices, sink) = (self.ctx.clone(), self.devices.clone(), self.sink.clone());
            self.task = Some(tokio::spawn(async move {
                let devices = move || lock(&devices).clone();
                let sink = move |request| -> BoxFuture<'static, Result<()>> {
                    let _ = sink.send(request);
                    Box::pin(async { Ok(()) })
                };
                run_with(&ctx, schedule, devices, sink).await
            }));
        }

        /// Runs the poller with the host's own responder (`punch::respond`) on the other end.
        fn start_serving(&mut self, schedule: Schedule) {
            let (ctx, devices) = (self.ctx.clone(), self.devices.clone());
            self.task = Some(tokio::spawn(async move {
                let devices = move || lock(&devices).clone();
                let sink = {
                    let ctx = ctx.clone();
                    move |request| -> BoxFuture<'static, Result<()>> {
                        let ctx = ctx.clone();
                        Box::pin(async move { punch::respond(&ctx, request).await })
                    }
                };
                run_with(&ctx, schedule, devices, sink).await
            }));
        }

        async fn next(&mut self) -> PunchRequest {
            tokio::time::timeout(Duration::from_secs(5), self.requests.recv())
                .await
                .expect("no request arrived")
                .expect("the poller ended")
        }

        /// Whether no request arrives for `wait`.
        async fn quiet_for(&mut self, wait: Duration) -> bool {
            tokio::time::timeout(wait, self.requests.recv()).await.is_err()
        }
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            let _ = self.stop.send(true);
        }
    }

    #[tokio::test]
    async fn a_request_left_in_the_dht_reaches_the_responder_once() {
        let (bytes, secret) = device_secret(1);
        let mut rig = Rig::new(vec![(fp(1), bytes)]);
        rig.start(fast());

        let seq = rig.dht.put(&secret, "198.51.100.7:40000", 42, SystemTime::now());
        let request = rig.next().await;
        assert_eq!(request, PunchRequest { from: fp(1).to_base64(), endpoint: "198.51.100.7:40000".into(), nonce: 42 });
        // Later lookups only ask for what is newer than that, and the item is not handed over again.
        assert!(rig.quiet_for(ms(800)).await);
        let asked = rig.dht.asked_for(&secret);
        assert!(asked.len() >= 3, "{asked:?}");
        assert!(asked.last().is_some_and(|last| last.newer_than == Some(seq)), "{asked:?}");

        // A newer item is a new request.
        rig.dht.put_after(&secret, "198.51.100.8:40001", 43, seq);
        let request = rig.next().await;
        assert_eq!((request.endpoint.as_str(), request.nonce), ("198.51.100.8:40001", 43));
    }

    #[tokio::test]
    async fn an_item_that_is_old_forged_or_dated_ahead_is_not_a_request() {
        let ((bytes, secret), (_, other)) = (device_secret(1), device_secret(2));
        let mut rig = Rig::new(vec![(fp(1), bytes)]);
        rig.start(fast());
        let (now, key) = (SystemTime::now(), punch_item::public_key(&secret));
        let latest_ask = |rig: &Rig| rig.dht.asked().into_iter().rfind(|asked| asked.key == key);

        // Left two minutes ago and still in the DHT: the usual answer to a poll.
        let old = rig.dht.put(&secret, "198.51.100.7:40000", 1, now - secs(120));
        assert!(rig.quiet_for(ms(500)).await);
        // It is not asked for again.
        assert_eq!(latest_ask(&rig).and_then(|asked| asked.newer_than), Some(old));

        // From a device whose clock is an hour ahead.
        let (_, _, ahead, value) =
            punch_item::build_after(&secret, "198.51.100.7:40000", 2, now + secs(3600), old).unwrap();
        lock(&rig.dht.items).insert(key, Found { value, seq: ahead });
        assert!(rig.quiet_for(ms(500)).await);

        // Sealed with another device's secret and put at this one's key, which anyone may do.
        let (_, _, forged, value) = punch_item::build_after(&other, "198.51.100.9:40002", 3, now, ahead).unwrap();
        lock(&rig.dht.items).insert(key, Found { value, seq: forged });
        assert!(rig.quiet_for(ms(500)).await);

        // And a good one still gets through.
        rig.dht.put_after(&secret, "198.51.100.10:40003", 4, forged);
        assert_eq!(rig.next().await.nonce, 4);
    }

    #[tokio::test]
    async fn nothing_is_asked_while_a_relay_carries_the_requests() {
        let (bytes, secret) = device_secret(1);
        let mut rig = Rig::new(vec![(fp(1), bytes)]);
        rig.ctx.reach.update(|state| {
            state.set_relays(vec![RelayEntry {
                fingerprint: fp(9),
                name: "desktop".into(),
                addresses: vec!["198.51.100.20:7420".into()],
            }])
        });
        rig.start(fast());
        rig.dht.put(&secret, "198.51.100.7:40000", 1, SystemTime::now());
        assert!(rig.quiet_for(ms(600)).await);
        assert!(rig.dht.asked().is_empty());

        // The relay goes away; the DHT is what is left.
        rig.ctx.reach.update(|state| state.set_relays(Vec::new()));
        assert_eq!(rig.next().await.nonce, 1);
    }

    #[tokio::test]
    async fn nothing_is_asked_until_there_is_a_node_to_ask() {
        let (bytes, secret) = device_secret(1);
        let mut rig = Rig::new(vec![(fp(1), bytes)]);
        // The DHT switch is off, or the node is not up yet: nobody gave the poller one.
        set_source(&rig.ctx, None);
        rig.start(fast());
        rig.dht.put(&secret, "198.51.100.7:40000", 1, SystemTime::now());
        assert!(rig.quiet_for(ms(500)).await);
        assert!(rig.dht.asked().is_empty());

        set_source(&rig.ctx, Some(rig.dht.clone()));
        assert_eq!(rig.next().await.nonce, 1);
        // Taken away again, it stops.
        set_source(&rig.ctx, None);
        tokio::time::sleep(ms(200)).await;
        let asked = rig.dht.asked().len();
        tokio::time::sleep(ms(500)).await;
        assert_eq!(rig.dht.asked().len(), asked);
    }

    #[tokio::test]
    async fn devices_are_looked_up_in_turn_spread_over_the_interval() {
        let secrets: Vec<_> = (1..=3).map(device_secret).collect();
        let devices = secrets.iter().enumerate().map(|(n, (bytes, _))| (fp(n as u8 + 1), *bytes)).collect();
        let mut rig = Rig::new(devices);
        rig.start(Schedule { interval: ms(600), min_gap: ms(50), ..fast() });
        tokio::time::sleep(ms(1500)).await;

        let asked = rig.dht.asked();
        for (_, secret) in &secrets {
            let ours = rig.dht.asked_for(secret);
            assert!(ours.len() >= 2, "every device is asked again and again: {ours:?}");
        }
        // The first lookup of each is a third of an interval after the one before; no two are closer than the gap.
        let first_of = |secret: &Secret| rig.dht.asked_for(secret).first().map(|asked| asked.at).unwrap();
        let mut firsts: Vec<Instant> = secrets.iter().map(|(_, secret)| first_of(secret)).collect();
        firsts.sort();
        assert!(firsts[1] - firsts[0] >= ms(100) && firsts[2] - firsts[1] >= ms(100), "{firsts:?}");
        let mut times: Vec<Instant> = asked.iter().map(|asked| asked.at).collect();
        times.sort();
        assert!(times.windows(2).all(|pair| pair[1] - pair[0] >= ms(40)), "lookups crowd each other");
    }

    #[tokio::test]
    async fn lookups_are_made_one_at_a_time() {
        let secrets: Vec<_> = (1..=2).map(device_secret).collect();
        let devices = secrets.iter().enumerate().map(|(n, (bytes, _))| (fp(n as u8 + 1), *bytes)).collect();
        let mut rig = Rig::new(devices);
        *lock(&rig.dht.delay) = ms(120);
        rig.start(Schedule { interval: ms(200), min_gap: ms(10), ..fast() });
        tokio::time::sleep(ms(1000)).await;

        let mut times: Vec<Instant> = rig.dht.asked().iter().map(|asked| asked.at).collect();
        times.sort();
        assert!(times.len() >= 4);
        // `newer_than` may only go forward for a record, so a lookup never begins while another runs.
        assert!(times.windows(2).all(|pair| pair[1] - pair[0] >= ms(100)), "{times:?}");
    }

    #[tokio::test]
    async fn a_secret_shared_by_several_devices_is_looked_up_once() {
        let (bytes, secret) = device_secret(7);
        let mut rig = Rig::new(vec![(fp(5), bytes), (fp(2), bytes), (fp(9), bytes)]);
        rig.start(fast());
        tokio::time::sleep(ms(700)).await;
        let keys: HashSet<[u8; 32]> = rig.dht.asked().iter().map(|asked| asked.key).collect();
        assert_eq!(keys.len(), 1);

        // The request cannot say which of them asked: the first in fingerprint order stands for them.
        rig.dht.put(&secret, "198.51.100.7:40000", 1, SystemTime::now());
        assert_eq!(rig.next().await.from, fp(2).to_base64());
    }

    #[tokio::test]
    async fn a_device_that_is_no_longer_paired_is_no_longer_looked_up() {
        let ((a, secret_a), (b, secret_b)) = (device_secret(1), device_secret(2));
        let mut rig = Rig::new(vec![(fp(1), a), (fp(2), b)]);
        rig.start(fast());
        eventually("both to be asked", || {
            !rig.dht.asked_for(&secret_a).is_empty() && !rig.dht.asked_for(&secret_b).is_empty()
        })
        .await;

        lock(&rig.devices).retain(|(device, _)| *device != fp(2));
        tokio::time::sleep(ms(400)).await;
        let before = rig.dht.asked_for(&secret_b).len();
        tokio::time::sleep(ms(700)).await;
        assert_eq!(rig.dht.asked_for(&secret_b).len(), before, "the removed device was still being asked about");
        assert!(rig.dht.asked_for(&secret_a).len() > 2);
        // And a device that appears is picked up.
        let (c, secret_c) = device_secret(3);
        lock(&rig.devices).push((fp(3), c));
        eventually("the new device to be asked", || !rig.dht.asked_for(&secret_c).is_empty()).await;
    }

    #[tokio::test]
    async fn after_the_last_connection_ends_the_device_that_connected_last_is_looked_up_often() {
        let ((a, secret_a), (b, secret_b)) = (device_secret(1), device_secret(2));
        let mut rig = Rig::new(vec![(fp(1), a), (fp(2), b)]);
        // A long interval: only the burst can make a device be asked again soon.
        let schedule = Schedule { interval: Duration::from_secs(3), min_gap: ms(10), ..fast() };
        rig.start(schedule);
        eventually("both to be asked once", || {
            !rig.dht.asked_for(&secret_a).is_empty() && !rig.dht.asked_for(&secret_b).is_empty()
        })
        .await;
        tokio::time::sleep(ms(150)).await;
        let (a_before, b_before) = (rig.dht.asked_for(&secret_a).len(), rig.dht.asked_for(&secret_b).len());
        assert_eq!((a_before, b_before), (1, 1), "nobody was expected, so nobody was asked again");

        // Device 1 connects and leaves: it is the one to look for.
        drop(rig.ctx.reach.client_connected(fp(1)));
        tokio::time::sleep(ms(350)).await;
        let (a_during, b_during) = (rig.dht.asked_for(&secret_a).len(), rig.dht.asked_for(&secret_b).len());
        assert!(a_during >= a_before + 3, "{a_during} lookups of the device that just left");
        assert_eq!(b_during, b_before, "the other devices stay on the slow rate");

        // The window passes and it goes back to the slow rate.
        tokio::time::sleep(ms(500)).await;
        let settled = rig.dht.asked_for(&secret_a).len();
        tokio::time::sleep(ms(400)).await;
        assert_eq!(rig.dht.asked_for(&secret_a).len(), settled);

        // While a device is connected nobody is expected to need a hole.
        let guard = rig.ctx.reach.client_connected(fp(2));
        let during = rig.dht.asked_for(&secret_b).len();
        tokio::time::sleep(ms(400)).await;
        assert_eq!(rig.dht.asked_for(&secret_b).len(), during);
        drop(guard);
    }

    #[tokio::test]
    async fn a_lookup_that_fails_does_not_end_the_poller() {
        let (bytes, secret) = device_secret(1);
        let mut rig = Rig::new(vec![(fp(1), bytes)]);
        *lock(&rig.dht.failing) = Some(LookupError::NoNetwork);
        rig.start(fast());
        eventually("a few lookups", || rig.dht.asked().len() >= 3).await;

        // The network is back and a client is waiting.
        *lock(&rig.dht.failing) = None;
        rig.dht.put(&secret, "198.51.100.7:40000", 1, SystemTime::now());
        assert_eq!(rig.next().await.nonce, 1);
        *lock(&rig.dht.failing) = Some(LookupError::Failed("the node stopped".into()));
        let asked = rig.dht.asked().len();
        eventually("another lookup", || rig.dht.asked().len() > asked).await;
    }

    #[tokio::test]
    async fn the_poller_ends_when_told_to_stop_even_in_the_middle_of_a_lookup() {
        let (bytes, _) = device_secret(1);
        let mut rig = Rig::new(vec![(fp(1), bytes)]);
        *lock(&rig.dht.delay) = Duration::from_secs(30);
        rig.start(fast());
        eventually("the lookup to begin", || !rig.dht.asked().is_empty()).await;

        rig.stop.send(true).unwrap();
        let task = rig.task.take().unwrap();
        tokio::time::timeout(Duration::from_secs(3), task).await.expect("the poller did not end").unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_request_found_in_the_dht_makes_the_host_send_toward_the_client() {
        // The whole chain, with the host's own responder at the end: a paired device leaves a request
        // in the DHT, the poller finds it, and a QUIC Initial goes to the endpoint it names.
        let phone = Identity::generate().unwrap();
        let (bytes, secret) = device_secret(1);
        let mut rig = Rig::new(vec![(phone.fingerprint(), bytes)]);
        pair(&rig.ctx, &phone, "phone");
        let target = nobody().await;
        rig.start_serving(fast());

        rig.dht.put(&secret, &target.local_addr().unwrap().to_string(), 99, SystemTime::now());
        let mut buffer = vec![0u8; 4096];
        let (len, from) = tokio::time::timeout(Duration::from_secs(5), target.recv_from(&mut buffer))
            .await
            .expect("nothing was sent toward the client")
            .unwrap();
        assert_eq!(from, rig.ctx.socket.local_addr());
        assert!(len >= 1200 && buffer[0] & 0xc0 == 0xc0, "a QUIC Initial");
        let punching = rig.ctx.ext::<punch::Punching>();
        assert_eq!(punching.stats().started, 1);
        // Polling the same item again does not send it again.
        tokio::time::sleep(ms(600)).await;
        assert_eq!(punching.stats().started, 1);
        assert_eq!(punching.stats().repeated, 0, "the poller does not even hand it over twice");
    }

    // ---- the schedule, with no clock and no network -----------------------------------------------

    fn devices(n: u8) -> Devices {
        (1..=n).map(|n| (fp(n), [n; DEVICE_SECRET_LEN])).collect()
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn new_devices_are_spread_over_the_interval_and_old_ones_keep_their_place() {
        let (t0, mut poller) = (Instant::now(), Poller::new(Schedule::default()));
        poller.set_devices(&devices(3), t0);
        let mut dues: Vec<Instant> = poller.groups.iter().map(|group| group.due).collect();
        dues.sort();
        assert_eq!(dues, [t0, t0 + secs(15), t0 + secs(30)], "a third of the 45 s interval apart");
        // The first is due at once; after it, the second is next.
        let (first, due) = poller.next(t0, None).unwrap();
        assert_eq!(due, t0);
        poller.finished(first, t0, t0 + secs(3));
        assert_eq!(poller.groups[first].due, t0 + secs(3) + secs(45));
        // Listing the devices again changes nothing for the ones that were there; a new one is due now.
        let before: Vec<_> = poller.groups.iter().map(|group| (group.key, group.due)).collect();
        poller.set_devices(&devices(4), t0 + secs(5));
        for (key, due) in before {
            assert_eq!(poller.groups.iter().find(|group| group.key == key).map(|group| group.due), Some(due));
        }
        assert!(poller.groups.iter().any(|group| group.due == t0 + secs(5)));
        // A device that is gone is dropped.
        poller.set_devices(&devices(2), t0 + secs(6));
        assert_eq!(poller.groups.len(), 2);
    }

    #[test]
    fn many_devices_stretch_the_interval_instead_of_crowding_the_lookups() {
        let (t0, mut poller) = (Instant::now(), Poller::new(Schedule::default()));
        poller.set_devices(&devices(5), t0);
        assert_eq!(poller.slow_interval(), secs(45), "five lookups three seconds apart fit in 45 s");
        poller.set_devices(&devices(30), t0);
        assert_eq!(poller.slow_interval(), secs(90), "thirty do not: 30 x 3 s");
        // Whatever is due, the next lookup is never sooner than the gap after the last one ended.
        poller.finished(0, t0, t0 + secs(2));
        let (_, due) = poller.next(t0 + secs(2), None).unwrap();
        assert!(due >= t0 + secs(5));
    }

    #[test]
    fn the_burst_pulls_one_device_forward_and_only_that_one() {
        let (t0, mut poller) = (Instant::now(), Poller::new(Schedule::default()));
        poller.set_devices(&devices(2), t0);
        for at in 0..2 {
            poller.finished(at, t0, t0 + secs(1));
        }
        let burst_member = poller.groups[1].members[0];
        // Quiet: the next lookup is the slow interval away, whoever it is for.
        let (_, slow) = poller.next(t0 + secs(2), None).unwrap();
        assert!(slow >= t0 + secs(40));
        // A device that just left is looked up every 8 s after its last lookup.
        let (at, soon) = poller.next(t0 + secs(2), Some(burst_member)).unwrap();
        assert_eq!(poller.groups[at].members[0], burst_member);
        assert_eq!(soon, t0 + secs(8));
        // And the burst only ever brings the due time closer.
        poller.groups[at].due = t0 + secs(5);
        assert_eq!(poller.next(t0 + secs(2), Some(burst_member)).unwrap().1, t0 + secs(5));
        // A device that was never looked up is looked up now.
        let mut fresh = Poller::new(Schedule::default());
        fresh.set_devices(&devices(1), t0 + secs(100));
        fresh.groups[0].due = t0 + secs(200);
        assert_eq!(fresh.next(t0 + secs(100), Some(fp(1))).unwrap().1, t0 + secs(100));
    }

    #[test]
    fn the_burst_is_for_the_device_that_connected_last_while_nobody_is_connected() {
        let (t0, schedule) = (Instant::now(), Schedule::default());
        let mut clients = ClientActivity::default();
        assert_eq!(burst_target(&clients, t0, &schedule), None, "nobody ever connected");
        clients.last_connect = Some((fp(1), t0));
        clients.connected = 1;
        assert_eq!(burst_target(&clients, t0, &schedule), None, "no disconnect yet");
        clients.last_disconnect = Some(t0 + secs(10));
        assert_eq!(burst_target(&clients, t0 + secs(11), &schedule), None, "somebody is still connected");
        clients.connected = 0;
        assert_eq!(burst_target(&clients, t0 + secs(11), &schedule), Some(fp(1)));
        assert_eq!(burst_target(&clients, t0 + secs(10) + secs(179), &schedule), Some(fp(1)));
        assert_eq!(burst_target(&clients, t0 + secs(10) + secs(180), &schedule), None, "three minutes are over");
    }

    #[test]
    fn what_is_wrong_with_an_item_is_said_once_per_device() {
        let (_, secret) = device_secret(1);
        let mut poller = Poller::new(Schedule::default());
        poller.set_devices(&[(fp(1), [1; DEVICE_SECRET_LEN])], Instant::now());
        let now = SystemTime::now();
        let (_, _, seq, value) = punch_item::build(&secret, "198.51.100.7:40000", 1, now + secs(3600)).unwrap();
        assert!(poller.open(0, &Found { value, seq }, now).is_none());
        assert!(poller.noted.contains(&(fp(1), "future")));
        let garbage = Found { value: vec![1, 2, 3], seq: seq + 1 };
        assert!(poller.open(0, &garbage, now).is_none());
        assert!(poller.noted.contains(&(fp(1), "damaged")));
        assert_eq!(poller.groups[0].newer_than, Some(seq + 1), "whatever it was, it is not asked for again");
        // A lower seq never moves it back.
        assert!(poller.open(0, &Found { value: vec![], seq: 1 }, now).is_none());
        assert_eq!(poller.groups[0].newer_than, Some(seq + 1));
    }
}
