//! Router port mapping and the host's public addresses (ticket E2); the plumbing it plugs into is `reach/mod.rs`,
//! which E2 does not edit.
//!
//! While standalone reach is on, [`run`] asks the router to forward the UDP port of the QUIC socket to this PC
//! (`velora_nat::mapping`: NAT-PMP first, UPnP second), keeps the mapping alive, and writes what it learns into
//! `ReachState`, which the rest of the host (the DHT record, `HostMsg::Reach`, the relay registration, the launcher)
//! reads:
//!
//! - `mapping`: the mapping the router granted, with `public: false` when its external address is not one the internet
//!   can reach (a private address, or one from 100.64.0.0/10, which a provider shares between customers: a second
//!   router or a CGNAT is in front). Such a mapping is shown, kept and not advertised.
//! - `Public`: the mapped `ip:port`, only when it is public. Nothing else puts an address there.
//! - `V6`: the global IPv6 addresses of this PC (the first of each interface) with the port of the socket, when the
//!   socket listens on IPv6 at all. They need no router, so they are listed whether or not one answered.
//!
//! The rules it follows:
//!
//! - **No router is a state, not an error.** Most home lines behind a CGNAT have neither UPnP nor NAT-PMP, and a
//!   router that is off or has them switched off is the same. The attempt fails, `mapping` and `Public` stay empty
//!   (which is how the launcher says "the router has not opened a port"), the reason is logged once at info for as
//!   long as it stays the same, and the next try comes after 1, 2, 4... up to 30 minutes. A tight loop is never
//!   possible: a mapping is renewed at half its lease, but not more often than every 10 seconds.
//! - **When.** At once at the start; to renew, at half the lease the router granted and at most every 30 minutes;
//!   when this PC's LAN address changes (a laptop moved: what the old router gave is withdrawn at once and a new
//!   mapping is asked for at once); after the machine slept (the router may have forgotten); and, for IPv6, every
//!   minute. A mapping that cannot be renewed is withdrawn from the state at once and asked for again after a
//!   minute. Nothing is asked while this PC has no network address. A move to a network that gives the same LAN
//!   address is not seen until the next renewal.
//! - **A public address is one that is public.** The router's external address is classified
//!   (`velora_nat::addresses`), and judged against the address the DHT nodes saw this PC at (`ReachState::observed`,
//!   E5's): a router that says it is at one address while the nodes see this PC at another has another NAT in front of
//!   it (a carrier that uses public-looking addresses, a full-tunnel VPN), and its mapping reaches only that far. A
//!   shared, a private or such an address is the CGNAT or double NAT case: logged at info once, shown with
//!   `public: false`, kept, not advertised. The nodes' word is weighed, not just obeyed, because E5 writes it on its
//!   own schedule and every change of `Public` makes E5 measure again. When they stop saying anything (E5 drops its
//!   measurement when a round learns nothing) the verdict stays as it was, also for the same address after the
//!   mapping was lost and made again. When they start to disagree with an address that was public, it is withdrawn
//!   at once and the router is asked what its address is now (the provider may have given this PC another one), but
//!   not more than once a minute. The address comes back only a minute after it was withdrawn, so that nodes whose
//!   answers keep changing cannot make it go back and forth (another address than the one that was withdrawn is
//!   judged anew, at once). For the few seconds after a move to another network, `observed` can still be the word
//!   about the network that was left: a mapping granted then can be taken for "another NAT in front" (one info line)
//!   until E5's new measurement judges it again, or drops the old word, which a verdict made of it does not survive
//!   (but only within 20 seconds of the move: later the word is taken for what it says, as it is also when it is
//!   measured again, and then silence changes nothing).
//! - **The old mapping is not given back on a move.** The request would go to the router of the network this PC is on
//!   now, which may hold a port of the same number for another computer (UPnP names no owner); the old router drops
//!   its mapping when the lease ends, and a conflict on the new one is B1's to settle with another port.
//! - **Stop.** What this task wrote is withdrawn first, then the latest mapping is given back (awaited here, for at
//!   most 3.8 seconds: the host waits 4), unless the network changed since it was made: E1 looks at the network every
//!   30 seconds, so the task looks once more first, for the reason a move does not give the port back. A router that
//!   does not answer the removal in time, or a stop that comes while a mapping is being asked for, leaves the mapping
//!   to its lease (an hour; a router that keeps only permanent mappings keeps it until the next run asks for the
//!   same port again).
//! - **A host that is not bound to every address maps nothing and lists nothing.** The router forwards to this PC's
//!   address towards it, which a socket bound to one address (the loopback, a VPN's, a second card's) may not take
//!   packets for, and an address nobody listens at would keep E4 from looking for a relay. The tests that switch
//!   standalone reach on through the runtime bind the loopback, and must not touch the router either.
//!
//! Every call into the library has its own limit (about 10 s at the worst), and this task adds one more, so that a
//! router that stays silent never holds it.

use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use tokio::{task::JoinHandle, time::Instant};
use velora_nat::{
    addresses::{classify, global_ipv6, AddressClass, GlobalV6},
    mapping::{self, Mapping, MappingError, MappingProtocol},
};
use velora_protocol::{control::MappingStatus, wire::AddressKind};

use super::{poll::BoxFuture, refresh_addresses, ReachContext};

/// How long the router is asked to keep a mapping; it is renewed long before.
const LEASE: Duration = Duration::from_secs(60 * 60);

/// How much more time the wall clock may count between two looks than the monotonic one before the machine is taken
/// to have slept: clocks differ by a second or so, and a step of a minute is not worth a request to the router.
const SLEPT: Duration = Duration::from_secs(120);

/// How often things happen. The product's values are the `Default`; the tests use others.
#[derive(Debug, Clone, Copy)]
struct Timing {
    /// How long the router is asked to keep a mapping.
    lease: Duration,
    /// A mapping is renewed at half its lease, but at least this often...
    renew_cap: Duration,
    /// ...and at most this often: a router that grants a lease of a second or two is not asked every second.
    renew_floor: Duration,
    /// After a failure the next try waits this long, twice as long after each further one...
    retry: Duration,
    /// ...up to this.
    retry_max: Duration,
    /// The IPv6 addresses of this PC (and its LAN address) are looked at again this often.
    look_again: Duration,
    /// After a change of network the DHT nodes' last word can be about the network that was left for this long: E5
    /// measures again two seconds after it sees the change, in a round of up to three.
    stale_for: Duration,
    /// How long giving the port back may take when the task is told to stop: the host waits 4 seconds for it.
    remove_limit: Duration,
    /// A call into the library that takes longer than this is a failure (the library has its own limits; this is the
    /// one that cannot be forgotten).
    call_limit: Duration,
    /// The wall clock in Unix seconds, to notice that the machine slept.
    wall: fn() -> u64,
}

impl Default for Timing {
    fn default() -> Self {
        Timing {
            lease: LEASE,
            renew_cap: Duration::from_secs(30 * 60),
            renew_floor: Duration::from_secs(10),
            retry: Duration::from_secs(60),
            retry_max: Duration::from_secs(30 * 60),
            look_again: Duration::from_secs(60),
            stale_for: Duration::from_secs(20),
            remove_limit: Duration::from_millis(3800),
            call_limit: Duration::from_secs(30),
            wall: unix_now,
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs())
}

/// Whether the machine slept between two looks, which the monotonic clock (`monotonic` long) did not count and the
/// wall clock (`wall` seconds) did.
fn slept(monotonic: Duration, wall: u64) -> bool {
    Duration::from_secs(wall) > monotonic + SLEPT
}

// ---------------------------------------------------------------------------------------------
// The router and the network cards, as far as this task is concerned
// ---------------------------------------------------------------------------------------------

/// What the task asks of the world: `System` is the real one, and the tests put a fake in its place.
trait Environment: Send + Sync {
    fn map(&self, port: u16, lease: Duration) -> BoxFuture<'_, Result<Mapping, MappingError>>;
    fn renew<'a>(&'a self, mapping: &'a Mapping) -> BoxFuture<'a, Result<Mapping, MappingError>>;
    fn remove<'a>(&'a self, mapping: &'a Mapping) -> BoxFuture<'a, Result<(), MappingError>>;
    /// The global IPv6 addresses of this PC, best first, as `velora_nat::addresses::global_ipv6` lists them (`None`:
    /// they cannot be told now).
    fn global_v6(&self) -> BoxFuture<'_, Option<Vec<GlobalV6>>>;
    /// Looks at this PC's LAN address again and records it in the state, as E1's housekeeping does every 30 seconds.
    fn refresh_lan<'a>(&'a self, ctx: &'a ReachContext) -> BoxFuture<'a, ()>;
}

/// This PC and its router.
struct System {
    /// What walks through the network cards: `global_ipv6`.
    walk: fn() -> Vec<GlobalV6>,
    /// The walk that is under way, if one is. A look that gives up on it leaves it here, and no other walk starts until
    /// it ends: one that never comes back costs one thread, not one a minute, and is not waited for again.
    walking: tokio::sync::Mutex<Option<JoinHandle<Vec<GlobalV6>>>>,
}

impl System {
    fn new(walk: fn() -> Vec<GlobalV6>) -> System {
        System { walk, walking: tokio::sync::Mutex::new(None) }
    }
}

impl Environment for System {
    fn map(&self, port: u16, lease: Duration) -> BoxFuture<'_, Result<Mapping, MappingError>> {
        // The same external port as the local one: addresses already stored in paired devices stay valid.
        Box::pin(mapping::map_udp(port, port, lease))
    }

    fn renew<'a>(&'a self, held: &'a Mapping) -> BoxFuture<'a, Result<Mapping, MappingError>> {
        Box::pin(mapping::renew(held))
    }

    fn remove<'a>(&'a self, held: &'a Mapping) -> BoxFuture<'a, Result<(), MappingError>> {
        Box::pin(mapping::remove(held))
    }

    fn global_v6(&self) -> BoxFuture<'_, Option<Vec<GlobalV6>>> {
        Box::pin(async move {
            // A walk through the adapters is a system call: off the async threads, and never two at a time.
            let mut walking = self.walking.lock().await;
            if walking.as_ref().is_some_and(|walk| !walk.is_finished()) {
                // The last one was given up on and is still going: not another one, and not waiting for it again.
                return None;
            }
            // A walk that was given up on and has ended since is as good as a new one, and ready at once.
            let walk = walking.get_or_insert_with(|| tokio::task::spawn_blocking(self.walk));
            let found = walk.await.ok();
            *walking = None;
            found
        })
    }

    fn refresh_lan<'a>(&'a self, ctx: &'a ReachContext) -> BoxFuture<'a, ()> {
        Box::pin(refresh_addresses(ctx))
    }
}

// ---------------------------------------------------------------------------------------------
// What is made known
// ---------------------------------------------------------------------------------------------

/// A mapping the router granted, and what is made of it.
struct Held {
    mapping: Mapping,
    verdict: Verdict,
    /// When the router is asked to renew it.
    renew_at: Instant,
}

/// What is made of the external address a router reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// An address the internet can reach, and (when the DHT nodes have seen this PC) the one they saw it at.
    Public,
    /// A private address, or one a provider shares between customers: a second router or a CGNAT is in front.
    Shared,
    /// A public-looking address, but the DHT nodes see this PC at another one: another NAT is in front all the same.
    Elsewhere(IpAddr),
}

impl Verdict {
    fn is_public(self) -> bool {
        self == Verdict::Public
    }
}

/// Judges the external address a router reports: by its class, and against the address the DHT nodes saw this PC at
/// when they have (`seen`, E5's, which is only ever a global one). A router that says it is at one address while the
/// nodes see this PC at another has another NAT in front of it, and its mapping reaches only that far. `before` is
/// what was made of this same address until now.
fn judge(external: IpAddr, seen: Option<SocketAddr>, before: Option<Verdict>) -> Verdict {
    if !classify(external).is_global() {
        return Verdict::Shared;
    }
    match seen {
        Some(seen) if seen.ip().to_canonical() != external.to_canonical() => {
            Verdict::Elsewhere(seen.ip().to_canonical())
        }
        Some(_) => Verdict::Public,
        // The nodes say nothing: E5 drops its measurement when a round learns nothing, which is no news about the
        // NAT, so what was made of this address stays.
        None => before.unwrap_or(Verdict::Public),
    }
}

/// Whether `verdict` was made of `word`, the DHT nodes' word.
fn made_of(verdict: Verdict, word: SocketAddr) -> bool {
    matches!(verdict, Verdict::Elsewhere(ip) if ip == word.ip().to_canonical())
}

/// What the task has made of the router's external address so far, and how fast it may change its mind.
struct Opinion {
    /// What was last made of an external address: it stays when the mapping is lost and made again.
    known: Option<(IpAddr, Verdict)>,
    /// Until then the DHT nodes' word does not bring a withdrawn address back, nor send the router another question:
    /// nodes whose answers keep changing would make `Public` go back and forth, and every change of it makes E5
    /// measure again.
    quiet_until: Instant,
    /// The word the DHT nodes had said when the network last changed, and until when it can still be about the network
    /// that was left. A verdict made of it is not kept for lack of news; once it is measured again (the word changes or
    /// is dropped) or is old enough, it is taken for what it says.
    left: Option<(SocketAddr, Instant)>,
}

/// What [`Opinion::consider`] makes of an address.
#[derive(Debug, PartialEq, Eq)]
struct Considered {
    verdict: Verdict,
    /// The nodes just contradicted an address that was public: the router is asked at once what its address is now.
    ask_router: bool,
    /// A return to public that is held back until then.
    settles_at: Option<Instant>,
}

impl Opinion {
    fn new(now: Instant) -> Opinion {
        Opinion { known: None, quiet_until: now, left: None }
    }

    /// The network changed: what was made of the old router's address is of no use, and what the nodes said (`seen`)
    /// may have been about the network that was left.
    fn moved(&mut self, seen: Option<SocketAddr>, now: Instant, timing: &Timing) {
        *self = Opinion { known: None, quiet_until: now, left: seen.map(|word| (word, now + timing.stale_for)) };
    }

    /// The verdict on `external` now that the nodes say `seen`. A change to "not public" is made at once; a change
    /// back waits until the quiet minute that follows a withdrawal is over; another address than the one last judged
    /// is judged anew, at once.
    fn consider(&mut self, external: IpAddr, seen: Option<SocketAddr>, now: Instant, timing: &Timing) -> Considered {
        let before = self.known.filter(|(ip, _)| *ip == external).map(|(_, verdict)| verdict);
        // For lack of news what was made stays, unless it was made of a word that may be about the network left.
        let left = self.left.filter(|&(_, until)| now < until).map(|(word, _)| word);
        let kept = before.filter(|&verdict| !left.is_some_and(|word| made_of(verdict, word)));
        let judged = judge(external, seen, kept);
        // Measured again, dropped, or old enough: the word is about this network from now on.
        if left.is_none_or(|word| seen != Some(word)) {
            self.left = None;
        }
        let mut considered = Considered { verdict: judged, ask_router: false, settles_at: None };
        match before {
            Some(before) if judged.is_public() && !before.is_public() && now < self.quiet_until => {
                // Withdrawn a moment ago: it comes back when the minute is up, if the nodes still agree.
                considered.verdict = before;
                considered.settles_at = Some(self.quiet_until);
            }
            Some(before) if before.is_public() && !judged.is_public() => {
                // The provider may have given this PC another address since the router said which.
                considered.ask_router = now >= self.quiet_until;
                self.quiet_until = now + timing.retry;
            }
            _ => {}
        }
        self.known = Some((external, considered.verdict));
        considered
    }
}

fn status_of(held: &Held) -> MappingStatus {
    MappingStatus {
        protocol: match held.mapping.protocol {
            MappingProtocol::NatPmp => "natpmp",
            MappingProtocol::Upnp => "upnp",
        }
        .to_string(),
        external: held.mapping.external_addr().to_string(),
        public: held.verdict.is_public(),
        lease_secs: held.mapping.lease.as_secs(),
    }
}

/// Writes the mapping and the public address it gives (none when there is no mapping, or it is not public).
fn show(ctx: &ReachContext, held: Option<&Held>) {
    let status = held.map(status_of);
    let public: Vec<String> = held
        .filter(|held| held.verdict.is_public())
        .map(|held| held.mapping.external_addr().to_string())
        .into_iter()
        .collect();
    ctx.reach.update(|state| {
        state.mapping = status;
        state.set_addresses(AddressKind::Public, public);
    });
}

/// The addresses to list: the first of each interface (the list is best first).
fn first_of_each_interface(found: &[GlobalV6]) -> Vec<Ipv6Addr> {
    let mut seen = Vec::new();
    found
        .iter()
        .filter(|address| {
            let new = !seen.contains(&address.interface);
            seen.push(address.interface);
            new
        })
        .map(|address| address.addr)
        .collect()
}

/// Whether a socket bound to `local` takes packets for the IPv6 addresses of this PC: a dual-stack (or IPv6) socket
/// bound to the unspecified address does; one bound to IPv4 does not, and one bound to a single address takes only
/// that one.
fn listens_on_ipv6(local: SocketAddr) -> bool {
    local.is_ipv6() && local.ip().is_unspecified()
}

/// Whether the router's forwarding reaches a socket bound to `local`: it sends to this PC's address towards the router
/// (`velora_nat::mapping`), which only a socket bound to every address is sure to take packets for. One bound to a
/// single address (the loopback, a VPN's, a second card's) may not, and an address nobody listens at is worse than
/// none.
fn takes_forwarded_packets(local: SocketAddr) -> bool {
    local.ip().is_unspecified()
}

/// Takes what the task made known out of the state again, however the task ends (aborted included).
struct Shown<'a>(&'a ReachContext);

impl Drop for Shown<'_> {
    fn drop(&mut self) {
        self.0.reach.update(|state| {
            state.mapping = None;
            state.set_addresses(AddressKind::Public, Vec::new());
            state.set_addresses(AddressKind::V6, Vec::new());
        });
    }
}

/// What was last said in the log, so that each thing is said once while it stays so (a renewal that gives the same
/// address is no news, and neither is the fifth failure in a row).
#[derive(Default)]
struct Said(Option<String>);

impl Said {
    fn once(&mut self, key: String, say: impl FnOnce()) {
        if self.0.as_deref() != Some(key.as_str()) {
            say();
            self.0 = Some(key);
        }
    }
}

/// Why the router did not do it, in the words of the log: both protocols' reasons, without the library's wrapping.
fn reasons(e: &MappingError) -> String {
    match e {
        MappingError::Failed { natpmp, upnp } => format!("NAT-PMP: {natpmp}; UPnP: {upnp}"),
        other => other.to_string(),
    }
}

/// Why an external address is not advertised, in words.
fn why_not_public(ip: IpAddr) -> &'static str {
    match classify(ip) {
        AddressClass::Shared => "an address the provider shares between customers (a CGNAT)",
        AddressClass::Private => "a private address (a second router is in front)",
        _ => "not an address the internet can reach",
    }
}

// ---------------------------------------------------------------------------------------------
// The task
// ---------------------------------------------------------------------------------------------

/// The mapping task. Started when standalone reach is on (at host start if it was saved on, or when the user turns
/// it on); it ends when `ctx.stop` fires, which is when the switch goes off or the host shuts down, and the host waits
/// a few seconds for it to return.
///
/// It maps `ctx.port()` on the router (`velora_nat::mapping`) at start and then before the lease ends (every 30
/// minutes at most), judges the external address (`velora_nat::addresses::classify`: private or shared means CGNAT or
/// double NAT and is not advertised), and writes what it found to `ctx.reach`: see the module docs for what, when and
/// why. A router that does not answer is not an error: it is logged, waited out with a backoff and tried again. It
/// never returns an `Err`: nothing it meets is something that trying again cannot fix.
pub async fn run(ctx: ReachContext) -> Result<()> {
    run_on(&ctx, &System::new(global_ipv6), Timing::default()).await;
    Ok(())
}

/// [`run`] on an environment of its own, which is how the tests keep it away from the router.
async fn run_on(ctx: &ReachContext, env: &dyn Environment, timing: Timing) {
    let local = ctx.socket.local_addr();
    if !takes_forwarded_packets(local) {
        tracing::info!(
            "the host is bound to {local}, not to every address: no port is mapped on the router and no IPv6 address \
             is listed"
        );
        ctx.stop.stopped().await;
        return;
    }
    serve(ctx, env, timing, local).await;
}

/// A call into the environment that is given up on after `limit` or when the task is told to stop: `None` then.
async fn calling<T>(
    ctx: &ReachContext,
    limit: Duration,
    call: impl std::future::Future<Output = T>,
) -> Option<Result<T, ()>> {
    tokio::select! {
        outcome = tokio::time::timeout(limit, call) => Some(outcome.map_err(|_| ())),
        () = ctx.stop.stopped() => None,
    }
}

/// The loop of [`run`] for a socket bound to `local`.
async fn serve(ctx: &ReachContext, env: &dyn Environment, timing: Timing, local: SocketAddr) {
    let _shown = Shown(ctx);
    let port = ctx.port();
    let mut changes = ctx.reach.subscribe();
    let mut said = Said::default();

    let mut held: Option<Held> = None;
    let mut opinion = Opinion::new(Instant::now());
    let (mut failures, mut retry_at) = (0u32, Instant::now());
    let mut lan = lan_of(ctx);
    let mut v6_at = Instant::now();
    let (mut looked_at, mut wall_then) = (Instant::now(), (timing.wall)());

    loop {
        if ctx.stop.is_stopped() {
            break;
        }
        let now = Instant::now();

        // The monotonic clock may stand still while the machine sleeps, the wall clock does not: the router may have
        // forgotten the mapping, and the network may be another one.
        let wall = (timing.wall)();
        if slept(now.saturating_duration_since(looked_at), wall.saturating_sub(wall_then)) {
            tracing::debug!("the machine slept: asking the router again");
            match &mut held {
                Some(held) => held.renew_at = now,
                None => (retry_at, failures) = (now, 0),
            }
            v6_at = now;
        }
        (looked_at, wall_then) = (now, wall);

        // A move to another network: what the old router gave, and what was made of its address, is of no use here.
        let current = lan_of(ctx);
        if current != lan {
            lan = current;
            failures = 0;
            retry_at = now;
            v6_at = now;
            said = Said::default();
            opinion.moved(ctx.reach.read().observed, now, &timing);
            // What the old router gave is of no use here, and giving it back is not ours to ask: the request would go
            // to the router of the network this PC is on now, which may hold a port of the same number for another
            // computer. The old router drops its mapping when the lease ends.
            if held.take().is_some() {
                show(ctx, None);
            }
        }

        // What the DHT nodes saw this PC at can come after the mapping, or change (E5 measures again after a move, and
        // every ten minutes): the mapping is judged again whenever it does.
        let mut settle_at = None;
        if let Some(mapped) = held.as_mut() {
            let seen = ctx.reach.read().observed;
            let considered = opinion.consider(mapped.mapping.external_ip, seen, now, &timing);
            settle_at = considered.settles_at;
            if considered.verdict != mapped.verdict {
                mapped.verdict = considered.verdict;
                tell(&mapped.mapping, mapped.verdict, &mut said);
                show(ctx, Some(&*mapped));
                if considered.ask_router {
                    mapped.renew_at = now;
                }
            }
        }

        // The IPv6 addresses: no router needed.
        if now >= v6_at {
            v6_at = now + timing.look_again;
            match calling(ctx, timing.call_limit, env.global_v6()).await {
                None => break,
                // Not knowing is not "there are none": what is listed stays until the next look.
                Some(Err(())) | Some(Ok(None)) => {}
                Some(Ok(Some(found))) => {
                    let listed: Vec<String> = if listens_on_ipv6(local) {
                        first_of_each_interface(&found)
                            .into_iter()
                            .map(|addr| SocketAddr::new(addr.into(), port).to_string())
                            .collect()
                    } else {
                        Vec::new()
                    };
                    ctx.reach.update(|state| state.set_addresses(AddressKind::V6, listed));
                }
            }
        }

        // The mapping: made when there is none and its time has come, renewed when its time has come. Nothing is asked
        // while this PC has no network.
        if !lan.is_empty() {
            let due_for_renewal = held.as_ref().filter(|held| now >= held.renew_at).map(|held| held.mapping.clone());
            if held.is_none() && now >= retry_at {
                match calling(ctx, timing.call_limit, env.map(port, timing.lease)).await {
                    None => break,
                    Some(Ok(Ok(mapping))) if mapping.external_port != 0 => {
                        failures = 0;
                        held = Some(granted(ctx, &mut opinion, mapping, &timing, &mut said));
                        show(ctx, held.as_ref());
                    }
                    Some(failed) => {
                        failures = failures.saturating_add(1);
                        let wait = backoff(&timing, failures);
                        retry_at = Instant::now() + wait;
                        let why = match failed {
                            Ok(Err(e)) => reasons(&e),
                            Ok(Ok(_)) => "the router granted port 0".to_string(),
                            Err(()) => "the router did not answer in time".to_string(),
                        };
                        said.once(format!("no router {why}"), || {
                            tracing::info!(
                                "no router opened UDP port {port} ({why}): this PC is not reachable from outside \
                                 through the router; asking again in {wait:?}"
                            )
                        });
                        show(ctx, None);
                    }
                }
            } else if let Some(current) = due_for_renewal {
                match calling(ctx, timing.call_limit, env.renew(&current)).await {
                    None => break,
                    Some(Ok(Ok(mapping))) if mapping.external_port != 0 => {
                        held = Some(granted(ctx, &mut opinion, mapping, &timing, &mut said));
                        show(ctx, held.as_ref());
                    }
                    Some(lost) => {
                        // Whatever the router had is probably gone (it restarted, or this PC is somewhere else).
                        held = None;
                        failures = 1;
                        let wait = backoff(&timing, failures);
                        retry_at = Instant::now() + wait;
                        let why = match lost {
                            Ok(Err(e)) => reasons(&e),
                            Ok(Ok(_)) => "the router granted port 0".to_string(),
                            Err(()) => "no answer in time".to_string(),
                        };
                        said.once(format!("lost {why}"), || {
                            tracing::info!(
                                "the router no longer renews the mapping ({why}): the address is withdrawn, asking \
                                 again in {wait:?}"
                            )
                        });
                        show(ctx, None);
                    }
                }
            }
        }

        // Until something is due, or the state changes (a new LAN address), or the task is told to stop.
        let mapping_due =
            if lan.is_empty() { None } else { Some(held.as_ref().map_or(retry_at, |held| held.renew_at)) };
        let wake = mapping_due.into_iter().chain(settle_at).fold(v6_at, Instant::min);
        tokio::select! {
            () = ctx.stop.stopped() => break,
            () = tokio::time::sleep_until(wake) => {}
            changed = changes.changed() => if changed.is_err() { break },
        }
    }

    // Told to stop: no longer advertised from here on, and the port is given back for as long as the host waits.
    show(ctx, None);
    if let Some(held) = held.take() {
        let giving_back = async {
            // E1 looks at the network every 30 seconds, and the host may have moved since: the request would go to
            // the router of the network this PC is on now, which is not the one that has the mapping.
            env.refresh_lan(ctx).await;
            if lan_of(ctx) != lan {
                return None;
            }
            Some(env.remove(&held.mapping).await)
        };
        match tokio::time::timeout(timing.remove_limit, giving_back).await {
            Ok(Some(Ok(()))) => tracing::debug!("the mapping of UDP port {port} was given back"),
            Ok(Some(Err(e))) => {
                tracing::info!("could not give the mapped port back ({e}): the router may keep it until its lease ends")
            }
            Ok(None) => tracing::info!(
                "this PC is on another network than the one that mapped UDP port {port}: the router that has it drops \
                 it when its lease ends"
            ),
            Err(_) => tracing::info!("the router did not answer in time when the mapped port was given back"),
        }
    }
}

/// The mapping the router granted, judged, and what is said of it.
fn granted(ctx: &ReachContext, opinion: &mut Opinion, mapping: Mapping, timing: &Timing, said: &mut Said) -> Held {
    let seen = ctx.reach.read().observed;
    let verdict = opinion.consider(mapping.external_ip, seen, Instant::now(), timing).verdict;
    tell(&mapping, verdict, said);
    let wait = mapping.renew_after().max(timing.renew_floor).min(timing.renew_cap);
    Held { mapping, verdict, renew_at: Instant::now() + wait }
}

/// Says what was made of a mapping, once while it stays so.
fn tell(mapping: &Mapping, verdict: Verdict, said: &mut Said) {
    let external = mapping.external_addr();
    match verdict {
        Verdict::Public => said.once(format!("public {external}"), || {
            tracing::info!(
                "reachable from outside at {external} (port mapped by {}, lease {} s)",
                mapping.protocol,
                mapping.lease.as_secs()
            )
        }),
        Verdict::Shared => said.once(format!("shared {}", mapping.external_ip), || {
            tracing::info!(
                "the router's external address {} is {}: the mapped port ({external}) is not advertised",
                mapping.external_ip,
                why_not_public(mapping.external_ip)
            )
        }),
        Verdict::Elsewhere(seen) => said.once(format!("elsewhere {external} {seen}"), || {
            tracing::info!(
                "the router says its external address is {}, but the DHT nodes see this PC at {seen}: another NAT is \
                 in front, so the mapped port ({external}) is not advertised",
                mapping.external_ip
            )
        }),
    }
}

/// How long the next try waits after `failures` failures in a row.
fn backoff(timing: &Timing, failures: u32) -> Duration {
    let doublings = failures.saturating_sub(1).min(16);
    timing.retry.saturating_mul(1 << doublings).min(timing.retry_max)
}

/// This PC's LAN address as the host lists it (E1 keeps it up to date): what changes when the network does.
fn lan_of(ctx: &ReachContext) -> Vec<String> {
    ctx.reach.read().addresses_of(&AddressKind::Lan)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{
            atomic::{AtomicBool, AtomicU64, Ordering},
            Arc, Mutex,
        },
    };

    use tokio::{sync::watch, task::JoinHandle};
    use velora_protocol::{tls::Fingerprint, wire::HostMsg};

    use super::*;
    use crate::reach::{
        self, lock, punch,
        testing::{self, Scratch},
        ReachState, Stop,
    };

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    /// An address the internet can reach, as far as `classify` is concerned: the ranges set aside for documentation are
    /// not (it says "other"), so the tests of a public address use one that is well known and nobody's in particular.
    const PUBLIC: &str = "8.8.4.4";

    /// A mapping as a router would grant it.
    fn granted_at(ip: &str, port: u16, lease: u64, protocol: MappingProtocol) -> Mapping {
        Mapping {
            protocol,
            local_port: 7420,
            external_ip: ip.parse().unwrap(),
            external_port: port,
            lease: secs(lease),
        }
    }

    fn natpmp(port: u16) -> Mapping {
        granted_at(PUBLIC, port, 3600, MappingProtocol::NatPmp)
    }

    fn no_router() -> MappingError {
        MappingError::Failed { natpmp: "no answer within 5s".into(), upnp: "no UPnP router found".into() }
    }

    #[derive(Clone)]
    enum Call {
        Map { at: Instant, port: u16, lease: Duration },
        Renew { at: Instant, of: Mapping },
        Remove { at: Instant, of: Mapping },
    }

    impl Call {
        fn at(&self) -> Instant {
            match self {
                Call::Map { at, .. } | Call::Renew { at, .. } | Call::Remove { at, .. } => *at,
            }
        }
    }

    #[derive(Clone)]
    enum Reply {
        Mapped(Mapping),
        NoRouter,
        /// No router, for a reason of the test's own words.
        Failed(&'static str),
        Hangs,
    }

    /// A router and the network cards of this PC, answering as told: a request with no reply left to it fails (nobody
    /// answers), except that a renewal is granted as it is asked for.
    struct Fake {
        calls: Mutex<Vec<Call>>,
        maps: Mutex<VecDeque<Reply>>,
        renewals: Mutex<VecDeque<Reply>>,
        removal_hangs: AtomicBool,
        removal_fails: AtomicBool,
        v6: Mutex<Vec<GlobalV6>>,
        v6_hangs: AtomicBool,
        /// The IPv6 look cannot tell (a walk through the cards that is stuck).
        v6_unknown: AtomicBool,
        /// The LAN address E1's housekeeping finds when it looks again; `None`: what the state says is right.
        lan_now: Mutex<Option<Vec<String>>>,
        /// How long a renewal takes to be answered.
        renew_delay: Mutex<Duration>,
        count: watch::Sender<usize>,
    }

    impl Fake {
        fn new() -> Arc<Fake> {
            Arc::new(Fake {
                calls: Mutex::default(),
                maps: Mutex::default(),
                renewals: Mutex::default(),
                removal_hangs: AtomicBool::new(false),
                removal_fails: AtomicBool::new(false),
                v6: Mutex::default(),
                v6_hangs: AtomicBool::new(false),
                v6_unknown: AtomicBool::new(false),
                lan_now: Mutex::default(),
                renew_delay: Mutex::default(),
                count: watch::channel(0).0,
            })
        }

        fn renewals_take(&self, delay: Duration) {
            *lock(&self.renew_delay) = delay;
        }

        /// This PC is on another network than E1's housekeeping has noticed yet: its next look finds `lan`.
        fn network_is_now(&self, lan: Option<&str>) {
            *lock(&self.lan_now) = Some(lan.map(String::from).into_iter().collect());
        }

        fn will_map(&self, reply: Reply) {
            lock(&self.maps).push_back(reply);
        }

        fn will_renew(&self, reply: Reply) {
            lock(&self.renewals).push_back(reply);
        }

        fn has_ipv6(&self, found: &[(&str, u32)]) {
            *lock(&self.v6) = found
                .iter()
                .map(|(addr, interface)| GlobalV6 {
                    addr: addr.parse().unwrap(),
                    interface: *interface,
                    valid_for: None,
                })
                .collect();
        }

        fn calls(&self) -> Vec<Call> {
            lock(&self.calls).clone()
        }

        fn note(&self, call: Call) {
            lock(&self.calls).push(call);
            self.count.send_modify(|calls| *calls += 1);
        }

        /// Waits until `n` requests were made. On the paused clock that costs no time, and a task that never gets there
        /// is a failure after a virtual day.
        async fn until(&self, n: usize) {
            let mut count = self.count.subscribe();
            tokio::time::timeout(secs(24 * 3600), count.wait_for(|calls| *calls >= n))
                .await
                .expect("the task made the requests in time")
                .expect("the fake is alive");
        }
    }

    impl Environment for Fake {
        fn map(&self, port: u16, lease: Duration) -> BoxFuture<'_, Result<Mapping, MappingError>> {
            Box::pin(async move {
                self.note(Call::Map { at: Instant::now(), port, lease });
                let reply = lock(&self.maps).pop_front().unwrap_or(Reply::NoRouter);
                match reply {
                    Reply::Mapped(mapping) => Ok(mapping),
                    Reply::NoRouter => Err(no_router()),
                    Reply::Failed(why) => Err(MappingError::Failed { natpmp: why.into(), upnp: "-".into() }),
                    Reply::Hangs => std::future::pending().await,
                }
            })
        }

        fn renew<'a>(&'a self, held: &'a Mapping) -> BoxFuture<'a, Result<Mapping, MappingError>> {
            Box::pin(async move {
                self.note(Call::Renew { at: Instant::now(), of: held.clone() });
                let delay = *lock(&self.renew_delay);
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let reply = lock(&self.renewals).pop_front();
                match reply {
                    None => Ok(held.clone()),
                    Some(Reply::Mapped(mapping)) => Ok(mapping),
                    Some(Reply::NoRouter) => Err(no_router()),
                    Some(Reply::Failed(why)) => Err(MappingError::Failed { natpmp: why.into(), upnp: "-".into() }),
                    Some(Reply::Hangs) => std::future::pending().await,
                }
            })
        }

        fn remove<'a>(&'a self, held: &'a Mapping) -> BoxFuture<'a, Result<(), MappingError>> {
            Box::pin(async move {
                self.note(Call::Remove { at: Instant::now(), of: held.clone() });
                if self.removal_hangs.load(Ordering::SeqCst) {
                    std::future::pending().await
                } else if self.removal_fails.load(Ordering::SeqCst) {
                    Err(MappingError::RemoveFailed { protocol: held.protocol, reason: "refused".into() })
                } else {
                    Ok(())
                }
            })
        }

        fn global_v6(&self) -> BoxFuture<'_, Option<Vec<GlobalV6>>> {
            Box::pin(async move {
                if self.v6_hangs.load(Ordering::SeqCst) {
                    std::future::pending().await
                } else if self.v6_unknown.load(Ordering::SeqCst) {
                    None
                } else {
                    Some(lock(&self.v6).clone())
                }
            })
        }

        fn refresh_lan<'a>(&'a self, ctx: &'a ReachContext) -> BoxFuture<'a, ()> {
            Box::pin(async move {
                let found = lock(&self.lan_now).clone();
                if let Some(lan) = found {
                    ctx.reach.update(|state| state.set_addresses(AddressKind::Lan, lan));
                }
            })
        }
    }

    /// A host on a loopback socket (or one said to be dual-stack) with the task running on a fake.
    struct Rig {
        ctx: ReachContext,
        _scratch: Scratch,
        fake: Arc<Fake>,
        stop: watch::Sender<bool>,
        task: JoinHandle<()>,
    }

    const LAN: &str = "192.0.2.10:7420";

    impl Rig {
        async fn start(fake: Arc<Fake>) -> Rig {
            Rig::start_with(Timing::default(), fake, Some(LAN), false).await
        }

        /// `lan`: the LAN address E1's housekeeping has found, if any; `dual_stack`: the socket is bound to `[::]`.
        async fn start_with(timing: Timing, fake: Arc<Fake>, lan: Option<&str>, dual_stack: bool) -> Rig {
            Rig::start_after(timing, fake, lan, dual_stack, |_| {}).await
        }

        /// [`Rig::start_with`], with `before` run on the host before the task starts.
        async fn start_after(
            timing: Timing,
            fake: Arc<Fake>,
            lan: Option<&str>,
            dual_stack: bool,
            before: impl FnOnce(&ReachContext),
        ) -> Rig {
            let (ctx, scratch) = testing::context("e2");
            // The context's socket is on the loopback; what the task is told about it is what the test needs, so that
            // the IPv6 cases do not depend on the machine having dual-stack sockets.
            let local = if dual_stack {
                SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), ctx.port())
            } else {
                ctx.socket.local_addr()
            };
            let (stop, stopped) = watch::channel(false);
            let ctx = ReachContext { stop: Stop::new(stopped), ..ctx };
            if let Some(lan) = lan {
                ctx.reach.update(|state| state.set_addresses(AddressKind::Lan, vec![lan.into()]));
            }
            before(&ctx);
            let task = tokio::spawn({
                let (ctx, fake) = (ctx.clone(), fake.clone());
                async move { serve(&ctx, fake.as_ref(), timing, local).await }
            });
            Rig { ctx, _scratch: scratch, fake, stop, task }
        }

        /// Waits until the state is what `done` says.
        async fn until_state(&self, what: &str, done: impl Fn(&ReachState) -> bool) {
            let mut changes = self.ctx.reach.subscribe();
            let waiting = async {
                loop {
                    if done(&self.ctx.reach.read()) {
                        return;
                    }
                    if changes.changed().await.is_err() {
                        return;
                    }
                }
            };
            if tokio::time::timeout(secs(24 * 3600), waiting).await.is_err() {
                panic!("timed out waiting for {what}");
            }
        }

        fn state(&self) -> ReachState {
            self.ctx.reach.read().clone()
        }

        fn lan_changes_to(&self, lan: Option<&str>) {
            let lan: Vec<String> = lan.map(String::from).into_iter().collect();
            self.ctx.reach.update(|state| state.set_addresses(AddressKind::Lan, lan));
        }

        /// Tells the task to stop and waits for it to return.
        async fn finish(self) {
            self.stop.send(true).unwrap();
            self.task.await.unwrap();
        }
    }

    /// `actual` is `expected`, give or take the millisecond a timer rounds up to.
    fn near(actual: Duration, expected: Duration) {
        assert!(actual >= expected && actual < expected + ms(100), "{actual:?}, not {expected:?}");
    }

    fn public_of(state: &ReachState) -> Vec<String> {
        state.addresses_of(&AddressKind::Public)
    }

    // === what the router grants, and what is made of it ===

    #[tokio::test(start_paused = true)]
    async fn a_mapping_the_router_grants_is_advertised_shown_and_sent_to_the_devices() {
        let fake = Fake::new();
        fake.will_map(Reply::Mapped(natpmp(51820)));
        let rig = Rig::start(fake).await;
        rig.until_state("the mapping", |state| state.mapping.is_some()).await;

        let state = rig.state();
        let shown = MappingStatus {
            protocol: "natpmp".into(),
            external: format!("{PUBLIC}:51820"),
            public: true,
            lease_secs: 3600,
        };
        assert_eq!(state.mapping, Some(shown.clone()));
        assert_eq!(public_of(&state), [format!("{PUBLIC}:51820")]);
        // In the status the launcher shows...
        let status = state.status();
        assert_eq!((status.mapping, status.public), (Some(shown), vec![format!("{PUBLIC}:51820")]));
        // ...and in the `Reach` a device that connects is sent.
        let HostMsg::Reach { addresses, .. } = reach::reach_message(&rig.ctx, &Fingerprint([1; 32])) else {
            panic!("a Reach message")
        };
        assert!(addresses.contains(&(AddressKind::Public, format!("{PUBLIC}:51820"))), "{addresses:?}");
        // It was asked for the port the socket is bound to, for an hour, and at once.
        let calls = rig.fake.calls();
        assert!(matches!(calls[0], Call::Map { port, lease, .. } if port == rig.ctx.port() && lease == secs(3600)));
        assert_eq!(calls.len(), 1);
        rig.finish().await;
    }

    #[tokio::test(start_paused = true)]
    async fn the_protocol_the_router_answered_is_named_for_the_launcher() {
        for (protocol, name) in [(MappingProtocol::NatPmp, "natpmp"), (MappingProtocol::Upnp, "upnp")] {
            let fake = Fake::new();
            fake.will_map(Reply::Mapped(granted_at(PUBLIC, 51820, 1800, protocol)));
            let rig = Rig::start(fake).await;
            rig.until_state("the mapping", |state| state.mapping.is_some()).await;
            assert_eq!(
                rig.state().mapping.map(|mapping| (mapping.protocol, mapping.lease_secs)),
                Some((name.into(), 1800))
            );
            rig.finish().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_shared_or_private_address_is_shown_but_not_advertised() {
        for ip in ["100.64.0.9", "100.127.255.1", "192.168.0.5", "10.1.2.3", "172.16.4.4", "203.0.113.9"] {
            let fake = Fake::new();
            fake.will_map(Reply::Mapped(granted_at(ip, 51820, 3600, MappingProtocol::Upnp)));
            let rig = Rig::start(fake).await;
            rig.until_state("the mapping", |state| state.mapping.is_some()).await;

            let state = rig.state();
            let external = format!("{ip}:51820");
            assert_eq!(
                state.mapping.as_ref().map(|mapping| (mapping.external.clone(), mapping.public)),
                Some((external, false))
            );
            assert!(public_of(&state).is_empty(), "{ip}");
            assert!(state.status().public.is_empty(), "{ip}");
            let HostMsg::Reach { addresses, .. } = reach::reach_message(&rig.ctx, &Fingerprint([1; 32])) else {
                panic!("a Reach message")
            };
            assert!(addresses.iter().all(|(kind, _)| *kind != AddressKind::Public), "{ip}: {addresses:?}");
            rig.finish().await;
        }
    }

    #[test]
    fn an_address_is_judged_by_its_class_and_against_the_one_the_dht_nodes_saw() {
        let ip = |text: &str| text.parse::<IpAddr>().unwrap();
        let saw = |text: &str| Some(text.parse::<SocketAddr>().unwrap());
        // The classification alone, while the nodes have not seen this PC.
        assert_eq!(judge(ip(PUBLIC), None, None), Verdict::Public);
        assert_eq!(judge(ip("100.64.0.9"), None, None), Verdict::Shared);
        assert_eq!(judge(ip("192.168.0.5"), None, None), Verdict::Shared);
        assert_eq!(
            judge(ip("203.0.113.9"), None, None),
            Verdict::Shared,
            "the ranges for documentation are not reachable"
        );
        // The nodes saw this PC at the router's address (the port is the NAT's business): nothing is in front.
        assert_eq!(judge(ip(PUBLIC), saw("8.8.4.4:40000"), None), Verdict::Public);
        assert_eq!(
            judge(ip(PUBLIC), saw("[::ffff:8.8.4.4]:40000"), None),
            Verdict::Public,
            "the same address, written so"
        );
        // At another address: another NAT is in front, whatever the router says.
        assert_eq!(judge(ip(PUBLIC), saw("8.8.8.8:40000"), None), Verdict::Elsewhere(ip("8.8.8.8")));
        assert!(!judge(ip(PUBLIC), saw("8.8.8.8:40000"), None).is_public());
        // A shared address stays shared.
        assert_eq!(judge(ip("100.64.0.9"), saw("8.8.8.8:40000"), None), Verdict::Shared);
        // When the nodes say nothing, what was made of the address stays; what they say wins over it.
        let elsewhere = Verdict::Elsewhere(ip("8.8.8.8"));
        assert_eq!(judge(ip(PUBLIC), None, Some(elsewhere)), elsewhere);
        assert_eq!(judge(ip(PUBLIC), None, Some(Verdict::Public)), Verdict::Public);
        assert_eq!(judge(ip(PUBLIC), saw("8.8.4.4:40000"), Some(elsewhere)), Verdict::Public);
        assert_eq!(judge(ip(PUBLIC), saw("8.8.9.9:40000"), Some(Verdict::Public)), Verdict::Elsewhere(ip("8.8.9.9")));
        assert_eq!(judge(ip("192.168.0.5"), None, Some(Verdict::Public)), Verdict::Shared, "the class comes first");
    }

    #[tokio::test(start_paused = true)]
    async fn an_observation_that_agrees_changes_nothing_and_one_that_disagrees_withdraws_the_address_until_it_agrees() {
        let fake = Fake::new();
        fake.will_map(Reply::Mapped(natpmp(51820)));
        let rig = Rig::start(fake).await;
        rig.until_state("the address", |state| !public_of(state).is_empty()).await;
        let advertised = vec![format!("{PUBLIC}:51820")];
        let seen_at =
            |text: Option<&str>| rig.ctx.reach.update(|state| state.observed = text.map(|t| t.parse().unwrap()));

        // E5 measures, and the nodes saw this PC at the router's address: all is as it was.
        seen_at(Some("8.8.4.4:40000"));
        tokio::time::sleep(secs(1)).await;
        assert_eq!(public_of(&rig.state()), advertised);
        assert_eq!(rig.state().mapping.map(|mapping| mapping.public), Some(true));
        assert_eq!(rig.fake.calls().len(), 1, "nothing to ask the router");

        // They see it at another address (or E5's measurement after a move shows another one): another NAT is in front.
        let withdrawn_at = Instant::now();
        seen_at(Some("8.8.8.8:41000"));
        rig.until_state("the address to go", |state| public_of(state).is_empty()).await;
        let state = rig.state();
        assert_eq!(
            state.mapping.map(|mapping| (mapping.external, mapping.public)),
            Some((format!("{PUBLIC}:51820"), false))
        );
        // The mapping is kept, and the router is asked at once what its address is now: the provider may have given
        // this PC another one. It says the same.
        rig.fake.until(2).await;
        let calls = rig.fake.calls();
        assert!(matches!(calls[1], Call::Renew { .. }), "asked about, not made again");
        assert!(calls[1].at() - withdrawn_at < secs(1), "{:?}", calls[1].at() - withdrawn_at);

        // They agree again at once, which is not believed for a minute: the address could go again.
        seen_at(Some("8.8.4.4:41001"));
        tokio::time::sleep(secs(59)).await;
        assert!(public_of(&rig.state()).is_empty(), "not within the minute");
        rig.until_state("the address again", |state| public_of(state) == advertised).await;
        near(Instant::now() - withdrawn_at, secs(60));
        assert_eq!(rig.state().mapping.map(|mapping| mapping.public), Some(true));
        rig.finish().await;
    }

    #[tokio::test(start_paused = true)]
    async fn nodes_that_stop_saying_anything_do_not_bring_a_withdrawn_address_back() {
        let fake = Fake::new();
        fake.will_map(Reply::Mapped(natpmp(51820)));
        let rig = Rig::start(fake).await;
        rig.until_state("the address", |state| !public_of(state).is_empty()).await;
        let seen_at =
            |text: Option<&str>| rig.ctx.reach.update(|state| state.observed = text.map(|t| t.parse().unwrap()));

        let withdrawn_at = Instant::now();
        seen_at(Some("8.8.8.8:41000"));
        rig.until_state("the address to go", |state| public_of(state).is_empty()).await;
        rig.fake.until(2).await;
        assert!(rig.fake.calls()[1].at() - withdrawn_at < secs(1), "asked at once, not at the regular renewal");

        // E5 measures again because `Public` changed, learns nothing and drops what it had: no news is no good news.
        seen_at(None);
        tokio::time::sleep(secs(300)).await;
        let state = rig.state();
        assert!(public_of(&state).is_empty());
        assert_eq!(state.mapping.map(|mapping| mapping.public), Some(false));
        assert_eq!(rig.fake.calls().len(), 2, "and the router was not asked again for it");

        // The mapping is renewed as usual in the hours that follow, and the renewals do not bring the address back.
        tokio::time::sleep(secs(2 * 3600)).await;
        let state = rig.state();
        assert!(public_of(&state).is_empty());
        assert_eq!(state.mapping.map(|mapping| mapping.public), Some(false));
        assert!(rig.fake.calls().len() > 3, "renewed all the while");

        // Until the nodes see this PC at the router's address.
        seen_at(Some("8.8.4.4:41002"));
        rig.until_state("the address again", |state| public_of(state) == [format!("{PUBLIC}:51820")]).await;
        rig.finish().await;
    }

    #[tokio::test(start_paused = true)]
    async fn what_was_made_of_an_address_is_remembered_for_that_address_when_the_mapping_is_lost_and_made_again() {
        let fake = Fake::new();
        fake.will_map(Reply::Mapped(natpmp(51820)));
        // The renewal that asks what the address is now gets no answer, the mapping made after it is the same address
        // again, and the one renewed after that is another address (the provider changed it).
        fake.will_renew(Reply::NoRouter);
        fake.will_map(Reply::Mapped(natpmp(51820)));
        fake.will_renew(Reply::Mapped(granted_at("1.1.1.1", 51820, 3600, MappingProtocol::NatPmp)));
        let rig = Rig::start(fake).await;
        rig.until_state("the address", |state| !public_of(state).is_empty()).await;
        let seen_at =
            |text: Option<&str>| rig.ctx.reach.update(|state| state.observed = text.map(|t| t.parse().unwrap()));

        // The nodes see this PC elsewhere: the address is withdrawn, the router is asked at once and does not answer.
        seen_at(Some("8.8.8.8:41000"));
        rig.until_state("the mapping to go", |state| state.mapping.is_none()).await;
        // E5 measures again and learns nothing; a minute later the router answers with the same address.
        seen_at(None);
        rig.until_state("the mapping again", |state| state.mapping.is_some()).await;
        let state = rig.state();
        assert!(public_of(&state).is_empty(), "the same address is not public because it was made again");
        assert_eq!(state.mapping.map(|mapping| mapping.public), Some(false));

        // Half an hour on, the renewal gives another address, which nobody has doubted: judged anew.
        rig.until_state("the other address", |state| public_of(state) == ["1.1.1.1:51820"]).await;
        rig.finish().await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_mapping_made_right_after_a_move_is_judged_again_when_the_nodes_measure_the_new_network() {
        let fake = Fake::new();
        fake.will_map(Reply::Mapped(natpmp(51820)));
        fake.will_map(Reply::Mapped(granted_at("1.1.1.1", 40000, 3600, MappingProtocol::Upnp)));
        let rig = Rig::start_after(Timing::default(), fake, Some(LAN), false, |ctx| {
            ctx.reach.update(|state| state.observed = Some("8.8.4.4:40000".parse().unwrap()))
        })
        .await;
        rig.until_state("the first address", |state| !public_of(state).is_empty()).await;

        // The laptop is somewhere else. For a moment what the nodes said last is still about the network it left.
        rig.lan_changes_to(Some("198.51.100.77:7420"));
        rig.until_state("the second mapping", |state| {
            state.mapping.as_ref().is_some_and(|mapping| mapping.external == "1.1.1.1:40000")
        })
        .await;
        assert_eq!(
            rig.state().mapping.map(|mapping| mapping.public),
            Some(false),
            "the premise: judged by the old word"
        );
        // E5 measures the new network: the nodes saw this PC at the router's address.
        rig.ctx.reach.update(|state| state.observed = Some("1.1.1.1:41000".parse().unwrap()));
        rig.until_state("the second address", |state| public_of(state) == ["1.1.1.1:40000"]).await;
        assert_eq!(rig.state().mapping.map(|mapping| mapping.public), Some(true));
        rig.finish().await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_mismatch_that_comes_after_the_mapping_asks_the_router_what_its_address_is_now() {
        let fake = Fake::new();
        fake.will_map(Reply::Mapped(natpmp(51820)));
        // The provider gave this PC another address while the mapping was held, and the router says so when asked.
        fake.will_renew(Reply::Mapped(granted_at("1.1.1.1", 51820, 3600, MappingProtocol::NatPmp)));
        let rig = Rig::start(fake).await;
        rig.until_state("the address", |state| !public_of(state).is_empty()).await;
        tokio::time::sleep(secs(100)).await;

        let seen_at = Instant::now();
        rig.ctx.reach.update(|state| state.observed = Some("1.1.1.1:41000".parse().unwrap()));
        rig.until_state("the new address", |state| public_of(state) == ["1.1.1.1:51820"]).await;
        let calls = rig.fake.calls();
        assert!(matches!(calls[1], Call::Renew { .. }));
        assert!(calls[1].at() - seen_at < secs(1), "{:?}", calls[1].at() - seen_at);
        assert_eq!(rig.state().mapping.map(|mapping| mapping.public), Some(true));
        rig.finish().await;
    }

    #[tokio::test(start_paused = true)]
    async fn nodes_that_keep_changing_their_mind_cannot_make_the_address_go_back_and_forth_faster_than_once_a_minute() {
        let fake = Fake::new();
        fake.will_map(Reply::Mapped(natpmp(51820)));
        let rig = Rig::start(fake).await;
        rig.until_state("the address", |state| !public_of(state).is_empty()).await;
        let seen_at = |text: &str| rig.ctx.reach.update(|state| state.observed = Some(text.parse().unwrap()));
        let renewals = |calls: &[Call]| calls.iter().filter(|call| matches!(call, Call::Renew { .. })).count();
        // Not at the instant of the IPv6 look, which would wake the task anyway.
        tokio::time::sleep(secs(7)).await;

        let mut withdrawn = Vec::new();
        for _ in 0..3 {
            seen_at("8.8.8.8:41000");
            rig.until_state("the address to go", |state| public_of(state).is_empty()).await;
            withdrawn.push(Instant::now());
            // The next round says the opposite at once.
            seen_at("8.8.4.4:41001");
            rig.until_state("the address again", |state| !public_of(state).is_empty()).await;
        }
        for pair in withdrawn.windows(2) {
            near(pair[1] - pair[0], secs(60));
        }
        assert_eq!(renewals(&rig.fake.calls()), 3, "a question for each withdrawal, a minute apart");
        rig.finish().await;
    }

    // === what is made of the nodes' word, step by step ===

    fn word(text: &str) -> Option<SocketAddr> {
        Some(text.parse().unwrap())
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn the_opinion_of_an_address_follows_the_class_and_the_nodes_and_stays_for_lack_of_news() {
        let (t0, timing) = (Instant::now(), Timing::default());
        let mut opinion = Opinion::new(t0);
        // No word: by class.
        assert_eq!(opinion.consider(ip(PUBLIC), None, t0, &timing).verdict, Verdict::Public);
        // The nodes disagree: withdrawn at once, and the router is asked what its address is now.
        let elsewhere = Verdict::Elsewhere(ip("8.8.8.8"));
        let considered = opinion.consider(ip(PUBLIC), word("8.8.8.8:1"), t0 + secs(1), &timing);
        assert_eq!(considered, Considered { verdict: elsewhere, ask_router: true, settles_at: None });
        // They fall silent: it stays.
        assert_eq!(opinion.consider(ip(PUBLIC), None, t0 + secs(2), &timing).verdict, elsewhere);
        // They agree at once: not within the minute that follows the withdrawal...
        let considered = opinion.consider(ip(PUBLIC), word("8.8.4.4:1"), t0 + secs(3), &timing);
        assert_eq!(considered, Considered { verdict: elsewhere, ask_router: false, settles_at: Some(t0 + secs(61)) });
        // ...but when it is up.
        assert_eq!(opinion.consider(ip(PUBLIC), word("8.8.4.4:1"), t0 + secs(61), &timing).verdict, Verdict::Public);
        // A shared address is shared, whatever the nodes say.
        let shared = opinion.consider(ip("100.64.0.9"), word("8.8.8.8:1"), t0 + secs(70), &timing);
        assert_eq!(shared.verdict, Verdict::Shared);
    }

    #[test]
    fn another_address_is_judged_anew_at_once_and_a_withdrawal_in_the_quiet_minute_does_not_ask_again() {
        let (t0, timing) = (Instant::now(), Timing::default());
        let mut opinion = Opinion::new(t0);
        opinion.consider(ip(PUBLIC), None, t0, &timing);
        assert!(opinion.consider(ip(PUBLIC), word("1.1.1.1:1"), t0, &timing).ask_router);
        // The provider gave this PC another address and the router says so: judged anew, public, within the minute.
        assert_eq!(opinion.consider(ip("1.1.1.1"), word("1.1.1.1:1"), t0 + secs(5), &timing).verdict, Verdict::Public);
        // The nodes contradict it inside the minute: withdrawn at once, but the router is not asked again...
        let considered = opinion.consider(ip("1.1.1.1"), word("9.9.9.9:1"), t0 + secs(10), &timing);
        assert_eq!(considered.verdict, Verdict::Elsewhere(ip("9.9.9.9")));
        assert!(!considered.ask_router);
        // ...and a new minute starts from that withdrawal.
        let considered = opinion.consider(ip("1.1.1.1"), word("1.1.1.1:2"), t0 + secs(30), &timing);
        assert_eq!(considered.settles_at, Some(t0 + secs(70)));
        // Asked again once a whole minute has gone by.
        assert_eq!(opinion.consider(ip("1.1.1.1"), word("1.1.1.1:2"), t0 + secs(70), &timing).verdict, Verdict::Public);
        assert!(opinion.consider(ip("1.1.1.1"), word("9.9.9.9:1"), t0 + secs(71), &timing).ask_router);
    }

    #[test]
    fn a_move_forgets_the_verdicts_and_one_made_of_the_word_about_the_old_network_is_not_kept_for_lack_of_news() {
        let (t0, timing) = (Instant::now(), Timing::default());
        let mut opinion = Opinion::new(t0);
        // A withdrawal on the old network starts a quiet minute...
        opinion.consider(ip(PUBLIC), None, t0, &timing);
        assert!(opinion.consider(ip(PUBLIC), word("8.8.8.8:1"), t0 + secs(95), &timing).ask_router);
        // ...which the move ends, along with the rest; the word in the state is still the one about the old network.
        opinion.moved(word("8.8.4.4:40000"), t0 + secs(100), &timing);
        // The router of the new network says 1.1.1.1: judged against that word.
        let stale = Verdict::Elsewhere(ip("8.8.4.4"));
        assert_eq!(opinion.consider(ip("1.1.1.1"), word("8.8.4.4:40000"), t0 + secs(101), &timing).verdict, stale);
        // E5 measures the new network, learns nothing and drops the word: that verdict does not stay.
        assert_eq!(opinion.consider(ip("1.1.1.1"), None, t0 + secs(105), &timing).verdict, Verdict::Public);

        // A verdict made of a word about this network does stay when they fall silent...
        let considered = opinion.consider(ip("1.1.1.1"), word("9.9.9.9:1"), t0 + secs(110), &timing);
        assert_eq!(considered.verdict, Verdict::Elsewhere(ip("9.9.9.9")));
        assert_eq!(opinion.consider(ip("1.1.1.1"), None, t0 + secs(120), &timing).verdict, considered.verdict);
        // ...until the next move, which forgets it.
        opinion.moved(None, t0 + secs(200), &timing);
        assert_eq!(opinion.consider(ip("1.1.1.1"), None, t0 + secs(201), &timing).verdict, Verdict::Public);
    }

    #[test]
    fn the_word_that_was_there_when_the_network_changed_is_doubted_only_until_it_is_measured_again_or_old() {
        let (t0, timing) = (Instant::now(), Timing::default());
        let elsewhere = Verdict::Elsewhere(ip("8.8.8.8"));

        // The same network under another address of this PC (a dock, a new DHCP lease, a VPN that reconnects): the
        // nodes still say 8.8.8.8 and that is true here. E5 measures again and gets the same address, another port.
        let mut opinion = Opinion::new(t0);
        opinion.consider(ip(PUBLIC), word("8.8.8.8:1"), t0, &timing);
        opinion.moved(word("8.8.8.8:1"), t0 + secs(10), &timing);
        assert_eq!(opinion.consider(ip(PUBLIC), word("8.8.8.8:1"), t0 + secs(11), &timing).verdict, elsewhere);
        assert_eq!(opinion.consider(ip(PUBLIC), word("8.8.8.8:2"), t0 + secs(15), &timing).verdict, elsewhere);
        // That was a measurement: a silent round after it changes nothing.
        assert_eq!(opinion.consider(ip(PUBLIC), None, t0 + secs(20), &timing).verdict, elsewhere);

        // A word that is not measured again is believed once it is old enough, and then stays for lack of news.
        let mut opinion = Opinion::new(t0);
        opinion.moved(word("8.8.8.8:1"), t0, &timing);
        assert_eq!(opinion.consider(ip(PUBLIC), word("8.8.8.8:1"), t0 + secs(1), &timing).verdict, elsewhere);
        assert_eq!(opinion.consider(ip(PUBLIC), word("8.8.8.8:1"), t0 + secs(30), &timing).verdict, elsewhere);
        assert_eq!(opinion.consider(ip(PUBLIC), None, t0 + secs(40), &timing).verdict, elsewhere);

        // Dropped while it could still be the old network's: it was.
        let mut opinion = Opinion::new(t0);
        opinion.moved(word("8.8.8.8:1"), t0, &timing);
        assert_eq!(opinion.consider(ip(PUBLIC), word("8.8.8.8:1"), t0 + secs(1), &timing).verdict, elsewhere);
        assert_eq!(opinion.consider(ip(PUBLIC), None, t0 + secs(5), &timing).verdict, Verdict::Public);
    }

    #[test]
    fn nodes_that_contradict_each_other_every_second_move_the_verdict_once_a_minute_at_most() {
        let (t0, timing) = (Instant::now(), Timing::default());
        let mut opinion = Opinion::new(t0);
        opinion.consider(ip(PUBLIC), None, t0, &timing);
        let (mut changes, mut last) = (0, Verdict::Public);
        for second in 1..=300 {
            let said = if second % 2 == 0 { "8.8.8.8:1" } else { "8.8.4.4:1" };
            let verdict = opinion.consider(ip(PUBLIC), word(said), t0 + secs(second), &timing).verdict;
            if verdict != last {
                changes += 1;
                last = verdict;
            }
        }
        assert!((2..=10).contains(&changes), "{changes} changes in five minutes");
    }

    // === the nodes' word, in the loop ===

    #[tokio::test(start_paused = true)]
    async fn a_slow_renewal_does_not_let_the_nodes_bring_the_address_back_within_the_quiet_minute() {
        let fake = Fake::new();
        fake.will_map(Reply::Mapped(natpmp(51820)));
        fake.renewals_take(secs(3));
        let rig = Rig::start(fake).await;
        rig.until_state("the address", |state| !public_of(state).is_empty()).await;
        let seen_at = |text: &str| rig.ctx.reach.update(|state| state.observed = Some(text.parse().unwrap()));
        // Not at the instant of the IPv6 look, which would wake the task anyway.
        tokio::time::sleep(secs(7)).await;

        let withdrawn_at = Instant::now();
        seen_at("8.8.8.8:41000");
        rig.until_state("the address to go", |state| public_of(state).is_empty()).await;
        // The router is being asked, and takes three seconds.
        rig.fake.until(2).await;
        // E5 measures again because `Public` changed, and now the nodes agree: the router's answer comes after.
        seen_at("8.8.4.4:41001");
        tokio::time::sleep(secs(10)).await;
        assert!(public_of(&rig.state()).is_empty(), "the minute is not up");
        rig.until_state("the address again", |state| !public_of(state).is_empty()).await;
        near(Instant::now() - withdrawn_at, secs(60));
        rig.finish().await;
    }

    #[tokio::test(start_paused = true)]
    async fn what_the_nodes_said_about_the_old_network_is_not_kept_when_they_say_nothing_about_the_new_one() {
        let fake = Fake::new();
        fake.will_map(Reply::Mapped(natpmp(51820)));
        fake.will_map(Reply::Mapped(granted_at("1.1.1.1", 40000, 3600, MappingProtocol::Upnp)));
        let rig = Rig::start_after(Timing::default(), fake, Some(LAN), false, |ctx| {
            ctx.reach.update(|state| state.observed = Some("8.8.4.4:40000".parse().unwrap()))
        })
        .await;
        rig.until_state("the first address", |state| !public_of(state).is_empty()).await;

        // The laptop moves straight to a network whose router answers at once, while E5 has not measured yet...
        rig.lan_changes_to(Some("198.51.100.77:7420"));
        rig.until_state("the second mapping", |state| {
            state.mapping.as_ref().is_some_and(|mapping| mapping.external == "1.1.1.1:40000")
        })
        .await;
        assert_eq!(
            rig.state().mapping.map(|mapping| mapping.public),
            Some(false),
            "the premise: judged by the old word"
        );
        // ...and then E5's round on the new network learns nothing (it blocks the DHT) and drops the old word.
        rig.ctx.reach.update(|state| state.observed = None);
        rig.until_state("the second address", |state| public_of(state) == ["1.1.1.1:40000"]).await;
        assert_eq!(rig.state().mapping.map(|mapping| mapping.public), Some(true));
        rig.finish().await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_mapping_the_nodes_do_not_confirm_leaves_the_observed_endpoint_to_the_record() {
        let log = logged();
        let fake = Fake::new();
        // A port that no other test uses, so that their lines are not counted.
        fake.will_map(Reply::Mapped(natpmp(51894)));
        let rig = Rig::start_after(Timing::default(), fake, Some(LAN), false, |ctx| {
            ctx.reach.update(|state| {
                state.observed = Some("8.8.8.8:41000".parse().unwrap());
                state.nat = Some(velora_nat::observe::NatType::EndpointIndependent);
            })
        })
        .await;
        rig.until_state("the mapping", |state| state.mapping.is_some()).await;
        let state = rig.state();
        assert!(public_of(&state).is_empty(), "judged against what the nodes saw from the start");
        assert_eq!(state.mapping.as_ref().map(|mapping| mapping.public), Some(false));
        // So the DHT record lists the endpoint a client can punch to, and E4 looks for a relay.
        assert!(state.record_addresses().contains(&(AddressKind::Public, "8.8.8.8:41000".to_string())));
        // And it was not called public in the log, not even for a moment, before it was called "another NAT".
        assert_eq!(log.lines_saying("reachable from outside at 8.8.4.4:51894"), 0, "{}", log.text());
        assert_eq!(log.lines_saying("(8.8.4.4:51894) is not advertised"), 1, "{}", log.text());
        rig.finish().await;
    }

    // === keeping it ===

    #[tokio::test(start_paused = true)]
    async fn the_mapping_is_renewed_at_half_the_lease_but_between_ten_seconds_and_half_an_hour_apart() {
        for (lease, every) in [(3600, 1800), (2400, 1200), (14400, 1800), (20, 10), (2, 10)] {
            let fake = Fake::new();
            fake.will_map(Reply::Mapped(granted_at(PUBLIC, 51820, lease, MappingProtocol::NatPmp)));
            let rig = Rig::start(fake).await;
            rig.fake.until(3).await;
            let calls = rig.fake.calls();
            assert!(matches!(calls[1], Call::Renew { .. }) && matches!(calls[2], Call::Renew { .. }), "lease {lease}");
            near(calls[1].at() - calls[0].at(), secs(every));
            near(calls[2].at() - calls[1].at(), secs(every));
            rig.finish().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_renewal_that_gives_another_address_moves_the_advertised_one_and_is_the_one_renewed_next() {
        let fake = Fake::new();
        fake.will_map(Reply::Mapped(natpmp(51820)));
        let other = granted_at("8.8.8.8", 40001, 3600, MappingProtocol::Upnp);
        fake.will_renew(Reply::Mapped(other.clone()));
        let rig = Rig::start(fake).await;
        rig.until_state("the other address", |state| public_of(state) == ["8.8.8.8:40001"]).await;
        assert_eq!(rig.state().mapping.map(|mapping| mapping.protocol), Some("upnp".into()));

        rig.fake.until(3).await;
        assert!(matches!(&rig.fake.calls()[2], Call::Renew { of, .. } if *of == other), "the new one is renewed");
        rig.finish().await;
    }

    #[tokio::test(start_paused = true)]
    async fn the_asking_never_waits_for_a_router_that_cannot_be_reached() {
        let fake = Fake::new();
        fake.will_map(Reply::Hangs);
        let rig = Rig::start(fake).await;
        rig.fake.until(2).await;
        let calls = rig.fake.calls();
        // The first request was given up on after thirty seconds, and the retry came a minute after that.
        near(calls[1].at() - calls[0].at(), secs(90));
        assert!(rig.state().mapping.is_none());
        rig.finish().await;
    }

    // === no router, and a router that goes ===

    #[tokio::test(start_paused = true)]
    async fn a_router_that_does_not_answer_is_asked_again_after_longer_and_longer_and_nothing_is_advertised() {
        let fake = Fake::new();
        let rig = Rig::start(fake).await;
        rig.fake.until(8).await;
        let calls = rig.fake.calls();
        // At once, and then after 1, 2, 4, 8, 16 and 30 minutes (and 30 again).
        for (n, wait) in [60, 120, 240, 480, 960, 1800, 1800].into_iter().enumerate() {
            near(calls[n + 1].at() - calls[n].at(), secs(wait));
        }
        let state = rig.state();
        assert!(state.mapping.is_none() && public_of(&state).is_empty(), "no router, no address");

        // The router comes back: the next try works, and the mapping is kept up as usual.
        rig.fake.will_map(Reply::Mapped(natpmp(51820)));
        rig.until_state("the address", |state| !public_of(state).is_empty()).await;
        rig.fake.until(10).await;
        assert!(matches!(rig.fake.calls()[9], Call::Renew { .. }), "{} calls", rig.fake.calls().len());
        rig.finish().await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_mapping_the_router_loses_is_withdrawn_at_once_and_asked_for_again_after_longer_and_longer() {
        let fake = Fake::new();
        fake.will_map(Reply::Mapped(natpmp(51820)));
        fake.will_renew(Reply::NoRouter);
        let rig = Rig::start(fake).await;
        rig.until_state("the address", |state| !public_of(state).is_empty()).await;

        // Half an hour on, the renewal gets no answer: the address goes from the state in the same instant.
        rig.fake.until(2).await;
        let renewed_at = rig.fake.calls()[1].at();
        rig.until_state("the address to go", |state| public_of(state).is_empty()).await;
        assert!(Instant::now() - renewed_at < secs(1), "{:?}", Instant::now() - renewed_at);
        assert!(rig.state().mapping.is_none());

        // A minute later it is asked for again, and when that fails the pauses go on from there: two minutes next.
        rig.fake.until(3).await;
        let calls = rig.fake.calls();
        assert!(matches!(calls[1], Call::Renew { .. }) && matches!(calls[2], Call::Map { .. }));
        near(calls[2].at() - calls[1].at(), secs(60));
        rig.fake.will_map(Reply::Mapped(natpmp(51821)));
        rig.until_state("the address again", |state| public_of(state) == [format!("{PUBLIC}:51821")]).await;
        near(rig.fake.calls()[3].at() - rig.fake.calls()[2].at(), secs(120));
        rig.finish().await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_renewal_nobody_answers_withdraws_the_address_after_half_a_minute_and_asks_again_a_minute_later() {
        let fake = Fake::new();
        fake.will_map(Reply::Mapped(natpmp(51820)));
        fake.will_renew(Reply::Hangs);
        fake.will_map(Reply::Mapped(natpmp(51821)));
        let rig = Rig::start(fake).await;
        rig.until_state("the address", |state| !public_of(state).is_empty()).await;

        // Half an hour on, the renewal is asked and the router is given its time: the address stays meanwhile.
        rig.fake.until(2).await;
        let asked_at = rig.fake.calls()[1].at();
        assert_eq!(public_of(&rig.state()), [format!("{PUBLIC}:51820")]);
        rig.until_state("the address to go", |state| public_of(state).is_empty()).await;
        near(Instant::now() - asked_at, secs(30));
        assert!(rig.state().mapping.is_none());

        // A minute after that it is asked for again.
        rig.until_state("the address again", |state| public_of(state) == [format!("{PUBLIC}:51821")]).await;
        near(rig.fake.calls()[2].at() - asked_at, secs(90));
        rig.finish().await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_router_that_grants_port_0_has_mapped_nothing() {
        // At the first request...
        let fake = Fake::new();
        fake.will_map(Reply::Mapped(natpmp(0)));
        let rig = Rig::start(fake).await;
        rig.fake.until(2).await;
        let state = rig.state();
        assert!(state.mapping.is_none() && public_of(&state).is_empty());
        near(rig.fake.calls()[1].at() - rig.fake.calls()[0].at(), secs(60));
        rig.finish().await;

        // ...and at a renewal.
        let fake = Fake::new();
        fake.will_map(Reply::Mapped(natpmp(51820)));
        fake.will_renew(Reply::Mapped(natpmp(0)));
        let rig = Rig::start(fake).await;
        rig.fake.until(2).await;
        rig.until_state("the address to go", |state| public_of(state).is_empty()).await;
        assert!(rig.state().mapping.is_none());
        rig.finish().await;
    }

    // === the network ===

    #[tokio::test(start_paused = true)]
    async fn a_move_to_another_network_asks_again_at_once_and_asks_the_new_router_to_remove_nothing() {
        let fake = Fake::new();
        let second = granted_at("8.8.8.8", 40000, 3600, MappingProtocol::Upnp);
        fake.will_map(Reply::Mapped(natpmp(51820)));
        fake.will_map(Reply::Mapped(second));
        let rig = Rig::start(fake).await;
        rig.until_state("the first address", |state| !public_of(state).is_empty()).await;
        tokio::time::sleep(secs(100)).await;

        // The laptop is somewhere else: another LAN address.
        let moved_at = Instant::now();
        rig.lan_changes_to(Some("198.51.100.77:7420"));
        rig.until_state("the second address", |state| public_of(state) == ["8.8.8.8:40000"]).await;
        let calls = rig.fake.calls();
        assert_eq!(calls.len(), 2, "one request for the new network, and none for the old mapping");
        assert!(matches!(calls[1], Call::Map { .. }));
        assert!(calls[1].at() - moved_at < secs(1), "{:?}", calls[1].at() - moved_at);
        rig.finish().await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_network_that_comes_after_a_failure_is_tried_at_once() {
        let fake = Fake::new();
        let rig = Rig::start(fake).await;
        rig.fake.until(3).await; // at once, a minute on, two more minutes on: the pauses are growing
        rig.fake.will_map(Reply::Mapped(natpmp(51820)));

        let moved_at = Instant::now();
        rig.lan_changes_to(Some("198.51.100.77:7420"));
        rig.until_state("the address", |state| !public_of(state).is_empty()).await;
        let calls = rig.fake.calls();
        assert!(calls[3].at() - moved_at < secs(1), "{:?}", calls[3].at() - moved_at);
        rig.finish().await;
    }

    #[tokio::test(start_paused = true)]
    async fn nothing_is_asked_while_this_pc_has_no_network_and_the_first_address_of_one_starts_it() {
        let fake = Fake::new();
        fake.will_map(Reply::Mapped(natpmp(51820)));
        let rig = Rig::start_with(Timing::default(), fake, None, false).await;
        tokio::time::sleep(secs(3600)).await;
        assert!(rig.fake.calls().is_empty(), "no network, nobody to ask");

        let up_at = Instant::now();
        rig.lan_changes_to(Some(LAN));
        rig.until_state("the address", |state| !public_of(state).is_empty()).await;
        assert!(rig.fake.calls()[0].at() - up_at < secs(1));
        rig.finish().await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_network_that_goes_away_withdraws_the_address_and_it_is_asked_for_again_when_one_comes() {
        let fake = Fake::new();
        fake.will_map(Reply::Mapped(natpmp(51820)));
        fake.will_map(Reply::Mapped(natpmp(51821)));
        let rig = Rig::start(fake).await;
        rig.until_state("the address", |state| !public_of(state).is_empty()).await;

        rig.lan_changes_to(None);
        rig.until_state("the address to go", |state| public_of(state).is_empty() && state.mapping.is_none()).await;
        tokio::time::sleep(secs(2 * 3600)).await;
        assert_eq!(rig.fake.calls().len(), 1, "nothing asked, nobody to ask, nothing to give back");

        rig.lan_changes_to(Some(LAN));
        rig.until_state("the address again", |state| public_of(state) == [format!("{PUBLIC}:51821")]).await;
        rig.finish().await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_machine_that_slept_asks_the_router_again_without_waiting_for_the_half_hour() {
        static WALL: AtomicU64 = AtomicU64::new(1_000_000);
        fn wall() -> u64 {
            WALL.load(Ordering::SeqCst)
        }
        let fake = Fake::new();
        fake.will_map(Reply::Mapped(natpmp(51820)));
        let rig = Rig::start_with(Timing { wall, ..Timing::default() }, fake, Some(LAN), false).await;
        rig.until_state("the address", |state| !public_of(state).is_empty()).await;
        tokio::time::sleep(secs(10)).await;

        // Three hours go by on the wall clock while the monotonic one stands still: a suspend.
        let woke_at = Instant::now();
        WALL.fetch_add(3 * 3600, Ordering::SeqCst);
        rig.fake.until(2).await;
        let calls = rig.fake.calls();
        assert!(matches!(calls[1], Call::Renew { .. }));
        assert!(calls[1].at() - woke_at < secs(70), "{:?}", calls[1].at() - woke_at);
        // Once is enough: the two clocks agree again, and the next renewal is the regular one.
        tokio::time::sleep(secs(600)).await;
        assert_eq!(rig.fake.calls().len(), 2);
        rig.finish().await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_machine_that_slept_while_no_router_answered_asks_at_once_and_the_pauses_start_over() {
        static WALL: AtomicU64 = AtomicU64::new(1_000_000);
        fn wall() -> u64 {
            WALL.load(Ordering::SeqCst)
        }
        let rig = Rig::start_with(Timing { wall, ..Timing::default() }, Fake::new(), Some(LAN), false).await;
        // At once, and after 1, 2, 4, 8, 16 and 30 minutes: the next one is half an hour away.
        rig.fake.until(7).await;

        // Three hours go by on the wall clock while the monotonic one stands still: a suspend.
        let woke_at = Instant::now();
        WALL.fetch_add(3 * 3600, Ordering::SeqCst);
        rig.fake.until(8).await;
        let calls = rig.fake.calls();
        assert!(calls[7].at() - woke_at < secs(70), "{:?}", calls[7].at() - woke_at);
        // That one failed too, and the pauses start over from a minute...
        rig.fake.until(9).await;
        near(rig.fake.calls()[8].at() - rig.fake.calls()[7].at(), secs(60));
        // ...and grow from there, the sleep being over: two minutes next.
        rig.fake.until(10).await;
        near(rig.fake.calls()[9].at() - rig.fake.calls()[8].at(), secs(120));
        rig.finish().await;
    }

    // === the end ===

    #[tokio::test(start_paused = true)]
    async fn stopping_gives_the_latest_mapping_back_and_takes_everything_out_of_the_state() {
        let fake = Fake::new();
        let renewed = granted_at(PUBLIC, 51999, 3600, MappingProtocol::NatPmp);
        fake.will_map(Reply::Mapped(natpmp(51820)));
        fake.will_renew(Reply::Mapped(renewed.clone()));
        fake.has_ipv6(&[("2001:db8::1", 4)]);
        let rig = Rig::start_with(Timing::default(), fake, Some(LAN), true).await;
        rig.fake.until(2).await; // the mapping, and half an hour on, its renewal
        rig.until_state("the renewed address", |state| public_of(state) == [format!("{PUBLIC}:51999")]).await;
        let (ctx, fake) = (rig.ctx.clone(), rig.fake.clone());
        assert!(!ctx.reach.read().addresses_of(&AddressKind::V6).is_empty(), "the premise: listed before the end");
        // E1's housekeeping is asked to look again as the task ends, and finds the PC on the network it was on.
        fake.network_is_now(Some(LAN));

        let told_at = Instant::now();
        rig.finish().await;
        let calls = fake.calls();
        assert!(matches!(calls.last(), Some(Call::Remove { of, .. }) if *of == renewed), "the latest is given back");
        assert!(calls.last().unwrap().at() - told_at < ms(10));
        let state = ctx.reach.read().clone();
        assert!(state.mapping.is_none() && public_of(&state).is_empty());
        assert!(state.addresses_of(&AddressKind::V6).is_empty(), "the IPv6 addresses go too");
    }

    #[tokio::test(start_paused = true)]
    async fn a_stop_after_a_move_that_nobody_noticed_yet_gives_nothing_back_to_the_router_of_the_new_network() {
        let fake = Fake::new();
        fake.will_map(Reply::Mapped(natpmp(51820)));
        let rig = Rig::start(fake).await;
        rig.until_state("the address", |state| !public_of(state).is_empty()).await;

        // The laptop was carried to another network, and E1's housekeeping has not looked since.
        rig.fake.network_is_now(Some("198.51.100.77:7420"));
        let (ctx, fake) = (rig.ctx.clone(), rig.fake.clone());
        rig.finish().await;
        let calls = fake.calls();
        assert!(
            !calls.iter().any(|call| matches!(call, Call::Remove { .. })),
            "a port of the same number may be someone's"
        );
        assert!(ctx.reach.read().mapping.is_none() && public_of(&ctx.reach.read()).is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_router_that_does_not_answer_the_removal_does_not_hold_up_the_end() {
        let fake = Fake::new();
        fake.will_map(Reply::Mapped(natpmp(51820)));
        fake.removal_hangs.store(true, Ordering::SeqCst);
        let rig = Rig::start(fake).await;
        rig.until_state("the address", |state| !public_of(state).is_empty()).await;

        let told_at = Instant::now();
        rig.stop.send(true).unwrap();
        tokio::time::sleep(ms(10)).await;
        // The address is not advertised while the removal is waited for.
        assert!(!rig.task.is_finished(), "the task is waiting for the router");
        assert!(rig.state().mapping.is_none() && public_of(&rig.state()).is_empty());
        let ctx = rig.ctx.clone();
        rig.task.await.unwrap();
        near(told_at.elapsed(), ms(3800));
        assert!(ctx.reach.read().mapping.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn a_stop_in_the_middle_of_a_request_ends_the_task_at_once() {
        let fake = Fake::new();
        fake.will_map(Reply::Hangs);
        let rig = Rig::start(fake).await;
        rig.fake.until(1).await;
        let told_at = Instant::now();
        let ctx = rig.ctx.clone();
        tokio::time::timeout(secs(1), rig.finish()).await.expect("it stops at once");
        assert!(told_at.elapsed() < ms(10));
        assert!(ctx.reach.read().mapping.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn a_task_that_is_aborted_takes_what_it_wrote_out_of_the_state() {
        let fake = Fake::new();
        fake.will_map(Reply::Mapped(natpmp(51820)));
        fake.has_ipv6(&[("2001:db8::1", 4)]);
        let rig = Rig::start_with(Timing::default(), fake, Some(LAN), true).await;
        rig.until_state("the address", |state| !public_of(state).is_empty()).await;

        let ctx = rig.ctx.clone();
        rig.until_state("the IPv6 address", |state| !state.addresses_of(&AddressKind::V6).is_empty()).await;
        rig.task.abort();
        let _ = rig.task.await;
        let state = ctx.reach.read().clone();
        assert!(
            state.mapping.is_none() && public_of(&state).is_empty() && state.addresses_of(&AddressKind::V6).is_empty()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_old_address_is_withdrawn_before_the_new_one_is_known() {
        let fake = Fake::new();
        fake.will_map(Reply::Mapped(natpmp(51820)));
        fake.will_map(Reply::Hangs);
        let rig = Rig::start(fake).await;
        rig.until_state("the address", |state| !public_of(state).is_empty()).await;

        let moved_at = Instant::now();
        rig.lan_changes_to(Some("198.51.100.77:7420"));
        rig.fake.until(2).await;
        // The new mapping is being asked for, and the router does not answer: the old address is gone already.
        assert!(public_of(&rig.state()).is_empty() && rig.state().mapping.is_none());
        assert!(Instant::now() - moved_at < secs(1));
        rig.finish().await;
    }

    #[tokio::test(start_paused = true)]
    async fn the_task_writes_its_three_things_and_touches_nothing_else() {
        let fake = Fake::new();
        fake.will_map(Reply::Mapped(natpmp(51820)));
        fake.has_ipv6(&[("2001:db8::1", 5)]);
        // What the other tasks keep there, before this one starts.
        let rig = Rig::start_after(Timing::default(), fake, Some(LAN), true, |ctx| {
            ctx.reach.update(|state| {
                state.set_addresses(AddressKind::Vpn, vec!["100.64.0.5:7420".into()]);
                state.observed = Some("8.8.4.4:40000".parse().unwrap());
                state.nat = Some(velora_nat::observe::NatType::EndpointIndependent);
                state.dht_key = Some([7; 32]);
                state.mac = Some([2, 0, 0, 0, 0, 1]);
            })
        })
        .await;
        let others = |state: &ReachState| {
            (
                state.addresses_of(&AddressKind::Lan),
                state.addresses_of(&AddressKind::Vpn),
                state.observed,
                state.nat,
                state.dht_key,
                state.mac,
                state.switches,
                state.relays.len(),
                state.last_reached.clone(),
            )
        };
        let before = others(&rig.state());
        rig.until_state("the address", |state| !public_of(state).is_empty()).await;
        assert_eq!(others(&rig.state()), before, "after the mapping");
        tokio::time::sleep(secs(2 * 3600)).await;
        assert_eq!(others(&rig.state()), before, "after two hours of renewing");
        let ctx = rig.ctx.clone();
        rig.finish().await;
        assert_eq!(others(&ctx.reach.read()), before, "after the end");
    }

    #[tokio::test(start_paused = true)]
    async fn a_stop_in_the_middle_of_a_renewal_still_gives_the_mapping_back() {
        let fake = Fake::new();
        fake.will_map(Reply::Mapped(natpmp(51820)));
        fake.will_renew(Reply::Hangs);
        let rig = Rig::start(fake).await;
        rig.fake.until(2).await; // the mapping, and half an hour on a renewal that never ends
        let fake = rig.fake.clone();
        rig.finish().await;
        let calls = fake.calls();
        assert!(matches!(calls.last(), Some(Call::Remove { of, .. }) if *of == natpmp(51820)), "the one it had");
    }

    #[tokio::test(start_paused = true)]
    async fn a_router_that_refuses_the_removal_does_not_stop_the_end_either() {
        let fake = Fake::new();
        fake.will_map(Reply::Mapped(natpmp(51820)));
        fake.removal_fails.store(true, Ordering::SeqCst);
        let rig = Rig::start(fake).await;
        rig.until_state("the address", |state| !public_of(state).is_empty()).await;
        let (ctx, fake) = (rig.ctx.clone(), rig.fake.clone());
        tokio::time::timeout(secs(10), rig.finish()).await.expect("it ends");
        assert!(matches!(fake.calls().last(), Some(Call::Remove { .. })), "the removal was tried");
        assert!(ctx.reach.read().mapping.is_none() && public_of(&ctx.reach.read()).is_empty());
    }

    // === IPv6 ===

    #[tokio::test(start_paused = true)]
    async fn the_first_ipv6_address_of_each_interface_is_listed_with_the_port_whether_or_not_a_router_answers() {
        let fake = Fake::new();
        fake.has_ipv6(&[("2001:db8::1", 5), ("2001:db8::2", 5), ("2001:db8:1::1", 6)]);
        let rig = Rig::start_with(Timing::default(), fake, Some(LAN), true).await;
        let port = rig.ctx.port();
        rig.until_state("the addresses", |state| !state.addresses_of(&AddressKind::V6).is_empty()).await;
        let state = rig.state();
        assert_eq!(
            state.addresses_of(&AddressKind::V6),
            [format!("[2001:db8::1]:{port}"), format!("[2001:db8:1::1]:{port}")]
        );
        assert!(state.mapping.is_none() && public_of(&state).is_empty(), "and no router answered");
        // They are in `Reach` and in the status.
        assert_eq!(state.status().v6.len(), 2);
        rig.finish().await;
    }

    #[tokio::test(start_paused = true)]
    async fn the_ipv6_addresses_follow_the_machine_every_minute() {
        let fake = Fake::new();
        fake.has_ipv6(&[("2001:db8::1", 5)]);
        let rig = Rig::start_with(Timing::default(), fake, Some(LAN), true).await;
        let port = rig.ctx.port();
        rig.until_state("the address", |state| !state.addresses_of(&AddressKind::V6).is_empty()).await;

        // The provider changes the prefix.
        rig.fake.has_ipv6(&[("2001:db8:2::7", 5)]);
        rig.until_state("the new address", |state| {
            state.addresses_of(&AddressKind::V6) == [format!("[2001:db8:2::7]:{port}")]
        })
        .await;
        // And then there is none.
        rig.fake.has_ipv6(&[]);
        rig.until_state("none", |state| state.addresses_of(&AddressKind::V6).is_empty()).await;
        rig.finish().await;
    }

    #[tokio::test(start_paused = true)]
    async fn an_ipv6_look_that_does_not_come_back_leaves_the_list_as_it_was() {
        let fake = Fake::new();
        fake.has_ipv6(&[("2001:db8::1", 5)]);
        let rig = Rig::start_with(Timing::default(), fake, Some(LAN), true).await;
        rig.until_state("the address", |state| !state.addresses_of(&AddressKind::V6).is_empty()).await;
        let listed = rig.state().addresses_of(&AddressKind::V6);

        rig.fake.v6_hangs.store(true, Ordering::SeqCst);
        tokio::time::sleep(secs(300)).await;
        assert_eq!(rig.state().addresses_of(&AddressKind::V6), listed, "not knowing is not 'there are none'");

        // Nor is a look that says at once that it cannot tell.
        rig.fake.v6_hangs.store(false, Ordering::SeqCst);
        rig.fake.v6_unknown.store(true, Ordering::SeqCst);
        tokio::time::sleep(secs(300)).await;
        assert_eq!(rig.state().addresses_of(&AddressKind::V6), listed);
        rig.finish().await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_socket_that_is_not_dual_stack_lists_no_ipv6_address() {
        let fake = Fake::new();
        fake.has_ipv6(&[("2001:db8::1", 5)]);
        fake.will_map(Reply::Mapped(natpmp(51820)));
        let rig = Rig::start(fake).await; // the context's socket is IPv4
        rig.until_state("the address", |state| !public_of(state).is_empty()).await;
        tokio::time::sleep(secs(300)).await;
        assert!(rig.state().addresses_of(&AddressKind::V6).is_empty());
        rig.finish().await;
    }

    #[tokio::test]
    async fn a_look_at_the_network_cards_that_never_comes_back_is_not_started_again_nor_waited_for_again() {
        use std::sync::atomic::AtomicUsize;
        static STARTED: AtomicUsize = AtomicUsize::new(0);
        static RELEASED: AtomicBool = AtomicBool::new(false);
        fn walk() -> Vec<GlobalV6> {
            STARTED.fetch_add(1, Ordering::SeqCst);
            while !RELEASED.load(Ordering::SeqCst) {
                std::thread::sleep(ms(5));
            }
            Vec::new()
        }
        /// Lets the stuck walk go however the test ends: the runtime waits for it when it is dropped.
        struct Release;
        impl Drop for Release {
            fn drop(&mut self) {
                RELEASED.store(true, Ordering::SeqCst);
            }
        }
        let release = Release;

        let system = System::new(walk);
        // The first look gives up on the stuck walk...
        assert!(tokio::time::timeout(ms(30), system.global_v6()).await.is_err(), "the walk is stuck");
        let started = async {
            while STARTED.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(ms(5)).await;
            }
        };
        tokio::time::timeout(secs(10), started).await.expect("the walk started");
        // ...and the next ones neither start another walk nor wait for this one.
        for _ in 0..3 {
            let found = tokio::time::timeout(secs(10), system.global_v6()).await.expect("no waiting for a stuck walk");
            assert!(found.is_none(), "not known while the walk is stuck");
        }
        tokio::time::sleep(ms(100)).await;
        assert_eq!(STARTED.load(Ordering::SeqCst), 1, "four looks, one walk");

        // Once that walk is over its answer is the next look's, whenever it was started...
        drop(release);
        let looking = async {
            loop {
                if let Some(found) = system.global_v6().await {
                    break found;
                }
                tokio::time::sleep(ms(5)).await;
            }
        };
        let found = tokio::time::timeout(secs(10), looking).await.expect("a look works again once the walk is over");
        assert!(found.is_empty());
        assert_eq!(STARTED.load(Ordering::SeqCst), 1, "the answer of the walk that was given up on");
        // ...and the look after that is a walk of its own.
        let found = tokio::time::timeout(secs(10), system.global_v6()).await.expect("a walk that ends at once");
        assert!(found.is_some());
        assert_eq!(STARTED.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn what_the_socket_listens_on_decides_whether_ipv6_addresses_are_worth_listing() {
        let listens = |text: &str| listens_on_ipv6(text.parse().unwrap());
        assert!(listens("[::]:7420"), "dual-stack");
        assert!(!listens("0.0.0.0:7420"));
        assert!(!listens("192.0.2.10:7420"));
        assert!(!listens("[::1]:7420"), "one address, which is not the PC's");
        assert!(!listens("[2001:db8::5]:7420"), "one address");
    }

    #[test]
    fn the_first_address_of_each_interface_is_the_one_and_the_order_is_kept() {
        let found: Vec<GlobalV6> =
            [("2001:db8::1", 5), ("2001:db8::2", 5), ("2001:db8:1::1", 6), ("2001:db8:1::2", 6), ("2001:db8:2::1", 5)]
                .iter()
                .map(|(addr, interface)| GlobalV6 {
                    addr: addr.parse().unwrap(),
                    interface: *interface,
                    valid_for: None,
                })
                .collect();
        let texts: Vec<String> = first_of_each_interface(&found).iter().map(|addr| addr.to_string()).collect();
        assert_eq!(texts, ["2001:db8::1", "2001:db8:1::1"]);
        assert!(first_of_each_interface(&[]).is_empty());
    }

    // === a host that nobody outside can reach ===

    #[tokio::test(start_paused = true)]
    async fn a_host_that_listens_on_the_loopback_only_touches_nothing_and_lists_nothing() {
        let fake = Fake::new();
        fake.will_map(Reply::Mapped(natpmp(51820)));
        fake.has_ipv6(&[("2001:db8::1", 5)]);
        let (ctx, _scratch) = testing::context("e2-loopback");
        assert!(ctx.socket.local_addr().ip().is_loopback(), "the premise");
        let (stop, stopped) = watch::channel(false);
        let ctx = ReachContext { stop: Stop::new(stopped), ..ctx };
        ctx.reach.update(|state| state.set_addresses(AddressKind::Lan, vec![LAN.into()]));
        let task = tokio::spawn({
            let (ctx, fake) = (ctx.clone(), fake.clone());
            async move { run_on(&ctx, fake.as_ref(), Timing::default()).await }
        });
        tokio::time::sleep(secs(3600)).await;
        assert!(fake.calls().is_empty(), "nothing was asked of the router");
        let state = ctx.reach.read().clone();
        assert!(
            state.mapping.is_none() && public_of(&state).is_empty() && state.addresses_of(&AddressKind::V6).is_empty()
        );

        stop.send(true).unwrap();
        tokio::time::timeout(secs(1), task).await.expect("it ends when told to").unwrap();
    }

    #[test]
    fn only_a_socket_bound_to_every_address_is_given_a_port_on_the_router() {
        let takes = |text: &str| takes_forwarded_packets(text.parse().unwrap());
        assert!(takes("0.0.0.0:7420"));
        assert!(takes("[::]:7420"));
        assert!(!takes("127.0.0.1:7420"), "the loopback");
        assert!(!takes("[::1]:7420"));
        assert!(!takes("192.0.2.10:7420"), "one card, which may not be the one the router sees");
        assert!(!takes("100.64.1.2:7420"), "a VPN mesh's address");
        assert!(!takes("[2001:db8::5]:7420"));
    }

    // === what is said ===

    /// What the host logs at info and above, in this process. The tests share one subscriber, set for the whole
    /// process: one set for a thread alone misses the log lines whose callsite another test's thread hit first. Each
    /// test finds its own lines by something only it says.
    #[derive(Clone, Default)]
    struct Logged(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Logged {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            lock(&self.0).extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Logged {
        type Writer = Logged;

        fn make_writer(&'a self) -> Logged {
            self.clone()
        }
    }

    impl Logged {
        fn text(&self) -> String {
            String::from_utf8_lossy(&lock(&self.0)).into_owned()
        }

        /// How many lines say `what`.
        fn lines_saying(&self, what: &str) -> usize {
            self.text().lines().filter(|line| line.contains(what)).count()
        }
    }

    fn logged() -> &'static Logged {
        static LOGGED: std::sync::OnceLock<Logged> = std::sync::OnceLock::new();
        LOGGED.get_or_init(|| {
            let logged = Logged::default();
            let subscriber = tracing_subscriber::fmt()
                .with_max_level(tracing::Level::INFO)
                .with_ansi(false)
                .with_writer(logged.clone())
                .finish();
            tracing::subscriber::set_global_default(subscriber).expect("the tests' log is the process's only one");
            logged
        })
    }

    #[tokio::test(start_paused = true)]
    async fn the_cgnat_case_is_logged_once_however_often_it_is_renewed() {
        let log = logged();
        let fake = Fake::new();
        // A port that no other test uses, so that their lines are not counted.
        fake.will_map(Reply::Mapped(granted_at("100.64.0.9", 51891, 3600, MappingProtocol::Upnp)));
        let rig = Rig::start(fake).await;
        rig.fake.until(5).await; // the mapping, and four renewals in the two hours after
        rig.finish().await;
        assert_eq!(log.lines_saying("(100.64.0.9:51891) is not advertised"), 1, "{}", log.text());
    }

    #[tokio::test(start_paused = true)]
    async fn no_router_is_logged_once_for_as_long_as_the_reason_stays_the_same() {
        let log = logged();
        let fake = Fake::new();
        // Reasons that no other test gives, so that their lines are not counted.
        for _ in 0..3 {
            fake.will_map(Reply::Failed("marker-one"));
        }
        for _ in 0..2 {
            fake.will_map(Reply::Failed("marker-two"));
        }
        let rig = Rig::start(fake).await;
        rig.fake.until(5).await; // the fifth request is made when the fourth has failed, and the third before it
        assert_eq!(log.lines_saying("NAT-PMP: marker-one"), 1, "three failures, one line: {}", log.text());
        assert_eq!(log.lines_saying("NAT-PMP: marker-two"), 1, "another reason is news, once: {}", log.text());
        rig.finish().await;
    }

    // === the numbers ===

    #[test]
    fn the_pauses_after_a_failure_double_up_to_half_an_hour() {
        let timing = Timing::default();
        let waits: Vec<u64> = (1..=9).map(|failures| backoff(&timing, failures).as_secs()).collect();
        assert_eq!(waits, [60, 120, 240, 480, 960, 1800, 1800, 1800, 1800]);
        assert_eq!(backoff(&timing, u32::MAX).as_secs(), 1800, "and no failure count overflows it");
    }

    #[test]
    fn a_machine_has_slept_when_the_wall_clock_ran_far_ahead_of_the_monotonic_one() {
        assert!(!slept(secs(60), 60));
        assert!(!slept(secs(60), 61), "a second of difference is the clocks' business");
        assert!(!slept(secs(60), 60 + 120), "exactly the margin is not enough");
        assert!(slept(secs(60), 60 + 121));
        assert!(!slept(secs(60), 0), "a wall clock that was set back is no sleep");
    }

    // === by hand ===

    /// By hand: `cargo test -p velora-host -- --ignored --nocapture on_this_network`. Asks the real router of the
    /// machine it runs on for a mapping of the port of a throwaway socket (a router that answers keeps it for a few
    /// seconds, until the test gives it back) and prints what the task found. This is the field test I1 in small.
    #[tokio::test]
    #[ignore = "asks the real router of this machine; run by hand"]
    async fn on_this_network_the_router_is_really_asked() {
        // What the task and the library say, so that a field test shows the reasons too.
        let _log = tracing::subscriber::set_default(
            tracing_subscriber::fmt().with_max_level(tracing::Level::DEBUG).with_test_writer().finish(),
        );
        let (ctx, _scratch) = testing::context("e2-real");
        let ctx = punch::test_support::dual_stack(ctx);
        let (stop, stopped) = watch::channel(false);
        let ctx = ReachContext { stop: Stop::new(stopped), ..ctx };
        assert!(!ctx.socket.local_addr().ip().is_loopback(), "the premise: a socket the router could forward to");
        let (lan, _vpn) = crate::server::local_addresses(ctx.bind);
        ctx.reach.update(|state| state.set_addresses(AddressKind::Lan, lan.into_iter().collect()));
        let started = std::time::Instant::now();
        let task = tokio::spawn({
            let ctx = ctx.clone();
            async move { run_on(&ctx, &System::new(global_ipv6), Timing::default()).await }
        });
        tokio::time::sleep(Duration::from_secs(15)).await;
        let state = ctx.reach.read().clone();
        println!("after {:?}: mapping {:?}", started.elapsed(), state.mapping);
        println!(
            "public {:?}, IPv6 {:?}",
            state.addresses_of(&AddressKind::Public),
            state.addresses_of(&AddressKind::V6)
        );
        stop.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(10), task).await.expect("it ends when told to").unwrap();
        let state = ctx.reach.read().clone();
        assert!(state.mapping.is_none() && state.addresses_of(&AddressKind::Public).is_empty());
        println!("stopped after {:?}", started.elapsed());
    }
}
