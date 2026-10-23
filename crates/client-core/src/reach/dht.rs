//! F2: finding the host through its record in the Mainline DHT (`docs/nat-traversal.md`, phase 2).
//!
//! The host publishes a signed record at its own key, sealed so that only the devices paired with it can read it (see
//! `velora_dht::{record, seal}`). It is how a client learns where a host is now when the addresses it stored are out of date:
//! the host's IP changed, or a mapping moved. [`resolve_record`] opens a DHT node from this device's saved routing table, asks
//! for the record under the key the host sent in its `Reach`, opens it with this device's secret and turns what it lists
//! into [`Candidate`]s for the race: the addresses, the relays the host is registered with and, where its NAT allows, a hole
//! punch toward the endpoint the NAT shows.
//!
//! The record is not trusted: a fake one can only point the client at a wrong address, where the TLS handshake fails, so
//! everything in it is checked for form (it must open, name this host, and be recent) and nothing else. A record that does
//! not open, or is damaged, or is not there, is "no candidates" and a line at debug level, never an error and never a panic.

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic))]

use std::{
    future::Future,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, Result};
use tokio::time::Instant;
use velora_dht::{
    node::{Config, Error as NodeError, Mode, Node, ResolveOptions, Resolved},
    record::{self, Kind, Nat, Record},
    seal::{self, OpenError, Secret},
};
use velora_nat::addresses::classify;
use velora_protocol::{tls::Fingerprint, wire::AddressKind};

use super::{non_zero, Candidate, RelayRef};
use crate::ConnectParams;

/// The time [`resolve_record`] has in all, from its start to its answer, the opening of the node included. Its first value
/// comes in 0.3-1 s from a saved routing table and 1-2 s without one (C2, S0); a cold lookup that heard from too few nodes is
/// repeated once on the same node and then needs about 6 s. The plan said 5 s, which cuts exactly those: nothing waits for
/// this (the race has the stored addresses meanwhile, and ends it as soon as one of them connects), so it is not shorter than
/// the lookups that can succeed. The race's own limit ([`LOOKUP_LIMIT`](super::LOOKUP_LIMIT), 10 s) is the safety net behind it.
const RESOLVE_CAP: Duration = Duration::from_secs(6);

/// The lookup's own deadline is the cap; this much more is allowed to a source that ignores it before the lookup is cut.
const GRACE: Duration = Duration::from_secs(1);

/// A record this much older than the clock (or ahead of it) is not read. The host republishes every 30 minutes and the nodes
/// drop an item after about two hours, so an older one is not from a running host, or comes from a clock that is a day off:
/// its addresses are probably someone else's by now. The bound is a day and not hours so that an ordinary clock error does not
/// silence the DHT for a device.
const MAX_RECORD_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// The file this device's DHT routing table is kept in, in its state directory. A table saved right after a lookup makes the
/// next one start in a fraction of a second; a node rots in 15 minutes, so it is saved at the end of each lookup.
const CACHE_FILE: &str = "dht_cache.txt";

/// How long the routing table gets to be written once the answer is known.
const SAVE_WAIT: Duration = Duration::from_secs(1);

const _: () = assert!(
    RESOLVE_CAP.as_millis() + GRACE.as_millis() < super::LOOKUP_LIMIT.as_millis(),
    "the race's limit must stay behind the lookup's cap"
);

/// Most relays a punch is told it may signal through.
const MAX_VIA: usize = 4;

/// Most hole punches one record asks for (it lists one observed endpoint, or the mapped addresses).
const MAX_PUNCH: usize = 2;

/// Where this device keeps its DHT routing table. The punch dialer (F4) opens a node of its own to publish its request: it
/// uses this file too, which the node supports (two nodes on one file keep each other's entries).
pub(super) fn cache_path(state_dir: &Path) -> PathBuf {
    state_dir.join(CACHE_FILE)
}

/// Looks the host up in the DHT and returns the ways of reaching it that its record lists.
///
/// **Receives** `params`, the connection being made. The race asks only when `params.reach` holds the host's DHT key and
/// this device's secret, so there `params.reach` is `Some` and `host.key` / `host.secret` are `Some`: `key` is where the
/// record lives (salt `velora_dht::record::SALT`), `secret` opens it (`velora_dht::seal::open`) and
/// `params.host_fingerprint` is what the record's own fingerprint must match. `reach.state_dir` is this device's state
/// directory, for the node's routing-table cache. A key or a secret that is missing or all zeros ends it at once with no
/// candidates, before anything is opened.
///
/// **Returns** the candidates the record lists, in this order: a `Candidate::Direct` for each address (with its kind, and in
/// the order the record lists them), a `Candidate::Punch` toward each `Public` address when the host's NAT is `Open` or `Cone`
/// (`via` are the relays the record lists, to signal through; empty means through the DHT), a `Candidate::Relay` for each
/// address of each relay in the record (`target` is `params.host_fingerprint`). The race drops what it already tries, so
/// repeating the stored addresses is fine. `Ok(vec![])` means "no record" (never published, expired or older than a day, not
/// this host's, damaged, or this device was removed from the host: its secret does not open it); `Err` is a lookup that could
/// not run or did not finish (no network, UDP blocked, out of time). The race logs an error at debug level and carries on:
/// neither is ever fatal.
///
/// **Timing.** The race starts it [`LOOKUP_DELAY`](super::LOOKUP_DELAY) after it began (at once when nothing else is
/// running or waiting), so a LAN or VPN address that answers in milliseconds never touches the DHT. It has [`RESOLVE_CAP`]
/// in all (6 s); it runs in a task of its own, so the future is `Send`, and it is aborted when another candidate wins, and
/// after [`LOOKUP_LIMIT`](super::LOOKUP_LIMIT) at the latest. The routing table is saved when the lookup ends, which a
/// connection that wins first skips: the table was already as good as the last lookup left it.
pub async fn resolve_record(params: &ConnectParams) -> Result<Vec<Candidate>> {
    let Some(lookup) = Lookup::of(params) else {
        tracing::debug!("no DHT key or secret for the host: not looking for its record");
        return Ok(Vec::new());
    };
    let mut config = Config::new(Mode::Client);
    config.cache_path = Some(cache_path(&lookup.state_dir));
    resolve_with(config, &lookup, RESOLVE_CAP).await
}

/// What a lookup needs, from the connection being made.
struct Lookup {
    /// The host's Ed25519 key: where its record is.
    key: [u8; 32],
    /// This device's secret: what opens the record.
    secret: Secret,
    host: Fingerprint,
    state_dir: PathBuf,
}

impl Lookup {
    /// `None` when there is nothing to look for: the connection has no stored entry, or it has no key or no secret (or
    /// zeros, which a host with no record sends).
    fn of(params: &ConnectParams) -> Option<Lookup> {
        let reach = params.reach.as_ref()?;
        let key = reach.host.key.and_then(non_zero)?;
        let secret = reach.host.secret.and_then(non_zero)?;
        Some(Lookup {
            key,
            secret: Secret::new(secret),
            host: params.host_fingerprint,
            state_dir: reach.state_dir.clone(),
        })
    }
}

/// Where a record is looked up: a DHT node, or a stand-in in the tests.
trait Source {
    /// The record under `key` and `salt`, looked for for at most `deadline`. `Ok(None)` is "there is none".
    fn record(
        &self,
        key: [u8; 32],
        salt: &'static [u8],
        deadline: Duration,
    ) -> impl Future<Output = Result<Option<Resolved>, NodeError>> + Send;
}

impl Source for Node {
    async fn record(
        &self,
        key: [u8; 32],
        salt: &'static [u8],
        deadline: Duration,
    ) -> Result<Option<Resolved>, NodeError> {
        // The 200 ms the node keeps listening for a newer record after the first is what keeps an old one, from a node that
        // has not heard of the host's new address yet, from being taken for the record.
        let options = ResolveOptions { newer_than: None, deadline: Some(deadline) };
        self.resolve_with(&key, salt, &options).await
    }
}

/// Opens the node from `config`, looks for the record and saves the routing table. The cap covers all of it.
async fn resolve_with(config: Config, lookup: &Lookup, cap: Duration) -> Result<Vec<Candidate>> {
    let started = Instant::now();
    let node = Node::open_with(config).await;
    let found = find(&node, lookup, cap.saturating_sub(started.elapsed())).await;
    // The table is fullest right after a lookup and rots in minutes: leave it for the next connection. The node does it by
    // itself three seconds after a resolve, which is later than this device keeps the node.
    if let Err(e) = tokio::time::timeout(SAVE_WAIT, node.save_cache()).await.unwrap_or(Ok(false)) {
        tracing::debug!("the DHT routing table was not saved: {e}");
    }
    found
}

/// Asks `source` for the host's record, for at most `cap`, and turns it into candidates.
async fn find<S: Source>(source: &S, lookup: &Lookup, cap: Duration) -> Result<Vec<Candidate>> {
    // The source keeps to its deadline; the bound here is for one that does not.
    let answer = tokio::time::timeout(cap + GRACE, source.record(lookup.key, record::SALT, cap))
        .await
        .map_err(|_| anyhow!("the DHT lookup did not finish in time"))?;
    match answer {
        Ok(Some(resolved)) => Ok(candidates(lookup, &resolved, now())),
        Ok(None) => {
            tracing::debug!("the host has no record in the DHT");
            Ok(Vec::new())
        }
        Err(e) => Err(anyhow::Error::new(e).context("the DHT lookup failed")),
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |since| since.as_secs())
}

/// Opens what the DHT returned and lists the ways in that it holds. Nothing here is an error: a record that cannot be used is
/// no candidates.
fn candidates(lookup: &Lookup, resolved: &Resolved, now: u64) -> Vec<Candidate> {
    let record = match seal::open(&resolved.value, record::SALT, resolved.seq, &lookup.secret) {
        Ok(record) => record,
        // A wrong secret, a removed device, a blob sealed for another sequence number: they look alike on purpose, and none
        // is an attack (anyone can put anything at a key they hold, and this key is the host's).
        Err(OpenError::NotRecipient) => {
            tracing::debug!(
                "the host's record does not open with this device's secret: it was removed from the host, or its secret is stale"
            );
            return Vec::new();
        }
        Err(e) => {
            tracing::debug!("the host's record cannot be used: {e}");
            return Vec::new();
        }
    };
    if record.fingerprint != lookup.host.0 {
        tracing::debug!("the record at the host's key is another host's");
        return Vec::new();
    }
    if record.ts.abs_diff(now) > MAX_RECORD_AGE.as_secs() {
        tracing::debug!("the host's record is {} hours from the clock: not read", record.ts.abs_diff(now) / 3600);
        return Vec::new();
    }
    let found = from_record(&record, lookup.host);
    tracing::info!(
        "the host's record in the DHT lists {} addresses and {} relays, {} ways in",
        record.addresses.len(),
        record.relays.len(),
        found.len()
    );
    found
}

/// The candidates a record holds: its addresses, a punch toward its public ones where the NAT allows it, and its relays.
fn from_record(record: &Record, host: Fingerprint) -> Vec<Candidate> {
    // The relays the host is registered with, one reference for each address. A relay entry among the addresses has no
    // fingerprint in a record (the kind is a code), so the list of relays is where they come from.
    let relays: Vec<RelayRef> = record
        .relays
        .iter()
        .filter(|relay| relay.fingerprint != host.0)
        .flat_map(|relay| {
            let fingerprint = Fingerprint(relay.fingerprint);
            relay.addresses.iter().filter_map(move |text| {
                let addr = text.parse().ok();
                if addr.is_none() {
                    tracing::debug!("a relay address in the host's record does not parse");
                }
                addr.map(|addr| RelayRef { addr, fingerprint })
            })
        })
        .collect();

    let mut found = Vec::new();
    for (kind, text) in &record.addresses {
        let Some(kind) = address_kind(*kind) else { continue };
        match text.parse() {
            Ok(addr) => found.push(Candidate::Direct(addr, kind)),
            Err(_) => tracing::debug!("an address in the host's record does not parse"),
        }
    }

    // Only the endpoint a NAT shows can need a punch, and only a NAT that shows the same one to everybody lets it work. An
    // `Open` host has no NAT at all, but its firewall may drop what it was not expecting, which the punch is for as well. A
    // host with a mapped port lists that address: the direct candidate wins before the punch would start.
    if matches!(record.nat, Nat::Open | Nat::Cone) {
        let via: Vec<RelayRef> = relays.iter().copied().take(MAX_VIA).collect();
        let public = record.addresses.iter().filter(|(kind, _)| *kind == Kind::Public);
        let endpoints = public.filter_map(|(_, text)| text.parse::<SocketAddr>().ok());
        for endpoint in endpoints.filter(|endpoint| classify(endpoint.ip()).is_global()).take(MAX_PUNCH) {
            found.push(Candidate::Punch { endpoint, via: via.clone() });
        }
    }

    found.extend(relays.into_iter().map(|relay| Candidate::Relay {
        relay_addr: relay.addr,
        relay_fingerprint: relay.fingerprint,
        target: host,
    }));
    found
}

/// What the race calls an address of this kind. `None` for a relay's: see [`from_record`].
fn address_kind(kind: Kind) -> Option<AddressKind> {
    match kind {
        Kind::Lan => Some(AddressKind::Lan),
        Kind::Vpn => Some(AddressKind::Vpn),
        Kind::Public => Some(AddressKind::Public),
        Kind::V6 => Some(AddressKind::V6),
        Kind::Relay => None,
        // From a newer host: a plain address as far as this version can tell, like the ones in a `Reach`.
        Kind::Other(code) => Some(AddressKind::Other(code)),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use velora_dht::{node::DefaultNodes, record::Relay};
    use velora_protocol::identity::{Identity, KnownHost};

    use super::*;
    use crate::{
        reach::ReachParams,
        testing::{within, TempDir},
    };

    const HOST: Fingerprint = Fingerprint([9; 32]);
    const KEY: [u8; 32] = [7; 32];
    const SECRET: [u8; 16] = [5; 16];

    fn lookup() -> Lookup {
        Lookup { key: KEY, secret: Secret::new(SECRET), host: HOST, state_dir: PathBuf::from("state") }
    }

    /// An address on the public internet, as far as this crate can tell (the documentation ranges are not).
    const PUBLIC: &str = "1.2.3.4:51820";

    fn relay_entry(fingerprint: u8, addresses: &[&str]) -> Relay {
        Relay { fingerprint: [fingerprint; 32], addresses: addresses.iter().map(|a| a.to_string()).collect() }
    }

    /// What a host behind a cone NAT with one relay publishes.
    fn record(nat: Nat) -> Record {
        Record {
            fingerprint: HOST.0,
            addresses: vec![
                (Kind::Lan, "192.0.2.10:7420".into()),
                (Kind::Vpn, "100.101.102.103:7420".into()),
                (Kind::Public, PUBLIC.into()),
                (Kind::V6, "[2606:4700:4700::1111]:7420".into()),
            ],
            nat,
            relays: vec![relay_entry(3, &["203.0.113.9:7420", "203.0.113.10:7420"])],
            mac: Some([0x02, 1, 2, 3, 4, 5]),
            ts: now(),
        }
    }

    fn seal_for(record: &Record, seq: i64, secret: [u8; 16]) -> Resolved {
        let sealed = seal::seal(record, record::SALT, seq, &[Secret::new(secret)], None).unwrap();
        Resolved { value: sealed.blob, seq }
    }

    fn relay_ref(fingerprint: u8, last: u8) -> RelayRef {
        RelayRef { addr: SocketAddr::from(([203, 0, 113, last], 7420)), fingerprint: Fingerprint([fingerprint; 32]) }
    }

    fn relay_candidate(fingerprint: u8, last: u8) -> Candidate {
        let RelayRef { addr, fingerprint } = relay_ref(fingerprint, last);
        Candidate::Relay { relay_addr: addr, relay_fingerprint: fingerprint, target: HOST }
    }

    // ---- from the record to the candidates ----

    #[test]
    fn a_record_gives_its_addresses_a_punch_and_its_relays_in_that_order() {
        let found = from_record(&record(Nat::Cone), HOST);
        assert_eq!(
            found,
            vec![
                Candidate::Direct("192.0.2.10:7420".parse().unwrap(), AddressKind::Lan),
                Candidate::Direct("100.101.102.103:7420".parse().unwrap(), AddressKind::Vpn),
                Candidate::Direct(PUBLIC.parse().unwrap(), AddressKind::Public),
                Candidate::Direct("[2606:4700:4700::1111]:7420".parse().unwrap(), AddressKind::V6),
                // Signalled through the relays the record lists.
                Candidate::Punch { endpoint: PUBLIC.parse().unwrap(), via: vec![relay_ref(3, 9), relay_ref(3, 10)] },
                relay_candidate(3, 9),
                relay_candidate(3, 10),
            ]
        );
    }

    #[test]
    fn only_a_nat_that_shows_one_endpoint_to_all_is_punched() {
        for (nat, punched) in [
            (Nat::Open, true),
            (Nat::Cone, true),
            (Nat::Symmetric, false),
            (Nat::Unknown, false),
            (Nat::Other(9), false),
        ] {
            let found = from_record(&record(nat), HOST);
            assert_eq!(found.iter().any(|c| matches!(c, Candidate::Punch { .. })), punched, "{nat:?}");
            // Whatever the NAT, the addresses and the relays are there.
            assert_eq!(found.len(), 4 + 2 + usize::from(punched), "{nat:?}");
        }
    }

    #[test]
    fn a_punch_needs_a_public_address_that_is_on_the_internet_and_goes_through_the_dht_without_relays() {
        let mut bare = record(Nat::Cone);
        bare.relays.clear();
        bare.addresses = vec![(Kind::Lan, "192.0.2.10:7420".into()), (Kind::Public, "10.0.0.5:7420".into())];
        // The only `Public` address is a private one, which no punch can reach.
        assert!(from_record(&bare, HOST).iter().all(|c| matches!(c, Candidate::Direct(..))));

        bare.addresses.push((Kind::Public, PUBLIC.into()));
        assert_eq!(
            from_record(&bare, HOST).last(),
            Some(&Candidate::Punch { endpoint: PUBLIC.parse().unwrap(), via: Vec::new() })
        );
        // The host has no address of this kind to punch toward at all.
        bare.addresses = vec![(Kind::Lan, "192.0.2.10:7420".into()), (Kind::V6, "[2606:4700:4700::1111]:7420".into())];
        assert!(from_record(&bare, HOST).iter().all(|c| matches!(c, Candidate::Direct(..))));
    }

    #[test]
    fn at_most_a_few_punches_and_a_few_relays_to_signal_through() {
        let mut crowded = record(Nat::Cone);
        crowded.addresses = (1..=5).map(|n| (Kind::Public, format!("1.2.3.{n}:51820"))).collect();
        crowded.relays = vec![relay_entry(
            3,
            &["203.0.113.1:1", "203.0.113.2:1", "203.0.113.3:1", "203.0.113.4:1", "203.0.113.5:1"],
        )];
        let found = from_record(&crowded, HOST);
        let punches: Vec<&Candidate> = found.iter().filter(|c| matches!(c, Candidate::Punch { .. })).collect();
        assert_eq!(punches.len(), MAX_PUNCH);
        assert!(punches.iter().all(|c| matches!(c, Candidate::Punch { via, .. } if via.len() == MAX_VIA)));
        // All five addresses of the relay are still ways in of their own.
        assert_eq!(found.iter().filter(|c| matches!(c, Candidate::Relay { .. })).count(), 5);
    }

    #[test]
    fn what_a_record_lists_that_cannot_be_used_is_left_out() {
        let mut odd = record(Nat::Unknown);
        odd.addresses = vec![
            (Kind::Lan, "not an address".into()),
            // A relay among the addresses has no fingerprint in a record: its relay is in the list of relays.
            (Kind::Relay, "203.0.113.50:7420".into()),
            // From a newer host.
            (Kind::Other(77), "192.0.2.77:7420".into()),
            (Kind::V6, "".into()),
        ];
        odd.relays = vec![
            relay_entry(3, &["garbage", "203.0.113.9:7420"]),
            // The host is never its own relay.
            Relay { fingerprint: HOST.0, addresses: vec!["203.0.113.11:7420".into()] },
        ];
        assert_eq!(
            from_record(&odd, HOST),
            vec![Candidate::Direct("192.0.2.77:7420".parse().unwrap(), AddressKind::Other(77)), relay_candidate(3, 9)]
        );
    }

    // ---- opening it ----

    #[test]
    fn a_record_that_opens_names_this_host_and_is_recent_gives_candidates() {
        let resolved = seal_for(&record(Nat::Cone), 1_000, SECRET);
        assert_eq!(candidates(&lookup(), &resolved, now()).len(), 7);
    }

    #[test]
    fn the_wrong_secret_or_a_record_sealed_for_another_sequence_number_is_no_record() {
        let record = record(Nat::Cone);
        // A device that was removed (the host seals without its secret), or whose secret is out of date.
        assert!(candidates(&lookup(), &seal_for(&record, 1_000, [6; 16]), now()).is_empty());
        // The sequence number is bound into the blob: the value of one record under the number of another does not open.
        let mut moved = seal_for(&record, 1_000, SECRET);
        moved.seq = 1_001;
        assert!(candidates(&lookup(), &moved, now()).is_empty());
    }

    #[test]
    fn a_record_of_another_host_is_no_record() {
        let mut other = record(Nat::Cone);
        other.fingerprint = [1; 32];
        assert!(candidates(&lookup(), &seal_for(&other, 1_000, SECRET), now()).is_empty());
    }

    #[test]
    fn a_record_a_day_from_the_clock_is_not_read_and_one_a_little_less_is() {
        let mut aged = record(Nat::Cone);
        let day = MAX_RECORD_AGE.as_secs();
        let clock = aged.ts + 5 * day;
        for (ts, read) in [
            (clock - 3600, true),
            (clock - day, true),
            (clock - day - 1, false),
            (clock - 3 * day, false),
            // A clock that is ahead of the host's by days, or a host's that is ahead of this one: the same.
            (clock + day, true),
            (clock + day + 1, false),
            (0, false),
        ] {
            aged.ts = ts;
            let found = candidates(&lookup(), &seal_for(&aged, 1_000, SECRET), clock);
            assert_eq!(!found.is_empty(), read, "ts {} against the clock {clock}", ts);
        }
    }

    #[test]
    fn junk_is_no_record_and_never_a_panic() {
        let good = seal_for(&record(Nat::Cone), 1_000, SECRET).value;
        let mut flipped = good.clone();
        if let Some(byte) = flipped.last_mut() {
            *byte ^= 1;
        }
        let mut another_version = good.clone();
        if let Some(byte) = another_version.first_mut() {
            *byte = 99;
        }
        let junk: Vec<Vec<u8>> = vec![
            Vec::new(),
            vec![0],
            vec![1],
            vec![1, 255],
            good[..good.len() / 2].to_vec(),
            good[..good.len() - 1].to_vec(),
            flipped,
            another_version,
            vec![0xAB; 996],
            vec![0xAB; 5000],
            // A record with trailing bytes cannot be made by `seal`; the length check is the first thing to refuse.
            [good.clone(), vec![0; 10]].concat(),
        ];
        for value in junk {
            let resolved = Resolved { value, seq: 1_000 };
            assert!(candidates(&lookup(), &resolved, now()).is_empty());
        }
    }

    // ---- asking ----

    /// What a lookup was asked: the key, the salt and the time it was given.
    type Asked = ([u8; 32], Vec<u8>, Duration);

    /// A DHT that answers from a script after a delay, and remembers what it was asked.
    struct Fake {
        delay: Duration,
        reply: Box<dyn Fn() -> Result<Option<Resolved>, NodeError> + Send + Sync>,
        asked: Mutex<Vec<Asked>>,
    }

    impl Fake {
        fn new(
            delay: Duration,
            reply: impl Fn() -> Result<Option<Resolved>, NodeError> + Send + Sync + 'static,
        ) -> Self {
            Self { delay, reply: Box::new(reply), asked: Mutex::new(Vec::new()) }
        }

        fn answering(resolved: Resolved) -> Self {
            Self::new(Duration::ZERO, move || Ok(Some(resolved.clone())))
        }

        fn asked(&self) -> Vec<Asked> {
            self.asked.lock().unwrap().clone()
        }
    }

    impl Source for Fake {
        async fn record(
            &self,
            key: [u8; 32],
            salt: &'static [u8],
            deadline: Duration,
        ) -> Result<Option<Resolved>, NodeError> {
            self.asked.lock().unwrap().push((key, salt.to_vec(), deadline));
            tokio::time::sleep(self.delay).await;
            (self.reply)()
        }
    }

    #[tokio::test]
    async fn the_host_is_asked_for_at_its_key_and_salt_with_the_time_there_is() {
        let fake = Fake::answering(seal_for(&record(Nat::Cone), 1_000, SECRET));
        let found = find(&fake, &lookup(), Duration::from_secs(4)).await.unwrap();
        assert_eq!(found.len(), 7);
        assert_eq!(fake.asked(), vec![(KEY, b"velora/1".to_vec(), Duration::from_secs(4))]);
    }

    #[tokio::test]
    async fn no_record_is_no_candidates_and_not_an_error() {
        let nothing = Fake::new(Duration::ZERO, || Ok(None));
        assert!(find(&nothing, &lookup(), RESOLVE_CAP).await.unwrap().is_empty());
        let removed = Fake::answering(seal_for(&record(Nat::Cone), 1_000, [6; 16]));
        assert!(find(&removed, &lookup(), RESOLVE_CAP).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_lookup_that_could_not_run_or_did_not_finish_is_an_error() {
        let failures: [fn() -> NodeError; 3] = [|| NodeError::NoNetwork, || NodeError::TimedOut, || NodeError::Stopped];
        for failure in failures {
            let fake = Fake::new(Duration::ZERO, move || Err(failure()));
            let err = find(&fake, &lookup(), RESOLVE_CAP).await.unwrap_err();
            assert!(err.downcast_ref::<NodeError>().is_some(), "{err:#}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_source_that_ignores_its_deadline_is_cut_after_a_second_more() {
        let stuck = Fake::new(Duration::from_secs(3600), || Ok(None));
        let began = Instant::now();
        let err = find(&stuck, &lookup(), Duration::from_secs(2)).await.unwrap_err();
        assert!(err.to_string().contains("did not finish in time"), "{err:#}");
        assert_eq!(began.elapsed(), Duration::from_secs(2) + GRACE);
        // One that answers late but in time is heard.
        let slow = Fake::new(Duration::from_secs(2), || Ok(None));
        assert!(find(&slow, &lookup(), Duration::from_secs(2)).await.unwrap().is_empty());
    }

    // ---- the hook ----

    fn params(host: KnownHost) -> ConnectParams {
        ConnectParams {
            addr: SocketAddr::from(([192, 0, 2, 1], 7420)),
            also: Vec::new(),
            host_fingerprint: HOST,
            identity: Identity::generate().unwrap(),
            device_name: "test device".into(),
            pairing_secret: None,
            password: None,
            reach: Some(ReachParams { host, state_dir: PathBuf::from("state") }),
        }
    }

    #[tokio::test]
    async fn without_a_key_or_a_secret_nothing_is_opened_and_nothing_is_asked() {
        // Anything that reached the network would have to open a node; these return before it.
        let with = |key, secret| params(KnownHost { key, secret, ..Default::default() });
        for p in [
            with(None, None),
            with(Some(KEY), None),
            with(None, Some(SECRET)),
            with(Some([0; 32]), Some(SECRET)),
            with(Some(KEY), Some([0; 16])),
        ] {
            assert_eq!(within("the hook", resolve_record(&p)).await.unwrap(), Vec::new());
        }
        let no_entry = ConnectParams { reach: None, ..with(None, None) };
        assert_eq!(within("the hook", resolve_record(&no_entry)).await.unwrap(), Vec::new());
    }

    #[tokio::test]
    async fn a_node_with_nobody_to_ask_is_no_network_and_the_cap_covers_the_opening_too() {
        let temp = TempDir::new();
        let mut config = Config::new(Mode::Client);
        config.default_nodes = DefaultNodes::fixed(Vec::new());
        config.cache_path = Some(cache_path(temp.path()));
        let began = std::time::Instant::now();
        let err = resolve_with(config, &lookup(), Duration::from_secs(5)).await.unwrap_err();
        assert!(matches!(err.downcast_ref::<NodeError>(), Some(NodeError::NoNetwork)), "{err:#}");
        assert!(began.elapsed() < Duration::from_secs(5), "{:?}", began.elapsed());
        // Nothing to save either: no table, no file.
        assert!(!cache_path(temp.path()).exists());
    }

    #[test]
    fn the_cache_lives_in_the_state_directory() {
        assert_eq!(cache_path(Path::new("state")), Path::new("state").join("dht_cache.txt"));
    }
}
