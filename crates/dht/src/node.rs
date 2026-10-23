//! The DHT node: open it from a saved routing table, publish a record, resolve one.
//!
//! A [`Node`] is a handle on one `mainline` DHT node (one thread, one UDP socket, a routing table). The host keeps
//! one for its lifetime and publishes through it; a client opens one when it connects, resolves, and lets it go.
//! Everything here is built on what `docs/dht-spike.md` measured on the live DHT with `mainline` 8.0.1:
//!
//! - A start is cheap (the first nodes arrive after 0.1 s), but the node is not *finished* for 3 s, and `bootstrapped()`
//!   and the observed address only exist after that. Nothing here waits for them: a lookup starts from the bootstrap
//!   list, and a cold start (no saved nodes) first waits, for at most 1.5 s, until the table holds a few nodes, because
//!   a lookup that starts from the four default names alone sometimes hears from none of them.
//! - The first value of a lookup arrives after 0.1 to 1.4 s and the lookup ends after 3 s, so [`Node::resolve`] stops at
//!   the first value (plus a short window for a newer one) instead of waiting for the end.
//! - The routing table rots in 15 minutes without lookups, and the default bootstrap names are resolved once, when the
//!   node is built. So the nodes of the table are saved right after a lookup or a publish, never over a table that is
//!   nearly empty, and a node that comes up with nothing to start from, or whose table stays empty, is built again.
//! - A value over 996 bytes or a salt over 64 is refused by every node, but `mainline` reports that as a timeout, so
//!   both are checked before anything is sent. A put acknowledged by a handful of nodes can be unfindable, so it
//!   counts as failed. An equal `seq` is acknowledged and ignored, a lower one refused: see [`Node::next_seq`].
//!
//! Neither mode serves the DHT: `mainline` cannot be told to stay a client (it would turn into a server after 15
//! minutes if it believed itself reachable), so the node is given a filter that answers nobody.
//!
//! The methods need a Tokio runtime. A panic inside `mainline` (its calls panic once its thread is gone) is caught on
//! its own task and reported as [`Error::Stopped`]; the next call builds a new node.

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic))]

use std::{
    collections::HashMap,
    fmt, fs,
    future::Future,
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex, MutexGuard, PoisonError,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use futures_lite::StreamExt;
use mainline::{
    async_dht::{AsyncDht, GetMutableDetailed},
    errors::{PutMutableError, PutQueryError},
    Dht, GetMutableOutcome, MutableItem, RequestFilter, RequestSpecific, ServerSettings, SigningKey,
    DEFAULT_BOOTSTRAP_NODES,
};
use thiserror::Error;
use tokio::{
    sync::{mpsc, oneshot},
    time::{sleep, timeout, timeout_at, Instant},
};
use tracing::{debug, info, warn};

use crate::keys::Keys;

/// The longest value a DHT node takes. BEP 44 allows 1000 bytes of bencoded value, and a byte string of this size is
/// written with a four-byte `NNN:` prefix; the nodes refuse 997 bytes, measured.
pub const MAX_VALUE_LEN: usize = 1000 - 4;

/// The longest salt, from BEP 44 (a 65-byte one is refused, measured).
pub const MAX_SALT_LEN: usize = 64;

/// How many nodes count as "enough": table entries before a cold lookup, answers that make a lookup healthy, nodes that
/// must acknowledge a put. A network smaller than this (a test network) lowers it to its own size, and
/// [`Config::quorum`] sets it.
const QUORUM: usize = 8;

/// Saved nodes go in the bootstrap list in front of the default ones. Every lookup asks the whole list again while the
/// table is smaller than it, so a long list makes every lookup dearer (about 500 datagrams with 100 entries, 300 with
/// 20).
const MAX_SAVED_NODES: usize = 16;

/// The DHT thread looks at its mailbox every 50 ms, so asking it more often gains nothing.
const POLL: Duration = Duration::from_millis(50);

/// The longest a cold start waits for the table to fill before looking up anyway.
const READY_WAIT: Duration = Duration::from_millis(1500);

/// The longest the default names are waited for. With saved nodes they are only a fallback, so a slow resolver must
/// not hold a warm start; without them, they are all the node has.
const DNS_WAIT_WARM: Duration = Duration::from_millis(300);
const DNS_WAIT_COLD: Duration = Duration::from_secs(2);

/// A retry of an empty lookup needs a lookup's worth of time left; the first value of one comes after about a second.
const MIN_RETRY: Duration = Duration::from_secs(1);

/// A resolve saves the routing table once its lookup has had time to end, when the table is fullest.
const SAVE_DELAY: Duration = Duration::from_secs(3);

/// A resolve does not rewrite the cache more often than this; a publish always does.
const SAVE_EVERY: Duration = Duration::from_secs(300);

/// A cache bigger than this is not ours.
const MAX_CACHE_BYTES: u64 = 64 * 1024;

/// How many `seq` numbers are kept in the cache file (the newest).
const MAX_SEQS: usize = 64;

/// A saved `seq` further ahead of the clock than this is a clock that was wrong once; it would pin the key ahead of
/// the clock for as long.
const MAX_SEQ_AHEAD: i64 = 7 * 24 * 60 * 60;

/// What the node is for. In both modes it answers nobody (see the module docs); they differ in how long it lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Opened to resolve (or to post a punch request) and then dropped: a short-lived node is never replaced.
    Client,
    /// Kept for the life of the process and used now and then. A node left alone for ten minutes has a rotted table,
    /// so the next call replaces it with one built from the table saved after the last use.
    Host,
}

/// Where the default bootstrap nodes come from.
#[derive(Clone)]
pub enum DefaultNodes {
    /// The well-known names of the public DHT (`mainline::DEFAULT_BOOTSTRAP_NODES`), resolved every time a node is
    /// built.
    Public,
    /// Whatever this returns every time a node is built: a test network, a private DHT. It must not block.
    With(Arc<dyn Fn() -> Vec<SocketAddrV4> + Send + Sync>),
}

impl DefaultNodes {
    /// These nodes, always.
    pub fn fixed(nodes: Vec<SocketAddrV4>) -> Self {
        Self::With(Arc::new(move || nodes.clone()))
    }
}

impl fmt::Debug for DefaultNodes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Public => f.write_str("Public"),
            Self::With(_) => f.write_str("With(..)"),
        }
    }
}

/// Everything [`Node::open_with`] can be told. Make one with [`Config::new`] and set what differs; only the cache
/// path matters in production, the rest is for tests and private networks.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Config {
    pub mode: Mode,
    /// Where the routing table and the last `seq` numbers are kept between runs. `None`: nothing is kept.
    pub cache_path: Option<PathBuf>,
    /// Where the nodes that come after the saved ones come from. `Public` in production.
    pub default_nodes: DefaultNodes,
    /// The address of the DHT socket. `None`: all interfaces.
    pub bind_address: Option<Ipv4Addr>,
    /// The port of the DHT socket. `None`: 6881, or any free port when that one is taken, which is what production
    /// wants (a busy fixed port is an error).
    pub port: Option<u16>,
    /// How long a node is waited for. `None`: `mainline`'s 2 s. A lookup lasts at least this long whenever one of the
    /// nodes it asks never answers, as on a test network, whose servers hand out the addresses of its clients.
    pub request_timeout: Option<Duration>,
    /// How long [`Node::resolve`] looks, retry included. A cold resolve that finds nothing takes about 6 s.
    pub resolve_deadline: Duration,
    /// How long [`Node::resolve`] keeps listening for a newer record after the first one.
    pub settle: Duration,
    /// How long [`Node::publish`] takes at most: a lookup and a put, twice when the first put was not enough.
    pub publish_deadline: Duration,
    /// Replace a node that has not been used for this long, before using it. `None`: never.
    pub recycle_after: Option<Duration>,
    /// How many nodes count as enough: in the table before a cold lookup, answering a lookup for it to be trusted,
    /// acknowledging a put. `None`: eight, or the size of the start list when it is smaller. The tests lower it: a
    /// network of three nodes would otherwise fail a put whenever one datagram is lost.
    pub quorum: Option<usize>,
}

impl Config {
    pub fn new(mode: Mode) -> Self {
        Self {
            mode,
            cache_path: None,
            default_nodes: DefaultNodes::Public,
            bind_address: None,
            port: None,
            request_timeout: None,
            resolve_deadline: Duration::from_secs(6),
            settle: Duration::from_millis(200),
            publish_deadline: Duration::from_secs(25),
            recycle_after: match mode {
                Mode::Client => None,
                Mode::Host => Some(Duration::from_secs(10 * 60)),
            },
            quorum: None,
        }
    }
}

/// What differs between two [`Node::resolve_with`] calls.
#[derive(Debug, Clone, Default)]
pub struct ResolveOptions {
    /// A poll for changes: only a record with a higher `seq` counts, and the nodes do not send the one the caller
    /// already has. An unchanged record reads as `None`.
    pub newer_than: Option<i64>,
    /// Gives up after this long. `None`: [`Config::resolve_deadline`].
    pub deadline: Option<Duration>,
}

/// Whatever signs a record: the device's [`Keys`], or a bare `mainline::SigningKey` (the punch items are signed with
/// a key derived from a device secret).
pub trait Signer {
    fn signing_key(&self) -> &SigningKey;

    /// The key the record is found by.
    fn public_key(&self) -> [u8; 32] {
        self.signing_key().verifying_key().to_bytes()
    }
}

impl Signer for SigningKey {
    fn signing_key(&self) -> &SigningKey {
        self
    }
}

impl Signer for Keys {
    fn signing_key(&self) -> &SigningKey {
        Keys::signing_key(self)
    }
}

/// What can go wrong, in the terms the callers decide on. "There is no record" is not one of them: that is
/// `Ok(None)` from [`Node::resolve`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// No DHT node answered: no network, a network that blocks UDP, or no node to start from. Worth trying again
    /// later; the node builds itself again on the next call.
    #[error("no DHT node answered: no network, or UDP is blocked")]
    NoNetwork,
    /// The value is longer than the nodes take (nothing was sent).
    #[error("a DHT value is at most {} bytes, this one has {len}", MAX_VALUE_LEN)]
    TooBig { len: usize },
    /// The salt is longer than the nodes take (nothing was sent).
    #[error("a DHT salt is at most {} bytes, this one has {len}", MAX_SALT_LEN)]
    SaltTooBig { len: usize },
    /// The nodes were there but did not keep the record: they refused it, did not answer, or too few acknowledged it
    /// for it to be found again. Nothing says which, because `mainline` reports all of them as a timeout.
    #[error("the DHT nodes did not keep the record ({acknowledged} acknowledged it)")]
    Refused { acknowledged: usize },
    /// A record with a `seq` at least as high is already stored. The blob was sealed for `seq` (the sealing binds it),
    /// so it cannot be sent with another: seal again with `seen + 1`, which is what [`Node::publish_with`] does.
    #[error("a record with seq {seen} is already stored, this one has {seq}: seal it again with a higher one")]
    SeqTooLow { seq: i64, seen: i64 },
    /// The DHT did not finish in time.
    #[error("the DHT did not finish in time")]
    TimedOut,
    /// The node's thread is gone (or the runtime is shutting down). The next call builds a new node.
    #[error("the DHT node stopped")]
    Stopped,
    /// The UDP socket could not be opened.
    #[error("cannot open the DHT socket")]
    Socket(#[source] io::Error),
    /// The cache file could not be written.
    #[error("cannot write the DHT cache")]
    Cache(#[source] io::Error),
    /// The closure that makes the blob for [`Node::publish_with`] failed.
    #[error("the record could not be made")]
    Blob(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// A record found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub value: Vec<u8>,
    /// The `seq` it was published with; the sealing binds it, so [`crate::seal::open`] needs it.
    pub seq: i64,
}

/// A record stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Published {
    pub seq: i64,
    /// How many nodes acknowledged it.
    pub stored_at: usize,
}

/// A handle on one DHT node. Cheap to clone: every clone is the same node, and the node ends with the last one.
#[derive(Clone)]
pub struct Node {
    inner: Arc<Inner>,
}

impl fmt::Debug for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Node").field("mode", &self.inner.config.mode).finish_non_exhaustive()
    }
}

impl Node {
    /// Opens a node that starts from the routing table saved at `cache_path`, when there is one, and the default
    /// bootstrap nodes behind it, and that saves its table there after its lookups and publishes.
    ///
    /// It does not fail: a network that is not there yet, or a socket that cannot be opened, are reported by the first
    /// call that needs the DHT, which tries again.
    pub async fn open(cache_path: impl AsRef<Path>, mode: Mode) -> Node {
        let mut config = Config::new(mode);
        config.cache_path = Some(cache_path.as_ref().to_path_buf());
        Self::open_with(config).await
    }

    /// [`Node::open`] with every setting.
    pub async fn open_with(config: Config) -> Node {
        let node = Node { inner: Arc::new(Inner::new(config)) };
        if let Some(path) = node.inner.config.cache_path.clone() {
            let cache = tokio::task::spawn_blocking(move || CacheFile::load(&path)).await.unwrap_or_default();
            node.inner.adopt(cache);
        }
        // Built now, so that it is warming up while the caller does other things; a failure is the first call's to
        // report.
        let started = node
            .run(|inner, used| async move {
                let handle = inner.handle().await?;
                used.store(handle.generation, Ordering::Relaxed);
                Ok(())
            })
            .await;
        if let Err(e) = started {
            debug!(error = %e, "the DHT node did not start yet");
        }
        node
    }

    pub fn mode(&self) -> Mode {
        self.inner.config.mode
    }

    /// The `seq` for the next record under this key and salt: the clock, or one more than the last one used or seen
    /// when that is not behind it. The nodes keep the first of two records with an equal `seq` and refuse a lower one,
    /// so two publishes in the same second, or a clock that stepped back, need this and not just the time. Seal the
    /// record with it and give the same number to [`Node::publish`].
    pub fn next_seq<S: Signer + ?Sized>(&self, signer: &S, salt: &[u8]) -> i64 {
        self.inner.next_seq(signer.public_key(), salt)
    }

    /// Stores `blob` under the signer's key and `salt`, with the `seq` it was sealed for.
    ///
    /// The nodes are read first: a record with a higher `seq` (or the same one and another value) makes this an
    /// [`Error::SeqTooLow`] before anything is sent. A put that fewer than a quorum of nodes acknowledge is tried once
    /// more, and then reported as [`Error::Refused`]. One publish runs at a time per node.
    pub async fn publish<S: Signer + ?Sized>(
        &self,
        signer: &S,
        salt: &[u8],
        blob: &[u8],
        seq: i64,
    ) -> Result<Published, Error> {
        if blob.len() > MAX_VALUE_LEN {
            return Err(Error::TooBig { len: blob.len() });
        }
        check_salt(salt)?;
        let public = signer.public_key();
        let salt = salt.to_vec();
        // Signed here, so that the key is not copied into the task.
        let item = MutableItem::new(signer.signing_key().clone(), blob, seq, salt_of(&salt));
        let deadline = after(self.inner.config.publish_deadline);
        self.run(move |inner, used| async move {
            inner.publish_op(&used, Publication { public, salt, item, deadline }).await
        })
        .await
    }

    /// [`Node::publish`] for a blob that depends on its `seq`, which the sealing does: `make_blob` is called with the
    /// `seq` to use, and again with a higher one (up to twice) when a record with a higher `seq` turns out to be
    /// stored, which is what a clock that stepped back, or a copy of the key somewhere else, leaves behind.
    pub async fn publish_with<S, F, E>(&self, signer: &S, salt: &[u8], mut make_blob: F) -> Result<Published, Error>
    where
        S: Signer + ?Sized,
        F: FnMut(i64) -> Result<Vec<u8>, E>,
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let mut seq = self.next_seq(signer, salt);
        let mut attempt = 0;
        loop {
            attempt += 1;
            let blob = make_blob(seq).map_err(|e| Error::Blob(e.into()))?;
            match self.publish(signer, salt, &blob, seq).await {
                Err(Error::SeqTooLow { seen, .. }) if attempt < 3 => {
                    seq = seen.saturating_add(1).max(self.next_seq(signer, salt));
                }
                other => return other,
            }
        }
    }

    /// Looks the record up: the first one a node returns, or a newer one that arrives within [`Config::settle`] of
    /// it. `Ok(None)` is "there is no record" (or none the nodes gave in time); [`Error::NoNetwork`] is "nobody
    /// answered".
    pub async fn resolve(&self, public_key: &[u8; 32], salt: &[u8]) -> Result<Option<Resolved>, Error> {
        self.resolve_with(public_key, salt, &ResolveOptions::default()).await
    }

    /// [`Node::resolve`] with options.
    pub async fn resolve_with(
        &self,
        public_key: &[u8; 32],
        salt: &[u8],
        options: &ResolveOptions,
    ) -> Result<Option<Resolved>, Error> {
        check_salt(salt)?;
        let (key, salt, options) = (*public_key, salt.to_vec(), options.clone());
        self.run(move |inner, used| async move { inner.resolve_op(&used, key, salt, options).await }).await
    }

    /// This node's public address as the DHT nodes see it (BEP 42), which is what a router mapping or a hole punch
    /// has to be compared with. `None` until the first lookup has ended (about 3 s after a start). It is not checked
    /// for being public: a few replies come from nodes inside the ISP and say `10.x`, and the library only counts
    /// votes. The last address seen is returned while a node that was built again learns it.
    pub async fn observed_address(&self) -> Option<SocketAddrV4> {
        let handle = self.inner.lock().running.as_ref().map(|r| r.handle.clone());
        let seen = match handle {
            Some(handle) => {
                self.run(move |_, _| async move { Ok(handle.dht.info().await.public_address()) }).await.ok().flatten()
            }
            None => None,
        };
        let mut state = self.inner.lock();
        if seen.is_some() {
            state.observed = seen;
        }
        state.observed
    }

    /// Writes the routing table and the `seq` numbers to the cache file now. [`Node::publish`] and [`Node::resolve`]
    /// already do it at the right time, right after a lookup, when the table is full; a table of fewer nodes than a
    /// quorum never replaces a saved one. `Ok(false)`: nothing to write (no cache path, or nothing changed).
    pub async fn save_cache(&self) -> Result<bool, Error> {
        self.run(|inner, _| async move { inner.save(true).await }).await
    }

    /// Runs `op` on a task of its own. `mainline` panics when its thread is gone, and it is a library handling
    /// whatever arrives from the internet; on the task that is a [`tokio::task::JoinError`] we can turn into an
    /// error and recover from, not a panic in the caller. `used` is the generation of the node `op` was using, so
    /// that only that one is forgotten.
    async fn run<T, F, Fut>(&self, op: F) -> Result<T, Error>
    where
        F: FnOnce(Arc<Inner>, Arc<AtomicU64>) -> Fut,
        Fut: Future<Output = Result<T, Error>> + Send + 'static,
        T: Send + 'static,
    {
        let used = Arc::new(AtomicU64::new(0));
        match tokio::spawn(op(self.inner.clone(), used.clone())).await {
            Ok(result) => result,
            Err(e) => {
                warn!(error = %e, "a DHT call ended without a result: the node is built again on the next call");
                self.inner.forget(used.load(Ordering::Relaxed));
                Err(Error::Stopped)
            }
        }
    }
}

struct Inner {
    config: Config,
    state: Mutex<State>,
    /// One build at a time: two calls that find the node missing would otherwise make two.
    build: tokio::sync::Mutex<()>,
    /// One publish at a time: `mainline` refuses a put while another one for the same key is in flight.
    publishing: tokio::sync::Mutex<()>,
    /// One write of the cache at a time: two would share the temporary file.
    saving: tokio::sync::Mutex<()>,
    generation: AtomicU64,
    save_scheduled: AtomicBool,
}

#[derive(Default)]
struct State {
    running: Option<Running>,
    /// The nodes of the cache, spread over the table they came from.
    saved: Vec<SocketAddrV4>,
    /// The last answer of the default names; used when they do not resolve.
    defaults: Vec<SocketAddrV4>,
    seqs: HashMap<SeqKey, SeqEntry>,
    seqs_dirty: bool,
    /// What the cache file holds, as far as this process knows.
    written: Option<Vec<u8>>,
    last_save: Option<Instant>,
    observed: Option<SocketAddrV4>,
}

type SeqKey = ([u8; 32], Vec<u8>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SeqEntry {
    seq: i64,
    /// Unix time of the last use, to drop the oldest when there are too many.
    at: i64,
}

struct Running {
    handle: Handle,
    /// What the node was built from, to tell whether building it again would change anything.
    list: Vec<SocketAddrV4>,
    /// When the node last did something useful. Wall clock, so a night asleep counts.
    fresh_since: SystemTime,
}

#[derive(Clone)]
struct Handle {
    dht: AsyncDht,
    /// Which node this is, so that a stale handle never forgets or touches its successor.
    generation: u64,
    quorum: usize,
    /// The list had a table's worth of saved nodes, so the node does not need to wait for its table to fill.
    warm: bool,
}

/// A record to publish, signed.
struct Publication {
    public: [u8; 32],
    salt: Vec<u8>,
    item: MutableItem,
    deadline: Instant,
}

impl Inner {
    fn new(config: Config) -> Self {
        Self {
            config,
            state: Mutex::new(State::default()),
            build: tokio::sync::Mutex::new(()),
            publishing: tokio::sync::Mutex::new(()),
            saving: tokio::sync::Mutex::new(()),
            generation: AtomicU64::new(0),
            save_scheduled: AtomicBool::new(false),
        }
    }

    /// A poisoned lock only means a panic elsewhere; the state is still plain data.
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn adopt(&self, cache: CacheFile) {
        let limit = unix_now().saturating_add(MAX_SEQ_AHEAD);
        let mut state = self.lock();
        // What the file holds, so that a save that would write the same thing does not.
        state.written = Some(cache.render());
        state.saved = spread(&cache.nodes, MAX_SAVED_NODES);
        for (key, entry) in cache.seqs {
            if entry.seq <= limit {
                state.seqs.insert(key, entry);
            }
        }
    }

    // === The node ===

    /// The running node, or a new one when there is none, or it has been left alone for too long.
    async fn handle(self: &Arc<Self>) -> Result<Handle, Error> {
        if let Some(handle) = self.fresh_handle() {
            return Ok(handle);
        }
        let _building = self.build.lock().await;
        if let Some(handle) = self.fresh_handle() {
            return Ok(handle);
        }
        let (list, warm) = self.bootstrap_list().await;
        self.build_from(list, warm).await
    }

    fn fresh_handle(&self) -> Option<Handle> {
        let state = self.lock();
        let running = state.running.as_ref()?;
        if let Some(limit) = self.config.recycle_after {
            if SystemTime::now().duration_since(running.fresh_since).unwrap_or_default() > limit {
                return None;
            }
        }
        Some(running.handle.clone())
    }

    /// The saved nodes, then the default ones. Saved ones first: they answer in 25 ms, and a start that only had the
    /// four names sometimes hears from none of them.
    async fn bootstrap_list(&self) -> (Vec<SocketAddrV4>, bool) {
        let saved = spread(&self.lock().saved, MAX_SAVED_NODES);
        let warm = saved.len() >= self.config.quorum.unwrap_or(QUORUM);
        let defaults = match &self.config.default_nodes {
            DefaultNodes::Public => self.public_defaults(if warm { DNS_WAIT_WARM } else { DNS_WAIT_COLD }).await,
            DefaultNodes::With(nodes) => nodes(),
        };
        let mut list = saved;
        for node in defaults {
            if !list.contains(&node) {
                list.push(node);
            }
        }
        (list, warm)
    }

    /// `mainline` resolves the names once, inside its blocking `build()`, with no limit on the wait and silently
    /// without the ones that fail. Done here instead, with a limit, and with the last good answer as the fallback.
    async fn public_defaults(&self, wait: Duration) -> Vec<SocketAddrV4> {
        let resolving = tokio::task::spawn_blocking(|| {
            DEFAULT_BOOTSTRAP_NODES
                .iter()
                .filter_map(|name| name.to_socket_addrs().ok())
                .flatten()
                .filter_map(|address| match address {
                    SocketAddr::V4(address) => Some(address),
                    SocketAddr::V6(_) => None,
                })
                .collect::<Vec<_>>()
        });
        match timeout(wait, resolving).await {
            Ok(Ok(found)) if !found.is_empty() => {
                self.lock().defaults = found.clone();
                found
            }
            _ => {
                debug!("the default bootstrap names did not resolve in time");
                self.lock().defaults.clone()
            }
        }
    }

    /// Builds a node. An empty list is an error and not a node: `mainline` never refills it (it would be a node
    /// of a network of one), so the node would be dead for good.
    async fn build_from(&self, list: Vec<SocketAddrV4>, warm: bool) -> Result<Handle, Error> {
        if list.is_empty() {
            debug!("no node to start the DHT from");
            return Err(Error::NoNetwork);
        }
        let (bind_address, port, request_timeout) =
            (self.config.bind_address, self.config.port, self.config.request_timeout);
        let nodes = list.clone();
        let dht = tokio::task::spawn_blocking(move || {
            let mut builder = Dht::builder();
            builder.bootstrap(&nodes).server_settings(Silent::settings());
            if let Some(address) = bind_address {
                builder.bind_address(address);
            }
            if let Some(port) = port {
                builder.port(port);
            }
            if let Some(request_timeout) = request_timeout {
                builder.request_timeout(request_timeout);
            }
            builder.build()
        })
        .await
        .map_err(|_| Error::Stopped)?
        .map_err(Error::Socket)?;
        let generation = self.generation.fetch_add(1, Ordering::Relaxed) + 1;
        debug!(generation, nodes = list.len(), warm, "started a DHT node");
        let quorum = self.config.quorum.unwrap_or_else(|| list.len().clamp(1, QUORUM)).max(1);
        let handle = Handle { dht: dht.as_async(), generation, quorum, warm };
        self.lock().running = Some(Running { handle: handle.clone(), list, fresh_since: SystemTime::now() });
        Ok(handle)
    }

    /// Makes the node forget the one that died, unless it has been replaced since.
    fn forget(&self, generation: u64) {
        let mut state = self.lock();
        if state.running.as_ref().is_some_and(|r| r.handle.generation == generation) {
            state.running = None;
        }
    }

    fn touch(&self, generation: u64) {
        let mut state = self.lock();
        if let Some(running) = state.running.as_mut().filter(|r| r.handle.generation == generation) {
            running.fresh_since = SystemTime::now();
        }
    }

    /// A cold start waits, a little, for its table to fill. If nothing is in it after that, either the start list was
    /// short of names (DNS was down) or nobody answers, and building again tells which.
    async fn ensure_ready(self: &Arc<Self>, handle: Handle, until: Instant, used: &AtomicU64) -> Result<Handle, Error> {
        if handle.warm || self.wait_for_table(&handle, until).await {
            return Ok(handle);
        }
        self.refresh_if_empty(handle, until, used).await
    }

    async fn wait_for_table(&self, handle: &Handle, until: Instant) -> bool {
        let limit = until.min(after(READY_WAIT));
        loop {
            if handle.dht.to_bootstrap().await.len() >= handle.quorum {
                return true;
            }
            if Instant::now() >= limit {
                return false;
            }
            sleep(POLL).await;
        }
    }

    /// If the node's table is empty, builds it again when the list it would be built from now is not the one it was
    /// built from (DNS answered since, the cache changed). The same list would only do the same, and the node already
    /// retries by itself every second.
    async fn refresh_if_empty(
        self: &Arc<Self>,
        handle: Handle,
        until: Instant,
        used: &AtomicU64,
    ) -> Result<Handle, Error> {
        if !handle.dht.to_bootstrap().await.is_empty() {
            return Ok(handle);
        }
        let (list, warm) = self.bootstrap_list().await;
        let fresh = {
            let _building = self.build.lock().await;
            {
                let state = self.lock();
                match state.running.as_ref() {
                    Some(running) if running.handle.generation != handle.generation => {
                        return Ok(running.handle.clone());
                    }
                    Some(running) if same_nodes(&running.list, &list) => return Ok(handle),
                    _ => {}
                }
            }
            if list.is_empty() {
                return Ok(handle);
            }
            info!(nodes = list.len(), "no DHT node answered: starting the node again");
            self.build_from(list, warm).await?
        };
        used.store(fresh.generation, Ordering::Relaxed);
        if !fresh.warm {
            self.wait_for_table(&fresh, until).await;
        }
        Ok(fresh)
    }

    // === resolve ===

    async fn resolve_op(
        self: &Arc<Self>,
        used: &AtomicU64,
        key: [u8; 32],
        salt: Vec<u8>,
        options: ResolveOptions,
    ) -> Result<Option<Resolved>, Error> {
        let deadline = after(options.deadline.unwrap_or(self.config.resolve_deadline));
        let salt = salt_of(&salt);
        let mut handle = self.handle().await?;
        used.store(handle.generation, Ordering::Relaxed);
        handle = self.ensure_ready(handle, deadline, used).await?;
        let mut attempt = 0;
        loop {
            let mut lookup = Lookup::start(&handle.dht, &key, salt, options.newer_than);
            let got = collect(&mut lookup, deadline, Some(self.config.settle)).await;
            if let Some(item) = got.best {
                self.touch(handle.generation);
                self.schedule_save();
                return Ok(Some(Resolved { value: item.value().to_vec(), seq: item.seq() }));
            }
            if !got.ended {
                // Out of time with the lookup still running. Nodes in the table mean the network is there.
                return if handle.dht.to_bootstrap().await.is_empty() { Err(Error::NoNetwork) } else { Ok(None) };
            }
            let reach = lookup.reach(&handle).await;
            match verdict(reach, attempt, deadline.saturating_duration_since(Instant::now())) {
                Verdict::NoRecord => {
                    self.touch(handle.generation);
                    self.schedule_save();
                    return Ok(None);
                }
                Verdict::NoNetwork => return Err(Error::NoNetwork),
                Verdict::Retry => {
                    // The first lookup of a cold node sometimes asks four names and hears from none; the same
                    // lookup a moment later, from the same node, found the record every time.
                    debug!(?reach, "nothing found and few nodes answered: looking again");
                    handle = self.refresh_if_empty(handle, deadline, used).await?;
                    attempt += 1;
                }
            }
        }
    }

    // === publish ===

    async fn publish_op(self: &Arc<Self>, used: &AtomicU64, publication: Publication) -> Result<Published, Error> {
        let Publication { public, salt: salt_bytes, item, deadline } = publication;
        let seq = item.seq();
        let salt = salt_of(&salt_bytes);
        let _one_at_a_time = self.publishing.lock().await;
        let mut handle = self.handle().await?;
        used.store(handle.generation, Ordering::Relaxed);
        handle = self.ensure_ready(handle, deadline, used).await?;
        let mut attempt = 0;
        loop {
            attempt += 1;
            // Read before writing: the highest `seq` stored says whether this record can win, and the lookup leaves the
            // nodes, with their tokens, that the put goes to.
            let stored = self.read_before_publish(&mut handle, used, &public, salt, deadline).await?;
            if let Some(stored) = stored.filter(|s| s.seq() > seq || (s.seq() == seq && s.value() != item.value())) {
                self.record_seq(public, &salt_bytes, stored.seq());
                return Err(Error::SeqTooLow { seq, seen: stored.seq() });
            }
            // From here this `seq` is spent, even if the put fails: a node may have kept it, and another blob under
            // the same `seq` would be ignored there.
            self.record_seq(public, &salt_bytes, seq);
            let put = match timeout_at(deadline, handle.dht.put_mutable(item.clone(), None)).await {
                Ok(put) => put,
                Err(_) => return Err(Error::TimedOut),
            };
            match put {
                Ok(outcome) => {
                    let stored_at = outcome.stored_at as usize;
                    if stored_at >= handle.quorum {
                        self.touch(handle.generation);
                        if let Err(e) = self.save(true).await {
                            warn!(error = %e, "could not save the DHT cache");
                        }
                        return Ok(Published { seq, stored_at });
                    }
                    // `put_mutable` succeeds when one node acknowledges; a record on one or two nodes was never found
                    // again. The second round starts with a new lookup, from a node that has a table by now.
                    debug!(stored_at, "too few nodes took the record");
                    if attempt >= 2 {
                        return Err(Error::Refused { acknowledged: stored_at });
                    }
                }
                Err(PutMutableError::Concurrency(e)) => {
                    debug!(error = %e, "a node holds a record this one cannot replace");
                    let seen = match self.read_stored(&handle, &public, salt, deadline).await {
                        Some(stored) => stored.seq().max(seq),
                        None => seq,
                    };
                    self.record_seq(public, &salt_bytes, seen);
                    return Err(Error::SeqTooLow { seq, seen });
                }
                Err(PutMutableError::Query(PutQueryError::NoClosestNodes)) => return Err(Error::NoNetwork),
                Err(PutMutableError::Query(e)) => {
                    // What `mainline` reports for a refusal and for no answer alike.
                    debug!(error = %e, "the put was not acknowledged");
                    if attempt >= 2 {
                        return Err(Error::Refused { acknowledged: 0 });
                    }
                }
            }
        }
    }

    /// The record stored now, whole lookup. Retries an empty one the way a resolve does.
    async fn read_before_publish(
        self: &Arc<Self>,
        handle: &mut Handle,
        used: &AtomicU64,
        key: &[u8; 32],
        salt: Option<&[u8]>,
        deadline: Instant,
    ) -> Result<Option<MutableItem>, Error> {
        let mut attempt = 0;
        loop {
            let mut lookup = Lookup::start(&handle.dht, key, salt, None);
            let got = collect(&mut lookup, deadline, None).await;
            if !got.ended {
                return Err(Error::TimedOut);
            }
            if got.best.is_some() {
                return Ok(got.best);
            }
            let reach = lookup.reach(handle).await;
            match verdict(reach, attempt, deadline.saturating_duration_since(Instant::now())) {
                Verdict::NoRecord => return Ok(None),
                Verdict::NoNetwork => return Err(Error::NoNetwork),
                Verdict::Retry => {
                    debug!(?reach, "nothing stored and few nodes answered: looking again before the put");
                    *handle = self.refresh_if_empty(handle.clone(), deadline, used).await?;
                    attempt += 1;
                }
            }
        }
    }

    async fn read_stored(
        &self,
        handle: &Handle,
        key: &[u8; 32],
        salt: Option<&[u8]>,
        deadline: Instant,
    ) -> Option<MutableItem> {
        let mut lookup = Lookup::start(&handle.dht, key, salt, None);
        collect(&mut lookup, deadline, None).await.best
    }

    // === seq numbers ===

    fn next_seq(&self, key: [u8; 32], salt: &[u8]) -> i64 {
        let last = self.lock().seqs.get(&(key, salt.to_vec())).map(|entry| entry.seq);
        unix_now().max(last.map_or(i64::MIN, |last| last.saturating_add(1)))
    }

    fn record_seq(&self, key: [u8; 32], salt: &[u8], seq: i64) {
        let mut state = self.lock();
        let entry = state.seqs.entry((key, salt.to_vec())).or_insert(SeqEntry { seq, at: 0 });
        entry.seq = entry.seq.max(seq);
        entry.at = unix_now();
        state.seqs_dirty = true;
        if state.seqs.len() > MAX_SEQS {
            let oldest = state.seqs.iter().min_by_key(|(_, entry)| entry.at).map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                state.seqs.remove(&oldest);
            }
        }
    }

    // === the cache ===

    /// A lookup is over, or soon is: its table is as full as it gets once the lookup has ended.
    fn schedule_save(self: &Arc<Self>) {
        if self.config.cache_path.is_none() || self.save_scheduled.swap(true, Ordering::AcqRel) {
            return;
        }
        let inner = self.clone();
        tokio::spawn(async move {
            sleep(SAVE_DELAY).await;
            inner.save_scheduled.store(false, Ordering::Release);
            if let Err(e) = inner.save(false).await {
                warn!(error = %e, "could not save the DHT cache");
            }
        });
    }

    /// Writes the table of the running node and the `seq` numbers. A table smaller than a quorum is not written over
    /// a better one (a node that has just started, or has been idle, has almost nothing in it); the old nodes stay
    /// and only the `seq` numbers are updated. `force` writes even if the file was written lately.
    async fn save(self: &Arc<Self>, force: bool) -> Result<bool, Error> {
        let Some(path) = self.config.cache_path.clone() else {
            return Ok(false);
        };
        let _saving = self.saving.lock().await;
        let handle = self.lock().running.as_ref().map(|r| r.handle.clone());
        let (table, quorum) = match &handle {
            Some(handle) => {
                let table = handle.dht.to_bootstrap().await;
                (table.iter().filter_map(|node| node.parse::<SocketAddrV4>().ok()).collect::<Vec<_>>(), handle.quorum)
            }
            None => (Vec::new(), self.config.quorum.unwrap_or(QUORUM)),
        };
        let (bytes, nodes) = {
            let state = self.lock();
            let nodes = if table.len() >= quorum { spread(&table, MAX_SAVED_NODES) } else { state.saved.clone() };
            let bytes = CacheFile { nodes: nodes.clone(), seqs: state.seqs.clone() }.render();
            if state.written.as_deref() == Some(bytes.as_slice()) {
                return Ok(false);
            }
            let lately = state.last_save.is_some_and(|saved| saved.elapsed() < SAVE_EVERY);
            if !force && !state.seqs_dirty && lately {
                return Ok(false);
            }
            (bytes, nodes)
        };
        let to_write = bytes.clone();
        tokio::task::spawn_blocking(move || write_atomically(&path, &to_write))
            .await
            .map_err(|_| Error::Stopped)?
            .map_err(Error::Cache)?;
        let mut state = self.lock();
        state.written = Some(bytes);
        state.last_save = Some(Instant::now());
        state.seqs_dirty = false;
        state.saved = nodes;
        Ok(true)
    }
}

// === Lookups ===

/// One `get_mutable` lookup: the records as they arrive, and how it ended.
struct Lookup {
    items: mpsc::UnboundedReceiver<MutableItem>,
    outcome: oneshot::Receiver<GetMutableOutcome>,
}

impl Lookup {
    fn start(dht: &AsyncDht, key: &[u8; 32], salt: Option<&[u8]>, newer_than: Option<i64>) -> Self {
        let GetMutableDetailed { items, outcome } = dht.get_mutable_detailed(key, salt, newer_than);
        let (item_tx, item_rx) = mpsc::unbounded_channel();
        let (outcome_tx, outcome_rx) = oneshot::channel();
        // On a task of its own: the lookup goes on after the caller has what it came for (dropping the stream does
        // not cancel it), and waiting for its outcome panics if the node dies meanwhile.
        tokio::spawn(async move {
            let mut items = items;
            while let Some(item) = items.next().await {
                if item_tx.send(item).is_err() {
                    return;
                }
            }
            drop(item_tx);
            let _ = outcome_tx.send(outcome.recv().await);
        });
        Self { items: item_rx, outcome: outcome_rx }
    }

    async fn next(&mut self) -> Option<MutableItem> {
        self.items.recv().await
    }

    /// How much of the network a lookup that has ended heard from.
    async fn reach(self, handle: &Handle) -> Reach {
        match timeout(Duration::from_secs(1), self.outcome).await {
            Ok(Ok(outcome)) => Reach::of(&outcome, handle.quorum),
            _ => Reach::of_table(handle.dht.to_bootstrap().await.len(), handle.quorum),
        }
    }
}

/// What a lookup gave until it ended, or the deadline came, or (with `settle`) the window after its first record
/// closed.
struct Collected {
    /// The highest `seq` seen. The order records arrive in says nothing about it.
    best: Option<MutableItem>,
    /// The lookup ran to its end: nothing more would have come.
    ended: bool,
}

async fn collect(lookup: &mut Lookup, deadline: Instant, settle: Option<Duration>) -> Collected {
    let mut best: Option<MutableItem> = None;
    let mut until = deadline;
    loop {
        match timeout_at(until, lookup.next()).await {
            Ok(Some(item)) => {
                if let (None, Some(settle)) = (&best, settle) {
                    until = until.min(after(settle));
                }
                if best.as_ref().is_none_or(|best| item.seq() > best.seq()) {
                    best = Some(item);
                }
            }
            Ok(None) => return Collected { best, ended: true },
            Err(_) => return Collected { best, ended: false },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reach {
    /// Nobody answered.
    Dead,
    /// Fewer nodes answered than a lookup of a healthy network hears from.
    Thin,
    Healthy,
}

impl Reach {
    fn of(outcome: &GetMutableOutcome, quorum: usize) -> Self {
        if outcome.responded() == 0 {
            Self::Dead
        } else if (outcome.valid_responses() as usize) < quorum {
            Self::Thin
        } else {
            Self::Healthy
        }
    }

    /// For when the outcome did not come: the table says as much, less precisely.
    fn of_table(nodes: usize, quorum: usize) -> Self {
        if nodes == 0 {
            Self::Dead
        } else if nodes < quorum {
            Self::Thin
        } else {
            Self::Healthy
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    NoRecord,
    NoNetwork,
    Retry,
}

/// What a lookup that found nothing means. One more try on the same node, if there is time for it, unless the lookup
/// heard from a healthy number of nodes: then nothing is stored.
fn verdict(reach: Reach, attempt: u32, time_left: Duration) -> Verdict {
    let can_retry = attempt == 0 && time_left >= MIN_RETRY;
    match reach {
        Reach::Healthy => Verdict::NoRecord,
        _ if can_retry => Verdict::Retry,
        Reach::Dead => Verdict::NoNetwork,
        Reach::Thin => Verdict::NoRecord,
    }
}

/// The filter that answers nobody (the module docs say why), and the smallest stores to go with it.
#[derive(Debug, Clone)]
struct Silent;

impl RequestFilter for Silent {
    fn allow_request(&self, _request: &RequestSpecific, _from: SocketAddrV4) -> bool {
        false
    }
}

impl Silent {
    fn settings() -> ServerSettings {
        ServerSettings {
            max_info_hashes: 1,
            max_peers_per_info_hash: 1,
            max_immutable_values: 1,
            max_mutable_values: 1,
            filter: Box::new(Silent),
        }
    }
}

// === The cache file ===

const CACHE_HEADER: &str = "velora-dht-cache 1";

/// More node lines than this are not read; a cache holds 16.
const MAX_CACHED_NODES: usize = 64;

/// What is kept between runs: the nodes of the routing table, and the last `seq` of every record this device
/// published. Plain text, one line each:
///
/// ```text
/// velora-dht-cache 1
/// node 203.0.113.7:6881
/// seq <public key, hex> <salt, hex or -> <seq> <unix time of the last use>
/// ```
///
/// Lines it does not know are skipped, so a later version can add some; a file with another first line, or one that
/// cannot be read, is an empty cache.
#[derive(Debug, Default, PartialEq, Eq)]
struct CacheFile {
    nodes: Vec<SocketAddrV4>,
    seqs: HashMap<SeqKey, SeqEntry>,
}

impl CacheFile {
    fn render(&self) -> Vec<u8> {
        let mut text = format!("{CACHE_HEADER}\n");
        for node in &self.nodes {
            text += &format!("node {node}\n");
        }
        // Sorted, so that the same content is the same bytes and an unchanged cache is not written again.
        let mut seqs: Vec<(&SeqKey, &SeqEntry)> = self.seqs.iter().collect();
        seqs.sort_by(|a, b| a.0.cmp(b.0));
        for ((key, salt), entry) in seqs {
            let salt = if salt.is_empty() { "-".to_owned() } else { to_hex(salt) };
            text += &format!("seq {} {salt} {} {}\n", to_hex(key), entry.seq, entry.at);
        }
        text.into_bytes()
    }

    fn parse(text: &str) -> Self {
        let mut lines = text.lines();
        if lines.next().map(str::trim) != Some(CACHE_HEADER) {
            return Self::default();
        }
        let mut cache = Self::default();
        for line in lines {
            let mut words = line.split_whitespace();
            match words.next() {
                Some("node") => {
                    let node = words.next().and_then(|word| word.parse::<SocketAddrV4>().ok());
                    if let Some(node) = node.filter(|node| !cache.nodes.contains(node)) {
                        if cache.nodes.len() < MAX_CACHED_NODES {
                            cache.nodes.push(node);
                        }
                    }
                }
                Some("seq") => {
                    if let Some((key, entry)) = parse_seq(&mut words) {
                        if cache.seqs.len() < MAX_SEQS {
                            cache.seqs.insert(key, entry);
                        }
                    }
                }
                _ => {}
            }
        }
        cache
    }

    fn load(path: &Path) -> Self {
        let mut text = String::new();
        let read = fs::File::open(path).and_then(|file| file.take(MAX_CACHE_BYTES + 1).read_to_string(&mut text));
        match read {
            Ok(len) if len as u64 <= MAX_CACHE_BYTES => Self::parse(&text),
            Ok(_) => {
                warn!(path = %path.display(), "the DHT cache is too big to be ours: ignored");
                Self::default()
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Self::default(),
            Err(e) => {
                warn!(path = %path.display(), error = %e, "cannot read the DHT cache: ignored");
                Self::default()
            }
        }
    }
}

fn parse_seq(words: &mut std::str::SplitWhitespace<'_>) -> Option<(SeqKey, SeqEntry)> {
    let key: [u8; 32] = from_hex(words.next()?)?.try_into().ok()?;
    let salt = match words.next()? {
        "-" => Vec::new(),
        hex => from_hex(hex)?,
    };
    let seq = words.next()?.parse().ok()?;
    let at = words.next()?.parse().ok()?;
    Some(((key, salt), SeqEntry { seq, at }))
}

/// Through a temporary file and a rename, so that a crash never leaves half a cache behind.
fn write_atomically(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(dir) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    let written = fs::File::create(&tmp)
        .and_then(|mut file| file.write_all(bytes).and_then(|()| file.sync_all()))
        .and_then(|()| fs::rename(&tmp, path));
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    written
}

// === Small things ===

/// An empty salt is no salt: the two would hash to the same place but be signed differently.
fn salt_of(salt: &[u8]) -> Option<&[u8]> {
    (!salt.is_empty()).then_some(salt)
}

fn check_salt(salt: &[u8]) -> Result<(), Error> {
    if salt.len() > MAX_SALT_LEN {
        return Err(Error::SaltTooBig { len: salt.len() });
    }
    Ok(())
}

fn after(span: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(span).unwrap_or_else(|| now + Duration::from_secs(24 * 60 * 60))
}

fn unix_now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |since| i64::try_from(since.as_secs()).unwrap_or(i64::MAX))
}

fn same_nodes(a: &[SocketAddrV4], b: &[SocketAddrV4]) -> bool {
    let (mut a, mut b) = (a.to_vec(), b.to_vec());
    a.sort();
    b.sort();
    a == b
}

/// `count` of the items, evenly spread. The table lists its nodes by distance from the node's own id, so the first
/// ones would all live in one corner of the id space.
fn spread<T: Clone>(items: &[T], count: usize) -> Vec<T> {
    if items.len() <= count {
        return items.to_vec();
    }
    (0..count).filter_map(|i| items.get(i * items.len() / count)).cloned().collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn from_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 == 1 {
        return None;
    }
    // `from_str_radix` takes a sign, which a hex pair does not have.
    (0..text.len())
        .step_by(2)
        .map(|at| {
            text.get(at..at + 2)
                .filter(|pair| pair.bytes().all(|byte| byte.is_ascii_hexdigit()))
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU32;

    use mainline::Testnet;
    use ring::rand::{SecureRandom, SystemRandom};

    use super::*;

    const SALT: &[u8] = b"velora/test";

    /// A scratch directory removed on drop; the crate has no `tempfile`.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let dir = std::env::temp_dir().join(format!(
                "velora-dht-node-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn file(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn testnet(nodes: usize) -> Testnet {
        // A machine short of socket buffers (Windows error 10055) fails to open the sockets for a moment.
        for _ in 0..5 {
            if let Ok(testnet) = Testnet::builder(nodes).build() {
                return testnet;
            }
            std::thread::sleep(Duration::from_millis(300));
        }
        Testnet::builder(nodes).build().unwrap()
    }

    fn addresses(testnet: &Testnet) -> Vec<SocketAddrV4> {
        testnet.bootstrap.iter().map(|address| address.parse().unwrap()).collect()
    }

    /// A node of the test network: on loopback, with the testnet as its default nodes. The testnet's servers hand out
    /// the addresses of the client nodes, which never answer, so every lookup lasts as long as a request timeout.
    ///
    /// One acknowledgement is enough: on Windows about one datagram in a hundred sent to a node of this process is
    /// lost (plain `mainline` too: one put in 150 reached one server of three), and a put to three nodes that needs
    /// all three, or two, fails a test now and then. For the same reason a resolve listens until its lookup ends
    /// instead of for 200 ms: the record from the server that got the newer put may come last.
    fn config(testnet: &Testnet, mode: Mode) -> Config {
        let mut config = Config::new(mode);
        config.default_nodes = DefaultNodes::fixed(addresses(testnet));
        config.bind_address = Some(Ipv4Addr::LOCALHOST);
        config.settle = Duration::from_secs(5);
        config.quorum = Some(1);
        config.resolve_deadline = Duration::from_secs(8);
        config.publish_deadline = Duration::from_secs(20);
        config
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    /// A node that never answers: an address of the range reserved for documentation (RFC 5737), where nothing is.
    /// A port that was bound and given back would do until another test took it.
    fn dead_node() -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 6881)
    }

    fn generation(node: &Node) -> u64 {
        node.inner.lock().running.as_ref().map_or(0, |r| r.handle.generation)
    }

    // The test network loses a datagram now and then (see `config`) and the machine it runs on stalls for a moment: a
    // publish that was refused or reached few nodes, or a resolve that found nothing or an older record, is asked
    // again a few times before a test calls it wrong. What a test is about (a refusal, a conflict, an empty answer)
    // is asked once.

    async fn stored<S: Signer + ?Sized>(
        node: &Node,
        signer: &S,
        salt: &[u8],
        blob: &[u8],
        seq: i64,
        at_least: usize,
    ) -> Published {
        let mut last = String::new();
        for _ in 0..6 {
            match node.publish(signer, salt, blob, seq).await {
                Ok(published) if published.stored_at >= at_least => return published,
                Ok(published) => last = format!("only {} nodes took it", published.stored_at),
                Err(e) => last = e.to_string(),
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        panic!("not published: {last}");
    }

    async fn stored_with<S: Signer + ?Sized>(
        node: &Node,
        signer: &S,
        salt: &[u8],
        mut make: impl FnMut(i64) -> Result<Vec<u8>, io::Error>,
        at_least: usize,
    ) -> Published {
        let mut last = String::new();
        for _ in 0..6 {
            match node.publish_with(signer, salt, &mut make).await {
                Ok(published) if published.stored_at >= at_least => return published,
                Ok(published) => last = format!("only {} nodes took it", published.stored_at),
                Err(e) => last = e.to_string(),
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        panic!("not published: {last}");
    }

    async fn found_with(
        node: &Node,
        key: &[u8; 32],
        salt: &[u8],
        options: &ResolveOptions,
        want: impl Fn(&Resolved) -> bool,
    ) -> Resolved {
        for _ in 0..6 {
            if let Ok(Some(resolved)) = node.resolve_with(key, salt, options).await {
                if want(&resolved) {
                    return resolved;
                }
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        panic!("the record never came");
    }

    async fn found(node: &Node, key: &[u8; 32], salt: &[u8], want: impl Fn(&Resolved) -> bool) -> Resolved {
        found_with(node, key, salt, &ResolveOptions::default(), want).await
    }

    // === publish and resolve ===

    #[tokio::test]
    async fn a_published_record_resolves_from_another_node() {
        let net = testnet(4);
        let host = Node::open_with(config(&net, Mode::Host)).await;
        let client = Node::open_with(config(&net, Mode::Client)).await;
        let signer = key(1);
        let record = vec![7u8; 300];

        let seq = host.next_seq(&signer, SALT);
        let published = stored(&host, &signer, SALT, &record, seq, 2).await;
        assert_eq!(published.seq, seq);

        let resolved = found(&client, &signer.public_key(), SALT, |r| r.value == record).await;
        assert_eq!(resolved, Resolved { value: record, seq });
    }

    #[tokio::test]
    async fn the_device_keys_sign_like_a_bare_key() {
        let net = testnet(3);
        let dir = Scratch::new();
        let keys = Keys::load_or_create(&dir.file(crate::keys::FILE_NAME)).unwrap();
        assert_eq!(Signer::public_key(&keys), keys.public_key());
        let host = Node::open_with(config(&net, Mode::Host)).await;

        let seq = host.next_seq(&keys, SALT);
        stored(&host, &keys, SALT, b"from the device key", seq, 2).await;

        let resolved = found(&host, &keys.public_key(), SALT, |_| true).await;
        assert_eq!(resolved.value, b"from the device key");
    }

    #[tokio::test]
    async fn a_record_nobody_published_is_none() {
        let net = testnet(3);
        let client = Node::open_with(config(&net, Mode::Client)).await;
        let started = std::time::Instant::now();
        assert_eq!(client.resolve(&key(2).public_key(), SALT).await.unwrap(), None);
        assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
    }

    #[tokio::test]
    async fn a_poll_asks_only_for_newer_records() {
        let net = testnet(3);
        let host = Node::open_with(config(&net, Mode::Host)).await;
        let signer = key(3);
        let seq = host.next_seq(&signer, SALT);
        stored(&host, &signer, SALT, b"first", seq, 2).await;

        let poll = |newer_than| ResolveOptions { newer_than: Some(newer_than), deadline: None };
        let public = signer.public_key();
        assert_eq!(host.resolve_with(&public, SALT, &poll(seq)).await.unwrap(), None, "unchanged");
        let resolved = found_with(&host, &public, SALT, &poll(seq - 1), |_| true).await;
        assert_eq!(resolved.seq, seq);
    }

    #[tokio::test]
    async fn a_value_or_a_salt_over_the_limit_is_refused_before_anything_is_sent() {
        // No node to talk to at all: the answer comes from the checks.
        let mut offline = Config::new(Mode::Client);
        offline.default_nodes = DefaultNodes::fixed(Vec::new());
        let node = Node::open_with(offline).await;
        let signer = key(4);

        let err = node.publish(&signer, SALT, &vec![0u8; MAX_VALUE_LEN + 1], 1).await.unwrap_err();
        assert!(matches!(err, Error::TooBig { len: 997 }), "{err:?}");
        let err = node.publish(&signer, &[b's'; MAX_SALT_LEN + 1], b"x", 1).await.unwrap_err();
        assert!(matches!(err, Error::SaltTooBig { len: 65 }), "{err:?}");
        let err = node.resolve(&signer.public_key(), &[b's'; MAX_SALT_LEN + 1]).await.unwrap_err();
        assert!(matches!(err, Error::SaltTooBig { len: 65 }), "{err:?}");
        // The limits themselves are not over them.
        let err = node.publish(&signer, &[b's'; MAX_SALT_LEN], &vec![0u8; MAX_VALUE_LEN], 1).await.unwrap_err();
        assert!(matches!(err, Error::NoNetwork), "{err:?}");
    }

    #[tokio::test]
    async fn the_longest_value_and_salt_are_stored_and_read_back() {
        let net = testnet(3);
        let host = Node::open_with(config(&net, Mode::Host)).await;
        let signer = key(5);
        let salt = [b'a'; MAX_SALT_LEN];
        let record: Vec<u8> = (0..MAX_VALUE_LEN).map(|i| (i % 251) as u8).collect();

        let seq = host.next_seq(&signer, &salt);
        stored(&host, &signer, &salt, &record, seq, 2).await;
        let resolved = found(&host, &signer.public_key(), &salt, |_| true).await;
        assert_eq!(resolved.value, record);
    }

    #[tokio::test]
    async fn an_empty_salt_is_the_same_record_on_both_sides() {
        let net = testnet(3);
        let host = Node::open_with(config(&net, Mode::Host)).await;
        let signer = key(6);
        let seq = host.next_seq(&signer, b"");
        stored(&host, &signer, b"", b"no salt", seq, 2).await;
        let resolved = found(&host, &signer.public_key(), b"", |_| true).await;
        assert_eq!(resolved.value, b"no salt");
    }

    // === seq numbers ===

    #[tokio::test]
    async fn next_seq_is_the_clock_until_something_is_ahead_of_it() {
        let net = testnet(3);
        let host = Node::open_with(config(&net, Mode::Host)).await;
        let signer = key(7);
        let (before, first, after) = (unix_now(), host.next_seq(&signer, SALT), unix_now());
        assert!((before..=after).contains(&first), "{first} vs {before}..{after}");
        // A record from the future (a clock that was wrong once): the next one goes above it, not back to the clock.
        let ahead = after + 1000;
        stored(&host, &signer, SALT, b"ahead", ahead, 2).await;
        assert_eq!(host.next_seq(&signer, SALT), ahead + 1);
        // Another salt is another record, with its own count.
        assert!(host.next_seq(&signer, b"other") < ahead);

        stored(&host, &signer, SALT, b"after", ahead + 1, 2).await;
        assert_eq!(host.next_seq(&signer, SALT), ahead + 2);
        let resolved = found(&host, &signer.public_key(), SALT, |r| r.seq == ahead + 1).await;
        assert_eq!(resolved.value, b"after");
    }

    #[tokio::test]
    async fn a_seq_that_cannot_win_is_refused_before_it_is_sent() {
        let net = testnet(3);
        let host = Node::open_with(config(&net, Mode::Host)).await;
        let signer = key(8);

        stored(&host, &signer, SALT, b"A", 1000, 2).await;
        let lower = host.publish(&signer, SALT, b"B", 999).await.unwrap_err();
        assert!(matches!(lower, Error::SeqTooLow { seq: 999, seen: 1000 }), "{lower:?}");
        // The nodes would acknowledge an equal seq and keep the old value; here it is an error.
        let equal = host.publish(&signer, SALT, b"B", 1000).await.unwrap_err();
        assert!(matches!(equal, Error::SeqTooLow { seq: 1000, seen: 1000 }), "{equal:?}");
        // The same record again is a refresh, not a conflict.
        stored(&host, &signer, SALT, b"A", 1000, 2).await;

        let resolved = found(&host, &signer.public_key(), SALT, |r| r.seq == 1000).await;
        assert_eq!(resolved.value, b"A");
    }

    #[tokio::test]
    async fn publish_with_seals_again_above_what_is_stored() {
        let net = testnet(3);
        let old = Node::open_with(config(&net, Mode::Host)).await;
        let signer = key(9);
        let ahead = unix_now() + 500;
        stored(&old, &signer, SALT, b"from a copy of this key", ahead, 2).await;

        // A node that knows nothing of it: its first seq is the clock, which is behind.
        let fresh = Node::open_with(config(&net, Mode::Host)).await;
        let mut asked = Vec::new();
        let published = fresh
            .publish_with(&signer, SALT, |seq| {
                asked.push(seq);
                Ok::<_, std::convert::Infallible>(format!("sealed for {seq}").into_bytes())
            })
            .await
            .unwrap();

        assert_eq!(asked.len(), 2, "{asked:?}");
        assert!(asked[0] < ahead && asked[1] == ahead + 1, "{asked:?}");
        assert_eq!(published.seq, ahead + 1);
        let resolved = found(&fresh, &signer.public_key(), SALT, |r| r.seq == ahead + 1).await;
        assert_eq!(resolved.value, format!("sealed for {}", ahead + 1).into_bytes());
        // And the node remembers: the next one goes on from there.
        assert_eq!(fresh.next_seq(&signer, SALT), ahead + 2);
    }

    #[tokio::test]
    async fn publish_with_reports_a_blob_that_could_not_be_made() {
        let net = testnet(3);
        let host = Node::open_with(config(&net, Mode::Host)).await;
        let signer = key(10);
        let err =
            host.publish_with(&signer, SALT, |_| Err::<Vec<u8>, _>(io::Error::other("no room"))).await.unwrap_err();
        assert!(matches!(&err, Error::Blob(inner) if inner.to_string() == "no room"), "{err:?}");
        assert_eq!(host.resolve(&signer.public_key(), SALT).await.unwrap(), None, "nothing was published");
    }

    #[tokio::test]
    async fn two_publishes_in_one_second_both_win() {
        let net = testnet(3);
        let host = Node::open_with(config(&net, Mode::Host)).await;
        let signer = key(11);
        let blob = |seq: i64| Ok::<_, io::Error>(seq.to_be_bytes().to_vec());
        let first = stored_with(&host, &signer, SALT, blob, 2).await;
        let second = stored_with(&host, &signer, SALT, blob, 2).await;
        assert!(second.seq > first.seq, "{first:?} {second:?}");
        found(&host, &signer.public_key(), SALT, |r| r.seq == second.seq).await;
    }

    #[tokio::test]
    async fn too_few_acknowledgements_is_refused_after_a_second_try() {
        // Eight nodes are needed and only three of them are there.
        let net = testnet(3);
        let mut config = config(&net, Mode::Host);
        config.quorum = Some(8);
        let host = Node::open_with(config).await;
        let signer = key(12);
        let ahead = unix_now() + 100;

        let err = host.publish(&signer, SALT, b"kept by three", ahead).await.unwrap_err();
        assert!(matches!(err, Error::Refused { acknowledged } if (1..=3).contains(&acknowledged)), "{err:?}");
        // Its seq is spent all the same: some nodes have it, and another blob under it would be ignored there.
        assert_eq!(host.next_seq(&signer, SALT), ahead + 1);
    }

    // === no network, and coming back from it ===

    #[tokio::test]
    async fn a_network_that_does_not_answer_is_no_network_and_not_no_record() {
        let mut config = Config::new(Mode::Client);
        config.default_nodes = DefaultNodes::fixed(vec![dead_node()]);
        config.bind_address = Some(Ipv4Addr::LOCALHOST);
        config.request_timeout = Some(Duration::from_millis(200));
        config.resolve_deadline = Duration::from_secs(4);
        config.publish_deadline = Duration::from_secs(8);
        let node = Node::open_with(config).await;
        let signer = key(13);

        let started = std::time::Instant::now();
        let err = node.resolve(&signer.public_key(), SALT).await.unwrap_err();
        assert!(matches!(err, Error::NoNetwork), "{err:?}");
        assert!(started.elapsed() < Duration::from_secs(6), "{:?}", started.elapsed());

        let err = node.publish(&signer, SALT, b"nobody to tell", 1000).await.unwrap_err();
        assert!(matches!(err, Error::NoNetwork), "{err:?}");
    }

    #[tokio::test]
    async fn the_deadline_of_a_call_is_kept() {
        let mut config = Config::new(Mode::Client);
        config.default_nodes = DefaultNodes::fixed(vec![dead_node()]);
        config.bind_address = Some(Ipv4Addr::LOCALHOST);
        let node = Node::open_with(config).await;
        let options = ResolveOptions { newer_than: None, deadline: Some(Duration::from_millis(600)) };

        let started = std::time::Instant::now();
        let err = node.resolve_with(&key(14).public_key(), SALT, &options).await.unwrap_err();
        assert!(matches!(err, Error::NoNetwork), "{err:?}");
        assert!(started.elapsed() < Duration::from_secs(3), "{:?}", started.elapsed());
    }

    #[tokio::test]
    async fn a_node_that_started_with_nothing_is_built_when_something_appears() {
        let net = testnet(3);
        let up = Arc::new(AtomicBool::new(false));
        let mut config = config(&net, Mode::Host);
        let live = addresses(&net);
        let flag = up.clone();
        // What the names resolve to: nothing while the network is down (and a node built from nothing would never
        // recover), the test network after.
        config.default_nodes =
            DefaultNodes::With(Arc::new(move || if flag.load(Ordering::SeqCst) { live.clone() } else { Vec::new() }));
        let host = Node::open_with(config).await;
        let signer = key(15);
        assert_eq!(generation(&host), 0, "no node was built from an empty list");
        let err = host.resolve(&signer.public_key(), SALT).await.unwrap_err();
        assert!(matches!(err, Error::NoNetwork), "{err:?}");

        up.store(true, Ordering::SeqCst);
        let seq = host.next_seq(&signer, SALT);
        stored(&host, &signer, SALT, b"back", seq, 2).await;
        assert_eq!(generation(&host), 1);
        let resolved = found(&host, &signer.public_key(), SALT, |_| true).await;
        assert_eq!(resolved.value, b"back");
    }

    #[tokio::test]
    async fn a_node_whose_table_stays_empty_is_built_again_from_the_names_that_work_now() {
        let net = testnet(3);
        let asked = Arc::new(AtomicU32::new(0));
        let mut config = config(&net, Mode::Client);
        let (live, dead) = (addresses(&net), dead_node());
        let counter = asked.clone();
        // The first answer is a list that leads nowhere (stale addresses, a name that resolved badly); later ones are
        // right.
        config.default_nodes = DefaultNodes::With(Arc::new(move || {
            if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                vec![dead]
            } else {
                live.clone()
            }
        }));
        let client = Node::open_with(config).await;
        let signer = key(16);
        let other = Node::open_with(self::config(&net, Mode::Host)).await;
        let seq = other.next_seq(&signer, SALT);
        stored(&other, &signer, SALT, b"found after a rebuild", seq, 2).await;

        let resolved = found(&client, &signer.public_key(), SALT, |_| true).await;
        assert_eq!(resolved.value, b"found after a rebuild");
        assert_eq!(generation(&client), 2, "built again once");
    }

    #[tokio::test]
    async fn a_host_node_left_alone_is_replaced_and_a_client_node_is_not() {
        let net = testnet(3);
        let mut host_config = config(&net, Mode::Host);
        host_config.recycle_after = Some(Duration::from_millis(5));
        let host = Node::open_with(host_config).await;
        let client = Node::open_with(config(&net, Mode::Client)).await;
        let signer = key(17);
        assert_eq!(Config::new(Mode::Client).recycle_after, None);
        assert_eq!(Config::new(Mode::Host).recycle_after, Some(Duration::from_secs(600)));

        for _ in 0..2 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let _ = client.resolve(&signer.public_key(), SALT).await;
            let _ = host.resolve(&signer.public_key(), SALT).await;
        }
        assert_eq!(generation(&client), 1);
        assert_eq!(generation(&host), 3, "built at open, and again before each use");
    }

    #[tokio::test]
    async fn a_call_that_panics_is_an_error_and_the_node_is_built_again() {
        let net = testnet(3);
        let host = Node::open_with(config(&net, Mode::Host)).await;
        let signer = key(18);
        assert_eq!(generation(&host), 1);

        let err = host
            .run(|inner, used| async move {
                used.store(inner.lock().running.as_ref().map_or(0, |r| r.handle.generation), Ordering::Relaxed);
                if used.load(Ordering::Relaxed) > 0 {
                    panic!("the thread of the node is gone");
                }
                Ok(())
            })
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Stopped), "{err:?}");
        assert_eq!(generation(&host), 0, "forgotten");

        let seq = host.next_seq(&signer, SALT);
        stored(&host, &signer, SALT, b"after", seq, 1).await;
        assert_eq!(generation(&host), 2);
    }

    #[tokio::test]
    async fn calls_at_once_share_one_node() {
        let net = testnet(3);
        let host = Node::open_with(config(&net, Mode::Host)).await;
        let signer = key(19);
        let seq = host.next_seq(&signer, SALT);
        stored(&host, &signer, SALT, b"shared", seq, 2).await;

        let public = signer.public_key();
        let (a, b, c) = (host.clone(), host.clone(), host.clone());
        let (a, b, c) = tokio::join!(
            async move { found(&a, &public, SALT, |_| true).await },
            async move { found(&b, &public, SALT, |_| true).await },
            async move { found(&c, &public, SALT, |_| true).await },
        );
        for resolved in [a, b, c] {
            assert_eq!(resolved.value, b"shared");
        }
        assert_eq!(generation(&host), 1);
    }

    #[tokio::test]
    async fn two_publishes_at_once_are_taken_in_turn_and_the_later_wins() {
        // The second publish must see the first one's record before it puts, so the lookup has to hear from enough
        // of the nodes that hold it: five nodes, three needed, not the one that is enough elsewhere.
        let net = testnet(5);
        let mut host_config = config(&net, Mode::Host);
        host_config.quorum = Some(3);
        let host = Node::open_with(host_config).await;
        let signer = key(25);
        let make = |name: &'static str| move |seq: i64| Ok::<_, io::Error>(format!("{name} {seq}").into_bytes());
        let (a, b) = (host.clone(), host.clone());
        let (a_key, b_key) = (signer.clone(), signer.clone());

        // Both start from the same `next_seq`; the second finds the first one's record under it and seals again.
        let (first, second) =
            tokio::join!(async move { a.publish_with(&a_key, SALT, make("first")).await }, async move {
                b.publish_with(&b_key, SALT, make("second")).await
            },);
        let (first, second) = (first.unwrap(), second.unwrap());
        assert_ne!(first.seq, second.seq);
        let latest = first.seq.max(second.seq);
        let resolved = found(&host, &signer.public_key(), SALT, |r| r.seq == latest).await;
        assert!(String::from_utf8(resolved.value).unwrap().ends_with(&latest.to_string()));
    }

    #[tokio::test]
    async fn a_busy_port_is_a_socket_error() {
        let taken = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut config = Config::new(Mode::Client);
        config.default_nodes = DefaultNodes::fixed(vec![dead_node()]);
        config.bind_address = Some(Ipv4Addr::LOCALHOST);
        config.port = Some(taken.local_addr().unwrap().port());
        let node = Node::open_with(config).await;
        let err = node.resolve(&key(26).public_key(), SALT).await.unwrap_err();
        assert!(matches!(err, Error::Socket(_)), "{err:?}");
    }

    #[tokio::test]
    async fn the_address_the_nodes_see_is_known_after_a_lookup() {
        let net = testnet(3);
        let host = Node::open_with(config(&net, Mode::Host)).await;
        let signer = key(20);
        let seq = host.next_seq(&signer, SALT);
        stored(&host, &signer, SALT, b"seen", seq, 1).await;

        let seen = host.observed_address().await.expect("a lookup has ended");
        assert_eq!(*seen.ip(), Ipv4Addr::LOCALHOST);
        // Kept when the node that learned it is gone.
        host.inner.forget(generation(&host));
        assert_eq!(host.observed_address().await, Some(seen));
    }

    // === the cache ===

    #[tokio::test]
    async fn the_cache_alone_is_enough_to_start_from() {
        let net = testnet(10);
        let dir = Scratch::new();
        let mut config_a = config(&net, Mode::Host);
        config_a.cache_path = Some(dir.file("a.txt"));
        let host = Node::open_with(config_a).await;
        let signer = key(21);
        let seq = host.next_seq(&signer, SALT);
        stored(&host, &signer, SALT, b"saved", seq, 5).await;

        // A publish saves the table at once.
        let saved = fs::read_to_string(dir.file("a.txt")).unwrap();
        assert_eq!(saved.lines().next(), Some(CACHE_HEADER));
        assert!(saved.lines().filter(|line| line.starts_with("node ")).count() >= 5, "{saved}");
        assert!(saved.contains(&format!("seq {} {} {seq} ", to_hex(&signer.public_key()), to_hex(SALT))), "{saved}");

        // Another device with no default nodes at all, only that file.
        fs::copy(dir.file("a.txt"), dir.file("b.txt")).unwrap();
        let mut config_b = config(&net, Mode::Client);
        config_b.default_nodes = DefaultNodes::fixed(Vec::new());
        config_b.cache_path = Some(dir.file("b.txt"));
        let client = Node::open_with(config_b).await;
        assert!(client.inner.lock().running.as_ref().is_some_and(|r| r.handle.warm));
        let resolved = found(&client, &signer.public_key(), SALT, |_| true).await;
        assert_eq!(resolved.value, b"saved");
    }

    #[tokio::test]
    async fn a_resolve_saves_the_table_once_its_lookup_has_ended() {
        let net = testnet(10);
        let dir = Scratch::new();
        let host = Node::open_with(config(&net, Mode::Host)).await;
        let signer = key(22);
        let seq = host.next_seq(&signer, SALT);
        stored(&host, &signer, SALT, b"x", seq, 5).await;

        let mut config = config(&net, Mode::Client);
        config.cache_path = Some(dir.file("client.txt"));
        let client = Node::open_with(config).await;
        assert!(!dir.file("client.txt").exists());
        found(&client, &signer.public_key(), SALT, |_| true).await;
        tokio::time::sleep(SAVE_DELAY + Duration::from_secs(1)).await;
        let saved = fs::read_to_string(dir.file("client.txt")).unwrap();
        assert!(saved.lines().filter(|line| line.starts_with("node ")).count() >= 5, "{saved}");
    }

    #[tokio::test]
    async fn a_small_table_never_replaces_a_good_cache() {
        let dir = Scratch::new();
        let cache = CacheFile {
            nodes: (1..=12).map(|n| SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, n), 6881)).collect(),
            seqs: HashMap::from([(([9; 32], b"s".to_vec()), SeqEntry { seq: 5, at: 5 })]),
        };
        fs::write(dir.file("cache.txt"), cache.render()).unwrap();
        let mut config = Config::new(Mode::Host);
        config.cache_path = Some(dir.file("cache.txt"));
        config.default_nodes = DefaultNodes::fixed(vec![dead_node()]);
        config.bind_address = Some(Ipv4Addr::LOCALHOST);
        let node = Node::open_with(config).await;

        // The node has just started and knows nobody: nothing to write.
        assert!(!node.save_cache().await.unwrap());
        assert_eq!(fs::read(dir.file("cache.txt")).unwrap(), cache.render());

        // A new seq is written, with the old nodes.
        node.inner.record_seq([9; 32], b"s", 6);
        assert!(node.save_cache().await.unwrap());
        let after = CacheFile::parse(&fs::read_to_string(dir.file("cache.txt")).unwrap());
        assert_eq!(after.nodes, cache.nodes);
        assert_eq!(after.seqs.get(&([9; 32], b"s".to_vec())).map(|e| e.seq), Some(6));
        assert!(!node.save_cache().await.unwrap(), "unchanged");
    }

    #[tokio::test]
    async fn the_seq_numbers_survive_a_restart() {
        let net = testnet(3);
        let dir = Scratch::new();
        let signer = key(23);
        let ahead = unix_now() + 1000;
        let mut first = config(&net, Mode::Host);
        first.cache_path = Some(dir.file("cache.txt"));
        let host = Node::open_with(first.clone()).await;
        stored(&host, &signer, SALT, b"before the restart", ahead, 2).await;
        drop(host);

        let host = Node::open_with(first).await;
        assert_eq!(host.next_seq(&signer, SALT), ahead + 1);
    }

    #[tokio::test]
    async fn a_seq_far_ahead_of_the_clock_in_the_cache_is_not_believed() {
        let dir = Scratch::new();
        let far = unix_now() + 30 * 24 * 60 * 60;
        let cache = CacheFile {
            nodes: Vec::new(),
            seqs: HashMap::from([(([5; 32], b"s".to_vec()), SeqEntry { seq: far, at: 1 })]),
        };
        fs::write(dir.file("cache.txt"), cache.render()).unwrap();
        let mut config = Config::new(Mode::Client);
        config.cache_path = Some(dir.file("cache.txt"));
        config.default_nodes = DefaultNodes::fixed(Vec::new());
        let node = Node::open_with(config).await;
        assert!(node.inner.next_seq([5; 32], b"s") < far);
    }

    #[tokio::test]
    async fn a_cache_that_is_not_ours_is_ignored() {
        let net = testnet(3);
        let dir = Scratch::new();
        let signer = key(24);
        for (name, bytes) in [
            ("empty", Vec::new()),
            ("binary", vec![0xff, 0xfe, 0x00, 0x01]),
            ("other format", br#"{"nodes": ["1.2.3.4:5"]}"#.to_vec()),
            ("big", vec![b'x'; MAX_CACHE_BYTES as usize + 10]),
        ] {
            fs::write(dir.file(name), bytes).unwrap();
            let mut config = config(&net, Mode::Client);
            config.cache_path = Some(dir.file(name));
            let node = Node::open_with(config).await;
            assert_eq!(node.resolve(&signer.public_key(), SALT).await.unwrap(), None, "{name}");
        }
        // A directory where the file should be is not a reason to fail either.
        fs::create_dir(dir.file("dir")).unwrap();
        let mut config = config(&net, Mode::Client);
        config.cache_path = Some(dir.file("dir"));
        let node = Node::open_with(config).await;
        assert_eq!(node.resolve(&signer.public_key(), SALT).await.unwrap(), None);
        assert!(matches!(node.save_cache().await, Err(Error::Cache(_)) | Ok(false)));
    }

    #[test]
    fn the_cache_file_round_trips_and_skips_what_it_does_not_know() {
        let cache = CacheFile {
            nodes: vec!["198.51.100.1:6881".parse().unwrap(), "198.51.100.2:25401".parse().unwrap()],
            seqs: HashMap::from([
                (([1; 32], b"velora/1".to_vec()), SeqEntry { seq: 1_700_000_000, at: 1_700_000_001 }),
                (([2; 32], Vec::new()), SeqEntry { seq: -4, at: 0 }),
            ]),
        };
        let text = String::from_utf8(cache.render()).unwrap();
        assert_eq!(CacheFile::parse(&text), cache);
        assert_eq!(cache.render(), CacheFile::parse(&text).render(), "same content, same bytes");

        let noisy = format!(
            "{text}future 1 2 3\n\nnode not-an-address\nnode 198.51.100.1:6881\nseq zz - 1 1\nseq {} - 1\n",
            to_hex(&[1; 32])
        );
        assert_eq!(CacheFile::parse(&noisy), cache, "unknown lines, bad lines and repeats are skipped");
        assert_eq!(CacheFile::parse("velora-dht-cache 2\nnode 198.51.100.1:6881\n"), CacheFile::default());
        assert_eq!(CacheFile::parse(""), CacheFile::default());
    }

    #[test]
    fn a_cache_is_cut_to_what_is_kept() {
        let mut text = format!("{CACHE_HEADER}\n");
        for n in 0..200u32 {
            text += &format!("node 198.51.100.{}:{}\n", n % 250, 1000 + n);
            text += &format!("seq {} - {n} {n}\n", to_hex(&[(n % 256) as u8; 32]));
        }
        let cache = CacheFile::parse(&text);
        assert_eq!(cache.nodes.len(), MAX_CACHED_NODES);
        assert_eq!(cache.seqs.len(), MAX_SEQS);
    }

    #[test]
    fn the_nodes_saved_are_spread_over_the_table() {
        let table: Vec<u32> = (0..100).collect();
        let picked = spread(&table, 16);
        assert_eq!(picked.len(), 16);
        assert_eq!(picked.first(), Some(&0));
        assert!(picked.last().is_some_and(|last| *last > 85), "{picked:?}");
        assert!(picked.windows(2).all(|pair| pair[1] - pair[0] >= 6), "{picked:?}");
        assert_eq!(spread(&table[..10], 16), table[..10].to_vec());
        assert_eq!(spread::<u32>(&[], 16), Vec::<u32>::new());
    }

    #[test]
    fn hex_round_trips_and_refuses_what_is_not_hex() {
        assert_eq!(from_hex(&to_hex(&[0, 1, 0xab, 0xff])), Some(vec![0, 1, 0xab, 0xff]));
        assert_eq!(from_hex(""), Some(Vec::new()));
        for bad in ["a", "abc", "zz", "+1", "é1"] {
            assert_eq!(from_hex(bad), None, "{bad}");
        }
    }

    // === what a lookup gives ===

    fn item(seq: i64) -> MutableItem {
        MutableItem::new(key(1), b"v", seq, Some(SALT))
    }

    fn fabricated() -> (mpsc::UnboundedSender<MutableItem>, Lookup) {
        let (tx, items) = mpsc::unbounded_channel();
        let (_, outcome) = oneshot::channel();
        (tx, Lookup { items, outcome })
    }

    #[tokio::test]
    async fn the_highest_seq_wins_whatever_the_order() {
        let (tx, mut lookup) = fabricated();
        for seq in [5, 9, 7] {
            tx.send(item(seq)).unwrap();
        }
        drop(tx);
        let got = collect(&mut lookup, after(Duration::from_secs(5)), Some(Duration::from_secs(1))).await;
        assert_eq!(got.best.map(|i| i.seq()), Some(9));
        assert!(got.ended);
    }

    #[tokio::test]
    async fn a_record_that_comes_after_the_window_is_left_for_the_next_look() {
        let (tx, mut lookup) = fabricated();
        tx.send(item(5)).unwrap();
        let late = tokio::spawn(async move {
            sleep(Duration::from_millis(600)).await;
            let _ = tx.send(item(99));
        });
        let started = Instant::now();
        let got = collect(&mut lookup, after(Duration::from_secs(5)), Some(Duration::from_millis(100))).await;
        assert_eq!(got.best.map(|i| i.seq()), Some(5));
        assert!(!got.ended);
        assert!(started.elapsed() < Duration::from_millis(500), "{:?}", started.elapsed());
        late.abort();
    }

    #[tokio::test]
    async fn without_a_window_everything_up_to_the_end_counts() {
        let (tx, mut lookup) = fabricated();
        tx.send(item(5)).unwrap();
        let later = tokio::spawn(async move {
            sleep(Duration::from_millis(300)).await;
            tx.send(item(8)).unwrap();
            sleep(Duration::from_millis(100)).await;
        });
        let got = collect(&mut lookup, after(Duration::from_secs(5)), None).await;
        later.await.unwrap();
        assert_eq!(got.best.map(|i| i.seq()), Some(8));
        assert!(got.ended);
    }

    #[tokio::test]
    async fn a_lookup_that_ends_empty_or_runs_out_of_time_says_which() {
        let (tx, mut lookup) = fabricated();
        drop(tx);
        let got = collect(&mut lookup, after(Duration::from_secs(5)), None).await;
        assert!(got.best.is_none() && got.ended);

        let (_tx, mut lookup) = fabricated();
        let got = collect(&mut lookup, after(Duration::from_millis(100)), None).await;
        assert!(got.best.is_none() && !got.ended);
    }

    #[test]
    fn how_far_a_lookup_reached_decides_what_nothing_means() {
        let heard = |no_values| GetMutableOutcome { queried: 30, no_values, ..Default::default() };
        assert_eq!(Reach::of(&GetMutableOutcome { queried: 8, ..Default::default() }, 8), Reach::Dead);
        assert_eq!(Reach::of(&heard(3), 8), Reach::Thin);
        assert_eq!(Reach::of(&heard(8), 8), Reach::Healthy);
        // An error answer is an answer: somebody is there.
        assert_eq!(Reach::of(&GetMutableOutcome { queried: 8, krpc_errors: 2, ..Default::default() }, 8), Reach::Thin);
        assert_eq!(Reach::of_table(0, 8), Reach::Dead);
        assert_eq!(Reach::of_table(5, 8), Reach::Thin);
        assert_eq!(Reach::of_table(8, 8), Reach::Healthy);

        let (plenty, little) = (Duration::from_secs(4), Duration::from_millis(200));
        assert_eq!(verdict(Reach::Healthy, 0, plenty), Verdict::NoRecord);
        assert_eq!(verdict(Reach::Thin, 0, plenty), Verdict::Retry);
        assert_eq!(verdict(Reach::Dead, 0, plenty), Verdict::Retry);
        assert_eq!(verdict(Reach::Thin, 1, plenty), Verdict::NoRecord, "only one more try");
        assert_eq!(verdict(Reach::Dead, 1, plenty), Verdict::NoNetwork);
        assert_eq!(verdict(Reach::Dead, 0, little), Verdict::NoNetwork, "no time for another");
        assert_eq!(verdict(Reach::Thin, 0, little), Verdict::NoRecord);
    }

    #[test]
    fn the_limits_are_the_ones_the_sealing_keeps_to() {
        assert_eq!(MAX_VALUE_LEN, crate::seal::MAX_SEALED_LEN);
        assert_eq!(MAX_VALUE_LEN, 996);
        assert_eq!(MAX_SALT_LEN, 64);
        assert_eq!(Error::TooBig { len: 997 }.to_string(), "a DHT value is at most 996 bytes, this one has 997");
        assert_eq!(Error::SaltTooBig { len: 65 }.to_string(), "a DHT salt is at most 64 bytes, this one has 65");
    }

    /// Whether a node built with `settings` and forced into server mode (the state `mainline` reaches by itself after
    /// 15 minutes when it believes it is reachable) answers a ping.
    async fn answers_a_ping(settings: ServerSettings) -> bool {
        let mut builder = Dht::builder();
        builder.server_mode().no_bootstrap().bind_address(Ipv4Addr::LOCALHOST).server_settings(settings);
        let server = builder.build().unwrap().as_async();
        let address = server.info().await.local_addr();
        tokio::task::spawn_blocking(move || {
            let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            socket.set_read_timeout(Some(Duration::from_millis(700))).unwrap();
            // BEP 5's example ping, with the four-byte transaction id `mainline` insists on.
            socket.send_to(b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t4:aaaa1:y1:qe", address).unwrap();
            let mut reply = [0u8; 1500];
            socket.recv_from(&mut reply).is_ok()
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn the_node_answers_nobody_even_as_a_server() {
        // The control: `mainline` as it comes answers.
        assert!(answers_a_ping(ServerSettings::default()).await);
        // And with the filter the nodes are given, it does not.
        assert!(!answers_a_ping(Silent::settings()).await);
    }

    // === the real DHT ===

    /// Publishes a throwaway record on the public DHT from one node and reads it from others, to see the timings the
    /// design counts on. Random key, random bytes, nothing of the product; the record expires on its own in about two
    /// hours. By hand:
    /// `cargo test -p velora-dht --lib node::tests::on_the_public_dht -- --ignored --nocapture`
    #[tokio::test]
    #[ignore = "uses the public Mainline DHT"]
    async fn on_the_public_dht() {
        fn random(len: usize) -> Vec<u8> {
            let mut bytes = vec![0u8; len];
            SystemRandom::new().fill(&mut bytes).unwrap();
            bytes
        }
        let dir = Scratch::new();
        let seed: [u8; 32] = random(32).try_into().unwrap();
        let signer = SigningKey::from_bytes(&seed);
        let public = signer.public_key();
        let record = random(300);
        let salt = b"velora/test/c2";

        // The host: nothing saved, so a cold start.
        let started = std::time::Instant::now();
        let host = Node::open(dir.file("host.txt"), Mode::Host).await;
        println!("host: opened in {:?}", started.elapsed());
        let seq = host.next_seq(&signer, salt);
        let started = std::time::Instant::now();
        let published = host.publish(&signer, salt, &record, seq).await.unwrap();
        println!("host: published in {:?}, acknowledged by {} nodes", started.elapsed(), published.stored_at);
        let cache = fs::read_to_string(dir.file("host.txt")).unwrap();
        println!("host: {} nodes saved", cache.lines().filter(|line| line.starts_with("node ")).count());
        println!("host: observed address known: {}", host.observed_address().await.is_some());

        // A client with nothing saved.
        tokio::time::sleep(Duration::from_secs(10)).await;
        let started = std::time::Instant::now();
        let cold = Node::open(dir.file("cold.txt"), Mode::Client).await;
        let opened = started.elapsed();
        let found = cold.resolve(&public, salt).await.unwrap().expect("the record");
        assert_eq!(found, Resolved { value: record.clone(), seq });
        println!("cold client: opened in {opened:?}, record found {:?} after the open", started.elapsed() - opened);

        // Clients that start from the host's saved table, a few seconds apart.
        let warm_client = |round: usize, expected: Resolved| {
            let (cache, copy) = (dir.file("host.txt"), dir.file(&format!("warm{round}.txt")));
            async move {
                tokio::time::sleep(Duration::from_secs(10)).await;
                fs::copy(cache, &copy).unwrap();
                let started = std::time::Instant::now();
                let warm = Node::open(&copy, Mode::Client).await;
                let opened = started.elapsed();
                let found = warm.resolve(&public, salt).await.unwrap().expect("the record");
                assert_eq!(found, expected);
                println!(
                    "warm client {round}: opened in {opened:?}, record found {:?} after the open, {:?} in all",
                    started.elapsed() - opened,
                    started.elapsed()
                );
            }
        };
        warm_client(1, Resolved { value: record.clone(), seq }).await;
        warm_client(2, Resolved { value: record.clone(), seq }).await;

        // The host changes the record: the same key, from the node that has a table by now, and a higher seq.
        let newer = random(300);
        let started = std::time::Instant::now();
        let again =
            host.publish_with(&signer, salt, |_| Ok::<_, std::convert::Infallible>(newer.clone())).await.unwrap();
        println!("host: published again in {:?}, acknowledged by {} nodes", started.elapsed(), again.stored_at);
        assert!(again.seq > seq);
        // The old one can no longer be put back, nor the new one's seq taken by another record.
        let old = host.publish(&signer, salt, &record, seq).await.unwrap_err();
        assert!(matches!(old, Error::SeqTooLow { seen, .. } if seen == again.seq), "{old:?}");
        let rival = host.publish(&signer, salt, &record, again.seq).await.unwrap_err();
        assert!(matches!(rival, Error::SeqTooLow { seen, .. } if seen == again.seq), "{rival:?}");
        warm_client(3, Resolved { value: newer.clone(), seq: again.seq }).await;
    }
}
