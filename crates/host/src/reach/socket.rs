//! The UDP socket under the host's QUIC endpoint.
//!
//! Standalone reach asks three things of one socket, and quinn's own only does the first:
//!
//! 1. **QUIC on the real socket**, dual-stack: every datagram that is not claimed by something
//!    below goes to quinn, whoever sent it (a client dials from an address nobody knew before).
//! 2. **Probes**: datagrams that are not QUIC (the DHT pings of `velora_nat::observe::DhtProbe`),
//!    sent from the very port quinn listens on, because a NAT maps each source port on its own
//!    and the endpoint a peer must be told is the one the NAT shows for *this* port. The replies
//!    arrive on the same socket and are kept away from quinn: a [`Probe`] gives the multiplexer a
//!    function that is offered every datagram before quinn sees it.
//! 3. **Relay tunnels**: a host that cannot be reached dials out to a relay, and the clients the
//!    relay passes through appear to quinn as ordinary peers, at synthetic IPv6 addresses
//!    (`fd00:7e1a::/32`, the rest derived from the relay's fingerprint). A [`Tunnel`] is the pair
//!    of queues behind such a peer: what the relay connection delivers goes in, what quinn sends
//!    to that peer comes out. The pump between the queues and the relay connection is E4's.
//!
//! Sends are never held up by a tunnel: UDP drops under pressure and QUIC treats that as loss, so
//! a full or closed tunnel drops the packet and counts it ([`Stats`]) instead of reporting
//! `WouldBlock` (quinn has no way to ask "writable *for this peer*", and a send that kept
//! failing would spin its driver). The same goes for packets delivered faster than quinn reads.
//!
//! ## Address forms
//!
//! On a dual-stack socket the OS reports IPv4 peers as IPv4-mapped IPv6 (`::ffff:a.b.c.d`), and
//! quinn keeps them that way: `Connection::remote_address()` shows the mapped form. This module
//! leaves what quinn sees as the OS gave it, so the endpoint behaves like quinn's own on a
//! dual-stack socket, and converts at its own edges: a [`Probe`] sends to either form and its
//! function is offered the plain IPv4 form (what `DhtProbe` matches on).

use std::{
    collections::HashMap,
    fmt,
    future::Future,
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6},
    num::NonZeroU16,
    panic::{catch_unwind, AssertUnwindSafe},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex, MutexGuard, PoisonError, RwLock, Weak,
    },
    task::{ready, Context, Poll},
};

use bytes::Bytes;
use quinn::{
    udp::{RecvMeta, Transmit, UdpSocketState},
    AsyncUdpSocket, UdpPoller,
};
use tokio::{io::Interest, sync::mpsc};

/// First four bytes of every tunnel address: `fd00:7e1a::/32`, a unique-local prefix of our own.
const TUNNEL_PREFIX: [u8; 4] = [0xfd, 0x00, 0x7e, 0x1a];
/// Packets quinn has produced for a tunnel that its pump has not taken yet.
const TUNNEL_OUTBOUND_QUEUE: usize = 256;
/// Packets waiting for quinn to read them, all tunnels together.
const TUNNEL_INBOUND_QUEUE: usize = 512;
/// Of those, what one tunnel may hold, so a flood through one relay cannot crowd out the others.
const TUNNEL_INBOUND_LIMIT: usize = 128;
/// Tunnels open at once. A host has a handful of relays; this only bounds a misbehaving caller.
const MAX_TUNNELS: usize = 64;
/// Receive batches the socket handles in one poll before it lets the runtime run something else.
const RECV_BATCHES_PER_POLL: usize = 64;
/// Receive errors in a row, other than the harmless kinds, after which the socket is reported broken.
const MAX_RECV_ERRORS: u32 = 16;

/// Whether `addr` is one of the synthetic addresses of relay tunnels (see [`tunnel_addr`]).
pub fn is_tunnel_addr(addr: SocketAddr) -> bool {
    matches!(addr.ip(), IpAddr::V6(ip) if ip.octets()[..4] == TUNNEL_PREFIX)
}

/// The address quinn sees for the peers behind `relay` (its fingerprint, raw): `fd00:7e1a:` and 96
/// bits of a hash of the fingerprint, with `flow` as the port. A relay that passes one client at a
/// time uses flow 1; a caller that keeps several connections to a relay uses one flow for each.
pub fn tunnel_addr(relay: &[u8; 32], flow: NonZeroU16) -> SocketAddr {
    let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
    hash.update(b"velora-relay-tunnel/1");
    hash.update(relay);
    let digest = hash.finish();
    let mut octets = [0u8; 16];
    octets[..4].copy_from_slice(&TUNNEL_PREFIX);
    octets[4..].copy_from_slice(&digest.as_ref()[..12]);
    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(octets), flow.get(), 0, 0))
}

/// The same address with an IPv4-mapped IPv6 address turned into the IPv4 one.
fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What the multiplexer did that quinn never hears about, for logs and tests.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    /// Datagrams a probe took, so quinn never saw them.
    pub probe_replies: u64,
    /// Datagrams that came in on the real socket from an address inside the tunnel range: nothing
    /// real can have that address, so they are dropped rather than taken for a relayed peer.
    pub spoofed: u64,
    /// Packets from tunnels handed to quinn.
    pub tunnel_in: u64,
    /// Packets a tunnel was given while its share of the queue (or the queue) was full.
    pub tunnel_in_full: u64,
    /// Packets given to a tunnel that was closed.
    pub tunnel_in_closed: u64,
    /// Packets quinn sent to a tunnel and its pump can take.
    pub tunnel_out: u64,
    /// Packets quinn sent to a tunnel whose queue was full: the pump is not keeping up.
    pub tunnel_out_full: u64,
    /// Packets quinn sent to an address in the tunnel range with no open tunnel.
    pub tunnel_out_closed: u64,
}

#[derive(Default)]
struct Counters {
    probe_replies: AtomicU64,
    spoofed: AtomicU64,
    tunnel_in: AtomicU64,
    tunnel_in_full: AtomicU64,
    tunnel_in_closed: AtomicU64,
    tunnel_out: AtomicU64,
    tunnel_out_full: AtomicU64,
    tunnel_out_closed: AtomicU64,
}

impl Counters {
    fn bump(counter: &AtomicU64) -> u64 {
        counter.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn snapshot(&self) -> Stats {
        let get = |c: &AtomicU64| c.load(Ordering::Relaxed);
        Stats {
            probe_replies: get(&self.probe_replies),
            spoofed: get(&self.spoofed),
            tunnel_in: get(&self.tunnel_in),
            tunnel_in_full: get(&self.tunnel_in_full),
            tunnel_in_closed: get(&self.tunnel_in_closed),
            tunnel_out: get(&self.tunnel_out),
            tunnel_out_full: get(&self.tunnel_out_full),
            tunnel_out_closed: get(&self.tunnel_out_closed),
        }
    }
}

/// Logs the first drop of a kind and then every 1024th, so a stuck relay cannot flood the log.
fn log_drop(count: u64, what: &str) {
    if count == 1 || count.is_multiple_of(1024) {
        tracing::debug!("relay tunnel: {what} ({count} so far)");
    }
}

/// The socket quinn's endpoint runs on. Build it with [`Multiplexer::new`] (inside a Tokio
/// runtime), give it to `quinn::Endpoint::new_with_abstract_socket`, and keep the `Arc`: probes
/// and tunnels are opened through it.
pub struct Multiplexer {
    io: tokio::net::UdpSocket,
    state: UdpSocketState,
    local: SocketAddr,
    probes: Probes,
    tunnels: Arc<Tunnels>,
    counters: Arc<Counters>,
    /// Which source `poll_recv` asks first, flipped on every call.
    turn: AtomicBool,
}

impl fmt::Debug for Multiplexer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Multiplexer").field("local", &self.local).field("stats", &self.stats()).finish()
    }
}

impl Multiplexer {
    /// Takes over a bound UDP socket. Needs a Tokio runtime, like quinn's own socket wrapper.
    pub fn new(socket: std::net::UdpSocket) -> io::Result<Multiplexer> {
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(io::Error::other("the socket needs a Tokio runtime"));
        }
        socket.set_nonblocking(true)?;
        let state = UdpSocketState::new((&socket).into())?;
        let io = tokio::net::UdpSocket::from_std(socket)?;
        let local = io.local_addr()?;
        Ok(Multiplexer {
            io,
            state,
            local,
            probes: Probes::default(),
            tunnels: Arc::new(Tunnels::new()),
            counters: Arc::default(),
            turn: AtomicBool::new(false),
        })
    }

    /// The address the real socket is bound to (IPv6 when it is dual-stack).
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// What the multiplexer has dropped or kept from quinn so far.
    pub fn stats(&self) -> Stats {
        self.counters.snapshot()
    }

    /// Lets `handler` look at every datagram that arrives on the real socket before quinn does,
    /// and keep the ones it returns `true` for. It is offered `(source, datagram)` with the
    /// source in plain IPv4 form when it is an IPv4 peer, from quinn's receiving task, so it must
    /// be quick, must not block and must not open or close probes. It answers for datagrams it
    /// does not recognize with `false`: those go on to quinn, so the match belongs on the source
    /// address and on something in the datagram that only a reply to the probe has (a
    /// transaction id). A panic inside it is caught: the probe is removed and logged.
    ///
    /// The probe lasts until the returned [`Probe`] is dropped.
    pub fn probe(self: &Arc<Self>, handler: impl FnMut(SocketAddr, &[u8]) -> bool + Send + 'static) -> Probe {
        let id = self.probes.add(Box::new(handler));
        Probe { mux: self.clone(), id }
    }

    /// Opens the tunnel for the peers behind `relay` (its raw fingerprint) at `flow`. Its address is
    /// [`tunnel_addr`]. Fails when that address is already open, or when too many are.
    pub fn open_tunnel(self: &Arc<Self>, relay: [u8; 32], flow: NonZeroU16) -> Result<Tunnel, TunnelError> {
        self.tunnels.open(relay, flow, &self.counters)
    }

    /// The relay (raw fingerprint) behind a tunnel address, if one is open there: how a connection
    /// that came through a relay is told from one that came straight in.
    pub fn tunnel_relay(&self, addr: SocketAddr) -> Option<[u8; 32]> {
        if !is_tunnel_addr(addr) {
            return None;
        }
        self.tunnels.get(addr).map(|entry| entry.shared.relay)
    }

    /// The form of `addr` the real socket takes, or `None` when it cannot reach it at all.
    fn for_socket(&self, addr: SocketAddr) -> Option<SocketAddr> {
        match (self.local.is_ipv6(), addr) {
            (true, SocketAddr::V4(v4)) => {
                Some(SocketAddr::V6(SocketAddrV6::new(v4.ip().to_ipv6_mapped(), v4.port(), 0, 0)))
            }
            (true, SocketAddr::V6(_)) | (false, SocketAddr::V4(_)) => Some(addr),
            (false, SocketAddr::V6(v6)) => v6.ip().to_ipv4_mapped().map(|ip| SocketAddr::new(ip.into(), v6.port())),
        }
    }

    fn poll_socket(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let (mut batches, mut errors) = (0, 0);
        loop {
            ready!(self.io.poll_recv_ready(cx))?;
            match self.io.try_io(Interest::READABLE, || self.state.recv((&self.io).into(), bufs, meta)) {
                Ok(received) => {
                    let kept = self.filter(bufs, meta, received);
                    if kept > 0 {
                        return Poll::Ready(Ok(kept));
                    }
                    batches += 1;
                    if batches >= RECV_BATCHES_PER_POLL {
                        // A stream of datagrams that all go to probes: let others run.
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                // `try_io` cleared the readiness: the next `poll_recv_ready` registers the waker.
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                // An ICMP error about an earlier send, reported on a later receive (Windows).
                Err(e) if matches!(e.kind(), io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted) => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    errors += 1;
                    if errors >= MAX_RECV_ERRORS {
                        return Poll::Ready(Err(e));
                    }
                }
            }
        }
    }

    /// Takes out of the received batch what quinn must not see, and moves the rest down so the
    /// first `n` entries are the datagrams to hand over. Returns `n`.
    fn filter(&self, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta], received: usize) -> usize {
        let probing = self.probes.active.load(Ordering::Relaxed) > 0;
        let mut kept = 0;
        for i in 0..received {
            let m = meta[i];
            if is_tunnel_addr(m.addr) {
                log_drop(
                    Counters::bump(&self.counters.spoofed),
                    "a datagram from the real network claimed a tunnel's address",
                );
                continue;
            }
            let len = if probing { self.take_probe_replies(&mut bufs[i], &m) } else { m.len };
            if len == 0 {
                continue;
            }
            if kept != i {
                let (done, rest) = bufs.split_at_mut(i);
                done[kept][..len].copy_from_slice(&rest[0][..len]);
            }
            meta[kept] = RecvMeta { len, ..m };
            kept += 1;
        }
        kept
    }

    /// Offers each datagram of `buf` (several when the kernel coalesced them) to the probes and
    /// squeezes out the ones taken. Returns how many bytes are left.
    fn take_probe_replies(&self, buf: &mut IoSliceMut<'_>, m: &RecvMeta) -> usize {
        let from = canonical(m.addr);
        let len = m.len.min(buf.len());
        let stride = if m.stride == 0 { len.max(1) } else { m.stride };
        let (mut read, mut kept) = (0, 0);
        while read < len {
            let end = (read + stride).min(len);
            if self.probes.offer(from, &buf[read..end]) {
                Counters::bump(&self.counters.probe_replies);
            } else {
                if kept != read {
                    buf.copy_within(read..end, kept);
                }
                kept += end - read;
            }
            read = end;
        }
        kept
    }

    fn poll_tunnels(&self, cx: &mut Context<'_>, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta]) -> Poll<usize> {
        let mut inbound = lock(&self.tunnels.inbound_rx);
        let mut n = 0;
        while n < bufs.len().min(meta.len()) {
            let Poll::Ready(Some(packet)) = inbound.poll_recv(cx) else { break };
            packet.tunnel.queued.fetch_sub(1, Ordering::Relaxed);
            let len = packet.data.len();
            if len > bufs[n].len() {
                tracing::debug!("a relayed packet of {len} bytes does not fit the receive buffer");
                continue;
            }
            bufs[n][..len].copy_from_slice(&packet.data);
            meta[n] = RecvMeta { addr: packet.tunnel.addr, len, stride: len, ecn: None, dst_ip: None };
            Counters::bump(&self.counters.tunnel_in);
            n += 1;
        }
        if n > 0 {
            Poll::Ready(n)
        } else {
            Poll::Pending
        }
    }

    /// Sends a datagram that is not QUIC from the real socket, waiting while its send buffer is
    /// full, and reports the error, which quinn's own sends would only log (a probe's sender
    /// decides what a failure means).
    async fn send_raw(&self, to: SocketAddr, datagram: &[u8]) -> io::Result<()> {
        if is_tunnel_addr(to) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "a relay tunnel takes no probes"));
        }
        let destination = self
            .for_socket(to)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "the socket cannot reach that address family"))?;
        let transmit = Transmit { destination, ecn: None, contents: datagram, segment_size: None, src_ip: None };
        loop {
            self.io.writable().await?;
            match self.io.try_io(Interest::WRITABLE, || self.state.try_send((&self.io).into(), &transmit)) {
                // The readiness was stale: wait for the next.
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                result => return result,
            }
        }
    }
}

impl AsyncUdpSocket for Multiplexer {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Poller { mux: self, writable: None })
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        if is_tunnel_addr(transmit.destination) {
            self.tunnels.send(transmit, &self.counters);
            return Ok(());
        }
        let Some(destination) = self.for_socket(transmit.destination) else {
            tracing::debug!("cannot send to {}: not an address this socket reaches", transmit.destination);
            return Ok(());
        };
        let transmit = Transmit { destination, ..transmit.clone() };
        self.io.try_io(Interest::WRITABLE, || self.state.send((&self.io).into(), &transmit))
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        // Ask the sources in turn, so a flood on one cannot keep the other waiting.
        if self.turn.fetch_xor(true, Ordering::Relaxed) {
            if let Poll::Ready(n) = self.poll_tunnels(cx, bufs, meta) {
                return Poll::Ready(Ok(n));
            }
            self.poll_socket(cx, bufs, meta)
        } else {
            if let Poll::Ready(result) = self.poll_socket(cx, bufs, meta) {
                return Poll::Ready(result);
            }
            self.poll_tunnels(cx, bufs, meta).map(Ok)
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }

    fn may_fragment(&self) -> bool {
        self.state.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        self.state.max_gso_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.state.gro_segments()
    }
}

/// Tells a connection when the real socket can take a send. Tunnel sends never wait (see the
/// module docs), so this is the real socket's readiness, as quinn's own wrapper reports it.
struct Poller {
    mux: Arc<Multiplexer>,
    writable: Option<Pin<Box<dyn Future<Output = io::Result<()>> + Send + Sync>>>,
}

impl fmt::Debug for Poller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Poller").finish_non_exhaustive()
    }
}

impl UdpPoller for Poller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mux = &this.mux;
        let writable = this.writable.get_or_insert_with(|| {
            let mux = mux.clone();
            Box::pin(async move { mux.io.writable().await })
        });
        let result = writable.as_mut().poll(cx);
        if result.is_ready() {
            // A finished future must not be polled again: the next call makes a new one.
            this.writable = None;
        }
        result
    }
}

type ProbeFn = Box<dyn FnMut(SocketAddr, &[u8]) -> bool + Send>;

#[derive(Default)]
struct Probes {
    handlers: Mutex<Vec<(u64, ProbeFn)>>,
    /// How many are open, so the receive path costs one load when there are none.
    active: AtomicUsize,
    next: AtomicU64,
}

impl Probes {
    fn add(&self, handler: ProbeFn) -> u64 {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let mut handlers = lock(&self.handlers);
        handlers.push((id, handler));
        self.active.store(handlers.len(), Ordering::Relaxed);
        id
    }

    fn remove(&self, id: u64) {
        let mut handlers = lock(&self.handlers);
        handlers.retain(|(other, _)| *other != id);
        self.active.store(handlers.len(), Ordering::Relaxed);
    }

    /// Whether some probe took the datagram.
    fn offer(&self, from: SocketAddr, datagram: &[u8]) -> bool {
        let mut handlers = lock(&self.handlers);
        let mut taken = false;
        let mut broken = Vec::new();
        for (id, handler) in handlers.iter_mut() {
            match catch_unwind(AssertUnwindSafe(|| handler(from, datagram))) {
                Ok(true) => {
                    taken = true;
                    break;
                }
                Ok(false) => {}
                Err(_) => broken.push(*id),
            }
        }
        if !broken.is_empty() {
            tracing::error!("a probe panicked on a datagram from {from}; it was removed");
            handlers.retain(|(id, _)| !broken.contains(id));
            self.active.store(handlers.len(), Ordering::Relaxed);
        }
        taken
    }
}

/// A probe on the multiplexer (see [`Multiplexer::probe`]). Dropping it stops offering datagrams
/// to its function.
pub struct Probe {
    mux: Arc<Multiplexer>,
    id: u64,
}

impl Probe {
    /// Sends `datagram` to `to` from the socket quinn listens on, so a NAT maps the same port for
    /// both. `to` may be a plain IPv4 address on a dual-stack socket. Waits while the socket's
    /// send buffer is full. Fails with the OS error (no route, an address family the socket does
    /// not reach) and with `InvalidInput` for a tunnel address; nothing is sent then.
    pub async fn send_to(&self, to: SocketAddr, datagram: &[u8]) -> io::Result<()> {
        self.mux.send_raw(to, datagram).await
    }

    /// The address of the socket (IPv6 when it is dual-stack).
    pub fn local_addr(&self) -> SocketAddr {
        self.mux.local
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        self.mux.probes.remove(self.id);
    }
}

/// Why a tunnel could not be opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelError {
    /// There is a tunnel at that address already: close it first.
    AlreadyOpen(SocketAddr),
    /// [`MAX_TUNNELS`] are open.
    TooMany,
}

impl fmt::Display for TunnelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TunnelError::AlreadyOpen(addr) => write!(f, "a tunnel is already open at {addr}"),
            TunnelError::TooMany => write!(f, "too many relay tunnels are open"),
        }
    }
}

impl std::error::Error for TunnelError {}

/// Why a packet was not queued for quinn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Undelivered {
    /// The tunnel's share of the queue is full: quinn is not reading fast enough. The packet is
    /// dropped, like one a full socket buffer drops; the inner QUIC recovers it.
    Full,
    /// The tunnel was closed, or the multiplexer is gone.
    Closed,
}

impl fmt::Display for Undelivered {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Undelivered::Full => write!(f, "the tunnel's queue is full"),
            Undelivered::Closed => write!(f, "the tunnel is closed"),
        }
    }
}

impl std::error::Error for Undelivered {}

/// A packet on its way from a tunnel to quinn.
struct Inbound {
    tunnel: Arc<TunnelShared>,
    data: Bytes,
}

struct TunnelShared {
    addr: SocketAddr,
    relay: [u8; 32],
    /// Tells a tunnel from an earlier one at the same address, so a stale handle closing late
    /// cannot take the new one out of the table.
    generation: u64,
    closed: AtomicBool,
    /// Packets of this tunnel waiting for quinn.
    queued: AtomicUsize,
}

struct Entry {
    shared: Arc<TunnelShared>,
    out: mpsc::Sender<Bytes>,
}

struct Tunnels {
    map: RwLock<HashMap<SocketAddr, Entry>>,
    inbound_tx: mpsc::Sender<Inbound>,
    inbound_rx: Mutex<mpsc::Receiver<Inbound>>,
    next_generation: AtomicU64,
}

impl Tunnels {
    fn new() -> Tunnels {
        let (inbound_tx, inbound_rx) = mpsc::channel(TUNNEL_INBOUND_QUEUE);
        Tunnels {
            map: RwLock::default(),
            inbound_tx,
            inbound_rx: Mutex::new(inbound_rx),
            next_generation: AtomicU64::new(1),
        }
    }

    fn open(
        self: &Arc<Self>,
        relay: [u8; 32],
        flow: NonZeroU16,
        counters: &Arc<Counters>,
    ) -> Result<Tunnel, TunnelError> {
        let addr = tunnel_addr(&relay, flow);
        let mut map = self.map.write().unwrap_or_else(PoisonError::into_inner);
        if map.contains_key(&addr) {
            return Err(TunnelError::AlreadyOpen(addr));
        }
        if map.len() >= MAX_TUNNELS {
            return Err(TunnelError::TooMany);
        }
        let shared = Arc::new(TunnelShared {
            addr,
            relay,
            generation: self.next_generation.fetch_add(1, Ordering::Relaxed),
            closed: AtomicBool::new(false),
            queued: AtomicUsize::new(0),
        });
        let (out, outbound) = mpsc::channel(TUNNEL_OUTBOUND_QUEUE);
        map.insert(addr, Entry { shared: shared.clone(), out });
        Ok(Tunnel { shared, outbound, tunnels: Arc::downgrade(self), counters: counters.clone() })
    }

    fn get(&self, addr: SocketAddr) -> Option<TunnelRef> {
        let map = self.map.read().unwrap_or_else(PoisonError::into_inner);
        map.get(&addr).map(|entry| TunnelRef { shared: entry.shared.clone(), out: entry.out.clone() })
    }

    fn close(&self, shared: &TunnelShared) {
        shared.closed.store(true, Ordering::Release);
        let mut map = self.map.write().unwrap_or_else(PoisonError::into_inner);
        if map.get(&shared.addr).is_some_and(|entry| entry.shared.generation == shared.generation) {
            map.remove(&shared.addr);
        }
    }

    /// Queues what quinn sent to a tunnel address for the tunnel's pump. Never blocks and never
    /// fails: a packet that has nowhere to go is dropped and counted.
    fn send(&self, transmit: &Transmit<'_>, counters: &Counters) {
        let Some(tunnel) = self.get(transmit.destination) else {
            log_drop(Counters::bump(&counters.tunnel_out_closed), "quinn sent to a tunnel that is not open");
            return;
        };
        // One transmit may hold several datagrams of `segment_size` bytes (GSO).
        let size = transmit.segment_size.filter(|s| *s > 0).unwrap_or(transmit.contents.len()).max(1);
        for datagram in transmit.contents.chunks(size) {
            match tunnel.out.try_send(Bytes::copy_from_slice(datagram)) {
                Ok(()) => {
                    Counters::bump(&counters.tunnel_out);
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    log_drop(Counters::bump(&counters.tunnel_out_full), "the relay connection is not taking packets")
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    log_drop(Counters::bump(&counters.tunnel_out_closed), "quinn sent to a tunnel that was closed")
                }
            }
        }
    }
}

struct TunnelRef {
    shared: Arc<TunnelShared>,
    out: mpsc::Sender<Bytes>,
}

/// One relay's way into the endpoint: quinn sees the peers behind it at [`Tunnel::addr`].
///
/// The caller (E4) pumps it: every inner packet read from the relay connection goes to
/// [`Tunnel::inbound`]`.deliver`, and every packet [`Tunnel::next_outbound`] yields is framed and
/// sent on the relay connection. Dropping the `Tunnel` closes it; quinn's connections through it
/// then see nothing arrive and end by their idle timeout, or carry on if the caller opens a tunnel
/// at the same address again (the same relay and flow) before that.
pub struct Tunnel {
    shared: Arc<TunnelShared>,
    outbound: mpsc::Receiver<Bytes>,
    tunnels: Weak<Tunnels>,
    counters: Arc<Counters>,
}

impl Tunnel {
    /// The address quinn sees for the peers behind this tunnel.
    pub fn addr(&self) -> SocketAddr {
        self.shared.addr
    }

    /// The relay this tunnel is for (its raw fingerprint).
    pub fn relay(&self) -> [u8; 32] {
        self.shared.relay
    }

    /// A handle for feeding packets to quinn, to use from another task than the one that reads
    /// [`Tunnel::next_outbound`].
    pub fn inbound(&self) -> TunnelInbound {
        TunnelInbound { shared: self.shared.clone(), tunnels: self.tunnels.clone(), counters: self.counters.clone() }
    }

    /// The next packet quinn sent to the peers behind this tunnel, to be sent on the relay
    /// connection. `None` once the multiplexer is gone.
    pub async fn next_outbound(&mut self) -> Option<Bytes> {
        self.outbound.recv().await
    }

    /// The next packet if one is already waiting.
    pub fn try_next_outbound(&mut self) -> Option<Bytes> {
        self.outbound.try_recv().ok()
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        match self.tunnels.upgrade() {
            Some(tunnels) => tunnels.close(&self.shared),
            None => self.shared.closed.store(true, Ordering::Release),
        }
    }
}

impl fmt::Debug for Tunnel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tunnel").field("addr", &self.shared.addr).finish_non_exhaustive()
    }
}

/// The feeding end of a [`Tunnel`]; clones share it. Outliving the tunnel is harmless: it then
/// reports [`Undelivered::Closed`].
#[derive(Clone)]
pub struct TunnelInbound {
    shared: Arc<TunnelShared>,
    tunnels: Weak<Tunnels>,
    counters: Arc<Counters>,
}

impl TunnelInbound {
    /// Queues one inner packet (what the relay connection delivered, after reassembly) for quinn,
    /// as if it had arrived from [`Tunnel::addr`]. Never blocks: when quinn is behind, the packet
    /// is dropped and `Full` returned.
    pub fn deliver(&self, packet: Bytes) -> Result<(), Undelivered> {
        let closed = || {
            log_drop(Counters::bump(&self.counters.tunnel_in_closed), "a packet reached a tunnel that was closed");
            Err(Undelivered::Closed)
        };
        if self.shared.closed.load(Ordering::Acquire) {
            return closed();
        }
        let Some(tunnels) = self.tunnels.upgrade() else { return closed() };
        let full = || {
            log_drop(Counters::bump(&self.counters.tunnel_in_full), "quinn is not reading relayed packets fast enough");
            Err(Undelivered::Full)
        };
        if self.shared.queued.fetch_add(1, Ordering::Relaxed) >= TUNNEL_INBOUND_LIMIT {
            self.shared.queued.fetch_sub(1, Ordering::Relaxed);
            return full();
        }
        match tunnels.inbound_tx.try_send(Inbound { tunnel: self.shared.clone(), data: packet }) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.shared.queued.fetch_sub(1, Ordering::Relaxed);
                full()
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.shared.queued.fetch_sub(1, Ordering::Relaxed);
                closed()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{future::poll_fn, net::Ipv4Addr, sync::Mutex, time::Duration};

    use tokio::net::UdpSocket;
    use velora_nat::observe::{reply_to_ping, DhtProbe};

    use super::*;

    const WAIT: Duration = Duration::from_secs(5);
    const RELAY: [u8; 32] = [7; 32];
    const ONE: NonZeroU16 = NonZeroU16::MIN;

    /// A multiplexer on the IPv4 loopback.
    fn v4() -> Arc<Multiplexer> {
        Arc::new(Multiplexer::new(std::net::UdpSocket::bind("127.0.0.1:0").unwrap()).unwrap())
    }

    /// A dual-stack multiplexer, when this machine has IPv6 at all.
    fn dual_stack() -> Option<Arc<Multiplexer>> {
        let socket = crate::reach::bind("[::]:0".parse().unwrap()).ok()?;
        let mux = Multiplexer::new(socket).ok()?;
        mux.local_addr().is_ipv6().then(|| Arc::new(mux))
    }

    fn mapped(port: u16) -> SocketAddr {
        SocketAddr::new(Ipv4Addr::LOCALHOST.to_ipv6_mapped().into(), port)
    }

    /// What one `poll_recv` of the multiplexer hands to quinn, with room for four datagrams.
    async fn received(mux: &Multiplexer) -> Vec<(SocketAddr, Vec<u8>)> {
        let mut storage = vec![vec![0u8; 2048]; 4];
        let mut bufs: Vec<IoSliceMut<'_>> = storage.iter_mut().map(|b| IoSliceMut::new(b)).collect();
        let mut meta = [RecvMeta::default(); 4];
        let n = tokio::time::timeout(WAIT, poll_fn(|cx| mux.poll_recv(cx, &mut bufs, &mut meta)))
            .await
            .expect("nothing reached quinn")
            .unwrap();
        (0..n).map(|i| (meta[i].addr, bufs[i][..meta[i].len].to_vec())).collect()
    }

    /// Whether nothing reaches quinn for a moment.
    async fn quiet(mux: &Multiplexer) -> bool {
        let mut storage = vec![vec![0u8; 2048]; 4];
        let mut bufs: Vec<IoSliceMut<'_>> = storage.iter_mut().map(|b| IoSliceMut::new(b)).collect();
        let mut meta = [RecvMeta::default(); 4];
        let wait = Duration::from_millis(250);
        tokio::time::timeout(wait, poll_fn(|cx| mux.poll_recv(cx, &mut bufs, &mut meta))).await.is_err()
    }

    fn send(mux: &Multiplexer, to: SocketAddr, contents: &[u8]) {
        mux.try_send(&Transmit { destination: to, ecn: None, contents, segment_size: None, src_ip: None }).unwrap();
    }

    /// Sends the way quinn does, after the socket says it is writable.
    async fn send_real(mux: &Arc<Multiplexer>, to: SocketAddr, contents: &[u8]) {
        let mut poller = mux.clone().create_io_poller();
        poll_fn(|cx| poller.as_mut().poll_writable(cx)).await.unwrap();
        send(mux, to, contents);
    }

    async fn recv_from(socket: &UdpSocket) -> (Vec<u8>, SocketAddr) {
        let mut buf = [0u8; 2048];
        let (n, from) = tokio::time::timeout(WAIT, socket.recv_from(&mut buf)).await.unwrap().unwrap();
        (buf[..n].to_vec(), from)
    }

    #[tokio::test]
    async fn a_datagram_from_an_unknown_source_reaches_quinn() {
        let mux = v4();
        let a = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        a.send_to(b"from a", mux.local_addr()).unwrap();
        assert_eq!(received(&mux).await, vec![(a.local_addr().unwrap(), b"from a".to_vec())]);
        b.send_to(b"from b", mux.local_addr()).unwrap();
        assert_eq!(received(&mux).await, vec![(b.local_addr().unwrap(), b"from b".to_vec())]);
        assert_eq!(mux.stats(), Stats::default());
    }

    #[tokio::test]
    async fn quinns_sends_reach_the_network() {
        let mux = v4();
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        send_real(&mux, peer.local_addr().unwrap(), b"hello").await;
        assert_eq!(recv_from(&peer).await, (b"hello".to_vec(), mux.local_addr()));
    }

    #[tokio::test]
    async fn a_dual_stack_socket_reports_ipv4_peers_mapped_and_sends_to_either_form() {
        let Some(mux) = dual_stack() else { return eprintln!("no IPv6 on this machine: skipped") };
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_port = peer.local_addr().unwrap().port();
        peer.send_to(b"hi", (Ipv4Addr::LOCALHOST, mux.local_addr().port())).await.unwrap();
        assert_eq!(received(&mux).await, vec![(mapped(peer_port), b"hi".to_vec())], "quinn sees the OS's form");

        // Both forms of the destination reach the IPv4 peer: quinn's (mapped) and a probe's (plain).
        send_real(&mux, mapped(peer_port), b"mapped").await;
        assert_eq!(recv_from(&peer).await.0, b"mapped");
        let probe = mux.probe(|_, _| false);
        probe.send_to(peer.local_addr().unwrap(), b"plain").await.unwrap();
        let (datagram, from) = recv_from(&peer).await;
        assert_eq!((datagram, from.port()), (b"plain".to_vec(), mux.local_addr().port()));
    }

    #[tokio::test]
    async fn an_ipv4_socket_takes_a_mapped_destination_and_drops_what_it_cannot_reach() {
        let mux = v4();
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        send_real(&mux, mapped(peer.local_addr().unwrap().port()), b"mapped").await;
        assert_eq!(recv_from(&peer).await.0, b"mapped");
        // Not an address this socket reaches: dropped quietly; failing would end a connection over it.
        send_real(&mux, "[2001:db8::1]:9".parse().unwrap(), b"nowhere").await;
    }

    /// A fake DHT node, and a `DhtProbe` that talks to it through the multiplexer.
    struct Dht {
        probe: Probe,
        state: Arc<Mutex<DhtProbe>>,
        node: UdpSocket,
    }

    async fn dht(mux: &Arc<Multiplexer>) -> Dht {
        let node = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let state = Arc::new(Mutex::new(DhtProbe::new(&[node.local_addr().unwrap()])));
        let handler = state.clone();
        let probe = mux.probe(move |from, datagram| handler.lock().unwrap().handle(from, datagram));
        Dht { probe, state, node }
    }

    impl Dht {
        fn ping(&self) -> Vec<u8> {
            self.state.lock().unwrap().pending().next().unwrap().1.to_vec()
        }

        /// Sends the pending pings through the probe and has the node answer, as a BEP 42 node does.
        async fn ping_and_answer(&self) {
            let pings: Vec<(SocketAddr, Vec<u8>)> =
                self.state.lock().unwrap().pending().map(|(node, ping)| (node, ping.to_vec())).collect();
            for (node, ping) in pings {
                self.probe.send_to(node, &ping).await.unwrap();
            }
            let (ping, requester) = recv_from(&self.node).await;
            let reply = reply_to_ping(&ping, requester).expect("a ping");
            self.node.send_to(&reply, requester).await.unwrap();
        }
    }

    #[tokio::test]
    async fn probe_replies_stay_away_from_quinn() {
        let mux = v4();
        let dht = dht(&mux).await;
        dht.ping_and_answer().await;
        assert!(quiet(&mux).await, "the reply must not reach quinn");
        // The node saw the multiplexer's own port: the endpoint a NAT would show for it.
        let seen: Vec<_> = dht.state.lock().unwrap().observations().iter().map(|o| o.endpoint).collect();
        assert_eq!(seen, vec![mux.local_addr()]);
        assert_eq!(mux.stats().probe_replies, 1);
    }

    #[tokio::test]
    async fn only_a_reply_from_the_node_with_our_transaction_id_is_kept_from_quinn() {
        let mux = v4();
        let dht = dht(&mux).await;
        let node = dht.node.local_addr().unwrap();
        // From the node, but another transaction id: not an answer to our ping, so quinn's.
        dht.node.send_to(b"d1:t4:xxxx1:y1:re", mux.local_addr()).await.unwrap();
        assert_eq!(received(&mux).await, vec![(node, b"d1:t4:xxxx1:y1:re".to_vec())]);
        // Garbage from the node is no reply either.
        dht.node.send_to(b"\x40garbage", mux.local_addr()).await.unwrap();
        assert_eq!(received(&mux).await, vec![(node, b"\x40garbage".to_vec())]);
        // The right bytes from another address are not the node's answer: quinn's.
        let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let reply = reply_to_ping(&dht.ping(), mux.local_addr()).unwrap();
        stranger.send_to(&reply, mux.local_addr()).await.unwrap();
        assert_eq!(received(&mux).await, vec![(stranger.local_addr().unwrap(), reply.clone())]);
        // From the node itself they are, and quinn never sees them.
        dht.node.send_to(&reply, mux.local_addr()).await.unwrap();
        assert!(quiet(&mux).await);
        assert_eq!(dht.state.lock().unwrap().observations().len(), 1);
    }

    #[tokio::test]
    async fn probes_hear_the_plain_ipv4_form_of_a_mapped_source() {
        let Some(mux) = dual_stack() else { return eprintln!("no IPv6 on this machine: skipped") };
        let heard = Arc::new(Mutex::new(Vec::new()));
        let handler = heard.clone();
        let _probe = mux.probe(move |from, _| {
            handler.lock().unwrap().push(from);
            true
        });
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        peer.send_to(b"x", (Ipv4Addr::LOCALHOST, mux.local_addr().port())).await.unwrap();
        assert!(quiet(&mux).await);
        assert_eq!(*heard.lock().unwrap(), vec![peer.local_addr().unwrap()]);
    }

    #[tokio::test]
    async fn a_dropped_probe_stops_taking_datagrams() {
        let mux = v4();
        let taken = Arc::new(Mutex::new(0));
        let counter = taken.clone();
        let probe = mux.probe(move |_, _| {
            *counter.lock().unwrap() += 1;
            true
        });
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        peer.send_to(b"one", mux.local_addr()).await.unwrap();
        assert!(quiet(&mux).await);
        assert_eq!(*taken.lock().unwrap(), 1);
        drop(probe);
        peer.send_to(b"two", mux.local_addr()).await.unwrap();
        assert_eq!(received(&mux).await.len(), 1);
        assert_eq!(*taken.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn a_probe_that_panics_is_removed_and_the_datagram_goes_on_to_quinn() {
        let mux = v4();
        let _probe = mux.probe(|_, _| panic!("a bug in a probe"));
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        peer.send_to(b"one", mux.local_addr()).await.unwrap();
        assert_eq!(received(&mux).await.len(), 1);
        assert_eq!(mux.probes.active.load(Ordering::Relaxed), 0);
        peer.send_to(b"two", mux.local_addr()).await.unwrap();
        assert_eq!(received(&mux).await.len(), 1);
    }

    #[tokio::test]
    async fn a_probe_cannot_send_to_a_tunnel_address() {
        let mux = v4();
        let probe = mux.probe(|_, _| false);
        let error = probe.send_to(tunnel_addr(&RELAY, ONE), b"x").await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    fn recv_meta(addr: SocketAddr, len: usize, stride: usize) -> RecvMeta {
        RecvMeta { addr, len, stride, ecn: None, dst_ip: None }
    }

    const NODE: &str = "192.0.2.7:6881";
    const STRANGER: &str = "192.0.2.8:9999";

    #[tokio::test]
    async fn coalesced_datagrams_lose_only_the_ones_a_probe_takes() {
        let mux = v4();
        let _probe = mux.probe(|from, datagram| from.port() == 6881 && datagram == b"bb");
        // Datagrams of two bytes, the last maybe shorter, glued together as GRO delivers them.
        let cases: [(&[u8], &[u8]); 7] = [
            (b"aabbcc", b"aacc"),
            (b"bbaacc", b"aacc"),
            (b"aaccbb", b"aacc"),
            (b"bbbbbb", b""),
            (b"aabbc", b"aac"),
            (b"aabb", b"aa"),
            (b"aabbaabb", b"aaaa"),
        ];
        for (glued, left) in cases {
            let mut data = glued.to_vec();
            let mut buf = IoSliceMut::new(&mut data);
            let kept = mux.take_probe_replies(&mut buf, &recv_meta(NODE.parse().unwrap(), glued.len(), 2));
            assert_eq!(&buf[..kept], left, "{}", String::from_utf8_lossy(glued));
        }
    }

    #[tokio::test]
    async fn the_datagrams_left_in_a_batch_are_packed_to_the_front() {
        let mux = v4();
        let _probe = mux.probe(|from, _| from.port() == 6881);
        let (node, stranger) = (NODE.parse().unwrap(), STRANGER.parse().unwrap());
        let mut storage = vec![vec![0u8; 64]; 4];
        for (buf, data) in storage.iter_mut().zip([&b"p1"[..], b"q-2", b"p3", b"q-4"]) {
            buf[..data.len()].copy_from_slice(data);
        }
        let mut bufs: Vec<IoSliceMut<'_>> = storage.iter_mut().map(|b| IoSliceMut::new(b)).collect();
        let mut batch =
            [recv_meta(node, 2, 2), recv_meta(stranger, 3, 3), recv_meta(node, 2, 2), recv_meta(stranger, 3, 3)];
        let kept = mux.filter(&mut bufs, &mut batch, 4);
        assert_eq!(kept, 2);
        assert_eq!((batch[0].addr, &bufs[0][..batch[0].len]), (stranger, &b"q-2"[..]));
        assert_eq!((batch[1].addr, &bufs[1][..batch[1].len]), (stranger, &b"q-4"[..]));
        assert_eq!(mux.stats().probe_replies, 2);
    }

    #[tokio::test]
    async fn a_datagram_from_the_real_network_claiming_a_tunnel_address_is_dropped() {
        let mux = v4();
        let forged = tunnel_addr(&RELAY, ONE);
        let mut storage = [vec![0u8; 64]];
        storage[0][..4].copy_from_slice(b"fake");
        let mut bufs: Vec<IoSliceMut<'_>> = storage.iter_mut().map(|b| IoSliceMut::new(b)).collect();
        let mut batch = [recv_meta(forged, 4, 4)];
        assert_eq!(mux.filter(&mut bufs, &mut batch, 1), 0);
        assert_eq!(mux.stats().spoofed, 1);
    }

    #[test]
    fn tunnel_addresses_derive_from_the_relay_and_the_flow() {
        let a = tunnel_addr(&RELAY, ONE);
        assert!(is_tunnel_addr(a));
        let IpAddr::V6(ip) = a.ip() else { panic!("an IPv6 address") };
        assert_eq!(ip.segments()[..2], [0xfd00, 0x7e1a]);
        assert_eq!(a.port(), 1);
        let two = NonZeroU16::new(2).unwrap();
        assert_ne!(a.ip(), tunnel_addr(&[8; 32], ONE).ip(), "another relay, another address");
        assert_eq!(a.ip(), tunnel_addr(&RELAY, two).ip(), "the flow is the port");
        assert_eq!(tunnel_addr(&RELAY, two).port(), 2);
        // Pinned: both ends of a future relay and the logs rely on the derivation not changing.
        assert_eq!(a.to_string(), "[fd00:7e1a:9ccc:117c:5c5b:c272:1c8f:22f]:1");
        for not_ours in
            ["[fd00:7e1b::1]:1", "[fd01:7e1a::1]:1", "192.168.1.9:1", "[::ffff:192.168.1.9]:1", "[fe80::1]:1"]
        {
            assert!(!is_tunnel_addr(not_ours.parse().unwrap()), "{not_ours}");
        }
    }

    #[tokio::test]
    async fn relayed_packets_reach_quinn_as_a_peer_at_the_tunnel_address() {
        let mux = v4();
        let tunnel = mux.open_tunnel(RELAY, ONE).unwrap();
        assert_eq!(mux.tunnel_relay(tunnel.addr()), Some(RELAY));
        assert_eq!(mux.tunnel_relay("127.0.0.1:1".parse().unwrap()), None);
        tunnel.inbound().deliver(Bytes::from_static(b"inner packet")).unwrap();
        assert_eq!(received(&mux).await, vec![(tunnel.addr(), b"inner packet".to_vec())]);
        assert_eq!(mux.stats().tunnel_in, 1);
    }

    #[tokio::test]
    async fn a_batch_of_relayed_packets_is_handed_over_together() {
        let mux = v4();
        let tunnel = mux.open_tunnel(RELAY, ONE).unwrap();
        for i in 0..3u8 {
            tunnel.inbound().deliver(Bytes::from(vec![i; 10 + i as usize])).unwrap();
        }
        let got = received(&mux).await;
        assert_eq!(
            got.iter().map(|(addr, data)| (*addr, data.len())).collect::<Vec<_>>(),
            vec![(tunnel.addr(), 10), (tunnel.addr(), 11), (tunnel.addr(), 12)]
        );
    }

    #[tokio::test]
    async fn quinns_sends_to_a_tunnel_come_out_of_it() {
        let mux = v4();
        let mut tunnel = mux.open_tunnel(RELAY, ONE).unwrap();
        send(&mux, tunnel.addr(), b"to the relay");
        assert_eq!(tunnel.next_outbound().await.unwrap(), Bytes::from_static(b"to the relay"));
        // One transmit that holds several datagrams (segmentation offload) is several packets.
        let segmented = Transmit {
            destination: tunnel.addr(),
            ecn: None,
            contents: b"aaabbbcc",
            segment_size: Some(3),
            src_ip: None,
        };
        mux.try_send(&segmented).unwrap();
        let packets: Vec<Bytes> = std::iter::from_fn(|| tunnel.try_next_outbound()).collect();
        assert_eq!(packets, vec![Bytes::from_static(b"aaa"), Bytes::from_static(b"bbb"), Bytes::from_static(b"cc")]);
        assert_eq!(mux.stats().tunnel_out, 4);
    }

    #[tokio::test]
    async fn a_pump_that_stalls_makes_quinns_sends_drop_without_blocking_or_failing() {
        let mux = v4();
        let mut tunnel = mux.open_tunnel(RELAY, ONE).unwrap();
        for i in 0..(TUNNEL_OUTBOUND_QUEUE + 10) as u32 {
            send(&mux, tunnel.addr(), &i.to_be_bytes());
        }
        let stats = mux.stats();
        assert_eq!((stats.tunnel_out, stats.tunnel_out_full), (TUNNEL_OUTBOUND_QUEUE as u64, 10));
        for i in 0..TUNNEL_OUTBOUND_QUEUE as u32 {
            assert_eq!(tunnel.next_outbound().await.unwrap().as_ref(), &i.to_be_bytes(), "kept in order");
        }
        assert!(tunnel.try_next_outbound().is_none());
        // The real network is not held up by it, and the tunnel takes packets again.
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        send_real(&mux, peer.local_addr().unwrap(), b"still works").await;
        assert_eq!(recv_from(&peer).await.0, b"still works");
        send(&mux, tunnel.addr(), b"again");
        assert_eq!(tunnel.try_next_outbound().unwrap().as_ref(), b"again");
    }

    #[tokio::test]
    async fn packets_delivered_faster_than_quinn_reads_are_dropped_per_tunnel_and_overall() {
        let mux = v4();
        let tunnels: Vec<Tunnel> =
            (1..=5).map(|n| mux.open_tunnel(RELAY, NonZeroU16::new(n).unwrap()).unwrap()).collect();
        let inbound: Vec<TunnelInbound> = tunnels.iter().map(Tunnel::inbound).collect();
        let packet = || Bytes::from_static(b"p");
        for _ in 0..TUNNEL_INBOUND_LIMIT {
            inbound[0].deliver(packet()).unwrap();
        }
        assert_eq!(inbound[0].deliver(packet()), Err(Undelivered::Full), "one tunnel's share is used up");
        // Four shares are the whole queue (512 = 4 x 128); the others are not crowded out by the first.
        for tunnel in &inbound[1..4] {
            for _ in 0..TUNNEL_INBOUND_LIMIT {
                tunnel.deliver(packet()).expect("another tunnel's share is its own");
            }
        }
        assert_eq!(inbound[4].deliver(packet()), Err(Undelivered::Full), "the whole queue is full");
        assert_eq!(inbound[4].shared.queued.load(Ordering::Relaxed), 0, "a refused packet is not left counted");
        // Once quinn reads, there is room again.
        assert!(!received(&mux).await.is_empty());
        inbound[4].deliver(packet()).unwrap();
        assert_eq!(mux.stats().tunnel_in_full, 2);
    }

    #[tokio::test]
    async fn a_closed_tunnel_drops_both_ways_and_can_be_opened_again() {
        let mux = v4();
        let tunnel = mux.open_tunnel(RELAY, ONE).unwrap();
        let (addr, inbound) = (tunnel.addr(), tunnel.inbound());
        assert_eq!(mux.open_tunnel(RELAY, ONE).unwrap_err(), TunnelError::AlreadyOpen(addr));
        drop(tunnel);
        assert_eq!(inbound.deliver(Bytes::from_static(b"late")), Err(Undelivered::Closed));
        // Sending to it is no error: failing a send would end quinn's connection over it, and the
        // connection may well outlive a relay that reconnects.
        send(&mux, addr, b"into the void");
        let stats = mux.stats();
        assert_eq!((stats.tunnel_in_closed, stats.tunnel_out_closed), (1, 1));
        assert_eq!(mux.tunnel_relay(addr), None);

        let mut again = mux.open_tunnel(RELAY, ONE).unwrap();
        assert_eq!(again.addr(), addr);
        assert_eq!(
            inbound.deliver(Bytes::from_static(b"stale")),
            Err(Undelivered::Closed),
            "the old handle stays closed"
        );
        send(&mux, addr, b"hello again");
        assert_eq!(again.next_outbound().await.unwrap().as_ref(), b"hello again");
    }

    #[tokio::test]
    async fn tunnels_end_when_the_multiplexer_goes() {
        let mux = v4();
        let mut tunnel = mux.open_tunnel(RELAY, ONE).unwrap();
        let inbound = tunnel.inbound();
        drop(mux);
        assert!(tunnel.next_outbound().await.is_none());
        assert_eq!(inbound.deliver(Bytes::from_static(b"x")), Err(Undelivered::Closed));
    }

    #[tokio::test]
    async fn only_so_many_tunnels_open_at_once() {
        let mux = v4();
        let open: Vec<Tunnel> =
            (1..=MAX_TUNNELS as u16).map(|n| mux.open_tunnel(RELAY, NonZeroU16::new(n).unwrap()).unwrap()).collect();
        assert_eq!(
            mux.open_tunnel(RELAY, NonZeroU16::new(MAX_TUNNELS as u16 + 1).unwrap()).unwrap_err(),
            TunnelError::TooMany
        );
        drop(open);
        mux.open_tunnel(RELAY, ONE).unwrap();
    }

    #[tokio::test]
    async fn neither_source_starves_the_other() {
        let mux = v4();
        let tunnel = mux.open_tunnel(RELAY, ONE).unwrap();
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        for i in 0..8u8 {
            tunnel.inbound().deliver(Bytes::from(vec![b't', i])).unwrap();
            peer.send_to(&[b'r', i], mux.local_addr()).unwrap();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        // One datagram at a time, as quinn reads them on Windows.
        let mut order = String::new();
        for _ in 0..16 {
            let mut storage = [vec![0u8; 64]];
            let mut bufs: Vec<IoSliceMut<'_>> = storage.iter_mut().map(|b| IoSliceMut::new(b)).collect();
            let mut batch = [RecvMeta::default()];
            let n = tokio::time::timeout(WAIT, poll_fn(|cx| mux.poll_recv(cx, &mut bufs, &mut batch)))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(n, 1);
            order.push(bufs[0][0] as char);
        }
        assert_eq!(order.matches('t').count(), 8, "{order}");
        assert!(order[..4].contains('t') && order[..4].contains('r'), "alternates while both have something: {order}");
    }

    // The multiplexer under a real quinn endpoint: a whole Velora-style handshake and a stream.

    use velora_protocol::{identity::Identity, tls};

    fn endpoint_on(mux: &Arc<Multiplexer>, host: &Identity) -> quinn::Endpoint {
        let config = tls::server_config(host).unwrap();
        quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(config),
            mux.clone(),
            Arc::new(quinn::TokioRuntime),
        )
        .unwrap()
    }

    /// What the echo server saw.
    #[derive(Default)]
    struct Seen {
        remotes: Vec<SocketAddr>,
        retries: usize,
    }

    /// Accepts connections on `endpoint` and echoes the first stream of each; with `retry`, makes
    /// every new address prove itself first, as the host does while standalone reach is on.
    fn echo_server(endpoint: quinn::Endpoint, retry: bool) -> (Arc<Mutex<Seen>>, tokio::task::JoinHandle<()>) {
        let seen = Arc::new(Mutex::new(Seen::default()));
        let log = seen.clone();
        let task = tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let incoming = match incoming.remote_address_validated() || !retry {
                    true => incoming,
                    false => match incoming.retry() {
                        Ok(()) => {
                            log.lock().unwrap().retries += 1;
                            continue;
                        }
                        Err(refused) => refused.into_incoming(),
                    },
                };
                log.lock().unwrap().remotes.push(incoming.remote_address());
                tokio::spawn(async move {
                    let conn = incoming.await.unwrap();
                    let (mut send, mut recv) = conn.accept_bi().await.unwrap();
                    let data = recv.read_to_end(1 << 20).await.unwrap();
                    send.write_all(&data).await.unwrap();
                    send.finish().unwrap();
                    let _ = send.stopped().await;
                });
            }
        });
        (seen, task)
    }

    /// Dials `to` from a plain IPv4 endpoint, sends `payload` and returns what comes back, with
    /// the client's own address.
    async fn echo(host: &Identity, to: SocketAddr, payload: &[u8]) -> (Vec<u8>, SocketAddr) {
        let client = Identity::generate().unwrap();
        let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let config = tls::client_config(&client, host.fingerprint()).unwrap();
        let conn = endpoint.connect_with(config, to, tls::SERVER_NAME).unwrap().await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(payload).await.unwrap();
        send.finish().unwrap();
        let echoed = tokio::time::timeout(Duration::from_secs(20), recv.read_to_end(1 << 20)).await.unwrap().unwrap();
        let local = endpoint.local_addr().unwrap();
        conn.close(0u32.into(), b"done");
        (echoed, local)
    }

    #[tokio::test]
    async fn a_quic_connection_runs_on_the_real_socket() {
        let (mux, host) = (v4(), Identity::generate().unwrap());
        let (seen, _server) = echo_server(endpoint_on(&mux, &host), false);
        let (echoed, client) = echo(&host, mux.local_addr(), b"hello over the multiplexer").await;
        assert_eq!(echoed, b"hello over the multiplexer");
        assert_eq!(seen.lock().unwrap().remotes, vec![client]);
    }

    #[tokio::test]
    async fn retry_works_through_the_multiplexer() {
        let (mux, host) = (v4(), Identity::generate().unwrap());
        let (seen, _server) = echo_server(endpoint_on(&mux, &host), true);
        let (echoed, client) = echo(&host, mux.local_addr(), b"after a retry").await;
        assert_eq!(echoed, b"after a retry");
        let seen = seen.lock().unwrap();
        assert_eq!((seen.retries, seen.remotes.clone()), (1, vec![client]), "one Retry, then the validated attempt");
    }

    #[tokio::test]
    async fn a_dual_stack_endpoint_serves_ipv4_clients_at_their_mapped_address() {
        let Some(mux) = dual_stack() else { return eprintln!("no IPv6 on this machine: skipped") };
        let host = Identity::generate().unwrap();
        let (seen, _server) = echo_server(endpoint_on(&mux, &host), true);
        let to = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), mux.local_addr().port());
        let (echoed, client) = echo(&host, to, b"over IPv4 to a dual-stack host").await;
        assert_eq!(echoed, b"over IPv4 to a dual-stack host");
        assert_eq!(seen.lock().unwrap().remotes, vec![mapped(client.port())]);
        assert_eq!(seen.lock().unwrap().retries, 1);
    }

    /// The part of a relay that matters here: a UDP socket the client dials, whose datagrams go into
    /// the tunnel and whose answers come out of it, like E4's pump between the relay connection
    /// and the tunnel.
    fn pump(relay: UdpSocket, mut tunnel: Tunnel) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let inbound = tunnel.inbound();
            let mut client = None;
            let mut buf = vec![0u8; 2048];
            loop {
                tokio::select! {
                    received = relay.recv_from(&mut buf) => {
                        let Ok((n, from)) = received else { break };
                        client = Some(from);
                        let _ = inbound.deliver(Bytes::copy_from_slice(&buf[..n]));
                    }
                    packet = tunnel.next_outbound() => {
                        let Some(packet) = packet else { break };
                        if let Some(client) = client {
                            let _ = relay.send_to(&packet, client).await;
                        }
                    }
                }
            }
        })
    }

    #[tokio::test]
    async fn a_client_behind_a_relay_tunnel_is_an_ordinary_incoming_connection() {
        let (mux, host) = (v4(), Identity::generate().unwrap());
        let (seen, _server) = echo_server(endpoint_on(&mux, &host), false);
        let tunnel = mux.open_tunnel(RELAY, ONE).unwrap();
        let tunnel_addr = tunnel.addr();
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let _pump = pump(relay, tunnel);

        // 300 KB each way: hundreds of packets through the queues in both directions.
        let payload: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        let (echoed, _) = echo(&host, relay_addr, &payload).await;
        assert!(echoed == payload, "the stream came back intact through the tunnel");
        assert_eq!(seen.lock().unwrap().remotes, vec![tunnel_addr], "quinn sees the tunnel's address as the peer");
        let stats = mux.stats();
        assert!(stats.tunnel_in > 100 && stats.tunnel_out > 100, "{stats:?}");
        assert_eq!((stats.tunnel_in_full, stats.tunnel_out_full), (0, 0), "{stats:?}");
        assert_eq!(mux.tunnel_relay(tunnel_addr), Some(RELAY));
    }

    #[tokio::test]
    async fn retry_through_a_tunnel_works_too() {
        let (mux, host) = (v4(), Identity::generate().unwrap());
        let (seen, _server) = echo_server(endpoint_on(&mux, &host), true);
        let tunnel = mux.open_tunnel(RELAY, ONE).unwrap();
        let tunnel_addr = tunnel.addr();
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let _pump = pump(relay, tunnel);
        let (echoed, _) = echo(&host, relay_addr, b"retried through a relay").await;
        assert_eq!(echoed, b"retried through a relay");
        let seen = seen.lock().unwrap();
        assert_eq!((seen.retries, seen.remotes.clone()), (1, vec![tunnel_addr]));
    }
}
