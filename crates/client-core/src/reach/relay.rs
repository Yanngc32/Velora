//! F3: reaching a host through a relay, and waking it through one (`docs/nat-traversal.md`, phase 4).
//!
//! A relay is another paired PC that both ends can reach (or `velora-host run --relay-only` on a VPS); see
//! `velora_relay::forward` for what it does. This device dials it (the *outer* connection, pinned to the relay's
//! certificate), says hello as a *link* (`files_only` and `reach` set, which is how the host knows that it must not start a
//! session for the connection), asks `RelayTo` the host and waits for the `RelayStatus`. From then on the datagrams of the
//! outer connection carry, framed by `velora_relay::frame`, the QUIC packets of the *inner* connection between this device
//! and the host: an ordinary Velora connection with the host's certificate pinned, made by an endpoint whose UDP socket is a
//! [`RelaySocket`]. The relay sees ciphertext only.
//!
//! [`dial_relay`] and [`wake_through_relay`] are the hooks the rest of the crate calls. [`Link`] (the outer connection past
//! its hello) is `pub(crate)` so that the punch dialer (F4), which signals through a relay too, does not write it again.

use std::{
    fmt,
    io::{self, IoSliceMut},
    net::{Ipv6Addr, SocketAddr, SocketAddrV6},
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, MutexGuard, PoisonError,
    },
    task::{Context, Poll},
    time::Duration,
};

use anyhow::{anyhow, bail, Context as _, Result};
use bytes::Bytes;
use quinn::{
    udp::{RecvMeta, Transmit},
    AsyncUdpSocket, UdpPoller,
};
use tokio::{
    sync::mpsc,
    task::{JoinHandle, JoinSet},
    time::Instant,
};
use velora_protocol::{
    identity::{Identity, KnownHost},
    tls::{self, Fingerprint},
    wire::{self, AddressKind, ClientMsg, HelloExt, HostMsg, PROTOCOL_VERSION},
};
use velora_relay::{
    forward::{CLOSE_HOST_GONE, CLOSE_REMOVED, CLOSE_REPLACED, CLOSE_SHUTDOWN, CLOSE_TAKEN_OVER},
    frame::{Reassembler, Splitter},
};

use super::{RelayRef, WakeOutcome};
use crate::ConnectParams;

/// How long each step of dealing with a relay may take. Nothing else times a dial out: the race starts it and waits.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Waits {
    /// The outer QUIC and TLS handshake with the relay.
    pub connect: Duration,
    /// The relay's welcome after the hello.
    pub welcome: Duration,
    /// Its `Reach` after the welcome: a relay that sends none predates links and cannot relay.
    pub reach: Duration,
    /// Its `RelayStatus` after a request.
    pub answer: Duration,
    /// The inner handshake with the host, through the relay.
    pub inner: Duration,
}

impl Waits {
    pub(crate) const DEFAULT: Waits = Waits {
        connect: Duration::from_secs(8),
        welcome: Duration::from_secs(5),
        reach: Duration::from_secs(3),
        answer: Duration::from_secs(5),
        inner: Duration::from_secs(10),
    };
}

/// How long the closing packets of the inner connection get to leave before the outer connection is closed.
const CLOSING_WAIT: Duration = Duration::from_secs(1);
/// Asking several relays to wake a host: each one starts this long after the one before.
const WAKE_STAGGER: Duration = Duration::from_millis(250);
/// Most relay addresses one wake asks.
const MAX_WAKE_ATTEMPTS: usize = 8;
/// What a wake calls itself in the relay's log: it has no name of this device to give.
const WAKE_NAME: &str = "velora";
/// Inner packets that wait for the inner endpoint to take them; past it they are dropped, as a full socket buffer would.
const INBOUND_QUEUE: usize = 512;
/// How often the table of half-received packets is swept while nothing arrives.
const SWEEP: Duration = Duration::from_secs(1);

/// Made-up addresses for the two ends of the tunnel. The inner endpoint believes it talks to one peer, at the second;
/// nothing is ever sent there. (The host's multiplexer derives addresses in the same range, `fd00:7e1a::/32`.)
const TUNNEL_LOCAL: SocketAddr =
    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::new(0xfd00, 0x7e1a, 0, 0, 0, 0, 0, 2), 41000, 0, 0));
const TUNNEL_PEER: SocketAddr =
    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::new(0xfd00, 0x7e1a, 0, 0, 0, 0, 0, 1), 7420, 0, 0));

/// Connects to the host through the relay at `relay_addr`, a paired device that both ends can reach.
///
/// **Receives** `params`, the connection being made (`params.identity` is this device's identity, for the connection to
/// the relay and for the inner one; `params.host_fingerprint` pins the host); `relay_addr` and `relay_fingerprint`, the
/// relay's address and the fingerprint its certificate must have; `target`, the fingerprint of the host to be relayed to
/// (the same as `params.host_fingerprint`, which is what the inner handshake is pinned to).
///
/// **Returns** the *inner* QUIC endpoint and connection, to the host, just as a direct dial would: the caller sends the
/// ordinary Velora hello on it. The endpoint owns whatever carries the tunnel (the outer connection to the relay, tasks),
/// so keeping it alive keeps the path up and dropping it ends everything; the caller keeps it for the session's lifetime.
///
/// **Timing.** The race starts it [`RELAY_DELAY`](super::RELAY_DELAY) after the first direct address and drops it when
/// another candidate wins, so the future must be cancel-safe and `Send` (it is spawned). It must give up by itself, with an
/// error the race logs at debug level (the race has no timeout for it): a relay that does not answer, a `RelayStatus` that is
/// not ok.
///
/// **One dial per relay and host.** A candidate is one address of a relay. A relay serves one client per host, and a second
/// `RelayTo` from this device takes the first over (`CLOSE_TAKEN_OVER`), so the race keeps the addresses of one relay
/// [`RELAY_ADDRESS_STAGGER`](super::RELAY_ADDRESS_STAGGER) apart. A dial that is still going when the next address starts may
/// be taken over: it should fail at once, not try again.
pub async fn dial_relay(
    params: &ConnectParams,
    relay_addr: SocketAddr,
    relay_fingerprint: Fingerprint,
    target: Fingerprint,
) -> Result<(quinn::Endpoint, quinn::Connection)> {
    let relay = RelayRef { addr: relay_addr, fingerprint: relay_fingerprint };
    dial(params, relay, target, &Waits::DEFAULT).await
}

async fn dial(
    params: &ConnectParams,
    relay: RelayRef,
    target: Fingerprint,
    waits: &Waits,
) -> Result<(quinn::Endpoint, quinn::Connection)> {
    let mut link = Link::open(&params.identity, &params.device_name, relay, waits).await?;
    link.ask(ClientMsg::RelayTo { fingerprint: target.to_base64() }, waits).await?;
    tracing::debug!("the relay at {} will relay to the host", relay.addr);

    // From here the relay copies datagrams between this connection and the host's. Nothing is read from the connection before
    // this point, so nothing the host sent earlier can reach the inner endpoint.
    let socket = RelaySocket::new(link.conn.clone(), TUNNEL_LOCAL, TUNNEL_PEER);
    let stats = socket.stats();
    let endpoint = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .context("could not start the endpoint of the tunnel")?;
    let config = tls::client_config(&params.identity, target)?;
    let connecting = endpoint.connect_with(config, TUNNEL_PEER, tls::SERVER_NAME)?;
    let inner = tokio::select! {
        connected = tokio::time::timeout(waits.inner, connecting) => match connected {
            Ok(Ok(inner)) => Ok(inner),
            Ok(Err(e)) => Err(anyhow::Error::new(e).context("the handshake with the host through the relay failed")),
            Err(_) => Err(anyhow!("the host did not answer through the relay")),
        },
        closed = link.conn.closed() => Err(anyhow!("the relay ended the link: {}", ended(&closed))),
    };
    let inner = match inner {
        Ok(inner) => inner,
        Err(e) => {
            // The socket of the inner endpoint holds the outer connection too, and lives until the endpoint has drained: close
            // it now, so that the relay is not left holding the host for a client that gave up.
            link.conn.close(0u32.into(), b"client gave up");
            return Err(e);
        }
    };
    tokio::spawn(watch(link, inner.clone(), endpoint.clone(), stats));
    Ok((endpoint, inner))
}

/// Ties the two connections together for as long as the session lasts: when the relay ends the link, the inner connection
/// ends at once instead of after its idle timeout; when the inner connection ends, the outer one is closed, which frees the
/// host for the next client. It holds the outer connection, so that nothing else has to.
async fn watch(link: Link, inner: quinn::Connection, endpoint: quinn::Endpoint, stats: Arc<Stats>) {
    tokio::select! {
        why = link.conn.closed() => {
            tracing::info!("the relay ended the link: {}", ended(&why));
            inner.close(0u32.into(), b"the relay ended the link");
        }
        _ = inner.closed() => {
            // The closing packets of the inner connection are still on their way out through the outer one.
            let _ = tokio::time::timeout(CLOSING_WAIT, endpoint.wait_idle()).await;
            link.conn.close(0u32.into(), b"client closed");
        }
    }
    tracing::debug!("the relay link is over: {stats}");
}

/// Asks the relays the host is registered with to send the Wake-on-LAN packet for `host`, which this device cannot reach on
/// its own network. [`wake`](super::wake) calls it only after trying this device's own networks, and only for a host with a
/// MAC address (`host.mac` is `Some`).
///
/// **Receives** `identity`, this device's identity, and `host`, the stored entry: `host.relays` lists the relays the host
/// is registered with (fingerprint and addresses), `host.fingerprint` is the host's fingerprint for `ClientMsg::Wake`.
///
/// **Returns** `Ok(WakeOutcome::Sent)` when a relay answered `RelayStatus { ok: true }`, `Ok(WakeOutcome::NoRelay)` when
/// there is no relay to ask or none could send the packet (not on the host's network, unreachable), and `Err` for a
/// failure worth showing the user. The future must be `Send`: callers run `hosts::wake` on a multi-threaded runtime.
///
/// The addresses of the relays are asked at the same time, 250 ms apart, and the first `ok` wins. A relay remembers the
/// hosts that registered with it, so a host that is asleep (and so connected to nobody) can still be woken.
pub async fn wake_through_relay(identity: &Identity, host: &KnownHost) -> Result<WakeOutcome> {
    wake(identity, host, &Waits::DEFAULT).await
}

async fn wake(identity: &Identity, host: &KnownHost, waits: &Waits) -> Result<WakeOutcome> {
    let mut relays = relays_of(host);
    relays.truncate(MAX_WAKE_ATTEMPTS);
    if relays.is_empty() {
        return Ok(WakeOutcome::NoRelay);
    }
    let target =
        Fingerprint::from_base64(&host.fingerprint).context("the stored fingerprint of the host is not valid")?;
    let mut asking = JoinSet::new();
    for (i, relay) in relays.into_iter().enumerate() {
        let (identity, waits) = (identity.clone(), *waits);
        asking.spawn(async move {
            tokio::time::sleep(WAKE_STAGGER * i as u32).await;
            let mut link = Link::open(&identity, WAKE_NAME, relay, &waits).await?;
            link.ask(ClientMsg::Wake { fingerprint: target.to_base64() }, &waits).await
        });
    }
    while let Some(done) = asking.join_next().await {
        match done {
            Ok(Ok(())) => {
                asking.abort_all();
                return Ok(WakeOutcome::Sent);
            }
            Ok(Err(e)) => tracing::debug!("wake through a relay: {e:#}"),
            Err(e) => tracing::debug!("wake through a relay ended abnormally: {e}"),
        }
    }
    Ok(WakeOutcome::NoRelay)
}

/// The relays a host is registered with, as its last `Reach` listed them: its relay list and the relay entries of its address
/// list, which name the same relays. The host is never its own relay.
fn relays_of(host: &KnownHost) -> Vec<RelayRef> {
    let mut found: Vec<RelayRef> = Vec::new();
    let mut add = |fingerprint: &str, address: &str| {
        let (Ok(fingerprint), Ok(addr)) = (Fingerprint::from_base64(fingerprint), address.parse::<SocketAddr>()) else {
            return;
        };
        let relay = RelayRef { addr, fingerprint };
        if fingerprint.to_base64() != host.fingerprint && !found.contains(&relay) {
            found.push(relay);
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

/// Why a connection to a relay ended, in words for a log.
fn ended(error: &quinn::ConnectionError) -> String {
    let quinn::ConnectionError::ApplicationClosed(close) = error else { return error.to_string() };
    match u32::try_from(close.error_code.into_inner()) {
        Ok(CLOSE_REPLACED) => "another connection of this device took its place".into(),
        Ok(CLOSE_HOST_GONE) => "the host left the relay".into(),
        Ok(CLOSE_TAKEN_OVER) => "another device took the host over".into(),
        Ok(CLOSE_REMOVED) => "this device was removed from the relay".into(),
        Ok(CLOSE_SHUTDOWN) => "the relay was switched off".into(),
        _ => error.to_string(),
    }
}

// ---- the outer connection ----

/// The relay said no to a request (`RelayStatus { ok: false }`). Find it in an error with `downcast_ref`.
#[derive(Debug)]
pub(crate) struct Refusal(pub String);

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the relay refused: {}", self.0)
    }
}

impl std::error::Error for Refusal {}

/// A connection to a relay, past its welcome: pinned to its certificate, hello said as a link, and the relay has said it
/// relays for others. Requests go through [`Link::ask`]. Dropping it closes the connection.
#[derive(Debug)]
pub(crate) struct Link {
    /// The connection itself, for whoever tunnels datagrams through it.
    pub conn: quinn::Connection,
    /// Keeps the UDP socket of the connection.
    _endpoint: quinn::Endpoint,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl Link {
    /// Dials `relay` and says hello as a link. Fails when the relay does not answer, is not the one pinned, asks for a
    /// password, does not send `Reach` (it predates links) or says it does not relay for other devices.
    pub(crate) async fn open(identity: &Identity, device_name: &str, relay: RelayRef, waits: &Waits) -> Result<Link> {
        let config = tls::client_config(identity, relay.fingerprint)?;
        let bind: SocketAddr = if relay.addr.is_ipv6() { "[::]:0".parse()? } else { "0.0.0.0:0".parse()? };
        let endpoint = quinn::Endpoint::client(bind)?;
        let connecting = endpoint.connect_with(config, relay.addr, tls::SERVER_NAME)?;
        let conn = tokio::time::timeout(waits.connect, connecting)
            .await
            .map_err(|_| anyhow!("the relay at {} did not answer", relay.addr))?
            .context("could not connect to the relay (wrong address, or its fingerprint changed?)")?;
        if conn.max_datagram_size().is_none() {
            bail!("the connection to the relay carries no datagrams, which relaying needs");
        }

        // `files_only` with `reach` is a link: the relay starts no session for it, whoever it is and whatever it is doing.
        let ext = HelloExt { files_only: true, reach: true, ..Default::default() };
        let hello = ClientMsg::Hello {
            version: PROTOCOL_VERSION,
            name: device_name.to_string(),
            pairing_secret: None,
            // The password of the relay PC, if it has one, is not one this device knows.
            password: None,
            ext: Some(ext),
        };
        let (mut send, mut recv) = conn.open_bi().await?;
        send.write_all(&hello.encode()).await?;

        let deadline = Instant::now() + waits.welcome;
        loop {
            match next_msg(&mut recv, deadline, "its welcome").await? {
                HostMsg::Welcome { version, .. } if version == PROTOCOL_VERSION => break,
                HostMsg::Welcome { version, .. } => {
                    bail!("the relay uses protocol version {version}, expected {PROTOCOL_VERSION}")
                }
                HostMsg::Paired => {}
                HostMsg::Rejected { reason } => bail!("the relay rejected this device: {reason}"),
                HostMsg::PasswordRequired { .. } => {
                    bail!("the relay asks for a password, and relaying cannot give one")
                }
                _ => bail!("the relay said something before its welcome"),
            }
        }
        // Right after the welcome, to a client that asked for it. A relay from before links is a file server to this hello and
        // sends none, and a relay that has relaying switched off says so here.
        let deadline = Instant::now() + waits.reach;
        let relays_for_others = loop {
            match next_msg(&mut recv, deadline, "its Reach").await {
                Ok(HostMsg::Reach { relays_for_others, .. }) => break relays_for_others,
                Ok(_) => tracing::debug!("skipping a message from the relay while its Reach is awaited"),
                Err(e) => return Err(e.context("the relay may be too old to relay")),
            }
        };
        if !relays_for_others {
            bail!("the relay does not relay for other devices");
        }
        Ok(Link { conn, _endpoint: endpoint, send, recv })
    }

    /// Sends a request and waits for the relay's `RelayStatus`. A `RelayStatus` that is not ok is a [`Refusal`].
    pub(crate) async fn ask(&mut self, request: ClientMsg, waits: &Waits) -> Result<()> {
        self.send.write_all(&request.encode()).await.context("could not send the request to the relay")?;
        let deadline = Instant::now() + waits.answer;
        loop {
            match next_msg(&mut self.recv, deadline, "its answer").await? {
                HostMsg::RelayStatus { ok: true, .. } => return Ok(()),
                HostMsg::RelayStatus { ok: false, reason } => return Err(Refusal(reason).into()),
                _ => tracing::debug!("ignoring a message from the relay while its answer is awaited"),
            }
        }
    }
}

/// The next message the relay sends on the control stream, skipping those this version does not understand.
async fn next_msg(recv: &mut quinn::RecvStream, deadline: Instant, what: &str) -> Result<HostMsg> {
    loop {
        let body = tokio::time::timeout_at(deadline, wire::read_msg(recv))
            .await
            .map_err(|_| anyhow!("the relay did not send {what} in time"))?
            .with_context(|| format!("reading {what} from the relay"))?
            .ok_or_else(|| anyhow!("the relay closed the control stream before sending {what}"))?;
        match HostMsg::decode(&body) {
            Ok(msg) => return Ok(msg),
            // From a newer relay: not for this version, and no reason to give up.
            Err(e) => tracing::debug!("skipping a message from the relay that does not decode: {e}"),
        }
    }
}

// ---- the tunnel ----

/// What a [`RelaySocket`] did.
#[derive(Debug, Default)]
struct Stats {
    packets_out: AtomicU64,
    datagrams_out: AtomicU64,
    packets_in: AtomicU64,
    datagrams_in: AtomicU64,
    dropped_out: AtomicU64,
    dropped_in: AtomicU64,
}

impl Stats {
    fn get(counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }

    /// Counts a packet that could not go on. The first and then every 1024th are logged: a link that is gone drops every packet.
    fn dropped(counter: &AtomicU64, direction: &str, why: &dyn fmt::Display) {
        let n = counter.fetch_add(1, Ordering::Relaxed);
        if n.is_multiple_of(1024) {
            tracing::debug!("a packet {direction} the relay was dropped ({} so far): {why}", n + 1);
        }
    }
}

impl fmt::Display for Stats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} packets out in {} datagrams ({} dropped), {} packets in from {} datagrams ({} dropped)",
            Self::get(&self.packets_out),
            Self::get(&self.datagrams_out),
            Self::get(&self.dropped_out),
            Self::get(&self.packets_in),
            Self::get(&self.datagrams_in),
            Self::get(&self.dropped_in),
        )
    }
}

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The UDP socket of an inner endpoint whose packets travel as datagrams of the outer connection to a relay. The endpoint
/// believes it talks to one peer at a made-up address: what it sends is framed by a [`Splitter`] for the datagram size the
/// outer connection allows at that moment (read at every send, since it grows as the path's MTU is found) and goes out as
/// outer datagrams. A task reads the outer connection's datagrams, puts them through a [`Reassembler`] and queues the inner
/// packets for `poll_recv`, tagged as coming from the peer.
///
/// It never fails a send and never blocks one: the endpoint ends a connection whose send errors (and logs an error), and a
/// full queue or a closed outer connection are losses like any other, which the inner QUIC lives with. A closed outer
/// connection is [`watch`]'s to act on.
#[derive(Debug)]
struct RelaySocket {
    local: SocketAddr,
    peer: SocketAddr,
    conn: quinn::Connection,
    splitter: Mutex<Splitter>,
    inbound: Mutex<mpsc::Receiver<Bytes>>,
    stats: Arc<Stats>,
    reader: JoinHandle<()>,
}

impl RelaySocket {
    fn new(conn: quinn::Connection, local: SocketAddr, peer: SocketAddr) -> Arc<Self> {
        let (to_endpoint, inbound) = mpsc::channel(INBOUND_QUEUE);
        let stats = Arc::new(Stats::default());
        let reader = tokio::spawn(read_outer(conn.clone(), to_endpoint, stats.clone()));
        Arc::new(Self {
            local,
            peer,
            conn,
            splitter: Mutex::new(Splitter::new()),
            inbound: Mutex::new(inbound),
            stats,
            reader,
        })
    }

    fn stats(&self) -> Arc<Stats> {
        self.stats.clone()
    }
}

impl Drop for RelaySocket {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

/// Feeds a [`RelaySocket`]: the outer connection's datagrams, put back together. Ends with the connection.
async fn read_outer(conn: quinn::Connection, packets: mpsc::Sender<Bytes>, stats: Arc<Stats>) {
    let mut reassembler = Reassembler::new();
    let mut sweep = tokio::time::interval(SWEEP);
    loop {
        tokio::select! {
            datagram = conn.read_datagram() => {
                let Ok(datagram) = datagram else { return };
                stats.datagrams_in.fetch_add(1, Ordering::Relaxed);
                if let Some(packet) = reassembler.push(datagram, std::time::Instant::now()) {
                    match packets.try_send(packet) {
                        Ok(()) => {
                            stats.packets_in.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_) => Stats::dropped(&stats.dropped_in, "from", &"the inner endpoint is not keeping up"),
                    }
                }
            }
            _ = sweep.tick() => reassembler.expire(std::time::Instant::now()),
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

impl AsyncUdpSocket for RelaySocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(AlwaysWritable)
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let Some(max) = self.conn.max_datagram_size() else {
            Stats::dropped(&self.stats.dropped_out, "toward", &"the outer connection carries no datagrams");
            return Ok(());
        };
        let datagrams = match locked(&self.splitter).split(transmit.contents, max) {
            Ok(datagrams) => datagrams,
            Err(e) => {
                Stats::dropped(&self.stats.dropped_out, "toward", &e);
                return Ok(());
            }
        };
        self.stats.packets_out.fetch_add(1, Ordering::Relaxed);
        for datagram in datagrams {
            match self.conn.send_datagram(datagram) {
                Ok(()) => {
                    self.stats.datagrams_out.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => {
                    Stats::dropped(&self.stats.dropped_out, "toward", &e);
                    break;
                }
            }
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
                // The outer connection ended: nothing more comes. An error here would stop the endpoint with a log line; the
                // inner connections are ended by `watch`.
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

    // Nothing here is fragmented, so the inner endpoint may probe for packets larger than 1200 bytes.
    fn may_fragment(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, path::PathBuf, task::Waker};

    use velora_nat::wake::Mac;
    use velora_protocol::wire::{Codec, FEATURE_CLIPBOARD, FEATURE_FILES};
    use velora_relay::forward::{Config, Refused, Relay, WakeError, Waker as MagicPacket};

    use super::*;
    use crate::{
        reach::{ReachParams, Route},
        testing::{eventually, sink, within},
    };

    const MAC: Mac = [0x02, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e];

    /// For the steps that are meant to time out.
    const QUICK: Waits = Waits {
        connect: Duration::from_millis(700),
        welcome: Duration::from_secs(2),
        reach: Duration::from_millis(400),
        answer: Duration::from_secs(2),
        inner: Duration::from_millis(700),
    };

    /// `len` bytes that differ per `seed` and per position, so that packets glued together wrongly never compare equal.
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

    // ---- a relay, a host and a client in one process ----

    /// What the relay under test does besides forwarding.
    #[derive(Clone, Copy)]
    struct Behaviour {
        /// What its `Reach` says about relaying for others; `None` sends no `Reach`, like a host from before links.
        reach: Option<bool>,
        /// Asks for a password instead of welcoming.
        password: bool,
        /// The protocol version its welcome says.
        version: u16,
    }

    impl Default for Behaviour {
        fn default() -> Self {
            Self { reach: Some(true), password: false, version: PROTOCOL_VERSION }
        }
    }

    /// A magic packet that goes nowhere and says what it was asked to do.
    #[derive(Default)]
    struct FakeWaker {
        calls: Mutex<Vec<(Mac, Ipv4Addr)>>,
        failure: Mutex<Option<WakeError>>,
    }

    impl MagicPacket for FakeWaker {
        fn wake(&self, mac: &Mac, host: Ipv4Addr) -> Result<usize, WakeError> {
            locked(&self.calls).push((*mac, host));
            match locked(&self.failure).clone() {
                Some(failure) => Err(failure),
                None => Ok(1),
            }
        }
    }

    /// A relay on loopback, run the way the host's relay code will run it: Velora's hello and welcome for a link, then the
    /// control messages handed to D2's [`Relay`] and its answers written back.
    struct Rig {
        relay: Relay,
        waker: Arc<FakeWaker>,
        addr: SocketAddr,
        identity: Identity,
        /// The control messages links sent after their hello.
        asked: Arc<Mutex<Vec<ClientMsg>>>,
        /// The extensions of the hellos links sent.
        hellos: Arc<Mutex<Vec<Option<HelloExt>>>>,
        _endpoint: quinn::Endpoint,
    }

    impl Rig {
        async fn start(behaviour: Behaviour) -> Rig {
            let identity = Identity::generate().unwrap();
            let server = tls::server_config(&identity).unwrap();
            let endpoint = quinn::Endpoint::server(server, "127.0.0.1:0".parse().unwrap()).unwrap();
            let waker = Arc::new(FakeWaker::default());
            let relay = Relay::with_waker(Config::default(), waker.clone());
            let (asked, hellos) = (Arc::new(Mutex::new(Vec::new())), Arc::new(Mutex::new(Vec::new())));
            let accepting = (relay.clone(), endpoint.clone(), asked.clone(), hellos.clone());
            tokio::spawn(async move {
                let (relay, endpoint, asked, hellos) = accepting;
                while let Some(incoming) = endpoint.accept().await {
                    let (relay, asked, hellos) = (relay.clone(), asked.clone(), hellos.clone());
                    tokio::spawn(async move {
                        if let Err(e) = serve_link(relay, incoming, behaviour, asked, hellos).await {
                            tracing::debug!("test relay: {e:#}");
                        }
                    });
                }
            });
            Rig { relay, waker, addr: endpoint.local_addr().unwrap(), identity, asked, hellos, _endpoint: endpoint }
        }

        fn relay_ref(&self) -> RelayRef {
            RelayRef { addr: self.addr, fingerprint: self.identity.fingerprint() }
        }
    }

    /// What the host does with a connection of a paired device that says hello as a link (`serve_link` in its `server.rs`).
    async fn serve_link(
        relay: Relay,
        incoming: quinn::Incoming,
        behaviour: Behaviour,
        asked: Arc<Mutex<Vec<ClientMsg>>>,
        hellos: Arc<Mutex<Vec<Option<HelloExt>>>>,
    ) -> Result<()> {
        let conn = incoming.await?;
        let (mut send, mut recv) = conn.accept_bi().await?;
        let body = wire::read_msg(&mut recv).await?.ok_or_else(|| anyhow!("no hello"))?;
        let ClientMsg::Hello { ext, .. } = ClientMsg::decode(&body)? else { bail!("not a hello") };
        locked(&hellos).push(ext);
        if behaviour.password {
            send.write_all(&HostMsg::PasswordRequired { wrong: false }.encode()).await?;
            let _ = send.finish();
            let _ = send.stopped().await;
            return Ok(());
        }
        let welcome = HostMsg::Welcome {
            version: behaviour.version,
            host_name: "relay".into(),
            codec: Codec::H264,
            width: 0,
            height: 0,
            features: ext.map(|_| 0),
            addresses: Vec::new(),
        };
        send.write_all(&welcome.encode()).await?;
        if let Some(relays_for_others) = behaviour.reach.filter(|_| ext.is_some_and(|e| e.reach)) {
            let reach = HostMsg::Reach {
                addresses: Vec::new(),
                key: [0; 32],
                secret: [0; 16],
                relays: Vec::new(),
                mac: None,
                relays_for_others,
            };
            send.write_all(&reach.encode()).await?;
        }
        while let Some(body) = wire::read_msg(&mut recv).await? {
            let msg = ClientMsg::decode(&body)?;
            locked(&asked).push(msg.clone());
            if let Some(answer) = relay.handle(&conn, &msg).await {
                send.write_all(&answer.encode()).await?;
            }
        }
        Ok(())
    }

    /// A host registered with the relay, serving the connections that come through it. Its end of the tunnel is the same
    /// socket as the client's, seeing the client at the other made-up address.
    struct TestHost {
        identity: Identity,
        /// The fingerprint of each client that made an inner connection.
        clients: mpsc::UnboundedReceiver<Fingerprint>,
        /// The extensions of each Velora hello.
        hellos: mpsc::UnboundedReceiver<Option<HelloExt>>,
        /// What clients send on their control streams after the hello.
        messages: mpsc::UnboundedReceiver<ClientMsg>,
        _serving: JoinHandle<()>,
    }

    impl TestHost {
        async fn start(rig: &Rig, mac: Option<Mac>) -> TestHost {
            let identity = Identity::generate().unwrap();
            let mut link = Link::open(&identity, "host", rig.relay_ref(), &Waits::DEFAULT).await.unwrap();
            link.ask(ClientMsg::RelayRegister { mac }, &Waits::DEFAULT).await.unwrap();
            let socket = RelaySocket::new(link.conn.clone(), TUNNEL_PEER, TUNNEL_LOCAL);
            let server = tls::server_config(&identity).unwrap();
            let endpoint = quinn::Endpoint::new_with_abstract_socket(
                quinn::EndpointConfig::default(),
                Some(server),
                socket,
                Arc::new(quinn::TokioRuntime),
            )
            .unwrap();
            let (clients_tx, clients) = mpsc::unbounded_channel();
            let (hellos_tx, hellos) = mpsc::unbounded_channel();
            let (messages_tx, messages) = mpsc::unbounded_channel();
            let serving = tokio::spawn(async move {
                // The host stays registered for as long as it serves.
                let _link = link;
                while let Some(incoming) = endpoint.accept().await {
                    let (clients, hellos, messages) = (clients_tx.clone(), hellos_tx.clone(), messages_tx.clone());
                    tokio::spawn(async move {
                        if let Err(e) = serve_inner(incoming, clients, hellos, messages).await {
                            tracing::debug!("test host: {e:#}");
                        }
                    });
                }
            });
            TestHost { identity, clients, hellos, messages, _serving: serving }
        }

        /// A host that is not registered anywhere: only its identity.
        fn start_unregistered() -> TestHost {
            let (_clients, clients) = mpsc::unbounded_channel();
            let (_hellos, hellos) = mpsc::unbounded_channel();
            let (_messages, messages) = mpsc::unbounded_channel();
            let serving = tokio::spawn(async {});
            TestHost { identity: Identity::generate().unwrap(), clients, hellos, messages, _serving: serving }
        }

        fn fingerprint(&self) -> Fingerprint {
            self.identity.fingerprint()
        }
    }

    /// What a host does with a client's connection: Velora's hello and welcome (and a `Reach` with nothing to say, for a
    /// client that asks), the streams the client opens next echoed back, and the control messages kept for the test.
    async fn serve_inner(
        incoming: quinn::Incoming,
        clients: mpsc::UnboundedSender<Fingerprint>,
        hellos: mpsc::UnboundedSender<Option<HelloExt>>,
        messages: mpsc::UnboundedSender<ClientMsg>,
    ) -> Result<()> {
        let conn = incoming.await?;
        let _ = clients.send(tls::peer_fingerprint(&conn)?);
        let (mut send, mut recv) = conn.accept_bi().await?;
        let body = wire::read_msg(&mut recv).await?.ok_or_else(|| anyhow!("no hello"))?;
        let ClientMsg::Hello { ext, .. } = ClientMsg::decode(&body)? else { bail!("not a hello") };
        let _ = hellos.send(ext);
        let welcome = HostMsg::Welcome {
            version: PROTOCOL_VERSION,
            host_name: "relayed-pc".into(),
            codec: Codec::H264,
            width: 1280,
            height: 720,
            features: ext.map(|_| FEATURE_FILES | FEATURE_CLIPBOARD),
            addresses: Vec::new(),
        };
        send.write_all(&welcome.encode()).await?;
        if ext.is_some_and(|e| e.reach) {
            let reach = HostMsg::Reach {
                addresses: vec![(AddressKind::Lan, "192.0.2.10:7420".into())],
                key: [0; 32],
                secret: [0; 16],
                relays: Vec::new(),
                mac: None,
                relays_for_others: false,
            };
            send.write_all(&reach.encode()).await?;
        }
        let echoing = conn.clone();
        tokio::spawn(async move {
            while let Ok((mut back, mut data)) = echoing.accept_bi().await {
                tokio::spawn(async move {
                    if let Ok(data) = data.read_to_end(4_000_000).await {
                        let _ = back.write_all(&data).await;
                        let _ = back.finish();
                    }
                });
            }
        });
        while let Some(body) = wire::read_msg(&mut recv).await? {
            let _ = messages.send(ClientMsg::decode(&body)?);
        }
        Ok(())
    }

    fn client_params(identity: &Identity, host: &TestHost) -> ConnectParams {
        ConnectParams {
            // Documentation address: nothing answers, and nothing is sent to it in these tests.
            addr: SocketAddr::from(([192, 0, 2, 1], 7420)),
            also: Vec::new(),
            host_fingerprint: host.fingerprint(),
            identity: identity.clone(),
            device_name: "test device".into(),
            pairing_secret: None,
            password: None,
            reach: None,
        }
    }

    /// The entry a client that paired with `host` keeps: it names the relays.
    fn known(host: &TestHost, relays: Vec<(Fingerprint, SocketAddr)>) -> KnownHost {
        KnownHost {
            name: "relayed-pc".into(),
            address: "192.0.2.1:7420".into(),
            fingerprint: host.fingerprint().to_base64(),
            relays: relays.into_iter().map(|(fp, addr)| (fp.to_base64(), vec![addr.to_string()])).collect(),
            mac: Some(MAC),
            ..Default::default()
        }
    }

    fn relay_to(host: &Identity) -> ClientMsg {
        ClientMsg::RelayTo { fingerprint: host.fingerprint().to_base64() }
    }

    /// An address nothing listens on.
    fn dead_address() -> SocketAddr {
        std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap()
    }

    // ---- reaching a host ----

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_client_reaches_a_host_through_a_relay_and_a_megabyte_comes_back() {
        let rig = Rig::start(Behaviour::default()).await;
        let mut host = TestHost::start(&rig, Some(MAC)).await;
        let client = Identity::generate().unwrap();
        let params = client_params(&client, &host);

        let (_endpoint, conn) =
            within("the dial", dial_relay(&params, rig.addr, rig.identity.fingerprint(), host.fingerprint()))
                .await
                .unwrap();
        // The inner handshake pinned the host's certificate, and the host saw this device's.
        assert_eq!(tls::peer_fingerprint(&conn).unwrap(), host.fingerprint());
        assert_eq!(within("the client", host.clients.recv()).await, Some(client.fingerprint()));
        // The link said what keeps a relay from starting a session for it, and asked for the host and nothing else.
        let hello = locked(&rig.hellos)[0].expect("the hello has extensions");
        assert!(hello.files_only && hello.reach && !hello.clipboard);
        assert_eq!(*locked(&rig.asked), vec![ClientMsg::RelayRegister { mac: Some(MAC) }, relay_to(&host.identity)]);

        // Velora's own hello and welcome, on a control stream of the inner connection.
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
        assert!(matches!(welcome, HostMsg::Welcome { width: 1280, height: 720, .. }), "{welcome:?}");

        // A megabyte on a stream and back: packets are split into two datagrams where the outer connection is small, put
        // back together at each end, and the inner QUIC recovers what was lost.
        let payload = pattern(1_000_000, 5);
        let (mut up, mut down) = conn.open_bi().await.unwrap();
        let echoed = tokio::time::timeout(Duration::from_secs(60), async {
            up.write_all(&payload).await.unwrap();
            up.finish().unwrap();
            down.read_to_end(2_000_000).await.unwrap()
        })
        .await
        .expect("the echo took too long");
        assert!(echoed == payload, "the echo differs from what was sent ({} bytes back)", echoed.len());

        let carried = rig.relay.registered().remove(0);
        assert_eq!(carried.client, Some(client.fingerprint()));
        assert!(carried.to_host.bytes > 1_000_000 && carried.to_client.bytes > 1_000_000, "{carried:?}");
        assert_eq!((carried.to_host.dropped, carried.to_client.dropped), (0, 0), "the relay dropped packets");
        assert!(carried.to_host.datagrams > carried.to_host.packets, "the Initial packet was not split: {carried:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_whole_client_handshake_runs_through_a_relay() {
        let rig = Rig::start(Behaviour::default()).await;
        let mut host = TestHost::start(&rig, None).await;
        let identity = Identity::generate().unwrap();
        // The host's stored address answers nobody (a socket that is bound and silent): the relay is the only way in.
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let stored = known(&host, vec![(rig.identity.fingerprint(), rig.addr)]);
        let params = ConnectParams {
            addr: silent.local_addr().unwrap(),
            reach: Some(ReachParams { host: stored, state_dir: PathBuf::from("state") }),
            ..client_params(&identity, &host)
        };

        let session = tokio::time::timeout(Duration::from_secs(30), crate::connect(params, sink()))
            .await
            .expect("the connection took too long")
            .unwrap();
        assert_eq!((session.host_name.as_str(), session.width, session.height), ("relayed-pc", 1280, 720));
        let relay = AddressKind::Relay(rig.identity.fingerprint().to_base64());
        assert_eq!(session.route(), Route { kind: relay.into(), address: rig.addr.to_string() });
        // The hello asked for Reach, the host sent one, and so it hears which of its addresses was reached: the relay's.
        assert!(within("hello", host.hellos.recv()).await.unwrap().unwrap().reach);
        let reached = ClientMsg::Reached { address: rig.addr.to_string() };
        assert_eq!(within("Reached", host.messages.recv()).await, Some(reached));
        session.close();
    }

    #[tokio::test]
    async fn a_relay_that_does_not_know_the_host_says_so() {
        let rig = Rig::start(Behaviour::default()).await;
        let stranger = Identity::generate().unwrap();
        let host = TestHost::start(&rig, None).await;
        let params = client_params(&Identity::generate().unwrap(), &host);
        let err = within("the dial", dial_relay(&params, rig.addr, rig.identity.fingerprint(), stranger.fingerprint()))
            .await
            .unwrap_err();
        let refusal = err.downcast_ref::<Refusal>().expect("the relay refused");
        assert_eq!(refusal.0, Refused::UnknownHost.to_string());
    }

    #[tokio::test]
    async fn a_relay_that_does_not_relay_for_others_is_not_asked() {
        let rig = Rig::start(Behaviour { reach: Some(false), ..Behaviour::default() }).await;
        let host = TestHost::start_unregistered();
        let params = client_params(&Identity::generate().unwrap(), &host);
        let err = within("the dial", dial_relay(&params, rig.addr, rig.identity.fingerprint(), host.fingerprint()))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("does not relay"), "{err:#}");
        assert!(locked(&rig.asked).is_empty(), "RelayTo went to a relay that said it does not relay");
    }

    #[tokio::test]
    async fn a_relay_from_before_links_sends_no_reach_and_cannot_relay() {
        let rig = Rig::start(Behaviour { reach: None, ..Behaviour::default() }).await;
        let host = TestHost::start_unregistered();
        let params = client_params(&Identity::generate().unwrap(), &host);
        let err = dial(&params, rig.relay_ref(), host.fingerprint(), &QUICK).await.unwrap_err();
        assert!(format!("{err:#}").contains("too old to relay"), "{err:#}");
        assert!(locked(&rig.asked).is_empty());
    }

    #[tokio::test]
    async fn a_relay_that_asks_for_a_password_is_a_failure_not_a_prompt() {
        let rig = Rig::start(Behaviour { password: true, ..Behaviour::default() }).await;
        let host = TestHost::start_unregistered();
        let params = client_params(&Identity::generate().unwrap(), &host);
        let err = within("the dial", dial_relay(&params, rig.addr, rig.identity.fingerprint(), host.fingerprint()))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("password"), "{err:#}");
        // The application asks the user for the host's password on a `PasswordRequired`: this is not one.
        assert!(err.downcast_ref::<crate::PasswordRequired>().is_none());
    }

    #[tokio::test]
    async fn a_relay_that_speaks_another_protocol_version_is_refused() {
        let rig = Rig::start(Behaviour { version: PROTOCOL_VERSION + 1, ..Behaviour::default() }).await;
        let host = TestHost::start_unregistered();
        let params = client_params(&Identity::generate().unwrap(), &host);
        let err = dial(&params, rig.relay_ref(), host.fingerprint(), &Waits::DEFAULT).await.unwrap_err();
        assert!(err.to_string().contains("protocol version"), "{err:#}");
    }

    #[tokio::test]
    async fn a_relay_that_does_not_answer_or_is_not_the_one_pinned_fails_at_once() {
        let rig = Rig::start(Behaviour::default()).await;
        let host = TestHost::start_unregistered();
        let params = client_params(&Identity::generate().unwrap(), &host);

        let dead = RelayRef { addr: dead_address(), fingerprint: rig.identity.fingerprint() };
        let err = dial(&params, dead, host.fingerprint(), &QUICK).await.unwrap_err();
        assert!(err.to_string().contains("did not answer"), "{err:#}");

        let impostor = RelayRef { addr: rig.addr, fingerprint: Identity::generate().unwrap().fingerprint() };
        let err = dial(&params, impostor, host.fingerprint(), &Waits::DEFAULT).await.unwrap_err();
        assert!(err.to_string().contains("could not connect to the relay"), "{err:#}");
    }

    #[tokio::test]
    async fn a_host_that_never_answers_through_the_relay_ends_the_dial_and_frees_the_relay() {
        let rig = Rig::start(Behaviour::default()).await;
        // Registered, but nothing serves its end of the tunnel.
        let identity = Identity::generate().unwrap();
        let mut registered = Link::open(&identity, "host", rig.relay_ref(), &Waits::DEFAULT).await.unwrap();
        registered.ask(ClientMsg::RelayRegister { mac: None }, &Waits::DEFAULT).await.unwrap();
        let params = ConnectParams {
            host_fingerprint: identity.fingerprint(),
            ..client_params(&Identity::generate().unwrap(), &TestHost::start_unregistered())
        };

        let err = dial(&params, rig.relay_ref(), identity.fingerprint(), &QUICK).await.unwrap_err();
        assert!(err.to_string().contains("did not answer"), "{err:#}");
        // The outer connection is closed with the failed dial, not when the inner endpoint has finished draining, so the
        // relay is not left holding the host for a client that gave up.
        let freed = async {
            while rig.relay.registered().first().is_some_and(|host| host.client.is_some()) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };
        tokio::time::timeout(Duration::from_millis(500), freed).await.expect("the relay still holds the host");

        // The same when the dial is dropped, as the race does to a candidate that lost.
        let waiting = dial(&params, rig.relay_ref(), identity.fingerprint(), &Waits::DEFAULT);
        assert!(tokio::time::timeout(Duration::from_millis(600), waiting).await.is_err());
        eventually("the relay frees the host again", || rig.relay.registered().first()?.client.is_none().then_some(()))
            .await;
    }

    // ---- the life of the link ----

    /// A client with a connection to the host through the relay.
    async fn connected(rig: &Rig, host: &TestHost) -> (quinn::Endpoint, quinn::Connection) {
        let params = client_params(&Identity::generate().unwrap(), host);
        within("the dial", dial_relay(&params, rig.addr, rig.identity.fingerprint(), host.fingerprint())).await.unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn closing_the_connection_frees_the_host_for_the_next_client() {
        let rig = Rig::start(Behaviour::default()).await;
        let host = TestHost::start(&rig, None).await;
        let (_endpoint, conn) = connected(&rig, &host).await;
        assert!(rig.relay.registered()[0].client.is_some());
        conn.close(0u32.into(), b"done");
        eventually("the relay frees the host", || rig.relay.registered()[0].client.is_none().then_some(())).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn when_the_relay_ends_the_link_the_connection_ends_at_once() {
        let rig = Rig::start(Behaviour::default()).await;
        let host = TestHost::start(&rig, None).await;
        let (_endpoint, conn) = connected(&rig, &host).await;
        let began = std::time::Instant::now();
        rig.relay.shutdown();
        let why = within("the connection to end", conn.closed()).await;
        // Closed here, not timed out: the idle timeout is fifteen seconds.
        assert!(matches!(why, quinn::ConnectionError::LocallyClosed), "{why}");
        assert!(began.elapsed() < Duration::from_secs(5), "{:?}", began.elapsed());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_device_that_takes_the_host_over_ends_the_connection_of_the_one_before() {
        let rig = Rig::start(Behaviour::default()).await;
        let host = TestHost::start(&rig, None).await;
        let (_endpoint, conn) = connected(&rig, &host).await;
        let other = Identity::generate().unwrap();
        let mut taker = Link::open(&other, "taker", rig.relay_ref(), &Waits::DEFAULT).await.unwrap();
        taker.ask(relay_to(&host.identity), &Waits::DEFAULT).await.unwrap();
        let why = within("the connection to end", conn.closed()).await;
        assert!(matches!(why, quinn::ConnectionError::LocallyClosed), "{why}");
    }

    #[test]
    fn closes_are_told_in_words() {
        let closed = |code: u32| {
            quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
                error_code: quinn::VarInt::from_u32(code),
                reason: Bytes::new(),
            })
        };
        assert_eq!(ended(&closed(CLOSE_TAKEN_OVER)), "another device took the host over");
        assert_eq!(ended(&closed(CLOSE_HOST_GONE)), "the host left the relay");
        assert_eq!(ended(&closed(CLOSE_SHUTDOWN)), "the relay was switched off");
        assert_eq!(ended(&closed(CLOSE_REMOVED)), "this device was removed from the relay");
        assert_eq!(ended(&closed(CLOSE_REPLACED)), "another connection of this device took its place");
        assert_eq!(ended(&closed(7)), "closed by peer: 7");
        assert_eq!(ended(&quinn::ConnectionError::TimedOut), "timed out");
    }

    // ---- the tunnel socket ----

    #[tokio::test]
    async fn a_closed_outer_connection_or_a_packet_too_big_is_a_loss_never_an_error() {
        let rig = Rig::start(Behaviour::default()).await;
        let identity = Identity::generate().unwrap();
        let link = Link::open(&identity, "device", rig.relay_ref(), &Waits::DEFAULT).await.unwrap();
        let socket = RelaySocket::new(link.conn.clone(), TUNNEL_LOCAL, TUNNEL_PEER);
        let send = |contents: &[u8]| {
            socket.try_send(&Transmit {
                destination: TUNNEL_PEER,
                ecn: None,
                contents,
                segment_size: None,
                src_ip: None,
            })
        };

        // Packets of any size up to two datagrams go out; more than that is dropped without failing.
        assert!(send(&[1; 1200]).is_ok());
        assert_eq!((Stats::get(&socket.stats.packets_out), Stats::get(&socket.stats.dropped_out)), (1, 0));
        assert!(Stats::get(&socket.stats.datagrams_out) >= 1);
        assert!(send(&[1; 6000]).is_ok());
        assert_eq!(Stats::get(&socket.stats.dropped_out), 1);

        // An error would end the inner connection without a word (and log one) and leave it half alive.
        link.conn.close(0u32.into(), b"gone");
        link.conn.closed().await;
        assert!(send(&[1; 1200]).is_ok());
        assert_eq!(Stats::get(&socket.stats.dropped_out), 2);

        // And nothing more is received, which is no error either.
        let mut storage = [0u8; 2000];
        let mut bufs = [IoSliceMut::new(&mut storage)];
        let mut metas = [RecvMeta::default()];
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(socket.poll_recv(&mut cx, &mut bufs, &mut metas), Poll::Pending));
    }

    #[tokio::test]
    async fn a_connection_without_datagrams_cannot_relay_and_drops_instead_of_failing() {
        // A server that takes no datagrams, as a host from long ago.
        let server_identity = Identity::generate().unwrap();
        let mut server = tls::server_config(&server_identity).unwrap();
        let mut transport = quinn::TransportConfig::default();
        transport.datagram_receive_buffer_size(None);
        server.transport_config(Arc::new(transport));
        let endpoint = quinn::Endpoint::server(server, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let accepting = endpoint.clone();
        let _held = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Some(incoming) = accepting.accept().await {
                held.extend(incoming.await.ok());
            }
        });

        let device = Identity::generate().unwrap();
        let relay = RelayRef { addr, fingerprint: server_identity.fingerprint() };
        let err = Link::open(&device, "device", relay, &Waits::DEFAULT).await.unwrap_err();
        assert!(err.to_string().contains("no datagrams"), "{err:#}");

        // A socket over such a connection loses what it is given, as over any other that cannot carry it.
        let client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let config = tls::client_config(&device, server_identity.fingerprint()).unwrap();
        let conn = client.connect_with(config, addr, tls::SERVER_NAME).unwrap().await.unwrap();
        assert_eq!(conn.max_datagram_size(), None);
        let socket = RelaySocket::new(conn, TUNNEL_LOCAL, TUNNEL_PEER);
        let sent = socket.try_send(&Transmit {
            destination: TUNNEL_PEER,
            ecn: None,
            contents: &[1; 1200],
            segment_size: None,
            src_ip: None,
        });
        assert!(sent.is_ok());
        assert_eq!((Stats::get(&socket.stats.packets_out), Stats::get(&socket.stats.dropped_out)), (0, 1));
    }

    // ---- waking ----

    #[tokio::test]
    async fn a_relay_that_can_reach_the_host_sends_the_magic_packet() {
        let rig = Rig::start(Behaviour::default()).await;
        let host = TestHost::start(&rig, Some(MAC)).await;
        let device = Identity::generate().unwrap();
        let stored = known(&host, vec![(rig.identity.fingerprint(), rig.addr)]);

        let outcome = within("the wake", wake(&device, &stored, &Waits::DEFAULT)).await.unwrap();
        assert_eq!(outcome, WakeOutcome::Sent);
        // The relay woke the host by the MAC it registered with, at the address its connection came from.
        assert_eq!(*locked(&rig.waker.calls), vec![(MAC, Ipv4Addr::LOCALHOST)]);
        assert!(locked(&rig.asked).contains(&ClientMsg::Wake { fingerprint: host.fingerprint().to_base64() }));
        // It is a request, not a pairing: nobody is relayed to the host.
        assert!(rig.relay.registered()[0].client.is_none());
    }

    #[tokio::test]
    async fn a_relay_that_cannot_wake_the_host_is_no_relay() {
        let rig = Rig::start(Behaviour::default()).await;
        let host = TestHost::start(&rig, Some(MAC)).await;
        let device = Identity::generate().unwrap();
        *locked(&rig.waker.failure) = Some(WakeError::NotOnNetwork);
        let stored = known(&host, vec![(rig.identity.fingerprint(), rig.addr)]);
        assert_eq!(wake(&device, &stored, &Waits::DEFAULT).await.unwrap(), WakeOutcome::NoRelay);
        assert_eq!(locked(&rig.waker.calls).len(), 1, "the relay was asked");
    }

    #[tokio::test]
    async fn a_relay_that_never_heard_of_the_host_or_does_not_relay_is_no_relay() {
        let rig = Rig::start(Behaviour::default()).await;
        let other = TestHost::start(&rig, Some(MAC)).await;
        let device = Identity::generate().unwrap();
        // The host in question never registered here.
        let unknown = Identity::generate().unwrap().fingerprint().to_base64();
        let stranger =
            KnownHost { fingerprint: unknown, ..known(&other, vec![(rig.identity.fingerprint(), rig.addr)]) };
        assert_eq!(wake(&device, &stranger, &Waits::DEFAULT).await.unwrap(), WakeOutcome::NoRelay);

        let closed = Rig::start(Behaviour { reach: Some(false), ..Behaviour::default() }).await;
        let stored = known(&other, vec![(closed.identity.fingerprint(), closed.addr)]);
        assert_eq!(wake(&device, &stored, &Waits::DEFAULT).await.unwrap(), WakeOutcome::NoRelay);
        assert!(locked(&closed.asked).is_empty(), "Wake went to a relay that said it does not relay");
    }

    #[tokio::test]
    async fn without_a_relay_in_reach_nothing_is_sent() {
        let rig = Rig::start(Behaviour::default()).await;
        let host = TestHost::start(&rig, Some(MAC)).await;
        let device = Identity::generate().unwrap();
        // No relay known.
        assert_eq!(wake(&device, &known(&host, vec![]), &QUICK).await.unwrap(), WakeOutcome::NoRelay);
        // One that does not answer.
        let dead = known(&host, vec![(rig.identity.fingerprint(), dead_address())]);
        assert_eq!(wake(&device, &dead, &QUICK).await.unwrap(), WakeOutcome::NoRelay);
        assert!(locked(&rig.waker.calls).is_empty());
        // A stored fingerprint that is not one is the one failure worth showing.
        let broken = KnownHost {
            fingerprint: "not a fingerprint".into(),
            ..known(&host, vec![(rig.identity.fingerprint(), rig.addr)])
        };
        assert!(wake(&device, &broken, &QUICK).await.is_err());
    }

    #[tokio::test]
    async fn the_first_relay_that_answers_wakes_the_host_whatever_the_others_do() {
        let rig = Rig::start(Behaviour::default()).await;
        let host = TestHost::start(&rig, Some(MAC)).await;
        let device = Identity::generate().unwrap();
        let dead = (Identity::generate().unwrap().fingerprint(), dead_address());
        let stored = known(&host, vec![dead, (rig.identity.fingerprint(), rig.addr)]);
        let began = std::time::Instant::now();
        assert_eq!(within("the wake", wake(&device, &stored, &Waits::DEFAULT)).await.unwrap(), WakeOutcome::Sent);
        assert!(began.elapsed() < Duration::from_secs(5), "the dead relay held it up for {:?}", began.elapsed());
    }

    #[test]
    fn the_relays_of_a_host_come_from_both_lists_without_repeats_and_never_the_host_itself() {
        let (one, two, host) = (Fingerprint([1; 32]), Fingerprint([2; 32]), Fingerprint([9; 32]));
        let addr = |last: u8| SocketAddr::from(([203, 0, 113, last], 7420));
        let entry = KnownHost {
            fingerprint: host.to_base64(),
            relays: vec![
                (one.to_base64(), vec![addr(1).to_string(), addr(2).to_string(), "garbage".into()]),
                ("not a fingerprint".into(), vec![addr(3).to_string()]),
                (host.to_base64(), vec![addr(4).to_string()]),
            ],
            kinds: vec![
                (AddressKind::Relay(one.to_base64()), addr(1).to_string()),
                (AddressKind::Relay(two.to_base64()), addr(5).to_string()),
                (AddressKind::Lan, addr(6).to_string()),
            ],
            ..Default::default()
        };
        let relay = |fingerprint: Fingerprint, last: u8| RelayRef { addr: addr(last), fingerprint };
        assert_eq!(relays_of(&entry), vec![relay(one, 1), relay(one, 2), relay(two, 5)]);
    }
}
