//! The endpoint a NAT shows the outside, seen from the socket that will carry QUIC.
//!
//! A NAT keeps one mapping per source port, so the address a peer must send to can only be learned
//! from the very socket that will carry the connection. Nodes of the BitTorrent Mainline DHT tell
//! every requester which ip:port its packet came from (BEP 42: the `ip` field of a reply), so a
//! plain KRPC `ping` is enough to ask; STUN is the fallback. Asking several nodes from one socket
//! also shows how the NAT maps ports, which says whether hole punching can work.
//!
//! The `observe*` functions take a std socket and block the calling thread: async callers must run
//! them with `tokio::task::spawn_blocking`. [`DhtProbe`] is the same exchange with no I/O, for
//! callers whose socket is driven another way (the host's multiplexed QUIC socket).

use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use stunclient::StunClient;

/// The bootstrap nodes of the Mainline DHT (the list `mainline` starts from), as `host:port`.
pub const DEFAULT_DHT_NODES: [&str; 4] =
    ["router.bittorrent.com:6881", "dht.transmissionbt.com:6881", "dht.libtorrent.org:25401", "relay.pkarr.org:6881"];

/// The STUN servers used when the DHT does not answer, as `host:port`.
pub const DEFAULT_STUN_SERVERS: [&str; 2] = ["stun.l.google.com:19302", "stun.cloudflare.com:3478"];

/// How long a phase of [`observe`] waits for answers unless the caller says otherwise. Answers
/// normally arrive within a few hundred milliseconds; this is the cap for a network that does not.
pub const DEFAULT_WAIT: Duration = Duration::from_secs(3);

/// A silent node is pinged again this often: UDP loses packets, and the first one opens the NAT.
const RESEND_EVERY: Duration = Duration::from_millis(750);
/// Answers after which waiting longer tells nothing new.
const ENOUGH_ANSWERS: usize = 3;
/// How long the nodes still silent get to answer once two have.
const SETTLE_FOR: Duration = Duration::from_millis(400);
/// Servers that must have answered to tell one kind of NAT from another.
const MIN_SERVERS_TO_CLASSIFY: usize = 2;
/// Addresses kept per name and family when resolving, so a DNS round-robin cannot multiply the probes.
const ADDRESSES_PER_NAME: usize = 2;
const STUN_RETRY_EVERY: Duration = Duration::from_millis(500);
const MIN_STUN_WAIT: Duration = Duration::from_millis(500);
/// Longer waits are cut to this, so adding one to the clock cannot overflow.
const MAX_WAIT: Duration = Duration::from_secs(24 * 3600);

/// One answer: which server said it, and the endpoint it saw our packets come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observation {
    /// The DHT node or STUN server that answered (IPv4-mapped addresses are turned into plain IPv4).
    pub from: SocketAddr,
    /// The ip:port the server saw: the NAT's public side of the socket, or the socket's own address
    /// when there is no NAT.
    pub endpoint: SocketAddr,
}

/// How a NAT maps the ports of one socket, which decides whether hole punching can work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NatType {
    /// The servers saw the socket's own address: nothing translates it, so anyone can send to it
    /// (a firewall may still drop what it did not see go out).
    Open,
    /// Every server saw the same external ip:port (a "cone" NAT): the endpoint another peer needs
    /// is the one observed, and hole punching works.
    EndpointIndependent,
    /// The external ip or port changed with the destination (a "symmetric" NAT, RFC 4787's address-
    /// or port-dependent mapping): the observed endpoint is only good for the server that saw it,
    /// and hole punching fails.
    Dependent,
    /// Not enough answers to tell: fewer than two servers answered.
    Unknown,
}

impl NatType {
    /// A short lowercase name, for logs and status lines.
    pub fn as_str(self) -> &'static str {
        match self {
            NatType::Open => "open",
            NatType::EndpointIndependent => "endpoint-independent",
            NatType::Dependent => "dependent",
            NatType::Unknown => "unknown",
        }
    }
}

impl fmt::Display for NatType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What failed in an observation.
#[derive(Debug, thiserror::Error)]
pub enum ObserveError {
    /// The socket failed, or no packet could be sent at all (no route, wrong address family).
    #[error("socket error: {0}")]
    Io(#[from] io::Error),
    /// Everything was asked and nobody answered with an address.
    #[error("no DHT node or STUN server answered ({asked} asked)")]
    NoAnswer {
        /// How many nodes and servers were on the lists.
        asked: usize,
    },
}

/// The outcome of [`observe`]: the endpoint to give to peers and what kind of NAT is in the way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    /// The endpoint most answers agree on. For a `Dependent` NAT it is only one of several and not
    /// worth giving to a peer.
    pub endpoint: SocketAddr,
    /// How the NAT maps ports.
    pub nat: NatType,
    /// Every answer, in the order received.
    pub observations: Vec<Observation>,
}

impl Observed {
    /// Summarises `observations` made from a socket bound to `local` (its `local_addr()`, which may
    /// be a wildcard address). `None` when there are no observations.
    pub fn new(local: SocketAddr, observations: Vec<Observation>) -> Option<Observed> {
        let endpoint = most_common_endpoint(&observations)?;
        let nat = classify_nat(local, &observations);
        Some(Observed { endpoint, nat, observations })
    }
}

fn most_common_endpoint(observations: &[Observation]) -> Option<SocketAddr> {
    let mut best: Option<(SocketAddr, usize)> = None;
    for o in observations {
        let count = observations.iter().filter(|p| p.endpoint == o.endpoint).count();
        // Strictly more, so a tie goes to the endpoint heard first.
        if best.is_none_or(|(_, most)| count > most) {
            best = Some((o.endpoint, count));
        }
    }
    best.map(|(endpoint, _)| endpoint)
}

fn distinct_servers(observations: &[Observation]) -> usize {
    let mut ips: Vec<IpAddr> = observations.iter().map(|o| o.from.ip()).collect();
    ips.sort();
    ips.dedup();
    ips.len()
}

/// Tells how the NAT maps ports from what servers saw of one socket, bound to `local` (its
/// `local_addr()`, which may be a wildcard address).
///
/// If every observation is the socket's own address nothing translates it and the NAT is `Open`.
/// Otherwise at least two servers on different IPs must have answered, or the result is `Unknown`
/// (one server cannot show that the mapping changes with the destination). If they all saw the
/// same endpoint the NAT is `EndpointIndependent`, and if any differs, `Dependent`.
///
/// For a socket bound to a wildcard address, "its own address" is any address of this PC, which
/// the OS tells by letting a socket bind to it (nothing is sent).
pub fn classify_nat(local: SocketAddr, observations: &[Observation]) -> NatType {
    let Some(first) = observations.first() else { return NatType::Unknown };
    if observations.iter().all(|o| is_own(local, o.endpoint)) {
        return NatType::Open;
    }
    if distinct_servers(observations) < MIN_SERVERS_TO_CLASSIFY {
        return NatType::Unknown;
    }
    if observations.iter().all(|o| o.endpoint == first.endpoint) {
        NatType::EndpointIndependent
    } else {
        NatType::Dependent
    }
}

/// Whether `endpoint` is the socket bound to `local` itself, not a NAT's side of it.
fn is_own(local: SocketAddr, endpoint: SocketAddr) -> bool {
    let (local, endpoint) = (canonical(local), canonical(endpoint));
    if endpoint.port() != local.port() {
        return false;
    }
    if local.ip().is_unspecified() {
        UdpSocket::bind((endpoint.ip(), 0)).is_ok()
    } else {
        endpoint.ip() == local.ip()
    }
}

/// Resolves `host:port` names, skipping the ones that fail. At most two IPv4 and two IPv6
/// addresses per name are kept. Blocking: it asks the system resolver, which can take seconds on
/// a network without DNS; async callers should use `spawn_blocking`.
pub fn resolve<S: AsRef<str>>(names: &[S]) -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = Vec::new();
    for name in names {
        let name = name.as_ref();
        match name.to_socket_addrs() {
            Ok(addrs) => {
                let (mut v4, mut v6) = (0, 0);
                for addr in addrs.map(canonical) {
                    let taken = if addr.is_ipv4() { &mut v4 } else { &mut v6 };
                    if *taken < ADDRESSES_PER_NAME && !out.contains(&addr) {
                        *taken += 1;
                        out.push(addr);
                    }
                }
            }
            Err(e) => tracing::debug!(name, "cannot resolve: {e}"),
        }
    }
    out
}

/// The IPv4 addresses of [`DEFAULT_DHT_NODES`] (the DHT does not run over IPv6). Blocking, see
/// [`resolve`].
pub fn default_dht_nodes() -> Vec<SocketAddr> {
    let mut nodes = resolve(&DEFAULT_DHT_NODES);
    nodes.retain(SocketAddr::is_ipv4);
    nodes
}

/// The addresses of [`DEFAULT_STUN_SERVERS`], IPv4 and IPv6. Blocking, see [`resolve`].
pub fn default_stun_servers() -> Vec<SocketAddr> {
    resolve(&DEFAULT_STUN_SERVERS)
}

/// The address with an IPv4-mapped IPv6 address turned into the plain IPv4 one: a dual-stack
/// socket reports its IPv4 peers in the mapped form.
fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

/// How to address `node` from a socket of the given family: an IPv6 socket reaches an IPv4 node
/// through its IPv4-mapped form, an IPv4 socket cannot reach an IPv6 node at all.
fn for_socket(socket_is_v6: bool, node: SocketAddr) -> Option<SocketAddr> {
    match (socket_is_v6, node) {
        (true, SocketAddr::V4(v4)) => Some(SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port())),
        (false, SocketAddr::V6(_)) => None,
        _ => Some(node),
    }
}

/// Unpredictable bytes for ids and transaction ids, with no random-number crate: `RandomState` is
/// seeded by the OS. They only have to be hard to guess for someone forging an answer off-path.
fn random_bytes<const N: usize>() -> [u8; N] {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};

    let mut out = [0u8; N];
    for chunk in out.chunks_mut(8) {
        let mut hasher = RandomState::new().build_hasher();
        // Mixed with the clock in case two states ever start alike.
        hasher.write_u128(SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos()));
        chunk.copy_from_slice(&hasher.finish().to_le_bytes()[..chunk.len()]);
    }
    out
}

// ---- KRPC (BEP 5) with the observed address of BEP 42 -----------------------------------------

/// The `ping` query. Keys are in sorted order, as bencode wants. The `ro` flag (BEP 43) tells the
/// node that we are a client, so it does not put us in its routing table. The transaction id is
/// four bytes because `mainline` nodes always answer with four (a shorter one comes back padded
/// and would not match the one sent).
fn encode_ping(node_id: &[u8; 20], transaction_id: &[u8; 4]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(b"d1:ad2:id20:");
    out.extend_from_slice(node_id);
    out.extend_from_slice(b"e1:q4:ping2:roi1e1:t4:");
    out.extend_from_slice(transaction_id);
    out.extend_from_slice(b"1:y1:qe");
    out
}

/// The compact form of BEP 5 and BEP 42: the address (4 or 16 bytes) then the port, big-endian.
fn encode_compact(addr: SocketAddr) -> Vec<u8> {
    let mut out = match addr.ip() {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    };
    out.extend_from_slice(&addr.port().to_be_bytes());
    out
}

/// Reads a compact address; `None` for any length but 6 and 18, and for an address nobody can
/// send to (port 0, unspecified, multicast), since a node that sends one told us nothing.
fn decode_compact(bytes: &[u8]) -> Option<SocketAddr> {
    let (ip, port): (IpAddr, [u8; 2]) = match bytes.len() {
        6 => (IpAddr::from(<[u8; 4]>::try_from(&bytes[..4]).ok()?), bytes[4..].try_into().ok()?),
        18 => (IpAddr::from(<[u8; 16]>::try_from(&bytes[..16]).ok()?), bytes[16..].try_into().ok()?),
        _ => return None,
    };
    let port = u16::from_be_bytes(port);
    (port != 0 && !ip.is_unspecified() && !ip.is_multicast()).then_some(SocketAddr::new(ip, port))
}

/// A ping answer: the transaction id echoed, a node id, and the requester's address when given.
fn encode_reply(node_id: &[u8; 20], transaction_id: &[u8], requester: Option<SocketAddr>) -> Vec<u8> {
    let mut out = vec![b'd'];
    if let Some(addr) = requester {
        let compact = encode_compact(addr);
        out.extend_from_slice(format!("2:ip{}:", compact.len()).as_bytes());
        out.extend_from_slice(&compact);
    }
    out.extend_from_slice(b"1:rd2:id20:");
    out.extend_from_slice(node_id);
    out.extend_from_slice(format!("e1:t{}:", transaction_id.len()).as_bytes());
    out.extend_from_slice(transaction_id);
    out.extend_from_slice(b"1:y1:re");
    out
}

/// What a BEP 42 node answers to a `ping`: `requester` is the address it saw the ping come from.
/// `None` when `ping` is not a well-formed ping query. For tests with a fake node, which would
/// otherwise each write their own bencode.
pub fn reply_to_ping(ping: &[u8], requester: SocketAddr) -> Option<Vec<u8>> {
    let message = parse(ping).ok()?;
    (message.kind == Kind::Query && message.query == Some(&b"ping"[..]))
        .then(|| encode_reply(&random_bytes(), message.transaction_id, Some(canonical(requester))))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Query,
    Response,
    Error,
}

/// The parts of a KRPC message that matter here.
#[derive(Debug, PartialEq, Eq)]
struct Message<'a> {
    transaction_id: &'a [u8],
    kind: Kind,
    /// The query name (`ping`, `find_node`, ...) when it is a query.
    query: Option<&'a [u8]>,
    /// The requester's address as the sender saw it (BEP 42), when it sent a usable one.
    observed: Option<SocketAddr>,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("malformed KRPC message: {0}")]
struct DecodeError(&'static str);

/// Bencode nests no deeper than this in a KRPC message; anything deeper is not worth following.
const MAX_DEPTH: usize = 16;

/// Reads a KRPC message without trusting it: every length is checked against what is left and
/// nesting is capped, so nothing a node sends can panic, overflow or allocate much.
fn parse(datagram: &[u8]) -> Result<Message<'_>, DecodeError> {
    let mut reader = Reader { data: datagram, pos: 0 };
    reader.expect(b'd')?;
    let (mut transaction_id, mut kind, mut query, mut observed) = (None, None, None, None);
    while reader.peek() != Some(b'e') {
        match reader.bytes()? {
            b"t" => transaction_id = Some(reader.bytes()?),
            b"y" => kind = Some(reader.bytes()?),
            b"q" => query = Some(reader.bytes()?),
            b"ip" => observed = decode_compact(reader.bytes()?),
            _ => reader.skip(1)?,
        }
    }
    let kind = match kind {
        Some(b"q") => Kind::Query,
        Some(b"r") => Kind::Response,
        Some(b"e") => Kind::Error,
        Some(_) => return Err(DecodeError("unknown message type")),
        None => return Err(DecodeError("no message type")),
    };
    let transaction_id = transaction_id.ok_or(DecodeError("no transaction id"))?;
    Ok(Message { transaction_id, kind, query, observed })
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn peek(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    fn expect(&mut self, byte: u8) -> Result<(), DecodeError> {
        if self.peek() == Some(byte) {
            self.pos += 1;
            Ok(())
        } else {
            Err(DecodeError("unexpected byte"))
        }
    }

    /// A byte string: `<length>:<bytes>`.
    fn bytes(&mut self) -> Result<&'a [u8], DecodeError> {
        let start = self.pos;
        let mut len = 0usize;
        while let Some(digit @ b'0'..=b'9') = self.peek() {
            // Nine digits at most: no overflow, and no string that long fits a datagram anyway.
            if self.pos - start >= 9 {
                return Err(DecodeError("string length too long"));
            }
            len = len * 10 + usize::from(digit - b'0');
            self.pos += 1;
        }
        if self.pos == start {
            return Err(DecodeError("expected a string"));
        }
        self.expect(b':')?;
        let end = self.pos.checked_add(len).ok_or(DecodeError("string runs past the end"))?;
        let bytes = self.data.get(self.pos..end).ok_or(DecodeError("string runs past the end"))?;
        self.pos = end;
        Ok(bytes)
    }

    /// Steps over one value of any kind.
    fn skip(&mut self, depth: usize) -> Result<(), DecodeError> {
        if depth > MAX_DEPTH {
            return Err(DecodeError("nested too deep"));
        }
        match self.peek() {
            Some(b'i') => {
                self.pos += 1;
                if self.peek() == Some(b'-') {
                    self.pos += 1;
                }
                let digits = self.pos;
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
                if self.pos == digits {
                    return Err(DecodeError("expected an integer"));
                }
                self.expect(b'e')
            }
            Some(b'l') => {
                self.pos += 1;
                while self.peek() != Some(b'e') {
                    self.skip(depth + 1)?;
                }
                self.pos += 1;
                Ok(())
            }
            Some(b'd') => {
                self.pos += 1;
                while self.peek() != Some(b'e') {
                    self.bytes()?;
                    self.skip(depth + 1)?;
                }
                self.pos += 1;
                Ok(())
            }
            Some(b'0'..=b'9') => self.bytes().map(|_| ()),
            Some(_) => Err(DecodeError("unexpected byte")),
            None => Err(DecodeError("truncated")),
        }
    }
}

// ---- Asking the DHT ---------------------------------------------------------------------------

/// A `ping` sent to one node, and whether it was answered.
#[derive(Debug)]
struct Ping {
    node: SocketAddr,
    transaction_id: [u8; 4],
    packet: Vec<u8>,
    answered: bool,
}

/// A round of KRPC pings asking DHT nodes where they see us, with no I/O: the caller sends what
/// [`pending`](DhtProbe::pending) lists, feeds every datagram received from a node to
/// [`handle`](DhtProbe::handle), and reads [`observations`](DhtProbe::observations). The blocking
/// [`observe_dht`] drives it over a std socket; a socket owned by something else (the host's QUIC
/// endpoint) can drive it from its own receive path.
///
/// IPv4 nodes are addressed as plain IPv4; on a dual-stack socket send to the IPv4-mapped form
/// (`handle` accepts replies from either form).
#[derive(Debug)]
pub struct DhtProbe {
    pings: Vec<Ping>,
    observations: Vec<Observation>,
}

impl DhtProbe {
    /// Prepares one ping per node (duplicates dropped). Nothing is sent.
    pub fn new(nodes: &[SocketAddr]) -> DhtProbe {
        let node_id: [u8; 20] = random_bytes();
        let mut pings: Vec<Ping> = Vec::new();
        for node in nodes.iter().copied().map(canonical) {
            if pings.iter().any(|p| p.node == node) {
                continue;
            }
            let transaction_id: [u8; 4] = random_bytes();
            pings.push(Ping { node, transaction_id, packet: encode_ping(&node_id, &transaction_id), answered: false });
        }
        DhtProbe { pings, observations: Vec::new() }
    }

    /// The pings that got no answer yet, as (node, datagram). Sending them again is the way to
    /// retry: the transaction ids stay the same, so a late answer to an earlier send still counts.
    pub fn pending(&self) -> impl Iterator<Item = (SocketAddr, &[u8])> + '_ {
        self.pings.iter().filter(|p| !p.answered).map(|p| (p.node, p.packet.as_slice()))
    }

    /// Offers a datagram received from `from`. Returns whether it answered one of the pings, in
    /// which case the caller should keep it away from whatever else reads the socket (QUIC),
    /// whether or not it carried our address. Anything else (a query, garbage, a stranger's
    /// datagram) returns `false` and changes nothing.
    pub fn handle(&mut self, from: SocketAddr, datagram: &[u8]) -> bool {
        let from = canonical(from);
        let Some(ping) = self.pings.iter_mut().find(|p| p.node == from) else { return false };
        let message = match parse(datagram) {
            Ok(message) => message,
            Err(e) => {
                tracing::debug!(%from, "not an answer to our DHT ping: {e}");
                return false;
            }
        };
        if message.kind == Kind::Query || message.transaction_id != ping.transaction_id {
            return false;
        }
        if ping.answered {
            return true;
        }
        ping.answered = true;
        match (message.kind, message.observed) {
            (Kind::Response, Some(endpoint)) => {
                tracing::debug!(node = %from, %endpoint, "DHT node sees us");
                self.observations.push(Observation { from, endpoint });
            }
            (Kind::Response, None) => tracing::debug!(node = %from, "DHT node answered without our address"),
            _ => tracing::debug!(node = %from, "DHT node answered with an error"),
        }
        true
    }

    /// The addresses nodes reported, in the order received.
    pub fn observations(&self) -> &[Observation] {
        &self.observations
    }
}

/// Keeps a socket in blocking mode while a probe runs, and puts its read timeout back after.
/// (std cannot say whether the socket was blocking before: it is left blocking, as `bind` returns
/// it. `quinn::Endpoint::new` switches a socket it is given to non-blocking itself.)
struct Blocking<'a> {
    socket: &'a UdpSocket,
    read_timeout: Option<Duration>,
}

impl<'a> Blocking<'a> {
    fn new(socket: &'a UdpSocket) -> io::Result<Blocking<'a>> {
        let read_timeout = socket.read_timeout()?;
        // A non-blocking socket would make the receive loops spin and resend at full speed.
        socket.set_nonblocking(false)?;
        Ok(Blocking { socket, read_timeout })
    }
}

impl Drop for Blocking<'_> {
    fn drop(&mut self) {
        if let Err(e) = self.socket.set_read_timeout(self.read_timeout) {
            tracing::debug!("cannot restore the socket's read timeout: {e}");
        }
    }
}

/// Errors of a receive that say nothing about the socket: the wait ended, or (on Windows) a
/// datagram was too big for the buffer, or an earlier send drew an ICMP "port unreachable".
fn is_transient(e: &io::Error) -> bool {
    use io::ErrorKind::*;
    #[cfg(windows)]
    {
        const WSAEMSGSIZE: i32 = 10040;
        if e.raw_os_error() == Some(WSAEMSGSIZE) {
            return true;
        }
    }
    matches!(e.kind(), WouldBlock | TimedOut | Interrupted | ConnectionReset | ConnectionRefused)
}

/// Throws away what already waits on the socket, errors included (Windows reports an earlier ICMP
/// "port unreachable" on the next receive), so none of it is taken for the answer to a new probe.
fn drain(socket: &UdpSocket) {
    if socket.set_read_timeout(Some(Duration::from_millis(1))).is_err() {
        return;
    }
    let mut buf = [0u8; 2048];
    for _ in 0..32 {
        match socket.recv_from(&mut buf) {
            Ok(_) => {}
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => break,
            Err(_) => {}
        }
    }
}

/// Pings DHT `nodes` from `socket` and returns the endpoint each one that answered saw. This is
/// the endpoint of the socket itself: use the socket that will carry QUIC, since a NAT maps each
/// source port on its own. Nodes that do not answer within `wait` (pinged again every 750 ms) or
/// answer without BEP 42's `ip` are left out; an empty list is not an error.
///
/// Returns as soon as three nodes gave their view or every node answered, and 400 ms after the
/// second view when the rest stay silent. Of the default nodes only some send BEP 42's `ip`
/// (`dht.libtorrent.org` and `relay.pkarr.org` do, Transmission's do not, `router.bittorrent.com`
/// often says nothing), so nodes saved from a routing table are the better source. Whatever else
/// arrives on the socket meanwhile is dropped, so call it before the socket carries traffic.
/// `nodes` can be those or [`default_dht_nodes`]. IPv6 nodes are skipped on an IPv4 socket.
///
/// The socket is put in blocking mode and left that way, with its read timeout as it was. It must
/// not be connected.
///
/// Blocking, up to `wait`: async callers must use `tokio::task::spawn_blocking`.
pub fn observe_dht(socket: &UdpSocket, nodes: &[SocketAddr], wait: Duration) -> Result<Vec<Observation>, ObserveError> {
    let socket_is_v6 = socket.local_addr()?.is_ipv6();
    let reachable: Vec<SocketAddr> =
        nodes.iter().copied().filter(|&node| for_socket(socket_is_v6, canonical(node)).is_some()).collect();
    let mut probe = DhtProbe::new(&reachable);
    if probe.pending().next().is_none() {
        return Ok(Vec::new());
    }
    let _blocking = Blocking::new(socket)?;
    drain(socket);

    let deadline = Instant::now() + wait.min(MAX_WAIT);
    let mut next_send = Instant::now();
    // Once two nodes have answered the rest get a moment to join, not the whole wait: some
    // bootstrap nodes never answer and some answer without our address.
    let mut settle_by: Option<Instant> = None;
    let mut sent_any = false;
    let mut send_error: Option<io::Error> = None;
    let mut fatal: Option<io::Error> = None;
    let mut buf = [0u8; 2048];
    loop {
        let now = Instant::now();
        if now >= deadline
            || probe.observations().len() >= ENOUGH_ANSWERS
            || probe.pending().next().is_none()
            || settle_by.is_some_and(|t| now >= t)
        {
            break;
        }
        if settle_by.is_none() && distinct_servers(probe.observations()) >= MIN_SERVERS_TO_CLASSIFY {
            settle_by = Some(now + SETTLE_FOR);
        }
        if now >= next_send {
            for (node, packet) in probe.pending() {
                let Some(target) = for_socket(socket_is_v6, node) else { continue };
                match socket.send_to(packet, target) {
                    Ok(_) => sent_any = true,
                    Err(e) => {
                        tracing::debug!(%node, "cannot send the DHT ping: {e}");
                        send_error = Some(e);
                    }
                }
            }
            next_send = Instant::now() + RESEND_EVERY;
        }
        let until = next_send.min(deadline).min(settle_by.unwrap_or(deadline));
        // Never zero: a zero read timeout is an error.
        let slice = until.saturating_duration_since(Instant::now()).max(Duration::from_millis(1));
        if let Err(e) = socket.set_read_timeout(Some(slice)) {
            fatal = Some(e);
            break;
        }
        match socket.recv_from(&mut buf) {
            Ok((len, from)) => {
                probe.handle(from, &buf[..len]);
            }
            Err(e) if is_transient(&e) => {}
            Err(e) => {
                fatal = Some(e);
                break;
            }
        }
    }
    // What was learned is kept even when the socket failed afterwards.
    if probe.observations().is_empty() {
        if let Some(e) = fatal.or(send_error.filter(|_| !sent_any)) {
            return Err(e.into());
        }
    }
    Ok(probe.observations().to_vec())
}

/// Asks STUN `servers` (binding requests, through `stunclient`) from `socket` where it appears to
/// them, one after the other, and returns what each one that answered saw. Same contract as
/// [`observe_dht`]: use the socket that will carry QUIC, it is left blocking with its read timeout
/// as it was, and traffic arriving meanwhile is dropped. `wait` is shared between the servers
/// (at least half a second each); it stops after three answers.
///
/// Blocking, up to `wait`: async callers must use `tokio::task::spawn_blocking`.
pub fn observe_stun(
    socket: &UdpSocket,
    servers: &[SocketAddr],
    wait: Duration,
) -> Result<Vec<Observation>, ObserveError> {
    let socket_is_v6 = socket.local_addr()?.is_ipv6();
    let mut targets: Vec<(SocketAddr, SocketAddr)> = Vec::new();
    for server in servers.iter().copied().map(canonical) {
        let Some(target) = for_socket(socket_is_v6, server) else { continue };
        if !targets.iter().any(|(s, _)| *s == server) {
            targets.push((server, target));
        }
    }
    if targets.is_empty() {
        return Ok(Vec::new());
    }
    let _blocking = Blocking::new(socket)?;
    drain(socket);

    let per_server = (wait.min(MAX_WAIT) / targets.len() as u32).max(MIN_STUN_WAIT);
    let mut found = Vec::new();
    for (server, target) in targets {
        let mut client = StunClient::new(target);
        client.set_timeout(per_server).set_retry_interval(STUN_RETRY_EVERY.min(per_server)).set_software(None);
        match client.query_external_address(socket) {
            Ok(endpoint) => {
                let endpoint = canonical(endpoint);
                tracing::debug!(%server, %endpoint, "STUN server sees us");
                found.push(Observation { from: server, endpoint });
                if found.len() >= ENOUGH_ANSWERS {
                    break;
                }
            }
            Err(e) => tracing::debug!(%server, "STUN binding failed: {e}"),
        }
    }
    Ok(found)
}

/// Finds the endpoint the outside sees for `socket` and the kind of NAT in front of it: asks the
/// DHT `dht_nodes` ([`observe_dht`]) and, when fewer than two distinct nodes answered, also the
/// STUN `stun_servers` ([`observe_stun`]; pass none to skip STUN). Every phase waits at most
/// `wait` ([`DEFAULT_WAIT`]), and the first returns early as soon as enough nodes answered, so a
/// working network takes well under a second.
///
/// Use the socket that will carry QUIC and call it before the socket carries traffic; see
/// [`observe_dht`] for what is done to the socket. Fails with [`ObserveError::NoAnswer`] when
/// nobody answered (or the I/O error that stopped the packets leaving).
///
/// Blocking: async callers must use `tokio::task::spawn_blocking`.
pub fn observe(
    socket: &UdpSocket,
    dht_nodes: &[SocketAddr],
    stun_servers: &[SocketAddr],
    wait: Duration,
) -> Result<Observed, ObserveError> {
    let local = socket.local_addr()?;
    let mut observations = Vec::new();
    let mut error = None;
    match observe_dht(socket, dht_nodes, wait) {
        Ok(found) => observations = found,
        Err(e) => {
            tracing::debug!("DHT observation failed: {e}");
            error = Some(e);
        }
    }
    if distinct_servers(&observations) < MIN_SERVERS_TO_CLASSIFY && !stun_servers.is_empty() {
        tracing::debug!(dht_answers = observations.len(), "asking STUN servers too");
        match observe_stun(socket, stun_servers, wait) {
            Ok(found) => observations.extend(found),
            Err(e) => {
                tracing::debug!("STUN observation failed: {e}");
                error.get_or_insert(e);
            }
        }
    }
    Observed::new(local, observations)
        .ok_or_else(|| error.unwrap_or(ObserveError::NoAnswer { asked: dht_nodes.len() + stun_servers.len() }))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread::JoinHandle;

    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    const ID: [u8; 20] = *b"AAAAAAAAAAAAAAAAAAAA";

    /// A query other than `ping`, as a DHT node sends to its neighbours.
    fn find_node_query() -> Vec<u8> {
        [&b"d1:ad2:id20:"[..], &ID, b"6:target20:", &ID, b"e1:q9:find_node1:t1:a1:y1:qe"].concat()
    }

    // ---- bencode ----

    #[test]
    fn ping_follows_bep_5_with_sorted_keys() {
        assert_eq!(
            encode_ping(&ID, b"abcd"),
            [&b"d1:ad2:id20:"[..], &ID, b"e1:q4:ping2:roi1e1:t4:abcd1:y1:qe"].concat()
        );
    }

    #[test]
    fn ping_reads_back_as_a_query() {
        let ping = encode_ping(&ID, b"abcd");
        let message = parse(&ping).unwrap();
        assert_eq!(message.kind, Kind::Query);
        assert_eq!(message.query, Some(&b"ping"[..]));
        assert_eq!(message.transaction_id, b"abcd");
        assert_eq!(message.observed, None);
    }

    #[test]
    fn reply_carries_the_address_in_the_top_level_ip_key() {
        let reply = encode_reply(&ID, b"abcd", Some(addr("1.2.3.4:5000")));
        let expected = [&b"d2:ip6:\x01\x02\x03\x04\x13\x88"[..], b"1:rd2:id20:", &ID, b"e1:t4:abcd1:y1:re"].concat();
        assert_eq!(reply, expected);
        let message = parse(&reply).unwrap();
        assert_eq!(message.kind, Kind::Response);
        assert_eq!(message.transaction_id, b"abcd");
        assert_eq!(message.observed, Some(addr("1.2.3.4:5000")));
    }

    #[test]
    fn reply_without_ip_has_no_address() {
        let reply = encode_reply(&ID, b"abcd", None);
        assert_eq!(reply, [&b"d1:rd2:id20:"[..], &ID, b"e1:t4:abcd1:y1:re"].concat());
        assert_eq!(parse(&reply).unwrap().observed, None);
    }

    #[test]
    fn reply_with_an_ipv6_address() {
        let reply = encode_reply(&ID, b"xy", Some(addr("[2001:db8::7]:443")));
        let message = parse(&reply).unwrap();
        assert_eq!(message.observed, Some(addr("[2001:db8::7]:443")));
        assert_eq!(message.transaction_id, b"xy");
    }

    #[test]
    fn reply_as_libtorrent_sends_it() {
        // Extra keys, a two-byte transaction id and a version, in the order libtorrent writes them.
        let reply = [
            &b"d2:ip6:\xc0\xa8\x01\x02\x1a\xe1"[..],
            b"1:rd2:id20:",
            &ID,
            b"5:nodes0:5:token2:abe1:t2:aa1:v4:LT\x01\x021:y1:re",
        ]
        .concat();
        let message = parse(&reply).unwrap();
        assert_eq!(message.kind, Kind::Response);
        assert_eq!(message.transaction_id, b"aa");
        assert_eq!(message.observed, Some(addr("192.168.1.2:6881")));
    }

    #[test]
    fn unusable_ip_fields_count_as_absent() {
        for ip in [&b"5:abcde"[..], b"7:abcdefg", b"0:", b"6:\x01\x02\x03\x04\x00\x00", b"6:\x00\x00\x00\x00\x13\x88"] {
            let mut reply = b"d2:ip".to_vec();
            reply.extend_from_slice(ip);
            reply.extend_from_slice(b"1:t1:a1:y1:re");
            assert_eq!(parse(&reply).unwrap().observed, None, "{ip:?}");
        }
    }

    #[test]
    fn error_replies_and_queries_are_told_apart() {
        // The example of BEP 5.
        let error = parse(b"d1:eli201e23:A Generic Error Ocurrede1:t2:aa1:y1:ee").unwrap();
        assert_eq!(error.kind, Kind::Error);
        assert_eq!(error.transaction_id, b"aa");
        assert_eq!(error.observed, None);
        let find_node = find_node_query();
        let query = parse(&find_node).unwrap();
        assert_eq!(query.kind, Kind::Query);
        assert_eq!(query.query, Some(&b"find_node"[..]));
    }

    #[test]
    fn malformed_messages_are_errors() {
        let deep = format!("d1:x{}{}1:t1:a1:y1:re", "l".repeat(200), "e".repeat(200));
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("empty", b"".to_vec()),
            ("not bencode", b"hello".to_vec()),
            ("a list", b"le".to_vec()),
            ("only the opening", b"d".to_vec()),
            ("key cut off", b"d1:t".to_vec()),
            ("string past the end", b"d1:t4:ab".to_vec()),
            ("no closing e", b"d1:t1:a1:y1:r".to_vec()),
            ("t is an integer", b"d1:ti5e1:y1:re".to_vec()),
            ("huge length", b"d1:t999999999:a1:y1:re".to_vec()),
            ("length overflow", b"d1:t99999999999999999999:a1:y1:re".to_vec()),
            ("negative length", b"d1:t-1:a1:y1:re".to_vec()),
            ("key is not a string", b"di1ei2ee".to_vec()),
            ("integer without end", b"d1:xi12".to_vec()),
            ("integer without digits", b"d1:xiee1:t1:a1:y1:re".to_vec()),
            ("list never closed", b"d1:xli1ei2e".to_vec()),
            ("garbage value", b"d1:x?1:t1:a1:y1:re".to_vec()),
            ("nested too deep", deep.into_bytes()),
            ("no transaction id", b"d1:y1:re".to_vec()),
            ("no message type", b"d1:t1:ae".to_vec()),
            ("unknown message type", b"d1:t1:a1:y1:xe".to_vec()),
            ("type is a dictionary", b"d1:t1:a1:yde1:re".to_vec()),
        ];
        for (what, bytes) in cases {
            assert!(parse(&bytes).is_err(), "{what}: {:?}", parse(&bytes));
        }
    }

    #[test]
    fn nothing_a_node_sends_can_panic_the_parser() {
        let valid = encode_reply(&ID, b"abcd", Some(addr("1.2.3.4:5000")));
        // Every byte of a valid reply replaced by a spread of values, and every prefix of it.
        for i in 0..valid.len() {
            for value in [0u8, b'0', b'9', b'-', b':', b'd', b'e', b'i', b'l', 0xff] {
                let mut mutated = valid.clone();
                mutated[i] = value;
                let _ = parse(&mutated);
            }
            let _ = parse(&valid[..i]);
        }
        // And a stream of pseudo-random datagrams.
        let mut state = 0x2545_f491_4f6c_dd1du64;
        for _ in 0..5000 {
            let len = (state % 120) as usize;
            let bytes: Vec<u8> = (0..len)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    // Biased toward the bytes bencode is made of.
                    b"dlei0123456789:-qryt"[(state % 20) as usize]
                })
                .collect();
            let _ = parse(&bytes);
        }
    }

    #[test]
    fn replies_to_a_ping_echo_its_transaction_id() {
        let ping = encode_ping(&ID, b"\x00\x01\x02\xff");
        let reply = reply_to_ping(&ping, addr("203.0.113.9:40000")).unwrap();
        let message = parse(&reply).unwrap();
        assert_eq!(message.kind, Kind::Response);
        assert_eq!(message.transaction_id, b"\x00\x01\x02\xff");
        assert_eq!(message.observed, Some(addr("203.0.113.9:40000")));
        // A mapped IPv6 requester is reported as the IPv4 address it is.
        let reply = reply_to_ping(&ping, addr("[::ffff:203.0.113.9]:40000")).unwrap();
        assert_eq!(parse(&reply).unwrap().observed, Some(addr("203.0.113.9:40000")));
        // Only pings get an answer.
        assert_eq!(reply_to_ping(&reply, addr("1.2.3.4:5")), None);
        assert_eq!(reply_to_ping(b"junk", addr("1.2.3.4:5")), None);
        assert_eq!(reply_to_ping(&find_node_query(), addr("1.2.3.4:5")), None);
    }

    // ---- DhtProbe ----

    fn answer(probe: &DhtProbe, node: SocketAddr, seen_as: Option<SocketAddr>) -> Vec<u8> {
        let ping = probe.pending().find(|(n, _)| *n == node).expect("pending ping").1;
        let t = parse(ping).unwrap().transaction_id.to_vec();
        encode_reply(&ID, &t, seen_as)
    }

    #[test]
    fn probe_pings_each_node_once_with_its_own_transaction_id() {
        let a = addr("198.51.100.1:6881");
        let b = addr("198.51.100.2:6881");
        let probe = DhtProbe::new(&[a, b, a, addr("[::ffff:198.51.100.1]:6881")]);
        let pings: Vec<_> = probe.pending().collect();
        assert_eq!(pings.len(), 2, "duplicates, mapped ones included, are dropped");
        assert_eq!(pings[0].0, a);
        assert_eq!(pings[1].0, b);
        let (t0, t1) = (parse(pings[0].1).unwrap().transaction_id, parse(pings[1].1).unwrap().transaction_id);
        assert_ne!(t0, t1);
        assert_eq!(t0.len(), 4);
        assert_eq!(DhtProbe::new(&[]).pending().count(), 0);
    }

    #[test]
    fn probe_takes_an_answer_from_the_node_asked() {
        let (a, b) = (addr("198.51.100.1:6881"), addr("198.51.100.2:6881"));
        let me = addr("203.0.113.7:50000");
        let mut probe = DhtProbe::new(&[a, b]);
        assert!(probe.handle(a, &answer(&probe, a, Some(me))));
        assert_eq!(probe.observations(), [Observation { from: a, endpoint: me }]);
        assert_eq!(probe.pending().map(|(n, _)| n).collect::<Vec<_>>(), [b], "an answered node is not pinged again");
        // The same answer twice (a retransmitted ping drew two) is consumed again but counted once.
        let again = encode_reply(&ID, &probe.pings[0].transaction_id, Some(me));
        assert!(probe.handle(a, &again));
        assert_eq!(probe.observations().len(), 1);
    }

    #[test]
    fn probe_accepts_the_mapped_form_of_a_node() {
        let a = addr("198.51.100.1:6881");
        let mut probe = DhtProbe::new(&[a]);
        let reply = answer(&probe, a, Some(addr("203.0.113.7:50000")));
        assert!(probe.handle(addr("[::ffff:198.51.100.1]:6881"), &reply));
        assert_eq!(probe.observations()[0].from, a);
    }

    #[test]
    fn probe_ignores_what_is_not_an_answer_to_it() {
        let (a, b) = (addr("198.51.100.1:6881"), addr("198.51.100.2:6881"));
        let me = Some(addr("203.0.113.7:50000"));
        let mut probe = DhtProbe::new(&[a, b]);
        let for_a = answer(&probe, a, me);
        // From a node we did not ask, or from the wrong one of the two.
        assert!(!probe.handle(addr("198.51.100.3:6881"), &for_a));
        assert!(!probe.handle(b, &for_a));
        // Wrong transaction id, garbage, a query, a QUIC-looking packet.
        assert!(!probe.handle(a, &encode_reply(&ID, b"zzzz", me)));
        assert!(!probe.handle(a, b"not bencode"));
        assert!(!probe.handle(a, &encode_ping(&ID, b"zzzz")));
        assert!(!probe.handle(a, &[0x40, 0x01, 0x02, 0x03]));
        assert!(probe.observations().is_empty());
        assert_eq!(probe.pending().count(), 2);
    }

    #[test]
    fn probe_consumes_answers_that_carry_no_address() {
        let (a, b) = (addr("198.51.100.1:6881"), addr("198.51.100.2:6881"));
        let mut probe = DhtProbe::new(&[a, b]);
        assert!(probe.handle(a, &answer(&probe, a, None)));
        let t = probe.pings[1].transaction_id;
        let error = [&b"d1:eli201e4:Oopse1:t4:"[..], &t, b"1:y1:ee"].concat();
        assert!(probe.handle(b, &error));
        assert!(probe.observations().is_empty());
        assert_eq!(probe.pending().count(), 0, "both answered, neither gave an address");
    }

    #[test]
    fn ipv4_nodes_are_reached_through_their_mapped_form_from_an_ipv6_socket() {
        let v4 = addr("198.51.100.1:6881");
        let v6 = addr("[2001:db8::1]:6881");
        assert_eq!(for_socket(false, v4), Some(v4));
        assert_eq!(for_socket(false, v6), None);
        assert_eq!(for_socket(true, v6), Some(v6));
        assert_eq!(for_socket(true, v4), Some(addr("[::ffff:198.51.100.1]:6881")));
    }

    // ---- NAT type ----

    fn seen(server: &str, endpoint: &str) -> Observation {
        Observation { from: addr(server), endpoint: addr(endpoint) }
    }

    #[test]
    fn nat_is_classified_from_what_the_servers_saw() {
        let me = addr("192.168.1.20:50000");
        let (a, b, c) = ("198.51.100.1:6881", "198.51.100.2:6881", "198.51.100.3:19302");
        // Same external endpoint from different servers: a cone NAT, whether or not it keeps the port.
        let same = [seen(a, "203.0.113.7:50000"), seen(b, "203.0.113.7:50000"), seen(c, "203.0.113.7:50000")];
        assert_eq!(classify_nat(me, &same), NatType::EndpointIndependent);
        let renumbered = [seen(a, "203.0.113.7:61234"), seen(b, "203.0.113.7:61234")];
        assert_eq!(classify_nat(me, &renumbered), NatType::EndpointIndependent);
        // The port changes with the destination: symmetric.
        let ports = [seen(a, "203.0.113.7:50000"), seen(b, "203.0.113.7:50001"), seen(c, "203.0.113.7:50002")];
        assert_eq!(classify_nat(me, &ports), NatType::Dependent);
        // The address changes with the destination (a carrier pool): also dependent.
        let ips = [seen(a, "203.0.113.7:50000"), seen(b, "203.0.113.8:50000")];
        assert_eq!(classify_nat(me, &ips), NatType::Dependent);
        // One dissenting server is enough: nothing is guessed from a majority.
        let odd = [seen(a, "203.0.113.7:50000"), seen(b, "203.0.113.7:50000"), seen(c, "203.0.113.7:50001")];
        assert_eq!(classify_nat(me, &odd), NatType::Dependent);
    }

    #[test]
    fn nat_is_open_when_the_servers_saw_the_socket_itself() {
        let me = addr("198.51.100.77:50000");
        let open = [seen("198.51.100.1:6881", "198.51.100.77:50000"), seen("198.51.100.2:6881", "198.51.100.77:50000")];
        assert_eq!(classify_nat(me, &open), NatType::Open);
        // One server is enough to see that nothing translates the socket.
        assert_eq!(classify_nat(me, &open[..1]), NatType::Open);
        // The same address with another port is a NAT that renumbers the port, not an open socket.
        let renumbered =
            [seen("198.51.100.1:6881", "198.51.100.77:50001"), seen("198.51.100.2:6881", "198.51.100.77:50001")];
        assert_eq!(classify_nat(me, &renumbered), NatType::EndpointIndependent);
        // A mapped local address is compared as the IPv4 address.
        assert_eq!(classify_nat(addr("[::ffff:198.51.100.77]:50000"), &open), NatType::Open);
        // Another address of the PC is not the one the servers saw.
        assert_eq!(classify_nat(addr("192.168.1.20:50000"), &open), NatType::EndpointIndependent);
        // Seen as open by one server and translated by another is a mapping that depends on the destination.
        let mixed = [seen("198.51.100.1:6881", "198.51.100.77:50000"), seen("198.51.100.2:6881", "203.0.113.7:50000")];
        assert_eq!(classify_nat(me, &mixed), NatType::Dependent);
    }

    #[test]
    fn a_socket_bound_to_a_wildcard_address_is_its_own_at_every_address_of_the_pc() {
        // Loopback is an address of any PC; 203.0.113.7 (documentation range) is one of none.
        let own = [seen("198.51.100.1:6881", "127.0.0.1:50000"), seen("198.51.100.2:6881", "127.0.0.1:50000")];
        let natted = [seen("198.51.100.1:6881", "203.0.113.7:50000"), seen("198.51.100.2:6881", "203.0.113.7:50000")];
        let renumbered = [seen("198.51.100.1:6881", "127.0.0.1:50001"), seen("198.51.100.2:6881", "127.0.0.1:50001")];
        for wildcard in ["0.0.0.0:50000", "[::]:50000"] {
            let wildcard = addr(wildcard);
            assert_eq!(classify_nat(wildcard, &own), NatType::Open, "{wildcard}");
            assert_eq!(classify_nat(wildcard, &natted), NatType::EndpointIndependent, "{wildcard}");
            assert_eq!(classify_nat(wildcard, &renumbered), NatType::EndpointIndependent, "{wildcard}");
        }
    }

    #[test]
    fn nat_is_unknown_without_two_servers() {
        let me = addr("192.168.1.20:50000");
        assert_eq!(classify_nat(me, &[]), NatType::Unknown);
        let one = [seen("198.51.100.1:6881", "203.0.113.7:50000")];
        assert_eq!(classify_nat(me, &one), NatType::Unknown);
        // Two ports of one machine are one server: the mapping might depend on the address only.
        let same_host =
            [seen("198.51.100.1:6881", "203.0.113.7:50000"), seen("198.51.100.1:19302", "203.0.113.7:50000")];
        assert_eq!(classify_nat(me, &same_host), NatType::Unknown);
    }

    #[test]
    fn nat_names() {
        assert_eq!(NatType::Open.to_string(), "open");
        assert_eq!(NatType::EndpointIndependent.to_string(), "endpoint-independent");
        assert_eq!(NatType::Dependent.to_string(), "dependent");
        assert_eq!(NatType::Unknown.to_string(), "unknown");
    }

    #[test]
    fn observed_picks_the_endpoint_most_servers_agree_on() {
        let local = addr("192.168.1.20:50000");
        let a = "198.51.100.1:6881";
        assert!(Observed::new(local, vec![]).is_none());
        let obs = vec![
            seen(a, "203.0.113.7:1"),
            seen("198.51.100.2:6881", "203.0.113.7:2"),
            seen("198.51.100.3:6881", "203.0.113.7:2"),
        ];
        let observed = Observed::new(local, obs.clone()).unwrap();
        assert_eq!(observed.endpoint, addr("203.0.113.7:2"));
        assert_eq!(observed.nat, NatType::Dependent);
        assert_eq!(observed.observations, obs);
        // A tie goes to the one heard first.
        let tie =
            Observed::new(local, vec![seen(a, "203.0.113.7:1"), seen("198.51.100.2:6881", "203.0.113.7:2")]).unwrap();
        assert_eq!(tie.endpoint, addr("203.0.113.7:1"));
    }

    #[test]
    fn resolve_keeps_numeric_addresses_and_skips_names_that_fail() {
        let names = ["127.0.0.1:6881", "[::1]:6881", "no-port-here", "127.0.0.1:6881"];
        assert_eq!(resolve(&names), [addr("127.0.0.1:6881"), addr("[::1]:6881")]);
        assert!(resolve::<&str>(&[]).is_empty());
    }

    // ---- over real sockets, on the loopback interface ----

    /// How a fake DHT node answers.
    enum Behavior {
        /// Reports the address the ping came from, as a real node does.
        Honest,
        /// Reports this address instead: a NAT in front of the client.
        Claims(SocketAddr),
        /// Answers but leaves out the `ip` field, like a node that predates BEP 42.
        NoIp,
        /// Answers with something that is not a KRPC message.
        Garbage,
        /// Never answers.
        Silent,
    }

    struct FakeNode {
        addr: SocketAddr,
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
    }

    impl FakeNode {
        /// Listens on 127.0.0.`last_octet`, so that nodes have distinct IPs.
        fn start(last_octet: u8, behavior: Behavior) -> FakeNode {
            let socket = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, last_octet), 0)).unwrap();
            socket.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
            let addr = socket.local_addr().unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let flag = stop.clone();
            let thread = std::thread::spawn(move || {
                let mut buf = [0u8; 2048];
                while !flag.load(Ordering::Relaxed) {
                    let Ok((len, from)) = socket.recv_from(&mut buf) else { continue };
                    let ping = &buf[..len];
                    let reply = match &behavior {
                        Behavior::Honest => reply_to_ping(ping, from),
                        Behavior::Claims(claimed) => reply_to_ping(ping, *claimed),
                        Behavior::NoIp => parse(ping).ok().map(|m| encode_reply(&ID, m.transaction_id, None)),
                        Behavior::Garbage => Some(b"this is not bencode".to_vec()),
                        Behavior::Silent => None,
                    };
                    if let Some(reply) = reply {
                        let _ = socket.send_to(&reply, from);
                    }
                }
            });
            FakeNode { addr, stop, thread: Some(thread) }
        }
    }

    impl Drop for FakeNode {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    fn client() -> UdpSocket {
        UdpSocket::bind("127.0.0.1:0").unwrap()
    }

    const SHORT: Duration = Duration::from_millis(600);

    #[test]
    fn dht_nodes_that_see_the_socket_itself_make_it_open() {
        let nodes = [
            FakeNode::start(2, Behavior::Honest),
            FakeNode::start(3, Behavior::Honest),
            FakeNode::start(4, Behavior::Honest),
        ];
        let socket = client();
        let addrs: Vec<_> = nodes.iter().map(|n| n.addr).collect();
        let started = Instant::now();
        let observed = observe(&socket, &addrs, &[], DEFAULT_WAIT).unwrap();
        assert!(started.elapsed() < Duration::from_secs(2), "returns as soon as the nodes answered");
        assert_eq!(observed.observations.len(), 3);
        assert_eq!(observed.endpoint, socket.local_addr().unwrap());
        assert_eq!(observed.nat, NatType::Open);
        for (observation, node) in observed.observations.iter().zip(&nodes) {
            assert_eq!(observation.endpoint, socket.local_addr().unwrap());
            assert!(addrs.contains(&observation.from), "{} from {}", observation.endpoint, node.addr);
        }
    }

    #[test]
    fn dht_nodes_behind_a_cone_nat_show_one_endpoint() {
        let mapped = addr("203.0.113.7:61000");
        let nodes = [
            FakeNode::start(2, Behavior::Claims(mapped)),
            FakeNode::start(3, Behavior::Claims(mapped)),
            FakeNode::start(4, Behavior::Claims(mapped)),
        ];
        let addrs: Vec<_> = nodes.iter().map(|n| n.addr).collect();
        let observed = observe(&client(), &addrs, &[], SHORT).unwrap();
        assert_eq!(observed.endpoint, mapped);
        assert_eq!(observed.nat, NatType::EndpointIndependent);
    }

    #[test]
    fn dht_nodes_behind_a_symmetric_nat_show_a_port_each() {
        let nodes = [
            FakeNode::start(2, Behavior::Claims(addr("203.0.113.7:61000"))),
            FakeNode::start(3, Behavior::Claims(addr("203.0.113.7:61001"))),
            FakeNode::start(4, Behavior::Claims(addr("203.0.113.7:61002"))),
        ];
        let addrs: Vec<_> = nodes.iter().map(|n| n.addr).collect();
        let observed = observe(&client(), &addrs, &[], SHORT).unwrap();
        assert_eq!(observed.observations.len(), 3);
        assert_eq!(observed.nat, NatType::Dependent);
    }

    #[test]
    fn silent_broken_and_old_nodes_do_not_stop_the_good_ones() {
        let mapped = addr("203.0.113.7:61000");
        let nodes = [
            FakeNode::start(2, Behavior::Silent),
            FakeNode::start(3, Behavior::Garbage),
            FakeNode::start(4, Behavior::NoIp),
            FakeNode::start(5, Behavior::Claims(mapped)),
        ];
        let addrs: Vec<_> = nodes.iter().map(|n| n.addr).collect();
        let found = observe_dht(&client(), &addrs, SHORT).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0], Observation { from: nodes[3].addr, endpoint: mapped });
    }

    #[test]
    fn two_answers_do_not_wait_for_a_node_that_never_answers() {
        let mapped = addr("203.0.113.7:61000");
        let nodes = [
            FakeNode::start(2, Behavior::Claims(mapped)),
            FakeNode::start(3, Behavior::Claims(mapped)),
            FakeNode::start(4, Behavior::Silent),
        ];
        let addrs: Vec<_> = nodes.iter().map(|n| n.addr).collect();
        let started = Instant::now();
        let found = observe_dht(&client(), &addrs, DEFAULT_WAIT).unwrap();
        assert_eq!(found.len(), 2);
        assert!(started.elapsed() < Duration::from_millis(1500), "{:?}", started.elapsed());
    }

    #[test]
    fn nobody_answering_is_an_error_not_a_hang() {
        let nodes = [FakeNode::start(2, Behavior::Silent), FakeNode::start(3, Behavior::Garbage)];
        let addrs: Vec<_> = nodes.iter().map(|n| n.addr).collect();
        let started = Instant::now();
        let error = observe(&client(), &addrs, &[], Duration::from_millis(400)).unwrap_err();
        assert!(matches!(error, ObserveError::NoAnswer { asked: 2 }), "{error}");
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(observe_dht(&client(), &[], SHORT).unwrap().is_empty());
    }

    #[test]
    fn a_lost_first_ping_is_sent_again() {
        // The node ignores the first ping and answers the second.
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let node = socket.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            let _lost = socket.recv_from(&mut buf).unwrap();
            let (len, from) = socket.recv_from(&mut buf).unwrap();
            let reply = reply_to_ping(&buf[..len], addr("203.0.113.7:61000")).unwrap();
            socket.send_to(&reply, from).unwrap();
        });
        let found = observe_dht(&client(), &[node], Duration::from_secs(3)).unwrap();
        server.join().unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].endpoint, addr("203.0.113.7:61000"));
    }

    #[test]
    fn the_socket_keeps_its_read_timeout_and_stays_usable() {
        let node = FakeNode::start(2, Behavior::Honest);
        let socket = client();
        socket.set_read_timeout(Some(Duration::from_millis(1234))).unwrap();
        observe_dht(&socket, &[node.addr], SHORT).unwrap();
        assert_eq!(socket.read_timeout().unwrap(), Some(Duration::from_millis(1234)));
        // A non-blocking socket is handled too (it would otherwise make the loop spin).
        let socket = client();
        socket.set_nonblocking(true).unwrap();
        let found = observe_dht(&socket, &[node.addr], SHORT).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(socket.read_timeout().unwrap(), None);
    }

    #[test]
    fn an_ipv4_socket_skips_ipv6_nodes() {
        let node = FakeNode::start(2, Behavior::Honest);
        let found = observe_dht(&client(), &[addr("[2001:db8::1]:6881"), node.addr], SHORT).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].from, node.addr);
    }

    #[test]
    fn an_ipv4_socket_given_only_ipv6_nodes_returns_at_once() {
        let started = Instant::now();
        let found = observe_dht(&client(), &[addr("[2001:db8::1]:6881")], DEFAULT_WAIT).unwrap();
        assert!(found.is_empty());
        assert!(started.elapsed() < Duration::from_millis(500), "{:?}", started.elapsed());
    }

    #[test]
    fn nothing_sent_is_an_io_error() {
        // A socket without SO_BROADCAST is refused a send to the broadcast address, on every OS.
        let broadcast = addr("255.255.255.255:6881");
        let error = observe_dht(&client(), &[broadcast], Duration::from_millis(300)).unwrap_err();
        assert!(matches!(error, ObserveError::Io(_)), "{error}");
        let error = observe(&client(), &[broadcast], &[], Duration::from_millis(300)).unwrap_err();
        assert!(matches!(error, ObserveError::Io(_)), "{error}");
    }

    #[test]
    fn an_endless_wait_does_not_overflow_the_clock() {
        let node = FakeNode::start(2, Behavior::Honest);
        assert_eq!(observe_dht(&client(), &[node.addr], Duration::MAX).unwrap().len(), 1);
        let stun = fake_stun(3, "203.0.113.7:61000".parse().unwrap());
        assert_eq!(observe_stun(&client(), &[stun.addr], Duration::MAX).unwrap().len(), 1);
    }

    /// A STUN server that always reports `mapped` (XOR-MAPPED-ADDRESS, RFC 5389).
    fn fake_stun(last_octet: u8, mapped: std::net::SocketAddrV4) -> FakeNode {
        let socket = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, last_octet), 0)).unwrap();
        socket.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
        let addr = socket.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let thread = std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            while !flag.load(Ordering::Relaxed) {
                let Ok((len, from)) = socket.recv_from(&mut buf) else { continue };
                // A binding request: type 0x0001, then the magic cookie and a 12-byte transaction id.
                if len < 20 || buf[..2] != [0x00, 0x01] {
                    continue;
                }
                let mut reply = vec![0x01, 0x01, 0x00, 0x0c];
                reply.extend_from_slice(&buf[4..20]);
                reply.extend_from_slice(&[0x00, 0x20, 0x00, 0x08, 0x00, 0x01]);
                reply.extend_from_slice(&(mapped.port() ^ 0x2112).to_be_bytes());
                reply.extend_from_slice(&(u32::from(*mapped.ip()) ^ 0x2112_a442).to_be_bytes());
                let _ = socket.send_to(&reply, from);
            }
        });
        FakeNode { addr, stop, thread: Some(thread) }
    }

    #[test]
    fn stun_servers_are_asked_through_stunclient() {
        let mapped = "203.0.113.7:61000".parse().unwrap();
        let servers = [fake_stun(2, mapped), fake_stun(3, mapped)];
        let addrs: Vec<_> = servers.iter().map(|s| s.addr).collect();
        let socket = client();
        let found = observe_stun(&socket, &addrs, SHORT).unwrap();
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|o| o.endpoint == SocketAddr::V4(mapped)));
        assert_eq!(found[0].from, addrs[0]);
        assert_eq!(socket.read_timeout().unwrap(), None);
    }

    #[test]
    fn stun_takes_over_when_the_dht_is_silent() {
        let mapped = "203.0.113.7:61000".parse().unwrap();
        let dht = FakeNode::start(2, Behavior::Silent);
        let stun = [fake_stun(3, mapped), fake_stun(4, mapped)];
        let stun_addrs: Vec<_> = stun.iter().map(|s| s.addr).collect();
        let observed = observe(&client(), &[dht.addr], &stun_addrs, Duration::from_millis(800)).unwrap();
        assert_eq!(observed.endpoint, SocketAddr::V4(mapped));
        assert_eq!(observed.nat, NatType::EndpointIndependent);
        assert_eq!(observed.observations.len(), 2);
    }

    #[test]
    fn stun_is_not_asked_when_the_dht_answered_enough() {
        let mapped = addr("203.0.113.7:61000");
        let dht = [FakeNode::start(2, Behavior::Claims(mapped)), FakeNode::start(3, Behavior::Claims(mapped))];
        let dht_addrs: Vec<_> = dht.iter().map(|n| n.addr).collect();
        // A STUN server that would report something else: it must not be reached.
        let stun = fake_stun(4, "198.51.100.9:1".parse().unwrap());
        let observed = observe(&client(), &dht_addrs, &[stun.addr], SHORT).unwrap();
        assert_eq!(observed.observations.len(), 2);
        assert_eq!(observed.endpoint, mapped);
    }

    /// Asks the real DHT and STUN servers from this PC and prints what they saw:
    /// `cargo test -p velora-nat observe::tests::print_this_pc -- --ignored --nocapture`.
    /// Only ordinary DHT pings and STUN binding requests leave the PC. Windows may ask to allow
    /// the test program through its firewall.
    #[test]
    #[ignore = "uses the internet"]
    fn print_this_pc() {
        let dht_nodes = default_dht_nodes();
        let stun_servers = default_stun_servers();
        println!("DHT nodes: {dht_nodes:?}");
        println!("STUN servers: {stun_servers:?}");

        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        let started = Instant::now();
        let found = observe_dht(&socket, &dht_nodes, DEFAULT_WAIT);
        show("DHT only", &socket, found, started);

        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        let started = Instant::now();
        let found = observe_stun(&socket, &stun_servers, DEFAULT_WAIT);
        show("STUN only", &socket, found, started);

        // Both kinds of server from one socket: the stronger test of the NAT, and the two must agree.
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        let started = Instant::now();
        let both = observe_dht(&socket, &dht_nodes, DEFAULT_WAIT).and_then(|mut found| {
            found.extend(observe_stun(&socket, &stun_servers, DEFAULT_WAIT)?);
            Ok(found)
        });
        show("DHT and STUN on one socket", &socket, both, started);

        // What a caller gets in one call.
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        let started = Instant::now();
        match observe(&socket, &dht_nodes, &stun_servers, DEFAULT_WAIT) {
            Ok(o) => println!("--- observe(): {} NAT {} after {:?}", o.endpoint, o.nat, started.elapsed()),
            Err(e) => println!("--- observe() failed after {:?}: {e}", started.elapsed()),
        }
    }

    fn show(label: &str, socket: &UdpSocket, found: Result<Vec<Observation>, ObserveError>, started: Instant) {
        let local = socket.local_addr().unwrap();
        println!("--- {label}, from {local}, took {:?}", started.elapsed());
        match found {
            Ok(found) => {
                for o in &found {
                    println!("  {} sees us as {}", o.from, o.endpoint);
                }
                match Observed::new(local, found) {
                    Some(o) => {
                        let class = crate::addresses::classify(o.endpoint.ip());
                        println!("  endpoint {} ({class:?}), NAT {}", o.endpoint, o.nat);
                    }
                    None => println!("  nobody answered"),
                }
            }
            Err(e) => println!("  failed: {e}"),
        }
    }
}
