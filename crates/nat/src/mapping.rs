//! Router port mapping through NAT-PMP and UPnP IGD.
//!
//! [`map_udp`] asks the router to forward a UDP port to this PC (NAT-PMP first, UPnP second) and
//! says which address and port the outside world has to use. [`renew`] asks again before the lease
//! ends and [`remove`] gives the port back. Whether the address is reachable is not decided here:
//! a router behind another NAT reports a private or shared (100.64.0.0/10) address, and that is
//! returned as it is for the caller to classify.
//!
//! ```no_run
//! # async fn host() -> Result<(), velora_nat::mapping::MappingError> {
//! use std::time::Duration;
//! use velora_nat::mapping;
//!
//! let mut mapping = mapping::map_udp(7420, 7420, Duration::from_secs(3600)).await?;
//! // ... advertise mapping.external_addr(), and now and then:
//! tokio::time::sleep(mapping.renew_after()).await;
//! mapping = mapping::renew(&mapping).await?;
//! // ... and on the way out:
//! mapping::remove(&mapping).await?;
//! # Ok(())
//! # }
//! ```
//!
//! Every call is bounded: about 3 s to find the gateway and 5 s per protocol in all. A router that
//! stays silent, refuses or answers nonsense is an `Err` (and a log line), never a panic. When both
//! protocols fail the error carries both reasons. The calls need a Tokio runtime.
//!
//! The wanted external port is tried first even where the router could choose one (IGDv2
//! `AddAnyPortMapping`): `igd-next` offers that call only with a random suggestion, and a stable
//! port keeps the addresses already stored in paired devices valid across restarts. The router
//! chooses (or the next port is tried) only when the wanted one is taken.
//!
//! UPnP does not report the lease it granted, so a UPnP [`Mapping`] carries the lease asked for.
//! A router that keeps only permanent mappings gets lease 0 on the wire, and the caller should
//! keep renewing as if it had a lease: that also puts the mapping back after a router restart.

use std::fmt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket as StdUdpSocket};
use std::time::Duration;

use igd_next::aio::tokio::{search_gateway, Tokio};
use igd_next::aio::Gateway;
use igd_next::{
    AddAnyPortError, AddPortError, GatewayIpVersion, GetExternalIpError, PortMappingProtocol, RemovePortError,
    SearchError, SearchOptions,
};
use tokio::net::UdpSocket;
use tokio::time::{timeout, Instant};

/// How the mapping was made; [`renew`] and [`remove`] go back to the same protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MappingProtocol {
    NatPmp,
    Upnp,
}

impl fmt::Display for MappingProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            MappingProtocol::NatPmp => "NAT-PMP",
            MappingProtocol::Upnp => "UPnP",
        })
    }
}

/// A UDP port of this PC that the router forwards from the outside.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapping {
    pub protocol: MappingProtocol,
    /// The port on this PC. NAT-PMP needs it to renew and to remove.
    pub local_port: u16,
    /// The router's address on its outside, as the router reports it.
    pub external_ip: IpAddr,
    /// The port on `external_ip` that reaches `local_port`; not always the one asked for.
    pub external_port: u16,
    /// How long the router keeps the mapping without a renewal.
    pub lease: Duration,
}

impl Mapping {
    pub fn external_addr(&self) -> SocketAddr {
        SocketAddr::new(self.external_ip, self.external_port)
    }

    /// When to call [`renew`]: half the lease, as RFC 6886 recommends, so that one lost request is not fatal.
    pub fn renew_after(&self) -> Duration {
        (self.lease / 2).max(Duration::from_secs(1))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MappingError {
    #[error("invalid request: {0}")]
    InvalidRequest(&'static str),
    /// Neither protocol did it; each reason says why in a sentence.
    #[error("no router mapped the port (NAT-PMP: {natpmp}; UPnP: {upnp})")]
    Failed { natpmp: String, upnp: String },
    /// The mapping stays until its lease ends.
    #[error("{protocol} could not remove the mapping: {reason}")]
    RemoveFailed { protocol: MappingProtocol, reason: String },
}

/// Ask for `wanted_external` (0: the same number as `local_port`) to be forwarded to `local_port`
/// for `lease`. The router may grant another port and a shorter lease: the [`Mapping`] says.
pub async fn map_udp(local_port: u16, wanted_external: u16, lease: Duration) -> Result<Mapping, MappingError> {
    let request = Request::new(local_port, wanted_external, lease)?;
    let (natpmp, upnp) = system().await;
    map_in_order(&natpmp, &upnp, &request, TIMEOUTS.total).await
}

/// Ask again for what `mapping` was, through the protocol that made it and then the other one. The
/// answer can differ (another port, another external address after a router restart or a new
/// network): use the returned mapping from then on.
pub async fn renew(mapping: &Mapping) -> Result<Mapping, MappingError> {
    let request = Request::renewing(mapping)?;
    let (natpmp, upnp) = system().await;
    match mapping.protocol {
        MappingProtocol::NatPmp => map_in_order(&natpmp, &upnp, &request, TIMEOUTS.total).await,
        MappingProtocol::Upnp => map_in_order(&upnp, &natpmp, &request, TIMEOUTS.total).await,
    }
}

/// Give the port back. A mapping the router no longer has counts as removed.
pub async fn remove(mapping: &Mapping) -> Result<(), MappingError> {
    let (natpmp, upnp) = system().await;
    match mapping.protocol {
        MappingProtocol::NatPmp => remove_with(&natpmp, mapping, TIMEOUTS.total).await,
        MappingProtocol::Upnp => remove_with(&upnp, mapping, TIMEOUTS.total).await,
    }
}

#[derive(Clone, Copy)]
struct Timeouts {
    /// Finding the gateway and getting a first answer from it.
    discovery: Duration,
    /// One protocol, discovery included.
    total: Duration,
}

const TIMEOUTS: Timeouts = Timeouts { discovery: Duration::from_secs(3), total: Duration::from_secs(5) };

/// RFC 6886 section 3.1: wait this long for the first answer and twice as long after each retry.
const NATPMP_FIRST_WAIT: Duration = Duration::from_millis(250);

/// Requests to a UPnP router before giving up on a port that keeps being taken.
const MAX_ATTEMPTS: usize = 10;

const DESCRIPTION: &str = "Velora";

#[derive(Debug, Clone, PartialEq, Eq)]
struct Request {
    local_port: u16,
    wanted_external: u16,
    lease_secs: u32,
}

impl Request {
    fn new(local_port: u16, wanted_external: u16, lease: Duration) -> Result<Request, MappingError> {
        if local_port == 0 {
            return Err(MappingError::InvalidRequest("the local port is 0"));
        }
        // A lifetime of 0 means "delete" to NAT-PMP and "forever" to UPnP: never by accident.
        if lease < Duration::from_secs(1) {
            return Err(MappingError::InvalidRequest("the lease is shorter than a second"));
        }
        Ok(Request {
            local_port,
            wanted_external: if wanted_external == 0 { local_port } else { wanted_external },
            lease_secs: lease.as_secs().min(u32::MAX.into()) as u32,
        })
    }

    /// A renewal asks for the port it has, so that a router which still has the mapping just extends it.
    fn renewing(mapping: &Mapping) -> Result<Request, MappingError> {
        Request::new(mapping.local_port, mapping.external_port, mapping.lease)
    }
}

/// What a protocol got from the router.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Granted {
    external_ip: IpAddr,
    external_port: u16,
    lease: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
enum Failure {
    #[error("no answer within {0:?}")]
    TimedOut(Duration),
    /// The protocol is not there: no gateway, no reply, not NAT-PMP, no UPnP router.
    #[error("{0}")]
    Unavailable(String),
    /// The router answered and said no.
    #[error("{0}")]
    Refused(String),
    /// Socket trouble or an answer that makes no sense.
    #[error("{0}")]
    Broken(String),
}

impl Failure {
    /// Not having a protocol is routine; being refused is worth a line; a broken exchange is a warning.
    fn log(&self, protocol: MappingProtocol, action: &str) {
        match self {
            Failure::TimedOut(_) | Failure::Unavailable(_) => tracing::debug!("{protocol} {action} failed: {self}"),
            Failure::Refused(_) => tracing::info!("{protocol} {action} failed: {self}"),
            Failure::Broken(_) => tracing::warn!("{protocol} {action} failed: {self}"),
        }
    }
}

/// One way of asking a router for a port. Private, so that tests can put a fake router in its place.
trait Mapper: Send + Sync {
    fn protocol(&self) -> MappingProtocol;
    fn map(&self, request: &Request) -> impl Future<Output = Result<Granted, Failure>> + Send;
    fn remove(&self, mapping: &Mapping) -> impl Future<Output = Result<(), Failure>> + Send;
}

/// Try `first`, then `second`; each gets the whole `total` to itself.
async fn map_in_order<A: Mapper, B: Mapper>(
    first: &A,
    second: &B,
    request: &Request,
    total: Duration,
) -> Result<Mapping, MappingError> {
    let first_failure = match attempt(first, request, total).await {
        Ok(mapping) => return Ok(mapping),
        Err(failure) => failure,
    };
    match attempt(second, request, total).await {
        Ok(mapping) => Ok(mapping),
        Err(second_failure) => {
            let (mut natpmp, mut upnp) = (String::new(), String::new());
            for (protocol, failure) in [(first.protocol(), first_failure), (second.protocol(), second_failure)] {
                match protocol {
                    MappingProtocol::NatPmp => natpmp = failure.to_string(),
                    MappingProtocol::Upnp => upnp = failure.to_string(),
                }
            }
            Err(MappingError::Failed { natpmp, upnp })
        }
    }
}

async fn attempt<M: Mapper>(mapper: &M, request: &Request, total: Duration) -> Result<Mapping, Failure> {
    let protocol = mapper.protocol();
    tracing::debug!("{protocol}: mapping UDP {} to external {}", request.local_port, request.wanted_external);
    let granted = match timeout(total, mapper.map(request)).await {
        Ok(Ok(granted)) => granted,
        Ok(Err(failure)) => {
            failure.log(protocol, "mapping");
            return Err(failure);
        }
        Err(_) => {
            let failure = Failure::TimedOut(total);
            failure.log(protocol, "mapping");
            return Err(failure);
        }
    };
    let mapping = Mapping {
        protocol,
        local_port: request.local_port,
        external_ip: granted.external_ip,
        external_port: granted.external_port,
        lease: granted.lease,
    };
    tracing::info!(
        "{protocol} mapped UDP {} to {} for {} s",
        mapping.local_port,
        mapping.external_addr(),
        mapping.lease.as_secs()
    );
    Ok(mapping)
}

async fn remove_with<M: Mapper>(mapper: &M, mapping: &Mapping, total: Duration) -> Result<(), MappingError> {
    let protocol = mapper.protocol();
    let failure = match timeout(total, mapper.remove(mapping)).await {
        Ok(Ok(())) => {
            tracing::info!("{protocol} removed the mapping of UDP {}", mapping.local_port);
            return Ok(());
        }
        Ok(Err(failure)) => failure,
        Err(_) => Failure::TimedOut(total),
    };
    failure.log(protocol, "removal");
    Err(MappingError::RemoveFailed { protocol, reason: failure.to_string() })
}

// ---------------------------------------------------------------------------------------------
// This PC's side: the gateway and the address the router knows us by.

/// The two protocols as they run on this PC. The gateway is looked up once for both.
async fn system() -> (NatPmp, Upnp) {
    let gateway = default_gateway(TIMEOUTS.discovery).await;
    let search = Search::towards(gateway.as_ref().ok().copied());
    (NatPmp { gateway, port: natpmp::NATPMP_PORT, timeouts: TIMEOUTS }, Upnp { search, timeouts: TIMEOUTS })
}

async fn default_gateway(limit: Duration) -> Result<Ipv4Addr, String> {
    // netdev walks every adapter and may wait on ARP for the gateway's MAC: off the async threads, and bounded.
    match timeout(limit, tokio::task::spawn_blocking(natpmp::get_default_gateway)).await {
        Ok(Ok(Ok(gateway))) => Ok(gateway),
        Ok(Ok(Err(e))) => Err(format!("no default gateway: {e}")),
        Ok(Err(e)) => Err(format!("looking for the default gateway failed: {e}")),
        Err(_) => Err(format!("looking for the default gateway took more than {limit:?}")),
    }
}

/// The address of this PC that `remote` sees. Connecting a UDP socket only makes the OS pick the
/// route, so nothing is sent.
fn local_ip_towards(remote: IpAddr) -> io::Result<IpAddr> {
    let any =
        if remote.is_ipv4() { IpAddr::V4(Ipv4Addr::UNSPECIFIED) } else { IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED) };
    let socket = StdUdpSocket::bind((any, 0))?;
    socket.connect((remote, 9))?;
    Ok(socket.local_addr()?.ip())
}

// ---------------------------------------------------------------------------------------------
// NAT-PMP (RFC 6886): UDP 5351 on the default gateway.

struct NatPmp {
    /// Why there is none, when there is none.
    gateway: Result<Ipv4Addr, String>,
    /// 5351; tests aim it at a fake router on loopback.
    port: u16,
    timeouts: Timeouts,
}

enum Ask {
    Address,
    Mapping { local_port: u16, external_port: u16, lifetime_secs: u32 },
}

impl Ask {
    async fn send(&self, client: &mut natpmp::NatpmpAsync<UdpSocket>) -> natpmp::Result<()> {
        match *self {
            Ask::Address => client.send_public_address_request().await,
            Ask::Mapping { local_port, external_port, lifetime_secs } => {
                client.send_port_mapping_request(natpmp::Protocol::UDP, local_port, external_port, lifetime_secs).await
            }
        }
    }
}

impl NatPmp {
    fn gateway(&self) -> Result<Ipv4Addr, Failure> {
        self.gateway.clone().map_err(Failure::Unavailable)
    }

    /// One question and its answer, on a socket of its own so that no stray answer can be taken for
    /// this one. `natpmp` neither times out nor retransmits, so that is done here.
    async fn ask(&self, gateway: Ipv4Addr, ask: Ask, budget: Duration) -> Result<natpmp::Response, Failure> {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .await
            .map_err(|e| Failure::Broken(format!("cannot open a UDP socket: {e}")))?;
        socket
            .connect((gateway, self.port))
            .await
            .map_err(|e| Failure::Unavailable(format!("cannot reach the gateway {gateway}: {e}")))?;
        let mut client = natpmp::new_natpmp_async_with(socket, gateway);

        let deadline = Instant::now() + budget;
        let mut wait = NATPMP_FIRST_WAIT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(Failure::TimedOut(budget));
            }
            ask.send(&mut client)
                .await
                .map_err(|e| Failure::Unavailable(format!("cannot reach the gateway {gateway}: {e}")))?;
            match timeout(wait.min(left), client.read_response_or_retry()).await {
                Ok(answer) => return answer.map_err(Failure::from),
                Err(_) => wait *= 2,
            }
        }
    }
}

impl Mapper for NatPmp {
    fn protocol(&self) -> MappingProtocol {
        MappingProtocol::NatPmp
    }

    async fn map(&self, request: &Request) -> Result<Granted, Failure> {
        let started = Instant::now();
        let gateway = self.gateway()?;

        // The mapping answer has no external address, and a gateway that answers this one speaks NAT-PMP.
        let external_ip = match self.ask(gateway, Ask::Address, self.timeouts.discovery).await? {
            natpmp::Response::Gateway(answer) => IpAddr::V4(*answer.public_address()),
            other => return Err(unexpected(&other)),
        };
        if external_ip.is_unspecified() {
            return Err(Failure::Unavailable("the router has no external address yet".into()));
        }

        let ask = Ask::Mapping {
            local_port: request.local_port,
            external_port: request.wanted_external,
            lifetime_secs: request.lease_secs,
        };
        let left = self.timeouts.total.saturating_sub(started.elapsed());
        match self.ask(gateway, ask, left).await? {
            natpmp::Response::UDP(answer) if answer.private_port() == request.local_port => {
                if answer.public_port() == 0 || answer.lifetime().is_zero() {
                    return Err(Failure::Refused("the router granted no port or no lease".into()));
                }
                Ok(Granted { external_ip, external_port: answer.public_port(), lease: *answer.lifetime() })
            }
            other => Err(unexpected(&other)),
        }
    }

    async fn remove(&self, mapping: &Mapping) -> Result<(), Failure> {
        let gateway = self.gateway()?;
        // RFC 6886 section 3.4: lifetime 0 and external port 0 delete the mapping of that internal port.
        let ask = Ask::Mapping { local_port: mapping.local_port, external_port: 0, lifetime_secs: 0 };
        match self.ask(gateway, ask, self.timeouts.total).await? {
            natpmp::Response::UDP(answer) if answer.private_port() == mapping.local_port => Ok(()),
            other => Err(unexpected(&other)),
        }
    }
}

fn unexpected(response: &natpmp::Response) -> Failure {
    Failure::Broken(format!("unexpected NAT-PMP answer: {response:?}"))
}

impl From<natpmp::Error> for Failure {
    fn from(error: natpmp::Error) -> Failure {
        use natpmp::Error as E;
        match error {
            E::NATPMP_ERR_UNSUPPORTEDVERSION | E::NATPMP_ERR_UNSUPPORTEDOPCODE | E::NATPMP_ERR_NOGATEWAYSUPPORT => {
                Failure::Unavailable(format!("the gateway does not do NAT-PMP ({error})"))
            }
            E::NATPMP_ERR_NOTAUTHORIZED | E::NATPMP_ERR_NETWORKFAILURE | E::NATPMP_ERR_OUTOFRESOURCES => {
                Failure::Refused(format!("the router said: {error}"))
            }
            _ => Failure::Broken(error.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// UPnP IGD: SSDP to find the router, then SOAP.

struct Upnp {
    search: Search,
    timeouts: Timeouts,
}

/// Where the SSDP search leaves from and goes to; tests aim it at a router on loopback.
struct Search {
    bind: SocketAddr,
    broadcast: SocketAddr,
    /// Addresses a router may use besides the one that answered. `igd-next` refuses loopback.
    allowed: Vec<IpAddr>,
}

impl Search {
    /// The usual multicast, sent from the interface that leads to the gateway: a PC with a VPN or
    /// a virtual switch would otherwise send it wherever the OS likes.
    fn towards(gateway: Option<Ipv4Addr>) -> Search {
        let defaults = SearchOptions::default();
        let bind = gateway
            .and_then(|gateway| local_ip_towards(gateway.into()).ok())
            .map_or(defaults.bind_addr, |ip| SocketAddr::new(ip, 0));
        Search { bind, broadcast: defaults.broadcast_address, allowed: Vec::new() }
    }
}

impl Upnp {
    async fn discover(&self) -> Result<RealIgd, Failure> {
        let mut options = SearchOptions::default();
        options.bind_addr = self.search.bind;
        options.broadcast_address = self.search.broadcast;
        options.allowed_gateway_ips = self.search.allowed.clone();
        options.timeout = Some(self.timeouts.discovery);
        // AddPortMapping has no way to name an IPv6 internal client.
        options.gateway_ip_version = GatewayIpVersion::V4;
        let gateway = search_gateway(options).await.map_err(|e| match e {
            SearchError::NoResponseWithinTimeout => {
                Failure::Unavailable(format!("no UPnP router answered within {:?}", self.timeouts.discovery))
            }
            other => Failure::Broken(format!("UPnP search failed: {other}")),
        })?;
        // The router needs the address it can send to: the one this PC has towards it.
        let local_ip = local_ip_towards(gateway.addr.ip())
            .map_err(|e| Failure::Broken(format!("cannot tell which address of this PC the router sees: {e}")))?;
        tracing::debug!("UPnP: router at {gateway}, this PC is {local_ip}");
        Ok(RealIgd { gateway, local_ip })
    }
}

impl Mapper for Upnp {
    fn protocol(&self) -> MappingProtocol {
        MappingProtocol::Upnp
    }

    async fn map(&self, request: &Request) -> Result<Granted, Failure> {
        upnp_map(&self.discover().await?, request).await
    }

    async fn remove(&self, mapping: &Mapping) -> Result<(), Failure> {
        match self.discover().await?.remove_port(mapping.external_port).await {
            Ok(()) => Ok(()),
            // Gone already (a restart, or the lease ended): that is what was asked for.
            Err(IgdError::NoSuchMapping) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

/// The calls UPnP mapping needs, as the router sees them. Private, for the same reason as [`Mapper`].
trait Igd: Send + Sync {
    fn external_ip(&self) -> impl Future<Output = Result<IpAddr, IgdError>> + Send;
    /// Whether the router has IGDv2's `AddAnyPortMapping`.
    fn can_add_any_port(&self) -> bool;
    fn add_any_port(&self, local_port: u16, lease_secs: u32) -> impl Future<Output = Result<u16, IgdError>> + Send;
    fn add_port(
        &self,
        external_port: u16,
        local_port: u16,
        lease_secs: u32,
    ) -> impl Future<Output = Result<(), IgdError>> + Send;
    fn remove_port(&self, external_port: u16) -> impl Future<Output = Result<(), IgdError>> + Send;
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum IgdError {
    /// 606: this PC may not map ports.
    NotAuthorized,
    /// 718, or 728 for `AddAnyPortMapping`: that external port is taken.
    PortInUse,
    /// 724: the router maps only equal internal and external ports.
    SamePortRequired,
    /// 725: the router keeps only permanent mappings (lease 0).
    PermanentLeaseOnly,
    /// 714: nothing is mapped there.
    NoSuchMapping,
    Other(String),
}

impl From<IgdError> for Failure {
    fn from(error: IgdError) -> Failure {
        match error {
            IgdError::NotAuthorized => Failure::Refused("the router does not let this PC map ports".into()),
            IgdError::PortInUse => Failure::Refused("the router has no free external port".into()),
            IgdError::SamePortRequired => {
                Failure::Refused("the router maps only equal internal and external ports, and that one is taken".into())
            }
            IgdError::PermanentLeaseOnly => Failure::Refused("the router keeps only permanent mappings".into()),
            IgdError::NoSuchMapping => Failure::Refused("the router has no such mapping".into()),
            IgdError::Other(reason) => Failure::Broken(reason),
        }
    }
}

impl From<AddPortError> for IgdError {
    fn from(error: AddPortError) -> IgdError {
        match error {
            AddPortError::ActionNotAuthorized => IgdError::NotAuthorized,
            AddPortError::PortInUse => IgdError::PortInUse,
            AddPortError::SamePortValuesRequired => IgdError::SamePortRequired,
            AddPortError::OnlyPermanentLeasesSupported => IgdError::PermanentLeaseOnly,
            other => IgdError::Other(other.to_string()),
        }
    }
}

impl From<AddAnyPortError> for IgdError {
    fn from(error: AddAnyPortError) -> IgdError {
        match error {
            AddAnyPortError::ActionNotAuthorized => IgdError::NotAuthorized,
            AddAnyPortError::NoPortsAvailable | AddAnyPortError::ExternalPortInUse => IgdError::PortInUse,
            AddAnyPortError::OnlyPermanentLeasesSupported => IgdError::PermanentLeaseOnly,
            other => IgdError::Other(other.to_string()),
        }
    }
}

impl From<GetExternalIpError> for IgdError {
    fn from(error: GetExternalIpError) -> IgdError {
        match error {
            GetExternalIpError::ActionNotAuthorized => IgdError::NotAuthorized,
            other => IgdError::Other(other.to_string()),
        }
    }
}

impl From<RemovePortError> for IgdError {
    fn from(error: RemovePortError) -> IgdError {
        match error {
            RemovePortError::ActionNotAuthorized => IgdError::NotAuthorized,
            RemovePortError::NoSuchPortMapping => IgdError::NoSuchMapping,
            other => IgdError::Other(other.to_string()),
        }
    }
}

struct RealIgd {
    gateway: Gateway<Tokio>,
    local_ip: IpAddr,
}

impl RealIgd {
    fn local_addr(&self, port: u16) -> SocketAddr {
        SocketAddr::new(self.local_ip, port)
    }
}

impl Igd for RealIgd {
    async fn external_ip(&self) -> Result<IpAddr, IgdError> {
        Ok(self.gateway.get_external_ip().await?)
    }

    fn can_add_any_port(&self) -> bool {
        self.gateway.control_schema.contains_key("AddAnyPortMapping")
    }

    async fn add_any_port(&self, local_port: u16, lease_secs: u32) -> Result<u16, IgdError> {
        let local = self.local_addr(local_port);
        Ok(self.gateway.add_any_port(PortMappingProtocol::UDP, local, lease_secs, DESCRIPTION).await?)
    }

    async fn add_port(&self, external_port: u16, local_port: u16, lease_secs: u32) -> Result<(), IgdError> {
        let local = self.local_addr(local_port);
        Ok(self.gateway.add_port(PortMappingProtocol::UDP, external_port, local, lease_secs, DESCRIPTION).await?)
    }

    async fn remove_port(&self, external_port: u16) -> Result<(), IgdError> {
        Ok(self.gateway.remove_port(PortMappingProtocol::UDP, external_port).await?)
    }
}

/// The port after `port` for a router that says it is taken.
fn next_port(port: u16) -> u16 {
    port.checked_add(1).unwrap_or(1024)
}

async fn upnp_map<I: Igd>(igd: &I, request: &Request) -> Result<Granted, Failure> {
    let external_ip = igd.external_ip().await?;
    if external_ip.is_unspecified() {
        return Err(Failure::Unavailable("the router has no external address".into()));
    }

    let lease = Duration::from_secs(request.lease_secs.into());
    let mut port = request.wanted_external;
    let mut router_chooses = false;
    let mut router_can_choose = igd.can_add_any_port();
    let mut permanent = false;
    let mut equal_ports_only = false;
    for _ in 0..MAX_ATTEMPTS {
        let lease_secs = if permanent { 0 } else { request.lease_secs };
        let attempt = if router_chooses {
            igd.add_any_port(request.local_port, lease_secs).await
        } else {
            igd.add_port(port, request.local_port, lease_secs).await.map(|()| port)
        };
        match attempt {
            Ok(external_port) => return Ok(Granted { external_ip, external_port, lease }),
            Err(IgdError::PermanentLeaseOnly) if !permanent => permanent = true,
            Err(IgdError::SamePortRequired) if !equal_ports_only && !router_chooses && port != request.local_port => {
                equal_ports_only = true;
                port = request.local_port;
            }
            Err(IgdError::PortInUse) if !equal_ports_only && !router_chooses => {
                if router_can_choose {
                    router_chooses = true;
                } else {
                    port = next_port(port);
                }
            }
            // The only port this router can use is taken: say that, not just "taken".
            Err(IgdError::PortInUse) if equal_ports_only => return Err(IgdError::SamePortRequired.into()),
            // Offered by the router but not working: the explicit ports are still there.
            Err(IgdError::Other(reason)) if router_chooses => {
                tracing::debug!("UPnP: AddAnyPortMapping failed ({reason}); trying explicit ports");
                router_chooses = false;
                router_can_choose = false;
                port = next_port(port);
            }
            Err(other) => return Err(other.into()),
        }
    }
    Err(Failure::Refused(format!("{MAX_ATTEMPTS} external ports in a row were refused or taken")))
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;

    use super::*;

    const FAST: Timeouts = Timeouts { discovery: Duration::from_millis(150), total: Duration::from_millis(300) };

    fn request() -> Request {
        Request { local_port: 7420, wanted_external: 7420, lease_secs: 3600 }
    }

    fn granted(port: u16) -> Granted {
        Granted { external_ip: "198.51.100.7".parse().unwrap(), external_port: port, lease: Duration::from_secs(3600) }
    }

    fn mapping(protocol: MappingProtocol, external_port: u16) -> Mapping {
        Mapping {
            protocol,
            local_port: 7420,
            external_ip: "198.51.100.7".parse().unwrap(),
            external_port,
            lease: Duration::from_secs(3600),
        }
    }

    // --- the orchestration, with a fake for each protocol ---

    #[derive(Clone)]
    enum Outcome<T> {
        Done(Result<T, Failure>),
        /// A router that never answers.
        Hang,
    }

    struct FakeMapper {
        protocol: MappingProtocol,
        on_map: Outcome<Granted>,
        on_remove: Outcome<()>,
        maps: Mutex<Vec<Request>>,
        removals: Mutex<Vec<Mapping>>,
    }

    impl FakeMapper {
        fn new(protocol: MappingProtocol, on_map: Outcome<Granted>) -> FakeMapper {
            FakeMapper {
                protocol,
                on_map,
                on_remove: Outcome::Done(Ok(())),
                maps: Mutex::default(),
                removals: Mutex::default(),
            }
        }

        fn grants(protocol: MappingProtocol, port: u16) -> FakeMapper {
            FakeMapper::new(protocol, Outcome::Done(Ok(granted(port))))
        }

        fn fails(protocol: MappingProtocol, failure: Failure) -> FakeMapper {
            FakeMapper::new(protocol, Outcome::Done(Err(failure)))
        }

        fn hangs(protocol: MappingProtocol) -> FakeMapper {
            FakeMapper::new(protocol, Outcome::Hang)
        }

        fn maps(&self) -> Vec<Request> {
            self.maps.lock().unwrap().clone()
        }
    }

    impl Mapper for FakeMapper {
        fn protocol(&self) -> MappingProtocol {
            self.protocol
        }

        async fn map(&self, request: &Request) -> Result<Granted, Failure> {
            self.maps.lock().unwrap().push(request.clone());
            match &self.on_map {
                Outcome::Done(result) => result.clone(),
                Outcome::Hang => std::future::pending().await,
            }
        }

        async fn remove(&self, mapping: &Mapping) -> Result<(), Failure> {
            self.removals.lock().unwrap().push(mapping.clone());
            match &self.on_remove {
                Outcome::Done(result) => result.clone(),
                Outcome::Hang => std::future::pending().await,
            }
        }
    }

    const TOTAL: Duration = Duration::from_millis(200);

    #[tokio::test]
    async fn natpmp_answering_is_enough() {
        let natpmp = FakeMapper::grants(MappingProtocol::NatPmp, 7420);
        let upnp = FakeMapper::grants(MappingProtocol::Upnp, 9999);
        let mapping = map_in_order(&natpmp, &upnp, &request(), TOTAL).await.unwrap();
        assert_eq!(mapping.protocol, MappingProtocol::NatPmp);
        assert_eq!((mapping.local_port, mapping.external_port), (7420, 7420));
        assert_eq!(mapping.external_addr(), "198.51.100.7:7420".parse().unwrap());
        assert_eq!(mapping.lease, Duration::from_secs(3600));
        assert!(upnp.maps().is_empty(), "UPnP is for when NAT-PMP did not do it");
    }

    #[tokio::test]
    async fn natpmp_refused_then_upnp_maps() {
        let natpmp = FakeMapper::fails(MappingProtocol::NatPmp, Failure::Refused("not authorized".into()));
        let upnp = FakeMapper::grants(MappingProtocol::Upnp, 7421);
        let mapping = map_in_order(&natpmp, &upnp, &request(), TOTAL).await.unwrap();
        assert_eq!(mapping.protocol, MappingProtocol::Upnp);
        assert_eq!(mapping.external_port, 7421);
        assert_eq!(natpmp.maps(), vec![request()]);
        assert_eq!(upnp.maps(), vec![request()]);
    }

    #[tokio::test]
    async fn both_failing_is_one_error_with_both_reasons() {
        let natpmp = FakeMapper::fails(MappingProtocol::NatPmp, Failure::Unavailable("not NAT-PMP".into()));
        let upnp = FakeMapper::fails(MappingProtocol::Upnp, Failure::Refused("no free port".into()));
        let error = map_in_order(&natpmp, &upnp, &request(), TOTAL).await.unwrap_err();
        assert!(
            matches!(&error, MappingError::Failed { natpmp, upnp } if natpmp == "not NAT-PMP" && upnp == "no free port")
        );
        let text = error.to_string();
        assert!(text.contains("NAT-PMP: not NAT-PMP") && text.contains("UPnP: no free port"), "{text}");
    }

    #[tokio::test]
    async fn the_reasons_stay_with_their_protocol_in_either_order() {
        let natpmp = FakeMapper::fails(MappingProtocol::NatPmp, Failure::Unavailable("a".into()));
        let upnp = FakeMapper::fails(MappingProtocol::Upnp, Failure::Unavailable("b".into()));
        let error = map_in_order(&upnp, &natpmp, &request(), TOTAL).await.unwrap_err();
        assert!(matches!(error, MappingError::Failed { natpmp, upnp } if natpmp == "a" && upnp == "b"));
    }

    #[tokio::test]
    async fn a_router_that_never_answers_ends_in_time() {
        let natpmp = FakeMapper::hangs(MappingProtocol::NatPmp);
        let upnp = FakeMapper::hangs(MappingProtocol::Upnp);
        let started = Instant::now();
        let error = map_in_order(&natpmp, &upnp, &request(), TOTAL).await.unwrap_err();
        let elapsed = started.elapsed();
        // Each protocol has its own `total`, and nothing more.
        assert!(elapsed >= 2 * TOTAL && elapsed < 2 * TOTAL + Duration::from_secs(2), "{elapsed:?}");
        let text = error.to_string();
        assert_eq!(text.matches("no answer within").count(), 2, "{text}");
    }

    #[tokio::test]
    async fn a_silent_natpmp_does_not_stop_upnp() {
        let natpmp = FakeMapper::hangs(MappingProtocol::NatPmp);
        let upnp = FakeMapper::grants(MappingProtocol::Upnp, 7420);
        let mapping = map_in_order(&natpmp, &upnp, &request(), TOTAL).await.unwrap();
        assert_eq!(mapping.protocol, MappingProtocol::Upnp);
    }

    #[test]
    fn requests_are_checked_before_any_network_use() {
        let lease = Duration::from_secs(60);
        assert!(matches!(Request::new(0, 7420, lease), Err(MappingError::InvalidRequest(_))));
        assert!(matches!(Request::new(7420, 7420, Duration::ZERO), Err(MappingError::InvalidRequest(_))));
        assert!(matches!(Request::new(7420, 7420, Duration::from_millis(900)), Err(MappingError::InvalidRequest(_))));
        // 0 means no preference, which for us is the port itself.
        assert_eq!(Request::new(7420, 0, lease).unwrap().wanted_external, 7420);
        assert_eq!(
            Request::new(7420, 9000, lease).unwrap(),
            Request { local_port: 7420, wanted_external: 9000, lease_secs: 60 }
        );
        // Longer than a u32 of seconds is capped, not wrapped.
        assert_eq!(Request::new(7420, 7420, Duration::from_secs(u64::MAX)).unwrap().lease_secs, u32::MAX);
        let broken = Mapping { local_port: 0, ..mapping(MappingProtocol::Upnp, 7420) };
        assert!(matches!(Request::renewing(&broken), Err(MappingError::InvalidRequest(_))));
    }

    #[tokio::test]
    async fn renewal_asks_the_protocol_that_made_it_for_the_same_port_and_lease() {
        let old = mapping(MappingProtocol::Upnp, 7431);
        let request = Request::renewing(&old).unwrap();
        assert_eq!(request, Request { local_port: 7420, wanted_external: 7431, lease_secs: 3600 });

        let natpmp = FakeMapper::grants(MappingProtocol::NatPmp, 7420);
        let upnp = FakeMapper::grants(MappingProtocol::Upnp, 7431);
        let renewed = map_in_order(&upnp, &natpmp, &request, TOTAL).await.unwrap();
        assert_eq!(renewed, old);
        assert!(natpmp.maps().is_empty());
        assert_eq!(upnp.maps(), vec![request]);
    }

    #[tokio::test]
    async fn renewal_returns_the_mapping_the_router_now_gives() {
        let old = mapping(MappingProtocol::NatPmp, 7420);
        let natpmp = FakeMapper::new(
            MappingProtocol::NatPmp,
            Outcome::Done(Ok(Granted {
                external_ip: "203.0.113.9".parse().unwrap(),
                external_port: 7433,
                lease: Duration::from_secs(1800),
            })),
        );
        let upnp = FakeMapper::grants(MappingProtocol::Upnp, 1);
        let renewed = map_in_order(&natpmp, &upnp, &Request::renewing(&old).unwrap(), TOTAL).await.unwrap();
        assert_eq!(renewed.external_addr(), "203.0.113.9:7433".parse().unwrap());
        assert_eq!(renewed.lease, Duration::from_secs(1800));
        assert_eq!(renewed.local_port, 7420);
    }

    #[tokio::test]
    async fn renewal_falls_back_to_the_other_protocol() {
        // The laptop moved to a network whose router speaks only UPnP.
        let old = mapping(MappingProtocol::NatPmp, 7420);
        let natpmp = FakeMapper::fails(MappingProtocol::NatPmp, Failure::TimedOut(TOTAL));
        let upnp = FakeMapper::grants(MappingProtocol::Upnp, 7420);
        let renewed = map_in_order(&natpmp, &upnp, &Request::renewing(&old).unwrap(), TOTAL).await.unwrap();
        assert_eq!(renewed.protocol, MappingProtocol::Upnp);
    }

    #[test]
    fn the_caller_renews_at_half_the_lease() {
        assert_eq!(mapping(MappingProtocol::Upnp, 1).renew_after(), Duration::from_secs(1800));
        let short = Mapping { lease: Duration::from_secs(1), ..mapping(MappingProtocol::Upnp, 1) };
        assert_eq!(short.renew_after(), Duration::from_secs(1));
    }

    #[tokio::test]
    async fn removal_goes_to_the_mapper_with_the_mapping() {
        let natpmp = FakeMapper::grants(MappingProtocol::NatPmp, 7420);
        let old = mapping(MappingProtocol::NatPmp, 7433);
        remove_with(&natpmp, &old, TOTAL).await.unwrap();
        assert_eq!(*natpmp.removals.lock().unwrap(), vec![old]);
    }

    #[tokio::test]
    async fn a_failed_removal_names_the_protocol() {
        let mut upnp = FakeMapper::grants(MappingProtocol::Upnp, 7420);
        upnp.on_remove = Outcome::Done(Err(Failure::Refused("not authorized".into())));
        let error = remove_with(&upnp, &mapping(MappingProtocol::Upnp, 7420), TOTAL).await.unwrap_err();
        assert!(
            matches!(&error, MappingError::RemoveFailed { protocol: MappingProtocol::Upnp, reason } if reason == "not authorized")
        );
        assert_eq!(error.to_string(), "UPnP could not remove the mapping: not authorized");
    }

    #[tokio::test]
    async fn a_removal_that_never_answers_ends_in_time() {
        let mut natpmp = FakeMapper::grants(MappingProtocol::NatPmp, 7420);
        natpmp.on_remove = Outcome::Hang;
        let started = Instant::now();
        let error = remove_with(&natpmp, &mapping(MappingProtocol::NatPmp, 7420), TOTAL).await.unwrap_err();
        assert!(matches!(error, MappingError::RemoveFailed { protocol: MappingProtocol::NatPmp, .. }));
        assert!(started.elapsed() >= TOTAL && started.elapsed() < TOTAL + Duration::from_secs(2));
    }

    #[test]
    fn the_futures_can_run_on_any_runtime_thread() {
        fn assert_send<T: Send>(_: &T) {}
        let old = mapping(MappingProtocol::Upnp, 7420);
        assert_send(&map_udp(7420, 7420, Duration::from_secs(60)));
        assert_send(&renew(&old));
        assert_send(&remove(&old));
    }

    #[test]
    fn protocols_print_their_names() {
        assert_eq!(MappingProtocol::NatPmp.to_string(), "NAT-PMP");
        assert_eq!(MappingProtocol::Upnp.to_string(), "UPnP");
    }

    // --- UPnP: the choice of ports, against a router that keeps state ---

    #[derive(Clone, Copy, PartialEq)]
    enum AnyPort {
        Missing,
        Works,
        /// In the description of the router, then an error when called.
        Broken,
    }

    struct FakeIgd {
        external_ip: Result<IpAddr, IgdError>,
        any_port: AnyPort,
        /// Ports other LAN clients hold.
        taken: HashSet<u16>,
        permanent_only: bool,
        same_port_only: bool,
        denied: bool,
        calls: Mutex<Vec<String>>,
        /// external port -> (internal port, lease)
        mapped: Mutex<HashMap<u16, (u16, u32)>>,
    }

    impl FakeIgd {
        fn new() -> FakeIgd {
            FakeIgd {
                external_ip: Ok("198.51.100.7".parse().unwrap()),
                any_port: AnyPort::Missing,
                taken: HashSet::new(),
                permanent_only: false,
                same_port_only: false,
                denied: false,
                calls: Mutex::default(),
                mapped: Mutex::default(),
            }
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    fn ports(ports: impl IntoIterator<Item = u16>) -> HashSet<u16> {
        ports.into_iter().collect()
    }

    impl Igd for FakeIgd {
        async fn external_ip(&self) -> Result<IpAddr, IgdError> {
            self.external_ip.clone()
        }

        fn can_add_any_port(&self) -> bool {
            self.any_port != AnyPort::Missing
        }

        async fn add_any_port(&self, local_port: u16, lease_secs: u32) -> Result<u16, IgdError> {
            self.calls.lock().unwrap().push(format!("any -> {local_port} lease {lease_secs}"));
            assert!(self.can_add_any_port(), "AddAnyPortMapping is not on this router");
            if self.any_port == AnyPort::Broken {
                return Err(IgdError::Other("500 action failed".into()));
            }
            let mut mapped = self.mapped.lock().unwrap();
            let port = (40000..).find(|port| !self.taken.contains(port) && !mapped.contains_key(port)).unwrap();
            mapped.insert(port, (local_port, lease_secs));
            Ok(port)
        }

        async fn add_port(&self, external_port: u16, local_port: u16, lease_secs: u32) -> Result<(), IgdError> {
            self.calls.lock().unwrap().push(format!("{external_port} -> {local_port} lease {lease_secs}"));
            if self.denied {
                return Err(IgdError::NotAuthorized);
            }
            if self.permanent_only && lease_secs != 0 {
                return Err(IgdError::PermanentLeaseOnly);
            }
            if self.same_port_only && external_port != local_port {
                return Err(IgdError::SamePortRequired);
            }
            if self.taken.contains(&external_port) {
                return Err(IgdError::PortInUse);
            }
            self.mapped.lock().unwrap().insert(external_port, (local_port, lease_secs));
            Ok(())
        }

        async fn remove_port(&self, external_port: u16) -> Result<(), IgdError> {
            match self.mapped.lock().unwrap().remove(&external_port) {
                Some(_) => Ok(()),
                None => Err(IgdError::NoSuchMapping),
            }
        }
    }

    #[tokio::test]
    async fn upnp_maps_the_wanted_port_when_it_is_free() {
        // Even on a router that could choose: the stable port is the point.
        let igd = FakeIgd { any_port: AnyPort::Works, ..FakeIgd::new() };
        let granted = upnp_map(&igd, &request()).await.unwrap();
        assert_eq!(granted.external_port, 7420);
        assert_eq!(granted.external_ip, "198.51.100.7".parse::<IpAddr>().unwrap());
        assert_eq!(granted.lease, Duration::from_secs(3600));
        assert_eq!(igd.calls(), ["7420 -> 7420 lease 3600"]);
        assert_eq!(igd.mapped.lock().unwrap().get(&7420), Some(&(7420, 3600)));
    }

    #[tokio::test]
    async fn upnp_conflict_moves_to_the_next_port() {
        let igd = FakeIgd { taken: ports([7420, 7421]), ..FakeIgd::new() };
        let granted = upnp_map(&igd, &request()).await.unwrap();
        assert_eq!(granted.external_port, 7422);
        assert_eq!(igd.calls(), ["7420 -> 7420 lease 3600", "7421 -> 7420 lease 3600", "7422 -> 7420 lease 3600"]);
    }

    #[tokio::test]
    async fn upnp_conflict_on_igdv2_lets_the_router_choose() {
        let igd = FakeIgd { any_port: AnyPort::Works, taken: ports([7420]), ..FakeIgd::new() };
        let granted = upnp_map(&igd, &request()).await.unwrap();
        assert_eq!(granted.external_port, 40000);
        assert_eq!(igd.calls(), ["7420 -> 7420 lease 3600", "any -> 7420 lease 3600"]);
    }

    #[tokio::test]
    async fn upnp_add_any_port_that_does_not_work_falls_back_to_add_port() {
        let igd = FakeIgd { any_port: AnyPort::Broken, taken: ports([7420]), ..FakeIgd::new() };
        let granted = upnp_map(&igd, &request()).await.unwrap();
        assert_eq!(granted.external_port, 7421);
        assert_eq!(igd.calls(), ["7420 -> 7420 lease 3600", "any -> 7420 lease 3600", "7421 -> 7420 lease 3600"]);
    }

    #[tokio::test]
    async fn upnp_gives_up_when_every_port_is_taken() {
        let igd = FakeIgd { taken: ports(7420..7500), ..FakeIgd::new() };
        let failure = upnp_map(&igd, &request()).await.unwrap_err();
        assert!(matches!(failure, Failure::Refused(_)), "{failure:?}");
        assert_eq!(igd.calls().len(), MAX_ATTEMPTS);
        assert!(igd.mapped.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn upnp_router_with_permanent_mappings_only_gets_lease_zero() {
        let igd = FakeIgd { permanent_only: true, ..FakeIgd::new() };
        let granted = upnp_map(&igd, &request()).await.unwrap();
        assert_eq!(igd.calls(), ["7420 -> 7420 lease 3600", "7420 -> 7420 lease 0"]);
        // The caller still renews on the lease it asked for.
        assert_eq!(granted.lease, Duration::from_secs(3600));
    }

    #[tokio::test]
    async fn upnp_router_with_equal_ports_only_gets_equal_ports() {
        let igd = FakeIgd { same_port_only: true, ..FakeIgd::new() };
        let granted = upnp_map(&igd, &Request { wanted_external: 8000, ..request() }).await.unwrap();
        assert_eq!(granted.external_port, 7420);
        assert_eq!(igd.calls(), ["8000 -> 7420 lease 3600", "7420 -> 7420 lease 3600"]);
    }

    #[tokio::test]
    async fn upnp_equal_ports_only_router_with_the_port_taken_is_refused() {
        let igd = FakeIgd { same_port_only: true, taken: ports([7420]), ..FakeIgd::new() };
        let failure = upnp_map(&igd, &request()).await.unwrap_err();
        assert!(matches!(&failure, Failure::Refused(reason) if reason.contains("equal")), "{failure:?}");
        // The router has to say it once before the number is known to matter.
        assert_eq!(igd.calls(), ["7420 -> 7420 lease 3600", "7421 -> 7420 lease 3600", "7420 -> 7420 lease 3600"]);
    }

    #[tokio::test]
    async fn upnp_not_authorized_is_not_retried() {
        let igd = FakeIgd { denied: true, ..FakeIgd::new() };
        let failure = upnp_map(&igd, &request()).await.unwrap_err();
        assert!(matches!(failure, Failure::Refused(_)), "{failure:?}");
        assert_eq!(igd.calls().len(), 1);
    }

    #[tokio::test]
    async fn upnp_without_an_external_address_maps_nothing() {
        let no_wan = FakeIgd { external_ip: Ok(Ipv4Addr::UNSPECIFIED.into()), ..FakeIgd::new() };
        assert!(matches!(upnp_map(&no_wan, &request()).await, Err(Failure::Unavailable(_))));
        let failing = FakeIgd { external_ip: Err(IgdError::Other("500".into())), ..FakeIgd::new() };
        assert_eq!(upnp_map(&failing, &request()).await, Err(Failure::Broken("500".into())));
        assert!(no_wan.calls().is_empty() && failing.calls().is_empty());
    }

    #[tokio::test]
    async fn upnp_returns_a_private_external_address_as_it_is() {
        // Double NAT is for the caller to see.
        let igd = FakeIgd { external_ip: Ok("192.168.1.2".parse().unwrap()), ..FakeIgd::new() };
        let granted = upnp_map(&igd, &request()).await.unwrap();
        assert_eq!(granted.external_ip, "192.168.1.2".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn upnp_renewal_of_a_live_mapping_keeps_the_port() {
        let igd = FakeIgd::new();
        let first = upnp_map(&igd, &request()).await.unwrap();
        let renewal = Request { wanted_external: first.external_port, ..request() };
        let again = upnp_map(&igd, &renewal).await.unwrap();
        assert_eq!(again.external_port, first.external_port);
        assert_eq!(igd.mapped.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn upnp_renewal_moves_when_the_port_was_lost_to_another_client() {
        let mut igd = FakeIgd::new();
        let first = upnp_map(&igd, &request()).await.unwrap();
        // The router restarted and another PC took the port.
        igd.taken.insert(first.external_port);
        igd.mapped.lock().unwrap().clear();
        let renewal = Request { wanted_external: first.external_port, ..request() };
        assert_eq!(upnp_map(&igd, &renewal).await.unwrap().external_port, first.external_port + 1);
    }

    #[test]
    fn ports_do_not_run_past_the_end() {
        assert_eq!(next_port(7420), 7421);
        assert_eq!(next_port(u16::MAX), 1024);
    }

    #[test]
    fn upnp_errors_keep_their_meaning() {
        assert_eq!(IgdError::from(AddPortError::PortInUse), IgdError::PortInUse);
        assert_eq!(IgdError::from(AddPortError::SamePortValuesRequired), IgdError::SamePortRequired);
        assert_eq!(IgdError::from(AddPortError::OnlyPermanentLeasesSupported), IgdError::PermanentLeaseOnly);
        assert_eq!(IgdError::from(AddPortError::ActionNotAuthorized), IgdError::NotAuthorized);
        assert!(matches!(IgdError::from(AddPortError::DescriptionTooLong), IgdError::Other(_)));
        assert_eq!(IgdError::from(AddAnyPortError::NoPortsAvailable), IgdError::PortInUse);
        assert_eq!(IgdError::from(AddAnyPortError::ExternalPortInUse), IgdError::PortInUse);
        assert_eq!(IgdError::from(AddAnyPortError::OnlyPermanentLeasesSupported), IgdError::PermanentLeaseOnly);
        assert_eq!(IgdError::from(RemovePortError::NoSuchPortMapping), IgdError::NoSuchMapping);
        assert_eq!(IgdError::from(GetExternalIpError::ActionNotAuthorized), IgdError::NotAuthorized);
    }

    #[tokio::test]
    async fn upnp_search_that_gets_no_answer_ends_in_time() {
        // A socket that is there but never reads stands for a network without a UPnP router.
        let silent = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let upnp = Upnp {
            search: Search {
                bind: (Ipv4Addr::LOCALHOST, 0).into(),
                broadcast: silent.local_addr().unwrap(),
                allowed: Vec::new(),
            },
            timeouts: FAST,
        };
        let started = Instant::now();
        let failure = upnp.map(&request()).await.unwrap_err();
        assert!(matches!(failure, Failure::Unavailable(_)), "{failure:?}");
        assert!(
            started.elapsed() >= FAST.discovery && started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
        assert!(upnp.remove(&mapping(MappingProtocol::Upnp, 7420)).await.is_err());
    }

    // --- UPnP: SSDP and SOAP for real, against a fake router on loopback ---

    const WAN_IP_CONNECTION: &str = "urn:schemas-upnp-org:service:WANIPConnection:1";

    const ROOT_DESCRIPTION: &str = r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0"><specVersion><major>1</major><minor>0</minor></specVersion>
<device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType><deviceList>
<device><deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType><deviceList>
<device><deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType><serviceList>
<service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
<serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId><controlURL>/ctl/IPConn</controlURL>
<eventSubURL>/evt/IPConn</eventSubURL><SCPDURL>/WANIPCn.xml</SCPDURL></service>
</serviceList></device></deviceList></device></deviceList></device></root>"#;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Stored {
        protocol: String,
        client: String,
        internal_port: u16,
        lease: u32,
    }

    struct RouterState {
        external_ip: String,
        /// Listed in the description of the router, as on IGDv2.
        add_any_port: bool,
        /// External ports other LAN clients hold.
        taken: HashSet<u16>,
        permanent_only: bool,
        denied: bool,
        /// external port -> what the router stored
        mapped: HashMap<u16, Stored>,
        /// The SOAP actions received, in order.
        actions: Vec<String>,
    }

    /// A router on loopback: answers the SSDP search, describes itself and speaks SOAP. It runs on
    /// threads of its own, with plain blocking sockets.
    struct FakeUpnpRouter {
        ssdp: SocketAddr,
        http: SocketAddr,
        state: Arc<Mutex<RouterState>>,
        stop: Arc<AtomicBool>,
    }

    impl FakeUpnpRouter {
        fn start(configure: impl FnOnce(&mut RouterState)) -> FakeUpnpRouter {
            let mut state = RouterState {
                external_ip: "198.51.100.7".into(),
                add_any_port: false,
                taken: HashSet::new(),
                permanent_only: false,
                denied: false,
                mapped: HashMap::new(),
                actions: Vec::new(),
            };
            configure(&mut state);
            let state = Arc::new(Mutex::new(state));
            let stop = Arc::new(AtomicBool::new(false));

            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let http = listener.local_addr().unwrap();
            let (shared, flag) = (state.clone(), stop.clone());
            thread::spawn(move || serve_http(listener, shared, flag));

            let socket = StdUdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let ssdp = socket.local_addr().unwrap();
            socket.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
            let flag = stop.clone();
            thread::spawn(move || answer_searches(socket, http, flag));

            FakeUpnpRouter { ssdp, http, state, stop }
        }

        fn upnp(&self) -> Upnp {
            Upnp {
                search: Search {
                    bind: (Ipv4Addr::LOCALHOST, 0).into(),
                    broadcast: self.ssdp,
                    allowed: vec![Ipv4Addr::LOCALHOST.into()],
                },
                timeouts: Timeouts { discovery: Duration::from_secs(2), total: Duration::from_secs(4) },
            }
        }

        fn actions(&self) -> Vec<String> {
            self.state.lock().unwrap().actions.clone()
        }
    }

    impl Drop for FakeUpnpRouter {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            // Wakes the accept() that is waiting.
            let _ = TcpStream::connect(self.http);
        }
    }

    fn answer_searches(socket: StdUdpSocket, http: SocketAddr, stop: Arc<AtomicBool>) {
        let mut buf = [0u8; 1024];
        while !stop.load(Ordering::Relaxed) {
            let Ok((n, from)) = socket.recv_from(&mut buf) else { continue };
            if buf[..n].starts_with(b"M-SEARCH") {
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nEXT:\r\nSERVER: fake UPnP/1.1\r\n\
                     ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
                     USN: uuid:fake::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
                     LOCATION: http://{http}/rootDesc.xml\r\n\r\n"
                );
                let _ = socket.send_to(reply.as_bytes(), from);
            }
        }
    }

    fn serve_http(listener: TcpListener, state: Arc<Mutex<RouterState>>, stop: Arc<AtomicBool>) {
        for stream in listener.incoming() {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            let Ok(mut stream) = stream else { continue };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let Some((method, path, headers, body)) = read_request(&mut stream) else { continue };
            let (status, reply) = respond(&mut state.lock().unwrap(), &method, &path, &headers, &body);
            let head = format!(
                "HTTP/1.1 {status} Fake\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                reply.len()
            );
            let _ = stream.write_all(head.as_bytes()).and_then(|()| stream.write_all(reply.as_bytes()));
        }
    }

    /// Method, path, headers (names in lower case) and body of an HTTP request.
    type RawRequest = (String, String, HashMap<String, String>, String);

    fn read_request(stream: &mut TcpStream) -> Option<RawRequest> {
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).ok()?;
        let mut parts = line.split_whitespace();
        let (method, path) = (parts.next()?.to_string(), parts.next()?.to_string());
        let mut headers = HashMap::new();
        loop {
            line.clear();
            reader.read_line(&mut line).ok()?;
            let header = line.trim_end();
            if header.is_empty() {
                break;
            }
            let (name, value) = header.split_once(':')?;
            headers.insert(name.to_ascii_lowercase(), value.trim().to_string());
        }
        let length: usize = headers.get("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
        let mut body = vec![0; length];
        reader.read_exact(&mut body).ok()?;
        Some((method, path, headers, String::from_utf8(body).ok()?))
    }

    fn respond(
        state: &mut RouterState,
        method: &str,
        path: &str,
        headers: &HashMap<String, String>,
        body: &str,
    ) -> (u16, String) {
        match (method, path) {
            ("GET", "/rootDesc.xml") => (200, ROOT_DESCRIPTION.into()),
            ("GET", "/WANIPCn.xml") => (200, service_description(state.add_any_port)),
            ("POST", "/ctl/IPConn") => {
                let header = headers.get("soapaction").map(|v| v.trim_matches('"')).unwrap_or_default();
                let action = header.split_once('#').map(|(_, action)| action).unwrap_or_default().to_string();
                state.actions.push(action.clone());
                soap(state, &action, body)
            }
            _ => (404, String::new()),
        }
    }

    fn service_description(add_any_port: bool) -> String {
        let argument = |name: &str, direction: &str| {
            format!("<argument><name>{name}</name><direction>{direction}</direction></argument>")
        };
        let action = |name: &str, arguments: &[(&str, &str)]| {
            let list: String = arguments.iter().map(|(n, d)| argument(n, d)).collect();
            format!("<action><name>{name}</name><argumentList>{list}</argumentList></action>")
        };
        let add_port = [
            ("NewRemoteHost", "in"),
            ("NewExternalPort", "in"),
            ("NewProtocol", "in"),
            ("NewInternalPort", "in"),
            ("NewInternalClient", "in"),
            ("NewEnabled", "in"),
            ("NewPortMappingDescription", "in"),
            ("NewLeaseDuration", "in"),
        ];
        let mut actions = action("AddPortMapping", &add_port);
        actions += &action("GetExternalIPAddress", &[("NewExternalIPAddress", "out")]);
        actions +=
            &action("DeletePortMapping", &[("NewRemoteHost", "in"), ("NewExternalPort", "in"), ("NewProtocol", "in")]);
        if add_any_port {
            let mut arguments = add_port.to_vec();
            arguments.push(("NewReservedPort", "out"));
            actions += &action("AddAnyPortMapping", &arguments);
        }
        format!(
            "<?xml version=\"1.0\"?><scpd xmlns=\"urn:schemas-upnp-org:service-1-0\">\
             <specVersion><major>1</major><minor>0</minor></specVersion><actionList>{actions}</actionList></scpd>"
        )
    }

    fn envelope(body: &str) -> String {
        format!(
            "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
             s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body>{body}</s:Body></s:Envelope>"
        )
    }

    fn fault(code: u16, description: &str) -> (u16, String) {
        let detail = format!(
            "<UPnPError xmlns=\"urn:schemas-upnp-org:control-1-0\"><errorCode>{code}</errorCode>\
             <errorDescription>{description}</errorDescription></UPnPError>"
        );
        let fault = format!("<s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail>{detail}</detail></s:Fault>");
        (500, envelope(&fault))
    }

    fn soap(state: &mut RouterState, action: &str, body: &str) -> (u16, String) {
        let arg = |name: &str| -> Option<String> {
            let start = body.find(&format!("<{name}>"))? + name.len() + 2;
            let end = start + body[start..].find(&format!("</{name}>"))?;
            Some(body[start..end].to_string())
        };
        let ok = |inner: &str| {
            (
                200,
                envelope(&format!("<u:{action}Response xmlns:u=\"{WAN_IP_CONNECTION}\">{inner}</u:{action}Response>")),
            )
        };
        match action {
            "GetExternalIPAddress" => {
                ok(&format!("<NewExternalIPAddress>{}</NewExternalIPAddress>", state.external_ip))
            }
            "AddPortMapping" | "AddAnyPortMapping" => {
                let port = |name: &str| arg(name).and_then(|value| value.parse::<u16>().ok());
                let (Some(external), Some(internal_port), Some(client)) =
                    (port("NewExternalPort"), port("NewInternalPort"), arg("NewInternalClient"))
                else {
                    return fault(402, "Invalid Args");
                };
                if state.denied {
                    return fault(606, "Action not authorized");
                }
                let lease = arg("NewLeaseDuration").and_then(|value| value.parse().ok()).unwrap_or(0);
                if state.permanent_only && lease != 0 {
                    return fault(725, "OnlyPermanentLeasesSupported");
                }
                let stored = Stored { protocol: arg("NewProtocol").unwrap_or_default(), client, internal_port, lease };
                let free = |port: u16, state: &RouterState| {
                    !state.taken.contains(&port)
                        && state.mapped.get(&port).is_none_or(|held| held.client == stored.client)
                };
                if action == "AddAnyPortMapping" {
                    let reserved = std::iter::once(external).chain(40000..).find(|port| free(*port, state)).unwrap();
                    state.mapped.insert(reserved, stored);
                    return ok(&format!("<NewReservedPort>{reserved}</NewReservedPort>"));
                }
                if !free(external, state) {
                    return fault(718, "ConflictInMappingEntry");
                }
                state.mapped.insert(external, stored);
                ok("")
            }
            "DeletePortMapping" => {
                match arg("NewExternalPort").and_then(|v| v.parse().ok()).and_then(|p: u16| state.mapped.remove(&p)) {
                    Some(_) => ok(""),
                    None => fault(714, "NoSuchEntryInArray"),
                }
            }
            _ => fault(401, "Invalid Action"),
        }
    }

    #[tokio::test]
    async fn upnp_maps_over_ssdp_and_soap() {
        let router = FakeUpnpRouter::start(|_| {});
        let granted = router.upnp().map(&request()).await.unwrap();
        let expected = Granted {
            external_ip: "198.51.100.7".parse().unwrap(),
            external_port: 7420,
            lease: Duration::from_secs(3600),
        };
        assert_eq!(granted, expected);
        let state = router.state.lock().unwrap();
        assert_eq!(state.actions, ["GetExternalIPAddress", "AddPortMapping"]);
        // What the router stored is what UPnP needs: UDP, the address of this PC, its port, the lease.
        let stored = Stored { protocol: "UDP".into(), client: "127.0.0.1".into(), internal_port: 7420, lease: 3600 };
        assert_eq!(state.mapped[&7420], stored);
    }

    #[tokio::test]
    async fn upnp_real_conflict_moves_to_the_next_port() {
        let router = FakeUpnpRouter::start(|state| {
            state.taken.insert(7420);
        });
        let granted = router.upnp().map(&request()).await.unwrap();
        assert_eq!(granted.external_port, 7421);
        assert_eq!(router.actions(), ["GetExternalIPAddress", "AddPortMapping", "AddPortMapping"]);
    }

    #[tokio::test]
    async fn upnp_real_igdv2_router_chooses_when_the_port_is_taken() {
        let router = FakeUpnpRouter::start(|state| {
            state.add_any_port = true;
            state.taken.insert(7420);
        });
        let granted = router.upnp().map(&request()).await.unwrap();
        assert!(granted.external_port >= 32768, "{}", granted.external_port);
        assert_eq!(router.actions(), ["GetExternalIPAddress", "AddPortMapping", "AddAnyPortMapping"]);
        assert!(router.state.lock().unwrap().mapped.contains_key(&granted.external_port));
    }

    #[tokio::test]
    async fn upnp_real_router_with_permanent_mappings_only() {
        let router = FakeUpnpRouter::start(|state| state.permanent_only = true);
        let granted = router.upnp().map(&request()).await.unwrap();
        assert_eq!(router.state.lock().unwrap().mapped[&7420].lease, 0);
        assert_eq!(granted.lease, Duration::from_secs(3600));
    }

    #[tokio::test]
    async fn upnp_real_refusal_and_missing_address() {
        let denied = FakeUpnpRouter::start(|state| state.denied = true);
        let failure = denied.upnp().map(&request()).await.unwrap_err();
        assert!(matches!(failure, Failure::Refused(_)), "{failure:?}");
        assert_eq!(denied.actions().len(), 2, "no retry after a refusal");

        let no_wan = FakeUpnpRouter::start(|state| state.external_ip = "0.0.0.0".into());
        let failure = no_wan.upnp().map(&request()).await.unwrap_err();
        assert!(matches!(failure, Failure::Unavailable(_)), "{failure:?}");
        assert_eq!(no_wan.actions(), ["GetExternalIPAddress"]);
    }

    #[tokio::test]
    async fn upnp_real_removal_and_renewal() {
        let router = FakeUpnpRouter::start(|_| {});
        let upnp = router.upnp();
        let unreachable = FakeMapper::fails(MappingProtocol::NatPmp, Failure::Unavailable("no".into()));

        let first = map_in_order(&upnp, &unreachable, &request(), Duration::from_secs(4)).await.unwrap();
        assert_eq!(first.protocol, MappingProtocol::Upnp);

        // Asking again for the port it has extends the mapping, not duplicates it.
        let again = Request::renewing(&first).unwrap();
        let renewed = map_in_order(&upnp, &unreachable, &again, Duration::from_secs(4)).await.unwrap();
        assert_eq!(renewed.external_port, first.external_port);
        assert_eq!(router.state.lock().unwrap().mapped.len(), 1);

        remove_with(&upnp, &renewed, Duration::from_secs(4)).await.unwrap();
        assert!(router.state.lock().unwrap().mapped.is_empty());
        // The router now says there is no such mapping, which is as good as removed.
        remove_with(&upnp, &renewed, Duration::from_secs(4)).await.unwrap();
    }

    // --- NAT-PMP: the real exchange, against a fake router on loopback ---

    #[derive(Clone)]
    struct Router {
        external_ip: [u8; 4],
        /// Requests that get no answer, as if lost.
        lose_first: usize,
        silent: bool,
        result_code: u16,
        version: u8,
        /// Another external port than the one asked for.
        port: Option<u16>,
        lifetime: Option<u32>,
    }

    impl Default for Router {
        fn default() -> Router {
            Router {
                external_ip: [198, 51, 100, 7],
                lose_first: 0,
                silent: false,
                result_code: 0,
                version: 0,
                port: None,
                lifetime: None,
            }
        }
    }

    impl Router {
        fn answer(&self, request: &[u8]) -> Option<Vec<u8>> {
            let opcode = *request.get(1)?;
            let mut answer = vec![self.version, 128 + opcode];
            answer.extend(self.result_code.to_be_bytes());
            answer.extend(1234u32.to_be_bytes()); // seconds since the router started
            match opcode {
                0 => answer.extend(self.external_ip),
                1 => {
                    answer.extend(&request[4..6]);
                    answer.extend(self.port.map_or([request[6], request[7]], u16::to_be_bytes));
                    answer.extend(
                        self.lifetime.map_or([request[8], request[9], request[10], request[11]], u32::to_be_bytes),
                    );
                }
                _ => return None,
            }
            Some(answer)
        }
    }

    struct FakeRouter {
        port: u16,
        seen: Arc<Mutex<Vec<Vec<u8>>>>,
        task: tokio::task::JoinHandle<()>,
    }

    impl FakeRouter {
        async fn start(router: Router) -> FakeRouter {
            let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let port = socket.local_addr().unwrap().port();
            let seen = Arc::new(Mutex::new(Vec::new()));
            let log = seen.clone();
            let task = tokio::spawn(async move {
                let mut buf = [0u8; 64];
                let mut count = 0;
                while let Ok((n, from)) = socket.recv_from(&mut buf).await {
                    log.lock().unwrap().push(buf[..n].to_vec());
                    count += 1;
                    if router.silent || count <= router.lose_first {
                        continue;
                    }
                    if let Some(answer) = router.answer(&buf[..n]) {
                        let _ = socket.send_to(&answer, from).await;
                    }
                }
            });
            FakeRouter { port, seen, task }
        }

        fn natpmp(&self, timeouts: Timeouts) -> NatPmp {
            NatPmp { gateway: Ok(Ipv4Addr::LOCALHOST), port: self.port, timeouts }
        }

        fn seen(&self) -> Vec<Vec<u8>> {
            self.seen.lock().unwrap().clone()
        }
    }

    impl Drop for FakeRouter {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    #[tokio::test]
    async fn natpmp_maps_and_reports_what_the_router_answered() {
        let router = FakeRouter::start(Router::default()).await;
        let granted = router.natpmp(FAST).map(&request()).await.unwrap();
        assert_eq!(
            granted,
            Granted {
                external_ip: "198.51.100.7".parse().unwrap(),
                external_port: 7420,
                lease: Duration::from_secs(3600)
            }
        );

        // The external address first, then the mapping, in the bytes of RFC 6886.
        let local = 7420u16.to_be_bytes();
        let mut asked = vec![0, 1, 0, 0, local[0], local[1], local[0], local[1]];
        asked.extend(3600u32.to_be_bytes());
        assert_eq!(router.seen(), vec![vec![0, 0], asked]);
    }

    #[tokio::test]
    async fn natpmp_takes_the_port_and_lease_the_router_chose() {
        let router = FakeRouter::start(Router { port: Some(40123), lifetime: Some(1800), ..Router::default() }).await;
        let granted = router.natpmp(FAST).map(&request()).await.unwrap();
        assert_eq!((granted.external_port, granted.lease), (40123, Duration::from_secs(1800)));
    }

    #[tokio::test]
    async fn natpmp_retransmits_a_lost_request() {
        let router = FakeRouter::start(Router { lose_first: 2, ..Router::default() }).await;
        let slow = Timeouts { discovery: Duration::from_secs(3), total: Duration::from_secs(5) };
        let granted = router.natpmp(slow).map(&request()).await.unwrap();
        assert_eq!(granted.external_port, 7420);
        // Sent at 0, 250 and 750 ms, answered the third time; then the mapping request.
        assert_eq!(router.seen().len(), 4);
    }

    #[tokio::test]
    async fn natpmp_router_that_never_answers_ends_in_time() {
        let router = FakeRouter::start(Router { silent: true, ..Router::default() }).await;
        let started = Instant::now();
        let failure = router.natpmp(FAST).map(&request()).await.unwrap_err();
        assert_eq!(failure, Failure::TimedOut(FAST.discovery));
        assert!(
            started.elapsed() >= FAST.discovery && started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );

        // Asked again, with growing pauses, not flooded.
        let longer = Timeouts { discovery: Duration::from_millis(700), total: Duration::from_millis(1400) };
        let before = router.seen().len();
        router.natpmp(longer).map(&request()).await.unwrap_err();
        let asked = router.seen().len() - before;
        assert!(asked <= 4, "{asked} requests in 700 ms");
        assert!(router.natpmp(FAST).remove(&mapping(MappingProtocol::NatPmp, 7420)).await.is_err());
    }

    #[tokio::test]
    async fn natpmp_refusal_is_refused() {
        // Result code 2: port mapping is switched off on the router.
        let router = FakeRouter::start(Router { result_code: 2, ..Router::default() }).await;
        let failure = router.natpmp(FAST).map(&request()).await.unwrap_err();
        assert!(matches!(failure, Failure::Refused(_)), "{failure:?}");
    }

    #[tokio::test]
    async fn natpmp_a_router_with_another_version_is_not_natpmp() {
        let router = FakeRouter::start(Router { version: 2, ..Router::default() }).await;
        let failure = router.natpmp(FAST).map(&request()).await.unwrap_err();
        assert!(matches!(failure, Failure::Unavailable(_)), "{failure:?}");
    }

    #[tokio::test]
    async fn natpmp_router_without_an_external_address_is_not_used() {
        let router = FakeRouter::start(Router { external_ip: [0, 0, 0, 0], ..Router::default() }).await;
        let failure = router.natpmp(FAST).map(&request()).await.unwrap_err();
        assert!(matches!(failure, Failure::Unavailable(_)), "{failure:?}");
        assert_eq!(router.seen().len(), 1, "no mapping asked for without an address to give");
    }

    #[tokio::test]
    async fn natpmp_a_lease_of_zero_is_no_mapping() {
        let router = FakeRouter::start(Router { lifetime: Some(0), ..Router::default() }).await;
        let failure = router.natpmp(FAST).map(&request()).await.unwrap_err();
        assert!(matches!(failure, Failure::Refused(_)), "{failure:?}");
    }

    #[tokio::test]
    async fn natpmp_removal_asks_for_lifetime_zero_on_the_internal_port() {
        let router = FakeRouter::start(Router::default()).await;
        router.natpmp(FAST).remove(&mapping(MappingProtocol::NatPmp, 7433)).await.unwrap();
        let local = 7420u16.to_be_bytes();
        assert_eq!(router.seen(), vec![vec![0, 1, 0, 0, local[0], local[1], 0, 0, 0, 0, 0, 0]]);
    }

    #[tokio::test]
    async fn natpmp_without_a_gateway_is_unavailable() {
        let natpmp = NatPmp { gateway: Err("no default gateway".into()), port: 5351, timeouts: FAST };
        assert_eq!(natpmp.map(&request()).await, Err(Failure::Unavailable("no default gateway".into())));
    }

    #[test]
    fn natpmp_errors_keep_their_meaning() {
        use natpmp::Error as E;
        assert!(matches!(Failure::from(E::NATPMP_ERR_UNSUPPORTEDVERSION), Failure::Unavailable(_)));
        assert!(matches!(Failure::from(E::NATPMP_ERR_NOGATEWAYSUPPORT), Failure::Unavailable(_)));
        assert!(matches!(Failure::from(E::NATPMP_ERR_NOTAUTHORIZED), Failure::Refused(_)));
        assert!(matches!(Failure::from(E::NATPMP_ERR_OUTOFRESOURCES), Failure::Refused(_)));
        assert!(matches!(Failure::from(E::NATPMP_ERR_RECVFROM), Failure::Broken(_)));
    }

    // --- this PC ---

    #[test]
    fn the_local_address_towards_loopback_is_loopback() {
        assert_eq!(local_ip_towards(Ipv4Addr::LOCALHOST.into()).unwrap(), IpAddr::from(Ipv4Addr::LOCALHOST));
    }

    #[tokio::test]
    async fn looking_for_the_gateway_comes_back_in_time() {
        // There may or may not be a default route where this runs; either way it is an answer.
        let started = Instant::now();
        let gateway = default_gateway(Duration::from_secs(5)).await;
        println!("default gateway: {gateway:?}");
        assert!(started.elapsed() < Duration::from_secs(6));
    }
}

/// By hand, against the router of the machine it runs on:
/// `cargo test -p velora-nat mapping::manual -- --ignored --nocapture`
#[cfg(test)]
mod manual {
    use igd_next::{GetGenericPortMappingEntryError, PortMappingEntry};

    use super::*;

    const PORT: u16 = 47420;

    /// What the router lists for UDP `PORT`, or `None` when it does not list mappings.
    async fn listed(upnp: &Upnp) -> Option<Vec<PortMappingEntry>> {
        let igd = match upnp.discover().await {
            Ok(igd) => igd,
            Err(e) => {
                println!("  (no UPnP router to list the mappings: {e})");
                return None;
            }
        };
        let mut found = Vec::new();
        for index in 0..512 {
            match igd.gateway.get_generic_port_mapping_entry(index).await {
                Ok(entry) if entry.protocol == PortMappingProtocol::UDP && entry.internal_port == PORT => {
                    found.push(entry)
                }
                Ok(_) => {}
                Err(GetGenericPortMappingEntryError::SpecifiedArrayIndexInvalid) => return Some(found),
                Err(e) => {
                    println!("  (the router does not list its mappings: {e})");
                    return None;
                }
            }
        }
        Some(found)
    }

    /// Whether a datagram sent to the router's own external address comes back to `PORT`. Only some
    /// routers loop it back, so `false` proves nothing.
    async fn loops_back(external: SocketAddr) -> bool {
        let Ok(listener) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, PORT)).await else {
            println!("  (cannot listen on {PORT} here)");
            return false;
        };
        let sender = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await.unwrap();
        let mut buf = [0u8; 64];
        for _ in 0..3 {
            let _ = sender.send_to(b"velora-b1", external).await;
            if let Ok(Ok((n, _))) = timeout(Duration::from_millis(700), listener.recv_from(&mut buf)).await {
                return &buf[..n] == b"velora-b1";
            }
        }
        false
    }

    #[tokio::test]
    #[ignore = "changes the router of this machine for up to two minutes"]
    async fn map_renew_and_remove_udp_47420() {
        let (natpmp, upnp) = system().await;
        println!("default gateway: {:?}", natpmp.gateway);
        println!("SSDP search from {} to {}", upnp.search.bind, upnp.search.broadcast);
        println!("UDP {PORT}: asking the router for a 120 s mapping");
        let started = Instant::now();
        let mapping = match map_udp(PORT, PORT, Duration::from_secs(120)).await {
            Ok(mapping) => mapping,
            Err(e) => panic!(
                "no mapping after {:?}: {e}\n(a router that does NAT-PMP, or UPnP switched on, is needed)",
                started.elapsed()
            ),
        };
        println!(
            "  mapped through {} in {:?}: {} -> external {} (lease {} s)",
            mapping.protocol,
            started.elapsed(),
            PORT,
            mapping.external_addr(),
            mapping.lease.as_secs()
        );

        // Whatever fails from here on, the mapping is removed before the test ends.
        let mut outcome = Vec::new();

        let listed_before = listed(&upnp).await;
        if let Some(entries) = &listed_before {
            println!(
                "  the router lists {} UDP mapping(s) to {PORT}: {:?}",
                entries.len(),
                entries.iter().map(|e| e.external_port).collect::<Vec<_>>()
            );
        }
        let loops_before = loops_back(mapping.external_addr()).await;
        println!("  a datagram to {} reaches this PC: {loops_before}", mapping.external_addr());

        let renewed = renew(&mapping).await;
        let mapping = match renewed {
            Ok(renewed) => {
                println!(
                    "  renewed through {}: external {} (lease {} s)",
                    renewed.protocol,
                    renewed.external_addr(),
                    renewed.lease.as_secs()
                );
                if renewed.external_port != mapping.external_port {
                    println!("  (the port changed on renewal)");
                }
                renewed
            }
            Err(e) => {
                outcome.push(format!("renewal failed: {e}"));
                mapping
            }
        };

        let removed = remove(&mapping).await;
        match &removed {
            Ok(()) => println!("  removed"),
            Err(e) => outcome.push(format!("removal failed: {e}")),
        }

        if let Some(entries) = listed(&upnp).await {
            let still = entries.iter().any(|e| e.external_port == mapping.external_port);
            println!("  the router lists {} UDP mapping(s) to {PORT} after the removal", entries.len());
            if still {
                outcome.push("the router still lists the mapping after the removal".into());
            }
        }
        let loops_after = loops_back(mapping.external_addr()).await;
        println!("  a datagram to {} reaches this PC after the removal: {loops_after}", mapping.external_addr());
        if loops_before && loops_after {
            outcome.push("a datagram still gets through after the removal".into());
        }

        assert!(outcome.is_empty(), "{outcome:?}");
    }
}
