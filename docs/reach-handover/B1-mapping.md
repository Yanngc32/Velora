# B1 (router port mapping): hand-over

Branch `claude/reach-b1-port-mapping-358cfe`, commit `3dd19d9`, one file: `crates/nat/src/mapping.rs`.
Written by the B1 session on 2026-10-23.

## Public API (`velora_nat::mapping`, std types only, needs a Tokio runtime)

```rust
pub enum MappingProtocol { NatPmp, Upnp }              // Display: "NAT-PMP" / "UPnP"
pub struct Mapping {                                    // all fields public, so E2 can build fakes
    pub protocol: MappingProtocol,
    pub local_port: u16,       // added to the ticket's shape: NAT-PMP renew/remove need it
    pub external_ip: IpAddr,   // returned as the router reports it (may be private / 100.64/10)
    pub external_port: u16,
    pub lease: Duration,
}
impl Mapping { pub fn external_addr(&self) -> SocketAddr; pub fn renew_after(&self) -> Duration /* lease / 2 */ }
pub enum MappingError {
    InvalidRequest(&'static str),
    Failed { natpmp: String, upnp: String },            // both reasons
    RemoveFailed { protocol: MappingProtocol, reason: String },
}
pub async fn map_udp(local_port: u16, wanted_external: u16 /* 0 = same as local */, lease: Duration) -> Result<Mapping, MappingError>;
pub async fn renew(&Mapping) -> Result<Mapping, MappingError>;   // same protocol first, then the other; may change port/ip
pub async fn remove(&Mapping) -> Result<(), MappingError>;       // a mapping the router no longer has counts as removed
```

Timeouts: 3 s to find the gateway, 5 s per protocol in all (worst case about 10 s when both are silent;
6.1 s measured when neither exists). E2 should call it from a background task.

## Decisions to review

1. UPnP asks for the wanted external port with `AddPortMapping` first, and uses `AddAnyPortMapping` (IGDv2)
   or the next port only on conflict 718. The ticket said AddAnyPortMapping first, but `igd-next` 0.18
   `add_any_port` only suggests a random port (32768..65535), so going through it first would change the
   advertised port on every restart.
2. `Mapping.local_port` was added (NAT-PMP renew and delete need the internal port).
3. A UPnP router that answers 725 (permanent mappings only) gets lease 0 on the wire; `Mapping.lease` still
   carries the lease asked for, so the caller keeps renewing on the same schedule.
4. `renew` falls back to the other protocol if the first fails (a laptop that changed network).
5. An external address of 0.0.0.0 (WAN down) is an error, not a mapping.

## What is tested without a router

52 tests (1 ignored): fakes per protocol for order/fallback/timeouts/renewal/removal; a stateful fake IGD for
the port choice (718 next port, AddAnyPortMapping, broken AddAnyPortMapping, 724, 725, 606, no external
address); a fake NAT-PMP router on loopback through the real `natpmp` client (retransmission, timeout,
result codes, port/lease chosen by the router, delete); a fake UPnP router on loopback (SSDP + SOAP) through
the real `igd-next` client. Linux was not compiled here (only the Windows target is installed).
