//! F3: reaching a host through a relay, and waking it through one. [`dial_relay`] and [`wake_through_relay`] are stubs
//! until F3 fills them in; from then on this file is F3's, and nothing outside it changes.

use std::net::SocketAddr;

use anyhow::{bail, Result};
use velora_protocol::{
    identity::{Identity, KnownHost},
    tls::Fingerprint,
};

use super::WakeOutcome;
use crate::ConnectParams;

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
    _params: &ConnectParams,
    _relay_addr: SocketAddr,
    _relay_fingerprint: Fingerprint,
    _target: Fingerprint,
) -> Result<(quinn::Endpoint, quinn::Connection)> {
    bail!("relaying is not available yet")
}

/// Asks a relay to send the Wake-on-LAN packet for `host`, which this device cannot reach on its own network.
/// [`wake`](super::wake) calls it only after trying this device's own networks, and only for a host with a MAC address
/// (`host.mac` is `Some`).
///
/// **Receives** `identity`, this device's identity, and `host`, the stored entry: `host.relays` lists the relays the host
/// is registered with (fingerprint and addresses), `host.fingerprint` is the host's fingerprint for `ClientMsg::Wake`.
///
/// **Returns** `Ok(WakeOutcome::Sent)` when a relay answered `RelayStatus { ok: true }`, `Ok(WakeOutcome::NoRelay)` when
/// there is no relay to ask or none could send the packet (not on the host's network, unreachable), and `Err` for a
/// failure worth showing the user. The future must be `Send`: callers run `hosts::wake` on a multi-threaded runtime.
pub async fn wake_through_relay(_identity: &Identity, _host: &KnownHost) -> Result<WakeOutcome> {
    Ok(WakeOutcome::NoRelay)
}
