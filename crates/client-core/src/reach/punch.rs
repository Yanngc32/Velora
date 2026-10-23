//! F4: reaching a host by hole punching. [`dial_punch`] is a stub until F4 fills it in; from then on this file is F4's,
//! and nothing outside it changes.

use std::net::SocketAddr;

use anyhow::{bail, Result};

use super::RelayRef;
use crate::ConnectParams;

/// Opens a hole in both NATs toward the host's public `endpoint` and connects through it.
///
/// **Receives** `params`, the connection being made (`params.identity`, `params.host_fingerprint`; `params.reach` holds
/// the host's stored entry and this device's state directory, where its DHT key file lives); `endpoint`, the host's
/// public endpoint as its NAT shows it, the address to dial once the hole is open; `via`, relays the punch request can be
/// signalled through (another paired device the host is registered with), best first. Empty means the signal goes through
/// the DHT (the punch item, sealed with the device secret).
///
/// **Returns** the QUIC endpoint and connection to the host, as a direct dial would: the caller sends the ordinary Velora
/// hello on it. The endpoint's socket is the one the NAT mapping was observed from.
///
/// **Timing.** The race starts it [`PUNCH_DELAY`](super::PUNCH_DELAY) after the first direct address, and drops it when
/// another candidate wins: the future must be cancel-safe and `Send` (it is spawned). It must give up by itself (the plan
/// says after 10 s) with an error, which the race logs at debug level; a relay candidate, if any, is already running.
pub async fn dial_punch(
    _params: &ConnectParams,
    _endpoint: SocketAddr,
    _via: &[RelayRef],
) -> Result<(quinn::Endpoint, quinn::Connection)> {
    bail!("hole punching is not available yet")
}
