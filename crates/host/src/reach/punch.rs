//! Hole punching, host side: seeing the endpoint the NAT shows, and opening a hole toward a client
//! on request. Filled in by ticket E5 (with `poll.rs`); the plumbing it plugs into is
//! `reach/mod.rs`, which E5 does not edit.

use anyhow::Result;

use super::{PunchRequest, ReachContext};

/// The observing task. Started when standalone reach is on; it ends when `ctx.stop` fires.
///
/// It measures the endpoint the NAT shows for the QUIC socket with a probe on the multiplexer
/// (`ctx.socket.probe(..)` and `velora_nat::observe::DhtProbe`: send its pings with
/// `Probe::send_to`, offer every datagram the probe hears to `DhtProbe::handle`) and writes
/// `state.observed` and `state.nat` (both `None` when it learnt nothing). Repeat when the network
/// may have changed, not in a tight loop. Do not add the observed endpoint to `state.addresses`:
/// `ReachState::record_addresses()` puts it in the DHT record as a `Public` address when the NAT
/// keeps one endpoint per socket and no mapped address is advertised, and nowhere else, since a
/// client dialling it straight would only fail.
pub async fn run(ctx: ReachContext) -> Result<()> {
    // reach: filled in by E5
    let _ = ctx;
    Ok(())
}

/// A client asked this host to open a hole toward it: from a relay (E4 passes on the
/// `HostMsg::PunchRequest` it reads on its registration connection) or from the DHT poller
/// (`poll.rs`). Parse the request (it is untrusted text), check the client is paired, and send
/// toward its endpoint from the listening port with `ctx.endpoint.connect_with`, dropping the
/// attempt when the client's own connection arrives. Return once the attempt is under way.
pub async fn respond(ctx: &ReachContext, request: PunchRequest) -> Result<()> {
    // reach: filled in by E5
    let _ = (ctx, request);
    Ok(())
}
