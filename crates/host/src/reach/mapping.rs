//! Router port mapping and the host's public addresses. Filled in by ticket E2; the plumbing it
//! plugs into is `reach/mod.rs`, which E2 does not edit.

use anyhow::Result;

use super::ReachContext;

/// The mapping task. Started when standalone reach is on (at host start if it was saved on, or when
/// the user turns it on); it ends when `ctx.stop` fires, which is when the switch goes off or the
/// host shuts down, and the host waits a few seconds for it to return.
///
/// It maps `ctx.port()` on the router (`velora_nat::mapping`) at start and then before the lease
/// ends (every 30 minutes at most), judges the external address (`velora_nat::addresses::classify`:
/// private or shared means CGNAT or double NAT and is not advertised), and writes what it found to
/// `ctx.reach`:
///
/// - `state.mapping` (shown on This PC), including a mapping that is not advertised, with
///   `public: false`;
/// - `state.set_addresses(AddressKind::Public, ..)` and `state.set_addresses(AddressKind::V6, ..)`
///   with `ip:port` strings, empty when there are none (a withdrawn address must go).
///
/// It may read `state.observed` (E5's view of the endpoint the NAT shows) to compare, but never
/// writes it, and never puts it in `Public`: a mapping that is not public leaves `Public` empty,
/// and the DHT record then lists the observed endpoint instead (`ReachState::record_addresses`).
/// When told to stop it removes the mapping, awaiting the removal in the task (not in a detached
/// blocking call, which an abort would not wait for), and clears all three. A router that does
/// not answer is not an error: log it, wait, try again. Return `Err` only for a failure retrying
/// cannot fix.
pub async fn run(ctx: ReachContext) -> Result<()> {
    // reach: filled in by E2
    let _ = ctx;
    Ok(())
}
