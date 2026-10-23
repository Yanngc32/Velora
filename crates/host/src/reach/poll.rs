//! Punch requests that arrive through the DHT. Filled in by ticket E5 (with `punch.rs`); the
//! plumbing it plugs into is `reach/mod.rs`, which E5 does not edit.

use anyhow::Result;

use super::ReachContext;

/// The polling task. Started when standalone reach is on; it ends when `ctx.stop` fires.
///
/// While no relay is registered (`state.relays` is empty) it looks up the punch items of the
/// paired clients in the DHT and hands each fresh one to `punch::respond`. It polls more often
/// for a while after a client disconnects: `state.clients.connected` and
/// `state.clients.last_disconnect` say when that was, and `ctx.reach.subscribe()` wakes it when
/// they change.
pub async fn run(ctx: ReachContext) -> Result<()> {
    // reach: filled in by E5
    let _ = ctx;
    Ok(())
}
