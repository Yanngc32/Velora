//! F2: finding the host through its record in the Mainline DHT. [`resolve_record`] is a stub until F2 fills it in; from
//! then on this file is F2's, and nothing outside it changes.

use anyhow::{bail, Result};

use super::Candidate;
use crate::ConnectParams;

/// Looks the host up in the DHT and returns the ways of reaching it that its record lists.
///
/// **Receives** `params`, the connection being made. The race asks only when `params.reach` holds the host's DHT key and
/// this device's secret, so there `params.reach` is `Some` and `host.key` / `host.secret` are `Some`: `key` is where the
/// record lives (salt `velora_dht::record::SALT`), `secret` opens it (`velora_dht::seal::open`) and
/// `params.host_fingerprint` is what the record's own fingerprint must match. `reach.state_dir` is this device's state
/// directory, for the node's routing-table cache.
///
/// **Returns** the candidates the record lists, most useful first: a `Candidate::Direct` for each address (with its
/// kind), a `Candidate::Relay` for each relay address (`target` is `params.host_fingerprint`), a `Candidate::Punch` when
/// the record's NAT type allows a punch and it names an endpoint to dial. The race drops what it already tries, so
/// repeating the stored addresses is fine. `Ok(vec![])` means "no record" (never published, expired, this device was
/// revoked); `Err` is a lookup that could not run (no network, UDP blocked). The race logs an error at debug level and
/// carries on: neither is ever fatal.
///
/// **Timing.** The race starts it [`LOOKUP_DELAY`](super::LOOKUP_DELAY) after it began (at once when nothing else is
/// running or waiting), so a LAN or VPN address that answers in milliseconds never touches the DHT. It runs in a task of
/// its own, so the future must be `Send`; the task is aborted when another candidate wins, and after
/// [`LOOKUP_LIMIT`](super::LOOKUP_LIMIT) (the plan caps a cold start at 5 s, so stop earlier than that): the future can
/// be dropped at any `.await`, so it must not leave tasks or threads running behind it (blocking work belongs in
/// `spawn_blocking`, which is not cancelled but ends by itself). A panic in it costs the lookup and nothing else.
pub async fn resolve_record(_params: &ConnectParams) -> Result<Vec<Candidate>> {
    bail!("looking the host up in the DHT is not available yet")
}
