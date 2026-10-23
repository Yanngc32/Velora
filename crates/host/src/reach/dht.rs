//! The host's record in the BitTorrent Mainline DHT. Filled in by ticket E3 (with `secrets.rs`);
//! the plumbing it plugs into is `reach/mod.rs`, which E3 does not edit.

use anyhow::Result;
use velora_protocol::tls::Fingerprint;

use super::{DeviceKeys, ReachContext};

/// The publishing task. Started when the DHT switch is on (independent of standalone reach); it
/// ends when `ctx.stop` fires.
///
/// It loads or creates the Ed25519 key in `ctx.state_dir` (`velora_dht::keys`), records its public
/// key in `state.dht_key` (that is what puts `key=` and `secret=` in pairing links and fills
/// `HostMsg::Reach`; clear it when the task ends), and publishes the sealed record (`velora_dht`)
/// for every paired device (`StateDir::AUTHORIZED_CLIENTS`, with the secrets of `secrets.rs`):
/// every 30 minutes and whenever `ctx.reach.subscribe()` says something changed. That signal fires
/// for any change, including ones the record does not hold (`last_reached`, `clients`): compare
/// the record to the last one published before putting it on the network. The record's addresses
/// are `state.addresses` (LAN, VPN, public, IPv6 and relays, already in order), `state.nat`,
/// `state.relays` and `state.mac`.
///
/// Having no network is not an error: wait and try again.
pub async fn run(ctx: ReachContext) -> Result<()> {
    // reach: filled in by E3
    let _ = ctx;
    Ok(())
}

/// What `HostMsg::Reach` carries for the device `fingerprint`: the host's DHT public key and the
/// secret that opens the record for that device. Called each time a client that asked for `Reach`
/// connects, from the async task of the connection, so it must not block for long.
///
/// `None` while there is no key (the DHT switch is off, or the key is not loaded yet): the message
/// then carries zeros, which readers treat as "no record". For a paired device that has no secret
/// yet (it paired before this version, or while the host had no key) it makes one, stores it, and
/// returns it. For a fingerprint that is not paired it returns `None`.
pub fn reach_message(ctx: &ReachContext, fingerprint: &Fingerprint) -> Option<DeviceKeys> {
    // reach: filled in by E3
    let _ = (ctx, fingerprint);
    None
}
