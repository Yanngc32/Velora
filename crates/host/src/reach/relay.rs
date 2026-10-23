//! Relaying through a paired PC: serving relays for other devices, and registering this host with
//! one. Filled in by ticket E4; the plumbing it plugs into is `reach/mod.rs`, which E4 does not edit.
//!
//! Connections that talk to a relay are *links*: the client's hello sets `files_only` and `reach`
//! (and nothing that starts a session), so the host does not capture a screen or send another
//! device away for it, and nothing reads the connection's datagrams but the relay. See
//! `docs/reach-handover/E1-host-plumbing.md`.

use anyhow::Result;
use velora_protocol::{
    tls::Fingerprint,
    wire::{ClientMsg, HostMsg},
};

use super::{ClientConn, ReachContext};

/// The serving task. Started when the host relays for others (the switch, or `--relay-only`); it
/// ends when `ctx.stop` fires. It owns the forwarder (D2) for as long as it runs; share it with
/// [`handle_message`] through `ctx.ext::<YourState>()`. When it ends, drop every relayed flow.
pub async fn serve(ctx: ReachContext) -> Result<()> {
    // reach: filled in by E4
    let _ = ctx;
    Ok(())
}

/// The registering task. Started when standalone reach is on (not under `--relay-only`); it ends
/// when `ctx.stop` fires.
///
/// It decides whether this host needs a relay (no public address, or the user asks), picks the
/// paired devices that relay, dials them with `ctx.endpoint.connect_with` and
/// `velora_protocol::tls::client_config(&ctx.identity, relay_fingerprint)`, sends `RelayRegister`
/// with `state.mac`, and exposes the relay to the endpoint with `ctx.socket.open_tunnel`, pumping
/// the tunnel against the relay connection's datagrams (`velora_relay::frame` does the splitting).
/// It writes the relays it is registered with to `state.set_relays(..)` and removes them when the
/// connection goes. It reconnects with backoff; no network is not an error.
pub async fn register_with(ctx: ReachContext) -> Result<()> {
    // reach: filled in by E4
    let _ = ctx;
    Ok(())
}

/// A relay request arrived from a paired device (`RelayRegister`, `RelayTo`, `Wake` or
/// `PunchRequest`) and this host relays for others (otherwise `reach::handle_client_msg` already
/// answered no, and `RelayRegister` and `RelayTo` came from a session, which has no business
/// handing over its datagrams). `from.control` sends the `RelayStatus` reply; `from.conn` is the
/// connection to hand to the forwarder; `from.link` says it is a link, which is always true for
/// the two requests that take the connection over. Return promptly: the connection's control
/// stream is not read while this runs, so spawn what takes long.
pub async fn handle_message(ctx: &ReachContext, from: &ClientConn, msg: ClientMsg) -> Result<()> {
    // reach: filled in by E4
    let _ = (ctx, msg);
    from.control.try_send(HostMsg::RelayStatus { ok: false, reason: "this build cannot relay yet".into() })
}

/// A paired device was removed in the launcher (called through `reach::on_revoked`, from a
/// blocking thread, with no lock held). Drop it from the forwarder (`velora_relay::forward::Relay::remove`):
/// its registration and any flow it is part of end. The forwarder holds its own handle on a
/// device's connection, so the host closing the device's link is not enough. Removals made with
/// `velora-host revoke` while the host runs do not come here.
pub fn on_revoked(ctx: &ReachContext, fingerprint: &Fingerprint) {
    // reach: filled in by E4
    let _ = (ctx, fingerprint);
}

/// Whether relayed traffic is flowing through this host right now. The host does not install an
/// update (which restarts it) while this is true; links that are only registered do not count.
pub fn busy(ctx: &ReachContext) -> bool {
    // reach: filled in by E4
    let _ = ctx;
    false
}
