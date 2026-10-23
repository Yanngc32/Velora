//! The secret each paired device opens the host's DHT record with. Filled in by ticket E3 (with
//! `dht.rs`); the plumbing it plugs into is `reach/mod.rs`, which E3 does not edit.

use velora_protocol::{tls::Fingerprint, wire::DEVICE_SECRET_LEN};

use super::ReachContext;

/// The secret that opens the host's DHT record for the paired device `fingerprint`, when it has
/// one. Reading only: it makes none (`dht::reach_message` does, when it must). E3 publishes with
/// these, and E5 needs the same secret to open the punch items that device leaves in the DHT. Also
/// available as `ReachContext::device_secret`.
pub fn get(ctx: &ReachContext, fingerprint: &Fingerprint) -> Option<[u8; DEVICE_SECRET_LEN]> {
    // reach: filled in by E3
    let _ = (ctx, fingerprint);
    None
}

/// The secrets of every paired device that has one. Devices removed from the paired list are
/// not in it, whether or not `on_revoked` was told.
pub fn all(ctx: &ReachContext) -> Vec<(Fingerprint, [u8; DEVICE_SECRET_LEN])> {
    // reach: filled in by E3
    let _ = ctx;
    Vec::new()
}

/// A device was just paired (called through `reach::on_paired`, from a blocking thread, with no
/// lock held). `secret` is the one the pairing link carried; store it for `fingerprint`. With
/// `None`, the link carried none and the secret is made later, the first time `dht::reach_message`
/// is asked for the device.
///
/// Storing is a small file write in `ctx.state_dir`; a failure is logged, not returned: the device
/// is paired either way and gets a secret with its next `Reach`.
pub fn on_paired(ctx: &ReachContext, fingerprint: &Fingerprint, secret: Option<[u8; DEVICE_SECRET_LEN]>) {
    // reach: filled in by E3
    let _ = (ctx, fingerprint, secret);
}

/// A device was removed from the paired list in the launcher (called through
/// `reach::on_revoked`). Forget its secret, so the next publish leaves it out. Removals made with
/// `velora-host revoke` while the host runs do not come here: reconcile with
/// `authorized_clients.json` whenever the secrets are used.
pub fn on_revoked(ctx: &ReachContext, fingerprint: &Fingerprint) {
    // reach: filled in by E3
    let _ = (ctx, fingerprint);
}
