//! The secret each paired device opens the host's DHT record with (ticket E3, with `dht.rs`; the plumbing it
//! plugs into is `reach/mod.rs`, which E3 does not edit).
//!
//! A secret is 16 random bytes made by the host for one device and handed to it in the pairing link or in
//! `HostMsg::Reach`. They are kept in `reach_secrets.json` in the host's state directory, written the way the other
//! state files are (a temporary file and a rename, readable by the owner only where the OS has such a thing). The file
//! is read once, kept in memory (`ReachContext::ext`) and written whenever something in it changes.
//!
//! - **The paired list rules.** `authorized_clients.json` is read at every use, so a device removed with
//!   `velora-host revoke` while the host runs (which nobody announces) is gone from every answer here, and its
//!   secret is dropped from the file the next time anything is written. [`on_revoked`] only makes that quicker.
//! - **One record, two ways to seal it.** A record carries 48 bytes per device, and a DHT value 996 in all, so
//!   [`dht::device_capacity`] devices fit beside the largest record the host ever makes. With more paired devices than
//!   that every device is given the one *shared* secret instead (`velora_dht::seal` falls back to it the same way), so
//!   the mode is a function of how many devices are paired and of nothing else: it cannot flip as addresses change.
//!   [`get`], [`all`] and [`secret_for`] answer with the secret a device must hold *now*, which is the shared one in
//!   that mode.
//! - **Revoking rotates.** Anyone who held the shared secret, or a copy of a device's own, can read the record they
//!   fetched, but must not read the next one. A device's own secret is simply dropped. The shared one is dropped too
//!   (and made again when it is next needed) whenever an entry goes, whatever the reason (a removal, a device paired
//!   anew whose old entry was still there, an entry that cannot be read): that device may have held it. The devices
//!   that remain learn the new one with their next `Reach`; one that is away cannot read the record until it connects
//!   some other way. The same lock-out happens to every device when one more is paired than a record has room for.
//! - **Nothing is lost to a bad read.** A file that cannot be read (a sharing violation, say) is not written over: the
//!   calls that need it fail and try again next time. So does a paired list that cannot be read, and a file that is
//!   "not found" in a directory that is not found either (on Windows a share that is gone for a moment reads as not
//!   found, and "nobody is paired" would drop every secret): only a missing file in a directory that is there is
//!   "nobody". A file that is read but is not what it should be is kept beside the original as
//!   `reach_secrets.json.damaged` and the devices get new secrets; one bad entry costs that entry (and, as any
//!   entry does, the shared secret).
//! - **Nothing is handed out that is not kept.** A secret made for a device is told to it (`HostMsg::Reach`) only once
//!   the file holds it; while writing fails the device is told nothing (a client keeps the secret it has when the host
//!   sends zeros), and the write is tried again with every call.
//! - Everything here is blocking but small (two files of a few hundred bytes), like the host's own use of them. The
//!   one slow thing is the write, with its `fsync`, the first time a device is given a secret; the lock is held for
//!   it, so the other callers wait a moment.

use std::{
    collections::{BTreeMap, HashMap},
    fs, io,
    sync::Mutex,
};

use anyhow::{Context as _, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use velora_dht::seal::Secret;
use velora_protocol::{
    identity::{AuthorizedClient, StateDir},
    tls::Fingerprint,
    wire::DEVICE_SECRET_LEN,
};

use super::{dht, lock, ReachContext};

/// Where the secrets are kept, in the host's state directory.
pub(super) const FILE: &str = "reach_secrets.json";

type Bytes = [u8; DEVICE_SECRET_LEN];

/// The secret that opens the host's DHT record for the paired device `fingerprint`, when it has one. Reading only: it
/// makes none (`dht::reach_message` does, when it must). E3 publishes with these, and E5 needs the same secret to open
/// the punch items that device leaves in the DHT. Also available as `ReachContext::device_secret`.
///
/// This is the secret the device must hold *now*: the shared one while more devices are paired than a record has room
/// for. `None` for a device that is not paired, one that was never given a secret, and (in the shared mode) while the
/// shared secret has not been made.
pub fn get(ctx: &ReachContext, fingerprint: &Fingerprint) -> Option<Bytes> {
    let capacity = dht::device_capacity();
    store(ctx).quietly(with(ctx, |data, paired| Ok(data.effective(fingerprint, paired, capacity)))).flatten()
}

/// The secrets of every paired device that has one. Devices removed from the paired list are not in it, whether or not
/// `on_revoked` was told. In the shared mode they all have the shared secret, which is how E5 knows to look up one slot
/// for the lot of them. In the order of the fingerprints.
pub fn all(ctx: &ReachContext) -> Vec<(Fingerprint, Bytes)> {
    let capacity = dht::device_capacity();
    store(ctx).quietly(with(ctx, |data, paired| Ok(data.listing(paired, capacity)))).unwrap_or_default()
}

/// A device was just paired (called through `reach::on_paired`, from a blocking thread, with no lock held). `secret` is
/// the one the pairing link carried; store it for `fingerprint`. With `None`, the link carried none and the secret is
/// made later, the first time `dht::reach_message` is asked for the device. What the device had before, if this is a
/// device that was removed (without anyone saying so) and paired again, is forgotten, the shared secret with it.
///
/// Storing is a small file write in `ctx.state_dir`; a failure is logged, not returned: the device is paired either way
/// and gets a secret with its next `Reach`.
pub fn on_paired(ctx: &ReachContext, fingerprint: &Fingerprint, secret: Option<Bytes>) {
    let stored = with(ctx, |data, _| {
        // A device that is paired anew and still has an entry was taken off the list without anyone saying so: it
        // may hold the shared secret.
        data.forget(fingerprint);
        if let Some(secret) = secret {
            data.devices.insert(*fingerprint, secret);
        }
        Ok(())
    });
    if let Err(e) = stored {
        tracing::warn!("could not keep the secret of the device {fingerprint}: {e:#}");
    }
}

/// A device was removed from the paired list in the launcher (called through `reach::on_revoked`). Forget its secret,
/// so the next publish leaves it out (and, when it may have held the shared secret, make a new one). Removals made with
/// `velora-host revoke` while the host runs do not come here: every call of this module reconciles with
/// `authorized_clients.json`, so they have the same effect a moment later.
pub fn on_revoked(ctx: &ReachContext, fingerprint: &Fingerprint) {
    let forgotten = with(ctx, |data, _| {
        data.forget(fingerprint);
        Ok(())
    });
    if let Err(e) = forgotten {
        tracing::warn!("could not forget the secret of the device {fingerprint}: {e:#}");
    }
}

/// The secret `fingerprint` must hold now, made (and kept) when it has none. `None` when the device is not paired.
/// What `dht::reach_message` calls. In the shared mode it also makes the shared secret. An error when the secrets
/// cannot be kept: nothing is handed out that a restart would lose.
pub(super) fn secret_for(ctx: &ReachContext, fingerprint: &Fingerprint) -> Result<Option<Bytes>> {
    let capacity = dht::device_capacity();
    with_saved(ctx, |data, paired| {
        if !paired.contains(fingerprint) {
            return Ok(None);
        }
        // Every device that is given a secret has an entry of its own, the shared mode included, so that removing
        // it is noticed (and the shared secret changed).
        if !data.devices.contains_key(fingerprint) {
            data.devices.insert(*fingerprint, new_secret()?);
        }
        if paired.len() > capacity && data.shared.is_none() {
            data.shared = Some(new_secret()?);
        }
        Ok(data.effective(fingerprint, paired, capacity))
    })
}

/// Who can read the record the host publishes now.
#[derive(Clone, PartialEq, Eq)]
pub(super) enum Recipients {
    /// No paired device has been given a secret: there is nobody to publish for.
    Nobody,
    /// Each device's own secret, in the order of the fingerprints.
    Devices(Vec<Bytes>),
    /// The one secret all devices share (more are paired than a record has room for).
    Shared(Bytes),
}

impl std::fmt::Debug for Recipients {
    /// Never the secrets themselves.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Recipients::Nobody => f.write_str("Nobody"),
            Recipients::Devices(secrets) => write!(f, "Devices({})", secrets.len()),
            Recipients::Shared(_) => f.write_str("Shared"),
        }
    }
}

/// Who the record is sealed for, with the shared secret made when it is needed.
pub(super) fn recipients(ctx: &ReachContext) -> Result<Recipients> {
    let capacity = dht::device_capacity();
    with(ctx, |data, paired| {
        let holders: Vec<&Fingerprint> =
            paired.iter().filter(|fingerprint| data.devices.contains_key(*fingerprint)).collect();
        if holders.is_empty() {
            return Ok(Recipients::Nobody);
        }
        if paired.len() > capacity {
            let shared = match data.shared {
                Some(shared) => shared,
                None => *data.shared.insert(new_secret()?),
            };
            return Ok(Recipients::Shared(shared));
        }
        Ok(Recipients::Devices(
            holders.iter().filter_map(|fingerprint| data.devices.get(*fingerprint).copied()).collect(),
        ))
    })
}

/// Wakes the publisher when the secrets change: a device got one, lost one, or the shared one was made or changed.
pub(super) fn changes(ctx: &ReachContext) -> watch::Receiver<u64> {
    store(ctx).changed.subscribe()
}

fn new_secret() -> Result<Bytes> {
    Ok(*Secret::generate().context("the system random generator failed")?.as_bytes())
}

// ---------------------------------------------------------------------------------------------
// What is kept
// ---------------------------------------------------------------------------------------------

/// What the file holds: every secret handed out, by device, and the shared one. No `Debug`: it would print them.
#[derive(Default, Clone, PartialEq, Eq)]
struct Data {
    devices: HashMap<Fingerprint, Bytes>,
    shared: Option<Bytes>,
}

impl Data {
    /// Takes a device's entry away, and the shared secret with it: the device may have held that one.
    fn forget(&mut self, fingerprint: &Fingerprint) {
        if self.devices.remove(fingerprint).is_some() {
            self.shared = None;
        }
    }

    /// Drops what belongs to devices that are no longer paired.
    fn reconcile(&mut self, paired: &[Fingerprint]) {
        let gone: Vec<Fingerprint> =
            self.devices.keys().filter(|fingerprint| !paired.contains(fingerprint)).copied().collect();
        for fingerprint in gone {
            self.forget(&fingerprint);
        }
    }

    /// The secret `fingerprint` must hold now: its own, or the shared one when more devices are paired than a record
    /// holds. Nothing for a device that is not paired or has no entry.
    fn effective(&self, fingerprint: &Fingerprint, paired: &[Fingerprint], capacity: usize) -> Option<Bytes> {
        if !paired.contains(fingerprint) {
            return None;
        }
        let own = self.devices.get(fingerprint)?;
        if paired.len() > capacity {
            self.shared
        } else {
            Some(*own)
        }
    }

    fn listing(&self, paired: &[Fingerprint], capacity: usize) -> Vec<(Fingerprint, Bytes)> {
        paired
            .iter()
            .filter_map(|fingerprint| Some((*fingerprint, self.effective(fingerprint, paired, capacity)?)))
            .collect()
    }

    fn from_file(file: OnDisk) -> Data {
        let devices: HashMap<Fingerprint, Bytes> = file
            .devices
            .iter()
            .filter_map(|(fingerprint, secret)| Some((Fingerprint::from_base64(fingerprint).ok()?, decode(secret)?)))
            .collect();
        // An entry that cannot be read may have been a device that holds the shared secret.
        let lost = devices.len() != file.devices.len();
        Data { devices, shared: file.shared.as_deref().and_then(decode).filter(|_| !lost) }
    }

    fn to_file(&self) -> OnDisk {
        OnDisk {
            devices: self
                .devices
                .iter()
                .map(|(fingerprint, secret)| (fingerprint.to_base64(), encode(secret)))
                .collect(),
            shared: self.shared.as_ref().map(encode),
        }
    }
}

/// The file as JSON: fingerprints and secrets as base64url text, like the other state files. A secret that is not text
/// of the right size is read as absent.
#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
struct OnDisk {
    devices: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    shared: Option<String>,
}

fn decode(text: &str) -> Option<Bytes> {
    URL_SAFE_NO_PAD.decode(text).ok()?.try_into().ok()
}

fn encode(secret: &Bytes) -> String {
    URL_SAFE_NO_PAD.encode(secret)
}

/// Whether a file that was not found is missing and not out of reach: its directory is there. On Windows `NotFound` is
/// also what a share that is gone for a moment says, and "no paired devices, no secrets" is the one wrong answer that
/// destroys what is kept.
fn directory_is_there(state: &StateDir) -> bool {
    state.dir().is_dir()
}

/// Reads the file. Nothing there is an empty set; a file that cannot be read is an error and is left alone; one that is
/// read but is not ours is set aside.
fn load(state: &StateDir) -> Result<Data> {
    let path = state.path(FILE);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound && directory_is_there(state) => return Ok(Data::default()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    match serde_json::from_slice::<OnDisk>(&bytes) {
        Ok(file) => Ok(Data::from_file(file)),
        Err(e) => {
            let aside = path.with_extension("json.damaged");
            tracing::warn!(
                "{} cannot be read ({e}): kept as {}, and the devices get new secrets",
                path.display(),
                aside.display()
            );
            if let Err(e) = fs::rename(&path, &aside) {
                tracing::warn!("could not set {} aside: {e}", path.display());
            }
            Ok(Data::default())
        }
    }
}

/// Writes the file; whether it worked. A failure is tried again with the next call, and said once, not at every try.
fn save(state: &StateDir, data: &Data, first_try: bool) -> bool {
    match state.save(FILE, &data.to_file()) {
        Ok(()) => true,
        Err(e) if first_try => {
            tracing::warn!("could not save the device secrets, trying again with the next call: {e:#}");
            false
        }
        Err(e) => {
            tracing::debug!("the device secrets are still not saved: {e:#}");
            false
        }
    }
}

/// The paired devices, in the order of their fingerprints, without repeats and without entries that are not
/// fingerprints. A list that is not there, in a directory that is, is an empty one; one that cannot be read is an
/// error, never "nobody is paired" (`StateDir::load` would say that for any failure to look at the file, a share that
/// dropped for a moment included, and every secret would be dropped with it).
fn paired(state: &StateDir) -> Result<Vec<Fingerprint>> {
    let path = state.path(StateDir::AUTHORIZED_CLIENTS);
    let clients: Vec<AuthorizedClient> = match fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))?,
        Err(e) if e.kind() == io::ErrorKind::NotFound && directory_is_there(state) => Vec::new(),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let mut paired: Vec<Fingerprint> =
        clients.iter().filter_map(|client| Fingerprint::from_base64(&client.fingerprint).ok()).collect();
    paired.sort_by_key(|fingerprint| fingerprint.0);
    paired.dedup();
    Ok(paired)
}

// ---------------------------------------------------------------------------------------------
// The store: one per host, in `ReachContext::ext`
// ---------------------------------------------------------------------------------------------

/// What a host keeps in memory: the secrets once read, whether the file is behind them, who is told of changes, and
/// the last error that was logged (so a list that cannot be read is said once, not every ten seconds).
struct Store {
    kept: Mutex<Kept>,
    changed: watch::Sender<u64>,
    reported: Mutex<Option<String>>,
}

#[derive(Default)]
struct Kept {
    /// `None` until the first use.
    data: Option<Data>,
    /// The last write failed: the next call writes again.
    unsaved: bool,
}

impl Default for Store {
    fn default() -> Self {
        Store { kept: Mutex::default(), changed: watch::channel(0).0, reported: Mutex::default() }
    }
}

impl Store {
    /// The answer, or nothing and a line in the log (once per distinct error until something works again).
    fn quietly<T>(&self, result: Result<T>) -> Option<T> {
        let mut reported = lock(&self.reported);
        match result {
            Ok(value) => {
                *reported = None;
                Some(value)
            }
            Err(e) => {
                let text = format!("{e:#}");
                if reported.as_deref() != Some(text.as_str()) {
                    tracing::warn!("the device secrets are not available: {text}");
                    *reported = Some(text);
                }
                None
            }
        }
    }
}

fn store(ctx: &ReachContext) -> std::sync::Arc<Store> {
    ctx.ext::<Store>()
}

/// Runs `f` on the secrets, reconciled with the paired list, and writes them when `f` or the reconciliation changed
/// something. Fails (changing nothing) when the paired list or the file cannot be read. A write that fails is not an
/// error here: the secrets stay in memory and the next call writes them.
fn with<R>(ctx: &ReachContext, f: impl FnOnce(&mut Data, &[Fingerprint]) -> Result<R>) -> Result<R> {
    with_state(ctx, f).map(|(result, _saved)| result)
}

/// [`with`] for what must not be given out before it is kept: fails when the file does not hold what the memory does
/// (a device that was told a secret the host then lost, by a restart, could not read any record).
fn with_saved<R>(ctx: &ReachContext, f: impl FnOnce(&mut Data, &[Fingerprint]) -> Result<R>) -> Result<R> {
    let (result, saved) = with_state(ctx, f)?;
    if saved {
        Ok(result)
    } else {
        anyhow::bail!("the device secrets cannot be saved, so none is handed out")
    }
}

/// [`with`], and whether the file holds what the memory does afterwards.
fn with_state<R>(ctx: &ReachContext, f: impl FnOnce(&mut Data, &[Fingerprint]) -> Result<R>) -> Result<(R, bool)> {
    let store = store(ctx);
    let mut guard = lock(&store.kept);
    let kept = &mut *guard;
    let paired = paired(&ctx.state_dir).context("reading the list of paired devices")?;
    let data = match &mut kept.data {
        Some(data) => data,
        empty => empty.insert(load(&ctx.state_dir)?),
    };
    let before = data.clone();
    data.reconcile(&paired);
    let result = f(data, &paired);
    let changed = *data != before;
    if changed || kept.unsaved {
        kept.unsaved = !save(&ctx.state_dir, data, !kept.unsaved);
    }
    let saved = !kept.unsaved;
    drop(guard);
    if changed {
        store.changed.send_modify(|version| *version += 1);
    }
    Ok((result?, saved))
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, sync::Arc};

    use super::*;
    use crate::reach::{
        testing::{self, Scratch},
        Reach, ReachState,
    };

    fn fp(n: u8) -> Fingerprint {
        Fingerprint([n; 32])
    }

    /// A host with an empty state directory.
    fn host() -> (ReachContext, Scratch) {
        testing::context("e3-secrets")
    }

    /// The paired list becomes exactly these devices.
    fn pair(ctx: &ReachContext, devices: &[Fingerprint]) {
        let clients: Vec<AuthorizedClient> = devices
            .iter()
            .map(|device| AuthorizedClient {
                name: format!("device {}", device.short()),
                fingerprint: device.to_base64(),
                added_unix: 0,
                trust_files: false,
            })
            .collect();
        ctx.state_dir.save(StateDir::AUTHORIZED_CLIENTS, &clients).unwrap();
    }

    /// The same host after a restart: the same state directory, nothing in memory.
    fn restart(ctx: &ReachContext) -> ReachContext {
        ReachContext::new(
            Reach::new(ReachState::default()),
            ctx.state_dir.clone(),
            (*ctx.identity).clone(),
            ctx.bind,
            ctx.endpoint.clone(),
            ctx.socket.clone(),
        )
    }

    fn file_text(ctx: &ReachContext) -> String {
        fs::read_to_string(ctx.state_dir.path(FILE)).unwrap()
    }

    /// `n` paired devices, `fp(1)` to `fp(n)`.
    fn crowd(ctx: &ReachContext, n: usize) -> Vec<Fingerprint> {
        let devices: Vec<Fingerprint> = (1..=u8::try_from(n).unwrap()).map(fp).collect();
        pair(ctx, &devices);
        devices
    }

    #[tokio::test]
    async fn the_secret_a_pairing_link_carried_is_stored_and_read_back() {
        let (ctx, _scratch) = host();
        pair(&ctx, &[fp(1)]);
        assert_eq!(get(&ctx, &fp(1)), None, "nothing before the device is given one");

        on_paired(&ctx, &fp(1), Some([7; 16]));
        assert_eq!(get(&ctx, &fp(1)), Some([7; 16]));
        assert_eq!(all(&ctx), vec![(fp(1), [7; 16])]);
        assert_eq!(ctx.device_secret(&fp(1)), Some([7; 16]), "the accessor on the context says the same");
        // And it is on disk for the next run, as text.
        let again = restart(&ctx);
        assert_eq!(get(&again, &fp(1)), Some([7; 16]));
        assert!(file_text(&ctx).contains(&encode(&[7; 16])), "{}", file_text(&ctx));
    }

    #[tokio::test]
    async fn a_device_that_asks_is_given_a_secret_once_and_keeps_it() {
        let (ctx, _scratch) = host();
        pair(&ctx, &[fp(1), fp(2)]);
        let first = secret_for(&ctx, &fp(1)).unwrap().expect("a secret");
        assert_eq!(secret_for(&ctx, &fp(1)).unwrap(), Some(first), "asking again changes nothing");
        assert_eq!(get(&ctx, &fp(1)), Some(first));
        let second = secret_for(&ctx, &fp(2)).unwrap().expect("a secret");
        assert_ne!(first, second, "every device has its own");
        assert_ne!(first, [0; 16], "and it is random");
        assert_eq!(secret_for(&restart(&ctx), &fp(1)).unwrap(), Some(first), "it survives a restart");
    }

    #[tokio::test]
    async fn a_device_that_is_not_paired_has_no_secret_and_is_given_none() {
        let (ctx, _scratch) = host();
        pair(&ctx, &[fp(1)]);
        assert_eq!(secret_for(&ctx, &fp(9)).unwrap(), None);
        let kept = fs::read_to_string(ctx.state_dir.path(FILE)).unwrap_or_default();
        assert!(!kept.contains(&fp(9).to_base64()), "nothing is made or kept for it: {kept}");
        assert_eq!(get(&ctx, &fp(9)), None);
        // A secret that was stored for it all the same is not an answer either.
        on_paired(&ctx, &fp(9), Some([9; 16]));
        assert_eq!(get(&ctx, &fp(9)), None);
        assert_eq!(all(&ctx), vec![]);
        assert!(!file_text(&ctx).contains(&encode(&[9; 16])), "and it is not kept: {}", file_text(&ctx));
    }

    #[tokio::test]
    async fn a_device_removed_behind_the_hosts_back_is_gone_from_every_answer() {
        let (ctx, _scratch) = host();
        pair(&ctx, &[fp(1), fp(2)]);
        let kept = secret_for(&ctx, &fp(1)).unwrap().unwrap();
        let gone = secret_for(&ctx, &fp(2)).unwrap().unwrap();
        assert_eq!(all(&ctx).len(), 2);

        // `velora-host revoke` while the host runs: the list changes, nothing announces it.
        pair(&ctx, &[fp(1)]);
        assert_eq!(get(&ctx, &fp(2)), None);
        assert_eq!(all(&ctx), vec![(fp(1), kept)]);
        assert_eq!(recipients(&ctx).unwrap(), Recipients::Devices(vec![kept]));
        assert!(!file_text(&ctx).contains(&encode(&gone)), "its secret is dropped from the file too");

        // Paired again later, it is a new pairing: whatever it held before opens nothing.
        pair(&ctx, &[fp(1), fp(2)]);
        assert_eq!(get(&ctx, &fp(2)), None);
        assert_ne!(secret_for(&ctx, &fp(2)).unwrap(), Some(gone));
    }

    #[tokio::test]
    async fn revoking_forgets_the_secret_and_pairing_without_one_starts_afresh() {
        let (ctx, _scratch) = host();
        pair(&ctx, &[fp(1), fp(2)]);
        on_paired(&ctx, &fp(1), Some([1; 16]));
        on_paired(&ctx, &fp(2), Some([2; 16]));

        pair(&ctx, &[fp(1)]);
        on_revoked(&ctx, &fp(2));
        assert_eq!(all(&ctx), vec![(fp(1), [1; 16])]);

        // A pairing whose link carried no secret drops one the device had: the next is made on demand.
        on_paired(&ctx, &fp(1), None);
        assert_eq!(get(&ctx, &fp(1)), None);
        let fresh = secret_for(&ctx, &fp(1)).unwrap().unwrap();
        assert_ne!(fresh, [1; 16]);
    }

    #[tokio::test]
    async fn revoking_forgets_the_secret_even_before_the_list_says_so() {
        let (ctx, _scratch) = host();
        pair(&ctx, &[fp(1), fp(2)]);
        on_paired(&ctx, &fp(1), Some([1; 16]));
        on_paired(&ctx, &fp(2), Some([2; 16]));
        // The launcher's hook comes while the device is still on the list (the list may be written after it).
        on_revoked(&ctx, &fp(2));
        assert_eq!(get(&ctx, &fp(2)), None);
        assert_eq!(all(&ctx), vec![(fp(1), [1; 16])]);
        assert!(!file_text(&ctx).contains(&encode(&[2; 16])));
    }

    #[tokio::test]
    async fn the_records_recipients_are_the_devices_that_hold_a_secret() {
        let (ctx, _scratch) = host();
        pair(&ctx, &[fp(1), fp(2), fp(3)]);
        assert_eq!(recipients(&ctx).unwrap(), Recipients::Nobody, "nobody holds a secret yet");

        on_paired(&ctx, &fp(3), Some([3; 16]));
        on_paired(&ctx, &fp(1), Some([1; 16]));
        // The order of the fingerprints, not of the pairing.
        assert_eq!(recipients(&ctx).unwrap(), Recipients::Devices(vec![[1; 16], [3; 16]]));
        // A device that is paired but has not been given a secret is not one of them.
        assert_eq!(get(&ctx, &fp(2)), None);
    }

    #[tokio::test]
    async fn more_devices_than_a_record_holds_share_one_secret() {
        let (ctx, _scratch) = host();
        let capacity = dht::device_capacity();
        let devices = crowd(&ctx, capacity + 1);
        let shared = secret_for(&ctx, &devices[0]).unwrap().expect("a secret");
        for device in &devices {
            assert_eq!(secret_for(&ctx, device).unwrap(), Some(shared), "the same for everybody");
            assert_eq!(get(&ctx, device), Some(shared));
        }
        assert_eq!(all(&ctx), devices.iter().map(|device| (*device, shared)).collect::<Vec<_>>());
        assert_eq!(recipients(&ctx).unwrap(), Recipients::Shared(shared));
        // It is kept, and not made again by the next run.
        assert_eq!(secret_for(&restart(&ctx), &devices[3]).unwrap(), Some(shared));

        // One device fewer: the last one is among those that held it, so the shared secret is dropped, and every
        // device is on its own secret again (which it does not hold yet: it learns it with its next `Reach`).
        let fewer = &devices[..capacity];
        pair(&ctx, fewer);
        let own: Vec<Bytes> = fewer.iter().map(|device| get(&ctx, device).expect("its own secret")).collect();
        assert!(own.iter().all(|secret| *secret != shared));
        assert_eq!(own.iter().collect::<HashSet<_>>().len(), own.len(), "all different");
        assert_eq!(recipients(&ctx).unwrap(), Recipients::Devices(own));
    }

    #[tokio::test]
    async fn the_shared_secret_changes_when_a_device_that_was_given_a_secret_goes() {
        let (ctx, _scratch) = host();
        // So many that one fewer is still too many.
        let devices = crowd(&ctx, dht::device_capacity() + 3);
        let (leaving, staying, never_asked) = (devices[0], devices[1], devices[devices.len() - 1]);
        let shared = secret_for(&ctx, &leaving).unwrap().unwrap();
        assert_eq!(secret_for(&ctx, &staying).unwrap(), Some(shared));

        // A device that held it goes, announced or not.
        let without = |gone: &[Fingerprint]| -> Vec<Fingerprint> {
            devices.iter().filter(|device| !gone.contains(device)).copied().collect()
        };
        pair(&ctx, &without(&[leaving]));
        let renewed = secret_for(&ctx, &staying).unwrap().unwrap();
        assert_ne!(renewed, shared, "what the one who left held opens nothing now");
        assert_eq!(get(&ctx, &staying), Some(renewed));
        assert_eq!(recipients(&ctx).unwrap(), Recipients::Shared(renewed));

        // One that was paired but never given a secret held nothing: nothing changes when it goes.
        pair(&ctx, &without(&[leaving, never_asked]));
        assert_eq!(secret_for(&ctx, &staying).unwrap(), Some(renewed));
    }

    #[tokio::test]
    async fn a_per_device_secret_that_goes_does_not_change_the_others() {
        let (ctx, _scratch) = host();
        pair(&ctx, &[fp(1), fp(2)]);
        let first = secret_for(&ctx, &fp(1)).unwrap().unwrap();
        let second = secret_for(&ctx, &fp(2)).unwrap().unwrap();
        pair(&ctx, &[fp(1)]);
        on_revoked(&ctx, &fp(2));
        assert_eq!(secret_for(&ctx, &fp(1)).unwrap(), Some(first));
        assert_ne!(secret_for(&ctx, &fp(1)).unwrap(), Some(second));
    }

    #[tokio::test]
    async fn the_file_holds_text_and_a_bad_entry_costs_that_entry_only() {
        let (ctx, _scratch) = host();
        pair(&ctx, &[fp(1), fp(2), fp(3)]);
        let text = format!(
            r#"{{"devices": {{"{}": "{}", "{}": "not base64!", "{}": "AAAA", "not a fingerprint": "{}"}},
                "shared": "AAAA"}}"#,
            fp(1).to_base64(),
            encode(&[1; 16]),
            fp(2).to_base64(),
            fp(3).to_base64(),
            encode(&[5; 16]),
        );
        fs::write(ctx.state_dir.path(FILE), text).unwrap();
        assert_eq!(all(&ctx), vec![(fp(1), [1; 16])]);
        assert_eq!(secret_for(&ctx, &fp(2)).unwrap().map(|secret| secret.len()), Some(16), "made again on demand");
    }

    #[tokio::test]
    async fn a_file_that_is_not_ours_is_kept_aside_and_the_devices_get_new_secrets() {
        let (ctx, _scratch) = host();
        pair(&ctx, &[fp(1)]);
        let path = ctx.state_dir.path(FILE);
        fs::write(&path, "[1, 2, 3]").unwrap();
        let fresh = secret_for(&ctx, &fp(1)).unwrap().expect("a secret");
        assert_eq!(fs::read_to_string(path.with_extension("json.damaged")).unwrap(), "[1, 2, 3]");
        assert!(file_text(&ctx).contains(&encode(&fresh)));
    }

    #[tokio::test]
    async fn a_file_that_cannot_be_read_is_not_written_over() {
        let (ctx, _scratch) = host();
        pair(&ctx, &[fp(1)]);
        // A directory where the file should be: reading it fails in a way that says nothing about its contents.
        let path = ctx.state_dir.path(FILE);
        fs::create_dir(&path).unwrap();
        assert!(secret_for(&ctx, &fp(1)).is_err());
        assert_eq!(get(&ctx, &fp(1)), None);
        assert!(path.is_dir(), "left as it was");

        // Once it can be read, the calls work, and nothing was decided meanwhile.
        fs::remove_dir(&path).unwrap();
        assert!(secret_for(&ctx, &fp(1)).unwrap().is_some());
    }

    #[tokio::test]
    async fn a_paired_list_that_cannot_be_read_is_an_error_and_not_nobody() {
        let (ctx, _scratch) = host();
        pair(&ctx, &[fp(1)]);
        let secret = secret_for(&ctx, &fp(1)).unwrap().unwrap();
        fs::write(ctx.state_dir.path(StateDir::AUTHORIZED_CLIENTS), "not json").unwrap();
        assert!(secret_for(&ctx, &fp(1)).is_err());
        assert_eq!(all(&ctx), vec![], "no answer, and the secrets are not dropped meanwhile");
        pair(&ctx, &[fp(1)]);
        assert_eq!(get(&ctx, &fp(1)), Some(secret));
    }

    #[tokio::test]
    async fn the_publisher_is_woken_by_changes_and_by_nothing_else() {
        let (ctx, _scratch) = host();
        pair(&ctx, &[fp(1), fp(2)]);
        let mut changes = changes(&ctx);
        changes.mark_unchanged();

        let _ = get(&ctx, &fp(1));
        let _ = all(&ctx);
        let _ = recipients(&ctx).unwrap();
        assert!(!changes.has_changed().unwrap(), "reading says nothing");

        let secret = secret_for(&ctx, &fp(1)).unwrap().unwrap();
        assert!(changes.has_changed().unwrap(), "a device was given a secret");
        changes.mark_unchanged();
        assert_eq!(secret_for(&ctx, &fp(1)).unwrap(), Some(secret));
        assert!(!changes.has_changed().unwrap(), "asking again changes nothing");

        pair(&ctx, &[fp(2)]);
        let _ = all(&ctx);
        assert!(changes.has_changed().unwrap(), "a device went, announced or not");
    }

    #[tokio::test]
    async fn a_write_that_failed_is_tried_again() {
        let (ctx, _scratch) = host();
        pair(&ctx, &[fp(1)]);
        // The temporary file cannot be made while a directory has its name.
        let tmp = ctx.state_dir.path(FILE).with_extension("tmp");
        fs::create_dir(&tmp).unwrap();
        on_paired(&ctx, &fp(1), Some([3; 16]));
        assert_eq!(get(&ctx, &fp(1)), Some([3; 16]), "kept in memory all the same");
        assert!(!ctx.state_dir.path(FILE).exists());

        fs::remove_dir(&tmp).unwrap();
        let _ = get(&ctx, &fp(1));
        assert!(file_text(&ctx).contains(&encode(&[3; 16])), "written by the next call");
    }

    #[tokio::test]
    async fn a_state_directory_that_is_gone_is_not_an_empty_one() {
        let (ctx, _scratch) = host();
        pair(&ctx, &[fp(1)]);
        let secret = secret_for(&ctx, &fp(1)).unwrap().unwrap();

        // The directory goes (a share that dropped, a disk that was pulled): nothing can be found in it, which is
        // not "nobody is paired and no secret was made".
        let dir = ctx.state_dir.dir().to_path_buf();
        let away = dir.with_extension("away");
        fs::rename(&dir, &away).unwrap();
        assert!(paired(&ctx.state_dir).is_err());
        assert!(secret_for(&ctx, &fp(1)).is_err());
        assert_eq!(get(&ctx, &fp(1)), None);
        assert_eq!(all(&ctx), vec![]);

        // It comes back as it was: nothing was dropped, and nothing was written over.
        fs::rename(&away, &dir).unwrap();
        assert_eq!(get(&ctx, &fp(1)), Some(secret));
        assert!(file_text(&ctx).contains(&encode(&secret)));
        assert_eq!(secret_for(&restart(&ctx), &fp(1)).unwrap(), Some(secret));
    }

    #[tokio::test]
    async fn a_directory_that_is_gone_when_the_secrets_are_first_read_is_not_an_empty_set_either() {
        let (ctx, _scratch) = host();
        let secrets = ctx.state_dir.path(FILE);
        fs::write(&secrets, "{}").unwrap();
        let dir = ctx.state_dir.dir().to_path_buf();
        let away = dir.with_extension("away");
        fs::rename(&dir, &away).unwrap();
        assert!(load(&ctx.state_dir).is_err(), "not found, in a directory that is not found");
        fs::rename(&away, &dir).unwrap();
        assert!(load(&ctx.state_dir).unwrap() == Data::default(), "found, and empty");
    }

    #[tokio::test]
    async fn pairing_a_device_anew_changes_the_shared_secret_it_may_hold() {
        let (ctx, _scratch) = host();
        let devices = crowd(&ctx, dht::device_capacity() + 2);
        let shared = secret_for(&ctx, &devices[0]).unwrap().unwrap();
        assert_eq!(secret_for(&ctx, &devices[1]).unwrap(), Some(shared));

        // The first device was taken off the list with `velora-host revoke` while nothing was looking, and paired
        // again (the link carried no secret): it still holds the shared secret, and its old entry was still there.
        on_paired(&ctx, &devices[0], None);
        let renewed = secret_for(&ctx, &devices[1]).unwrap().unwrap();
        assert_ne!(renewed, shared);
        assert_eq!(secret_for(&ctx, &devices[0]).unwrap(), Some(renewed), "and it is told the new one");

        // Removed for good later, it is the new one that changes.
        let rest: Vec<Fingerprint> = devices.iter().filter(|device| **device != devices[0]).copied().collect();
        pair(&ctx, &rest);
        assert_ne!(secret_for(&ctx, &devices[1]).unwrap().unwrap(), renewed);
    }

    #[tokio::test]
    async fn an_entry_that_cannot_be_read_takes_the_shared_secret_with_it() {
        let (ctx, _scratch) = host();
        let devices = crowd(&ctx, dht::device_capacity() + 2);
        let text = format!(
            r#"{{"devices": {{"{}": "{}", "{}": "not base64!"}}, "shared": "{}"}}"#,
            devices[0].to_base64(),
            encode(&[1; 16]),
            devices[1].to_base64(),
            encode(&[9; 16]),
        );
        fs::write(ctx.state_dir.path(FILE), text).unwrap();
        // The device whose entry is lost may have held the shared secret in the file: it is not used again.
        let shared = secret_for(&ctx, &devices[0]).unwrap().unwrap();
        assert_ne!(shared, [9; 16]);
    }

    #[tokio::test]
    async fn a_secret_that_is_not_kept_is_not_handed_out_until_it_is() {
        let (ctx, _scratch) = host();
        pair(&ctx, &[fp(1)]);
        // The temporary file cannot be made while a directory has its name.
        let tmp = ctx.state_dir.path(FILE).with_extension("tmp");
        fs::create_dir(&tmp).unwrap();
        assert!(secret_for(&ctx, &fp(1)).is_err(), "it could not be written, so the device is not told it");
        assert!(secret_for(&ctx, &fp(1)).is_err(), "nor the second time, when the entry is in memory only");

        fs::remove_dir(&tmp).unwrap();
        let told = secret_for(&ctx, &fp(1)).unwrap().expect("a secret now");
        assert!(file_text(&ctx).contains(&encode(&told)), "and what it was told is on disk");
        assert_eq!(secret_for(&restart(&ctx), &fp(1)).unwrap(), Some(told));
    }

    #[tokio::test]
    async fn a_list_that_is_not_there_is_nobody_and_one_that_cannot_be_read_is_not() {
        let (ctx, _scratch) = host();
        assert_eq!(paired(&ctx.state_dir).unwrap(), vec![]);
        // A directory in its place cannot be read: an error, and no secret is dropped for it.
        let list = ctx.state_dir.path(StateDir::AUTHORIZED_CLIENTS);
        fs::create_dir(&list).unwrap();
        assert!(paired(&ctx.state_dir).is_err());
        fs::remove_dir(&list).unwrap();
        pair(&ctx, &[fp(2), fp(1), fp(1)]);
        assert_eq!(paired(&ctx.state_dir).unwrap(), vec![fp(1), fp(2)], "in order, without repeats");
    }

    #[tokio::test]
    async fn calls_from_several_threads_agree() {
        let (ctx, _scratch) = host();
        pair(&ctx, &[fp(1)]);
        let ctx = Arc::new(ctx);
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let ctx = ctx.clone();
                std::thread::spawn(move || secret_for(&ctx, &fp(1)).unwrap().unwrap())
            })
            .collect();
        let secrets: HashSet<Bytes> = handles.into_iter().map(|handle| handle.join().unwrap()).collect();
        assert_eq!(secrets.len(), 1, "one secret for the device, however many asked at once");
    }
}
