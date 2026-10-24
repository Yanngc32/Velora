//! Sealing a record for each paired device, so a revoked device cannot read the next one.
//!
//! The DHT is public: anyone can fetch the value stored at a key. What goes in is encrypted so that only the
//! devices paired with the host can read it, and so that unpairing one means something: the next value is simply
//! sealed without it.
//!
//! A fresh random content key encrypts the payload. That key is wrapped once per recipient, under a key derived
//! from the recipient's own 16-byte [`Secret`]. A recipient finds its wrap by trying them all (there are at most
//! 20), so the blob names no device: a public record shows how many devices are paired, and nothing that tells
//! them apart or links one to another host.
//!
//! ```text
//! blob = VERSION (1) | count (1) | nonce (12) | wrap * count | payload under the content key + tag (16)
//! wrap = the content key (32) under the recipient's key + tag (16) = 48 bytes
//! ```
//!
//! Only `ring` is used, and nothing is hand-made:
//! - A recipient's key is `HKDF-SHA256(secret)` with a fixed label, 32 bytes for ChaCha20-Poly1305. The secret has
//!   128 bits, the cipher wants 256, and the label keeps the key from being a key for anything else.
//! - One 96-bit nonce per seal, random. Every AEAD call of a seal gets its own nonce from it: the payload uses it
//!   as is, wrap `i` (counting from 1) has `i` XORed into the last byte. A wrap has no room for a nonce of its own
//!   (at 60 bytes per device, 12 devices would leave too little of the 1000 bytes for the record), and this way no
//!   two calls of a seal share a (key, nonce) pair even if two recipients were given the same secret. A
//!   recipient's key outlives the seal, so across seals a pair repeats only if two random nonces coincide but for
//!   the last byte.
//! - The associated data of every call binds the purpose (wrap or payload), [`VERSION`], `seq` and the salt, so a
//!   blob cannot be replayed under another sequence number or salt, and a wrap is no payload. The payload's also
//!   covers the count, the nonce and every wrap, so changing any byte of the blob, one that is another device's
//!   wrap included, makes it fail for everybody.
//!
//! The value must stay under BEP 44's limit ([`MAX_SEALED_LEN`]), and the layout leaves room for a record with 8
//! addresses and about 12 devices. When the devices do not fit, [`seal`] falls back to a single wrap under one
//! *shared* secret, if the caller has one: every paired device must hold it, so revoking one then means changing
//! the secret of all of them. [`Sealed::per_device`] says which happened. Getting the shared secret to the devices
//! is the caller's job, and it must reach them over a connection before the first shared blob, since a device that
//! holds only its own secret cannot read one.
//!
//! Revoking takes effect from the next publish. A revoked device can still read the last value it could open,
//! which DHT nodes keep for about two hours.

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic))]

use std::fmt;

use ring::{
    aead::{self, Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305},
    error::Unspecified,
    hkdf,
    rand::{SecureRandom, SystemRandom},
};
use thiserror::Error;

use crate::record::{Record, RecordError};

/// First byte of a sealed blob, and part of every call's associated data.
pub const VERSION: u8 = 1;

/// The longest blob [`seal`] returns. BEP 44 allows 1000 bytes of bencoded value, and a byte string of this size
/// is bencoded with a four-byte `NNN:` prefix; `mainline` would take the 1000 raw bytes, but nodes that count the
/// prefix would not.
pub const MAX_SEALED_LEN: usize = 1000 - 4;

/// What one recipient costs in the blob.
pub const WRAP_LEN: usize = KEY_LEN + TAG_LEN;

/// What a blob costs besides its wraps and the payload: version, count, nonce and the payload's tag.
pub const OVERHEAD: usize = 1 + 1 + NONCE_LEN + TAG_LEN;

/// Length of a [`Secret`].
pub const SECRET_LEN: usize = 16;

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = aead::NONCE_LEN;
const TAG_LEN: usize = 16;

/// Which call an associated data is for.
const PURPOSE_WRAP: u8 = 1;
const PURPOSE_CONTENT: u8 = 2;

const WRAP_KEY_LABEL: &[u8] = b"velora-dht/seal/v1 wrap key";

/// What a device holds to read the host's record: given to it at pairing or over `HostMsg::Reach`. It never
/// shows in `Debug`.
#[derive(Clone)]
pub struct Secret([u8; SECRET_LEN]);

impl Secret {
    pub fn new(bytes: [u8; SECRET_LEN]) -> Self {
        Self(bytes)
    }

    /// A fresh random one.
    pub fn generate() -> Result<Self, SealError> {
        let mut bytes = [0u8; SECRET_LEN];
        SystemRandom::new().fill(&mut bytes)?;
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; SECRET_LEN] {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(..)")
    }
}

/// What [`seal`] made.
#[derive(Debug)]
pub struct Sealed {
    /// The value to publish.
    pub blob: Vec<u8>,
    /// True when each device has its own wrap. False when the devices did not fit and only the holders of the
    /// shared secret can read it.
    pub per_device: bool,
}

#[derive(Debug, Error)]
pub enum SealError {
    #[error("there is no device and no shared secret to seal for")]
    NoRecipients,
    #[error("sealed record is {over} bytes over the {limit}-byte DHT limit ({wraps} wraps)", limit = MAX_SEALED_LEN)]
    TooLarge { over: usize, wraps: usize },
    #[error(transparent)]
    Record(#[from] RecordError),
    #[error("the system random generator or the cipher failed")]
    Crypto,
}

impl From<Unspecified> for SealError {
    fn from(_: Unspecified) -> Self {
        Self::Crypto
    }
}

#[derive(Debug, Error)]
pub enum OpenError {
    #[error("the sealed record is malformed: {0}")]
    Malformed(&'static str),
    #[error("sealed record version {0} is not supported (this build reads version {current})", current = VERSION)]
    Version(u8),
    /// The wrong secret, a revoked device, or a blob sealed for another salt or sequence number: they look alike
    /// on purpose.
    #[error("no key wrap in the sealed record opens with this secret, salt and sequence number")]
    NotRecipient,
    #[error("the sealed record failed authentication")]
    Corrupt,
    #[error(transparent)]
    Record(#[from] RecordError),
    #[error("the cipher failed")]
    Crypto,
}

impl From<Unspecified> for OpenError {
    fn from(_: Unspecified) -> Self {
        Self::Crypto
    }
}

/// Seals `record` for the DHT item at `salt` with sequence number `seq`. `devices` are the secrets of the paired
/// devices (leave a revoked one out); `shared` is what to use instead when they do not fit, if there is one.
pub fn seal(
    record: &Record,
    salt: &[u8],
    seq: i64,
    devices: &[Secret],
    shared: Option<&Secret>,
) -> Result<Sealed, SealError> {
    seal_payload(&record.encode()?, salt, seq, devices, shared)
}

/// Opens what [`seal`] made, with the secret of one of its recipients, for the same `salt` and `seq`.
pub fn open(blob: &[u8], salt: &[u8], seq: i64, secret: &Secret) -> Result<Record, OpenError> {
    Ok(Record::decode(&open_payload(blob, salt, seq, secret)?)?)
}

/// [`seal`] for any bytes, for the other items that travel the same way.
pub fn seal_payload(
    plain: &[u8],
    salt: &[u8],
    seq: i64,
    devices: &[Secret],
    shared: Option<&Secret>,
) -> Result<Sealed, SealError> {
    let fits = !devices.is_empty() && blob_len(plain.len(), devices.len()) <= MAX_SEALED_LEN;
    let (recipients, per_device) = match shared {
        Some(shared) if !fits => {
            if !devices.is_empty() {
                tracing::warn!(
                    devices = devices.len(),
                    "devices do not fit in one record, sealing for the shared secret: revoking one needs a new secret"
                );
            }
            (std::slice::from_ref(shared), false)
        }
        _ => (devices, true),
    };
    if recipients.is_empty() {
        return Err(SealError::NoRecipients);
    }
    let len = blob_len(plain.len(), recipients.len());
    if len > MAX_SEALED_LEN {
        return Err(SealError::TooLarge { over: len - MAX_SEALED_LEN, wraps: recipients.len() });
    }

    let rng = SystemRandom::new();
    let mut content_key = [0u8; KEY_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill(&mut content_key)?;
    rng.fill(&mut nonce)?;
    let blob = seal_with(plain, salt, seq, recipients, &content_key, &nonce)?;
    Ok(Sealed { blob, per_device })
}

/// [`open`] for any bytes.
pub fn open_payload(blob: &[u8], salt: &[u8], seq: i64, secret: &Secret) -> Result<Vec<u8>, OpenError> {
    const TRUNCATED: OpenError = OpenError::Malformed("truncated");

    if blob.len() > MAX_SEALED_LEN {
        return Err(OpenError::Malformed("longer than a DHT value can be"));
    }
    let (&version, body) = blob.split_first().ok_or(TRUNCATED)?;
    if version != VERSION {
        return Err(OpenError::Version(version));
    }
    let (&count, rest) = body.split_first().ok_or(TRUNCATED)?;
    let (nonce, rest) = rest.split_first_chunk::<NONCE_LEN>().ok_or(TRUNCATED)?;
    let (wraps, payload) = rest.split_at_checked(usize::from(count) * WRAP_LEN).ok_or(TRUNCATED)?;
    if count == 0 {
        return Err(OpenError::Malformed("no key wraps"));
    }
    if payload.len() < TAG_LEN {
        return Err(TRUNCATED);
    }
    // Count, nonce and wraps: authenticated with the payload.
    let header = body.get(..1 + NONCE_LEN + wraps.len()).ok_or(TRUNCATED)?;

    let key = wrap_key(secret)?;
    let wrap_aad = aad(PURPOSE_WRAP, salt, seq, &[]);
    let content_key = wraps
        .as_chunks::<WRAP_LEN>()
        .0
        .iter()
        .enumerate()
        .find_map(|(i, wrap)| {
            let mut buf = wrap.to_vec();
            let opened = key.open_in_place(nonce_at(nonce, i + 1), Aad::from(&wrap_aad), &mut buf).ok()?;
            <[u8; KEY_LEN]>::try_from(&*opened).ok()
        })
        .ok_or(OpenError::NotRecipient)?;

    let mut buf = payload.to_vec();
    let content = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &content_key)?);
    let len = content
        .open_in_place(nonce_at(nonce, 0), Aad::from(aad(PURPOSE_CONTENT, salt, seq, header)), &mut buf)
        .map_err(|_| OpenError::Corrupt)?
        .len();
    buf.truncate(len);
    Ok(buf)
}

/// How many recipients fit beside a payload of `payload_len` bytes.
pub fn max_devices(payload_len: usize) -> usize {
    MAX_SEALED_LEN.saturating_sub(OVERHEAD.saturating_add(payload_len)) / WRAP_LEN
}

fn blob_len(payload_len: usize, recipients: usize) -> usize {
    OVERHEAD.saturating_add(recipients.saturating_mul(WRAP_LEN)).saturating_add(payload_len)
}

/// The deterministic part of [`seal_payload`], with the randomness handed in so a test can pin the bytes.
fn seal_with(
    plain: &[u8],
    salt: &[u8],
    seq: i64,
    recipients: &[Secret],
    content_key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>, SealError> {
    let mut header = Vec::with_capacity(1 + NONCE_LEN + recipients.len() * WRAP_LEN);
    // The caller has checked the blob fits, so there are at most 20 recipients.
    header.push(recipients.len() as u8);
    header.extend_from_slice(nonce);

    let wrap_aad = aad(PURPOSE_WRAP, salt, seq, &[]);
    for (i, secret) in recipients.iter().enumerate() {
        let mut wrap = content_key.to_vec();
        wrap_key(secret)?.seal_in_place_append_tag(nonce_at(nonce, i + 1), Aad::from(&wrap_aad), &mut wrap)?;
        header.extend_from_slice(&wrap);
    }

    let mut payload = plain.to_vec();
    let content = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, content_key)?);
    content.seal_in_place_append_tag(
        nonce_at(nonce, 0),
        Aad::from(aad(PURPOSE_CONTENT, salt, seq, &header)),
        &mut payload,
    )?;

    let mut blob = Vec::with_capacity(1 + header.len() + payload.len());
    blob.push(VERSION);
    blob.extend_from_slice(&header);
    blob.extend_from_slice(&payload);
    Ok(blob)
}

fn wrap_key(secret: &Secret) -> Result<LessSafeKey, Unspecified> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(secret.as_bytes());
    let okm = prk.expand(&[WRAP_KEY_LABEL], &CHACHA20_POLY1305)?;
    Ok(LessSafeKey::new(UnboundKey::from(okm)))
}

/// The nonce of the `index`th AEAD call of a seal: 0 for the payload, 1.. for the wraps. `index` is at most 20.
fn nonce_at(base: &[u8; NONCE_LEN], index: usize) -> Nonce {
    Nonce::assume_unique_for_key(nonce_bytes(base, index))
}

fn nonce_bytes(base: &[u8; NONCE_LEN], index: usize) -> [u8; NONCE_LEN] {
    let mut nonce = *base;
    nonce[NONCE_LEN - 1] ^= index as u8;
    nonce
}

/// Fixed-size fields first, then the salt behind its length, then whatever the call authenticates besides.
fn aad(purpose: u8, salt: &[u8], seq: i64, header: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(2 + 8 + 8 + salt.len() + header.len());
    aad.extend_from_slice(&[purpose, VERSION]);
    aad.extend_from_slice(&seq.to_be_bytes());
    aad.extend_from_slice(&(salt.len() as u64).to_be_bytes());
    aad.extend_from_slice(salt);
    aad.extend_from_slice(header);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{Kind, Nat, Relay, SALT};

    const SEQ: i64 = 1_760_000_000;

    fn secret(n: u8) -> Secret {
        Secret::new([n; SECRET_LEN])
    }

    fn secrets(n: u8) -> Vec<Secret> {
        (1..=n).map(secret).collect()
    }

    /// A record as large as a real one: 8 addresses of every kind, a relay and a MAC.
    fn record() -> Record {
        Record {
            fingerprint: [0xAB; 32],
            addresses: vec![
                (Kind::Lan, "192.168.100.200:7420".into()),
                (Kind::Lan, "10.20.30.40:7420".into()),
                (Kind::Vpn, "100.101.102.103:7420".into()),
                (Kind::Public, "203.0.113.145:57421".into()),
                (Kind::V6, "[2804:14d:8084:1234:5678:9abc:def0:1234]:7420".into()),
                (Kind::V6, "[2804:14d:8084:1234:abcd:ef01:2345:6789]:7420".into()),
                (Kind::Relay, "198.51.100.77:7420".into()),
                (Kind::Public, "198.51.100.78:7420".into()),
            ],
            nat: Nat::Cone,
            relays: vec![Relay { fingerprint: [0xCD; 32], addresses: vec!["198.51.100.7:7420".into()] }],
            mac: Some([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]),
            ts: SEQ as u64,
        }
    }

    fn seal_for(devices: &[Secret]) -> Vec<u8> {
        seal(&record(), SALT, SEQ, devices, None).unwrap().blob
    }

    #[test]
    fn constants_match_the_cipher() {
        assert_eq!(CHACHA20_POLY1305.key_len(), KEY_LEN);
        assert_eq!(CHACHA20_POLY1305.tag_len(), TAG_LEN);
        assert_eq!(CHACHA20_POLY1305.nonce_len(), NONCE_LEN);
        assert_eq!(WRAP_LEN, 48);
        assert_eq!(OVERHEAD, 30);
        assert_eq!(MAX_SEALED_LEN, 996);
    }

    #[test]
    fn round_trips_for_every_device() {
        let devices = secrets(5);
        let sealed = seal(&record(), SALT, SEQ, &devices, None).unwrap();
        assert!(sealed.per_device);
        for device in &devices {
            assert_eq!(open(&sealed.blob, SALT, SEQ, device).unwrap(), record());
        }
    }

    #[test]
    fn a_device_that_was_not_sealed_for_cannot_open() {
        let blob = seal_for(&secrets(3));
        assert!(matches!(open(&blob, SALT, SEQ, &secret(4)), Err(OpenError::NotRecipient)));
        assert!(matches!(open(&blob, SALT, SEQ, &secret(0)), Err(OpenError::NotRecipient)));
    }

    #[test]
    fn a_revoked_device_cannot_open_the_next_record() {
        let mut devices = secrets(4);
        let before = seal_for(&devices);
        let revoked = devices.remove(1);
        let after = seal_for(&devices);

        assert!(open(&before, SALT, SEQ, &revoked).is_ok(), "it could read what was sealed while it was paired");
        assert!(matches!(open(&after, SALT, SEQ, &revoked), Err(OpenError::NotRecipient)));
        for device in &devices {
            assert!(open(&after, SALT, SEQ, device).is_ok());
        }
    }

    #[test]
    fn another_salt_or_sequence_number_does_not_open() {
        let devices = secrets(2);
        let blob = seal_for(&devices);
        for device in &devices {
            assert!(open(&blob, SALT, SEQ, device).is_ok());
            assert!(matches!(open(&blob, SALT, SEQ + 1, device), Err(OpenError::NotRecipient)));
            assert!(matches!(open(&blob, SALT, SEQ - 1, device), Err(OpenError::NotRecipient)));
            assert!(matches!(open(&blob, b"velora/2", SEQ, device), Err(OpenError::NotRecipient)));
            assert!(matches!(open(&blob, b"velora/", SEQ, device), Err(OpenError::NotRecipient)));
            assert!(matches!(open(&blob, b"", SEQ, device), Err(OpenError::NotRecipient)));
            assert!(matches!(open(&blob, b"velora/1\0", SEQ, device), Err(OpenError::NotRecipient)));
        }
    }

    #[test]
    fn the_salt_and_the_header_cannot_trade_places() {
        // The associated data carries the salt behind its length, so moving bytes between them changes it.
        assert_ne!(aad(PURPOSE_CONTENT, b"ab", 1, b"c"), aad(PURPOSE_CONTENT, b"a", 1, b"bc"));
        assert_ne!(aad(PURPOSE_WRAP, b"a", 1, &[]), aad(PURPOSE_CONTENT, b"a", 1, &[]));
    }

    #[test]
    fn every_byte_of_the_blob_is_authenticated() {
        for devices in [secrets(1), secrets(3)] {
            let blob = seal_for(&devices);
            for i in 0..blob.len() {
                for flip in [0x01u8, 0x80, 0xFF] {
                    let mut bad = blob.clone();
                    bad[i] ^= flip;
                    for device in &devices {
                        assert!(
                            open(&bad, SALT, SEQ, device).is_err(),
                            "byte {i} of {} flipped with {flip:#04x} still opened for {} devices",
                            blob.len(),
                            devices.len()
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn every_byte_of_the_shared_blob_is_authenticated() {
        let shared = secret(99);
        let blob = seal(&record(), SALT, SEQ, &[], Some(&shared)).unwrap().blob;
        assert!(open(&blob, SALT, SEQ, &shared).is_ok());
        for i in 0..blob.len() {
            let mut bad = blob.clone();
            bad[i] ^= 0x01;
            assert!(open(&bad, SALT, SEQ, &shared).is_err(), "byte {i}");
        }
    }

    #[test]
    fn swapping_two_wraps_does_not_open() {
        let devices = secrets(3);
        let blob = seal_for(&devices);
        let wrap = |i: usize| (2 + NONCE_LEN + i * WRAP_LEN)..(2 + NONCE_LEN + (i + 1) * WRAP_LEN);
        let mut swapped = blob.clone();
        swapped[wrap(0)].copy_from_slice(&blob[wrap(1)]);
        swapped[wrap(1)].copy_from_slice(&blob[wrap(0)]);
        assert_ne!(swapped, blob);
        for device in &devices {
            assert!(open(&swapped, SALT, SEQ, device).is_err());
        }
    }

    #[test]
    fn truncated_input_is_an_error_at_every_length() {
        let devices = secrets(3);
        let blob = seal_for(&devices);
        for len in 0..blob.len() {
            assert!(open(&blob[..len], SALT, SEQ, &devices[0]).is_err(), "{len} bytes opened");
        }
    }

    #[test]
    fn oversized_and_garbage_input_is_an_error() {
        let device = secret(1);
        let blob = seal_for(std::slice::from_ref(&device));

        let mut long = blob.clone();
        long.resize(MAX_SEALED_LEN + 1, 0);
        assert!(matches!(open(&long, SALT, SEQ, &device), Err(OpenError::Malformed(_))));
        assert!(matches!(open(&vec![VERSION; 1_000_000], SALT, SEQ, &device), Err(OpenError::Malformed(_))));

        assert!(matches!(open(&[], SALT, SEQ, &device), Err(OpenError::Malformed(_))));
        assert!(matches!(open(&[VERSION], SALT, SEQ, &device), Err(OpenError::Malformed(_))));
        assert!(matches!(open(&[VERSION, 0], SALT, SEQ, &device), Err(OpenError::Malformed(_))));
        // No wraps, a count that promises more wraps than there are bytes, and the largest count.
        let mut header = vec![VERSION, 0];
        header.extend([0u8; NONCE_LEN + TAG_LEN]);
        assert!(matches!(open(&header, SALT, SEQ, &device), Err(OpenError::Malformed("no key wraps"))));
        for count in [1u8, 2, 21, 255] {
            let mut bytes = vec![VERSION, count];
            bytes.extend([7u8; NONCE_LEN + TAG_LEN]);
            assert!(matches!(open(&bytes, SALT, SEQ, &device), Err(OpenError::Malformed(_))), "count {count}");
        }
        // Right shape, nothing real inside.
        for fill in [0x00u8, 0x55, 0xFF] {
            let mut bytes = vec![VERSION, 2];
            bytes.resize(MAX_SEALED_LEN, fill);
            assert!(open(&bytes, SALT, SEQ, &device).is_err());
        }
        // Another version.
        let mut bad = blob.clone();
        for version in [0, VERSION + 1, 255] {
            bad[0] = version;
            assert!(matches!(open(&bad, SALT, SEQ, &device), Err(OpenError::Version(v)) if v == version));
        }
    }

    #[test]
    fn a_wrap_that_opens_with_a_damaged_payload_is_corrupt_not_unknown() {
        let device = secret(1);
        let mut blob = seal_for(std::slice::from_ref(&device));
        let last = blob.len() - 1;
        blob[last] ^= 1;
        assert!(matches!(open(&blob, SALT, SEQ, &device), Err(OpenError::Corrupt)));
    }

    #[test]
    fn sealing_twice_gives_different_blobs_with_different_nonces() {
        let devices = secrets(2);
        let (a, b) = (seal_for(&devices), seal_for(&devices));
        assert_ne!(a, b);
        assert_ne!(a[2..2 + NONCE_LEN], b[2..2 + NONCE_LEN]);
        // The nonce is the one random value a device key sees again and again, so it must not repeat.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..2000 {
            let blob = seal_for(&devices[..1]);
            assert!(seen.insert(blob[2..2 + NONCE_LEN].to_vec()));
        }
    }

    #[test]
    fn every_call_of_a_seal_has_its_own_nonce() {
        let base = [0x5A; NONCE_LEN];
        let calls = max_devices(0) + 1; // the payload and the most wraps a blob can hold
        let nonces: std::collections::HashSet<_> = (0..calls).map(|index| nonce_bytes(&base, index)).collect();
        assert_eq!(nonces.len(), calls);
        assert_eq!(nonce_bytes(&base, 0), base, "the payload uses the nonce as it is");
    }

    #[test]
    fn a_record_with_eight_addresses_fits_twelve_devices() {
        let payload = record().encode().unwrap();
        assert_eq!(record().addresses.len(), 8);
        assert!(
            max_devices(payload.len()) >= 12,
            "only {} devices fit beside {} bytes",
            max_devices(payload.len()),
            payload.len()
        );

        let blob = seal_for(&secrets(12));
        assert!(blob.len() <= MAX_SEALED_LEN, "{} bytes", blob.len());
        assert_eq!(blob.len(), blob_len(payload.len(), 12));
        for device in secrets(12) {
            assert_eq!(open(&blob, SALT, SEQ, &device).unwrap(), record());
        }
    }

    #[test]
    fn the_limit_is_exact() {
        for devices in [1usize, 2, 12, 20] {
            let at = MAX_SEALED_LEN - OVERHEAD - devices * WRAP_LEN;
            let recipients = secrets(devices as u8);

            let sealed = seal_payload(&vec![7; at], SALT, SEQ, &recipients, None).unwrap();
            assert_eq!(sealed.blob.len(), MAX_SEALED_LEN);
            assert_eq!(open_payload(&sealed.blob, SALT, SEQ, &recipients[0]).unwrap(), vec![7; at]);

            let err = seal_payload(&vec![7; at + 1], SALT, SEQ, &recipients, None).unwrap_err();
            assert!(matches!(err, SealError::TooLarge { over: 1, wraps } if wraps == devices), "{err}");
            let err = seal_payload(&vec![7; at + 100], SALT, SEQ, &recipients, None).unwrap_err();
            assert!(matches!(err, SealError::TooLarge { over: 100, .. }), "{err}");
        }
        assert_eq!(max_devices(MAX_SEALED_LEN - OVERHEAD - 12 * WRAP_LEN), 12);
        assert_eq!(max_devices(MAX_SEALED_LEN - OVERHEAD - 12 * WRAP_LEN + 1), 11);
        assert_eq!(max_devices(MAX_SEALED_LEN), 0);
    }

    #[test]
    fn a_record_is_cut_to_the_exact_limit() {
        // Grow one address until the encoded record is exactly what two devices leave room for.
        let target = MAX_SEALED_LEN - OVERHEAD - 2 * WRAP_LEN;
        let with_text = |n: usize| {
            let mut r = record();
            r.addresses = vec![(Kind::Lan, "x".repeat(n))];
            r
        };
        let n = (0..target).find(|&n| with_text(n).encode().unwrap().len() == target).unwrap();
        let devices = secrets(2);

        let blob = seal(&with_text(n), SALT, SEQ, &devices, None).unwrap().blob;
        assert_eq!(blob.len(), MAX_SEALED_LEN);
        assert_eq!(open(&blob, SALT, SEQ, &devices[1]).unwrap(), with_text(n));

        let err = seal(&with_text(n + 1), SALT, SEQ, &devices, None).unwrap_err();
        assert!(matches!(err, SealError::TooLarge { over: 1, wraps: 2 }), "{err}");
        assert!(err.to_string().contains("1 bytes over"), "{err}");
    }

    #[test]
    fn too_many_devices_fall_back_to_the_shared_secret() {
        let devices = secrets(30);
        let shared = secret(200);

        let sealed = seal(&record(), SALT, SEQ, &devices, Some(&shared)).unwrap();
        assert!(!sealed.per_device);
        assert_eq!(sealed.blob.len(), OVERHEAD + WRAP_LEN + record().encode().unwrap().len());
        assert_eq!(open(&sealed.blob, SALT, SEQ, &shared).unwrap(), record());
        for device in &devices {
            assert!(
                matches!(open(&sealed.blob, SALT, SEQ, device), Err(OpenError::NotRecipient)),
                "a device secret opened the shared blob"
            );
        }
    }

    #[test]
    fn without_a_shared_secret_too_many_devices_is_an_error_that_says_by_how_much() {
        let payload = record().encode().unwrap();
        let too_many = max_devices(payload.len()) + 3;
        let err = seal(&record(), SALT, SEQ, &secrets(too_many as u8), None).unwrap_err();
        let over = blob_len(payload.len(), too_many) - MAX_SEALED_LEN;
        assert!(matches!(err, SealError::TooLarge { over: o, wraps } if o == over && wraps == too_many), "{err}");
        assert!(err.to_string().contains(&format!("{over} bytes over")), "{err}");
    }

    #[test]
    fn devices_that_fit_are_not_sealed_for_the_shared_secret() {
        let devices = secrets(3);
        let shared = secret(200);
        let sealed = seal(&record(), SALT, SEQ, &devices, Some(&shared)).unwrap();
        assert!(sealed.per_device);
        assert!(open(&sealed.blob, SALT, SEQ, &devices[2]).is_ok());
        assert!(matches!(open(&sealed.blob, SALT, SEQ, &shared), Err(OpenError::NotRecipient)));
    }

    #[test]
    fn a_record_too_big_even_for_one_wrap_is_an_error_even_with_a_shared_secret() {
        let shared = secret(200);
        let at = MAX_SEALED_LEN - OVERHEAD - WRAP_LEN;
        assert!(seal_payload(&vec![0; at], SALT, SEQ, &secrets(30), Some(&shared)).is_ok());
        let err = seal_payload(&vec![0; at + 7], SALT, SEQ, &secrets(30), Some(&shared)).unwrap_err();
        assert!(matches!(err, SealError::TooLarge { over: 7, wraps: 1 }), "{err}");
    }

    #[test]
    fn nobody_to_seal_for_is_an_error() {
        assert!(matches!(seal(&record(), SALT, SEQ, &[], None), Err(SealError::NoRecipients)));
        // The shared secret alone is a recipient.
        let shared = secret(9);
        let sealed = seal(&record(), SALT, SEQ, &[], Some(&shared)).unwrap();
        assert!(!sealed.per_device);
        assert!(open(&sealed.blob, SALT, SEQ, &shared).is_ok());
    }

    #[test]
    fn the_same_secret_twice_is_harmless() {
        let blob = seal_for(&[secret(1), secret(1), secret(2)]);
        assert_eq!(open(&blob, SALT, SEQ, &secret(1)).unwrap(), record());
        assert_eq!(open(&blob, SALT, SEQ, &secret(2)).unwrap(), record());
    }

    #[test]
    fn other_payloads_travel_the_same_way() {
        let device = secret(1);
        let blob =
            seal_payload(b"punch here", b"velora/punch/abcd", SEQ, std::slice::from_ref(&device), None).unwrap().blob;
        assert_eq!(open_payload(&blob, b"velora/punch/abcd", SEQ, &device).unwrap(), b"punch here");
        assert!(open_payload(&blob, SALT, SEQ, &device).is_err(), "bound to its salt");
        let empty = seal_payload(b"", SALT, SEQ, std::slice::from_ref(&device), None).unwrap().blob;
        assert_eq!(empty.len(), OVERHEAD + WRAP_LEN);
        assert_eq!(open_payload(&empty, SALT, SEQ, &device).unwrap(), b"");
    }

    #[test]
    fn a_blob_that_is_not_a_record_is_a_record_error_after_opening() {
        let device = secret(1);
        let blob = seal_payload(b"\x01not a record", SALT, SEQ, std::slice::from_ref(&device), None).unwrap().blob;
        assert!(matches!(open(&blob, SALT, SEQ, &device), Err(OpenError::Record(_))));
    }

    #[test]
    fn secrets_are_random_and_do_not_show() {
        let (a, b) = (Secret::generate().unwrap(), Secret::generate().unwrap());
        assert_ne!(a.as_bytes(), b.as_bytes());
        assert_eq!(format!("{a:?}"), "Secret(..)");
        assert_eq!(Secret::new([3; SECRET_LEN]).as_bytes(), &[3; SECRET_LEN]);
    }

    /// The bytes of a seal with every random value fixed. The layout is a contract between versions of Velora and
    /// between implementations, so a change here is a change of `VERSION`.
    #[test]
    fn the_wire_format_is_pinned() {
        let blob = seal_with(
            b"hello velora",
            SALT,
            1_700_000_000,
            &[secret(0x11), secret(0x12)],
            &[0x22; KEY_LEN],
            &[0x33; NONCE_LEN],
        )
        .unwrap();
        let hex: String = blob.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, EXPECTED, "length {}", blob.len());
        assert_eq!(blob.len(), OVERHEAD + 2 * WRAP_LEN + b"hello velora".len());
        assert_eq!(open_payload(&blob, SALT, 1_700_000_000, &secret(0x12)).unwrap(), b"hello velora");
    }

    /// The same bytes come out of an independent implementation of the layout described at the top of this file
    /// (Python's `cryptography`, OpenSSL underneath), which also opens them with both secrets.
    const EXPECTED: &str = concat!(
        // Version, two wraps, the nonce.
        "01",
        "02",
        "333333333333333333333333",
        // Wrap 1.
        "d27972a881d2905811f52d1317fc7738c1ff111db633d90b606b59e22a478d9e96c4421a8f76e4dbaeb2239ee15e6428",
        // Wrap 2.
        "8ca4e82eeb87f05a660458eac68f21880ba7d2bc668e5ba703773024f55f87ae8aea0f6122a5e90f8687bfa6402d361f",
        // "hello velora" and its tag.
        "e72d36f6bf31f5bab2f4354dd7f87fdf5b08779f01d1509a8c18492f",
    );
}
