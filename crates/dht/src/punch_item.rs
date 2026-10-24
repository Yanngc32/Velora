//! The punch request a client leaves in the DHT for a host that has no relay.
//!
//! A host nobody can reach directly and that has no relay has no channel to hear "a client wants in, from here". So
//! the client publishes one as a BEP 44 item, `{ endpoint, nonce, ts }`, and the host, which polls for such items,
//! sends a single QUIC Initial to the endpoint from its listening port. That opens the host's NAT toward the client,
//! and the client's own handshake packets get through. See `docs/nat-traversal.md`, phase 3.
//!
//! Nothing in the protocol tells a host the DHT key of a paired client, so the item is not published under the
//! client's own key. It lives under a key *derived from the device secret*, which the host made for that device and
//! the device holds (pairing link, `HostMsg::Reach`): the client signs with the key [`build`] returns and the host
//! polls [`public_key`], the same bytes on both ends. A secret belongs to one (host, device) pair, so that key is
//! the pair's own slot and the salt can be a constant. A newer request replaces the older one in the slot, which is
//! what a request wants, and revoking a device is dropping its secret.
//!
//! The endpoint is the client's address, which the DHT must not show, so the value is sealed with
//! [`seal::seal_payload`] and that same secret as its only recipient. The signature only lets the DHT accept the
//! item; what tells the host the request comes from a paired device is that it opens with that device's secret.
//!
//! Pure functions: the caller passes the time in, and publishing and polling belong to the DHT node. Nothing is
//! logged here either: a stale item is what most polls return, and only the caller knows which device it polled.

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic))]

use std::time::{SystemTime, UNIX_EPOCH};

use mainline::SigningKey;
use ring::hmac;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::seal::{self, OpenError, SealError, Secret};

/// Salt of the item in the DHT, at the key [`public_key`] gives. The last part is the version of the item: a format
/// that cannot be read as this one moves to `velora/punch/2`, another slot, so versions never read each other's.
pub const SALT: &[u8] = b"velora/punch/1";

/// First byte of the sealed payload.
pub const VERSION: u8 = 1;

/// How old a request's own `ts` may be when a host serves it. The DHT keeps an item for hours and a host polls
/// every few seconds, so this is what stops a request from being served again long after its client gave up.
pub const MAX_AGE_SECS: u64 = 60;

/// How far ahead of the host's clock a request's `ts` may be: two devices never agree to the second. Past a clock's
/// usual error it is not an honest client, and a far-future `ts` would make an item outlive its window.
pub const MAX_FUTURE_SECS: u64 = 10;

/// The longest endpoint text. The longest `SocketAddr` std prints is 58 bytes (a scoped IPv6 address and a port).
pub const MAX_ENDPOINT_LEN: usize = 64;

const SIGNING_KEY_LABEL: &[u8] = b"velora-dht/punch/v1 signing key";
const SEED_LEN: usize = 32;

/// What a client asks of a host: "open your NAT toward this endpoint".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PunchItem {
    /// Where the client's packets come from as seen from outside its NAT, as `ip:port` text. [`open`] bounds the
    /// length and nothing more: whether the host may send there is the host's call.
    pub endpoint: String,
    /// Random, one per request, so a host can serve each request once.
    pub nonce: u64,
    /// Unix seconds when the client built the request.
    pub ts: u64,
}

#[derive(Debug, Error)]
pub enum PunchError {
    /// The clock is before 1970, or past what a sequence number holds.
    #[error("the clock is before 1970 or out of range")]
    Clock,
    #[error("the endpoint is {len} bytes, a punch request takes 1 to {MAX_ENDPOINT_LEN}")]
    EndpointLength { len: usize },
    /// The usual answer to a poll: the item of an earlier request is still in the DHT.
    #[error("the punch request is {age} s old, at most {MAX_AGE_SECS} s are served")]
    Stale { age: u64 },
    /// The client's clock runs ahead of this one's.
    #[error("the punch request is dated {ahead} s ahead of this clock, at most {MAX_FUTURE_SECS} s are allowed")]
    FromTheFuture { ahead: u64 },
    #[error("punch request version {0} is not supported (this build reads version {current})", current = VERSION)]
    Version(u8),
    #[error("the punch request is empty")]
    Empty,
    #[error("malformed punch request: {0}")]
    Malformed(postcard::Error),
    #[error("{0} bytes follow the end of the punch request")]
    Trailing(usize),
    #[error("encoding the punch request failed: {0}")]
    Encode(postcard::Error),
    #[error(transparent)]
    Seal(#[from] SealError),
    /// `NotRecipient` is the wrong secret, and also an item sealed for another sequence number or salt: nothing
    /// tells them apart.
    #[error(transparent)]
    Open(#[from] OpenError),
}

/// Where a host looks for the requests of the device that holds `secret`: [`SALT`] at this key. The client
/// derives the same bytes, and every secret gives another key. A host with N paired devices has N keys, so N
/// lookups per polling round; derive them when the list of devices changes, not on every poll.
pub fn public_key(secret: &Secret) -> [u8; 32] {
    signing_key(secret).verifying_key().to_bytes()
}

/// What a client publishes, in the order `MutableItem::new(key, &blob, seq, Some(salt))` wants it: the key to
/// sign with, the salt, the sequence number and the sealed value.
pub type Built = (SigningKey, &'static [u8], i64, Vec<u8>);

/// Builds the request of a client that holds `secret` for the host it wants to reach.
///
/// `seq` is the unix seconds of `now`, and so is the `ts` inside. `nonce` must be random.
pub fn build(secret: &Secret, endpoint: &str, nonce: u64, now: SystemTime) -> Result<Built, PunchError> {
    build_after(secret, endpoint, nonce, now, i64::MIN)
}

/// [`build`] for a client that knows the highest `seq` the DHT may hold at its key (the last request it published
/// to this host, or the one a refused put turned up): `seq` is the larger of the clock and `last_seq + 1`, and
/// `ts` stays the clock, so the host still sees a current request. The DHT ignores an item with the `seq` it
/// already holds (two requests in one second) and refuses a lower one (a clock that was wrong once and has been
/// set right), and in neither case does the host ever hear of the request.
pub fn build_after(
    secret: &Secret,
    endpoint: &str,
    nonce: u64,
    now: SystemTime,
    last_seq: i64,
) -> Result<Built, PunchError> {
    let ts = unix_secs(now)?;
    let clock = i64::try_from(ts).map_err(|_| PunchError::Clock)?;
    let seq = clock.max(last_seq.saturating_add(1));
    check_endpoint(endpoint)?;
    let item = PunchItem { endpoint: endpoint.to_owned(), nonce, ts };
    let blob = seal::seal_payload(&encode(&item)?, SALT, seq, std::slice::from_ref(secret), None)?.blob;
    Ok((signing_key(secret), SALT, seq, blob))
}

/// Opens the value of the item a host found at [`public_key`]`(secret)`, with the `seq` the item carries, and
/// returns the request if a host may serve it now: sealed with this secret, for this `seq`, well formed, and
/// dated at most [`MAX_AGE_SECS`] before `now` or [`MAX_FUTURE_SECS`] after it (by its own `ts`, which the seal
/// authenticates). Whatever the bytes are, this returns an error and never panics.
///
/// A request proves a device that holds the secret, nothing more: anyone who has it can make one, for any
/// endpoint. Serving it once (by `nonce`), how often, and toward which addresses is up to the host.
pub fn open(blob: &[u8], secret: &Secret, seq: i64, now: SystemTime) -> Result<PunchItem, PunchError> {
    let now = unix_secs(now)?;
    let item = decode(&seal::open_payload(blob, SALT, seq, secret)?)?;
    check_fresh(item.ts, now)?;
    Ok(item)
}

fn signing_key(secret: &Secret) -> SigningKey {
    SigningKey::from_bytes(&derive_seed(secret))
}

/// HKDF-SHA256 (RFC 5869) of the secret, no salt, with [`SIGNING_KEY_LABEL`] as `info`, for the one 32-byte block
/// asked of it: the extract step and the first expand block are an HMAC each. `ring::hkdf` computes the same bytes
/// (a test keeps the two together), but it can only report failure, for lengths that cannot occur here, and
/// [`public_key`] has no use for an error.
fn derive_seed(secret: &Secret) -> [u8; SEED_LEN] {
    let prk = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &[]), secret.as_bytes());
    let mut info = SIGNING_KEY_LABEL.to_vec();
    info.push(1);
    let block = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, prk.as_ref()), &info);
    let mut seed = [0u8; SEED_LEN];
    seed.iter_mut().zip(block.as_ref()).for_each(|(to, from)| *to = *from);
    seed
}

fn encode(item: &PunchItem) -> Result<Vec<u8>, PunchError> {
    postcard::to_extend(item, vec![VERSION]).map_err(PunchError::Encode)
}

/// Strict, like `Record::decode`: the version must be ours and nothing may follow the request.
fn decode(bytes: &[u8]) -> Result<PunchItem, PunchError> {
    let (&version, body) = bytes.split_first().ok_or(PunchError::Empty)?;
    if version != VERSION {
        return Err(PunchError::Version(version));
    }
    let (item, rest): (PunchItem, &[u8]) = postcard::take_from_bytes(body).map_err(PunchError::Malformed)?;
    if !rest.is_empty() {
        return Err(PunchError::Trailing(rest.len()));
    }
    check_endpoint(&item.endpoint)?;
    Ok(item)
}

fn unix_secs(now: SystemTime) -> Result<u64, PunchError> {
    now.duration_since(UNIX_EPOCH).map(|since| since.as_secs()).map_err(|_| PunchError::Clock)
}

fn check_endpoint(endpoint: &str) -> Result<(), PunchError> {
    match endpoint.len() {
        1..=MAX_ENDPOINT_LEN => Ok(()),
        len => Err(PunchError::EndpointLength { len }),
    }
}

fn check_fresh(ts: u64, now: u64) -> Result<(), PunchError> {
    if ts > now {
        let ahead = ts - now;
        if ahead > MAX_FUTURE_SECS {
            return Err(PunchError::FromTheFuture { ahead });
        }
    } else {
        let age = now - ts;
        if age > MAX_AGE_SECS {
            return Err(PunchError::Stale { age });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        array,
        collections::HashSet,
        net::{Ipv6Addr, SocketAddr, SocketAddrV6},
        time::Duration,
    };

    use mainline::MutableItem;
    use ring::hkdf;

    use super::*;
    use crate::{
        record::{self, Nat, Record},
        seal::SECRET_LEN,
    };

    const NOW: u64 = 1_760_000_000;
    const SEQ: i64 = NOW as i64;
    const ENDPOINT: &str = "203.0.113.45:40000";

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn secret(n: u8) -> Secret {
        Secret::new([n; SECRET_LEN])
    }

    /// The secret `00 01 02 .. 0f`, the one the pinned vectors use.
    fn counting_secret() -> Secret {
        Secret::new(array::from_fn(|i| i as u8))
    }

    fn item(endpoint: &str, nonce: u64, ts: u64) -> PunchItem {
        PunchItem { endpoint: endpoint.into(), nonce, ts }
    }

    fn seal_raw(secret: &Secret, seq: i64, plain: &[u8]) -> Vec<u8> {
        seal::seal_payload(plain, SALT, seq, std::slice::from_ref(secret), None).unwrap().blob
    }

    fn seal_item(secret: &Secret, seq: i64, item: &PunchItem) -> Vec<u8> {
        seal_raw(secret, seq, &encode(item).unwrap())
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn round_trips() {
        let client = secret(1);
        let (key, salt, seq, blob) = build(&client, ENDPOINT, 0xDEAD_BEEF, at(NOW)).unwrap();
        assert_eq!(salt, SALT);
        assert_eq!(seq, SEQ);
        assert_eq!(key.verifying_key().to_bytes(), public_key(&client));

        // The host holds its own copy of the secret and opens a few seconds later.
        let host = Secret::new(*client.as_bytes());
        assert_eq!(open(&blob, &host, seq, at(NOW + 3)).unwrap(), item(ENDPOINT, 0xDEAD_BEEF, NOW));
    }

    #[test]
    fn build_after_keeps_the_seq_ahead_of_the_last_one_and_the_ts_on_the_clock() {
        let client = secret(1);
        // The clock decides unless the last seq is as high or higher: then it is one more than that.
        for (last, expected) in
            [(i64::MIN, SEQ), (SEQ - 100, SEQ), (SEQ - 1, SEQ), (SEQ, SEQ + 1), (SEQ + 10_000, SEQ + 10_001)]
        {
            let (key, salt, seq, blob) = build_after(&client, ENDPOINT, 1, at(NOW), last).unwrap();
            assert_eq!(seq, expected, "last seq {last}");
            assert_eq!(salt, SALT);
            assert_eq!(key.verifying_key().to_bytes(), public_key(&client));
            // Whatever the seq, the host sees a request as fresh as the clock.
            assert_eq!(open(&blob, &client, seq, at(NOW)).unwrap(), item(ENDPOINT, 1, NOW));
        }
        // The largest last seq cannot overflow, and `build` is `build_after` with nothing before it.
        assert_eq!(build_after(&client, ENDPOINT, 1, at(NOW), i64::MAX).unwrap().2, i64::MAX);
        assert_eq!(build(&client, ENDPOINT, 1, at(NOW)).unwrap().2, SEQ);
    }

    #[test]
    fn what_build_returns_is_what_the_dht_item_wants() {
        let client = secret(1);
        let (key, salt, seq, blob) = build(&client, ENDPOINT, 7, at(NOW)).unwrap();
        let published = MutableItem::new(key, &blob, seq, Some(salt));

        // A host looks the item up by the key it computes and the constant salt.
        let polled = public_key(&client);
        assert_eq!(published.key(), &polled);
        assert_eq!(published.target(), &MutableItem::target_from_key(&polled, Some(SALT)));
        assert_eq!(published.salt(), Some(SALT));
        assert_eq!(published.seq(), SEQ);
        assert_eq!(published.value(), &blob[..]);
        assert_eq!(open(published.value(), &client, published.seq(), at(NOW)).unwrap().endpoint, ENDPOINT);
    }

    #[test]
    fn the_longest_request_fits_a_dht_value() {
        let longest = "x".repeat(MAX_ENDPOINT_LEN);
        let (_, salt, _, blob) = build(&secret(1), &longest, u64::MAX, at(u64::from(u32::MAX))).unwrap();
        assert!(blob.len() <= seal::MAX_SEALED_LEN, "{} bytes", blob.len());
        assert!(salt.len() <= 64, "BEP 44 allows a salt of 64 bytes");

        let longest_text = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from([0xFFFF; 8]), u16::MAX, 0, u32::MAX));
        assert!(longest_text.to_string().len() <= MAX_ENDPOINT_LEN, "{longest_text}");
    }

    #[test]
    fn a_stale_item_is_rejected() {
        let client = secret(1);
        let (_, _, seq, blob) = build(&client, ENDPOINT, 1, at(NOW)).unwrap();
        for age in [0, 1, 30, MAX_AGE_SECS - 1, MAX_AGE_SECS] {
            assert!(open(&blob, &client, seq, at(NOW + age)).is_ok(), "{age} s old");
        }
        for age in [MAX_AGE_SECS + 1, 120, 7_200, 86_400 * 365] {
            let err = open(&blob, &client, seq, at(NOW + age)).unwrap_err();
            assert!(matches!(err, PunchError::Stale { age: a } if a == age), "{age} s old: {err}");
        }
        let err = open(&blob, &client, seq, at(NOW + 61)).unwrap_err();
        assert!(err.to_string().contains("61 s old"), "{err}");
    }

    #[test]
    fn an_item_from_the_future_is_rejected() {
        // The client's clock is ahead of the host's, which still reads NOW.
        let client = secret(1);
        for ahead in [0, 1, MAX_FUTURE_SECS] {
            let (_, _, seq, blob) = build(&client, ENDPOINT, 1, at(NOW + ahead)).unwrap();
            assert!(open(&blob, &client, seq, at(NOW)).is_ok(), "{ahead} s ahead");
        }
        for ahead in [MAX_FUTURE_SECS + 1, 60, 3_600] {
            let (_, _, seq, blob) = build(&client, ENDPOINT, 1, at(NOW + ahead)).unwrap();
            let err = open(&blob, &client, seq, at(NOW)).unwrap_err();
            assert!(matches!(err, PunchError::FromTheFuture { ahead: a } if a == ahead), "{ahead} s ahead: {err}");
        }
    }

    #[test]
    fn freshness_follows_the_ts_inside_and_not_the_seq_outside() {
        let client = secret(1);
        let stale = seal_item(&client, SEQ, &item(ENDPOINT, 1, NOW - 61));
        assert!(matches!(open(&stale, &client, SEQ, at(NOW)), Err(PunchError::Stale { age: 61 })));
        let future = seal_item(&client, SEQ, &item(ENDPOINT, 1, NOW + 11));
        assert!(matches!(open(&future, &client, SEQ, at(NOW)), Err(PunchError::FromTheFuture { ahead: 11 })));

        // The extremes subtract without overflowing.
        let epoch = seal_item(&client, SEQ, &item(ENDPOINT, 1, 0));
        assert!(matches!(open(&epoch, &client, SEQ, at(NOW)), Err(PunchError::Stale { age }) if age == NOW));
        let last = seal_item(&client, SEQ, &item(ENDPOINT, 1, u64::MAX));
        let err = open(&last, &client, SEQ, at(NOW)).unwrap_err();
        assert!(matches!(err, PunchError::FromTheFuture { ahead } if ahead == u64::MAX - NOW), "{err}");
    }

    #[test]
    fn the_wrong_secret_does_not_open() {
        let (_, _, seq, blob) = build(&secret(1), ENDPOINT, 1, at(NOW)).unwrap();
        for wrong in [secret(2), secret(0), counting_secret()] {
            let err = open(&blob, &wrong, seq, at(NOW)).unwrap_err();
            assert!(matches!(err, PunchError::Open(OpenError::NotRecipient)), "{err}");
        }
        // One flipped bit is another secret.
        let mut bytes = [1u8; SECRET_LEN];
        bytes[SECRET_LEN - 1] ^= 1;
        assert!(open(&blob, &Secret::new(bytes), seq, at(NOW)).is_err());
    }

    #[test]
    fn a_replay_under_another_seq_fails() {
        let client = secret(1);
        let (_, _, seq, blob) = build(&client, ENDPOINT, 1, at(NOW)).unwrap();
        assert!(open(&blob, &client, seq, at(NOW)).is_ok());
        // The same value under a newer seq would look fresh to anything that went by the seq alone.
        for other in [seq + 1, seq + 60, seq - 1, 0, -1, i64::MAX, i64::MIN] {
            let err = open(&blob, &client, other, at(NOW)).unwrap_err();
            assert!(matches!(err, PunchError::Open(OpenError::NotRecipient)), "seq {other}: {err}");
        }
    }

    #[test]
    fn garbage_is_an_error() {
        let client = secret(1);
        for garbage in
            [&[][..], &[0], &[VERSION], &[VERSION, 1], &[0xFF; 20], &[7; 100], &[VERSION; 997], &[0; 1_000_000]]
        {
            assert!(open(garbage, &client, SEQ, at(NOW)).is_err(), "{} bytes", garbage.len());
        }
        // Right shape, nothing real inside.
        for fill in [0x00u8, 0x55, 0xFF] {
            let mut bytes = vec![VERSION, 1];
            bytes.resize(120, fill);
            assert!(open(&bytes, &client, SEQ, at(NOW)).is_err());
        }
    }

    #[test]
    fn every_byte_of_the_blob_is_authenticated() {
        let client = secret(1);
        let (_, _, seq, blob) = build(&client, ENDPOINT, 1, at(NOW)).unwrap();
        for i in 0..blob.len() {
            for flip in [0x01u8, 0x80, 0xFF] {
                let mut bad = blob.clone();
                bad[i] ^= flip;
                assert!(open(&bad, &client, seq, at(NOW)).is_err(), "byte {i} flipped with {flip:#04x} still opened");
            }
        }
    }

    #[test]
    fn a_truncated_blob_is_an_error_at_every_length() {
        let client = secret(1);
        let (_, _, seq, blob) = build(&client, ENDPOINT, 1, at(NOW)).unwrap();
        for len in 0..blob.len() {
            assert!(open(&blob[..len], &client, seq, at(NOW)).is_err(), "{len} bytes opened");
        }
    }

    #[test]
    fn the_endpoint_is_bounded_both_ways() {
        let client = secret(1);
        let longest = "x".repeat(MAX_ENDPOINT_LEN);
        let (_, _, seq, blob) = build(&client, &longest, 1, at(NOW)).unwrap();
        assert_eq!(open(&blob, &client, seq, at(NOW)).unwrap().endpoint, longest);

        for bad in ["".to_owned(), "x".repeat(MAX_ENDPOINT_LEN + 1), "x".repeat(10_000)] {
            let err = build(&client, &bad, 1, at(NOW)).unwrap_err();
            assert!(matches!(err, PunchError::EndpointLength { len } if len == bad.len()), "{err}");
        }
        // A client that skipped the check: sealed correctly, and still refused.
        for len in [0, MAX_ENDPOINT_LEN + 1, 500] {
            let blob = seal_item(&client, SEQ, &item(&"x".repeat(len), 1, NOW));
            let err = open(&blob, &client, SEQ, at(NOW)).unwrap_err();
            assert!(matches!(err, PunchError::EndpointLength { len: l } if l == len), "{len} bytes: {err}");
        }
    }

    #[test]
    fn a_sealed_payload_that_is_not_a_request_is_an_error_not_a_panic() {
        let client = secret(1);
        let good = encode(&item(ENDPOINT, 1, NOW)).unwrap();
        let open_raw = |plain: &[u8]| open(&seal_raw(&client, SEQ, plain), &client, SEQ, at(NOW));

        assert!(open_raw(&good).is_ok());
        assert!(matches!(open_raw(&[]), Err(PunchError::Empty)));
        for version in [0, VERSION + 1, 255] {
            let mut bad = good.clone();
            bad[0] = version;
            assert!(matches!(open_raw(&bad), Err(PunchError::Version(v)) if v == version));
        }
        let mut trailing = good.clone();
        trailing.extend([0, 0, 0]);
        assert!(matches!(open_raw(&trailing), Err(PunchError::Trailing(3))));
        for len in 1..good.len() {
            assert!(open_raw(&good[..len]).is_err(), "decoded {len} of {} bytes", good.len());
        }
        // An endpoint that is not UTF-8, and lengths that promise gigabytes the payload does not have.
        assert!(matches!(open_raw(&[VERSION, 2, 0xFF, 0xFE, 1, 1]), Err(PunchError::Malformed(_))));
        assert!(matches!(open_raw(&[VERSION, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F, 1, 2]), Err(PunchError::Malformed(_))));
        assert!(open_raw(&[VERSION; 900]).is_err());
    }

    #[test]
    fn a_clock_before_1970_is_an_error() {
        let before = UNIX_EPOCH - Duration::from_secs(1);
        let client = secret(1);
        assert!(matches!(build(&client, ENDPOINT, 1, before), Err(PunchError::Clock)));
        let (_, _, seq, blob) = build(&client, ENDPOINT, 1, at(NOW)).unwrap();
        assert!(matches!(open(&blob, &client, seq, before), Err(PunchError::Clock)));
        // The epoch itself is a clock, if a useless one.
        assert_eq!(build(&client, ENDPOINT, 1, UNIX_EPOCH).unwrap().2, 0);
    }

    #[test]
    fn the_public_key_is_the_same_on_both_ends_and_differs_per_secret() {
        let (host, client) = (Secret::new([5; SECRET_LEN]), Secret::new([5; SECRET_LEN]));
        assert_eq!(public_key(&host), public_key(&client));
        // What the client signs with is what the host polls.
        let (key, ..) = build(&client, ENDPOINT, 1, at(NOW)).unwrap();
        assert_eq!(key.verifying_key().to_bytes(), public_key(&host));

        // Every secret one bit away has a key of its own, and so does a different pair of secrets.
        let mut seen = HashSet::from([public_key(&host)]);
        for byte in 0..SECRET_LEN {
            for bit in 0..8 {
                let mut bytes = [5u8; SECRET_LEN];
                bytes[byte] ^= 1 << bit;
                assert!(seen.insert(public_key(&Secret::new(bytes))), "byte {byte} bit {bit} gave a key twice");
            }
        }
        assert!(seen.insert(public_key(&secret(6))));
        assert!(seen.insert(public_key(&counting_secret())));
    }

    #[test]
    fn the_key_derivation_is_pinned() {
        // Worked out by `cryptography`'s HKDF and Ed25519 and by RFC 5869 written out in Python, not by this code.
        let secret = counting_secret();
        assert_eq!(hex(&derive_seed(&secret)), "211ba8985aa34365fdf398b0755646b5d3fd4a2d76e3ad6ce205a7ecad01b4fc");
        assert_eq!(hex(&public_key(&secret)), "0f58c88a26c6e63f2bdb9bbc802f0d515e612dd5983529ca7e6be0c15e6b373c");

        let secret = Secret::new([0x11; SECRET_LEN]);
        assert_eq!(hex(&derive_seed(&secret)), "0481ca3bf2cdc77d416d5fc754f37d6f245af1c86c08029059c14ebc7552f2c3");
        assert_eq!(hex(&public_key(&secret)), "a8845d85013208becfe66629149155238045c7d54ca8b670f7ebb88bc4272d2b");
    }

    #[test]
    fn the_seed_is_what_ring_hkdf_derives() {
        struct Len32;
        impl hkdf::KeyType for Len32 {
            fn len(&self) -> usize {
                SEED_LEN
            }
        }

        let mut secrets: Vec<Secret> = (0..=255u8).map(secret).collect();
        secrets.extend((0..50).map(|_| Secret::generate().unwrap()));
        for secret in secrets {
            let mut expected = [0u8; SEED_LEN];
            hkdf::Salt::new(hkdf::HKDF_SHA256, &[])
                .extract(secret.as_bytes())
                .expand(&[SIGNING_KEY_LABEL], Len32)
                .unwrap()
                .fill(&mut expected)
                .unwrap();
            assert_eq!(derive_seed(&secret), expected);
        }
    }

    #[test]
    fn the_payload_format_is_pinned() {
        let request = item(ENDPOINT, 0x0102_0304_0506_0708, NOW);
        let mut expected = vec![VERSION];
        expected.push(18); // the endpoint: 18 bytes of text
        expected.extend(ENDPOINT.as_bytes());
        expected.extend([0x88, 0x8E, 0x98, 0xA8, 0xC0, 0xE0, 0x80, 0x81, 0x01]); // the nonce as a varint
        expected.extend([0x80, 0xF0, 0x9D, 0xC7, 0x06]); // the ts as a varint
        assert_eq!(encode(&request).unwrap(), expected);
        assert_eq!(decode(&expected).unwrap(), request);
    }

    /// A request sealed by this version, as bytes: a later build must still open what an earlier one made, so a
    /// change of the salt, the payload or the way it is sealed shows up here.
    #[test]
    fn a_request_sealed_by_this_version_still_opens() {
        let blob = unhex(STORED_REQUEST);
        let opened = open(&blob, &counting_secret(), SEQ, at(NOW + 5)).unwrap();
        assert_eq!(opened, item(ENDPOINT, 0x0102_0304_0506_0708, NOW));
    }

    /// Made by `build(&counting_secret(), ENDPOINT, 0x0102_0304_0506_0708, at(NOW))`, split as `seal` lays a blob out.
    const STORED_REQUEST: &str = concat!(
        // Version, one wrap, the nonce.
        "01",
        "01",
        "ab14ac52cc8660efcd88a37c",
        // The wrap of the content key.
        "8c608c55ed486b41277ce07c8d9d607a57a2ea2ab90ad450d685cad9115977cd21420da2aee3b5f9785c5a03b06e56e4",
        // The payload (34 bytes, see `the_payload_format_is_pinned`) and its tag.
        "278cb78a8be1f4d9c36a31ec569f6cc86a7262928f95033c60324a0fdbaec8afb9c54793ee4be9460fd97c16656572a83449",
    );

    #[test]
    fn a_host_record_is_not_a_request_and_a_request_is_not_a_host_record() {
        // The same secret opens both, and only the salt in the associated data keeps them apart.
        let client = secret(1);
        let host_record =
            Record { fingerprint: [0; 32], addresses: vec![], nat: Nat::Unknown, relays: vec![], mac: None, ts: NOW };
        let record_blob =
            seal::seal(&host_record, record::SALT, SEQ, std::slice::from_ref(&client), None).unwrap().blob;
        let err = open(&record_blob, &client, SEQ, at(NOW)).unwrap_err();
        assert!(matches!(err, PunchError::Open(OpenError::NotRecipient)), "{err}");

        let (_, _, seq, request_blob) = build(&client, ENDPOINT, 1, at(NOW)).unwrap();
        assert!(seal::open(&request_blob, record::SALT, seq, &client).is_err());
    }

    #[test]
    fn two_requests_are_never_the_same_bytes() {
        let client = secret(1);
        let (a, b) = (build(&client, ENDPOINT, 1, at(NOW)).unwrap(), build(&client, ENDPOINT, 1, at(NOW)).unwrap());
        assert_eq!(
            (a.0.to_bytes(), a.1, a.2),
            (b.0.to_bytes(), b.1, b.2),
            "the key, salt and seq are fixed by the inputs"
        );
        assert_ne!(a.3, b.3, "the nonce and content key of the seal are fresh");
    }
}
