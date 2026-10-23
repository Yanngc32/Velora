# C1 DHT record, keys and sealing: hand-over for C2, C3, E3, F2 (and the review)

Branch `claude/reach-c1-record-seal-809191` (from 2c25df3), commits 92a185b (keys), 1577468 (record), 60ebe70 (seal).
Files: `crates/dht/src/{keys,record,seal}.rs`, nothing else touched. 44 unit tests; fmt, clippy `-D warnings` and tests
green. `seal.rs` carries `#![cfg_attr(not(test), deny(clippy::unwrap_used, expect_used, indexing_slicing, panic))]`, so
"never panic on network input" is checked by the compiler there (I injected an `unwrap` and an index to see it fail).

## API

```rust
// keys.rs
pub const FILE_NAME: &str = "dht_key.bin";            // put it in the state dir beside identity.json
Keys::load_or_create(path: &Path) -> anyhow::Result<Keys>   // 32-byte seed file; wrong size = Err, never replaced
Keys::public_key(&self) -> [u8; 32]                    // goes in HostMsg::Reach.key and the pairing link
Keys::signing_key(&self) -> &mainline::SigningKey      // .clone() into MutableItem::new(signer, &blob, seq, Some(SALT))

// record.rs
pub const SALT: &[u8] = b"velora/1";  pub const VERSION: u8 = 1;
enum Kind { Lan = 0, Vpn = 1, Public = 2, V6 = 3, Relay = 4, Other(u8) }    // From<u8> / Into<u8>
enum Nat  { Unknown = 0, Open = 1, Cone = 2, Symmetric = 3, Other(u8) }
struct Relay  { fingerprint: [u8; 32], addresses: Vec<String> }
struct Record { fingerprint: [u8; 32], addresses: Vec<(Kind, String)>, nat: Nat, relays: Vec<Relay>,
                mac: Option<[u8; 6]>, ts: u64 }
Record::encode(&self) -> Result<Vec<u8>, RecordError>;  Record::decode(&[u8]) -> Result<Record, RecordError>

// seal.rs
struct Secret([u8; 16])   // Secret::new([u8;16]), Secret::generate(), .as_bytes(); Debug prints "Secret(..)"
seal(&Record, salt: &[u8], seq: i64, devices: &[Secret], shared: Option<&Secret>) -> Result<Sealed, SealError>
open(blob: &[u8], salt: &[u8], seq: i64, secret: &Secret) -> Result<Record, OpenError>
seal_payload(plain: &[u8], ...same...) / open_payload(blob, ...same...) -> Result<Vec<u8>, OpenError>   // for C3
struct Sealed { blob: Vec<u8>, per_device: bool }
max_devices(payload_len: usize) -> usize     // wraps that fit beside a payload; MAX_SEALED_LEN = 996, WRAP_LEN = 48, OVERHEAD = 30
SealError { NoRecipients, TooLarge { over, wraps }, Record(..), Crypto }
OpenError { Malformed(&str), Version(u8), NotRecipient, Corrupt, Record(..), Crypto }
```

## Sealed layout (version 1, pinned by a test vector; changing it is a protocol change)

`01 | count | nonce(12) | wrap(48) * count | ChaCha20-Poly1305(content key, record) + tag(16)`;
`wrap = ChaCha20-Poly1305(HKDF-SHA256(secret, info "velora-dht/seal/v1 wrap key"), content key) + tag`.
Nonce: one random 96-bit per seal; the payload uses it as is, wrap `i` (from 1) has `i` XORed into the last byte.
AAD: `[purpose, 01] | seq (i64 BE) | salt.len() (u64 BE) | salt | (payload only) count | nonce | every wrap`.
`C1-kat_check.py` (this folder) re-implements the layout in Python with OpenSSL (`cryptography`); its output is the vector
in `seal::tests::the_wire_format_is_pinned`, byte for byte, and it opens the Rust blob. Run:
`python -I C1-kat_check.py <hex of a blob sealed with the test's fixed inputs>`.

Sizes (the test record: 8 addresses, two of them IPv6, one relay, a MAC): payload 316 bytes, 13 devices fit,
12 devices make a 922-byte blob. A record with more IPv6 addresses fits fewer devices; the fallback covers it.

## Decisions to review

1. **No `DeviceId` in the API.** The wraps carry no id: `open` tries each (at most 20, microseconds). That keeps the 48
   bytes per device the design counts on, and keeps a public DHT record from carrying a stable per-device tag (a
   fingerprint hash there would let anyone watching the DHT follow which devices are paired). Cost: the blob shows
   how many devices are paired. E3 passes the secrets only; F2 opens with its secret only.
2. **996, not 1000.** BEP 44 caps the *bencoded* value, and a byte string of 100..=999 bytes gets a 4-byte `NNN:` prefix.
   `mainline` would accept 1000 raw bytes, but nodes that count the prefix would not. Change `MAX_SEALED_LEN` if you
   disagree; 4 bytes is a third of a device.
3. **HKDF for the 16-byte secret.** ChaCha20-Poly1305 wants 32 bytes. Zero-padding was the alternative; HKDF-SHA256
   from `ring` with a fixed label is the usual way and keeps the key from serving anything else. It is the only
   primitive besides the AEAD.
4. **Nonces.** The brief said a fresh random nonce per seal *and per wrap*; at 48 bytes per wrap there is no room, so
   wrap nonces derive from the seal's (see above): every call of a seal has its own nonce, and a device key sees
   a repeat across seals only if two random 96-bit nonces coincide up to the last byte.
5. **The shared-secret fallback needs the shared secret as an argument** (`shared: Option<&Secret>`). With only per-device
   secrets nothing can fall back to anything. `Sealed::per_device == false` tells the caller it happened (and a
   `tracing::warn!` says so). The shared blob has one wrap, and no device secret opens it. Without `shared`, the
   devices that do not fit are `TooLarge { over, wraps }`, with `over` the bytes past the limit.
6. **`Kind` codes** are the ones in the brief (T0's codes were not available); E3 converts. `Record` holds fingerprints
   as raw `[u8; 32]` (the hex form would cost 32 more bytes each), so E3/F2 convert from `Fingerprint`/hex.
7. **Strict decoding.** `Record::decode` rejects another version and trailing bytes; `open_payload` rejects blobs over
   996 bytes. Adding a record field means bumping `record::VERSION`; an older client then ignores the record.
8. The key file is not guarded against two processes creating it in the same instant (last rename wins), like
   `write_json` in `identity.rs`. No `zeroize` (not in the dependency set); the seed also lives in the `SigningKey`.

## What the other tickets must know

- **E3 (host).** Publish: `seal::seal(&record, SALT, seq, &secrets, Some(&shared))`, then
  `MutableItem::new(keys.signing_key().clone(), &sealed.blob, seq, Some(SALT))` (C2). `seq` must grow on every publish
  (unix seconds; two publishes in one second need a bump). Revoking: drop the device's secret from the list and publish.
  It can still read what it fetched, and DHT nodes keep the last value ~2 h. **Shared mode is a protocol matter**: once
  `per_device` is false, every device must hold the shared secret, and `HostMsg::Reach.secret` is the only way it gets
  there, so E3 must send the *shared* secret there while the host is in that mode, and a device away during the switch
  cannot read the record until it connects some other way. Decide the threshold by device count with the worst-case
  record (`max_devices(worst_len)`), not per publish, or the mode (and every client's secret) would flip as addresses
  change. `Secret::generate()` makes device secrets.
- **C2 (node).** Value is `&sealed.blob` (at most 996 bytes), salt `SALT`. The seq in `MutableItem` is the one passed to `seal`.
- **F2 (client).** `seal::open(&blob, SALT, item.seq(), &Secret::new(known_host.secret))`. `NotRecipient` means revoked,
  a stale secret, or a record sealed for another seq/salt; treat it as "no record", not as an attack. `Corrupt` and
  `Malformed` are damage. A signature check on the item is `mainline`'s, before `open`.
- **C3 (punch item).** Use `seal_payload`/`open_payload` with salt `velora/punch/<host key prefix>`, the host's view of the
  client's device secret as the only recipient, and the item's seq. The salt is in the AAD, so a punch blob never opens as
  a record. The 60 s freshness check goes on your own `ts` inside the payload.
- **T0.** `Reach.secret: [u8; 16]` and `Reach.key: [u8; 32]` match `SECRET_LEN` and `Keys::public_key()`.
