# C3 punch request item: hand-over for E5, F4 (and C2, E3)

Branch `claude/reach-c3-punch-item-71d463` (from 35081ec), commit 9fbcc18, file `crates/dht/src/punch_item.rs` (nothing else
touched). 22 unit tests (66 in the crate with C1's); fmt, clippy `-D warnings` and tests green. The module carries the guard of
`seal.rs` (`deny(clippy::unwrap_used, expect_used, indexing_slicing, panic)` outside tests), so "never panic on network input" is
checked by the compiler. Also checked by hand with 15 planted bugs (the two tolerances, the salt, the label, the seq, the
freshness check, the length limits, the version and trailing-byte checks...): every one made a test fail. No traffic to the
DHT: the module is pure.

## API

```rust
pub const SALT: &[u8] = b"velora/punch/1";  VERSION: u8 = 1;  MAX_AGE_SECS = 60;  MAX_FUTURE_SECS = 10;  MAX_ENDPOINT_LEN = 64;
struct PunchItem { endpoint: String, nonce: u64, ts: u64 }

public_key(&Secret) -> [u8; 32]                        // E5: the DHT key to poll for the device that holds this secret
build(&Secret, endpoint: &str, nonce: u64, now: SystemTime) -> Result<Built, PunchError>                   // F4
build_after(&Secret, endpoint, nonce, now, last_seq: i64) -> Result<Built, PunchError>                      // F4, see the seq below
type Built = (SigningKey, &'static [u8], i64, Vec<u8>)  // key to sign with, salt, seq, value: MutableItem::new's order
open(blob: &[u8], &Secret, seq: i64, now: SystemTime) -> Result<PunchItem, PunchError>                      // E5
enum PunchError { Clock, EndpointLength { len }, Stale { age }, FromTheFuture { ahead }, Version(u8), Empty,
                  Malformed(postcard::Error), Trailing(usize), Encode(postcard::Error), Seal(SealError), Open(OpenError) }
```

`Secret` is C1's (`seal::Secret`). `now` is passed in: nothing here reads a clock.

## What was built instead of what the ticket said

The ticket (and the plan before it was corrected) has the client sign with its own Ed25519 key and a salt with a host key
prefix. A host cannot poll that: nothing in the protocol tells it the DHT key of a paired client (`HostMsg::Reach.key` goes
the other way, host to client), so it would have no key to look at. Both ends do hold the device secret (the host made it for
that device; the client has it from the pairing link or `HostMsg::Reach`), so the signing key is derived from it:

```
seed = HKDF-SHA256(ikm = secret (16 bytes), salt = none, info = "velora-dht/punch/v1 signing key", L = 32)
key  = Ed25519 key of the seed (mainline::SigningKey::from_bytes)
item = BEP 44 item at that key, salt "velora/punch/1", seq = unix seconds, value = the sealed request below
```

- A host knows the key of each paired device without any new message, and `public_key` is the same bytes on both ends.
- The client's own `dht_key.bin` is not involved: F4 needs no `Keys`, only the secret it holds for that host.
- A secret is per (host, device), so the key is the pair's own slot, constant salt included. One item lives in a slot: a newer
  request replaces the older one.
- Revoking a device is dropping its secret: E5 stops polling its key.
- A watcher of the DHT sees an item at a key and its seq: the times of a pairing's requests, and that two of them belong
  together; not who asked or which host, since the key is a function of a secret.

## Wire format (version 1, pinned)

Value = `seal::seal_payload(payload, SALT, seq, &[secret], None)`: C1's layout with one wrap (78 bytes of overhead), so the
host and the client are its only readers. Payload = `01 | postcard { endpoint: String, nonce: u64, ts: u64 }` (varints). The
test request (an 18-byte endpoint) is a 34-byte payload and a 112-byte value; the longest `build` makes is under 170 (the limit
is 996, and the salt is 14 of 64 bytes).

Pinned by the vectors of the key derivation (worked out independently, below), the bytes of the payload, and a stored sealed
value that must keep opening (`a_request_sealed_by_this_version_still_opens`). Changing any of them is a protocol change.

```python
# python -I, needs `cryptography`; the test also has RFC 5869 written out with hashlib and hmac
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
secret = bytes(range(16))
seed = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"velora-dht/punch/v1 signing key").derive(secret)
key = Ed25519PrivateKey.from_private_bytes(seed).public_key()
print(seed.hex(), key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex())
```

## Decisions to review

1. **The key comes from the device secret**, not from the client's own key (above).
2. **HKDF is two `ring::hmac` calls** (RFC 5869 for one 32-byte block), not `ring::hkdf`: `Okm::fill` returns a `Result` for
   lengths that cannot occur here, and `public_key(secret) -> [u8; 32]` has no room for an error. A test compares the two for
   306 secrets and the pinned vectors come from Python's HKDF, so they cannot drift apart. Say so if you would rather have
   `ring::hkdf` and a `Result` from `public_key`: it is five lines.
3. **`now` is a `SystemTime`**, so seconds cannot be mistaken for milliseconds (before 1970 is `PunchError::Clock`); `seq` is an
   `i64` like `MutableItem`'s and `ts` a `u64` like `Record::ts`.
4. **`Built` is a type alias** because clippy's `type_complexity` refused the bare four-tuple of the ticket. It is that tuple.
5. **`build_after` is an addition.** The S0 seq rules (`dht-spike.md` §4.3): an equal seq is acknowledged and ignored, a lower one
   refused, and a seq that ran ahead once blocks the key until the item expires. `build` ties `seq` to the clock, and so to
   `ts`, so it cannot recover from either; `build_after` takes `max(clock, last_seq + 1)` and leaves `ts` on the clock, so the
   host still sees a fresh request. `open` does not require `seq == ts` for that reason.
6. **Tolerances: 60 s old (the ticket), 10 s ahead ("a small skew")**, both inclusive. A request 60 s old is one its client
   made less than a minute ago; one dated ahead comes from a clock that is wrong. The host applies them in `open`, so a host
   release can raise `MAX_FUTURE_SECS` if the field shows bigger clock errors; clients need no change. A client whose clock is
   more than 10 s ahead or more than 60 s behind is never served, and its punch fails like any other.
7. **`PunchError` is a typed enum**, not `anyhow`: E5 must tell `Stale` and `Open(NotRecipient)` (quiet) from `FromTheFuture`
   (worth a line: the client's clock) and from damage.
8. **The endpoint is bounded** (1 to 64 bytes, checked in `build` and in `open`) **and not parsed**: no format check, no
   address policy (E5's, below). 64 is above the 58 bytes of the longest `SocketAddr` text (a test checks it).
9. **No logging here**: a stale item is what most polls return, and only the caller knows which device it polled.

## What E5 (host: poll and respond) must know

- **Poll.** For each paired device, with its secret from E3's list: `public_key(&secret)` (once per change of the list; it
  costs a point multiplication), then C2's `resolve(key, SALT)` for `(blob, seq)`, then `open(&blob, &secret, seq,
  SystemTime::now())`. Take the first valid item of the resolve stream.
- **N paired devices are N lookups per round**, and a lookup is dear: about 300 datagrams sent and 200 received from a fresh
  node, about 70 and 40 repeated from a running one (`dht-spike.md` §8); the plan's own figure is about 10 datagrams a second
  per device at a 10 s poll. So poll sparingly: the plan's 30-60 s, with the short burst after a disconnect for the device that
  was last connected only and the slow rate for the others; nothing while the host is registered with a relay (the relay is
  the signalling channel); nothing for a revoked device; and spread a round's lookups over the interval instead of firing
  them together.
- **Most answers are quiet.** `Stale` and `Open(NotRecipient)` are the usual ones (trace or debug). `FromTheFuture` deserves a
  line, since it is a client with a wrong clock. `Malformed`, `Version`, `Trailing`, `Empty`, `EndpointLength` and
  `Open(Corrupt | Malformed | Version)` are damage or a newer client: debug, once per device.
- **Skip what was served.** The DHT keeps an item for hours: remember per device the highest `seq` opened and skip an item
  whose seq is not newer (saves the AEAD too).
- **Anyone who holds a device's secret can forge a request for that device**, for any endpoint: the device, a copy of its
  config, whoever it leaked to. All it costs the host is a QUIC Initial toward an endpoint of the forger's choosing, a
  reflected packet of 1200 bytes and a probe of whatever listens there, a LAN service included. So E5 must:
  - accept each nonce once: remember `(device, nonce)` until `ts + MAX_AGE_SECS`, after which `open` says `Stale` anyway;
  - rate-limit, per device and overall;
  - decide where it may send, since `open` checks the length of the endpoint and nothing else: global unicast only, port not 0,
    never loopback, private, link-local, multicast or unspecified (the endpoint is the client's public address as the DHT
    sees it).

  The slot helps: one item per device, so a flood of requests overwrites itself and a poll sees at most one per device.
- **Shared mode** (C1: more devices than fit in a record): every device then holds the same secret, so they share one slot, a
  request replaces another's and any of them can forge for the others. Poll that one slot once.

## What F4 (client: punch dialer) must know

- The secret is the one the host gave this client (`known_host.secret`, from the pairing link or `HostMsg::Reach`). Without
  one (a host paired before this version, not connected to since) there is no request to send: skip this path.
- `nonce` must be random (`ring::rand::SystemRandom`): the host serves each one once.
- Publish: `let (key, salt, seq, blob) = punch_item::build_after(&secret, &endpoint.to_string(), nonce, SystemTime::now(),
  last_seq)?;` then `MutableItem::new(key, &blob, seq, Some(salt))` through C2. Keep the last `seq` published per host (in memory
  is enough; `build`, or `i64::MIN`, for the first). On `Concurrency(NotMostRecent)` or `CasFailed`, resolve the item at
  `public_key(&secret)`, take its seq as `last_seq` and build again (S0 §4.3).
- The endpoint is the client's address as the DHT sees it, observed from the socket that will carry the QUIC connection (plan,
  phase 3), as `SocketAddr::to_string()`.
- Publish only when the direct addresses and a relay failed or are missing: a put is hundreds of datagrams.
- A host that polls every 30-60 s answers after half of that on average, so the plan's "give up after 10 s" fits the relay
  path, not this one: F4's wait on this path has to cover a poll interval plus the DHT's propagation (or the host's burst).

## C2 and E3

- **C2.** The punch key is not a `Keys` file (C1's `Keys` has no constructor from a `SigningKey`), so `publish` has to accept
  a `SigningKey` (or `&SigningKey`), or `Keys` needs one. `resolve(public_key, salt)` is what E5 calls with `public_key(&secret)`
  and `SALT`.
- **E3.** The device secrets it keeps are what E5 derives its poll list from: adding a device adds a key, revoking one drops it.
  Nothing else changes.
