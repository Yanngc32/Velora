# T0 protocol: hand-over for E1, F1, G1 (and anyone reading `velora_protocol`)

Branch `claude/reach-t0-protocol-ad10c7` (one commit, `43c0ebe`), cut from `standalone-reach`. Files: `crates/protocol/src/{wire,pairing,control,identity}.rs`
plus the mechanical edits listed at the end. Everything below is also in the doc comments; the tests pin it.
Checked: `cargo fmt --all --check`, `clippy -p velora-protocol --all-targets -D warnings`, `test -p velora-protocol` (49 unit + 4
integration), and `clippy --workspace --all-targets -D warnings` (build dir `velora-reach-target-ws`, left in place).

## Hello

`HelloExt.reach` is bit 5 of the flags byte (0 files_only, 1 clipboard, 2 addresses, 3 displays, 4 audio, 5 reach, 6 free).
Bit 7 (`0x80`) = "another flags byte follows": this version reads and skips those bytes (each one with its own top bit
meaning "and another"), exposes nothing from them, and never sets the bit. A lone `0x80` bit with nothing after it
decodes as it always did.

## Control messages (little-endian; `str` = u16 length + UTF-8, cut at 256 bytes; `mac` = u8 0|1 then 6 bytes if 1)

| dir | tag | message | body |
|---|---|---|---|
| client | 11 | `Reached { address }` | str |
| client | 12 | `RelayRegister { mac: Option<[u8;6]> }` | mac |
| client | 13 | `RelayTo { fingerprint }` | str |
| client | 14 | `Wake { fingerprint }` | str |
| client | 15 | `PunchRequest { to, endpoint, nonce: u64 }` | str, str, u64 |
| host | 6 | `Reach { addresses, key, secret, relays, mac, relays_for_others }` | u8 n (<=16), n x (kind, str); 32 bytes key; 16 bytes secret; u8 n (<=8), n x (str fingerprint, u8 m (<=16), m x str); mac; u8 bool |
| host | 7 | `RelayStatus { ok, reason }` | u8 bool, str |
| host | 8 | `PunchRequest { from, endpoint, nonce: u64 }` | str, str, u64 |

`kind` = one byte: 0 Lan, 1 Vpn, 2 Public, 3 V6, 4 Relay (then the relay fingerprint as a str), anything else `Other(code)`
with nothing after it. Fingerprints are `Fingerprint::to_base64()` text (base64url, no padding, 43 characters), like
`KnownHost.fingerprint`. Lists longer than their cap are read and cut (never an error), and cut on encode.
Old hosts decode tags 11-15 as `ClientMsg::Unsupported` (payload ignored), as before.

## Things to know before building on it

1. **The welcome stays at 8 addresses.** `MAX_ADDRESSES` is now 16 and is the cap of `Reach` (and of each relay in it), but
   clients before this version read exactly 8 addresses in a welcome and then reject trailing bytes, so a welcome with more
   would break them. `MAX_WELCOME_ADDRESSES = 8` is what `HostMsg::Welcome` encodes (first 8 of the list, so put the most
   useful first) and what it decodes (a longer list from a newer host is read and cut). `docs/nat-traversal.md` §8 and §13.15
   say "old clients truncate harmlessly"; that is not true of the welcome, so the doc needs a correction (H1).
2. **The pairing link cannot hold 8 addresses plus key and secret in 300 characters.** `key=` is 43 characters and `secret=`
   22 (base64url, no padding, like the code), 78 with their names; one IPv4 address makes a 114-character link, each further
   one adds about 25 and an IPv6 one about 72. Measured: LAN + VPN + public + key + secret = 245; eight IPv4 addresses with
   key and secret = about 360. E1 should put only the addresses a first connection needs in the link; the rest arrives in
   `Reach` (the device is connected by then).
3. `pairing_uri_with(address, also, code, key: Option<&[u8;32]>, secret: Option<&[u8;16]>)`: two new parameters. `PairingLink`
   gained `key: Option<[u8;32]>` and `secret: Option<[u8;16]>` (a damaged or wrong-sized value is read as absent, the link
   still pairs). With `None, None` the link is byte-for-byte what earlier versions wrote.
4. `KnownHost` (all new fields skipped when empty, so a host that never uses reach keeps the file earlier versions wrote):
   `kinds: Vec<(AddressKind, String)>` (the last `Reach` list as pairs, replace it whole; `address`/`also` stay as they were),
   `key: Option<[u8;32]>`, `secret: Option<[u8;16]>`, `mac: Option<[u8;6]>` (typed in Rust, base64url text in the JSON; a
   damaged text reads as absent instead of failing the file), `relays: Vec<(String, Vec<String>)>`. It derives `Default`
   and `PartialEq, Eq` now.
5. `control::Status.reach: Option<ReachStatus>`; `ReachStatus` and `MappingStatus` derive `Default` and read missing fields
   as default, so a fake status for a card test is `ReachStatus { standalone: true, ..Default::default() }`.
   `MappingStatus { protocol: "natpmp"|"upnp", external: "ip:port", public: bool (false = CGNAT/double NAT, not advertised),
   lease_secs: u64 }`. `registered_with` holds relay names, for display. `last_reached` is `(AddressKind, String)`.
   `AddressKind` as JSON: `"lan"`, `"vpn"`, `"public"`, `"v6"`, `{"relay":"<fp>"}`, `{"other":9}`.
6. `Request::SetReach { standalone, relay_for_others, dht }` is not in the host's `harmless` list in `Server::control`: under
   the service only an administrator can send it. E1 decides if that is right.
7. `KnownHost` does not store `relays_for_others` (the ticket does not list it): E4 learns it from the `Reach` it gets when it
   connects to each paired device. Adding `relays_for_others: bool` later would need an edit to `identity.rs` (T0-owned).
8. Fingerprints on the wire are base64url `String`s, not 32 raw bytes (as in the ticket's `relays`); receivers parse them with
   `Fingerprint::from_base64` and answer `RelayStatus { ok: false, .. }` when that fails. `nonce` is a `u64`.
9. A kind added to `AddressKind` later must carry no payload (this version cannot skip one); `Relay` is the only one with a
   fingerprint after its code.

## Edits outside the four files (mechanical, each with a `// reach: ... filled in by ...` comment)

- `crates/client-core/src/lib.rs`: `HelloExt { reach: false, .. }` in `connect` (F1 sets it); an arm in the handshake match that
  fails on `Reach`/`RelayStatus`/`PunchRequest` before the welcome (F1).
- `crates/client-core/src/hosts.rs`: `..Default::default()` in the `KnownHost` literal of `remember` (F1; note that `remember`
  rebuilds the entry, so it drops reach data on a re-pair until F1 handles it).
- `crates/host/src/server.rs`: `Request::SetReach` arm (does nothing), `reach: None` in `status`, an arm for the five new
  client messages (ignored), `None, None` in `pairing_uri_with` (E1).
- `crates/host/src/main.rs`: `None, None` in `pairing_uri_with` (E1).
