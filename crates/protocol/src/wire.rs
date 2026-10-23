//! Binary wire format.
//!
//! Three channels share one QUIC connection:
//! - **Control stream** (client-opened bidirectional stream): length-prefixed [`ClientMsg`] /
//!   [`HostMsg`]. Reliable and ordered: used for everything that must not be lost (keys,
//!   buttons, scroll, acks), because a lost key-up means a stuck key on the host.
//! - **Datagrams** (client -> host): [`MouseMove`]. Unreliable; a newer position supersedes an
//!   older one, so retransmitting stale positions would only add latency.
//! - **Video** (host -> client): one unidirectional stream per encoded frame, starting with a
//!   [`FrameHeader`] followed by the H.264 Annex-B bitstream until end of stream.
//! - **Files** (either side opens): one bidirectional stream per operation, see
//!   [`crate::files`]. Only with hosts that announce [`FEATURE_FILES`].
//!
//! Control messages start with a one-byte tag, numbered separately for each direction. A new
//! message takes the next free number and is sent only to a peer that said it understands it
//! (a hello bit, or an earlier message that announced it): a host decodes a tag it does not
//! know as [`ClientMsg::Unsupported`] and ignores it, a client fails on one.
//!
//! | tag | [`ClientMsg`]     | [`HostMsg`]        |
//! |----:|-------------------|--------------------|
//! |   1 | `Hello`           | `Welcome`          |
//! |   2 | `Key`             | `Paired`           |
//! |   3 | `MouseButton`     | `Rejected`         |
//! |   4 | `Scroll`          | `PasswordRequired` |
//! |   5 | `FrameAck`        | `Displays`         |
//! |   6 | `RequestKeyframe` | `Reach`            |
//! |   7 | `ReleaseAll`      | `RelayStatus`      |
//! |   8 | `Text`            | `PunchRequest`     |
//! |   9 | `OfferPairing`    |                    |
//! |  10 | `SelectDisplay`   |                    |
//! |  11 | `Reached`         |                    |
//! |  12 | `RelayRegister`   |                    |
//! |  13 | `RelayTo`         |                    |
//! |  14 | `Wake`            |                    |
//! |  15 | `PunchRequest`    |                    |

use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u16 = 1;
pub const ALPN: &[u8] = b"velora/1";
pub const DEFAULT_PORT: u16 = 7420;

/// Upper bound for a single control message, enforced before allocation.
pub const MAX_CONTROL_MSG: usize = 64 * 1024;
/// Upper bound for a single encoded video frame.
pub const MAX_FRAME_BYTES: usize = 32 * 1024 * 1024;

pub const PAIRING_SECRET_LEN: usize = 16;
/// Device names longer than this are truncated on encode.
pub const MAX_NAME_LEN: usize = 256;
/// Longest text carried by one [`ClientMsg::Text`]; longer input is split by [`split_text`].
pub const MAX_TEXT_LEN: usize = 4096;
/// Most addresses a [`HostMsg::Reach`] lists, and most it lists for one relay.
pub const MAX_ADDRESSES: usize = 16;
/// Most addresses a welcome carries. Clients that predate [`HostMsg::Reach`] read this many and
/// reject a welcome with more (they insist the message ends after the last one), so it stays
/// at 8 while [`MAX_ADDRESSES`] grew: the rest of the host's addresses travel in `Reach`.
pub const MAX_WELCOME_ADDRESSES: usize = 8;
/// Most relays a [`HostMsg::Reach`] lists.
pub const MAX_RELAYS: usize = 8;
/// Longest pairing link in [`ClientMsg::OfferPairing`], in bytes.
pub const MAX_LINK_LEN: usize = 1024;
/// Longest access password, in bytes.
pub const MAX_PASSWORD_LEN: usize = 256;
/// Most displays a [`HostMsg::Displays`] lists.
pub const MAX_DISPLAYS: usize = 16;
/// Length of the Ed25519 public key a host publishes its DHT record under, in bytes.
pub const REACH_KEY_LEN: usize = 32;
/// Length of the secret that opens a host's DHT record, in bytes. The host gives one to each
/// paired device, so that removing a device also cuts it off from the record.
pub const DEVICE_SECRET_LEN: usize = 16;

/// [`HostMsg::Welcome`] feature bit: the host serves file streams.
pub const FEATURE_FILES: u32 = 1;
/// [`HostMsg::Welcome`] feature bit: the host shares its clipboard (see `files::FileMsg::Clipboard`).
pub const FEATURE_CLIPBOARD: u32 = 2;
/// [`HostMsg::Welcome`] feature bit: the host sends its sound (see [`AudioPacket`]).
pub const FEATURE_AUDIO: u32 = 4;

/// What a client that knows about extensions adds to its hello. Hosts that predate them reject
/// such a hello, and only hellos with it are answered with `features` in the welcome.
///
/// On the wire these are the bits of one flags byte after the password field: 0 `files_only`,
/// 1 `clipboard`, 2 `addresses`, 3 `displays`, 4 `audio`, 5 `reach`; bit 6 is free. Bit 7 is
/// reserved for "another flags byte follows", so a later version can add flags without
/// running out of bits. This version decodes such a hello and skips those bytes, which it has no
/// use for yet, and never sets the bit; a host that predates the bit drops a hello that has
/// them. Every host so far ignores bits it does not know, which is why a new bit is safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HelloExt {
    /// Only file transfers: no video or input, and the host's current session is left alone.
    pub files_only: bool,
    /// The client takes clipboard content on its file streams.
    pub clipboard: bool,
    /// The client wants the host's other addresses in the welcome (see `HostMsg::Welcome`).
    pub addresses: bool,
    /// The client can pick among the host's displays (see [`HostMsg::Displays`]).
    pub displays: bool,
    /// The client plays the host's sound (see [`AudioPacket`]).
    pub audio: bool,
    /// The client understands standalone reach: it wants a [`HostMsg::Reach`] after the welcome.
    /// Hosts that predate it ignore the bit and send none.
    pub reach: bool,
}

/// Bit 7 of the hello's flags byte: another flags byte follows (see [`HelloExt`]).
const HELLO_MORE_FLAGS: u8 = 0x80;

/// How one of the host's addresses is reached, as [`HostMsg::Reach`] lists them. On the wire a
/// kind is one byte: 0 `Lan`, 1 `Vpn`, 2 `Public`, 3 `V6`, 4 `Relay`, followed (for `Relay` only)
/// by the relay's fingerprint as a string. Any other code is [`AddressKind::Other`], which
/// carries the code unchanged. A kind added later must not carry anything after its code,
/// since this version could not tell where it ends.
///
/// As JSON (the control channel, the known-hosts file) it is `"lan"`, `"vpn"`, `"public"`,
/// `"v6"`, `{"relay":"<fingerprint>"}` or `{"other":<code>}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressKind {
    /// On the host's local network (code 0).
    Lan,
    /// On a VPN mesh like Tailscale or Netbird (code 1).
    Vpn,
    /// The router's public IPv4 address and the port it maps to the host (code 2).
    Public,
    /// A global IPv6 address of the host (code 3).
    V6,
    /// Through a relay: another paired PC that both ends can reach (code 4). Holds the relay's
    /// fingerprint, base64url as `Fingerprint::to_base64` writes it; the address next to it is
    /// the relay's own.
    Relay(String),
    /// A kind this version does not know, by its code (above 4: reading a code listed above
    /// never makes this, and one made by hand from such a code would not round-trip).
    Other(u8),
}

impl AddressKind {
    /// The kind's byte on the wire.
    pub fn code(&self) -> u8 {
        match self {
            Self::Lan => 0,
            Self::Vpn => 1,
            Self::Public => 2,
            Self::V6 => 3,
            Self::Relay(_) => 4,
            Self::Other(code) => *code,
        }
    }
}

/// One of the host's displays, as [`HostMsg::Displays`] lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayInfo {
    pub name: String,
    pub width: u16,
    pub height: u16,
    pub primary: bool,
}

/// The host's displays, left to right, and the one being streamed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DisplayList {
    pub current: u8,
    pub list: Vec<DisplayInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MouseButton {
    Left = 1,
    Right = 2,
    Middle = 3,
    Back = 4,
    Forward = 5,
}

impl MouseButton {
    fn from_u8(v: u8) -> Result<Self> {
        Ok(match v {
            1 => Self::Left,
            2 => Self::Right,
            3 => Self::Middle,
            4 => Self::Back,
            5 => Self::Forward,
            _ => bail!("invalid mouse button {v}"),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyState {
    Up = 0,
    Down = 1,
    /// Auto-repeat generated by the client OS while the key is held.
    Repeat = 2,
}

impl KeyState {
    fn from_u8(v: u8) -> Result<Self> {
        Ok(match v {
            0 => Self::Up,
            1 => Self::Down,
            2 => Self::Repeat,
            _ => bail!("invalid key state {v}"),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Codec {
    H264 = 1,
}

impl Codec {
    fn from_u8(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Self::H264),
            _ => bail!("unsupported codec {v}"),
        }
    }
}

/// Messages sent by the client on the control stream.
///
/// Pointer coordinates are absolute and normalized to the streamed display: `0..=65535` on
/// each axis, independent of client and host resolutions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientMsg {
    Hello {
        version: u16,
        name: String,
        pairing_secret: Option<[u8; PAIRING_SECRET_LEN]>,
        /// The host's access password, when it has one (see [`HostMsg::PasswordRequired`]).
        /// Sent inside TLS to the pinned host. Encoded only when present, so hosts that
        /// predate passwords still understand every hello without one.
        password: Option<String>,
        /// Present from clients that know about extensions, encoded after the password field.
        ext: Option<HelloExt>,
    },
    /// `code` is a Linux evdev key code (`KEY_*`), i.e. a physical, layout-independent key.
    Key {
        code: u16,
        state: KeyState,
    },
    /// Carries the pointer position so the click lands where the user saw the cursor, even if
    /// the latest move datagram was lost or reordered.
    MouseButton {
        button: MouseButton,
        down: bool,
        x: u16,
        y: u16,
    },
    /// Wheel deltas in 1/120 notch units. Positive `dy` scrolls up, positive `dx` scrolls right.
    Scroll {
        dx: i16,
        dy: i16,
    },
    /// The frame with this id was fully received.
    FrameAck {
        frame_id: u32,
    },
    RequestKeyframe,
    /// Release every key and button currently held (e.g. the client window lost focus).
    ReleaseAll,
    /// Characters to type on the host, independent of its keyboard layout (soft keyboards).
    Text {
        text: String,
    },
    /// A `velora://pair?..` link to the client's own host, so the host's computer can pair back
    /// and reach the client's too. Hosts that predate it ignore it.
    OfferPairing {
        link: String,
    },
    /// Stream another of the host's displays, by its index in [`HostMsg::Displays`].
    SelectDisplay {
        index: u8,
    },
    /// Which of the host's addresses this connection was made to (the one that won the
    /// client's race), as the client dialed it. The host logs it and shows it as "last reached".
    /// Sent once, after the welcome, to hosts that sent a [`HostMsg::Reach`].
    Reached {
        address: String,
    },
    /// Asks the host (a relay) to keep this connection as its way in from outside: the sender
    /// is a host that cannot be reached directly, so it dials out and clients are passed
    /// through to it (see [`ClientMsg::RelayTo`]). `mac` is the MAC address of its network
    /// adapter, which lets the relay wake it (see [`ClientMsg::Wake`]); `None` when it knows
    /// none. Answered with [`HostMsg::RelayStatus`]. Sent only to a host whose `Reach` said
    /// `relays_for_others`.
    RelayRegister {
        mac: Option<[u8; 6]>,
    },
    /// Asks the host (a relay) to pass this connection's datagrams to the registered host with
    /// this fingerprint (base64url, as `Fingerprint::to_base64`), and the host's back. Answered
    /// with [`HostMsg::RelayStatus`]. Sent only to a host whose `Reach` said `relays_for_others`.
    RelayTo {
        fingerprint: String,
    },
    /// Asks the host (a relay) to wake the registered host with this fingerprint by
    /// Wake-on-LAN, using the MAC address it registered with. Answered with
    /// [`HostMsg::RelayStatus`]. Sent only to a host whose `Reach` said `relays_for_others`.
    Wake {
        fingerprint: String,
    },
    /// Asks the host (a relay) to tell the registered host `to` (fingerprint, as in
    /// [`ClientMsg::RelayTo`]) to open a hole in its NAT toward `endpoint`: the sender's public
    /// `ip:port` as its NAT shows it. The relay passes it on as [`HostMsg::PunchRequest`].
    /// `nonce` is a random number the sender picks per attempt, to tell attempts apart. Sent
    /// only to a host whose `Reach` said `relays_for_others`.
    PunchRequest {
        to: String,
        endpoint: String,
        nonce: u64,
    },
    /// A message from a newer client that this version does not know; ignored.
    Unsupported {
        tag: u8,
    },
}

/// Messages sent by the host on the control stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostMsg {
    Welcome {
        version: u16,
        host_name: String,
        codec: Codec,
        width: u16,
        height: u16,
        /// `FEATURE_*` bits. Sent only in reply to a hello with [`HelloExt`]: clients that
        /// predate it reject trailing bytes.
        features: Option<u32>,
        /// `ip:port` addresses the host can also be reached at (its LAN address, and on a VPN
        /// mesh like Tailscale or Netbird, that one), for the client to try next time. Sent
        /// only to clients that ask ([`HelloExt::addresses`]), after `features`.
        addresses: Vec<String>,
    },
    /// Sent before `Welcome` when the client was just authorized through a pairing secret.
    Paired,
    Rejected {
        reason: String,
    },
    /// The host has an access password and the hello carried none (`wrong: false`) or a
    /// wrong one. The host closes the connection; the client asks the user and reconnects.
    PasswordRequired {
        wrong: bool,
    },
    /// The host's displays, after the welcome and whenever the streamed one changes. Sent only
    /// to clients that ask ([`HelloExt::displays`]) and only when there is a choice.
    Displays(DisplayList),
    /// How to reach the host from another network, once, after the welcome. Sent only to
    /// clients that ask ([`HelloExt::reach`]); the welcome's `addresses` stay as they were.
    Reach {
        /// Every address the host can be reached at, with its kind, most useful first; a
        /// superset of the welcome's. At most [`MAX_ADDRESSES`]; longer lists are cut.
        addresses: Vec<(AddressKind, String)>,
        /// The host's Ed25519 key: where it publishes its record in the DHT.
        key: [u8; REACH_KEY_LEN],
        /// The secret that opens that record for the device this message is sent to.
        secret: [u8; DEVICE_SECRET_LEN],
        /// The relays the host is registered with: each one's fingerprint (base64url, as
        /// `Fingerprint::to_base64`) and the addresses it answers at. At most [`MAX_RELAYS`],
        /// each with at most [`MAX_ADDRESSES`].
        relays: Vec<(String, Vec<String>)>,
        /// The MAC address of the host's network adapter, for Wake-on-LAN, when it knows one.
        mac: Option<[u8; 6]>,
        /// The host relays for its other paired devices: it accepts [`ClientMsg::RelayRegister`],
        /// [`ClientMsg::RelayTo`], [`ClientMsg::Wake`] and [`ClientMsg::PunchRequest`].
        relays_for_others: bool,
    },
    /// A relay's answer to [`ClientMsg::RelayRegister`], [`ClientMsg::RelayTo`] or
    /// [`ClientMsg::Wake`]: done (`ok`), or why not, in words for a log or a message to the user.
    RelayStatus {
        ok: bool,
        reason: String,
    },
    /// A relay passing on a client's [`ClientMsg::PunchRequest`] to the registered host it is
    /// for: the client `from` (its fingerprint, base64url) is at `endpoint`, with this `nonce`.
    PunchRequest {
        from: String,
        endpoint: String,
        nonce: u64,
    },
}

/// Unreliable absolute pointer update. `seq` lets the host drop reordered datagrams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MouseMove {
    pub seq: u32,
    pub x: u16,
    pub y: u16,
}

impl MouseMove {
    const TAG: u8 = 1;
    pub const LEN: usize = 9;

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut b = [0u8; Self::LEN];
        b[0] = Self::TAG;
        b[1..5].copy_from_slice(&self.seq.to_le_bytes());
        b[5..7].copy_from_slice(&self.x.to_le_bytes());
        b[7..9].copy_from_slice(&self.y.to_le_bytes());
        b
    }

    pub fn decode(b: &[u8]) -> Result<Self> {
        ensure!(b.len() == Self::LEN && b[0] == Self::TAG, "invalid mouse datagram");
        Ok(Self {
            seq: u32::from_le_bytes(b[1..5].try_into().unwrap()),
            x: u16::from_le_bytes(b[5..7].try_into().unwrap()),
            y: u16::from_le_bytes(b[7..9].try_into().unwrap()),
        })
    }

    /// Whether `self` is newer than `last`, tolerating sequence wrap-around.
    pub fn is_newer_than(&self, last: u32) -> bool {
        (self.seq.wrapping_sub(last) as i32) > 0
    }
}

/// Host -> client datagram: 20 ms of the host's sound in Opus (see `velora-audio`). Lost ones
/// are gaps, not retransmissions; `seq` lets the client drop reordered ones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioPacket {
    pub seq: u32,
    pub data: Vec<u8>,
}

impl AudioPacket {
    const TAG: u8 = 2;

    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(5 + self.data.len());
        b.push(Self::TAG);
        b.extend_from_slice(&self.seq.to_le_bytes());
        b.extend_from_slice(&self.data);
        b
    }

    pub fn decode(b: &[u8]) -> Result<Self> {
        ensure!(b.len() > 5 && b[0] == Self::TAG, "invalid audio datagram");
        Ok(Self { seq: u32::from_le_bytes(b[1..5].try_into().unwrap()), data: b[5..].to_vec() })
    }

    /// Whether `self` is newer than `last`, tolerating sequence wrap-around.
    pub fn is_newer_than(&self, last: u32) -> bool {
        (self.seq.wrapping_sub(last) as i32) > 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub frame_id: u32,
    pub keyframe: bool,
    pub width: u16,
    pub height: u16,
}

impl FrameHeader {
    pub const LEN: usize = 9;

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut b = [0u8; Self::LEN];
        b[0..4].copy_from_slice(&self.frame_id.to_le_bytes());
        b[4] = self.keyframe as u8;
        b[5..7].copy_from_slice(&self.width.to_le_bytes());
        b[7..9].copy_from_slice(&self.height.to_le_bytes());
        b
    }

    pub fn decode(b: &[u8; Self::LEN]) -> Self {
        Self {
            frame_id: u32::from_le_bytes(b[0..4].try_into().unwrap()),
            keyframe: b[4] & 1 != 0,
            width: u16::from_le_bytes(b[5..7].try_into().unwrap()),
            height: u16::from_le_bytes(b[7..9].try_into().unwrap()),
        }
    }
}

pub(crate) struct Writer(Vec<u8>);

impl Writer {
    pub(crate) fn new(tag: u8) -> Self {
        // Reserve the u32 length prefix, patched in `finish`.
        Self(vec![0, 0, 0, 0, tag])
    }
    pub(crate) fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn i16(&mut self, v: i16) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    pub(crate) fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn bytes(&mut self, v: &[u8]) {
        self.0.extend_from_slice(v);
    }
    fn str(&mut self, s: &str) {
        self.str_max(s, MAX_NAME_LEN);
    }
    pub(crate) fn str_max(&mut self, s: &str, max: usize) {
        let s = truncate_utf8(s, max);
        self.u16(s.len() as u16);
        self.bytes(s.as_bytes());
    }
    fn mac(&mut self, mac: &Option<[u8; 6]>) {
        match mac {
            Some(mac) => {
                self.u8(1);
                self.bytes(mac);
            }
            None => self.u8(0),
        }
    }
    fn kind(&mut self, kind: &AddressKind) {
        self.u8(kind.code());
        if let AddressKind::Relay(fingerprint) = kind {
            self.str(fingerprint);
        }
    }
    pub(crate) fn finish(mut self) -> Vec<u8> {
        let len = (self.0.len() - 4) as u32;
        self.0[0..4].copy_from_slice(&len.to_le_bytes());
        self.0
    }
}

/// Splits text into pieces that fit in one [`ClientMsg::Text`], on character boundaries.
pub fn split_text(mut text: &str) -> impl Iterator<Item = &str> {
    std::iter::from_fn(move || {
        if text.is_empty() {
            return None;
        }
        let head = truncate_utf8(text, MAX_TEXT_LEN);
        text = &text[head.len()..];
        Some(head)
    })
}

fn truncate_utf8(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

pub(crate) struct Reader<'a>(pub(crate) &'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        ensure!(self.0.len() >= n, "truncated message");
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }
    pub(crate) fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn bool(&mut self) -> Result<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            v => bail!("invalid bool {v}"),
        }
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn i16(&mut self) -> Result<i16> {
        Ok(i16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    pub(crate) fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    pub(crate) fn str(&mut self) -> Result<String> {
        let len = self.u16()? as usize;
        String::from_utf8(self.take(len)?.to_vec()).context("invalid utf-8")
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().unwrap())
    }
    fn mac(&mut self) -> Result<Option<[u8; 6]>> {
        if self.bool()? {
            Ok(Some(self.array()?))
        } else {
            Ok(None)
        }
    }
    fn kind(&mut self) -> Result<AddressKind> {
        Ok(match self.u8()? {
            0 => AddressKind::Lan,
            1 => AddressKind::Vpn,
            2 => AddressKind::Public,
            3 => AddressKind::V6,
            4 => AddressKind::Relay(self.str()?),
            code => AddressKind::Other(code),
        })
    }
    /// A list that starts with its length in one byte. Items past `max` are read and dropped:
    /// a longer list comes from a version that allows more, and the rest of the message is
    /// still good.
    fn list<T>(&mut self, max: usize, mut read: impl FnMut(&mut Self) -> Result<T>) -> Result<Vec<T>> {
        let n = self.u8()? as usize;
        let mut list = Vec::with_capacity(n.min(max));
        for _ in 0..n {
            let item = read(self)?;
            if list.len() < max {
                list.push(item);
            }
        }
        Ok(list)
    }
    pub(crate) fn end(&self) -> Result<()> {
        ensure!(self.0.is_empty(), "trailing bytes in message");
        Ok(())
    }
}

impl ClientMsg {
    /// Encodes the message including its u32 length prefix.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Hello { version, name, pairing_secret, password, ext } => {
                let mut w = Writer::new(1);
                w.u16(*version);
                w.str(name);
                match pairing_secret {
                    Some(s) => {
                        w.u8(1);
                        w.bytes(s);
                    }
                    None => w.u8(0),
                }
                match (password, ext) {
                    (Some(password), _) => {
                        w.u8(1);
                        w.str_max(password, MAX_PASSWORD_LEN);
                    }
                    (None, Some(_)) => w.u8(0),
                    (None, None) => {}
                }
                if let Some(ext) = ext {
                    // Never sets HELLO_MORE_FLAGS: this version has no second flags byte to send.
                    w.u8(ext.files_only as u8
                        | (ext.clipboard as u8) << 1
                        | (ext.addresses as u8) << 2
                        | (ext.displays as u8) << 3
                        | (ext.audio as u8) << 4
                        | (ext.reach as u8) << 5);
                }
                w.finish()
            }
            Self::Key { code, state } => {
                let mut w = Writer::new(2);
                w.u16(*code);
                w.u8(*state as u8);
                w.finish()
            }
            Self::MouseButton { button, down, x, y } => {
                let mut w = Writer::new(3);
                w.u8(*button as u8);
                w.u8(*down as u8);
                w.u16(*x);
                w.u16(*y);
                w.finish()
            }
            Self::Scroll { dx, dy } => {
                let mut w = Writer::new(4);
                w.i16(*dx);
                w.i16(*dy);
                w.finish()
            }
            Self::FrameAck { frame_id } => {
                let mut w = Writer::new(5);
                w.u32(*frame_id);
                w.finish()
            }
            Self::RequestKeyframe => Writer::new(6).finish(),
            Self::ReleaseAll => Writer::new(7).finish(),
            Self::Text { text } => {
                let mut w = Writer::new(8);
                w.str_max(text, MAX_TEXT_LEN);
                w.finish()
            }
            Self::OfferPairing { link } => {
                let mut w = Writer::new(9);
                w.str_max(link, MAX_LINK_LEN);
                w.finish()
            }
            Self::SelectDisplay { index } => {
                let mut w = Writer::new(10);
                w.u8(*index);
                w.finish()
            }
            Self::Reached { address } => {
                let mut w = Writer::new(11);
                w.str(address);
                w.finish()
            }
            Self::RelayRegister { mac } => {
                let mut w = Writer::new(12);
                w.mac(mac);
                w.finish()
            }
            Self::RelayTo { fingerprint } => {
                let mut w = Writer::new(13);
                w.str(fingerprint);
                w.finish()
            }
            Self::Wake { fingerprint } => {
                let mut w = Writer::new(14);
                w.str(fingerprint);
                w.finish()
            }
            Self::PunchRequest { to, endpoint, nonce } => {
                let mut w = Writer::new(15);
                w.str(to);
                w.str(endpoint);
                w.u64(*nonce);
                w.finish()
            }
            Self::Unsupported { tag } => Writer::new(*tag).finish(),
        }
    }

    /// Decodes a message body (without the length prefix).
    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut r = Reader(body);
        let msg = match r.u8()? {
            1 => {
                let version = r.u16()?;
                let name = r.str()?;
                let pairing_secret =
                    if r.bool()? { Some(r.take(PAIRING_SECRET_LEN)?.try_into().unwrap()) } else { None };
                // Absent in hellos without a password, and from clients that predate them.
                let password = if !r.0.is_empty() && r.bool()? { Some(r.str()?) } else { None };
                // Unknown flag bits come from newer clients and are ignored.
                let ext = if r.0.is_empty() {
                    None
                } else {
                    let flags = r.u8()?;
                    // Each flags byte with its top bit set is followed by another, in which this
                    // version knows no flag: skip them. A top bit with nothing after it is
                    // fine too, as it always was.
                    let mut more = flags & HELLO_MORE_FLAGS != 0;
                    while more && !r.0.is_empty() {
                        more = r.u8()? & HELLO_MORE_FLAGS != 0;
                    }
                    Some(HelloExt {
                        files_only: flags & 1 != 0,
                        clipboard: flags & 2 != 0,
                        addresses: flags & 4 != 0,
                        displays: flags & 8 != 0,
                        audio: flags & 16 != 0,
                        reach: flags & 32 != 0,
                    })
                };
                Self::Hello { version, name, pairing_secret, password, ext }
            }
            2 => Self::Key { code: r.u16()?, state: KeyState::from_u8(r.u8()?)? },
            3 => {
                Self::MouseButton { button: MouseButton::from_u8(r.u8()?)?, down: r.bool()?, x: r.u16()?, y: r.u16()? }
            }
            4 => Self::Scroll { dx: r.i16()?, dy: r.i16()? },
            5 => Self::FrameAck { frame_id: r.u32()? },
            6 => Self::RequestKeyframe,
            7 => Self::ReleaseAll,
            8 => Self::Text { text: r.str()? },
            9 => Self::OfferPairing { link: r.str()? },
            10 => Self::SelectDisplay { index: r.u8()? },
            11 => Self::Reached { address: r.str()? },
            12 => Self::RelayRegister { mac: r.mac()? },
            13 => Self::RelayTo { fingerprint: r.str()? },
            14 => Self::Wake { fingerprint: r.str()? },
            15 => Self::PunchRequest { to: r.str()?, endpoint: r.str()?, nonce: r.u64()? },
            // Forward compatibility: skip messages added by newer clients.
            tag => return Ok(Self::Unsupported { tag }),
        };
        r.end()?;
        Ok(msg)
    }
}

impl HostMsg {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Welcome { version, host_name, codec, width, height, features, addresses } => {
                let mut w = Writer::new(1);
                w.u16(*version);
                w.str(host_name);
                w.u8(*codec as u8);
                w.u16(*width);
                w.u16(*height);
                if let Some(features) = features {
                    w.u32(*features);
                    if !addresses.is_empty() {
                        let addresses: Vec<&String> = addresses.iter().take(MAX_WELCOME_ADDRESSES).collect();
                        w.u8(addresses.len() as u8);
                        for address in addresses {
                            w.str(address);
                        }
                    }
                }
                w.finish()
            }
            Self::Paired => Writer::new(2).finish(),
            Self::Rejected { reason } => {
                let mut w = Writer::new(3);
                w.str(reason);
                w.finish()
            }
            Self::PasswordRequired { wrong } => {
                let mut w = Writer::new(4);
                w.u8(*wrong as u8);
                w.finish()
            }
            Self::Displays(displays) => {
                let mut w = Writer::new(5);
                w.u8(displays.current);
                let list = &displays.list[..displays.list.len().min(MAX_DISPLAYS)];
                w.u8(list.len() as u8);
                for d in list {
                    w.str(&d.name);
                    w.u16(d.width);
                    w.u16(d.height);
                    w.u8(d.primary as u8);
                }
                w.finish()
            }
            Self::Reach { addresses, key, secret, relays, mac, relays_for_others } => {
                let mut w = Writer::new(6);
                let addresses = &addresses[..addresses.len().min(MAX_ADDRESSES)];
                w.u8(addresses.len() as u8);
                for (kind, address) in addresses {
                    w.kind(kind);
                    w.str(address);
                }
                w.bytes(key);
                w.bytes(secret);
                let relays = &relays[..relays.len().min(MAX_RELAYS)];
                w.u8(relays.len() as u8);
                for (fingerprint, addresses) in relays {
                    w.str(fingerprint);
                    let addresses = &addresses[..addresses.len().min(MAX_ADDRESSES)];
                    w.u8(addresses.len() as u8);
                    for address in addresses {
                        w.str(address);
                    }
                }
                w.mac(mac);
                w.u8(*relays_for_others as u8);
                w.finish()
            }
            Self::RelayStatus { ok, reason } => {
                let mut w = Writer::new(7);
                w.u8(*ok as u8);
                w.str(reason);
                w.finish()
            }
            Self::PunchRequest { from, endpoint, nonce } => {
                let mut w = Writer::new(8);
                w.str(from);
                w.str(endpoint);
                w.u64(*nonce);
                w.finish()
            }
        }
    }

    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut r = Reader(body);
        let msg = match r.u8()? {
            1 => Self::Welcome {
                version: r.u16()?,
                host_name: r.str()?,
                codec: Codec::from_u8(r.u8()?)?,
                width: r.u16()?,
                height: r.u16()?,
                features: if r.0.is_empty() { None } else { Some(r.u32()?) },
                addresses: if r.0.is_empty() { Vec::new() } else { r.list(MAX_WELCOME_ADDRESSES, Reader::str)? },
            },
            2 => Self::Paired,
            3 => Self::Rejected { reason: r.str()? },
            4 => Self::PasswordRequired { wrong: r.bool()? },
            5 => {
                let current = r.u8()?;
                let n = r.u8()? as usize;
                ensure!(n <= MAX_DISPLAYS, "too many displays");
                let list = (0..n)
                    .map(|_| Ok(DisplayInfo { name: r.str()?, width: r.u16()?, height: r.u16()?, primary: r.bool()? }))
                    .collect::<Result<_>>()?;
                Self::Displays(DisplayList { current, list })
            }
            6 => Self::Reach {
                addresses: r.list(MAX_ADDRESSES, |r| Ok((r.kind()?, r.str()?)))?,
                key: r.array()?,
                secret: r.array()?,
                relays: r.list(MAX_RELAYS, |r| Ok((r.str()?, r.list(MAX_ADDRESSES, Reader::str)?)))?,
                mac: r.mac()?,
                relays_for_others: r.bool()?,
            },
            7 => Self::RelayStatus { ok: r.bool()?, reason: r.str()? },
            8 => Self::PunchRequest { from: r.str()?, endpoint: r.str()?, nonce: r.u64()? },
            t => bail!("unknown host message tag {t}"),
        };
        r.end()?;
        Ok(msg)
    }
}

/// Reads one length-prefixed message body from a QUIC stream.
/// Returns `Ok(None)` on a clean end of stream.
pub async fn read_msg(recv: &mut quinn::RecvStream) -> Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match recv.read_exact(&mut len).await {
        Ok(()) => {}
        Err(quinn::ReadExactError::FinishedEarly(0)) => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_le_bytes(len) as usize;
    ensure!(len > 0 && len <= MAX_CONTROL_MSG, "invalid control message length {len}");
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body).await?;
    Ok(Some(body))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip_client(msg: ClientMsg) {
        let enc = msg.encode();
        let len = u32::from_le_bytes(enc[0..4].try_into().unwrap()) as usize;
        assert_eq!(len, enc.len() - 4);
        assert_eq!(ClientMsg::decode(&enc[4..]).unwrap(), msg);
    }

    fn roundtrip_host(msg: HostMsg) {
        let enc = msg.encode();
        assert_eq!(HostMsg::decode(&enc[4..]).unwrap(), msg);
    }

    #[test]
    fn client_messages_roundtrip() {
        roundtrip_client(ClientMsg::Hello {
            version: 1,
            name: "laptop".into(),
            pairing_secret: None,
            password: None,
            ext: None,
        });
        roundtrip_client(ClientMsg::Hello {
            version: 1,
            name: "telefone".into(),
            pairing_secret: Some([7; PAIRING_SECRET_LEN]),
            password: None,
            ext: None,
        });
        roundtrip_client(ClientMsg::Hello {
            version: 1,
            name: "telefone".into(),
            pairing_secret: None,
            password: Some("senha secreta".into()),
            ext: None,
        });
        for password in [None, Some("senha".to_string())] {
            roundtrip_client(ClientMsg::Hello {
                version: 1,
                name: "laptop".into(),
                pairing_secret: None,
                password,
                ext: Some(HelloExt { files_only: true, ..Default::default() }),
            });
            roundtrip_client(ClientMsg::Hello {
                version: 1,
                name: "a".into(),
                pairing_secret: None,
                password: None,
                ext: Some(HelloExt {
                    files_only: false,
                    clipboard: true,
                    addresses: true,
                    displays: true,
                    audio: true,
                    reach: true,
                }),
            });
        }
        roundtrip_client(ClientMsg::Key { code: 30, state: KeyState::Repeat });
        roundtrip_client(ClientMsg::MouseButton { button: MouseButton::Back, down: true, x: 65535, y: 0 });
        roundtrip_client(ClientMsg::Scroll { dx: -120, dy: 360 });
        roundtrip_client(ClientMsg::FrameAck { frame_id: u32::MAX });
        roundtrip_client(ClientMsg::RequestKeyframe);
        roundtrip_client(ClientMsg::ReleaseAll);
        roundtrip_client(ClientMsg::Text { text: "olá, ação ✓".into() });
        roundtrip_client(ClientMsg::OfferPairing { link: "velora://pair?address=10.0.0.2%3A7420&code=VL1-x".into() });
        roundtrip_client(ClientMsg::SelectDisplay { index: 2 });
    }

    #[test]
    fn hellos_without_extensions_are_unchanged() {
        // What hosts that predate extensions accept: nothing after the pairing secret flag.
        let plain = ClientMsg::Hello { version: 1, name: "a".into(), pairing_secret: None, password: None, ext: None };
        assert_eq!(plain.encode().len(), 4 + 1 + 2 + 2 + 1 + 1);
    }

    #[test]
    fn unknown_messages_are_skipped_not_fatal() {
        assert_eq!(ClientMsg::decode(&[200, 1, 2, 3]).unwrap(), ClientMsg::Unsupported { tag: 200 });
    }

    #[test]
    fn long_text_is_split_on_char_boundaries() {
        let text = "ç".repeat(MAX_TEXT_LEN); // 2 bytes each
        let parts: Vec<&str> = split_text(&text).collect();
        assert_eq!(parts.len(), 2);
        assert!(parts.iter().all(|p| p.len() <= MAX_TEXT_LEN));
        assert_eq!(parts.concat(), text);
    }

    #[test]
    fn host_messages_roundtrip() {
        roundtrip_host(HostMsg::Welcome {
            version: 1,
            host_name: "desktop".into(),
            codec: Codec::H264,
            width: 2560,
            height: 1440,
            features: None,
            addresses: Vec::new(),
        });
        roundtrip_host(HostMsg::Welcome {
            version: 1,
            host_name: "desktop".into(),
            codec: Codec::H264,
            width: 0,
            height: 0,
            features: Some(FEATURE_FILES),
            addresses: Vec::new(),
        });
        roundtrip_host(HostMsg::Welcome {
            version: 1,
            host_name: "desktop".into(),
            codec: Codec::H264,
            width: 1920,
            height: 1080,
            features: Some(FEATURE_FILES | FEATURE_CLIPBOARD),
            addresses: vec!["192.168.1.9:7420".into(), "100.64.1.2:7420".into()],
        });
        roundtrip_host(HostMsg::Paired);
        roundtrip_host(HostMsg::PasswordRequired { wrong: true });
        roundtrip_host(HostMsg::Rejected { reason: "not authorized".into() });
        roundtrip_host(HostMsg::Displays(DisplayList {
            current: 1,
            list: vec![
                DisplayInfo { name: "DISPLAY1".into(), width: 2560, height: 1440, primary: true },
                DisplayInfo { name: "DISPLAY2".into(), width: 1920, height: 1080, primary: false },
            ],
        }));
    }

    #[test]
    fn rejects_malformed_messages() {
        assert!(ClientMsg::decode(&[]).is_err());
        assert!(ClientMsg::decode(&[2, 30]).is_err()); // truncated
        assert!(ClientMsg::decode(&[7, 0]).is_err()); // trailing byte
        assert!(ClientMsg::decode(&[3, 9, 1, 0, 0, 0, 0]).is_err()); // bad button
        assert!(HostMsg::decode(&[1, 1, 0, 0, 0, 9, 0, 0, 0, 0]).is_err()); // bad codec
    }

    #[test]
    fn audio_packet_roundtrip_and_ordering() {
        let packet = AudioPacket { seq: 7, data: vec![1, 2, 3] };
        assert_eq!(AudioPacket::decode(&packet.encode()).unwrap(), packet);
        assert!(AudioPacket::decode(&MouseMove { seq: 1, x: 0, y: 0 }.encode()).is_err());
        assert!(packet.is_newer_than(6) && !packet.is_newer_than(7) && packet.is_newer_than(u32::MAX));
    }

    #[test]
    fn mouse_move_roundtrip_and_ordering() {
        let m = MouseMove { seq: 42, x: 100, y: 65535 };
        assert_eq!(MouseMove::decode(&m.encode()).unwrap(), m);
        assert!(m.is_newer_than(41));
        assert!(!m.is_newer_than(42));
        assert!(!m.is_newer_than(43));
        let wrapped = MouseMove { seq: 2, x: 0, y: 0 };
        assert!(wrapped.is_newer_than(u32::MAX - 1));
    }

    #[test]
    fn frame_header_roundtrip() {
        let h = FrameHeader { frame_id: 9, keyframe: true, width: 1920, height: 1080 };
        assert_eq!(FrameHeader::decode(&h.encode()), h);
    }

    #[test]
    fn long_names_are_truncated_on_char_boundary() {
        let name = "é".repeat(1000);
        let enc = ClientMsg::Hello { version: 1, name, pairing_secret: None, password: None, ext: None }.encode();
        let ClientMsg::Hello { name, .. } = ClientMsg::decode(&enc[4..]).unwrap() else { panic!() };
        assert_eq!(name.len(), MAX_NAME_LEN);
        assert!(name.chars().all(|c| c == 'é'));
    }

    // Standalone reach (docs/nat-traversal.md). The hex strings below are what versions before
    // it wrote, taken from their encoder; nothing here may ever change.

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
    }

    const HELLO_PLAIN: &str = "0c00000001010006006c6170746f7000";
    const HELLO_ALL_FIVE_FLAGS: &str = "0e00000001010006006c6170746f7000001f";
    const HELLO_FILES_PASSWORD: &str = "1d0000000101000100610107070707070707070707070707070707010200707701";
    const WELCOME_TWO_ADDRESSES: &str = concat!(
        "3900000001010007006465736b746f7001800738040300000002",
        "10003139322e3136382e312e393a37343230",
        "0f003130302e36342e312e323a37343230",
    );
    /// The welcome of a host with ten addresses: the old encoder cut it to eight.
    const WELCOME_TEN_ADDRESSES: &str = concat!(
        "8e00000001010007006465736b746f7001800738040700000008",
        "0d0031302e302e302e313a37343230",
        "0d0031302e302e302e323a37343230",
        "0d0031302e302e302e333a37343230",
        "0d0031302e302e302e343a37343230",
        "0d0031302e302e302e353a37343230",
        "0d0031302e302e302e363a37343230",
        "0d0031302e302e302e373a37343230",
        "0d0031302e302e302e383a37343230",
    );
    const DISPLAYS: &str = "120000000501010800444953504c415931000aa00501";

    fn old_hellos() -> [(&'static str, ClientMsg); 3] {
        let hello = |name: &str, pairing_secret, password: Option<&str>, ext| ClientMsg::Hello {
            version: 1,
            name: name.into(),
            pairing_secret,
            password: password.map(Into::into),
            ext,
        };
        let five =
            HelloExt { files_only: true, clipboard: true, addresses: true, displays: true, audio: true, reach: false };
        [
            (HELLO_PLAIN, hello("laptop", None, None, None)),
            (HELLO_ALL_FIVE_FLAGS, hello("laptop", None, None, Some(five))),
            (
                HELLO_FILES_PASSWORD,
                hello(
                    "a",
                    Some([7; PAIRING_SECRET_LEN]),
                    Some("pw"),
                    Some(HelloExt { files_only: true, ..Default::default() }),
                ),
            ),
        ]
    }

    fn old_welcomes() -> [(&'static str, HostMsg); 3] {
        let welcome = |features, addresses: Vec<String>| HostMsg::Welcome {
            version: 1,
            host_name: "desktop".into(),
            codec: Codec::H264,
            width: 1920,
            height: 1080,
            features: Some(features),
            addresses,
        };
        let ten: Vec<String> = (1..=10).map(|i| format!("10.0.0.{i}:7420")).collect();
        [
            (
                WELCOME_TWO_ADDRESSES,
                welcome(FEATURE_FILES | FEATURE_CLIPBOARD, vec!["192.168.1.9:7420".into(), "100.64.1.2:7420".into()]),
            ),
            // The ten go in; eight come out, as for the clients that cannot read more.
            (WELCOME_TEN_ADDRESSES, welcome(FEATURE_FILES | FEATURE_CLIPBOARD | FEATURE_AUDIO, ten)),
            (
                DISPLAYS,
                HostMsg::Displays(DisplayList {
                    current: 1,
                    list: vec![DisplayInfo { name: "DISPLAY1".into(), width: 2560, height: 1440, primary: true }],
                }),
            ),
        ]
    }

    #[test]
    fn what_older_versions_wrote_is_still_written_and_read() {
        for (old, msg) in old_hellos() {
            assert_eq!(hex(&msg.encode()), old);
            assert_eq!(ClientMsg::decode(&unhex(old)[4..]).unwrap(), msg);
        }
        for (old, msg) in old_welcomes() {
            assert_eq!(hex(&msg.encode()), old);
        }
        // Reading back what they wrote: the welcome with ten addresses holds the first eight.
        let HostMsg::Welcome { addresses, .. } = HostMsg::decode(&unhex(WELCOME_TEN_ADDRESSES)[4..]).unwrap() else {
            panic!()
        };
        assert_eq!(addresses, (1..=8).map(|i| format!("10.0.0.{i}:7420")).collect::<Vec<_>>());
        assert_eq!(HostMsg::decode(&unhex(DISPLAYS)[4..]).unwrap(), old_welcomes()[2].1);
    }

    /// The flags byte of a hello ends the message, so it is the last byte of the encoding.
    fn flags_of(ext: HelloExt) -> u8 {
        let hello =
            ClientMsg::Hello { version: 1, name: "a".into(), pairing_secret: None, password: None, ext: Some(ext) };
        *hello.encode().last().unwrap()
    }

    #[test]
    fn the_reach_bit_is_bit_5_and_older_bits_stay_where_they_were() {
        assert_eq!(flags_of(HelloExt { files_only: true, ..Default::default() }), 1);
        assert_eq!(flags_of(HelloExt { clipboard: true, ..Default::default() }), 2);
        assert_eq!(flags_of(HelloExt { addresses: true, ..Default::default() }), 4);
        assert_eq!(flags_of(HelloExt { displays: true, ..Default::default() }), 8);
        assert_eq!(flags_of(HelloExt { audio: true, ..Default::default() }), 16);
        assert_eq!(flags_of(HelloExt { reach: true, ..Default::default() }), 32);
        // Hellos from clients without the bit read with it off, whatever else they set.
        for flags in 0..32u8 {
            let body = hello_with_flags(&[flags]);
            let ClientMsg::Hello { ext: Some(ext), .. } = ClientMsg::decode(&body).unwrap() else { panic!() };
            assert!(!ext.reach, "flags {flags:#x}");
            assert_eq!(flags_of(ext), flags);
        }
    }

    #[test]
    fn hello_flags_roundtrip_and_never_set_the_reserved_bits() {
        for bits in 0..64u8 {
            let ext = HelloExt {
                files_only: bits & 1 != 0,
                clipboard: bits & 2 != 0,
                addresses: bits & 4 != 0,
                displays: bits & 8 != 0,
                audio: bits & 16 != 0,
                reach: bits & 32 != 0,
            };
            assert_eq!(flags_of(ext), bits);
            roundtrip_client(ClientMsg::Hello {
                version: 1,
                name: "a".into(),
                pairing_secret: None,
                password: None,
                ext: Some(ext),
            });
        }
    }

    /// A hello for a client "a" with no pairing secret and no password, then `flags`.
    fn hello_with_flags(flags: &[u8]) -> Vec<u8> {
        let mut body = vec![1, 1, 0, 1, 0, b'a', 0, 0];
        body.extend_from_slice(flags);
        body
    }

    #[test]
    fn a_hello_with_bit_7_is_still_decoded() {
        let reach_and_files = HelloExt { files_only: true, reach: true, ..Default::default() };
        let more = HELLO_MORE_FLAGS;
        for flags in [
            // The bit alone, as this version has always read it.
            &[more | 0x21][..],
            // Another flags byte follows, and it ends the chain; or it goes on.
            &[more | 0x21, 0x00],
            &[more | 0x21, 0x7f],
            &[more | 0x21, more | 0x01, 0x00],
            &[more | 0x21, 0xff, 0xff, 0x01],
        ] {
            let decoded = ClientMsg::decode(&hello_with_flags(flags)).unwrap();
            let ClientMsg::Hello { name, ext, .. } = decoded else { panic!() };
            assert_eq!((name.as_str(), ext), ("a", Some(reach_and_files)), "{flags:x?}");
        }
        // The flags bytes are part of the hello: one more byte after the chain ends is not.
        assert!(ClientMsg::decode(&hello_with_flags(&[more | 0x21, 0x00, 0x00])).is_err());
    }

    #[test]
    fn tags_are_the_next_free_numbers() {
        let tag = |encoded: Vec<u8>| encoded[4];
        let client = [
            (ClientMsg::Reached { address: "a".into() }, 11),
            (ClientMsg::RelayRegister { mac: None }, 12),
            (ClientMsg::RelayTo { fingerprint: "f".into() }, 13),
            (ClientMsg::Wake { fingerprint: "f".into() }, 14),
            (ClientMsg::PunchRequest { to: "f".into(), endpoint: "e".into(), nonce: 1 }, 15),
        ];
        for (msg, expected) in client {
            assert_eq!(tag(msg.encode()), expected);
        }
        let host = [
            (
                HostMsg::Reach {
                    addresses: Vec::new(),
                    key: [0; REACH_KEY_LEN],
                    secret: [0; DEVICE_SECRET_LEN],
                    relays: Vec::new(),
                    mac: None,
                    relays_for_others: false,
                },
                6,
            ),
            (HostMsg::RelayStatus { ok: true, reason: String::new() }, 7),
            (HostMsg::PunchRequest { from: "f".into(), endpoint: "e".into(), nonce: 1 }, 8),
        ];
        for (msg, expected) in host {
            assert_eq!(tag(msg.encode()), expected);
        }
        // The ones before them did not move.
        assert_eq!(tag(ClientMsg::SelectDisplay { index: 0 }.encode()), 10);
        assert_eq!(tag(HostMsg::Displays(DisplayList::default()).encode()), 5);
    }

    fn mac() -> Option<[u8; 6]> {
        Some([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e])
    }

    fn reach(addresses: Vec<(AddressKind, String)>, relays: Vec<(String, Vec<String>)>) -> HostMsg {
        HostMsg::Reach {
            addresses,
            key: [0xA5; REACH_KEY_LEN],
            secret: [0x5A; DEVICE_SECRET_LEN],
            relays,
            mac: mac(),
            relays_for_others: true,
        }
    }

    #[test]
    fn reach_messages_roundtrip() {
        let relay = "BnsLmYQrD2vHZkJ5Bn8o0Hz4w8mYH7qN3m1kTn0yqlE".to_string();
        roundtrip_host(reach(
            vec![
                (AddressKind::Lan, "192.168.1.9:7420".into()),
                (AddressKind::Vpn, "100.101.102.103:7420".into()),
                (AddressKind::Public, "203.0.113.7:51820".into()),
                (AddressKind::V6, "[2804:14c:5b82:1234:abcd:ef01:2345:6789]:7420".into()),
                (AddressKind::Relay(relay.clone()), "198.51.100.2:7420".into()),
                (AddressKind::Other(200), "kind:from-the-future".into()),
            ],
            vec![(relay, vec!["198.51.100.2:7420".into(), "[2001:db8::2]:7420".into()]), ("other".into(), Vec::new())],
        ));
        roundtrip_host(HostMsg::Reach {
            addresses: Vec::new(),
            key: [0; REACH_KEY_LEN],
            secret: [0xFF; DEVICE_SECRET_LEN],
            relays: Vec::new(),
            mac: None,
            relays_for_others: false,
        });
        roundtrip_host(HostMsg::RelayStatus { ok: true, reason: String::new() });
        roundtrip_host(HostMsg::RelayStatus { ok: false, reason: "that host is not registered here".into() });
        roundtrip_host(HostMsg::PunchRequest {
            from: "fingerprint".into(),
            endpoint: "203.0.113.7:51820".into(),
            nonce: u64::MAX,
        });

        roundtrip_client(ClientMsg::Reached { address: "203.0.113.7:51820".into() });
        roundtrip_client(ClientMsg::RelayRegister { mac: mac() });
        roundtrip_client(ClientMsg::RelayRegister { mac: None });
        roundtrip_client(ClientMsg::RelayTo { fingerprint: "fingerprint".into() });
        roundtrip_client(ClientMsg::Wake { fingerprint: "fingerprint".into() });
        roundtrip_client(ClientMsg::PunchRequest {
            to: "fingerprint".into(),
            endpoint: "[2001:db8::7]:51820".into(),
            nonce: 0x0123_4567_89ab_cdef,
        });
    }

    #[test]
    fn address_kind_codes_are_fixed() {
        let kinds = [
            (AddressKind::Lan, 0),
            (AddressKind::Vpn, 1),
            (AddressKind::Public, 2),
            (AddressKind::V6, 3),
            (AddressKind::Relay("fp".into()), 4),
            (AddressKind::Other(5), 5),
            (AddressKind::Other(255), 255),
        ];
        for (kind, code) in kinds {
            assert_eq!(kind.code(), code);
            // The code is the byte after the message's tag and the number of addresses.
            let msg = reach(vec![(kind.clone(), "a".into())], Vec::new());
            let encoded = msg.encode();
            assert_eq!(encoded[6], code);
            // Only a relay's code is followed by anything but the address.
            assert_eq!(encoded[7..9], if code == 4 { [2, 0] } else { [1, 0] });
            assert_eq!(HostMsg::decode(&encoded[4..]).unwrap(), msg);
        }
    }

    #[test]
    fn address_kinds_read_from_json_and_write_back() {
        for (kind, json) in [
            (AddressKind::Lan, r#""lan""#),
            (AddressKind::Vpn, r#""vpn""#),
            (AddressKind::Public, r#""public""#),
            (AddressKind::V6, r#""v6""#),
            (AddressKind::Relay("fp".into()), r#"{"relay":"fp"}"#),
            (AddressKind::Other(9), r#"{"other":9}"#),
        ] {
            assert_eq!(serde_json::to_string(&kind).unwrap(), json);
            assert_eq!(serde_json::from_str::<AddressKind>(json).unwrap(), kind);
        }
    }

    #[test]
    fn reach_lists_are_cut_to_their_limits() {
        let many = |n: usize| (0..n).map(|i| format!("10.0.0.{i}:7420")).collect::<Vec<_>>();
        let msg = reach(
            many(MAX_ADDRESSES + 4).into_iter().map(|a| (AddressKind::Lan, a)).collect(),
            (0..MAX_RELAYS + 4).map(|i| (format!("relay{i}"), many(MAX_ADDRESSES + 4))).collect(),
        );
        let HostMsg::Reach { addresses, relays, .. } = HostMsg::decode(&msg.encode()[4..]).unwrap() else { panic!() };
        assert_eq!(addresses.len(), MAX_ADDRESSES);
        assert_eq!(relays.len(), MAX_RELAYS);
        assert!(relays.iter().all(|(_, addresses)| addresses.len() == MAX_ADDRESSES));
        assert_eq!(relays[3].0, "relay3");
    }

    /// A list that a newer version allows to be longer is read and cut, not refused: the rest of
    /// the message is still good.
    #[test]
    fn longer_lists_from_newer_versions_are_cut_not_refused() {
        let mut w = Writer::new(6);
        w.u8(MAX_ADDRESSES as u8 + 4);
        for i in 0..MAX_ADDRESSES + 4 {
            w.u8(0);
            w.str(&format!("10.0.0.{i}:7420"));
        }
        w.bytes(&[1; REACH_KEY_LEN]);
        w.bytes(&[2; DEVICE_SECRET_LEN]);
        w.u8(0);
        w.mac(&mac());
        w.u8(1);
        let HostMsg::Reach { addresses, key, secret, mac: m, relays_for_others, .. } =
            HostMsg::decode(&w.finish()[4..]).unwrap()
        else {
            panic!()
        };
        assert_eq!(addresses.len(), MAX_ADDRESSES);
        assert_eq!((key, secret, m, relays_for_others), ([1; REACH_KEY_LEN], [2; DEVICE_SECRET_LEN], mac(), true));
    }

    #[test]
    fn welcomes_keep_to_what_older_clients_read() {
        // They read 8 addresses and refuse a welcome that goes on after them, so a host with more
        // sends the rest in `Reach`: the welcome is cut at MAX_WELCOME_ADDRESSES, not MAX_ADDRESSES.
        assert_eq!(MAX_WELCOME_ADDRESSES, 8);
        // A welcome from a version that allowed more is read and cut.
        let mut w = Writer::new(1);
        w.u16(1);
        w.str("desktop");
        w.u8(Codec::H264 as u8);
        w.u16(1920);
        w.u16(1080);
        w.u32(FEATURE_FILES);
        w.u8(12);
        for i in 0..12 {
            w.str(&format!("10.0.0.{i}:7420"));
        }
        let HostMsg::Welcome { addresses, .. } = HostMsg::decode(&w.finish()[4..]).unwrap() else { panic!() };
        assert_eq!(addresses.len(), MAX_WELCOME_ADDRESSES);
    }

    #[test]
    fn new_messages_refuse_what_is_cut_short_or_garbled() {
        let relay = ("relay".to_string(), vec!["198.51.100.2:7420".to_string()]);
        let hosts = [
            reach(vec![(AddressKind::Relay("r".into()), "a".into()), (AddressKind::Lan, "b".into())], vec![relay]),
            HostMsg::RelayStatus { ok: false, reason: "no".into() },
            HostMsg::PunchRequest { from: "f".into(), endpoint: "e".into(), nonce: 7 },
        ];
        for msg in hosts {
            let body = &msg.encode()[4..];
            for cut in 0..body.len() {
                assert!(HostMsg::decode(&body[..cut]).is_err(), "{msg:?} cut at {cut}");
            }
        }
        let clients = [
            ClientMsg::Reached { address: "a".into() },
            ClientMsg::RelayRegister { mac: mac() },
            ClientMsg::RelayTo { fingerprint: "f".into() },
            ClientMsg::Wake { fingerprint: "f".into() },
            ClientMsg::PunchRequest { to: "f".into(), endpoint: "e".into(), nonce: 7 },
        ];
        for msg in clients {
            let body = &msg.encode()[4..];
            for cut in 1..body.len() {
                assert!(ClientMsg::decode(&body[..cut]).is_err(), "{msg:?} cut at {cut}");
            }
            // Nothing may follow the end.
            assert!(ClientMsg::decode(&[body, &[0]].concat()).is_err(), "{msg:?} with a trailing byte");
        }
        // Not a flag, not UTF-8, not a count the message can back up: errors, never a panic.
        assert!(HostMsg::decode(&[7, 2, 0, 0]).is_err());
        assert!(HostMsg::decode(&[7, 1, 1, 0, 0xff]).is_err());
        assert!(HostMsg::decode(&[6, 255]).is_err());
        assert!(ClientMsg::decode(&[12, 2]).is_err());
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        for tag in (11..=15).chain(6..=8) {
            for _ in 0..500 {
                let len = {
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    (seed % 80) as usize
                };
                let body: Vec<u8> = std::iter::once(tag)
                    .chain((0..len).map(|_| {
                        seed ^= seed << 13;
                        seed ^= seed >> 7;
                        seed ^= seed << 17;
                        seed as u8
                    }))
                    .collect();
                let _ = ClientMsg::decode(&body);
                let _ = HostMsg::decode(&body);
            }
        }
    }
}
