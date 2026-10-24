//! What a host publishes: its fingerprint, addresses, NAT type, relays and MAC.
//!
//! The wire form is a version byte followed by the postcard encoding of [`Record`]; `seal` encrypts it before it
//! reaches the DHT. It is a format between versions of Velora, so changing a field means a new [`VERSION`]: a
//! client that does not know the version gets [`RecordError::Version`] and keeps the addresses it already has.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Salt of the host's record in the DHT; the record lives at the host's key and this salt.
pub const SALT: &[u8] = b"velora/1";

/// First byte of an encoded record.
pub const VERSION: u8 = 1;

/// What an address is. The codes are the ones the address kinds carry on the wire in `HostMsg::Reach`, so a code
/// means the same in a welcome and in a record. A code this version does not know is kept as `Other`, so a
/// record from a newer host still opens (`Other(c)` with `c` below 5 encodes as the kind that owns the code).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "u8", into = "u8")]
pub enum Kind {
    Lan,
    Vpn,
    Public,
    V6,
    /// The string is whatever the host's `Reach` message carries for a relay address.
    Relay,
    Other(u8),
}

impl From<u8> for Kind {
    fn from(code: u8) -> Self {
        match code {
            0 => Self::Lan,
            1 => Self::Vpn,
            2 => Self::Public,
            3 => Self::V6,
            4 => Self::Relay,
            other => Self::Other(other),
        }
    }
}

impl From<Kind> for u8 {
    fn from(kind: Kind) -> Self {
        match kind {
            Kind::Lan => 0,
            Kind::Vpn => 1,
            Kind::Public => 2,
            Kind::V6 => 3,
            Kind::Relay => 4,
            Kind::Other(code) => code,
        }
    }
}

/// What the router in front of the host does to its packets, as `velora-nat` classified it. It tells a client
/// whether hole punching has a chance. Unknown codes are kept, like `Kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "u8", into = "u8")]
pub enum Nat {
    /// Not classified yet.
    Unknown,
    /// Reachable without any translation, or through a mapping the router was asked for.
    Open,
    /// The same outside endpoint for every destination (endpoint-independent mapping).
    Cone,
    /// A different outside endpoint per destination.
    Symmetric,
    Other(u8),
}

impl From<u8> for Nat {
    fn from(code: u8) -> Self {
        match code {
            0 => Self::Unknown,
            1 => Self::Open,
            2 => Self::Cone,
            3 => Self::Symmetric,
            other => Self::Other(other),
        }
    }
}

impl From<Nat> for u8 {
    fn from(nat: Nat) -> Self {
        match nat {
            Nat::Unknown => 0,
            Nat::Open => 1,
            Nat::Cone => 2,
            Nat::Symmetric => 3,
            Nat::Other(code) => code,
        }
    }
}

/// A relay the host is registered with: a paired PC the client dials, asking it for the host by fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Relay {
    pub fingerprint: [u8; 32],
    pub addresses: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// SHA-256 of the host's TLS certificate: what the client pins, raw so it takes 32 bytes and not 64.
    pub fingerprint: [u8; 32],
    /// `host:port` strings, most useful first.
    pub addresses: Vec<(Kind, String)>,
    pub nat: Nat,
    pub relays: Vec<Relay>,
    /// For Wake-on-LAN through a relay on the host's LAN.
    pub mac: Option<[u8; 6]>,
    /// Unix seconds when the host built the record.
    pub ts: u64,
}

#[derive(Debug, Error)]
pub enum RecordError {
    #[error("record version {0} is not supported (this build reads version {current})", current = VERSION)]
    Version(u8),
    #[error("record is empty")]
    Empty,
    #[error("malformed record: {0}")]
    Malformed(postcard::Error),
    #[error("{0} bytes follow the end of the record")]
    Trailing(usize),
    #[error("encoding the record failed: {0}")]
    Encode(postcard::Error),
}

impl Record {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        postcard::to_extend(self, vec![VERSION]).map_err(RecordError::Encode)
    }

    /// Strict: the version must be ours and nothing may follow the record. Whatever the bytes are, this returns an
    /// error and never panics.
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        let (&version, body) = bytes.split_first().ok_or(RecordError::Empty)?;
        if version != VERSION {
            return Err(RecordError::Version(version));
        }
        let (record, rest) = postcard::take_from_bytes(body).map_err(RecordError::Malformed)?;
        if rest.is_empty() {
            Ok(record)
        } else {
            Err(RecordError::Trailing(rest.len()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Record {
        Record {
            fingerprint: [0xAB; 32],
            addresses: vec![
                (Kind::Lan, "192.168.1.20:7420".into()),
                (Kind::Vpn, "100.101.102.103:7420".into()),
                (Kind::Public, "203.0.113.45:7421".into()),
                (Kind::V6, "[2804:14d:8084:1234:5678:9abc:def0:1234]:7420".into()),
                (Kind::Relay, "relay.example.net:7420".into()),
                (Kind::Other(200), "from.the.future:7420".into()),
            ],
            nat: Nat::Cone,
            relays: vec![Relay { fingerprint: [0xCD; 32], addresses: vec!["198.51.100.7:7420".into()] }],
            mac: Some([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]),
            ts: 1_760_000_000,
        }
    }

    #[test]
    fn round_trips() {
        let record = sample();
        assert_eq!(Record::decode(&record.encode().unwrap()).unwrap(), record);
    }

    #[test]
    fn an_empty_record_round_trips_too() {
        let record =
            Record { fingerprint: [0; 32], addresses: vec![], nat: Nat::Unknown, relays: vec![], mac: None, ts: 0 };
        let bytes = record.encode().unwrap();
        assert_eq!(bytes.len(), 1 + 32 + 1 + 1 + 1 + 1 + 1);
        assert_eq!(Record::decode(&bytes).unwrap(), record);
    }

    /// The bytes of a small record, written out: the format is a contract between versions, so a change here is a
    /// change of `VERSION`.
    #[test]
    fn the_wire_format_is_pinned() {
        let record = Record {
            fingerprint: [0xAB; 32],
            addresses: vec![(Kind::Lan, "10.0.0.2:7420".into())],
            nat: Nat::Cone,
            relays: vec![],
            mac: Some([1, 2, 3, 4, 5, 6]),
            ts: 300,
        };
        let mut expected = vec![VERSION];
        expected.extend([0xAB; 32]); // fingerprint, raw
        expected.extend([1, 0, 13]); // one address: kind 0, 13 bytes of text
        expected.extend(b"10.0.0.2:7420");
        expected.push(2); // nat: cone
        expected.push(0); // no relays
        expected.extend([1, 1, 2, 3, 4, 5, 6]); // mac: Some, six bytes
        expected.extend([0xAC, 0x02]); // ts 300 as a varint
        assert_eq!(record.encode().unwrap(), expected);
    }

    #[test]
    fn kind_codes_are_the_wire_codes() {
        for (kind, code) in
            [(Kind::Lan, 0u8), (Kind::Vpn, 1), (Kind::Public, 2), (Kind::V6, 3), (Kind::Relay, 4), (Kind::Other(9), 9)]
        {
            assert_eq!(u8::from(kind), code);
            assert_eq!(Kind::from(code), kind);
        }
        assert_eq!(Kind::from(255), Kind::Other(255));
    }

    #[test]
    fn nat_codes_are_stable() {
        for (nat, code) in
            [(Nat::Unknown, 0u8), (Nat::Open, 1), (Nat::Cone, 2), (Nat::Symmetric, 3), (Nat::Other(40), 40)]
        {
            assert_eq!(u8::from(nat), code);
            assert_eq!(Nat::from(code), nat);
        }
    }

    #[test]
    fn unknown_codes_survive_a_round_trip() {
        let mut record = sample();
        record.nat = Nat::Other(77);
        let back = Record::decode(&record.encode().unwrap()).unwrap();
        assert_eq!(back.nat, Nat::Other(77));
        assert_eq!(back.addresses.last().unwrap().0, Kind::Other(200));
    }

    #[test]
    fn another_version_is_refused() {
        let mut bytes = sample().encode().unwrap();
        for version in [0, VERSION + 1, 255] {
            bytes[0] = version;
            assert!(matches!(Record::decode(&bytes), Err(RecordError::Version(v)) if v == version));
        }
    }

    #[test]
    fn nothing_may_follow_the_record() {
        let mut bytes = sample().encode().unwrap();
        bytes.extend([0, 0, 0]);
        assert!(matches!(Record::decode(&bytes), Err(RecordError::Trailing(3))));
    }

    #[test]
    fn truncated_input_is_an_error_at_every_length() {
        let bytes = sample().encode().unwrap();
        assert!(matches!(Record::decode(&[]), Err(RecordError::Empty)));
        for len in 1..bytes.len() {
            assert!(Record::decode(&bytes[..len]).is_err(), "decoded {len} of {} bytes", bytes.len());
        }
    }

    #[test]
    fn hostile_lengths_do_not_panic_or_allocate_wildly() {
        // A version byte, then lengths that promise gigabytes the input does not have.
        let mut huge = vec![VERSION];
        huge.extend([0u8; 32]);
        huge.extend([0xFF, 0xFF, 0xFF, 0xFF, 0x0F]); // 4 GiB addresses
        assert!(Record::decode(&huge).is_err());

        let mut long_text = vec![VERSION];
        long_text.extend([0u8; 32]);
        long_text.extend([1, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F]); // one address whose text claims 4 GiB
        assert!(Record::decode(&long_text).is_err());

        for fill in [0x00u8, 0x7F, 0x80, 0xFF] {
            let mut garbage = vec![VERSION];
            garbage.extend([fill; 300]);
            let _ = Record::decode(&garbage);
        }
    }
}
