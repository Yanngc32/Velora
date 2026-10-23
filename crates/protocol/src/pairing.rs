//! Pairing codes.
//!
//! The host displays a code containing its certificate fingerprint and a one-time random
//! secret. The client uses the fingerprint to authenticate the host (no MITM possible on first
//! contact) and sends the secret over the encrypted channel to prove it was given the code; the
//! host then stores the client's fingerprint. 128 random bits make guessing infeasible.

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};

use crate::{
    tls::Fingerprint,
    wire::{DEVICE_SECRET_LEN, PAIRING_SECRET_LEN, REACH_KEY_LEN},
};

const PREFIX: &str = "VL1-";
/// Scheme of the pairing link shown as a QR code; apps register it to fill in address and code.
pub const URI_PREFIX: &str = "velora://pair?";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingCode {
    pub host: Fingerprint,
    pub secret: [u8; PAIRING_SECRET_LEN],
}

impl PairingCode {
    pub fn generate(host: Fingerprint) -> Result<Self> {
        use ring::rand::SecureRandom;
        let mut secret = [0u8; PAIRING_SECRET_LEN];
        ring::rand::SystemRandom::new().fill(&mut secret).map_err(|_| anyhow::anyhow!("system RNG failure"))?;
        Ok(Self { host, secret })
    }

    pub fn encode(&self) -> String {
        let mut raw = Vec::with_capacity(32 + PAIRING_SECRET_LEN);
        raw.extend_from_slice(&self.host.0);
        raw.extend_from_slice(&self.secret);
        format!("{PREFIX}{}", B64.encode(raw))
    }

    pub fn parse(code: &str) -> Result<Self> {
        let body = code.trim().strip_prefix(PREFIX).context("pairing code must start with VL1-")?;
        let raw = B64.decode(body).context("malformed pairing code")?;
        if raw.len() != 32 + PAIRING_SECRET_LEN {
            bail!("pairing code has the wrong length");
        }
        Ok(Self { host: Fingerprint(raw[..32].try_into().unwrap()), secret: raw[32..].try_into().unwrap() })
    }

    /// Constant-time comparison of the secret.
    pub fn secret_matches(&self, candidate: &[u8; PAIRING_SECRET_LEN]) -> bool {
        self.secret.iter().zip(candidate).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
    }
}

/// What a pairing link carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingLink {
    pub address: String,
    /// Other addresses of the host (on a VPN mesh), tried along with `address`.
    pub also: Vec<String>,
    pub code: PairingCode,
    /// The host's Ed25519 key, where it publishes its record in the DHT (`key=`). Only links
    /// from hosts with standalone reach have it.
    pub key: Option<[u8; REACH_KEY_LEN]>,
    /// The secret that opens that record for the device pairing with this link (`secret=`).
    pub secret: Option<[u8; DEVICE_SECRET_LEN]>,
}

/// Link carrying everything a device needs to pair: `velora://pair?address=..&code=..`, plus
/// an `also=..` for each other address, and the `key=..` and `secret=..` of a host with
/// standalone reach (see [`PairingLink`]), which clients that predate them skip. Without
/// `key` and `secret` the link is the one earlier versions wrote.
///
/// `key` and `secret` are base64url without padding, like the code: 43 and 22 characters, 78
/// with their names. A link with one IPv4 address is 114 characters long and each further
/// address adds about 25 (an IPv6 one about 72). With key and secret, the three addresses the
/// first connection needs (LAN, VPN mesh, public) come to about 250 characters, but eight no
/// longer fit in 300: list only the former and leave the rest to
/// [`HostMsg::Reach`](crate::wire::HostMsg::Reach), which the device gets once connected.
pub fn pairing_uri_with(
    address: &str,
    also: &[String],
    code: &PairingCode,
    key: Option<&[u8; REACH_KEY_LEN]>,
    secret: Option<&[u8; DEVICE_SECRET_LEN]>,
) -> String {
    let mut uri = pairing_uri(address, code);
    for other in also {
        uri.push_str("&also=");
        uri.push_str(&encode_component(other));
    }
    if let Some(key) = key {
        uri.push_str("&key=");
        uri.push_str(&B64.encode(key));
    }
    if let Some(secret) = secret {
        uri.push_str("&secret=");
        uri.push_str(&B64.encode(secret));
    }
    uri
}

fn encode_component(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Link carrying everything a device needs to pair: `velora://pair?address=..&code=..`.
pub fn pairing_uri(address: &str, code: &PairingCode) -> String {
    fn encode(s: &str) -> String {
        s.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => (b as char).to_string(),
                _ => format!("%{b:02X}"),
            })
            .collect()
    }
    format!("{URI_PREFIX}address={}&code={}", encode(address), encode(&code.encode()))
}

/// Inverse of [`pairing_uri`]: the address and code carried by a pairing link.
pub fn parse_pairing_uri(link: &str) -> Option<(String, PairingCode)> {
    parse_pairing_link(link).map(|l| (l.address, l.code))
}

/// Inverse of [`pairing_uri_with`].
pub fn parse_pairing_link(link: &str) -> Option<PairingLink> {
    fn decode(s: &str) -> Option<String> {
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' {
                out.push(u8::from_str_radix(s.get(i + 1..i + 3)?, 16).ok()?);
                i += 3;
            } else {
                out.push(bytes[i]);
                i += 1;
            }
        }
        String::from_utf8(out).ok()
    }
    // A key or secret that is damaged or of another size is left out rather than failing the
    // link: pairing works with the addresses alone, and the host sends both again once connected.
    fn reach_bytes<const N: usize>(value: &str) -> Option<[u8; N]> {
        B64.decode(decode(value)?).ok()?.try_into().ok()
    }
    let query = link.trim().strip_prefix(URI_PREFIX)?;
    let (mut address, mut code, mut also, mut key, mut secret) = (None, None, Vec::new(), None, None);
    for pair in query.split('&') {
        match pair.split_once('=')? {
            ("address", v) => address = Some(decode(v)?),
            ("code", v) => code = Some(PairingCode::parse(&decode(v)?).ok()?),
            ("also", v) => also.push(decode(v)?),
            ("key", v) => key = reach_bytes(v),
            ("secret", v) => secret = reach_bytes(v),
            _ => {}
        }
    }
    Some(PairingLink { address: address.filter(|a| !a.is_empty())?, also, code: code?, key, secret })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let code = PairingCode::generate(Fingerprint([3; 32])).unwrap();
        let text = code.encode();
        assert!(text.starts_with(PREFIX));
        assert_eq!(PairingCode::parse(&format!("  {text}\n")).unwrap(), code);
    }

    #[test]
    fn pairing_link() {
        let code = PairingCode { host: Fingerprint([0; 32]), secret: [0; PAIRING_SECRET_LEN] };
        let uri = pairing_uri("[fe80::1]:7420", &code);
        assert!(uri.starts_with("velora://pair?address=%5Bfe80%3A%3A1%5D%3A7420&code=VL1-AAAA"), "{uri}");
    }

    #[test]
    fn pairing_link_roundtrip() {
        let code = PairingCode::generate(Fingerprint([9; 32])).unwrap();
        let uri = pairing_uri("[fe80::1]:7420", &code);
        assert_eq!(parse_pairing_uri(&uri), Some(("[fe80::1]:7420".to_string(), code)));
        assert_eq!(parse_pairing_uri("https://example.com"), None);
        assert_eq!(parse_pairing_uri("velora://pair?address=1.2.3.4&code=nope"), None);
    }

    #[test]
    fn rejects_bad_codes() {
        assert!(PairingCode::parse("XX1-abc").is_err());
        assert!(PairingCode::parse("VL1-abc").is_err());
        assert!(PairingCode::parse("VL1-!!!!").is_err());
    }

    #[test]
    fn secret_comparison() {
        let code = PairingCode::generate(Fingerprint([0; 32])).unwrap();
        assert!(code.secret_matches(&code.secret.clone()));
        let mut other = code.secret;
        other[15] ^= 1;
        assert!(!code.secret_matches(&other));
    }

    #[test]
    fn pairing_link_with_other_addresses() {
        let code = PairingCode { host: Fingerprint([1; 32]), secret: [2; PAIRING_SECRET_LEN] };
        let also = vec!["100.101.102.103:7420".to_string(), "[fd7a:115c:a1e0::1]:7420".to_string()];
        let uri = pairing_uri_with("192.168.1.9:7420", &also, &code, None, None);
        let link = parse_pairing_link(&uri).unwrap();
        assert_eq!((link.address.as_str(), link.also, link.code), ("192.168.1.9:7420", also, code.clone()));
        // Older parsers read the same address and code.
        assert_eq!(parse_pairing_uri(&uri), Some(("192.168.1.9:7420".to_string(), code)));
    }

    // Standalone reach (docs/nat-traversal.md).

    fn fixed_code() -> PairingCode {
        PairingCode { host: Fingerprint([1; 32]), secret: [2; PAIRING_SECRET_LEN] }
    }

    fn fixed_also() -> Vec<String> {
        vec!["100.101.102.103:7420".to_string(), "[fd7a:115c:a1e0::1]:7420".to_string()]
    }

    /// The link earlier versions wrote for `fixed_code` and `fixed_also`.
    const OLD_LINK: &str = "velora://pair?address=192.168.1.9%3A7420&code=VL1-AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQECAgICAgICAgICAgICAgIC\
                            &also=100.101.102.103%3A7420&also=%5Bfd7a%3A115c%3Aa1e0%3A%3A1%5D%3A7420";

    #[test]
    fn a_link_without_key_and_secret_is_the_one_earlier_versions_wrote() {
        assert_eq!(pairing_uri_with("192.168.1.9:7420", &fixed_also(), &fixed_code(), None, None), OLD_LINK);
        let link = parse_pairing_link(OLD_LINK).unwrap();
        assert_eq!(link.address, "192.168.1.9:7420");
        assert_eq!(link.also, fixed_also());
        assert_eq!(link.code, fixed_code());
        assert_eq!((link.key, link.secret), (None, None));
    }

    /// Base64url without padding of 32 bytes of 0xAB, and of 16 bytes of 0xCD.
    const KEY_TEXT: &str = "q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s";
    const SECRET_TEXT: &str = "zc3Nzc3Nzc3Nzc3Nzc3NzQ";

    #[test]
    fn key_and_secret_ride_at_the_end_of_the_link() {
        let (key, secret) = ([0xAB; REACH_KEY_LEN], [0xCD; DEVICE_SECRET_LEN]);
        let uri = pairing_uri_with("192.168.1.9:7420", &fixed_also(), &fixed_code(), Some(&key), Some(&secret));
        // What comes before them is the old link, so older parsers read what they always did.
        assert_eq!(uri, format!("{OLD_LINK}&key={KEY_TEXT}&secret={SECRET_TEXT}"));
        assert_eq!(parse_pairing_uri(&uri), Some(("192.168.1.9:7420".to_string(), fixed_code())));
        let link = parse_pairing_link(&uri).unwrap();
        assert_eq!((link.key, link.secret), (Some(key), Some(secret)));
        assert_eq!((link.address.as_str(), link.also, link.code), ("192.168.1.9:7420", fixed_also(), fixed_code()));
        // Either one alone, anywhere in the link.
        let only_key = pairing_uri_with("192.168.1.9:7420", &[], &fixed_code(), Some(&key), None);
        let link = parse_pairing_link(&only_key).unwrap();
        assert_eq!((link.key, link.secret), (Some(key), None));
        let reordered = format!("velora://pair?secret={SECRET_TEXT}&{}", &uri["velora://pair?".len()..]);
        assert_eq!(parse_pairing_link(&reordered).unwrap().secret, Some(secret));
    }

    #[test]
    fn a_damaged_key_or_secret_is_left_out_and_the_link_still_pairs() {
        for damaged in [
            "key=!!!!".to_string(),             // not base64
            format!("key={KEY_TEXT}%zz"),       // not percent-encoding
            format!("key={}", &KEY_TEXT[4..]),  // too short
            format!("key={KEY_TEXT}q6ur"),      // too long
            "key=".to_string(),                 // empty
            format!("secret={SECRET_TEXT}%00"), // not base64
            format!("secret={KEY_TEXT}"),       // the key's size
        ] {
            let link = parse_pairing_link(&format!("{OLD_LINK}&{damaged}")).unwrap_or_else(|| panic!("{damaged}"));
            assert_eq!((link.key, link.secret), (None, None), "{damaged}");
            assert_eq!(link.code, fixed_code());
        }
    }

    #[test]
    fn what_a_link_with_key_and_secret_costs() {
        let (key, secret) = ([7; REACH_KEY_LEN], [9; DEVICE_SECRET_LEN]);
        let link = |also: &[&str], reach: bool| {
            let also: Vec<String> = also.iter().map(|a| a.to_string()).collect();
            let (key, secret) = if reach { (Some(&key), Some(&secret)) } else { (None, None) };
            pairing_uri_with("192.168.1.9:7420", &also, &fixed_code(), key, secret).len()
        };
        // The key and the secret add 78 characters, whatever else the link carries.
        let first_connection = ["100.101.102.103:7420", "203.0.113.7:51820"];
        assert_eq!(link(&first_connection, true) - link(&first_connection, false), 78);
        // What a device needs for its first connection (LAN, VPN mesh, public) stays under the 300
        // characters the plan allows.
        assert!(link(&first_connection, true) < 300);
        // Eight addresses do not: each adds about 25 characters (an IPv6 one 72). The host lists
        // only the first few in the link, and the rest reach the device in `HostMsg::Reach`.
        let eight = [
            "100.101.102.103:7420",
            "203.0.113.7:51820",
            "10.0.0.5:7420",
            "172.16.0.5:7420",
            "192.168.56.1:7420",
            "198.51.100.9:7420",
            "100.64.0.9:7420",
        ];
        assert!(link(&eight, true) > 300);
    }
}
