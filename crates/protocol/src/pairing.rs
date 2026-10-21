//! Pairing codes.
//!
//! The host displays a code containing its certificate fingerprint and a one-time random
//! secret. The client uses the fingerprint to authenticate the host (no MITM possible on first
//! contact) and sends the secret over the encrypted channel to prove it was given the code; the
//! host then stores the client's fingerprint. 128 random bits make guessing infeasible.

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};

use crate::{tls::Fingerprint, wire::PAIRING_SECRET_LEN};

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
    let query = link.trim().strip_prefix(URI_PREFIX)?;
    let (mut address, mut code) = (None, None);
    for pair in query.split('&') {
        match pair.split_once('=')? {
            ("address", v) => address = Some(decode(v)?),
            ("code", v) => code = Some(PairingCode::parse(&decode(v)?).ok()?),
            _ => {}
        }
    }
    Some((address.filter(|a| !a.is_empty())?, code?))
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
}
