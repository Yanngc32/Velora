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
