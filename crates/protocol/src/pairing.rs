//! Pairing codes.
//!
//! The host displays a code containing its certificate fingerprint and a one-time random
//! secret. The client uses the fingerprint to authenticate the host (no MITM possible on first
//! contact) and sends the secret over the encrypted channel to prove it was given the code; the
//! host then stores the client's fingerprint. 128 random bits make guessing infeasible.

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};

use crate::{tls::Fingerprint, wire::PAIRING_SECRET_LEN};

const PREFIX: &str = "SM1-";

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
        let body = code.trim().strip_prefix(PREFIX).context("pairing code must start with SM1-")?;
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
    fn rejects_bad_codes() {
        assert!(PairingCode::parse("XX1-abc").is_err());
        assert!(PairingCode::parse("SM1-abc").is_err());
        assert!(PairingCode::parse("SM1-!!!!").is_err());
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
