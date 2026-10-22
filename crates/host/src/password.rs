//! Optional access password: paired devices must also send it to open a session, so a lost
//! phone alone is not enough to reach the computer.
//!
//! Only a salted PBKDF2-HMAC-SHA256 hash is stored. Consecutive wrong guesses from a device
//! lock that device out for a growing time; other devices (the owner's) are not affected.
//! Checks run one at a time, so parallel connections cannot multiply the guesses allowed,
//! nor keep every core busy hashing.

use std::{
    collections::HashMap,
    num::NonZeroU32,
    sync::Mutex,
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ring::{pbkdf2, rand::SecureRandom};
use serde::{Deserialize, Serialize};
use velora_protocol::{identity::StateDir, tls::Fingerprint, wire::MAX_PASSWORD_LEN};

/// OWASP's recommendation for PBKDF2-HMAC-SHA256.
const ITERATIONS: u32 = 600_000;
const ALGORITHM: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA256;
/// Wrong guesses allowed before a lockout.
const FREE_ATTEMPTS: u32 = 5;
const FIRST_LOCKOUT: Duration = Duration::from_secs(30);
const MAX_LOCKOUT: Duration = Duration::from_secs(15 * 60);

#[derive(Clone, Serialize, Deserialize)]
struct StoredHash {
    salt: String,
    iterations: u32,
    hash: String,
}

/// Outcome of checking a connecting device's password.
pub enum Check {
    Ok,
    /// No password sent (`wrong: false`) or a wrong one.
    Required {
        wrong: bool,
    },
    /// Too many wrong passwords; try again after this long.
    LockedOut(Duration),
}

/// The password is read from the state directory on every check, so a change applies to a
/// running host, like `velora-host revoke`.
#[derive(Default)]
pub struct Gate {
    /// Per device: consecutive wrong guesses, and until when it is locked out. Held for the
    /// whole check, which serializes checks.
    failures: Mutex<HashMap<Fingerprint, (u32, Option<Instant>)>>,
}

fn stored(state: &StateDir) -> Result<Option<StoredHash>> {
    state.load(StateDir::ACCESS_PASSWORD)
}

pub fn is_set(state: &StateDir) -> Result<bool> {
    Ok(stored(state)?.is_some())
}

/// Sets (`Some`) or removes the password.
pub fn set(state: &StateDir, password: Option<&str>) -> Result<()> {
    let stored = match password {
        Some(p) => Some(hash(p)?),
        None => None,
    };
    state.save(StateDir::ACCESS_PASSWORD, &stored)
}

impl Gate {
    /// Checks the password `device` sent against the stored one. Slow by design (key
    /// stretching): call it from a blocking context. Fails closed: an unreadable password
    /// file refuses everyone.
    pub fn check(&self, state: &StateDir, device: Fingerprint, password: Option<&str>) -> Check {
        let mut failures = self.failures.lock().unwrap();
        let stored = match stored(state) {
            Ok(None) => return Check::Ok,
            Ok(Some(s)) => s,
            Err(e) => {
                tracing::error!("cannot read the access password: {e:#}");
                return Check::LockedOut(FIRST_LOCKOUT);
            }
        };
        let entry = failures.entry(device).or_insert((0, None));
        if let Some(left) = entry.1.and_then(|until| until.checked_duration_since(Instant::now())) {
            return Check::LockedOut(left);
        }
        let Some(password) = password else { return Check::Required { wrong: false } };
        if verify(&stored, password) {
            failures.remove(&device);
            return Check::Ok;
        }
        entry.0 += 1;
        if entry.0 >= FREE_ATTEMPTS {
            let doublings = (entry.0 - FREE_ATTEMPTS).min(10);
            let lockout = (FIRST_LOCKOUT * 2u32.pow(doublings)).min(MAX_LOCKOUT);
            entry.1 = Some(Instant::now() + lockout);
            tracing::warn!("{} wrong passwords in a row from {device}; locked for {lockout:?}", entry.0);
        }
        Check::Required { wrong: true }
    }

    /// Forgets every lockout, after the owner set a new password.
    pub fn reset(&self) {
        self.failures.lock().unwrap().clear();
    }
}

fn hash(password: &str) -> Result<StoredHash> {
    if password.is_empty() {
        bail!("the password cannot be empty");
    }
    if password.len() > MAX_PASSWORD_LEN {
        bail!("the password is longer than {MAX_PASSWORD_LEN} bytes");
    }
    let mut salt = [0u8; 16];
    ring::rand::SystemRandom::new().fill(&mut salt).map_err(|_| anyhow::anyhow!("system RNG failure"))?;
    let mut out = [0u8; 32];
    let iterations = NonZeroU32::new(ITERATIONS).context("iterations")?;
    pbkdf2::derive(ALGORITHM, iterations, &salt, password.as_bytes(), &mut out);
    Ok(StoredHash { salt: B64.encode(salt), iterations: ITERATIONS, hash: B64.encode(out) })
}

/// Constant-time comparison (ring's `verify`).
fn verify(stored: &StoredHash, password: &str) -> bool {
    let (Ok(salt), Ok(hash), Some(iterations)) =
        (B64.decode(&stored.salt), B64.decode(&stored.hash), NonZeroU32::new(stored.iterations))
    else {
        return false;
    };
    pbkdf2::verify(ALGORITHM, iterations, &salt, password.as_bytes(), &hash).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(test: &str) -> (StateDir, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("velora-password-{test}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        (StateDir::open(Some(dir.clone()), "host").unwrap(), dir)
    }

    const PHONE: Fingerprint = Fingerprint([1; 32]);
    const LAPTOP: Fingerprint = Fingerprint([2; 32]);

    #[test]
    fn no_password_lets_everyone_through() {
        let (state, dir) = state("none");
        assert!(matches!(Gate::default().check(&state, PHONE, None), Check::Ok));
        assert!(!is_set(&state).unwrap());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn checks_and_persists_the_password() {
        let (state, dir) = state("persist");
        let gate = Gate::default();
        set(&state, Some("correct horse")).unwrap();
        assert!(is_set(&state).unwrap());
        assert!(matches!(gate.check(&state, PHONE, None), Check::Required { wrong: false }));
        assert!(matches!(gate.check(&state, PHONE, Some("wrong")), Check::Required { wrong: true }));
        assert!(matches!(gate.check(&state, PHONE, Some("correct horse")), Check::Ok));
        set(&state, None).unwrap();
        assert!(matches!(gate.check(&state, PHONE, None), Check::Ok));
        assert!(set(&state, Some("")).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn locks_out_after_repeated_wrong_guesses() {
        let (state, dir) = state("lockout");
        let gate = Gate::default();
        set(&state, Some("right")).unwrap();
        for _ in 0..FREE_ATTEMPTS {
            assert!(matches!(gate.check(&state, PHONE, Some("nope")), Check::Required { wrong: true }));
        }
        // Even the right password waits out the lockout...
        assert!(matches!(gate.check(&state, PHONE, Some("right")), Check::LockedOut(_)));
        // ...but only on that device.
        assert!(matches!(gate.check(&state, LAPTOP, Some("right")), Check::Ok));
        gate.reset();
        assert!(matches!(gate.check(&state, PHONE, Some("right")), Check::Ok));
        let _ = std::fs::remove_dir_all(dir);
    }
}
