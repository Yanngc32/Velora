//! The Ed25519 key a device signs its DHT records with, kept beside the TLS identity.
//!
//! BEP 44 signs with Ed25519 and the TLS identity is ECDSA P-256, so this is a second key. Its public half is
//! the address of the device's record in the DHT. The file holds the 32-byte seed and nothing else.

use std::{
    fs,
    io::{ErrorKind, Write},
    path::Path,
};

use anyhow::{Context, Result};
use mainline::SigningKey;
use ring::rand::{SecureRandom, SystemRandom};

/// Where the key lives in a state directory, next to `identity.json`.
pub const FILE_NAME: &str = "dht_key.bin";

const SEED_LEN: usize = 32;

/// The device's DHT key pair. `Debug` shows the public half only.
#[derive(Debug, Clone)]
pub struct Keys {
    signing: SigningKey,
}

impl Keys {
    /// Reads the seed from `path`, or creates the file with a fresh random one when there is none.
    ///
    /// A file of the wrong size is an error, never replaced: a new key would silently orphan every pairing
    /// that already holds the old public key.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        match fs::read(path) {
            Ok(bytes) => {
                let seed: [u8; SEED_LEN] = bytes.as_slice().try_into().ok().with_context(|| {
                    format!("{} holds {} bytes, a DHT key file holds {SEED_LEN}", path.display(), bytes.len())
                })?;
                Ok(Self { signing: SigningKey::from_bytes(&seed) })
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {
                let mut seed = [0u8; SEED_LEN];
                SystemRandom::new().fill(&mut seed).ok().context("the system random generator failed")?;
                write_new(path, &seed)?;
                Ok(Self { signing: SigningKey::from_bytes(&seed) })
            }
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    /// The 32 bytes other devices learn at pairing and look the record up by.
    pub fn public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// For `mainline::MutableItem::new`.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing
    }
}

/// Writes through a temp file and a rename so a crash never leaves half a seed behind. Readable only by the
/// current user on Unix; on Windows the file inherits the permissions of the user's config directory.
fn write_new(path: &Path, seed: &[u8; SEED_LEN]) -> Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let tmp = path.with_extension("tmp");
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let written = opts.open(&tmp).and_then(|mut f| f.write_all(seed).and_then(|()| f.sync_all()));
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("writing {}", tmp.display()));
    }
    fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU32, Ordering},
    };

    use super::*;

    /// A scratch directory removed on drop; the crate has no `tempfile` and the tests need nothing more.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let dir = std::env::temp_dir().join(format!(
                "velora-dht-keys-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn key_file(&self) -> PathBuf {
            self.0.join(FILE_NAME)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn creates_then_reloads_the_same_key() {
        let dir = Scratch::new();
        let path = dir.key_file();
        assert!(!path.exists());

        let created = Keys::load_or_create(&path).unwrap();
        assert_eq!(fs::read(&path).unwrap().len(), SEED_LEN);
        assert!(!path.with_extension("tmp").exists(), "the temp file is renamed away");

        let reloaded = Keys::load_or_create(&path).unwrap();
        assert_eq!(created.public_key(), reloaded.public_key());
        assert_eq!(created.signing_key().to_bytes(), reloaded.signing_key().to_bytes());
    }

    #[test]
    fn two_devices_get_different_keys() {
        let (a, b) = (Scratch::new(), Scratch::new());
        let ka = Keys::load_or_create(&a.key_file()).unwrap();
        let kb = Keys::load_or_create(&b.key_file()).unwrap();
        assert_ne!(ka.public_key(), kb.public_key());
    }

    #[test]
    fn the_seed_in_the_file_is_the_signing_key() {
        let dir = Scratch::new();
        let path = dir.key_file();
        let seed = [7u8; SEED_LEN];
        fs::write(&path, seed).unwrap();

        let keys = Keys::load_or_create(&path).unwrap();
        assert_eq!(keys.signing_key().to_bytes(), seed);
        assert_eq!(keys.public_key(), SigningKey::from_bytes(&seed).verifying_key().to_bytes());
        assert_eq!(fs::read(&path).unwrap(), seed, "an existing file is left alone");
    }

    #[test]
    fn creates_the_missing_directory() {
        let dir = Scratch::new();
        let path = dir.0.join("not").join("yet").join(FILE_NAME);
        Keys::load_or_create(&path).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn a_corrupt_file_is_an_error_and_is_kept() {
        let dir = Scratch::new();
        let path = dir.key_file();
        for bad in [&b""[..], &[1u8; SEED_LEN - 1][..], &[1u8; SEED_LEN + 1][..], &b"-----BEGIN PRIVATE KEY-----"[..]] {
            fs::write(&path, bad).unwrap();
            let err = Keys::load_or_create(&path).unwrap_err().to_string();
            assert!(err.contains(&format!("{} bytes", bad.len())), "{err}");
            assert_eq!(fs::read(&path).unwrap(), bad, "a corrupt file is never overwritten");
        }
    }

    #[test]
    fn a_directory_in_the_way_is_an_error() {
        let dir = Scratch::new();
        let path = dir.key_file();
        fs::create_dir(&path).unwrap();
        assert!(Keys::load_or_create(&path).is_err());
    }

    #[test]
    fn debug_does_not_show_the_seed() {
        let dir = Scratch::new();
        let path = dir.key_file();
        let keys = Keys::load_or_create(&path).unwrap();
        let seed = fs::read(&path).unwrap();
        assert!(!format!("{keys:?}").contains(&format!("{seed:?}")));
    }

    #[cfg(unix)]
    #[test]
    fn the_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = Scratch::new();
        let path = dir.key_file();
        Keys::load_or_create(&path).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }
}
