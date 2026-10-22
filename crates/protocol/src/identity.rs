//! Persistent device identity and local state (paired clients, known hosts).

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::tls::Fingerprint;

/// A self-signed certificate and its PKCS#8 private key, both DER-encoded.
#[derive(Clone)]
pub struct Identity {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
}

impl Identity {
    pub fn generate() -> Result<Self> {
        let ck = rcgen::generate_simple_self_signed(vec![crate::tls::SERVER_NAME.to_string()])?;
        Ok(Self { cert_der: ck.cert.der().to_vec(), key_der: ck.signing_key.serialize_der() })
    }

    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of(&self.cert_der)
    }
}

#[derive(Serialize, Deserialize)]
struct IdentityFile {
    cert: String,
    key: String,
}

/// Paired client allowed to control this host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizedClient {
    pub name: String,
    pub fingerprint: String,
    pub added_unix: u64,
    /// Files it sends are saved without asking ("always accept from this device").
    #[serde(default)]
    pub trust_files: bool,
}

/// Host this client has paired with.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownHost {
    pub name: String,
    pub address: String,
    pub fingerprint: String,
}

/// Per-role state directory (`<config>/host` or `<config>/client`).
pub struct StateDir(PathBuf);

impl StateDir {
    pub const IDENTITY: &'static str = "identity.json";
    pub const AUTHORIZED_CLIENTS: &'static str = "authorized_clients.json";
    pub const KNOWN_HOSTS: &'static str = "known_hosts.json";
    /// Hash of the host's access password (see the host's `password` module).
    pub const ACCESS_PASSWORD: &'static str = "access_password.json";

    /// Uses `base` when given, otherwise the platform config directory.
    pub fn open(base: Option<PathBuf>, role: &str) -> Result<Self> {
        let base = match base {
            Some(b) => b,
            None => directories::ProjectDirs::from("", "", "velora")
                .context("could not determine the config directory")?
                .config_dir()
                .to_path_buf(),
        };
        let dir = base.join(role);
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        Ok(Self(dir))
    }

    pub fn dir(&self) -> &Path {
        &self.0
    }

    pub fn path(&self, file: &str) -> PathBuf {
        self.0.join(file)
    }

    pub fn load_or_create_identity(&self) -> Result<Identity> {
        let path = self.path(Self::IDENTITY);
        if path.exists() {
            let f: IdentityFile = read_json(&path)?;
            return Ok(Identity { cert_der: B64.decode(f.cert)?, key_der: B64.decode(f.key)? });
        }
        let id = Identity::generate()?;
        write_json(&path, &IdentityFile { cert: B64.encode(&id.cert_der), key: B64.encode(&id.key_der) })?;
        Ok(id)
    }

    pub fn load<T: DeserializeOwned + Default>(&self, file: &str) -> Result<T> {
        let path = self.path(file);
        if !path.exists() {
            return Ok(T::default());
        }
        read_json(&path)
    }

    pub fn save<T: Serialize>(&self, file: &str, value: &T) -> Result<()> {
        write_json(&self.path(file), value)
    }
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let data = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&data).with_context(|| format!("parsing {}", path.display()))
}

/// Writes atomically (temp file + rename), readable only by the current user on Unix since
/// these files contain private keys and authorization lists.
fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let tmp = path.with_extension("tmp");
    let data = serde_json::to_vec_pretty(value)?;
    {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        use std::io::Write;
        let mut f = opts.open(&tmp).with_context(|| format!("writing {}", tmp.display()))?;
        f.write_all(&data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display()))
}
