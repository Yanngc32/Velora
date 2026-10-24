//! Persistent device identity and local state (paired clients, known hosts).

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    tls::Fingerprint,
    wire::{AddressKind, DEVICE_SECRET_LEN, REACH_KEY_LEN},
};

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
///
/// The fields after `also` are what standalone reach adds (see `HostMsg::Reach`): hosts paired
/// before it have none of them, and a host that never uses it never gets any. Empty ones are
/// not written, so the file of such a host is the one earlier versions wrote.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownHost {
    pub name: String,
    pub address: String,
    pub fingerprint: String,
    /// Other addresses the host told about (LAN, VPN mesh), tried along with `address`.
    #[serde(default)]
    pub also: Vec<String>,
    /// The host's addresses with their kinds, as its last `HostMsg::Reach` listed them. `address`
    /// and `also` hold the same addresses without kinds, for versions that predate them; empty
    /// until the host sends one. A refresh replaces the whole list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kinds: Vec<(AddressKind, String)>,
    /// The host's Ed25519 key, where it publishes its DHT record: from the pairing link or from
    /// `HostMsg::Reach`. Written as base64url text.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "base64_bytes")]
    pub key: Option<[u8; REACH_KEY_LEN]>,
    /// The secret that opens that record for this device. Written as base64url text.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "base64_bytes")]
    pub secret: Option<[u8; DEVICE_SECRET_LEN]>,
    /// The relays the host is registered with, as its last `HostMsg::Reach` listed them: each
    /// one's fingerprint (base64url) and the addresses it answers at.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relays: Vec<(String, Vec<String>)>,
    /// The MAC address of the host's network adapter, for Wake-on-LAN. Written as base64url text.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "base64_bytes")]
    pub mac: Option<[u8; 6]>,
    /// The ways in a connection to the host may take: the user's choice. Not written while it
    /// is [`ConnectMode::Auto`].
    #[serde(default, skip_serializing_if = "ConnectMode::is_auto")]
    pub mode: ConnectMode,
}

/// Which ways of reaching a host a connection may take.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum ConnectMode {
    /// Whichever answers first, and a better one when it appears during the session.
    #[default]
    Auto,
    /// Only the host's addresses on the local network.
    Lan,
    /// Only the host's addresses on a VPN mesh (Tailscale, Netbird).
    Vpn,
    /// Only Velora's own ways from other networks: the router's public address, global IPv6,
    /// hole punching and relays through the user's other PCs.
    Velora,
}

impl ConnectMode {
    pub const ALL: [ConnectMode; 4] = [Self::Auto, Self::Lan, Self::Vpn, Self::Velora];

    pub fn is_auto(&self) -> bool {
        *self == Self::Auto
    }

    /// The word written in the state file.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Lan => "lan",
            Self::Vpn => "vpn",
            Self::Velora => "velora",
        }
    }
}

impl std::str::FromStr for ConnectMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::ALL.into_iter().find(|mode| mode.as_str() == s).with_context(|| format!("unknown connection mode '{s}'"))
    }
}

impl Serialize for ConnectMode {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

/// A word this version does not know (a later one's mode) reads as `Auto`: the entry stays usable.
impl<'de> Deserialize<'de> for ConnectMode {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        Ok(String::deserialize(d)?.parse().unwrap_or_default())
    }
}

/// `Option<[u8; N]>` as base64url text, which reads better in a state file than a list of
/// numbers. Text that is not valid or not of the right size reads as absent: a damaged field
/// costs that field (the host sends it again on the next connection), not the whole file.
mod base64_bytes {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer, const N: usize>(value: &Option<[u8; N]>, s: S) -> Result<S::Ok, S::Error> {
        value.as_ref().map(|bytes| URL_SAFE_NO_PAD.encode(bytes)).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(d: D) -> Result<Option<[u8; N]>, D::Error> {
        let text = Option::<String>::deserialize(d)?;
        Ok(text.and_then(|text| URL_SAFE_NO_PAD.decode(text).ok()).and_then(|bytes| bytes.try_into().ok()))
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    const FINGERPRINT: &str = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM";

    /// A known-hosts file as earlier versions wrote it.
    const OLD_FILE: &str = r#"[
  {
    "name": "PC",
    "address": "192.168.1.9:7420",
    "fingerprint": "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM",
    "also": [
      "100.101.102.103:7420",
      "[fd7a:115c:a1e0::1]:7420"
    ]
  }
]"#;

    fn old_host() -> KnownHost {
        KnownHost {
            name: "PC".into(),
            address: "192.168.1.9:7420".into(),
            fingerprint: FINGERPRINT.into(),
            also: vec!["100.101.102.103:7420".into(), "[fd7a:115c:a1e0::1]:7420".into()],
            ..Default::default()
        }
    }

    #[test]
    fn known_hosts_from_earlier_versions_read_and_are_written_back_unchanged() {
        let hosts: Vec<KnownHost> = serde_json::from_str(OLD_FILE).unwrap();
        assert_eq!(hosts, vec![old_host()]);
        assert_eq!(serde_json::to_string_pretty(&hosts).unwrap(), OLD_FILE);
        // The first versions had no `also` either.
        let first: KnownHost = serde_json::from_str(r#"{"name":"PC","address":"a:1","fingerprint":"f"}"#).unwrap();
        assert_eq!((first.also, first.kinds, first.key, first.secret, first.relays, first.mac), Default::default());
    }

    #[test]
    fn reach_fields_are_written_as_text_and_read_back() {
        let host = KnownHost {
            kinds: vec![
                (AddressKind::Lan, "192.168.1.9:7420".into()),
                (AddressKind::Public, "203.0.113.7:51820".into()),
                (AddressKind::Relay("relay".into()), "198.51.100.2:7420".into()),
            ],
            key: Some([0xAB; REACH_KEY_LEN]),
            secret: Some([0xCD; DEVICE_SECRET_LEN]),
            relays: vec![("relay".into(), vec!["198.51.100.2:7420".into()])],
            mac: Some([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]),
            ..old_host()
        };
        let json = serde_json::to_string(&host).unwrap();
        assert!(json.contains(r#""key":"q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s""#), "{json}");
        assert!(json.contains(r#""secret":"zc3Nzc3Nzc3Nzc3Nzc3NzQ""#), "{json}");
        assert!(json.contains(r#""mac":"ABorPE1e""#), "{json}");
        assert!(
            json.contains(r#""kinds":[["lan","192.168.1.9:7420"],["public","203.0.113.7:51820"],[{"relay":"relay"},"#),
            "{json}"
        );
        assert_eq!(serde_json::from_str::<KnownHost>(&json).unwrap(), host);
    }

    #[test]
    fn a_damaged_reach_field_costs_that_field_not_the_file() {
        let json = r#"[{"name":"PC","address":"a:1","fingerprint":"f","key":"not base64!","secret":"AAAA",
            "mac":"","kinds":[["lan","a:1"]]}]"#;
        let hosts: Vec<KnownHost> = serde_json::from_str(json).unwrap();
        assert_eq!((hosts[0].key, hosts[0].secret, hosts[0].mac), (None, None, None));
        assert_eq!(hosts[0].kinds, vec![(AddressKind::Lan, "a:1".to_string())]);
    }

    #[test]
    fn the_connection_mode_is_written_only_when_chosen_and_an_unknown_one_reads_as_auto() {
        assert!(!serde_json::to_string(&old_host()).unwrap().contains("mode"), "auto is not written");
        let tailscale = KnownHost { mode: ConnectMode::Vpn, ..old_host() };
        let json = serde_json::to_string(&tailscale).unwrap();
        assert!(json.contains(r#""mode":"vpn""#), "{json}");
        assert_eq!(serde_json::from_str::<KnownHost>(&json).unwrap(), tailscale);
        let later = r#"{"name":"PC","address":"a:1","fingerprint":"f","mode":"carrier-pigeon"}"#;
        assert_eq!(serde_json::from_str::<KnownHost>(later).unwrap().mode, ConnectMode::Auto);
        for mode in ConnectMode::ALL {
            assert_eq!(mode.as_str().parse::<ConnectMode>().unwrap(), mode);
        }
    }
}
