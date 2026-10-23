//! Local control channel between a running host and the desktop launcher on the same
//! computer: a named pipe on Windows, a Unix socket elsewhere. Only the local user (and, for a
//! host running as a service, the administrators and the system) can open it.
//!
//! Each connection carries one request and one reply, both a single line of JSON. Every
//! request is answered with the host's current [`Status`], so a client never needs a second
//! round trip to see the effect of what it asked.

use std::{
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    time::Duration,
};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use crate::wire::AddressKind;

/// Requests and replies are tiny; anything larger is not from a well-behaved peer.
pub const MAX_LINE: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Status,
    /// Opens a pairing window, replacing any open one.
    StartPairing,
    CancelPairing,
    /// Removes a paired device (by base64 fingerprint) and disconnects it.
    Revoke {
        fingerprint: String,
    },
    /// Stops the host after replying (used before installing it as a service).
    Shutdown,
    /// Sets (`Some`) or removes the password paired devices must also give to connect.
    SetPassword {
        password: Option<String>,
    },
    /// Sends files and folders to the connected device, into its Downloads folder (Send To).
    /// The reply comes once the transfer started; it continues in the background.
    SendFiles {
        paths: Vec<PathBuf>,
    },
    /// Forgets a pairing offer once the launcher has acted on it (see [`Status::offers`]).
    DismissOffer {
        uri: String,
    },
    /// Answers a device asking to send files here (see [`Status::requests`]). With `always`,
    /// that device's files are saved without asking from now on.
    AnswerFiles {
        id: u64,
        accept: bool,
        always: bool,
    },
    /// Keeps the computer from sleeping while the host runs (see [`Status::stay_awake`]).
    SetStayAwake {
        on: bool,
    },
    /// Sets the switches of standalone reach (see [`Status::reach`]). All three are given
    /// together: the launcher always knows the current ones.
    SetReach {
        standalone: bool,
        relay_for_others: bool,
        dht: bool,
    },
}

pub type Reply = std::result::Result<Status, String>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    pub name: String,
    pub version: String,
    /// Short host fingerprint, for confirmation on the other device.
    pub fingerprint: String,
    /// Address other devices should dial, when it could be determined.
    pub address: Option<String>,
    /// Addresses on a VPN mesh (Tailscale, Netbird) other devices can also dial, from outside
    /// the local network. Absent from hosts that predate them.
    #[serde(default)]
    pub also: Vec<String>,
    /// Running as the system service, so it also works on the lock screen.
    pub service: bool,
    /// Devices must also give an access password to connect. Absent from hosts that predate
    /// passwords.
    #[serde(default)]
    pub password_set: bool,
    pub devices: Vec<Device>,
    pub pairing: Option<Pairing>,
    /// Paired devices that offered to be reached from here too: the launcher pairs with each.
    /// Absent from hosts that predate offers.
    #[serde(default)]
    pub offers: Vec<Offer>,
    /// Devices waiting for an answer before their files are saved here. Absent from hosts
    /// that predate requests.
    #[serde(default)]
    pub requests: Vec<FileRequest>,
    /// The computer stays awake while the host runs, so it remains reachable; the screen is
    /// kept on during a session. `None` from hosts that can't do it or predate it.
    #[serde(default)]
    pub stay_awake: Option<bool>,
    /// How this host is reached from other networks without a mesh VPN. `None` from hosts that
    /// predate standalone reach: the launcher shows nothing for it and sends no
    /// [`Request::SetReach`].
    #[serde(default)]
    pub reach: Option<ReachStatus>,
}

/// What the host does to be reachable from other networks, for This PC to show
/// (`docs/nat-traversal.md`). Fields missing from a status read as off or empty.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ReachStatus {
    /// Standalone reach is on: the host asks the router to map its port, and tells devices its
    /// public and IPv6 addresses.
    pub standalone: bool,
    /// Other paired devices may connect through this computer to reach their own host.
    pub relay_for_others: bool,
    /// The host publishes its addresses in the BitTorrent Mainline DHT for its paired devices.
    pub dht: bool,
    /// The router's port mapping, when there is one.
    pub mapping: Option<MappingStatus>,
    /// Public IPv4 addresses (`ip:port`) the host advertises.
    pub public: Vec<String>,
    /// Global IPv6 addresses (`[ip]:port`) the host advertises.
    pub v6: Vec<String>,
    /// The address (and its kind) the device that connected last reached the host at.
    pub last_reached: Option<(AddressKind, String)>,
    /// The relays the host is registered with, by the names it knows them under.
    pub registered_with: Vec<String>,
}

/// A port mapping the router granted the host (NAT-PMP or UPnP).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MappingStatus {
    /// How the router was asked: `"natpmp"` or `"upnp"`.
    pub protocol: String,
    /// The `ip:port` the mapping makes the host answer at from outside: the router's external
    /// address and the port it assigned, which is not always the host's own.
    pub external: String,
    /// The external address is public. `false` means the ISP shares it between customers or a
    /// second router sits in front: the mapping reaches only that far and is not advertised.
    pub public: bool,
    /// Seconds until the router drops the mapping unless it is renewed, which the host does.
    pub lease_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRequest {
    pub id: u64,
    /// The device sending, as it is named in [`Status::devices`].
    pub name: String,
    /// Total size of the files.
    pub bytes: u64,
    /// Where they would be saved: a folder path, or "Downloads".
    pub folder: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Offer {
    /// The device that offered, as it is named in [`Status::devices`].
    pub name: String,
    /// `velora://pair?..` link to that device's host.
    pub uri: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    pub name: String,
    /// Full base64 fingerprint; identifies the device in [`Request::Revoke`].
    pub fingerprint: String,
    pub short: String,
    pub added_unix: u64,
    pub connected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pairing {
    /// `velora://pair?..` link, shown as a QR code.
    pub uri: String,
    pub code: String,
    pub address: String,
    pub expires_in_secs: u64,
}

/// How long a client waits for the host's reply.
const REPLY_TIMEOUT: Duration = Duration::from_secs(5);

/// Name of the pipe (Windows) or path of the socket (Unix) of the host on this computer.
pub fn endpoint() -> PathBuf {
    #[cfg(windows)]
    return PathBuf::from(r"\\.\pipe\velora-host");
    #[cfg(unix)]
    {
        if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR").filter(|d| !d.is_empty()) {
            return PathBuf::from(dir).join("velora-host.sock");
        }
        // Not a shared directory like /tmp, where another user could take the name first.
        directories::ProjectDirs::from("", "", "velora")
            .map(|d| d.config_dir().join("host.sock"))
            .unwrap_or_else(|| PathBuf::from("velora-host.sock"))
    }
}

/// Sends one request to the local host. Fails quickly when no host is running, and after
/// [`REPLY_TIMEOUT`] when it does not answer.
pub fn request(req: &Request) -> Result<Status> {
    let mut line = serde_json::to_vec(req)?;
    line.push(b'\n');
    let stream = connect()?;
    // Pipes have no read timeout: wait on a helper thread, which ends once the host replies
    // or closes the pipe.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(round_trip(stream, &line));
    });
    let reply = rx.recv_timeout(REPLY_TIMEOUT).map_err(|_| anyhow!("the host did not reply"))??;
    let reply: Reply = serde_json::from_slice(&reply).context("malformed reply from the host")?;
    reply.map_err(|e| anyhow!(e))
}

#[cfg(windows)]
fn connect() -> Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    const ERROR_PIPE_BUSY: i32 = 231;
    /// The server may identify the caller but not act as it.
    const SECURITY_IDENTIFICATION: u32 = 1 << 16;
    let path = endpoint();
    let mut attempts = 0;
    loop {
        let opened =
            std::fs::OpenOptions::new().read(true).write(true).security_qos_flags(SECURITY_IDENTIFICATION).open(&path);
        match opened {
            Ok(p) => return Ok(p),
            // Every instance is serving another client; a new one is created right away.
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) && attempts < 20 => {
                attempts += 1;
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => return Err(e).context("no host is running on this computer"),
        }
    }
}

#[cfg(unix)]
fn connect() -> Result<std::os::unix::net::UnixStream> {
    std::os::unix::net::UnixStream::connect(endpoint()).context("no host is running on this computer")
}

fn round_trip<S: std::io::Read + Write>(mut stream: S, line: &[u8]) -> Result<Vec<u8>> {
    stream.write_all(line)?;
    stream.flush()?;
    let mut reply = Vec::new();
    BufReader::new(stream.take(MAX_LINE as u64)).read_until(b'\n', &mut reply)?;
    if reply.last() != Some(&b'\n') {
        return Err(anyhow!("the host closed the connection without replying"));
    }
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_format() {
        assert_eq!(serde_json::to_string(&Request::Status).unwrap(), r#"{"op":"status"}"#);
        let revoke = Request::Revoke { fingerprint: "abc".into() };
        let json = serde_json::to_string(&revoke).unwrap();
        assert_eq!(json, r#"{"op":"revoke","fingerprint":"abc"}"#);
        assert_eq!(serde_json::from_str::<Request>(&json).unwrap(), revoke);
        let send = Request::SendFiles { paths: vec![PathBuf::from("foto.jpg")] };
        let json = serde_json::to_string(&send).unwrap();
        assert_eq!(json, r#"{"op":"send_files","paths":["foto.jpg"]}"#);

        let err: Reply = Err("nope".into());
        let json = serde_json::to_string(&err).unwrap();
        assert_eq!(serde_json::from_str::<Reply>(&json).unwrap(), err);

        let awake = Request::SetStayAwake { on: false };
        assert_eq!(serde_json::to_string(&awake).unwrap(), r#"{"op":"set_stay_awake","on":false}"#);
    }

    /// A status from a host that predates the newer fields still reads, with them unset.
    #[test]
    fn older_status() {
        let json = r#"{"name":"PC","version":"0.3.1","fingerprint":"AB12","address":null,
            "service":false,"devices":[],"pairing":null}"#;
        let status: Status = serde_json::from_str(json).unwrap();
        assert_eq!(status.stay_awake, None);
        assert_eq!(status.reach, None);
        assert!(status.also.is_empty() && status.requests.is_empty() && !status.password_set);
    }

    /// The last status before standalone reach, as the host wrote it: everything but `reach`.
    #[test]
    fn status_before_standalone_reach() {
        let json = r#"{"name":"PC","version":"0.4.0","fingerprint":"AB12","address":"192.168.1.9:7420","also":[],
            "service":false,"password_set":false,"devices":[],"pairing":null,"offers":[],"requests":[],
            "stay_awake":true}"#;
        let status: Status = serde_json::from_str(json).unwrap();
        assert_eq!((status.stay_awake, status.reach), (Some(true), None));
    }

    #[test]
    fn set_reach_wire_format() {
        let set = Request::SetReach { standalone: true, relay_for_others: false, dht: true };
        let json = serde_json::to_string(&set).unwrap();
        assert_eq!(json, r#"{"op":"set_reach","standalone":true,"relay_for_others":false,"dht":true}"#);
        assert_eq!(serde_json::from_str::<Request>(&json).unwrap(), set);
    }

    fn reach_status() -> ReachStatus {
        ReachStatus {
            standalone: true,
            relay_for_others: false,
            dht: true,
            mapping: Some(MappingStatus {
                protocol: "upnp".into(),
                external: "203.0.113.7:51820".into(),
                public: true,
                lease_secs: 3600,
            }),
            public: vec!["203.0.113.7:51820".into()],
            v6: vec!["[2804:14c:5b82:1234:abcd:ef01:2345:6789]:7420".into()],
            last_reached: Some((AddressKind::Public, "203.0.113.7:51820".into())),
            registered_with: vec!["STUDIO-PC".into()],
        }
    }

    #[test]
    fn status_with_reach_roundtrips() {
        let status = Status {
            name: "PC".into(),
            version: "0.5.0".into(),
            fingerprint: "AB12".into(),
            address: Some("192.168.1.9:7420".into()),
            also: Vec::new(),
            service: false,
            password_set: false,
            devices: Vec::new(),
            pairing: None,
            offers: Vec::new(),
            requests: Vec::new(),
            stay_awake: None,
            reach: Some(reach_status()),
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains(r#""last_reached":["public","203.0.113.7:51820"]"#), "{json}");
        assert!(json.contains(
            r#""mapping":{"protocol":"upnp","external":"203.0.113.7:51820","public":true,"lease_secs":3600}"#
        ));
        assert_eq!(serde_json::from_str::<Status>(&json).unwrap(), status);
        // A relay as the last address reached carries its fingerprint.
        let relayed = ReachStatus {
            last_reached: Some((AddressKind::Relay("fp".into()), "198.51.100.2:7420".into())),
            ..reach_status()
        };
        let json = serde_json::to_string(&relayed).unwrap();
        assert_eq!(serde_json::from_str::<ReachStatus>(&json).unwrap(), relayed);
    }

    #[test]
    fn fields_missing_from_a_reach_status_read_as_off() {
        let status: ReachStatus = serde_json::from_str(r#"{"standalone":true}"#).unwrap();
        assert_eq!(status, ReachStatus { standalone: true, ..Default::default() });
        let status: ReachStatus = serde_json::from_str(r#"{"mapping":{"protocol":"natpmp"}}"#).unwrap();
        assert_eq!(status.mapping, Some(MappingStatus { protocol: "natpmp".into(), ..Default::default() }));
    }
}
