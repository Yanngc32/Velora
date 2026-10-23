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
        assert!(status.also.is_empty() && status.requests.is_empty() && !status.password_set);
    }
}
