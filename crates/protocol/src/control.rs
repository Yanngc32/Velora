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
    /// Running as the system service, so it also works on the lock screen.
    pub service: bool,
    /// Devices must also give an access password to connect. Absent from hosts that predate
    /// passwords.
    #[serde(default)]
    pub password_set: bool,
    pub devices: Vec<Device>,
    pub pairing: Option<Pairing>,
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

        let err: Reply = Err("nope".into());
        let json = serde_json::to_string(&err).unwrap();
        assert_eq!(serde_json::from_str::<Reply>(&json).unwrap(), err);
    }
}
