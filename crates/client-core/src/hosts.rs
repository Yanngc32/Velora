//! Paired hosts: pairing, lookup and connection by name, shared by every client UI.

use std::net::{IpAddr, SocketAddr};

use anyhow::{Context, Result};
use velora_protocol::{
    identity::{KnownHost, StateDir},
    pairing::PairingCode,
    tls::Fingerprint,
    wire::DEFAULT_PORT,
};

use crate::{ConnectParams, FilesSession, Session, VideoOutput};

pub fn list(state: &StateDir) -> Result<Vec<KnownHost>> {
    state.load(StateDir::KNOWN_HOSTS)
}

pub fn forget(state: &StateDir, name: &str) -> Result<()> {
    let mut hosts = list(state)?;
    hosts.retain(|h| h.name != name);
    state.save(StateDir::KNOWN_HOSTS, &hosts)
}

fn remember(state: &StateDir, name: &str, address: &str, fingerprint: Fingerprint) -> Result<()> {
    let mut hosts = list(state)?;
    let fp = fingerprint.to_base64();
    hosts.retain(|h| h.fingerprint != fp && h.name != name);
    hosts.push(KnownHost { name: name.to_string(), address: address.to_string(), fingerprint: fp });
    state.save(StateDir::KNOWN_HOSTS, &hosts)
}

/// Pairs with the host at `address` using the code it printed, saves it and returns the
/// established session. Fails with [`crate::PasswordRequired`] when the host has an access
/// password and `password` is missing or wrong; the code stays valid for another try.
pub async fn pair(
    state: &StateDir,
    address: &str,
    code: &str,
    device_name: &str,
    password: Option<&str>,
    output: VideoOutput,
) -> Result<Session> {
    let code = PairingCode::parse(code)?;
    let params = ConnectParams {
        addr: resolve(address).await?,
        host_fingerprint: code.host,
        identity: state.load_or_create_identity()?,
        device_name: device_name.to_string(),
        pairing_secret: Some(code.secret),
        password: password.map(str::to_string),
    };
    let session = crate::connect(params, output).await?;
    remember(state, &session.host_name, address, code.host)?;
    Ok(session)
}

/// Pairs like [`pair`] without opening a session: over a file connection, closed right away.
/// Returns the host's name.
pub async fn pair_quietly(
    state: &StateDir,
    address: &str,
    code: &str,
    device_name: &str,
    password: Option<&str>,
) -> Result<String> {
    let code = PairingCode::parse(code)?;
    let params = ConnectParams {
        addr: resolve(address).await?,
        host_fingerprint: code.host,
        identity: state.load_or_create_identity()?,
        device_name: device_name.to_string(),
        pairing_secret: Some(code.secret),
        password: password.map(str::to_string),
    };
    let session = crate::connect_files(params).await?;
    remember(state, &session.host_name, address, code.host)?;
    Ok(session.host_name.clone())
}

/// Connects to a paired host by name or address. Fails with [`crate::PasswordRequired`] like
/// [`pair`].
pub async fn connect(
    state: &StateDir,
    host: &str,
    device_name: &str,
    password: Option<&str>,
    output: VideoOutput,
) -> Result<Session> {
    crate::connect(known_params(state, host, device_name, password).await?, output).await
}

/// Connects to a paired host for file transfers only. Fails with [`crate::PasswordRequired`]
/// like [`pair`].
pub async fn connect_files(
    state: &StateDir,
    host: &str,
    device_name: &str,
    password: Option<&str>,
) -> Result<FilesSession> {
    crate::connect_files(known_params(state, host, device_name, password).await?).await
}

async fn known_params(
    state: &StateDir,
    host: &str,
    device_name: &str,
    password: Option<&str>,
) -> Result<ConnectParams> {
    let hosts = list(state)?;
    let known = hosts
        .iter()
        .find(|h| h.name == host || h.address == host)
        .with_context(|| format!("'{host}' is not paired yet"))?;
    Ok(ConnectParams {
        addr: resolve(&known.address).await?,
        host_fingerprint: Fingerprint::from_base64(&known.fingerprint)?,
        identity: state.load_or_create_identity()?,
        device_name: device_name.to_string(),
        pairing_secret: None,
        password: password.map(str::to_string),
    })
}

/// Resolves `ip[:port]` or `hostname[:port]`, defaulting to the standard port.
pub async fn resolve(address: &str) -> Result<SocketAddr> {
    let target = with_default_port(address);
    let mut addrs = tokio::net::lookup_host(&target).await.with_context(|| format!("resolving {target}"))?;
    addrs.next().with_context(|| format!("no address for {target}"))
}

fn with_default_port(address: &str) -> String {
    if address.parse::<SocketAddr>().is_ok() {
        return address.to_string();
    }
    if let Ok(ip) = address.parse::<IpAddr>() {
        return SocketAddr::new(ip, DEFAULT_PORT).to_string();
    }
    match address.rsplit_once(':') {
        Some((_, port)) if port.parse::<u16>().is_ok() => address.to_string(),
        _ => format!("{address}:{DEFAULT_PORT}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolves_addresses() {
        assert_eq!(resolve("127.0.0.1").await.unwrap().port(), DEFAULT_PORT);
        assert_eq!(resolve("127.0.0.1:9000").await.unwrap().port(), 9000);
        assert_eq!(resolve("::1").await.unwrap().port(), DEFAULT_PORT);
        assert_eq!(resolve("[::1]:9000").await.unwrap().port(), 9000);
        assert_eq!(resolve("localhost:9000").await.unwrap().port(), 9000);
    }
}
