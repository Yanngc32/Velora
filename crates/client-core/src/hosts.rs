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

/// Saves a paired host. `also`: its other addresses, as it told them (it may list `address`).
fn remember(state: &StateDir, name: &str, address: &str, also: &[String], fingerprint: Fingerprint) -> Result<()> {
    let mut hosts = list(state)?;
    let fp = fingerprint.to_base64();
    hosts.retain(|h| h.fingerprint != fp && h.name != name);
    let also = also.iter().filter(|a| *a != address).cloned().collect();
    hosts.push(KnownHost { name: name.to_string(), address: address.to_string(), fingerprint: fp, also });
    state.save(StateDir::KNOWN_HOSTS, &hosts)
}

/// Keeps the other addresses a paired host just told about, for the next connection.
fn learn(state: &StateDir, name: &str, addresses: &[String]) -> Result<()> {
    if addresses.is_empty() {
        return Ok(());
    }
    let mut hosts = list(state)?;
    let Some(host) = hosts.iter_mut().find(|h| h.name == name) else { return Ok(()) };
    let also: Vec<String> = addresses.iter().filter(|a| **a != host.address).cloned().collect();
    if host.also == also {
        return Ok(());
    }
    host.also = also;
    state.save(StateDir::KNOWN_HOSTS, &hosts)
}

/// Pairs with the host at `address` (or one of `also`, tried at once) using the code it
/// printed, saves it and returns the established session. Fails with
/// [`crate::PasswordRequired`] when the host has an access password and `password` is missing
/// or wrong; the code stays valid for another try.
pub async fn pair(
    state: &StateDir,
    address: &str,
    also: &[String],
    code: &str,
    device_name: &str,
    password: Option<&str>,
    output: VideoOutput,
) -> Result<Session> {
    let code = PairingCode::parse(code)?;
    let params = pairing_params(state, address, also, &code, device_name, password).await?;
    let session = crate::connect(params, output).await?;
    remember(state, &session.host_name, address, &merged(also, &session.addresses), code.host)?;
    Ok(session)
}

/// Pairs like [`pair`] without opening a session: over a file connection, closed right away.
/// Returns the host's name.
pub async fn pair_quietly(
    state: &StateDir,
    address: &str,
    also: &[String],
    code: &str,
    device_name: &str,
    password: Option<&str>,
) -> Result<String> {
    let code = PairingCode::parse(code)?;
    let params = pairing_params(state, address, also, &code, device_name, password).await?;
    let session = crate::connect_files(params).await?;
    remember(state, &session.host_name, address, &merged(also, &session.addresses), code.host)?;
    Ok(session.host_name.clone())
}

async fn pairing_params(
    state: &StateDir,
    address: &str,
    also: &[String],
    code: &PairingCode,
    device_name: &str,
    password: Option<&str>,
) -> Result<ConnectParams> {
    let (addr, also) = resolve_all(address, also).await?;
    Ok(ConnectParams {
        addr,
        also,
        host_fingerprint: code.host,
        identity: state.load_or_create_identity()?,
        device_name: device_name.to_string(),
        pairing_secret: Some(code.secret),
        password: password.map(str::to_string),
    })
}

/// Addresses from a pairing link and from the host itself, without repeats.
fn merged(link: &[String], told: &[String]) -> Vec<String> {
    let mut out: Vec<String> = told.to_vec();
    out.extend(link.iter().filter(|a| !told.contains(a)).cloned());
    out
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
    let session = crate::connect(known_params(state, host, device_name, password).await?, output).await?;
    if let Err(e) = learn(state, &session.host_name, &session.addresses) {
        tracing::warn!("could not save the host's addresses: {e:#}");
    }
    Ok(session)
}

/// Connects to a paired host for file transfers only. Fails with [`crate::PasswordRequired`]
/// like [`pair`].
pub async fn connect_files(
    state: &StateDir,
    host: &str,
    device_name: &str,
    password: Option<&str>,
) -> Result<FilesSession> {
    let session = crate::connect_files(known_params(state, host, device_name, password).await?).await?;
    if let Err(e) = learn(state, &session.host_name, &session.addresses) {
        tracing::warn!("could not save the host's addresses: {e:#}");
    }
    Ok(session)
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
    let (addr, also) = resolve_all(&known.address, &known.also).await?;
    Ok(ConnectParams {
        addr,
        also,
        host_fingerprint: Fingerprint::from_base64(&known.fingerprint)?,
        identity: state.load_or_create_identity()?,
        device_name: device_name.to_string(),
        pairing_secret: None,
        password: password.map(str::to_string),
    })
}

/// Resolves the main address and the others; the first that resolves leads. Fails only when
/// none does.
async fn resolve_all(address: &str, also: &[String]) -> Result<(SocketAddr, Vec<SocketAddr>)> {
    let mut found = Vec::new();
    let mut first_error = None;
    for candidate in std::iter::once(address).chain(also.iter().map(String::as_str)) {
        match resolve(candidate).await {
            Ok(addr) if !found.contains(&addr) => found.push(addr),
            Ok(_) => {}
            Err(e) => {
                first_error.get_or_insert(e);
            }
        }
    }
    match found.split_first() {
        Some((addr, also)) => Ok((*addr, also.to_vec())),
        None => Err(first_error.unwrap_or_else(|| anyhow::anyhow!("no address for '{address}'"))),
    }
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
