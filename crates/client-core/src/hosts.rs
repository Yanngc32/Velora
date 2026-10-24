//! Paired hosts: pairing, lookup and connection by name, shared by every client UI.

use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use anyhow::{Context, Result};
use velora_protocol::{
    identity::{ConnectMode, KnownHost, StateDir},
    pairing::PairingCode,
    tls::Fingerprint,
    wire::DEFAULT_PORT,
};

use crate::{
    reach::{self, ReachInfo, ReachParams, WakeOutcome},
    ConnectParams, FilesSession, Session, VideoOutput,
};

/// Changes to the known-hosts file are read, edited and written one at a time in this process: what a host says about
/// reaching it arrives while its session already runs, in the middle of the other changes.
static KNOWN_HOSTS: Mutex<()> = Mutex::new(());

fn exclusive() -> MutexGuard<'static, ()> {
    KNOWN_HOSTS.lock().unwrap_or_else(PoisonError::into_inner)
}

pub fn list(state: &StateDir) -> Result<Vec<KnownHost>> {
    state.load(StateDir::KNOWN_HOSTS)
}

pub fn forget(state: &StateDir, name: &str) -> Result<()> {
    let _exclusive = exclusive();
    let mut hosts = list(state)?;
    hosts.retain(|h| h.name != name);
    state.save(StateDir::KNOWN_HOSTS, &hosts)
}

/// Sets the ways in connections to the paired host called `name` may take (see [`ConnectMode`]).
pub fn set_mode(state: &StateDir, name: &str, mode: ConnectMode) -> Result<()> {
    let _exclusive = exclusive();
    let mut hosts = list(state)?;
    let host = hosts.iter_mut().find(|h| h.name == name).with_context(|| format!("'{name}' is not paired"))?;
    host.mode = mode;
    state.save(StateDir::KNOWN_HOSTS, &hosts)
}

/// Saves a paired host. `also`: its other addresses, as it told them (it may list `address`).
fn remember(state: &StateDir, name: &str, address: &str, also: &[String], fingerprint: Fingerprint) -> Result<()> {
    let _exclusive = exclusive();
    let mut hosts = list(state)?;
    let fp = fingerprint.to_base64();
    // Pairing again with a host already known keeps what it said about reaching it (kinds, key, secret, relays, MAC): it
    // says it again on the first connection, and until then the old values are the best there are.
    let previous = hosts.iter().find(|h| h.fingerprint == fp).cloned().unwrap_or_default();
    hosts.retain(|h| h.fingerprint != fp && h.name != name);
    let also = also.iter().filter(|a| *a != address).cloned().collect();
    hosts.push(KnownHost { name: name.to_string(), address: address.to_string(), fingerprint: fp, also, ..previous });
    state.save(StateDir::KNOWN_HOSTS, &hosts)
}

/// Keeps the other addresses a paired host just told about, for the next connection.
fn learn(state: &StateDir, name: &str, addresses: &[String]) -> Result<()> {
    if addresses.is_empty() {
        return Ok(());
    }
    let _exclusive = exclusive();
    let mut hosts = list(state)?;
    let Some(host) = hosts.iter_mut().find(|h| h.name == name) else { return Ok(()) };
    let also: Vec<String> = addresses.iter().filter(|a| **a != host.address).cloned().collect();
    if host.also == also {
        return Ok(());
    }
    host.also = also;
    state.save(StateDir::KNOWN_HOSTS, &hosts)
}

/// Keeps what a host just said about reaching it from other networks (see `HostMsg::Reach`), for the next connection.
/// The host is found by `fingerprint`, since its name may have changed since it was paired. The address list and the
/// relay list replace the old ones whole: what the host says now is what is true. The key, the secret and the MAC replace
/// the old ones only when the host sent one: a host with no DHT record sends zeros, and one that could not read its MAC
/// this time is no reason to forget the MAC it read before. Returns whether the file changed.
fn store_reach(state: &StateDir, fingerprint: &str, info: &ReachInfo) -> Result<bool> {
    let _exclusive = exclusive();
    let mut hosts = list(state)?;
    let Some(host) = hosts.iter_mut().find(|h| h.fingerprint == fingerprint) else { return Ok(false) };
    let before = host.clone();
    host.kinds = info.addresses.clone();
    host.relays = info.relays.clone();
    host.key = info.key.or(host.key);
    host.secret = info.secret.or(host.secret);
    host.mac = info.mac.or(host.mac);
    if *host == before {
        return Ok(false);
    }
    state.save(StateDir::KNOWN_HOSTS, &hosts)?;
    Ok(true)
}

/// A second handle on the same state directory. `StateDir` is not `Clone`, and the callback that saves what the host says
/// outlives the borrow `connect` was given.
fn reopen(state: &StateDir) -> Option<StateDir> {
    let dir = state.dir();
    StateDir::open(Some(dir.parent()?.to_path_buf()), dir.file_name()?.to_str()?).ok()
}

/// Has [`store_reach`] run whenever the host of `session` tells how else it can be reached. A host that predates
/// standalone reach never does, and the file stays as it was.
fn keep_reach(state: &StateDir, session: &Session, host: Fingerprint) {
    let Some(state) = reopen(state) else {
        tracing::debug!("cannot save how to reach the host: no second handle on the state directory");
        return;
    };
    let host = host.to_base64();
    session.on_reach(Arc::new(move |info| {
        if let Err(e) = store_reach(&state, &host, info) {
            tracing::warn!("could not save how to reach the host: {e:#}");
        }
    }));
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
    keep_reach(state, &session, code.host);
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
        // Nothing is known of how else to reach a host being paired for the first time.
        reach: None,
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
    let params = known_params(state, host, device_name, password).await?;
    let fingerprint = params.host_fingerprint;
    let session = crate::connect(params, output).await?;
    if let Err(e) = learn(state, &session.host_name, &session.addresses) {
        tracing::warn!("could not save the host's addresses: {e:#}");
    }
    keep_reach(state, &session, fingerprint);
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

/// Wakes a paired host that is asleep, by Wake-on-LAN: from this device's own network when it is on the host's, through
/// a relay on the host's network otherwise (see [`reach::wake`]). `host` is a name or an address, as for [`connect`].
/// When there is nothing to do it says so, in the [`WakeOutcome`], rather than failing: the host reported no MAC address
/// (`Unsupported`), or this device is away from the host's network and no relay could send the packet (`NoRelay`).
pub async fn wake(state: &StateDir, host: &str) -> Result<WakeOutcome> {
    let paired = paired(state, host)?;
    reach::wake(&state.load_or_create_identity()?, &paired).await
}

/// The paired host called `host`, by name or by its main address.
fn paired(state: &StateDir, host: &str) -> Result<KnownHost> {
    list(state)?
        .into_iter()
        .find(|h| h.name == host || h.address == host)
        .with_context(|| format!("'{host}' is not paired yet"))
}

async fn known_params(
    state: &StateDir,
    host: &str,
    device_name: &str,
    password: Option<&str>,
) -> Result<ConnectParams> {
    let known = paired(state, host)?;
    let (addr, also) = resolve_all(&known.address, &known.also).await?;
    Ok(ConnectParams {
        addr,
        also,
        host_fingerprint: Fingerprint::from_base64(&known.fingerprint)?,
        identity: state.load_or_create_identity()?,
        device_name: device_name.to_string(),
        pairing_secret: None,
        password: password.map(str::to_string),
        reach: Some(ReachParams { host: known, state_dir: state.dir().to_path_buf() }),
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
    use std::time::Duration;

    use velora_protocol::wire::AddressKind;

    use super::*;
    use crate::testing::{eventually, reach_msg, sink, within, FakeHost, Script, TempDir};

    #[tokio::test]
    async fn resolves_addresses() {
        assert_eq!(resolve("127.0.0.1").await.unwrap().port(), DEFAULT_PORT);
        assert_eq!(resolve("127.0.0.1:9000").await.unwrap().port(), 9000);
        assert_eq!(resolve("::1").await.unwrap().port(), DEFAULT_PORT);
        assert_eq!(resolve("[::1]:9000").await.unwrap().port(), 9000);
        assert_eq!(resolve("localhost:9000").await.unwrap().port(), 9000);
    }

    fn state(temp: &TempDir) -> StateDir {
        StateDir::open(Some(temp.path().to_path_buf()), "client").unwrap()
    }

    fn info() -> ReachInfo {
        ReachInfo {
            addresses: vec![
                (AddressKind::Lan, "192.0.2.10:7420".into()),
                (AddressKind::Public, "198.51.100.7:51820".into()),
            ],
            key: Some([7; 32]),
            secret: Some([9; 16]),
            relays: vec![("relay".into(), vec!["203.0.113.9:7420".into()])],
            mac: Some([0x02, 1, 2, 3, 4, 5]),
            relays_for_others: false,
        }
    }

    const FINGERPRINT: Fingerprint = Fingerprint([1; 32]);

    #[test]
    fn pairing_again_keeps_what_the_host_said_about_reaching_it() {
        let temp = TempDir::new();
        let state = state(&temp);
        remember(&state, "pc", "192.0.2.10:7420", &["198.51.100.7:51820".to_string()], FINGERPRINT).unwrap();
        assert!(store_reach(&state, &FINGERPRINT.to_base64(), &info()).unwrap());
        let known = list(&state).unwrap();

        // A second pairing, with a new name and address, replaces those and the addresses the host told, not the rest.
        remember(&state, "pc renamed", "192.0.2.99:7420", &[], FINGERPRINT).unwrap();
        let again = list(&state).unwrap();
        assert_eq!(again.len(), 1);
        assert_eq!((again[0].name.as_str(), again[0].address.as_str()), ("pc renamed", "192.0.2.99:7420"));
        assert_eq!(again[0].also, Vec::<String>::new());
        assert_eq!(
            KnownHost {
                name: known[0].name.clone(),
                address: known[0].address.clone(),
                also: known[0].also.clone(),
                ..again[0].clone()
            },
            known[0]
        );
        assert_eq!(
            (again[0].key, again[0].secret, again[0].mac),
            (Some([7; 32]), Some([9; 16]), Some([0x02, 1, 2, 3, 4, 5]))
        );
        assert_eq!(again[0].kinds.len(), 2);
        assert_eq!(again[0].relays.len(), 1);
    }

    #[test]
    fn another_host_with_the_same_name_keeps_nothing_of_the_old_one() {
        let temp = TempDir::new();
        let state = state(&temp);
        remember(&state, "pc", "192.0.2.10:7420", &[], FINGERPRINT).unwrap();
        store_reach(&state, &FINGERPRINT.to_base64(), &info()).unwrap();
        remember(&state, "pc", "192.0.2.10:7420", &[], Fingerprint([2; 32])).unwrap();
        let hosts = list(&state).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].fingerprint, Fingerprint([2; 32]).to_base64());
        assert_eq!((hosts[0].key, hosts[0].secret, hosts[0].mac), (None, None, None));
        assert!(hosts[0].kinds.is_empty() && hosts[0].relays.is_empty());
    }

    #[test]
    fn what_the_host_says_replaces_the_lists_and_zeros_keep_the_old_key_secret_and_mac() {
        let temp = TempDir::new();
        let state = state(&temp);
        remember(&state, "pc", "192.0.2.10:7420", &[], FINGERPRINT).unwrap();
        let fp = FINGERPRINT.to_base64();
        assert!(store_reach(&state, &fp, &info()).unwrap());

        // Later it has a different address, no relay, no DHT record and could not read its MAC.
        let later = ReachInfo {
            addresses: vec![(AddressKind::Lan, "192.0.2.11:7420".into())],
            key: None,
            secret: None,
            relays: Vec::new(),
            mac: None,
            relays_for_others: true,
        };
        assert!(store_reach(&state, &fp, &later).unwrap());
        let host = list(&state).unwrap().remove(0);
        assert_eq!(host.kinds, vec![(AddressKind::Lan, "192.0.2.11:7420".to_string())]);
        assert!(host.relays.is_empty());
        assert_eq!((host.key, host.secret, host.mac), (Some([7; 32]), Some([9; 16]), Some([0x02, 1, 2, 3, 4, 5])));

        // A new key and MAC do replace the old ones.
        let rotated = ReachInfo { key: Some([8; 32]), mac: Some([0x02, 9, 9, 9, 9, 9]), ..later };
        assert!(store_reach(&state, &fp, &rotated).unwrap());
        let host = list(&state).unwrap().remove(0);
        assert_eq!((host.key, host.mac), (Some([8; 32]), Some([0x02, 9, 9, 9, 9, 9])));
        assert_eq!(host.secret, Some([9; 16]));
    }

    #[test]
    fn saying_the_same_again_does_not_write_the_file() {
        let temp = TempDir::new();
        let state = state(&temp);
        remember(&state, "pc", "192.0.2.10:7420", &[], FINGERPRINT).unwrap();
        let fp = FINGERPRINT.to_base64();
        assert!(store_reach(&state, &fp, &info()).unwrap());
        assert!(!store_reach(&state, &fp, &info()).unwrap());
        // A host that is not paired (forgotten while the session ran) is left alone too.
        assert!(!store_reach(&state, &Fingerprint([3; 32]).to_base64(), &info()).unwrap());
        assert_eq!(list(&state).unwrap().len(), 1);
    }

    #[test]
    fn a_reopened_state_directory_is_the_same_one() {
        let temp = TempDir::new();
        let state = state(&temp);
        let again = reopen(&state).unwrap();
        assert_eq!(again.dir(), state.dir());
        remember(&again, "pc", "192.0.2.10:7420", &[], FINGERPRINT).unwrap();
        assert_eq!(list(&state).unwrap().len(), 1);
    }

    #[tokio::test]
    async fn connecting_remembers_what_the_host_says_about_reaching_it() {
        let temp = TempDir::new();
        let state = state(&temp);
        let host = FakeHost::start(Script { reach: Some(reach_msg()), ..Default::default() });
        state.save(StateDir::KNOWN_HOSTS, &vec![host.entry()]).unwrap();

        let session = within("connect", connect(&state, "fake-pc", "test device", None, sink())).await.unwrap();
        let stored =
            eventually("the stored reach data", || list(&state).unwrap().into_iter().find(|h| h.key.is_some())).await;
        assert_eq!(
            stored,
            KnownHost {
                // What the welcome said (see `learn`) and what `Reach` said.
                also: vec!["192.0.2.10:7420".into()],
                kinds: vec![
                    (AddressKind::Lan, "192.0.2.10:7420".into()),
                    (AddressKind::Public, "198.51.100.7:51820".into())
                ],
                key: Some([7; 32]),
                secret: Some([9; 16]),
                relays: vec![(Fingerprint([5; 32]).to_base64(), vec!["203.0.113.9:7420".into()])],
                mac: Some([0x02, 1, 2, 3, 4, 5]),
                ..host.entry()
            }
        );
        session.close();
    }

    #[tokio::test]
    async fn connecting_to_a_host_without_reach_leaves_the_entry_as_it_always_was() {
        let temp = TempDir::new();
        let state = state(&temp);
        let host = FakeHost::start(Script::default());
        state.save(StateDir::KNOWN_HOSTS, &vec![host.entry()]).unwrap();

        let session = within("connect", connect(&state, "fake-pc", "test device", None, sink())).await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        // Only what the welcome told: the same file the version before reach would have written.
        assert_eq!(list(&state).unwrap(), vec![KnownHost { also: vec!["192.0.2.10:7420".into()], ..host.entry() }]);
        let written = std::fs::read_to_string(state.path(StateDir::KNOWN_HOSTS)).unwrap();
        for field in ["kinds", "\"key\"", "secret", "relays", "mac"] {
            assert!(!written.contains(field), "{field} in {written}");
        }
        session.close();
    }

    #[tokio::test]
    async fn pairing_stores_the_host_and_then_what_it_says_about_reaching_it() {
        let temp = TempDir::new();
        let state = state(&temp);
        let host = FakeHost::start(Script { reach: Some(reach_msg()), ..Default::default() });
        let code = PairingCode { host: host.identity.fingerprint(), secret: [4; 16] }.encode();
        let session = within("pair", pair(&state, &host.addr.to_string(), &[], &code, "test device", None, sink()))
            .await
            .unwrap();
        let stored =
            eventually("the stored reach data", || list(&state).unwrap().into_iter().find(|h| h.key.is_some())).await;
        assert_eq!((stored.name.as_str(), stored.fingerprint.as_str()), ("fake-pc", host.entry().fingerprint.as_str()));
        assert_eq!(stored.secret, Some([9; 16]));
        session.close();
    }

    #[test]
    fn the_mode_is_kept_through_pairing_again_and_unknown_hosts_are_an_error() {
        let temp = TempDir::new();
        let state = state(&temp);
        remember(&state, "pc", "192.0.2.10:7420", &[], FINGERPRINT).unwrap();
        set_mode(&state, "pc", ConnectMode::Lan).unwrap();
        remember(&state, "pc", "192.0.2.11:7420", &[], FINGERPRINT).unwrap();
        assert_eq!(list(&state).unwrap()[0].mode, ConnectMode::Lan);
        assert!(set_mode(&state, "nobody", ConnectMode::Vpn).is_err());
    }

    #[tokio::test]
    async fn waking_a_host_that_is_not_paired_is_an_error_and_one_without_a_mac_is_unsupported() {
        let temp = TempDir::new();
        let state = state(&temp);
        assert!(wake(&state, "nobody").await.unwrap_err().to_string().contains("is not paired yet"));
        remember(&state, "pc", "192.0.2.10:7420", &[], FINGERPRINT).unwrap();
        assert_eq!(wake(&state, "pc").await.unwrap(), WakeOutcome::Unsupported);
        assert_eq!(wake(&state, "192.0.2.10:7420").await.unwrap(), WakeOutcome::Unsupported);
    }
}
