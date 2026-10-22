//! Serves the local control channel (see `velora_protocol::control`) for the launcher.

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use velora_protocol::control::{Reply, Request, MAX_LINE};

use crate::server::Shared;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Answers one request. `privileged`: the caller is an administrator or SYSTEM, which a host
/// running as the service requires to change who has access (see `Shared::control`).
async fn handle<S: AsyncRead + AsyncWrite + Unpin>(stream: S, shared: Arc<Shared>, privileged: bool) -> Result<()> {
    let mut stream = BufReader::new(stream);
    let mut line = Vec::new();
    tokio::time::timeout(REQUEST_TIMEOUT, (&mut stream).take(MAX_LINE as u64).read_until(b'\n', &mut line))
        .await
        .context("request timeout")??;
    let reply: Reply = match serde_json::from_slice::<Request>(&line) {
        // Setting a password hashes it, which takes a while.
        Ok(request) => tokio::task::spawn_blocking(move || shared.control(request, privileged)).await?,
        Err(e) => Err(format!("malformed request: {e}")),
    };
    let mut out = serde_json::to_vec(&reply)?;
    out.push(b'\n');
    let stream = stream.get_mut();
    stream.write_all(&out).await?;
    stream.flush().await?;
    Ok(())
}

/// Serves until a pipe instance cannot be created.
#[cfg(windows)]
pub async fn serve(shared: Arc<Shared>) -> Result<()> {
    use std::os::windows::io::AsRawHandle;

    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

    /// How often a service host checks whether someone else logged on at the console.
    const ACCESS_REFRESH: Duration = Duration::from_secs(3);

    let name = velora_protocol::control::endpoint();
    let service = shared.is_service();
    let create = |first: bool, sddl: &str| -> Result<NamedPipeServer> {
        let mut attributes = crate::win::SecurityAttributes::from_sddl(sddl)?;
        let mut options = ServerOptions::new();
        // `first_pipe_instance` refuses to start if another process already owns the name,
        // so nothing else can pose as the host to the launcher through it.
        options.first_pipe_instance(first).reject_remote_clients(true);
        // SAFETY: `attributes` holds a valid SECURITY_ATTRIBUTES that outlives the call.
        unsafe { options.create_with_security_attributes_raw(&name, attributes.as_mut_ptr()) }
            .with_context(|| format!("creating {}", name.display()))
    };
    // A service host follows whoever is logged on at the console.
    let mut sddl = crate::win::pipe_sddl(service);
    let mut server = create(true, &sddl)?;
    loop {
        tokio::select! {
            connected = server.connect() => {
                let next = create(false, &sddl)?;
                let client = std::mem::replace(&mut server, next);
                if let Err(e) = connected {
                    tracing::debug!("control client went away while connecting: {e}");
                    continue;
                }
                let privileged = crate::win::pipe_client_is_admin(client.as_raw_handle());
                let shared = shared.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle(client, shared, privileged).await {
                        tracing::debug!("control request failed: {e:#}");
                    }
                });
            }
            () = tokio::time::sleep(ACCESS_REFRESH), if service => {
                let current = crate::win::pipe_sddl(true);
                if current != sddl {
                    // The waiting instance still carries the old access list.
                    sddl = current;
                    server = create(false, &sddl)?;
                }
            }
        }
    }
}

/// Serves until the socket fails. Only this user can open the socket (mode 0600).
#[cfg(unix)]
pub async fn serve(shared: Arc<Shared>) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let path = velora_protocol::control::endpoint();
    if std::os::unix::net::UnixStream::connect(&path).is_ok() {
        anyhow::bail!("another host already serves {}", path.display());
    }
    // A socket left behind by a host that did not exit cleanly.
    let _ = std::fs::remove_file(&path);
    let listener = tokio::net::UnixListener::bind(&path).with_context(|| format!("binding {}", path.display()))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(e) => {
                tracing::debug!("control accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let shared = shared.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(stream, shared, true).await {
                tracing::debug!("control request failed: {e:#}");
            }
        });
    }
}
