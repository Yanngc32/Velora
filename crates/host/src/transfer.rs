//! File streams (see `velora_protocol::files`): served on this computer's file system, as the
//! user the host runs as, or, for a host running as the service, through an agent started as
//! the user signed in at the console (see `agent`).

use std::{path::PathBuf, sync::Arc};

use anyhow::{bail, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use velora_protocol::{
    files::{self, FileMsg, Tree},
    tls::Fingerprint,
};

use crate::server::Shared;

/// The device whose file streams these are, so the user here can be asked before its files
/// are saved.
#[derive(Clone)]
pub struct Peer {
    pub shared: Arc<Shared>,
    pub name: String,
    pub fingerprint: Fingerprint,
}

/// Serves the file streams a device opens, until the connection closes.
pub async fn accept(conn: quinn::Connection, peer: Peer) -> Result<()> {
    loop {
        let (send, recv) = conn.accept_bi().await?;
        let peer = peer.clone();
        tokio::spawn(async move {
            if let Err(e) = serve(send, recv, peer).await {
                tracing::info!("file request failed: {e:#}");
            }
        });
    }
}

async fn serve(mut send: quinn::SendStream, mut recv: quinn::RecvStream, peer: Peer) -> Result<()> {
    let service = peer.shared.is_service();
    let Some(request) = files::read(&mut recv).await? else { return Ok(()) };
    // Read here, then handed on with the rest of the stream.
    let mut prefix = request.encode();
    let folder = match &request {
        FileMsg::Upload { dir } if !dir.is_empty() => Some(dir.clone()),
        FileMsg::Upload { .. } | FileMsg::Offer => Some("Downloads".to_string()),
        _ => None,
    };
    if let Some(folder) = folder {
        // The tree opens with its size: enough to ask about it before anything is written.
        let total = files::next(&mut recv).await?;
        let FileMsg::Total { bytes } = total else { bail!("expected the transfer size") };
        prefix.extend(total.encode());
        if let Err(why) = peer.shared.ask_to_receive(&peer.name, &peer.fingerprint, bytes, folder).await {
            files::write(&mut send, &FileMsg::Error { message: why.to_string() }).await?;
            send.finish()?;
            return Ok(());
        }
    }
    #[cfg(windows)]
    if service {
        return match crate::agent::Agent::spawn(&std::env::current_exe()?, &[]) {
            Ok(agent) => agent.bridge(&prefix, send, recv).await,
            Err(e) => {
                // Nobody signed in, typically: tell the device why.
                files::write(&mut send, &FileMsg::Error { message: format!("{e:#}") }).await?;
                send.finish()?;
                Err(e)
            }
        };
    }
    let _ = service;
    let mut stream = std::io::Cursor::new(prefix).chain(recv);
    files::serve(&mut stream, &mut send).await
}

/// Sends `paths` to the device on `conn`, into its Downloads folder, and returns what it saved.
pub async fn offer(conn: quinn::Connection, paths: Vec<PathBuf>, service: bool) -> Result<Vec<String>> {
    let (mut send, mut recv) = conn.open_bi().await?;
    #[cfg(windows)]
    if service {
        let mut args = vec!["--send".to_string()];
        args.extend(paths.iter().map(|p| p.display().to_string()));
        crate::agent::Agent::spawn(&std::env::current_exe()?, &args)?.bridge(&[], send, recv).await?;
        return Ok(Vec::new());
    }
    let _ = service;
    send_tree(&mut recv, &mut send, paths).await
}

async fn send_tree<R, W>(r: &mut R, w: &mut W, paths: Vec<PathBuf>) -> Result<Vec<String>>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let tree = tokio::task::spawn_blocking(move || Tree::gather(&paths)).await??;
    files::request_send(r, w, FileMsg::Offer, &tree, &mut |_, _| {}).await
}

/// `velora-host files-agent`: serves one file stream on standard input and output, or with
/// `send`, offers those files to the device. Started by the service's host as the user signed
/// in at the console; standard output carries the stream, so nothing else may write to it.
pub async fn agent(send: Vec<PathBuf>) -> Result<()> {
    let mut input = tokio::io::stdin();
    let mut output = tokio::io::stdout();
    if send.is_empty() {
        files::serve(&mut input, &mut output).await
    } else {
        send_tree(&mut input, &mut output, send).await.map(drop)
    }
}
