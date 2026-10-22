//! File streams (see `velora_protocol::files`): served on this computer's file system, as the
//! user the host runs as, or, for a host running as the service, through an agent started as
//! the user signed in at the console (see `agent`).

use std::path::PathBuf;

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite};
use velora_protocol::files::{self, FileMsg, Tree};

/// Serves the file streams a device opens, until the connection closes.
pub async fn accept(conn: quinn::Connection, service: bool) -> Result<()> {
    loop {
        let (send, recv) = conn.accept_bi().await?;
        tokio::spawn(async move {
            if let Err(e) = serve(send, recv, service).await {
                tracing::info!("file request failed: {e:#}");
            }
        });
    }
}

async fn serve(mut send: quinn::SendStream, mut recv: quinn::RecvStream, service: bool) -> Result<()> {
    #[cfg(windows)]
    if service {
        return match crate::agent::Agent::spawn(&std::env::current_exe()?, &[]) {
            Ok(agent) => agent.bridge(send, recv).await,
            Err(e) => {
                // Nobody signed in, typically: tell the device why.
                files::write(&mut send, &FileMsg::Error { message: format!("{e:#}") }).await?;
                send.finish()?;
                Err(e)
            }
        };
    }
    let _ = service;
    files::serve(&mut recv, &mut send).await
}

/// Sends `paths` to the device on `conn`, into its Downloads folder, and returns what it saved.
pub async fn offer(conn: quinn::Connection, paths: Vec<PathBuf>, service: bool) -> Result<Vec<String>> {
    let (mut send, mut recv) = conn.open_bi().await?;
    #[cfg(windows)]
    if service {
        let mut args = vec!["--send".to_string()];
        args.extend(paths.iter().map(|p| p.display().to_string()));
        crate::agent::Agent::spawn(&std::env::current_exe()?, &args)?.bridge(send, recv).await?;
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
