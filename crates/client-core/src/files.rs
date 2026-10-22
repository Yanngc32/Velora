//! File transfers with a host that announces [`velora_protocol::wire::FEATURE_FILES`]: browsing
//! and moving files with [`RemoteFiles`], and receiving what the host sends (Send To).

use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use anyhow::{bail, Result};
use velora_protocol::files::{self, Entry, FileMsg, Tree};

pub use velora_protocol::files::{Entry as RemoteEntry, EntryKind};

/// The host's file system. Cheap to clone; each call is its own stream, so calls can run at
/// the same time.
#[derive(Clone)]
pub struct RemoteFiles {
    pub(crate) conn: quinn::Connection,
}

impl RemoteFiles {
    /// Drives and well-known folders (Downloads, Desktop, ...) of the user signed in there.
    pub async fn roots(&self) -> Result<Vec<Entry>> {
        let (mut send, mut recv) = self.conn.open_bi().await?;
        files::request_list(&mut recv, &mut send, None).await
    }

    /// The entries of a folder, folders first.
    pub async fn list(&self, path: &str) -> Result<Vec<Entry>> {
        let (mut send, mut recv) = self.conn.open_bi().await?;
        files::request_list(&mut recv, &mut send, Some(path)).await
    }

    /// Copies the host's `path` (file or folder) into the local folder `dest`. Returns the
    /// names it got there (`foto (1).jpg` when `foto.jpg` existed). `progress` gets bytes done
    /// and the total.
    pub async fn download(&self, path: &str, dest: &Path, progress: files::Progress<'_>) -> Result<Vec<String>> {
        let (mut send, mut recv) = self.conn.open_bi().await?;
        files::request_download(&mut recv, &mut send, path, dest, progress).await
    }

    /// Copies local files and folders into the host's folder `dir` (empty: its Downloads).
    /// Returns the names they got there.
    pub async fn upload(&self, sources: Vec<PathBuf>, dir: &str, progress: files::Progress<'_>) -> Result<Vec<String>> {
        let tree = tokio::task::spawn_blocking(move || Tree::gather(&sources)).await??;
        let (mut send, mut recv) = self.conn.open_bi().await?;
        files::request_send(&mut recv, &mut send, FileMsg::Upload { dir: dir.to_string() }, &tree, progress).await
    }
}

/// What happens to files the host sends (Send To on the host).
#[derive(Debug, Clone)]
pub enum OfferEvent {
    Progress {
        id: u64,
        done: u64,
        total: u64,
    },
    /// Saved into the destination folder under these names.
    Saved {
        id: u64,
        names: Vec<String>,
    },
    Failed {
        id: u64,
        error: String,
    },
}

/// Accepts the host's file streams until the connection closes, saving offered files into
/// `dest`.
pub(crate) async fn receive_offers(
    conn: quinn::Connection,
    dest: PathBuf,
    on_event: Arc<dyn Fn(OfferEvent) + Send + Sync>,
) {
    let ids = Arc::new(AtomicU64::new(0));
    while let Ok((send, recv)) = conn.accept_bi().await {
        let id = ids.fetch_add(1, Ordering::Relaxed);
        let (dest, on_event) = (dest.clone(), on_event.clone());
        tokio::spawn(async move {
            if let Err(e) = receive_offer(send, recv, &dest, id, &on_event).await {
                on_event(OfferEvent::Failed { id, error: format!("{e:#}") });
            }
        });
    }
}

async fn receive_offer(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    dest: &Path,
    id: u64,
    on_event: &Arc<dyn Fn(OfferEvent) + Send + Sync>,
) -> Result<()> {
    if files::read(&mut recv).await? != Some(FileMsg::Offer) {
        bail!("the host sent an unknown file request");
    }
    let mut progress = |done, total| on_event(OfferEvent::Progress { id, done, total });
    match files::receive_tree(&mut recv, dest, &mut progress).await {
        Ok(names) => {
            files::write(&mut send, &FileMsg::Saved { names: names.clone() }).await?;
            send.finish()?;
            on_event(OfferEvent::Saved { id, names });
            Ok(())
        }
        Err(e) => {
            let _ = files::write(&mut send, &FileMsg::Error { message: format!("{e:#}") }).await;
            let _ = send.finish();
            Err(e)
        }
    }
}
