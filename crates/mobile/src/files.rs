//! File transfers for the apps: browsing a computer's files, moving files both ways, and
//! saving what the computer sends during a session (Send To → Velora there).
//!
//! Like the rest of the API, calls that touch the network block and must run off the UI
//! thread. Progress reaches the listeners from background threads, a few times a second.

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use velora_client_core::{
    files::{EntryKind, OfferEvent, RemoteEntry},
    hosts, FilesSession, RemoteFiles,
};

use crate::{runtime, Client, MobileError, Result, Session};

/// How often progress is reported, at most (the end always is).
const PROGRESS_EVERY: Duration = Duration::from_millis(150);

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FileKind {
    File,
    Folder,
    /// A drive or a well-known folder (Downloads, Desktop, ...), as [`Files::roots`] lists them.
    Place,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FileEntry {
    pub name: String,
    /// Full path on the computer: pass it back to [`Files::list`] or [`Files::download`].
    pub path: String,
    pub kind: FileKind,
    pub size: u64,
    pub modified_unix: u64,
}

impl From<RemoteEntry> for FileEntry {
    fn from(e: RemoteEntry) -> Self {
        let kind = match e.kind {
            EntryKind::File => FileKind::File,
            EntryKind::Dir => FileKind::Folder,
            EntryKind::Place => FileKind::Place,
        };
        Self { name: e.name, path: e.path, kind, size: e.size, modified_unix: e.modified_unix }
    }
}

/// Implemented by the app: progress of one upload or download. Called from background threads.
#[uniffi::export(with_foreign)]
pub trait TransferListener: Send + Sync {
    /// Bytes done out of `total`.
    fn on_progress(&self, done: u64, total: u64);
}

/// Implemented by the app: files the computer sends during a session. `id` tells transfers
/// apart. Called from background threads.
#[uniffi::export(with_foreign)]
pub trait OfferListener: Send + Sync {
    fn on_offer_progress(&self, id: u64, done: u64, total: u64);
    /// Saved into the destination folder under these names (files or folders).
    fn on_offer_saved(&self, id: u64, names: Vec<String>);
    fn on_offer_failed(&self, id: u64, error: String);
}

/// A computer's files. Calls can run at the same time, each on its own thread.
#[derive(uniffi::Object)]
pub struct Files {
    host_name: String,
    remote: RemoteFiles,
    /// The files-only connection, when [`Client::open_files`] opened one; dropping it closes it.
    connection: Mutex<Option<FilesSession>>,
}

impl Files {
    fn new(host_name: String, remote: RemoteFiles, connection: Option<FilesSession>) -> Arc<Self> {
        Arc::new(Self { host_name, remote, connection: Mutex::new(connection) })
    }
}

#[uniffi::export]
impl Files {
    pub fn host_name(&self) -> String {
        self.host_name.clone()
    }

    /// The computer's drives and well-known folders (Downloads, Desktop, ...). Blocking.
    pub fn roots(&self) -> Result<Vec<FileEntry>> {
        let entries = runtime().block_on(self.remote.roots())?;
        Ok(entries.into_iter().map(FileEntry::from).collect())
    }

    /// The entries of a folder on the computer, folders first. Blocking.
    pub fn list(&self, path: String) -> Result<Vec<FileEntry>> {
        let entries = runtime().block_on(self.remote.list(&path))?;
        Ok(entries.into_iter().map(FileEntry::from).collect())
    }

    /// Copies the computer's `path` (a file or a whole folder) into the local folder
    /// `dest_dir`, created if missing. Returns the names it got there (`foto (1).jpg` when
    /// `foto.jpg` existed). Blocking.
    pub fn download(&self, path: String, dest_dir: String, listener: Arc<dyn TransferListener>) -> Result<Vec<String>> {
        let dest = PathBuf::from(dest_dir);
        std::fs::create_dir_all(&dest).map_err(|e| MobileError::Failed(format!("creating {}: {e}", dest.display())))?;
        let mut progress = throttled(listener);
        Ok(runtime().block_on(self.remote.download(&path, &dest, &mut progress))?)
    }

    /// Copies local files and folders (`sources`, absolute paths) into the computer's folder
    /// `dir`; an empty `dir` means its Downloads folder. The computer may ask its user first,
    /// so this can wait a while. Returns the names they got there. Blocking.
    pub fn upload(
        &self,
        sources: Vec<String>,
        dir: String,
        listener: Arc<dyn TransferListener>,
    ) -> Result<Vec<String>> {
        if sources.is_empty() {
            return Err(MobileError::Failed("nothing to send".into()));
        }
        let sources = sources.into_iter().map(PathBuf::from).collect();
        let mut progress = throttled(listener);
        Ok(runtime().block_on(self.remote.upload(sources, &dir, &mut progress))?)
    }

    /// Closes the files-only connection, which also stops transfers under way. Does nothing
    /// for the files of a session (end the session instead). (`close()` on the Kotlin object
    /// only frees the handle.)
    pub fn disconnect(&self) {
        if let Some(connection) = self.connection.lock().unwrap().take() {
            connection.close();
        }
    }
}

#[uniffi::export]
impl Client {
    /// Connects to a paired computer for file transfers only: no video, and a session someone
    /// has with it carries on. Blocking. Fails like [`Client::connect`] when a password is
    /// needed, or when the computer's Velora is too old for file transfers.
    pub fn open_files(&self, host: String, password: Option<String>) -> Result<Arc<Files>> {
        let session =
            runtime().block_on(hosts::connect_files(&self.state, &host, &self.device_name, password.as_deref()))?;
        Ok(Files::new(session.host_name.clone(), session.files.clone(), Some(session)))
    }
}

#[uniffi::export]
impl Session {
    /// The computer's files over this session's connection; `None` when its Velora is too old
    /// for file transfers.
    pub fn files(&self) -> Option<Arc<Files>> {
        let remote = self.inner.files()?;
        Some(Files::new(self.inner.host_name.clone(), remote, None))
    }

    /// Saves files the computer sends during this session (Send To → Velora there) into the
    /// local folder `dest_dir`, created if missing, and reports them to `listener`. Call once.
    pub fn receive_files(&self, dest_dir: String, listener: Arc<dyn OfferListener>) {
        let dest = PathBuf::from(dest_dir);
        if let Err(e) = std::fs::create_dir_all(&dest) {
            tracing::warn!("cannot receive files into {}: {e}", dest.display());
        }
        // The computer's clipboard also arrives on these streams; the apps don't take it (yet).
        self.inner.receive_files(dest, offer_handler(listener), Arc::new(|_, _| {}));
    }
}

/// Reports progress to `listener` at most every [`PROGRESS_EVERY`], and always at the end.
fn throttled(listener: Arc<dyn TransferListener>) -> impl FnMut(u64, u64) + Send {
    let mut last: Option<Instant> = None;
    move |done, total| {
        let now = Instant::now();
        if done >= total || last.is_none_or(|t| now.duration_since(t) >= PROGRESS_EVERY) {
            last = Some(now);
            listener.on_progress(done, total);
        }
    }
}

/// Turns the core's offer events into `listener` calls, progress throttled per transfer.
fn offer_handler(listener: Arc<dyn OfferListener>) -> Arc<dyn Fn(OfferEvent) + Send + Sync> {
    let last = Mutex::new(HashMap::<u64, Instant>::new());
    Arc::new(move |event| match event {
        OfferEvent::Progress { id, done, total } => {
            let now = Instant::now();
            let due = {
                let mut last = last.lock().unwrap();
                let due = done >= total || last.get(&id).is_none_or(|t| now.duration_since(*t) >= PROGRESS_EVERY);
                if due {
                    last.insert(id, now);
                }
                due
            };
            if due {
                listener.on_offer_progress(id, done, total);
            }
        }
        OfferEvent::Saved { id, names } => {
            last.lock().unwrap().remove(&id);
            listener.on_offer_saved(id, names);
        }
        OfferEvent::Failed { id, error } => {
            last.lock().unwrap().remove(&id);
            listener.on_offer_failed(id, error);
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use velora_protocol::{
        files::{self, FileMsg, Tree},
        identity::Identity,
        tls,
    };

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("velora-mobile-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A computer answering every file stream on its own file system, and the app's side of the
    /// connection to it.
    fn connect() -> (quinn::Connection, quinn::Connection) {
        runtime().block_on(async {
            let (host, client) = (Identity::generate().unwrap(), Identity::generate().unwrap());
            let endpoint =
                quinn::Endpoint::server(tls::server_config(&host).unwrap(), "127.0.0.1:0".parse().unwrap()).unwrap();
            let addr = endpoint.local_addr().unwrap();
            let (tx, rx) = tokio::sync::oneshot::channel();
            tokio::spawn(async move {
                let conn = endpoint.accept().await.unwrap().await.unwrap();
                let _ = tx.send(conn.clone());
                while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                    tokio::spawn(async move {
                        let _ = files::serve(&mut recv, &mut send).await;
                    });
                }
                drop(endpoint);
            });
            let mut client_ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            client_ep.set_default_client_config(tls::client_config(&client, host.fingerprint()).unwrap());
            let conn = client_ep.connect(addr, tls::SERVER_NAME).unwrap().await.unwrap();
            (conn, rx.await.unwrap())
        })
    }

    #[derive(Default)]
    struct Progress(Mutex<Vec<(u64, u64)>>);

    impl TransferListener for Progress {
        fn on_progress(&self, done: u64, total: u64) {
            self.0.lock().unwrap().push((done, total));
        }
    }

    #[derive(Default)]
    struct Offers {
        saved: Mutex<Vec<(u64, Vec<String>)>>,
        failed: Mutex<Vec<String>>,
        progress: Mutex<Vec<(u64, u64)>>,
    }

    impl OfferListener for Offers {
        fn on_offer_progress(&self, _id: u64, done: u64, total: u64) {
            self.progress.lock().unwrap().push((done, total));
        }
        fn on_offer_saved(&self, id: u64, names: Vec<String>) {
            self.saved.lock().unwrap().push((id, names));
        }
        fn on_offer_failed(&self, _id: u64, error: String) {
            self.failed.lock().unwrap().push(error);
        }
    }

    #[test]
    fn upload_list_and_download() {
        let (conn, _host) = connect();
        let files = Files::new("pc".into(), RemoteFiles::new(conn), None);
        let (phone, pc, back) = (temp_dir("phone"), temp_dir("pc"), temp_dir("back"));
        std::fs::write(phone.join("foto.jpg"), vec![7u8; 2_000_000]).unwrap();
        std::fs::write(phone.join("nota.txt"), b"oi").unwrap();
        let sources = vec![phone.join("foto.jpg").display().to_string(), phone.join("nota.txt").display().to_string()];

        let progress = Arc::new(Progress::default());
        let saved = files.upload(sources.clone(), pc.display().to_string(), progress.clone()).unwrap();
        assert_eq!(saved, ["foto.jpg", "nota.txt"]);
        assert_eq!(progress.0.lock().unwrap().last(), Some(&(2_000_002, 2_000_002)));
        // Again: the names clash, so the computer keeps both.
        let again = files.upload(sources, pc.display().to_string(), Arc::new(Progress::default())).unwrap();
        assert_eq!(again, ["foto (1).jpg", "nota (1).txt"]);

        let listed = files.list(pc.display().to_string()).unwrap();
        let names: Vec<_> = listed.iter().map(|e| (e.name.as_str(), e.kind)).collect();
        assert!(names.contains(&("foto.jpg", FileKind::File)), "{names:?}");
        assert_eq!(listed.len(), 4);
        assert!(!files.roots().unwrap().is_empty());

        let foto = listed.iter().find(|e| e.name == "foto.jpg").unwrap();
        let dest = back.join("Velora");
        let got = files.download(foto.path.clone(), dest.display().to_string(), Arc::new(Progress::default())).unwrap();
        assert_eq!(got, ["foto.jpg"]);
        assert_eq!(std::fs::read(dest.join("foto.jpg")).unwrap(), vec![7u8; 2_000_000]);

        let err = files.list(pc.join("nope").display().to_string()).unwrap_err();
        assert!(err.to_string().contains("nope"), "{err}");

        for dir in [phone, pc, back] {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn offers_land_in_the_destination() {
        let (conn, host) = connect();
        let (pc, phone) = (temp_dir("offer-pc"), temp_dir("offer-phone"));
        std::fs::create_dir_all(pc.join("pasta")).unwrap();
        std::fs::write(pc.join("pasta/a.txt"), b"alpha").unwrap();
        std::fs::write(pc.join("b.bin"), vec![1u8; 1_000_000]).unwrap();

        let offers = Arc::new(Offers::default());
        runtime().spawn(velora_client_core::files::receive_offers(
            conn,
            phone.clone(),
            offer_handler(offers.clone()),
            Arc::new(|_, _| {}),
        ));
        // Send To on the computer.
        let saved = runtime().block_on(async {
            let tree = Tree::gather(&[pc.join("pasta"), pc.join("b.bin")]).unwrap();
            let (mut send, mut recv) = host.open_bi().await.unwrap();
            files::request_send(&mut recv, &mut send, FileMsg::Offer, &tree, &mut |_, _| {}).await.unwrap()
        });
        assert_eq!(saved, ["pasta", "b.bin"]);
        // The phone reports it right after answering.
        let deadline = Instant::now() + Duration::from_secs(5);
        while offers.saved.lock().unwrap().is_empty() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(*offers.saved.lock().unwrap(), [(0, vec!["pasta".to_string(), "b.bin".to_string()])]);
        assert!(offers.failed.lock().unwrap().is_empty());
        assert_eq!(offers.progress.lock().unwrap().last(), Some(&(1_000_005, 1_000_005)));
        assert_eq!(std::fs::read(phone.join("pasta/a.txt")).unwrap(), b"alpha");
        assert_eq!(std::fs::read(phone.join("b.bin")).unwrap().len(), 1_000_000);

        for dir in [pc, phone] {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn progress_is_throttled_but_ends() {
        let progress = Arc::new(Progress::default());
        let mut report = throttled(progress.clone());
        for done in 0..=1000 {
            report(done, 1000);
        }
        let calls = progress.0.lock().unwrap();
        assert!(calls.len() < 10, "{}", calls.len());
        assert_eq!(calls.last(), Some(&(1000, 1000)));
    }
}
