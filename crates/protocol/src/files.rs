//! File transfer streams. Each operation is one bidirectional QUIC stream (or, for a host
//! running as the service, the pipes of a helper process acting as the signed-in user).
//!
//! The opener sends one request, then:
//! - [`FileMsg::Roots`], [`FileMsg::List`]: the other side answers `Entry`* `End`, or `Error`.
//! - [`FileMsg::Download`]: the other side sends a tree, or `Error`.
//! - [`FileMsg::Upload`], [`FileMsg::Offer`]: the opener sends a tree into the given folder
//!   (`Offer`: the receiver's Downloads); the receiver answers `Saved` or `Error`.
//!
//! A tree is `Total`, then `Dir` and `File` items, each `File` followed by exactly `size` raw
//! bytes, then `End`. Item paths are relative and `/`-separated. The receiver checks every
//! component ([`relative_components`]) before touching the disk, writes each file under a
//! temporary name, and renames it only once complete. Top-level names that already exist get a
//! ` (n)` suffix rather than being overwritten.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    time::UNIX_EPOCH,
};

use anyhow::{anyhow, bail, ensure, Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::wire::{Reader, Writer, MAX_CONTROL_MSG};

/// Longest path in a request or item.
pub const MAX_PATH_LEN: usize = 4096;
/// Most items (files and folders) in one listing or transfer.
pub const MAX_ITEMS: usize = 100_000;
const MAX_NAME_LEN: usize = 255;
const MAX_ERROR_LEN: usize = 1024;
/// Suffix of files still being received. Never accepted as a name from the other side.
const PART_SUFFIX: &str = ".velora-part";
const BUFFER: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EntryKind {
    File = 1,
    Dir = 2,
    /// A drive or a well-known folder, listed by [`FileMsg::Roots`].
    Place = 3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    /// Full path on the side that listed it, to pass back in `List` or `Download`.
    pub path: String,
    pub kind: EntryKind,
    pub size: u64,
    pub modified_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileMsg {
    Roots,
    List {
        path: String,
    },
    Download {
        path: String,
    },
    /// Into `dir` on the receiver; empty means its Downloads folder.
    Upload {
        dir: String,
    },
    /// Host to client: files for the client's Downloads folder.
    Offer,
    Entry(Entry),
    /// Total size of the files in the tree that follows.
    Total {
        bytes: u64,
    },
    File {
        path: String,
        size: u64,
    },
    Dir {
        path: String,
    },
    End,
    /// Where a received tree went: its top-level names in the destination folder.
    Saved {
        names: Vec<String>,
    },
    Error {
        message: String,
    },
}

impl FileMsg {
    /// Encodes the message including its u32 length prefix.
    pub fn encode(&self) -> Vec<u8> {
        let path = |tag: u8, p: &str| {
            let mut w = Writer::new(tag);
            w.str_max(p, MAX_PATH_LEN);
            w.finish()
        };
        match self {
            Self::Roots => Writer::new(1).finish(),
            Self::List { path: p } => path(2, p),
            Self::Download { path: p } => path(3, p),
            Self::Upload { dir } => path(4, dir),
            Self::Offer => Writer::new(5).finish(),
            Self::Entry(e) => {
                let mut w = Writer::new(16);
                w.str_max(&e.name, MAX_PATH_LEN);
                w.str_max(&e.path, MAX_PATH_LEN);
                w.u8(e.kind as u8);
                w.u64(e.size);
                w.u64(e.modified_unix);
                w.finish()
            }
            Self::Total { bytes } => {
                let mut w = Writer::new(17);
                w.u64(*bytes);
                w.finish()
            }
            Self::File { path, size } => {
                let mut w = Writer::new(18);
                w.str_max(path, MAX_PATH_LEN);
                w.u64(*size);
                w.finish()
            }
            Self::Dir { path: p } => path(19, p),
            Self::End => Writer::new(20).finish(),
            Self::Saved { names } => {
                let mut w = Writer::new(21);
                // Bounded so the message stays under the control message limit.
                let names: Vec<&String> = names.iter().take(64).collect();
                w.u8(names.len() as u8);
                for name in names {
                    w.str_max(name, MAX_NAME_LEN);
                }
                w.finish()
            }
            Self::Error { message } => {
                let mut w = Writer::new(22);
                w.str_max(message, MAX_ERROR_LEN);
                w.finish()
            }
        }
    }

    /// Decodes a message body (without the length prefix).
    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut r = Reader(body);
        let msg = match r.u8()? {
            1 => Self::Roots,
            2 => Self::List { path: r.str()? },
            3 => Self::Download { path: r.str()? },
            4 => Self::Upload { dir: r.str()? },
            5 => Self::Offer,
            16 => Self::Entry(Entry {
                name: r.str()?,
                path: r.str()?,
                kind: match r.u8()? {
                    1 => EntryKind::File,
                    2 => EntryKind::Dir,
                    3 => EntryKind::Place,
                    k => bail!("invalid entry kind {k}"),
                },
                size: r.u64()?,
                modified_unix: r.u64()?,
            }),
            17 => Self::Total { bytes: r.u64()? },
            18 => Self::File { path: r.str()?, size: r.u64()? },
            19 => Self::Dir { path: r.str()? },
            20 => Self::End,
            21 => {
                let n = r.u8()?;
                Self::Saved { names: (0..n).map(|_| r.str()).collect::<Result<_>>()? }
            }
            22 => Self::Error { message: r.str()? },
            t => bail!("unknown file message {t}"),
        };
        r.end()?;
        Ok(msg)
    }
}

/// Reads one message. `Ok(None)` when the stream ends before one starts.
pub async fn read<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<FileMsg>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_le_bytes(len) as usize;
    ensure!(len > 0 && len <= MAX_CONTROL_MSG, "invalid file message length {len}");
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    FileMsg::decode(&body).map(Some)
}

/// Reads the next message, turning an `Error` from the other side into an error here.
pub async fn next<R: AsyncRead + Unpin>(r: &mut R) -> Result<FileMsg> {
    match read(r).await?.ok_or_else(|| anyhow!("the transfer was interrupted"))? {
        FileMsg::Error { message } => Err(anyhow!(message)),
        msg => Ok(msg),
    }
}

pub async fn write<W: AsyncWrite + Unpin>(w: &mut W, msg: &FileMsg) -> Result<()> {
    w.write_all(&msg.encode()).await?;
    Ok(())
}

/// Bytes moved so far and the total, as a transfer goes.
pub type Progress<'a> = &'a mut (dyn FnMut(u64, u64) + Send);

/// Files and folders to send, gathered before anything is written so the total is known.
pub struct Tree {
    items: Vec<Item>,
    bytes: u64,
}

enum Item {
    Dir(String),
    File { rel: String, path: PathBuf, size: u64 },
}

impl Tree {
    /// Walks `sources` (blocking). Symbolic links and junctions are skipped, never followed.
    /// Names the other side could not store are made safe (see [`safe_name`]).
    pub fn gather(sources: &[PathBuf]) -> Result<Self> {
        let mut tree = Tree { items: Vec::new(), bytes: 0 };
        for source in sources {
            let name = source.file_name().with_context(|| format!("{} has no name", source.display()))?;
            tree.walk(source, safe_name(&name.to_string_lossy()))?;
        }
        ensure!(!tree.items.is_empty(), "nothing to send");
        Ok(tree)
    }

    fn walk(&mut self, path: &Path, rel: String) -> Result<()> {
        ensure!(self.items.len() < MAX_ITEMS, "more than {MAX_ITEMS} files and folders");
        let meta = std::fs::symlink_metadata(path).with_context(|| format!("reading {}", path.display()))?;
        if meta.file_type().is_symlink() {
            return Ok(());
        }
        if meta.is_dir() {
            self.items.push(Item::Dir(rel.clone()));
            let mut children: Vec<_> = std::fs::read_dir(path)
                .with_context(|| format!("reading {}", path.display()))?
                .filter_map(|e| e.ok())
                .collect();
            children.sort_by_key(|e| e.file_name());
            for child in children {
                let name = safe_name(&child.file_name().to_string_lossy());
                self.walk(&child.path(), format!("{rel}/{name}"))?;
            }
        } else if meta.is_file() {
            self.bytes += meta.len();
            self.items.push(Item::File { rel, path: path.to_path_buf(), size: meta.len() });
        }
        Ok(())
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }
}

/// Sends a gathered tree. A file that shrank since it was gathered fails the transfer; one that
/// grew is sent as it was.
pub async fn send_tree<W: AsyncWrite + Unpin>(w: &mut W, tree: &Tree, progress: Progress<'_>) -> Result<()> {
    write(w, &FileMsg::Total { bytes: tree.bytes }).await?;
    let mut done = 0u64;
    let mut buf = vec![0u8; BUFFER];
    for item in &tree.items {
        match item {
            Item::Dir(rel) => write(w, &FileMsg::Dir { path: rel.clone() }).await?,
            Item::File { rel, path, size } => {
                write(w, &FileMsg::File { path: rel.clone(), size: *size }).await?;
                let mut file =
                    tokio::fs::File::open(path).await.with_context(|| format!("opening {}", path.display()))?;
                let mut left = *size;
                while left > 0 {
                    let n = file.read(&mut buf[..left.min(BUFFER as u64) as usize]).await?;
                    ensure!(n > 0, "{} changed while it was being sent", path.display());
                    w.write_all(&buf[..n]).await?;
                    left -= n as u64;
                    done += n as u64;
                    progress(done, tree.bytes);
                }
            }
        }
    }
    write(w, &FileMsg::End).await
}

/// Receives a tree into the existing folder `dest`. Returns the top-level names as saved.
pub async fn receive_tree<R: AsyncRead + Unpin>(r: &mut R, dest: &Path, progress: Progress<'_>) -> Result<Vec<String>> {
    let FileMsg::Total { bytes: total } = next(r).await? else { bail!("expected the transfer size") };
    ensure!(tokio::fs::metadata(dest).await.is_ok_and(|m| m.is_dir()), "{} is not a folder", dest.display());
    let mut renamed = HashMap::new();
    let mut saved = Vec::new();
    let mut done = 0u64;
    let mut buf = vec![0u8; BUFFER];
    for count in 0.. {
        ensure!(count <= MAX_ITEMS, "more than {MAX_ITEMS} files and folders");
        match next(r).await? {
            FileMsg::Dir { path } => {
                let target = place(dest, &path, &mut renamed, &mut saved)?;
                tokio::fs::create_dir_all(&target).await.with_context(|| format!("creating {}", target.display()))?;
            }
            FileMsg::File { path, size } => {
                let target = place(dest, &path, &mut renamed, &mut saved)?;
                if let Some(parent) = target.parent() {
                    tokio::fs::create_dir_all(parent).await?;
                }
                let part = PartFile::new(&target);
                let mut file =
                    tokio::fs::File::create(&part.0).await.with_context(|| format!("creating {}", target.display()))?;
                let mut left = size;
                while left > 0 {
                    let n = r.read(&mut buf[..left.min(BUFFER as u64) as usize]).await?;
                    ensure!(n > 0, "the transfer was interrupted");
                    file.write_all(&buf[..n]).await?;
                    left -= n as u64;
                    done += n as u64;
                    progress(done, total);
                }
                file.flush().await?;
                drop(file);
                part.finish(&target).await?;
            }
            FileMsg::End => break,
            other => bail!("unexpected {other:?} in a transfer"),
        }
    }
    Ok(saved)
}

/// A file being received, deleted unless [`PartFile::finish`] renames it into place: also when
/// the transfer is cancelled by dropping its future.
struct PartFile(PathBuf, bool);

impl PartFile {
    fn new(target: &Path) -> Self {
        let mut name = target.file_name().unwrap_or_default().to_os_string();
        name.push(PART_SUFFIX);
        Self(target.with_file_name(name), true)
    }

    async fn finish(mut self, target: &Path) -> Result<()> {
        tokio::fs::rename(&self.0, target).await.with_context(|| format!("saving {}", target.display()))?;
        self.1 = false;
        Ok(())
    }
}

impl Drop for PartFile {
    fn drop(&mut self) {
        if self.1 {
            let _ = std::fs::remove_file(&self.0);
        }
    }
}

/// Where an item goes: under `dest`, with its top-level name made unique the first time it is
/// seen, so nothing that was already there is overwritten.
fn place(dest: &Path, rel: &str, renamed: &mut HashMap<String, String>, saved: &mut Vec<String>) -> Result<PathBuf> {
    let parts = relative_components(rel)?;
    let top = match renamed.get(parts[0]) {
        Some(name) => name.clone(),
        None => {
            let name = unique_name(dest, parts[0]);
            renamed.insert(parts[0].to_string(), name.clone());
            saved.push(name.clone());
            name
        }
    };
    let mut path = dest.join(top);
    path.extend(&parts[1..]);
    Ok(path)
}

/// Splits a relative item path into components, refusing anything that could leave the
/// destination folder or that some file system could misread.
pub fn relative_components(path: &str) -> Result<Vec<&str>> {
    ensure!(!path.is_empty() && path.len() <= MAX_PATH_LEN, "invalid path");
    let parts: Vec<&str> = path.split('/').collect();
    for part in &parts {
        ensure!(valid_name(part), "invalid file name {part:?}");
    }
    Ok(parts)
}

/// A single file or folder name that is safe on Windows, macOS and Linux, and cannot name
/// another place (`..`, drive letters, alternate data streams, devices).
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name != "."
        && name != ".."
        && !name.chars().any(|c| c.is_control() || matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|'))
        && !name.ends_with(['.', ' '])
        && !name.ends_with(PART_SUFFIX)
        && !is_device_name(name)
}

/// `name` with what [`valid_name`] refuses replaced, so a file named on another system can
/// still be sent.
pub fn safe_name(name: &str) -> String {
    let mut out: String =
        name.chars()
            .map(|c| {
                if c.is_control() || matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') {
                    '_'
                } else {
                    c
                }
            })
            .collect();
    while out.ends_with(['.', ' ']) {
        out.pop();
    }
    if out.len() > MAX_NAME_LEN {
        let mut end = MAX_NAME_LEN;
        while !out.is_char_boundary(end) {
            end -= 1;
        }
        out.truncate(end);
    }
    if out.ends_with(PART_SUFFIX) {
        out.push('_');
    }
    if is_device_name(&out) {
        out.insert(0, '_');
    }
    if out.is_empty() || out == "." || out == ".." {
        out = "_".into();
    }
    out
}

/// Windows device names, reserved with any extension.
fn is_device_name(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or("").trim_end().to_ascii_uppercase();
    match stem.as_str() {
        "CON" | "PRN" | "AUX" | "NUL" => true,
        _ => {
            let b = stem.as_bytes();
            b.len() == 4 && (stem.starts_with("COM") || stem.starts_with("LPT")) && (b'1'..=b'9').contains(&b[3])
        }
    }
}

/// `name`, or `name (n).ext` with the first `n` not taken in `dir`.
pub fn unique_name(dir: &Path, name: &str) -> String {
    let taken = |n: &str| std::fs::symlink_metadata(dir.join(n)).is_ok();
    if !taken(name) {
        return name.to_string();
    }
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => name.split_at(i),
        _ => (name, ""),
    };
    (1..).map(|n| format!("{stem} ({n}){ext}")).find(|c| !taken(c)).unwrap()
}

/// This user's Downloads folder, created if missing.
pub fn downloads_dir() -> Result<PathBuf> {
    let dirs = directories::UserDirs::new().context("no home folder")?;
    let dir = dirs.download_dir().map(Path::to_path_buf).unwrap_or_else(|| dirs.home_dir().join("Downloads"));
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir)
}

/// Drives and well-known folders of this user, as `Place` entries.
pub fn roots() -> Vec<Entry> {
    let mut out = Vec::new();
    let mut place = |name: &str, path: &Path| {
        if path.is_dir() {
            out.push(Entry {
                name: name.to_string(),
                path: path.to_string_lossy().into_owned(),
                kind: EntryKind::Place,
                size: 0,
                modified_unix: 0,
            });
        }
    };
    if let Some(dirs) = directories::UserDirs::new() {
        for (name, dir) in [
            ("Downloads", dirs.download_dir()),
            ("Desktop", dirs.desktop_dir()),
            ("Documents", dirs.document_dir()),
            ("Pictures", dirs.picture_dir()),
            ("Home", Some(dirs.home_dir())),
        ] {
            if let Some(dir) = dir {
                place(name, dir);
            }
        }
    }
    if cfg!(windows) {
        for letter in 'A'..='Z' {
            let root = format!("{letter}:\\");
            place(&format!("{letter}:"), Path::new(&root));
        }
    } else {
        place("/", Path::new("/"));
    }
    out
}

/// The entries of the folder `path` (blocking): folders first, then by name.
pub fn list(path: &Path) -> Result<Vec<Entry>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(path).with_context(|| format!("reading {}", path.display()))? {
        let Ok(entry) = entry else { continue };
        // Follows links, so a link to a folder can be opened; unreadable entries are left out.
        let Ok(meta) = std::fs::metadata(entry.path()) else { continue };
        out.push(Entry {
            name: entry.file_name().to_string_lossy().into_owned(),
            path: entry.path().to_string_lossy().into_owned(),
            kind: if meta.is_dir() { EntryKind::Dir } else { EntryKind::File },
            size: if meta.is_dir() { 0 } else { meta.len() },
            modified_unix: meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_secs()),
        });
        ensure!(out.len() <= MAX_ITEMS, "more than {MAX_ITEMS} entries");
    }
    out.sort_by(|a, b| {
        (b.kind == EntryKind::Dir)
            .cmp(&(a.kind == EntryKind::Dir))
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    Ok(out)
}

/// Answers one stream opened by the other side, on this side's file system. Errors that happen
/// before a reply starts are sent back; later ones end the stream, which the other side sees as
/// an interrupted transfer.
pub async fn serve<R, W>(r: &mut R, w: &mut W) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let Some(request) = read(r).await? else { return Ok(()) };
    let result = async {
        match request {
            FileMsg::Roots => send_entries(w, roots()).await,
            FileMsg::List { path } => {
                let entries = tokio::task::spawn_blocking(move || list(Path::new(&path))).await??;
                send_entries(w, entries).await
            }
            FileMsg::Download { path } => {
                let tree = tokio::task::spawn_blocking(move || Tree::gather(&[PathBuf::from(path)])).await??;
                send_tree(w, &tree, &mut |_, _| {}).await.map_err(Started)?;
                Ok(())
            }
            FileMsg::Upload { dir } => {
                let dest = if dir.is_empty() { downloads_dir()? } else { PathBuf::from(dir) };
                receive(r, w, &dest).await
            }
            FileMsg::Offer => receive(r, w, &downloads_dir()?).await,
            other => bail!("unexpected request {other:?}"),
        }
    }
    .await;
    if let Err(e) = &result {
        if e.downcast_ref::<Started>().is_none() {
            let _ = write(w, &FileMsg::Error { message: format!("{e:#}") }).await;
        }
    }
    w.shutdown().await?;
    result
}

/// An error after a reply started streaming: too late to send an `Error` message.
#[derive(Debug)]
struct Started(anyhow::Error);

impl std::fmt::Display for Started {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#}", self.0)
    }
}

impl std::error::Error for Started {}

async fn send_entries<W: AsyncWrite + Unpin>(w: &mut W, entries: Vec<Entry>) -> Result<()> {
    for entry in entries {
        write(w, &FileMsg::Entry(entry)).await?;
    }
    write(w, &FileMsg::End).await
}

async fn receive<R, W>(r: &mut R, w: &mut W, dest: &Path) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let names = receive_tree(r, dest, &mut |_, _| {}).await?;
    write(w, &FileMsg::Saved { names }).await
}

/// Asks the other side for its places (`path: None`) or a folder's entries.
pub async fn request_list<R, W>(r: &mut R, w: &mut W, path: Option<&str>) -> Result<Vec<Entry>>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let request = match path {
        None => FileMsg::Roots,
        Some(path) => FileMsg::List { path: path.to_string() },
    };
    write(w, &request).await?;
    w.shutdown().await?;
    let mut entries = Vec::new();
    loop {
        match next(r).await? {
            FileMsg::Entry(e) => entries.push(e),
            FileMsg::End => return Ok(entries),
            other => bail!("unexpected {other:?} in a listing"),
        }
        ensure!(entries.len() <= MAX_ITEMS, "more than {MAX_ITEMS} entries");
    }
}

/// Fetches the other side's `path` (file or folder) into the local folder `dest`.
pub async fn request_download<R, W>(
    r: &mut R,
    w: &mut W,
    path: &str,
    dest: &Path,
    progress: Progress<'_>,
) -> Result<Vec<String>>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    write(w, &FileMsg::Download { path: path.to_string() }).await?;
    w.shutdown().await?;
    receive_tree(r, dest, progress).await
}

/// Sends a gathered tree with `request` ([`FileMsg::Upload`] or [`FileMsg::Offer`]) and waits
/// for the other side to confirm. Returns the names it saved.
pub async fn request_send<R, W>(
    r: &mut R,
    w: &mut W,
    request: FileMsg,
    tree: &Tree,
    progress: Progress<'_>,
) -> Result<Vec<String>>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    write(w, &request).await?;
    send_tree(w, tree, progress).await?;
    w.shutdown().await?;
    match next(r).await? {
        FileMsg::Saved { names } => Ok(names),
        other => bail!("unexpected {other:?} after a transfer"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(msg: FileMsg) {
        let enc = msg.encode();
        assert_eq!(FileMsg::decode(&enc[4..]).unwrap(), msg);
    }

    #[test]
    fn messages_roundtrip() {
        roundtrip(FileMsg::Roots);
        roundtrip(FileMsg::List { path: r"C:\Users\ana\Fotos".into() });
        roundtrip(FileMsg::Download { path: "/home/ana/vídeo.mp4".into() });
        roundtrip(FileMsg::Upload { dir: String::new() });
        roundtrip(FileMsg::Offer);
        roundtrip(FileMsg::Entry(Entry {
            name: "relatório.pdf".into(),
            path: r"C:\relatório.pdf".into(),
            kind: EntryKind::File,
            size: u64::MAX,
            modified_unix: 1_700_000_000,
        }));
        roundtrip(FileMsg::Total { bytes: 5 << 40 });
        roundtrip(FileMsg::File { path: "a/b.txt".into(), size: 3 });
        roundtrip(FileMsg::Dir { path: "a".into() });
        roundtrip(FileMsg::End);
        roundtrip(FileMsg::Saved { names: vec!["a (1)".into(), "b.txt".into()] });
        roundtrip(FileMsg::Error { message: "disk full".into() });
    }

    #[test]
    fn refuses_names_that_escape_or_misbehave() {
        for bad in [
            "",
            ".",
            "..",
            "a/b",
            r"a\b",
            "C:",
            "x:stream",
            "con",
            "NUL.txt",
            "com1",
            "lpt9.log",
            "end.",
            "end ",
            "a\0b",
            "x.velora-part",
        ] {
            assert!(!valid_name(bad), "{bad:?} should be refused");
        }
        for good in ["a", "relatório final.pdf", ".hidden", "com10", "console.log", "a..b"] {
            assert!(valid_name(good), "{good:?} should be accepted");
        }
        assert!(relative_components("a/../b").is_err());
        assert!(relative_components("/abs").is_err());
        assert!(relative_components("a//b").is_err());
        assert_eq!(relative_components("pasta/sub/x.txt").unwrap(), ["pasta", "sub", "x.txt"]);
    }

    #[test]
    fn safe_names_are_valid() {
        let long = "é".repeat(300);
        for name in ["a:b", "what?", "trailing. ", "CON", "..", "", "x.velora-part", &long] {
            let safe = safe_name(name);
            assert!(valid_name(&safe), "{name:?} -> {safe:?}");
        }
        assert_eq!(safe_name("foto.jpg"), "foto.jpg");
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("velora-files-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn existing_names_get_a_number() {
        let dir = temp_dir("unique");
        std::fs::write(dir.join("foto.jpg"), b"x").unwrap();
        std::fs::write(dir.join("foto (1).jpg"), b"x").unwrap();
        std::fs::create_dir(dir.join("pasta")).unwrap();
        assert_eq!(unique_name(&dir, "foto.jpg"), "foto (2).jpg");
        assert_eq!(unique_name(&dir, "pasta"), "pasta (1)");
        assert_eq!(unique_name(&dir, "novo.txt"), "novo.txt");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn sends_and_receives_a_tree() {
        let src = temp_dir("src");
        std::fs::create_dir_all(src.join("pasta/vazia")).unwrap();
        std::fs::write(src.join("pasta/a.txt"), b"hello").unwrap();
        std::fs::write(src.join("pasta/b.bin"), vec![7u8; 600_000]).unwrap();
        let dest = temp_dir("dest");
        // Already there: the received folder must not merge into it.
        std::fs::create_dir(dest.join("pasta")).unwrap();

        let tree = Tree::gather(&[src.join("pasta")]).unwrap();
        assert_eq!(tree.bytes(), 600_005);
        let (mut a, mut b) = tokio::io::duplex(64 * 1024);
        let sender = async move { send_tree(&mut a, &tree, &mut |_, _| {}).await };
        let mut last = (0, 0);
        let mut track = |done, total| last = (done, total);
        let receiver = receive_tree(&mut b, &dest, &mut track);
        let (sent, saved) = tokio::join!(sender, receiver);
        sent.unwrap();
        assert_eq!(saved.unwrap(), ["pasta (1)"]);
        assert_eq!(last, (600_005, 600_005));
        assert_eq!(std::fs::read(dest.join("pasta (1)/a.txt")).unwrap(), b"hello");
        assert_eq!(std::fs::read(dest.join("pasta (1)/b.bin")).unwrap().len(), 600_000);
        assert!(dest.join("pasta (1)/vazia").is_dir());
        let _ = std::fs::remove_dir_all(&src);
        let _ = std::fs::remove_dir_all(&dest);
    }

    #[tokio::test]
    async fn interrupted_transfers_leave_nothing_behind() {
        let dest = temp_dir("cut");
        let mut stream = Vec::new();
        stream.extend(FileMsg::Total { bytes: 10 }.encode());
        stream.extend(FileMsg::File { path: "x.bin".into(), size: 10 }.encode());
        stream.extend([1, 2, 3]);
        let result = receive_tree(&mut stream.as_slice(), &dest, &mut |_, _| {}).await;
        assert!(result.is_err());
        assert_eq!(std::fs::read_dir(&dest).unwrap().count(), 0);
        let _ = std::fs::remove_dir_all(&dest);
    }

    #[tokio::test]
    async fn refuses_paths_that_leave_the_destination() {
        let dest = temp_dir("escape");
        let mut stream = Vec::new();
        stream.extend(FileMsg::Total { bytes: 1 }.encode());
        stream.extend(FileMsg::File { path: "../evil.txt".into(), size: 1 }.encode());
        stream.push(b'x');
        assert!(receive_tree(&mut stream.as_slice(), &dest, &mut |_, _| {}).await.is_err());
        assert!(!dest.parent().unwrap().join("evil.txt").exists());
        let _ = std::fs::remove_dir_all(&dest);
    }
}
