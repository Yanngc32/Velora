//! Self-updates from the project's GitHub Releases.
//!
//! Every release publishes `manifest.json`, listing per target each installed file with its
//! SHA-256 and size. Releases are trusted as published on GitHub and fetched over HTTPS from
//! the fixed repository URL; only files matching the manifest's hashes are installed, only
//! inside the install directory, and versions never go backwards.
//!
//! Only files whose hash differs from the installed copy are downloaded. They are swapped in by
//! rename (`x` -> `x.old`, `x.new` -> `x`), which works for running executables and loaded
//! libraries on both Windows and Linux; leftovers are removed on the next start.

use std::{
    collections::BTreeMap,
    fmt,
    fs::{self, File},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
    str::FromStr,
    time::{Duration, SystemTime},
};

use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};

pub const DEFAULT_BASE_URL: &str = "https://github.com/Yanngc32/Velora/releases";
pub const MANIFEST: &str = "manifest.json";

const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;
const LOCK_FILE: &str = ".velora-update.lock";
const STALE_LOCK: Duration = Duration::from_secs(30 * 60);

/// Official release builds set `VELORA_RELEASE_BUILD=1` at compile time. Source builds never update
/// themselves, so a developer's binary is not silently replaced by a release.
pub fn is_release_build() -> bool {
    option_env!("VELORA_RELEASE_BUILD") == Some("1")
}

/// Release target of this binary, if releases are published for it.
pub fn target() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("windows", "x86_64") => Some("x86_64-pc-windows-msvc"),
        ("linux", "x86_64") => Some("x86_64-unknown-linux-gnu"),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(pub u32, pub u32, pub u32);

impl Version {
    pub fn current() -> Self {
        env!("CARGO_PKG_VERSION").parse().expect("crate version is MAJOR.MINOR.PATCH")
    }
}

impl FromStr for Version {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let parts: Vec<u32> = s.trim_start_matches('v').split('.').map(str::parse).collect::<Result<_, _>>()?;
        let [a, b, c] = parts[..] else { bail!("version must be MAJOR.MINOR.PATCH: {s}") };
        Ok(Self(a, b, c))
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub version: String,
    /// Target triple -> files installed for it.
    pub targets: BTreeMap<String, Vec<FileEntry>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    /// Path relative to the install directory, `/`-separated.
    pub path: String,
    /// Release asset holding the file's contents.
    pub asset: String,
    /// Lowercase hex SHA-256.
    pub sha256: String,
    pub size: u64,
    /// Needs the executable bit on Unix.
    pub executable: bool,
}

/// Parses and validates a manifest: a well-formed version and only safe relative paths.
pub fn parse_manifest(manifest: &[u8]) -> Result<Manifest> {
    let manifest: Manifest = serde_json::from_slice(manifest).context("malformed manifest")?;
    manifest.version.parse::<Version>()?;
    for files in manifest.targets.values() {
        for f in files {
            safe_relative_path(&f.path)?;
        }
    }
    Ok(manifest)
}

/// Rejects absolute paths and `..`, so a manifest can only touch the install directory.
fn safe_relative_path(path: &str) -> Result<PathBuf> {
    let p = Path::new(path);
    ensure!(
        !path.is_empty() && p.components().all(|c| matches!(c, Component::Normal(_))),
        "unsafe path in manifest: {path}"
    );
    Ok(p.to_path_buf())
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(ring::digest::digest(&ring::digest::SHA256, data).as_ref())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn file_sha256(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        ctx.update(&buf[..n]);
    }
    Ok(hex(ctx.finish().as_ref()))
}

/// An available release and the files that differ from what is installed.
#[derive(Debug)]
pub struct Update {
    pub version: Version,
    pub files: Vec<FileEntry>,
}

pub struct Updater {
    base_url: String,
    target: String,
    install_dir: PathBuf,
    current: Version,
    agent: ureq::Agent,
}

impl Updater {
    /// Updater for the running binary, installed next to it, from the project's releases.
    pub fn for_current_exe() -> Result<Self> {
        let exe = std::env::current_exe().context("locating the running executable")?;
        let install_dir = exe.parent().context("executable has no parent directory")?.to_path_buf();
        let target = target().context("no releases are published for this platform")?;
        Ok(Self::new(DEFAULT_BASE_URL.to_string(), target.to_string(), install_dir, Version::current()))
    }

    pub fn new(base_url: String, target: String, install_dir: PathBuf, current: Version) -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_connect(Some(Duration::from_secs(15)))
            .user_agent(format!("velora/{current}"))
            // The OS trust store also covers corporate TLS-inspecting proxies.
            .tls_config(ureq::tls::TlsConfig::builder().root_certs(ureq::tls::RootCerts::PlatformVerifier).build())
            .build()
            .into();
        Self { base_url: base_url.trim_end_matches('/').to_string(), target, install_dir, current, agent }
    }

    pub fn install_dir(&self) -> &Path {
        &self.install_dir
    }

    fn get(&self, url: &str, limit: u64) -> Result<Vec<u8>> {
        let mut resp = self.agent.get(url).call().with_context(|| format!("downloading {url}"))?;
        Ok(resp.body_mut().with_config().limit(limit).read_to_vec()?)
    }

    /// Fetches and validates the latest manifest. `None` when already up to date.
    pub fn check(&self) -> Result<Option<Update>> {
        let manifest = self.get(&format!("{}/latest/download/{MANIFEST}", self.base_url), MAX_MANIFEST_BYTES)?;
        let manifest = parse_manifest(&manifest)?;
        let version: Version = manifest.version.parse()?;
        if version <= self.current {
            return Ok(None);
        }
        let files = manifest
            .targets
            .get(&self.target)
            .with_context(|| format!("release {version} has no build for {}", self.target))?;
        let changed = files
            .iter()
            .filter(|f| {
                let local = self.install_dir.join(safe_relative_path(&f.path).unwrap());
                file_sha256(&local).map(|h| h != f.sha256).unwrap_or(true)
            })
            .cloned()
            .collect();
        Ok(Some(Update { version, files: changed }))
    }

    /// Downloads, verifies and swaps in the changed files. On error nothing is left replaced.
    pub fn install(&self, update: &Update) -> Result<()> {
        let _lock = Lock::acquire(&self.install_dir)?;
        let staged = self.download(update)?;
        swap_in(&self.install_dir, &staged)
    }

    fn download(&self, update: &Update) -> Result<Vec<PathBuf>> {
        let mut staged = Vec::new();
        let result = (|| {
            for f in &update.files {
                let target = self.install_dir.join(safe_relative_path(&f.path)?);
                let new = with_suffix(&target, ".new");
                if let Some(parent) = new.parent() {
                    fs::create_dir_all(parent)?;
                }
                staged.push(target.clone());
                let url = format!("{}/download/v{}/{}", self.base_url, update.version, f.asset);
                ensure!(f.size <= MAX_FILE_BYTES, "{} is too large", f.path);
                let mut resp = self.agent.get(&url).call().with_context(|| format!("downloading {url}"))?;
                // ureq rejects a body equal to the limit; the exact size is checked below anyway.
                let mut reader = resp.body_mut().with_config().limit(f.size + 1).reader();
                let mut out = File::create(&new).with_context(|| format!("writing {}", new.display()))?;
                let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
                let mut buf = vec![0u8; 256 * 1024];
                let mut total = 0u64;
                loop {
                    let n = reader.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    ctx.update(&buf[..n]);
                    out.write_all(&buf[..n])?;
                    total += n as u64;
                }
                out.sync_all()?;
                drop(out);
                ensure!(
                    total == f.size && hex(ctx.finish().as_ref()) == f.sha256,
                    "{} does not match the signed manifest",
                    f.path
                );
                set_executable(&new, f.executable)?;
            }
            Ok(())
        })();
        if let Err(e) = result {
            for target in &staged {
                let _ = fs::remove_file(with_suffix(target, ".new"));
            }
            return Err(e);
        }
        Ok(staged)
    }
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

#[cfg(unix)]
fn set_executable(path: &Path, executable: bool) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(if executable { 0o755 } else { 0o644 }))
}

#[cfg(not(unix))]
fn set_executable(_path: &Path, _executable: bool) -> io::Result<()> {
    Ok(())
}

/// Renames every `x.new` over `x`, keeping `x.old` until the next start. Rolls back on error.
fn swap_in(dir: &Path, targets: &[PathBuf]) -> Result<()> {
    let mut done: Vec<(PathBuf, Option<PathBuf>)> = Vec::new();
    let result = (|| -> Result<()> {
        for target in targets {
            let backup = if target.exists() {
                let old = free_backup_name(target);
                fs::rename(target, &old).with_context(|| format!("moving {} aside", target.display()))?;
                Some(old)
            } else {
                None
            };
            done.push((target.clone(), backup));
            fs::rename(with_suffix(target, ".new"), target)
                .with_context(|| format!("installing {}", target.display()))?;
        }
        Ok(())
    })();
    if let Err(e) = result {
        for (target, backup) in done.into_iter().rev() {
            if let Some(old) = backup {
                let _ = fs::rename(target.clone(), with_suffix(&target, ".new"));
                let _ = fs::rename(&old, &target);
            }
        }
        for target in targets {
            let _ = fs::remove_file(with_suffix(target, ".new"));
        }
        return Err(e).with_context(|| format!("updating {}", dir.display()));
    }
    Ok(())
}

/// `x.old`, or `x.old.N` when an older backup is still locked (Windows keeps a running
/// executable's file busy until the process exits).
fn free_backup_name(target: &Path) -> PathBuf {
    let old = with_suffix(target, ".old");
    if !old.exists() || fs::remove_file(&old).is_ok() {
        return old;
    }
    (1..).map(|n| with_suffix(target, &format!(".old.{n}"))).find(|p| !p.exists()).unwrap()
}

fn is_leftover(name: &str) -> bool {
    name.ends_with(".new")
        || name.ends_with(".old")
        || name.rsplit_once(".old.").is_some_and(|(_, n)| n.parse::<u32>().is_ok())
}

/// Removes backups and partial downloads left by a previous update. Backups are deleted only
/// when the file they back up exists, so an interrupted update never loses the last copy.
pub fn cleanup(dir: &Path) {
    let mut dirs = vec![dir.to_path_buf()];
    while let Some(d) = dirs.pop() {
        let Ok(entries) = fs::read_dir(&d) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if d == dir {
                    dirs.push(path);
                }
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if !is_leftover(&name) {
                continue;
            }
            let original = name.trim_end_matches(".new").split(".old").next().unwrap_or_default().to_string();
            if name.ends_with(".new") || d.join(&original).exists() {
                let _ = fs::remove_file(&path);
            }
        }
    }
}

/// Exclusive update lock so a host and a client sharing an install never update at once.
struct Lock(PathBuf);

impl Lock {
    fn acquire(dir: &Path) -> Result<Self> {
        let path = dir.join(LOCK_FILE);
        for _ in 0..2 {
            match fs::OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(_) => return Ok(Self(path)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    let stale = fs::metadata(&path)
                        .and_then(|m| m.modified())
                        .map(|t| SystemTime::now().duration_since(t).unwrap_or_default() > STALE_LOCK)
                        .unwrap_or(true);
                    if !stale {
                        bail!("another update is in progress");
                    }
                    let _ = fs::remove_file(&path);
                }
                Err(e) => {
                    return Err(e).with_context(|| {
                        format!(
                            "{} is not writable; install in a user-writable directory to get updates",
                            dir.display()
                        )
                    })
                }
            }
        }
        bail!("could not lock {}", path.display())
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// Whether this process should update itself in the background.
pub fn auto_update_enabled(disabled_by_flag: bool) -> bool {
    is_release_build() && !disabled_by_flag && std::env::var_os("VELORA_NO_UPDATE").is_none()
}

/// Checks for and installs the latest release next to the running executable.
/// Returns the installed version, or `None` when already up to date.
pub fn update_now() -> Result<Option<Version>> {
    let updater = Updater::for_current_exe()?;
    match updater.check()? {
        Some(update) if !update.files.is_empty() => {
            updater.install(&update)?;
            Ok(Some(update.version))
        }
        _ => Ok(None),
    }
}

/// Removes leftovers of a previous update next to the running executable.
pub fn cleanup_current_exe() {
    if let Some(dir) = std::env::current_exe().ok().and_then(|e| e.parent().map(Path::to_path_buf)) {
        cleanup(&dir);
    }
}

/// Replaces the running process with `exe` (a path captured before the update, since the
/// running file has been renamed). On Unix the PID, terminal and service supervision stay the
/// same; on Windows a new process is started and this one exits.
pub fn restart(exe: &Path) -> ! {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = std::process::Command::new(exe).args(&args).exec();
        eprintln!("restart after update failed: {err}");
        std::process::exit(1);
    }
    #[cfg(not(unix))]
    {
        match std::process::Command::new(exe).args(&args).spawn() {
            Ok(_) => std::process::exit(0),
            Err(e) => {
                eprintln!("restart after update failed: {e}");
                std::process::exit(1);
            }
        }
    }
}

#[cfg(test)]
mod tests;
