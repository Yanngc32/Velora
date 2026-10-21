//! Release tooling used by CI (`.github/workflows/release.yml`).
//!
//! `package` turns a staged install directory into per-file release assets plus a zip for
//! manual installs; `manifest` merges the packaged targets into the signed update manifest.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use clap::{Parser, Subcommand};
use ring::signature::{Ed25519KeyPair, KeyPair};
use velora_update::{FileEntry, Manifest, Version, MANIFEST, SIGNATURE};

#[derive(Parser)]
#[command(name = "velora-release")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create the release signing key. Keep the private key secret (CI secret
    /// `VELORA_SIGNING_KEY`); commit the printed public key to crates/update/release-public-key.txt.
    Keygen {
        #[arg(long)]
        private_key_out: PathBuf,
    },
    /// Package a staged install directory for one target.
    Package {
        #[arg(long)]
        target: String,
        /// Directory laid out exactly as installed.
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        dist: PathBuf,
    },
    /// Merge packaged targets into manifest.json and sign it with `VELORA_SIGNING_KEY`.
    Manifest {
        #[arg(long)]
        dist: PathBuf,
        /// Skip signing (dry runs without access to the key).
        #[arg(long)]
        unsigned: bool,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Keygen { private_key_out } => keygen(&private_key_out),
        Command::Package { target, root, dist } => package(&target, &root, &dist),
        Command::Manifest { dist, unsigned } => manifest(&dist, unsigned),
    }
}

fn keygen(out: &Path) -> Result<()> {
    ensure!(!out.exists(), "{} already exists; refusing to overwrite a signing key", out.display());
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
        .map_err(|_| anyhow::anyhow!("key generation failed"))?;
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).map_err(|_| anyhow::anyhow!("invalid key"))?;
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(out)?.write_all(B64.encode(pkcs8.as_ref()).as_bytes())?;
    println!("Private key written to {} (store it as the VELORA_SIGNING_KEY secret).", out.display());
    println!("Public key (commit to crates/update/release-public-key.txt):");
    println!("{}", B64.encode(pair.public_key().as_ref()));
    Ok(())
}

/// Files under `root`, as sorted `/`-separated relative paths.
fn walk(root: &Path) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).with_context(|| format!("reading {}", dir.display()))? {
            let path = entry?.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let rel =
                    path.strip_prefix(root)?.components().map(|c| c.as_os_str().to_string_lossy()).collect::<Vec<_>>();
                out.push(rel.join("/"));
            }
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(unix)]
fn is_executable(path: &Path) -> Result<bool> {
    use std::os::unix::fs::PermissionsExt;
    Ok(fs::metadata(path)?.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(_path: &Path) -> Result<bool> {
    Ok(false)
}

fn package(target: &str, root: &Path, dist: &Path) -> Result<()> {
    fs::create_dir_all(dist)?;
    let files = walk(root)?;
    ensure!(!files.is_empty(), "{} is empty", root.display());

    let zip_name = format!("velora-{}-{target}.zip", Version::current());
    let mut zip = zip::ZipWriter::new(fs::File::create(dist.join(&zip_name))?);
    let mut entries = Vec::new();
    for rel in &files {
        let src = root.join(rel);
        let data = fs::read(&src)?;
        let executable = is_executable(&src)?;
        let asset = format!("{target}_{}", rel.replace('/', "_"));
        fs::write(dist.join(&asset), &data)?;

        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .unix_permissions(if executable { 0o755 } else { 0o644 });
        zip.start_file(format!("velora/{rel}"), options)?;
        zip.write_all(&data)?;

        entries.push(FileEntry {
            path: rel.clone(),
            asset,
            sha256: velora_update::sha256_hex(&data),
            size: data.len() as u64,
            executable,
        });
    }
    zip.finish()?;
    fs::write(dist.join(format!("{target}.files.json")), serde_json::to_vec_pretty(&entries)?)?;
    println!("packaged {} files for {target} ({zip_name})", entries.len());
    Ok(())
}

fn manifest(dist: &Path, unsigned: bool) -> Result<()> {
    let mut targets = std::collections::BTreeMap::new();
    for entry in fs::read_dir(dist)? {
        let path = entry?.path();
        let name = path.file_name().unwrap_or_default().to_string_lossy().into_owned();
        if let Some(target) = name.strip_suffix(".files.json") {
            let files: Vec<FileEntry> = serde_json::from_slice(&fs::read(&path)?)?;
            targets.insert(target.to_string(), files);
            fs::remove_file(&path)?;
        }
    }
    ensure!(!targets.is_empty(), "no packaged targets in {}", dist.display());
    let manifest = Manifest { version: Version::current().to_string(), targets };
    let bytes = serde_json::to_vec_pretty(&manifest)?;
    fs::write(dist.join(MANIFEST), &bytes)?;
    if unsigned {
        println!("wrote unsigned {MANIFEST} for {}", manifest.targets.keys().cloned().collect::<Vec<_>>().join(", "));
        return Ok(());
    }

    let key = std::env::var("VELORA_SIGNING_KEY").context("VELORA_SIGNING_KEY is not set")?;
    let pkcs8 = B64.decode(key.trim()).context("VELORA_SIGNING_KEY is not base64")?;
    let pair =
        Ed25519KeyPair::from_pkcs8(&pkcs8).map_err(|_| anyhow::anyhow!("VELORA_SIGNING_KEY is not an Ed25519 key"))?;
    let signature = B64.encode(pair.sign(&bytes).as_ref());
    // Refuse to publish what the shipped binaries would reject.
    let public = velora_update::embedded_public_key();
    if public.is_empty() {
        bail!("crates/update/release-public-key.txt is empty; run `velora-release keygen` and commit the public key");
    }
    velora_update::verify_manifest(&bytes, &signature, public)
        .context("the signing key does not match crates/update/release-public-key.txt")?;
    fs::write(dist.join(SIGNATURE), signature)?;
    println!("wrote signed {MANIFEST} for version {}", manifest.version);
    Ok(())
}
