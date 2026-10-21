use std::{
    collections::HashMap,
    io::{BufRead, BufReader},
    net::TcpListener,
    sync::{Arc, Mutex},
};

use ring::signature::{Ed25519KeyPair, KeyPair};

use super::*;

const TARGET: &str = "x86_64-unknown-linux-gnu";

fn keypair() -> (Ed25519KeyPair, String) {
    let doc = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap();
    let public = B64.encode(pair.public_key().as_ref());
    (pair, public)
}

fn entry(path: &str, data: &[u8]) -> FileEntry {
    FileEntry {
        path: path.into(),
        asset: format!("{TARGET}_{}", path.replace('/', "_")),
        sha256: sha256_hex(data),
        size: data.len() as u64,
        executable: !path.contains('/'),
    }
}

fn signed(manifest: &Manifest, key: &Ed25519KeyPair) -> (Vec<u8>, String) {
    let bytes = serde_json::to_vec(manifest).unwrap();
    let sig = B64.encode(key.sign(&bytes).as_ref());
    (bytes, sig)
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("velora-update-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn versions() {
    let v: Version = "v1.2.10".parse().unwrap();
    assert_eq!(v, Version(1, 2, 10));
    assert!(Version(1, 2, 10) > Version(1, 2, 9));
    assert!(Version(0, 10, 0) > Version(0, 9, 99));
    assert!("1.2".parse::<Version>().is_err());
    assert!("1.2.3-beta".parse::<Version>().is_err());
    assert_eq!(Version::current().to_string(), env!("CARGO_PKG_VERSION"));
}

#[test]
fn manifest_signatures() {
    let (key, public) = keypair();
    let manifest = Manifest {
        version: "0.2.0".into(),
        targets: BTreeMap::from([(TARGET.into(), vec![entry("velora-host", b"x")])]),
    };
    let (bytes, sig) = signed(&manifest, &key);
    assert_eq!(verify_manifest(&bytes, &sig, &public).unwrap(), manifest);

    let mut tampered = bytes.clone();
    tampered[5] ^= 1;
    assert!(verify_manifest(&tampered, &sig, &public).is_err());
    let (_, other) = keypair();
    assert!(verify_manifest(&bytes, &sig, &other).is_err());
    assert!(verify_manifest(&bytes, &sig, "").is_err(), "unconfigured key disables updates");
}

#[test]
fn rejects_paths_outside_the_install_dir() {
    let (key, public) = keypair();
    for path in ["../evil", "/etc/passwd", "lib/../../x", ""] {
        let manifest = Manifest {
            version: "0.2.0".into(),
            targets: BTreeMap::from([(TARGET.into(), vec![entry("ok", b"")]), ("t".into(), vec![entry(path, b"")])]),
        };
        let (bytes, sig) = signed(&manifest, &key);
        assert!(verify_manifest(&bytes, &sig, &public).is_err(), "{path:?} accepted");
    }
}

#[test]
fn swap_rolls_back_on_failure() {
    let dir = temp_dir("rollback");
    let (a, b) = (dir.join("a"), dir.join("b"));
    fs::write(&a, "old a").unwrap();
    fs::write(&b, "old b").unwrap();
    fs::write(with_suffix(&a, ".new"), "new a").unwrap();
    // `b.new` is missing, so the second rename fails.
    assert!(swap_in(&dir, &[a.clone(), b.clone()]).is_err());
    assert_eq!(fs::read_to_string(&a).unwrap(), "old a");
    assert_eq!(fs::read_to_string(&b).unwrap(), "old b");
    assert!(!with_suffix(&a, ".new").exists());
    assert!(!with_suffix(&a, ".old").exists());
}

#[test]
fn cleanup_keeps_the_only_copy() {
    let dir = temp_dir("cleanup");
    fs::create_dir_all(dir.join("lib")).unwrap();
    for f in ["app", "app.old", "app.old.3", "lib/x.so.1", "lib/x.so.1.old", "orphan.old", "partial.new", "keep.txt"] {
        fs::write(dir.join(f), "").unwrap();
    }
    cleanup(&dir);
    let left = |f: &str| dir.join(f).exists();
    assert!(left("app") && left("lib/x.so.1") && left("keep.txt"));
    assert!(!left("app.old") && !left("app.old.3") && !left("lib/x.so.1.old") && !left("partial.new"));
    assert!(left("orphan.old"), "a backup whose original is missing is kept");
}

/// Minimal HTTP/1.1 server returning fixed bodies by path and counting requests.
fn serve(files: HashMap<String, Vec<u8>>) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}/releases", listener.local_addr().unwrap());
    let log = Arc::new(Mutex::new(Vec::new()));
    let seen = log.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut line = String::new();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            reader.read_line(&mut line).unwrap();
            loop {
                let mut header = String::new();
                if reader.read_line(&mut header).unwrap() == 0 || header == "\r\n" {
                    break;
                }
            }
            let path = line.split_whitespace().nth(1).unwrap_or_default().to_string();
            seen.lock().unwrap().push(path.clone());
            let (status, body) = match files.get(&path) {
                Some(b) => ("200 OK", b.clone()),
                None => ("404 Not Found", Vec::new()),
            };
            let head = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&body);
        }
    });
    (base, log)
}

#[test]
fn updates_only_changed_files() {
    let (key, public) = keypair();
    let dir = temp_dir("install");
    fs::create_dir_all(dir.join("lib")).unwrap();
    fs::write(dir.join("velora-host"), "host v1").unwrap();
    fs::write(dir.join("lib/libav.so.1"), "same lib").unwrap();

    let files = [("velora-host", &b"host v2"[..]), ("velora", b"client v2"), ("lib/libav.so.1", b"same lib")];
    let entries: Vec<FileEntry> = files.iter().map(|(p, d)| entry(p, d)).collect();
    let manifest = Manifest { version: "0.9.0".into(), targets: BTreeMap::from([(TARGET.into(), entries.clone())]) };
    let (bytes, sig) = signed(&manifest, &key);
    let mut served = HashMap::from([
        (format!("/releases/latest/download/{MANIFEST}"), bytes),
        (format!("/releases/latest/download/{SIGNATURE}"), sig.into_bytes()),
    ]);
    for (e, (_, data)) in entries.iter().zip(&files) {
        served.insert(format!("/releases/download/v0.9.0/{}", e.asset), data.to_vec());
    }
    let (base, log) = serve(served);

    let updater = Updater::new(base.clone(), public.clone(), TARGET.into(), dir.clone(), Version(0, 1, 0));
    let update = updater.check().unwrap().expect("newer version available");
    assert_eq!(update.version, Version(0, 9, 0));
    let paths: Vec<_> = update.files.iter().map(|f| f.path.as_str()).collect();
    assert_eq!(paths, ["velora-host", "velora"], "unchanged files are skipped");

    updater.install(&update).unwrap();
    assert_eq!(fs::read_to_string(dir.join("velora-host")).unwrap(), "host v2");
    assert_eq!(fs::read_to_string(dir.join("velora")).unwrap(), "client v2");
    assert_eq!(fs::read_to_string(dir.join("velora-host.old")).unwrap(), "host v1");
    assert!(!log.lock().unwrap().iter().any(|p| p.ends_with("libav.so.1")));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(dir.join("velora")).unwrap().permissions().mode() & 0o777, 0o755);
    }
    cleanup(&dir);
    assert!(!dir.join("velora-host.old").exists());

    // Same version is not offered again; a newer local build ignores older releases.
    let current = Updater::new(base.clone(), public.clone(), TARGET.into(), dir.clone(), Version(0, 9, 0));
    assert!(current.check().unwrap().is_none());
    let newer = Updater::new(base, public, TARGET.into(), dir, Version(1, 0, 0));
    assert!(newer.check().unwrap().is_none());
}

#[test]
fn corrupted_download_changes_nothing() {
    let (key, public) = keypair();
    let dir = temp_dir("corrupt");
    fs::write(dir.join("velora-host"), "host v1").unwrap();
    let e = entry("velora-host", b"host v2");
    let manifest = Manifest { version: "0.9.0".into(), targets: BTreeMap::from([(TARGET.into(), vec![e.clone()])]) };
    let (bytes, sig) = signed(&manifest, &key);
    let (base, _) = serve(HashMap::from([
        (format!("/releases/latest/download/{MANIFEST}"), bytes),
        (format!("/releases/latest/download/{SIGNATURE}"), sig.into_bytes()),
        (format!("/releases/download/v0.9.0/{}", e.asset), b"host vX".to_vec()),
    ]));
    let updater = Updater::new(base, public, TARGET.into(), dir.clone(), Version(0, 1, 0));
    let update = updater.check().unwrap().unwrap();
    let err = updater.install(&update).unwrap_err();
    assert!(format!("{err:#}").contains("does not match"), "{err:#}");
    assert_eq!(fs::read_to_string(dir.join("velora-host")).unwrap(), "host v1");
    assert!(!dir.join("velora-host.new").exists() && !dir.join(LOCK_FILE).exists());
}
