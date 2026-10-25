use std::{
    collections::HashMap,
    io::{BufRead, BufReader},
    net::TcpListener,
    sync::{Arc, Mutex},
};

use super::*;

const TARGET: &str = "x86_64-unknown-linux-gnu";

fn entry(path: &str, data: &[u8]) -> FileEntry {
    FileEntry {
        path: path.into(),
        asset: format!("{TARGET}_{}", path.replace('/', "_")),
        sha256: sha256_hex(data),
        size: data.len() as u64,
        executable: !path.contains('/'),
    }
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
fn parses_manifests() {
    let manifest = Manifest {
        version: "0.2.0".into(),
        targets: BTreeMap::from([(TARGET.into(), vec![entry("velora-host", b"x")])]),
    };
    let bytes = serde_json::to_vec(&manifest).unwrap();
    assert_eq!(parse_manifest(&bytes).unwrap(), manifest);
    assert!(parse_manifest(b"{").is_err());
    let bad_version = Manifest { version: "latest".into(), ..manifest };
    assert!(parse_manifest(&serde_json::to_vec(&bad_version).unwrap()).is_err());
}

#[test]
fn rejects_paths_outside_the_install_dir() {
    for path in ["../evil", "/etc/passwd", "lib/../../x", ""] {
        let manifest = Manifest {
            version: "0.2.0".into(),
            targets: BTreeMap::from([(TARGET.into(), vec![entry("ok", b"")]), ("t".into(), vec![entry(path, b"")])]),
        };
        assert!(parse_manifest(&serde_json::to_vec(&manifest).unwrap()).is_err(), "{path:?} accepted");
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
    let dir = temp_dir("install");
    fs::create_dir_all(dir.join("lib")).unwrap();
    fs::write(dir.join("velora-host"), "host v1").unwrap();
    fs::write(dir.join("lib/libav.so.1"), "same lib").unwrap();

    let files = [("velora-host", &b"host v2"[..]), ("velora", b"client v2"), ("lib/libav.so.1", b"same lib")];
    let entries: Vec<FileEntry> = files.iter().map(|(p, d)| entry(p, d)).collect();
    let manifest = Manifest { version: "0.9.0".into(), targets: BTreeMap::from([(TARGET.into(), entries.clone())]) };
    let mut served =
        HashMap::from([(format!("/releases/latest/download/{MANIFEST}"), serde_json::to_vec(&manifest).unwrap())]);
    for (e, (_, data)) in entries.iter().zip(&files) {
        served.insert(format!("/releases/download/v0.9.0/{}", e.asset), data.to_vec());
    }
    let (base, log) = serve(served);

    let updater = Updater::new(base.clone(), TARGET.into(), dir.clone(), Version(0, 1, 0));
    let update = updater.check().unwrap().expect("newer version available");
    assert_eq!(update.version, Version(0, 9, 0));
    let paths: Vec<_> = update.files.iter().map(|f| f.path.as_str()).collect();
    assert_eq!(paths, ["velora-host", "velora"], "unchanged files are skipped");

    assert_eq!(update.size(), 7 + 9);
    let mut reported = Vec::new();
    updater.install_with_progress(&update, &mut |done, total| reported.push((done, total))).unwrap();
    assert_eq!(reported.first(), Some(&(0, 16)));
    assert_eq!(reported.last(), Some(&(16, 16)));
    assert!(reported.windows(2).all(|w| w[0].0 <= w[1].0), "progress only grows");
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

    // Installed by another process: still newer than this one, with nothing left to fetch.
    let stale = updater.check().unwrap().expect("still newer than the running version");
    assert!(stale.files.is_empty());

    // Same version is not offered again; a newer local build ignores older releases.
    let current = Updater::new(base.clone(), TARGET.into(), dir.clone(), Version(0, 9, 0));
    assert!(current.check().unwrap().is_none());
    let newer = Updater::new(base, TARGET.into(), dir, Version(1, 0, 0));
    assert!(newer.check().unwrap().is_none());
}

#[test]
fn corrupted_download_changes_nothing() {
    let dir = temp_dir("corrupt");
    fs::write(dir.join("velora-host"), "host v1").unwrap();
    let e = entry("velora-host", b"host v2");
    let manifest = Manifest { version: "0.9.0".into(), targets: BTreeMap::from([(TARGET.into(), vec![e.clone()])]) };
    let (base, _) = serve(HashMap::from([
        (format!("/releases/latest/download/{MANIFEST}"), serde_json::to_vec(&manifest).unwrap()),
        (format!("/releases/download/v0.9.0/{}", e.asset), b"host vX".to_vec()),
    ]));
    let updater = Updater::new(base, TARGET.into(), dir.clone(), Version(0, 1, 0));
    let update = updater.check().unwrap().unwrap();
    let err = updater.install(&update).unwrap_err();
    assert!(format!("{err:#}").contains("does not match"), "{err:#}");
    assert_eq!(fs::read_to_string(dir.join("velora-host")).unwrap(), "host v1");
    assert!(!dir.join("velora-host.new").exists());
    // The failed install let go of the lock.
    Lock::acquire(&dir).unwrap();
}

#[test]
fn update_lock_is_exclusive_and_released_on_close() {
    let dir = temp_dir("lock");
    // A lock file left by an update that was killed (or by a version that deleted it on exit)
    // does not block: only a lock held by a live process does.
    fs::write(dir.join(LOCK_FILE), "").unwrap();
    let held = Lock::acquire(&dir).unwrap();
    let err = Lock::acquire(&dir).err().expect("a second lock while the first is held");
    assert_eq!(err.to_string(), "another update is in progress");
    drop(held);
    Lock::acquire(&dir).unwrap();
}
