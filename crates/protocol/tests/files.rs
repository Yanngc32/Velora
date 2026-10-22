//! File streams over a real QUIC connection: upload a folder, list it, download it back.

use std::path::{Path, PathBuf};

use velora_protocol::{
    files::{self, EntryKind, FileMsg, Tree},
    identity::Identity,
    tls,
};

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("velora-quic-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A server answering every file stream on its own file system, and a client connected to it.
async fn connect() -> quinn::Connection {
    let (host, client) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let endpoint = quinn::Endpoint::server(tls::server_config(&host).unwrap(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = endpoint.local_addr().unwrap();
    tokio::spawn(async move {
        let conn = endpoint.accept().await.unwrap().await.unwrap();
        while let Ok((mut send, mut recv)) = conn.accept_bi().await {
            tokio::spawn(async move {
                let _ = files::serve(&mut recv, &mut send).await;
            });
        }
    });
    let mut client_ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_ep.set_default_client_config(tls::client_config(&client, host.fingerprint()).unwrap());
    client_ep.connect(addr, tls::SERVER_NAME).unwrap().await.unwrap()
}

fn write_tree(root: &Path) {
    std::fs::create_dir_all(root.join("sub")).unwrap();
    std::fs::write(root.join("a.txt"), b"alpha").unwrap();
    std::fs::write(root.join("sub/b.bin"), (0..3_000_000u32).map(|i| i as u8).collect::<Vec<_>>()).unwrap();
}

#[tokio::test]
async fn upload_list_and_download() {
    let conn = connect().await;
    let (src, remote, back) = (temp_dir("src"), temp_dir("remote"), temp_dir("back"));
    write_tree(&src.join("pasta"));

    // Upload into a folder of the other side.
    let tree = Tree::gather(&[src.join("pasta")]).unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let upload = FileMsg::Upload { dir: remote.display().to_string() };
    let saved = files::request_send(&mut recv, &mut send, upload, &tree, &mut |_, _| {}).await.unwrap();
    assert_eq!(saved, ["pasta"]);

    // List it there.
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let path = remote.join("pasta").display().to_string();
    let entries = files::request_list(&mut recv, &mut send, Some(&path)).await.unwrap();
    let names: Vec<_> = entries.iter().map(|e| (e.name.as_str(), e.kind)).collect();
    assert_eq!(names, [("sub", EntryKind::Dir), ("a.txt", EntryKind::File)]);

    // And fetch it back.
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let got = files::request_download(&mut recv, &mut send, &path, &back, &mut |_, _| {}).await.unwrap();
    assert_eq!(got, ["pasta"]);
    assert_eq!(std::fs::read(back.join("pasta/a.txt")).unwrap(), b"alpha");
    assert_eq!(
        std::fs::read(back.join("pasta/sub/b.bin")).unwrap(),
        std::fs::read(src.join("pasta/sub/b.bin")).unwrap()
    );

    for dir in [src, remote, back] {
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[tokio::test]
async fn errors_come_back_as_messages() {
    let conn = connect().await;
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let missing = temp_dir("missing").join("nope");
    let err = files::request_list(&mut recv, &mut send, Some(&missing.display().to_string())).await.unwrap_err();
    assert!(format!("{err:#}").contains("nope"), "{err:#}");
}
