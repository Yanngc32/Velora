//! Certificate pinning and client identification over a real QUIC handshake.

use velora_protocol::{
    identity::Identity,
    tls::{self, Fingerprint},
};

async fn connect(server: &Identity, client: &Identity, pinned: Fingerprint) -> Result<Fingerprint, String> {
    let endpoint =
        quinn::Endpoint::server(tls::server_config(server).unwrap(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = endpoint.local_addr().unwrap();
    let accept = tokio::spawn(async move {
        let conn = endpoint.accept().await.unwrap().await.map_err(|e| e.to_string())?;
        tls::peer_fingerprint(&conn).map_err(|e| e.to_string())
    });

    let mut client_ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_ep.set_default_client_config(tls::client_config(client, pinned).unwrap());
    let result = client_ep.connect(addr, tls::SERVER_NAME).unwrap().await;
    match result {
        Ok(conn) => {
            let seen = accept.await.unwrap();
            conn.close(0u32.into(), b"");
            seen
        }
        Err(e) => {
            accept.abort();
            Err(e.to_string())
        }
    }
}

#[tokio::test]
async fn host_sees_the_client_fingerprint() {
    let (host, client) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let seen = connect(&host, &client, host.fingerprint()).await.unwrap();
    assert_eq!(seen, client.fingerprint());
}

#[tokio::test]
async fn client_rejects_an_unpinned_host() {
    let (host, impostor, client) =
        (Identity::generate().unwrap(), Identity::generate().unwrap(), Identity::generate().unwrap());
    let err = connect(&impostor, &client, host.fingerprint()).await.unwrap_err();
    assert!(err.to_lowercase().contains("certificate"), "{err}");
}
