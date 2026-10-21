//! QUIC/TLS setup with certificate pinning.
//!
//! There is no CA. Every device has a long-lived self-signed certificate and is identified by
//! the SHA-256 fingerprint of it:
//! - the client accepts the host only if its certificate matches the pinned fingerprint
//!   (obtained once through the pairing code);
//! - the host requires a client certificate and authorizes the connection at the application
//!   layer by checking its fingerprint against the list of paired clients.
//!
//! The TLS handshake still verifies that each peer holds the private key of the certificate it
//! presents, so fingerprints cannot be spoofed.

use std::{fmt, sync::Arc, time::Duration};

use anyhow::{anyhow, Context, Result};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, WebPkiSupportedAlgorithms},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
    DigitallySignedStruct, DistinguishedName, SignatureScheme,
};

use crate::{identity::Identity, wire::ALPN};

/// TLS server name used by clients; ignored by the pinning verifier.
pub const SERVER_NAME: &str = "velora-host";

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint(pub [u8; 32]);

impl Fingerprint {
    pub fn of(cert_der: &[u8]) -> Self {
        let digest = ring::digest::digest(&ring::digest::SHA256, cert_der);
        Self(digest.as_ref().try_into().unwrap())
    }

    /// Short human-readable form, for confirmation in UIs and logs.
    pub fn short(&self) -> String {
        self.0[..6].iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
    }

    pub fn to_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.0)
    }

    pub fn from_base64(s: &str) -> Result<Self> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)?;
        Ok(Self(bytes.try_into().map_err(|_| anyhow!("fingerprint must be 32 bytes"))?))
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({})", self.short())
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.short())
    }
}

/// Extracts the peer's certificate fingerprint from an established connection.
pub fn peer_fingerprint(conn: &quinn::Connection) -> Result<Fingerprint> {
    let identity = conn.peer_identity().context("peer presented no certificate")?;
    let certs =
        identity.downcast::<Vec<CertificateDer<'static>>>().map_err(|_| anyhow!("unexpected peer identity type"))?;
    let leaf = certs.first().context("peer presented no certificate")?;
    Ok(Fingerprint::of(leaf))
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn cert_and_key(identity: &Identity) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    (
        vec![CertificateDer::from(identity.cert_der.clone())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(identity.key_der.clone())),
    )
}

/// Transport tuned for interactive streaming: fast loss detection and frequent keep-alives so
/// NAT mappings stay open. Limits are per direction: only the client receives video (large
/// windows, many streams), while the host accepts just the control stream and datagrams, so an
/// unauthenticated peer cannot make it buffer much.
fn transport_config(receives_video: bool) -> quinn::TransportConfig {
    let mut t = quinn::TransportConfig::default();
    t.max_idle_timeout(Some(Duration::from_secs(15).try_into().unwrap()))
        .keep_alive_interval(Some(Duration::from_secs(2)))
        .initial_rtt(Duration::from_millis(50))
        .datagram_receive_buffer_size(Some(64 * 1024));
    if receives_video {
        // Room for a 4K keyframe in flight.
        t.max_concurrent_uni_streams(256u32.into())
            .max_concurrent_bidi_streams(0u32.into())
            .stream_receive_window((8u32 * 1024 * 1024).into())
            .receive_window((32u32 * 1024 * 1024).into());
    } else {
        t.max_concurrent_uni_streams(0u32.into())
            .max_concurrent_bidi_streams(1u32.into())
            .stream_receive_window((256u32 * 1024).into())
            .receive_window((512u32 * 1024).into())
            .send_window(32 * 1024 * 1024);
    }
    t
}

pub fn server_config(identity: &Identity) -> Result<quinn::ServerConfig> {
    let provider = provider();
    let (certs, key) = cert_and_key(identity);
    let mut tls = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(RequireClientCert(provider.signature_verification_algorithms)))
        .with_single_cert(certs, key)?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    tls.max_early_data_size = 0;

    let mut config = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
    config.transport_config(Arc::new(transport_config(false)));
    Ok(config)
}

pub fn client_config(identity: &Identity, host: Fingerprint) -> Result<quinn::ClientConfig> {
    let provider = provider();
    let (certs, key) = cert_and_key(identity);
    let mut tls = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedServerCert {
            expected: host,
            algorithms: provider.signature_verification_algorithms,
        }))
        .with_client_auth_cert(certs, key)?;
    tls.alpn_protocols = vec![ALPN.to_vec()];

    let mut config = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?));
    config.transport_config(Arc::new(transport_config(true)));
    Ok(config)
}

#[derive(Debug)]
struct PinnedServerCert {
    expected: Fingerprint,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedServerCert {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if Fingerprint::of(end_entity) == self.expected {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(rustls::PeerIncompatible::Tls13RequiredForQuic))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// Requires a certificate and proof of key possession; authorization happens later by
/// fingerprint.
#[derive(Debug)]
struct RequireClientCert(WebPkiSupportedAlgorithms);

impl ClientCertVerifier for RequireClientCert {
    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(rustls::PeerIncompatible::Tls13RequiredForQuic))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_schemes()
    }
}
