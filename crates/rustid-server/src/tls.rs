//! HTTPS on the server's own socket: a listener that completes each TLS
//! handshake on a task of its own, so a slow or stalled client never holds
//! up the others, and hands finished connections to `axum::serve`.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls;
use tokio_rustls::server::TlsStream;

use crate::config::{CipherSuites, ClientCertificateMode, TlsConfig};

/// How long a client has to complete the handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Handshakes finished but not yet taken by the server.
const BACKLOG: usize = 128;

/// Whether the configured private key is an RSA key (`None` when it
/// can't be read; `server_config` reports why).
pub fn key_is_rsa(config: &TlsConfig) -> Option<bool> {
    let key = PrivateKeyDer::from_pem_file(&config.key_file).ok()?;
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let signing = provider.key_provider.load_private_key(key).ok()?;
    Some(signing.algorithm() == rustls::SignatureAlgorithm::RSA)
}

/// Reads the certificate chain and key into a rustls server configuration
/// that offers HTTP/1.1.
pub fn server_config(config: &TlsConfig) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    let chain = read_chain(&config.cert_file)?;
    let key = PrivateKeyDer::from_pem_file(&config.key_file)
        .with_context(|| format!("reading a private key from {}", config.key_file.display()))?;
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    if config.cipher_suites == CipherSuites::Fapi {
        use rustls::CipherSuite::{
            TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        };
        provider.cipher_suites.retain(|s| {
            s.tls13().is_some()
                || matches!(
                    s.suite(),
                    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 | TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                )
        });
    }
    let provider = Arc::new(provider);
    let builder = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .context("TLS protocol versions")?;
    let builder = match config.client_certificates {
        ClientCertificateMode::None => builder.with_no_client_auth(),
        ClientCertificateMode::Request => {
            builder.with_client_cert_verifier(Arc::new(AnyClientCertificate { provider }))
        }
    };
    let mut server = builder.with_single_cert(chain, key).with_context(|| {
        format!(
            "the key in {} does not match the certificate in {}",
            config.key_file.display(),
            config.cert_file.display()
        )
    })?;
    server.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(server))
}

/// Asks for a client certificate without requiring one and accepts any:
/// the handshake signature proves the client holds its key, and client
/// authentication decides what the certificate is worth (a thumbprint
/// secret, or a subject name when it chains to `mutual_tls.client_ca_file`).
#[derive(Debug)]
struct AnyClientCertificate {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::server::danger::ClientCertVerifier for AnyClientCertificate {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The client certificate a finished handshake presented, with its chain.
pub fn peer_certificate(
    stream: &TlsStream<TcpStream>,
    roots: Option<&rustid_core::client_certificate::ClientCaRoots>,
) -> Option<rustid_core::client_certificate::ClientCertificate> {
    let (leaf, intermediates) = stream.get_ref().1.peer_certificates()?.split_first()?;
    rustid_core::client_certificate::ClientCertificate::parse_chain(leaf, intermediates, roots)
}

fn read_chain(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let chain = CertificateDer::pem_file_iter(path)
        .and_then(Iterator::collect::<Result<Vec<_>, _>>)
        .with_context(|| format!("reading certificates from {}", path.display()))?;
    if chain.is_empty() {
        anyhow::bail!("no certificate in {}", path.display());
    }
    Ok(chain)
}

/// Accepts TCP connections and yields them once their TLS handshake is done.
pub struct TlsListener {
    local: SocketAddr,
    ready: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    accepting: tokio::task::JoinHandle<()>,
}

impl TlsListener {
    pub fn new(listener: TcpListener, config: Arc<rustls::ServerConfig>) -> std::io::Result<Self> {
        let local = listener.local_addr()?;
        let acceptor = TlsAcceptor::from(config);
        let (tx, ready) = mpsc::channel(BACKLOG);
        let accepting = tokio::spawn(async move {
            loop {
                let (stream, remote) = match listener.accept().await {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        // As axum's TcpListener: log, back off briefly, retry.
                        tracing::warn!(%error, "accepting a connection failed");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                };
                let acceptor = acceptor.clone();
                let tx = tx.clone();
                tokio::spawn(async move {
                    match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                        Ok(Ok(tls)) => {
                            let _ = tx.send((tls, remote)).await;
                        }
                        Ok(Err(error)) => {
                            tracing::debug!(%error, %remote, "TLS handshake failed");
                        }
                        Err(_) => tracing::debug!(%remote, "TLS handshake timed out"),
                    }
                });
            }
        });
        Ok(TlsListener {
            local,
            ready,
            accepting,
        })
    }
}

impl Drop for TlsListener {
    fn drop(&mut self) {
        self.accepting.abort();
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.ready.recv().await {
            Some(accepted) => accepted,
            // The accept loop only ends when this listener is dropped.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.local)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CipherSuites;

    fn config(dir: &Path, cipher_suites: CipherSuites) -> TlsConfig {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        std::fs::write(dir.join("cert.pem"), cert.pem()).unwrap();
        std::fs::write(dir.join("key.pem"), key.serialize_pem()).unwrap();
        TlsConfig {
            cert_file: dir.join("cert.pem"),
            key_file: dir.join("key.pem"),
            client_certificates: ClientCertificateMode::None,
            cipher_suites,
        }
    }

    fn suites(server: &rustls::ServerConfig) -> Vec<String> {
        server
            .crypto_provider()
            .cipher_suites
            .iter()
            .map(|s| format!("{:?}", s.suite()))
            .collect()
    }

    /// FAPI2-SP-ID2-5.2.2: over TLS 1.2, only the ECDHE-RSA AES-GCM suites
    /// (the DHE ones aren't offered by rustls); TLS 1.3's all remain.
    #[test]
    fn fapi_cipher_suites_limit_tls12_to_the_permitted_ones() {
        let dir = tempfile::tempdir().unwrap();
        let fapi = suites(&server_config(&config(dir.path(), CipherSuites::Fapi)).unwrap());
        let tls12: Vec<&String> = fapi.iter().filter(|s| !s.starts_with("TLS13")).collect();
        assert_eq!(
            tls12,
            [
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
            ]
        );
        assert!(fapi.iter().any(|s| s.starts_with("TLS13")));
        let default = suites(&server_config(&config(dir.path(), CipherSuites::Default)).unwrap());
        assert!(
            default
                .iter()
                .any(|s| s.contains("ECDSA") && !s.starts_with("TLS13"))
        );
    }
}
