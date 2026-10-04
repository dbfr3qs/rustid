//! `--probe`: the container health check, over plain HTTP or, on loopback,
//! against a listener configured with `[tls]`.

use rustid_server::probe::{fallback_allowed, probe};

/// A TLS listener (certificate from a throwaway CA) answering `/ready` with
/// `status`; its port.
async fn tls_server(dir: &std::path::Path, status: u16) -> u16 {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = rcgen::CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .signed_by(&key, &ca)
        .unwrap();
    std::fs::write(dir.join("cert.pem"), cert.pem()).unwrap();
    std::fs::write(dir.join("key.pem"), key.serialize_pem()).unwrap();
    let tls = rustid_server::tls::server_config(&rustid_server::config::TlsConfig {
        client_certificates: Default::default(),
        cipher_suites: Default::default(),
        cert_file: dir.join("cert.pem"),
        key_file: dir.join("key.pem"),
    })
    .unwrap();
    let status = axum::http::StatusCode::from_u16(status).unwrap();
    let app =
        axum::Router::new().route("/ready", axum::routing::get(move || async move { status }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let listener = rustid_server::tls::TlsListener::new(listener, tls).unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await });
    port
}

#[tokio::test]
async fn probe_falls_back_to_https_on_loopback() {
    let dir = tempfile::tempdir().unwrap();
    let port = tls_server(dir.path(), 200).await;
    assert_eq!(probe(&format!("http://127.0.0.1:{port}/ready")).await, 0);
}

#[tokio::test]
async fn probe_reports_unready_and_unreachable() {
    let dir = tempfile::tempdir().unwrap();
    let port = tls_server(dir.path(), 503).await;
    assert_eq!(probe(&format!("http://127.0.0.1:{port}/ready")).await, 1);
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed_port = closed.local_addr().unwrap().port();
    drop(closed);
    assert_eq!(
        probe(&format!("http://127.0.0.1:{closed_port}/ready")).await,
        1
    );
}

#[test]
fn probe_never_skips_verification_off_loopback() {
    assert!(fallback_allowed("http://127.0.0.1:8080/ready"));
    assert!(fallback_allowed("http://[::1]:8080/ready"));
    assert!(fallback_allowed("http://localhost:8080/ready"));
    assert!(!fallback_allowed("http://example.com/ready"));
    assert!(
        !fallback_allowed("https://127.0.0.1:8080/ready"),
        "only http falls back"
    );
    assert!(!fallback_allowed("not a url"));
}
