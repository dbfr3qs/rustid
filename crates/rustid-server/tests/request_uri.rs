//! The server's request URI fetcher: GET without following redirects,
//! the media type without parameters, and unreachable hosts as `None`.

use rustid_core::request_uri::RequestUriFetcher;
use rustid_server::request_uri::HttpRequestUriFetcher;

async fn host() -> String {
    let app = axum::Router::new()
        .route(
            "/object",
            axum::routing::get(|| async {
                (
                    [(
                        "content-type",
                        "application/oauth-authz-req+jwt; charset=utf-8",
                    )],
                    "a.b.c",
                )
            }),
        )
        .route(
            "/redirect",
            axum::routing::get(|| async {
                (axum::http::StatusCode::FOUND, [("location", "/object")], "")
            }),
        )
        .route(
            "/missing",
            axum::routing::get(|| async { axum::http::StatusCode::NOT_FOUND }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await });
    base
}

#[tokio::test]
async fn fetches_bodies_statuses_and_media_types_without_following_redirects() {
    let base = host().await;
    let fetcher = HttpRequestUriFetcher::new().unwrap();
    let object = fetcher.fetch(&format!("{base}/object")).await.unwrap();
    assert_eq!(object.status, 200);
    assert_eq!(
        object.content_type.as_deref(),
        Some("application/oauth-authz-req+jwt")
    );
    assert_eq!(object.body, "a.b.c");
    let redirect = fetcher.fetch(&format!("{base}/redirect")).await.unwrap();
    assert_eq!(redirect.status, 302, "not followed");
    let missing = fetcher.fetch(&format!("{base}/missing")).await.unwrap();
    assert_eq!(missing.status, 404);
    assert!(
        fetcher
            .fetch("http://127.0.0.1:1/unreachable")
            .await
            .is_none()
    );
    assert!(fetcher.fetch("not a url").await.is_none());
}

/// A request object host on HTTPS, its certificate signed by a private CA;
/// the base URL and the CA's PEM file.
async fn tls_host(dir: &std::path::Path) -> (String, std::path::PathBuf) {
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
    std::fs::write(dir.join("ca.pem"), ca.pem()).unwrap();
    let tls = rustid_server::tls::server_config(&rustid_server::config::TlsConfig {
        client_certificates: Default::default(),
        cipher_suites: Default::default(),
        cert_file: dir.join("cert.pem"),
        key_file: dir.join("key.pem"),
    })
    .unwrap();
    let app = axum::Router::new().route("/object", axum::routing::get(|| async { "a.b.c" }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let listener = rustid_server::tls::TlsListener::new(listener, tls).unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await });
    (format!("https://localhost:{port}"), dir.join("ca.pem"))
}

#[tokio::test]
async fn a_configured_ca_is_trusted_for_https_hosts() {
    let dir = tempfile::tempdir().unwrap();
    let (base, ca) = tls_host(dir.path()).await;
    let uri = format!("{base}/object");
    assert!(
        HttpRequestUriFetcher::new()
            .unwrap()
            .fetch(&uri)
            .await
            .is_none()
    );
    let fetched = HttpRequestUriFetcher::with_ca_file(Some(&ca))
        .unwrap()
        .fetch(&uri)
        .await
        .expect("trusted");
    assert_eq!(fetched.status, 200);
}
