//! Behind a reverse proxy: forwarded headers from a trusted proxy set the
//! scheme and host URLs are built from; anyone else's are ignored.

use std::path::{Path, PathBuf};

use rustid_server::config::ServerConfig;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

fn config(
    dir: &Path,
    trusted: &[&str],
) -> Result<ServerConfig, rustid_server::config::ConfigError> {
    let config = serde_json::json!({
        "signing_keys": [{ "kid": "k1", "alg": "RS256", "key_file": fixture("signing-key.pem") }],
        "clients_file": fixture("clients.json"),
        "resources_file": fixture("resources.json"),
        "protocol": { "key_management": { "enabled": false } },
        "forwarded_headers": { "trusted_proxies": trusted },
    });
    let path = dir.join("rustid.json");
    std::fs::write(&path, config.to_string()).unwrap();
    ServerConfig::load(Some(&path))
}

async fn start(trusted: &[&str]) -> (String, tokio::sync::oneshot::Sender<()>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let config = config(dir.path(), trusted).unwrap();
    let app = rustid_server::build(&config).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(rustid_server::serve(listener, app, async move {
        let _ = stopped.await;
    }));
    (base, stop, dir)
}

async fn issuer(base: &str, headers: &[(&str, &str)]) -> (u16, Option<String>) {
    let mut request =
        reqwest::Client::new().get(format!("{base}/.well-known/openid-configuration"));
    for (k, v) in headers {
        request = request.header(*k, *v);
    }
    let response = request.send().await.unwrap();
    let status = response.status().as_u16();
    let issuer = response
        .json::<serde_json::Value>()
        .await
        .ok()
        .and_then(|d| d["issuer"].as_str().map(str::to_owned));
    (status, issuer)
}

#[tokio::test]
async fn a_trusted_proxys_rightmost_scheme_and_host_are_used() {
    let (base, _stop, _dir) = start(&["127.0.0.0/8", "::1"]).await;
    let (status, iss) = issuer(
        &base,
        &[
            ("x-forwarded-proto", "http, https"),
            ("x-forwarded-host", "spoofed.test, id.example.com"),
        ],
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(iss.as_deref(), Some("https://id.example.com"));

    // A host that isn't one is refused, never built into URLs.
    let (status, _) = issuer(&base, &[("x-forwarded-host", "bad host/")]).await;
    assert_eq!(status, 400);

    // Nothing forwarded: the request as it arrived.
    let (_, iss) = issuer(&base, &[]).await;
    assert_eq!(iss.as_deref(), Some(base.as_str()));
}

#[tokio::test]
async fn an_untrusted_peers_headers_are_ignored() {
    let (base, _stop, _dir) = start(&["10.0.0.0/8"]).await;
    let (_, iss) = issuer(
        &base,
        &[
            ("x-forwarded-proto", "https"),
            ("x-forwarded-host", "id.example.com"),
        ],
    )
    .await;
    assert_eq!(iss.as_deref(), Some(base.as_str()));
}

#[test]
fn an_invalid_proxy_entry_fails_startup() {
    let dir = tempfile::tempdir().unwrap();
    for bad in ["10.0.0.0/33", "not-an-ip", "::1/129"] {
        let error = config(dir.path(), &[bad]).unwrap_err();
        assert!(error.to_string().contains(bad), "{error}");
    }
}

/// A server on TLS with `trusted` proxies: its base URL and an HTTPS
/// client that trusts its certificate.
async fn start_tls(
    trusted: &[&str],
) -> (
    String,
    reqwest::Client,
    tokio::sync::oneshot::Sender<()>,
    tempfile::TempDir,
) {
    let dir = tempfile::tempdir().unwrap();
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = rcgen::CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .signed_by(&key, &ca)
        .unwrap();
    std::fs::write(dir.path().join("cert.pem"), cert.pem()).unwrap();
    std::fs::write(dir.path().join("key.pem"), key.serialize_pem()).unwrap();
    let config = serde_json::json!({
        "tls": { "cert_file": dir.path().join("cert.pem"), "key_file": dir.path().join("key.pem") },
        "signing_keys": [{ "kid": "k1", "alg": "RS256", "key_file": fixture("signing-key.pem") }],
        "clients_file": fixture("clients.json"),
        "resources_file": fixture("resources.json"),
        "protocol": { "key_management": { "enabled": false } },
        "forwarded_headers": { "trusted_proxies": trusted },
    });
    let path = dir.path().join("rustid.json");
    std::fs::write(&path, config.to_string()).unwrap();
    let app = rustid_server::build(&ServerConfig::load(Some(&path)).unwrap())
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(rustid_server::serve(listener, app, async move {
        let _ = stopped.await;
    }));
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca.pem().as_bytes()).unwrap())
        .resolve("localhost", addr)
        .build()
        .unwrap();
    (
        format!("https://localhost:{}", addr.port()),
        client,
        stop,
        dir,
    )
}

async fn tls_issuer(client: &reqwest::Client, base: &str, proto: &str) -> String {
    let document: serde_json::Value = client
        .get(format!("{base}/.well-known/openid-configuration"))
        .header("x-forwarded-proto", proto)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    document["issuer"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn over_tls_only_a_trusted_proxy_can_say_the_request_was_http() {
    let (base, client, _stop, _dir) = start_tls(&["127.0.0.0/8"]).await;
    let plain = base.replace("https://", "http://");
    assert_eq!(tls_issuer(&client, &base, "http").await, plain);
    assert_eq!(tls_issuer(&client, &base, "https").await, base);

    let (base, client, _stop, _dir) = start_tls(&["10.0.0.0/8"]).await;
    assert_eq!(tls_issuer(&client, &base, "http").await, base);
}
