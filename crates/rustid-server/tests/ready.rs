#![cfg(unix)]

//! The binary's readiness: `/ready` over a real listener, key management
//! on (its default) with a writable or unwritable key path, Postgres, and
//! `--probe`.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn wait_for_listen(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "server never started listening");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The server with `config` (plus the fixture clients and resources),
/// listening on `port`.
fn start(dir: &Path, port: u16, mut config: serde_json::Value) -> Child {
    config["listen"] = format!("127.0.0.1:{port}").into();
    config["clients_file"] = fixture("clients.json").to_str().unwrap().into();
    config["resources_file"] = fixture("resources.json").to_str().unwrap().into();
    let path = dir.join("rustid.json");
    std::fs::write(&path, config.to_string()).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_rustid-server"))
        .args(["--config", path.to_str().unwrap()])
        .env("NO_COLOR", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait_for_listen(port);
    child
}

/// Key management on, keys kept in `key_path`, and a configured data
/// protection key: without one the memory store keeps its generated key in
/// `key_path` too, and an unwritable `key_path` stops startup instead.
fn key_management(key_path: &Path) -> serde_json::Value {
    serde_json::json!({
        "protocol": { "key_management": { "enabled": true, "key_path": key_path } },
        "data_protection": { "keys": [{ "id": "t", "secret": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" }] },
    })
}

fn probe(url: &str) -> std::process::ExitStatus {
    Command::new(env!("CARGO_BIN_EXE_rustid-server"))
        .args(["--probe", url])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
}

/// Probes until `url` is ready, as a container health check retries:
/// key management creates the first key on demand, which can take longer
/// than one probe allows.
fn probe_until_ready(url: &str) -> std::process::ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let status = probe(url);
        if status.success() || Instant::now() > deadline {
            return status;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn stop(mut child: Child) {
    child.kill().unwrap();
    child.wait().unwrap();
}

#[test]
fn a_fresh_server_with_key_management_is_ready() {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let child = start(dir.path(), port, key_management(&dir.path().join("keys")));
    let status = probe_until_ready(&format!("http://127.0.0.1:{port}/ready"));
    stop(child);
    assert!(status.success(), "{status}");
}

#[test]
fn an_unwritable_key_path_is_not_ready() {
    let dir = tempfile::tempdir().unwrap();
    // A file where the key directory should be: keys can't be written.
    let blocked = dir.path().join("keys");
    std::fs::write(&blocked, "not a directory").unwrap();
    let port = free_port();
    let mut child = start(dir.path(), port, key_management(&blocked));
    let url = format!("http://127.0.0.1:{port}/ready");
    // A fresh server's first probes can be 503 while the first key is
    // made; this one must stay unready.
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        assert_eq!(probe(&url).code(), Some(1), "became ready");
        std::thread::sleep(Duration::from_millis(500));
    }
    let body: serde_json::Value = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(async { reqwest::get(&url).await.unwrap().json().await.unwrap() });
    let still_running = child.try_wait().unwrap().is_none();
    stop(child);
    assert_eq!(
        body,
        serde_json::json!({ "status": "unavailable", "reason": "signing_key" })
    );
    assert!(still_running, "readiness failures must not stop the server");
}

#[test]
fn probe_fails_when_nothing_listens() {
    let port = free_port();
    let started = Instant::now();
    let status = probe(&format!("http://127.0.0.1:{port}/ready"));
    assert_eq!(status.code(), Some(1));
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[test]
fn a_postgres_server_is_ready() {
    let Some(db) = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(scratch_database())
    else {
        eprintln!("skipped: TEST_POSTGRES_URL is not set");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let child = start(
        dir.path(),
        port,
        serde_json::json!({
            "signing_keys": [{ "kid": "k1", "alg": "RS256", "key_file": fixture("signing-key.pem") }],
            "protocol": { "key_management": { "enabled": false } },
            "store": { "kind": "postgres", "postgres": { "url": db } },
        }),
    );
    let status = probe(&format!("http://127.0.0.1:{port}/ready"));
    stop(child);
    assert!(status.success(), "{status}");
}

/// A fresh database on the TEST_POSTGRES_URL server.
async fn scratch_database() -> Option<String> {
    let base = std::env::var("TEST_POSTGRES_URL").ok()?;
    let name = format!("ready_{}", std::process::id());
    let admin = sqlx::PgPool::connect(&base).await.ok()?;
    let _ = sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP DATABASE IF EXISTS {name}"
    )))
    .execute(&admin)
    .await;
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
        .execute(&admin)
        .await
        .ok()?;
    let mut url = url::Url::parse(&base).ok()?;
    url.set_path(&name);
    Some(url.to_string())
}

/// A static signing key: ready as soon as it listens.
fn static_key() -> serde_json::Value {
    serde_json::json!({
        "signing_keys": [{ "kid": "k1", "alg": "RS256", "key_file": fixture("signing-key.pem") }],
        "protocol": { "key_management": { "enabled": false } },
    })
}

fn probe_with(url: &str, env: &[(&str, &str)]) -> std::process::ExitStatus {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rustid-server"));
    command
        .args(["--probe", url])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for (key, value) in env {
        command.env(key, value);
    }
    command.status().unwrap()
}

#[test]
fn probe_ignores_proxy_settings() {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let child = start(dir.path(), port, static_key());
    // A proxy that isn't there: a probe sent through it fails.
    let proxy = format!("http://127.0.0.1:{}", free_port());
    let status = probe_with(
        &format!("http://127.0.0.1:{port}/ready"),
        &[
            ("HTTP_PROXY", &proxy),
            ("http_proxy", &proxy),
            ("ALL_PROXY", &proxy),
        ],
    );
    stop(child);
    assert!(status.success(), "{status}");
}

#[test]
fn probe_trusts_the_ssl_cert_file() {
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
    let ca_file = dir.path().join("ca.pem");
    std::fs::write(&ca_file, ca.pem()).unwrap();

    let mut config = static_key();
    config["tls"] = serde_json::json!({
        "cert_file": dir.path().join("cert.pem"),
        "key_file": dir.path().join("key.pem"),
    });
    let port = free_port();
    let child = start(dir.path(), port, config);
    let url = format!("https://localhost:{port}/ready");
    let untrusted = probe_with(&url, &[("SSL_CERT_FILE", "/nonexistent")]);
    let trusted = probe_with(&url, &[("SSL_CERT_FILE", ca_file.to_str().unwrap())]);
    stop(child);
    assert_eq!(untrusted.code(), Some(1));
    assert!(trusted.success(), "{trusted}");
}
