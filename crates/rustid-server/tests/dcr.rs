//! Dynamic client registration in the server: off by default, an initial
//! access token (or `open`) required when on.

use std::path::{Path, PathBuf};

use rustid_server::config::ServerConfig;

const TOKEN: &str = "an-initial-access-token-of-32-chars!!";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

fn config(dir: &Path, dcr: serde_json::Value) -> anyhow::Result<ServerConfig> {
    let config = serde_json::json!({
        "signing_keys": [{ "kid": "k1", "alg": "RS256", "key_file": fixture("signing-key.pem") }],
        "clients_file": fixture("clients.json"),
        "resources_file": fixture("resources.json"),
        "protocol": { "key_management": { "enabled": false } },
        "dynamic_client_registration": dcr,
    });
    let path = dir.join("rustid.json");
    std::fs::write(&path, config.to_string()).unwrap();
    Ok(ServerConfig::load(Some(&path))?)
}

async fn start(config: &ServerConfig) -> (String, tokio::sync::oneshot::Sender<()>) {
    let app = rustid_server::build(config).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(rustid_server::serve(listener, app, async move {
        let _ = stopped.await;
    }));
    (base, stop)
}

async fn refused(dcr: serde_json::Value) -> String {
    let dir = tempfile::tempdir().unwrap();
    let error = match config(dir.path(), dcr) {
        Err(e) => e,
        Ok(config) => match rustid_server::build(&config).await {
            Err(e) => e,
            Ok(_) => panic!("refused"),
        },
    };
    format!("{error:#}")
}

#[tokio::test]
async fn enabled_without_tokens_or_open_is_refused() {
    let error = refused(serde_json::json!({ "enabled": true })).await;
    assert!(error.contains("initial_access_tokens"), "{error}");
}

#[tokio::test]
async fn short_initial_access_tokens_are_refused() {
    let short = "a".repeat(31);
    let error =
        refused(serde_json::json!({ "enabled": true, "initial_access_tokens": [short] })).await;
    assert!(error.contains("32"), "{error}");
}

#[tokio::test]
async fn off_by_default_and_on_with_a_token() {
    let dir = tempfile::tempdir().unwrap();
    let (base, _stop) = start(&config(dir.path(), serde_json::json!({})).unwrap()).await;
    let http = reqwest::Client::new();
    let body = serde_json::json!({ "grant_types": ["client_credentials"] });
    let r = http
        .post(format!("{base}/connect/dcr"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);

    let on = serde_json::json!({ "enabled": true, "initial_access_tokens": [TOKEN], "secret_lifetime": 60, "default_scopes": ["api1"] });
    let (base, _stop) = start(&config(dir.path(), on).unwrap()).await;
    let r = http
        .post(format!("{base}/connect/dcr"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    let r = http
        .post(format!("{base}/connect/dcr"))
        .bearer_auth(TOKEN)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201);
    let registered: serde_json::Value = r.json().await.unwrap();
    assert_ne!(registered["client_secret_expires_at"], 0, "secret_lifetime");
    assert_eq!(registered["scope"], "api1", "default_scopes");
}

#[tokio::test]
async fn dcr_paths_that_shadow_routes_are_refused() {
    for path in [
        "/connect/token",
        "/CONNECT/AUTHORIZE",
        "/connect/par",
        "/.well-known/openid-configuration",
        "/interaction/login",
        "/health",
    ] {
        let error =
            refused(serde_json::json!({ "enabled": true, "open": true, "path": path })).await;
        assert!(error.contains(path), "{path}: {error}");
    }
    let dir = tempfile::tempdir().unwrap();
    let ok = config(
        dir.path(),
        serde_json::json!({ "enabled": true, "open": true, "path": "/register" }),
    )
    .unwrap();
    assert!(rustid_server::build(&ok).await.is_ok());
}

/// Admin and the reference UI, when on, own their paths too.
#[tokio::test]
async fn dcr_paths_under_admin_or_the_reference_ui_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    for path in ["/admin/clients", "/Account/Login", "/consent"] {
        let config = serde_json::json!({
            "signing_keys": [{ "kid": "k1", "alg": "RS256", "key_file": fixture("signing-key.pem") }],
            "clients_file": fixture("clients.json"),
            "resources_file": fixture("resources.json"),
            "protocol": { "key_management": { "enabled": false } },
            "admin": { "enabled": true, "api_keys": [TOKEN] },
            "reference_ui": { "enabled": true, "users_file": fixture("users.json"), "default_user": "alice" },
            "dynamic_client_registration": { "enabled": true, "open": true, "path": path },
        });
        let file = dir.path().join("rustid.json");
        std::fs::write(&file, config.to_string()).unwrap();
        let config = ServerConfig::load(Some(&file)).unwrap();
        let error = format!(
            "{:#}",
            match rustid_server::build(&config).await {
                Err(e) => e,
                Ok(_) => panic!("refused"),
            }
        );
        assert!(error.contains(path), "{path}: {error}");
    }
}
