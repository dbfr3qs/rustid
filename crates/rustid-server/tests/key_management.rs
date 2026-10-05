//! Automatic key management in the running server: the first token creates and persists
//! a key, its `kid` is the stored key's id, later tokens reuse it, and
//! discovery's JWKS publishes it.

use std::path::{Path, PathBuf};

use base64::Engine;
use rustid_server::config::ServerConfig;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

fn kid(token: &str) -> String {
    let header = token.split('.').next().unwrap();
    let json: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(header)
            .unwrap(),
    )
    .unwrap();
    json["kid"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn managed_keys_sign_tokens_and_appear_in_discovery() {
    let dir = tempfile::tempdir().unwrap();
    let keys = dir.path().join("keys");
    let config = serde_json::json!({
        "clients_file": fixture("clients.json"),
        "resources_file": fixture("resources.json"),
        "protocol": { "key_management": { "enabled": true, "key_path": keys } },
    });
    let path = dir.path().join("rustid.json");
    std::fs::write(&path, config.to_string()).unwrap();
    let app = rustid_server::build(&ServerConfig::load(Some(&path)).unwrap())
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let (_stop, stopped) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(rustid_server::serve(listener, app, async move {
        let _ = stopped.await;
    }));
    let http = reqwest::Client::new();
    let token = || async {
        let body: serde_json::Value = http
            .post(format!("{base}/connect/token"))
            .basic_auth("m2m", Some("secret"))
            .form(&[("grant_type", "client_credentials"), ("scope", "api1")])
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        body["access_token"].as_str().unwrap().to_owned()
    };

    let first = kid(&token().await);
    let stored: Vec<String> = std::fs::read_dir(&keys)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("is-signing-key-"))
        .collect();
    assert_eq!(stored.len(), 1, "{stored:?}");
    assert!(stored[0].contains(&first), "{stored:?} holds {first}");
    assert_eq!(kid(&token().await), first, "later tokens reuse the key");

    let jwks: serde_json::Value = http
        .get(format!("{base}/.well-known/openid-configuration/jwks"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        jwks["keys"]
            .as_array()
            .unwrap()
            .iter()
            .any(|k| k["kid"] == first),
        "{jwks}"
    );
}
