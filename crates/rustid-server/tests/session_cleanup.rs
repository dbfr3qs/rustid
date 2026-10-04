//! The server's expired session cleanup job.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rustid_core::server_side_sessions::ServerSideSession;
use rustid_server::config::ServerConfig;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

#[tokio::test]
async fn expired_sessions_are_removed_by_the_job() {
    let dir = tempfile::tempdir().unwrap();
    let config = serde_json::json!({
        "signing_keys": [{ "kid": "k1", "alg": "RS256", "key_file": fixture("signing-key.pem") }],
        "clients_file": fixture("clients.json"),
        "resources_file": fixture("resources.json"),
        "server_side_sessions": { "enabled": true },
        "protocol": {
            "key_management": { "enabled": false },
            "server_side_sessions": {
                "remove_expired_sessions_frequency": "00:00:01",
                "fuzz_expired_session_removal_start": false,
            },
        },
    });
    let path = dir.path().join("rustid.json");
    std::fs::write(&path, config.to_string()).unwrap();
    let app = rustid_server::build(&ServerConfig::load(Some(&path)).unwrap())
        .await
        .unwrap();
    let sessions = app.state.0.stores.sessions.clone().expect("enabled");
    let now = chrono::Utc::now();
    let record = |key: &str, expires: chrono::DateTime<chrono::Utc>| ServerSideSession {
        key: key.into(),
        scheme: "idsrv".into(),
        subject_id: "1".into(),
        session_id: key.into(),
        display_name: None,
        created: now,
        renewed: now,
        expires: Some(expires),
        ticket: "unreadable".into(),
    };
    sessions
        .store
        .create_session(record("OLD", now - chrono::Duration::minutes(1)))
        .await
        .unwrap();
    sessions
        .store
        .create_session(record("NEW", now + chrono::Duration::hours(1)))
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(rustid_server::serve(listener, app, async move {
        let _ = stopped.await;
    }));
    let start = Instant::now();
    while sessions.store.get_session("OLD").await.unwrap().is_some() {
        assert!(start.elapsed() < Duration::from_secs(5), "not removed");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(sessions.store.get_session("NEW").await.unwrap().is_some());
    let _ = stop.send(());
}
