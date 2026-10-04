//! Automatic key management on a running server: keys are created on first
//! use, published, used to sign, and survive restarts.

use rustid_core::options::TimeSpan;
use rustid_server::config::{
    DataProtectionConfig, DataProtectionKey, PostgresConfig, ServerConfig, StoreConfig, StoreKind,
};
use rustid_testkit::client::Client;
use rustid_testkit::postgres::ScratchDatabase;
use rustid_testkit::recorded::Body;
use rustid_testkit::server::TestServer;
use rustid_testkit::test_config;
use serde_json::{Value, json};

/// The default profile with automatic keys instead of the static key, and
/// no configured data protection key, so one is generated in the key path.
fn managed(key_path: &std::path::Path) -> ServerConfig {
    let mut config = test_config();
    config.signing_keys.clear();
    config.data_protection.keys.clear();
    let km = &mut config.protocol.key_management;
    km.enabled = true;
    km.key_path = Some(key_path.to_path_buf());
    km.initialization_synchronization_delay = TimeSpan(0);
    config
}

async fn json_body(client: &Client, url: &str) -> Value {
    match client.get(url).await.unwrap().body {
        Body::Json(v) => v,
        other => panic!("{url}: {other:?}"),
    }
}

async fn token_kid(client: &Client, server: &TestServer) -> String {
    let response = client
        .post_form(
            &server.url("/connect/token"),
            &[
                ("grant_type", "client_credentials"),
                ("client_id", "client"),
                ("client_secret", "secret"),
                ("scope", "api1"),
            ],
        )
        .await
        .unwrap();
    let Body::Json(body) = response.body else {
        panic!("token response was not JSON");
    };
    let jwt = body["access_token"].as_str().expect("an access token");
    rustid_core::jwt::Jws::decode(jwt)
        .unwrap()
        .header_str("kid")
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn keys_are_created_published_used_and_kept_across_restarts() {
    let dir = tempfile::tempdir().unwrap();
    let keys = dir.path().join("keys");
    let client = Client::new().unwrap();
    let server = TestServer::spawn(managed(&keys)).await.unwrap();
    let jwks = json_body(
        &client,
        &server.url("/.well-known/openid-configuration/jwks"),
    )
    .await;
    let published = jwks["keys"].as_array().unwrap();
    assert_eq!(published.len(), 1, "{jwks}");
    let key = published[0].as_object().unwrap();
    // The shape published for an automatic RSA key.
    assert_eq!(
        key.keys().map(String::as_str).collect::<Vec<_>>(),
        ["kty", "use", "kid", "e", "n", "alg"]
    );
    assert_eq!(
        (key["kty"].as_str(), key["alg"].as_str(), key["e"].as_str()),
        (Some("RSA"), Some("RS256"), Some("AQAB"))
    );
    let kid = key["kid"].as_str().unwrap().to_owned();
    assert!(
        kid.len() == 32 && kid.chars().all(|c| matches!(c, '0'..='9' | 'A'..='F')),
        "{kid}"
    );
    let discovery = json_body(&client, &server.url("/.well-known/openid-configuration")).await;
    assert_eq!(
        discovery["id_token_signing_alg_values_supported"],
        json!(["RS256"])
    );
    assert_eq!(token_kid(&client, &server).await, kid);
    server.shutdown().await.unwrap();

    let names: Vec<String> = std::fs::read_dir(&keys)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        names.contains(&format!("is-signing-key-{kid}.json")),
        "{names:?}"
    );
    assert!(
        names.contains(&"data-protection.key".to_owned()),
        "{names:?}"
    );
    let stored = std::fs::read_to_string(keys.join(format!("is-signing-key-{kid}.json"))).unwrap();
    assert!(
        stored.contains("\"DataProtected\":true") && stored.contains("\"Data\":\"v1.local."),
        "{stored}"
    );

    let server = TestServer::spawn(managed(&keys)).await.unwrap();
    assert_eq!(
        token_kid(&client, &server).await,
        kid,
        "the stored key is reused"
    );
    server.shutdown().await.unwrap();
}

fn on_postgres(mut config: ServerConfig, url: &str) -> ServerConfig {
    config.store = StoreConfig {
        kind: StoreKind::Postgres,
        postgres: Some(PostgresConfig {
            url: url.to_owned(),
            max_connections: 4,
            create_database: false,
            run_migrations: true,
        }),
        ..Default::default()
    };
    config
}

#[tokio::test]
async fn postgres_keeps_protected_keys_across_restarts() {
    let Some(db) = ScratchDatabase::create().await else {
        eprintln!("skipped: TEST_POSTGRES_URL is not set");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let mut config = on_postgres(managed(dir.path()), &db.url);
    // Without a key ring Postgres-stored keys can't be protected.
    let err = rustid_server::build_state(&config)
        .await
        .expect_err("needs a ring");
    assert!(
        format!("{err:#}").contains("data_protection.keys"),
        "{err:#}"
    );
    config.data_protection = DataProtectionConfig {
        keys: vec![DataProtectionKey {
            id: "ring1".into(),
            secret: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".into(),
        }],
    };
    let client = Client::new().unwrap();
    let server = TestServer::spawn(config.clone()).await.unwrap();
    let kid = token_kid(&client, &server).await;
    server.shutdown().await.unwrap();
    let pool = sqlx::PgPool::connect(&db.url).await.unwrap();
    let (id, data, protected): (String, String, bool) =
        sqlx::query_as("SELECT id, data, data_protected FROM signing_keys")
            .fetch_one(&pool)
            .await
            .unwrap();
    pool.close().await;
    assert_eq!(id, kid);
    assert!(protected && data.starts_with("v1.ring1."), "{data}");
    assert!(
        !std::fs::read_dir(dir.path()).unwrap().any(|_| true),
        "nothing written to key_path"
    );
    let server = TestServer::spawn(config).await.unwrap();
    assert_eq!(token_kid(&client, &server).await, kid);
    server.shutdown().await.unwrap();
    db.drop().await;
}

#[tokio::test]
async fn turning_protection_off_keeps_existing_protected_keys_readable() {
    // Keys are unprotected according to each stored record; the option only
    // decides how new keys are written.
    let dir = tempfile::tempdir().unwrap();
    let keys = dir.path().join("keys");
    let client = Client::new().unwrap();
    let server = TestServer::spawn(managed(&keys)).await.unwrap();
    let kid = token_kid(&client, &server).await;
    server.shutdown().await.unwrap();
    let mut clear = managed(&keys);
    clear.protocol.key_management.data_protect_keys = false;
    let server = TestServer::spawn(clear).await.unwrap();
    assert_eq!(
        token_kid(&client, &server).await,
        kid,
        "the protected key is still used"
    );
    server.shutdown().await.unwrap();
}
