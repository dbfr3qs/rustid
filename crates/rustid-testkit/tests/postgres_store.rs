//! Postgres behaviour beyond the shared store contract. Every test skips
//! when `TEST_POSTGRES_URL` is unset.

use rustid_core::stores::{ClientStore, ResourceStore, StoreError};
use rustid_server::config::{PostgresConfig, StoreConfig, StoreKind};
use rustid_store_postgres::{PgError, PgStore};
use rustid_testkit::client::Client;
use rustid_testkit::postgres::ScratchDatabase;
use rustid_testkit::recorded::Body;
use rustid_testkit::server::TestServer;
use rustid_testkit::test_config;
use serde_json::json;

async fn migrated(db: &ScratchDatabase) -> PgStore {
    let store = PgStore::connect(&db.url, 4, false).await.unwrap();
    store.migrate().await.unwrap();
    store
}

macro_rules! scratch {
    () => {
        match ScratchDatabase::create().await {
            Some(db) => db,
            None => {
                eprintln!("skipped: TEST_POSTGRES_URL is not set");
                return;
            }
        }
    };
}

#[tokio::test]
async fn migrations_apply_once_and_are_idempotent() {
    let db = scratch!();
    let store = migrated(&db).await;
    store.migrate().await.unwrap();
    store.close().await;
    db.drop().await;
}

#[tokio::test]
async fn importing_again_replaces_values_and_order() {
    let db = scratch!();
    let store = migrated(&db).await;
    store
        .import_resources(&json!({"apiScopes": [{"name": "a"}, {"name": "b"}, {"name": "c"}]}))
        .await
        .unwrap();
    store
        .import_resources(&json!({"apiScopes": [
            {"name": "c", "displayName": "C"}, {"name": "a", "enabled": false}, {"name": "b"}
        ]}))
        .await
        .unwrap();
    let enabled = store.get_all_enabled_resources().await.unwrap();
    let scopes: Vec<(&str, Option<&str>)> = enabled
        .api_scopes
        .iter()
        .map(|s| (s.name.as_str(), s.display_name.as_deref()))
        .collect();
    assert_eq!(scopes, [("c", Some("C")), ("b", None)]);

    store
        .import_clients(&[json!({"clientId": "x", "allowedCorsOrigins": ["https://x.test/app"]})])
        .await
        .unwrap();
    assert!(
        store
            .is_cors_origin_allowed("https://x.test")
            .await
            .unwrap()
    );
    store
        .import_clients(&[json!({"clientId": "x", "enabled": false})])
        .await
        .unwrap();
    assert!(
        !store
            .is_cors_origin_allowed("https://x.test")
            .await
            .unwrap(),
        "origins replaced"
    );
    let x = store.find_client_by_id("x").await.unwrap().unwrap();
    assert!(!x.enabled);
    store.close().await;
    db.drop().await;
}

#[tokio::test]
async fn an_invalid_import_changes_nothing() {
    let db = scratch!();
    let store = migrated(&db).await;
    let result = store
        .import_clients(&[
            json!({"clientId": "first"}),
            json!({"clientId": "second", "accessTokenType": "bogus"}),
        ])
        .await;
    assert!(
        matches!(
            result,
            Err(PgError::InvalidModel {
                kind: "client",
                index: 1,
                ..
            })
        ),
        "{result:?}"
    );
    assert!(store.find_client_by_id("first").await.unwrap().is_none());
    store.close().await;
    db.drop().await;
}

#[tokio::test]
async fn unreadable_rows_are_store_errors() {
    let db = scratch!();
    let store = migrated(&db).await;
    store
        .import_clients(&[json!({"clientId": "c"})])
        .await
        .unwrap();
    let pool = sqlx::PgPool::connect(&db.url).await.unwrap();
    sqlx::query("UPDATE clients SET data = '{\"clientId\": 5}'")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
    assert!(matches!(
        store.find_client_by_id("c").await,
        Err(StoreError::Backend(_))
    ));
    store.close().await;
    db.drop().await;
}

#[tokio::test]
async fn a_missing_database_is_created_on_request() {
    let db = scratch!();
    let missing = format!("{}_new", db.url);
    assert!(PgStore::connect(&missing, 1, false).await.is_err());
    let store = PgStore::connect(&missing, 1, true).await.unwrap();
    store.close().await;
    ScratchDatabase { url: missing }.drop().await;
    db.drop().await;
}

#[tokio::test]
async fn reference_tokens_survive_a_restart() {
    let db = scratch!();
    let mut config = test_config();
    config.store = StoreConfig {
        kind: StoreKind::Postgres,
        postgres: Some(PostgresConfig {
            url: db.url.clone(),
            max_connections: 4,
            create_database: false,
            run_migrations: true,
        }),
        ..Default::default()
    };
    let client = Client::new().unwrap();
    let server = TestServer::spawn(config.clone()).await.unwrap();
    let issued = client
        .post_form(
            &server.url("/connect/token"),
            &[
                ("grant_type", "client_credentials"),
                ("client_id", "client.reference"),
                ("client_secret", "secret"),
                ("scope", "api1"),
            ],
        )
        .await
        .unwrap();
    let Body::Json(issued) = issued.body else {
        panic!("token response was not JSON");
    };
    let handle = issued["access_token"].as_str().unwrap().to_owned();
    server.shutdown().await.unwrap();

    let server = TestServer::spawn(config).await.unwrap();
    let answer = client
        .post_form(
            &server.url("/connect/introspect"),
            &[
                ("client_id", "client.reference"),
                ("client_secret", "secret"),
                ("token", &handle),
            ],
        )
        .await
        .unwrap();
    let Body::Json(answer) = answer.body else {
        panic!("introspection response was not JSON");
    };
    assert_eq!(answer["active"], json!(true), "{answer}");
    server.shutdown().await.unwrap();
    db.drop().await;
}

#[tokio::test]
async fn imports_reject_duplicates_and_malformed_resources() {
    let db = scratch!();
    let store = migrated(&db).await;
    let result = store
        .import_clients(&[json!({"clientId": "m2m"}), json!({"clientId": "m2m"})])
        .await;
    assert!(
        matches!(&result, Err(PgError::Duplicate { kind: "client", name }) if name == "m2m"),
        "{result:?}"
    );
    assert!(store.find_client_by_id("m2m").await.unwrap().is_none());
    let result = store
        .import_resources(&json!({"apiScopes": [{"name": "s"}, {"name": "s"}]}))
        .await;
    assert!(
        matches!(
            &result,
            Err(PgError::Duplicate {
                kind: "API scope",
                ..
            })
        ),
        "{result:?}"
    );
    for malformed in [json!([]), json!({"apiScopes": {"name": "s"}})] {
        let result = store.import_resources(&malformed).await;
        assert!(
            matches!(result, Err(PgError::InvalidResources(_))),
            "{malformed}: {result:?}"
        );
    }
    store.close().await;
    db.drop().await;
}

#[tokio::test]
async fn startup_validates_files_like_the_memory_store() {
    let db = scratch!();
    let dir = tempfile::tempdir().unwrap();
    let clients = dir.path().join("clients.json");
    // A repeated property: Clients::load refuses it, a JSON Value would keep the last.
    std::fs::write(
        &clients,
        r#"[{"clientId": "m2m", "enabled": true, "enabled": false}]"#,
    )
    .unwrap();
    let mut config = test_config();
    config.clients_file = Some(clients);
    config.store = StoreConfig {
        kind: StoreKind::Postgres,
        postgres: Some(PostgresConfig {
            url: db.url.clone(),
            max_connections: 2,
            create_database: false,
            run_migrations: true,
        }),
        ..Default::default()
    };
    let memory = rustid_server::config::ServerConfig {
        store: StoreConfig::default(),
        ..config.clone()
    };
    assert!(rustid_server::build_state(&memory).await.is_err());
    let err = rustid_server::build_state(&config)
        .await
        .expect_err("postgres refuses too");
    assert!(format!("{err:#}").contains("enabled"), "{err:#}");
    db.drop().await;
}
