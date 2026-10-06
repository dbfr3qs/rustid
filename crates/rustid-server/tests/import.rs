//! `rustid-server import`: a migration bundle into the Postgres store, or
//! into files for the memory store.

use std::path::{Path, PathBuf};

use axum::body::Body;
use axum::http::Request;
use rustid_server::config::ServerConfig;
use rustid_server::import::{self, BUNDLE_FORMAT, BUNDLE_VERSION};
use tower::ServiceExt;

const MASTER_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

fn read(name: &str) -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(fixture(name)).unwrap()).unwrap()
}

/// A bundle of the fixtures, one fresh key of `alg`, and the bundle's grants.
fn bundle(dir: &Path, alg: &str) -> (PathBuf, String) {
    use base64::Engine;
    let pkcs8 = rustid_core::keys::generate_pkcs8(alg, 2048).unwrap();
    let kid = format!("migrated-{}", alg.to_lowercase());
    let bundle = serde_json::json!({
        "format": BUNDLE_FORMAT,
        "version": BUNDLE_VERSION,
        "exported_at": "2026-10-03T09:00:00Z",
        "clients": read("clients.json"),
        "resources": read("resources.json"),
        "saml_service_providers": read("saml-service-providers.json"),
        "signing_keys": [{
            "id": kid,
            "algorithm": alg,
            "created": "2026-10-01T00:00:00Z",
            "pkcs8": base64::engine::general_purpose::STANDARD.encode(pkcs8),
            "certificate": null,
        }],
        "grants": read("migration/bundle-grants.json"),
        "skipped": { "authorization_code": 2, "server_side_sessions": 1 },
    });
    let path = dir.join("bundle.json");
    std::fs::write(&path, bundle.to_string()).unwrap();
    (path, kid)
}

fn config(dir: &Path, extra: serde_json::Value) -> ServerConfig {
    let mut config = serde_json::json!({
        "signing_keys": [{ "kid": "k1", "alg": "RS256", "key_file": fixture("signing-key.pem") }],
        "protocol": { "key_management": { "enabled": true, "signing_algorithms": [{ "name": "RS256" }] } },
        "data_protection": { "keys": [{ "id": "m", "secret": MASTER_KEY }] },
    });
    merge(&mut config, extra);
    let path = dir.join("rustid.json");
    std::fs::write(&path, config.to_string()).unwrap();
    ServerConfig::load(Some(&path)).unwrap()
}

fn merge(target: &mut serde_json::Value, extra: serde_json::Value) {
    match (target, extra) {
        (serde_json::Value::Object(t), serde_json::Value::Object(e)) => {
            for (k, v) in e {
                merge(t.entry(k).or_insert(serde_json::Value::Null), v);
            }
        }
        (t, e) => *t = e,
    }
}

async fn jwks_kids(config: &ServerConfig) -> Vec<String> {
    let app = rustid_server::build(config).await.unwrap();
    let router = rustid_server::router(&app, ([127, 0, 0, 1], 8080).into());
    let response = router
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-configuration/jwks")
                .header("host", "localhost:8080")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let jwks: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["kid"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn import_is_idempotent() {
    let Some(db) = scratch_database("import_twice").await else {
        eprintln!("skipped: TEST_POSTGRES_URL is not set");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let (path, kid) = bundle(dir.path(), "RS256");
    let config = config(
        dir.path(),
        serde_json::json!({ "store": { "kind": "postgres", "postgres": { "url": db } } }),
    );
    let first = import::run(&config, &path, None).await.unwrap();
    assert_eq!((first.keys_stored, first.keys_existing), (1, 0));
    assert_eq!(first.grants, 3);
    assert_eq!(first.skipped.get("authorization_code"), Some(&2));
    let second = import::run(&config, &path, None).await.unwrap();
    assert_eq!((second.keys_stored, second.keys_existing), (0, 1));
    assert_eq!(second.grants, 3);
    assert_eq!(second.clients, first.clients);

    let pool = sqlx::PgPool::connect(&db).await.unwrap();
    let keys: i64 = sqlx::query_scalar("SELECT count(*) FROM signing_keys")
        .fetch_one(&pool)
        .await
        .unwrap();
    let grants: i64 = sqlx::query_scalar("SELECT count(*) FROM persisted_grants")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!((keys, grants), (1, 3));

    // imported_configuration_and_keys_serve
    assert!(jwks_kids(&config).await.contains(&kid));
}

#[tokio::test]
async fn memory_out_dir_writes_loadable_files() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    let (path, kid) = bundle(dir.path(), "RS256");
    let report = import::run(
        &config(dir.path(), serde_json::json!({})),
        &path,
        Some(&out),
    )
    .await
    .unwrap();
    assert_eq!(report.keys_stored, 1);
    assert_eq!(report.grants, 0);
    // The grants the bundle carries are reported as not imported.
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("3 grants") && w.contains("memory store")),
        "{:?}",
        report.warnings
    );
    for file in [
        "clients.json",
        "resources.json",
        "saml-service-providers.json",
    ] {
        assert!(out.join(file).exists(), "{file}");
    }
    let config = config(
        dir.path(),
        serde_json::json!({
            "clients_file": out.join("clients.json"),
            "resources_file": out.join("resources.json"),
            "saml": { "enabled": true, "service_providers_file": out.join("saml-service-providers.json") },
            "protocol": { "key_management": { "key_path": out.join("keys") } },
        }),
    );
    assert!(jwks_kids(&config).await.contains(&kid));
}

#[tokio::test]
async fn memory_without_out_dir_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let (path, _) = bundle(dir.path(), "RS256");
    let error = import::run(&config(dir.path(), serde_json::json!({})), &path, None)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("--out-dir") && error.contains("Postgres"),
        "{error}"
    );
}

#[tokio::test]
async fn wrong_format_or_version_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let (path, _) = bundle(dir.path(), "RS256");
    let mut value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    value["version"] = 2.into();
    std::fs::write(&path, value.to_string()).unwrap();
    let out = dir.path().join("out");
    let error = import::run(
        &config(dir.path(), serde_json::json!({})),
        &path,
        Some(&out),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("version 2"), "{error}");
    value["version"] = 1.into();
    value["format"] = "something-else".into();
    std::fs::write(&path, value.to_string()).unwrap();
    let error = import::run(
        &config(dir.path(), serde_json::json!({})),
        &path,
        Some(&out),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("something-else"), "{error}");
}

#[tokio::test]
async fn keys_need_a_master_key() {
    let dir = tempfile::tempdir().unwrap();
    let (path, _) = bundle(dir.path(), "RS256");
    let config = config(
        dir.path(),
        serde_json::json!({ "data_protection": { "keys": [] } }),
    );
    let error = import::run(&config, &path, Some(&dir.path().join("out")))
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("data_protection.keys"), "{error}");
}

#[tokio::test]
async fn an_unconfigured_algorithm_warns() {
    let dir = tempfile::tempdir().unwrap();
    let (path, kid) = bundle(dir.path(), "ES256");
    let report = import::run(
        &config(dir.path(), serde_json::json!({})),
        &path,
        Some(&dir.path().join("out")),
    )
    .await
    .unwrap();
    assert_eq!(report.keys_stored, 1);
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains(&kid) && w.contains("ES256")),
        "{:?}",
        report.warnings
    );
}

#[tokio::test]
async fn a_key_without_the_certificate_its_algorithm_needs_warns() {
    let dir = tempfile::tempdir().unwrap();
    let (path, kid) = bundle(dir.path(), "RS256");
    let config = config(
        dir.path(),
        serde_json::json!({ "protocol": { "key_management": {
            "signing_algorithms": [{ "name": "RS256", "use_x509_certificate": true }] } } }),
    );
    let report = import::run(&config, &path, Some(&dir.path().join("out")))
        .await
        .unwrap();
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains(&kid) && w.contains("use_x509_certificate")),
        "{:?}",
        report.warnings
    );
}

/// A fresh database on the TEST_POSTGRES_URL server.
async fn scratch_database(name: &str) -> Option<String> {
    let base = std::env::var("TEST_POSTGRES_URL").ok()?;
    let name = format!("{name}_{}", std::process::id());
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

#[tokio::test]
async fn out_dir_with_postgres_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let (path, _) = bundle(dir.path(), "RS256");
    let config = config(
        dir.path(),
        serde_json::json!({ "store": { "kind": "postgres", "postgres": { "url": "postgres://nobody@127.0.0.1:1/none" } } }),
    );
    let error = import::run(&config, &path, Some(&dir.path().join("out")))
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("--out-dir") && error.contains("memory store"),
        "{error}"
    );
}

#[test]
fn the_format_is_rustid_migration_bundle_and_the_earlier_name_is_still_read() {
    assert_eq!(BUNDLE_FORMAT, "rustid-migration-bundle");
    let dir = tempfile::tempdir().unwrap();
    let (path, _) = bundle(dir.path(), "RS256");
    import::read_bundle(&path).unwrap();
    let mut value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    value["format"] = "rustid-ef-export".into();
    std::fs::write(&path, value.to_string()).unwrap();
    import::read_bundle(&path).unwrap();
}

#[tokio::test]
async fn a_failed_memory_import_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (path, _) = bundle(dir.path(), "RS256");
    let mut value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    // Valid clients, then resources the loader refuses.
    value["resources"] = serde_json::json!({ "apiScopes": "not a list" });
    std::fs::write(&path, value.to_string()).unwrap();
    let out = dir.path().join("out");
    import::run(&config(dir.path(), serde_json::json!({})), &path, Some(&out))
        .await
        .unwrap_err();
    let written: Vec<_> = std::fs::read_dir(&out)
        .map(|d| d.map(|e| e.unwrap().file_name()).collect())
        .unwrap_or_default();
    assert!(written.is_empty(), "{written:?}");
}
