//! A database exported as a migration bundle (by an external
//! harness), imported into Postgres: the refresh token
//! the source server issued redeems at rustid, the JWT it signed verifies at
//! rustid's JWKS, and the expired grant wasn't carried over. Skipped unless
//! MIGRATION_EXPORT_DIR and TEST_POSTGRES_URL are set.

use std::path::{Path, PathBuf};

use rustid_server::config::ServerConfig;

const MASTER_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

fn read(dir: &Path, name: &str) -> String {
    std::fs::read_to_string(dir.join(name))
        .unwrap()
        .trim()
        .to_owned()
}

#[tokio::test]
async fn an_exported_database_moves_to_rustid() {
    let (Some(export), Some(db)) = (
        std::env::var_os("MIGRATION_EXPORT_DIR").map(PathBuf::from),
        scratch_database().await,
    ) else {
        eprintln!("skipped: MIGRATION_EXPORT_DIR or TEST_POSTGRES_URL is not set");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let config = serde_json::json!({
        "protocol": { "issuer_uri": "https://idsrv.test" },
        "data_protection": { "keys": [{ "id": "m", "secret": MASTER_KEY }] },
        "store": { "kind": "postgres", "postgres": { "url": db } },
    });
    let path = dir.path().join("rustid.json");
    std::fs::write(&path, config.to_string()).unwrap();
    let config = ServerConfig::load(Some(&path)).unwrap();

    let report = rustid_server::import::run(&config, &export.join("bundle.json"), None)
        .await
        .unwrap();
    assert_eq!(report.keys_stored, 1);
    assert_eq!(report.grants, 2, "the refresh token and the consent");
    assert_eq!(report.skipped.get("expired refresh_token"), Some(&1));

    let app = rustid_server::build(&config).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let served = tokio::spawn(rustid_server::serve(listener, app, async move {
        let _ = stopped.await;
    }));
    let client = reqwest::Client::new();

    // The refresh token the source issued redeems.
    let client_id = read(&export, "refresh.client");
    let redeem = |handle: String| {
        let client = client.clone();
        let base = base.clone();
        let client_id = client_id.clone();
        async move {
            client
                .post(format!("{base}/connect/token"))
                .basic_auth(&client_id, Some("secret"))
                .form(&[("grant_type", "refresh_token"), ("refresh_token", &handle)])
                .send()
                .await
                .unwrap()
        }
    };
    let response = redeem(read(&export, "refresh.handle")).await;
    assert_eq!(response.status(), 200);
    let tokens: serde_json::Value = response.json().await.unwrap();
    assert!(tokens["access_token"].is_string() && tokens["refresh_token"].is_string());

    // The expired one wasn't carried over.
    let response = redeem(read(&export, "expired.handle")).await;
    assert_eq!(response.status(), 400);

    // The JWT the source signed verifies with the key rustid now publishes.
    let jwt = read(&export, "signed.jwt");
    let jws = rustid_core::jwt::Jws::decode(&jwt).unwrap();
    let kid = jws.header_str("kid").unwrap().to_owned();
    let jwks: serde_json::Value = client
        .get(format!("{base}/.well-known/openid-configuration/jwks"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let jwk = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["kid"] == kid.as_str())
        .unwrap_or_else(|| panic!("{kid} is not in {jwks}"));
    let key = rustid_core::jwt::PublicJwk::parse(&jwk.to_string()).unwrap();
    assert!(
        jws.verify(&key),
        "the migrated key doesn't verify the source's JWT"
    );

    let _ = stop.send(());
    served.await.unwrap().unwrap();
}

/// A fresh database on the TEST_POSTGRES_URL server.
async fn scratch_database() -> Option<String> {
    let base = std::env::var("TEST_POSTGRES_URL").ok()?;
    let name = format!("migration_{}", std::process::id());
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
