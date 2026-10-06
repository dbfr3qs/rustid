//! When the replay cache can't be reached, a client assertion is never
//! accepted on trust: the request fails with a server error.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use rustid_core::clients::Clients;
use rustid_core::keys::{KeyConfig, KeyMaterial, LoadedKey};
use rustid_core::options::ProtocolOptions;
use rustid_core::replay::ReplayCache;
use rustid_core::resources::Resources;
use rustid_core::stores::StoreError;
use rustid_http::{AppState, ProtocolState};
use tower::ServiceExt;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

struct Down;

#[async_trait::async_trait]
impl ReplayCache for Down {
    async fn add_if_absent(&self, _: &str, _: &str, _: i64, _: i64) -> Result<bool, StoreError> {
        Err(StoreError::Backend("down".into()))
    }

    async fn remove_expired(&self, _: i64, _: usize) -> Result<u64, StoreError> {
        Err(StoreError::Backend("down".into()))
    }

    async fn remove(&self, _: &str, _: &str) -> Result<(), StoreError> {
        Err(StoreError::Backend("down".into()))
    }
}

fn state(replay: Arc<dyn ReplayCache>) -> AppState {
    let key = KeyConfig {
        kid: "k1".into(),
        alg: "RS256".into(),
        key_file: fixture("signing-key.pem"),
        cert_file: None,
    };
    let mut stores = rustid_store_memory::stores(
        Clients::load(&fixture("clients.json")).unwrap(),
        Resources::load(&fixture("resources.json")).unwrap(),
    );
    stores.replay = replay;
    AppState::new(ProtocolState {
        options: ProtocolOptions {
            issuer_uri: Some("https://idsrv.test".into()),
            ..Default::default()
        },
        keys: rustid_core::key_service::KeyService::new(
            KeyMaterial::load(&[key], &[]).unwrap(),
            None,
        ),
        features: rustid_core::discovery::DiscoveryFeatures {
            private_key_jwt: true,
            ..Default::default()
        },
        stores,
        events: Default::default(),
        path_base: None,
        protected_resource: None,
        dcr: None,
        saml: Default::default(),
        interaction: Default::default(),
    })
}

fn assertion() -> String {
    let key = LoadedKey::load(&KeyConfig {
        kid: "client-jwt-rsa".into(),
        alg: "RS256".into(),
        key_file: fixture("client-jwt-key.pem"),
        cert_file: None,
    })
    .unwrap();
    let now = chrono::Utc::now().timestamp();
    let serde_json::Value::Object(claims) = serde_json::json!({
        "iss": "client.jwt", "sub": "client.jwt", "aud": "https://idsrv.test",
        "jti": rustid_core::tokens::new_jwt_id(), "exp": now + 60, "iat": now,
    }) else {
        unreachable!()
    };
    rustid_core::jwt::encode(&key, &[("typ", "JWT")], &claims).unwrap()
}

async fn token(state: AppState, assertion: &str) -> StatusCode {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("grant_type", "client_credentials"),
            (
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ),
            ("client_assertion", assertion),
        ])
        .finish();
    rustid_http::router(state)
        .oneshot(
            Request::post("/connect/token")
                .header("host", "server")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn a_failing_replay_cache_fails_the_request() {
    let assertion = assertion();
    // The same assertion is accepted once with a working cache...
    let working = state(Arc::new(rustid_core::replay::InMemoryReplayCache::default()));
    assert_eq!(token(working.clone(), &assertion).await, StatusCode::OK);
    assert_eq!(token(working, &assertion).await, StatusCode::BAD_REQUEST);
    // ...and never without one.
    assert_eq!(
        token(state(Arc::new(Down)), &assertion).await,
        StatusCode::INTERNAL_SERVER_ERROR
    );
}
