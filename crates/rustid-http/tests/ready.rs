//! `/ready`: whether the server can serve tokens now. The store answers
//! and a signing key is available; otherwise 503 with a reason and nothing
//! from the error itself.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use rustid_core::grants::{GrantFilter, PersistedGrant};
use rustid_core::key_service::KeyService;
use rustid_core::keys::{KeyConfig, KeyMaterial};
use rustid_core::stores::{PersistedGrantStore, StoreError};
use rustid_http::{AppState, ProtocolState};
use serde_json::{Value, json};
use tower::ServiceExt;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

fn keys() -> KeyService {
    let key = KeyConfig {
        kid: "k1".into(),
        alg: "RS256".into(),
        key_file: fixture("signing-key.pem"),
        cert_file: None,
    };
    KeyService::new(KeyMaterial::load(&[key], &[]).unwrap(), None)
}

enum Grants {
    Down,
    Hung,
}

#[async_trait]
impl PersistedGrantStore for Grants {
    async fn store(&self, _: PersistedGrant) -> Result<(), StoreError> {
        unreachable!()
    }
    async fn get(&self, _: &str) -> Result<Option<PersistedGrant>, StoreError> {
        match self {
            Grants::Down => Err(StoreError::Backend(
                "connection to postgres://rustid:hunter2@db/rustid refused".into(),
            )),
            Grants::Hung => std::future::pending().await,
        }
    }
    async fn get_all(&self, _: &GrantFilter) -> Result<Vec<PersistedGrant>, StoreError> {
        unreachable!()
    }
    async fn remove(&self, _: &str) -> Result<(), StoreError> {
        unreachable!()
    }
    async fn take(&self, _: &str) -> Result<Option<PersistedGrant>, StoreError> {
        unreachable!()
    }
    async fn remove_all(&self, _: &GrantFilter) -> Result<(), StoreError> {
        unreachable!()
    }
    async fn remove_expired(
        &self,
        _: chrono::DateTime<chrono::Utc>,
        _: usize,
        _: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<u64, StoreError> {
        unreachable!()
    }
}

fn state(keys: KeyService, grants: Option<Grants>) -> AppState {
    let mut stores = rustid_store_memory::stores(Default::default(), Default::default());
    if let Some(grants) = grants {
        stores.grants = Arc::new(grants);
    }
    AppState::new(ProtocolState {
        options: Default::default(),
        keys,
        features: Default::default(),
        stores,
        events: Default::default(),
        path_base: None,
        protected_resource: None,
        dcr: None,
        saml: Default::default(),
        interaction: Default::default(),
    })
}

async fn get(state: AppState, uri: &str) -> (StatusCode, String, String) {
    let response = rustid_http::router(state)
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let content_type = response
        .headers()
        .get("content-type")
        .map(|v| v.to_str().unwrap().to_owned())
        .unwrap_or_default();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        content_type,
        String::from_utf8(bytes.to_vec()).unwrap(),
    )
}

async fn ready(state: AppState) -> (StatusCode, String, Value) {
    let (status, content_type, body) = get(state, "/ready").await;
    (status, content_type, serde_json::from_str(&body).unwrap())
}

#[tokio::test]
async fn ready_when_the_store_answers_and_a_key_is_loaded() {
    let (status, content_type, body) = ready(state(keys(), None)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(content_type, "application/json; charset=utf-8");
    assert_eq!(body, json!({ "status": "ready" }));
}

#[tokio::test]
async fn a_failing_store_is_unavailable() {
    let (status, content_type, body) = ready(state(keys(), Some(Grants::Down))).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(content_type, "application/json; charset=utf-8");
    assert_eq!(body, json!({ "status": "unavailable", "reason": "store" }));
}

#[tokio::test]
async fn the_body_never_carries_the_error() {
    let (_, _, text) = get(state(keys(), Some(Grants::Down)), "/ready").await;
    assert!(
        !text.contains("hunter2") && !text.contains("postgres://"),
        "{text}"
    );
}

#[tokio::test(start_paused = true)]
async fn a_hung_store_is_unavailable_in_time() {
    let started = tokio::time::Instant::now();
    let (status, _, body) = ready(state(keys(), Some(Grants::Hung))).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body, json!({ "status": "unavailable", "reason": "store" }));
    assert!(started.elapsed() <= rustid_http::READY_PROBE_TIMEOUT * 2);
}

#[tokio::test]
async fn no_signing_key_is_unavailable() {
    let (status, _, body) = ready(state(KeyService::default(), None)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        body,
        json!({ "status": "unavailable", "reason": "signing_key" })
    );
}

#[tokio::test]
async fn health_is_unchanged_when_not_ready() {
    let (status, _, body) = get(state(KeyService::default(), Some(Grants::Down)), "/health").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, r#"{"status":"ok"}"#);
}
