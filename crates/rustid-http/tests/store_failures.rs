//! A failing store answers 500 wherever a request needs it
//! when a store throws, and never turns into a protocol answer.

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use rustid_core::clients::Client;
use rustid_core::grants::{GrantFilter, PersistedGrant};
use rustid_core::resources::{ApiResource, Resources};
use rustid_core::stores::{ClientStore, PersistedGrantStore, ResourceStore, StoreError, Stores};
use rustid_http::{AppState, ProtocolState};
use tower::ServiceExt;

struct Down;

fn down<T>() -> Result<T, StoreError> {
    Err(StoreError::Backend("connection refused".into()))
}

#[async_trait]
impl ClientStore for Down {
    async fn find_client_by_id(&self, _: &str) -> Result<Option<Arc<Client>>, StoreError> {
        down()
    }
    async fn is_cors_origin_allowed(&self, _: &str) -> Result<bool, StoreError> {
        down()
    }
}

#[async_trait]
impl ResourceStore for Down {
    async fn get_all_enabled_resources(&self) -> Result<Arc<Resources>, StoreError> {
        down()
    }
    async fn find_api_resources_by_name(
        &self,
        _: &[String],
    ) -> Result<Vec<ApiResource>, StoreError> {
        down()
    }
    async fn get_all_resources(&self) -> Result<Arc<Resources>, StoreError> {
        down()
    }
}

#[async_trait]
impl PersistedGrantStore for Down {
    async fn store(&self, _: PersistedGrant) -> Result<(), StoreError> {
        down()
    }
    async fn get(&self, _: &str) -> Result<Option<PersistedGrant>, StoreError> {
        down()
    }
    async fn get_all(&self, _: &GrantFilter) -> Result<Vec<PersistedGrant>, StoreError> {
        down()
    }
    async fn remove(&self, _: &str) -> Result<(), StoreError> {
        down()
    }
    async fn take(&self, _: &str) -> Result<Option<PersistedGrant>, StoreError> {
        down()
    }
    async fn remove_all(&self, _: &GrantFilter) -> Result<(), StoreError> {
        down()
    }
    async fn remove_expired(
        &self,
        _: chrono::DateTime<chrono::Utc>,
        _: usize,
        _: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<u64, StoreError> {
        down()
    }
}

async fn status(
    method: Method,
    path: &str,
    headers: &[(&str, &str)],
    body: &'static str,
) -> StatusCode {
    let state = AppState::new(ProtocolState {
        options: Default::default(),
        keys: Default::default(),
        features: Default::default(),
        stores: Stores {
            clients: Arc::new(Down),
            resources: Arc::new(Down),
            grants: Arc::new(Down),
            device_flow: Arc::new(rustid_store_memory::InMemoryDeviceFlowStore::default()),
            device_throttling: Arc::new(
                rustid_core::stores::InMemoryDeviceFlowThrottling::default(),
            ),
            replay: Arc::new(rustid_core::replay::InMemoryReplayCache::default()),
            configuration: Arc::new(rustid_store_memory::InMemoryConfiguration::default()),
            profile: Arc::new(rustid_core::profile::DefaultProfileService),
            token_request: Arc::new(rustid_core::token_request::DefaultTokenRequestValidator),
            request_uri: Arc::new(rustid_core::request_uri::NoRequestUriFetcher),
            client_jwks: Default::default(),
            back_channel: Arc::new(rustid_core::logout::NoBackChannelSender),
            grant_validation: Arc::new(rustid_core::grant_validation::NoGrantValidator),
            ciba: Arc::new(rustid_core::ciba::NopCibaService),
            sessions: None,
            federation: Default::default(),
        },
        events: Default::default(),
        path_base: None,
        protected_resource: None,
        dcr: None,
        saml: Default::default(),
        interaction: Default::default(),
    });
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "server");
    for (k, v) in headers {
        request = request.header(*k, *v);
    }
    rustid_http::router(state)
        .oneshot(request.body(Body::from(body)).unwrap())
        .await
        .unwrap()
        .status()
}

const FORM: (&str, &str) = ("content-type", "application/x-www-form-urlencoded");
#[tokio::test]
async fn endpoints_that_need_a_store_answer_500() {
    let token = "grant_type=client_credentials&client_id=client&client_secret=secret";
    assert_eq!(
        status(Method::POST, "/connect/token", &[FORM], token).await,
        500
    );
    let introspect = "client_id=client&client_secret=secret&token=x";
    assert_eq!(
        status(Method::POST, "/connect/introspect", &[FORM], introspect).await,
        500
    );
    let revoke = "client_id=client&client_secret=secret&token=x";
    assert_eq!(
        status(Method::POST, "/connect/revocation", &[FORM], revoke).await,
        500
    );
    assert_eq!(
        status(Method::GET, "/.well-known/openid-configuration", &[], "").await,
        500
    );
    let origin = ("origin", "https://client.test");
    assert_eq!(
        status(
            Method::GET,
            "/.well-known/openid-configuration/jwks",
            &[origin],
            ""
        )
        .await,
        500
    );
}

#[tokio::test]
async fn requests_that_fail_before_any_store_use_are_unaffected() {
    assert_eq!(status(Method::GET, "/health", &[], "").await, 200);
    assert_eq!(
        status(
            Method::GET,
            "/.well-known/openid-configuration/jwks",
            &[],
            ""
        )
        .await,
        200
    );
    assert_eq!(
        status(Method::GET, "/connect/introspect", &[], "").await,
        405
    );
    assert_eq!(
        status(Method::POST, "/connect/token", &[FORM], "a=%00").await,
        400
    );
}
