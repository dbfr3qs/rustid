//! Events raised through the HTTP layer carry the connection's addresses,
//! and server-side failures are raised as unhandled exceptions.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Method, Request};
use rustid_core::clients::{Client, Clients};
use rustid_core::events::{Event, EventService, EventSink};
use rustid_core::key_service::KeyService;
use rustid_core::keys::{KeyConfig, KeyMaterial};
use rustid_core::options::EventsOptions;
use rustid_core::resources::Resources;
use rustid_core::stores::{ClientStore, StoreError};
use rustid_http::{AppState, LocalAddr, ProtocolState};
use tower::ServiceExt;

#[derive(Default)]
struct Recording(Mutex<Vec<Event>>);

impl EventSink for Recording {
    fn persist(&self, event: &Event) {
        self.0.lock().unwrap().push(event.clone());
    }
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

fn all_events() -> EventsOptions {
    EventsOptions {
        raise_success_events: true,
        raise_failure_events: true,
        raise_information_events: true,
        raise_error_events: true,
    }
}

fn state(sink: Arc<Recording>, clients: Option<Arc<dyn ClientStore>>) -> AppState {
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
    if let Some(clients) = clients {
        stores.clients = clients;
    }
    AppState::new(ProtocolState {
        options: Default::default(),
        keys: KeyService::new(KeyMaterial::load(&[key], &[]).unwrap(), None),
        features: Default::default(),
        stores,
        events: EventService::new(all_events(), sink),
        path_base: None,
        protected_resource: None,
        dcr: None,
        saml: Default::default(),
        interaction: Default::default(),
    })
}

async fn post_token(app: AppState, body: &'static str) -> u16 {
    let mut request = Request::builder()
        .method(Method::POST)
        .uri("/connect/token")
        .header("host", "server")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "203.0.113.9:50123".parse::<SocketAddr>().unwrap(),
    ));
    request
        .extensions_mut()
        .insert(LocalAddr("127.0.0.1:8080".parse().unwrap()));
    rustid_http::router(app)
        .oneshot(request)
        .await
        .unwrap()
        .status()
        .as_u16()
}

#[tokio::test]
async fn events_carry_the_remote_and_local_addresses() {
    let sink = Arc::new(Recording::default());
    let status = post_token(
        state(sink.clone(), None),
        "grant_type=client_credentials&client_id=client&client_secret=secret",
    )
    .await;
    assert_eq!(status, 200);
    let events = sink.0.lock().unwrap().clone();
    assert_eq!(events.len(), 2, "{events:?}");
    for event in events {
        assert_eq!(
            event.remote_ip_address.as_deref(),
            Some("203.0.113.9:50123")
        );
        assert_eq!(event.local_ip_address.as_deref(), Some("127.0.0.1:8080"));
        assert_eq!(
            event.activity_id, None,
            "no OpenTelemetry layer is installed"
        );
    }
}

struct Down;

#[async_trait]
impl ClientStore for Down {
    async fn find_client_by_id(&self, _: &str) -> Result<Option<Arc<Client>>, StoreError> {
        Err(StoreError::Backend("connection refused".into()))
    }
    async fn is_cors_origin_allowed(&self, _: &str) -> Result<bool, StoreError> {
        Err(StoreError::Backend("connection refused".into()))
    }
}

#[tokio::test]
async fn a_store_failure_is_an_unhandled_exception_event() {
    let sink = Arc::new(Recording::default());
    let status = post_token(
        state(sink.clone(), Some(Arc::new(Down))),
        "grant_type=client_credentials&client_id=client&client_secret=secret",
    )
    .await;
    assert_eq!(status, 500);
    let events = sink.0.lock().unwrap().clone();
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].name, "Unhandled Exception");
    assert_eq!(events[0].id, 3000);
    assert!(
        events[0]
            .message
            .as_deref()
            .unwrap()
            .contains("connection refused")
    );
}
