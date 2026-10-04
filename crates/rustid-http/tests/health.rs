use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use rustid_http::{AppState, ProtocolState};
use tower::ServiceExt;

#[tokio::test]
async fn health_returns_ok_json() {
    let app = rustid_http::router(AppState::new(ProtocolState {
        options: Default::default(),
        keys: Default::default(),
        features: Default::default(),
        stores: rustid_store_memory::stores(Default::default(), Default::default()),
        events: Default::default(),
        path_base: None,
        protected_resource: None,
        dcr: None,
        saml: Default::default(),
        interaction: Default::default(),
    }));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    // The exact content type, which clients and probes may compare.
    assert_eq!(
        response.headers()["content-type"],
        "application/json; charset=utf-8"
    );
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json, serde_json::json!({ "status": "ok" }));
}
