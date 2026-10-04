//! HTTP behaviour of the introspection and revocation endpoints. Protocol
//! outcomes are covered in rustid-core; these pin status codes, headers and
//! the endpoint switches.

use std::path::{Path, PathBuf};

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use rustid_core::clients::Clients;
use rustid_core::keys::{KeyConfig, KeyMaterial};
use rustid_core::options::ProtocolOptions;
use rustid_core::resources::Resources;
use rustid_http::{AppState, ProtocolState};
use tower::ServiceExt;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

fn state(options: ProtocolOptions) -> AppState {
    let key = KeyConfig {
        kid: "k1".into(),
        alg: "RS256".into(),
        key_file: fixture("signing-key.pem"),
        cert_file: None,
    };
    AppState::new(ProtocolState {
        options: ProtocolOptions {
            issuer_uri: Some("https://idsrv.test".into()),
            ..options
        },
        keys: rustid_core::key_service::KeyService::new(
            KeyMaterial::load(&[key], &[]).unwrap(),
            None,
        ),
        features: Default::default(),
        stores: rustid_store_memory::stores(
            Clients::load(&fixture("clients.json")).unwrap(),
            Resources::load(&fixture("resources.json")).unwrap(),
        ),
        events: Default::default(),
        path_base: None,
        protected_resource: None,
        dcr: None,
        saml: Default::default(),
        interaction: Default::default(),
    })
}

struct Reply {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: String,
}

async fn send_to(
    app: &AppState,
    method: Method,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Reply {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "server");
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let response = rustid_http::router(app.clone())
        .oneshot(builder.body(Body::from(body.to_owned())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    Reply {
        status,
        headers,
        body: String::from_utf8(bytes.to_vec()).unwrap(),
    }
}

const FORM: (&str, &str) = ("content-type", "application/x-www-form-urlencoded");
const API: (&str, &str) = ("authorization", "Basic YXBpOnNlY3JldA=="); // api:secret

#[tokio::test]
async fn introspection_statuses() {
    let app = state(Default::default());
    let path = "/connect/introspect";
    let r = send_to(&app, Method::GET, path, &[API], "").await;
    assert_eq!(
        (r.status, r.body.as_str()),
        (StatusCode::METHOD_NOT_ALLOWED, "")
    );
    let r = send_to(
        &app,
        Method::POST,
        path,
        &[API, ("content-type", "text/plain")],
        "token=x",
    )
    .await;
    assert_eq!(r.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let r = send_to(&app, Method::POST, path, &[API, FORM], "token=a%00b").await;
    assert_eq!((r.status, r.body.as_str()), (StatusCode::BAD_REQUEST, ""));
    let r = send_to(&app, Method::POST, path, &[FORM], "token=x").await;
    assert_eq!((r.status, r.body.as_str()), (StatusCode::UNAUTHORIZED, ""));
    let r = send_to(&app, Method::POST, path, &[API, FORM], "").await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(r.body, r#"{"error":"missing_token"}"#);
    assert_eq!(r.headers["cache-control"], "no-store, no-cache, max-age=0");
    let r = send_to(&app, Method::POST, path, &[API, FORM], "token=x").await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.headers["content-type"], "application/json; charset=UTF-8");
    assert_eq!(r.headers["pragma"], "no-cache");
    assert_eq!(r.body, r#"{"active":false}"#);
}

#[tokio::test]
async fn introspection_can_answer_with_a_jwt() {
    let app = state(Default::default());
    let accept = ("accept", "application/token-introspection+jwt");
    let r = send_to(
        &app,
        Method::POST,
        "/connect/introspect",
        &[API, FORM, accept],
        "token=x",
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(
        r.headers["content-type"],
        "application/token-introspection+jwt"
    );
    assert_eq!(r.headers["cache-control"], "no-store, no-cache, max-age=0");
    let jws = rustid_core::jwt::Jws::decode(&r.body).unwrap();
    assert_eq!(
        jws.payload["token_introspection"],
        serde_json::json!({"active": false})
    );
}

#[tokio::test]
async fn issued_reference_tokens_are_introspectable_and_revocable() {
    let app = state(Default::default());
    let r = send_to(
        &app,
        Method::POST,
        "/connect/token",
        &[FORM],
        "grant_type=client_credentials&client_id=client.reference&client_secret=secret&scope=api1",
    )
    .await;
    let handle = serde_json::from_str::<serde_json::Value>(&r.body).unwrap()["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let introspect = format!("token={handle}");
    let r = send_to(
        &app,
        Method::POST,
        "/connect/introspect",
        &[API, FORM],
        &introspect,
    )
    .await;
    assert!(r.body.contains(r#""active":true"#), "{}", r.body);
    let revoke = format!("client_id=client.reference&client_secret=secret&token={handle}");
    let r = send_to(&app, Method::POST, "/connect/revocation", &[FORM], &revoke).await;
    assert_eq!((r.status, r.body.as_str()), (StatusCode::OK, ""));
    let r = send_to(
        &app,
        Method::POST,
        "/connect/introspect",
        &[API, FORM],
        &introspect,
    )
    .await;
    assert_eq!(r.body, r#"{"active":false}"#);
}

#[tokio::test]
async fn revocation_errors_are_json_without_cache_headers() {
    let app = state(Default::default());
    let r = send_to(
        &app,
        Method::POST,
        "/connect/revocation",
        &[FORM],
        "token=x",
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(r.body, r#"{"error":"invalid_request"}"#);
    assert_eq!(r.headers["content-type"], "application/json; charset=UTF-8");
    assert!(r.headers.get("cache-control").is_none());
    let r = send_to(&app, Method::GET, "/connect/revocation", &[], "").await;
    assert_eq!(r.status, StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn disabled_endpoints_are_not_found() {
    let mut options = ProtocolOptions::default();
    options.endpoints.enable_introspection_endpoint = false;
    options.endpoints.enable_token_revocation_endpoint = false;
    let app = state(options);
    for path in ["/connect/introspect", "/connect/revocation"] {
        let r = send_to(&app, Method::POST, path, &[API, FORM], "token=x").await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{path}");
    }
}
