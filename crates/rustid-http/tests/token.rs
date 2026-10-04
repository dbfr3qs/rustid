use std::path::{Path, PathBuf};

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use rustid_core::clients::Clients;
use rustid_core::keys::{KeyConfig, KeyMaterial};
use rustid_core::options::ProtocolOptions;
use rustid_core::resources::Resources;
use rustid_http::{AppState, ProtocolState};
use serde_json::Value;
use tower::ServiceExt;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

fn state() -> AppState {
    let key = KeyConfig {
        kid: "k1".into(),
        alg: "RS256".into(),
        key_file: fixture("signing-key.pem"),
        cert_file: None,
    };
    AppState::new(ProtocolState {
        options: ProtocolOptions {
            issuer_uri: Some("https://idsrv.test".into()),
            ..Default::default()
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
    body: Option<Value>,
}

async fn send(method: Method, path: &str, headers: &[(&str, &str)], body: &'static [u8]) -> Reply {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "server");
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let response = rustid_http::router(state())
        .oneshot(builder.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    Reply {
        status,
        headers,
        body: (!bytes.is_empty()).then(|| serde_json::from_slice(&bytes).unwrap()),
    }
}

const FORM: (&str, &str) = ("content-type", "application/x-www-form-urlencoded");

#[tokio::test]
async fn token_success_is_json_with_no_cache_headers() {
    let r = send(
        Method::POST,
        "/connect/token",
        &[FORM],
        b"grant_type=client_credentials&client_id=client&client_secret=secret&scope=api1",
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.headers["content-type"], "application/json; charset=UTF-8");
    assert_eq!(r.headers["cache-control"], "no-store, no-cache, max-age=0");
    assert_eq!(r.headers["pragma"], "no-cache");
    let body = r.body.unwrap();
    assert_eq!(
        (
            body["token_type"].as_str(),
            body["expires_in"].as_i64(),
            body["scope"].as_str()
        ),
        (Some("Bearer"), Some(3600), Some("api1"))
    );
}

#[tokio::test]
async fn errors_are_400_json_with_no_cache_headers() {
    let r = send(
        Method::POST,
        "/connect/token",
        &[FORM],
        b"grant_type=client_credentials&client_id=nobody&client_secret=x",
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(r.headers["cache-control"], "no-store, no-cache, max-age=0");
    assert_eq!(
        r.body.unwrap(),
        serde_json::json!({ "error": "invalid_client" })
    );
}

#[tokio::test]
async fn non_post_non_form_and_nul_bodies_are_invalid_requests() {
    for (method, headers, body) in [
        (Method::GET, vec![], &b""[..]),
        (
            Method::POST,
            vec![("content-type", "application/json")],
            &b"{}"[..],
        ),
        (
            Method::POST,
            vec![FORM],
            &b"grant_type=client_credentials&x=%00"[..],
        ),
    ] {
        let r = send(method, "/connect/token", &headers, body).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST);
        assert_eq!(r.body.unwrap()["error"], "invalid_request");
    }
    let r = send(
        Method::POST,
        "/connect/token",
        &[(
            "content-type",
            "Application/X-WWW-Form-UrlEncoded; charset=utf-8",
        )],
        b"grant_type=client_credentials&client_id=client&client_secret=secret",
    )
    .await;
    assert_eq!(
        r.status,
        StatusCode::OK,
        "media type is case-insensitive and parameters are ignored"
    );
}

#[tokio::test]
async fn disabled_token_endpoint_and_unknown_paths_are_404() {
    let mut s = (*state().0).clone();
    s.options.endpoints.enable_token_endpoint = false;
    let response = rustid_http::router(AppState::new(s))
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/connect/token")
                .header("host", "h")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        send(Method::POST, "/connect/token/", &[FORM], b"")
            .await
            .status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn cors_preflight_for_an_allowed_origin_short_circuits_with_echoed_request() {
    let r = send(
        Method::OPTIONS,
        "/connect/userinfo",
        &[
            ("origin", "https://client.test"),
            ("access-control-request-method", "GET"),
            (
                "access-control-request-headers",
                "Content-Type , Authorization",
            ),
        ],
        b"",
    )
    .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(
        r.headers["access-control-allow-origin"],
        "https://client.test"
    );
    assert_eq!(r.headers["access-control-allow-methods"], "GET");
    assert_eq!(
        r.headers["access-control-allow-headers"],
        "Content-Type,Authorization"
    );
}

#[tokio::test]
async fn cors_preflight_with_origin_in_other_case_has_no_headers() {
    let r = send(
        Method::OPTIONS,
        "/connect/token",
        &[
            ("origin", "HTTPS://CLIENT.TEST"),
            ("access-control-request-method", "POST"),
        ],
        b"",
    )
    .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert!(r.headers.get("access-control-allow-origin").is_none());
}

#[tokio::test]
async fn cors_unknown_origin_or_non_cors_path_passes_through() {
    let r = send(
        Method::OPTIONS,
        "/connect/token",
        &[
            ("origin", "https://evil.test"),
            ("access-control-request-method", "POST"),
        ],
        b"",
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let r = send(
        Method::OPTIONS,
        "/.well-known/oauth-authorization-server",
        &[
            ("origin", "https://client.test"),
            ("access-control-request-method", "GET"),
        ],
        b"",
    )
    .await;
    assert_eq!(r.status, StatusCode::METHOD_NOT_ALLOWED);
    assert!(r.headers.get("access-control-allow-origin").is_none());
}

#[tokio::test]
async fn cors_actual_requests_get_the_allow_origin_header_even_on_errors() {
    let r = send(
        Method::POST,
        "/connect/token",
        &[("origin", "https://client.test")],
        b"",
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        r.headers["access-control-allow-origin"],
        "https://client.test"
    );
    let same_origin = send(
        Method::GET,
        "/.well-known/openid-configuration",
        &[("origin", "http://server")],
        b"",
    )
    .await;
    assert!(
        same_origin
            .headers
            .get("access-control-allow-origin")
            .is_none(),
        "an Origin equal to the server's own is not CORS"
    );
}

#[tokio::test]
async fn cors_headers_are_added_to_404s_on_cors_paths_without_an_endpoint() {
    // CorsMiddleware runs outside the protocol's endpoint routing, so a
    // CORS path whose endpoint is disabled still gets the header on its 404.
    let mut s = (*state().0).clone();
    s.options.endpoints.enable_user_info_endpoint = false;
    let response = rustid_http::router(AppState::new(s))
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/connect/userinfo")
                .header("host", "server")
                .header("origin", "https://client.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response.headers()["access-control-allow-origin"],
        "https://client.test"
    );
}

const M2M: &[u8] = b"grant_type=client_credentials&client_id=m2m&client_secret=secret&scope=api1";

#[tokio::test]
async fn dpop_headers_are_read_one_at_most() {
    let r = send(
        Method::POST,
        "/connect/token",
        &[FORM, ("DPoP", "a"), ("DPoP", "b")],
        M2M,
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let body = r.body.unwrap();
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "Too many DPoP headers provided.");

    let r = send(
        Method::POST,
        "/connect/token",
        &[FORM, ("dpop", "malformed")],
        M2M,
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let body = r.body.unwrap();
    assert_eq!(body["error"], "invalid_dpop_proof");
    assert_eq!(body["error_description"], "Malformed DPoP token.");
    assert!(r.headers.get("dpop-nonce").is_none());
}

#[tokio::test]
async fn device_authorization_needs_a_form_post() {
    for (method, headers) in [(Method::GET, vec![]), (Method::POST, vec![])] {
        let r = send(method, "/connect/deviceauthorization", &headers, b"").await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST);
        assert_eq!(r.body.unwrap()["error"], "invalid_request");
        assert_eq!(r.headers["cache-control"], "no-store, no-cache, max-age=0");
    }
    // An authenticated client without the grant.
    let r = send(Method::POST, "/connect/deviceauthorization", &[FORM], M2M).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(r.body.unwrap()["error"], "unauthorized_client");
}

#[tokio::test]
async fn ciba_answers_with_cibas_status_codes() {
    let r = send(Method::GET, "/connect/ciba", &[], b"").await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(r.body.unwrap()["error"], "invalid_request");
    let r = send(
        Method::POST,
        "/connect/ciba",
        &[FORM],
        b"client_id=nobody&client_secret=x&scope=openid&login_hint=a",
    )
    .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(r.body.unwrap()["error"], "invalid_client");
    assert_eq!(r.headers["cache-control"], "no-store, no-cache, max-age=0");
    let r = send(Method::POST, "/connect/ciba", &[FORM], M2M).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(r.body.unwrap()["error"], "unauthorized_client");
}
