use std::path::{Path, PathBuf};

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use rustid_core::discovery::DiscoveryFeatures;
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

fn state(options: ProtocolOptions, path_base: Option<&str>) -> AppState {
    let key = KeyConfig {
        kid: "k1".into(),
        alg: "RS256".into(),
        key_file: fixture("signing-key.pem"),
        cert_file: None,
    };
    AppState::new(ProtocolState {
        options,
        keys: rustid_core::key_service::KeyService::new(
            KeyMaterial::load(&[key], &[]).unwrap(),
            None,
        ),
        features: DiscoveryFeatures::default(),
        stores: rustid_store_memory::stores(
            Default::default(),
            Resources::load(&fixture("resources.json")).unwrap(),
        ),
        events: Default::default(),
        path_base: path_base.map(str::to_owned),
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

async fn send(state: AppState, method: Method, path: &str, host: Option<&str>) -> Reply {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(host) = host {
        builder = builder.header("host", host);
    }
    let response = rustid_http::router(state)
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = (!bytes.is_empty()).then(|| serde_json::from_slice(&bytes).unwrap());
    Reply {
        status,
        headers,
        body,
    }
}

async fn get(state: AppState, path: &str) -> Reply {
    send(state, Method::GET, path, Some("server:5001")).await
}

#[tokio::test]
async fn discovery_uses_request_origin_for_urls_and_its_content_type() {
    let r = get(
        state(ProtocolOptions::default(), None),
        "/.well-known/openid-configuration",
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.headers["content-type"], "application/json; charset=UTF-8");
    let body = r.body.unwrap();
    assert_eq!(body["issuer"], "http://server:5001");
    assert_eq!(body["token_endpoint"], "http://server:5001/connect/token");
}

#[tokio::test]
async fn paths_match_case_insensitively_and_path_base_keeps_request_casing() {
    let r = get(
        state(ProtocolOptions::default(), Some("/root")),
        "/ROOT/.WELL-KNOWN/OPENID-CONFIGURATION",
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    let body = r.body.unwrap();
    assert_eq!(body["issuer"], "http://server:5001/root");
    assert_eq!(
        body["token_endpoint"],
        "http://server:5001/ROOT/connect/token"
    );
}

#[tokio::test]
async fn path_base_is_optional_like_use_path_base() {
    let r = get(
        state(ProtocolOptions::default(), Some("/root")),
        "/.well-known/openid-configuration",
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body.unwrap()["issuer"], "http://server:5001");
}

#[tokio::test]
async fn non_get_is_405_and_unknown_or_trailing_slash_paths_are_404() {
    let s = || state(ProtocolOptions::default(), None);
    assert_eq!(
        send(
            s(),
            Method::POST,
            "/.well-known/openid-configuration",
            Some("h")
        )
        .await
        .status,
        StatusCode::METHOD_NOT_ALLOWED
    );
    assert_eq!(
        send(
            s(),
            Method::POST,
            "/.well-known/openid-configuration/jwks",
            Some("h")
        )
        .await
        .status,
        StatusCode::METHOD_NOT_ALLOWED
    );
    let r = get(s(), "/.well-known/openid-configuration/").await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert!(r.body.is_none());
    assert_eq!(
        get(s(), "/connect/nothing-here").await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn disabled_discovery_is_404_even_for_post() {
    let mut options = ProtocolOptions::default();
    options.endpoints.enable_discovery_endpoint = false;
    let r = send(
        state(options, None),
        Method::POST,
        "/.well-known/openid-configuration",
        Some("h"),
    )
    .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn hidden_key_set_makes_jwks_404() {
    let mut options = ProtocolOptions::default();
    options.discovery.show_key_set = false;
    assert_eq!(
        get(
            state(options, None),
            "/.well-known/openid-configuration/jwks"
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn cache_interval_sets_max_age_and_vary_or_no_store_for_zero() {
    let mut options = ProtocolOptions::default();
    options.discovery.response_cache_interval = Some(60);
    let r = get(
        state(options.clone(), None),
        "/.well-known/openid-configuration/jwks",
    )
    .await;
    assert_eq!(r.headers["cache-control"], "max-age=60");
    assert_eq!(r.headers["vary"], "Origin");

    options.discovery.response_cache_interval = Some(0);
    let r = get(state(options, None), "/.well-known/openid-configuration").await;
    assert_eq!(r.headers["cache-control"], "no-store, no-cache, max-age=0");
    assert_eq!(r.headers["pragma"], "no-cache");
}

#[tokio::test]
async fn request_without_host_header_is_400_not_a_panic() {
    let r = send(
        state(ProtocolOptions::default(), None),
        Method::GET,
        "/.well-known/openid-configuration",
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn oauth_metadata_requires_issuer_to_equal_request_origin() {
    // Dynamic issuer: equals the origin, so metadata is served.
    let r = get(
        state(ProtocolOptions::default(), None),
        "/.well-known/oauth-authorization-server",
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body.unwrap()["issuer"], "http://server:5001");

    // Fixed issuer on another host: 404.
    let fixed = ProtocolOptions {
        issuer_uri: Some("https://idsrv.test".into()),
        ..Default::default()
    };
    assert_eq!(
        get(
            state(fixed, None),
            "/.well-known/oauth-authorization-server"
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn oauth_metadata_inserts_the_issuer_path_after_the_well_known_segment() {
    let options = ProtocolOptions {
        issuer_uri: Some("http://idsrv.test/identity".into()),
        ..Default::default()
    };
    let s = || state(options.clone(), Some("/identity"));
    let host = Some("idsrv.test");

    let r = send(
        s(),
        Method::GET,
        "/.well-known/oauth-authorization-server/identity?query=string",
        host,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    let body = r.body.unwrap();
    assert_eq!(body["issuer"], "http://idsrv.test/identity");
    assert_eq!(
        body["token_endpoint"],
        "http://idsrv.test/identity/connect/token"
    );

    for path in [
        "/.well-known/oauth-authorization-server",
        "/.well-known/oauth-authorization-server/wrong",
        "/.well-known/oauth-authorization-server/IDENTITY",
        "/identity/.well-known/oauth-authorization-server",
    ] {
        assert_eq!(
            send(s(), Method::GET, path, host).await.status,
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
    assert_eq!(
        send(
            s(),
            Method::POST,
            "/.well-known/oauth-authorization-server/identity",
            host
        )
        .await
        .status,
        StatusCode::METHOD_NOT_ALLOWED
    );
}

#[tokio::test]
async fn oauth_metadata_with_trailing_slash_is_404_like_remove_trailing_slash() {
    // The base path has its trailing slash removed, so the issuer stays the
    // bare origin and no longer equals the requested origin plus "/".
    let r = get(
        state(ProtocolOptions::default(), None),
        "/.well-known/oauth-authorization-server/",
    )
    .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn syntactically_invalid_host_header_is_400_like_kestrel() {
    for host in [
        "a b",
        "a\"b",
        "evil.test/x",
        "host:port",
        "host:80:81",
        "[::1",
        "a@b",
    ] {
        let r = send(
            state(ProtocolOptions::default(), None),
            Method::GET,
            "/.well-known/openid-configuration",
            Some(host),
        )
        .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{host:?}");
    }
    for host in [
        "server:5001",
        "[::1]:8080",
        "xn--80af5akm.xn--p1ai",
        "idsrv.test",
        "a-b_c~d",
    ] {
        let r = send(
            state(ProtocolOptions::default(), None),
            Method::GET,
            "/.well-known/openid-configuration",
            Some(host),
        )
        .await;
        assert_eq!(r.status, StatusCode::OK, "{host:?}");
    }
}

#[tokio::test]
async fn paths_are_percent_decoded_before_matching_except_encoded_slash() {
    let s = || state(ProtocolOptions::default(), None);
    assert_eq!(
        get(s(), "/%2Ewell-known/openid-configuration").await.status,
        StatusCode::OK
    );
    assert_eq!(
        get(s(), "/.well-known/openid%2Dconfiguration").await.status,
        StatusCode::OK
    );
    // Kestrel leaves %2F encoded, so it never becomes a path separator.
    assert_eq!(
        get(s(), "/.well-known%2Fopenid-configuration").await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get(s(), "/.well-known%2fopenid-configuration").await.status,
        StatusCode::NOT_FOUND
    );
    // An invalid escape is kept literally and simply doesn't match.
    assert_eq!(
        get(s(), "/.well-known/openid-configuration%zz")
            .await
            .status,
        StatusCode::NOT_FOUND
    );
}
