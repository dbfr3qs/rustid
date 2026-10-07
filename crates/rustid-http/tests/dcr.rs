//! `POST /connect/dcr`: dynamic client registration over HTTP, behind
//! initial access tokens.

mod browser;

use axum::http::{Method, StatusCode};
use browser::*;
use rustid_http::{AppState, ProtocolState};

const TOKEN: &str = "an-initial-access-token-of-32-chars!!";
const JSON: (&str, &str) = ("content-type", "application/json");
const FORM: (&str, &str) = ("content-type", "application/x-www-form-urlencoded");
const BODY: &str = r#"{"grant_types":["client_credentials"],"scope":"api1"}"#;

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

#[tokio::test]
async fn registration_needs_an_initial_access_token() {
    let app = state_with_dcr(false, vec![TOKEN.into()], false);
    let mut b = Browser::new(&app);
    let r = b.send(Method::POST, "/connect/dcr", &[JSON], BODY).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        r.headers["www-authenticate"],
        r#"Bearer error="invalid_token""#
    );
    let wrong = bearer("wrong-token-wrong-token-wrong-token");
    let r = b
        .send(
            Method::POST,
            "/connect/dcr",
            &[JSON, ("authorization", &wrong)],
            BODY,
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let right = bearer(TOKEN);
    let r = b
        .send(
            Method::POST,
            "/connect/dcr",
            &[JSON, ("authorization", &right)],
            BODY,
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    assert_eq!(r.headers["content-type"], "application/json; charset=utf-8");
}

#[tokio::test]
async fn open_registration_then_the_client_gets_a_token() {
    let app = state_with_dcr(true, vec![], false);
    let mut b = Browser::new(&app);
    let r = b.send(Method::POST, "/connect/dcr", &[JSON], BODY).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    let body: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    let form = format!(
        "grant_type=client_credentials&client_id={}&client_secret={}",
        body["client_id"].as_str().unwrap(),
        body["client_secret"].as_str().unwrap()
    );
    let r = b.send(Method::POST, "/connect/token", &[FORM], &form).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
}

#[tokio::test]
async fn method_content_type_and_body_errors() {
    let app = state_with_dcr(true, vec![], false);
    let mut b = Browser::new(&app);
    assert_eq!(
        b.send(Method::GET, "/connect/dcr", &[], "").await.status,
        StatusCode::METHOD_NOT_ALLOWED
    );
    let r = b
        .send(Method::POST, "/connect/dcr", &[FORM], "grant_types=x")
        .await;
    assert_eq!(r.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert!(r.body.is_empty());
    let r = b
        .send(
            Method::POST,
            "/connect/dcr",
            &[("content-type", "Application/JSON; charset=utf-8")],
            "{",
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        r.body,
        r#"{"error":"invalid_client_metadata","error_description":"malformed metadata document"}"#
    );
    let r = b
        .send(
            Method::POST,
            "/connect/dcr",
            &[JSON],
            r#"{"redirect_uris":["https://a/cb"]}"#,
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        r.body,
        r#"{"error":"invalid_client_metadata","error_description":"grant type is required"}"#
    );
}

#[tokio::test]
async fn disabled_is_not_found() {
    let app = state();
    assert_eq!(
        Browser::new(&app)
            .send(Method::POST, "/connect/dcr", &[JSON], BODY)
            .await
            .status,
        StatusCode::NOT_FOUND
    );
}

/// The test requests' base URL (`Host: server`), which management URIs use,
/// as discovery's endpoint URLs do.
const ISSUER: &str = "http://server";

async fn register_managed(b: &mut Browser) -> serde_json::Value {
    let r = b
        .send(
            Method::POST,
            "/connect/dcr",
            &[JSON],
            r#"{"grant_types":["authorization_code"],"redirect_uris":["https://rp/cb"],"initiate_login_uri":"https://rp/login"}"#,
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    serde_json::from_str(&r.body).unwrap()
}

fn management_path(registration: &serde_json::Value) -> String {
    registration["registration_client_uri"]
        .as_str()
        .unwrap()
        .trim_start_matches(ISSUER)
        .to_owned()
}

#[tokio::test]
async fn a_registered_client_is_read_and_deleted_with_its_token() {
    let app = state_with_dcr(true, vec![], true);
    let mut b = Browser::new(&app);
    let reg = register_managed(&mut b).await;
    let client_id = reg["client_id"].as_str().unwrap();
    assert_eq!(
        reg["registration_client_uri"],
        format!("{ISSUER}/connect/dcr/{client_id}")
    );
    let keys: Vec<&String> = reg.as_object().unwrap().keys().take(5).collect();
    assert_eq!(
        keys,
        [
            "client_id",
            "client_secret",
            "client_secret_expires_at",
            "registration_client_uri",
            "registration_access_token"
        ]
    );
    let path = management_path(&reg);
    let auth = bearer(reg["registration_access_token"].as_str().unwrap());
    let r = b
        .send(Method::GET, &path, &[("authorization", &auth)], "")
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.headers["cache-control"], "no-store");
    let read: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(read["initiate_login_uri"], "https://rp/login");
    assert_eq!(read["client_id"], reg["client_id"]);
    assert_eq!(
        read["registration_client_uri"],
        reg["registration_client_uri"]
    );
    assert!(read.get("client_secret").is_none() && read.get("registration_access_token").is_none());

    let r = b
        .send(Method::DELETE, &path, &[("authorization", &auth)], "")
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(
        b.send(Method::GET, &path, &[("authorization", &auth)], "")
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    let token = format!(
        "grant_type=client_credentials&client_id={client_id}&client_secret={}",
        reg["client_secret"].as_str().unwrap()
    );
    let r = b
        .send(Method::POST, "/connect/token", &[FORM], &token)
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(
        r.body.contains(r#""error":"invalid_client""#),
        "the deleted client is gone: {}",
        r.body
    );
}

#[tokio::test]
async fn a_token_only_manages_its_own_client() {
    let app = state_with_dcr(true, vec![], true);
    let mut b = Browser::new(&app);
    let a = register_managed(&mut b).await;
    let other = register_managed(&mut b).await;
    let path = management_path(&other);
    let auth = bearer(a["registration_access_token"].as_str().unwrap());
    let r = b
        .send(Method::DELETE, &path, &[("authorization", &auth)], "")
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        r.headers["www-authenticate"],
        r#"Bearer error="invalid_token""#
    );
    let auth = bearer(other["registration_access_token"].as_str().unwrap());
    assert_eq!(
        b.send(Method::GET, &path, &[("authorization", &auth)], "")
            .await
            .status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn static_clients_and_management_off_are_unreachable() {
    let app = state_with_dcr(true, vec![], true);
    let mut b = Browser::new(&app);
    let auth = bearer("anything-anything-anything-anything");
    assert_eq!(
        b.send(
            Method::GET,
            "/connect/dcr/web",
            &[("authorization", &auth)],
            ""
        )
        .await
        .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        b.send(Method::GET, "/connect/dcr/web", &[], "")
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    let off = state_with_dcr(true, vec![], false);
    let mut b = Browser::new(&off);
    let r = b.send(Method::POST, "/connect/dcr", &[JSON], BODY).await;
    let reg: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    assert!(reg.get("registration_client_uri").is_none());
    assert!(reg.get("registration_access_token").is_none());
    assert_eq!(
        b.send(Method::GET, "/connect/dcr/web", &[], "")
            .await
            .status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn put_is_not_allowed() {
    let app = state_with_dcr(true, vec![], true);
    let mut b = Browser::new(&app);
    let reg = register_managed(&mut b).await;
    let path = management_path(&reg);
    let auth = bearer(reg["registration_access_token"].as_str().unwrap());
    assert_eq!(
        b.send(Method::PUT, &path, &[JSON, ("authorization", &auth)], "{}")
            .await
            .status,
        StatusCode::METHOD_NOT_ALLOWED
    );
}

#[tokio::test]
async fn oversized_registration_is_413() {
    let app = state_with_dcr(true, vec![], false);
    let body = format!(r#"{{"client_name":"{}"}}"#, "x".repeat(1024 * 1024));
    let r = Browser::new(&app)
        .send(Method::POST, "/connect/dcr", &[JSON], &body)
        .await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(r.body.is_empty());
}

#[tokio::test]
async fn a_jwk_only_client_cannot_use_client_secret_basic() {
    let app = state_with_dcr(true, vec![], false);
    let mut b = Browser::new(&app);
    let r = b
        .send(
            Method::POST,
            "/connect/dcr",
            &[JSON],
            r#"{"grant_types":["client_credentials"],"token_endpoint_auth_method":"private_key_jwt","jwks":{"keys":[{"kty":"RSA","alg":"RS256","e":"AQAB","n":"sXch"}]}}"#,
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    let id = serde_json::from_str::<serde_json::Value>(&r.body).unwrap()["client_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let form = format!("grant_type=client_credentials&client_id={id}&client_secret=anything");
    let r = b.send(Method::POST, "/connect/token", &[FORM], &form).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(r.body.contains(r#""error":"invalid_client""#), "{}", r.body);
}

#[tokio::test]
async fn management_uris_include_the_path_base() {
    let app = AppState::new(ProtocolState {
        dcr: Some(rustid_http::DcrSettings {
            path: "/connect/dcr".into(),
            open: true,
            client_management: true,
            ..Default::default()
        }),
        path_base: Some("/idp".into()),
        ..protocol_state_with(Default::default())
    });
    let mut b = Browser::new(&app);
    let r = b
        .send(Method::POST, "/idp/connect/dcr", &[JSON], BODY)
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    let reg: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    let id = reg["client_id"].as_str().unwrap();
    assert_eq!(
        reg["registration_client_uri"],
        format!("http://server/idp/connect/dcr/{id}")
    );
    let auth = bearer(reg["registration_access_token"].as_str().unwrap());
    let r = b
        .send(
            Method::GET,
            &format!("/idp/connect/dcr/{id}"),
            &[("authorization", &auth)],
            "",
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
}

/// A DCR path that is the parent of other routes never hides them: a
/// request for a served route is that route's, not a management call.
#[tokio::test]
async fn a_parent_dcr_path_never_hides_the_routes_below_it() {
    let app = AppState::new(ProtocolState {
        dcr: Some(rustid_http::DcrSettings {
            path: "/connect".into(),
            open: true,
            client_management: true,
            ..Default::default()
        }),
        ..protocol_state_with(Default::default())
    });
    let mut b = Browser::new(&app);
    let r = b
        .send(
            Method::POST,
            "/connect/token",
            &[FORM],
            "grant_type=client_credentials&client_id=client&client_secret=secret",
        )
        .await;
    assert_ne!(r.status, StatusCode::UNAUTHORIZED, "{}", r.body);
    assert!(
        r.body.contains("access_token") || r.body.contains("\"error\""),
        "{}",
        r.body
    );
    assert!(
        !r.headers.contains_key("www-authenticate"),
        "not a management answer"
    );
    // Registration and management still work at /connect.
    let reg = b.send(Method::POST, "/connect", &[JSON], BODY).await;
    assert_eq!(reg.status, StatusCode::CREATED, "{}", reg.body);
}
