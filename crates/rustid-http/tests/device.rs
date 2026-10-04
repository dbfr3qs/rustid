//! The device flow through HTTP: device authorization, the interaction
//! API's device calls with the browser's session, and polling.

mod browser;

use axum::http::{Method, StatusCode};
use browser::*;
use serde_json::{Value, json};

const FORM: (&str, &str) = ("content-type", "application/x-www-form-urlencoded");

async fn post_form(browser: &mut Browser, path: &str, body: &str) -> (StatusCode, Value) {
    let r = browser.send(Method::POST, path, &[FORM], body).await;
    (
        r.status,
        serde_json::from_str(&r.body).unwrap_or(Value::Null),
    )
}

async fn api(
    browser: &mut Browser,
    method: Method,
    path: &str,
    body: Value,
) -> (StatusCode, Value) {
    let bearer = format!("Bearer {API_KEY}");
    let r = browser
        .send(
            method,
            path,
            &[
                ("authorization", &bearer),
                ("content-type", "application/json"),
            ],
            &body.to_string(),
        )
        .await;
    (
        r.status,
        serde_json::from_str(&r.body).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn a_signed_in_user_approves_a_device() {
    // No polling interval, so the test can poll straight away.
    let mut options = rustid_core::options::ProtocolOptions::default();
    options.device_flow.interval = 0;
    let app = state_with(options);
    let mut device = Browser::new(&app);
    let (status, auth) = post_form(
        &mut device,
        "/connect/deviceauthorization",
        "client_id=device&client_secret=secret&scope=openid%20api1",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{auth}");
    let user_code = auth["user_code"].as_str().unwrap().to_owned();
    let poll = format!(
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&client_id=device&client_secret=secret&device_code={}",
        auth["device_code"].as_str().unwrap()
    );
    let (_, pending) = post_form(&mut device, "/connect/token", &poll).await;
    assert_eq!(pending["error"], "authorization_pending");

    let mut user = Browser::new(&app);
    let (status, context) = api(
        &mut user,
        Method::GET,
        &format!("/interaction/device?userCode={user_code}"),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(context["clientName"], "Device client");
    assert_eq!(context["scopes"], json!(["openid", "api1"]));
    let (status, _) = api(
        &mut user,
        Method::GET,
        "/interaction/device?userCode=1",
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Without a session: refused.
    let (status, body) = api(
        &mut user,
        Method::POST,
        "/interaction/device",
        json!({ "userCode": user_code, "scopes": ["openid"] }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["errorDescription"],
        "No user present in device flow request"
    );

    sign_in(&mut user, "1").await;
    let (status, _) = api(
        &mut user,
        Method::POST,
        "/interaction/device",
        json!({ "userCode": user_code, "scopes": ["openid"] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, tokens) = post_form(&mut device, "/connect/token", &poll).await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    assert_eq!(tokens["scope"], "openid");
    assert!(tokens["id_token"].is_string());
}
