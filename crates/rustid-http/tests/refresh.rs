//! Refresh tokens through the token endpoint: where the field goes in the
//! JSON, and a refresh.

mod browser;

use axum::http::{Method, StatusCode};
use browser::*;

const FORM: (&str, &str) = ("content-type", "application/x-www-form-urlencoded");

fn keys(body: &str) -> Vec<String> {
    let value: serde_json::Value = serde_json::from_str(body).unwrap();
    value.as_object().unwrap().keys().cloned().collect()
}

#[tokio::test]
async fn refresh_tokens_come_after_the_token_type_and_redeem() {
    let app = state();
    let mut browser = Browser::new(&app);
    sign_in(&mut browser, "1").await;
    let r = browser
        .get(&authorize_uri("").replace(
            "scope=openid%20api1",
            "scope=openid%20api1%20offline_access",
        ))
        .await;
    let location = url::Url::parse(&r.location()).unwrap();
    let code = location
        .query_pairs()
        .find(|(k, _)| k == "code")
        .unwrap()
        .1
        .into_owned();
    let form = format!(
        "grant_type=authorization_code&client_id=web&code={code}&redirect_uri=https%3A%2F%2Fclient.test%2Fcallback&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    );
    let r = browser
        .send(Method::POST, "/connect/token", &[FORM], &form)
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(
        keys(&r.body),
        [
            "id_token",
            "access_token",
            "expires_in",
            "token_type",
            "refresh_token",
            "scope"
        ]
    );
    let body: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    let refresh_token = body["refresh_token"].as_str().unwrap();

    let form = format!("grant_type=refresh_token&client_id=web&refresh_token={refresh_token}");
    let r = browser
        .send(Method::POST, "/connect/token", &[FORM], &form)
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let refreshed: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(
        refreshed["refresh_token"], body["refresh_token"],
        "reused, the default"
    );
    assert_eq!(refreshed["scope"], "openid api1 offline_access");

    let form = "grant_type=refresh_token&client_id=web&refresh_token=unknown-1";
    let r = browser
        .send(Method::POST, "/connect/token", &[FORM], form)
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&r.body).unwrap(),
        serde_json::json!({ "error": "invalid_grant" })
    );
}
