//! Signed userinfo over HTTP (OIDC Core §5.3.2).

use axum::http::{Method, StatusCode};
use rustid_core::clients::Clients;
use rustid_core::resources::Resources;
use rustid_http::AppState;

mod browser;

use browser::*;

fn state(alg: Option<&str>) -> AppState {
    let mut state = protocol_state_with(Default::default());
    let mut clients = Clients::load(&fixture("clients.json")).unwrap();
    for client in clients.clients.iter_mut().filter(|c| c.client_id == "web") {
        client.userinfo_signed_response_alg = alg.map(str::to_owned);
    }
    state.stores = rustid_store_memory::stores(
        clients,
        Resources::load(&fixture("resources.json")).unwrap(),
    );
    AppState::new(state)
}

async fn access_token(app: &AppState) -> String {
    let mut browser = Browser::new(app);
    let callback = sign_in(&mut browser, "1").await;
    let r = browser.get(&callback).await;
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
        .send(
            Method::POST,
            "/connect/token",
            &[("content-type", "application/x-www-form-urlencoded")],
            &form,
        )
        .await;
    let body: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    body["access_token"].as_str().unwrap().to_owned()
}

async fn userinfo(app: &AppState, bearer: &str) -> Reply {
    Browser::new(app)
        .send(
            Method::GET,
            "/connect/userinfo",
            &[("authorization", &format!("Bearer {bearer}"))],
            "",
        )
        .await
}

#[tokio::test]
async fn a_client_asking_for_signed_userinfo_gets_application_jwt() {
    let app = state(Some("RS256"));
    let token = access_token(&app).await;
    let r = userinfo(&app, &token).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.headers["content-type"], "application/jwt");
    assert!(
        r.headers["cache-control"]
            .to_str()
            .unwrap()
            .contains("no-store")
    );
    let jws = rustid_core::jwt::Jws::decode(&r.body).unwrap();
    assert_eq!(jws.payload["aud"], "web");
    assert_eq!(jws.payload["sub"], "1");
}

#[tokio::test]
async fn others_get_json_and_errors_stay_unsigned() {
    let app = state(None);
    let token = access_token(&app).await;
    let r = userinfo(&app, &token).await;
    assert!(
        r.headers["content-type"]
            .to_str()
            .unwrap()
            .starts_with("application/json")
    );

    let app = state(Some("RS256"));
    let r = userinfo(&app, "not-a-token").await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(r.headers.contains_key("www-authenticate"));
}
