//! Pairwise subjects over HTTP: a pairwise client's id token and userinfo
//! answers carry its pairwise subject, its access token the user's own.

use axum::http::{Method, StatusCode};
use rustid_core::clients::{Clients, SubjectType};
use rustid_core::resources::Resources;
use rustid_http::AppState;

mod browser;

use browser::*;

const SALT: &str = "server-salt-0123456789";

fn pairwise_state() -> (
    AppState,
    rustid_core::options::ProtocolOptions,
    rustid_core::clients::Client,
) {
    let mut options = rustid_core::options::ProtocolOptions::default();
    options.pairwise.salt = Some(SALT.into());
    let mut state = protocol_state_with(options);
    let mut clients = Clients::load(&fixture("clients.json")).unwrap();
    for client in &mut clients.clients {
        if client.client_id == "web" {
            client.subject_type = SubjectType::Pairwise;
        }
    }
    let web = clients
        .clients
        .iter()
        .find(|c| c.client_id == "web")
        .unwrap()
        .clone();
    state.stores = rustid_store_memory::stores(
        clients,
        Resources::load(&fixture("resources.json")).unwrap(),
    );
    let options = state.options.clone();
    (AppState::new(state), options, web)
}

async fn tokens(app: &AppState) -> serde_json::Value {
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
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    serde_json::from_str(&r.body).unwrap()
}

#[tokio::test]
async fn the_id_token_is_pairwise_and_the_access_token_local() {
    let (app, options, web) = pairwise_state();
    let expected = rustid_core::pairwise::subject_for(&options, &web, "1");
    assert_ne!(expected, "1");
    let body = tokens(&app).await;
    let id_token = rustid_core::jwt::Jws::decode(body["id_token"].as_str().unwrap()).unwrap();
    assert_eq!(id_token.claim_str("sub"), Some(expected.as_str()));
    let access = rustid_core::jwt::Jws::decode(body["access_token"].as_str().unwrap()).unwrap();
    assert_eq!(access.claim_str("sub"), Some("1"));
}

#[tokio::test]
async fn userinfo_answers_the_pairwise_subject_and_still_finds_the_user() {
    let (app, options, web) = pairwise_state();
    let body = tokens(&app).await;
    let bearer = format!("Bearer {}", body["access_token"].as_str().unwrap());
    let r = Browser::new(&app)
        .send(
            Method::GET,
            "/connect/userinfo",
            &[("authorization", &bearer)],
            "",
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let info: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(
        info["sub"],
        rustid_core::pairwise::subject_for(&options, &web, "1")
    );
}
