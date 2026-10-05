//! The session management calls of the interaction API: querying sessions and removing them, with
//! their tokens, consents and back-channel notifications.

mod browser;

use std::sync::{Arc, Mutex};

use axum::http::{Method, StatusCode};
use browser::*;
use rustid_store_memory::InMemoryServerSideSessionStore;

#[derive(Default)]
struct Recorder(Mutex<Vec<String>>);

#[async_trait::async_trait]
impl rustid_core::logout::BackChannelSender for Recorder {
    async fn send(&self, _uri: &str, logout_token: &str) {
        self.0.lock().unwrap().push(logout_token.to_owned());
    }
}

fn build(enabled: bool) -> (rustid_http::AppState, Arc<Recorder>) {
    let mut s = (*state().0).clone();
    if enabled {
        let store = Arc::new(InMemoryServerSideSessionStore::default());
        s.stores.sessions = Some(Arc::new(
            rustid_core::server_side_sessions::ServerSideSessions {
                outbox: store.outbox(),
                store,
                protector: s.interaction.protector.clone(),
            },
        ));
    }
    let recorder = Arc::new(Recorder::default());
    s.stores.back_channel = recorder.clone();
    (rustid_http::AppState::new(s), recorder)
}

async fn api(app: &rustid_http::AppState, method: Method, path: &str, body: &str) -> Reply {
    let bearer = format!("Bearer {API_KEY}");
    let mut ui = Browser::new(app);
    let mut headers = vec![("authorization", bearer.as_str())];
    if !body.is_empty() {
        headers.push(("content-type", "application/json"));
    }
    ui.send(method, path, &headers, body).await
}

const FORM: (&str, &str) = ("content-type", "application/x-www-form-urlencoded");

/// Signs `subject` in in a new browser and gets `logout.back` a refresh token.
async fn signed_in(app: &rustid_http::AppState, subject: &str) -> (Browser, String) {
    let mut browser = Browser::new(app);
    sign_in(&mut browser, subject).await;
    let r = browser
        .get(
            &authorize_uri("")
                .replace("client_id=web", "client_id=logout.back")
                .replace(
                    "scope=openid%20api1",
                    "scope=openid%20api1%20offline_access",
                ),
        )
        .await;
    let code = url::Url::parse(&r.location())
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "code")
        .unwrap()
        .1
        .into_owned();
    let form = format!(
        "grant_type=authorization_code&client_id=logout.back&code={code}&redirect_uri=https%3A%2F%2Fclient.test%2Fcallback&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    );
    let r = browser
        .send(Method::POST, "/connect/token", &[FORM], &form)
        .await;
    let tokens: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    let refresh = tokens["refresh_token"].as_str().unwrap().to_owned();
    (browser, refresh)
}

async fn refreshes(browser: &mut Browser, refresh_token: &str) -> bool {
    let form =
        format!("grant_type=refresh_token&client_id=logout.back&refresh_token={refresh_token}");
    browser
        .send(Method::POST, "/connect/token", &[FORM], &form)
        .await
        .status
        == StatusCode::OK
}

#[tokio::test]
async fn sessions_are_queried_with_substring_filters_and_pages() {
    let (app, _) = build(true);
    for subject in ["1", "2", "12"] {
        signed_in(&app, subject).await;
    }
    let r = api(&app, Method::GET, "/interaction/sessions", "").await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let page: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(page["totalCount"], 3);
    assert_eq!(page["currentPage"], 1);
    let first = &page["results"][0];
    for field in [
        "subjectId",
        "sessionId",
        "created",
        "renewed",
        "expires",
        "issuer",
    ] {
        assert!(first[field].is_string(), "{field}: {first}");
    }
    assert_eq!(first["clientIds"], serde_json::json!(["logout.back"]));

    let r = api(
        &app,
        Method::GET,
        "/interaction/sessions?subjectId=1&count=1",
        "",
    )
    .await;
    let page: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(page["totalCount"], 2, "1 and 12");
    assert_eq!(page["totalPages"], 2);
    assert_eq!(page["hasNextResults"], true);
    let token = page["resultsToken"].as_str().unwrap();
    let r = api(
        &app,
        Method::GET,
        &format!("/interaction/sessions?subjectId=1&count=1&resultsToken={token}"),
        "",
    )
    .await;
    let next: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(next["currentPage"], 2);
    assert_ne!(
        next["results"][0]["subjectId"],
        page["results"][0]["subjectId"]
    );
}

#[tokio::test]
async fn removing_sessions_revokes_tokens_notifies_and_signs_out() {
    let (app, sent) = build(true);
    let (mut alice, alice_refresh) = signed_in(&app, "1").await;
    let (mut bob, bob_refresh) = signed_in(&app, "2").await;
    let r = api(
        &app,
        Method::POST,
        "/interaction/sessions/remove",
        r#"{"subjectId":"1"}"#,
    )
    .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.body);
    assert!(!refreshes(&mut alice, &alice_refresh).await);
    assert!(refreshes(&mut bob, &bob_refresh).await);
    let tokens = sent.0.lock().unwrap().clone();
    assert_eq!(tokens.len(), 1);
    let token = rustid_core::jwt::Jws::decode(&tokens[0]).unwrap();
    assert_eq!(token.payload["logout_reason"], "terminated");
    assert_eq!(token.payload["sub"], "1");
    let silent = alice.get(&authorize_uri("&prompt=none")).await;
    assert!(
        silent.location().contains("error=login_required"),
        "signed out"
    );
}

#[tokio::test]
async fn removal_options_and_client_filters() {
    let (app, sent) = build(true);
    let (mut alice, refresh_token) = signed_in(&app, "1").await;
    // A client filter that excludes logout.back: nothing of its is touched.
    let r = api(
        &app,
        Method::POST,
        "/interaction/sessions/remove",
        r#"{"subjectId":"1","clientIds":["web"],"removeServerSideSession":false}"#,
    )
    .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert!(sent.0.lock().unwrap().is_empty());
    assert!(refreshes(&mut alice, &refresh_token).await);

    // Tokens and notifications off: only the session goes.
    let r = api(
        &app,
        Method::POST,
        "/interaction/sessions/remove",
        r#"{"subjectId":"1","revokeTokens":false,"revokeConsents":false,"sendBackchannelLogoutNotification":false}"#,
    )
    .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert!(sent.0.lock().unwrap().is_empty());
    let silent = alice.get(&authorize_uri("&prompt=none")).await;
    assert!(silent.location().contains("error=login_required"));
}

#[tokio::test]
async fn bad_requests_and_disabled_sessions() {
    let (app, _) = build(true);
    let r = api(&app, Method::POST, "/interaction/sessions/remove", "{}").await;
    assert_eq!(
        r.status,
        StatusCode::BAD_REQUEST,
        "a subject or session is needed"
    );
    let mut anonymous = Browser::new(&app);
    let r = anonymous.get("/interaction/sessions").await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);

    let (app, _) = build(false);
    let r = api(&app, Method::GET, "/interaction/sessions", "").await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert!(
        r.body.contains("server_side_sessions_disabled"),
        "{}",
        r.body
    );
}
