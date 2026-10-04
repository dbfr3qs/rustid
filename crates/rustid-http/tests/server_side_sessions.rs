//! Server-side sessions over HTTP: the `idsrv` cookie carries a key, the
//! session lives in the store, and the store decides who is signed in.

mod browser;

use std::sync::Arc;

use axum::http::{Method, StatusCode};
use browser::*;
use rustid_core::server_side_sessions::{SessionFilter, open_ticket};
use rustid_core::stores::ServerSideSessionStore;
use rustid_store_memory::InMemoryServerSideSessionStore;

fn with_sessions() -> (rustid_http::AppState, Arc<InMemoryServerSideSessionStore>) {
    let store = Arc::new(InMemoryServerSideSessionStore::default());
    let mut s = (*state().0).clone();
    s.stores.sessions = Some(Arc::new(
        rustid_core::server_side_sessions::ServerSideSessions {
            store: store.clone(),
            outbox: store.outbox(),
            protector: s.interaction.protector.clone(),
        },
    ));
    (rustid_http::AppState::new(s), store)
}

async fn sessions_of(
    store: &InMemoryServerSideSessionStore,
    subject: &str,
) -> Vec<rustid_core::server_side_sessions::ServerSideSession> {
    store
        .get_sessions(&SessionFilter {
            subject_id: Some(subject.into()),
            ..Default::default()
        })
        .await
        .unwrap()
}

/// Whether the browser's session is good for a silent authorize request.
async fn signed_in(browser: &mut Browser) -> bool {
    let r = browser.get(&authorize_uri("&prompt=none")).await;
    r.location().contains("code=")
}

#[tokio::test]
async fn signing_in_stores_the_session_and_the_cookie_holds_a_key() {
    let (app, store) = with_sessions();
    let mut browser = Browser::new(&app);
    sign_in(&mut browser, "1").await;
    let records = sessions_of(&store, "1").await;
    assert_eq!(records.len(), 1);
    let cookie = browser
        .cookies
        .iter()
        .find(|(k, _)| k == "idsrv")
        .unwrap()
        .1
        .clone();
    let protector = &app.0.interaction.protector;
    assert_eq!(
        rustid_core::server_side_sessions::open_key(protector, &cookie).as_deref(),
        Some(records[0].key.as_str())
    );
    assert!(
        rustid_core::session::UserSession::open(protector, &cookie, chrono::Utc::now()).is_none(),
        "the session itself isn't in the cookie"
    );
    assert!(signed_in(&mut browser).await);

    // The client list goes to the record.
    let ticket = open_ticket(protector, &sessions_of(&store, "1").await[0]).unwrap();
    assert_eq!(ticket.client_ids, ["web"]);
}

#[tokio::test]
async fn removing_or_corrupting_the_record_signs_the_browser_out() {
    let (app, store) = with_sessions();
    let mut browser = Browser::new(&app);
    sign_in(&mut browser, "1").await;
    let filter = SessionFilter {
        subject_id: Some("1".into()),
        ..Default::default()
    };
    store.delete_sessions(&filter).await.unwrap();
    assert!(!signed_in(&mut browser).await);

    let mut browser = Browser::new(&app);
    sign_in(&mut browser, "1").await;
    let mut record = sessions_of(&store, "1").await.remove(0);
    record.ticket = "invalid".into();
    store.update_session(record).await.unwrap();
    assert!(!signed_in(&mut browser).await);
    assert!(sessions_of(&store, "1").await.is_empty(), "deleted");
}

#[tokio::test]
async fn signing_in_again_reuses_the_key_and_logout_removes_the_record() {
    let (app, store) = with_sessions();
    let mut browser = Browser::new(&app);
    sign_in(&mut browser, "1").await;
    let key = sessions_of(&store, "1").await[0].key.clone();
    sign_in(&mut browser, "1").await;
    assert_eq!(sessions_of(&store, "1").await[0].key, key);
    let old_cookie = browser
        .cookies
        .iter()
        .find(|(k, _)| k == "idsrv")
        .unwrap()
        .1
        .clone();
    sign_in(&mut browser, "2").await;
    assert!(sessions_of(&store, "1").await.is_empty());
    assert_ne!(
        sessions_of(&store, "2").await[0].key,
        key,
        "another user gets a new key"
    );
    // A cookie holding the old key (say, planted by an attacker who signed
    // in first) opens nothing now.
    let mut planted = Browser::new(&app);
    planted.cookies.push(("idsrv".into(), old_cookie));
    assert!(!signed_in(&mut planted).await);

    // Logout through the interaction API deletes the record.
    let bearer = format!("Bearer {API_KEY}");
    let cookie: Vec<String> = browser
        .cookies
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    let mut ui = Browser::new(&app);
    let r = ui
        .send(
            Method::POST,
            "/interaction/logout",
            &[
                ("authorization", &bearer),
                ("content-type", "application/json"),
                ("cookie", &cookie.join("; ")),
            ],
            r#"{"returnUrl":"/"}"#,
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let body: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    let path = body["continueUrl"]
        .as_str()
        .unwrap()
        .strip_prefix("http://server")
        .unwrap()
        .to_owned();
    assert_eq!(browser.get(&path).await.status, StatusCode::FOUND);
    assert!(sessions_of(&store, "2").await.is_empty());
}

const FORM: (&str, &str) = ("content-type", "application/x-www-form-urlencoded");

/// Authorizes `client` with offline access and redeems the code.
async fn tokens(browser: &mut Browser, client: &str) -> serde_json::Value {
    let r = browser
        .get(
            &authorize_uri("")
                .replace("client_id=web", &format!("client_id={client}"))
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
        "grant_type=authorization_code&client_id={client}&code={code}&redirect_uri=https%3A%2F%2Fclient.test%2Fcallback&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    );
    let r = browser
        .send(Method::POST, "/connect/token", &[FORM], &form)
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    serde_json::from_str(&r.body).unwrap()
}

async fn refresh(browser: &mut Browser, client: &str, tokens: &serde_json::Value) -> Reply {
    let form = format!(
        "grant_type=refresh_token&client_id={client}&refresh_token={}",
        tokens["refresh_token"].as_str().unwrap()
    );
    browser
        .send(Method::POST, "/connect/token", &[FORM], &form)
        .await
}

async fn userinfo(browser: &mut Browser, tokens: &serde_json::Value) -> StatusCode {
    let bearer = format!("Bearer {}", tokens["access_token"].as_str().unwrap());
    browser
        .send(
            Method::GET,
            "/connect/userinfo",
            &[("authorization", &bearer)],
            "",
        )
        .await
        .status
}

#[tokio::test]
async fn coordinated_tokens_live_and_die_with_the_session() {
    let (app, store) = with_sessions();
    let mut browser = Browser::new(&app);
    sign_in(&mut browser, "1").await;
    let back = tokens(&mut browser, "logout.back").await;
    let web = tokens(&mut browser, "web").await;

    // Using a coordinated client's refresh token extends the session.
    let mut record = sessions_of(&store, "1").await.remove(0);
    let span = record.expires.unwrap() - record.renewed;
    record.renewed -= chrono::Duration::hours(1);
    record.expires = Some(record.renewed + span);
    store.update_session(record.clone()).await.unwrap();
    assert_eq!(
        refresh(&mut browser, "logout.back", &back).await.status,
        StatusCode::OK
    );
    let extended = sessions_of(&store, "1").await.remove(0);
    assert!(extended.renewed > record.renewed);
    assert_eq!(extended.expires.unwrap() - extended.renewed, span);
    assert_eq!(userinfo(&mut browser, &back).await, StatusCode::OK);

    // Without the session, the coordinated client's tokens stop working;
    // the others' don't.
    store
        .delete_sessions(&SessionFilter {
            subject_id: Some("1".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    let r = refresh(&mut browser, "logout.back", &back).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(r.body.contains("invalid_grant"), "{}", r.body);
    assert_eq!(
        userinfo(&mut browser, &back).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        refresh(&mut browser, "web", &web).await.status,
        StatusCode::OK
    );
    assert_eq!(userinfo(&mut browser, &web).await, StatusCode::OK);
}

/// Records every back-channel logout token sent.
#[derive(Default)]
struct Recorder(std::sync::Mutex<Vec<String>>);

#[async_trait::async_trait]
impl rustid_core::logout::BackChannelSender for Recorder {
    async fn send(&self, _uri: &str, logout_token: &str) {
        self.0.lock().unwrap().push(logout_token.to_owned());
    }
}

#[tokio::test]
async fn an_expired_session_met_on_a_request_is_processed() {
    let (app, store) = with_sessions();
    let recorder = Arc::new(Recorder::default());
    let mut s = (*app.0).clone();
    s.stores.back_channel = recorder.clone();
    let app = rustid_http::AppState::new(s);
    let mut browser = Browser::new(&app);
    sign_in(&mut browser, "1").await;
    let back = tokens(&mut browser, "logout.back").await;
    let mut record = sessions_of(&store, "1").await.remove(0);
    record.expires = Some(chrono::Utc::now() - chrono::Duration::minutes(1));
    store.update_session(record).await.unwrap();

    assert!(!signed_in(&mut browser).await);
    let sent = recorder.0.lock().unwrap().clone();
    assert_eq!(sent.len(), 1);
    let token = rustid_core::jwt::Jws::decode(&sent[0]).unwrap();
    assert_eq!(token.payload["logout_reason"], "session_expiration");
    assert!(sessions_of(&store, "1").await.is_empty());
    let r = refresh(&mut browser, "logout.back", &back).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "revoked");
}
