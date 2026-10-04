//! Persistent ("remember me") and sliding session cookies, as the
//! cookie handler renews them, in both cookie modes.

mod browser;

use std::sync::Arc;

use axum::http::{Method, StatusCode};
use browser::*;
use chrono::{Duration, Utc};
use rustid_core::server_side_sessions::{SessionFilter, open_ticket, store_session};
use rustid_core::stores::ServerSideSessionStore;
use rustid_store_memory::InMemoryServerSideSessionStore;

const LIFETIME: i64 = 4 * 3600;

fn build(
    sliding: bool,
    server_side: bool,
) -> (
    rustid_http::AppState,
    Option<Arc<InMemoryServerSideSessionStore>>,
) {
    let mut options = rustid_core::options::ProtocolOptions::default();
    options.authentication.cookie_sliding_expiration = sliding;
    options.authentication.cookie_lifetime = rustid_core::options::TimeSpan(LIFETIME);
    let mut s = (*state_with(options).0).clone();
    let store = server_side.then(|| Arc::new(InMemoryServerSideSessionStore::default()));
    let protector = s.interaction.protector.clone();
    s.stores.sessions = store.clone().map(|store| {
        Arc::new(rustid_core::server_side_sessions::ServerSideSessions {
            outbox: store.outbox(),
            store,
            protector: protector.clone(),
        })
    });
    (rustid_http::AppState::new(s), store)
}

/// Signs `subject` in through the login API with extra body fields.
async fn sign_in_with(browser: &mut Browser, extra: serde_json::Value) {
    let login = browser.get(&authorize_uri("&prompt=login")).await;
    let return_url = return_url(&login.location());
    let mut body = serde_json::json!({ "returnUrl": return_url, "subjectId": "1" });
    for (k, v) in extra.as_object().unwrap() {
        body[k] = v.clone();
    }
    let bearer = format!("Bearer {API_KEY}");
    let mut ui = Browser::new(&browser.app);
    let r = ui
        .send(
            Method::POST,
            "/interaction/login",
            &[
                ("authorization", &bearer),
                ("content-type", "application/json"),
            ],
            &body.to_string(),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let continue_url: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    let path = continue_url["continueUrl"]
        .as_str()
        .unwrap()
        .strip_prefix("http://server")
        .unwrap()
        .to_owned();
    let signed_in = browser.get(&path).await;
    assert_eq!(signed_in.status, StatusCode::FOUND, "{}", signed_in.body);
}

fn session_cookie(reply: &Reply) -> Option<String> {
    reply
        .set_cookies()
        .into_iter()
        .find(|c| c.starts_with("idsrv="))
}

/// Rewrites the browser's session as if it had been issued `age` ago with
/// `left` to go, and optionally flagged for renewal.
async fn age_session(
    app: &rustid_http::AppState,
    browser: &mut Browser,
    store: Option<&InMemoryServerSideSessionStore>,
    age: Duration,
    left: Duration,
    force: bool,
) {
    let protector = &app.0.interaction.protector;
    let now = Utc::now();
    match store {
        Some(store) => {
            let mut record = store
                .get_sessions(&SessionFilter {
                    subject_id: Some("1".into()),
                    ..Default::default()
                })
                .await
                .unwrap()
                .remove(0);
            let mut session = open_ticket(protector, &record).unwrap();
            session.force_renewal = force;
            store_session(
                store,
                app.0.stores.grants.as_ref(),
                protector,
                &app.0.options,
                &mut session,
                "https://idsrv.test",
            )
            .await
            .unwrap();
            record = store.get_session(&record.key).await.unwrap().unwrap();
            record.renewed = now - age;
            record.expires = Some(now + left);
            store.update_session(record).await.unwrap();
        }
        None => {
            let cookie = browser
                .cookies
                .iter()
                .find(|(k, _)| k == "idsrv")
                .unwrap()
                .1
                .clone();
            let mut session =
                rustid_core::session::UserSession::open(protector, &cookie, now).unwrap();
            session.issued = now - age;
            session.expires = now + left;
            session.force_renewal = force;
            browser.drop_cookie("idsrv");
            browser
                .cookies
                .push(("idsrv".into(), session.seal(protector)));
        }
    }
}

#[tokio::test]
async fn only_remembered_sessions_get_a_persistent_cookie() {
    for server_side in [false, true] {
        let (app, _) = build(false, server_side);
        let r = continuation_cookie(&app, serde_json::json!({ "remember": true })).await;
        assert!(r.contains("; expires="), "{r}");
        let r = continuation_cookie(&app, serde_json::json!({})).await;
        assert!(!r.contains("expires="), "{r}");
    }
}

/// Signs a fresh browser in and returns the `idsrv` cookie the
/// continuation set.
async fn continuation_cookie(app: &rustid_http::AppState, extra: serde_json::Value) -> String {
    let mut browser = Browser::new(app);
    let login = browser.get(&authorize_uri("&prompt=login")).await;
    let return_url = return_url(&login.location());
    let mut body = serde_json::json!({ "returnUrl": return_url, "subjectId": "1" });
    for (k, v) in extra.as_object().unwrap() {
        body[k] = v.clone();
    }
    let bearer = format!("Bearer {API_KEY}");
    let mut ui = Browser::new(app);
    let r = ui
        .send(
            Method::POST,
            "/interaction/login",
            &[
                ("authorization", &bearer),
                ("content-type", "application/json"),
            ],
            &body.to_string(),
        )
        .await;
    let continue_url: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    let path = continue_url["continueUrl"]
        .as_str()
        .unwrap()
        .strip_prefix("http://server")
        .unwrap()
        .to_owned();
    session_cookie(&browser.get(&path).await).unwrap()
}

#[tokio::test]
async fn sliding_renews_past_half_life_or_when_flagged() {
    for server_side in [false, true] {
        let (app, store) = build(true, server_side);
        let mut browser = Browser::new(&app);
        sign_in_with(&mut browser, serde_json::json!({ "remember": true })).await;

        // Less than half gone: nothing.
        age_session(
            &app,
            &mut browser,
            store.as_deref(),
            Duration::hours(1),
            Duration::hours(3),
            false,
        )
        .await;
        let r = browser.get("/.well-known/openid-configuration").await;
        assert_eq!(session_cookie(&r), None, "server_side={server_side}");

        // More gone than left: renewed for the whole span again.
        age_session(
            &app,
            &mut browser,
            store.as_deref(),
            Duration::hours(3),
            Duration::hours(1),
            false,
        )
        .await;
        let r = browser.get("/.well-known/openid-configuration").await;
        let cookie = session_cookie(&r).expect("renewed");
        assert!(cookie.contains("; expires="), "{cookie}");
        assert_eq!(r.headers["cache-control"], "no-cache,no-store");
        assert_eq!(r.headers["pragma"], "no-cache");
        if let Some(store) = &store {
            let record = store
                .get_sessions(&SessionFilter {
                    subject_id: Some("1".into()),
                    ..Default::default()
                })
                .await
                .unwrap()
                .remove(0);
            let span = record.expires.unwrap() - record.renewed;
            assert_eq!(span, Duration::hours(4));
            assert!(Utc::now() - record.renewed < Duration::seconds(5));
        }

        // Flagged by token use: renewed although young, and only once.
        age_session(
            &app,
            &mut browser,
            store.as_deref(),
            Duration::hours(1),
            Duration::hours(3),
            true,
        )
        .await;
        let r = browser.get("/.well-known/openid-configuration").await;
        assert!(
            session_cookie(&r).is_some(),
            "flag: server_side={server_side}"
        );
        let r = browser.get("/.well-known/openid-configuration").await;
        assert_eq!(session_cookie(&r), None, "the flag is cleared");
    }
}

#[tokio::test]
async fn no_renewal_without_sliding_or_when_refresh_is_not_allowed() {
    for server_side in [false, true] {
        let (app, store) = build(false, server_side);
        let mut browser = Browser::new(&app);
        sign_in_with(&mut browser, serde_json::json!({ "remember": true })).await;
        age_session(
            &app,
            &mut browser,
            store.as_deref(),
            Duration::hours(3),
            Duration::hours(1),
            true,
        )
        .await;
        let r = browser.get("/.well-known/openid-configuration").await;
        assert_eq!(session_cookie(&r), None, "not sliding");

        let (app, store) = build(true, server_side);
        let mut browser = Browser::new(&app);
        sign_in_with(
            &mut browser,
            serde_json::json!({ "remember": true, "allowRefresh": false }),
        )
        .await;
        age_session(
            &app,
            &mut browser,
            store.as_deref(),
            Duration::hours(3),
            Duration::hours(1),
            false,
        )
        .await;
        let r = browser.get("/.well-known/openid-configuration").await;
        assert_eq!(session_cookie(&r), None, "allowRefresh false");
    }
}
