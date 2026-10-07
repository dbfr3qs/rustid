//! Signing out:
//! coordinated clients' tokens are removed and back-channel logout tokens
//! go to every client with a URI.

mod support;

use std::sync::{Arc, Mutex};

use chrono::Utc;
use rustid_core::grants::{GrantFilter, PersistedGrant};
use rustid_core::jwt::Jws;
use rustid_core::logout::{BackChannelSender, process_logout};
use rustid_core::session::{SignIn, UserSession};
use serde_json::json;
use support::{Fixture, ISSUER};

/// Records every logout token sent, and where.
#[derive(Default)]
struct Recorder(Mutex<Vec<(String, String)>>);

#[async_trait::async_trait]
impl BackChannelSender for Recorder {
    async fn send(&self, uri: &str, logout_token: &str) {
        self.0
            .lock()
            .unwrap()
            .push((uri.to_owned(), logout_token.to_owned()));
    }
}

fn with_recorder(f: &mut Fixture) -> Arc<Recorder> {
    let recorder = Arc::new(Recorder::default());
    f.stores.back_channel = recorder.clone();
    recorder
}

fn session(clients: &[&str]) -> UserSession {
    let mut s = UserSession::sign_in(
        SignIn {
            subject_id: "1".into(),
            ..Default::default()
        },
        None,
        Utc::now(),
        3600,
    );
    for c in clients {
        s.add_client(c);
    }
    s
}

fn refresh_token(key: &str, client: &str, session: &UserSession) -> PersistedGrant {
    PersistedGrant {
        key: key.into(),
        grant_type: "refresh_token".into(),
        client_id: client.into(),
        subject_id: Some(session.subject_id.clone()),
        session_id: Some(session.session_id.clone()),
        description: None,
        creation_time: Utc::now(),
        expiration: None,
        consumed_time: None,
        data: "{}".into(),
    }
}

#[tokio::test]
async fn back_channel_clients_get_a_signed_logout_token() {
    let mut f = Fixture::new();
    let recorder = with_recorder(&mut f);
    let s = session(&["web", "logout.back", "logout.front"]);
    process_logout(&f.validation_ctx(Utc::now()), &s)
        .await
        .unwrap();
    let sent = recorder.0.lock().unwrap().clone();
    assert_eq!(sent.len(), 1, "only logout.back has a back-channel URI");
    assert_eq!(sent[0].0, "http://127.0.0.1:5192/backchannel");
    let jws = Jws::decode(&sent[0].1).unwrap();
    assert_eq!(jws.header_str("typ"), Some("logout+jwt"));
    let key = f.material.signing.first().unwrap();
    assert!(jws.verify(&key.public_jwk()));
    let names: Vec<&str> = jws.payload.keys().map(String::as_str).collect();
    assert_eq!(
        names,
        [
            "iss",
            "nbf",
            "iat",
            "exp",
            "aud",
            "jti",
            "events",
            "sub",
            "sid",
            "logout_reason"
        ]
    );
    let p = &jws.payload;
    assert_eq!(p["iss"], ISSUER);
    assert_eq!(p["aud"], "logout.back");
    assert_eq!(p["sub"], "1");
    assert_eq!(p["sid"], s.session_id.as_str());
    assert_eq!(p["logout_reason"], "user_logout");
    assert_eq!(
        p["events"],
        json!({ "http://schemas.openid.net/event/backchannel-logout": {} })
    );
    assert_eq!(p["exp"].as_i64().unwrap() - p["iat"].as_i64().unwrap(), 300);
    assert_eq!(p["jti"].as_str().unwrap().len(), 32);
}

#[tokio::test]
async fn coordinated_clients_lose_the_sessions_tokens() {
    let mut f = Fixture::new();
    with_recorder(&mut f);
    let s = session(&["web", "logout.back"]);
    let other = session(&["logout.back"]);
    let grants = f.stores.grants.clone();
    grants
        .store(refresh_token("back", "logout.back", &s))
        .await
        .unwrap();
    grants.store(refresh_token("web", "web", &s)).await.unwrap();
    grants
        .store(refresh_token("other", "logout.back", &other))
        .await
        .unwrap();
    process_logout(&f.validation_ctx(Utc::now()), &s)
        .await
        .unwrap();
    assert!(grants.get("back").await.unwrap().is_none());
    assert!(
        grants.get("web").await.unwrap().is_some(),
        "not coordinated"
    );
    assert!(
        grants.get("other").await.unwrap().is_some(),
        "another session's tokens stay"
    );

    // The global option coordinates every client that doesn't opt out.
    f.options
        .authentication
        .coordinate_client_lifetimes_with_user_session = true;
    process_logout(&f.validation_ctx(Utc::now()), &s)
        .await
        .unwrap();
    assert!(grants.get("web").await.unwrap().is_none());
    let left = grants
        .get_all(&GrantFilter {
            subject_id: Some("1".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(left.len(), 1);
}

#[tokio::test]
async fn a_session_without_clients_notifies_nobody() {
    let mut f = Fixture::new();
    let recorder = with_recorder(&mut f);
    process_logout(&f.validation_ctx(Utc::now()), &session(&[]))
        .await
        .unwrap();
    assert!(recorder.0.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_pairwise_client_gets_its_own_subject_in_the_logout_token() {
    let mut f = Fixture::new();
    let recorder = with_recorder(&mut f);
    f.options.pairwise.salt = Some("server-salt-0123456789".into());
    f.edit_clients(|clients| {
        for c in clients.iter_mut().filter(|c| c.client_id == "logout.back") {
            c.subject_type = rustid_core::clients::SubjectType::Pairwise;
        }
    });
    let client = f
        .clients
        .clients
        .iter()
        .find(|c| c.client_id == "logout.back")
        .unwrap()
        .clone();
    let s = session(&["logout.back"]);
    process_logout(&f.validation_ctx(Utc::now()), &s)
        .await
        .unwrap();
    let sent = recorder.0.lock().unwrap().clone();
    let jws = Jws::decode(&sent[0].1).unwrap();
    let expected = rustid_core::pairwise::subject_for(&f.options, &client, "1");
    assert_ne!(expected, "1");
    assert_eq!(jws.payload["sub"], expected.as_str());
}

#[tokio::test]
async fn a_pairwise_client_on_a_server_without_salt_gets_no_logout_token() {
    let mut f = Fixture::new();
    let recorder = with_recorder(&mut f);
    f.edit_clients(|clients| {
        for c in clients.iter_mut().filter(|c| c.client_id == "logout.back") {
            c.subject_type = rustid_core::clients::SubjectType::Pairwise;
        }
    });
    process_logout(&f.validation_ctx(Utc::now()), &session(&["logout.back"]))
        .await
        .unwrap();
    assert!(recorder.0.lock().unwrap().is_empty(), "never the user's own subject");
}
