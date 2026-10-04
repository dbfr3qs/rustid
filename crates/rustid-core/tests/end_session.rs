//! End session requests and the logout
//! message the logout page reads (`LogoutMessage`).

mod support;

use chrono::Utc;
use rustid_core::end_session::{self, LogoutMessage};
use rustid_core::issuance::Issuer;
use rustid_core::params::Params;
use rustid_core::scopes::validate_requested_resources;
use rustid_core::session::{SignIn, UserSession};
use rustid_core::tokens::IdentityTokenRequest;
use support::{Fixture, ISSUER};

fn session(subject: &str) -> UserSession {
    let mut s = UserSession::sign_in(
        SignIn {
            subject_id: subject.into(),
            ..Default::default()
        },
        None,
        Utc::now(),
        3600,
    );
    s.add_client("web");
    s
}

/// An identity token for `web`, for the session's subject and sid.
async fn id_token(f: &Fixture, session: &UserSession) -> String {
    let client = f
        .clients
        .clients
        .iter()
        .find(|c| c.client_id == "web")
        .unwrap()
        .clone();
    let resources =
        validate_requested_resources(&client, &f.resources.enabled(), &["openid".to_owned()], &[])
            .unwrap();
    Issuer {
        options: &f.options,
        stores: &f.stores,
        keys: &f.keys,
        issuer: ISSUER,
        now: Utc::now() - chrono::Duration::hours(2),
    }
    .identity_token(
        &client,
        &resources,
        session,
        &IdentityTokenRequest {
            session_id: Some(&session.session_id),
            ..Default::default()
        },
    )
    .await
    .unwrap()
}

async fn validate(
    f: &Fixture,
    query: &str,
    session: Option<&UserSession>,
) -> Result<end_session::EndSessionRequest, String> {
    end_session::validate(
        &f.validation_ctx(Utc::now()),
        Params::parse_query(query),
        session,
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn a_hint_names_the_client_and_its_registered_redirect_carries_state() {
    let f = Fixture::new();
    let s = session("1");
    let hint = id_token(&f, &s).await;
    let r = validate(
        &f,
        &format!(
            "id_token_hint={hint}&post_logout_redirect_uri=https%3A%2F%2Fclient.test%2Fsignout&state=st&custom=x"
        ),
        Some(&s),
    )
    .await
    .unwrap();
    assert_eq!(r.client.as_ref().map(|c| c.client_id.as_str()), Some("web"));
    assert_eq!(r.subject_id.as_deref(), Some("1"));
    assert_eq!(r.session_id.as_deref(), Some(s.session_id.as_str()));
    assert_eq!(r.client_ids, ["web"]);
    let message = LogoutMessage::from_request(&r);
    assert_eq!(
        message.post_logout_redirect_uri.as_deref(),
        Some("https://client.test/signout?state=st")
    );
    assert!(message.contains_payload());
    assert_eq!(
        serde_json::to_value(&message.parameters).unwrap(),
        serde_json::json!({ "custom": ["x"] }),
        "the hint, redirect, state and ui_locales travel separately"
    );

    // An unregistered redirect is dropped, and its state with it.
    let r = validate(
        &f,
        &format!("id_token_hint={hint}&post_logout_redirect_uri=https%3A%2F%2Fevil.test&state=st"),
        Some(&s),
    )
    .await
    .unwrap();
    assert_eq!(
        LogoutMessage::from_request(&r).post_logout_redirect_uri,
        None
    );
}

#[tokio::test]
async fn a_hint_for_another_session_or_forged_is_refused() {
    let f = Fixture::new();
    let other = session("1");
    let hint = id_token(&f, &other).await;
    let mine = session("1");
    assert_eq!(
        validate(&f, &format!("id_token_hint={hint}"), Some(&mine))
            .await
            .unwrap_err(),
        "Session ID in id_token_hint does not match current session"
    );
    let mut forged = hint.clone();
    forged.pop();
    forged.push(if hint.ends_with('A') { 'B' } else { 'A' });
    assert_eq!(
        validate(&f, &format!("id_token_hint={forged}"), Some(&other))
            .await
            .unwrap_err(),
        "Error validating id token hint"
    );
}

#[tokio::test]
async fn anonymous_requests_keep_the_hints_client_unless_a_user_is_required() {
    let mut f = Fixture::new();
    let s = session("1");
    let hint = id_token(&f, &s).await;
    let query = format!(
        "id_token_hint={hint}&post_logout_redirect_uri=https%3A%2F%2Fclient.test%2Fsignout"
    );
    let r = validate(&f, &query, None).await.unwrap();
    assert_eq!(r.subject_id, None);
    assert_eq!(
        LogoutMessage::from_request(&r)
            .post_logout_redirect_uri
            .as_deref(),
        Some("https://client.test/signout")
    );
    f.options
        .authentication
        .require_authenticated_user_for_sign_out_message = true;
    assert_eq!(
        validate(&f, &query, None).await.unwrap_err(),
        "User is anonymous. Ignoring end session parameters"
    );
}

#[tokio::test]
async fn without_a_hint_the_session_is_the_payload_and_long_locales_are_ignored() {
    let f = Fixture::new();
    let s = session("1");
    let long = "x".repeat(101);
    let r = validate(&f, &format!("ui_locales={long}"), Some(&s))
        .await
        .unwrap();
    assert_eq!(r.client, None);
    assert_eq!(r.client_ids, ["web"]);
    assert_eq!(r.ui_locales, None);
    let r = validate(&f, "ui_locales=nb-NO", None).await.unwrap();
    assert_eq!(r.ui_locales.as_deref(), Some("nb-NO"));
    assert!(!LogoutMessage::from_request(&r).contains_payload());
}
