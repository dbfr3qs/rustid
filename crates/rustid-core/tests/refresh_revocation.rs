//! Revoking and introspecting refresh tokens (revoke refresh token,
//! get refresh token claims).

mod support;

use base64::Engine;
use chrono::{DateTime, Utc};
use rustid_core::authorize::code::AuthorizationCode;
use rustid_core::authorize::validate;
use rustid_core::clients::AccessTokenType;
use rustid_core::form::Form;
use rustid_core::introspection::{self, Introspection};
use rustid_core::params::Params;
use rustid_core::session::{SignIn, UserSession};
use rustid_core::token::{TokenResponse, process};
use support::Fixture;

const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

fn now() -> DateTime<Utc> {
    Utc::now()
}

/// A new session for subject 1 (a new session id each time).
fn session() -> UserSession {
    UserSession::sign_in(
        SignIn {
            subject_id: "1".into(),
            ..Default::default()
        },
        None,
        now(),
        3600,
    )
}

async fn tokens(f: &Fixture, session: &UserSession) -> TokenResponse {
    let ctx = f.authorize_ctx(now());
    let params = Params::parse_query(&format!(
        "client_id=web&redirect_uri=https%3A%2F%2Fclient.test%2Fcallback&response_type=code\
         &scope=api1%20offline_access&state=s&code_challenge={CHALLENGE}&code_challenge_method=S256"
    ));
    let request = validate(&ctx, params, Some(session)).await.unwrap();
    let handle = AuthorizationCode::for_request(&request, now())
        .store(f.stores.grants.as_ref())
        .await
        .unwrap();
    let form = Form::from_pairs(&[
        ("grant_type", "authorization_code"),
        ("client_id", "web"),
        ("code", &handle),
        ("redirect_uri", "https://client.test/callback"),
        ("code_verifier", VERIFIER),
    ]);
    process(&f.ctx(now()), None, &form).await.unwrap()
}

async fn revoke(f: &Fixture, client_id: &str, token: &str, hint: Option<&str>) {
    let mut pairs = vec![("client_id", client_id), ("token", token)];
    if let Some(hint) = hint {
        pairs.push(("token_type_hint", hint));
    }
    if client_id == "client" {
        pairs.push(("client_secret", "secret"));
    }
    let result = rustid_core::revocation::process(&f.ctx(now()), None, &Form::from_pairs(&pairs))
        .await
        .unwrap();
    assert_eq!(result, Ok(()));
}

async fn refreshes(f: &Fixture, token: &str) -> bool {
    let form = Form::from_pairs(&[
        ("grant_type", "refresh_token"),
        ("client_id", "web"),
        ("refresh_token", token),
    ]);
    process(&f.ctx(now()), None, &form).await.is_ok()
}

fn reference_client(f: &mut Fixture) {
    f.edit_clients(|clients| {
        let web = clients.iter_mut().find(|c| c.client_id == "web").unwrap();
        web.access_token_type = AccessTokenType::Reference;
        web.refresh_token_usage = rustid_core::clients::RefreshTokenUsage::ReUse;
    });
}

async fn introspect(
    f: &Fixture,
    authorization: Option<&str>,
    pairs: &[(&str, &str)],
) -> serde_json::Map<String, serde_json::Value> {
    match introspection::process(&f.ctx(now()), authorization, &Form::from_pairs(pairs))
        .await
        .unwrap()
    {
        Introspection::Response { entries, .. } => entries,
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn a_client_revokes_its_refresh_token_with_or_without_a_hint() {
    let mut f = Fixture::new();
    reference_client(&mut f);
    for hint in [Some("refresh_token"), None] {
        let issued = tokens(&f, &session()).await;
        let refresh = issued.refresh_token.unwrap();
        assert!(refreshes(&f, &refresh).await);
        revoke(&f, "web", &refresh, hint).await;
        assert!(!refreshes(&f, &refresh).await, "{hint:?}");
    }
    // An access token hint only looks at access tokens.
    let issued = tokens(&f, &session()).await;
    let refresh = issued.refresh_token.unwrap();
    revoke(&f, "web", &refresh, Some("access_token")).await;
    assert!(refreshes(&f, &refresh).await);
}

#[tokio::test]
async fn another_clients_revocation_succeeds_without_revoking() {
    let f = Fixture::new();
    let refresh = tokens(&f, &session()).await.refresh_token.unwrap();
    revoke(&f, "client", &refresh, Some("refresh_token")).await;
    assert!(refreshes(&f, &refresh).await);
}

#[tokio::test]
async fn revoking_removes_that_sessions_reference_tokens_only() {
    let mut f = Fixture::new();
    reference_client(&mut f);
    let first = tokens(&f, &session()).await;
    let second = tokens(&f, &session()).await;
    let active = |r: serde_json::Map<String, serde_json::Value>| r["active"] == true;
    let basic = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("api:secret")
    );
    assert!(active(
        introspect(&f, Some(&basic), &[("token", &first.access_token)]).await
    ));
    revoke(&f, "web", first.refresh_token.as_deref().unwrap(), None).await;
    assert!(
        !active(introspect(&f, Some(&basic), &[("token", &first.access_token)]).await),
        "the revoked session's reference token is gone"
    );
    assert!(
        active(introspect(&f, Some(&basic), &[("token", &second.access_token)]).await),
        "the other session's is not"
    );
}

#[tokio::test]
async fn clients_introspect_their_own_refresh_tokens_with_any_hint() {
    let f = Fixture::new();
    let refresh = tokens(&f, &session()).await.refresh_token.unwrap();
    for hint in [
        None,
        Some("refresh_token"),
        Some("access_token"),
        Some("bogus"),
    ] {
        let mut pairs = vec![("client_id", "web"), ("token", refresh.as_str())];
        if let Some(hint) = hint {
            pairs.push(("token_type_hint", hint));
        }
        let entries = introspect(&f, None, &pairs).await;
        assert_eq!(entries["active"], true, "{hint:?}");
        assert_eq!(entries["token_type"], "refresh_token");
        assert_eq!(entries["client_id"], "web");
        assert_eq!(entries["sub"], "1");
        assert_eq!(entries["scope"], "api1 offline_access");
        let lifetime = entries["exp"].as_i64().unwrap() - entries["iat"].as_i64().unwrap();
        assert_eq!(lifetime, 2_592_000);
    }
    let other = introspect(
        &f,
        None,
        &[
            ("client_id", "client"),
            ("client_secret", "secret"),
            ("token", &refresh),
        ],
    )
    .await;
    assert_eq!(other["active"], false, "another client's refresh token");
    let basic = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("api:secret")
    );
    let api = introspect(&f, Some(&basic), &[("token", &refresh)]).await;
    assert_eq!(api["active"], false, "APIs never see refresh tokens");

    revoke(&f, "web", &refresh, None).await;
    let revoked = introspect(&f, None, &[("client_id", "web"), ("token", &refresh)]).await;
    assert_eq!(revoked["active"], false);
}
