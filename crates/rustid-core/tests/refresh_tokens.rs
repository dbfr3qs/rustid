//! Refresh tokens (the refresh token service and the `refresh_token`
//! grant): issuance with `offline_access`, rotation or reuse, lifetimes,
//! and every way a refresh is refused.

mod support;

use chrono::{DateTime, Duration, Utc};
use rustid_core::authorize::code::AuthorizationCode;
use rustid_core::authorize::validate;
use rustid_core::clients::{RefreshTokenExpiration, RefreshTokenUsage};
use rustid_core::form::Form;
use rustid_core::jwt::Jws;
use rustid_core::params::Params;
use rustid_core::session::{SignIn, UserSession};
use rustid_core::token::{TokenFailure, TokenResponse, process};
use rustid_core::tokens::Claim;
use support::Fixture;

const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

fn t0() -> DateTime<Utc> {
    Utc::now()
}

fn session(now: DateTime<Utc>) -> UserSession {
    UserSession::sign_in(
        SignIn {
            subject_id: "1".into(),
            claims: vec![Claim::string("name", "Alice")],
            ..Default::default()
        },
        None,
        now,
        3600,
    )
}

/// Redeems a fresh code for `web` with `scope`.
async fn redeem(f: &Fixture, scope: &str, now: DateTime<Utc>) -> TokenResponse {
    let ctx = f.authorize_ctx(now);
    let params = Params::parse_query(&format!(
        "client_id=web&redirect_uri=https%3A%2F%2Fclient.test%2Fcallback&response_type=code\
         &scope={}&state=s&nonce=n&code_challenge={CHALLENGE}&code_challenge_method=S256",
        scope.replace(' ', "%20")
    ));
    let session = session(now);
    let request = validate(&ctx, params, Some(&session)).await.unwrap();
    let code = AuthorizationCode::for_request(&request, now);
    let handle = code.store(f.stores.grants.as_ref()).await.unwrap();
    let form = Form::from_pairs(&[
        ("grant_type", "authorization_code"),
        ("client_id", "web"),
        ("code", &handle),
        ("redirect_uri", "https://client.test/callback"),
        ("code_verifier", VERIFIER),
    ]);
    process(&f.ctx(now), None, &form).await.unwrap()
}

async fn refresh(
    f: &Fixture,
    client_id: &str,
    token: &str,
    now: DateTime<Utc>,
) -> Result<TokenResponse, TokenFailure> {
    let form = Form::from_pairs(&[
        ("grant_type", "refresh_token"),
        ("client_id", client_id),
        ("refresh_token", token),
    ]);
    process(&f.ctx(now), None, &form).await
}

fn error(result: Result<TokenResponse, TokenFailure>) -> String {
    match result {
        Err(TokenFailure::Protocol(e)) => e.error.into_owned(),
        other => panic!("expected an error, got {other:?}"),
    }
}

fn payload(token: &str) -> serde_json::Map<String, serde_json::Value> {
    Jws::decode(token).unwrap().payload
}

fn set_web(f: &mut Fixture, edit: impl FnOnce(&mut rustid_core::clients::Client)) {
    f.edit_clients(|clients| edit(clients.iter_mut().find(|c| c.client_id == "web").unwrap()));
}

#[tokio::test]
async fn offline_access_issues_a_refresh_token() {
    let f = Fixture::new();
    let with = redeem(&f, "openid api1 offline_access", t0()).await;
    let handle = with.refresh_token.expect("a refresh token");
    assert_eq!(handle.len(), 66, "64 hex characters and the -1 suffix");
    assert!(handle.ends_with("-1"));
    assert_eq!(with.scope, "openid api1 offline_access");
    let without = redeem(&f, "openid api1", t0()).await;
    assert_eq!(without.refresh_token, None);

    let grant = f
        .stores
        .grants
        .get(&rustid_core::grants::hashed_key(&handle, "refresh_token"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(grant.grant_type, "refresh_token");
    assert_eq!(grant.client_id, "web");
    assert_eq!(grant.subject_id.as_deref(), Some("1"));
    assert!(grant.session_id.is_some());
    assert_eq!(
        grant.expiration.unwrap() - grant.creation_time,
        Duration::seconds(2_592_000),
        "absolute by default, the client's absolute lifetime"
    );
}

fn one_time_only(f: &mut Fixture) {
    set_web(f, |c| {
        c.refresh_token_usage = RefreshTokenUsage::OneTimeOnly
    });
}

#[tokio::test]
async fn one_time_only_tokens_rotate_and_the_old_handle_is_refused() {
    let mut f = Fixture::new();
    one_time_only(&mut f);
    let first = redeem(&f, "openid api1 offline_access", t0()).await;
    let old = first.refresh_token.unwrap();
    let second = refresh(&f, "web", &old, t0()).await.unwrap();
    let new = second.refresh_token.unwrap();
    assert_ne!(new, old);
    assert_eq!(error(refresh(&f, "web", &old, t0()).await), "invalid_grant");
    assert!(refresh(&f, "web", &new, t0()).await.is_ok());
}

#[tokio::test]
async fn without_deletion_a_used_token_is_marked_consumed_and_still_refused() {
    let mut f = Fixture::new();
    one_time_only(&mut f);
    f.options
        .persistent_grants
        .delete_one_time_only_refresh_tokens_on_use = false;
    let old = redeem(&f, "openid api1 offline_access", t0())
        .await
        .refresh_token
        .unwrap();
    refresh(&f, "web", &old, t0()).await.unwrap();
    let key = rustid_core::grants::hashed_key(&old, "refresh_token");
    let grant = f.stores.grants.get(&key).await.unwrap().expect("kept");
    let record: serde_json::Value = serde_json::from_str(&grant.data).unwrap();
    assert!(!record["consumed_time"].is_null(), "{record}");
    assert_eq!(error(refresh(&f, "web", &old, t0()).await), "invalid_grant");
}

#[tokio::test]
async fn reuse_is_the_default_and_keeps_the_handle() {
    let f = Fixture::new();
    let handle = redeem(&f, "api1 offline_access", t0())
        .await
        .refresh_token
        .unwrap();
    for _ in 0..2 {
        let again = refresh(&f, "web", &handle, t0()).await.unwrap();
        assert_eq!(again.refresh_token.as_deref(), Some(handle.as_str()));
    }
}

#[tokio::test]
async fn the_access_token_is_reissued_unless_claims_are_updated_on_refresh() {
    let mut f = Fixture::new();
    set_web(&mut f, |c| c.refresh_token_usage = RefreshTokenUsage::ReUse);
    let first = redeem(&f, "openid api1 offline_access", t0()).await;
    let handle = first.refresh_token.clone().unwrap();
    let original = payload(&first.access_token);
    let later = t0() + Duration::seconds(30);
    let reissued = refresh(&f, "web", &handle, later).await.unwrap();
    let reissued = payload(&reissued.access_token);
    assert_eq!(reissued["jti"], original["jti"], "the same token record");
    assert_eq!(reissued["sid"], original["sid"]);
    assert_eq!(
        reissued["iat"].as_i64().unwrap(),
        later.timestamp(),
        "a new creation time"
    );

    set_web(&mut f, |c| c.update_access_token_claims_on_refresh = true);
    let updated = refresh(&f, "web", &handle, later).await.unwrap();
    let updated = payload(&updated.access_token);
    assert_ne!(updated["jti"], original["jti"], "a new token");
    assert_eq!(
        updated["sid"], original["sid"],
        "the refresh token's session"
    );
    assert_eq!(updated["sub"], "1");
}

#[tokio::test]
async fn openid_refreshes_get_an_identity_token() {
    let f = Fixture::new();
    let first = redeem(&f, "openid api1 offline_access", t0()).await;
    let response = refresh(&f, "web", first.refresh_token.as_deref().unwrap(), t0())
        .await
        .unwrap();
    let id = payload(response.id_token.as_deref().expect("an identity token"));
    assert_eq!(id["sub"], "1");
    assert_eq!(id["aud"], "web");
    assert!(id.get("nonce").is_none(), "no nonce on refresh");
    assert_eq!(
        id["at_hash"],
        rustid_core::tokens::hash_claim_value(&response.access_token, "RS256")
    );
    assert!(id.get("sid").is_some());
    assert_eq!(response.scope, "openid api1 offline_access");

    let api_only = redeem(&f, "api1 offline_access", t0()).await;
    let response = refresh(&f, "web", api_only.refresh_token.as_deref().unwrap(), t0())
        .await
        .unwrap();
    assert_eq!(response.id_token, None);
}

#[tokio::test]
async fn sliding_lifetimes_grow_but_never_past_the_absolute_lifetime() {
    let mut f = Fixture::new();
    set_web(&mut f, |c| {
        c.refresh_token_expiration = RefreshTokenExpiration::Sliding;
        c.refresh_token_usage = RefreshTokenUsage::ReUse;
        c.sliding_refresh_token_lifetime = 100;
        c.absolute_refresh_token_lifetime = 150;
    });
    let handle = redeem(&f, "api1 offline_access", t0())
        .await
        .refresh_token
        .unwrap();
    let key = rustid_core::grants::hashed_key(&handle, "refresh_token");
    let lifetime = |grant: rustid_core::grants::PersistedGrant| {
        (grant.expiration.unwrap() - grant.creation_time).num_seconds()
    };
    assert_eq!(
        lifetime(f.stores.grants.get(&key).await.unwrap().unwrap()),
        100
    );
    refresh(&f, "web", &handle, t0() + Duration::seconds(30))
        .await
        .unwrap();
    assert_eq!(
        lifetime(f.stores.grants.get(&key).await.unwrap().unwrap()),
        130,
        "30 seconds old plus the sliding 100"
    );
    refresh(&f, "web", &handle, t0() + Duration::seconds(90))
        .await
        .unwrap();
    assert_eq!(
        lifetime(f.stores.grants.get(&key).await.unwrap().unwrap()),
        150,
        "capped by the absolute lifetime"
    );
    assert_eq!(
        error(refresh(&f, "web", &handle, t0() + Duration::seconds(151)).await),
        "invalid_grant",
        "expired"
    );
}

#[tokio::test]
async fn refreshes_are_refused_for_the_wrong_client_input_or_client_settings() {
    let mut f = Fixture::new();
    let handle = redeem(&f, "api1 offline_access", t0())
        .await
        .refresh_token
        .unwrap();
    let missing = process(
        &f.ctx(t0()),
        None,
        &Form::from_pairs(&[("grant_type", "refresh_token"), ("client_id", "web")]),
    )
    .await;
    assert_eq!(error(missing), "invalid_request");
    assert_eq!(
        error(refresh(&f, "web", &"x".repeat(101), t0()).await),
        "invalid_grant",
        "longer than the input length limit"
    );
    assert_eq!(
        error(refresh(&f, "web", "unknown-1", t0()).await),
        "invalid_grant"
    );
    assert_eq!(
        error(refresh(&f, "spa", &handle, t0()).await),
        "invalid_grant",
        "another client's refresh token"
    );
    set_web(&mut f, |c| c.allow_offline_access = false);
    assert_eq!(
        error(refresh(&f, "web", &handle, t0()).await),
        "invalid_grant",
        "the client no longer allows offline access"
    );
}

#[tokio::test]
async fn of_two_concurrent_rotations_of_one_token_only_one_succeeds() {
    // Both requests validated the same record; the second to rotate it
    // finds it already taken.
    let mut f = Fixture::new();
    one_time_only(&mut f);
    let handle = redeem(&f, "api1 offline_access", t0())
        .await
        .refresh_token
        .unwrap();
    let grants = f.stores.grants.as_ref();
    let record = rustid_core::refresh_tokens::get(grants, &handle)
        .await
        .unwrap()
        .unwrap();
    let client = f
        .clients
        .clients
        .iter()
        .find(|c| c.client_id == "web")
        .unwrap();
    let options = &f.options.persistent_grants;
    let first = rustid_core::refresh_tokens::update(
        grants,
        options,
        client,
        &handle,
        &mut record.clone(),
        false,
        t0(),
    )
    .await
    .unwrap();
    assert!(first.is_some());
    let second = rustid_core::refresh_tokens::update(
        grants,
        options,
        client,
        &handle,
        &mut record.clone(),
        false,
        t0(),
    )
    .await
    .unwrap();
    assert_eq!(second, None, "already rotated by the first");
}
