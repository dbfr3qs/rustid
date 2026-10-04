//! A replacement profile service: it supplies the
//! profile claims of every token and userinfo, and decides whether the
//! subject is still active wherever that is asked.

mod support;

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rustid_core::authorize::{Interaction, process_interaction, validate};
use rustid_core::params::Params;
use rustid_core::profile::{ActiveRequest, ProfileError, ProfileRequest, ProfileService};
use rustid_core::session::{SignIn, UserSession};
use rustid_core::tokens::Claim;
use support::Fixture;

/// Answers `foo=bar` for every profile request and the configured
/// activity; records each call as `caller requested-types`.
struct Custom {
    active: bool,
    calls: Mutex<Vec<String>>,
}

#[async_trait]
impl ProfileService for Custom {
    async fn profile_claims(&self, r: &ProfileRequest<'_>) -> Result<Vec<Claim>, ProfileError> {
        self.calls.lock().unwrap().push(format!(
            "{} {} {}",
            r.caller,
            r.client.client_id,
            r.requested_claim_types.join(",")
        ));
        Ok(vec![
            Claim::string("foo", "bar"),
            Claim::string("sub", "forged"),
        ])
    }

    async fn is_active(&self, r: &ActiveRequest<'_>) -> Result<bool, ProfileError> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("active {} {}", r.caller, r.subject_id));
        Ok(self.active)
    }
}

fn now() -> DateTime<Utc> {
    Utc::now()
}

fn session() -> UserSession {
    UserSession::sign_in(
        SignIn {
            subject_id: "1".into(),
            claims: vec![Claim::string("name", "Alice")],
            ..Default::default()
        },
        None,
        now(),
        3600,
    )
}

fn fixture(active: bool) -> (Fixture, Arc<Custom>) {
    let mut f = Fixture::new();
    let custom = Arc::new(Custom {
        active,
        calls: Mutex::new(Vec::new()),
    });
    f.stores.profile = custom.clone();
    (f, custom)
}

const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

#[tokio::test]
async fn identity_tokens_take_their_claims_from_the_profile_service() {
    let (f, custom) = fixture(true);
    let ctx = f.authorize_ctx(now());
    let params = Params::parse_query(
        "client_id=spa&redirect_uri=https%3A%2F%2Fspa.test%2Fcb&response_type=id_token\
         &scope=openid%20profile&state=s&nonce=n",
    );
    let session = session();
    let mut request = validate(&ctx, params, Some(&session)).await.unwrap();
    assert_eq!(
        process_interaction(&mut request, &ctx, None).await.unwrap(),
        Interaction::None
    );
    let issuer = rustid_core::issuance::Issuer {
        options: &f.options,
        stores: &f.stores,
        keys: &f.keys,
        issuer: support::ISSUER,
        now: now(),
    };
    let tokens = rustid_core::authorize::implicit::browser_tokens(&issuer, &request, None)
        .await
        .unwrap();
    let id = rustid_core::jwt::Jws::decode(&tokens.id_token.unwrap()).unwrap();
    assert_eq!(id.payload["foo"], "bar");
    assert_eq!(
        id.payload["sub"], "1",
        "protocol claims from the service are dropped"
    );
    let calls = custom.calls.lock().unwrap().clone();
    assert_eq!(calls[0], "active AuthorizeEndpoint 1");
    assert!(
        calls[1].starts_with("ClaimsProviderIdentityToken spa name,"),
        "{calls:?}"
    );
}

#[tokio::test]
async fn an_inactive_subject_logs_in_again_and_loses_codes_userinfo_and_introspection() {
    // Tokens issued while active...
    let (f, _) = fixture(true);
    let ctx = f.authorize_ctx(now());
    let params = Params::parse_query(&format!(
        "client_id=web&redirect_uri=https%3A%2F%2Fclient.test%2Fcallback&response_type=code\
         &scope=openid%20profile%20api1&state=s&code_challenge={CHALLENGE}&code_challenge_method=S256"
    ));
    let session = session();
    let request = validate(&ctx, params.clone(), Some(&session))
        .await
        .unwrap();
    let code = rustid_core::authorize::code::AuthorizationCode::for_request(&request, now());
    let handle = code.store(f.stores.grants.as_ref()).await.unwrap();
    let access_token = f.issue_user_token(&session, "openid profile api1").await;

    // ...are refused once the subject is inactive.
    let mut f = f;
    let inactive = Arc::new(Custom {
        active: false,
        calls: Mutex::new(Vec::new()),
    });
    f.stores.profile = inactive.clone();
    let ctx = f.authorize_ctx(now());
    let mut again = validate(&ctx, params, Some(&session)).await.unwrap();
    assert_eq!(
        process_interaction(&mut again, &ctx, None).await.unwrap(),
        Interaction::Login
    );

    let form = rustid_core::form::Form::from_pairs(&[
        ("grant_type", "authorization_code"),
        ("client_id", "web"),
        ("code", &handle),
        ("redirect_uri", "https://client.test/callback"),
        (
            "code_verifier",
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        ),
    ]);
    match rustid_core::token::process(&f.ctx(now()), None, &form).await {
        Err(rustid_core::token::TokenFailure::Protocol(e)) => assert_eq!(e.error, "invalid_grant"),
        other => panic!("expected invalid_grant, got {other:?}"),
    }

    let validation = f.validation_ctx(now());
    assert_eq!(
        rustid_core::userinfo::userinfo(&validation, &access_token)
            .await
            .unwrap(),
        Err("invalid_token")
    );
    let calls = inactive.calls.lock().unwrap().clone();
    assert!(
        calls.contains(&"active AuthorizeEndpoint 1".to_owned()),
        "{calls:?}"
    );
    assert!(
        calls.contains(&"active AuthorizationCodeValidation 1".to_owned()),
        "{calls:?}"
    );
    assert!(
        calls.contains(&"active AccessTokenValidation 1".to_owned()),
        "{calls:?}"
    );
}
