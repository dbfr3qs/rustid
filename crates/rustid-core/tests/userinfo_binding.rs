//! Sender-constrained access tokens at the userinfo endpoint: a DPoP-bound
//! token needs its proof (RFC 9449 §7) and a certificate-bound token its
//! certificate (RFC 8705); a bearer token is served as before.

mod support;

use chrono::Utc;
use rustid_core::authorize::code::{AuthorizationCode, sha256_base64};
use rustid_core::client_certificate::ClientCertificate;
use rustid_core::form::Form;
use rustid_core::keys::LoadedKey;
use rustid_core::session::{SignIn, UserSession};
use rustid_core::token::process;
use rustid_core::tokens::Claim;
use rustid_core::userinfo::{
    UserInfoAnswer, UserInfoRefusal, UserInfoRequest, userinfo_for_request,
};
use serde_json::json;
use support::Fixture;

const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const USERINFO: &str = "http://h/connect/userinfo";

fn rsa() -> LoadedKey {
    support::key("client-jwt-key.pem", "p", "RS256")
}

fn certificate(cn: &str) -> ClientCertificate {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    let der = params.self_signed(&key).unwrap().der().to_vec();
    ClientCertificate::parse(&der, None).unwrap()
}

/// An access token for `client_id` and user 1 (scope `openid api1`),
/// redeemed with a DPoP proof by `key` or over a connection presenting
/// `cert` when given.
async fn token(
    f: &Fixture,
    client_id: &str,
    key: Option<&LoadedKey>,
    cert: Option<&ClientCertificate>,
) -> String {
    let subject = UserSession::sign_in(
        SignIn {
            subject_id: "1".into(),
            claims: vec![Claim::string("name", "Alice")],
            ..Default::default()
        },
        None,
        Utc::now(),
        3600,
    );
    let code = AuthorizationCode {
        creation_time: Utc::now(),
        client_id: client_id.into(),
        lifetime: 300,
        session_id: subject.session_id.clone(),
        subject,
        description: None,
        code_challenge: Some(sha256_base64(CHALLENGE)),
        code_challenge_method: Some("S256".into()),
        dpop_key_thumbprint: None,
        is_open_id: true,
        requested_scopes: vec!["openid".into(), "profile".into(), "api1".into()],
        requested_resource_indicators: Vec::new(),
        redirect_uri: "https://client.test/callback".into(),
        nonce: None,
        state_hash: None,
        was_consent_shown: false,
        requested_claims: Default::default(),
    };
    let handle = code.store(f.stores.grants.as_ref()).await.unwrap();
    let proof = key.map(|k| support::dpop_proof(k, "http://h/connect/token", None));
    let proofs: Vec<&str> = proof.as_deref().into_iter().collect();
    let mut ctx = f.ctx(Utc::now());
    ctx.dpop_proofs = &proofs;
    ctx.client_certificate = cert;
    process(
        &ctx,
        None,
        &Form::from_pairs(&[
            ("grant_type", "authorization_code"),
            ("client_id", client_id),
            ("code", &handle),
            ("redirect_uri", "https://client.test/callback"),
            ("code_verifier", VERIFIER),
        ]),
    )
    .await
    .unwrap()
    .access_token
}

async fn call(
    f: &Fixture,
    token: &str,
    dpop: bool,
    proofs: &[String],
    cert: Option<&ClientCertificate>,
) -> Result<UserInfoAnswer, UserInfoRefusal> {
    userinfo_for_request(
        &f.validation_ctx(Utc::now()),
        &UserInfoRequest {
            token,
            dpop,
            dpop_proofs: proofs,
            method: "GET",
            url: USERINFO,
            client_certificate: cert,
        },
        &f.protector,
    )
    .await
    .unwrap()
}

fn served(answer: Result<UserInfoAnswer, UserInfoRefusal>) -> serde_json::Value {
    match answer {
        Ok(UserInfoAnswer::Json(claims)) => serde_json::Value::Object(claims),
        other => panic!("not served: {other:?}"),
    }
}

fn challenge(
    answer: Result<UserInfoAnswer, UserInfoRefusal>,
) -> rustid_core::protected_resource::Challenge {
    match answer {
        Err(UserInfoRefusal::Challenge(c)) => c,
        other => panic!("expected a challenge: {other:?}"),
    }
}

#[tokio::test]
async fn a_dpop_bound_token_is_served_with_its_proof_only() {
    let f = Fixture::new();
    let key = rsa();
    let at = token(&f, "web", Some(&key), None).await;
    let proof = support::dpop_resource_proof(&key, "GET", USERINFO, Some(&at));
    assert_eq!(
        served(call(&f, &at, true, std::slice::from_ref(&proof), None).await)["sub"],
        "1"
    );
    // Replayed, missing, for another URL, or by another key.
    assert!(
        challenge(call(&f, &at, true, &[proof], None).await)
            .dpop_error
            .is_some()
    );
    assert!(
        challenge(call(&f, &at, true, &[], None).await)
            .dpop_error
            .is_some()
    );
    let elsewhere = support::dpop_resource_proof(&key, "GET", "http://h/other", Some(&at));
    assert!(
        challenge(call(&f, &at, true, &[elsewhere], None).await)
            .dpop_error
            .is_some()
    );
    let thief = support::key("client-jwt-ec-key.pem", "p", "ES256");
    let stolen = support::dpop_resource_proof(&thief, "GET", USERINFO, Some(&at));
    assert!(
        challenge(call(&f, &at, true, &[stolen], None).await)
            .dpop_error
            .is_some()
    );
}

#[tokio::test]
async fn a_dpop_bound_token_is_never_served_as_a_bearer_token() {
    let f = Fixture::new();
    let at = token(&f, "web", Some(&rsa()), None).await;
    let refused = challenge(call(&f, &at, false, &[], None).await);
    assert_eq!(
        refused.bearer_error,
        Some((
            "invalid_token".to_owned(),
            Some("Must use DPoP when using an access token with a 'cnf' claim".to_owned())
        ))
    );
}

#[tokio::test]
async fn a_certificate_bound_token_needs_its_certificate() {
    let cert = certificate("client");
    let mut f = Fixture::new();
    let thumbprint = cert.thumbprint.clone();
    f.edit_clients(|clients| {
        clients.push(
            serde_json::from_value(json!({
                "clientId": "mtls-web",
                "clientSecrets": [{ "type": "X509Thumbprint", "value": thumbprint }],
                "allowedGrantTypes": ["authorization_code"],
                "redirectUris": ["https://client.test/callback"],
                "allowedScopes": ["openid", "profile", "api1"],
                "requireConsent": false,
            }))
            .unwrap(),
        );
    });
    let at = token(&f, "mtls-web", None, Some(&cert)).await;
    assert!(rustid_core::jwt::Jws::decode(&at).is_some());
    assert_eq!(
        served(call(&f, &at, false, &[], Some(&cert)).await)["sub"],
        "1"
    );
    assert!(
        challenge(call(&f, &at, false, &[], None).await)
            .bearer_error
            .is_some()
    );
    let other = certificate("someone else");
    assert!(
        challenge(call(&f, &at, false, &[], Some(&other)).await)
            .bearer_error
            .is_some()
    );
}

#[tokio::test]
async fn bearer_tokens_are_served_as_before() {
    let f = Fixture::new();
    let at = token(&f, "web", None, None).await;
    assert_eq!(served(call(&f, &at, false, &[], None).await)["sub"], "1");
    assert!(matches!(
        call(&f, "nonsense", false, &[], None).await,
        Err(UserInfoRefusal::Error("invalid_token"))
    ));
    assert!(matches!(
        call(&f, "nonsense", true, &[], None).await,
        Err(UserInfoRefusal::Error("invalid_token"))
    ));
}

/// Counts the active checks access token validation makes.
#[derive(Default)]
struct Counting {
    token_checks: std::sync::Mutex<usize>,
}

#[async_trait::async_trait]
impl rustid_core::profile::ProfileService for Counting {
    async fn profile_claims(
        &self,
        request: &rustid_core::profile::ProfileRequest<'_>,
    ) -> Result<Vec<Claim>, rustid_core::profile::ProfileError> {
        rustid_core::profile::DefaultProfileService
            .profile_claims(request)
            .await
    }

    async fn is_active(
        &self,
        request: &rustid_core::profile::ActiveRequest<'_>,
    ) -> Result<bool, rustid_core::profile::ProfileError> {
        if request.caller == rustid_core::profile::active_callers::ACCESS_TOKEN {
            *self.token_checks.lock().unwrap() += 1;
        }
        Ok(true)
    }
}

#[tokio::test]
async fn the_token_is_validated_once_per_request() {
    let mut f = Fixture::new();
    let counting = std::sync::Arc::new(Counting::default());
    f.stores.profile = counting.clone();
    let at = token(&f, "web", None, None).await;
    *counting.token_checks.lock().unwrap() = 0;
    served(call(&f, &at, false, &[], None).await);
    assert_eq!(*counting.token_checks.lock().unwrap(), 1);
}
