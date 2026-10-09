mod support;

use chrono::{DateTime, Utc};
use rustid_core::authorize::code::{AuthorizationCode, sha256_base64};
use rustid_core::form::Form;
use rustid_core::session::{SignIn, UserSession};
use rustid_core::token::{TokenFailure, process};
use rustid_core::tokens::Claim;
use support::Fixture;

const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

fn now() -> DateTime<Utc> {
    Utc::now()
}

fn code(client_id: &str, scopes: &[&str]) -> AuthorizationCode {
    let subject = UserSession::sign_in(
        SignIn {
            subject_id: "1".into(),
            claims: vec![Claim::string("role", "admin")],
            ..Default::default()
        },
        None,
        now(),
        3600,
    );
    AuthorizationCode {
        creation_time: now(),
        client_id: client_id.into(),
        lifetime: 300,
        session_id: subject.session_id.clone(),
        subject,
        description: None,
        code_challenge: Some(sha256_base64(CHALLENGE)),
        code_challenge_method: Some("S256".into()),
        dpop_key_thumbprint: None,
        is_open_id: scopes.contains(&"openid"),
        requested_scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
        requested_resource_indicators: Vec::new(),
        redirect_uri: "https://client.test/callback".into(),
        nonce: Some("n1".into()),
        state_hash: None,
        was_consent_shown: false,
        requested_claims: Default::default(),
    }
}

fn form(client_id: &str, handle: &str, extra: &[(&str, &str)]) -> Form {
    let mut pairs = vec![
        ("grant_type", "authorization_code"),
        ("client_id", client_id),
        ("code", handle),
        ("redirect_uri", "https://client.test/callback"),
        ("code_verifier", VERIFIER),
    ];
    for (k, v) in extra {
        pairs.retain(|(key, _)| key != k);
        if !v.is_empty() {
            pairs.push((k, v));
        }
    }
    Form::from_pairs(&pairs)
}

async fn error(f: &Fixture, form: &Form) -> (String, Option<String>) {
    match process(&f.ctx(now()), None, form).await {
        Err(TokenFailure::Protocol(e)) => (e.error.into_owned(), e.description),
        other => panic!("expected a protocol error, got {other:?}"),
    }
}

fn payload(jwt: &str) -> serde_json::Value {
    use base64::Engine;
    let part = jwt.split('.').nth(1).unwrap();
    serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(part)
            .unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn a_code_redeems_once_for_an_access_token_and_an_identity_token() {
    let f = Fixture::new();
    let issued = code("web", &["openid", "api1"]);
    let handle = issued.store(f.stores.grants.as_ref()).await.unwrap();
    let response = process(&f.ctx(now()), None, &form("web", &handle, &[]))
        .await
        .unwrap();
    assert_eq!(response.scope, "openid api1");
    let id = payload(response.id_token.as_deref().unwrap());
    assert_eq!(id["aud"], "web");
    assert_eq!(id["nonce"], "n1");
    assert_eq!(id["sub"], "1");
    assert_eq!(id["sid"], issued.session_id.as_str());
    assert_eq!(
        id["at_hash"],
        rustid_core::tokens::hash_claim_value(&response.access_token, "RS256").as_str()
    );
    let access = payload(&response.access_token);
    assert_eq!(access["sub"], "1");
    assert_eq!(access["role"], "admin");
    assert_eq!(access["client_id"], "web");
    assert_eq!(
        error(&f, &form("web", &handle, &[])).await.0,
        "invalid_grant",
        "one use only"
    );
    let names = f.events.names();
    assert!(names.contains(&"Token Issued Success"), "{names:?}");
}

#[tokio::test]
async fn codes_fail() {
    let f = Fixture::new();
    let store = |c: AuthorizationCode| {
        let grants = f.stores.grants.clone();
        async move { c.store(grants.as_ref()).await.unwrap() }
    };
    let h = store(code("web", &["openid"])).await;
    assert_eq!(
        error(&f, &form("web.plain", &h, &[])).await.0,
        "invalid_grant",
        "another client's code"
    );
    assert!(
        process(&f.ctx(now()), None, &form("web", &h, &[]))
            .await
            .is_ok(),
        "not consumed by the other client"
    );

    let h = store(code("web", &["openid"])).await;
    assert_eq!(
        error(&f, &form("web", &h, &[("redirect_uri", "")])).await.0,
        "unauthorized_client"
    );
    assert_eq!(
        error(&f, &form("web", &h, &[])).await.0,
        "invalid_grant",
        "consumed by the failed attempt"
    );

    let h = store(code("web", &["openid"])).await;
    assert_eq!(
        error(
            &f,
            &form(
                "web",
                &h,
                &[("redirect_uri", "https://client.test/Callback")]
            )
        )
        .await
        .0,
        "invalid_grant"
    );
    for verifier in ["", "short", "aBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"] {
        let h = store(code("web", &["openid"])).await;
        assert_eq!(
            error(&f, &form("web", &h, &[("code_verifier", verifier)]))
                .await
                .0,
            "invalid_grant",
            "{verifier}"
        );
    }
    let mut expired = code("web", &["openid"]);
    expired.creation_time = now() - chrono::Duration::seconds(301);
    let h = store(expired).await;
    assert_eq!(error(&f, &form("web", &h, &[])).await.0, "invalid_grant");

    let mut dpop = code("web", &["openid"]);
    dpop.dpop_key_thumbprint = Some("jkt".into());
    let h = store(dpop).await;
    assert_eq!(
        error(&f, &form("web", &h, &[])).await.0,
        "invalid_dpop_proof"
    );

    let mut no_scopes = code("web", &[]);
    no_scopes.requested_scopes.clear();
    let h = store(no_scopes).await;
    assert_eq!(error(&f, &form("web", &h, &[])).await.0, "invalid_request");

    assert_eq!(
        error(&f, &form("web", &"x".repeat(101), &[])).await.0,
        "invalid_grant"
    );
    assert_eq!(
        error(&f, &form("spa", "nope", &[])).await.0,
        "unauthorized_client"
    );
}

#[tokio::test]
async fn pkce_is_checked_only_when_required_or_used() {
    let f = Fixture::new();
    let mut plain = code("web.plain", &["openid"]);
    plain.code_challenge = Some(sha256_base64(VERIFIER));
    plain.code_challenge_method = Some("plain".into());
    let h = plain.store(f.stores.grants.as_ref()).await.unwrap();
    assert!(
        process(&f.ctx(now()), None, &form("web.plain", &h, &[]))
            .await
            .is_ok()
    );

    let mut optional = code("web.idclaims", &["openid"]);
    optional.code_challenge = None;
    optional.code_challenge_method = None;
    let h = optional
        .clone()
        .store(f.stores.grants.as_ref())
        .await
        .unwrap();
    assert_eq!(
        error(&f, &form("web.idclaims", &h, &[])).await.0,
        "invalid_grant",
        "a verifier without a challenge"
    );
    let h = optional.store(f.stores.grants.as_ref()).await.unwrap();
    assert!(
        process(
            &f.ctx(now()),
            None,
            &form("web.idclaims", &h, &[("code_verifier", "")])
        )
        .await
        .is_ok()
    );
}

#[tokio::test]
async fn codes_without_openid_get_no_identity_token() {
    let f = Fixture::new();
    let h = code("web", &["api1"])
        .store(f.stores.grants.as_ref())
        .await
        .unwrap();
    let response = process(&f.ctx(now()), None, &form("web", &h, &[]))
        .await
        .unwrap();
    assert_eq!(response.id_token, None);
}

#[tokio::test]
async fn success_events_list_the_identity_token_before_the_access_token() {
    let f = Fixture::new();
    let h = code("web", &["openid"])
        .store(f.stores.grants.as_ref())
        .await
        .unwrap();
    f.events.take();
    process(&f.ctx(now()), None, &form("web", &h, &[]))
        .await
        .unwrap();
    let events = f.events.take();
    let success = events
        .iter()
        .find(|e| e.name == "Token Issued Success")
        .unwrap();
    let details = serde_json::to_value(&success.details).unwrap();
    let types: Vec<&str> = details["Tokens"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["TokenType"].as_str().unwrap())
        .collect();
    assert_eq!(
        types,
        ["id_token", "access_token"],
        "as TokenIssuedSuccessEvent orders them"
    );
    assert_eq!(details["SubjectId"], "1");
}

#[tokio::test]
async fn failure_events_name_the_subject_whose_code_failed() {
    let f = Fixture::new();
    let h = code("web", &["openid"])
        .store(f.stores.grants.as_ref())
        .await
        .unwrap();
    f.events.take();
    let failing = form(
        "web",
        &h,
        &[
            (
                "code_verifier",
                "aBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            ),
            ("scope", "openid"),
        ],
    );
    assert_eq!(error(&f, &failing).await.0, "invalid_grant");
    let events = f.events.take();
    let failure = events
        .iter()
        .find(|e| e.name == "Token Issued Failure")
        .unwrap();
    let details = serde_json::to_value(&failure.details).unwrap();
    assert_eq!(details["SubjectId"], "1");
    assert!(
        details.get("Scopes").is_none(),
        "code requests carry no requested scopes: {details}"
    );
    // Before the code is loaded there is no subject.
    assert_eq!(
        error(&f, &form("web", "nope", &[])).await.0,
        "invalid_grant"
    );
    let events = f.events.take();
    let failure = events
        .iter()
        .find(|e| e.name == "Token Issued Failure")
        .unwrap();
    assert!(
        serde_json::to_value(&failure.details)
            .unwrap()
            .get("SubjectId")
            .is_none()
    );
}
