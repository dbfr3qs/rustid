//! The `claims` request parameter (OpenID Connect Core 1.0 §5.5): parsed,
//! limited to what the client may have, and carried to the id token and
//! userinfo.

mod support;

use rustid_core::authorize::{AuthorizeFailure, validate};
use rustid_core::claims_request::RequestedClaims;
use rustid_core::params::Params;
use support::Fixture;

const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

fn web(client_id: &str, claims: &str) -> Params {
    Params::from_pairs([
        ("client_id", client_id),
        ("redirect_uri", "https://client.test/callback"),
        ("response_type", "code"),
        ("scope", "openid"),
        ("state", "s1"),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
        ("claims", claims),
    ])
}

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_owned()).collect()
}

#[test]
fn members_name_the_claims_wanted() {
    let parsed = RequestedClaims::parse(
        r#"{"userinfo":{"name":{"essential":true},"email":null,"name":null},
            "id_token":{"auth_time":{"essential":true},"nickname":{"value":"x"}},
            "other":{"x":null}}"#,
    )
    .unwrap();
    assert_eq!(parsed.userinfo, names(&["name", "email"]));
    assert_eq!(parsed.id_token, names(&["auth_time", "nickname"]));
    assert_eq!(
        RequestedClaims::parse("{}").unwrap(),
        RequestedClaims::default()
    );
}

#[test]
fn malformed_claims_are_refused() {
    for bad in [
        "name",
        "[]",
        r#"{"userinfo":[]}"#,
        r#"{"id_token":"name"}"#,
        r#"{"userinfo":{"name":3}}"#,
    ] {
        assert!(RequestedClaims::parse(bad).is_none(), "{bad}");
    }
}

#[test]
fn only_claims_of_the_given_identity_resources_remain() {
    let f = Fixture::new();
    let resources = f.resources.enabled();
    let profile: Vec<_> = resources
        .identity_resources
        .iter()
        .filter(|r| r.name == "openid" || r.name == "profile")
        .cloned()
        .collect();
    let parsed = RequestedClaims::parse(
        r#"{"userinfo":{"name":null,"foo":null},"id_token":{"secret":null,"nickname":null}}"#,
    )
    .unwrap();
    let limited = parsed.limited_to(&profile);
    assert_eq!(limited.userinfo, names(&["name"]));
    assert_eq!(limited.id_token, names(&["nickname"]));
}

#[tokio::test]
async fn authorize_keeps_what_the_clients_scopes_allow() {
    let f = Fixture::new();
    // `web` may ask for profile but not custom_identity (`foo`); `email`
    // belongs to no identity resource.
    let r = validate(
        &f.authorize_ctx(chrono::Utc::now()),
        web(
            "web",
            r#"{"userinfo":{"name":{"essential":true},"foo":null,"email":null},"id_token":{"nickname":null}}"#,
        ),
        None,
    )
    .await
    .unwrap();
    assert_eq!(r.requested_claims.userinfo, names(&["name"]));
    assert_eq!(r.requested_claims.id_token, names(&["nickname"]));
}

#[tokio::test]
async fn authorize_refuses_a_malformed_claims_parameter() {
    let f = Fixture::new();
    match validate(
        &f.authorize_ctx(chrono::Utc::now()),
        web("web", "{nope"),
        None,
    )
    .await
    {
        Err(AuthorizeFailure::Invalid(e)) => {
            assert_eq!(e.error, "invalid_request");
            assert_eq!(e.description.as_deref(), Some("Invalid claims parameter"));
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn without_claims_nothing_is_requested() {
    let f = Fixture::new();
    let mut params = web("web", "");
    params.remove("claims");
    let r = validate(&f.authorize_ctx(chrono::Utc::now()), params, None)
        .await
        .unwrap();
    assert_eq!(r.requested_claims, RequestedClaims::default());
}

mod carried {
    use std::sync::Arc;

    use chrono::Utc;
    use rustid_core::authorize::code::{AuthorizationCode, sha256_base64};
    use rustid_core::authorize::implicit::browser_tokens;
    use rustid_core::authorize::request::ValidatedAuthorizeRequest;
    use rustid_core::claims_request::RequestedClaims;
    use rustid_core::form::Form;
    use rustid_core::issuance::Issuer;
    use rustid_core::session::{SignIn, UserSession};
    use rustid_core::token::process;
    use rustid_core::tokens::Claim;
    use serde_json::Value;

    use super::support::{Fixture, ISSUER};
    use super::{CHALLENGE, names};

    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    fn session() -> UserSession {
        UserSession::sign_in(
            SignIn {
                subject_id: "1".into(),
                claims: vec![
                    Claim::string("name", "Alice"),
                    Claim::string("role", "admin"),
                ],
                ..Default::default()
            },
            None,
            Utc::now(),
            3600,
        )
    }

    fn payload(jwt: &str) -> Value {
        use base64::Engine;
        let part = jwt.split('.').nth(1).unwrap();
        serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(part)
                .unwrap(),
        )
        .unwrap()
    }

    fn client(f: &Fixture, id: &str) -> Arc<rustid_core::clients::Client> {
        Arc::new(
            f.clients
                .clients
                .iter()
                .find(|c| c.client_id == id)
                .unwrap()
                .clone(),
        )
    }

    /// A validated request by `client_id` for `scopes`, signed in.
    fn request(
        f: &Fixture,
        client_id: &str,
        response_type: &'static str,
        scopes: &[&str],
        claims: RequestedClaims,
    ) -> ValidatedAuthorizeRequest {
        let client = client(f, client_id);
        let requested: Vec<String> = scopes.iter().map(|s| (*s).to_owned()).collect();
        let resources = rustid_core::scopes::validate_requested_resources(
            &client,
            &f.resources.enabled(),
            &requested,
            &[],
        )
        .unwrap();
        let subject = session();
        ValidatedAuthorizeRequest {
            client_id: Some(client_id.to_owned()),
            client: Some(client),
            redirect_uri: Some("https://client.test/callback".into()),
            response_type: Some(response_type),
            is_openid_request: true,
            requested_scopes: requested,
            resources: Some(resources),
            nonce: Some("n1".into()),
            code_challenge: Some(CHALLENGE.into()),
            code_challenge_method: Some("S256".into()),
            session_id: Some(subject.session_id.clone()),
            subject: Some(subject),
            requested_claims: claims,
            ..Default::default()
        }
    }

    fn asking(userinfo: &[&str], id_token: &[&str]) -> RequestedClaims {
        RequestedClaims {
            userinfo: names(userinfo),
            id_token: names(id_token),
        }
    }

    async fn redeem(
        f: &Fixture,
        client_id: &str,
        scopes: &[&str],
        claims: RequestedClaims,
    ) -> rustid_core::token::TokenResponse {
        let code = AuthorizationCode::for_request(
            &request(f, client_id, "code", scopes, claims),
            Utc::now(),
        );
        assert_eq!(
            code.code_challenge.as_deref(),
            Some(sha256_base64(CHALLENGE).as_str())
        );
        let handle = code.store(f.stores.grants.as_ref()).await.unwrap();
        let form = Form::from_pairs(&[
            ("grant_type", "authorization_code"),
            ("client_id", client_id),
            ("code", &handle),
            ("redirect_uri", "https://client.test/callback"),
            ("code_verifier", VERIFIER),
        ]);
        process(&f.ctx(Utc::now()), None, &form).await.unwrap()
    }

    async fn userinfo(f: &Fixture, access_token: &str) -> Value {
        Value::Object(
            rustid_core::userinfo::userinfo(&f.validation_ctx(Utc::now()), access_token)
                .await
                .unwrap()
                .unwrap(),
        )
    }

    #[tokio::test]
    async fn the_code_flow_issues_what_was_asked_for() {
        let f = Fixture::new();
        let response = redeem(&f, "web", &["openid", "api1"], asking(&["name"], &["name"])).await;
        let id = payload(response.id_token.as_deref().unwrap());
        assert_eq!(id["name"], "Alice");
        assert_eq!(payload(&response.access_token)["userinfo_claims"], "name");
        assert_eq!(
            userinfo(&f, &response.access_token).await,
            serde_json::json!({ "name": "Alice", "sub": "1" })
        );
    }

    #[tokio::test]
    async fn without_claims_the_tokens_are_unchanged() {
        let f = Fixture::new();
        let response = redeem(&f, "web", &["openid", "api1"], RequestedClaims::default()).await;
        let id = payload(response.id_token.as_deref().unwrap());
        assert!(id.get("name").is_none(), "{id}");
        assert!(
            payload(&response.access_token)
                .get("userinfo_claims")
                .is_none()
        );
        assert_eq!(
            userinfo(&f, &response.access_token).await,
            serde_json::json!({ "sub": "1" })
        );
    }

    #[test]
    fn under_consent_only_granted_identity_resources_count() {
        let f = Fixture::new();
        let wanted = asking(&["name"], &["name"]);
        let code = AuthorizationCode::for_request(
            &request(
                &f,
                "web-consent",
                "code",
                &["openid", "api1"],
                wanted.clone(),
            ),
            Utc::now(),
        );
        assert_eq!(
            code.requested_claims,
            RequestedClaims::default(),
            "profile wasn't granted"
        );
        let code = AuthorizationCode::for_request(
            &request(
                &f,
                "web-consent",
                "code",
                &["openid", "profile"],
                wanted.clone(),
            ),
            Utc::now(),
        );
        assert_eq!(code.requested_claims, wanted);
        let code = AuthorizationCode::for_request(
            &request(&f, "web", "code", &["openid", "api1"], wanted.clone()),
            Utc::now(),
        );
        assert_eq!(
            code.requested_claims, wanted,
            "no consent: the allowed scopes count"
        );
    }

    #[tokio::test]
    async fn a_refresh_that_builds_a_new_access_token_keeps_the_request() {
        let f = Fixture::new();
        let response = redeem(
            &f,
            "code-update-claims",
            &["openid", "api1", "offline_access"],
            asking(&["name"], &["name"]),
        )
        .await;
        let form = Form::from_pairs(&[
            ("grant_type", "refresh_token"),
            ("client_id", "code-update-claims"),
            ("refresh_token", response.refresh_token.as_deref().unwrap()),
        ]);
        let refreshed = process(&f.ctx(Utc::now()), None, &form).await.unwrap();
        assert_eq!(payload(&refreshed.access_token)["userinfo_claims"], "name");
        assert_eq!(
            payload(refreshed.id_token.as_deref().unwrap())["name"],
            "Alice"
        );
    }

    #[tokio::test]
    async fn hybrid_and_implicit_tokens_carry_the_request() {
        let f = Fixture::new();
        let issuer = Issuer {
            options: &f.options,
            stores: &f.stores,
            keys: &f.keys,
            issuer: ISSUER,
            now: Utc::now(),
        };
        let r = request(
            &f,
            "hybrid",
            "code id_token token",
            &["openid", "api1"],
            asking(&["name"], &["name"]),
        );
        let tokens = browser_tokens(&issuer, &r, Some("code")).await.unwrap();
        assert_eq!(
            payload(tokens.id_token.as_deref().unwrap())["name"],
            "Alice"
        );
        assert_eq!(
            payload(tokens.access_token.as_deref().unwrap())["userinfo_claims"],
            "name"
        );
        let plain = request(
            &f,
            "hybrid",
            "code id_token token",
            &["openid", "api1"],
            Default::default(),
        );
        let tokens = browser_tokens(&issuer, &plain, Some("code")).await.unwrap();
        assert!(
            payload(tokens.id_token.as_deref().unwrap())
                .get("name")
                .is_none()
        );
    }

    #[test]
    fn a_profile_service_cant_set_the_userinfo_request() {
        assert!(rustid_core::tokens::PROTOCOL_CLAIM_TYPES.contains(&"userinfo_claims"));
    }
}
