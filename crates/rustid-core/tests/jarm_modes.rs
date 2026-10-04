//! JARM response modes (JARM 2.3): accepted only when `jarm.enabled`;
//! `jwt` resolves by response type; tokens never go in a query.

mod support;

use rustid_core::authorize::{AuthorizeFailure, ValidatedAuthorizeRequest, validate};
use rustid_core::params::Params;
use support::Fixture;

const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

fn code(mode: &str) -> Params {
    Params::from_pairs([
        ("client_id", "web"),
        ("redirect_uri", "https://client.test/callback"),
        ("response_type", "code"),
        ("scope", "openid profile"),
        ("state", "s1"),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
        ("response_mode", mode),
    ])
}

fn hybrid(mode: &str) -> Params {
    Params::from_pairs([
        ("client_id", "hybrid"),
        ("redirect_uri", "https://client.test/callback"),
        ("response_type", "code id_token"),
        ("scope", "openid profile"),
        ("state", "s1"),
        ("nonce", "n1"),
        ("response_mode", mode),
    ])
}

async fn validated(
    params: Params,
    jarm: bool,
) -> Result<ValidatedAuthorizeRequest, (&'static str, Option<String>)> {
    let mut f = Fixture::new();
    f.options.jarm.enabled = jarm;
    match validate(&f.authorize_ctx(chrono::Utc::now()), params, None).await {
        Ok(r) => Ok(r),
        Err(AuthorizeFailure::Invalid(e)) => Err((e.error, e.description)),
        Err(AuthorizeFailure::Server(m)) => panic!("server error {m}"),
    }
}

#[tokio::test]
async fn jarm_modes_are_refused_when_off() {
    for mode in ["jwt", "query.jwt", "fragment.jwt", "form_post.jwt"] {
        let error = validated(code(mode), false).await.unwrap_err();
        assert_eq!(
            error,
            (
                "unsupported_response_type",
                Some("Invalid response_mode".to_owned())
            ),
            "{mode}"
        );
    }
}

#[tokio::test]
async fn jwt_resolves_by_response_type() {
    let r = validated(code("jwt"), true).await.unwrap();
    assert_eq!(r.response_mode, Some("query.jwt"));
    let r = validated(hybrid("jwt"), true).await.unwrap();
    assert_eq!(r.response_mode, Some("fragment.jwt"));
    let r = validated(code("form_post.jwt"), true).await.unwrap();
    assert_eq!(r.response_mode, Some("form_post.jwt"));
    let r = validated(code("fragment.jwt"), true).await.unwrap();
    assert_eq!(r.response_mode, Some("fragment.jwt"));
    // Plain modes are untouched.
    let r = validated(code("form_post"), true).await.unwrap();
    assert_eq!(r.response_mode, Some("form_post"));
}

#[tokio::test]
async fn query_jwt_is_refused_for_token_responses() {
    let error = validated(hybrid("query.jwt"), true).await.unwrap_err();
    assert_eq!(
        error,
        (
            "invalid_request",
            Some("Invalid response_mode for response_type".to_owned())
        )
    );
}

#[test]
fn the_response_jwt_carries_the_parameters_signed() {
    use rustid_core::authorize::jarm::{base_mode, response_jwt};
    use rustid_core::jwt::{Jws, PublicJwk};
    let key = support::key("signing-key.pem", "k1", "RS256");
    let mut params = Params::default();
    params.add("code", "the-code");
    params.add("state", "s1");
    params.add("iss", "https://idsrv.test");
    let jwt = response_jwt(&key, "https://idsrv.test", "web", &params, 1_000, 300).unwrap();
    let jws = Jws::decode(&jwt).unwrap();
    let public = PublicJwk::parse(&support::public_jwk_json(&key)).unwrap();
    assert!(jws.verify(&public));
    assert_eq!(jws.header_str("kid"), Some("k1"));
    assert_eq!(jws.claim_str("iss"), Some("https://idsrv.test"));
    assert_eq!(
        jws.payload["aud"],
        serde_json::json!("web"),
        "a string, not an array"
    );
    assert_eq!(jws.claim_i64("exp"), Some(1_300));
    assert_eq!(jws.claim_str("code"), Some("the-code"));
    assert_eq!(jws.claim_str("state"), Some("s1"));
    assert_eq!(base_mode("query.jwt"), "query");
    assert_eq!(base_mode("fragment.jwt"), "fragment");
    assert_eq!(base_mode("form_post.jwt"), "form_post");
    assert_eq!(base_mode("query"), "query");
}
