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
