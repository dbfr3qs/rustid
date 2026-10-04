mod support;

use rustid_core::authorize::{
    AuthorizeFailure, Interaction, PROCESSED_MAX_AGE, PROCESSED_PROMPT, process_interaction,
    validate,
};
use rustid_core::params::Params;
use support::Fixture;

const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

/// `web`'s code request with `overrides` applied (an empty value removes).
fn web(overrides: &[(&str, &str)]) -> Params {
    let mut p = Params::from_pairs([
        ("client_id", "web"),
        ("redirect_uri", "https://client.test/callback"),
        ("response_type", "code"),
        ("scope", "openid profile"),
        ("state", "s1"),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
    ]);
    for (k, v) in overrides {
        if v.is_empty() {
            p.remove(k);
        } else {
            p.set(k, v);
        }
    }
    p
}

fn spa(overrides: &[(&str, &str)]) -> Params {
    let mut p = web(&[
        ("client_id", "spa"),
        ("redirect_uri", "https://spa.test/cb"),
        ("response_type", "id_token"),
        ("nonce", "n1"),
        ("code_challenge", ""),
        ("code_challenge_method", ""),
    ]);
    for (k, v) in overrides {
        if v.is_empty() {
            p.remove(k);
        } else {
            p.set(k, v);
        }
    }
    p
}

async fn error_of(f: &Fixture, params: Params) -> (&'static str, Option<String>) {
    match validate(&f.authorize_ctx(chrono::Utc::now()), params, None).await {
        Err(AuthorizeFailure::Invalid(e)) => (e.error, e.description),
        Err(AuthorizeFailure::Server(m)) => panic!("server error {m}"),
        Ok(r) => panic!("unexpectedly valid: {r:?}"),
    }
}

#[tokio::test]
async fn each_check_fails_with_its_error_and_description() {
    let f = Fixture::new();
    let long = |n| "x".repeat(n);
    let cases: Vec<(Params, &str, Option<&str>)> = vec![
        (
            web(&[("ui_locales", &long(101))]),
            "invalid_request",
            Some("Invalid ui_locales"),
        ),
        (
            web(&[("client_id", "")]),
            "invalid_request",
            Some("Invalid client_id"),
        ),
        (
            web(&[("client_id", &long(101))]),
            "invalid_request",
            Some("Invalid client_id"),
        ),
        (
            web(&[("client_id", "nope")]),
            "unauthorized_client",
            Some("Unknown client or client not enabled"),
        ),
        (
            web(&[("client_id", "client.disabled")]),
            "unauthorized_client",
            Some("Unknown client or client not enabled"),
        ),
        (
            web(&[("request", "a.b.c"), ("request_uri", "https://x/r")]),
            "invalid_request",
            Some("Only one request parameter is allowed"),
        ),
        (
            web(&[("request_uri", "https://x/r")]),
            "request_uri_not_supported",
            None,
        ),
        (
            web(&[("request_uri", "urn:ietf:params:oauth:request_uri:x")]),
            "invalid_request_uri",
            Some("invalid or reused PAR request uri"),
        ),
        (
            web(&[("request", "a.b.c")]),
            "invalid_request_object",
            Some("Invalid JWT request"),
        ),
        (
            web(&[("redirect_uri", "")]),
            "invalid_request",
            Some("Invalid redirect_uri"),
        ),
        (
            web(&[("redirect_uri", "not a uri")]),
            "invalid_request",
            Some("Invalid redirect_uri"),
        ),
        (
            web(&[("client_id", "client.saml")]),
            "unauthorized_client",
            Some("Invalid protocol"),
        ),
        (
            web(&[("redirect_uri", "https://client.test/other")]),
            "invalid_request",
            Some("Invalid redirect_uri"),
        ),
        (
            web(&[("response_type", "")]),
            "invalid_request",
            Some("Missing response_type"),
        ),
        (
            web(&[("response_type", "foo")]),
            "unsupported_response_type",
            Some("Response type not supported"),
        ),
        (
            web(&[("response_mode", "foo")]),
            "unsupported_response_type",
            Some("Invalid response_mode"),
        ),
        (
            spa(&[("response_mode", "query")]),
            "invalid_request",
            Some("Invalid response_mode for response_type"),
        ),
        (
            web(&[("code_challenge", "")]),
            "invalid_request",
            Some("code challenge required"),
        ),
        (
            web(&[("code_challenge", "short")]),
            "invalid_request",
            Some("Invalid code_challenge"),
        ),
        (
            web(&[("code_challenge_method", "plain")]),
            "invalid_request",
            Some("Transform algorithm not supported"),
        ),
        (
            web(&[("code_challenge_method", "S512")]),
            "invalid_request",
            Some("Transform algorithm not supported"),
        ),
        (
            web(&[("response_type", "id_token"), ("nonce", "n")]),
            "unauthorized_client",
            Some("Invalid grant type for client"),
        ),
        (
            web(&[("scope", "")]),
            "invalid_request",
            Some("Invalid scope"),
        ),
        (
            web(&[("scope", &format!("openid {}", long(294)))]),
            "invalid_request",
            Some("Invalid scope"),
        ),
        (
            spa(&[("scope", "profile")]),
            "invalid_request",
            Some("Missing openid scope"),
        ),
        (
            web(&[("resource", "not-a-uri")]),
            "invalid_target",
            Some("Invalid resource indicator format"),
        ),
        (
            spa(&[("resource", "https://api.test/")]),
            "invalid_target",
            Some("Resource indicators not allowed for response_type 'token'."),
        ),
        (
            web(&[("resource", "https://unknown.test/")]),
            "invalid_target",
            Some("Invalid resource indicator"),
        ),
        (
            web(&[("scope", "openid api2")]),
            "invalid_scope",
            Some("Invalid scope"),
        ),
        (
            web(&[("scope", "profile")]),
            "invalid_scope",
            Some("Identity scopes requested, but openid scope is missing"),
        ),
        (
            spa(&[("response_type", "token"), ("scope", "openid api1")]),
            "invalid_scope",
            Some("Invalid scope for response type"),
        ),
        (
            spa(&[("nonce", "")]),
            "invalid_request",
            Some("Invalid nonce"),
        ),
        (
            web(&[("nonce", &long(301))]),
            "invalid_request",
            Some("Invalid nonce"),
        ),
        (
            web(&[("prompt", "unknown")]),
            "invalid_request",
            Some("Unsupported prompt mode"),
        ),
        (
            web(&[("prompt", "none login")]),
            "invalid_request",
            Some("Invalid prompt"),
        ),
        (
            web(&[("suppressed_prompt", "bogus")]),
            "invalid_request",
            Some("Invalid prompt"),
        ),
        (
            web(&[("max_age", "abc")]),
            "invalid_request",
            Some("Invalid max_age"),
        ),
        (
            web(&[("max_age", "-1")]),
            "invalid_request",
            Some("Invalid max_age"),
        ),
        (
            web(&[("login_hint", &long(101))]),
            "invalid_request",
            Some("Invalid login_hint"),
        ),
        (
            web(&[("acr_values", &long(301))]),
            "invalid_request",
            Some("Invalid acr_values"),
        ),
        (
            web(&[("dpop_jkt", &long(101))]),
            "invalid_request",
            Some("Invalid dpop_jkt"),
        ),
    ];
    for (params, error, description) in cases {
        let query = params.to_query_string();
        assert_eq!(
            error_of(&f, params).await,
            (error, description.map(str::to_owned)),
            "{query}"
        );
    }
}

#[tokio::test]
async fn a_valid_request_carries_everything_the_response_needs() {
    let f = Fixture::new();
    let r = validate(
        &f.authorize_ctx(chrono::Utc::now()),
        web(&[
            ("response_type", "code"),
            ("response_mode", "form_post"),
            ("display", "popup"),
            ("ui_locales", "nb-NO"),
            ("login_hint", "alice"),
            ("acr_values", "idp:google urn:x urn:x"),
            ("max_age", " 30"),
        ]),
        None,
    )
    .await
    .unwrap();
    assert_eq!(r.client_id.as_deref(), Some("web"));
    assert_eq!(r.grant_type, Some("authorization_code"));
    assert_eq!(r.response_mode, Some("form_post"));
    assert_eq!(r.requested_scopes, ["openid", "profile"]);
    assert!(r.is_openid_request);
    assert_eq!(r.display_mode.as_deref(), Some("popup"));
    assert_eq!(r.max_age, Some(30));
    assert_eq!(r.acr_values, ["idp:google", "urn:x"]);
    assert_eq!(r.idp(), Some("google"));
    assert_eq!(r.code_challenge_method.as_deref(), Some("S256"));
    assert_eq!(r.session_id.as_deref(), Some(""));
}

#[tokio::test]
async fn response_types_in_any_order_and_defaults_per_flow() {
    let f = Fixture::new();
    let r = validate(
        &f.authorize_ctx(chrono::Utc::now()),
        spa(&[
            ("response_type", "token id_token"),
            ("scope", "openid api1"),
        ]),
        None,
    )
    .await
    .unwrap();
    assert_eq!(r.response_type, Some("id_token token"));
    assert_eq!(r.response_mode, Some("fragment"));
    assert!(r.is_api_resource_request);
}

#[tokio::test]
async fn disallowed_idp_is_removed_from_the_request() {
    let f = Fixture::new();
    let r = validate(
        &f.authorize_ctx(chrono::Utc::now()),
        web(&[
            ("client_id", "web.idp"),
            ("acr_values", "idp:facebook urn:x"),
            ("code_challenge", ""),
            ("code_challenge_method", ""),
        ]),
        None,
    )
    .await
    .unwrap();
    assert_eq!(r.idp(), None);
    assert_eq!(r.raw.get("acr_values").as_deref(), Some("urn:x"));
}

#[tokio::test]
async fn processed_prompts_and_max_age_are_not_acted_on_again() {
    let f = Fixture::new();
    let mut r = validate(
        &f.authorize_ctx(chrono::Utc::now()),
        web(&[("prompt", "login"), ("max_age", "0")]),
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        process_interaction(&mut r, &f.authorize_ctx(chrono::Utc::now()), None)
            .await
            .unwrap(),
        Interaction::Login
    );
    assert_eq!(r.raw.get(PROCESSED_PROMPT).as_deref(), Some("login"));
    assert_eq!(r.raw.get(PROCESSED_MAX_AGE).as_deref(), Some("0"));

    let again = validate(&f.authorize_ctx(chrono::Utc::now()), r.raw.clone(), None)
        .await
        .unwrap();
    assert!(again.prompt_modes.is_empty());
    assert_eq!(again.max_age, None);
}

#[tokio::test]
async fn invalid_client_configuration_counts_as_unknown_and_raises_an_event() {
    let mut f = Fixture::new();
    f.edit_clients(|clients| {
        let web = clients.iter_mut().find(|c| c.client_id == "web").unwrap();
        web.redirect_uris.clear();
    });
    assert_eq!(
        error_of(&f, web(&[])).await,
        (
            "unauthorized_client",
            Some("Unknown client or client not enabled".to_owned())
        )
    );
    assert_eq!(f.events.names(), ["Invalid Client Configuration"]);
}
