//! RFC 8707 resource indicators at the token endpoint: parsing one
//! indicator, and narrowing validated resources to it
//! (`ResourceValidationResult.FilterByResourceIndicator`).

use rustid_core::clients::Client;
use rustid_core::form::Form;
use rustid_core::resources::{ApiResource, ApiScope, IdentityResource, Resources};
use rustid_core::scopes::validate_requested_resources;
use rustid_core::token::requested_resource_indicator;

fn resources() -> Resources {
    let api = |name: &str, scopes: &[&str], isolated: bool| ApiResource {
        name: name.into(),
        scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
        require_resource_indicator: isolated,
        ..Default::default()
    };
    Resources {
        identity_resources: vec![IdentityResource {
            name: "openid".into(),
            user_claims: vec!["sub".into()],
            ..Default::default()
        }],
        api_scopes: ["scope1", "scope2", "scope3", "scope4"]
            .iter()
            .map(|s| ApiScope {
                name: (*s).into(),
                ..Default::default()
            })
            .collect(),
        api_resources: vec![
            api("urn:api1", &["scope1", "scope3"], false),
            api("urn:api2", &["scope2"], false),
            api("urn:api3", &["scope1", "scope3"], true),
            api("urn:api4", &[], true),
        ],
    }
}

fn client() -> Client {
    Client {
        client_id: "client".into(),
        allowed_scopes: ["openid", "scope1", "scope2", "scope3", "scope4"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect(),
        allow_offline_access: true,
        ..Default::default()
    }
}

fn scopes(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| (*s).to_owned()).collect()
}

#[test]
fn narrowing_keeps_one_api_its_scopes_offline_access_and_identity() {
    let all = scopes(&["openid", "scope1", "scope2", "scope3", "offline_access"]);
    let validated =
        validate_requested_resources(&client(), &resources(), &all, &scopes(&["urn:api1"]))
            .unwrap();
    let narrowed = validated.filter_by_resource_indicator(Some("urn:api1"));
    assert_eq!(narrowed.audiences(), ["urn:api1"]);
    assert_eq!(narrowed.scopes, ["scope1", "scope3", "offline_access"]);
    assert_eq!(
        narrowed.identity_resources.len(),
        1,
        "the id token still has openid"
    );
    assert!(narrowed.offline_access);

    // No indicator: every non-isolated API, scopes as they were.
    let validated = validate_requested_resources(&client(), &resources(), &all, &[]).unwrap();
    let wide = validated.filter_by_resource_indicator(None);
    assert_eq!(wide.audiences(), ["urn:api1", "urn:api2"]);
    assert_eq!(wide.scopes, all);

    // An isolated resource only by name.
    let validated = validate_requested_resources(
        &client(),
        &resources(),
        &scopes(&["scope1"]),
        &scopes(&["urn:api3"]),
    )
    .unwrap();
    let isolated = validated.filter_by_resource_indicator(Some("urn:api3"));
    assert_eq!(isolated.audiences(), ["urn:api3"]);
    assert_eq!(isolated.scopes, ["scope1"]);
}

fn form(query: &str) -> Form {
    Form::parse(query.as_bytes()).unwrap()
}

#[test]
fn one_well_formed_indicator_at_most() {
    let limits = rustid_core::options::InputLengthRestrictions::default();
    let parse = |q: &str| requested_resource_indicator(&form(q), &limits);
    assert_eq!(parse("grant_type=x"), Ok(None));
    assert_eq!(parse("resource="), Ok(None), "empty is none");
    assert_eq!(parse("resource=urn%3Aapi1"), Ok(Some("urn:api1".into())));
    let described = |r: Result<Option<String>, rustid_core::token::TokenError>| {
        let e = r.unwrap_err();
        (e.error.into_owned(), e.description)
    };
    assert_eq!(
        described(parse("resource=urn%3Aa&resource=urn%3Ab")),
        (
            "invalid_target".into(),
            Some("Multiple resource indicators not supported on token endpoint.".into())
        )
    );
    assert_eq!(
        described(parse("resource=not-a-uri")),
        (
            "invalid_target".into(),
            Some("Invalid resource indicator format".into())
        )
    );
    assert_eq!(
        described(parse("resource=https%3A%2F%2Fapi%23frag")),
        (
            "invalid_target".into(),
            Some("Invalid resource indicator format".into())
        )
    );
    let long = format!("resource=urn%3A{}", "a".repeat(600));
    assert_eq!(
        described(parse(&long)),
        (
            "invalid_target".into(),
            Some("Resource indicator maximum length exceeded".into())
        )
    );
}

mod support;

use chrono::Utc;
use rustid_core::authorize::code::AuthorizationCode;
use rustid_core::authorize::validate;
use rustid_core::jwt::Jws;
use rustid_core::params::Params;
use rustid_core::session::{SignIn, UserSession};
use rustid_core::token::{TokenFailure, TokenResponse, process};
use support::Fixture;

/// The fixture profile's clients and the given resources file.
fn fixture(resources: &str) -> Fixture {
    let mut f = Fixture::new();
    let dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/resource-indicators");
    f.clients = rustid_core::clients::Clients::load(&dir.join("clients.json")).unwrap();
    f.resources = Resources::load(&dir.join(resources)).unwrap();
    f.stores = rustid_store_memory::stores(f.clients.clone(), f.resources.clone());
    f
}

fn access(response: &TokenResponse) -> (Vec<String>, String) {
    let payload = Jws::decode(&response.access_token).unwrap().payload;
    let aud = match &payload["aud"] {
        serde_json::Value::String(a) => vec![a.clone()],
        serde_json::Value::Array(a) => a.iter().map(|v| v.as_str().unwrap().to_owned()).collect(),
        _ => Vec::new(),
    };
    (aud, response.scope.clone())
}

fn failure(result: Result<TokenResponse, TokenFailure>) -> (String, Option<String>) {
    match result {
        Err(TokenFailure::Protocol(e)) => (e.error.into_owned(), e.description),
        other => panic!("expected an error, got {other:?}"),
    }
}

/// A code for client1 with `scope` and `resources`, redeemed with an
/// optional `resource`.
async fn code_exchange(
    f: &Fixture,
    scope: &str,
    resources: &[&str],
    resource: Option<&str>,
) -> Result<TokenResponse, TokenFailure> {
    let now = Utc::now();
    let mut query = format!(
        "client_id=client1&redirect_uri=https%3A%2F%2Fclient1%2Fcallback&response_type=code&scope={}&state=s&nonce=n",
        scope.replace(' ', "%20")
    );
    for r in resources {
        query.push_str(&format!("&resource={}", rustid_core::params::url_encode(r)));
    }
    let session = UserSession::sign_in(
        SignIn {
            subject_id: "1".into(),
            ..Default::default()
        },
        None,
        now,
        3600,
    );
    let request = validate(
        &f.authorize_ctx(now),
        Params::parse_query(&query),
        Some(&session),
    )
    .await
    .unwrap();
    let code = AuthorizationCode::for_request(&request, now);
    let handle = code.store(f.stores.grants.as_ref()).await.unwrap();
    let mut pairs = vec![
        ("grant_type", "authorization_code"),
        ("client_id", "client1"),
        ("client_secret", "secret"),
        ("code", handle.as_str()),
        ("redirect_uri", "https://client1/callback"),
    ];
    if let Some(r) = resource {
        pairs.push(("resource", r));
    }
    process(&f.ctx(now), None, &Form::from_pairs(&pairs)).await
}

async fn refresh(
    f: &Fixture,
    token: &str,
    resource: Option<&str>,
) -> Result<TokenResponse, TokenFailure> {
    let mut pairs = vec![
        ("grant_type", "refresh_token"),
        ("client_id", "client1"),
        ("client_secret", "secret"),
        ("refresh_token", token),
    ];
    if let Some(r) = resource {
        pairs.push(("resource", r));
    }
    process(&f.ctx(Utc::now()), None, &Form::from_pairs(&pairs)).await
}

#[tokio::test]
async fn a_code_exchange_narrows_to_an_authorized_resource() {
    let f = fixture("authorize-resources.json");
    let scope = "openid scope1 scope2 scope3 offline_access";
    let wide = code_exchange(&f, scope, &["urn:resource1", "urn:resource3"], None)
        .await
        .unwrap();
    assert_eq!(
        access(&wide).0,
        ["urn:resource1", "urn:resource2"],
        "no isolated one unnamed"
    );
    assert!(wide.id_token.is_some());

    let narrow = code_exchange(
        &f,
        scope,
        &["urn:resource1", "urn:resource3"],
        Some("urn:resource3"),
    )
    .await
    .unwrap();
    assert_eq!(
        access(&narrow),
        (
            vec!["urn:resource3".to_owned()],
            "scope3 offline_access".to_owned()
        )
    );
    assert!(
        narrow.id_token.is_some(),
        "the id token doesn't depend on the indicator"
    );

    // Only what the authorize request named.
    assert_eq!(
        failure(code_exchange(&f, scope, &["urn:resource1"], Some("urn:resource2")).await),
        (
            "invalid_target".into(),
            Some("Resource indicator does not match any resource indicator in the original authorize request.".into())
        )
    );
}

#[tokio::test]
async fn refreshes_narrow_within_what_was_authorized() {
    let f = fixture("authorize-resources.json");
    let scope = "openid scope1 scope2 scope3 offline_access";
    let first = code_exchange(&f, scope, &["urn:resource1", "urn:resource3"], None)
        .await
        .unwrap();
    let token = first.refresh_token.clone().unwrap();
    let narrow = refresh(&f, &token, Some("urn:resource3")).await.unwrap();
    assert_eq!(
        access(&narrow),
        (
            vec!["urn:resource3".to_owned()],
            "scope3 offline_access".to_owned()
        )
    );
    let wide = refresh(&f, &token, None).await.unwrap();
    assert_eq!(access(&wide).0, ["urn:resource1", "urn:resource2"]);
    assert_eq!(
        failure(refresh(&f, &token, Some("urn:resource2")).await).0,
        "invalid_target",
        "not named at authorize"
    );

    // A code grant's refresh token keeps the authorize request's list,
    // even an empty one: naming any resource later is refused.
    let open = code_exchange(&f, scope, &[], None).await.unwrap();
    let token = open.refresh_token.unwrap();
    assert_eq!(
        failure(refresh(&f, &token, Some("urn:resource2")).await),
        ("invalid_target".into(), Some(NOT_NAMED.into()))
    );
}

const NOT_NAMED: &str =
    "Resource indicator does not match any resource indicator in the original authorize request.";

async fn client_credentials(
    f: &Fixture,
    extra: &[(&str, &str)],
) -> Result<TokenResponse, TokenFailure> {
    let mut pairs = vec![
        ("grant_type", "client_credentials"),
        ("client_id", "client"),
        ("client_secret", "secret"),
    ];
    pairs.extend_from_slice(extra);
    process(&f.ctx(Utc::now()), None, &Form::from_pairs(&pairs)).await
}

#[tokio::test]
async fn client_credentials_narrow_to_the_named_resource() {
    let f = fixture("token-resources.json");
    let all = client_credentials(&f, &[]).await.unwrap();
    assert_eq!(
        access(&all),
        (
            vec!["urn:api1".to_owned(), "urn:api2".to_owned()],
            "scope1 scope2 scope3 scope4".to_owned()
        )
    );
    let one = client_credentials(&f, &[("resource", "urn:api1")])
        .await
        .unwrap();
    assert_eq!(
        access(&one),
        (vec!["urn:api1".to_owned()], "scope1 scope3".to_owned())
    );
    let isolated = client_credentials(&f, &[("resource", "urn:api3")])
        .await
        .unwrap();
    assert_eq!(
        access(&isolated),
        (vec!["urn:api3".to_owned()], "scope1 scope3".to_owned())
    );
    let scoped = client_credentials(&f, &[("resource", "urn:api1"), ("scope", "scope1 scope2")])
        .await
        .unwrap();
    assert_eq!(
        access(&scoped),
        (vec!["urn:api1".to_owned()], "scope1".to_owned())
    );
    assert_eq!(
        failure(client_credentials(&f, &[("resource", "urn:api2"), ("scope", "scope1")]).await),
        ("invalid_target".into(), None),
        "no description for client credentials"
    );
    let empty = client_credentials(&f, &[("resource", "")]).await.unwrap();
    assert_eq!(access(&empty), access(&all), "an empty indicator is none");
}
