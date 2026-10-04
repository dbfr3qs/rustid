//! The events and request details the protocol flows raise.

mod support;

use chrono::Utc;
use rustid_core::events::EventDetails;
use rustid_core::form::Form;
use serde_json::json;
use support::Fixture;

fn cc<'a>(client: &'a str, scope: &'a str) -> Vec<(&'a str, &'a str)> {
    vec![
        ("grant_type", "client_credentials"),
        ("client_id", client),
        ("client_secret", "secret"),
        ("scope", scope),
    ]
}

async fn token(f: &Fixture, form: &[(&str, &str)]) {
    let _ = rustid_core::token::process(&f.ctx(Utc::now()), None, &Form::from_pairs(form)).await;
}

#[tokio::test]
async fn issuing_a_token_raises_authentication_and_issued_events() {
    let f = Fixture::new();
    token(&f, &cc("client", "api1")).await;
    let events = f.events.take();
    let names: Vec<&str> = events.iter().map(|e| e.name).collect();
    assert_eq!(
        names,
        ["Client Authentication Success", "Token Issued Success"]
    );
    assert_eq!(
        events[0].remote_ip_address.as_deref(),
        Some("10.0.0.7:50000")
    );
    let issued = serde_json::to_value(&events[1]).unwrap();
    assert_eq!(issued["ClientId"], "client");
    assert_eq!(issued["Endpoint"], "Token");
    assert_eq!(issued["GrantType"], "client_credentials");
    assert_eq!(issued["Scopes"], "api1");
    assert_eq!(issued["Tokens"][0]["TokenType"], "access_token");
    assert!(
        issued["Tokens"][0]["TokenValue"]
            .as_str()
            .unwrap()
            .starts_with("****")
    );
    let auth = serde_json::to_value(&events[0]).unwrap();
    assert_eq!(auth["AuthenticationMethod"], "SharedSecret");
}

#[tokio::test]
async fn failures_name_their_cause() {
    let f = Fixture::new();
    token(
        &f,
        &[
            ("grant_type", "client_credentials"),
            ("client_id", "client"),
            ("client_secret", "wrong"),
        ],
    )
    .await;
    let events = f.events.take();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].name, "Client Authentication Failure");
    assert_eq!(events[0].message.as_deref(), Some("Invalid client secret"));

    token(&f, &[("grant_type", "client_credentials")]).await;
    let events = f.events.take();
    assert_eq!(events[0].message.as_deref(), Some("No client id found"));
    assert_eq!(
        serde_json::to_value(&events[0]).unwrap()["ClientId"],
        "unknown"
    );

    token(&f, &cc("client", "nope")).await;
    let events = f.events.take();
    assert_eq!(events[1].name, "Token Issued Failure");
    let EventDetails::TokenIssuedFailure {
        error,
        scopes,
        grant_type,
        ..
    } = &events[1].details
    else {
        panic!("{:?}", events[1]);
    };
    assert_eq!(
        (error.as_str(), scopes.as_deref(), grant_type.as_deref()),
        ("invalid_scope", Some("nope"), Some("client_credentials"))
    );
}

#[tokio::test]
async fn an_invalid_client_configuration_is_reported_then_treated_as_unknown() {
    let f = Fixture::new();
    token(
        &f,
        &[
            ("grant_type", "client_credentials"),
            ("client_id", "client.no_secret"),
        ],
    )
    .await;
    let events = f.events.take();
    let names: Vec<&str> = events.iter().map(|e| e.name).collect();
    assert_eq!(
        names,
        [
            "Invalid Client Configuration",
            "Client Authentication Failure"
        ]
    );
    assert_eq!(events[1].message.as_deref(), Some("Unknown client"));
}

async fn introspect(f: &Fixture, caller: &str, form: &[(&str, &str)]) {
    use base64::Engine;
    let basic = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{caller}:secret"))
    );
    rustid_core::introspection::process(&f.ctx(Utc::now()), Some(&basic), &Form::from_pairs(form))
        .await
        .unwrap();
}

#[tokio::test]
async fn introspection_events_follow_the_caller_and_outcome() {
    let f = Fixture::new();
    let jwt = f.issue("client", "api1 other_api", Utc::now()).await;
    f.events.take();

    introspect(&f, "api", &[("token", &jwt)]).await;
    let events = f.events.take();
    let names: Vec<&str> = events.iter().map(|e| e.name).collect();
    assert_eq!(
        names,
        ["API Authentication Success", "Token Introspection Success"]
    );
    let success = serde_json::to_value(&events[1]).unwrap();
    assert_eq!(success["ApiName"], "api");
    assert_eq!(success["IsActive"], true);
    assert_eq!(success["TokenScopes"], json!(["api1", "other_api"]));
    assert!(
        success["ClaimTypes"]
            .as_array()
            .unwrap()
            .contains(&json!("client_id"))
    );
    assert!(success["Token"].as_str().unwrap().starts_with("****"));

    // A client caller is first tried, and fails, as an API.
    introspect(&f, "client", &[("token", &jwt)]).await;
    let events = f.events.take();
    let names: Vec<&str> = events.iter().map(|e| e.name).collect();
    assert_eq!(
        names,
        [
            "API Authentication Failure",
            "Client Authentication Success",
            "Token Introspection Success"
        ]
    );
    assert_eq!(events[0].message.as_deref(), Some("Unknown API resource"));

    introspect(&f, "api", &[]).await;
    let events = f.events.take();
    assert_eq!(events[1].name, "Token Introspection Failure");
    assert_eq!(events[1].message.as_deref(), Some("missing_token"));

    let other = f.issue("client", "other_api", Utc::now()).await;
    f.events.take();
    introspect(&f, "api", &[("token", &other)]).await;
    let events = f.events.take();
    assert_eq!(events[1].name, "Token Introspection Failure");
    assert_eq!(
        events[1].message.as_deref(),
        Some("Expected scopes are missing")
    );
    let failure = serde_json::to_value(&events[1]).unwrap();
    assert_eq!(failure["ApiScopes"], json!(["api1", "api2"]));
    assert_eq!(failure["TokenScopes"], json!(["other_api"]));

    introspect(&f, "api", &[("token", "garbage")]).await;
    let events = f.events.take();
    assert_eq!(serde_json::to_value(&events[1]).unwrap()["IsActive"], false);
}

#[tokio::test]
async fn revocation_raises_an_event_only_when_a_token_is_found() {
    let f = Fixture::new();
    let handle = f.issue("client.reference", "api1", Utc::now()).await;
    f.events.take();
    let revoke = |token: String, hint: Option<&'static str>| {
        let mut form = vec![
            ("client_id".to_owned(), "client.reference".to_owned()),
            ("client_secret".to_owned(), "secret".to_owned()),
            ("token".to_owned(), token),
        ];
        if let Some(hint) = hint {
            form.push(("token_type_hint".to_owned(), hint.to_owned()));
        }
        form
    };
    for (token, hint, expected) in [
        (
            handle.clone(),
            Some("access_token"),
            vec!["Client Authentication Success", "Token Revoked Success"],
        ),
        (
            "unknown".to_owned(),
            None,
            vec!["Client Authentication Success"],
        ),
    ] {
        let form = revoke(token, hint);
        let pairs: Vec<(&str, &str)> = form.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        rustid_core::revocation::process(&f.ctx(Utc::now()), None, &Form::from_pairs(&pairs))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(f.events.names(), expected);
    }
}
