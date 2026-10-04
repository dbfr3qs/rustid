mod support;

use chrono::{TimeZone, Utc};
use rustid_core::form::Form;
use rustid_core::introspection::{Introspection, jwt_response, process};
use rustid_core::jwt::Jws;
use serde_json::{Value, json};
use support::{Fixture, ISSUER};

fn now() -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(1_800_000_000, 0).unwrap()
}

fn basic(id: &str) -> String {
    use base64::Engine;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{id}:secret"))
    )
}

async fn introspect(f: &Fixture, caller: &str, form: &[(&str, &str)]) -> Introspection {
    process(&f.ctx(now()), Some(&basic(caller)), &Form::from_pairs(form))
        .await
        .unwrap()
}

fn entries(result: Introspection) -> Value {
    match result {
        Introspection::Response { entries, .. } => Value::Object(entries),
        other => panic!("expected a response, got {other:?}"),
    }
}

#[tokio::test]
async fn an_api_sees_its_own_scopes_only() {
    let f = Fixture::new();
    let token = f.issue("client", "api1 other_api", now()).await;
    let mut body = entries(introspect(&f, "api", &[("token", &token)]).await);
    body["jti"] = json!("<jti>");
    assert_eq!(
        body,
        json!({"iss": ISSUER, "nbf": 1800000000, "iat": 1800000000, "exp": 1800003600,
               "aud": ["api1-resource", "api", "other_api"], "client_id": "client",
               "jti": "<jti>", "active": true, "scope": "api1"})
    );
    let other = f.issue("client", "other_api", now()).await;
    assert_eq!(
        entries(introspect(&f, "api", &[("token", &other)]).await),
        json!({"active": false})
    );
}

#[tokio::test]
async fn a_client_sees_its_own_tokens_only() {
    let f = Fixture::new();
    let own = f.issue("client.reference", "api1", now()).await;
    let mut body = entries(introspect(&f, "client.reference", &[("token", &own)]).await);
    body["jti"] = json!("<jti>");
    assert_eq!(
        body,
        json!({"iss": ISSUER, "nbf": 1800000000, "iat": 1800000000, "exp": 1800003600,
               "aud": ["api1-resource", "api"], "client_id": "client.reference",
               "client_role": "service", "client_count": 7, "jti": "<jti>",
               "token_type": "access_token", "active": true, "scope": "api1"})
    );
    // An unsupported hint is ignored; refresh_token falls back to access tokens.
    for hint in ["refresh_token", "bogus"] {
        let body = entries(
            introspect(
                &f,
                "client.reference",
                &[("token", &own), ("token_type_hint", hint)],
            )
            .await,
        );
        assert_eq!(body["active"], json!(true), "{hint}");
    }
    assert_eq!(
        entries(introspect(&f, "client", &[("token", &own)]).await),
        json!({"active": false})
    );
}

#[tokio::test]
async fn typed_client_claims_keep_their_json_types() {
    let f = Fixture::new();
    let token = f.issue("client.claims", "api1", now()).await;
    let body = entries(introspect(&f, "api", &[("token", &token)]).await);
    assert_eq!(body["client_role"], json!(["service", "batch"]));
    assert_eq!(body["client_flag"], json!(true));
    assert_eq!(body["client_count"], json!(42));
    assert_eq!(body["client_obj"], json!({"a": 1, "b": [true]}));
}

#[tokio::test]
async fn request_errors() {
    let f = Fixture::new();
    assert_eq!(
        introspect(&f, "api", &[]).await,
        Introspection::Invalid("missing_token")
    );
    assert_eq!(
        introspect(&f, "api", &[("token", " ")]).await,
        Introspection::Invalid("missing_token")
    );
    assert_eq!(
        entries(introspect(&f, "api", &[("token", "garbage")]).await),
        json!({"active": false})
    );
    for caller in ["nobody", "api.disabled", "other_api", "client.disabled"] {
        assert_eq!(
            introspect(&f, caller, &[("token", "x")]).await,
            Introspection::Unauthorized,
            "{caller}"
        );
    }
    assert_eq!(
        process(&f.ctx(now()), None, &Form::from_pairs(&[("token", "x")]))
            .await
            .unwrap(),
        Introspection::Unauthorized
    );
}

#[tokio::test]
async fn jwt_responses_wrap_the_entries() {
    let f = Fixture::new();
    let entries = json!({"active": false}).as_object().unwrap().clone();
    let jwt = jwt_response(&f.ctx(now()), &entries, "api").await.unwrap();
    let jws = Jws::decode(&jwt).unwrap();
    assert_eq!(jws.header_str("typ"), Some("token-introspection+jwt"));
    assert_eq!(jws.header_str("kid"), Some("fixture-rsa-1"));
    assert_eq!(
        Value::Object(jws.payload),
        json!({"iss": ISSUER, "iat": 1800000000, "aud": "api",
               "token_introspection": {"active": false}})
    );
}

#[tokio::test]
async fn api_credentials_take_precedence_over_a_client_of_the_same_name() {
    let mut f = Fixture::new();
    f.edit_clients(|clients| {
        let mut twin = clients
            .iter()
            .find(|c| c.client_id == "client")
            .unwrap()
            .clone();
        twin.client_id = "api".into();
        clients.push(twin);
    });
    let token = f.issue("client", "api1", now()).await;
    let body = entries(introspect(&f, "api", &[("token", &token)]).await);
    assert_eq!(body["active"], json!(true));
    assert!(
        body.get("token_type").is_none(),
        "answered as the API: {body}"
    );
}
