//! The password grant and extension grant hooks (the resource owner password validator,
//! the extension grant validator): what they are sent and how their answers
//! become grant results.

use std::path::Path;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::StatusCode;
use rustid_core::clients::{AccessTokenType, Client};
use rustid_core::grant_validation::{
    ExtensionRequest, GrantResult, GrantSubject, GrantValidator, PasswordRequest,
};
use rustid_core::key_service::KeyService;
use rustid_core::keys::{KeyConfig, KeyMaterial};
use rustid_core::options::TimeSpan;
use rustid_core::tokens::Claim;
use rustid_hooks::{FailurePolicy, HookConfig, Hooks, HooksConfig};
use serde_json::{Value, json};

type Seen = Arc<Mutex<Vec<Value>>>;

/// Answers `body` with `status` at `/hook`; its URL and what it was sent.
async fn receiver(status: StatusCode, body: Value) -> (String, Seen) {
    let seen: Seen = Arc::default();
    let log = seen.clone();
    let app = axum::Router::new()
        .route(
            "/hook",
            axum::routing::post(move |State(()): State<()>, request: String| {
                let log = log.clone();
                let body = body.clone();
                async move {
                    log.lock()
                        .unwrap()
                        .push(serde_json::from_str(&request).unwrap_or(Value::Null));
                    (status, body.to_string())
                }
            }),
        )
        .with_state(());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/hook", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await });
    (url, seen)
}

fn keys() -> KeyService {
    let key = KeyConfig {
        kid: "k1".into(),
        alg: "RS256".into(),
        key_file: Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/signing-key.pem"),
        cert_file: None,
    };
    KeyService::new(KeyMaterial::load(&[key], &[]).unwrap(), None)
}

fn hook(url: &str) -> HookConfig {
    HookConfig {
        url: url.parse().unwrap(),
        timeout: TimeSpan(1),
        failure_policy: FailurePolicy::FailClosed,
        cache_duration: TimeSpan(0),
    }
}

fn build(config: HooksConfig) -> Hooks {
    Hooks::new(config, keys(), "https://idsrv.test".into()).unwrap()
}

fn client() -> Client {
    Client {
        client_id: "roclient".into(),
        ..Default::default()
    }
}

async fn password(
    hooks: &Hooks,
) -> Result<rustid_core::grant_validation::GrantAnswer, rustid_core::profile::ProfileError> {
    let client = client();
    let parameters = vec![("scope".to_owned(), "api1".to_owned())];
    hooks
        .validate_password(&PasswordRequest {
            client: &client,
            username: "bob",
            password: "p@ss",
            parameters: &parameters,
        })
        .await
}

#[tokio::test]
async fn the_password_hook_gets_the_credentials_and_answers_a_subject() {
    let (url, seen) = receiver(
        StatusCode::OK,
        json!({
            "version": 1,
            "subject": {
                "sub": "bob",
                "amr": "pwd",
                "claims": [
                    { "type": "name", "value": "Bob" },
                    { "type": "age", "value": "42", "value_type": "http://www.w3.org/2001/XMLSchema#integer" },
                ],
            },
            "custom_response": { "int_value": 42 },
        }),
    )
    .await;
    let hooks = build(HooksConfig {
        password_grant: Some(hook(&url)),
        ..Default::default()
    });
    assert!(hooks.supports_password());
    let answer = password(&hooks).await.unwrap();
    assert_eq!(
        answer.result,
        GrantResult::Subject(GrantSubject {
            subject_id: "bob".into(),
            authentication_method: "pwd".into(),
            idp: None,
            claims: vec![
                Claim::string("name", "Bob"),
                Claim {
                    claim_type: "age".into(),
                    value: "42".into(),
                    value_type: "http://www.w3.org/2001/XMLSchema#integer".into(),
                },
            ],
        })
    );
    assert_eq!(answer.custom["int_value"], 42);
    let body = seen.lock().unwrap()[0].clone();
    assert_eq!(body["version"], 1);
    assert_eq!(body["client_id"], "roclient");
    assert_eq!(body["username"], "bob");
    assert_eq!(body["password"], "p@ss");
    assert_eq!(body["parameters"], json!({ "scope": "api1" }));
}

#[tokio::test]
async fn errors_and_failures() {
    let (url, _) = receiver(
        StatusCode::OK,
        json!({ "version": 1, "error": "invalid_grant", "error_description": "bad" }),
    )
    .await;
    let hooks = build(HooksConfig {
        password_grant: Some(hook(&url)),
        ..Default::default()
    });
    assert_eq!(
        password(&hooks).await.unwrap().result,
        GrantResult::Error {
            error: Some("invalid_grant".into()),
            description: Some("bad".into())
        }
    );

    // A failing hook fails the request, whatever the policy: a grant can't
    // be let through without its validator.
    let (url, _) = receiver(StatusCode::INTERNAL_SERVER_ERROR, json!({})).await;
    for policy in [FailurePolicy::FailClosed, FailurePolicy::FailOpen] {
        let hooks = build(HooksConfig {
            password_grant: Some(HookConfig {
                failure_policy: policy,
                ..hook(&url)
            }),
            ..Default::default()
        });
        assert!(password(&hooks).await.is_err(), "{policy:?}");
    }

    // Without the hook, the grant is unsupported.
    let none = build(HooksConfig::default());
    assert!(!none.supports_password());
    assert_eq!(
        password(&none).await.unwrap().result,
        GrantResult::Error {
            error: Some("unsupported_grant_type".into()),
            description: None
        }
    );
}

#[tokio::test]
async fn extension_hooks_are_per_grant_type_and_may_change_the_request() {
    let (url, seen) = receiver(
        StatusCode::OK,
        json!({
            "version": 1,
            "client_id": "impersonated",
            "access_token_lifetime": 5000,
            "access_token_type": "reference",
            "client_claims": [{ "type": "extra", "value": "x" }],
        }),
    )
    .await;
    let hooks = build(HooksConfig {
        extension_grants: [("dynamic".to_owned(), hook(&url))].into_iter().collect(),
        ..Default::default()
    });
    assert_eq!(hooks.extension_grant_types(), ["dynamic"]);
    let client = client();
    let parameters = vec![("sub".to_owned(), "1".to_owned())];
    let answer = hooks
        .validate_extension(&ExtensionRequest {
            grant_type: "dynamic",
            client: &client,
            parameters: &parameters,
        })
        .await
        .unwrap();
    assert_eq!(answer.result, GrantResult::NoSubject);
    assert_eq!(answer.changes.client_id.as_deref(), Some("impersonated"));
    assert_eq!(answer.changes.access_token_lifetime, Some(5000));
    assert_eq!(
        answer.changes.access_token_type,
        Some(AccessTokenType::Reference)
    );
    assert_eq!(answer.changes.client_claims, [Claim::string("extra", "x")]);
    let body = seen.lock().unwrap()[0].clone();
    assert_eq!(body["grant_type"], "dynamic");
    assert_eq!(body["parameters"], json!({ "sub": "1" }));

    // A type without a hook is unsupported.
    let other = hooks
        .validate_extension(&ExtensionRequest {
            grant_type: "other",
            client: &client,
            parameters: &parameters,
        })
        .await
        .unwrap();
    assert!(matches!(other.result, GrantResult::Error { .. }));
}

#[tokio::test]
async fn a_subject_needs_an_authentication_method() {
    for amr in [json!(null), json!(""), json!(" ")] {
        let (url, _) = receiver(
            StatusCode::OK,
            json!({ "version": 1, "subject": { "sub": "bob", "amr": amr } }),
        )
        .await;
        let hooks = build(HooksConfig {
            password_grant: Some(hook(&url)),
            ..Default::default()
        });
        assert!(password(&hooks).await.is_err(), "amr {amr}");
    }
}
