//! The CIBA hooks (the backchannel authentication user validator,
//! the backchannel authentication user notification service,
//! the custom backchannel authentication validator): what they are sent and how
//! their answers become results.

use std::path::Path;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::StatusCode;
use rustid_core::ciba::{
    CibaCustomAnswer, CibaCustomRequest, CibaNotification, CibaService, CibaUserRequest,
    CibaUserResult,
};
use rustid_core::clients::Client;
use rustid_core::key_service::KeyService;
use rustid_core::keys::{KeyConfig, KeyMaterial};
use rustid_core::options::TimeSpan;
use rustid_core::tokens::Claim;
use rustid_hooks::{FailurePolicy, HookConfig, Hooks, HooksConfig};
use serde_json::{Map, Value, json};

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
        client_id: "ciba".into(),
        ..Default::default()
    }
}

async fn validate_user(
    hooks: &Hooks,
) -> Result<CibaUserResult, rustid_core::profile::ProfileError> {
    let client = client();
    let mut hint_claims = Map::new();
    hint_claims.insert("sub".into(), json!("alice"));
    hooks
        .validate_user(&CibaUserRequest {
            client: &client,
            login_hint: Some("alice"),
            login_hint_token: None,
            id_token_hint: Some("eyJ.x.y"),
            id_token_hint_claims: Some(&hint_claims),
            user_code: Some("1234"),
            binding_message: Some("msg"),
        })
        .await
}

async fn validate_request(
    hooks: &Hooks,
) -> Result<CibaCustomAnswer, rustid_core::profile::ProfileError> {
    let client = client();
    let parameters: Vec<(String, String)> = [
        ("scope", "openid api1"),
        ("custom", "value"),
        ("client_secret", "secret"),
        ("client_assertion", "jwt"),
        ("client_assertion_type", "urn:x"),
        ("request", "jwt"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v.to_owned()))
    .collect();
    let scopes = vec!["openid".to_owned(), "api1".to_owned()];
    hooks
        .validate_request(&CibaCustomRequest {
            client: &client,
            parameters: &parameters,
            subject_id: "alice",
            scopes: &scopes,
            binding_message: Some("msg"),
        })
        .await
}

async fn notify(hooks: &Hooks) -> Result<(), rustid_core::profile::ProfileError> {
    let client = client();
    let scopes = vec!["openid".to_owned()];
    let indicators = vec!["urn:api1".to_owned()];
    let acr = vec!["mfa".to_owned()];
    let mut properties = Map::new();
    properties.insert("custom".into(), json!("value"));
    hooks
        .notify_user(&CibaNotification {
            internal_id: "internal",
            subject_id: "alice",
            client: &client,
            scopes: &scopes,
            resource_indicators: &indicators,
            binding_message: Some("msg"),
            acr_values: &acr,
            tenant: Some("t1"),
            idp: None,
            properties: &properties,
        })
        .await
}

#[tokio::test]
async fn the_user_hook_gets_the_hints_and_answers_a_subject() {
    let (url, seen) = receiver(
        StatusCode::OK,
        json!({
            "version": 1,
            "subject": {
                "sub": "alice",
                "claims": [{ "type": "name", "value": "Alice" }],
            },
        }),
    )
    .await;
    let hooks = build(HooksConfig {
        ciba_user: Some(hook(&url)),
        ..Default::default()
    });
    assert!(!hooks.is_empty());
    assert_eq!(
        validate_user(&hooks).await.unwrap(),
        CibaUserResult::Subject {
            subject_id: Some("alice".into()),
            claims: vec![Claim::string("name", "Alice")],
        }
    );
    let body = seen.lock().unwrap()[0].clone();
    assert_eq!(body["version"], 1);
    assert_eq!(body["client_id"], "ciba");
    assert_eq!(body["login_hint"], "alice");
    assert_eq!(body["login_hint_token"], Value::Null);
    assert_eq!(body["id_token_hint"], "eyJ.x.y");
    assert_eq!(body["id_token_hint_claims"], json!({ "sub": "alice" }));
    assert_eq!(body["user_code"], "1234");
    assert_eq!(body["binding_message"], "msg");
}

#[tokio::test]
async fn the_user_hook_may_refuse_or_name_no_one() {
    let (url, _) = receiver(
        StatusCode::OK,
        json!({ "version": 1, "error": "unknown_user_id", "error_description": "who?" }),
    )
    .await;
    let hooks = build(HooksConfig {
        ciba_user: Some(hook(&url)),
        ..Default::default()
    });
    assert_eq!(
        validate_user(&hooks).await.unwrap(),
        CibaUserResult::Error {
            error: "unknown_user_id".into(),
            description: Some("who?".into()),
        }
    );

    // A subject without `sub`, or no answer at all, names no one; the
    // endpoint turns that into `unknown_user_id`.
    for answer in [
        json!({ "version": 1, "subject": { "claims": [] } }),
        json!({ "version": 1 }),
    ] {
        let (url, _) = receiver(StatusCode::OK, answer.clone()).await;
        let hooks = build(HooksConfig {
            ciba_user: Some(hook(&url)),
            ..Default::default()
        });
        assert_eq!(
            validate_user(&hooks).await.unwrap(),
            CibaUserResult::Subject {
                subject_id: None,
                claims: vec![]
            },
            "{answer}"
        );
    }
}

#[tokio::test]
async fn the_request_hook_gets_the_parameters_without_credentials() {
    let (url, seen) = receiver(
        StatusCode::OK,
        json!({ "version": 1, "properties": { "custom": "value" } }),
    )
    .await;
    let hooks = build(HooksConfig {
        ciba_request: Some(hook(&url)),
        ..Default::default()
    });
    let answer = validate_request(&hooks).await.unwrap();
    assert_eq!(answer.error, None);
    assert_eq!(answer.properties["custom"], "value");
    let body = seen.lock().unwrap()[0].clone();
    assert_eq!(body["version"], 1);
    assert_eq!(body["client_id"], "ciba");
    assert_eq!(body["subject_id"], "alice");
    assert_eq!(body["scopes"], json!(["openid", "api1"]));
    assert_eq!(body["binding_message"], "msg");
    assert_eq!(
        body["parameters"],
        json!({ "scope": "openid api1", "custom": "value" })
    );

    let (url, _) = receiver(StatusCode::OK, json!({ "version": 1, "error": "no" })).await;
    let hooks = build(HooksConfig {
        ciba_request: Some(hook(&url)),
        ..Default::default()
    });
    assert_eq!(
        validate_request(&hooks).await.unwrap().error.as_deref(),
        Some("no")
    );
}

#[tokio::test]
async fn the_notification_hook_gets_the_login_request() {
    let (url, seen) = receiver(StatusCode::OK, json!({ "version": 1 })).await;
    let hooks = build(HooksConfig {
        ciba_notification: Some(hook(&url)),
        ..Default::default()
    });
    notify(&hooks).await.unwrap();
    let body = seen.lock().unwrap()[0].clone();
    assert_eq!(
        body,
        json!({
            "version": 1,
            "internal_id": "internal",
            "subject_id": "alice",
            "client_id": "ciba",
            "scopes": ["openid"],
            "resource_indicators": ["urn:api1"],
            "binding_message": "msg",
            "acr_values": ["mfa"],
            "tenant": "t1",
            "idp": null,
            "properties": { "custom": "value" },
        })
    );
}

#[tokio::test]
async fn failures_fail_the_request_whatever_the_policy() {
    let (url, _) = receiver(StatusCode::INTERNAL_SERVER_ERROR, json!({})).await;
    for policy in [FailurePolicy::FailClosed, FailurePolicy::FailOpen] {
        let failing = HookConfig {
            failure_policy: policy,
            ..hook(&url)
        };
        let hooks = build(HooksConfig {
            ciba_user: Some(failing.clone()),
            ciba_notification: Some(failing.clone()),
            ciba_request: Some(failing),
            ..Default::default()
        });
        assert!(validate_user(&hooks).await.is_err(), "{policy:?}");
        assert!(notify(&hooks).await.is_err(), "{policy:?}");
        assert!(validate_request(&hooks).await.is_err(), "{policy:?}");
    }

    // Unreadable answers fail too.
    for answer in [
        json!({ "version": 1, "subject": { "sub": "alice", "claims": "x" } }),
        json!({ "version": 1, "error": 7 }),
    ] {
        let (url, _) = receiver(StatusCode::OK, answer.clone()).await;
        let hooks = build(HooksConfig {
            ciba_user: Some(hook(&url)),
            ..Default::default()
        });
        assert!(validate_user(&hooks).await.is_err(), "{answer}");
    }
    let (url, _) = receiver(StatusCode::OK, json!({ "version": 1, "properties": [] })).await;
    let hooks = build(HooksConfig {
        ciba_request: Some(hook(&url)),
        ..Default::default()
    });
    assert!(validate_request(&hooks).await.is_err());
}

#[tokio::test]
async fn without_hooks_the_defaults_apply() {
    let hooks = build(HooksConfig::default());
    assert_eq!(
        validate_user(&hooks).await.unwrap(),
        CibaUserResult::Error {
            error: "not implemented".into(),
            description: None
        }
    );
    notify(&hooks).await.unwrap();
    assert_eq!(
        validate_request(&hooks).await.unwrap(),
        CibaCustomAnswer::default()
    );
    assert!(!hooks.has_ciba());
    let (url, _) = receiver(StatusCode::OK, json!({ "version": 1 })).await;
    assert!(
        build(HooksConfig {
            ciba_notification: Some(hook(&url)),
            ..Default::default()
        })
        .has_ciba()
    );
}
