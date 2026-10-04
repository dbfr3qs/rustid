//! A custom token request validator: runs
//! after the standard validation, may refuse the request, and may add
//! fields to the response or the error.

mod support;

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use rustid_core::form::Form;
use rustid_core::profile::ProfileError;
use rustid_core::token::{TokenFailure, process};
use rustid_core::token_request::{TokenRequest, TokenRequestValidator, TokenRequestVerdict};
use serde_json::json;
use support::Fixture;

/// Refuses requests asking for `api2`; otherwise adds `custom`. Records
/// what it was asked.
struct Custom(Mutex<Vec<String>>);

#[async_trait]
impl TokenRequestValidator for Custom {
    async fn validate(&self, r: &TokenRequest<'_>) -> Result<TokenRequestVerdict, ProfileError> {
        let parameters: Vec<&str> = r.parameters.iter().map(|(k, _)| k.as_str()).collect();
        self.0.lock().unwrap().push(format!(
            "{} {} {:?} {} {}",
            r.grant_type,
            r.client.client_id,
            r.subject_id,
            r.scopes.join(" "),
            parameters.join(",")
        ));
        let mut custom = serde_json::Map::new();
        custom.insert("custom".into(), json!("custom"));
        custom.insert("access_token".into(), json!("overwritten?"));
        if r.scopes.iter().any(|s| s == "api2") {
            return Ok(TokenRequestVerdict::Reject {
                error: "invalid_scope".into(),
                description: Some("api2 is closed".into()),
                custom,
            });
        }
        Ok(TokenRequestVerdict::Accept { custom })
    }
}

fn fixture() -> (Fixture, Arc<Custom>) {
    let mut f = Fixture::new();
    let custom = Arc::new(Custom(Mutex::new(Vec::new())));
    f.stores.token_request = custom.clone();
    (f, custom)
}

fn client_credentials(scope: &str) -> Form {
    Form::from_pairs(&[
        ("grant_type", "client_credentials"),
        ("client_id", "client"),
        ("client_secret", "secret"),
        ("scope", scope),
    ])
}

#[tokio::test]
async fn an_accepted_request_carries_the_custom_fields() {
    let (f, custom) = fixture();
    let response = process(
        &f.ctx(chrono::Utc::now()),
        None,
        &client_credentials("api1"),
    )
    .await
    .unwrap();
    assert_eq!(response.custom["custom"], "custom");
    assert!(response.access_token.contains('.'), "the real access token");
    assert_eq!(
        custom.0.lock().unwrap().as_slice(),
        ["client_credentials client None api1 grant_type,client_id,scope"],
        "the secret is never sent"
    );
}

#[tokio::test]
async fn a_refused_request_is_an_error_with_the_custom_fields() {
    let (f, _) = fixture();
    match process(
        &f.ctx(chrono::Utc::now()),
        None,
        &client_credentials("api2"),
    )
    .await
    {
        Err(TokenFailure::Protocol(e)) => {
            assert_eq!(e.error, "invalid_scope");
            assert_eq!(e.description.as_deref(), Some("api2 is closed"));
            assert_eq!(e.custom["custom"], "custom");
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn standard_validation_runs_first() {
    let (f, custom) = fixture();
    let result = process(
        &f.ctx(chrono::Utc::now()),
        None,
        &client_credentials("nope"),
    )
    .await;
    assert!(
        matches!(result, Err(TokenFailure::Protocol(e)) if e.error == "invalid_scope" && e.custom.is_empty())
    );
    assert!(custom.0.lock().unwrap().is_empty());
}
