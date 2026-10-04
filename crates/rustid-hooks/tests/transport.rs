//! The hook transport against a receiver on the loopback interface: request
//! shape and authentication, failures under both policies, and caching.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use rustid_core::clients::Client;
use rustid_core::key_service::KeyService;
use rustid_core::keys::{KeyConfig, KeyMaterial};
use rustid_core::options::TimeSpan;
use rustid_core::profile::{ActiveRequest, ProfileRequest, ProfileService};
use rustid_core::tokens::Claim;
use rustid_hooks::{FailurePolicy, HookConfig, Hooks, HooksConfig};

/// What the receiver answers, and what it was sent.
#[derive(Clone)]
struct Receiver {
    status: StatusCode,
    body: String,
    delay: Duration,
    seen: Arc<Mutex<Vec<(HeaderMap, serde_json::Value)>>>,
}

async fn answer(State(r): State<Receiver>, headers: HeaderMap, body: String) -> impl IntoResponse {
    let json = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    r.seen.lock().unwrap().push((headers, json));
    tokio::time::sleep(r.delay).await;
    (r.status, r.body.clone())
}

/// Serves `body` with `status` at `/hook`; returns its URL and what it saw.
async fn receiver(
    status: StatusCode,
    body: &str,
    delay: Duration,
) -> (String, Arc<Mutex<Vec<(HeaderMap, serde_json::Value)>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let state = Receiver {
        status,
        body: body.to_owned(),
        delay,
        seen: seen.clone(),
    };
    let app = axum::Router::new()
        .route("/hook", axum::routing::post(answer))
        .with_state(state);
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

fn hook(url: &str, policy: FailurePolicy, cache: i64) -> HookConfig {
    HookConfig {
        url: url.parse().unwrap(),
        timeout: TimeSpan(1),
        failure_policy: policy,
        cache_duration: TimeSpan(cache),
    }
}

fn hooks(profile: Option<HookConfig>, active: Option<HookConfig>) -> Hooks {
    Hooks::new(
        HooksConfig {
            profile_claims: profile,
            subject_active: active,
            ..Default::default()
        },
        keys(),
        "https://idsrv.test".into(),
    )
    .unwrap()
}

fn client(id: &str) -> Client {
    Client {
        client_id: id.into(),
        ..Default::default()
    }
}

fn subject_claims() -> Vec<Claim> {
    vec![
        Claim::string("name", "Alice"),
        Claim::string("role", "admin"),
    ]
}

async fn profile(
    hooks: &Hooks,
    caller: &str,
    client_id: &str,
    requested: &[&str],
) -> Result<Vec<Claim>, rustid_core::profile::ProfileError> {
    let requested: Vec<String> = requested.iter().map(|s| (*s).to_owned()).collect();
    let claims = subject_claims();
    let client = client(client_id);
    hooks
        .profile_claims(&ProfileRequest {
            caller,
            client: &client,
            subject_id: "1",
            subject_claims: &claims,
            requested_claim_types: &requested,
        })
        .await
}

async fn active(hooks: &Hooks) -> Result<bool, rustid_core::profile::ProfileError> {
    let claims = subject_claims();
    let client = client("web");
    hooks
        .is_active(&ActiveRequest {
            caller: "AuthorizeEndpoint",
            client: &client,
            subject_id: "1",
            subject_claims: &claims,
        })
        .await
}

fn types(claims: &[Claim]) -> Vec<String> {
    claims
        .iter()
        .map(|c| format!("{}={}", c.claim_type, c.value))
        .collect()
}

#[tokio::test]
async fn the_profile_hook_gets_a_signed_request_and_its_claims_are_filtered() {
    let (url, seen) = receiver(
        StatusCode::OK,
        r#"{"version":1,"claims":[{"type":"foo","value":"bar"},{"type":"other","value":"x"},{"type":"n","value":"1","value_type":"http://www.w3.org/2001/XMLSchema#integer"}]}"#,
        Duration::ZERO,
    )
    .await;
    let hooks = hooks(Some(hook(&url, FailurePolicy::FailClosed, 0)), None);
    let claims = profile(&hooks, "ClaimsProviderIdentityToken", "web", &["foo", "n"])
        .await
        .unwrap();
    assert_eq!(types(&claims), ["foo=bar", "n=1"], "only requested types");
    assert_eq!(
        claims[1].value_type,
        "http://www.w3.org/2001/XMLSchema#integer"
    );

    let seen = seen.lock().unwrap().clone();
    let (headers, body) = &seen[0];
    assert_eq!(
        body,
        &serde_json::json!({
            "version": 1,
            "caller": "ClaimsProviderIdentityToken",
            "client_id": "web",
            "subject": {
                "sub": "1",
                "claims": [
                    { "type": "name", "value": "Alice", "value_type": "http://www.w3.org/2001/XMLSchema#string" },
                    { "type": "role", "value": "admin", "value_type": "http://www.w3.org/2001/XMLSchema#string" },
                ],
            },
            "requested_claim_types": ["foo", "n"],
        })
    );
    assert_eq!(headers["content-type"], "application/json");
    let bearer = headers["authorization"].to_str().unwrap();
    let jwt = bearer.strip_prefix("Bearer ").unwrap();
    let jws = rustid_core::jwt::Jws::decode(jwt).unwrap();
    let key = keys().signing_key(&[]).await.unwrap().unwrap();
    assert!(
        jws.verify(&key.public_jwk()),
        "signed with the server's key"
    );
    assert_eq!(jws.header_str("kid"), Some("k1"));
    assert_eq!(jws.claim_str("iss"), Some("https://idsrv.test"));
    assert_eq!(jws.claim_str("aud"), Some(url.as_str()));
    let iat = jws.claim_i64("iat").unwrap();
    assert_eq!(jws.claim_i64("exp").unwrap() - iat, 60);
    assert!(jws.claim_str("jti").is_some());
}

#[tokio::test]
async fn the_active_hook_decides_activity() {
    let (url, seen) = receiver(
        StatusCode::OK,
        r#"{"version":1,"active":false}"#,
        Duration::ZERO,
    )
    .await;
    let hooks = hooks(None, Some(hook(&url, FailurePolicy::FailClosed, 0)));
    assert_eq!(active(&hooks).await, Ok(false));
    let body = seen.lock().unwrap()[0].1.clone();
    assert_eq!(body["caller"], "AuthorizeEndpoint");
    assert_eq!(body["subject"]["sub"], "1");
    assert!(body.get("requested_claim_types").is_none());
}

#[tokio::test]
async fn without_hooks_the_default_profile_service_answers() {
    let hooks = hooks(None, None);
    let claims = profile(&hooks, "ClaimsProviderAccessToken", "web", &["role"])
        .await
        .unwrap();
    assert_eq!(types(&claims), ["role=admin"]);
    assert_eq!(active(&hooks).await, Ok(true));
}

#[tokio::test]
async fn failures_are_errors_when_closed_and_defaults_when_open() {
    for (status, body, delay) in [
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            r#"{"version":1,"active":true}"#,
            Duration::ZERO,
        ),
        (StatusCode::OK, "not json", Duration::ZERO),
        (
            StatusCode::OK,
            r#"{"version":2,"active":true,"claims":[]}"#,
            Duration::ZERO,
        ),
        (
            StatusCode::OK,
            r#"{"version":1,"active":true,"claims":[]}"#,
            Duration::from_secs(3),
        ),
    ] {
        let (url, _) = receiver(status, body, delay).await;
        let closed = hooks(
            Some(hook(&url, FailurePolicy::FailClosed, 0)),
            Some(hook(&url, FailurePolicy::FailClosed, 0)),
        );
        assert!(
            profile(&closed, "ClaimsProviderAccessToken", "web", &["role"])
                .await
                .is_err(),
            "{status} {body}"
        );
        assert!(active(&closed).await.is_err(), "{status} {body}");

        let open = hooks(
            Some(hook(&url, FailurePolicy::FailOpen, 0)),
            Some(hook(&url, FailurePolicy::FailOpen, 0)),
        );
        let claims = profile(&open, "ClaimsProviderAccessToken", "web", &["role"])
            .await
            .unwrap();
        assert_eq!(
            types(&claims),
            ["role=admin"],
            "the default profile service"
        );
        assert_eq!(active(&open).await, Ok(true));
    }
}

#[tokio::test]
async fn answers_are_cached_per_caller_client_subject_and_requested_types() {
    let (url, seen) = receiver(
        StatusCode::OK,
        r#"{"version":1,"claims":[{"type":"foo","value":"bar"}],"active":true}"#,
        Duration::ZERO,
    )
    .await;
    let hooks = hooks(
        Some(hook(&url, FailurePolicy::FailClosed, 60)),
        Some(hook(&url, FailurePolicy::FailClosed, 60)),
    );
    let calls = || seen.lock().unwrap().len();
    profile(&hooks, "ClaimsProviderAccessToken", "web", &["foo"])
        .await
        .unwrap();
    profile(&hooks, "ClaimsProviderAccessToken", "web", &["foo"])
        .await
        .unwrap();
    assert_eq!(calls(), 1, "cached");
    profile(&hooks, "ClaimsProviderAccessToken", "other", &["foo"])
        .await
        .unwrap();
    assert_eq!(calls(), 2, "another client");
    profile(&hooks, "ClaimsProviderIdentityToken", "web", &["foo"])
        .await
        .unwrap();
    assert_eq!(calls(), 3, "another caller");
    profile(&hooks, "ClaimsProviderAccessToken", "web", &["foo", "bar"])
        .await
        .unwrap();
    assert_eq!(calls(), 4, "other requested types");
    active(&hooks).await.unwrap();
    active(&hooks).await.unwrap();
    assert_eq!(calls(), 5, "activity is cached too");
}

#[test]
fn hook_urls_must_be_https_except_on_loopback() {
    for (url, ok) in [
        ("https://hooks.example.com/profile", true),
        ("http://127.0.0.1:9/profile", true),
        ("http://localhost:9/profile", true),
        ("http://[::1]:9/profile", true),
        ("http://hooks.example.com/profile", false),
        ("ftp://hooks.example.com/profile", false),
    ] {
        let result = Hooks::new(
            HooksConfig {
                profile_claims: Some(hook(url, FailurePolicy::FailClosed, 0)),
                ..Default::default()
            },
            keys(),
            "https://idsrv.test".into(),
        );
        assert_eq!(result.is_ok(), ok, "{url}");
    }
}

#[tokio::test]
async fn a_profile_answer_without_claims_means_no_claims() {
    for body in [r#"{"version":1}"#, r#"{"version":1,"claims":null}"#] {
        let (url, _) = receiver(StatusCode::OK, body, Duration::ZERO).await;
        let hooks = hooks(Some(hook(&url, FailurePolicy::FailClosed, 0)), None);
        let claims = profile(&hooks, "ClaimsProviderAccessToken", "web", &["role"]).await;
        assert_eq!(claims, Ok(Vec::new()), "{body}");
    }
    // A malformed array is still a failure.
    let (url, _) = receiver(
        StatusCode::OK,
        r#"{"version":1,"claims":[1]}"#,
        Duration::ZERO,
    )
    .await;
    let hooks = hooks(Some(hook(&url, FailurePolicy::FailClosed, 0)), None);
    assert!(
        profile(&hooks, "ClaimsProviderAccessToken", "web", &["role"])
            .await
            .is_err()
    );
}

#[tokio::test]
async fn hook_tokens_have_their_own_type() {
    let (url, seen) = receiver(
        StatusCode::OK,
        r#"{"version":1,"active":true}"#,
        Duration::ZERO,
    )
    .await;
    let hooks = hooks(None, Some(hook(&url, FailurePolicy::FailClosed, 0)));
    active(&hooks).await.unwrap();
    let headers = seen.lock().unwrap()[0].0.clone();
    let jwt = headers["authorization"]
        .to_str()
        .unwrap()
        .strip_prefix("Bearer ")
        .unwrap()
        .to_owned();
    let jws = rustid_core::jwt::Jws::decode(&jwt).unwrap();
    assert_eq!(
        jws.header_str("typ"),
        Some("hook+jwt"),
        "never mistaken for an access token"
    );
}

fn token_hooks(url: &str, policy: FailurePolicy) -> Hooks {
    Hooks::new(
        HooksConfig {
            token_request: Some(hook(url, policy, 0)),
            ..Default::default()
        },
        keys(),
        "https://idsrv.test".into(),
    )
    .unwrap()
}

async fn token_request(
    hooks: &Hooks,
) -> Result<rustid_core::token_request::TokenRequestVerdict, rustid_core::profile::ProfileError> {
    use rustid_core::token_request::{TokenRequest, TokenRequestValidator};
    let client = client("web");
    let scopes = vec!["openid".to_owned(), "api1".to_owned()];
    let parameters = vec![("grant_type".to_owned(), "refresh_token".to_owned())];
    hooks
        .validate(&TokenRequest {
            grant_type: "refresh_token",
            client: &client,
            subject_id: Some("1"),
            scopes: &scopes,
            parameters: &parameters,
        })
        .await
}

#[tokio::test]
async fn the_token_request_hook_adds_fields_or_refuses() {
    use rustid_core::token_request::TokenRequestVerdict;
    let (url, seen) = receiver(
        StatusCode::OK,
        r#"{"version":1,"custom_response":{"custom":"custom"}}"#,
        Duration::ZERO,
    )
    .await;
    let hooks = token_hooks(&url, FailurePolicy::FailClosed);
    let verdict = token_request(&hooks).await.unwrap();
    let TokenRequestVerdict::Accept { custom } = verdict else {
        panic!("{verdict:?}");
    };
    assert_eq!(custom["custom"], "custom");
    let body = seen.lock().unwrap()[0].1.clone();
    assert_eq!(
        body,
        serde_json::json!({
            "version": 1,
            "grant_type": "refresh_token",
            "client_id": "web",
            "subject_id": "1",
            "scopes": ["openid", "api1"],
            "parameters": { "grant_type": "refresh_token" },
        })
    );

    let (url, _) = receiver(
        StatusCode::OK,
        r#"{"version":1,"error":"invalid_request","error_description":"no","custom_response":{"why":"policy"}}"#,
        Duration::ZERO,
    )
    .await;
    let verdict = token_request(&token_hooks(&url, FailurePolicy::FailClosed))
        .await
        .unwrap();
    assert_eq!(
        verdict,
        TokenRequestVerdict::Reject {
            error: "invalid_request".into(),
            description: Some("no".into()),
            custom: serde_json::json!({ "why": "policy" })
                .as_object()
                .unwrap()
                .clone(),
        }
    );

    let (url, _) = receiver(StatusCode::INTERNAL_SERVER_ERROR, "{}", Duration::ZERO).await;
    assert!(
        token_request(&token_hooks(&url, FailurePolicy::FailClosed))
            .await
            .is_err()
    );
    assert_eq!(
        token_request(&token_hooks(&url, FailurePolicy::FailOpen)).await,
        Ok(TokenRequestVerdict::Accept {
            custom: serde_json::Map::new()
        })
    );
}

#[tokio::test]
async fn a_token_hook_error_must_be_an_oauth_error_code() {
    use rustid_core::token_request::TokenRequestVerdict;
    for body in [
        r#"{"version":1,"error":""}"#,
        r#"{"version":1,"error":"   "}"#,
        r#"{"version":1,"error":"quote\"inside"}"#,
        r#"{"version":1,"error":"line\nbreak"}"#,
    ] {
        let (url, _) = receiver(StatusCode::OK, body, Duration::ZERO).await;
        assert!(
            token_request(&token_hooks(&url, FailurePolicy::FailClosed))
                .await
                .is_err(),
            "{body}"
        );
        assert_eq!(
            token_request(&token_hooks(&url, FailurePolicy::FailOpen)).await,
            Ok(TokenRequestVerdict::Accept {
                custom: serde_json::Map::new()
            }),
            "{body}"
        );
    }
    let long = format!(r#"{{"version":1,"error":"{}"}}"#, "x".repeat(101));
    let (url, _) = receiver(StatusCode::OK, &long, Duration::ZERO).await;
    assert!(
        token_request(&token_hooks(&url, FailurePolicy::FailClosed))
            .await
            .is_err()
    );
}
