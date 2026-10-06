//! The device authorization endpoint (RFC 8628; `DeviceAuthorizationEndpoint`,
//! the device authorization request validator, the device authorization response generator).

mod support;

use chrono::Utc;
use rustid_core::clients::Client;
use rustid_core::device_flow::{self, DeviceAuthorizationResponse, DeviceCode};
use rustid_core::form::Form;
use rustid_core::token::{TokenError, TokenFailure};
use serde_json::{Value, json};
use support::Fixture;

pub fn fixture() -> Fixture {
    let mut f = Fixture::new();
    f.edit_clients(|clients| {
        let client = |value: Value| serde_json::from_value::<Client>(value).unwrap();
        clients.push(client(json!({
            "clientId": "device",
            "clientSecrets": [{ "value": "K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=" }],
            "allowedGrantTypes": ["urn:ietf:params:oauth:grant-type:device_code"],
            "allowOfflineAccess": true,
            "allowedScopes": ["openid", "profile", "api1"],
        })));
    });
    f
}

async fn authorize(
    f: &Fixture,
    pairs: &[(&str, &str)],
) -> Result<DeviceAuthorizationResponse, TokenFailure> {
    device_flow::authorize(&f.ctx(Utc::now()), None, &Form::from_pairs(pairs)).await
}

fn error(result: Result<DeviceAuthorizationResponse, TokenFailure>) -> (String, Option<String>) {
    match result {
        Err(TokenFailure::Protocol(TokenError {
            error, description, ..
        })) => (error.into_owned(), description),
        other => panic!("expected an error, got {other:?}"),
    }
}

const DEVICE: [(&str, &str); 2] = [("client_id", "device"), ("client_secret", "secret")];

#[tokio::test]
async fn a_device_authorization_is_stored_and_answered() {
    let f = fixture();
    let mut pairs = DEVICE.to_vec();
    pairs.push(("scope", "openid api1"));
    let r = authorize(&f, &pairs).await.unwrap();
    assert_eq!(r.user_code.len(), 9);
    assert!(r.user_code.bytes().all(|b| b.is_ascii_digit()));
    assert!(!r.user_code.starts_with('0'));
    assert!(r.device_code.len() >= 32);
    assert_eq!(r.verification_uri, "http://h/device");
    assert_eq!(
        r.verification_uri_complete.as_deref(),
        Some(format!("http://h/device?userCode={}", r.user_code).as_str())
    );
    assert_eq!((r.expires_in, r.interval), (300, 5));

    let stored: DeviceCode = serde_json::from_str(
        &f.stores
            .device_flow
            .find_by_user_code(&device_flow::hash(&r.user_code))
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(stored.client_id, "device");
    assert_eq!(stored.requested_scopes, ["openid", "api1"]);
    assert!(stored.is_open_id);
    assert!(!stored.is_authorized);
    assert_eq!(stored.lifetime, 300);
    let names = f.events.names();
    assert_eq!(names.last(), Some(&"Device Authorization Success"));
}

#[tokio::test]
async fn default_scopes_are_the_allowed_ones() {
    let f = fixture();
    let r = authorize(&f, &DEVICE).await.unwrap();
    let stored: DeviceCode = serde_json::from_str(
        &f.stores
            .device_flow
            .find_by_device_code(&device_flow::hash(&r.device_code))
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        stored.requested_scopes,
        ["openid", "profile", "api1", "offline_access"]
    );
}

#[tokio::test]
async fn request_errors() {
    let f = fixture();
    // No credentials.
    assert_eq!(error(authorize(&f, &[]).await).0, "invalid_request");
    assert_eq!(
        error(authorize(&f, &[("client_id", "device"), ("client_secret", "x")]).await).0,
        "invalid_client"
    );
    // A client without the grant.
    assert_eq!(
        error(authorize(&f, &[("client_id", "client"), ("client_secret", "secret")]).await),
        ("unauthorized_client".into(), None)
    );
    let with_scope = |scope: &'static str| {
        let mut pairs = DEVICE.to_vec();
        pairs.push(("scope", scope));
        pairs
    };
    assert_eq!(
        error(authorize(&f, &with_scope("api2")).await),
        ("invalid_scope".into(), None)
    );
    assert_eq!(
        error(authorize(&f, &with_scope("profile api1")).await),
        ("invalid_scope".into(), None),
        "identity scopes without openid"
    );
    let long = "x".repeat(301);
    let mut pairs = DEVICE.to_vec();
    pairs.push(("scope", &long));
    assert_eq!(
        error(authorize(&f, &pairs).await),
        ("invalid_request".into(), Some("Invalid scope".into()))
    );
    assert_eq!(
        f.events.names().last(),
        Some(&"Device Authorization Failure")
    );
}

// The device code grant (the device code validator, validate device code request).

async fn token(
    f: &Fixture,
    at: chrono::DateTime<Utc>,
    pairs: &[(&str, &str)],
) -> Result<rustid_core::token::TokenResponse, TokenFailure> {
    rustid_core::token::process(&f.ctx(at), None, &Form::from_pairs(pairs)).await
}

fn poll(device_code: &str) -> Vec<(&str, &str)> {
    vec![
        ("grant_type", device_flow::GRANT_TYPE),
        ("client_id", "device"),
        ("client_secret", "secret"),
        ("device_code", device_code),
    ]
}

fn token_error(result: Result<rustid_core::token::TokenResponse, TokenFailure>) -> String {
    match result {
        Err(TokenFailure::Protocol(e)) => e.error.into_owned(),
        other => panic!("expected an error, got {other:?}"),
    }
}

/// Approves (or with no scopes, denies) the authorization for `user_code`.
async fn decide(f: &Fixture, user_code: &str, scopes: Option<&[&str]>) {
    let key = device_flow::hash(user_code);
    let mut code: DeviceCode = serde_json::from_str(
        &f.stores
            .device_flow
            .find_by_user_code(&key)
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    code.is_authorized = true;
    code.authorized_scopes = Some(
        scopes
            .unwrap_or_default()
            .iter()
            .map(|s| (*s).to_owned())
            .collect(),
    );
    code.subject = Some(rustid_core::session::UserSession::sign_in(
        rustid_core::session::SignIn {
            subject_id: "alice".into(),
            ..Default::default()
        },
        None,
        Utc::now(),
        3600,
    ));
    code.session_id = Some("sid".into());
    f.stores
        .device_flow
        .update_by_user_code(&key, Some("alice"), &serde_json::to_string(&code).unwrap())
        .await
        .unwrap();
}

#[tokio::test]
async fn polling_until_approved_then_tokens_once() {
    let f = fixture();
    let start = Utc::now();
    let r = authorize(&f, &DEVICE).await.unwrap();
    let dc = r.device_code.as_str();
    assert_eq!(
        token_error(token(&f, start, &poll(dc)).await),
        "authorization_pending"
    );
    // Within the interval: slow down.
    assert_eq!(
        token_error(token(&f, start + chrono::Duration::seconds(2), &poll(dc)).await),
        "slow_down"
    );
    decide(
        &f,
        &r.user_code,
        Some(&["openid", "api1", "offline_access"]),
    )
    .await;
    let later = start + chrono::Duration::seconds(10);
    let tokens = token(&f, later, &poll(dc)).await.unwrap();
    assert!(tokens.id_token.is_some(), "openid was requested");
    assert!(tokens.refresh_token.is_some());
    assert_eq!(tokens.scope, "openid api1 offline_access");
    let access = rustid_core::jwt::Jws::decode(&tokens.access_token)
        .unwrap()
        .payload;
    assert_eq!(access["sub"], "alice");
    // Redeemed: gone.
    assert_eq!(
        token_error(token(&f, later + chrono::Duration::seconds(10), &poll(dc)).await),
        "invalid_grant"
    );
}

#[tokio::test]
async fn denied_expired_foreign_and_malformed_codes() {
    let f = fixture();
    let start = Utc::now();
    let r = authorize(&f, &DEVICE).await.unwrap();
    decide(&f, &r.user_code, None).await;
    assert_eq!(
        token_error(token(&f, start, &poll(&r.device_code)).await),
        "access_denied"
    );

    let r = authorize(&f, &DEVICE).await.unwrap();
    assert_eq!(
        token_error(
            token(
                &f,
                start + chrono::Duration::seconds(301),
                &poll(&r.device_code)
            )
            .await
        ),
        "expired_token"
    );

    assert_eq!(
        token_error(token(&f, start, &poll("unknown")).await),
        "invalid_grant"
    );
    let long = "x".repeat(101);
    assert_eq!(
        token_error(token(&f, start, &poll(&long)).await),
        "invalid_grant"
    );
    let mut missing = poll("x");
    missing.pop();
    assert_eq!(
        token_error(token(&f, start, &missing).await),
        "invalid_request"
    );
    let mut with_resource = poll(&r.device_code);
    with_resource.push(("resource", "urn:api"));
    assert_eq!(
        token_error(token(&f, start, &with_resource).await),
        "invalid_target"
    );
    // Another client can't use it (client isn't allowed the grant at all).
    let other = [
        ("grant_type", device_flow::GRANT_TYPE),
        ("client_id", "client"),
        ("client_secret", "secret"),
        ("device_code", r.device_code.as_str()),
    ];
    assert_eq!(
        token_error(token(&f, start, &other).await),
        "unauthorized_client"
    );
}

// The device flow interaction service.

#[tokio::test]
async fn the_interaction_service_reads_and_decides_a_user_code() {
    let f = fixture();
    let mut pairs = DEVICE.to_vec();
    pairs.push(("scope", "openid api1"));
    let r = authorize(&f, &pairs).await.unwrap();
    let context = device_flow::authorization_context(&f.stores, &r.user_code)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(context.client.client_id, "device");
    assert_eq!(context.scopes, ["openid", "api1"]);
    assert!(
        device_flow::authorization_context(&f.stores, "000000000")
            .await
            .unwrap()
            .is_none()
    );

    let session = rustid_core::session::UserSession::sign_in(
        rustid_core::session::SignIn {
            subject_id: "alice".into(),
            ..Default::default()
        },
        None,
        Utc::now(),
        3600,
    );
    let scopes = vec!["openid".to_owned()];
    assert_eq!(
        device_flow::decide(&f.stores, "000000000", Some(&session), &scopes, None)
            .await
            .unwrap(),
        Err("Invalid user code")
    );
    assert_eq!(
        device_flow::decide(&f.stores, &r.user_code, None, &scopes, None)
            .await
            .unwrap(),
        Err("No user present in device flow request")
    );
    device_flow::decide(&f.stores, &r.user_code, Some(&session), &scopes, Some("tv"))
        .await
        .unwrap()
        .unwrap();
    let tokens = token(&f, Utc::now(), &poll(&r.device_code)).await.unwrap();
    assert_eq!(tokens.scope, "openid");
}

/// Another request takes the first user code between the check and the
/// write.
struct TakenOnce {
    inner: std::sync::Arc<dyn rustid_core::stores::DeviceFlowStore>,
    taken: std::sync::atomic::AtomicBool,
}

#[async_trait::async_trait]
impl rustid_core::stores::DeviceFlowStore for TakenOnce {
    async fn store_device_authorization(
        &self,
        device_code: &str,
        user_code: &str,
        client_id: &str,
        creation_time: chrono::DateTime<Utc>,
        expiration: chrono::DateTime<Utc>,
        data: &str,
    ) -> Result<(), rustid_core::stores::StoreError> {
        if !self.taken.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return Err(rustid_core::stores::StoreError::DuplicateDeviceCode);
        }
        self.inner
            .store_device_authorization(
                device_code,
                user_code,
                client_id,
                creation_time,
                expiration,
                data,
            )
            .await
    }
    async fn find_by_user_code(
        &self,
        user_code: &str,
    ) -> Result<Option<String>, rustid_core::stores::StoreError> {
        self.inner.find_by_user_code(user_code).await
    }
    async fn find_by_device_code(
        &self,
        device_code: &str,
    ) -> Result<Option<String>, rustid_core::stores::StoreError> {
        self.inner.find_by_device_code(device_code).await
    }
    async fn update_by_user_code(
        &self,
        user_code: &str,
        subject_id: Option<&str>,
        data: &str,
    ) -> Result<(), rustid_core::stores::StoreError> {
        self.inner
            .update_by_user_code(user_code, subject_id, data)
            .await
    }
    async fn remove_by_device_code(
        &self,
        device_code: &str,
    ) -> Result<bool, rustid_core::stores::StoreError> {
        self.inner.remove_by_device_code(device_code).await
    }
    async fn remove_expired(
        &self,
        now: chrono::DateTime<Utc>,
        batch: usize,
    ) -> Result<u64, rustid_core::stores::StoreError> {
        self.inner.remove_expired(now, batch).await
    }
}

#[tokio::test]
async fn a_user_code_taken_meanwhile_is_replaced() {
    let mut f = fixture();
    f.stores.device_flow = std::sync::Arc::new(TakenOnce {
        inner: f.stores.device_flow.clone(),
        taken: Default::default(),
    });
    let r = authorize(&f, &DEVICE).await.unwrap();
    assert!(
        f.stores
            .device_flow
            .find_by_user_code(&device_flow::hash(&r.user_code))
            .await
            .unwrap()
            .is_some()
    );
}
