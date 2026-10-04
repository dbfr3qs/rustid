//! The backchannel authentication endpoint (CIBA; `BackchannelAuthenticationEndpoint`,
//! the backchannel authentication request validator, the response generator).

mod support;

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::Utc;
use rustid_core::ciba::{
    self, CibaCustomAnswer, CibaCustomRequest, CibaNotification, CibaRequest, CibaResponse,
    CibaService, CibaUserRequest, CibaUserResult,
};
use rustid_core::clients::Client;
use rustid_core::form::Form;
use rustid_core::jwt::b64url;
use rustid_core::profile::ProfileError;
use rustid_core::token::{TokenError, TokenFailure};
use rustid_core::tokens::Claim;
use serde_json::{Map, Value, json};
use support::Fixture;

/// A notification: internal id, subject, binding message, properties.
pub type Notified = (String, String, Option<String>, Map<String, Value>);

/// Scripted hooks: `login_hint` names the outcome; notifications are kept.
#[derive(Default)]
pub struct Scripted {
    pub notified: Mutex<Vec<Notified>>,
    pub users: Mutex<Vec<Option<String>>>,
}

#[async_trait]
impl CibaService for Scripted {
    async fn validate_user(&self, r: &CibaUserRequest<'_>) -> Result<CibaUserResult, ProfileError> {
        self.users
            .lock()
            .unwrap()
            .push(r.login_hint.map(str::to_owned));
        let error = |e: &str| CibaUserResult::Error {
            error: e.into(),
            description: Some(format!("{e} described")),
        };
        Ok(match r.login_hint.unwrap_or("alice") {
            "unknown" => error("unknown_user_id"),
            "denied" => error("access_denied"),
            "weird" => error("weird_error"),
            "nosub" => CibaUserResult::Subject {
                subject_id: None,
                claims: vec![],
            },
            _ => CibaUserResult::Subject {
                subject_id: Some("1".into()),
                claims: vec![Claim::string("name", "Alice")],
            },
        })
    }

    async fn notify_user(&self, n: &CibaNotification<'_>) -> Result<(), ProfileError> {
        self.notified.lock().unwrap().push((
            n.internal_id.to_owned(),
            n.subject_id.to_owned(),
            n.binding_message.map(str::to_owned),
            n.properties.clone(),
        ));
        Ok(())
    }

    async fn validate_request(
        &self,
        r: &CibaCustomRequest<'_>,
    ) -> Result<CibaCustomAnswer, ProfileError> {
        let custom = r
            .parameters
            .iter()
            .find(|(k, _)| k == "custom")
            .map(|(_, v)| v.clone());
        Ok(match custom.as_deref() {
            Some("refuse") => CibaCustomAnswer {
                error: Some("nope".into()),
                properties: Map::new(),
            },
            Some(value) => CibaCustomAnswer {
                error: None,
                properties: [("custom".to_owned(), json!(value))].into_iter().collect(),
            },
            None => CibaCustomAnswer::default(),
        })
    }
}

pub fn fixture() -> (Fixture, Arc<Scripted>) {
    let mut f = Fixture::new();
    let key = support::key("client-jwt-key.pem", "ciba", "RS256");
    let jwk = support::public_jwk_json(&key);
    f.edit_clients(|clients| {
        let client = |value: Value| serde_json::from_value::<Client>(value).unwrap();
        clients.push(client(json!({
            "clientId": "ciba",
            "clientSecrets": [
                { "value": "K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=" },
                { "type": "JWK", "value": jwk },
            ],
            "allowedGrantTypes": ["urn:openid:params:grant-type:ciba"],
            "allowOfflineAccess": true,
            "allowedScopes": ["openid", "profile", "api1"],
        })));
    });
    let scripted = Arc::new(Scripted::default());
    f.stores.ciba = scripted.clone();
    (f, scripted)
}

pub async fn authorize(f: &Fixture, pairs: &[(&str, &str)]) -> Result<CibaResponse, TokenFailure> {
    ciba::authorize(&f.ctx(Utc::now()), None, &Form::from_pairs(pairs)).await
}

fn error(result: Result<CibaResponse, TokenFailure>) -> (String, Option<String>) {
    match result {
        Err(TokenFailure::Protocol(TokenError {
            error, description, ..
        })) => (error.into_owned(), description),
        other => panic!("expected an error, got {other:?}"),
    }
}

pub fn request<'a>(extra: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
    let mut pairs = vec![
        ("client_id", "ciba"),
        ("client_secret", "secret"),
        ("scope", "openid profile api1 offline_access"),
        ("login_hint", "alice"),
    ];
    for (k, v) in extra {
        pairs.retain(|(existing, _)| existing != k);
        pairs.push((k, v));
    }
    pairs.retain(|(_, v)| !v.is_empty());
    pairs
}

#[tokio::test]
async fn a_valid_request_is_stored_and_the_user_notified() {
    let (f, scripted) = fixture();
    let r = authorize(&f, &request(&[("binding_message", "tv-42")]))
        .await
        .unwrap();
    assert_eq!((r.expires_in, r.interval), (300, 5));
    let notified = scripted.notified.lock().unwrap().clone();
    assert_eq!(notified.len(), 1);
    let (internal_id, subject, binding, _) = &notified[0];
    assert_eq!((subject.as_str(), binding.as_deref()), ("1", Some("tv-42")));
    let stored: CibaRequest = ciba::get_by_internal_id(f.stores.grants.as_ref(), internal_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.client_id, "ciba");
    assert_eq!(stored.subject.subject_id, "1");
    assert_eq!(
        stored.requested_scopes,
        ["openid", "profile", "api1", "offline_access"]
    );
    assert!(!stored.is_complete);
    assert_eq!(
        ciba::get_by_request_id(f.stores.grants.as_ref(), &r.auth_req_id)
            .await
            .unwrap()
            .unwrap()
            .internal_id,
        *internal_id
    );
    assert_eq!(
        f.events.names().last(),
        Some(&"Backchannel Authentication Success")
    );
}

#[tokio::test]
async fn requested_expiry_within_the_lifetime() {
    let (f, _) = fixture();
    let r = authorize(&f, &request(&[("requested_expiry", "120")]))
        .await
        .unwrap();
    assert_eq!(r.expires_in, 120);
    for bad in ["0", "301", "abc", "1234567890"] {
        assert_eq!(
            error(authorize(&f, &request(&[("requested_expiry", bad)])).await),
            (
                "invalid_request".into(),
                Some("Invalid requested_expiry".into())
            ),
            "{bad}"
        );
    }
}

#[tokio::test]
async fn request_errors() {
    let (f, _) = fixture();
    async fn check(f: &Fixture, extra: &[(&str, &str)], expected: (&str, Option<&str>)) {
        let got = error(authorize(f, &request(extra)).await);
        assert_eq!((got.0.as_str(), got.1.as_deref()), expected, "{extra:?}");
    }
    check(
        &f,
        &[("scope", "")],
        ("invalid_request", Some("Missing scope")),
    )
    .await;
    check(
        &f,
        &[("scope", "profile api1")],
        ("invalid_request", Some("Missing the openid scope")),
    )
    .await;
    check(
        &f,
        &[("scope", "openid api2")],
        ("invalid_scope", Some("Invalid scope")),
    )
    .await;
    check(
        &f,
        &[("login_hint", "")],
        (
            "invalid_request",
            Some("Missing login_hint_token, id_token_hint, or login_hint"),
        ),
    )
    .await;
    check(
        &f,
        &[("login_hint_token", "token")],
        (
            "invalid_request",
            Some("Too many of login_hint_token, id_token_hint, or login_hint"),
        ),
    )
    .await;
    check(
        &f,
        &[("login_hint", ""), ("id_token_hint", "not.a.token")],
        ("invalid_request", Some("Invalid id_token_hint")),
    )
    .await;
    check(
        &f,
        &[("resource", "not a uri")],
        ("invalid_target", Some("Invalid resource indicator format")),
    )
    .await;
    check(
        &f,
        &[("login_hint", "unknown")],
        ("unknown_user_id", Some("unknown_user_id described")),
    )
    .await;
    check(
        &f,
        &[("login_hint", "denied")],
        ("access_denied", Some("access_denied described")),
    )
    .await;
    check(&f, &[("login_hint", "weird")], ("unknown_user_id", None)).await;
    check(&f, &[("login_hint", "nosub")], ("unknown_user_id", None)).await;
    check(&f, &[("custom", "refuse")], ("invalid_request", None)).await;
    // A client without the grant.
    let got = error(
        authorize(
            &f,
            &[
                ("client_id", "client"),
                ("client_secret", "secret"),
                ("scope", "openid"),
                ("login_hint", "alice"),
            ],
        )
        .await,
    );
    assert_eq!(
        got,
        (
            "unauthorized_client".into(),
            Some("Unauthorized client".into())
        )
    );
    assert_eq!(
        f.events.names().last(),
        Some(&"Backchannel Authentication Failure")
    );
}

#[tokio::test]
async fn binding_message_and_input_limits() {
    let (f, _) = fixture();
    let long = "x".repeat(101);
    assert_eq!(
        error(authorize(&f, &request(&[("binding_message", &long)])).await),
        (
            "invalid_binding_message".into(),
            Some("Invalid binding_message".into())
        )
    );
    assert_eq!(
        error(authorize(&f, &request(&[("user_code", &long)])).await),
        ("invalid_request".into(), Some("Invalid user_code".into()))
    );
}

#[tokio::test]
async fn custom_properties_reach_the_notification_but_not_the_response() {
    let (f, scripted) = fixture();
    authorize(&f, &request(&[("custom", "input")]))
        .await
        .unwrap();
    let notified = scripted.notified.lock().unwrap().clone();
    assert_eq!(notified[0].3["custom"], "input");
}

/// A request object signed by the client's key.
fn request_object(payload: Value) -> String {
    let key = support::key("client-jwt-key.pem", "ciba", "RS256");
    let header = json!({ "alg": "RS256", "kid": "ciba" });
    let input = format!(
        "{}.{}",
        b64url(header.to_string().as_bytes()),
        b64url(payload.to_string().as_bytes())
    );
    format!("{input}.{}", b64url(&key.sign(input.as_bytes()).unwrap()))
}

fn signed(extra: Value) -> Value {
    let now = Utc::now().timestamp();
    let mut payload = json!({
        "iss": "ciba",
        "aud": support::ISSUER,
        "exp": now + 60,
        "jti": "j1",
        "scope": "openid api1",
        "login_hint": "alice",
    });
    for (k, v) in extra.as_object().unwrap() {
        if v.is_null() {
            payload.as_object_mut().unwrap().remove(k);
        } else {
            payload[k] = v.clone();
        }
    }
    payload
}

#[tokio::test]
async fn request_objects() {
    let (f, scripted) = fixture();
    let base = [("client_id", "ciba"), ("client_secret", "secret")];
    let with = |object: String| {
        let mut pairs: Vec<(&str, String)> =
            base.iter().map(|(k, v)| (*k, (*v).to_owned())).collect();
        pairs.push(("request", object));
        pairs
    };
    let run = |pairs: Vec<(&'static str, String)>| {
        let f = &f;
        async move {
            let pairs: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (*k, v.as_str())).collect();
            authorize(f, &pairs).await
        }
    };
    run(with(request_object(signed(json!({}))))).await.unwrap();
    assert_eq!(
        scripted.users.lock().unwrap().last().unwrap().as_deref(),
        Some("alice")
    );

    let invalid = |d: &str| ("invalid_request_object".to_owned(), Some(d.to_owned()));
    assert_eq!(
        error(run(with(request_object(signed(json!({ "jti": null }))))).await),
        invalid("Missing jti in JWT request object")
    );
    assert_eq!(
        error(
            run(with(request_object(signed(
                json!({ "client_id": "other" })
            ))))
            .await
        ),
        invalid("Invalid client_id in JWT request")
    );
    assert_eq!(
        error(
            run(with(request_object(signed(
                json!({ "request_uri": "https://x" })
            ))))
            .await
        ),
        invalid("Invalid JWT request")
    );
    let mut shadowed = with(request_object(signed(json!({}))));
    shadowed.push(("login_hint", "bob".to_owned()));
    assert_eq!(
        error(run(shadowed).await),
        invalid("Parameter from JWT request object also found in request body")
    );
    assert_eq!(
        error(run(with("x".repeat(51200))).await),
        invalid("Invalid request value")
    );
    let mut forged = request_object(signed(json!({})));
    forged.push('x');
    assert_eq!(
        error(run(with(forged)).await),
        invalid("Invalid JWT request")
    );
}

// The CIBA grant.

async fn poll(
    f: &Fixture,
    at: chrono::DateTime<Utc>,
    auth_req_id: &str,
    extra: &[(&str, &str)],
) -> Result<rustid_core::token::TokenResponse, TokenFailure> {
    let mut pairs = vec![
        ("grant_type", ciba::GRANT_TYPE),
        ("client_id", "ciba"),
        ("client_secret", "secret"),
        ("auth_req_id", auth_req_id),
    ];
    pairs.extend_from_slice(extra);
    rustid_core::token::process(&f.ctx(at), None, &Form::from_pairs(&pairs)).await
}

fn grant_error(result: Result<rustid_core::token::TokenResponse, TokenFailure>) -> String {
    match result {
        Err(TokenFailure::Protocol(e)) => e.error.into_owned(),
        other => panic!("expected an error, got {other:?}"),
    }
}

/// Completes the request as the user would, with `scopes` (none denies).
async fn complete(f: &Fixture, auth_req_id: &str, scopes: &[&str]) {
    let mut request = ciba::get_by_request_id(f.stores.grants.as_ref(), auth_req_id)
        .await
        .unwrap()
        .unwrap();
    request.is_complete = true;
    request.authorized_scopes = Some(scopes.iter().map(|s| (*s).to_owned()).collect());
    request.subject.auth_time = Utc::now().timestamp();
    ciba::store(f.stores.grants.as_ref(), &request)
        .await
        .unwrap();
}

#[tokio::test]
async fn polling_until_completed_then_tokens_once() {
    let (f, _) = fixture();
    let start = Utc::now();
    let r = authorize(&f, &request(&[])).await.unwrap();
    let id = r.auth_req_id.as_str();
    assert_eq!(
        grant_error(poll(&f, start, id, &[]).await),
        "authorization_pending"
    );
    assert_eq!(
        grant_error(poll(&f, start + chrono::Duration::seconds(1), id, &[]).await),
        "slow_down"
    );
    complete(&f, id, &["openid", "api1", "offline_access"]).await;
    let later = start + chrono::Duration::seconds(10);
    let tokens = poll(&f, later, id, &[]).await.unwrap();
    assert!(
        tokens.id_token.is_some(),
        "CIBA always issues an identity token"
    );
    assert!(tokens.refresh_token.is_some());
    assert_eq!(tokens.scope, "openid api1 offline_access");
    let id_claims = rustid_core::jwt::Jws::decode(tokens.id_token.as_deref().unwrap())
        .unwrap()
        .payload;
    assert_eq!(id_claims["sub"], "1");
    assert_eq!(
        grant_error(poll(&f, later + chrono::Duration::seconds(10), id, &[]).await),
        "invalid_grant"
    );
}

#[tokio::test]
async fn denied_expired_and_foreign_requests() {
    let (f, _) = fixture();
    let start = Utc::now();
    let r = authorize(&f, &request(&[])).await.unwrap();
    complete(&f, &r.auth_req_id, &[]).await;
    assert_eq!(
        grant_error(poll(&f, start, &r.auth_req_id, &[]).await),
        "access_denied"
    );
    // Denied requests are removed.
    assert_eq!(
        grant_error(
            poll(
                &f,
                start + chrono::Duration::seconds(10),
                &r.auth_req_id,
                &[]
            )
            .await
        ),
        "invalid_grant"
    );

    let r = authorize(&f, &request(&[])).await.unwrap();
    assert_eq!(
        grant_error(
            poll(
                &f,
                start + chrono::Duration::seconds(301),
                &r.auth_req_id,
                &[]
            )
            .await
        ),
        "expired_token"
    );

    let r = authorize(&f, &request(&[("resource", "urn:api1")])).await;
    // api1's resource isn't an indicator in the fixtures: invalid target.
    assert!(r.is_err());

    assert_eq!(
        grant_error(poll(&f, start, "unknown", &[]).await),
        "invalid_grant"
    );
    let long = "x".repeat(101);
    assert_eq!(
        grant_error(poll(&f, start, &long, &[]).await),
        "invalid_grant"
    );
    let pairs = [
        ("grant_type", ciba::GRANT_TYPE),
        ("client_id", "ciba"),
        ("client_secret", "secret"),
    ];
    assert_eq!(
        grant_error(
            rustid_core::token::process(&f.ctx(start), None, &Form::from_pairs(&pairs)).await
        ),
        "invalid_request"
    );
    let other = [
        ("grant_type", ciba::GRANT_TYPE),
        ("client_id", "client"),
        ("client_secret", "secret"),
        ("auth_req_id", "x"),
    ];
    assert_eq!(
        grant_error(
            rustid_core::token::process(&f.ctx(start), None, &Form::from_pairs(&other)).await
        ),
        "unauthorized_client"
    );
}

// The backchannel authentication interaction service.

fn session(subject_id: &str) -> rustid_core::session::UserSession {
    rustid_core::session::UserSession::sign_in(
        rustid_core::session::SignIn {
            subject_id: subject_id.into(),
            ..Default::default()
        },
        None,
        Utc::now(),
        3600,
    )
}

#[tokio::test]
async fn the_user_completes_their_own_requests() {
    let (f, scripted) = fixture();
    let r = authorize(
        &f,
        &request(&[("scope", "openid api1"), ("binding_message", "m")]),
    )
    .await
    .unwrap();
    let internal_id = scripted.notified.lock().unwrap()[0].0.clone();

    let pending = ciba::pending_for_subject(&f.stores, "1").await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].internal_id, internal_id);
    assert_eq!(pending[0].client.client_id, "ciba");
    assert_eq!(pending[0].scopes, ["openid", "api1"]);
    assert_eq!(pending[0].binding_message.as_deref(), Some("m"));
    assert!(
        ciba::pending_for_subject(&f.stores, "2")
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        ciba::login_request(&f.stores, &internal_id)
            .await
            .unwrap()
            .is_some()
    );

    let alice = session("1");
    let bob = session("2");
    let scopes = |s: &[&str]| s.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>();
    assert_eq!(
        ciba::complete(
            &f.stores,
            "nope",
            Some(&alice),
            Some(&scopes(&["openid"])),
            None,
            Utc::now()
        )
        .await
        .unwrap(),
        Err("Invalid backchannel authentication request id.".to_owned())
    );
    assert_eq!(
        ciba::complete(
            &f.stores,
            &internal_id,
            None,
            Some(&scopes(&["openid"])),
            None,
            Utc::now()
        )
        .await
        .unwrap(),
        Err("Invalid subject.".to_owned())
    );
    // Another user: the message names both subjects.
    assert_eq!(
        ciba::complete(
            &f.stores,
            &internal_id,
            Some(&bob),
            Some(&scopes(&["openid"])),
            None,
            Utc::now()
        )
        .await
        .unwrap(),
        Err("User's subject id: '2' does not match subject id for backchannel authentication request: '1'.".to_owned())
    );
    assert_eq!(
        ciba::complete(
            &f.stores,
            &internal_id,
            Some(&alice),
            Some(&scopes(&["openid", "profile"])),
            None,
            Utc::now()
        )
        .await
        .unwrap(),
        Err("More scopes consented than originally requested.".to_owned())
    );
    ciba::complete(
        &f.stores,
        &internal_id,
        Some(&alice),
        Some(&scopes(&["openid"])),
        None,
        Utc::now(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        ciba::pending_for_subject(&f.stores, "1")
            .await
            .unwrap()
            .is_empty()
    );
    // The decided request's grant carries the session, so revoking the
    // session's grants removes it.
    let grant = f.stores.grants.get(&internal_id).await.unwrap().unwrap();
    assert_eq!(grant.session_id.as_deref(), Some(alice.session_id.as_str()));
    let tokens = poll(&f, Utc::now(), &r.auth_req_id, &[]).await.unwrap();
    assert_eq!(tokens.scope, "openid");
}

/// Repeated parameters are joined
/// with commas, and a requested expiry may carry surrounding spaces.
#[tokio::test]
async fn parameters_are_read_exactly() {
    let (f, _) = fixture();
    let r = authorize(&f, &request(&[("requested_expiry", " 5 ")]))
        .await
        .unwrap();
    assert_eq!(r.expires_in, 5);
    let mut pairs = request(&[]);
    pairs.push(("requested_expiry", "5"));
    pairs.push(("requested_expiry", "6"));
    assert_eq!(
        error(authorize(&f, &pairs).await),
        (
            "invalid_request".into(),
            Some("Invalid requested_expiry".into())
        )
    );
}
