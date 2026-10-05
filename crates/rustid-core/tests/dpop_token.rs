//! DPoP at the token endpoint: bound access and
//! refresh tokens, `requireDPoP`, server nonces, codes bound by `dpop_jkt`,
//! and the refresh token proof rules.

mod support;

use chrono::Utc;
use rustid_core::authorize::code::AuthorizationCode;
use rustid_core::authorize::validate;
use rustid_core::clients::{AccessTokenType, Client};
use rustid_core::dpop::DPoPValidationMode;
use rustid_core::form::Form;
use rustid_core::jwt::Jws;
use rustid_core::keys::LoadedKey;
use rustid_core::params::Params;
use rustid_core::session::{SignIn, UserSession};
use rustid_core::token::{TokenFailure, TokenResponse, process};
use serde_json::{Value, json};
use support::Fixture;

const TOKEN_URL: &str = "http://h/connect/token";

fn rsa() -> LoadedKey {
    support::key("client-jwt-key.pem", "p", "RS256")
}

fn ec() -> LoadedKey {
    support::key("client-jwt-ec-key.pem", "p", "ES256")
}

fn thumbprint(key: &LoadedKey) -> String {
    support::dpop_thumbprint(key)
}

fn proof_with(key: &LoadedKey, nonce: Option<&str>) -> String {
    support::dpop_proof(key, TOKEN_URL, nonce)
}

fn proof(key: &LoadedKey) -> String {
    proof_with(key, None)
}

/// The DPoP test clients: a confidential `client1` (code and client
/// credentials) and a public `client2`, both with refresh tokens.
fn fixture() -> Fixture {
    let mut f = Fixture::new();
    f.edit_clients(|clients| {
        let client = |value: Value| serde_json::from_value::<Client>(value).unwrap();
        clients.push(client(json!({
            "clientId": "client1",
            "clientSecrets": [{ "value": "K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=" }],
            "allowedGrantTypes": ["authorization_code", "client_credentials"],
            "redirectUris": ["https://client1/callback"],
            "requirePkce": false,
            "allowOfflineAccess": true,
            "allowedScopes": ["openid", "api1"],
        })));
        clients.push(client(json!({
            "clientId": "client2",
            "requireClientSecret": false,
            "allowedGrantTypes": ["authorization_code"],
            "redirectUris": ["https://client2/callback"],
            "requirePkce": false,
            "allowOfflineAccess": true,
            "allowedScopes": ["openid", "api1"],
        })));
    });
    f
}

async fn request(
    f: &Fixture,
    proof: Option<&str>,
    pairs: &[(&str, &str)],
) -> Result<TokenResponse, TokenFailure> {
    let proofs: Vec<&str> = proof.into_iter().collect();
    let mut ctx = f.ctx(Utc::now());
    ctx.dpop_proofs = &proofs;
    process(&ctx, None, &Form::from_pairs(pairs)).await
}

const CLIENT_CREDENTIALS: &[(&str, &str)] = &[
    ("grant_type", "client_credentials"),
    ("client_id", "client1"),
    ("client_secret", "secret"),
    ("scope", "api1"),
];

fn cnf(response: &TokenResponse) -> Option<Value> {
    Jws::decode(&response.access_token)
        .unwrap()
        .payload
        .get("cnf")
        .cloned()
}

fn error(result: Result<TokenResponse, TokenFailure>) -> rustid_core::token::TokenError {
    match result {
        Err(TokenFailure::Protocol(e)) => e,
        other => panic!("expected an error, got {other:?}"),
    }
}

#[tokio::test]
async fn a_proof_binds_the_access_token() {
    let f = fixture();
    let key = rsa();
    let r = request(&f, Some(&proof(&key)), CLIENT_CREDENTIALS)
        .await
        .unwrap();
    assert_eq!(r.token_type, "DPoP");
    assert_eq!(cnf(&r), Some(json!({ "jkt": thumbprint(&key) })));

    let bearer = request(&f, None, CLIENT_CREDENTIALS).await.unwrap();
    assert_eq!(bearer.token_type, "Bearer");
    assert_eq!(cnf(&bearer), None);
}

#[tokio::test]
async fn a_reference_token_records_the_confirmation() {
    let mut f = fixture();
    f.edit_clients(|clients| {
        let c = clients
            .iter_mut()
            .find(|c| c.client_id == "client1")
            .unwrap();
        c.access_token_type = AccessTokenType::Reference;
    });
    let key = ec();
    let r = request(&f, Some(&proof(&key)), CLIENT_CREDENTIALS)
        .await
        .unwrap();
    assert_eq!(r.token_type, "DPoP");
    let stored = rustid_core::reference_tokens::get(f.stores.grants.as_ref(), &r.access_token)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.confirmation,
        Some(json!({ "jkt": thumbprint(&key) }).to_string())
    );
}

#[tokio::test]
async fn invalid_proofs_and_required_dpop() {
    let mut f = fixture();
    let e = error(request(&f, Some("malformed"), CLIENT_CREDENTIALS).await);
    assert_eq!(
        (e.error.as_ref(), e.description.as_deref()),
        ("invalid_dpop_proof", Some("Malformed DPoP token."))
    );
    let long = "x".repeat(4001);
    let e = error(request(&f, Some(&long), CLIENT_CREDENTIALS).await);
    assert_eq!(
        (e.error.as_ref(), e.description),
        ("invalid_dpop_proof", None)
    );

    f.edit_clients(|clients| {
        let c = clients
            .iter_mut()
            .find(|c| c.client_id == "client1")
            .unwrap();
        c.require_dpop = true;
    });
    let e = error(request(&f, None, CLIENT_CREDENTIALS).await);
    assert_eq!(
        (e.error.as_ref(), e.description.as_deref()),
        (
            "invalid_request",
            Some("Client requires DPoP and a DPoP header value was not provided.")
        )
    );
}

#[tokio::test]
async fn nonce_mode_answers_a_server_nonce() {
    let mut f = fixture();
    f.edit_clients(|clients| {
        let c = clients
            .iter_mut()
            .find(|c| c.client_id == "client1")
            .unwrap();
        c.dpop_validation_mode = DPoPValidationMode::Nonce;
    });
    let key = rsa();
    let e = error(request(&f, Some(&proof(&key)), CLIENT_CREDENTIALS).await);
    assert_eq!(e.error, "use_dpop_nonce");
    let nonce = e.dpop_nonce.expect("a server nonce");
    let r = request(
        &f,
        Some(&proof_with(&key, Some(&nonce))),
        CLIENT_CREDENTIALS,
    )
    .await
    .unwrap();
    assert_eq!(r.token_type, "DPoP");
}

/// A code for `client_id` (openid api1 offline_access), with `dpop_jkt`.
async fn code(f: &Fixture, client_id: &str, dpop_jkt: Option<&str>) -> String {
    let now = Utc::now();
    let mut query = format!(
        "client_id={client_id}&redirect_uri=https%3A%2F%2F{client_id}%2Fcallback&response_type=code&scope=openid%20api1%20offline_access&state=s&nonce=n"
    );
    if let Some(jkt) = dpop_jkt {
        query.push_str(&format!("&dpop_jkt={jkt}"));
    }
    let session = UserSession::sign_in(
        SignIn {
            subject_id: "bob".into(),
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
    AuthorizationCode::for_request(&request, now)
        .store(f.stores.grants.as_ref())
        .await
        .unwrap()
}

async fn redeem(
    f: &Fixture,
    client_id: &str,
    code: &str,
    proof: Option<&str>,
) -> Result<TokenResponse, TokenFailure> {
    let redirect = format!("https://{client_id}/callback");
    let mut pairs = vec![
        ("grant_type", "authorization_code"),
        ("client_id", client_id),
        ("code", code),
        ("redirect_uri", redirect.as_str()),
    ];
    if client_id == "client1" {
        pairs.push(("client_secret", "secret"));
    }
    request(f, proof, &pairs).await
}

async fn refresh(
    f: &Fixture,
    client_id: &str,
    token: &str,
    proof: Option<&str>,
) -> Result<TokenResponse, TokenFailure> {
    let mut pairs = vec![
        ("grant_type", "refresh_token"),
        ("client_id", client_id),
        ("refresh_token", token),
    ];
    if client_id == "client1" {
        pairs.push(("client_secret", "secret"));
    }
    request(f, proof, &pairs).await
}

#[tokio::test]
async fn a_code_bound_by_dpop_jkt_needs_the_same_key() {
    let f = fixture();
    let key = rsa();
    let jkt = thumbprint(&key);

    let e = error(redeem(&f, "client1", &code(&f, "client1", Some(&jkt)).await, None).await);
    assert_eq!(
        (e.error.as_ref(), e.description.as_deref()),
        (
            "invalid_dpop_proof",
            Some(
                "DPoP must be used on the token endpoint when a DPoP key thumbprint is used on the authorize endpoint."
            )
        )
    );
    let other = proof(&ec());
    let e = error(
        redeem(
            &f,
            "client1",
            &code(&f, "client1", Some(&jkt)).await,
            Some(&other),
        )
        .await,
    );
    assert_eq!(
        (e.error.as_ref(), e.description.as_deref()),
        (
            "invalid_dpop_proof",
            Some(
                "The DPoP proof token used on the token endpoint does not match the original used on the authorize endpoint."
            )
        )
    );
    let r = redeem(
        &f,
        "client1",
        &code(&f, "client1", Some(&jkt)).await,
        Some(&proof(&key)),
    )
    .await
    .unwrap();
    assert_eq!(r.token_type, "DPoP");
    assert_eq!(cnf(&r), Some(json!({ "jkt": jkt })));
}

#[tokio::test]
async fn refresh_tokens_keep_their_proof_type() {
    let f = fixture();
    let key = rsa();
    // DPoP-issued: renewal needs a proof.
    let r = redeem(
        &f,
        "client1",
        &code(&f, "client1", None).await,
        Some(&proof(&key)),
    )
    .await
    .unwrap();
    let rt = r.refresh_token.unwrap();
    let e = error(refresh(&f, "client1", &rt, None).await);
    assert_eq!(
        (e.error.as_ref(), e.description.as_deref()),
        (
            "invalid_request",
            Some(
                "Proof of possession was used to obtain the initial refresh token and is required for subsequent token requests."
            )
        )
    );
    // A confidential client may present a new key; the token follows it.
    let other = ec();
    let renewed = refresh(&f, "client1", &rt, Some(&proof(&other)))
        .await
        .unwrap();
    assert_eq!(renewed.token_type, "DPoP");
    assert_eq!(cnf(&renewed), Some(json!({ "jkt": thumbprint(&other) })));

    // Bearer-issued: renewal can't start using DPoP.
    let r = redeem(&f, "client1", &code(&f, "client1", None).await, None)
        .await
        .unwrap();
    let rt = r.refresh_token.unwrap();
    let e = error(refresh(&f, "client1", &rt, Some(&proof(&key))).await);
    assert_eq!(
        (e.error.as_ref(), e.description.as_deref()),
        (
            "invalid_request",
            Some(
                "Proof of possession can't be used on subsequent token requests unless used when requesting the initial refresh token."
            )
        )
    );
    assert_eq!(
        refresh(&f, "client1", &rt, None).await.unwrap().token_type,
        "Bearer"
    );
}

#[tokio::test]
async fn a_public_client_must_keep_its_key() {
    let f = fixture();
    let key = rsa();
    let r = redeem(
        &f,
        "client2",
        &code(&f, "client2", None).await,
        Some(&proof(&key)),
    )
    .await
    .unwrap();
    let rt = r.refresh_token.unwrap();
    let e = error(refresh(&f, "client2", &rt, Some(&proof(&ec()))).await);
    assert_eq!(
        (e.error.as_ref(), e.description.as_deref()),
        (
            "invalid_dpop_proof",
            Some(
                "The DPoP proof token in the refresh token request does not match the original used."
            )
        )
    );
    let renewed = refresh(&f, "client2", &rt, Some(&proof(&key)))
        .await
        .unwrap();
    assert_eq!(cnf(&renewed), Some(json!({ "jkt": thumbprint(&key) })));
}

/// Introspects `token` as the `api` resource.
async fn introspect(f: &Fixture, token: &str) -> Value {
    use base64::Engine;
    let basic = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("api:secret")
    );
    match rustid_core::introspection::process(
        &f.ctx(Utc::now()),
        Some(&basic),
        &Form::from_pairs(&[("token", token)]),
    )
    .await
    .unwrap()
    {
        rustid_core::introspection::Introspection::Response { entries, .. } => {
            Value::Object(entries)
        }
        other => panic!("expected a response, got {other:?}"),
    }
}

#[tokio::test]
async fn introspection_shows_the_binding() {
    let mut f = fixture();
    let key = rsa();
    let jwt = request(&f, Some(&proof(&key)), CLIENT_CREDENTIALS)
        .await
        .unwrap();
    let body = introspect(&f, &jwt.access_token).await;
    assert_eq!(body["active"], true);
    assert_eq!(body["cnf"], json!({ "jkt": thumbprint(&key) }));

    f.edit_clients(|clients| {
        let c = clients
            .iter_mut()
            .find(|c| c.client_id == "client1")
            .unwrap();
        c.access_token_type = AccessTokenType::Reference;
    });
    let reference = request(&f, Some(&proof(&key)), CLIENT_CREDENTIALS)
        .await
        .unwrap();
    let body = introspect(&f, &reference.access_token).await;
    assert_eq!(body["active"], true);
    assert_eq!(body["cnf"], json!({ "jkt": thumbprint(&key) }));
}

#[tokio::test]
async fn the_proof_length_limit_counts_utf16_units() {
    let f = fixture();
    // 2100 characters, 4200 bytes: within the 4000-unit limit, so the
    // proof is read (and is malformed) rather than too long.
    let proof = "é".repeat(2100);
    let e = error(request(&f, Some(&proof), CLIENT_CREDENTIALS).await);
    assert_eq!(e.description.as_deref(), Some("Malformed DPoP token."));
}
