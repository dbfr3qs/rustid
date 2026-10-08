//! Dynamic client registration (RFC 7591):
//! the validator, processing, persistence and the response.

use rustid_core::dcr::{self, RegistrationRequest};
use serde_json::json;

fn request(body: serde_json::Value) -> RegistrationRequest {
    serde_json::from_value(body).unwrap()
}

fn error(body: serde_json::Value) -> (&'static str, String) {
    let e = dcr::validate(&mut request(body)).unwrap_err();
    (e.error, e.error_description)
}

fn metadata(description: &str) -> (&'static str, String) {
    ("invalid_client_metadata", description.to_owned())
}

const CB: &str = "https://example.com/callback";

fn public_jwk() -> serde_json::Value {
    json!({ "kty": "RSA", "alg": "RS256", "e": "AQAB", "n": "sXch" })
}

#[test]
fn missing_grant_type_fails() {
    assert_eq!(
        error(json!({ "redirect_uris": [CB] })),
        metadata("grant type is required")
    );
}

#[test]
fn unsupported_grant_type_fails() {
    assert_eq!(
        error(json!({ "redirect_uris": [CB], "grant_types": ["password"] })),
        metadata("unsupported grant type")
    );
}

#[test]
fn client_credentials_with_redirect_uri_fails() {
    assert_eq!(
        error(json!({ "redirect_uris": [CB], "grant_types": ["client_credentials"] })),
        (
            "invalid_redirect_uri",
            "redirect URI not compatible with client_credentials grant type".into()
        )
    );
}

#[test]
fn auth_code_without_redirect_uri_fails() {
    assert_eq!(
        error(json!({ "grant_types": ["authorization_code"] })),
        (
            "invalid_redirect_uri",
            "redirect URI required for authorization_code grant type".into()
        )
    );
}

#[test]
fn relative_redirect_uri_fails() {
    assert_eq!(
        error(json!({ "grant_types": ["authorization_code"], "redirect_uris": ["/cb"] })),
        ("invalid_redirect_uri", "malformed redirect URI".into())
    );
}

#[test]
fn client_credentials_and_refresh_token_fails() {
    assert_eq!(
        error(json!({ "grant_types": ["client_credentials", "refresh_token"] })),
        metadata(
            "Refresh token grant requested, but no grant that supports refresh tokens was requested"
        )
    );
}

#[test]
fn jwks_and_jwks_uri_together_fail() {
    assert_eq!(
        error(json!({ "grant_types": ["client_credentials"],
            "jwks_uri": "https://example.com/jwks", "jwks": { "keys": [] } })),
        metadata("The jwks_uri and jwks parameters must not be used together")
    );
}

#[test]
fn client_credentials_without_client_secret_fails() {
    for body in [
        json!({ "grant_types": ["client_credentials"], "require_client_secret": false }),
        json!({ "grant_types": ["client_credentials"], "token_endpoint_auth_method": "none" }),
    ] {
        assert_eq!(
            error(body),
            metadata("client secret is required for client credentials grant type")
        );
    }
}

#[test]
fn negative_absolute_refresh_token_lifetime_fails() {
    assert_eq!(
        error(
            json!({ "grant_types": ["authorization_code", "refresh_token"],
            "redirect_uris": [CB], "absolute_refresh_token_lifetime": -1 })
        ),
        metadata("The absolute refresh token lifetime must be 0 or greater if used")
    );
}

#[test]
fn every_other_failure_branch() {
    let code = |extra: serde_json::Value| {
        let mut body = json!({ "grant_types": ["authorization_code", "refresh_token"], "redirect_uris": [CB] });
        for (k, v) in extra.as_object().unwrap() {
            body[k] = v.clone();
        }
        error(body)
    };
    let rows = [
        (
            json!({ "authorization_code_lifetime": 0 }),
            "The authorization code lifetime must be greater than 0 if used",
        ),
        (
            json!({ "sliding_refresh_token_lifetime": 0 }),
            "The sliding refresh token lifetime must be greater than 0 if used",
        ),
        (
            json!({ "refresh_token_expiration": "absolute" }),
            "invalid refresh token expiration - use Absolute or Sliding (case-sensitive)",
        ),
        (
            json!({ "refresh_token_usage": "reuse" }),
            "invalid refresh token usage - use OneTimeOnly or ReUse (case-sensitive)",
        ),
        (
            json!({ "default_max_age": 0 }),
            "default_max_age must be greater than 0 if used",
        ),
        (
            json!({ "consent_lifetime": 0 }),
            "The consent lifetime must be greater than 0 if used",
        ),
        (
            json!({ "access_token_type": "jwt" }),
            "invalid access token type - use Jwt or Reference (case-sensitive)",
        ),
        (
            json!({ "access_token_lifetime": 0 }),
            "The access token lifetime must be greater than 0 if used",
        ),
        (
            json!({ "identity_token_lifetime": -5 }),
            "The identity token lifetime must be greater than 0 if used",
        ),
        (
            json!({ "require_signed_request_object": true }),
            "Jwks are required when the require signed request object flag is enabled",
        ),
    ];
    for (extra, description) in rows {
        assert_eq!(code(extra.clone()), metadata(description), "{extra}");
    }
    assert_eq!(
        error(json!({ "grant_types": ["client_credentials"], "default_max_age": 10 })),
        metadata("default_max_age requires authorization code grant type")
    );
}

#[test]
fn a_valid_request_maps_onto_the_client() {
    let mut r = request(json!({
        "redirect_uris": [CB, CB], "grant_types": ["authorization_code", "refresh_token"],
        "client_name": "test", "client_uri": "https://example.com", "default_max_age": 10000,
        "scope": "api1 openid  profile offline_access api1", "absolute_refresh_token_lifetime": 0,
        "refresh_token_usage": "OneTimeOnly", "access_token_type": "Reference",
        "token_endpoint_auth_method": "none", "post_logout_redirect_uris": ["https://example.com/out"]
    }));
    let client = dcr::validate(&mut r).unwrap();
    assert_eq!(client.allowed_grant_types, vec!["authorization_code"]);
    assert!(client.allow_offline_access);
    assert_eq!(client.redirect_uris, vec![CB], "a set");
    assert_eq!(
        client.allowed_scopes,
        vec!["api1", "openid", "profile"],
        "offline_access dropped"
    );
    assert_eq!(client.client_name.as_deref(), Some("test"));
    assert_eq!(
        client.client_uri.as_deref(),
        Some("https://example.com/"),
        "Uri.AbsoluteUri"
    );
    assert_eq!(client.user_sso_lifetime, Some(10000));
    assert_eq!(client.absolute_refresh_token_lifetime, 0);
    assert_eq!(
        client.refresh_token_usage,
        rustid_core::clients::RefreshTokenUsage::OneTimeOnly
    );
    assert_eq!(
        client.access_token_type,
        rustid_core::clients::AccessTokenType::Reference
    );
    assert!(!client.require_client_secret, "none");
    assert_eq!(
        client.post_logout_redirect_uris,
        vec!["https://example.com/out"]
    );
    assert!(
        client.front_channel_logout_session_required && client.back_channel_logout_session_required
    );
}

#[test]
fn the_auth_method_defaults_to_basic_after_the_jwks_checks() {
    let mut r = request(json!({ "grant_types": ["client_credentials"] }));
    dcr::validate(&mut r).unwrap();
    assert_eq!(
        r.token_endpoint_auth_method.as_deref(),
        Some("client_secret_basic")
    );
    assert_eq!(
        error(
            json!({ "grant_types": ["client_credentials"], "token_endpoint_auth_method": "private_key_jwt" })
        ),
        metadata(
            "Missing jwks parameter - the private_key_jwt token_endpoint_auth_method requires the jwks parameter"
        )
    );
}

#[test]
fn jwks_become_jwk_secrets() {
    let client = dcr::validate(&mut request(json!({
        "grant_types": ["client_credentials"], "jwks": { "keys": [public_jwk()] },
        "require_signed_request_object": true
    })))
    .unwrap();
    assert_eq!(client.client_secrets.len(), 1);
    assert_eq!(client.client_secrets[0].secret_type, "JWK");
    assert_eq!(client.client_secrets[0].value, public_jwk().to_string());
    assert!(client.require_request_object);
}

/// A private key (RSA private members or an EC `d`) with an
/// `HS` algorithm; and a key that isn't a JWK object.
#[test]
fn private_keys_for_hmac_and_malformed_keys_are_refused() {
    let private = json!({ "kty": "RSA", "alg": "HS256", "e": "AQAB", "n": "sXch",
        "d": "a", "dp": "b", "dq": "c", "p": "d", "q": "e", "qi": "f" });
    assert_eq!(
        error(json!({ "grant_types": ["client_credentials"], "jwks": { "keys": [private] } })),
        metadata("unexpected private key in jwk")
    );
    assert_eq!(
        error(json!({ "grant_types": ["client_credentials"], "jwks": { "keys": [42] } })),
        metadata("malformed jwk")
    );
}

/// The memory stores: `configuration` is what registration writes, and
/// `clients` (the same `InMemoryConfiguration`) is what the runtime reads.
fn memory() -> rustid_core::stores::Stores {
    rustid_store_memory::stores(Default::default(), Default::default())
}

async fn register_in(
    stores: &rustid_core::stores::Stores,
    options: &dcr::DcrOptions,
    body: serde_json::Value,
) -> serde_json::Map<String, serde_json::Value> {
    let request = dcr::parse(body.to_string().as_bytes()).unwrap();
    dcr::register(
        stores.configuration.as_ref(),
        &Default::default(),
        options,
        &rustid_core::request_uri::NoRequestUriFetcher,
        request,
        chrono::Utc::now(),
    )
    .await
    .unwrap()
    .unwrap()
}

async fn stored(
    stores: &rustid_core::stores::Stores,
    body: &serde_json::Map<String, serde_json::Value>,
) -> std::sync::Arc<rustid_core::clients::Client> {
    stores
        .clients
        .find_client_by_id(body["client_id"].as_str().unwrap())
        .await
        .unwrap()
        .expect("served at once")
}

/// A valid request creates the client.
#[tokio::test]
async fn a_confidential_client_gets_a_generated_secret_stored_hashed() {
    use rustid_core::admin::secrets::{HashAlgorithm, hash_secret};
    let stores = memory();
    let body = register_in(&stores, &Default::default(), json!({
        "redirect_uris": [CB], "grant_types": ["authorization_code"], "client_name": "test",
        "client_uri": "https://example.com", "default_max_age": 10000, "scope": "api1 openid profile"
    }))
    .await;
    let secret = body["client_secret"].as_str().unwrap();
    assert_eq!(
        body["client_id"].as_str().unwrap().len(),
        43,
        "32 random bytes, base64url"
    );
    assert_eq!(body["client_secret_expires_at"], 0);
    assert_eq!(body["token_endpoint_auth_method"], "client_secret_basic");
    assert_eq!(body["response_types"], json!(["code"]));

    let client = stored(&stores, &body).await;
    assert_eq!(client.allowed_grant_types, vec!["authorization_code"]);
    assert_eq!(client.client_name.as_deref(), Some("test"));
    assert_eq!(client.client_uri.as_deref(), Some("https://example.com/"));
    assert_eq!(client.user_sso_lifetime, Some(10000));
    assert_eq!(client.client_secrets.len(), 1);
    assert_eq!(client.client_secrets[0].secret_type, "SharedSecret");
    assert_eq!(
        client.client_secrets[0].value,
        hash_secret(secret, HashAlgorithm::Sha256)
    );
}

#[tokio::test]
async fn public_and_private_key_jwt_clients_get_no_secret() {
    let stores = memory();
    let public = register_in(
        &stores,
        &Default::default(),
        json!({ "redirect_uris": [CB],
        "grant_types": ["authorization_code"], "token_endpoint_auth_method": "none" }),
    )
    .await;
    assert!(public.get("client_secret").is_none());
    assert!(public.get("client_secret_expires_at").is_none());
    assert_eq!(public["require_client_secret"], false);
    let pkj = register_in(
        &stores,
        &Default::default(),
        json!({ "redirect_uris": [CB],
        "grant_types": ["authorization_code"], "token_endpoint_auth_method": "private_key_jwt",
        "jwks": { "keys": [public_jwk()] } }),
    )
    .await;
    assert!(pkj.get("client_secret").is_none());
    let client = stored(&stores, &pkj).await;
    assert_eq!(client.client_secrets.len(), 1);
    assert_eq!(client.client_secrets[0].secret_type, "JWK");
}

#[tokio::test]
async fn jwks_with_basic_auth_get_both_secrets() {
    let stores = memory();
    let body = register_in(
        &stores,
        &Default::default(),
        json!({ "redirect_uris": [CB],
        "grant_types": ["authorization_code"], "jwks": { "keys": [public_jwk()] } }),
    )
    .await;
    assert!(body["client_secret"].is_string());
    assert_eq!(body["token_endpoint_auth_method"], "client_secret_basic");
    assert_eq!(
        body["jwks"],
        json!({ "Keys": [public_jwk()] }),
        "KeySet.Keys, unnamed"
    );
    let first: Vec<&String> = body.keys().take(4).collect();
    assert_eq!(
        first,
        [
            "client_id",
            "client_secret",
            "client_secret_expires_at",
            "response_types"
        ]
    );
    let types: Vec<String> = stored(&stores, &body)
        .await
        .client_secrets
        .iter()
        .map(|s| s.secret_type.clone())
        .collect();
    assert_eq!(types, vec!["JWK", "SharedSecret"]);
}

#[tokio::test]
async fn secret_lifetime_sets_client_secret_expires_at() {
    let stores = memory();
    let options = dcr::DcrOptions {
        secret_lifetime: Some(3600),
        ..Default::default()
    };
    let now = chrono::Utc::now();
    let request = dcr::parse(
        json!({ "grant_types": ["client_credentials"] })
            .to_string()
            .as_bytes(),
    )
    .unwrap();
    let body = dcr::register(
        stores.configuration.as_ref(),
        &Default::default(),
        &options,
        &rustid_core::request_uri::NoRequestUriFetcher,
        request,
        now,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(body["client_secret_expires_at"], now.timestamp() + 3600);
}

#[test]
fn wrong_member_types_are_malformed() {
    for body in [
        r#"{"grant_types":"authorization_code"}"#,
        r#"{"default_max_age":"x"}"#,
        r#"{"default_max_age":1.5}"#,
        "[]",
        "nope",
        "null",
        "",
    ] {
        let e = dcr::parse(body.as_bytes()).unwrap_err();
        assert_eq!(
            (e.error, e.error_description.as_str()),
            ("invalid_client_metadata", "malformed metadata document"),
            "{body}"
        );
    }
}

#[tokio::test]
async fn extensions_are_echoed_but_never_override_response_fields() {
    let body = register_in(
        &memory(),
        &Default::default(),
        json!({ "grant_types": ["client_credentials"],
        "contacts": ["a@b.c"], "client_secret": "mine", "client_secret_expires_at": 5,
        "response_types": ["token"] }),
    )
    .await;
    assert_eq!(body["contacts"], json!(["a@b.c"]));
    assert_ne!(body["client_secret"], "mine");
    assert_eq!(body["client_secret_expires_at"], 0);
    assert!(
        body.get("response_types").is_none(),
        "non-interactive: null, omitted"
    );
}

/// The response for a code client, nulls omitted.
#[tokio::test]
async fn the_response_echoes_the_client() {
    let body = register_in(
        &memory(),
        &Default::default(),
        json!({
            "redirect_uris": [CB], "grant_types": ["authorization_code", "refresh_token"],
            "scope": "openid", "frontchannel_logout_uri": "https://example.com/fc"
        }),
    )
    .await;
    assert_eq!(
        body["grant_types"],
        json!(["authorization_code", "refresh_token"])
    );
    assert_eq!(body["redirect_uris"], json!([CB]));
    assert_eq!(body["scope"], "openid");
    assert_eq!(body["refresh_token_expiration"], "Absolute");
    assert_eq!(body["refresh_token_usage"], "ReUse");
    assert_eq!(body["absolute_refresh_token_lifetime"], 2592000);
    assert!(
        body.get("sliding_refresh_token_lifetime").is_none(),
        "absolute expiration"
    );
    assert_eq!(body["authorization_code_lifetime"], 300);
    assert_eq!(body["frontchannel_logout_uri"], "https://example.com/fc");
    assert_eq!(body["frontchannel_logout_session_required"], true);
    assert!(
        body.get("backchannel_logout_session_required").is_none(),
        "no back-channel URI"
    );
    assert_eq!(body["post_logout_redirect_uris"], json!([]));
    assert_eq!(body["require_consent"], false);
    assert!(body.get("allow_remember_consent").is_none(), "consent off");
    assert_eq!(body["access_token_type"], "Jwt");
    assert_eq!(body["access_token_lifetime"], 3600);
    assert_eq!(body["identity_token_lifetime"], 300);
    assert!(
        body.get("allowed_identity_token_signing_algorithms")
            .is_none()
    );
    assert_eq!(body["require_signed_request_object"], false);
    assert_eq!(body["allowed_cors_origins"], json!([]));
    assert_eq!(body["enable_local_login"], true);
}

/// Default scopes for a request without
/// `scope`: none by default, the configured ones when set.
#[tokio::test]
async fn default_scopes_apply_only_without_a_requested_scope() {
    let stores = memory();
    let none = register_in(
        &stores,
        &Default::default(),
        json!({ "grant_types": ["client_credentials"] }),
    )
    .await;
    assert_eq!(none["scope"], "");
    let options = dcr::DcrOptions {
        default_scopes: vec!["openid".into(), "profile".into()],
        ..Default::default()
    };
    let defaulted = register_in(
        &stores,
        &options,
        json!({ "grant_types": ["client_credentials"] }),
    )
    .await;
    assert_eq!(defaulted["scope"], "openid profile");
    let asked = register_in(
        &stores,
        &options,
        json!({ "grant_types": ["client_credentials"], "scope": "api1" }),
    )
    .await;
    assert_eq!(asked["scope"], "api1");
}

/// Registered clients get the `Client` default (PKCE required) unless
/// the server says otherwise.
#[tokio::test]
async fn require_pkce_follows_the_option() {
    let stores = memory();
    let body = json!({ "grant_types": ["authorization_code"], "redirect_uris": [CB] });
    let default = register_in(&stores, &Default::default(), body.clone()).await;
    assert!(stored(&stores, &default).await.require_pkce);
    let options = dcr::DcrOptions {
        require_pkce: Some(false),
        ..Default::default()
    };
    let relaxed = register_in(&stores, &options, body).await;
    assert!(!stored(&stores, &relaxed).await.require_pkce);
}

/// Members named like the management ones never reach a read (RFC 7592).
#[tokio::test]
async fn extensions_never_override_the_management_read() {
    let stores = memory();
    let options = dcr::DcrOptions {
        management: Some(dcr::ManagementUri {
            base: "https://idp.test/connect/dcr".into(),
        }),
        ..Default::default()
    };
    let body = register_in(
        &stores,
        &options,
        json!({ "grant_types": ["client_credentials"],
        "registration_client_uri": "https://evil.test/x", "registration_access_token": "bogus" }),
    )
    .await;
    let uri = body["registration_client_uri"].as_str().unwrap().to_owned();
    assert!(uri.starts_with("https://idp.test/connect/dcr/"), "{uri}");
    assert_ne!(body["registration_access_token"], "bogus");
    let client = stored(&stores, &body).await;
    let read = dcr::read(&client, &uri).unwrap();
    assert_eq!(read["registration_client_uri"], uri.as_str());
    assert!(read.get("registration_access_token").is_none());
}

#[tokio::test]
async fn management_members_are_not_echoed_without_management() {
    let body = register_in(
        &memory(),
        &Default::default(),
        json!({ "grant_types": ["client_credentials"],
        "registration_client_uri": "https://evil.test/x", "registration_access_token": "bogus" }),
    )
    .await;
    assert!(body.get("registration_client_uri").is_none());
    assert!(body.get("registration_access_token").is_none());
}

/// An admin update (a rename) keeps the client's RFC 7592 management: the
/// `dcr_` properties aren't extended properties, so admin carries them over.
#[tokio::test]
async fn an_admin_update_keeps_management() {
    use rustid_core::admin::clients::{ClientAdmin, ClientInput};
    let stores = memory();
    let options = dcr::DcrOptions {
        management: Some(dcr::ManagementUri {
            base: "https://idp.test/connect/dcr".into(),
        }),
        ..Default::default()
    };
    let body = register_in(
        &stores,
        &options,
        json!({ "grant_types": ["client_credentials"] }),
    )
    .await;
    let token = body["registration_access_token"].as_str().unwrap();
    let admin = ClientAdmin::default();
    let found = admin
        .get_by_client_id(
            stores.configuration.as_ref(),
            body["client_id"].as_str().unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    let mut client = found.item.client.clone();
    client.client_name = Some("renamed".into());
    let input = ClientInput {
        client,
        client_secrets: Vec::new(),
        extended_properties: Default::default(),
    };
    admin
        .update(
            stores.configuration.as_ref(),
            &found.id,
            input,
            found.version,
        )
        .await
        .unwrap()
        .unwrap();
    let client = stored(&stores, &body).await;
    assert_eq!(client.client_name.as_deref(), Some("renamed"));
    assert!(
        dcr::authorize_management(&client, token),
        "the token still manages it"
    );
    assert!(dcr::read(&client, "u").is_some());
}

#[test]
fn jwk_members_of_the_wrong_type_are_malformed() {
    for key in [
        json!({ "kty": 5 }),
        json!({ "kty": "RSA", "n": 5, "e": "AQAB" }),
        json!({ "kty": "RSA", "alg": true }),
        json!({ "kty": "RSA", "x5c": [1] }),
    ] {
        assert_eq!(
            error(
                json!({ "grant_types": ["client_credentials"], "jwks": { "keys": [key.clone()] } })
            ),
            metadata("malformed jwk"),
            "{key}"
        );
    }
    assert!(
        dcr::validate(&mut request(json!({ "grant_types": ["client_credentials"],
        "jwks": { "keys": [{ "kty": "RSA", "x5c": ["abc"], "key_ops": ["verify"] }] } })))
        .is_ok()
    );
}

#[tokio::test]
async fn stored_dcr_secrets_name_their_hash_algorithm() {
    let stores = memory();
    let body = register_in(
        &stores,
        &Default::default(),
        json!({ "grant_types": ["client_credentials"] }),
    )
    .await;
    let entity = stores
        .configuration
        .read_by_key(
            rustid_core::stores::EntityKind::Client,
            body["client_id"].as_str().unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(entity.data["clientSecrets"][0]["hashAlgorithm"], "SHA256");
}

/// Answers the sector identifier document at one URL.
struct Sector(&'static str, Option<rustid_core::request_uri::Fetched>);

#[async_trait::async_trait]
impl rustid_core::request_uri::RequestUriFetcher for Sector {
    async fn fetch(&self, uri: &str) -> Option<rustid_core::request_uri::Fetched> {
        (uri == self.0).then(|| self.1.clone()).flatten()
    }
}

const SECTOR: &str = "https://sector.example/uris.json";

fn document(status: u16, body: &str) -> Option<rustid_core::request_uri::Fetched> {
    Some(rustid_core::request_uri::Fetched {
        status,
        content_type: Some("application/json".into()),
        body: body.into(),
    })
}

async fn register_pairwise(
    stores: &rustid_core::stores::Stores,
    pairwise_supported: bool,
    fetched: Option<rustid_core::request_uri::Fetched>,
    body: serde_json::Value,
) -> Result<serde_json::Map<String, serde_json::Value>, dcr::RegistrationError> {
    let request = dcr::parse(body.to_string().as_bytes()).unwrap();
    dcr::register(
        stores.configuration.as_ref(),
        &rustid_core::admin::clients::ClientAdmin {
            pairwise_supported,
            ..Default::default()
        },
        &Default::default(),
        &Sector(SECTOR, fetched),
        request,
        chrono::Utc::now(),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn a_pairwise_client_registers_with_its_sector_document() {
    let stores = memory();
    let body = register_pairwise(
        &stores,
        true,
        document(200, &format!(r#"["{CB}", "https://other.example/cb"]"#)),
        json!({ "redirect_uris": [CB], "grant_types": ["authorization_code"], "subject_type": "pairwise", "sector_identifier_uri": SECTOR }),
    )
    .await
    .unwrap();
    assert_eq!(body["subject_type"], "pairwise");
    assert_eq!(body["sector_identifier_uri"], SECTOR);
    let client = stored(&stores, &body).await;
    assert_eq!(
        client.subject_type,
        rustid_core::clients::SubjectType::Pairwise
    );
    assert_eq!(client.sector_identifier_uri.as_deref(), Some(SECTOR));
}

#[tokio::test]
async fn bad_pairwise_registrations_are_invalid_client_metadata() {
    let pairwise = |uri: &str| json!({ "redirect_uris": [CB], "grant_types": ["authorization_code"], "subject_type": "pairwise", "sector_identifier_uri": uri });
    let missing = r#"["https://other.example/cb"]"#.to_string();
    for (label, supported, fetched, body) in [
        ("unreachable", true, None, pairwise(SECTOR)),
        ("not 200", true, document(404, "[]"), pairwise(SECTOR)),
        ("not JSON", true, document(200, "<html>"), pairwise(SECTOR)),
        (
            "not an array",
            true,
            document(200, r#"{"a":1}"#),
            pairwise(SECTOR),
        ),
        (
            "not strings",
            true,
            document(200, "[1, 2]"),
            pairwise(SECTOR),
        ),
        (
            "missing the redirect",
            true,
            document(200, &missing),
            pairwise(SECTOR),
        ),
        (
            "http",
            true,
            document(200, "[]"),
            pairwise("http://sector.example/uris.json"),
        ),
        (
            "no salt",
            false,
            document(200, &format!(r#"["{CB}"]"#)),
            pairwise(SECTOR),
        ),
        (
            "unknown type",
            true,
            None,
            json!({ "redirect_uris": [CB], "grant_types": ["authorization_code"], "subject_type": "secret" }),
        ),
    ] {
        let error = register_pairwise(&memory(), supported, fetched, body)
            .await
            .expect_err(label);
        assert_eq!(error.error, "invalid_client_metadata", "{label}");
    }
}

#[tokio::test]
async fn a_public_registration_is_unchanged() {
    let stores = memory();
    let body = register_pairwise(
        &stores,
        false,
        None,
        json!({ "redirect_uris": [CB], "grant_types": ["authorization_code"], "subject_type": "public" }),
    )
    .await
    .unwrap();
    assert_eq!(body["subject_type"], "public");
    let client = stored(&stores, &body).await;
    assert_eq!(
        client.subject_type,
        rustid_core::clients::SubjectType::Public
    );
}

#[test]
fn redirect_uris_never_carry_a_fragment_and_login_initiation_is_https() {
    assert_eq!(
        error(json!({ "redirect_uris": ["https://example.com/cb#frag"], "grant_types": ["authorization_code"] })).0,
        "invalid_redirect_uri"
    );
    assert_eq!(
        error(
            json!({ "redirect_uris": [CB], "grant_types": ["authorization_code"], "initiate_login_uri": "http://example.com/login" })
        ),
        metadata("initiate_login_uri must be an https URL")
    );
    let mut ok = request(
        json!({ "redirect_uris": [CB], "grant_types": ["authorization_code"], "initiate_login_uri": "https://example.com/login" }),
    );
    assert!(dcr::validate(&mut ok).is_ok());
}

async fn register_userinfo(
    body: serde_json::Value,
) -> (
    rustid_core::stores::Stores,
    Result<serde_json::Map<String, serde_json::Value>, dcr::RegistrationError>,
) {
    let stores = memory();
    let options = dcr::DcrOptions {
        userinfo_signing_algorithms: vec!["RS256".into(), "PS256".into()],
        ..Default::default()
    };
    let request = dcr::parse(body.to_string().as_bytes()).unwrap();
    let result = dcr::register(
        stores.configuration.as_ref(),
        &Default::default(),
        &options,
        &rustid_core::request_uri::NoRequestUriFetcher,
        request,
        chrono::Utc::now(),
    )
    .await
    .unwrap();
    (stores, result)
}

#[tokio::test]
async fn signed_userinfo_is_registered_with_an_advertised_algorithm() {
    let (stores, result) = register_userinfo(json!({
        "redirect_uris": [CB], "grant_types": ["authorization_code"],
        "userinfo_signed_response_alg": "RS256",
    }))
    .await;
    let body = result.unwrap();
    assert_eq!(body["userinfo_signed_response_alg"], "RS256");
    let client = stored(&stores, &body).await;
    assert_eq!(
        client.userinfo_signed_response_alg.as_deref(),
        Some("RS256")
    );
}

#[tokio::test]
async fn unadvertised_or_encrypted_userinfo_is_invalid_client_metadata() {
    for body in [
        json!({ "redirect_uris": [CB], "grant_types": ["authorization_code"], "userinfo_signed_response_alg": "ES512" }),
        json!({ "redirect_uris": [CB], "grant_types": ["authorization_code"], "userinfo_signed_response_alg": "none" }),
        json!({ "redirect_uris": [CB], "grant_types": ["authorization_code"], "userinfo_encrypted_response_alg": "RSA-OAEP" }),
    ] {
        let (_, result) = register_userinfo(body.clone()).await;
        assert_eq!(
            result.expect_err(&body.to_string()).error,
            "invalid_client_metadata"
        );
    }
}
