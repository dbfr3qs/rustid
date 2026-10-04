//! Signed request objects by value (the JWT request validator and
//! the request object validator): keys, claims checks, and how the object's
//! parameters replace the query's.

mod support;

use chrono::Utc;
use rustid_core::authorize::{AuthorizeFailure, validate};
use rustid_core::jwt::b64url;
use rustid_core::keys::{KeyConfig, LoadedKey};
use rustid_core::params::Params;
use serde_json::{Map, Value, json};
use support::{Fixture, ISSUER, fixture};

fn key(file: &str, alg: &str) -> LoadedKey {
    LoadedKey::load(&KeyConfig {
        kid: "k".into(),
        alg: alg.into(),
        key_file: fixture(file),
        cert_file: None,
    })
    .unwrap()
}

fn claims(extra: Value) -> Map<String, Value> {
    let now = Utc::now().timestamp();
    let mut payload = json!({
        "iss": "jar",
        "aud": ISSUER,
        "exp": now + 60,
        "iat": now,
        "client_id": "jar",
        "response_type": "id_token",
        "scope": "openid profile",
        "redirect_uri": "https://client.test/callback",
        "state": "object_state",
        "nonce": "object_nonce",
        "foo": "123foo",
    });
    for (k, v) in extra.as_object().unwrap() {
        if v.is_null() {
            payload.as_object_mut().unwrap().remove(k);
        } else {
            payload[k] = v.clone();
        }
    }
    payload.as_object().unwrap().clone()
}

fn signed(file: &str, alg: &str, typ: Option<&str>, payload: &Map<String, Value>) -> String {
    let header: Vec<(&str, &str)> = typ.map(|t| ("typ", t)).into_iter().collect();
    rustid_core::jwt::encode(&key(file, alg), &header, payload).unwrap()
}

/// An HS256 object signed with the `jar` client's symmetric JWK.
fn hmac(payload: &Map<String, Value>) -> String {
    let header = b64url(br#"{"alg":"HS256","typ":"JWT"}"#);
    let body = b64url(serde_json::to_string(payload).unwrap().as_bytes());
    let input = format!("{header}.{body}");
    let key = aws_lc_rs::hmac::Key::new(
        aws_lc_rs::hmac::HMAC_SHA256,
        b"a symmetric key of at least 32 bytes for HS256!",
    );
    let tag = aws_lc_rs::hmac::sign(&key, input.as_bytes());
    format!("{input}.{}", b64url(tag.as_ref()))
}

fn unsigned(payload: &Map<String, Value>) -> String {
    let header = b64url(br#"{"alg":"none"}"#);
    let body = b64url(serde_json::to_string(payload).unwrap().as_bytes());
    format!("{header}.{body}.")
}

/// The authorize request `client_id=jar&response_type=id_token` with the
/// object and extra query parameters.
async fn authorize(
    f: &Fixture,
    object: &str,
    query: &str,
) -> Result<rustid_core::authorize::ValidatedAuthorizeRequest, (String, Option<String>)> {
    let raw = Params::parse_query(&format!(
        "client_id=jar&response_type=id_token&request={object}{query}"
    ));
    match validate(&f.authorize_ctx(Utc::now()), raw, None).await {
        Ok(r) => Ok(r),
        Err(AuthorizeFailure::Invalid(e)) => Err((e.error.to_owned(), e.description)),
        Err(AuthorizeFailure::Server(m)) => panic!("{m}"),
    }
}

fn jar_error() -> (String, Option<String>) {
    (
        "invalid_request_object".to_owned(),
        Some("Invalid JWT request".to_owned()),
    )
}

fn with_hs256(f: &mut Fixture) {
    f.options
        .supported_request_object_signing_algorithms
        .push("HS256".into());
}

#[tokio::test]
async fn the_objects_parameters_replace_the_querys() {
    let f = Fixture::new();
    let object = signed("client-jwt-key.pem", "RS256", None, &claims(json!({})));
    let r = authorize(&f, &object, "&state=query_state&display=popup")
        .await
        .unwrap();
    assert_eq!(r.raw.get("state").as_deref(), Some("object_state"));
    assert_eq!(r.raw.get("foo").as_deref(), Some("123foo"));
    assert_eq!(r.raw.get("display").as_deref(), Some("popup"), "kept");
    assert_eq!(r.raw.get("request").as_deref(), Some(object.as_str()));
    assert!(r.raw.get("iss").is_none() && r.raw.get("aud").is_none());
    assert!(r.raw.get("exp").is_none() && r.raw.get("iat").is_none());
    assert_eq!(r.nonce.as_deref(), Some("object_nonce"));
    assert_eq!(r.request_object.as_deref(), Some(object.as_str()));
}

#[tokio::test]
async fn complex_values_arrive_as_json() {
    let f = Fixture::new();
    let payload = claims(json!({
        "claims": { "id_token": { "name": { "essential": true } } },
    }));
    let object = signed("client-jwt-key.pem", "RS256", None, &payload);
    let r = authorize(&f, &object, "").await.unwrap();
    assert_eq!(
        r.raw.get("claims").as_deref(),
        Some(r#"{"id_token":{"name":{"essential":true}}}"#)
    );
}

#[tokio::test]
async fn rsa_ec_symmetric_and_certificate_keys_are_accepted() {
    let mut f = Fixture::new();
    with_hs256(&mut f);
    let payload = claims(json!({}));
    for object in [
        signed("client-jwt-key.pem", "RS256", None, &payload),
        signed("client-jwt-ec-key.pem", "ES256", None, &payload),
        signed("validation-cert-key.pem", "RS256", None, &payload),
        hmac(&payload),
    ] {
        assert!(authorize(&f, &object, "").await.is_ok());
    }
}

#[tokio::test]
async fn invalid_objects_are_invalid_request_objects() {
    let f = Fixture::new();
    let now = Utc::now().timestamp();
    for (why, object) in [
        (
            "audience",
            signed(
                "client-jwt-key.pem",
                "RS256",
                None,
                &claims(json!({ "aud": "https://other" })),
            ),
        ),
        (
            "issuer",
            signed(
                "client-jwt-key.pem",
                "RS256",
                None,
                &claims(json!({ "iss": "other" })),
            ),
        ),
        (
            "no expiry",
            signed(
                "client-jwt-key.pem",
                "RS256",
                None,
                &claims(json!({ "exp": null })),
            ),
        ),
        (
            "expired",
            signed(
                "client-jwt-key.pem",
                "RS256",
                None,
                &claims(json!({ "exp": now - 600 })),
            ),
        ),
        (
            "not yet valid",
            signed(
                "client-jwt-key.pem",
                "RS256",
                None,
                &claims(json!({ "nbf": now + 600 })),
            ),
        ),
        (
            "another key",
            signed("signing-key.pem", "RS256", None, &claims(json!({}))),
        ),
        ("unsigned", unsigned(&claims(json!({})))),
        ("HS256 not allowed", hmac(&claims(json!({})))),
        (
            "request inside",
            signed(
                "client-jwt-key.pem",
                "RS256",
                None,
                &claims(json!({ "request": "x" })),
            ),
        ),
        (
            "request_uri inside",
            signed(
                "client-jwt-key.pem",
                "RS256",
                None,
                &claims(json!({ "request_uri": "https://x" })),
            ),
        ),
        (
            "no client_id",
            signed(
                "client-jwt-key.pem",
                "RS256",
                None,
                &claims(json!({ "client_id": null })),
            ),
        ),
    ] {
        assert_eq!(
            authorize(&f, &object, "").await.unwrap_err(),
            jar_error(),
            "{why}"
        );
    }
}

#[tokio::test]
async fn a_mismatched_client_or_response_type_is_an_invalid_request() {
    let f = Fixture::new();
    for payload in [
        claims(json!({ "client_id": "web" })),
        claims(json!({ "response_type": "code" })),
    ] {
        let object = signed("client-jwt-key.pem", "RS256", None, &payload);
        assert_eq!(
            authorize(&f, &object, "").await.unwrap_err(),
            (
                "invalid_request".to_owned(),
                Some("Invalid JWT request".to_owned())
            )
        );
    }
}

#[tokio::test]
async fn strict_validation_wants_the_authorization_request_type() {
    let mut f = Fixture::new();
    f.options.strict_jar_validation = true;
    let payload = claims(json!({}));
    let missing = signed("client-jwt-key.pem", "RS256", None, &payload);
    assert_eq!(authorize(&f, &missing, "").await.unwrap_err(), jar_error());
    let generic = signed("client-jwt-key.pem", "RS256", Some("JWT"), &payload);
    assert_eq!(authorize(&f, &generic, "").await.unwrap_err(), jar_error());
    let typed = signed(
        "client-jwt-key.pem",
        "RS256",
        Some("oauth-authz-req+jwt"),
        &payload,
    );
    assert!(authorize(&f, &typed, "").await.is_ok());
}

#[tokio::test]
async fn a_client_requiring_objects_needs_one() {
    let f = Fixture::new();
    let raw = Params::parse_query(
        "client_id=jar.required&response_type=id_token&scope=openid&redirect_uri=https%3A%2F%2Fclient.test%2Fcallback&nonce=n",
    );
    match validate(&f.authorize_ctx(Utc::now()), raw, None).await {
        Err(AuthorizeFailure::Invalid(e)) => {
            assert_eq!(e.error, "invalid_request");
            assert_eq!(
                e.description.as_deref(),
                Some(
                    "Client must use request object, but no request or request_uri parameter present"
                )
            );
        }
        other => panic!("{other:?}"),
    }
}

/// Answers every fetch with one response, and records the URIs asked for.
struct Fetcher {
    status: u16,
    content_type: &'static str,
    body: String,
    asked: std::sync::Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl rustid_core::request_uri::RequestUriFetcher for Fetcher {
    async fn fetch(&self, uri: &str) -> Option<rustid_core::request_uri::Fetched> {
        self.asked.lock().unwrap().push(uri.to_owned());
        Some(rustid_core::request_uri::Fetched {
            status: self.status,
            content_type: Some(self.content_type.to_owned()),
            body: self.body.clone(),
        })
    }
}

fn fetching(f: &mut Fixture, status: u16, content_type: &'static str) -> std::sync::Arc<Fetcher> {
    let object = signed(
        "client-jwt-key.pem",
        "RS256",
        Some("oauth-authz-req+jwt"),
        &claims(json!({})),
    );
    let fetcher = std::sync::Arc::new(Fetcher {
        status,
        content_type,
        body: object,
        asked: Default::default(),
    });
    f.stores.request_uri = fetcher.clone();
    f.options.endpoints.enable_jwt_request_uri = true;
    fetcher
}

async fn by_reference(
    f: &Fixture,
    uri: &str,
) -> Result<rustid_core::authorize::ValidatedAuthorizeRequest, (String, Option<String>)> {
    let raw = Params::parse_query(&format!(
        "client_id=jar&response_type=id_token&request_uri={}",
        rustid_core::params::url_encode(uri)
    ));
    match validate(&f.authorize_ctx(Utc::now()), raw, None).await {
        Ok(r) => Ok(r),
        Err(AuthorizeFailure::Invalid(e)) => Err((e.error.to_owned(), e.description)),
        Err(AuthorizeFailure::Server(m)) => panic!("{m}"),
    }
}

#[tokio::test]
async fn a_request_uri_is_fetched_and_replaced_by_the_object() {
    let mut f = Fixture::new();
    let fetcher = fetching(&mut f, 200, "application/jwt");
    let r = by_reference(&f, "https://client.test/request/1")
        .await
        .unwrap();
    assert_eq!(r.raw.get("state").as_deref(), Some("object_state"));
    assert!(r.raw.get("request_uri").is_none());
    assert_eq!(r.raw.get("request"), Some(fetcher.body.clone()));
    assert_eq!(
        fetcher.asked.lock().unwrap().as_slice(),
        ["https://client.test/request/1"]
    );
}

#[tokio::test]
async fn failed_or_strictly_mistyped_fetches_are_invalid_request_uris() {
    let no_value = (
        "invalid_request_uri".to_owned(),
        Some("no value returned from request_uri".to_owned()),
    );
    for status in [404, 500] {
        let mut f = Fixture::new();
        fetching(&mut f, status, "application/oauth-authz-req+jwt");
        assert_eq!(
            by_reference(&f, "https://client.test/r").await.unwrap_err(),
            no_value
        );
    }
    let mut f = Fixture::new();
    fetching(&mut f, 200, "application/jwt");
    f.options.strict_jar_validation = true;
    assert_eq!(
        by_reference(&f, "https://client.test/r").await.unwrap_err(),
        no_value
    );
    let mut f = Fixture::new();
    fetching(&mut f, 200, "application/oauth-authz-req+jwt");
    f.options.strict_jar_validation = true;
    assert!(by_reference(&f, "https://client.test/r").await.is_ok());
}

#[tokio::test]
async fn request_uris_are_disabled_by_default_long_ones_refused_and_not_mixed() {
    let f = Fixture::new();
    assert_eq!(
        by_reference(&f, "https://client.test/r").await.unwrap_err(),
        ("request_uri_not_supported".to_owned(), None)
    );
    let mut f = Fixture::new();
    fetching(&mut f, 200, "application/jwt");
    let long = format!("https://client.test/{}", "x".repeat(500));
    assert_eq!(
        by_reference(&f, &long).await.unwrap_err(),
        (
            "invalid_request_uri".to_owned(),
            Some("request_uri is too long".to_owned())
        )
    );
    let raw = Params::parse_query(
        "client_id=jar&response_type=id_token&request=a.b.c&request_uri=https%3A%2F%2Fclient.test%2Fr",
    );
    match validate(&f.authorize_ctx(Utc::now()), raw, None).await {
        Err(AuthorizeFailure::Invalid(e)) => {
            assert_eq!(e.error, "invalid_request");
            assert_eq!(
                e.description.as_deref(),
                Some("Only one request parameter is allowed")
            );
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn ec_certificates_are_keys_for_their_curve_only() {
    use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384};
    for (curve, alg, other_alg) in [
        (&PKCS_ECDSA_P256_SHA256, "ES256", "ES384"),
        (&PKCS_ECDSA_P384_SHA384, "ES384", "ES256"),
    ] {
        let key = KeyPair::generate_for(curve).unwrap();
        let cert = CertificateParams::new(vec!["jar.test".to_owned()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let jwk = rustid_core::keys::certificate_jwk(cert.der()).expect("an EC key");
        assert_eq!(jwk.kty, "EC");
        let pkcs8 = key.serialize_der();
        let signer = LoadedKey::from_der("k", alg, &pkcs8, None, &Default::default()).unwrap();
        let object = rustid_core::jwt::encode(&signer, &[], &claims(json!({}))).unwrap();
        let jws = rustid_core::jwt::Jws::decode(&object).unwrap();
        assert!(jws.verify(&jwk), "{alg}");
        let mut forged = jws.clone();
        forged.header.insert("alg".into(), json!(other_alg));
        assert!(!forged.verify(&jwk), "{other_alg} with a {alg} key");
    }
}

/// FAPI 2 Message Signing 5.3.1: `nbf` required, at most an hour before
/// `exp`, and at most an hour old.
fn with_max_lifetime(f: &mut Fixture) {
    f.options.request_object_max_lifetime = Some(rustid_core::options::TimeSpan(3600));
    f.options.jwt_validation_clock_skew = rustid_core::options::TimeSpan(10);
}

async fn lifetime_result(
    f: &Fixture,
    nbf: Option<i64>,
    exp: i64,
) -> Result<(), (String, Option<String>)> {
    let now = Utc::now().timestamp();
    let object = signed(
        "client-jwt-key.pem",
        "RS256",
        None,
        &claims(json!({ "nbf": nbf.map(|n| now + n), "exp": now + exp })),
    );
    authorize(f, &object, "").await.map(|_| ())
}

#[tokio::test]
async fn without_nbf_is_refused() {
    let mut f = Fixture::new();
    with_max_lifetime(&mut f);
    assert_eq!(lifetime_result(&f, None, 60).await, Err(jar_error()));
}

#[tokio::test]
async fn exp_more_than_an_hour_after_nbf_is_refused() {
    let mut f = Fixture::new();
    with_max_lifetime(&mut f);
    assert_eq!(lifetime_result(&f, Some(0), 3601).await, Err(jar_error()));
}

#[tokio::test]
async fn nbf_more_than_an_hour_old_is_refused() {
    let mut f = Fixture::new();
    with_max_lifetime(&mut f);
    assert_eq!(lifetime_result(&f, Some(-3700), 60).await, Err(jar_error()));
}

#[tokio::test]
async fn lifetime_boundaries() {
    let mut f = Fixture::new();
    with_max_lifetime(&mut f);
    for (nbf, exp) in [(8, 8 + 3600), (0, 3600), (-3600, 0)] {
        assert_eq!(
            lifetime_result(&f, Some(nbf), exp).await,
            Ok(()),
            "nbf {nbf}, exp {exp}"
        );
    }
}

#[tokio::test]
async fn unset_keeps_todays_rules() {
    let f = Fixture::new();
    assert_eq!(lifetime_result(&f, None, 60).await, Ok(()));
}
