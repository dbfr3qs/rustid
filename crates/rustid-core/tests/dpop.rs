//! DPoP proof validation: every check, in
//! a fixed order, with its error and description.

use std::path::Path;

use rustid_core::data_protection::DataProtector;
use rustid_core::dpop::{
    self, DPoPError, DPoPValidationMode, INVALID_DPOP_PROOF, ProofRequest, USE_DPOP_NONCE,
};
use rustid_core::jwt::b64url;
use rustid_core::keys::{KeyConfig, LoadedKey};
use rustid_core::options::DPoPOptions;
use rustid_core::replay::InMemoryReplayCache;
use serde_json::{Map, Value, json};

const URL: &str = "https://idsrv.test/connect/token";
const NOW: i64 = 1_700_000_000;

fn key(file: &str, alg: &str) -> LoadedKey {
    LoadedKey::load(&KeyConfig {
        kid: "proof".into(),
        alg: alg.into(),
        key_file: Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures")
            .join(file),
        cert_file: None,
    })
    .unwrap()
}

fn rsa() -> LoadedKey {
    key("client-jwt-key.pem", "RS256")
}

/// The public JWK of `key` as a proof header carries it.
fn jwk(key: &LoadedKey) -> Value {
    let public = key.public_jwk();
    let mut jwk = Map::new();
    jwk.insert("kty".into(), json!(public.kty));
    for (name, value) in [
        ("n", &public.n),
        ("e", &public.e),
        ("crv", &public.crv),
        ("x", &public.x),
        ("y", &public.y),
    ] {
        if let Some(value) = value {
            jwk.insert(name.into(), json!(value));
        }
    }
    Value::Object(jwk)
}

fn sign(key: &LoadedKey, header: &Value, payload: &Value) -> String {
    let input = format!(
        "{}.{}",
        b64url(header.to_string().as_bytes()),
        b64url(payload.to_string().as_bytes())
    );
    let signature = key.sign(input.as_bytes()).unwrap();
    format!("{input}.{}", b64url(&signature))
}

fn header(key: &LoadedKey) -> Value {
    json!({ "typ": "dpop+jwt", "alg": key.alg, "jwk": jwk(key) })
}

fn payload(jti: &str) -> Value {
    json!({ "jti": jti, "htm": "POST", "htu": URL, "iat": NOW })
}

fn proof(jti: &str) -> String {
    let key = rsa();
    sign(&key, &header(&key), &payload(jti))
}

struct Fixture {
    options: DPoPOptions,
    replay: InMemoryReplayCache,
    protector: DataProtector,
}

impl Fixture {
    fn new() -> Self {
        Fixture {
            options: DPoPOptions::default(),
            replay: InMemoryReplayCache::default(),
            protector: DataProtector::new([("k", [7u8; 32].as_slice())]).unwrap(),
        }
    }

    fn request<'a>(&'a self, proof: &'a str, mode: DPoPValidationMode) -> ProofRequest<'a> {
        ProofRequest {
            proof,
            method: "POST",
            url: URL,
            mode,
            client_clock_skew: 300,
            options: &self.options,
            replay: &self.replay,
            protector: &self.protector,
            now: NOW,
            access_token: None,
        }
    }

    fn validate(&self, proof: &str) -> Result<dpop::ValidProof, DPoPError> {
        validate_proof(&self.request(proof, DPoPValidationMode::Iat))
    }
}

fn description(result: Result<dpop::ValidProof, DPoPError>) -> String {
    let error = result.expect_err("an invalid proof");
    assert_eq!(error.error, INVALID_DPOP_PROOF);
    error.description.unwrap_or_default().to_owned()
}

#[test]
fn a_valid_proof_answers_the_thumbprint_and_cnf() {
    let f = Fixture::new();
    let valid = f.validate(&proof("a")).unwrap();
    let jwk = jwk(&rsa());
    // RFC 7638: the required members in order, no whitespace.
    let canonical = format!(
        r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#,
        jwk["e"].as_str().unwrap(),
        jwk["n"].as_str().unwrap()
    );
    let expected = b64url(
        aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, canonical.as_bytes()).as_ref(),
    );
    assert_eq!(valid.thumbprint, expected);
    assert_eq!(valid.cnf, json!({ "jkt": expected }).to_string());
}

#[test]
fn ec_keys_work_and_have_their_own_thumbprint_members() {
    let f = Fixture::new();
    let ec = key("client-jwt-ec-key.pem", "ES256");
    let jwk = jwk(&ec);
    let valid = f
        .validate(&sign(&ec, &header(&ec), &payload("ec")))
        .unwrap();
    let canonical = format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
        jwk["x"].as_str().unwrap(),
        jwk["y"].as_str().unwrap()
    );
    let expected = b64url(
        aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, canonical.as_bytes()).as_ref(),
    );
    assert_eq!(valid.thumbprint, expected);
}

#[test]
fn header_checks() {
    let f = Fixture::new();
    let key = rsa();
    assert_eq!(description(f.validate("")), "Missing DPoP proof value.");
    assert_eq!(
        description(f.validate("malformed")),
        "Malformed DPoP token."
    );
    let with = |change: &dyn Fn(&mut Value)| {
        let mut h = header(&key);
        change(&mut h);
        sign(&key, &h, &payload("h"))
    };
    assert_eq!(
        description(f.validate(&with(&|h| h["typ"] = json!("JWT")))),
        "Invalid 'typ' value."
    );
    assert_eq!(
        description(f.validate(&with(&|h| {
            h.as_object_mut().unwrap().remove("typ");
        }))),
        "Invalid 'typ' value."
    );
    for alg in ["none", "HS256", "RS1"] {
        assert_eq!(
            description(f.validate(&with(&|h| h["alg"] = json!(alg)))),
            "Invalid 'alg' value.",
            "{alg}"
        );
    }
    assert_eq!(
        description(f.validate(&with(&|h| {
            h.as_object_mut().unwrap().remove("jwk");
        }))),
        "Invalid 'jwk' value."
    );
    assert_eq!(
        description(f.validate(&with(&|h| h["jwk"] = json!("a string")))),
        "Invalid 'jwk' value."
    );
    assert_eq!(
        description(f.validate(&with(
            &|h| h["jwk"] = json!({ "kty": "oct", "k": "c2VjcmV0" })
        ))),
        "Invalid signature on DPoP token.",
        "a symmetric key can't verify an asymmetric signature"
    );
    assert_eq!(
        description(f.validate(&with(&|h| h["jwk"] = json!({ "kty": "OKP", "x": "AA" })))),
        "Invalid 'jwk' value.",
        "a key type without a thumbprint"
    );
    assert_eq!(
        description(f.validate(&with(&|h| {
            for member in ["d", "p", "q", "dp", "dq", "qi"] {
                h["jwk"][member] = json!("AQAB");
            }
        }))),
        "'jwk' value contains a private key."
    );
    let ec = key_ec();
    assert_eq!(
        description(f.validate(&with(&|h| {
            h["jwk"] = jwk(&ec);
            h["jwk"]["d"] = json!("AQAB");
        }))),
        "'jwk' value contains a private key."
    );
}

fn key_ec() -> LoadedKey {
    key("client-jwt-ec-key.pem", "ES256")
}

#[test]
fn the_signature_must_be_by_the_embedded_key() {
    let f = Fixture::new();
    let key = rsa();
    let ec = key_ec();
    // Signed by another key than the one in the header.
    let mut h = header(&key);
    h["jwk"] = jwk(&ec);
    h["alg"] = json!("ES256");
    assert_eq!(
        description(f.validate(&sign(&key, &h, &payload("s")))),
        "Invalid signature on DPoP token."
    );
    // A tampered payload.
    let good = proof("t");
    let mut parts: Vec<&str> = good.split('.').collect();
    let other = b64url(payload("other").to_string().as_bytes());
    parts[1] = &other;
    assert_eq!(
        description(f.validate(&parts.join("."))),
        "Invalid signature on DPoP token."
    );
}

#[test]
fn payload_checks() {
    let f = Fixture::new();
    let key = rsa();
    let with = |change: &dyn Fn(&mut Value)| {
        let mut p = payload("p");
        change(&mut p);
        sign(&key, &header(&key), &p)
    };
    let remove = |name: &'static str| {
        move |p: &mut Value| {
            p.as_object_mut().unwrap().remove(name);
        }
    };
    assert_eq!(
        description(f.validate(&with(&remove("jti")))),
        "Invalid 'jti' value."
    );
    assert_eq!(
        description(f.validate(&with(&|p| p["jti"] = json!(5)))),
        "Invalid 'jti' value."
    );
    assert_eq!(
        description(f.validate(&with(&remove("htm")))),
        "Invalid 'htm' value."
    );
    assert_eq!(
        description(f.validate(&with(&|p| p["htm"] = json!("GET")))),
        "Invalid 'htm' value."
    );
    assert_eq!(
        description(f.validate(&with(&remove("htu")))),
        "Invalid 'htu' value."
    );
    for htu in [
        "https://idsrv.test/connect/par",
        "http://idsrv.test/connect/token",
        "https://other.test/connect/token",
        "https://idsrv.test:8443/connect/token",
        "https://idsrv.test/Connect/Token",
        "/connect/token",
    ] {
        assert_eq!(
            description(f.validate(&with(&|p| p["htu"] = json!(htu)))),
            "Invalid 'htu' value.",
            "{htu}"
        );
    }
    // Case-insensitive scheme and host, the default port, and no query or
    // fragment.
    for (i, htu) in [
        "HTTPS://IDSRV.TEST/connect/token",
        "https://idsrv.test:443/connect/token",
        "https://idsrv.test/connect/token?x=1#y",
    ]
    .into_iter()
    .enumerate()
    {
        let proof = {
            let mut p = payload(&format!("htu{i}"));
            p["htu"] = json!(htu);
            sign(&key, &header(&key), &p)
        };
        assert!(f.validate(&proof).is_ok(), "{htu}");
    }
    assert_eq!(
        description(f.validate(&with(&remove("iat")))),
        "Missing 'iat' value."
    );
    assert_eq!(
        description(f.validate(&with(&|p| p["iat"] = json!(1.7e9)))),
        "Missing 'iat' value."
    );
}

#[test]
fn iat_must_be_fresh_within_the_client_clock_skew() {
    let f = Fixture::new();
    let key = rsa();
    let at = |iat: i64, jti: &str| {
        let mut p = payload(jti);
        p["iat"] = json!(iat);
        sign(&key, &header(&key), &p)
    };
    // Validity 60s, client skew 300s.
    assert!(f.validate(&at(NOW + 300, "f1")).is_ok());
    assert_eq!(
        description(f.validate(&at(NOW + 301, "f2"))),
        "Invalid 'iat' value."
    );
    assert!(f.validate(&at(NOW - 360, "f3")).is_ok());
    assert_eq!(
        description(f.validate(&at(NOW - 361, "f4"))),
        "Invalid 'iat' value."
    );
    // Custom mode checks no freshness.
    assert!(
        validate_proof(&f.request(&at(NOW - 100_000, "f5"), DPoPValidationMode::Custom)).is_ok()
    );
}

#[test]
fn nonce_mode_issues_and_checks_server_nonces() {
    let f = Fixture::new();
    let key = rsa();
    let with_nonce = |nonce: Option<&str>, jti: &str| {
        let mut p = payload(jti);
        if let Some(nonce) = nonce {
            p["nonce"] = json!(nonce);
        }
        sign(&key, &header(&key), &p)
    };
    let nonce_mode = |proof: &str| validate_proof(&f.request(proof, DPoPValidationMode::Nonce));

    let missing = nonce_mode(&with_nonce(None, "n1")).unwrap_err();
    assert_eq!(missing.error, USE_DPOP_NONCE);
    assert_eq!(missing.description, Some("Missing 'nonce' value."));
    let nonce = missing.nonce.expect("a server nonce");

    assert!(nonce_mode(&with_nonce(Some(&nonce), "n2")).is_ok());

    let forged = nonce_mode(&with_nonce(Some("forged"), "n3")).unwrap_err();
    assert_eq!(
        (forged.error, forged.description),
        (USE_DPOP_NONCE, Some("Invalid 'nonce' value."))
    );
    assert!(forged.nonce.is_some());

    // A value protected for another purpose isn't a nonce.
    let other = f.protector.protect("other", NOW.to_string().as_bytes());
    let err = nonce_mode(&with_nonce(Some(&other), "n4")).unwrap_err();
    assert_eq!(err.description, Some("Invalid 'nonce' value."));

    // An expired nonce (validity 60s, server skew 0).
    let old = f
        .protector
        .protect(dpop::NONCE_PURPOSE, (NOW - 61).to_string().as_bytes());
    let err = nonce_mode(&with_nonce(Some(&old), "n5")).unwrap_err();
    assert_eq!(err.description, Some("Invalid 'nonce' value."));

    // Iat mode ignores the nonce; IatAndNonce checks both, iat first.
    assert!(f.validate(&with_nonce(Some("forged"), "n6")).is_ok());
    let both = validate_proof(&f.request(&with_nonce(None, "n7"), DPoPValidationMode::IatAndNonce))
        .unwrap_err();
    assert_eq!(both.error, USE_DPOP_NONCE);
}

#[test]
fn a_replayed_proof_is_refused() {
    let f = Fixture::new();
    let proof = proof("once");
    assert!(f.validate(&proof).is_ok());
    assert_eq!(
        description(f.validate(&proof)),
        "Detected replay of DPoP proof token."
    );
}

#[test]
fn the_validation_mode_reads_names_and_flags() {
    for (json, mode) in [
        (json!("Iat"), DPoPValidationMode::Iat),
        (json!("Nonce"), DPoPValidationMode::Nonce),
        (json!("IatAndNonce"), DPoPValidationMode::IatAndNonce),
        (json!("Custom"), DPoPValidationMode::Custom),
        (json!(3), DPoPValidationMode::IatAndNonce),
        (json!(0), DPoPValidationMode::Custom),
    ] {
        assert_eq!(
            serde_json::from_value::<DPoPValidationMode>(json).unwrap(),
            mode
        );
    }
    let client: rustid_core::clients::Client = serde_json::from_value(json!({
        "clientId": "c",
        "requireDPoP": true,
        "dPoPValidationMode": "Nonce",
        "dPoPClockSkew": "00:00:10",
    }))
    .unwrap();
    assert!(client.require_dpop);
    assert_eq!(client.dpop_validation_mode, DPoPValidationMode::Nonce);
    assert_eq!(client.dpop_clock_skew.0, 10);
    let defaults = rustid_core::clients::Client::default();
    assert!(!defaults.require_dpop);
    assert_eq!(defaults.dpop_validation_mode, DPoPValidationMode::Iat);
    assert_eq!(defaults.dpop_clock_skew.0, 300);
}

#[test]
fn a_symmetric_key_never_proves_possession_even_with_an_hmac_algorithm_allowed() {
    let mut f = Fixture::new();
    f.options
        .supported_dpop_signing_algorithms
        .push("HS256".into());
    let secret = b"a secret the client chose";
    let header = json!({
        "typ": "dpop+jwt",
        "alg": "HS256",
        "jwk": { "kty": "oct", "k": b64url(secret) },
    });
    let input = format!(
        "{}.{}",
        b64url(header.to_string().as_bytes()),
        b64url(payload("hmac").to_string().as_bytes())
    );
    let tag = aws_lc_rs::hmac::sign(
        &aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, secret),
        input.as_bytes(),
    );
    let proof = format!("{input}.{}", b64url(tag.as_ref()));
    assert_eq!(
        description(f.validate(&proof)),
        "Invalid signature on DPoP token."
    );
}

/// `dpop::validate` on the in-memory replay cache, which never waits: the
/// proof's verdict.
fn validate_proof(request: &dpop::ProofRequest<'_>) -> Result<dpop::ValidProof, DPoPError> {
    futures::executor::block_on(dpop::validate(request)).expect("the in-memory replay cache")
}

struct DownCache;

#[async_trait::async_trait]
impl rustid_core::replay::ReplayCache for DownCache {
    async fn add_if_absent(
        &self,
        _: &str,
        _: &str,
        _: i64,
        _: i64,
    ) -> Result<bool, rustid_core::stores::StoreError> {
        Err(rustid_core::stores::StoreError::Backend("down".into()))
    }

    async fn remove_expired(
        &self,
        _: i64,
        _: usize,
    ) -> Result<u64, rustid_core::stores::StoreError> {
        Err(rustid_core::stores::StoreError::Backend("down".into()))
    }
}

/// A proof is never accepted when its replay can't be checked.
#[test]
fn a_failing_replay_cache_is_an_error_not_a_valid_proof() {
    let f = Fixture::new();
    let down = DownCache;
    let proof = proof("down");
    let request = ProofRequest {
        replay: &down,
        ..f.request(&proof, DPoPValidationMode::Iat)
    };
    assert!(futures::executor::block_on(dpop::validate(&request)).is_err());
}

// A proof presented with an access token (a protected resource): `ath`
// must hash the token and `cnf.jkt` must be the proof's key.

const TOKEN: &str = "an.access.token";

fn ath(token: &str) -> String {
    b64url(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, token.as_bytes()).as_ref())
}

fn thumbprint_of(key: &LoadedKey) -> String {
    let f = Fixture::new();
    let p = sign(key, &header(key), &payload("thumb"));
    validate_proof(&f.request(&p, DPoPValidationMode::Iat))
        .unwrap()
        .thumbprint
}

fn bound(f: &Fixture, proof: &str, cnf: Option<&Value>) -> Result<dpop::ValidProof, DPoPError> {
    validate_proof(&ProofRequest {
        access_token: Some(dpop::BoundToken { token: TOKEN, cnf }),
        ..f.request(proof, DPoPValidationMode::Iat)
    })
}

fn with_ath(jti: &str, ath: Option<String>) -> String {
    let key = rsa();
    let mut payload = payload(jti);
    if let Some(ath) = ath {
        payload["ath"] = json!(ath);
    }
    sign(&key, &header(&key), &payload)
}

#[test]
fn a_bound_proof_needs_the_tokens_hash_and_key() {
    let f = Fixture::new();
    let cnf = json!({ "jkt": thumbprint_of(&rsa()) });
    assert!(bound(&f, &with_ath("b1", Some(ath(TOKEN))), Some(&cnf)).is_ok());
    assert_eq!(
        description(bound(&f, &with_ath("b2", Some(ath("other"))), Some(&cnf))),
        "Invalid 'ath' value."
    );
    assert_eq!(
        description(bound(&f, &with_ath("b3", None), Some(&cnf))),
        "Invalid 'ath' value."
    );
    assert_eq!(
        description(bound(&f, &with_ath("b4", Some(ath(TOKEN))), None)),
        "Missing 'cnf' value."
    );
    let other = json!({ "jkt": thumbprint_of(&key("client-jwt-ec-key.pem", "ES256")) });
    assert_eq!(
        description(bound(&f, &with_ath("b5", Some(ath(TOKEN))), Some(&other))),
        "Invalid 'cnf' value."
    );
    // cnf is kept as a JSON string claim.
    let text = json!(cnf.to_string());
    assert!(bound(&f, &with_ath("b6", Some(ath(TOKEN))), Some(&text)).is_ok());
}
