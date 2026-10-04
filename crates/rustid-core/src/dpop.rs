//! DPoP proofs (RFC 9449), as the DPoP proof validator validates them:
//! the header, the signature by the embedded key, the payload, freshness
//! by `iat` and/or a server nonce, and replay. A valid proof answers the
//! key's RFC 7638 thumbprint and the `cnf` a bound token carries.

use aws_lc_rs::digest;
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value, json};

use crate::data_protection::DataProtector;
use crate::jwt::{Jws, PublicJwk, b64url};
use crate::options::DPoPOptions;
use crate::replay::ReplayCache;
use crate::stores::StoreError;

pub const INVALID_DPOP_PROOF: &str = "invalid_dpop_proof";
pub const USE_DPOP_NONCE: &str = "use_dpop_nonce";
/// The proof's `typ`.
pub const PROOF_TYPE: &str = "dpop+jwt";
/// The request header carrying a proof, and the one carrying a nonce.
pub const DPOP_HEADER: &str = "DPoP";
pub const NONCE_HEADER: &str = "DPoP-Nonce";
/// The token type of a DPoP-bound access token.
pub const TOKEN_TYPE: &str = "DPoP";
/// The data protection purpose of server nonces.
pub const NONCE_PURPOSE: &str = "DPoPProofValidation-nonce";
const REPLAY_PURPOSE: &str = "DPoPReplay-jti-";

/// `DPoPTokenExpirationValidationMode`: how a proof's freshness is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DPoPValidationMode {
    /// No built-in check.
    Custom,
    #[default]
    Iat,
    Nonce,
    IatAndNonce,
}

impl DPoPValidationMode {
    fn iat(self) -> bool {
        matches!(self, Self::Iat | Self::IatAndNonce)
    }

    fn nonce(self) -> bool {
        matches!(self, Self::Nonce | Self::IatAndNonce)
    }
}

impl serde::Serialize for DPoPValidationMode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(match self {
            Self::Custom => "Custom",
            Self::Iat => "Iat",
            Self::Nonce => "Nonce",
            Self::IatAndNonce => "IatAndNonce",
        })
    }
}

impl<'de> Deserialize<'de> for DPoPValidationMode {
    /// The enum name, or its flags value.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match Value::deserialize(deserializer)? {
            Value::String(name) => match name.as_str() {
                "Custom" => Ok(Self::Custom),
                "Iat" => Ok(Self::Iat),
                "Nonce" => Ok(Self::Nonce),
                "IatAndNonce" | "Iat, Nonce" => Ok(Self::IatAndNonce),
                other => Err(serde::de::Error::custom(format!(
                    "unknown DPoP validation mode {other:?}"
                ))),
            },
            Value::Number(n) => match n.as_u64() {
                Some(0) => Ok(Self::Custom),
                Some(1) => Ok(Self::Iat),
                Some(2) => Ok(Self::Nonce),
                Some(3) => Ok(Self::IatAndNonce),
                _ => Err(serde::de::Error::custom(format!(
                    "unknown DPoP validation mode {n}"
                ))),
            },
            other => Err(serde::de::Error::custom(format!(
                "a DPoP validation mode is a name or a number, not {other}"
            ))),
        }
    }
}

/// A proof to validate, for the request it came with.
pub struct ProofRequest<'a> {
    pub proof: &'a str,
    /// The request's method and URL, which `htm` and `htu` must name.
    pub method: &'a str,
    pub url: &'a str,
    /// The client's validation mode and clock skew (seconds).
    pub mode: DPoPValidationMode,
    pub client_clock_skew: i64,
    pub options: &'a DPoPOptions,
    pub replay: &'a dyn ReplayCache,
    pub protector: &'a DataProtector,
    /// Unix seconds.
    pub now: i64,
    /// At a protected resource: the access token the proof comes with,
    /// which it must be bound to (`ValidateAccessToken`).
    pub access_token: Option<BoundToken<'a>>,
}

/// An access token presented with a proof, and its `cnf` claim (an object,
/// or as JSON text).
#[derive(Debug, Clone, Copy)]
pub struct BoundToken<'a> {
    pub token: &'a str,
    pub cnf: Option<&'a Value>,
}

/// `ath`: the base64url SHA-256 of the access token.
fn access_token_hash(token: &str) -> String {
    crate::jwt::b64url(
        aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, token.as_bytes()).as_ref(),
    )
}

/// The `jkt` of a `cnf` claim, object or JSON text.
fn confirmation_jkt(cnf: &Value) -> Option<String> {
    let parsed;
    let object = match cnf {
        Value::String(text) => {
            parsed = serde_json::from_str::<Value>(text).ok()?;
            &parsed
        }
        other => other,
    };
    object.get("jkt")?.as_str().map(str::to_owned)
}

/// A valid proof's key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidProof {
    /// The RFC 7638 SHA-256 thumbprint of the proof's JWK.
    pub thumbprint: String,
    /// The `cnf` claim value binding a token to the key: `{"jkt": ...}`.
    pub cnf: String,
}

/// Why a proof was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DPoPError {
    /// `invalid_dpop_proof`, or `use_dpop_nonce` with a fresh `nonce`.
    pub error: &'static str,
    pub description: Option<&'static str>,
    /// A server nonce for the client to use next.
    pub nonce: Option<String>,
}

fn invalid(description: &'static str) -> DPoPError {
    DPoPError {
        error: INVALID_DPOP_PROOF,
        description: Some(description),
        nonce: None,
    }
}

/// `{"jkt": thumbprint}`, as a bound token's `cnf`.
pub fn cnf(thumbprint: &str) -> String {
    json!({ "jkt": thumbprint }).to_string()
}

/// The `jkt` of a `cnf` claim value, when it has one.
pub fn cnf_thumbprint(cnf: &str) -> Option<String> {
    let value: Value = serde_json::from_str(cnf).ok()?;
    value
        .get("jkt")
        .and_then(Value::as_str)
        .filter(|j| !j.is_empty())
        .map(str::to_owned)
}

/// Validates a proof, in the order, recording its
/// `jti` so it can't be used again. The outer error is the replay store
/// failing, which never lets a proof through.
pub async fn validate(
    request: &ProofRequest<'_>,
) -> Result<Result<ValidProof, DPoPError>, StoreError> {
    let (proof, jti, expires_at) = match check(request) {
        Ok(checked) => checked,
        Err(e) => return Ok(Err(e)),
    };
    if !request
        .replay
        .add_if_absent(REPLAY_PURPOSE, &jti, expires_at, request.now)
        .await?
    {
        return Ok(Err(invalid("Detected replay of DPoP proof token.")));
    }
    Ok(Ok(proof))
}

/// Every check but replay: the proof, its `jti` and how long to remember it.
fn check(request: &ProofRequest<'_>) -> Result<(ValidProof, String, i64), DPoPError> {
    if request.proof.is_empty() {
        return Err(invalid("Missing DPoP proof value."));
    }
    let jws = Jws::decode(request.proof).ok_or(invalid("Malformed DPoP token."))?;

    // The header.
    if jws.header_str("typ") != Some(PROOF_TYPE) {
        return Err(invalid("Invalid 'typ' value."));
    }
    let alg = jws.header_str("alg").unwrap_or_default();
    if !request
        .options
        .supported_dpop_signing_algorithms
        .iter()
        .any(|a| a == alg)
    {
        return Err(invalid("Invalid 'alg' value."));
    }
    let Some(Value::Object(jwk)) = jws.header.get("jwk") else {
        return Err(invalid("Invalid 'jwk' value."));
    };
    if has_private_key(jwk) {
        return Err(invalid("'jwk' value contains a private key."));
    }
    let thumbprint = thumbprint(jwk).ok_or(invalid("Invalid 'jwk' value."))?;
    // At a protected resource, the token must be bound to this key.
    if let Some(bound) = &request.access_token {
        let cnf = bound
            .cnf
            .filter(|c| !c.is_null() && c.as_str() != Some(""))
            .ok_or(invalid("Missing 'cnf' value."))?;
        if confirmation_jkt(cnf).as_deref() != Some(thumbprint.as_str()) {
            return Err(invalid("Invalid 'cnf' value."));
        }
    }
    let key = serde_json::from_value::<PublicJwk>(Value::Object(jwk.clone()))
        .map_err(|_| invalid("Invalid 'jwk' value."))?;

    // The signature, by the embedded key. A symmetric key never proves
    // possession (RFC 9449 section 4.2), whatever algorithms are allowed.
    if key.kty == "oct" || !jws.verify(&key) {
        return Err(invalid("Invalid signature on DPoP token."));
    }

    // The payload.
    let claims = &jws.payload;
    if let Some(bound) = &request.access_token
        && claims.get("ath").and_then(Value::as_str)
            != Some(access_token_hash(bound.token).as_str())
    {
        return Err(invalid("Invalid 'ath' value."));
    }
    let jti = claims
        .get("jti")
        .and_then(Value::as_str)
        .filter(|j| !j.is_empty())
        .ok_or(invalid("Invalid 'jti' value."))?;
    if claims.get("htm").and_then(Value::as_str) != Some(request.method) {
        return Err(invalid("Invalid 'htm' value."));
    }
    let htu_matches = claims
        .get("htu")
        .and_then(Value::as_str)
        .is_some_and(|htu| same_endpoint(request.url, htu));
    if !htu_matches {
        return Err(invalid("Invalid 'htu' value."));
    }
    let iat = claims
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or(invalid("Missing 'iat' value."))?;
    let nonce = claims.get("nonce").and_then(Value::as_str);

    // Freshness.
    let validity = request.options.proof_token_validity_duration.0;
    let server_skew = request.options.server_clock_skew.0;
    if request.mode.iat() && expired(request.now, request.client_clock_skew, validity, iat) {
        return Err(invalid("Invalid 'iat' value."));
    }
    if request.mode.nonce() {
        let use_nonce = |description| DPoPError {
            error: USE_DPOP_NONCE,
            description: Some(description),
            nonce: Some(new_nonce(request.protector, request.now)),
        };
        let Some(nonce) = nonce.filter(|n| !n.is_empty()) else {
            return Err(use_nonce("Missing 'nonce' value."));
        };
        let issued = nonce_time(request.protector, nonce);
        if issued <= 0 || expired(request.now, server_skew, validity, issued) {
            return Err(use_nonce("Invalid 'nonce' value."));
        }
    }

    // Replay: remembered for the validity window plus twice the skew.
    let mut skew = 0;
    if request.mode.iat() {
        skew = skew.max(request.client_clock_skew);
    }
    if request.mode.nonce() {
        skew = skew.max(server_skew);
    }
    let expires_at = request.now + validity + 2 * skew;
    Ok((
        ValidProof {
            cnf: cnf(&thumbprint),
            thumbprint,
        },
        jti.to_owned(),
        expires_at,
    ))
}

/// `JsonWebKey.HasPrivateKey`: every RSA private member, or an EC `d`.
fn has_private_key(jwk: &Map<String, Value>) -> bool {
    let has = |m: &str| jwk.get(m).is_some_and(|v| !v.is_null());
    match jwk.get("kty").and_then(Value::as_str) {
        Some("RSA") => ["d", "dp", "dq", "p", "q", "qi"].iter().all(|m| has(m)),
        Some("EC") => has("d"),
        _ => false,
    }
}

/// RFC 7638: SHA-256 over the key's required members, in order. A
/// symmetric (`oct`) key has one too, as `JsonWebKey.CreateThumbprint`
/// computes; it then fails the signature check, since only asymmetric
/// algorithms are supported.
fn thumbprint(jwk: &Map<String, Value>) -> Option<String> {
    let member = |m: &str| jwk.get(m).and_then(Value::as_str);
    let canonical = match member("kty")? {
        "RSA" => json!({ "e": member("e")?, "kty": "RSA", "n": member("n")? }),
        "EC" => json!({
            "crv": member("crv")?, "kty": "EC", "x": member("x")?, "y": member("y")?,
        }),
        "oct" => json!({ "k": member("k")?, "kty": "oct" }),
        _ => return None,
    };
    // serde_json's map is ordered by key, and `to_string` adds no spaces.
    let digest = digest::digest(&digest::SHA256, canonical.to_string().as_bytes());
    Some(b64url(digest.as_ref()))
}

/// `IsExpired`: issued too far in the future, or past its validity.
fn expired(now: i64, skew: i64, validity: i64, issued: i64) -> bool {
    now + skew < issued || issued + validity < now - skew
}

/// A server nonce: the current time, data-protected.
pub fn new_nonce(protector: &DataProtector, now: i64) -> String {
    protector.protect(NONCE_PURPOSE, now.to_string().as_bytes())
}

/// The time a nonce was issued, or 0 when it isn't one of ours.
fn nonce_time(protector: &DataProtector, nonce: &str) -> i64 {
    protector
        .unprotect(NONCE_PURPOSE, nonce)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|text| text.parse().ok())
        .unwrap_or(0)
}

/// `IsHtuMatch`: scheme and host without regard to case, the port (the
/// scheme's default when absent), and the exact path.
fn same_endpoint(expected: &str, htu: &str) -> bool {
    let (Ok(expected), Ok(htu)) = (url::Url::parse(expected), url::Url::parse(htu)) else {
        return false;
    };
    expected.scheme() == htu.scheme()
        && expected.host_str().map(str::to_ascii_lowercase)
            == htu.host_str().map(str::to_ascii_lowercase)
        && expected.port_or_known_default() == htu.port_or_known_default()
        && expected.path() == htu.path()
}
