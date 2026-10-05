//! Compact JWS: encoding with a configured key, decoding, and verification
//! against a public JSON Web Key.

use aws_lc_rs::signature::{self, UnparsedPublicKey, VerificationAlgorithm};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::keys::{LoadedKey, SignError};

pub fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn b64url_decode(text: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(text.trim_end_matches('=')).ok()
}

/// Encodes and signs a JWT. The header is `alg` and `kid` from the key,
/// followed by `extra_header` entries (for example `typ`).
pub fn encode(
    key: &LoadedKey,
    extra_header: &[(&str, &str)],
    payload: &Map<String, Value>,
) -> Result<String, SignError> {
    let mut header = Map::new();
    header.insert("alg".into(), Value::String(key.alg.clone()));
    header.insert("kid".into(), Value::String(key.kid.clone()));
    for (name, value) in extra_header {
        header.insert((*name).to_owned(), Value::String((*value).to_owned()));
    }
    let signing_input = format!(
        "{}.{}",
        b64url(Value::Object(header).to_string().as_bytes()),
        b64url(Value::Object(payload.clone()).to_string().as_bytes())
    );
    let signature = key.sign(signing_input.as_bytes())?;
    Ok(format!("{signing_input}.{}", b64url(&signature)))
}

/// A decoded, not yet verified, compact JWS.
#[derive(Debug, Clone, PartialEq)]
pub struct Jws {
    pub header: Map<String, Value>,
    pub payload: Map<String, Value>,
    pub signing_input: String,
    pub signature: Vec<u8>,
}

impl Jws {
    pub fn decode(token: &str) -> Option<Jws> {
        let mut parts = token.split('.');
        let (h, p, s) = (parts.next()?, parts.next()?, parts.next()?);
        if parts.next().is_some() {
            return None;
        }
        let object = |segment: &str| match serde_json::from_slice(&b64url_decode(segment)?) {
            Ok(Value::Object(map)) => Some(map),
            _ => None,
        };
        Some(Jws {
            header: object(h)?,
            payload: object(p)?,
            signing_input: format!("{h}.{p}"),
            signature: b64url_decode(s)?,
        })
    }

    pub fn header_str(&self, name: &str) -> Option<&str> {
        self.header.get(name).and_then(Value::as_str)
    }

    pub fn claim_str(&self, name: &str) -> Option<&str> {
        self.payload.get(name).and_then(Value::as_str)
    }

    /// A NumericDate claim (`exp`, `nbf`, `iat`): an integer, a number
    /// rounded half to even,
    /// or a string holding either. `Ok(None)` when absent; an error when
    /// present but not readable as a 64-bit integer, which makes validation reject
    /// the whole token.
    pub fn numeric_date(&self, name: &str) -> Result<Option<i64>, InvalidNumericDate> {
        let Some(value) = self.payload.get(name) else {
            return Ok(None);
        };
        let read = match value {
            Value::Number(n) => n.as_i64().or_else(|| n.as_f64().and_then(round_to_i64)),
            Value::String(text) => {
                let text = text.trim();
                text.parse::<i64>()
                    .ok()
                    .or_else(|| text.parse::<f64>().ok().and_then(round_to_i64))
            }
            _ => None,
        };
        read.map(Some).ok_or(InvalidNumericDate)
    }

    /// [`Jws::numeric_date`] when present and readable.
    pub fn claim_i64(&self, name: &str) -> Option<i64> {
        self.numeric_date(name).ok().flatten()
    }

    /// Verifies the signature with `key` using the header's algorithm.
    pub fn verify(&self, key: &PublicJwk) -> bool {
        let Some(alg) = self.header_str("alg") else {
            return false;
        };
        key.verify(alg, self.signing_input.as_bytes(), &self.signature)
    }
}

/// A NumericDate claim that is present but not a 64-bit integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidNumericDate;

/// Rounds half to even, failing outside the `i64` range.
fn round_to_i64(f: f64) -> Option<i64> {
    let r = f.round_ties_even();
    // 2^63 is exactly representable; every double below it fits in an i64.
    (r.is_finite() && (-9_223_372_036_854_775_808.0..9_223_372_036_854_775_808.0).contains(&r))
        .then_some(r as i64)
}

/// A public key parsed from a JSON Web Key, as clients register them.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct PublicJwk {
    pub kty: String,
    #[serde(default)]
    pub kid: Option<String>,
    #[serde(default)]
    pub n: Option<String>,
    #[serde(default)]
    pub e: Option<String>,
    #[serde(default)]
    pub crv: Option<String>,
    #[serde(default)]
    pub x: Option<String>,
    #[serde(default)]
    pub y: Option<String>,
    /// The key of an `oct` (symmetric) JWK.
    #[serde(default)]
    pub k: Option<String>,
}

impl PublicJwk {
    pub fn parse(json: &str) -> Option<PublicJwk> {
        serde_json::from_str(json).ok()
    }

    pub fn verify(&self, alg: &str, message: &[u8], sig: &[u8]) -> bool {
        match (self.kty.as_str(), alg) {
            ("RSA", "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512") => {
                let (Some(n), Some(e)) = (
                    self.n.as_deref().and_then(b64url_decode),
                    self.e.as_deref().and_then(b64url_decode),
                ) else {
                    return false;
                };
                let params: &'static signature::RsaParameters = match alg {
                    "RS256" => &signature::RSA_PKCS1_2048_8192_SHA256,
                    "RS384" => &signature::RSA_PKCS1_2048_8192_SHA384,
                    "RS512" => &signature::RSA_PKCS1_2048_8192_SHA512,
                    "PS256" => &signature::RSA_PSS_2048_8192_SHA256,
                    "PS384" => &signature::RSA_PSS_2048_8192_SHA384,
                    _ => &signature::RSA_PSS_2048_8192_SHA512,
                };
                signature::RsaPublicKeyComponents { n: &n, e: &e }
                    .verify(params, message, sig)
                    .is_ok()
            }
            ("EC", "ES256" | "ES384" | "ES512") => {
                let (curve, verifier): (&str, &'static dyn VerificationAlgorithm) = match alg {
                    "ES256" => ("P-256", &signature::ECDSA_P256_SHA256_FIXED),
                    "ES384" => ("P-384", &signature::ECDSA_P384_SHA384_FIXED),
                    _ => ("P-521", &signature::ECDSA_P521_SHA512_FIXED),
                };
                if self.crv.as_deref() != Some(curve) {
                    return false;
                }
                let (Some(x), Some(y)) = (
                    self.x.as_deref().and_then(b64url_decode),
                    self.y.as_deref().and_then(b64url_decode),
                ) else {
                    return false;
                };
                let mut point = Vec::with_capacity(1 + x.len() + y.len());
                point.push(0x04);
                point.extend_from_slice(&x);
                point.extend_from_slice(&y);
                UnparsedPublicKey::new(verifier, point)
                    .verify(message, sig)
                    .is_ok()
            }
            ("oct", "HS256" | "HS384" | "HS512") => {
                let Some(k) = self.k.as_deref().and_then(b64url_decode) else {
                    return false;
                };
                let algorithm = match alg {
                    "HS256" => aws_lc_rs::hmac::HMAC_SHA256,
                    "HS384" => aws_lc_rs::hmac::HMAC_SHA384,
                    _ => aws_lc_rs::hmac::HMAC_SHA512,
                };
                // Constant-time comparison.
                aws_lc_rs::hmac::verify(&aws_lc_rs::hmac::Key::new(algorithm, &k), message, sig)
                    .is_ok()
            }
            _ => false,
        }
    }
}
