//! Validating an upstream id token as OIDC Core §3.1.3.7 requires: an
//! asymmetric algorithm the provider advertises, a signature by one of its
//! keys, the issuer, the audience and authorized party, the lifetime, the
//! nonce, and a subject.

use serde_json::{Map, Value};

use super::upstream::ASYMMETRIC_ALGORITHMS;
use crate::jwt::{Jws, PublicJwk};

/// An id token that passed every check.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidatedIdToken {
    pub issuer: String,
    pub subject: String,
    pub payload: Map<String, Value>,
}

/// The check an id token failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdTokenCheck {
    Malformed,
    Algorithm,
    /// No key has the token's `kid`: the provider may have rotated keys.
    UnknownKey,
    Signature,
    Issuer,
    Audience,
    AuthorizedParty,
    Expired,
    IssuedInFuture,
    Nonce,
    Subject,
}

impl IdTokenCheck {
    pub fn as_str(self) -> &'static str {
        match self {
            IdTokenCheck::Malformed => "malformed",
            IdTokenCheck::Algorithm => "alg",
            IdTokenCheck::UnknownKey => "kid",
            IdTokenCheck::Signature => "signature",
            IdTokenCheck::Issuer => "iss",
            IdTokenCheck::Audience => "aud",
            IdTokenCheck::AuthorizedParty => "azp",
            IdTokenCheck::Expired => "exp",
            IdTokenCheck::IssuedInFuture => "iat",
            IdTokenCheck::Nonce => "nonce",
            IdTokenCheck::Subject => "sub",
        }
    }
}

/// What the token must say.
pub struct Expectations<'a> {
    pub issuer: &'a str,
    pub client_id: &'a str,
    pub nonce: &'a str,
    /// The algorithms the provider advertises (asymmetric only).
    pub algorithms: &'a [String],
    pub now: i64,
    /// Clock skew allowed on `exp` and `iat`, in seconds.
    pub skew: i64,
}

fn key_type(alg: &str) -> &'static str {
    if alg.starts_with("ES") { "EC" } else { "RSA" }
}

/// The checks, in order: format, algorithm, key, signature, issuer,
/// audience, authorized party, expiry, issue time, nonce, subject.
pub fn validate(
    token: &str,
    keys: &[PublicJwk],
    expect: &Expectations<'_>,
) -> Result<ValidatedIdToken, IdTokenCheck> {
    let jws = Jws::decode(token).ok_or(IdTokenCheck::Malformed)?;
    let alg = jws.header_str("alg").ok_or(IdTokenCheck::Algorithm)?;
    if !ASYMMETRIC_ALGORITHMS.contains(&alg) || !expect.algorithms.iter().any(|a| a == alg) {
        return Err(IdTokenCheck::Algorithm);
    }
    let key = match jws.header_str("kid") {
        Some(kid) => keys
            .iter()
            .find(|k| k.kid.as_deref() == Some(kid))
            .ok_or(IdTokenCheck::UnknownKey)?,
        None => {
            let mut suitable = keys.iter().filter(|k| k.kty == key_type(alg));
            match (suitable.next(), suitable.next()) {
                (Some(key), None) => key,
                _ => return Err(IdTokenCheck::Signature),
            }
        }
    };
    if !jws.verify(key) {
        return Err(IdTokenCheck::Signature);
    }
    if jws.claim_str("iss") != Some(expect.issuer) {
        return Err(IdTokenCheck::Issuer);
    }
    let audiences: Vec<&str> = match jws.payload.get("aud") {
        Some(Value::String(a)) => vec![a.as_str()],
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    };
    if !audiences.contains(&expect.client_id) {
        return Err(IdTokenCheck::Audience);
    }
    let azp = jws.claim_str("azp");
    if (audiences.len() > 1 && azp.is_none()) || azp.is_some_and(|a| a != expect.client_id) {
        return Err(IdTokenCheck::AuthorizedParty);
    }
    match jws.numeric_date("exp") {
        Ok(Some(exp)) if exp.saturating_add(expect.skew) >= expect.now => {}
        _ => return Err(IdTokenCheck::Expired),
    }
    match jws.numeric_date("iat") {
        Ok(Some(iat)) if iat > expect.now.saturating_add(expect.skew) => {
            return Err(IdTokenCheck::IssuedInFuture);
        }
        Err(_) => return Err(IdTokenCheck::IssuedInFuture),
        _ => {}
    }
    if jws.claim_str("nonce") != Some(expect.nonce) {
        return Err(IdTokenCheck::Nonce);
    }
    let subject = jws
        .claim_str("sub")
        .filter(|s| !s.is_empty())
        .ok_or(IdTokenCheck::Subject)?
        .to_owned();
    Ok(ValidatedIdToken {
        issuer: expect.issuer.to_owned(),
        subject,
        payload: jws.payload,
    })
}
