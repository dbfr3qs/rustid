//! Logout started by an upstream provider: validating the logout token its
//! back channel posts (OpenID Connect Back-Channel Logout 1.0 §2.6).

use serde_json::Value;

use super::id_token::{IdTokenCheck, verified};
use crate::jwt::PublicJwk;
use crate::logout::BACK_CHANNEL_LOGOUT_EVENT;

/// The replay cache purpose of logout token `jti`s.
pub const LOGOUT_TOKEN_REPLAY_PURPOSE: &str = "federation_logout_token";
/// How long past its issue time a logout token's `jti` is remembered.
pub const LOGOUT_TOKEN_REPLAY_SECONDS: i64 = 300;

/// The check a logout token failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogoutTokenCheck {
    Malformed,
    Algorithm,
    UnknownKey,
    Signature,
    Issuer,
    Audience,
    IssuedAt,
    Expired,
    Jti,
    Replayed,
    Events,
    SubjectOrSession,
    Nonce,
}

impl LogoutTokenCheck {
    pub fn as_str(self) -> &'static str {
        match self {
            LogoutTokenCheck::Malformed => "malformed",
            LogoutTokenCheck::Algorithm => "alg",
            LogoutTokenCheck::UnknownKey => "kid",
            LogoutTokenCheck::Signature => "signature",
            LogoutTokenCheck::Issuer => "iss",
            LogoutTokenCheck::Audience => "aud",
            LogoutTokenCheck::IssuedAt => "iat",
            LogoutTokenCheck::Expired => "exp",
            LogoutTokenCheck::Jti => "jti",
            LogoutTokenCheck::Replayed => "replayed",
            LogoutTokenCheck::Events => "events",
            LogoutTokenCheck::SubjectOrSession => "sub_or_sid",
            LogoutTokenCheck::Nonce => "nonce",
        }
    }
}

impl From<IdTokenCheck> for LogoutTokenCheck {
    fn from(check: IdTokenCheck) -> Self {
        match check {
            IdTokenCheck::Malformed => LogoutTokenCheck::Malformed,
            IdTokenCheck::Algorithm => LogoutTokenCheck::Algorithm,
            IdTokenCheck::UnknownKey => LogoutTokenCheck::UnknownKey,
            _ => LogoutTokenCheck::Signature,
        }
    }
}

/// A logout token that passed every check (but the replay check, which
/// needs the store).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoutToken {
    pub issuer: String,
    pub sub: Option<String>,
    pub sid: Option<String>,
    pub jti: String,
    pub iat: i64,
}

/// What the token must say.
pub struct LogoutExpectations<'a> {
    pub issuer: &'a str,
    pub client_id: &'a str,
    pub algorithms: &'a [String],
    pub now: i64,
    pub skew: i64,
}

/// The §2.6 checks: signature, issuer, audience, issue time, expiry,
/// `jti`, the back-channel logout event, `sub` or `sid`, and no `nonce`.
pub fn validate_logout_token(
    token: &str,
    keys: &[PublicJwk],
    expect: &LogoutExpectations<'_>,
) -> Result<LogoutToken, LogoutTokenCheck> {
    let jws = verified(token, keys, expect.algorithms)?;
    if jws.claim_str("iss") != Some(expect.issuer) {
        return Err(LogoutTokenCheck::Issuer);
    }
    let audience_ok = match jws.payload.get("aud") {
        Some(Value::String(a)) => a == expect.client_id,
        Some(Value::Array(a)) => a.iter().any(|v| v.as_str() == Some(expect.client_id)),
        _ => false,
    };
    if !audience_ok {
        return Err(LogoutTokenCheck::Audience);
    }
    let iat = match jws.numeric_date("iat") {
        Ok(Some(iat)) if iat <= expect.now.saturating_add(expect.skew) => iat,
        _ => return Err(LogoutTokenCheck::IssuedAt),
    };
    match jws.numeric_date("exp") {
        Ok(None) => {}
        Ok(Some(exp)) if exp.saturating_add(expect.skew) >= expect.now => {}
        _ => return Err(LogoutTokenCheck::Expired),
    }
    let jti = jws
        .claim_str("jti")
        .filter(|j| !j.is_empty())
        .ok_or(LogoutTokenCheck::Jti)?
        .to_owned();
    let event_ok = jws
        .payload
        .get("events")
        .and_then(Value::as_object)
        .and_then(|events| events.get(BACK_CHANNEL_LOGOUT_EVENT))
        .is_some_and(Value::is_object);
    if !event_ok {
        return Err(LogoutTokenCheck::Events);
    }
    let text = |name: &str| {
        jws.claim_str(name)
            .filter(|v| !v.is_empty())
            .map(str::to_owned)
    };
    let (sub, sid) = (text("sub"), text("sid"));
    if sub.is_none() && sid.is_none() {
        return Err(LogoutTokenCheck::SubjectOrSession);
    }
    if jws.payload.contains_key("nonce") {
        return Err(LogoutTokenCheck::Nonce);
    }
    Ok(LogoutToken {
        issuer: expect.issuer.to_owned(),
        sub,
        sid,
        jti,
        iat,
    })
}
