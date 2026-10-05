//! From an upstream identity to a rustid session: the subject is derived
//! from the upstream issuer and subject (OIDC Core §5.7), never from a
//! claim like `email`, and the session takes the configured claims.

use aws_lc_rs::digest;
use serde_json::{Map, Value};

use crate::jwt::b64url;
use crate::tokens::Claim;

/// Claims about the token itself, never copied into a session.
pub const PROTOCOL_CLAIMS: &[&str] = &[
    "iss",
    "sub",
    "aud",
    "exp",
    "iat",
    "nbf",
    "nonce",
    "at_hash",
    "c_hash",
    "azp",
    "auth_time",
    "acr",
    "amr",
    "sid",
    "jti",
    "tid",
    "idp",
];

/// The OIDC Core §5.1 standard claims: what a provider copies by default.
pub const STANDARD_CLAIMS: &[&str] = &[
    "name",
    "given_name",
    "family_name",
    "middle_name",
    "nickname",
    "preferred_username",
    "profile",
    "picture",
    "website",
    "email",
    "email_verified",
    "gender",
    "birthdate",
    "zoneinfo",
    "locale",
    "phone_number",
    "phone_number_verified",
    "address",
    "updated_at",
];

/// The local subject for an upstream user: base64url of the SHA-256 of the
/// issuer, a zero byte and the subject. The zero byte keeps ("ab", "c")
/// and ("a", "bc") apart.
pub fn subject_for(issuer: &str, sub: &str) -> String {
    let mut ctx = digest::Context::new(&digest::SHA256);
    ctx.update(issuer.as_bytes());
    ctx.update(&[0]);
    ctx.update(sub.as_bytes());
    b64url(ctx.finish().as_ref())
}

/// The payload's claims of the `wanted` types, in payload order, protocol
/// claims excepted.
pub fn select_claims(payload: &Map<String, Value>, wanted: &[String]) -> Vec<Claim> {
    crate::claims::from_jwt_payload(payload)
        .into_iter()
        .filter(|c| {
            wanted.contains(&c.claim_type) && !PROTOCOL_CLAIMS.contains(&c.claim_type.as_str())
        })
        .collect()
}

/// The sign-in for a validated id token: the derived subject, the
/// provider as `idp`, the token's `amr` (or `external`) and `auth_time`
/// (or now), and the configured claims.
pub fn sign_in(
    provider: &super::provider::IdentityProvider,
    token: &super::id_token::ValidatedIdToken,
    now: i64,
) -> crate::session::SignIn {
    let amr: Vec<String> = token
        .payload
        .get("amr")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .filter(|a: &Vec<String>| !a.is_empty())
        .unwrap_or_else(|| vec!["external".to_owned()]);
    let auth_time = token
        .payload
        .get("auth_time")
        .and_then(Value::as_i64)
        .unwrap_or(now);
    crate::session::SignIn {
        subject_id: subject_for(&token.issuer, &token.subject),
        idp: Some(provider.scheme.clone()),
        amr,
        auth_time: Some(auth_time),
        claims: select_claims(&token.payload, &provider.claims),
        persistent: false,
        allow_refresh: None,
    }
}
