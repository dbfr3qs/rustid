//! Validates a `private_key_jwt` client
//! assertion against the client's `JWK` secrets.

use serde_json::Value;

use crate::clients::Secret;
use crate::jwt::Jws;
use crate::options::ProtocolOptions;
use crate::replay::ReplayCache;
use crate::secrets::{ParsedSecret, ParsedSecretKind, jwk_secrets};
use crate::stores::StoreError;

pub const CLIENT_AUTHENTICATION_JWT_TYPE: &str = "client-authentication+jwt";
const REPLAY_PURPOSE: &str = "PrivateKeyJwtSecretValidator";
/// 9999-12-31T23:59:59Z, the latest instant, in Unix seconds.
const MAX_NUMERIC_DATE: i64 = 253_402_300_799;

pub struct AssertionContext<'a> {
    pub options: &'a ProtocolOptions,
    /// The issuer for this request.
    pub issuer: &'a str,
    /// Origin plus path base, without a trailing slash.
    pub base_url: &'a str,
    pub replay: &'a dyn ReplayCache,
    /// Unix seconds.
    pub now: i64,
}

/// Returns `true` when the assertion is valid for the client identified by
/// `parsed.id`, recording its `jti` so it can't be used again. Every
/// failure is a plain `false`; only the replay store failing is
/// an error.
pub async fn validate(
    secrets: &[&Secret],
    parsed: &ParsedSecret,
    ctx: &AssertionContext<'_>,
) -> Result<bool, StoreError> {
    match check(secrets, parsed, ctx) {
        Some((jti, expires_at)) => {
            ctx.replay
                .add_if_absent(REPLAY_PURPOSE, &jti, expires_at, ctx.now)
                .await
        }
        None => Ok(false),
    }
}

/// Every check but replay: the `jti` and how long to remember it.
fn check(
    secrets: &[&Secret],
    parsed: &ParsedSecret,
    ctx: &AssertionContext<'_>,
) -> Option<(String, i64)> {
    if parsed.kind != ParsedSecretKind::JwtBearer {
        return None;
    }
    let token = parsed.credential.as_deref()?;
    if token.len() > ctx.options.input_length_restrictions.jwt {
        return None;
    }
    let keys = jwk_secrets(secrets);
    if keys.is_empty() {
        return None;
    }
    let jws = Jws::decode(token)?;

    // Algorithm: signed, and one of the allowed client assertion algorithms.
    let alg = jws.header_str("alg")?;
    if !ctx
        .options
        .supported_client_assertion_signing_algorithms
        .iter()
        .any(|a| a == alg)
    {
        return None;
    }
    // Signature: any trusted key may verify it, whatever the kid says.
    if !keys.iter().any(|k| jws.verify(k)) {
        return None;
    }

    // Issuer must be the client id.
    if jws.claim_str("iss") != Some(parsed.id.as_str()) {
        return None;
    }

    // Audience.
    let strict = ctx.options.strict_client_assertion_audience_validation
        || jws
            .header_str("typ")
            .is_some_and(|t| t.eq_ignore_ascii_case(CLIENT_AUTHENTICATION_JWT_TYPE));
    let audience_ok = if strict || ctx.options.issuer_only_client_assertion_audience {
        // Strict mode wants the type too; issuer-only doesn't.
        let typ_ok = !strict
            || jws
                .header_str("typ")
                .is_some_and(|t| t.eq_ignore_ascii_case(CLIENT_AUTHENTICATION_JWT_TYPE));
        let single = match jws.payload.get("aud") {
            Some(Value::String(aud)) => Some(aud.as_str()),
            Some(Value::Array(auds)) if auds.len() == 1 => auds[0].as_str(),
            _ => None,
        };
        typ_ok && single.is_some_and(|aud| audiences_match(aud, ctx.issuer))
    } else {
        let base = format!("{}/", ctx.base_url.trim_end_matches('/'));
        let issuer_slash = format!("{}/", ctx.issuer.trim_end_matches('/'));
        let valid = [
            format!("{base}connect/token"),
            format!("{issuer_slash}connect/token"),
            ctx.issuer.to_owned(),
            format!("{base}connect/ciba"),
            format!("{base}connect/par"),
        ];
        let audiences: Vec<&str> = match jws.payload.get("aud") {
            Some(Value::String(aud)) => vec![aud.as_str()],
            Some(Value::Array(auds)) => auds.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        };
        audiences
            .iter()
            .any(|aud| valid.iter().any(|v| audiences_match(aud, v)))
    };
    if !audience_ok {
        return None;
    }

    // NumericDates that don't read as integers make the token invalid.
    if ["exp", "nbf", "iat"]
        .iter()
        .any(|name| jws.numeric_date(name).is_err())
    {
        return None;
    }

    // Lifetime: exp required; nbf honoured; both with clock skew.
    let skew = ctx.options.jwt_validation_clock_skew.0;
    let exp = jws.claim_i64("exp")?;
    // Instants after 9999-12-31T23:59:59Z can't be represented, which fails the
    // request; reject such an assertion rather than overflow.
    if exp > MAX_NUMERIC_DATE {
        return None;
    }
    if ctx.now > exp.saturating_add(skew) {
        return None;
    }
    if jws
        .claim_i64("nbf")
        .is_some_and(|nbf| ctx.now.saturating_add(skew) < nbf)
    {
        return None;
    }

    // Sub and iss both carry the client id.
    if jws.claim_str("sub") != jws.claim_str("iss") {
        return None;
    }

    // Jti is required and single-use until five minutes after expiry.
    let jti = jws.claim_str("jti").filter(|j| !j.trim().is_empty())?;
    Some((jti.to_owned(), exp.saturating_add(300)))
}

/// Exact match, or equal apart from one trailing slash on either side.
fn audiences_match(token_audience: &str, valid: &str) -> bool {
    token_audience == valid
        || token_audience.strip_suffix('/') == Some(valid)
        || valid.strip_suffix('/') == Some(token_audience)
}
