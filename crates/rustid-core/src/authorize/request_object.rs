//! A signed request object (RFC 9101) from a client,
//! validated against the client's keys, and its claims as authorize
//! parameters.

use serde_json::Value;

use crate::clients::Client;
use crate::jwt::Jws;
use crate::options::ProtocolOptions;
use crate::secrets::request_object_keys;

/// The `typ` of a JWT-secured authorization request (RFC 9101).
pub const AUTHORIZATION_REQUEST_JWT_TYPE: &str = "oauth-authz-req+jwt";

/// Claims about the object
/// itself, never authorize parameters.
const FILTERED_CLAIMS: &[&str] = &["aud", "exp", "iat", "iss", "nbf", "jti"];

/// Validates the object for `client` and returns its parameters, in
/// payload order; `None` for any failure (logged). The
/// object must be signed with one of the allowed algorithms by one of the
/// client's keys, be issued by the client for `issuer`, carry an unexpired
/// `exp`, be typed `oauth-authz-req+jwt` under strict validation, and carry
/// neither `request` nor `request_uri`.
pub fn validate(
    options: &ProtocolOptions,
    issuer: &str,
    client: &Client,
    token: &str,
    now: i64,
) -> Option<Vec<(String, String)>> {
    validate_with(
        options,
        issuer,
        client,
        token,
        now,
        options.strict_jar_validation,
        false,
    )
}

/// [`validate`] with the context's strictness, and `jti` kept among the
/// parameters when `include_jti` (as CIBA validates request objects).
pub fn validate_with(
    options: &ProtocolOptions,
    issuer: &str,
    client: &Client,
    token: &str,
    now: i64,
    strict: bool,
    include_jti: bool,
) -> Option<Vec<(String, String)>> {
    let secrets: Vec<_> = client.client_secrets.iter().collect();
    let keys = request_object_keys(&secrets);
    if keys.is_empty() {
        return None;
    }
    let jws = Jws::decode(token)?;
    let alg = jws.header_str("alg")?;
    if !options
        .supported_request_object_signing_algorithms
        .iter()
        .any(|a| a == alg)
    {
        return None;
    }
    if !keys.iter().any(|k| jws.verify(k)) {
        return None;
    }
    if strict && jws.header_str("typ") != Some(AUTHORIZATION_REQUEST_JWT_TYPE) {
        return None;
    }
    if jws.claim_str("iss") != Some(client.client_id.as_str()) {
        return None;
    }
    if !audience_matches(jws.payload.get("aud"), issuer) {
        return None;
    }
    let skew = options.jwt_validation_clock_skew.0;
    let exp = jws.numeric_date("exp").ok()??;
    if exp + skew < now {
        return None;
    }
    if let Some(nbf) = jws.numeric_date("nbf").ok()?
        && nbf - skew > now
    {
        return None;
    }
    // FAPI 2 Message Signing 5.3.1 (opt-in): `nbf` present, `exp` at most
    // the limit after it, and `nbf` at most the limit old.
    if let Some(limit) = &options.request_object_max_lifetime {
        let nbf = jws.numeric_date("nbf").ok()??;
        if exp - nbf > limit.0 || nbf < now - limit.0 - skew {
            return None;
        }
    }
    if jws.payload.contains_key("request") || jws.payload.contains_key("request_uri") {
        return None;
    }
    Some(parameters(&jws, include_jti))
}

/// The audience is the issuer, ignoring a trailing slash on either.
fn audience_matches(aud: Option<&Value>, issuer: &str) -> bool {
    let issuer = issuer.trim_end_matches('/');
    let matches = |a: &str| a.trim_end_matches('/') == issuer;
    match aud {
        Some(Value::String(a)) => matches(a),
        Some(Value::Array(auds)) => auds.iter().filter_map(Value::as_str).any(matches),
        _ => false,
    }
}

/// The payload's claims minus the filtered ones: strings as they are,
/// numbers and booleans as text, each array element a claim of its own,
/// and objects as JSON.
fn parameters(jws: &Jws, include_jti: bool) -> Vec<(String, String)> {
    let text = |v: &Value| match v {
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        other => other.to_string(),
    };
    let mut out = Vec::new();
    for (name, value) in &jws.payload {
        if FILTERED_CLAIMS.contains(&name.as_str()) && !(include_jti && name == "jti") {
            continue;
        }
        match value {
            Value::Array(items) => {
                out.extend(items.iter().map(|item| (name.clone(), text(item))));
            }
            Value::Null => {}
            other => out.push((name.clone(), text(other))),
        }
    }
    out
}
