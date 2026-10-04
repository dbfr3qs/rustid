//! JARM (JWT Secured Authorization Response Mode): the response modes and
//! the signed response JWT.

use serde_json::{Map, Value};

use crate::keys::{LoadedKey, SignError};
use crate::params::Params;

/// The JARM response modes; `jwt` resolves by response type (JARM 2.3.4).
pub const JARM_RESPONSE_MODES: &[&str] = &["query.jwt", "fragment.jwt", "form_post.jwt", "jwt"];

/// The response JWT (JARM 2.1): `iss`, `aud` (the client id, a string) and
/// `exp`, then every response parameter as a claim. An `iss` parameter
/// (RFC 9207) is the claim already.
pub fn response_jwt(
    key: &LoadedKey,
    issuer: &str,
    client_id: &str,
    params: &Params,
    now: i64,
    lifetime: i64,
) -> Result<String, SignError> {
    let mut claims = Map::new();
    claims.insert("iss".into(), Value::String(issuer.to_owned()));
    claims.insert("aud".into(), Value::String(client_id.to_owned()));
    claims.insert("exp".into(), Value::from(now.saturating_add(lifetime)));
    for (name, values) in params.iter() {
        if name == "iss" {
            continue;
        }
        if let Some(value) = values.first() {
            claims.insert(name.to_owned(), Value::String(value.clone()));
        }
    }
    crate::jwt::encode(key, &[], &claims)
}

/// How a JARM response travels: the mode without `.jwt`.
pub fn base_mode(mode: &str) -> &str {
    mode.strip_suffix(".jwt").unwrap_or(mode)
}
