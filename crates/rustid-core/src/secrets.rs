//! Client authentication: parsing a credential from the request and
//! validating it against the client's secrets.

use aws_lc_rs::digest;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::{DateTime, Utc};

use crate::clients::{SECRET_TYPE_JWK, SECRET_TYPE_SHARED, Secret};
use crate::form::Form;
use crate::jwt::Jws;
use crate::options::InputLengthRestrictions;

pub const CLIENT_ASSERTION_TYPE_JWT_BEARER: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParsedSecretKind {
    SharedSecret,
    NoSecret,
    JwtBearer,
    /// A TLS client certificate.
    X509Certificate,
}

impl ParsedSecretKind {
    /// The parsed secret type, the authentication method
    /// events and metrics report.
    pub fn as_str(self) -> &'static str {
        match self {
            ParsedSecretKind::SharedSecret => "SharedSecret",
            ParsedSecretKind::NoSecret => "NoSecret",
            ParsedSecretKind::JwtBearer => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ParsedSecretKind::X509Certificate => "X509Certificate",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSecret {
    pub id: String,
    pub credential: Option<String>,
    pub kind: ParsedSecretKind,
}

fn present(value: Option<&str>) -> Option<&str> {
    value.filter(|v| !v.trim().is_empty())
}

/// The basic authentication secret parser.
pub fn parse_basic(
    authorization: Option<&str>,
    limits: &InputLengthRestrictions,
) -> Option<ParsedSecret> {
    let header = present(authorization)?;
    if header.len() < 6 || !header.as_bytes()[..6].eq_ignore_ascii_case(b"Basic ") {
        return None;
    }
    if header.len() > 4 * (limits.client_id + limits.client_secret) + 10 {
        return None;
    }
    let decoded = STANDARD.decode(header[6..].trim()).ok()?;
    let pair = String::from_utf8_lossy(&decoded);
    let (id, secret) = pair.split_once(':')?;
    let (id, secret) = (url_decode(id), url_decode(secret));
    if id.trim().is_empty() || id.len() > limits.client_id {
        return None;
    }
    if secret.trim().is_empty() {
        return Some(ParsedSecret {
            id,
            credential: None,
            kind: ParsedSecretKind::NoSecret,
        });
    }
    if secret.len() > limits.client_secret {
        return None;
    }
    Some(ParsedSecret {
        id,
        credential: Some(secret),
        kind: ParsedSecretKind::SharedSecret,
    })
}

/// The post body secret parser.
pub fn parse_post_body(form: &Form, limits: &InputLengthRestrictions) -> Option<ParsedSecret> {
    let id = present(form.first("client_id"))?;
    if id.len() > limits.client_id {
        return None;
    }
    match present(form.first("client_secret")) {
        Some(secret) if secret.len() > limits.client_secret => None,
        Some(secret) => Some(ParsedSecret {
            id: id.to_owned(),
            credential: Some(secret.to_owned()),
            kind: ParsedSecretKind::SharedSecret,
        }),
        None => Some(ParsedSecret {
            id: id.to_owned(),
            credential: None,
            kind: ParsedSecretKind::NoSecret,
        }),
    }
}

/// The client id is the unverified
/// assertion's `sub`.
pub fn parse_jwt_bearer(form: &Form, limits: &InputLengthRestrictions) -> Option<ParsedSecret> {
    let assertion = present(form.first("client_assertion"))?;
    if form.first("client_assertion_type") != Some(CLIENT_ASSERTION_TYPE_JWT_BEARER)
        || assertion.len() > limits.jwt
    {
        return None;
    }
    let jws = Jws::decode(assertion)?;
    let id = present(jws.claim_str("sub"))?;
    if id.len() > limits.client_id {
        return None;
    }
    Some(ParsedSecret {
        id: id.to_owned(),
        credential: Some(assertion.to_owned()),
        kind: ParsedSecretKind::JwtBearer,
    })
}

/// Parsers in registration order (Basic, post
/// body, then JWT bearer when enabled). The first real credential wins; a
/// client id without a secret is kept only if nothing better is found.
pub fn parse(
    authorization: Option<&str>,
    form: &Form,
    limits: &InputLengthRestrictions,
    private_key_jwt: bool,
) -> Option<ParsedSecret> {
    let mut best = None;
    let parsers: [Option<ParsedSecret>; 3] = [
        parse_basic(authorization, limits),
        parse_post_body(form, limits),
        if private_key_jwt {
            parse_jwt_bearer(form, limits)
        } else {
            None
        },
    ];
    for parsed in parsers.into_iter().flatten() {
        let is_real = parsed.kind != ParsedSecretKind::NoSecret;
        best = Some(parsed);
        if is_real {
            break;
        }
    }
    best
}

/// The hashed shared secret validator over the unexpired secrets.
pub fn validate_shared_secret(secrets: &[&Secret], parsed: &ParsedSecret) -> bool {
    if parsed.kind != ParsedSecretKind::SharedSecret {
        return false;
    }
    let Some(credential) = parsed.credential.as_deref() else {
        return false;
    };
    let hashed_256 = STANDARD.encode(digest::digest(&digest::SHA256, credential.as_bytes()));
    let hashed_512 = STANDARD.encode(digest::digest(&digest::SHA512, credential.as_bytes()));
    for secret in secrets
        .iter()
        .filter(|s| s.secret_type == SECRET_TYPE_SHARED)
    {
        // A secret value that isn't a SHA-256 or SHA-512 hash fails the whole
        // validation, returning early.
        let Ok(bytes) = STANDARD.decode(&secret.value) else {
            return false;
        };
        let expected = match bytes.len() {
            32 => &hashed_256,
            64 => &hashed_512,
            _ => return false,
        };
        if constant_time_eq(secret.value.as_bytes(), expected.as_bytes()) {
            return true;
        }
    }
    false
}

/// Secrets that have not expired, as the secret validator filters them.
pub fn current_secrets(secrets: &[Secret], now: DateTime<Utc>) -> Vec<&Secret> {
    secrets.iter().filter(|s| !s.has_expired(now)).collect()
}

/// JSON Web Keys registered as `JWK` secrets.
pub fn jwk_secrets(secrets: &[&Secret]) -> Vec<crate::jwt::PublicJwk> {
    secrets
        .iter()
        .filter(|s| s.secret_type == SECRET_TYPE_JWK)
        .filter_map(|s| crate::jwt::PublicJwk::parse(&s.value))
        .collect()
}

/// Get keys for request objects: the `JWK` secrets (RSA, EC and
/// symmetric) and the public keys of `X509CertificateBase64` secrets.
pub fn request_object_keys(secrets: &[&Secret]) -> Vec<crate::jwt::PublicJwk> {
    let mut keys = jwk_secrets(secrets);
    keys.extend(
        secrets
            .iter()
            .filter(|s| s.secret_type == crate::clients::SECRET_TYPE_X509_BASE64)
            .filter_map(|s| {
                base64::engine::general_purpose::STANDARD
                    .decode(s.value.trim())
                    .ok()
            })
            .filter_map(|der| crate::keys::certificate_jwk(&der)),
    );
    keys
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// RFC 6749 form-encoding of Basic credentials: `+` is a space, then
/// percent-decoding (invalid escapes kept).
fn url_decode(value: &str) -> String {
    let bytes = value.replace('+', " ").into_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let (Some(h), Some(l)) = (hex(bytes.get(i + 1)), hex(bytes.get(i + 2)))
        {
            out.push(h * 16 + l);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(b: Option<&u8>) -> Option<u8> {
    b.and_then(|b| (*b as char).to_digit(16)).map(|d| d as u8)
}
