//! Access token contents: claims and the JWT
//! payload.

use serde_json::{Map, Value};

use crate::clients::{Client, ClientClaim};
use crate::options::ProtocolOptions;
use crate::profile::without_protocol_claims;
use crate::scopes::{OFFLINE_ACCESS, ValidatedResources};
use crate::session::UserSession;

pub const CLAIM_VALUE_BOOLEAN: &str = "http://www.w3.org/2001/XMLSchema#boolean";
pub const CLAIM_VALUE_INTEGER: &str = "http://www.w3.org/2001/XMLSchema#integer";
pub const CLAIM_VALUE_INTEGER32: &str = "http://www.w3.org/2001/XMLSchema#integer32";
pub const CLAIM_VALUE_INTEGER64: &str = "http://www.w3.org/2001/XMLSchema#integer64";
pub const CLAIM_VALUE_DOUBLE: &str = "http://www.w3.org/2001/XMLSchema#double";
pub const CLAIM_VALUE_JSON: &str = "json";

/// A claim with its value type, which decides its JSON form.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Claim {
    #[serde(rename = "type")]
    pub claim_type: String,
    pub value: String,
    pub value_type: String,
}

impl Claim {
    pub fn string(claim_type: &str, value: &str) -> Claim {
        Claim {
            claim_type: claim_type.to_owned(),
            value: value.to_owned(),
            value_type: crate::clients::CLAIM_VALUE_TYPE_STRING.to_owned(),
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("claim {claim_type} has value {value:?} that is not a valid {value_type}")]
pub struct ClaimValueError {
    pub claim_type: String,
    pub value: String,
    pub value_type: String,
}

/// An access token before it is serialised: what a token holds.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AccessToken {
    pub issuer: String,
    pub client_id: String,
    pub lifetime: i64,
    pub audiences: Vec<String>,
    pub claims: Vec<Claim>,
    /// The `cnf` binding the token to a proof key,
    /// as JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmation: Option<String>,
}

/// Claims for a client-only access token (no subject): `client_id`, the
/// client's claims with its prefix, then one `scope` claim per granted scope
/// except `offline_access`.
pub fn client_access_token(
    options: &ProtocolOptions,
    issuer: &str,
    client: &Client,
    resources: &ValidatedResources,
) -> AccessToken {
    let mut claims = vec![Claim::string("client_id", &client.client_id)];
    let prefix = client
        .client_claims_prefix
        .as_deref()
        .filter(|p| !p.trim().is_empty())
        .unwrap_or("");
    for ClientClaim {
        claim_type,
        value,
        value_type,
    } in &client.claims
    {
        claims.push(Claim {
            claim_type: format!("{prefix}{claim_type}"),
            value: value.clone(),
            value_type: value_type.clone(),
        });
    }
    for scope in resources.scopes.iter().filter(|s| *s != OFFLINE_ACCESS) {
        claims.push(Claim::string("scope", scope));
    }
    // Duplicates of type and value are dropped.
    let mut distinct: Vec<Claim> = Vec::new();
    for claim in claims {
        if !distinct
            .iter()
            .any(|c| c.claim_type == claim.claim_type && c.value == claim.value)
        {
            distinct.push(claim);
        }
    }
    let mut audiences = resources.audiences();
    if options.emit_static_audience_claim {
        audiences.push(format!("{}/resources", issuer.trim_end_matches('/')));
    }
    AccessToken {
        issuer: issuer.to_owned(),
        client_id: client.client_id.clone(),
        lifetime: i64::from(client.access_token_lifetime),
        audiences,
        claims: distinct,
        confirmation: None,
    }
}

/// `iss`, `nbf`, `iat`, `exp`, `aud`, `scope`, then every
/// other claim type in first-seen order (arrays when repeated), then `jti`
/// when given.
pub fn jwt_payload(
    options: &ProtocolOptions,
    token: &AccessToken,
    now: i64,
    jti: Option<&str>,
) -> Result<Map<String, Value>, ClaimValueError> {
    let mut claims = token.claims.clone();
    if let Some(jti) = jti {
        claims.retain(|c| c.claim_type != "jti");
        claims.push(Claim::string("jti", jti));
    }
    let mut payload = Map::new();
    payload.insert("iss".into(), Value::String(token.issuer.clone()));
    payload.insert("nbf".into(), Value::from(now));
    payload.insert("iat".into(), Value::from(now));
    payload.insert(
        "exp".into(),
        Value::from(now.saturating_add(token.lifetime)),
    );
    match token.audiences.as_slice() {
        [] => {}
        [single] => {
            payload.insert("aud".into(), Value::String(single.clone()));
        }
        many => {
            payload.insert(
                "aud".into(),
                Value::Array(many.iter().cloned().map(Value::String).collect()),
            );
        }
    }
    let scopes: Vec<&str> = claims
        .iter()
        .filter(|c| c.claim_type == "scope")
        .map(|c| c.value.as_str())
        .collect();
    if !scopes.is_empty() {
        let value = if options.emit_scopes_as_space_delimited_string_in_jwt {
            Value::String(scopes.join(" "))
        } else {
            Value::Array(
                scopes
                    .iter()
                    .map(|s| Value::String((*s).to_owned()))
                    .collect(),
            )
        };
        payload.insert("scope".into(), value);
    }
    // amr is always an array of its distinct values.
    let mut amr: Vec<Value> = Vec::new();
    for claim in claims.iter().filter(|c| c.claim_type == "amr") {
        let value = Value::String(claim.value.clone());
        if !amr.contains(&value) {
            amr.push(value);
        }
    }
    if !amr.is_empty() {
        payload.insert("amr".into(), Value::Array(amr));
    }
    let mut seen: Vec<&str> = Vec::new();
    for claim in claims
        .iter()
        .filter(|c| c.claim_type != "scope" && c.claim_type != "amr")
    {
        if seen.contains(&claim.claim_type.as_str()) || payload.contains_key(&claim.claim_type) {
            continue;
        }
        seen.push(&claim.claim_type);
        let same: Vec<&Claim> = claims
            .iter()
            .filter(|c| c.claim_type == claim.claim_type)
            .collect();
        let value = if same.len() > 1 {
            Value::Array(
                same.iter()
                    .map(|c| claim_json(c))
                    .collect::<Result<_, _>>()?,
            )
        } else {
            claim_json(claim)?
        };
        payload.insert(claim.claim_type.clone(), value);
    }
    if let Some(cnf) = &token.confirmation
        && let Ok(cnf) = serde_json::from_str::<Value>(cnf)
    {
        payload.insert("cnf".into(), cnf);
    }
    Ok(payload)
}

/// The JSON form of a claim value by its value type.
fn claim_json(claim: &Claim) -> Result<Value, ClaimValueError> {
    let error = || ClaimValueError {
        claim_type: claim.claim_type.clone(),
        value: claim.value.clone(),
        value_type: claim.value_type.clone(),
    };
    let vt = claim.value_type.as_str();
    Ok(if vt == CLAIM_VALUE_BOOLEAN {
        Value::Bool(match claim.value.trim().to_ascii_lowercase().as_str() {
            "true" => true,
            "false" => false,
            _ => return Err(error()),
        })
    } else if vt == CLAIM_VALUE_INTEGER || vt == CLAIM_VALUE_INTEGER32 {
        Value::from(claim.value.trim().parse::<i32>().map_err(|_| error())?)
    } else if vt == CLAIM_VALUE_INTEGER64 {
        Value::from(claim.value.trim().parse::<i64>().map_err(|_| error())?)
    } else if vt == CLAIM_VALUE_DOUBLE {
        crate::claims::wire_double(claim.value.trim().parse::<f64>().map_err(|_| error())?)
    } else if vt.eq_ignore_ascii_case(CLAIM_VALUE_JSON) {
        serde_json::from_str(&claim.value).map_err(|_| error())?
    } else {
        Value::String(claim.value.clone())
    })
}

/// Claim types the
/// profile service may not supply, because the protocol owns them.
pub const PROTOCOL_CLAIM_TYPES: &[&str] = &[
    "at_hash",
    "aud",
    "amr",
    "auth_time",
    "azp",
    "c_hash",
    "client_id",
    "exp",
    "idp",
    "iat",
    "iss",
    "jti",
    "nonce",
    "nbf",
    "reference_token_id",
    "sid",
    "sub",
    "scope",
    "cnf",
];

/// Distinct types, without the ones a token's
/// protocol claims own.
fn requested_types<'a>(types: impl Iterator<Item = &'a String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for claim_type in types {
        if !PROTOCOL_CLAIM_TYPES.contains(&claim_type.as_str()) && !out.contains(claim_type) {
            out.push(claim_type.clone());
        }
    }
    out
}

/// The claim types a user access token asks the profile service for: the
/// requested APIs' user claims, then their scopes'.
pub fn access_token_claim_types(resources: &ValidatedResources) -> Vec<String> {
    requested_types(
        resources
            .api_resources
            .iter()
            .flat_map(|a| &a.user_claims)
            .chain(resources.api_scopes.iter().flat_map(|s| &s.user_claims)),
    )
}

/// The claim types an identity token asks the profile service for when it
/// carries identity claims: the identity resources' user claims.
pub fn identity_token_claim_types(resources: &ValidatedResources) -> Vec<String> {
    requested_types(
        resources
            .identity_resources
            .iter()
            .flat_map(|r| &r.user_claims),
    )
}

/// Whether an identity token carries identity claims: asked for (no access
/// token issued alongside), or always for the client.
pub fn includes_identity_claims(client: &Client, request: &IdentityTokenRequest<'_>) -> bool {
    request.include_all_identity_claims || client.always_include_user_claims_in_id_token
}

/// `sub`, `auth_time`,
/// `idp`, each `amr`, then `acr` when the session has one.
fn subject_claims(session: &UserSession, sub: &str) -> Vec<Claim> {
    let mut claims = vec![
        Claim::string("sub", sub),
        Claim {
            claim_type: "auth_time".into(),
            value: session.auth_time.to_string(),
            value_type: CLAIM_VALUE_INTEGER64.into(),
        },
        Claim::string("idp", &session.idp),
    ];
    claims.extend(session.amr.iter().map(|a| Claim::string("amr", a)));
    if let Some(acr) = session.claim("acr") {
        claims.push(Claim::string("acr", acr));
    }
    claims
}

/// Duplicates of type and value are dropped.
fn distinct(claims: Vec<Claim>) -> Vec<Claim> {
    let mut out: Vec<Claim> = Vec::new();
    for claim in claims {
        if !out
            .iter()
            .any(|c| c.claim_type == claim.claim_type && c.value == claim.value)
        {
            out.push(claim);
        }
    }
    out
}

/// The token service for a user: `client_id`,
/// the client's claims when `always_send_client_claims`, the scopes
/// (`offline_access` last), the subject's claims, the profile claims (from
/// the profile service, for `access_token_claim_types`), then `sid`.
pub fn user_access_token(
    options: &ProtocolOptions,
    issuer: &str,
    client: &Client,
    resources: &ValidatedResources,
    session: &UserSession,
    session_id: Option<&str>,
    profile_claims: Vec<Claim>,
) -> AccessToken {
    let mut claims = vec![Claim::string("client_id", &client.client_id)];
    if client.always_send_client_claims {
        let prefix = client
            .client_claims_prefix
            .as_deref()
            .filter(|p| !p.trim().is_empty())
            .unwrap_or("");
        claims.extend(client.claims.iter().map(|c| Claim {
            claim_type: format!("{prefix}{}", c.claim_type),
            value: c.value.clone(),
            value_type: c.value_type.clone(),
        }));
    }
    for scope in resources.scopes.iter().filter(|s| *s != OFFLINE_ACCESS) {
        claims.push(Claim::string("scope", scope));
    }
    if resources.offline_access {
        claims.push(Claim::string("scope", OFFLINE_ACCESS));
    }
    claims.extend(subject_claims(session, &session.subject_id));
    claims.extend(without_protocol_claims(profile_claims));
    if let Some(sid) = session_id.filter(|s| !s.trim().is_empty()) {
        claims.push(Claim::string("sid", sid));
    }
    let mut audiences = resources.audiences();
    if options.emit_static_audience_claim {
        audiences.push(format!("{}/resources", issuer.trim_end_matches('/')));
    }
    AccessToken {
        issuer: issuer.to_owned(),
        client_id: client.client_id.clone(),
        lifetime: i64::from(client.access_token_lifetime),
        audiences,
        claims: distinct(claims),
        confirmation: None,
    }
}

/// What goes into an identity token beside the subject.
#[derive(Debug, Clone, Default)]
pub struct IdentityTokenRequest<'a> {
    pub nonce: Option<&'a str>,
    /// The access token issued alongside, hashed into `at_hash`.
    pub access_token: Option<&'a str>,
    /// The code issued alongside (hybrid), hashed into `c_hash`.
    pub authorization_code: Option<&'a str>,
    pub state_hash: Option<&'a str>,
    pub session_id: Option<&'a str>,
    /// Issue every requested identity claim (no access token was issued).
    pub include_all_identity_claims: bool,
    /// The `sub` the client sees, when it isn't the session's own (a
    /// pairwise subject).
    pub subject: Option<&'a str>,
}

/// `nonce`, `at_hash`,
/// `c_hash`, `s_hash`, `sid`, the subject's claims, then the profile claims
/// (empty unless `includes_identity_claims`); the client is the audience.
/// `algorithm` is the signing key's.
pub fn identity_token(
    issuer: &str,
    client: &Client,
    session: &UserSession,
    request: &IdentityTokenRequest<'_>,
    algorithm: &str,
    profile_claims: Vec<Claim>,
) -> AccessToken {
    let mut claims = Vec::new();
    if let Some(nonce) = request.nonce.filter(|n| !n.trim().is_empty()) {
        claims.push(Claim::string("nonce", nonce));
    }
    if let Some(token) = request.access_token.filter(|t| !t.trim().is_empty()) {
        claims.push(Claim::string(
            "at_hash",
            &hash_claim_value(token, algorithm),
        ));
    }
    if let Some(code) = request.authorization_code.filter(|c| !c.trim().is_empty()) {
        claims.push(Claim::string("c_hash", &hash_claim_value(code, algorithm)));
    }
    if let Some(hash) = request.state_hash.filter(|h| !h.trim().is_empty()) {
        claims.push(Claim::string("s_hash", hash));
    }
    if let Some(sid) = request.session_id.filter(|s| !s.trim().is_empty()) {
        claims.push(Claim::string("sid", sid));
    }
    claims.extend(subject_claims(
        session,
        request.subject.unwrap_or(&session.subject_id),
    ));
    claims.extend(without_protocol_claims(profile_claims));
    AccessToken {
        issuer: issuer.to_owned(),
        client_id: client.client_id.clone(),
        lifetime: i64::from(client.identity_token_lifetime),
        audiences: vec![client.client_id.clone()],
        claims: distinct(claims),
        confirmation: None,
    }
}

/// The left half of the value's hash
/// (SHA-256, -384 or -512 by the algorithm's size), base64url. The value is
/// read as ASCII, non-ASCII characters becoming `?`.
pub fn hash_claim_value(value: &str, algorithm: &str) -> String {
    use aws_lc_rs::digest;
    use base64::Engine;
    let bytes: Vec<u8> = value
        .chars()
        .map(|c| if c.is_ascii() { c as u8 } else { b'?' })
        .collect();
    let hash = match algorithm.get(algorithm.len().saturating_sub(3)..) {
        Some("384") => digest::digest(&digest::SHA384, &bytes),
        Some("512") => digest::digest(&digest::SHA512, &bytes),
        _ => digest::digest(&digest::SHA256, &bytes),
    };
    let half = &hash.as_ref()[..hash.as_ref().len() / 2];
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(half)
}

/// A new JWT id: 16 random bytes as upper-case hex.
pub fn new_jwt_id() -> String {
    use aws_lc_rs::rand::SecureRandom;
    let mut bytes = [0u8; 16];
    aws_lc_rs::rand::SystemRandom::new()
        .fill(&mut bytes)
        .expect("system random source");
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}
