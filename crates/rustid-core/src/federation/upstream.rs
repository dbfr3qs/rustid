//! Talking to an upstream provider: the outbound HTTP rustid needs (a
//! trait, so the core does no I/O), its discovery document, and the token
//! request for an authorization code.

use serde_json::{Map, Value};

use super::provider::{Credential, Provider, is_allowed_url};
use crate::jwt::b64url;

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[error("{0}")]
pub struct UpstreamError(pub String);

/// A form POST: the URL, the fields, and HTTP Basic credentials (raw; the
/// client form-encodes them, RFC 6749 §2.3.1).
#[derive(Debug, Clone, PartialEq)]
pub struct FormPost {
    pub url: String,
    pub form: Vec<(String, String)>,
    pub basic: Option<(String, String)>,
}

/// The outbound HTTP federation needs.
#[async_trait::async_trait]
pub trait UpstreamClient: Send + Sync {
    /// GETs a JSON document; non-2xx answers, timeouts and oversized
    /// bodies are errors.
    async fn get_json(&self, url: &str) -> Result<Value, UpstreamError>;
    /// POSTs a form; the status and the JSON body (an error when the body
    /// isn't JSON).
    async fn post_form(&self, post: &FormPost) -> Result<(u16, Value), UpstreamError>;
}

/// Reaches nothing: every call fails.
pub struct NoUpstream;

#[async_trait::async_trait]
impl UpstreamClient for NoUpstream {
    async fn get_json(&self, _: &str) -> Result<Value, UpstreamError> {
        Err(UpstreamError("no upstream client".into()))
    }
    async fn post_form(&self, _: &FormPost) -> Result<(u16, Value), UpstreamError> {
        Err(UpstreamError("no upstream client".into()))
    }
}

/// The parts of a provider's discovery document federation uses.
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub struct Metadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub id_token_signing_alg_values_supported: Vec<String>,
    #[serde(default)]
    pub authorization_response_iss_parameter_supported: bool,
    #[serde(default)]
    pub end_session_endpoint: Option<String>,
}

/// The algorithms an id token may be signed with.
pub const ASYMMETRIC_ALGORITHMS: &[&str] = &[
    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512",
];

impl Metadata {
    /// The issuer must be the authority (Discovery §4.3), and the endpoints
    /// https (or loopback, when allowed).
    pub fn check(&self, authority: &str, allow_insecure_loopback: bool) -> Result<(), String> {
        if self.issuer != authority {
            return Err(format!(
                "the discovery issuer {:?} isn't the authority {authority:?}",
                self.issuer
            ));
        }
        for (name, url) in [
            ("authorization_endpoint", &self.authorization_endpoint),
            ("token_endpoint", &self.token_endpoint),
            ("jwks_uri", &self.jwks_uri),
        ] {
            if !is_allowed_url(url, allow_insecure_loopback) {
                return Err(format!("the discovery {name} {url:?} must be https"));
            }
        }
        Ok(())
    }

    /// The advertised asymmetric algorithms, or RS256 when none are
    /// advertised.
    pub fn id_token_algorithms(&self) -> Vec<String> {
        if self.id_token_signing_alg_values_supported.is_empty() {
            return vec!["RS256".to_owned()];
        }
        self.id_token_signing_alg_values_supported
            .iter()
            .filter(|a| ASYMMETRIC_ALGORITHMS.contains(&a.as_str()))
            .cloned()
            .collect()
    }
}

/// The token request for an authorization code, authenticated as the
/// provider's credential says: HTTP Basic, the form, or a signed client
/// assertion (RFC 7523) that carries `x5t` when the key has a certificate.
pub fn token_request(
    provider: &Provider,
    metadata: &Metadata,
    code: &str,
    redirect_uri: &str,
    code_verifier: &str,
    now: i64,
) -> Result<FormPost, String> {
    let client_id = &provider.config.client_id;
    let mut form: Vec<(String, String)> = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("code_verifier", code_verifier),
    ]
    .map(|(k, v)| (k.to_owned(), v.to_owned()))
    .to_vec();
    let mut basic = None;
    match &provider.credential {
        Credential::Basic(secret) => basic = Some((client_id.clone(), secret.clone())),
        Credential::Post(secret) => {
            form.push(("client_id".into(), client_id.clone()));
            form.push(("client_secret".into(), secret.clone()));
        }
        Credential::PrivateKeyJwt(key) => {
            let mut payload = Map::new();
            payload.insert("iss".into(), client_id.clone().into());
            payload.insert("sub".into(), client_id.clone().into());
            payload.insert("aud".into(), metadata.token_endpoint.clone().into());
            payload.insert("iat".into(), now.into());
            payload.insert("exp".into(), (now + 60).into());
            payload.insert("jti".into(), super::challenge::random_value().into());
            let x5t = key.certificate().map(|der| {
                let digest =
                    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY, &der);
                b64url(digest.as_ref())
            });
            let header: Vec<(&str, &str)> =
                x5t.as_deref().map(|t| ("x5t", t)).into_iter().collect();
            let assertion =
                crate::jwt::encode(key, &header, &payload).map_err(|e| format!("{e:?}"))?;
            form.push(("client_id".into(), client_id.clone()));
            form.push((
                "client_assertion_type".into(),
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".into(),
            ));
            form.push(("client_assertion".into(), assertion));
        }
    }
    Ok(FormPost {
        url: metadata.token_endpoint.clone(),
        form,
        basic,
    })
}
