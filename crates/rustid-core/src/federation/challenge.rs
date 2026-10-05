//! Starting an upstream sign-in: the values bound to the browser in the
//! correlation cookie (`state`, `nonce`, the PKCE verifier and where to
//! return), and the authorization URL the browser is sent to.

use aws_lc_rs::digest;
use aws_lc_rs::rand::SecureRandom;
use serde::{Deserialize, Serialize};

use super::provider::IdentityProvider;
use super::upstream::Metadata;
use crate::data_protection::DataProtector;
use crate::jwt::b64url;
use crate::params::{add_query_string, url_encode};

pub const CORRELATION_COOKIE: &str = "idsrv.federation";
pub const CORRELATION_PURPOSE: &str = "rustid.federation";
pub const CORRELATION_LIFETIME_SECONDS: i64 = 600;

/// 32 random bytes, base64url.
pub fn random_value() -> String {
    let mut bytes = [0u8; 32];
    aws_lc_rs::rand::SystemRandom::new()
        .fill(&mut bytes)
        .expect("the system random source works");
    b64url(&bytes)
}

/// A started sign-in, sealed into the correlation cookie.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Correlation {
    pub scheme: String,
    pub state: String,
    pub nonce: String,
    pub code_verifier: String,
    pub return_url: String,
    /// Seconds since the epoch.
    pub created: i64,
    /// The client the sign-in is for, when known, for events.
    #[serde(default)]
    pub client_id: Option<String>,
}

impl Correlation {
    pub fn new(scheme: &str, return_url: &str, now: i64) -> Correlation {
        Correlation {
            scheme: scheme.to_owned(),
            state: random_value(),
            nonce: random_value(),
            code_verifier: random_value(),
            return_url: return_url.to_owned(),
            created: now,
            client_id: None,
        }
    }

    pub fn seal(&self, protector: &DataProtector) -> String {
        let json = serde_json::to_vec(self).expect("a correlation serializes");
        protector.protect(CORRELATION_PURPOSE, &json)
    }

    /// The correlation in `cookie`; `None` when it can't be read or has
    /// expired.
    pub fn open(protector: &DataProtector, cookie: &str, now: i64) -> Option<Correlation> {
        let json = protector.unprotect(CORRELATION_PURPOSE, cookie).ok()?;
        let correlation: Correlation = serde_json::from_slice(&json).ok()?;
        (now - correlation.created <= CORRELATION_LIFETIME_SECONDS).then_some(correlation)
    }

    /// The PKCE S256 challenge.
    pub fn code_challenge(&self) -> String {
        b64url(digest::digest(&digest::SHA256, self.code_verifier.as_bytes()).as_ref())
    }
}

/// The upstream authorization URL for the code flow with PKCE. `forward`
/// holds parameters passed on from the original request (`login_hint`,
/// `prompt`, `max_age`).
pub fn authorization_url(
    provider: &IdentityProvider,
    metadata: &Metadata,
    redirect_uri: &str,
    correlation: &Correlation,
    forward: &[(&str, String)],
) -> String {
    let challenge = correlation.code_challenge();
    let scope = provider.scopes.join(" ");
    let mut query: Vec<(&str, &str)> = vec![
        ("response_type", "code"),
        ("client_id", &provider.client_id),
        ("redirect_uri", redirect_uri),
        ("scope", &scope),
        ("state", &correlation.state),
        ("nonce", &correlation.nonce),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
    ];
    query.extend(forward.iter().map(|(k, v)| (*k, v.as_str())));
    let query = query
        .iter()
        .map(|(k, v)| format!("{k}={}", url_encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    add_query_string(&metadata.authorization_endpoint, &query)
}
