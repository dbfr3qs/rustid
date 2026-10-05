//! Upstream identity providers: how they are configured, the rules a
//! configuration must follow, and the set a client may sign in through.

use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::clients::Client;
use crate::keys::LoadedKey;
use crate::session::LOCAL_IDP;

use super::session::STANDARD_CLAIMS;

/// An upstream OpenID Connect provider, as configured.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityProvider {
    /// The provider's identifier: the URL path segment, the `idp:` acr
    /// value, the clients' restrictions and the session's `idp`.
    pub scheme: String,
    /// Shown on sign-in buttons.
    pub display_name: String,
    #[serde(default = "enabled_default")]
    pub enabled: bool,
    /// The upstream issuer.
    pub authority: String,
    pub client_id: String,
    #[serde(default)]
    pub client_authentication: ClientAuthentication,
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
    /// The id token claims copied into the session.
    #[serde(default = "default_claims")]
    pub claims: Vec<String>,
    /// Also call the provider's userinfo endpoint with the access token;
    /// its claims join the id token's (OIDC Core §5.3).
    #[serde(default)]
    pub userinfo: bool,
}

fn enabled_default() -> bool {
    true
}

fn default_scopes() -> Vec<String> {
    ["openid", "profile", "email"].map(str::to_owned).to_vec()
}

fn default_claims() -> Vec<String> {
    STANDARD_CLAIMS.iter().map(|c| (*c).to_owned()).collect()
}

/// How rustid authenticates to the provider's token endpoint.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientAuthentication {
    #[serde(default)]
    pub method: ClientAuthMethod,
    #[serde(default)]
    pub secret: Option<String>,
    /// An environment variable holding the secret.
    #[serde(default)]
    pub secret_env: Option<String>,
    /// `private_key_jwt`: a PKCS#8 PEM private key.
    #[serde(default)]
    pub key_file: Option<PathBuf>,
    #[serde(default)]
    pub key_id: Option<String>,
    /// `private_key_jwt`: RS256 (the default), ES256 or ES384.
    #[serde(default)]
    pub algorithm: Option<String>,
    /// `private_key_jwt`: the key's X.509 certificate (PEM), whose
    /// thumbprint the assertion then carries as `x5t`.
    #[serde(default)]
    pub certificate_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuthMethod {
    #[default]
    ClientSecretBasic,
    ClientSecretPost,
    PrivateKeyJwt,
}

/// The algorithms a `private_key_jwt` key may use.
pub const ASSERTION_ALGORITHMS: &[&str] = &["RS256", "ES256", "ES384"];

/// How rustid authenticates to the token endpoint, resolved at load.
#[derive(Debug, Clone)]
pub enum Credential {
    Basic(String),
    Post(String),
    PrivateKeyJwt(Arc<LoadedKey>),
}

/// A provider ready to use.
#[derive(Debug, Clone)]
pub struct Provider {
    pub config: IdentityProvider,
    pub credential: Credential,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProviderError {
    #[error("identity provider scheme {0:?} must match ^[a-z0-9][a-z0-9_-]{{0,63}}$")]
    Scheme(String),
    #[error("identity provider scheme \"local\" is reserved")]
    Reserved,
    #[error("identity provider {0:?} is defined twice")]
    Duplicate(String),
    #[error("identity provider {scheme}: {message}")]
    Invalid { scheme: String, message: String },
}

fn valid_scheme(scheme: &str) -> bool {
    let bytes = scheme.as_bytes();
    let allowed = |b: &u8, first: bool| {
        b.is_ascii_lowercase() || b.is_ascii_digit() || (!first && (*b == b'_' || *b == b'-'))
    };
    !bytes.is_empty()
        && bytes.len() <= 64
        && allowed(&bytes[0], true)
        && bytes[1..].iter().all(|b| allowed(b, false))
}

impl IdentityProvider {
    /// The rules that need nothing outside the provider itself.
    pub fn validate(&self, allow_insecure_loopback: bool) -> Result<(), ProviderError> {
        if self.scheme == LOCAL_IDP {
            return Err(ProviderError::Reserved);
        }
        if !valid_scheme(&self.scheme) {
            return Err(ProviderError::Scheme(self.scheme.clone()));
        }
        let invalid = |message: &str| {
            Err(ProviderError::Invalid {
                scheme: self.scheme.clone(),
                message: message.to_owned(),
            })
        };
        if self.display_name.trim().is_empty() {
            return invalid("`displayName` must not be empty");
        }
        if self.client_id.trim().is_empty() {
            return invalid("`clientId` must not be empty");
        }
        if !is_allowed_url(&self.authority, allow_insecure_loopback) {
            return invalid("`authority` must be https");
        }
        if !self.scopes.iter().any(|s| s == "openid") {
            return invalid("`scopes` must contain openid");
        }
        let auth = &self.client_authentication;
        match auth.method {
            ClientAuthMethod::ClientSecretBasic | ClientAuthMethod::ClientSecretPost => {
                if auth.secret.is_some() == auth.secret_env.is_some() {
                    return invalid("set exactly one of `secret` and `secretEnv`");
                }
            }
            ClientAuthMethod::PrivateKeyJwt => {
                if auth.key_file.is_none() || auth.key_id.is_none() {
                    return invalid("`private_key_jwt` needs `keyFile` and `keyId`");
                }
                if let Some(alg) = &auth.algorithm
                    && !ASSERTION_ALGORITHMS.contains(&alg.as_str())
                {
                    return invalid("`algorithm` must be RS256, ES256 or ES384");
                }
            }
        }
        Ok(())
    }
}

/// `https`, or an `http` loopback URL (`localhost`, `127.0.0.1`) when
/// allowed.
pub fn is_allowed_url(url: &str, allow_insecure_loopback: bool) -> bool {
    let Ok(url) = url::Url::parse(url) else {
        return false;
    };
    match url.scheme() {
        "https" => url.host_str().is_some(),
        "http" => {
            allow_insecure_loopback && matches!(url.host_str(), Some("localhost" | "127.0.0.1"))
        }
        _ => false,
    }
}

/// The configured providers.
#[derive(Debug, Clone, Default)]
pub struct Providers(Vec<Provider>);

impl Providers {
    /// Refuses two providers with the same scheme.
    pub fn new(providers: Vec<Provider>) -> Result<Providers, ProviderError> {
        for (i, p) in providers.iter().enumerate() {
            if providers[..i]
                .iter()
                .any(|q| q.config.scheme == p.config.scheme)
            {
                return Err(ProviderError::Duplicate(p.config.scheme.clone()));
            }
        }
        Ok(Providers(providers))
    }

    /// An enabled provider.
    pub fn find(&self, scheme: &str) -> Option<&Provider> {
        self.0
            .iter()
            .find(|p| p.config.enabled && p.config.scheme == scheme)
    }

    /// The enabled providers `client` may sign in through: all of them when
    /// it has no restrictions, otherwise those it names.
    pub fn allowed_for(&self, client: &Client) -> Vec<&Provider> {
        let restrictions = &client.identity_provider_restrictions;
        self.0
            .iter()
            .filter(|p| p.config.enabled)
            .filter(|p| restrictions.is_empty() || restrictions.contains(&p.config.scheme))
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Provider> {
        self.0.iter()
    }
}
