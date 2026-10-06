//! Upstream identity providers: how they are configured, the rules a
//! configuration must follow, and the set a client may sign in through.

use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::clients::Client;
use crate::keys::LoadedKey;
use crate::session::LOCAL_IDP;

use super::session::STANDARD_CLAIMS;
use super::upstream::{ASYMMETRIC_ALGORITHMS, Metadata};

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
    /// Signing out of rustid also signs the user out of the provider
    /// (OpenID Connect RP-Initiated Logout 1.0).
    #[serde(default)]
    pub sign_out: bool,
    /// The provider's back channel may end rustid sessions (OpenID
    /// Connect Back-Channel Logout 1.0).
    #[serde(default)]
    pub back_channel_logout: bool,
    /// The provider's front channel may end rustid sessions (OpenID
    /// Connect Front-Channel Logout 1.0).
    #[serde(default)]
    pub front_channel_logout: bool,
    /// One entry for a shared multi-tenant endpoint (Entra ID's
    /// `organizations` or `common`), accepting the tenants listed.
    #[serde(default)]
    pub multi_tenant: Option<MultiTenant>,
    /// The id token signing algorithm registered at the provider: id
    /// tokens and logout tokens signed otherwise are refused. Unset, any
    /// asymmetric algorithm the provider advertises (OIDC Core §3.1.3.7).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_token_signed_response_alg: Option<String>,
}

/// The tenants a multi-tenant provider accepts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MultiTenant {
    pub tenants: Vec<String>,
}

impl MultiTenant {
    /// Whether `tid` is one of the tenants (tenant ids compare without
    /// case).
    pub fn allows(&self, tid: &str) -> bool {
        self.tenants.iter().any(|t| t.eq_ignore_ascii_case(tid))
    }
}

/// A tenant id: a GUID, 8-4-4-4-12 hex digits.
fn is_guid(value: &str) -> bool {
    let groups: Vec<&str> = value.split('-').collect();
    groups.len() == 5
        && groups
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(g, n)| g.len() == n && g.bytes().all(|b| b.is_ascii_hexdigit()))
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
    /// `private_key_jwt`: the PKCS#8 PEM private key itself, as the admin
    /// API takes it (stored encrypted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// `private_key_jwt`: the certificate PEM itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
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
    /// The algorithms its id tokens and logout tokens may be signed with.
    pub fn id_token_algorithms(&self, metadata: &Metadata) -> Vec<String> {
        match &self.id_token_signed_response_alg {
            Some(alg) => vec![alg.clone()],
            None => metadata.id_token_algorithms(),
        }
    }

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
        if let Some(multi) = &self.multi_tenant {
            if multi.tenants.is_empty() {
                return invalid("`multiTenant.tenants` must not be empty");
            }
            if !multi.tenants.iter().all(|t| is_guid(t)) {
                return invalid("`multiTenant.tenants` entries must be tenant ids (GUIDs)");
            }
        }
        if let Some(alg) = &self.id_token_signed_response_alg
            && !ASYMMETRIC_ALGORITHMS.contains(&alg.as_str())
        {
            return invalid("`idTokenSignedResponseAlg` must be an asymmetric algorithm");
        }
        let auth = &self.client_authentication;
        match auth.method {
            ClientAuthMethod::ClientSecretBasic | ClientAuthMethod::ClientSecretPost => {
                if auth.secret.is_some() == auth.secret_env.is_some() {
                    return invalid("set exactly one of `secret` and `secretEnv`");
                }
            }
            ClientAuthMethod::PrivateKeyJwt => {
                if auth.key_id.is_none() || (auth.key_file.is_none() && auth.key.is_none()) {
                    return invalid("`private_key_jwt` needs `keyId`, and `keyFile` or `key`");
                }
                if auth.key_file.is_some() && auth.key.is_some() {
                    return invalid("set one of `keyFile` and `key`");
                }
                if auth.certificate_file.is_some() && auth.certificate.is_some() {
                    return invalid("set one of `certificateFile` and `certificate`");
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

/// The credential a provider's configuration describes: the secret given
/// (or read from `secretEnv` through `env`), or the private key given
/// inline or read from `keyFile`, relative to `base` (with its
/// certificate). The configuration must have passed `validate`.
pub fn resolve_credential(
    config: &IdentityProvider,
    base: &std::path::Path,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Credential, String> {
    let auth = &config.client_authentication;
    let secret = || -> Result<String, String> {
        match (&auth.secret, &auth.secret_env) {
            (Some(secret), _) => Ok(secret.clone()),
            (None, Some(name)) => {
                env(name).ok_or_else(|| format!("the environment variable {name} is not set"))
            }
            (None, None) => Err("no secret".into()),
        }
    };
    Ok(match auth.method {
        ClientAuthMethod::ClientSecretBasic => Credential::Basic(secret()?),
        ClientAuthMethod::ClientSecretPost => Credential::Post(secret()?),
        ClientAuthMethod::PrivateKeyJwt => {
            let kid = auth.key_id.clone().ok_or("no keyId")?;
            let alg = auth.algorithm.clone().unwrap_or_else(|| "RS256".to_owned());
            let read = |inline: &Option<String>,
                        file: &Option<PathBuf>,
                        what: &str|
             -> Result<Option<Vec<u8>>, String> {
                let text = match (inline, file) {
                    (Some(text), _) => text.clone(),
                    (None, Some(path)) => {
                        let path = base.join(path);
                        std::fs::read_to_string(&path)
                            .map_err(|e| format!("reading {}: {e}", path.display()))?
                    }
                    (None, None) => return Ok(None),
                };
                pem::parse(text.trim())
                    .map(|p| Some(p.into_contents()))
                    .map_err(|e| format!("the {what} isn't PEM: {e}"))
            };
            let key = read(&auth.key, &auth.key_file, "key")?.ok_or("no key")?;
            let certificate = read(&auth.certificate, &auth.certificate_file, "certificate")?;
            let origin = crate::keys::KeyOrigin {
                key: auth
                    .key_file
                    .as_ref()
                    .map_or("the inline key".to_owned(), |p| p.display().to_string()),
                cert: None,
            };
            let loaded = LoadedKey::from_der(&kid, &alg, &key, certificate.as_deref(), &origin)
                .map_err(|e| e.to_string())?;
            Credential::PrivateKeyJwt(Arc::new(loaded))
        }
    })
}
