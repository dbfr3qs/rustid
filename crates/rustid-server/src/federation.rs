//! Federation in the server: the providers file, with secrets from the
//! environment and `private_key_jwt` keys from PEM files, and the HTTP
//! client that reaches upstream providers (no redirects followed, 10
//! seconds, at most 1 MiB read).

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use rustid_core::clients::Client;
use rustid_core::federation::provider::{
    ClientAuthMethod, Credential, IdentityProvider, Provider, Providers,
};
use rustid_core::federation::upstream::{FormPost, UpstreamClient, UpstreamError};
use rustid_core::keys::{KeyConfig, LoadedKey};
use serde_json::Value;

/// The most of a response body read.
const MAX_BODY: usize = 1024 * 1024;

/// The providers in `path` (a JSON array), validated, with each
/// `secretEnv` read through `env` and keys loaded from files relative to
/// `path`.
pub fn load_providers(
    path: &Path,
    allow_insecure_loopback: bool,
    env: &dyn Fn(&str) -> Option<String>,
) -> anyhow::Result<Providers> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let configs: Vec<IdentityProvider> = serde_json::from_str(&text).with_context(|| {
        format!(
            "{} must hold a JSON array of identity providers",
            path.display()
        )
    })?;
    let base = path.parent().unwrap_or(Path::new("."));
    let mut providers = Vec::new();
    for config in configs {
        config.validate(allow_insecure_loopback)?;
        let auth = &config.client_authentication;
        let secret = || -> anyhow::Result<String> {
            match (&auth.secret, &auth.secret_env) {
                (Some(secret), _) => Ok(secret.clone()),
                (None, Some(name)) => env(name).with_context(|| {
                    format!(
                        "identity provider {}: the environment variable {name} is not set",
                        config.scheme
                    )
                }),
                (None, None) => unreachable!("validated"),
            }
        };
        let credential = match auth.method {
            ClientAuthMethod::ClientSecretBasic => Credential::Basic(secret()?),
            ClientAuthMethod::ClientSecretPost => Credential::Post(secret()?),
            ClientAuthMethod::PrivateKeyJwt => {
                let key = KeyConfig {
                    kid: auth.key_id.clone().expect("validated"),
                    alg: auth.algorithm.clone().unwrap_or_else(|| "RS256".to_owned()),
                    key_file: base.join(auth.key_file.as_ref().expect("validated")),
                    cert_file: auth.certificate_file.as_ref().map(|c| base.join(c)),
                };
                let loaded = LoadedKey::load(&key).with_context(|| {
                    format!("identity provider {}: loading its key", config.scheme)
                })?;
                Credential::PrivateKeyJwt(Arc::new(loaded))
            }
        };
        providers.push(Provider { config, credential });
    }
    Ok(Providers::new(providers)?)
}

/// Clients whose restrictions name a provider that isn't configured, as
/// (client id, scheme) pairs.
pub fn unknown_restrictions(clients: &[Client], known: &[String]) -> Vec<(String, String)> {
    clients
        .iter()
        .flat_map(|c| {
            c.identity_provider_restrictions
                .iter()
                .filter(|s| s.as_str() != rustid_core::session::LOCAL_IDP && !known.contains(s))
                .map(|s| (c.client_id.clone(), s.clone()))
        })
        .collect()
}

pub struct HttpUpstreamClient {
    client: reqwest::Client,
}

impl HttpUpstreamClient {
    /// Also trusts the CA certificates in `ca_file` (PEM), for providers
    /// behind a private PKI.
    pub fn with_ca_file(ca_file: Option<&Path>) -> anyhow::Result<Self> {
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10));
        if let Some(path) = ca_file {
            let pem = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
            for certificate in reqwest::Certificate::from_pem_bundle(&pem)
                .with_context(|| format!("parsing {}", path.display()))?
            {
                builder = builder.add_root_certificate(certificate);
            }
        }
        Ok(HttpUpstreamClient {
            client: builder.build()?,
        })
    }
}

fn error(e: impl std::fmt::Display) -> UpstreamError {
    UpstreamError(e.to_string())
}

/// The status and body, refusing bodies over `MAX_BODY`.
async fn read(mut response: reqwest::Response) -> Result<(u16, Vec<u8>), UpstreamError> {
    let status = response.status().as_u16();
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(error)? {
        if body.len() + chunk.len() > MAX_BODY {
            return Err(UpstreamError("the response is larger than 1 MiB".into()));
        }
        body.extend_from_slice(&chunk);
    }
    Ok((status, body))
}

/// RFC 6749 §2.3.1: the client id and secret are form-encoded before they
/// are joined for HTTP Basic.
fn form_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

#[async_trait]
impl UpstreamClient for HttpUpstreamClient {
    async fn get_json(&self, url: &str) -> Result<Value, UpstreamError> {
        let response = self.client.get(url).send().await.map_err(error)?;
        let (status, body) = read(response).await?;
        if !(200..300).contains(&status) {
            return Err(UpstreamError(format!("{url} answered {status}")));
        }
        serde_json::from_slice(&body).map_err(|e| UpstreamError(format!("{url}: {e}")))
    }

    async fn get_userinfo(&self, url: &str, access_token: &str) -> Result<Value, UpstreamError> {
        let response = self
            .client
            .get(url)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(error)?;
        let (status, body) = read(response).await?;
        if !(200..300).contains(&status) {
            return Err(UpstreamError(format!("{url} answered {status}")));
        }
        serde_json::from_slice(&body).map_err(|e| UpstreamError(format!("{url}: {e}")))
    }

    async fn post_form(&self, post: &FormPost) -> Result<(u16, Value), UpstreamError> {
        let mut request = self.client.post(&post.url).form(&post.form);
        if let Some((id, secret)) = &post.basic {
            request = request.basic_auth(form_encode(id), Some(form_encode(secret)));
        }
        let response = request.send().await.map_err(error)?;
        let (status, body) = read(response).await?;
        let json = serde_json::from_slice(&body).map_err(|e| {
            UpstreamError(format!("{} answered {status} without JSON: {e}", post.url))
        })?;
        Ok((status, json))
    }
}
