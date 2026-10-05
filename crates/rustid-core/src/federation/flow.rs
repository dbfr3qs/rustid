//! The configured providers, how rustid reaches them, and the two steps
//! that need the network: discovery (cached for a day) and redeeming a
//! code, which refetches the provider's keys once, at most once a minute,
//! when a token names a key it doesn't know.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::Value;
use tracing::Instrument;

use super::challenge::Correlation;
use super::id_token::{Expectations, IdTokenCheck, ValidatedIdToken, validate};
use super::provider::{Provider, Providers};
use super::upstream::{Metadata, NoUpstream, UpstreamClient, token_request};
use crate::jwt::PublicJwk;

/// How long discovery documents and key sets are kept.
pub const METADATA_LIFETIME_SECONDS: i64 = 86_400;
/// The least time between two key set fetches for one provider.
pub const JWKS_REFETCH_SECONDS: i64 = 60;

#[derive(Debug, Clone)]
struct Cached {
    metadata: Arc<Metadata>,
    fetched_at: i64,
    keys: Option<Vec<PublicJwk>>,
    keys_fetched_at: i64,
}

/// Federation: the providers, the outbound client and the metadata cache.
pub struct Federation {
    pub providers: Providers,
    pub upstream: Arc<dyn UpstreamClient>,
    pub allow_insecure_loopback: bool,
    cache: Mutex<HashMap<String, Cached>>,
}

impl std::fmt::Debug for Federation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Federation")
            .field("providers", &self.providers)
            .finish_non_exhaustive()
    }
}

impl Default for Federation {
    /// No providers, and nothing reachable.
    fn default() -> Self {
        Federation::new(Providers::default(), Arc::new(NoUpstream), false)
    }
}

/// Why an upstream sign-in failed.
#[derive(Debug, Clone, PartialEq)]
pub enum Failure {
    MetadataUnavailable(String),
    TokenRequestFailed(String),
    IdTokenInvalid(IdTokenCheck),
}

impl Failure {
    /// The reason recorded in events.
    pub fn reason(&self) -> &'static str {
        match self {
            Failure::MetadataUnavailable(_) => "metadata_unavailable",
            Failure::TokenRequestFailed(_) => "token_request_failed",
            Failure::IdTokenInvalid(_) => "id_token_invalid",
        }
    }

    /// What went wrong, for events and logs (never for the browser).
    pub fn detail(&self) -> String {
        match self {
            Failure::MetadataUnavailable(d) | Failure::TokenRequestFailed(d) => d.clone(),
            Failure::IdTokenInvalid(check) => {
                format!("the id token failed the {} check", check.as_str())
            }
        }
    }
}

fn cache_key(provider: &Provider) -> String {
    format!("{}\0{}", provider.config.scheme, provider.config.authority)
}

impl Federation {
    pub fn new(
        providers: Providers,
        upstream: Arc<dyn UpstreamClient>,
        allow_insecure_loopback: bool,
    ) -> Federation {
        Federation {
            providers,
            upstream,
            allow_insecure_loopback,
            cache: Mutex::new(HashMap::new()),
        }
    }

    fn cached(&self, provider: &Provider) -> Option<Cached> {
        self.cache
            .lock()
            .unwrap()
            .get(&cache_key(provider))
            .cloned()
    }

    fn store(&self, provider: &Provider, entry: Cached) {
        self.cache
            .lock()
            .unwrap()
            .insert(cache_key(provider), entry);
    }

    /// The provider's discovery document, checked against its authority.
    pub async fn metadata(&self, provider: &Provider, now: i64) -> Result<Arc<Metadata>, Failure> {
        if let Some(entry) = self.cached(provider)
            && now - entry.fetched_at < METADATA_LIFETIME_SECONDS
        {
            return Ok(entry.metadata);
        }
        let authority = &provider.config.authority;
        let url = format!(
            "{}/.well-known/openid-configuration",
            authority.trim_end_matches('/')
        );
        let span = tracing::info_span!("federation.discovery", scheme = %provider.config.scheme);
        let document = self
            .upstream
            .get_json(&url)
            .instrument(span)
            .await
            .map_err(|e| Failure::MetadataUnavailable(e.0))?;
        let metadata: Metadata = serde_json::from_value(document)
            .map_err(|e| Failure::MetadataUnavailable(format!("the discovery document: {e}")))?;
        metadata
            .check(authority, self.allow_insecure_loopback)
            .map_err(Failure::MetadataUnavailable)?;
        let metadata = Arc::new(metadata);
        self.store(
            provider,
            Cached {
                metadata: metadata.clone(),
                fetched_at: now,
                keys: None,
                keys_fetched_at: 0,
            },
        );
        Ok(metadata)
    }

    async fn fetch_keys(
        &self,
        provider: &Provider,
        metadata: &Metadata,
        now: i64,
    ) -> Result<Vec<PublicJwk>, Failure> {
        let span = tracing::info_span!("federation.jwks", scheme = %provider.config.scheme);
        let document = self
            .upstream
            .get_json(&metadata.jwks_uri)
            .instrument(span)
            .await
            .map_err(|e| Failure::MetadataUnavailable(e.0))?;
        let keys: Vec<PublicJwk> = document
            .get("keys")
            .and_then(Value::as_array)
            .ok_or_else(|| Failure::MetadataUnavailable("the key set has no keys".into()))?
            .iter()
            .filter_map(|k| serde_json::from_value(k.clone()).ok())
            .collect();
        if let Some(mut entry) = self.cached(provider) {
            entry.keys = Some(keys.clone());
            entry.keys_fetched_at = now;
            self.store(provider, entry);
        }
        Ok(keys)
    }

    /// Redeems `code` and validates the id token. A token naming an unknown
    /// key refetches the key set once, unless it was fetched less than a
    /// minute ago.
    pub async fn redeem(
        &self,
        provider: &Provider,
        code: &str,
        redirect_uri: &str,
        correlation: &Correlation,
        skew: i64,
        now: i64,
    ) -> Result<ValidatedIdToken, Failure> {
        let metadata = self.metadata(provider, now).await?;
        let post = token_request(
            provider,
            &metadata,
            code,
            redirect_uri,
            &correlation.code_verifier,
            now,
        )
        .map_err(Failure::TokenRequestFailed)?;
        let span = tracing::info_span!("federation.token", scheme = %provider.config.scheme);
        let (status, body) = self
            .upstream
            .post_form(&post)
            .instrument(span)
            .await
            .map_err(|e| Failure::TokenRequestFailed(e.0))?;
        if !(200..300).contains(&status) {
            let error = body.get("error").and_then(Value::as_str).unwrap_or("");
            return Err(Failure::TokenRequestFailed(format!(
                "the token endpoint answered {status} {error}"
            )));
        }
        let id_token = body
            .get("id_token")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                Failure::TokenRequestFailed("the token response has no id_token".into())
            })?;
        let algorithms = metadata.id_token_algorithms();
        let expect = Expectations {
            issuer: &provider.config.authority,
            client_id: &provider.config.client_id,
            nonce: &correlation.nonce,
            algorithms: &algorithms,
            now,
            skew,
        };
        let entry = self.cached(provider);
        let keys = match entry.as_ref().and_then(|e| e.keys.clone()) {
            Some(keys) => keys,
            None => self.fetch_keys(provider, &metadata, now).await?,
        };
        match validate(id_token, &keys, &expect) {
            Err(IdTokenCheck::UnknownKey) => {
                let fetched_at = self
                    .cached(provider)
                    .map(|e| e.keys_fetched_at)
                    .unwrap_or(0);
                if now - fetched_at < JWKS_REFETCH_SECONDS {
                    return Err(Failure::IdTokenInvalid(IdTokenCheck::UnknownKey));
                }
                let keys = self.fetch_keys(provider, &metadata, now).await?;
                validate(id_token, &keys, &expect).map_err(Failure::IdTokenInvalid)
            }
            other => other.map_err(Failure::IdTokenInvalid),
        }
    }
}
