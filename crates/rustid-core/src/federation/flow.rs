//! The configured providers, how rustid reaches them, and the two steps
//! that need the network: discovery (cached for a day) and redeeming a
//! code, which refetches the provider's keys once when a token's key isn't
//! among them (a provider rotating keys), at most sixty times a minute.

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
/// The most key set refetches for one provider in a minute.
pub const JWKS_REFETCH_LIMIT: usize = 60;

#[derive(Debug, Clone)]
struct Cached {
    metadata: Arc<Metadata>,
    fetched_at: i64,
    keys: Option<Vec<PublicJwk>>,
    /// When the key set was refetched for unknown keys, in the last minute.
    refetches: Vec<i64>,
}

/// Stored providers resolved, by scheme: the entity id and version they
/// were resolved at.
type Resolved = Mutex<HashMap<String, (crate::admin::EntityId, i32, Arc<Provider>)>>;

/// Where federation's providers come from.
enum Source {
    /// A fixed set.
    Static(Providers),
    /// The configuration store, read on every use; resolved providers are
    /// kept by scheme and version, so a change is seen at once.
    Store {
        configuration: Arc<dyn crate::stores::ConfigurationStore>,
        protector: Arc<crate::data_protection::DataProtector>,
        resolved: Resolved,
    },
}

/// Federation: the providers, the outbound client and the metadata cache.
pub struct Federation {
    source: Source,
    pub upstream: Arc<dyn UpstreamClient>,
    pub allow_insecure_loopback: bool,
    cache: Mutex<HashMap<String, Cached>>,
}

impl std::fmt::Debug for Federation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Federation").finish_non_exhaustive()
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
    UserinfoFailed(String),
    TenantNotAllowed(String),
}

impl Failure {
    /// The reason recorded in events.
    pub fn reason(&self) -> &'static str {
        match self {
            Failure::MetadataUnavailable(_) => "metadata_unavailable",
            Failure::TokenRequestFailed(_) => "token_request_failed",
            Failure::IdTokenInvalid(_) => "id_token_invalid",
            Failure::UserinfoFailed(_) => "userinfo_failed",
            Failure::TenantNotAllowed(_) => "tenant_not_allowed",
        }
    }

    /// What went wrong, for events and logs (never for the browser).
    pub fn detail(&self) -> String {
        match self {
            Failure::MetadataUnavailable(d)
            | Failure::TokenRequestFailed(d)
            | Failure::UserinfoFailed(d)
            | Failure::TenantNotAllowed(d) => d.clone(),
            Failure::IdTokenInvalid(check) => {
                format!("the id token failed the {} check", check.as_str())
            }
        }
    }
}

/// A multi-tenant provider's issuer for this token: the token's `tid`
/// must be one of the tenants, and the issuer is the template with it.
/// The id token checks that follow verify the signature over both.
fn tenant_issuer(
    multi: &super::provider::MultiTenant,
    metadata: &Metadata,
    id_token: &str,
) -> Result<String, Failure> {
    let tid = crate::jwt::Jws::decode(id_token)
        .and_then(|jws| jws.claim_str("tid").map(str::to_owned))
        .ok_or_else(|| Failure::TenantNotAllowed("the id token has no tid".into()))?;
    if !multi.allows(&tid) {
        return Err(Failure::TenantNotAllowed(format!(
            "tenant {tid} isn't one of the provider's tenants"
        )));
    }
    Ok(metadata
        .issuer
        .replace(super::upstream::TENANT_PLACEHOLDER, &tid))
}

fn cache_key(provider: &Provider) -> String {
    format!("{}\0{}", provider.config.scheme, provider.config.authority)
}

impl Federation {
    /// Federation over a fixed set of providers.
    pub fn new(
        providers: Providers,
        upstream: Arc<dyn UpstreamClient>,
        allow_insecure_loopback: bool,
    ) -> Federation {
        Federation {
            source: Source::Static(providers),
            upstream,
            allow_insecure_loopback,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Federation over the providers in the configuration store, whose
    /// secrets `protector` opens.
    pub fn from_store(
        configuration: Arc<dyn crate::stores::ConfigurationStore>,
        protector: Arc<crate::data_protection::DataProtector>,
        upstream: Arc<dyn UpstreamClient>,
        allow_insecure_loopback: bool,
    ) -> Federation {
        Federation {
            source: Source::Store {
                configuration,
                protector,
                resolved: Mutex::new(HashMap::new()),
            },
            upstream,
            allow_insecure_loopback,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// A stored provider, resolved once per version. One that can't be
    /// resolved (its secret's environment variable has gone, say) is
    /// logged and left out.
    fn resolved(
        resolved: &Resolved,
        protector: &crate::data_protection::DataProtector,
        entity: &crate::stores::StoredEntity,
    ) -> Option<Arc<Provider>> {
        // The id too: a provider deleted and created again starts at
        // version 1 again.
        if let Some((id, version, provider)) = resolved.lock().unwrap().get(&entity.key)
            && *id == entity.id
            && *version == entity.version
        {
            return Some(provider.clone());
        }
        match crate::admin::identity_providers::resolve(entity, protector, &|name| {
            std::env::var(name).ok()
        }) {
            Ok(provider) => {
                let provider = Arc::new(provider);
                resolved.lock().unwrap().insert(
                    entity.key.clone(),
                    (entity.id, entity.version, provider.clone()),
                );
                Some(provider)
            }
            Err(error) => {
                tracing::warn!(scheme = %entity.key, %error, "identity provider left out: it can't be used");
                None
            }
        }
    }

    /// Every provider, enabled or not.
    pub async fn providers(&self) -> Result<Vec<Arc<Provider>>, crate::stores::StoreError> {
        match &self.source {
            Source::Static(providers) => Ok(providers.iter().cloned().map(Arc::new).collect()),
            Source::Store {
                configuration,
                protector,
                resolved,
            } => Ok(configuration
                .list(crate::stores::EntityKind::IdentityProvider)
                .await?
                .iter()
                .filter_map(|entity| Self::resolved(resolved, protector, entity))
                .collect()),
        }
    }

    /// An enabled provider.
    pub async fn find(
        &self,
        scheme: &str,
    ) -> Result<Option<Arc<Provider>>, crate::stores::StoreError> {
        let provider = match &self.source {
            Source::Static(providers) => providers.find(scheme).cloned().map(Arc::new),
            Source::Store {
                configuration,
                protector,
                resolved,
            } => configuration
                .read_by_key(crate::stores::EntityKind::IdentityProvider, scheme)
                .await?
                .and_then(|entity| Self::resolved(resolved, protector, &entity)),
        };
        Ok(provider.filter(|p| p.config.enabled))
    }

    /// The enabled providers `client` may sign in through: all of them when
    /// it has no restrictions, otherwise those it names.
    pub async fn allowed_for(
        &self,
        client: &crate::clients::Client,
    ) -> Result<Vec<Arc<Provider>>, crate::stores::StoreError> {
        let restrictions = &client.identity_provider_restrictions;
        Ok(self
            .providers()
            .await?
            .into_iter()
            .filter(|p| p.config.enabled)
            .filter(|p| restrictions.is_empty() || restrictions.contains(&p.config.scheme))
            .collect())
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
            .check(
                authority,
                self.allow_insecure_loopback,
                provider.config.multi_tenant.is_some(),
            )
            .map_err(Failure::MetadataUnavailable)?;
        let metadata = Arc::new(metadata);
        self.store(
            provider,
            Cached {
                metadata: metadata.clone(),
                fetched_at: now,
                keys: None,
                refetches: Vec::new(),
            },
        );
        Ok(metadata)
    }

    async fn fetch_keys(
        &self,
        provider: &Provider,
        metadata: &Metadata,
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
        let algorithms = provider.config.id_token_algorithms(&metadata);
        let issuer = match &provider.config.multi_tenant {
            None => provider.config.authority.clone(),
            Some(multi) => tenant_issuer(multi, &metadata, id_token)?,
        };
        let expect = Expectations {
            issuer: &issuer,
            client_id: &provider.config.client_id,
            nonce: &correlation.nonce,
            algorithms: &algorithms,
            now,
            skew,
        };
        let entry = self.cached(provider);
        let keys = match entry.as_ref().and_then(|e| e.keys.clone()) {
            Some(keys) => keys,
            None => self.fetch_keys(provider, &metadata).await?,
        };
        let no_kid =
            crate::jwt::Jws::decode(id_token).is_some_and(|jws| jws.header_str("kid").is_none());
        let token = match validate(id_token, &keys, &expect) {
            // The provider may have rotated its keys: refetch them once.
            Err(check @ (IdTokenCheck::UnknownKey | IdTokenCheck::Signature))
                if check == IdTokenCheck::UnknownKey || no_kid =>
            {
                if !self.may_refetch(provider, now) {
                    return Err(Failure::IdTokenInvalid(check));
                }
                let keys = self.fetch_keys(provider, &metadata).await?;
                validate(id_token, &keys, &expect).map_err(Failure::IdTokenInvalid)?
            }
            other => other.map_err(Failure::IdTokenInvalid)?,
        };
        if !provider.config.userinfo {
            return Ok(token);
        }
        let access_token = body.get("access_token").and_then(Value::as_str);
        self.with_userinfo(provider, &metadata, access_token, token)
            .await
    }

    /// Whether the key set may be refetched now (fewer than
    /// `JWKS_REFETCH_LIMIT` refetches in the last minute), counting this one.
    fn may_refetch(&self, provider: &Provider, now: i64) -> bool {
        let mut cache = self.cache.lock().unwrap();
        let Some(entry) = cache.get_mut(&cache_key(provider)) else {
            return true;
        };
        entry.refetches.retain(|t| now - t < 60);
        if entry.refetches.len() >= JWKS_REFETCH_LIMIT {
            return false;
        }
        entry.refetches.push(now);
        true
    }

    /// The token with the userinfo response's claims added: its `sub` must
    /// be the token's (OIDC Core §5.3.4), and protocol claims are ignored.
    async fn with_userinfo(
        &self,
        provider: &Provider,
        metadata: &Metadata,
        access_token: Option<&str>,
        mut token: ValidatedIdToken,
    ) -> Result<ValidatedIdToken, Failure> {
        let endpoint = metadata.userinfo_endpoint.as_deref().ok_or_else(|| {
            Failure::UserinfoFailed("the provider advertises no userinfo_endpoint".into())
        })?;
        let access_token = access_token.ok_or_else(|| {
            Failure::UserinfoFailed("the token response has no access_token".into())
        })?;
        let span = tracing::info_span!("federation.userinfo", scheme = %provider.config.scheme);
        let response = self
            .upstream
            .get_userinfo(endpoint, access_token)
            .instrument(span)
            .await
            .map_err(|e| Failure::UserinfoFailed(e.0))?;
        let Value::Object(claims) = response else {
            return Err(Failure::UserinfoFailed(
                "the userinfo response isn't a JSON object".into(),
            ));
        };
        if claims.get("sub").and_then(Value::as_str) != Some(token.subject.as_str()) {
            return Err(Failure::UserinfoFailed(
                "the userinfo response's sub isn't the id token's".into(),
            ));
        }
        for (name, value) in claims {
            if !super::session::PROTOCOL_CLAIMS.contains(&name.as_str()) {
                token.payload.insert(name, value);
            }
        }
        Ok(token)
    }
}

/// Why a logout token was refused.
#[derive(Debug, Clone, PartialEq)]
pub enum LogoutFailure {
    MetadataUnavailable(String),
    Invalid(super::logout::LogoutTokenCheck),
    /// The replay cache couldn't be read: a server fault, not the token's.
    ReplayUnavailable(String),
}

impl LogoutFailure {
    /// The failed check, for an invalid token.
    pub fn check(&self) -> Option<super::logout::LogoutTokenCheck> {
        match self {
            LogoutFailure::Invalid(check) => Some(*check),
            LogoutFailure::MetadataUnavailable(_) | LogoutFailure::ReplayUnavailable(_) => None,
        }
    }

    pub fn reason(&self) -> &'static str {
        match self {
            LogoutFailure::MetadataUnavailable(_) => "metadata_unavailable",
            LogoutFailure::Invalid(_) => "logout_token_invalid",
            LogoutFailure::ReplayUnavailable(_) => "replay_unavailable",
        }
    }

    pub fn detail(&self) -> String {
        match self {
            LogoutFailure::MetadataUnavailable(d) | LogoutFailure::ReplayUnavailable(d) => {
                d.clone()
            }
            LogoutFailure::Invalid(check) => {
                format!("the logout token failed the {} check", check.as_str())
            }
        }
    }
}

fn replay_handle(provider: &Provider, token: &super::logout::LogoutToken) -> String {
    format!("{}\0{}", provider.config.scheme, token.jti)
}

impl Federation {
    /// A logout token from `provider`'s back channel, checked as
    /// Back-Channel Logout 1.0 §2.6 requires, with the key set refetched
    /// as for id tokens, and its `jti` recorded so a replay is refused.
    pub async fn verify_logout_token(
        &self,
        provider: &Provider,
        token: &str,
        replay: &dyn crate::replay::ReplayCache,
        skew: i64,
        now: i64,
    ) -> Result<super::logout::LogoutToken, LogoutFailure> {
        use super::logout::{
            LOGOUT_TOKEN_REPLAY_PURPOSE, LOGOUT_TOKEN_REPLAY_SECONDS, LogoutExpectations,
            LogoutTokenCheck, validate_logout_token,
        };
        let invalid = LogoutFailure::Invalid;
        let metadata = self
            .metadata(provider, now)
            .await
            .map_err(|f| LogoutFailure::MetadataUnavailable(f.detail()))?;
        let algorithms = provider.config.id_token_algorithms(&metadata);
        let issuer = match &provider.config.multi_tenant {
            None => provider.config.authority.clone(),
            Some(multi) => tenant_issuer(multi, &metadata, token)
                .map_err(|_| invalid(LogoutTokenCheck::Issuer))?,
        };
        let expect = LogoutExpectations {
            issuer: &issuer,
            client_id: &provider.config.client_id,
            algorithms: &algorithms,
            now,
            skew,
        };
        let keys = match self.cached(provider).and_then(|e| e.keys) {
            Some(keys) => keys,
            None => self
                .fetch_keys(provider, &metadata)
                .await
                .map_err(|f| LogoutFailure::MetadataUnavailable(f.detail()))?,
        };
        let no_kid =
            crate::jwt::Jws::decode(token).is_some_and(|jws| jws.header_str("kid").is_none());
        let checked = match validate_logout_token(token, &keys, &expect) {
            Err(check @ (LogoutTokenCheck::UnknownKey | LogoutTokenCheck::Signature))
                if check == LogoutTokenCheck::UnknownKey || no_kid =>
            {
                if !self.may_refetch(provider, now) {
                    return Err(invalid(check));
                }
                let keys = self
                    .fetch_keys(provider, &metadata)
                    .await
                    .map_err(|f| LogoutFailure::MetadataUnavailable(f.detail()))?;
                validate_logout_token(token, &keys, &expect).map_err(invalid)?
            }
            other => other.map_err(invalid)?,
        };
        let expires = checked.iat.max(now) + LOGOUT_TOKEN_REPLAY_SECONDS + skew;
        match replay
            .add_if_absent(
                LOGOUT_TOKEN_REPLAY_PURPOSE,
                &replay_handle(provider, &checked),
                expires,
                now,
            )
            .await
        {
            Ok(true) => Ok(checked),
            Ok(false) => Err(invalid(LogoutTokenCheck::Replayed)),
            Err(e) => Err(LogoutFailure::ReplayUnavailable(e.to_string())),
        }
    }

    /// Forgets a verified logout token's `jti`, when the logout it asked
    /// for failed, so the provider's retry of the same token is accepted.
    pub async fn release_logout_token(
        &self,
        provider: &Provider,
        token: &super::logout::LogoutToken,
        replay: &dyn crate::replay::ReplayCache,
    ) -> Result<(), crate::stores::StoreError> {
        replay
            .remove(
                super::logout::LOGOUT_TOKEN_REPLAY_PURPOSE,
                &replay_handle(provider, token),
            )
            .await
    }
}
