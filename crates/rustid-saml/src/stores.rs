//! The SAML stores: service providers, sign-in
//! state and logout sessions. Methods that judge expiry take `now`.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rustid_core::admin::EntityId;
use rustid_core::stores::StoreError;

use crate::model::ServiceProvider;
use crate::state::{AuthenticationState, LogoutSession};

pub const MISSING_SIGNIN_EXPIRY: &str =
    "ExpiresAtUtc must be set before storing SAML signin state.";
pub const MISSING_LOGOUT_EXPIRY: &str =
    "ExpiresAtUtc must be set before storing SAML logout session.";

#[async_trait]
pub trait ServiceProviderStore: Send + Sync {
    /// The enabled provider with exactly this entity id.
    async fn find_by_entity_id(
        &self,
        entity_id: &str,
    ) -> Result<Option<Arc<ServiceProvider>>, StoreError>;
    /// Every provider, enabled or not.
    async fn get_all(&self) -> Result<Vec<Arc<ServiceProvider>>, StoreError>;
}

#[async_trait]
impl<S: ServiceProviderStore + ?Sized> ServiceProviderStore for Arc<S> {
    async fn find_by_entity_id(
        &self,
        entity_id: &str,
    ) -> Result<Option<Arc<ServiceProvider>>, StoreError> {
        (**self).find_by_entity_id(entity_id).await
    }

    async fn get_all(&self) -> Result<Vec<Arc<ServiceProvider>>, StoreError> {
        (**self).get_all().await
    }
}

#[async_trait]
pub trait SigninStateStore: Send + Sync {
    /// Stores the state under a new UUIDv7 id; the state must have an
    /// expiry.
    async fn store(&self, state: AuthenticationState) -> Result<EntityId, StoreError>;
    /// The state, unless unknown, not a v7 id, or expired (`now >
    /// expires`), which also removes it.
    async fn retrieve(
        &self,
        id: &EntityId,
        now: DateTime<Utc>,
    ) -> Result<Option<AuthenticationState>, StoreError>;
    /// Replaces a live state, keeping its stored expiry; unknown, non-v7
    /// and expired ids are ignored.
    async fn update(
        &self,
        id: &EntityId,
        state: AuthenticationState,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError>;
    /// Idempotent.
    async fn remove(&self, id: &EntityId) -> Result<(), StoreError>;
    /// The storage purge: up to `batch` states that expired before `now`;
    /// how many.
    async fn remove_expired(&self, now: DateTime<Utc>, batch: usize) -> Result<u64, StoreError>;
}

#[async_trait]
pub trait LogoutSessionStore: Send + Sync {
    /// The session must have an expiry, and a new logout id.
    async fn store(&self, session: LogoutSession) -> Result<(), StoreError>;
    /// The session, unless unknown or expired (`expires <= now`).
    async fn get(
        &self,
        logout_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<LogoutSession>, StoreError>;
    /// Records an SP's response to the LogoutRequest `request_id`: false
    /// when the request is unknown, its session expired, or `issuer` isn't
    /// the SP it was sent to.
    async fn try_record_response(
        &self,
        request_id: &str,
        issuer: &str,
        success: bool,
        now: DateTime<Utc>,
    ) -> Result<bool, StoreError>;
    /// Idempotent; its request ids stop resolving.
    async fn remove(&self, logout_id: &str) -> Result<(), StoreError>;
    /// The storage purge: up to `batch` sessions expired at `now`; how many.
    async fn remove_expired(&self, now: DateTime<Utc>, batch: usize) -> Result<u64, StoreError>;
}

/// Whether an id is a UUIDv7, as the storage stores require.
pub fn is_v7(id: &EntityId) -> bool {
    id.0[6] >> 4 == 7
}

/// Providers that fail the
/// configuration validator are logged and treated as absent.
pub struct ValidatingServiceProviderStore<S> {
    inner: S,
}

impl<S> ValidatingServiceProviderStore<S> {
    pub fn new(inner: S) -> Self {
        ValidatingServiceProviderStore { inner }
    }
}

fn valid(sp: &ServiceProvider) -> bool {
    match crate::validation::validate_service_provider(sp) {
        Ok(()) => true,
        Err(message) => {
            tracing::error!(entity_id = %sp.entity_id, %message, "invalid SAML service provider configuration");
            false
        }
    }
}

#[async_trait]
impl<S: ServiceProviderStore> ServiceProviderStore for ValidatingServiceProviderStore<S> {
    async fn find_by_entity_id(
        &self,
        entity_id: &str,
    ) -> Result<Option<Arc<ServiceProvider>>, StoreError> {
        Ok(self
            .inner
            .find_by_entity_id(entity_id)
            .await?
            .filter(|sp| valid(sp)))
    }

    async fn get_all(&self) -> Result<Vec<Arc<ServiceProvider>>, StoreError> {
        Ok(self
            .inner
            .get_all()
            .await?
            .into_iter()
            .filter(|sp| valid(sp))
            .collect())
    }
}

/// The SAML stores a server uses.
#[derive(Clone)]
pub struct SamlStores {
    pub service_providers: Arc<dyn ServiceProviderStore>,
    pub signin_states: Arc<dyn SigninStateStore>,
    pub logout_sessions: Arc<dyn LogoutSessionStore>,
}

/// One purge run over the SAML stores (alongside `rustid_core::purge`):
/// expired sign-in states and logout sessions, in batches.
pub async fn purge(
    stores: &SamlStores,
    now: DateTime<Utc>,
    batch: usize,
) -> Result<u64, StoreError> {
    let batch = batch.clamp(1, rustid_core::purge::MAX_BATCH);
    let mut total = 0;
    loop {
        let removed = stores.signin_states.remove_expired(now, batch).await?;
        total += removed;
        if removed < batch as u64 {
            break;
        }
    }
    loop {
        let removed = stores.logout_sessions.remove_expired(now, batch).await?;
        total += removed;
        if removed < batch as u64 {
            break;
        }
    }
    Ok(total)
}
