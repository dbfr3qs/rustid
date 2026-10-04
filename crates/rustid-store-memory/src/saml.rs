//! In-memory SAML stores (the in memory SAML service provider store,
//! the in memory SAML signin state store, the in memory SAML logout session store).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rustid_core::admin::EntityId;
use rustid_core::stores::StoreError;
use rustid_saml::model::ServiceProvider;
use rustid_saml::state::{AuthenticationState, LogoutSession, SpLogoutResponse};
use rustid_saml::stores::{
    LogoutSessionStore, MISSING_LOGOUT_EXPIRY, MISSING_SIGNIN_EXPIRY, ServiceProviderStore,
    SigninStateStore, is_v7,
};

/// Service providers from configuration.
#[derive(Debug, Default)]
pub struct InMemoryServiceProviderStore {
    providers: Vec<Arc<ServiceProvider>>,
}

impl InMemoryServiceProviderStore {
    /// Panics on duplicate entity ids
    /// (`parse_service_providers` reports them as an error first).
    pub fn new(providers: Vec<ServiceProvider>) -> Self {
        let mut seen = std::collections::HashSet::new();
        for sp in &providers {
            assert!(
                seen.insert(sp.entity_id.as_str()),
                "duplicate SAML service provider entity id: {}",
                sp.entity_id
            );
        }
        InMemoryServiceProviderStore {
            providers: providers.into_iter().map(Arc::new).collect(),
        }
    }
}

#[async_trait]
impl ServiceProviderStore for InMemoryServiceProviderStore {
    async fn find_by_entity_id(
        &self,
        entity_id: &str,
    ) -> Result<Option<Arc<ServiceProvider>>, StoreError> {
        Ok(self
            .providers
            .iter()
            .find(|sp| sp.entity_id == entity_id && sp.enabled)
            .cloned())
    }

    async fn get_all(&self) -> Result<Vec<Arc<ServiceProvider>>, StoreError> {
        Ok(self.providers.clone())
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[derive(Debug, Default)]
pub struct InMemorySigninStateStore {
    states: Mutex<HashMap<EntityId, AuthenticationState>>,
}

fn expired(state: &AuthenticationState, now: DateTime<Utc>) -> bool {
    state.expires_at_utc.is_none_or(|e| now > e)
}

#[async_trait]
impl SigninStateStore for InMemorySigninStateStore {
    async fn store(&self, state: AuthenticationState) -> Result<EntityId, StoreError> {
        if state.expires_at_utc.is_none() {
            return Err(StoreError::MissingExpiration(MISSING_SIGNIN_EXPIRY));
        }
        let id = EntityId::new_v7();
        lock(&self.states).insert(id, state);
        Ok(id)
    }

    async fn retrieve(
        &self,
        id: &EntityId,
        now: DateTime<Utc>,
    ) -> Result<Option<AuthenticationState>, StoreError> {
        if !is_v7(id) {
            return Ok(None);
        }
        let mut states = lock(&self.states);
        match states.get(id) {
            Some(state) if expired(state, now) => {
                states.remove(id);
                Ok(None)
            }
            found => Ok(found.cloned()),
        }
    }

    async fn update(
        &self,
        id: &EntityId,
        state: AuthenticationState,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        if !is_v7(id) {
            return Ok(());
        }
        let mut states = lock(&self.states);
        match states.get(id) {
            None => tracing::warn!(%id, "SAML signin state not found for update"),
            Some(existing) if expired(existing, now) => {
                states.remove(id);
                tracing::warn!(%id, "SAML signin state expired, cannot update");
            }
            Some(existing) => {
                // The stored expiry stands.
                let state = AuthenticationState {
                    expires_at_utc: existing.expires_at_utc,
                    ..state
                };
                states.insert(*id, state);
            }
        }
        Ok(())
    }

    async fn remove(&self, id: &EntityId) -> Result<(), StoreError> {
        lock(&self.states).remove(id);
        Ok(())
    }

    async fn remove_expired(&self, now: DateTime<Utc>, batch: usize) -> Result<u64, StoreError> {
        let mut states = lock(&self.states);
        let expired_ids: Vec<EntityId> = states
            .iter()
            .filter(|(_, s)| expired(s, now))
            .map(|(id, _)| *id)
            .take(batch)
            .collect();
        for id in &expired_ids {
            states.remove(id);
        }
        Ok(expired_ids.len() as u64)
    }
}

#[derive(Debug, Default)]
struct Sessions {
    by_logout_id: HashMap<String, LogoutSession>,
    /// Request id to logout id.
    requests: HashMap<String, String>,
}

impl Sessions {
    fn remove(&mut self, logout_id: &str) {
        if let Some(session) = self.by_logout_id.remove(logout_id) {
            for request in session.expected_responses.keys() {
                self.requests.remove(request);
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct InMemoryLogoutSessionStore {
    sessions: Mutex<Sessions>,
}

/// The storage store's rule: gone at the expiry instant.
fn session_expired(session: &LogoutSession, now: DateTime<Utc>) -> bool {
    session.expires_at_utc.is_none_or(|e| e <= now)
}

#[async_trait]
impl LogoutSessionStore for InMemoryLogoutSessionStore {
    async fn store(&self, session: LogoutSession) -> Result<(), StoreError> {
        if session.expires_at_utc.is_none() {
            return Err(StoreError::MissingExpiration(MISSING_LOGOUT_EXPIRY));
        }
        let mut sessions = lock(&self.sessions);
        if sessions.by_logout_id.contains_key(&session.logout_id) {
            return Err(StoreError::DuplicateLogoutId(session.logout_id));
        }
        for request in session.expected_responses.keys() {
            sessions
                .requests
                .insert(request.clone(), session.logout_id.clone());
        }
        sessions
            .by_logout_id
            .insert(session.logout_id.clone(), session);
        Ok(())
    }

    async fn get(
        &self,
        logout_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<LogoutSession>, StoreError> {
        let mut sessions = lock(&self.sessions);
        match sessions.by_logout_id.get(logout_id) {
            Some(session) if session_expired(session, now) => {
                sessions.remove(logout_id);
                Ok(None)
            }
            found => Ok(found.cloned()),
        }
    }

    async fn try_record_response(
        &self,
        request_id: &str,
        issuer: &str,
        success: bool,
        now: DateTime<Utc>,
    ) -> Result<bool, StoreError> {
        let mut sessions = lock(&self.sessions);
        let Some(logout_id) = sessions.requests.get(request_id).cloned() else {
            return Ok(false);
        };
        let Some(session) = sessions.by_logout_id.get_mut(&logout_id) else {
            return Ok(false);
        };
        if session_expired(session, now) {
            sessions.remove(&logout_id);
            return Ok(false);
        }
        let Some(expected) = session.expected_responses.get_mut(request_id) else {
            return Ok(false);
        };
        if expected.sp_entity_id != issuer {
            tracing::warn!(request_id, expected = %expected.sp_entity_id, received = issuer, "SAML logout response issuer mismatch");
            return Ok(false);
        }
        expected.response = Some(SpLogoutResponse {
            success,
            received_utc: now,
        });
        Ok(true)
    }

    async fn remove(&self, logout_id: &str) -> Result<(), StoreError> {
        lock(&self.sessions).remove(logout_id);
        Ok(())
    }

    async fn remove_expired(&self, now: DateTime<Utc>, batch: usize) -> Result<u64, StoreError> {
        let mut sessions = lock(&self.sessions);
        let expired_ids: Vec<String> = sessions
            .by_logout_id
            .values()
            .filter(|s| session_expired(s, now))
            .map(|s| s.logout_id.clone())
            .take(batch)
            .collect();
        for id in &expired_ids {
            sessions.remove(id);
        }
        Ok(expired_ids.len() as u64)
    }
}
