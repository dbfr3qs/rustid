#![forbid(unsafe_code)]

//! In-memory implementations of the store traits, for tests, development and
//! static-config deployments; the file system signing key store; and the
//! caching decorators that front slower stores (`CachingClientStore`,
//! `CachingResourceStore` and a caching CORS policy service).

mod caching;
mod configuration;
pub mod saml;
mod signing_keys;

use rustid_core::server_side_sessions::{
    QueryResult, ServerSideSession, SessionFilter, SessionQuery, SortedSessions, query_page,
};
use rustid_core::stores::ServerSideSessionStore;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use async_trait::async_trait;
use rustid_core::clients::{Client, Clients};
use rustid_core::grants::{GrantFilter, PersistedGrant};
use rustid_core::resources::{ApiResource, Resources};
use rustid_core::stores::{ClientStore, PersistedGrantStore, ResourceStore, StoreError, Stores};

pub use caching::{CacheDurations, CachingClientStore, CachingResourceStore};
pub use configuration::InMemoryConfiguration;
pub use signing_keys::{FileSystemSigningKeyStore, InMemorySigningKeyStore};

/// `InMemoryClientStore` and the in memory CORS policy service over a fixed list.
#[derive(Debug, Default)]
pub struct InMemoryClientStore {
    clients: Clients,
    by_id: HashMap<String, Arc<Client>>,
}

impl InMemoryClientStore {
    pub fn new(clients: Clients) -> Self {
        let mut by_id = HashMap::new();
        for client in &clients.clients {
            // The first client with an id wins, as a linear search finds it.
            by_id
                .entry(client.client_id.clone())
                .or_insert_with(|| Arc::new(client.clone()));
        }
        InMemoryClientStore { clients, by_id }
    }
}

#[async_trait]
impl ClientStore for InMemoryClientStore {
    async fn find_client_by_id(&self, client_id: &str) -> Result<Option<Arc<Client>>, StoreError> {
        Ok(self.by_id.get(client_id).cloned())
    }

    async fn is_cors_origin_allowed(&self, origin: &str) -> Result<bool, StoreError> {
        Ok(self.clients.is_cors_origin_allowed(origin))
    }
}

/// The in memory resources store over fixed lists.
#[derive(Debug, Default)]
pub struct InMemoryResourceStore {
    all: Resources,
    enabled: Arc<Resources>,
}

impl InMemoryResourceStore {
    pub fn new(resources: Resources) -> Self {
        let enabled = Arc::new(resources.enabled());
        InMemoryResourceStore {
            all: resources,
            enabled,
        }
    }
}

#[async_trait]
impl ResourceStore for InMemoryResourceStore {
    async fn get_all_enabled_resources(&self) -> Result<Arc<Resources>, StoreError> {
        Ok(self.enabled.clone())
    }

    async fn find_api_resources_by_name(
        &self,
        names: &[String],
    ) -> Result<Vec<ApiResource>, StoreError> {
        Ok(self
            .all
            .api_resources
            .iter()
            .filter(|api| names.contains(&api.name))
            .cloned()
            .collect())
    }

    async fn get_all_resources(&self) -> Result<Arc<Resources>, StoreError> {
        Ok(Arc::new(self.all.clone()))
    }
}

/// `InMemoryPersistedGrantStore`.
#[derive(Debug, Default)]
pub struct InMemoryPersistedGrantStore {
    grants: Mutex<HashMap<String, PersistedGrant>>,
}

impl InMemoryPersistedGrantStore {
    fn lock(&self) -> MutexGuard<'_, HashMap<String, PersistedGrant>> {
        self.grants
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[async_trait]
impl PersistedGrantStore for InMemoryPersistedGrantStore {
    async fn store(&self, grant: PersistedGrant) -> Result<(), StoreError> {
        self.lock().insert(grant.key.clone(), grant);
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<PersistedGrant>, StoreError> {
        Ok(self.lock().get(key).cloned())
    }

    async fn get_all(&self, filter: &GrantFilter) -> Result<Vec<PersistedGrant>, StoreError> {
        if filter.is_empty() {
            return Err(StoreError::EmptyFilter);
        }
        Ok(self
            .lock()
            .values()
            .filter(|g| filter.matches(g))
            .cloned()
            .collect())
    }

    async fn remove(&self, key: &str) -> Result<(), StoreError> {
        self.lock().remove(key);
        Ok(())
    }

    async fn take(&self, key: &str) -> Result<Option<PersistedGrant>, StoreError> {
        Ok(self.lock().remove(key))
    }

    async fn remove_all(&self, filter: &GrantFilter) -> Result<(), StoreError> {
        if filter.is_empty() {
            return Err(StoreError::EmptyFilter);
        }
        self.lock().retain(|_, g| !filter.matches(g));
        Ok(())
    }

    async fn remove_expired(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        batch: usize,
        consumed_before: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<u64, StoreError> {
        let mut grants = self.lock();
        let purge: Vec<String> = grants
            .values()
            .filter(|g| {
                g.expiration.is_some_and(|e| e < now)
                    || consumed_before
                        .is_some_and(|cutoff| g.consumed_time.is_some_and(|c| c < cutoff))
            })
            .map(|g| g.key.clone())
            .take(batch)
            .collect();
        for key in &purge {
            grants.remove(key);
        }
        Ok(purge.len() as u64)
    }
}

/// In-memory stores for the given clients and resources, with an empty
/// grant store.
pub fn stores(clients: Clients, resources: Resources) -> Stores {
    stores_with(Arc::new(InMemoryConfiguration::new(&clients, &resources)))
}

/// In-memory stores over this configuration, with an empty grant store.
/// Admin and the runtime client and resource lookups share it.
pub fn stores_with(configuration: Arc<InMemoryConfiguration>) -> Stores {
    Stores {
        clients: configuration.clone(),
        resources: configuration.clone(),
        configuration,
        grants: Arc::new(InMemoryPersistedGrantStore::default()),
        device_flow: Arc::new(InMemoryDeviceFlowStore::default()),
        device_throttling: Arc::new(rustid_core::stores::InMemoryDeviceFlowThrottling::default()),
        replay: Arc::new(rustid_core::replay::InMemoryReplayCache::default()),
        profile: Arc::new(rustid_core::profile::DefaultProfileService),
        token_request: Arc::new(rustid_core::token_request::DefaultTokenRequestValidator),
        request_uri: Arc::new(rustid_core::request_uri::NoRequestUriFetcher),
        back_channel: Arc::new(rustid_core::logout::NoBackChannelSender),
        grant_validation: Arc::new(rustid_core::grant_validation::NoGrantValidator),
        ciba: Arc::new(rustid_core::ciba::NopCibaService),
        sessions: None,
        federation: Default::default(),
    }
}

/// One device authorization.
#[derive(Debug)]
struct DeviceRow {
    device_code: String,
    user_code: String,
    data: String,
    expiration: chrono::DateTime<chrono::Utc>,
}

/// `InMemoryDeviceFlowStore`.
#[derive(Debug, Default)]
pub struct InMemoryDeviceFlowStore {
    rows: Mutex<Vec<DeviceRow>>,
}

impl InMemoryDeviceFlowStore {
    fn lock(&self) -> MutexGuard<'_, Vec<DeviceRow>> {
        self.rows
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[async_trait]
impl rustid_core::stores::DeviceFlowStore for InMemoryDeviceFlowStore {
    async fn store_device_authorization(
        &self,
        device_code: &str,
        user_code: &str,
        _client_id: &str,
        _creation_time: chrono::DateTime<chrono::Utc>,
        expiration: chrono::DateTime<chrono::Utc>,
        data: &str,
    ) -> Result<(), StoreError> {
        let mut rows = self.lock();
        if rows
            .iter()
            .any(|r| r.device_code == device_code || r.user_code == user_code)
        {
            return Err(StoreError::DuplicateDeviceCode);
        }
        rows.push(DeviceRow {
            device_code: device_code.to_owned(),
            user_code: user_code.to_owned(),
            data: data.to_owned(),
            expiration,
        });
        Ok(())
    }

    async fn find_by_user_code(&self, user_code: &str) -> Result<Option<String>, StoreError> {
        Ok(self
            .lock()
            .iter()
            .find(|r| r.user_code == user_code)
            .map(|r| r.data.clone()))
    }

    async fn find_by_device_code(&self, device_code: &str) -> Result<Option<String>, StoreError> {
        Ok(self
            .lock()
            .iter()
            .find(|r| r.device_code == device_code)
            .map(|r| r.data.clone()))
    }

    async fn update_by_user_code(
        &self,
        user_code: &str,
        _subject_id: Option<&str>,
        data: &str,
    ) -> Result<(), StoreError> {
        let mut rows = self.lock();
        let row = rows
            .iter_mut()
            .find(|r| r.user_code == user_code)
            .ok_or(StoreError::UnknownUserCode)?;
        row.data = data.to_owned();
        Ok(())
    }

    async fn remove_by_device_code(&self, device_code: &str) -> Result<bool, StoreError> {
        let mut rows = self.lock();
        let before = rows.len();
        rows.retain(|r| r.device_code != device_code);
        Ok(rows.len() != before)
    }

    async fn remove_expired(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        batch: usize,
    ) -> Result<u64, StoreError> {
        let mut rows = self.lock();
        let mut removed = 0;
        rows.retain(|r| {
            let purge = r.expiration < now && removed < batch;
            if purge {
                removed += 1;
            }
            !purge
        });
        Ok(removed as u64)
    }
}

/// `InMemoryServerSideSessionStore`, with the outbox it moves expired
/// sessions into.
#[derive(Debug, Default)]
pub struct InMemoryServerSideSessionStore {
    sessions: Mutex<std::collections::BTreeMap<String, ServerSideSession>>,
    outbox: Arc<rustid_core::outbox::InMemoryOutbox>,
}

impl InMemoryServerSideSessionStore {
    /// The outbox expired sessions move into.
    pub fn outbox(&self) -> Arc<rustid_core::outbox::InMemoryOutbox> {
        self.outbox.clone()
    }

    fn lock(&self) -> MutexGuard<'_, std::collections::BTreeMap<String, ServerSideSession>> {
        self.sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[async_trait]
impl ServerSideSessionStore for InMemoryServerSideSessionStore {
    async fn create_session(&self, session: ServerSideSession) -> Result<(), StoreError> {
        let mut sessions = self.lock();
        if sessions.contains_key(&session.key) {
            return Err(StoreError::DuplicateSession(session.key));
        }
        sessions.insert(session.key.clone(), session);
        Ok(())
    }

    async fn get_session(&self, key: &str) -> Result<Option<ServerSideSession>, StoreError> {
        Ok(self.lock().get(key).cloned())
    }

    async fn update_session(&self, session: ServerSideSession) -> Result<(), StoreError> {
        self.lock().insert(session.key.clone(), session);
        Ok(())
    }

    async fn delete_session(&self, key: &str) -> Result<(), StoreError> {
        self.lock().remove(key);
        Ok(())
    }

    async fn get_sessions(
        &self,
        filter: &SessionFilter,
    ) -> Result<Vec<ServerSideSession>, StoreError> {
        if filter.is_empty() {
            return Err(StoreError::EmptyFilter);
        }
        Ok(self
            .lock()
            .values()
            .filter(|s| filter.matches(s))
            .cloned()
            .collect())
    }

    async fn delete_sessions(&self, filter: &SessionFilter) -> Result<(), StoreError> {
        if filter.is_empty() {
            return Err(StoreError::EmptyFilter);
        }
        self.lock().retain(|_, s| !filter.matches(s));
        Ok(())
    }

    async fn move_expired_to_outbox(
        &self,
        count: usize,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<usize, StoreError> {
        let mut sessions = self.lock();
        let expired: Vec<String> = sessions
            .values()
            .filter(|s| s.expires.is_some_and(|e| e < now))
            .take(count)
            .map(|s| s.key.clone())
            .collect();
        for key in &expired {
            if let Some(session) = sessions.remove(key) {
                let payload = serde_json::to_string(&session)
                    .map_err(|e| StoreError::Backend(e.to_string()))?;
                self.outbox
                    .push(rustid_core::outbox::SESSION_EXPIRED, &payload, now);
            }
        }
        Ok(expired.len())
    }

    async fn query_sessions(
        &self,
        query: &SessionQuery,
    ) -> Result<QueryResult<ServerSideSession>, StoreError> {
        let matching: Vec<ServerSideSession> = self
            .lock()
            .values()
            .filter(|s| query.matches(s))
            .cloned()
            .collect();
        query_page(&SortedSessions(matching), query).await
    }
}
