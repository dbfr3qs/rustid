//! Caching decorators over the stores:
//! A found client is cached for `client_store_expiration`, a missing one is
//! not; CORS answers are cached either way for `cors_expiration`; resource
//! lookups for `resource_store_expiration`. Entries expire by time only, so
//! other instances see changes once their entries expire.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use moka::future::Cache;
use rustid_core::clients::Client;
use rustid_core::resources::{ApiResource, Resources};
use rustid_core::stores::{ClientStore, ResourceStore, StoreError};

/// Entries per cache; beyond this the least recently used are evicted.
const MAX_ENTRIES: u64 = 10_000;

/// `HybridCacheOptions.MaximumKeyLength`: longer keys go straight to the
/// store, so request input (an `Origin` header) can't pin large entries.
const MAX_KEY_LENGTH: usize = 1024;

/// `CachingOptions` durations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheDurations {
    pub client_store: Duration,
    pub resource_store: Duration,
    pub cors: Duration,
}

fn cache<V: Clone + Send + Sync + 'static>(ttl: Duration) -> Cache<String, V> {
    Cache::builder()
        .max_capacity(MAX_ENTRIES)
        .time_to_live(ttl)
        .build()
}

pub struct CachingClientStore<S> {
    inner: S,
    clients: Cache<String, Arc<Client>>,
    cors: Cache<String, bool>,
}

impl<S: ClientStore> CachingClientStore<S> {
    pub fn new(inner: S, durations: CacheDurations) -> Self {
        CachingClientStore {
            inner,
            clients: cache(durations.client_store),
            cors: cache(durations.cors),
        }
    }

    /// Forgets every cached answer (after an admin write on this instance).
    pub fn invalidate(&self) {
        self.clients.invalidate_all();
        self.cors.invalidate_all();
    }
}

#[async_trait]
impl<S: ClientStore> ClientStore for CachingClientStore<S> {
    async fn find_client_by_id(&self, client_id: &str) -> Result<Option<Arc<Client>>, StoreError> {
        if client_id.len() > MAX_KEY_LENGTH {
            return self.inner.find_client_by_id(client_id).await;
        }
        if let Some(client) = self.clients.get(client_id).await {
            return Ok(Some(client));
        }
        let found = self.inner.find_client_by_id(client_id).await?;
        if let Some(client) = &found {
            self.clients
                .insert(client_id.to_owned(), client.clone())
                .await;
        }
        Ok(found)
    }

    async fn is_cors_origin_allowed(&self, origin: &str) -> Result<bool, StoreError> {
        if origin.len() > MAX_KEY_LENGTH {
            return self.inner.is_cors_origin_allowed(origin).await;
        }
        if let Some(allowed) = self.cors.get(origin).await {
            return Ok(allowed);
        }
        let allowed = self.inner.is_cors_origin_allowed(origin).await?;
        self.cors.insert(origin.to_owned(), allowed).await;
        Ok(allowed)
    }
}

pub struct CachingResourceStore<S> {
    inner: S,
    enabled: Cache<String, Arc<Resources>>,
    api_resources: Cache<String, Arc<Vec<ApiResource>>>,
}

impl<S: ResourceStore> CachingResourceStore<S> {
    pub fn new(inner: S, durations: CacheDurations) -> Self {
        CachingResourceStore {
            inner,
            enabled: cache(durations.resource_store),
            api_resources: cache(durations.resource_store),
        }
    }

    /// Forgets every cached answer (after an admin write on this instance).
    pub fn invalidate(&self) {
        self.enabled.invalidate_all();
        self.api_resources.invalidate_all();
    }
}

#[async_trait]
impl<S: ResourceStore> ResourceStore for CachingResourceStore<S> {
    async fn get_all_enabled_resources(&self) -> Result<Arc<Resources>, StoreError> {
        const KEY: &str = "__all__";
        if let Some(resources) = self.enabled.get(KEY).await {
            return Ok(resources);
        }
        let resources = self.inner.get_all_enabled_resources().await?;
        self.enabled.insert(KEY.to_owned(), resources.clone()).await;
        Ok(resources)
    }

    async fn find_api_resources_by_name(
        &self,
        names: &[String],
    ) -> Result<Vec<ApiResource>, StoreError> {
        // Length-prefixed, so no two name lists share a key.
        let key: String = names.iter().map(|n| format!("{}:{n}", n.len())).collect();
        if key.len() > MAX_KEY_LENGTH {
            return self.inner.find_api_resources_by_name(names).await;
        }
        if let Some(found) = self.api_resources.get(&key).await {
            return Ok(found.as_ref().clone());
        }
        let found = Arc::new(self.inner.find_api_resources_by_name(names).await?);
        self.api_resources.insert(key, found.clone()).await;
        Ok(found.as_ref().clone())
    }

    /// Not cached: the caching store caches the engine's lookups only.
    async fn get_all_resources(&self) -> Result<Arc<Resources>, StoreError> {
        self.inner.get_all_resources().await
    }
}
