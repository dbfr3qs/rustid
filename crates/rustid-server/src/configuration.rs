//! Admin writes and the caching stores: a configuration store that forgets
//! this instance's cached clients and resources after each write, so the
//! change takes effect at once here. Other instances see it when their
//! entries expire (`caching.*_expiration`).

use std::sync::Arc;

use async_trait::async_trait;
use rustid_core::admin::EntityId;
use rustid_core::stores::{
    ClientStore, ConfigurationStore, CreateOutcome, EntityKind, ResourceStore, StoreError,
    StoredEntity, UpdateOutcome,
};
use rustid_store_memory::{CachingClientStore, CachingResourceStore};

pub struct InvalidatingConfiguration<S, C, R> {
    pub inner: S,
    pub clients: Arc<CachingClientStore<C>>,
    pub resources: Arc<CachingResourceStore<R>>,
}

impl<S, C: ClientStore, R: ResourceStore> InvalidatingConfiguration<S, C, R> {
    fn changed(&self) {
        self.clients.invalidate();
        self.resources.invalidate();
    }
}

#[async_trait]
impl<S, C, R> ConfigurationStore for InvalidatingConfiguration<S, C, R>
where
    S: ConfigurationStore,
    C: ClientStore,
    R: ResourceStore,
{
    async fn create(
        &self,
        kind: EntityKind,
        entity: &StoredEntity,
    ) -> Result<CreateOutcome, StoreError> {
        let outcome = self.inner.create(kind, entity).await?;
        if outcome == CreateOutcome::Created {
            self.changed();
        }
        Ok(outcome)
    }

    async fn read(
        &self,
        kind: EntityKind,
        id: &EntityId,
    ) -> Result<Option<StoredEntity>, StoreError> {
        self.inner.read(kind, id).await
    }

    async fn read_by_key(
        &self,
        kind: EntityKind,
        key: &str,
    ) -> Result<Option<StoredEntity>, StoreError> {
        self.inner.read_by_key(kind, key).await
    }

    async fn update(
        &self,
        kind: EntityKind,
        entity: &StoredEntity,
    ) -> Result<UpdateOutcome, StoreError> {
        let outcome = self.inner.update(kind, entity).await?;
        if outcome == UpdateOutcome::Updated {
            self.changed();
        }
        Ok(outcome)
    }

    async fn delete(&self, kind: EntityKind, id: &EntityId) -> Result<(), StoreError> {
        self.inner.delete(kind, id).await?;
        self.changed();
        Ok(())
    }

    async fn list(&self, kind: EntityKind) -> Result<Vec<StoredEntity>, StoreError> {
        self.inner.list(kind).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustid_core::resources::Resources;
    use rustid_store_memory::{CacheDurations, InMemoryConfiguration};
    use std::time::Duration;

    /// A cached resource set is refreshed after a write.
    #[tokio::test]
    async fn writes_clear_this_instances_caches() {
        let inner = Arc::new(InMemoryConfiguration::new(
            &Default::default(),
            &Resources::default(),
        ));
        let durations = CacheDurations {
            client_store: Duration::from_secs(3600),
            resource_store: Duration::from_secs(3600),
            cors: Duration::from_secs(3600),
        };
        let resources = Arc::new(CachingResourceStore::new(inner.clone(), durations));
        let clients = Arc::new(CachingClientStore::new(
            rustid_store_memory::InMemoryClientStore::default(),
            durations,
        ));
        let store = InvalidatingConfiguration {
            inner: inner.clone(),
            clients,
            resources: resources.clone(),
        };
        assert!(
            resources
                .get_all_enabled_resources()
                .await
                .unwrap()
                .api_scopes
                .is_empty()
        );
        store
            .create(
                EntityKind::ApiScope,
                &StoredEntity {
                    id: EntityId::new_v7(),
                    key: "fresh".into(),
                    version: 1,
                    data: serde_json::json!({ "name": "fresh" }),
                },
            )
            .await
            .unwrap();
        assert_eq!(
            resources
                .get_all_enabled_resources()
                .await
                .unwrap()
                .api_scopes[0]
                .name,
            "fresh"
        );
    }
}
