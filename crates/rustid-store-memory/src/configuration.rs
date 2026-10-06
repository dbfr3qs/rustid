//! `InMemoryConfiguration`: the configuration entities admin edits, held in
//! process, and the runtime `ClientStore`, `ResourceStore` and SAML
//! `ServiceProviderStore` built from the same entities, so an admin write
//! takes effect at once.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use rustid_core::admin::EntityId;
use rustid_core::clients::{Client, Clients};
use rustid_core::resources::{ApiResource, Resources};
use rustid_core::stores::{
    ClientStore, ConfigurationStore, CreateOutcome, EntityKind, ResourceStore, StoreError,
    StoredEntity, UpdateOutcome,
};
use rustid_saml::model::ServiceProvider;
use rustid_saml::stores::ServiceProviderStore;
use serde::de::DeserializeOwned;

#[derive(Debug, Default)]
struct State {
    /// Per kind, in configuration order.
    entities: HashMap<EntityKind, Vec<StoredEntity>>,
    /// The resources built from the entities: all, and the enabled ones.
    resources: Option<(Arc<Resources>, Arc<Resources>)>,
    /// The client store built from the client entities.
    clients: Option<Arc<crate::InMemoryClientStore>>,
    /// The SAML service provider store built from its entities.
    service_providers: Option<Arc<crate::saml::InMemoryServiceProviderStore>>,
}

impl State {
    fn changed(&mut self) {
        self.resources = None;
        self.clients = None;
        self.service_providers = None;
    }
}

#[derive(Debug, Default)]
pub struct InMemoryConfiguration {
    state: RwLock<State>,
}

fn entities<T: serde::Serialize>(items: &[T], key: impl Fn(&T) -> String) -> Vec<StoredEntity> {
    items
        .iter()
        .map(|item| StoredEntity {
            id: EntityId::new_v7(),
            key: key(item),
            version: 1,
            data: serde_json::to_value(item).expect("configuration serialises"),
        })
        .collect()
}

fn parse<T: DeserializeOwned>(entities: Option<&Vec<StoredEntity>>) -> Result<Vec<T>, StoreError> {
    entities
        .into_iter()
        .flatten()
        .map(|e| {
            serde_json::from_value(e.data.clone())
                .map_err(|err| StoreError::Backend(format!("stored {}: {err}", e.key)))
        })
        .collect()
}

/// As [`parse`], leaving out (with a warning) entities that won't decode:
/// one broken client must not stop every other client signing in.
fn parse_each<T: DeserializeOwned>(entities: Option<&Vec<StoredEntity>>) -> Vec<T> {
    entities
        .into_iter()
        .flatten()
        .filter_map(|e| match serde_json::from_value(e.data.clone()) {
            Ok(item) => Some(item),
            Err(error) => {
                tracing::warn!(key = %e.key, %error, "a stored entity can't be read; it's left out");
                None
            }
        })
        .collect()
}

impl InMemoryConfiguration {
    /// The clients and resources, each with a fresh id at version 1.
    pub fn new(clients: &Clients, resources: &Resources) -> Self {
        let mut state = State::default();
        state.entities.insert(
            EntityKind::Client,
            entities(&clients.clients, |c| c.client_id.clone()),
        );
        state.entities.insert(
            EntityKind::IdentityResource,
            entities(&resources.identity_resources, |r| r.name.clone()),
        );
        state.entities.insert(
            EntityKind::ApiScope,
            entities(&resources.api_scopes, |r| r.name.clone()),
        );
        state.entities.insert(
            EntityKind::ApiResource,
            entities(&resources.api_resources, |r| r.name.clone()),
        );
        InMemoryConfiguration {
            state: RwLock::new(state),
        }
    }

    /// With these SAML service providers, each with a fresh id at version 1.
    pub fn with_saml_service_providers(self, providers: &[ServiceProvider]) -> Self {
        {
            let mut state = self.write_state();
            state.entities.insert(
                EntityKind::SamlServiceProvider,
                entities(providers, |sp| sp.entity_id.clone()),
            );
            state.changed();
        }
        self
    }

    fn read_state(&self) -> std::sync::RwLockReadGuard<'_, State> {
        self.state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn write_state(&self) -> std::sync::RwLockWriteGuard<'_, State> {
        self.state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// All resources and the enabled ones, built once per change.
    fn resources(&self) -> Result<(Arc<Resources>, Arc<Resources>), StoreError> {
        if let Some(built) = &self.read_state().resources {
            return Ok(built.clone());
        }
        let mut state = self.write_state();
        if let Some(built) = &state.resources {
            return Ok(built.clone());
        }
        let all = Resources {
            identity_resources: parse(state.entities.get(&EntityKind::IdentityResource))?,
            api_scopes: parse(state.entities.get(&EntityKind::ApiScope))?,
            api_resources: parse(state.entities.get(&EntityKind::ApiResource))?,
        };
        let built = (Arc::new(all.clone()), Arc::new(all.enabled()));
        state.resources = Some(built.clone());
        Ok(built)
    }

    /// The client store, built once per change.
    fn clients(&self) -> Result<Arc<crate::InMemoryClientStore>, StoreError> {
        if let Some(built) = &self.read_state().clients {
            return Ok(built.clone());
        }
        let mut state = self.write_state();
        if let Some(built) = &state.clients {
            return Ok(built.clone());
        }
        let built = Arc::new(crate::InMemoryClientStore::new(Clients {
            clients: parse_each(state.entities.get(&EntityKind::Client)),
        }));
        state.clients = Some(built.clone());
        Ok(built)
    }

    /// The SAML service provider store, built once per change.
    fn service_providers(
        &self,
    ) -> Result<Arc<crate::saml::InMemoryServiceProviderStore>, StoreError> {
        if let Some(built) = &self.read_state().service_providers {
            return Ok(built.clone());
        }
        let mut state = self.write_state();
        if let Some(built) = &state.service_providers {
            return Ok(built.clone());
        }
        let built = Arc::new(crate::saml::InMemoryServiceProviderStore::new(parse(
            state.entities.get(&EntityKind::SamlServiceProvider),
        )?));
        state.service_providers = Some(built.clone());
        Ok(built)
    }
}

#[async_trait]
impl ConfigurationStore for InMemoryConfiguration {
    async fn create(
        &self,
        kind: EntityKind,
        entity: &StoredEntity,
    ) -> Result<CreateOutcome, StoreError> {
        let mut state = self.write_state();
        let list = state.entities.entry(kind).or_default();
        if list.iter().any(|e| e.key == entity.key) {
            return Ok(CreateOutcome::KeyExists);
        }
        list.push(StoredEntity {
            version: 1,
            ..entity.clone()
        });
        state.changed();
        Ok(CreateOutcome::Created)
    }

    async fn read(
        &self,
        kind: EntityKind,
        id: &EntityId,
    ) -> Result<Option<StoredEntity>, StoreError> {
        Ok(self
            .read_state()
            .entities
            .get(&kind)
            .and_then(|list| list.iter().find(|e| e.id == *id))
            .cloned())
    }

    async fn read_by_key(
        &self,
        kind: EntityKind,
        key: &str,
    ) -> Result<Option<StoredEntity>, StoreError> {
        Ok(self
            .read_state()
            .entities
            .get(&kind)
            .and_then(|list| list.iter().find(|e| e.key == key))
            .cloned())
    }

    async fn update(
        &self,
        kind: EntityKind,
        entity: &StoredEntity,
    ) -> Result<UpdateOutcome, StoreError> {
        let mut state = self.write_state();
        let list = state.entities.entry(kind).or_default();
        let Some(index) = list.iter().position(|e| e.id == entity.id) else {
            return Ok(UpdateOutcome::DoesNotExist);
        };
        if list[index].version != entity.version {
            return Ok(UpdateOutcome::UnexpectedVersion);
        }
        if list
            .iter()
            .any(|e| e.id != entity.id && e.key == entity.key)
        {
            return Ok(UpdateOutcome::KeyConflict);
        }
        list[index] = StoredEntity {
            version: entity.version + 1,
            ..entity.clone()
        };
        state.changed();
        Ok(UpdateOutcome::Updated)
    }

    async fn delete(&self, kind: EntityKind, id: &EntityId) -> Result<(), StoreError> {
        let mut state = self.write_state();
        if let Some(list) = state.entities.get_mut(&kind) {
            list.retain(|e| e.id != *id);
        }
        state.changed();
        Ok(())
    }

    async fn list(&self, kind: EntityKind) -> Result<Vec<StoredEntity>, StoreError> {
        Ok(self
            .read_state()
            .entities
            .get(&kind)
            .cloned()
            .unwrap_or_default())
    }

    async fn reorder(&self, kind: EntityKind, first: &[String]) -> Result<(), StoreError> {
        if kind == EntityKind::Client {
            return Ok(());
        }
        let mut state = self.write_state();
        let Some(list) = state.entities.get_mut(&kind) else {
            return Ok(());
        };
        let current: Vec<String> = list.iter().map(|e| e.key.clone()).collect();
        let order = rustid_core::stores::reordered(&current, first);
        if order == current {
            return Ok(());
        }
        list.sort_by_key(|e| order.iter().position(|k| *k == e.key));
        state.changed();
        Ok(())
    }
}

#[async_trait]
impl ResourceStore for InMemoryConfiguration {
    async fn get_all_enabled_resources(&self) -> Result<Arc<Resources>, StoreError> {
        Ok(self.resources()?.1)
    }

    async fn get_all_resources(&self) -> Result<Arc<Resources>, StoreError> {
        Ok(self.resources()?.0)
    }

    async fn find_api_resources_by_name(
        &self,
        names: &[String],
    ) -> Result<Vec<ApiResource>, StoreError> {
        Ok(self
            .resources()?
            .0
            .api_resources
            .iter()
            .filter(|api| names.contains(&api.name))
            .cloned()
            .collect())
    }
}

#[async_trait]
impl ClientStore for InMemoryConfiguration {
    async fn find_client_by_id(&self, client_id: &str) -> Result<Option<Arc<Client>>, StoreError> {
        self.clients()?.find_client_by_id(client_id).await
    }

    async fn is_cors_origin_allowed(&self, origin: &str) -> Result<bool, StoreError> {
        self.clients()?.is_cors_origin_allowed(origin).await
    }
}

#[async_trait]
impl ServiceProviderStore for InMemoryConfiguration {
    async fn find_by_entity_id(
        &self,
        entity_id: &str,
    ) -> Result<Option<Arc<ServiceProvider>>, StoreError> {
        self.service_providers()?.find_by_entity_id(entity_id).await
    }

    async fn get_all(&self) -> Result<Vec<Arc<ServiceProvider>>, StoreError> {
        self.service_providers()?.get_all().await
    }
}
