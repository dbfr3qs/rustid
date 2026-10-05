//! API scope and identity resource admin: the two have the same fields,
//! validation and
//! queries, so one service serves both kinds.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::query::{Direction, QueryResult, Range, paginate};
use super::{AdminError, EntityId, SaveResult, Saved, Versioned};
use crate::stores::{
    ConfigurationStore, CreateOutcome, EntityKind, StoreError, StoredEntity, UpdateOutcome,
};

fn yes() -> bool {
    true
}

/// A list that may be `null` in JSON, meaning empty (as the admin models
/// accept `null` list properties).
fn nullable_list<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    Ok(Option::<Vec<String>>::deserialize(d)?.unwrap_or_default())
}

fn nullable_map<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Map<String, Value>, D::Error> {
    Ok(Option::<Map<String, Value>>::deserialize(d)?.unwrap_or_default())
}

/// An API scope or identity resource as the admin API shows it, and the
/// create and update inputs, which have the same fields.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceConfiguration {
    #[serde(default)]
    pub name: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default = "yes")]
    pub show_in_discovery_document: bool,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub emphasize: bool,
    #[serde(default, deserialize_with = "nullable_list")]
    pub user_claims: Vec<String>,
    #[serde(default, deserialize_with = "nullable_map")]
    pub extended_properties: Map<String, Value>,
}

impl Default for ResourceConfiguration {
    fn default() -> Self {
        ResourceConfiguration {
            name: String::new(),
            enabled: true,
            display_name: None,
            description: None,
            show_in_discovery_document: true,
            required: false,
            emphasize: false,
            user_claims: Vec::new(),
            extended_properties: Map::new(),
        }
    }
}

/// An API scope or identity resource in a list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceListItem {
    pub id: EntityId,
    pub name: String,
    pub display_name: Option<String>,
    pub enabled: bool,
    pub description: Option<String>,
}

/// A name substring, and
/// enabled or not.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResourceFilter {
    pub name: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceSortField {
    Name,
    Enabled,
}

/// The admin service for one of the two kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceAdmin {
    kind: EntityKind,
}

impl ResourceAdmin {
    pub fn identity_resources() -> Self {
        ResourceAdmin {
            kind: EntityKind::IdentityResource,
        }
    }

    pub fn api_scopes() -> Self {
        ResourceAdmin {
            kind: EntityKind::ApiScope,
        }
    }

    pub fn kind(&self) -> EntityKind {
        self.kind
    }

    fn name(&self) -> &'static str {
        self.kind.error_name()
    }

    /// The other kind, whose names this kind can't take: `resources_file`
    /// refuses an identity resource and an API scope sharing a name, since
    /// the runtime resolves the name to the identity resource.
    fn sibling(&self) -> EntityKind {
        match self.kind {
            EntityKind::IdentityResource => EntityKind::ApiScope,
            _ => EntityKind::IdentityResource,
        }
    }

    async fn name_taken_by_sibling(
        &self,
        store: &dyn ConfigurationStore,
        name: &str,
    ) -> Result<Option<AdminError>, StoreError> {
        let sibling = self.sibling();
        Ok(store
            .read_by_key(sibling, name)
            .await?
            .map(|_| AdminError::already_exists(sibling.error_name(), name)))
    }

    /// Checks the input's own fields, before any store lookups.
    fn validate(&self, input: &ResourceConfiguration) -> Option<AdminError> {
        if input.name.trim().is_empty() {
            return Some(AdminError::required("Name"));
        }
        if input.user_claims.iter().any(|c| c.trim().is_empty()) {
            return Some(AdminError::invalid_value(
                "UserClaims",
                "Claim type must not be null or whitespace.",
            ));
        }
        None
    }

    fn schema_id(&self) -> &'static str {
        match self.kind {
            EntityKind::IdentityResource => super::schemas::IDENTITY_RESOURCE_SCHEMA,
            _ => super::schemas::API_SCOPE_SCHEMA,
        }
    }

    /// The runtime model (`IdentityResource`/`ApiScope`) as stored, with the
    /// extended properties and their string values as `properties`.
    fn data(
        input: &ResourceConfiguration,
        properties: std::collections::BTreeMap<String, String>,
    ) -> Value {
        serde_json::json!({
            "name": input.name,
            "enabled": input.enabled,
            "displayName": input.display_name,
            "description": input.description,
            "showInDiscoveryDocument": input.show_in_discovery_document,
            "required": input.required,
            "emphasize": input.emphasize,
            "userClaims": input.user_claims,
            "properties": properties,
            "extendedProperties": input.extended_properties,
        })
    }

    async fn extended_properties(
        &self,
        store: &dyn ConfigurationStore,
        input: &ResourceConfiguration,
    ) -> Result<Result<std::collections::BTreeMap<String, String>, AdminError>, StoreError> {
        super::schemas::check_extended_properties(
            store,
            self.schema_id(),
            &input.extended_properties,
        )
        .await
    }

    fn configuration(entity: &StoredEntity) -> Result<ResourceConfiguration, StoreError> {
        // The runtime models deserialize these fields with the same defaults.
        let model: crate::resources::ApiScope = serde_json::from_value(entity.data.clone())
            .map_err(|e| StoreError::Backend(format!("stored {}: {e}", entity.key)))?;
        Ok(ResourceConfiguration {
            name: model.name,
            enabled: model.enabled,
            display_name: model.display_name,
            description: model.description,
            show_in_discovery_document: model.show_in_discovery_document,
            required: model.required,
            emphasize: model.emphasize,
            user_claims: model.user_claims,
            extended_properties: super::schemas::stored_extended_properties(&entity.data),
        })
    }

    pub async fn create(
        &self,
        store: &dyn ConfigurationStore,
        input: ResourceConfiguration,
    ) -> SaveResult {
        if let Some(error) = self.validate(&input) {
            return Ok(Err(vec![error]));
        }
        let properties = match self.extended_properties(store, &input).await? {
            Ok(properties) => properties,
            Err(error) => return Ok(Err(vec![error])),
        };
        if let Some(error) = self.name_taken_by_sibling(store, &input.name).await? {
            return Ok(Err(vec![error]));
        }
        let entity = StoredEntity {
            id: EntityId::new_v7(),
            key: input.name.clone(),
            version: 1,
            data: Self::data(&input, properties),
        };
        Ok(match store.create(self.kind, &entity).await? {
            CreateOutcome::Created => Ok(Saved {
                id: entity.id,
                version: 1,
            }),
            CreateOutcome::KeyExists => {
                Err(vec![AdminError::already_exists(self.name(), &input.name)])
            }
        })
    }

    /// The read with only the extended properties the schema still accepts.
    async fn readable(
        &self,
        store: &dyn ConfigurationStore,
        found: Option<Versioned<ResourceConfiguration>>,
    ) -> Result<Option<Versioned<ResourceConfiguration>>, StoreError> {
        let Some(mut found) = found else {
            return Ok(None);
        };
        let values = std::mem::take(&mut found.item.extended_properties);
        found.item.extended_properties =
            super::schemas::readable_extended_properties(store, self.schema_id(), values).await?;
        Ok(Some(found))
    }

    fn versioned(
        entity: Option<StoredEntity>,
    ) -> Result<Option<Versioned<ResourceConfiguration>>, StoreError> {
        entity
            .map(|e| {
                Ok(Versioned {
                    id: e.id,
                    version: e.version,
                    item: Self::configuration(&e)?,
                })
            })
            .transpose()
    }

    pub async fn get(
        &self,
        store: &dyn ConfigurationStore,
        id: &EntityId,
    ) -> Result<Option<Versioned<ResourceConfiguration>>, StoreError> {
        self.readable(store, Self::versioned(store.read(self.kind, id).await?)?)
            .await
    }

    pub async fn get_by_name(
        &self,
        store: &dyn ConfigurationStore,
        name: &str,
    ) -> Result<Option<Versioned<ResourceConfiguration>>, StoreError> {
        self.readable(
            store,
            Self::versioned(store.read_by_key(self.kind, name).await?)?,
        )
        .await
    }

    pub async fn update(
        &self,
        store: &dyn ConfigurationStore,
        id: &EntityId,
        input: ResourceConfiguration,
        expected_version: i32,
    ) -> SaveResult {
        if let Some(error) = self.validate(&input) {
            return Ok(Err(vec![error]));
        }
        let not_found = || vec![AdminError::not_found(self.name(), &id.to_string())];
        if store.read(self.kind, id).await?.is_none() {
            return Ok(Err(not_found()));
        }
        let properties = match self.extended_properties(store, &input).await? {
            Ok(properties) => properties,
            Err(error) => return Ok(Err(vec![error])),
        };
        if let Some(error) = self.name_taken_by_sibling(store, &input.name).await? {
            return Ok(Err(vec![error]));
        }
        let entity = StoredEntity {
            id: *id,
            key: input.name.clone(),
            version: expected_version,
            data: Self::data(&input, properties),
        };
        Ok(match store.update(self.kind, &entity).await? {
            UpdateOutcome::Updated => Ok(Saved {
                id: *id,
                version: expected_version + 1,
            }),
            UpdateOutcome::UnexpectedVersion => Err(vec![AdminError::version_conflict()]),
            UpdateOutcome::DoesNotExist => Err(not_found()),
            UpdateOutcome::KeyConflict => {
                Err(vec![AdminError::already_exists(self.name(), &input.name)])
            }
        })
    }

    /// Idempotent: version 0.
    pub async fn delete(&self, store: &dyn ConfigurationStore, id: &EntityId) -> SaveResult {
        store.delete(self.kind, id).await?;
        Ok(Ok(Saved {
            id: *id,
            version: 0,
        }))
    }

    pub async fn query(
        &self,
        store: &dyn ConfigurationStore,
        filter: &ResourceFilter,
        sort: Option<(ResourceSortField, Direction)>,
        range: &Range,
    ) -> Result<Result<QueryResult<ResourceListItem>, AdminError>, StoreError> {
        let mut items = Vec::new();
        for entity in store.list(self.kind).await? {
            let c = Self::configuration(&entity)?;
            let name_matches = filter
                .name
                .as_deref()
                .is_none_or(|part| c.name.contains(part));
            let enabled_matches = filter.enabled.is_none_or(|e| c.enabled == e);
            if name_matches && enabled_matches {
                items.push(ResourceListItem {
                    id: entity.id,
                    name: c.name,
                    display_name: c.display_name,
                    enabled: c.enabled,
                    description: c.description,
                });
            }
        }
        let (field, direction) = sort.unwrap_or((ResourceSortField::Name, Direction::Ascending));
        items.sort_by(|a, b| {
            let order = match field {
                ResourceSortField::Name => a.name.cmp(&b.name),
                ResourceSortField::Enabled => a.enabled.cmp(&b.enabled),
            };
            let order = match direction {
                Direction::Ascending => order,
                Direction::Descending => order.reverse(),
            };
            order.then_with(|| a.id.cmp(&b.id))
        });
        Ok(paginate(items, range))
    }
}
