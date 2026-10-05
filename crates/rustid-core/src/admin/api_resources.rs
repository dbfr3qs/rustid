//! API resource admin (`ApiResourceAdmin`): the resource with its scopes
//! (which must exist as API scopes) and its secrets, created and deleted one
//! at a time and kept across updates. The stored data is the runtime
//! `ApiResource`; secrets also carry their admin `id` and `hashAlgorithm`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::query::{Direction, QueryResult, Range, paginate};
use super::resources::ResourceSortField;
use super::schemas;
use super::secrets::{self, CreateSecret, SecretConfiguration};
use super::{AdminError, EntityId, SaveResult, Saved, Versioned};
use crate::stores::{
    ConfigurationStore, CreateOutcome, EntityKind, StoreError, StoredEntity, UpdateOutcome,
};

const KIND: EntityKind = EntityKind::ApiResource;
const NAME: &str = "api_resource";

fn yes() -> bool {
    true
}

fn nullable_list<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    Ok(Option::<Vec<String>>::deserialize(d)?.unwrap_or_default())
}

fn nullable_map<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Map<String, Value>, D::Error> {
    Ok(Option::<Map<String, Value>>::deserialize(d)?.unwrap_or_default())
}

/// An API resource to create or update.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApiResourceInput {
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
    pub require_resource_indicator: bool,
    #[serde(default, deserialize_with = "nullable_list")]
    pub user_claims: Vec<String>,
    #[serde(default, deserialize_with = "nullable_list")]
    pub scopes: Vec<String>,
    #[serde(default, deserialize_with = "nullable_list")]
    pub allowed_access_token_signing_algorithms: Vec<String>,
    #[serde(default, deserialize_with = "nullable_map")]
    pub extended_properties: Map<String, Value>,
}

impl Default for ApiResourceInput {
    fn default() -> Self {
        ApiResourceInput {
            name: String::new(),
            enabled: true,
            display_name: None,
            description: None,
            show_in_discovery_document: true,
            require_resource_indicator: false,
            user_claims: Vec::new(),
            scopes: Vec::new(),
            allowed_access_token_signing_algorithms: Vec::new(),
            extended_properties: Map::new(),
        }
    }
}

/// `ApiResourceConfiguration`: the input's fields and the secrets (never
/// their values).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiResourceConfiguration {
    #[serde(flatten)]
    pub resource: ApiResourceInput,
    pub api_secrets: Vec<SecretConfiguration>,
}

impl std::ops::Deref for ApiResourceConfiguration {
    type Target = ApiResourceInput;

    fn deref(&self) -> &ApiResourceInput {
        &self.resource
    }
}

/// `ApiResourceFilter`: a name substring, enabled or not, and a scope the
/// resource has.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApiResourceFilter {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub scope: Option<String>,
}

/// `ApiResourceListItem`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiResourceListItem {
    pub id: EntityId,
    pub name: String,
    pub display_name: Option<String>,
    pub enabled: bool,
    pub description: Option<String>,
    pub scope_count: usize,
}

fn parse(entity: &StoredEntity) -> Result<crate::resources::ApiResource, StoreError> {
    serde_json::from_value(entity.data.clone())
        .map_err(|e| StoreError::Backend(format!("stored {}: {e}", entity.key)))
}

fn stored_secrets(entity: &StoredEntity) -> Vec<Value> {
    entity
        .data
        .get("apiSecrets")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// The runtime model as stored, with these secrets, the extended
/// properties, and their string values as `properties`.
fn data(
    input: &ApiResourceInput,
    secrets: Vec<Value>,
    properties: BTreeMap<String, String>,
) -> Value {
    serde_json::json!({
        "name": input.name,
        "enabled": input.enabled,
        "displayName": input.display_name,
        "description": input.description,
        "showInDiscoveryDocument": input.show_in_discovery_document,
        "requireResourceIndicator": input.require_resource_indicator,
        "userClaims": input.user_claims,
        "scopes": input.scopes,
        "allowedAccessTokenSigningAlgorithms": input.allowed_access_token_signing_algorithms,
        "apiSecrets": secrets,
        "properties": properties,
        "extendedProperties": input.extended_properties,
    })
}

fn blank(values: &[String]) -> bool {
    values.iter().any(|v| v.trim().is_empty())
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ApiResourceAdmin;

impl ApiResourceAdmin {
    /// Checks the input's own fields, before any store lookups.
    fn structure(input: &ApiResourceInput) -> Option<AdminError> {
        if input.name.trim().is_empty() {
            return Some(AdminError::required("Name"));
        }
        if blank(&input.user_claims) {
            return Some(AdminError::invalid_value(
                "UserClaims",
                "Claim type must not be null or whitespace.",
            ));
        }
        if blank(&input.scopes) {
            return Some(AdminError::invalid_value(
                "Scopes",
                "Scope name must not be null or whitespace.",
            ));
        }
        let mut seen = std::collections::HashSet::new();
        if !input.scopes.iter().all(|s| seen.insert(s)) {
            return Some(AdminError::invalid_value(
                "Scopes",
                "Scope list contains duplicate names.",
            ));
        }
        if blank(&input.allowed_access_token_signing_algorithms) {
            return Some(AdminError::invalid_value(
                "AllowedAccessTokenSigningAlgorithms",
                "Algorithm must not be null or whitespace.",
            ));
        }
        None
    }

    /// The extended properties against the API resource schema, then
    /// Every scope must exist. On success, the
    /// runtime `properties`.
    async fn references(
        store: &dyn ConfigurationStore,
        input: &ApiResourceInput,
    ) -> Result<Result<BTreeMap<String, String>, AdminError>, StoreError> {
        let properties = match schemas::check_extended_properties(
            store,
            schemas::API_RESOURCE_SCHEMA,
            &input.extended_properties,
        )
        .await?
        {
            Ok(properties) => properties,
            Err(error) => return Ok(Err(error)),
        };
        for scope in &input.scopes {
            if store
                .read_by_key(EntityKind::ApiScope, scope)
                .await?
                .is_none()
            {
                return Ok(Err(AdminError::invalid_value(
                    "Scopes",
                    format!("Scope '{scope}' does not exist."),
                )));
            }
        }
        Ok(Ok(properties))
    }

    pub async fn create(
        &self,
        store: &dyn ConfigurationStore,
        input: ApiResourceInput,
    ) -> SaveResult {
        if let Some(error) = Self::structure(&input) {
            return Ok(Err(vec![error]));
        }
        let properties = match Self::references(store, &input).await? {
            Ok(properties) => properties,
            Err(error) => return Ok(Err(vec![error])),
        };
        let entity = StoredEntity {
            id: EntityId::new_v7(),
            key: input.name.clone(),
            version: 1,
            data: data(&input, Vec::new(), properties),
        };
        Ok(match store.create(KIND, &entity).await? {
            CreateOutcome::Created => Ok(Saved {
                id: entity.id,
                version: 1,
            }),
            CreateOutcome::KeyExists => Err(vec![AdminError::already_exists(NAME, &input.name)]),
        })
    }

    /// The read with only the extended properties the schema still accepts.
    async fn readable(
        store: &dyn ConfigurationStore,
        found: Option<Versioned<ApiResourceConfiguration>>,
    ) -> Result<Option<Versioned<ApiResourceConfiguration>>, StoreError> {
        let Some(mut found) = found else {
            return Ok(None);
        };
        let values = std::mem::take(&mut found.item.resource.extended_properties);
        found.item.resource.extended_properties =
            schemas::readable_extended_properties(store, schemas::API_RESOURCE_SCHEMA, values)
                .await?;
        Ok(Some(found))
    }

    fn versioned(
        entity: Option<StoredEntity>,
    ) -> Result<Option<Versioned<ApiResourceConfiguration>>, StoreError> {
        let Some(entity) = entity else {
            return Ok(None);
        };
        let model = parse(&entity)?;
        Ok(Some(Versioned {
            id: entity.id,
            version: entity.version,
            item: ApiResourceConfiguration {
                resource: ApiResourceInput {
                    name: model.name,
                    enabled: model.enabled,
                    display_name: model.display_name,
                    description: model.description,
                    show_in_discovery_document: model.show_in_discovery_document,
                    require_resource_indicator: model.require_resource_indicator,
                    user_claims: model.user_claims,
                    scopes: model.scopes,
                    allowed_access_token_signing_algorithms: model
                        .allowed_access_token_signing_algorithms,
                    extended_properties: schemas::stored_extended_properties(&entity.data),
                },
                api_secrets: stored_secrets(&entity)
                    .iter()
                    .map(secrets::configuration)
                    .collect(),
            },
        }))
    }

    pub async fn get(
        &self,
        store: &dyn ConfigurationStore,
        id: &EntityId,
    ) -> Result<Option<Versioned<ApiResourceConfiguration>>, StoreError> {
        Self::readable(store, Self::versioned(store.read(KIND, id).await?)?).await
    }

    pub async fn get_by_name(
        &self,
        store: &dyn ConfigurationStore,
        name: &str,
    ) -> Result<Option<Versioned<ApiResourceConfiguration>>, StoreError> {
        Self::readable(
            store,
            Self::versioned(store.read_by_key(KIND, name).await?)?,
        )
        .await
    }

    /// Saves `entity` at `version`, mapping the outcome.
    async fn save(
        store: &dyn ConfigurationStore,
        entity: StoredEntity,
        saved_id: EntityId,
    ) -> SaveResult {
        let version = entity.version;
        Ok(match store.update(KIND, &entity).await? {
            UpdateOutcome::Updated => Ok(Saved {
                id: saved_id,
                version: version + 1,
            }),
            UpdateOutcome::UnexpectedVersion => Err(vec![AdminError::version_conflict()]),
            UpdateOutcome::DoesNotExist => {
                Err(vec![AdminError::not_found(NAME, &entity.id.to_string())])
            }
            UpdateOutcome::KeyConflict => Err(vec![AdminError::already_exists(NAME, &entity.key)]),
        })
    }

    pub async fn update(
        &self,
        store: &dyn ConfigurationStore,
        id: &EntityId,
        input: ApiResourceInput,
        expected_version: i32,
    ) -> SaveResult {
        if let Some(error) = Self::structure(&input) {
            return Ok(Err(vec![error]));
        }
        let Some(existing) = store.read(KIND, id).await? else {
            return Ok(Err(vec![AdminError::not_found(NAME, &id.to_string())]));
        };
        let properties = match Self::references(store, &input).await? {
            Ok(properties) => properties,
            Err(error) => return Ok(Err(vec![error])),
        };
        let entity = StoredEntity {
            id: *id,
            key: input.name.clone(),
            version: expected_version,
            data: data(
                &input,
                secrets::with_ids(&stored_secrets(&existing)),
                properties,
            ),
        };
        Self::save(store, entity, *id).await
    }

    /// Idempotent: version 0.
    pub async fn delete(&self, store: &dyn ConfigurationStore, id: &EntityId) -> SaveResult {
        store.delete(KIND, id).await?;
        Ok(Ok(Saved {
            id: *id,
            version: 0,
        }))
    }

    /// The stored entity with its secrets replaced, at its current version.
    fn with_secrets(entity: &StoredEntity, secrets: Vec<Value>) -> StoredEntity {
        let mut data = entity.data.clone();
        if let Value::Object(object) = &mut data {
            object.insert("apiSecrets".into(), Value::Array(secrets));
        }
        StoredEntity {
            data,
            ..entity.clone()
        }
    }

    pub async fn create_secret(
        &self,
        store: &dyn ConfigurationStore,
        id: &EntityId,
        input: CreateSecret,
    ) -> SaveResult {
        if input.plaintext_value.trim().is_empty() {
            return Ok(Err(vec![AdminError::required("plaintextValue")]));
        }
        let Some(existing) = store.read(KIND, id).await? else {
            return Ok(Err(vec![AdminError::not_found(NAME, &id.to_string())]));
        };
        let (secret_id, secret) = secrets::new_secret(&input);
        let mut all = secrets::with_ids(&stored_secrets(&existing));
        all.push(secret);
        Self::save(store, Self::with_secrets(&existing, all), secret_id).await
    }

    pub async fn delete_secret(
        &self,
        store: &dyn ConfigurationStore,
        id: &EntityId,
        secret_id: &EntityId,
    ) -> SaveResult {
        let Some(existing) = store.read(KIND, id).await? else {
            return Ok(Err(vec![AdminError::not_found(NAME, &id.to_string())]));
        };
        let all = secrets::with_ids(&stored_secrets(&existing));
        let remaining: Vec<Value> = all
            .iter()
            .filter(|s| secrets::stored_id(s) != *secret_id)
            .cloned()
            .collect();
        if remaining.len() == all.len() {
            return Ok(Err(vec![AdminError::not_found(
                "secret",
                &secret_id.to_string(),
            )]));
        }
        Self::save(store, Self::with_secrets(&existing, remaining), *secret_id).await
    }

    pub async fn query(
        &self,
        store: &dyn ConfigurationStore,
        filter: &ApiResourceFilter,
        sort: Option<(ResourceSortField, Direction)>,
        range: &Range,
    ) -> Result<Result<QueryResult<ApiResourceListItem>, AdminError>, StoreError> {
        let mut items = Vec::new();
        for entity in store.list(KIND).await? {
            let model = parse(&entity)?;
            let matches = filter
                .name
                .as_deref()
                .is_none_or(|part| model.name.contains(part))
                && filter.enabled.is_none_or(|e| model.enabled == e)
                && filter
                    .scope
                    .as_deref()
                    .is_none_or(|scope| model.scopes.iter().any(|s| s == scope));
            if matches {
                items.push(ApiResourceListItem {
                    id: entity.id,
                    scope_count: model.scopes.len(),
                    name: model.name,
                    display_name: model.display_name,
                    enabled: model.enabled,
                    description: model.description,
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
