//! Data extension schemas (entity attribute values): the
//! attributes an entity kind's `extendedProperties` may carry, and the
//! validation of those values (`AttributeValueCollection.TryValidateAgainst`),
//! with stable messages.

use std::collections::BTreeMap;

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::{AdminError, EntityId, SaveResult, Saved, Versioned};
use crate::stores::{
    ConfigurationStore, CreateOutcome, EntityKind, StoreError, StoredEntity, UpdateOutcome,
};

/// `ScalarDataType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScalarDataType {
    String,
    Integer,
    Decimal,
    Boolean,
    Date,
    DateTime,
}

impl ScalarDataType {
    fn name(self) -> &'static str {
        match self {
            Self::String => "String",
            Self::Integer => "Integer",
            Self::Decimal => "Decimal",
            Self::Boolean => "Boolean",
            Self::Date => "Date",
            Self::DateTime => "DateTime",
        }
    }

    fn accepts(self, value: &Value) -> bool {
        match self {
            Self::String => value.is_string(),
            Self::Integer => value.as_i64().is_some_and(|n| i32::try_from(n).is_ok()),
            Self::Decimal => value.is_number(),
            Self::Boolean => value.is_boolean(),
            Self::Date => value.as_str().is_some_and(|s| {
                s.len() == 10 && chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").is_ok()
            }),
            Self::DateTime => value
                .as_str()
                .is_some_and(|s| chrono::DateTime::parse_from_rfc3339(s).is_ok()),
        }
    }
}

/// `AttributeType`: scalar, list (of a non-list) or complex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum AttributeType {
    #[serde(rename_all = "camelCase")]
    Scalar { data_type: ScalarDataType },
    #[serde(rename_all = "camelCase")]
    List { element_type: Box<AttributeType> },
    #[serde(rename_all = "camelCase")]
    Complex {
        properties: IndexMap<String, ComplexAttributeProperty>,
    },
}

impl Default for AttributeType {
    fn default() -> Self {
        AttributeType::Scalar {
            data_type: ScalarDataType::String,
        }
    }
}

impl AttributeType {
    /// The name a type mismatch reports.
    fn name(&self) -> &'static str {
        match self {
            Self::Scalar { data_type } => data_type.name(),
            Self::List { .. } => "ListAttributeType",
            Self::Complex { .. } => "ComplexAttributeType",
        }
    }

    /// Only the shape is checked: list elements and complex properties
    /// aren't validated.
    fn accepts(&self, value: &Value) -> bool {
        match self {
            Self::Scalar { data_type } => data_type.accepts(value),
            Self::List { .. } => value.is_array(),
            Self::Complex { .. } => value.is_object(),
        }
    }

    fn validate(&self, in_list: bool) -> Option<AdminError> {
        match self {
            Self::Scalar { .. } => None,
            Self::List { .. } if in_list => Some(definitions_error(
                "List types cannot be nested inside another list type.",
            )),
            Self::List { element_type } => element_type.validate(true),
            Self::Complex { properties } if properties.is_empty() => Some(definitions_error(
                "Properties must contain at least one entry.",
            )),
            Self::Complex { properties } => properties.iter().find_map(|(code, property)| {
                code_error(code)
                    .or_else(|| text_error(&property.display_name))
                    .or_else(|| text_error(&property.description))
                    .or_else(|| property.property_type.validate(in_list))
            }),
        }
    }
}

/// `ComplexAttributeProperty`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplexAttributeProperty {
    #[serde(rename = "type")]
    pub property_type: AttributeType,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

/// `AttributeDefinition`. Uniqueness and queryability are stored, not
/// enforced (value validation enforces neither).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttributeDefinition {
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub attribute_type: AttributeType,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub is_required: bool,
    #[serde(default)]
    pub is_unique: bool,
    #[serde(default)]
    pub is_queryable: bool,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub group_code: Option<String>,
    #[serde(default)]
    pub order: i32,
}

/// `AttributeGroup`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttributeGroup {
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub order: i32,
}

/// `SchemaConfiguration`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SchemaConfiguration {
    #[serde(default)]
    pub schema_id: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub attribute_definitions: Vec<AttributeDefinition>,
    #[serde(default)]
    pub groups: Vec<AttributeGroup>,
}

/// The schema ids of the kinds.
pub const CLIENT_SCHEMA: &str = "client";
pub const API_RESOURCE_SCHEMA: &str = "api-resource";
pub const API_SCOPE_SCHEMA: &str = "api-scope";
pub const IDENTITY_RESOURCE_SCHEMA: &str = "identity-resource";
pub const SAML_SERVICE_PROVIDER_SCHEMA: &str = "saml-service-provider";

const MAX_SCHEMA_ID: usize = 50;
const MAX_CODE: usize = 100;
const MAX_TEXT: usize = 200;

fn definitions_error(message: &str) -> AdminError {
    AdminError::invalid_value("AttributeDefinitions", message)
}

/// `AttributeCode`'s rules.
fn code_error(code: &str) -> Option<AdminError> {
    if code.is_empty() {
        return Some(AdminError::required("AttributeDefinitions"));
    }
    let message = if code.chars().count() > MAX_CODE {
        "Must not exceed 100 characters."
    } else if !code.starts_with(|c: char| c.is_ascii_alphabetic()) {
        "Must start with an ASCII letter."
    } else if !code.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        "Must only contain ASCII letters, digits, or underscores."
    } else if code.ends_with('_') {
        "Must not end with an underscore."
    } else {
        return None;
    };
    Some(definitions_error(message))
}

/// `AttributeDisplayName` and `AttributeDescription`'s length.
fn text_error(text: &Option<String>) -> Option<AdminError> {
    text.as_deref()
        .filter(|t| t.chars().count() > MAX_TEXT)
        .map(|_| definitions_error("Must not exceed 200 characters."))
}

/// `SchemaId`'s rules.
pub fn schema_id_error(id: &str) -> Option<AdminError> {
    if id.trim().is_empty() {
        return Some(AdminError::required("SchemaId"));
    }
    if id.chars().count() > MAX_SCHEMA_ID {
        return Some(AdminError::invalid_value(
            "SchemaId",
            "Must not exceed 50 characters.",
        ));
    }
    let valid = id.starts_with(|c: char| c.is_ascii_alphanumeric())
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | ':' | '-'));
    (!valid).then(|| AdminError::invalid_value("SchemaId", "Must match the required pattern."))
}

impl SchemaConfiguration {
    /// The first rule the schema breaks.
    pub fn validate(&self) -> Option<AdminError> {
        schema_id_error(&self.schema_id).or_else(|| {
            self.attribute_definitions.iter().find_map(|d| {
                code_error(&d.code)
                    .or_else(|| text_error(&d.display_name))
                    .or_else(|| text_error(&d.description))
                    .or_else(|| d.attribute_type.validate(false))
            })
        })
    }

    /// The definition for `code` (case-insensitive); the last wins, as
    /// `InMemorySchemaStore` keeps the last of duplicates.
    pub fn definition(&self, code: &str) -> Option<&AttributeDefinition> {
        self.attribute_definitions
            .iter()
            .rev()
            .find(|d| d.code.eq_ignore_ascii_case(code))
    }
}

/// `TryValidateAgainst`: the errors, in order (each value in input
/// order, then each missing required attribute). No schema defines nothing.
pub fn validate_extended_properties(
    values: &Map<String, Value>,
    schema: Option<&SchemaConfiguration>,
) -> Vec<String> {
    let codes: Vec<&String> = values.keys().collect();
    if let Some(duplicate) = codes
        .iter()
        .enumerate()
        .find(|(i, code)| codes[..*i].iter().any(|c| c.eq_ignore_ascii_case(code)))
        .map(|(_, code)| code)
    {
        return vec![format!(
            "The attributes contain more than one attribute named '{duplicate}'."
        )];
    }
    let mut errors = Vec::new();
    for (code, value) in values {
        match schema.and_then(|s| s.definition(code)) {
            None => errors.push(format!("Attribute '{code}' is not defined in the schema.")),
            Some(d) if !d.attribute_type.accepts(value) => errors.push(format!(
                "Attribute '{code}' type mismatch: expected '{}'.",
                d.attribute_type.name()
            )),
            Some(_) => {}
        }
    }
    let mut seen: Vec<String> = Vec::new();
    for d in schema
        .map(|s| s.attribute_definitions.as_slice())
        .unwrap_or_default()
    {
        let lower = d.code.to_ascii_lowercase();
        if d.is_required
            && !seen.contains(&lower)
            && !values.keys().any(|k| k.eq_ignore_ascii_case(&d.code))
        {
            errors.push(format!("Required attribute '{}' is missing.", d.code));
        }
        seen.push(lower);
    }
    errors
}

/// `EavPropertyMapper.ExtractStringProperties`: the string-typed values, for
/// the runtime models' `properties`.
pub fn string_properties(
    values: &Map<String, Value>,
    schema: Option<&SchemaConfiguration>,
) -> BTreeMap<String, String> {
    values
        .iter()
        .filter(|(code, _)| {
            schema.and_then(|s| s.definition(code)).is_some_and(|d| {
                d.attribute_type
                    == AttributeType::Scalar {
                        data_type: ScalarDataType::String,
                    }
            })
        })
        .filter_map(|(code, value)| Some((code.clone(), value.as_str()?.to_owned())))
        .collect()
}

const KIND: EntityKind = EntityKind::Schema;
const NAME: &str = "schema";

/// The storage key: schema ids compare case-insensitively.
fn key(schema_id: &str) -> String {
    schema_id.to_ascii_lowercase()
}

fn parse(entity: &StoredEntity) -> Result<SchemaConfiguration, StoreError> {
    serde_json::from_value(entity.data.clone())
        .map_err(|e| StoreError::Backend(format!("stored schema {}: {e}", entity.key)))
}

/// The schema with this id, if registered.
pub async fn schema_for(
    store: &dyn ConfigurationStore,
    schema_id: &str,
) -> Result<Option<SchemaConfiguration>, StoreError> {
    store
        .read_by_key(KIND, &key(schema_id))
        .await?
        .as_ref()
        .map(parse)
        .transpose()
}

/// `SchemaSummary`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SchemaSummary {
    pub schema_id: String,
    pub display_name: Option<String>,
    pub attribute_count: usize,
    pub group_count: usize,
}

/// The schema admin, over the configuration store.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SchemaAdmin;

impl SchemaAdmin {
    fn data(schema: &SchemaConfiguration) -> Value {
        serde_json::to_value(schema).expect("a schema serialises")
    }

    pub async fn create(
        &self,
        store: &dyn ConfigurationStore,
        schema: SchemaConfiguration,
    ) -> SaveResult {
        if let Some(error) = schema.validate() {
            return Ok(Err(vec![error]));
        }
        let entity = StoredEntity {
            id: EntityId::new_v7(),
            key: key(&schema.schema_id),
            version: 1,
            data: Self::data(&schema),
        };
        Ok(match store.create(KIND, &entity).await? {
            CreateOutcome::Created => Ok(Saved {
                id: entity.id,
                version: 1,
            }),
            CreateOutcome::KeyExists => {
                Err(vec![AdminError::already_exists(NAME, &schema.schema_id)])
            }
        })
    }

    pub async fn get(
        &self,
        store: &dyn ConfigurationStore,
        schema_id: &str,
    ) -> Result<Option<Versioned<SchemaConfiguration>>, StoreError> {
        let Some(entity) = store.read_by_key(KIND, &key(schema_id)).await? else {
            return Ok(None);
        };
        Ok(Some(Versioned {
            id: entity.id,
            version: entity.version,
            item: parse(&entity)?,
        }))
    }

    pub async fn update(
        &self,
        store: &dyn ConfigurationStore,
        schema_id: &str,
        schema: SchemaConfiguration,
        expected_version: i32,
    ) -> SaveResult {
        if !schema.schema_id.eq_ignore_ascii_case(schema_id) {
            return Ok(Err(vec![AdminError::invalid_value(
                "SchemaId",
                "Schema ID in the body must match the route schema ID.",
            )]));
        }
        if let Some(error) = schema.validate() {
            return Ok(Err(vec![error]));
        }
        let Some(existing) = store.read_by_key(KIND, &key(schema_id)).await? else {
            return Ok(Err(vec![AdminError::not_found(NAME, schema_id)]));
        };
        let entity = StoredEntity {
            id: existing.id,
            key: existing.key,
            version: expected_version,
            data: Self::data(&schema),
        };
        Ok(match store.update(KIND, &entity).await? {
            UpdateOutcome::Updated => Ok(Saved {
                id: entity.id,
                version: expected_version + 1,
            }),
            UpdateOutcome::UnexpectedVersion => Err(vec![AdminError::version_conflict()]),
            UpdateOutcome::DoesNotExist => Err(vec![AdminError::not_found(NAME, schema_id)]),
            UpdateOutcome::KeyConflict => Err(vec![AdminError::already_exists(NAME, schema_id)]),
        })
    }

    /// Idempotent: version 0.
    pub async fn delete(&self, store: &dyn ConfigurationStore, schema_id: &str) -> SaveResult {
        let existing = store.read_by_key(KIND, &key(schema_id)).await?;
        if let Some(existing) = &existing {
            store.delete(KIND, &existing.id).await?;
        }
        Ok(Ok(Saved {
            id: existing.map(|e| e.id).unwrap_or(EntityId([0; 16])),
            version: 0,
        }))
    }

    /// Every schema's summary, by id.
    pub async fn query(
        &self,
        store: &dyn ConfigurationStore,
    ) -> Result<Vec<SchemaSummary>, StoreError> {
        let mut summaries = store
            .list(KIND)
            .await?
            .iter()
            .map(|e| {
                parse(e).map(|s| SchemaSummary {
                    attribute_count: s.attribute_definitions.len(),
                    group_count: s.groups.len(),
                    schema_id: s.schema_id,
                    display_name: s.display_name,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        summaries.sort_by_key(|s| s.schema_id.to_ascii_lowercase());
        Ok(summaries)
    }
}

/// The extended properties checked against the kind's schema (as each
/// None are never checked), and on
/// success their string values for the runtime `properties`.
pub async fn check_extended_properties(
    store: &dyn ConfigurationStore,
    schema_id: &str,
    values: &Map<String, Value>,
) -> Result<Result<BTreeMap<String, String>, AdminError>, StoreError> {
    if values.is_empty() {
        return Ok(Ok(BTreeMap::new()));
    }
    let schema = schema_for(store, schema_id).await?;
    let errors = validate_extended_properties(values, schema.as_ref());
    Ok(if errors.is_empty() {
        Ok(string_properties(values, schema.as_ref()))
    } else {
        Err(AdminError::validation_failed(errors.join("; ")))
    })
}

/// The stored extended properties of an entity, or none.
pub fn stored_extended_properties(data: &Value) -> Map<String, Value> {
    data.get("extendedProperties")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
}

/// `EavMapper.ToAttributeValues`: the stored values the current schema
/// still accepts. Reads show only these, so after a schema change an update
/// sent back from a read succeeds and drops the rest.
pub async fn readable_extended_properties(
    store: &dyn ConfigurationStore,
    schema_id: &str,
    values: Map<String, Value>,
) -> Result<Map<String, Value>, StoreError> {
    if values.is_empty() {
        return Ok(values);
    }
    let schema = schema_for(store, schema_id).await?;
    Ok(values
        .into_iter()
        .filter(|(code, value)| {
            schema
                .as_ref()
                .and_then(|s| s.definition(code))
                .is_some_and(|d| d.attribute_type.accepts(value))
        })
        .collect())
}
