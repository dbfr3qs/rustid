//! Client admin (`ClientAdmin`): the runtime `Client` as the admin model,
//! checked by admin's structure validation and then the configuration
//! validator (`validate_client`), with its secrets created and deleted one at
//! a time and kept across updates. The stored data is the runtime `Client`;
//! secrets also carry their admin `id` and `hashAlgorithm`.

use std::collections::HashSet;

use serde::Serialize;
use serde_json::{Map, Value};

use super::query::{Direction, QueryResult, Range, paginate};
use super::schemas;
use super::secrets::{self, CreateSecret, SecretConfiguration};
use super::{AdminError, EntityId, SaveResult, Saved, Versioned};
use crate::clients::{Client, Secret, validate_client};
use crate::stores::{
    ConfigurationStore, CreateOutcome, EntityKind, StoreError, StoredEntity, UpdateOutcome,
};

const KIND: EntityKind = EntityKind::Client;
const NAME: &str = "client";
/// Runtime properties dynamic client registration owns (`dcr::manage`).
const DCR_PROPERTY_PREFIX: &str = "dcr_";
/// Admin stores every client as OpenID Connect, so
/// the configuration validator always applies.
const OIDC: &str = "oidc";

/// The client (its `client_secrets` are
/// ignored), the secrets to create with it (create only), and extended
/// properties.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ClientInput {
    pub client: Client,
    pub client_secrets: Vec<CreateSecret>,
    pub extended_properties: Map<String, Value>,
}

/// Members the deserializer reads under another name.
const ALIASES: [&str; 3] = ["requireDpop", "dpopValidationMode", "dpopClockSkew"];

impl ClientInput {
    /// The input from a request body. Unknown members are refused, and a
    /// `null` list means empty. With `with_secrets`, `clientSecrets` are the
    /// secrets to create; without, they are ignored (an update sends back
    /// what a read returned).
    pub fn from_json(body: Value, with_secrets: bool) -> Result<ClientInput, AdminError> {
        let Value::Object(mut body) = body else {
            return Err(AdminError::validation_failed(
                "The request body must be a JSON object.",
            ));
        };
        let Value::Object(defaults) =
            serde_json::to_value(Client::default()).expect("a client serialises")
        else {
            unreachable!("a client serialises as an object")
        };
        if let Some(unknown) = body.keys().find(|key| {
            // `properties` is the runtime's view of the extended properties.
            (!defaults.contains_key(*key) || *key == "properties")
                && !ALIASES.contains(&key.as_str())
                && *key != "extendedProperties"
        }) {
            return Err(AdminError::invalid_value(
                unknown,
                format!("'{unknown}' is not a client setting."),
            ));
        }
        let client_secrets = match body.remove("clientSecrets") {
            Some(value) if with_secrets => {
                serde_json::from_value::<Option<Vec<CreateSecret>>>(value)
                    .map_err(|e| AdminError::invalid_value("ClientSecrets", e.to_string()))?
                    .unwrap_or_default()
            }
            _ => Vec::new(),
        };
        let extended_properties = match body.remove("extendedProperties") {
            Some(value) => serde_json::from_value::<Option<Map<String, Value>>>(value)
                .map_err(|e| AdminError::invalid_value("ExtendedProperties", e.to_string()))?
                .unwrap_or_default(),
            None => Map::new(),
        };
        body.retain(|key, value| {
            !(value.is_null() && defaults.get(key).is_some_and(Value::is_array))
        });
        let client = serde_json::from_value(Value::Object(body))
            .map_err(|e| AdminError::validation_failed(format!("Invalid client: {e}")))?;
        Ok(ClientInput {
            client,
            client_secrets,
            extended_properties,
        })
    }
}

/// `ClientConfiguration`: the client without secret values, its secrets'
/// configurations, and extended properties.
#[derive(Debug, Clone, PartialEq)]
pub struct ClientConfiguration {
    /// `client_secrets` is always empty.
    pub client: Client,
    pub client_secrets: Vec<SecretConfiguration>,
    pub extended_properties: Map<String, Value>,
}

impl Serialize for ClientConfiguration {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        let mut json = serde_json::to_value(&self.client).map_err(S::Error::custom)?;
        if let Value::Object(object) = &mut json {
            object.insert(
                "clientSecrets".into(),
                serde_json::to_value(&self.client_secrets).map_err(S::Error::custom)?,
            );
            object.insert(
                "extendedProperties".into(),
                Value::Object(self.extended_properties.clone()),
            );
            object.remove("properties");
        }
        json.serialize(serializer)
    }
}

/// `ClientFilter`: client id and name substrings, enabled or not, and a grant
/// type and a scope the client allows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientFilter {
    pub client_id: Option<String>,
    pub client_name: Option<String>,
    pub enabled: Option<bool>,
    pub grant_type: Option<String>,
    pub allowed_scope: Option<String>,
}

/// `ClientSortField`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientSortField {
    ClientId,
    ClientName,
    Enabled,
}

/// `ClientListItem`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientListItem {
    pub id: EntityId,
    pub client_id: String,
    pub client_name: Option<String>,
    pub enabled: bool,
    pub description: Option<String>,
    pub allowed_grant_types: Vec<String>,
    pub allowed_scope_count: usize,
    pub redirect_uri_count: usize,
}

fn parse(entity: &StoredEntity) -> Result<Client, StoreError> {
    serde_json::from_value(entity.data.clone())
        .map_err(|e| StoreError::Backend(format!("stored {}: {e}", entity.key)))
}

fn stored_secrets(entity: &StoredEntity) -> Vec<Value> {
    entity
        .data
        .get("clientSecrets")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// The runtime model as stored, with these secrets, the extended
/// properties, and their string values as the runtime `properties`.
fn data(
    client: &Client,
    secrets: Vec<Value>,
    extended_properties: &Map<String, Value>,
    properties: std::collections::BTreeMap<String, String>,
) -> Value {
    let client = Client {
        properties,
        ..client.clone()
    };
    let mut json = serde_json::to_value(&client).expect("a client serialises");
    if let Value::Object(object) = &mut json {
        object.insert("clientSecrets".into(), Value::Array(secrets));
        object.insert(
            "extendedProperties".into(),
            Value::Object(extended_properties.clone()),
        );
    }
    json
}

fn blank(values: &[String]) -> bool {
    values.iter().any(|v| v.trim().is_empty())
}

/// Grant types that can't be combined.
const EXCLUSIVE_GRANTS: [(&str, &str); 3] = [
    ("implicit", "authorization_code"),
    ("implicit", "hybrid"),
    ("authorization_code", "hybrid"),
];

/// `ClientAdmin`. `allow_unregistered_pushed_redirect_uris` is the server's
/// PAR option, which the configuration validator consults.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClientAdmin {
    pub allow_unregistered_pushed_redirect_uris: bool,
}

impl ClientAdmin {
    /// The checks on secrets created with a client.
    fn create_secrets(secrets: &[CreateSecret]) -> Option<AdminError> {
        for secret in secrets {
            if secret.plaintext_value.trim().is_empty() {
                return Some(AdminError::required("ClientSecrets.PlaintextValue"));
            }
            if secret
                .secret_type
                .as_deref()
                .is_some_and(|t| t.trim().is_empty())
            {
                return Some(AdminError::invalid_value(
                    "ClientSecrets.Type",
                    "Secret type must not be empty or whitespace.",
                ));
            }
        }
        None
    }

    /// The client structure validator.
    fn structure(client: &Client) -> Option<AdminError> {
        if client.client_id.trim().is_empty() {
            return Some(AdminError::required("ClientId"));
        }
        if client
            .client_name
            .as_deref()
            .is_some_and(|n| n.trim().is_empty())
        {
            return Some(AdminError::invalid_value(
                "ClientName",
                "Client name must not be empty or whitespace.",
            ));
        }
        let grants = &client.allowed_grant_types;
        if blank(grants) {
            return Some(AdminError::invalid_value(
                "AllowedGrantTypes",
                "Grant type must not be null or whitespace.",
            ));
        }
        if let Some(grant) = grants.iter().find(|g| g.contains(' ')) {
            return Some(AdminError::invalid_value(
                "AllowedGrantTypes",
                format!("Grant type '{grant}' contains spaces."),
            ));
        }
        let mut seen = HashSet::new();
        if !grants.iter().all(|g| seen.insert(g)) {
            return Some(AdminError::invalid_value(
                "AllowedGrantTypes",
                "Grant types list contains duplicate values.",
            ));
        }
        for (a, b) in EXCLUSIVE_GRANTS {
            if seen.contains(&a.to_owned()) && seen.contains(&b.to_owned()) {
                return Some(AdminError::validation_failed_on(
                    "AllowedGrantTypes",
                    format!("Grant types list cannot contain both {a} and {b}."),
                ));
            }
        }
        let lists = [
            (
                &client.allowed_scopes,
                "AllowedScopes",
                "Scope must not be null or whitespace.",
            ),
            (
                &client.allowed_cors_origins,
                "AllowedCorsOrigins",
                "CORS origin must not be null or whitespace.",
            ),
            (
                &client.redirect_uris,
                "RedirectUris",
                "Redirect URI must not be null or whitespace.",
            ),
            (
                &client.post_logout_redirect_uris,
                "PostLogoutRedirectUris",
                "Post-logout redirect URI must not be null or whitespace.",
            ),
        ];
        lists
            .into_iter()
            .find(|(values, _, _)| blank(values))
            .map(|(_, property, message)| AdminError::invalid_value(property, message))
    }

    /// The configuration validator over the client with these stored
    /// secrets, then the extended properties against the client schema; on
    /// success, the runtime `properties`.
    async fn configuration(
        &self,
        store: &dyn ConfigurationStore,
        client: &Client,
        secrets: &[Value],
        extended_properties: &Map<String, Value>,
    ) -> Result<Result<std::collections::BTreeMap<String, String>, AdminError>, StoreError> {
        let secrets = secrets
            .iter()
            .map(|s| serde_json::from_value::<Secret>(s.clone()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| StoreError::Backend(format!("stored secret: {e}")))?;
        let candidate = Client {
            client_secrets: secrets,
            ..client.clone()
        };
        if let Err(problem) =
            validate_client(&candidate, self.allow_unregistered_pushed_redirect_uris)
        {
            return Ok(Err(AdminError::validation_failed(problem)));
        }
        schemas::check_extended_properties(store, schemas::CLIENT_SCHEMA, extended_properties).await
    }

    pub async fn create(
        &self,
        store: &dyn ConfigurationStore,
        mut input: ClientInput,
    ) -> SaveResult {
        input.client.protocol_type = OIDC.to_owned();
        if let Some(error) =
            Self::create_secrets(&input.client_secrets).or_else(|| Self::structure(&input.client))
        {
            return Ok(Err(vec![error]));
        }
        let secrets: Vec<Value> = input
            .client_secrets
            .iter()
            .map(|s| secrets::new_secret(s).1)
            .collect();
        let properties = match self
            .configuration(store, &input.client, &secrets, &input.extended_properties)
            .await?
        {
            Ok(properties) => properties,
            Err(error) => return Ok(Err(vec![error])),
        };
        let entity = StoredEntity {
            id: EntityId::new_v7(),
            key: input.client.client_id.clone(),
            version: 1,
            data: data(
                &input.client,
                secrets,
                &input.extended_properties,
                properties,
            ),
        };
        Ok(match store.create(KIND, &entity).await? {
            CreateOutcome::Created => Ok(Saved {
                id: entity.id,
                version: 1,
            }),
            CreateOutcome::KeyExists => Err(vec![AdminError::already_exists(
                NAME,
                &input.client.client_id,
            )]),
        })
    }

    /// Saves a dynamically registered client as built, with its secrets
    /// already hashed (or `JWK`s as given): admin's structure checks, but
    /// not the configuration validator: registration saves what its
    /// validator built.
    pub async fn register(&self, store: &dyn ConfigurationStore, client: &Client) -> SaveResult {
        let client = Client {
            protocol_type: OIDC.to_owned(),
            ..client.clone()
        };
        if let Some(error) = Self::structure(&client) {
            return Ok(Err(vec![error]));
        }
        let secrets: Vec<Value> = client
            .client_secrets
            .iter()
            .map(|s| {
                let mut value = serde_json::to_value(s).expect("a secret serialises");
                // Shared secrets are SHA-256 hashes, named as admin names them.
                if s.secret_type != crate::clients::SECRET_TYPE_JWK
                    && let Value::Object(object) = &mut value
                {
                    object.insert(
                        "hashAlgorithm".into(),
                        Value::String(secrets::HashAlgorithm::Sha256.stored_name().into()),
                    );
                }
                value
            })
            .collect();
        let entity = StoredEntity {
            id: EntityId::new_v7(),
            key: client.client_id.clone(),
            version: 1,
            data: data(
                &Client {
                    client_secrets: Vec::new(),
                    ..client.clone()
                },
                secrets::with_ids(&secrets),
                &Map::new(),
                client.properties.clone(),
            ),
        };
        Ok(match store.create(KIND, &entity).await? {
            CreateOutcome::Created => Ok(Saved {
                id: entity.id,
                version: 1,
            }),
            CreateOutcome::KeyExists => {
                Err(vec![AdminError::already_exists(NAME, &client.client_id)])
            }
        })
    }

    /// The read with only the extended properties the schema still accepts.
    async fn readable(
        store: &dyn ConfigurationStore,
        found: Option<Versioned<ClientConfiguration>>,
    ) -> Result<Option<Versioned<ClientConfiguration>>, StoreError> {
        let Some(mut found) = found else {
            return Ok(None);
        };
        let values = std::mem::take(&mut found.item.extended_properties);
        found.item.extended_properties =
            schemas::readable_extended_properties(store, schemas::CLIENT_SCHEMA, values).await?;
        Ok(Some(found))
    }

    fn versioned(
        entity: Option<StoredEntity>,
    ) -> Result<Option<Versioned<ClientConfiguration>>, StoreError> {
        let Some(entity) = entity else {
            return Ok(None);
        };
        let client = Client {
            client_secrets: Vec::new(),
            properties: Default::default(),
            ..parse(&entity)?
        };
        Ok(Some(Versioned {
            id: entity.id,
            version: entity.version,
            item: ClientConfiguration {
                client,
                client_secrets: stored_secrets(&entity)
                    .iter()
                    .map(secrets::configuration)
                    .collect(),
                extended_properties: schemas::stored_extended_properties(&entity.data),
            },
        }))
    }

    pub async fn get(
        &self,
        store: &dyn ConfigurationStore,
        id: &EntityId,
    ) -> Result<Option<Versioned<ClientConfiguration>>, StoreError> {
        Self::readable(store, Self::versioned(store.read(KIND, id).await?)?).await
    }

    pub async fn get_by_client_id(
        &self,
        store: &dyn ConfigurationStore,
        client_id: &str,
    ) -> Result<Option<Versioned<ClientConfiguration>>, StoreError> {
        Self::readable(
            store,
            Self::versioned(store.read_by_key(KIND, client_id).await?)?,
        )
        .await
    }

    /// Saves `entity` at its version, mapping the outcome.
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

    /// Replaces the client, keeping its secrets; `input.client_secrets` is
    /// ignored.
    pub async fn update(
        &self,
        store: &dyn ConfigurationStore,
        id: &EntityId,
        mut input: ClientInput,
        expected_version: i32,
    ) -> SaveResult {
        input.client.protocol_type = OIDC.to_owned();
        if let Some(error) = Self::structure(&input.client) {
            return Ok(Err(vec![error]));
        }
        let Some(existing) = store.read(KIND, id).await? else {
            return Ok(Err(vec![AdminError::not_found(NAME, &id.to_string())]));
        };
        let secrets = secrets::with_ids(&stored_secrets(&existing));
        let mut properties = match self
            .configuration(store, &input.client, &secrets, &input.extended_properties)
            .await?
        {
            Ok(properties) => properties,
            Err(error) => return Ok(Err(vec![error])),
        };
        // A dynamically registered client's management properties (its
        // registration access token hash and metadata) aren't extended
        // properties: an admin update keeps them.
        properties.extend(
            parse(&existing)?
                .properties
                .into_iter()
                .filter(|(key, _)| key.starts_with(DCR_PROPERTY_PREFIX)),
        );
        let entity = StoredEntity {
            id: *id,
            key: input.client.client_id.clone(),
            version: expected_version,
            data: data(
                &input.client,
                secrets,
                &input.extended_properties,
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
            object.insert("clientSecrets".into(), Value::Array(secrets));
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
            return Ok(Err(vec![AdminError::required("PlaintextValue")]));
        }
        if input
            .secret_type
            .as_deref()
            .is_some_and(|t| t.trim().is_empty())
        {
            return Ok(Err(vec![AdminError::invalid_value(
                "Type",
                "Secret type must not be empty or whitespace.",
            )]));
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
        filter: &ClientFilter,
        sort: Option<(ClientSortField, Direction)>,
        range: &Range,
    ) -> Result<Result<QueryResult<ClientListItem>, AdminError>, StoreError> {
        let contains = |value: Option<&str>, part: &Option<String>| {
            part.as_deref()
                .is_none_or(|part| value.is_some_and(|v| v.contains(part)))
        };
        let has = |values: &[String], wanted: &Option<String>| {
            wanted
                .as_deref()
                .is_none_or(|wanted| values.iter().any(|v| v == wanted))
        };
        let mut items = Vec::new();
        for entity in store.list(KIND).await? {
            let client = parse(&entity)?;
            let matches = contains(Some(&client.client_id), &filter.client_id)
                && contains(client.client_name.as_deref(), &filter.client_name)
                && filter.enabled.is_none_or(|e| client.enabled == e)
                && has(&client.allowed_grant_types, &filter.grant_type)
                && has(&client.allowed_scopes, &filter.allowed_scope);
            if matches {
                items.push(ClientListItem {
                    id: entity.id,
                    allowed_scope_count: client.allowed_scopes.len(),
                    redirect_uri_count: client.redirect_uris.len(),
                    client_id: client.client_id,
                    client_name: client.client_name,
                    enabled: client.enabled,
                    description: client.description,
                    allowed_grant_types: client.allowed_grant_types,
                });
            }
        }
        let (field, direction) = sort.unwrap_or((ClientSortField::ClientId, Direction::Ascending));
        items.sort_by(|a, b| {
            let order = match field {
                ClientSortField::ClientId => a.client_id.cmp(&b.client_id),
                ClientSortField::ClientName => a.client_name.cmp(&b.client_name),
                ClientSortField::Enabled => a.enabled.cmp(&b.enabled),
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
