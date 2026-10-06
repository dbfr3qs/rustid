//! Upstream identity providers as configuration entities, keyed by scheme.
//! Secrets and private keys given inline are stored encrypted with data
//! protection and never read back: reads say only whether there is one.

use std::sync::Arc;

use serde::Serialize;
use serde_json::{Map, Value};

use super::query::{Direction, QueryResult, Range, paginate};
use super::{AdminError, EntityId, SaveResult, Saved, Versioned};
use crate::data_protection::DataProtector;
use crate::federation::provider::{IdentityProvider, Provider, resolve_credential};
use crate::stores::{
    ConfigurationStore, CreateOutcome, EntityKind, StoreError, StoredEntity, UpdateOutcome,
};

const KIND: EntityKind = EntityKind::IdentityProvider;
const NAME: &str = "Identity provider";
/// The data protection purpose of stored secrets and keys.
pub const SECRET_PURPOSE: &str = "rustid.federation.secret";

/// A provider as an admin call sends it.
#[derive(Debug, Clone, PartialEq)]
pub struct IdentityProviderInput(pub IdentityProvider);

impl IdentityProviderInput {
    /// The JSON of a provider; unknown members are refused.
    pub fn from_json(body: Value) -> Result<Self, AdminError> {
        serde_json::from_value(body)
            .map(IdentityProviderInput)
            .map_err(|e| AdminError::validation_failed(input_error(&e)))
    }
}

/// What was wrong with a provider's JSON, naming members but never
/// repeating a value, which may be a secret sent in the wrong place.
fn input_error(error: &serde_json::Error) -> String {
    let text = error.to_string();
    if ["unknown field", "missing field", "duplicate field"]
        .iter()
        .any(|prefix| text.starts_with(prefix))
    {
        return text;
    }
    match text.split_once(", expected ") {
        Some((_, expected)) => format!("a member has the wrong type or value: expected {expected}"),
        None => "a member has the wrong type or value".to_owned(),
    }
}

/// A provider as reads show it: the configuration without its secret or
/// private key, and `hasSecret` and `hasKey` instead.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(transparent)]
pub struct IdentityProviderConfiguration(pub Value);

/// Scheme and display name substrings, and enabled or not.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IdentityProviderFilter {
    pub scheme: Option<String>,
    pub display_name: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityProviderSortField {
    Scheme,
    DisplayName,
    Enabled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityProviderListItem {
    pub id: EntityId,
    pub scheme: String,
    pub display_name: String,
    pub enabled: bool,
    pub authority: String,
}

/// A stored provider opened: its configuration with the secret and key
/// back in place.
struct Opened {
    config: IdentityProvider,
}

fn backend(message: impl Into<String>) -> StoreError {
    StoreError::Backend(message.into())
}

/// The stored form: the configuration, with an inline secret and key
/// replaced by their protected forms.
fn sealed(config: &IdentityProvider, protector: &DataProtector) -> Value {
    let mut data = serde_json::to_value(config).expect("a provider serializes");
    let auth = data["clientAuthentication"]
        .as_object_mut()
        .expect("client authentication is an object");
    for (plain, protected) in [("secret", "secretProtected"), ("key", "keyProtected")] {
        if let Some(Value::String(value)) = auth.remove(plain) {
            auth.insert(
                protected.into(),
                protector.protect(SECRET_PURPOSE, value.as_bytes()).into(),
            );
        }
    }
    data
}

/// The configuration a stored provider holds, secret and key opened.
fn opened(entity: &StoredEntity, protector: &DataProtector) -> Result<Opened, StoreError> {
    let mut data = entity.data.clone();
    let auth = data["clientAuthentication"]
        .as_object_mut()
        .ok_or_else(|| backend("a stored identity provider has no clientAuthentication"))?;
    for (plain, protected) in [("secret", "secretProtected"), ("key", "keyProtected")] {
        if let Some(Value::String(value)) = auth.remove(protected) {
            let bytes = protector
                .unprotect(SECRET_PURPOSE, &value)
                .map_err(|_| backend(format!("identity provider {}: its {plain} can't be opened with the data protection keys", entity.key)))?;
            let text = String::from_utf8(bytes).map_err(|_| {
                backend(format!(
                    "identity provider {}: its {plain} isn't text",
                    entity.key
                ))
            })?;
            auth.insert(plain.into(), text.into());
        }
    }
    let config: IdentityProvider = serde_json::from_value(data)
        .map_err(|e| backend(format!("identity provider {}: {e}", entity.key)))?;
    Ok(Opened { config })
}

/// A stored provider, ready to use: its configuration and resolved
/// credential. File paths in it are absolute by the time it is stored.
pub fn resolve(
    entity: &StoredEntity,
    protector: &DataProtector,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Provider, String> {
    let config = opened(entity, protector).map_err(|e| e.to_string())?.config;
    let credential = resolve_credential(&config, std::path::Path::new("/"), env)
        .map_err(|e| format!("identity provider {}: {e}", config.scheme))?;
    Ok(Provider { config, credential })
}

/// The read form: no secret or key, and whether there is one.
fn configuration(config: &IdentityProvider) -> IdentityProviderConfiguration {
    let mut data = serde_json::to_value(config).expect("a provider serializes");
    let auth: &mut Map<String, Value> = data["clientAuthentication"]
        .as_object_mut()
        .expect("client authentication is an object");
    let has_secret = auth.remove("secret").is_some();
    let has_key = auth.remove("key").is_some();
    auth.insert("hasSecret".into(), has_secret.into());
    auth.insert("hasKey".into(), has_key.into());
    IdentityProviderConfiguration(data)
}

/// Reads an environment variable, for `secretEnv`.
type Env = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// The admin service for identity providers.
pub struct IdentityProviderAdmin {
    protector: Arc<DataProtector>,
    allow_insecure_loopback: bool,
    inline_secrets: bool,
    env: Env,
}

impl IdentityProviderAdmin {
    /// Secrets are protected with `protector`; `secretEnv` names are read
    /// from the process environment.
    pub fn new(protector: Arc<DataProtector>) -> Self {
        IdentityProviderAdmin {
            protector,
            allow_insecure_loopback: false,
            inline_secrets: true,
            env: Arc::new(|name| std::env::var(name).ok()),
        }
    }

    /// Accepts `http://localhost` authorities too, as
    /// `[federation] allow_insecure_loopback` does.
    pub fn with_insecure_loopback(mut self, allow: bool) -> Self {
        self.allow_insecure_loopback = allow;
        self
    }

    /// Refuses secrets and keys given inline, for a store that outlives a
    /// data protection key that isn't configured (Postgres with a
    /// per-process key): they couldn't be read after a restart.
    pub fn with_inline_secrets(mut self, allow: bool) -> Self {
        self.inline_secrets = allow;
        self
    }

    /// The provider rules, then its credential must resolve.
    fn check(&self, config: &IdentityProvider) -> Option<AdminError> {
        let auth = &config.client_authentication;
        // An environment variable or a file would be read on the admin's
        // behalf and sent to a provider the admin chose: those forms are
        // for identity_providers_file only.
        if auth.secret_env.is_some() || auth.key_file.is_some() || auth.certificate_file.is_some() {
            return Some(AdminError::validation_failed(
                "secretEnv, keyFile and certificateFile can only be set in identity_providers_file; give the secret, key or certificate itself.",
            ));
        }
        if !self.inline_secrets && (auth.secret.is_some() || auth.key.is_some()) {
            return Some(AdminError::validation_failed(
                "Storing a secret or key needs data_protection.keys to be configured; use secretEnv or keyFile instead.",
            ));
        }
        if let Err(error) = config.validate(self.allow_insecure_loopback) {
            return Some(AdminError::validation_failed(error.to_string()));
        }
        resolve_credential(config, std::path::Path::new("/"), &*self.env)
            .err()
            .map(AdminError::validation_failed)
    }

    pub async fn create(
        &self,
        store: &dyn ConfigurationStore,
        input: IdentityProviderInput,
    ) -> SaveResult {
        let config = input.0;
        if let Some(error) = self.check(&config) {
            return Ok(Err(vec![error]));
        }
        let entity = StoredEntity {
            id: EntityId::new_v7(),
            key: config.scheme.clone(),
            version: 1,
            data: sealed(&config, &self.protector),
        };
        Ok(match store.create(KIND, &entity).await? {
            CreateOutcome::Created => Ok(Saved {
                id: entity.id,
                version: 1,
            }),
            CreateOutcome::KeyExists => Err(vec![AdminError::already_exists(NAME, &config.scheme)]),
        })
    }

    fn versioned(
        &self,
        entity: Option<StoredEntity>,
    ) -> Result<Option<Versioned<IdentityProviderConfiguration>>, StoreError> {
        let Some(entity) = entity else {
            return Ok(None);
        };
        let config = opened(&entity, &self.protector)?.config;
        Ok(Some(Versioned {
            id: entity.id,
            version: entity.version,
            item: configuration(&config),
        }))
    }

    pub async fn get(
        &self,
        store: &dyn ConfigurationStore,
        id: &EntityId,
    ) -> Result<Option<Versioned<IdentityProviderConfiguration>>, StoreError> {
        self.versioned(store.read(KIND, id).await?)
    }

    pub async fn get_by_scheme(
        &self,
        store: &dyn ConfigurationStore,
        scheme: &str,
    ) -> Result<Option<Versioned<IdentityProviderConfiguration>>, StoreError> {
        self.versioned(store.read_by_key(KIND, scheme).await?)
    }

    /// Replaces the provider. Its scheme can't change. A secret or key not
    /// sent is kept, when the method is the same and nothing else (an
    /// environment variable, a file) replaces it.
    pub async fn update(
        &self,
        store: &dyn ConfigurationStore,
        id: &EntityId,
        input: IdentityProviderInput,
        expected_version: i32,
    ) -> SaveResult {
        let mut config = input.0;
        let Some(existing) = store.read(KIND, id).await? else {
            return Ok(Err(vec![AdminError::not_found(NAME, &id.to_string())]));
        };
        if config.scheme != existing.key {
            return Ok(Err(vec![AdminError::invalid_value(
                "Scheme",
                "The scheme of an identity provider can't change.",
            )]));
        }
        let previous = opened(&existing, &self.protector)?.config;
        let (new, old) = (
            &mut config.client_authentication,
            &previous.client_authentication,
        );
        if new.method == old.method {
            if new.secret.is_none() && new.secret_env.is_none() {
                new.secret.clone_from(&old.secret);
            }
            if new.key.is_none() && new.key_file.is_none() {
                new.key.clone_from(&old.key);
            }
        }
        if let Some(error) = self.check(&config) {
            return Ok(Err(vec![error]));
        }
        let entity = StoredEntity {
            id: *id,
            key: config.scheme.clone(),
            version: expected_version,
            data: sealed(&config, &self.protector),
        };
        Ok(match store.update(KIND, &entity).await? {
            UpdateOutcome::Updated => Ok(Saved {
                id: *id,
                version: expected_version + 1,
            }),
            UpdateOutcome::UnexpectedVersion => Err(vec![AdminError::version_conflict()]),
            UpdateOutcome::DoesNotExist => Err(vec![AdminError::not_found(NAME, &id.to_string())]),
            UpdateOutcome::KeyConflict => {
                Err(vec![AdminError::already_exists(NAME, &config.scheme)])
            }
        })
    }

    /// Idempotent: version 0.
    pub async fn delete(&self, store: &dyn ConfigurationStore, id: &EntityId) -> SaveResult {
        store.delete(KIND, id).await?;
        Ok(Ok(Saved {
            id: *id,
            version: 0,
        }))
    }

    pub async fn query(
        &self,
        store: &dyn ConfigurationStore,
        filter: &IdentityProviderFilter,
        sort: Option<(IdentityProviderSortField, Direction)>,
        range: &Range,
    ) -> Result<Result<QueryResult<IdentityProviderListItem>, AdminError>, StoreError> {
        let contains = |value: &str, part: &Option<String>| {
            part.as_deref().is_none_or(|part| value.contains(part))
        };
        let mut items = Vec::new();
        for entity in store.list(KIND).await? {
            // One that can't be opened is left out of lists; reading it
            // by itself says why.
            let config = match opened(&entity, &self.protector) {
                Ok(opened) => opened.config,
                Err(error) => {
                    tracing::warn!(scheme = %entity.key, %error, "identity provider left out of the list: it can't be read");
                    continue;
                }
            };
            if contains(&config.scheme, &filter.scheme)
                && contains(&config.display_name, &filter.display_name)
                && filter.enabled.is_none_or(|e| config.enabled == e)
            {
                items.push(IdentityProviderListItem {
                    id: entity.id,
                    scheme: config.scheme,
                    display_name: config.display_name,
                    enabled: config.enabled,
                    authority: config.authority,
                });
            }
        }
        let (field, direction) =
            sort.unwrap_or((IdentityProviderSortField::Scheme, Direction::Ascending));
        items.sort_by(|a, b| {
            let order = match field {
                IdentityProviderSortField::Scheme => a.scheme.cmp(&b.scheme),
                IdentityProviderSortField::DisplayName => a.display_name.cmp(&b.display_name),
                IdentityProviderSortField::Enabled => a.enabled.cmp(&b.enabled),
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

/// Imports providers from the configuration file: each is created, or
/// updated when it differs from the stored one (compared opened, since a
/// secret is sealed afresh each time), so an unchanged file keeps versions.
/// Providers the file doesn't name are kept, after the file's in order.
/// Another instance importing at the same moment (a create or update
/// that lost) is retried once.
pub async fn import(
    store: &dyn ConfigurationStore,
    protector: &DataProtector,
    providers: &[IdentityProvider],
) -> Result<(), StoreError> {
    if let Err(lost) = import_once(store, protector, providers).await? {
        tracing::info!(scheme = %lost, "identity provider import raced another instance; trying again");
        if let Err(lost) = import_once(store, protector, providers).await? {
            return Err(backend(format!(
                "importing identity provider {lost}: it changed meanwhile"
            )));
        }
    }
    let schemes: Vec<String> = providers.iter().map(|p| p.scheme.clone()).collect();
    store.reorder(KIND, &schemes).await
}

/// One import pass; `Ok(Err(scheme))` when another writer got there first.
async fn import_once(
    store: &dyn ConfigurationStore,
    protector: &DataProtector,
    providers: &[IdentityProvider],
) -> Result<Result<(), String>, StoreError> {
    for config in providers {
        match store.read_by_key(KIND, &config.scheme).await? {
            Some(existing) => {
                if opened(&existing, protector)
                    .map(|o| o.config == *config)
                    .unwrap_or(false)
                {
                    continue;
                }
                let entity = StoredEntity {
                    id: existing.id,
                    key: config.scheme.clone(),
                    version: existing.version,
                    data: sealed(config, protector),
                };
                match store.update(KIND, &entity).await? {
                    UpdateOutcome::Updated => {}
                    UpdateOutcome::UnexpectedVersion => return Ok(Err(config.scheme.clone())),
                    other => {
                        return Err(backend(format!(
                            "importing identity provider {}: {other:?}",
                            config.scheme
                        )));
                    }
                }
            }
            None => {
                let entity = StoredEntity {
                    id: EntityId::new_v7(),
                    key: config.scheme.clone(),
                    version: 1,
                    data: sealed(config, protector),
                };
                if store.create(KIND, &entity).await? == CreateOutcome::KeyExists {
                    return Ok(Err(config.scheme.clone()));
                }
            }
        }
    }
    Ok(Ok(()))
}
