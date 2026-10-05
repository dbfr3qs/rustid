//! Store traits: what the protocol engine reads and writes, with no storage
//! types. `rustid-store-memory` and `rustid-store-postgres` implement them.
//! Each is a trait the memory and Postgres stores implement.

use std::sync::Arc;

use async_trait::async_trait;

use crate::clients::Client;
use crate::grants::{GrantFilter, PersistedGrant};
use crate::resources::{ApiResource, Resources};

/// A backend failure. The endpoints answer HTTP 500 when a
/// store throws.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    #[error("store backend failed: {0}")]
    Backend(String),
    /// A filter needs at least one criterion.
    #[error("a grant filter needs at least one of subject, session, client or type")]
    EmptyFilter,
    #[error("a signing key with id {0} is already stored")]
    DuplicateKey(String),
    #[error("a server-side session with key {0} is already stored")]
    DuplicateSession(String),
    /// The device or user
    /// code is taken.
    #[error("a device authorization with this device or user code is already stored")]
    DuplicateDeviceCode,
    #[error("no device authorization with this user code")]
    UnknownUserCode,
    /// A SAML sign-in state or logout session without an expiry (the store's
    /// message).
    #[error("{0}")]
    MissingExpiration(&'static str),
    #[error("a SAML logout session with id {0} is already stored")]
    DuplicateLogoutId(String),
}

/// The client store plus the CORS policy service, which reads the same data.
#[async_trait]
pub trait ClientStore: Send + Sync {
    /// The client whether or not it is enabled.
    async fn find_client_by_id(&self, client_id: &str) -> Result<Option<Arc<Client>>, StoreError>;

    /// Some client lists `origin` among its allowed
    /// CORS origins, compared case-insensitively with each configured URL's
    /// origin (scheme, host and non-default port).
    async fn is_cors_origin_allowed(&self, origin: &str) -> Result<bool, StoreError>;
}

/// The client store.
pub async fn find_enabled_client(
    store: &dyn ClientStore,
    client_id: &str,
) -> Result<Option<Arc<Client>>, StoreError> {
    Ok(store
        .find_client_by_id(client_id)
        .await?
        .filter(|client| client.enabled))
}

/// The resource store. The engine reads the enabled set and API resources by
/// name; the other lookups are over every resource.
#[async_trait]
pub trait ResourceStore: Send + Sync {
    /// Get all enabled resources, in store order.
    async fn get_all_enabled_resources(&self) -> Result<Arc<Resources>, StoreError>;

    /// Enabled or not, in store order.
    async fn find_api_resources_by_name(
        &self,
        names: &[String],
    ) -> Result<Vec<ApiResource>, StoreError>;

    /// Every resource, enabled or not, in store
    /// order.
    async fn get_all_resources(&self) -> Result<Arc<Resources>, StoreError>;

    /// Enabled or not.
    async fn find_identity_resources_by_scope_name(
        &self,
        names: &[String],
    ) -> Result<Vec<crate::resources::IdentityResource>, StoreError> {
        if names.is_empty() {
            return Ok(Vec::new());
        }
        Ok(self
            .get_all_resources()
            .await?
            .identity_resources
            .iter()
            .filter(|r| names.contains(&r.name))
            .cloned()
            .collect())
    }

    /// Enabled or not.
    async fn find_api_scopes_by_name(
        &self,
        names: &[String],
    ) -> Result<Vec<crate::resources::ApiScope>, StoreError> {
        if names.is_empty() {
            return Ok(Vec::new());
        }
        Ok(self
            .get_all_resources()
            .await?
            .api_scopes
            .iter()
            .filter(|s| names.contains(&s.name))
            .cloned()
            .collect())
    }

    /// The API resources with any of
    /// the scopes, enabled or not.
    async fn find_api_resources_by_scope_name(
        &self,
        scope_names: &[String],
    ) -> Result<Vec<ApiResource>, StoreError> {
        if scope_names.is_empty() {
            return Ok(Vec::new());
        }
        Ok(self
            .get_all_resources()
            .await?
            .api_resources
            .iter()
            .filter(|a| a.scopes.iter().any(|s| scope_names.contains(s)))
            .cloned()
            .collect())
    }
}

/// The persisted grant store. Keys are already hashed (see `grants::hashed_key`).
#[async_trait]
pub trait PersistedGrantStore: Send + Sync {
    /// Inserts or replaces the grant with the same key.
    async fn store(&self, grant: PersistedGrant) -> Result<(), StoreError>;

    async fn get(&self, key: &str) -> Result<Option<PersistedGrant>, StoreError>;

    /// Every grant matching the filter; `EmptyFilter` when it has no criteria.
    async fn get_all(&self, filter: &GrantFilter) -> Result<Vec<PersistedGrant>, StoreError>;

    async fn remove(&self, key: &str) -> Result<(), StoreError>;

    /// Removes the grant and returns it, atomically: of two concurrent
    /// takes of one key, exactly one gets the grant. One-time grants
    /// (authorization codes, interaction continuations) are redeemed this way.
    async fn take(&self, key: &str) -> Result<Option<PersistedGrant>, StoreError>;

    /// Removes every grant matching the filter; `EmptyFilter` when it has
    /// no criteria.
    async fn remove_all(&self, filter: &GrantFilter) -> Result<(), StoreError>;

    /// Removes up to `batch` grants expired at `now` and, when
    /// `consumed_before` is set, consumed before it; how many.
    async fn remove_expired(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        batch: usize,
        consumed_before: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<u64, StoreError>;
}

/// A configuration entity's kind: which table, or list, it lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntityKind {
    IdentityResource,
    ApiScope,
    ApiResource,
    Client,
    /// A data extension schema, keyed by its lower-cased id.
    Schema,
    /// A SAML service provider, keyed by entity id.
    SamlServiceProvider,
}

impl EntityKind {
    /// The name errors give the kind.
    pub fn error_name(self) -> &'static str {
        match self {
            EntityKind::IdentityResource => "identity_resource",
            EntityKind::ApiScope => "api_scope",
            EntityKind::ApiResource => "api_resource",
            EntityKind::Client => "client",
            EntityKind::Schema => "schema",
            EntityKind::SamlServiceProvider => "saml_service_provider",
        }
    }
}

/// A configuration entity as stored: its admin id, natural key (name or
/// client id), version, and its runtime model as JSON (the format of
/// `resources_file` and `clients_file`).
#[derive(Debug, Clone, PartialEq)]
pub struct StoredEntity {
    pub id: crate::admin::EntityId,
    pub key: String,
    pub version: i32,
    pub data: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateOutcome {
    Created,
    /// Another entity of the kind has the key.
    KeyExists,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateOutcome {
    Updated,
    UnexpectedVersion,
    DoesNotExist,
    /// Another entity of the kind has the new key.
    KeyConflict,
}

/// The configuration entities admin edits and the runtime stores serve.
#[async_trait]
pub trait ConfigurationStore: Send + Sync {
    async fn create(
        &self,
        kind: EntityKind,
        entity: &StoredEntity,
    ) -> Result<CreateOutcome, StoreError>;

    async fn read(
        &self,
        kind: EntityKind,
        id: &crate::admin::EntityId,
    ) -> Result<Option<StoredEntity>, StoreError>;

    async fn read_by_key(
        &self,
        kind: EntityKind,
        key: &str,
    ) -> Result<Option<StoredEntity>, StoreError>;

    /// Saves `entity` if it is still at `entity.version`; it becomes
    /// version + 1.
    async fn update(
        &self,
        kind: EntityKind,
        entity: &StoredEntity,
    ) -> Result<UpdateOutcome, StoreError>;

    /// Idempotent.
    async fn delete(&self, kind: EntityKind, id: &crate::admin::EntityId)
    -> Result<(), StoreError>;

    /// Every entity of the kind, in configuration order.
    async fn list(&self, kind: EntityKind) -> Result<Vec<StoredEntity>, StoreError>;
}

/// The server side session store.
#[async_trait]
pub trait ServerSideSessionStore: Send + Sync {
    /// Adds a session; `DuplicateSession` when the key exists.
    async fn create_session(
        &self,
        session: crate::server_side_sessions::ServerSideSession,
    ) -> Result<(), StoreError>;

    async fn get_session(
        &self,
        key: &str,
    ) -> Result<Option<crate::server_side_sessions::ServerSideSession>, StoreError>;

    /// Replaces the session with the same key, or adds it.
    async fn update_session(
        &self,
        session: crate::server_side_sessions::ServerSideSession,
    ) -> Result<(), StoreError>;

    async fn delete_session(&self, key: &str) -> Result<(), StoreError>;

    /// Sessions matching the filter; `EmptyFilter` when it has no criteria.
    async fn get_sessions(
        &self,
        filter: &crate::server_side_sessions::SessionFilter,
    ) -> Result<Vec<crate::server_side_sessions::ServerSideSession>, StoreError>;

    /// Deletes the sessions matching the filter; `EmptyFilter` when it has
    /// no criteria.
    async fn delete_sessions(
        &self,
        filter: &crate::server_side_sessions::SessionFilter,
    ) -> Result<(), StoreError>;

    /// Moves up to `count` sessions that expired before `now`, in key
    /// order, into the outbox as `session_expired` events, in one step
    /// (one transaction in Postgres); how many. Concurrent callers never
    /// move the same session.
    async fn move_expired_to_outbox(
        &self,
        count: usize,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<usize, StoreError>;

    /// A page of the sessions the query matches.
    async fn query_sessions(
        &self,
        query: &crate::server_side_sessions::SessionQuery,
    ) -> Result<
        crate::server_side_sessions::QueryResult<crate::server_side_sessions::ServerSideSession>,
        StoreError,
    >;
}

// A shared store is a store, so decorators can wrap `Arc<dyn ...>`.

#[async_trait]
impl<T: ClientStore + ?Sized> ClientStore for Arc<T> {
    async fn find_client_by_id(&self, client_id: &str) -> Result<Option<Arc<Client>>, StoreError> {
        (**self).find_client_by_id(client_id).await
    }

    async fn is_cors_origin_allowed(&self, origin: &str) -> Result<bool, StoreError> {
        (**self).is_cors_origin_allowed(origin).await
    }
}

#[async_trait]
impl<T: ResourceStore + ?Sized> ResourceStore for Arc<T> {
    async fn get_all_enabled_resources(&self) -> Result<Arc<Resources>, StoreError> {
        (**self).get_all_enabled_resources().await
    }

    async fn find_api_resources_by_name(
        &self,
        names: &[String],
    ) -> Result<Vec<ApiResource>, StoreError> {
        (**self).find_api_resources_by_name(names).await
    }

    async fn get_all_resources(&self) -> Result<Arc<Resources>, StoreError> {
        (**self).get_all_resources().await
    }
}

#[async_trait]
impl<T: ConfigurationStore + ?Sized> ConfigurationStore for Arc<T> {
    async fn create(
        &self,
        kind: EntityKind,
        entity: &StoredEntity,
    ) -> Result<CreateOutcome, StoreError> {
        (**self).create(kind, entity).await
    }

    async fn read(
        &self,
        kind: EntityKind,
        id: &crate::admin::EntityId,
    ) -> Result<Option<StoredEntity>, StoreError> {
        (**self).read(kind, id).await
    }

    async fn read_by_key(
        &self,
        kind: EntityKind,
        key: &str,
    ) -> Result<Option<StoredEntity>, StoreError> {
        (**self).read_by_key(kind, key).await
    }

    async fn update(
        &self,
        kind: EntityKind,
        entity: &StoredEntity,
    ) -> Result<UpdateOutcome, StoreError> {
        (**self).update(kind, entity).await
    }

    async fn delete(
        &self,
        kind: EntityKind,
        id: &crate::admin::EntityId,
    ) -> Result<(), StoreError> {
        (**self).delete(kind, id).await
    }

    async fn list(&self, kind: EntityKind) -> Result<Vec<StoredEntity>, StoreError> {
        (**self).list(kind).await
    }
}

/// A signing key as stored: the key material in `data`, protected when
/// `data_protected` is set. the `SerializedKey`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SerializedKey {
    pub version: i32,
    pub id: String,
    pub created: chrono::DateTime<chrono::Utc>,
    pub algorithm: String,
    pub is_x509_certificate: bool,
    pub data: String,
    pub data_protected: bool,
}

/// The signing key store.
#[async_trait]
pub trait SigningKeyStore: Send + Sync {
    async fn load_keys(&self) -> Result<Vec<SerializedKey>, StoreError>;

    /// Fails with `StoreError::DuplicateKey` when a key with the id exists.
    async fn store_key(&self, key: SerializedKey) -> Result<(), StoreError>;

    /// Deleting a missing key succeeds.
    async fn delete_key(&self, id: &str) -> Result<(), StoreError>;
}

/// Device authorizations (the serialized `DeviceCode`),
/// keyed by the hash of the device code and of the user code.
#[async_trait]
pub trait DeviceFlowStore: Send + Sync {
    /// `DuplicateDeviceCode` when either code is taken.
    #[allow(clippy::too_many_arguments)]
    async fn store_device_authorization(
        &self,
        device_code: &str,
        user_code: &str,
        client_id: &str,
        creation_time: chrono::DateTime<chrono::Utc>,
        expiration: chrono::DateTime<chrono::Utc>,
        data: &str,
    ) -> Result<(), StoreError>;

    async fn find_by_user_code(&self, user_code: &str) -> Result<Option<String>, StoreError>;

    async fn find_by_device_code(&self, device_code: &str) -> Result<Option<String>, StoreError>;

    /// Replaces the data; `UnknownUserCode` when there is none.
    async fn update_by_user_code(
        &self,
        user_code: &str,
        subject_id: Option<&str>,
        data: &str,
    ) -> Result<(), StoreError>;

    /// Removes the authorization, atomically: `true` only for the caller
    /// that removed it.
    async fn remove_by_device_code(&self, device_code: &str) -> Result<bool, StoreError>;

    /// Removes authorizations that expired before `now` (the token cleanup
    /// job's device codes); how many.
    async fn remove_expired(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        batch: usize,
    ) -> Result<u64, StoreError>;
}

/// Whether a device code is polled faster
/// than its interval. Each poll refreshes the last-seen time.
#[async_trait]
pub trait DeviceFlowThrottling: Send + Sync {
    /// `true` when `device_code` was last polled less than `interval`
    /// seconds before `now`; remembered for `lifetime` seconds.
    async fn should_slow_down(
        &self,
        device_code: &str,
        interval: i64,
        lifetime: i64,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, StoreError>;

    /// Removes up to `batch` entries forgotten by `now`; how many.
    async fn remove_expired(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        batch: usize,
    ) -> Result<u64, StoreError>;
}

/// The distributed device flow throttling service over an in-process cache.
#[derive(Debug, Default)]
pub struct InMemoryDeviceFlowThrottling {
    /// Device code to (last seen, forget after), Unix milliseconds.
    seen: std::sync::Mutex<std::collections::HashMap<String, (i64, i64)>>,
}

#[async_trait]
impl DeviceFlowThrottling for InMemoryDeviceFlowThrottling {
    async fn should_slow_down(
        &self,
        device_code: &str,
        interval: i64,
        lifetime: i64,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, StoreError> {
        let now = now.timestamp_millis();
        let (interval, lifetime) = (interval * 1000, lifetime * 1000);
        let mut seen = self
            .seen
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        seen.retain(|_, (_, forget)| *forget > now);
        let previous = seen.insert(device_code.to_owned(), (now, now + lifetime));
        Ok(previous.is_some_and(|(last, _)| now < last + interval))
    }

    async fn remove_expired(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        batch: usize,
    ) -> Result<u64, StoreError> {
        let now = now.timestamp_millis();
        let mut seen = self
            .seen
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let forgotten: Vec<String> = seen
            .iter()
            .filter(|(_, (_, forget))| *forget <= now)
            .map(|(k, _)| k.clone())
            .take(batch)
            .collect();
        for key in &forgotten {
            seen.remove(key);
        }
        Ok(forgotten.len() as u64)
    }
}

/// The stores the engine uses, wired once at startup.
#[derive(Clone)]
pub struct Stores {
    pub clients: Arc<dyn ClientStore>,
    pub resources: Arc<dyn ResourceStore>,
    pub grants: Arc<dyn PersistedGrantStore>,
    pub device_flow: Arc<dyn DeviceFlowStore>,
    pub device_throttling: Arc<dyn DeviceFlowThrottling>,
    /// One-time values (client assertion and DPoP proof `jti`s).
    pub replay: Arc<dyn crate::replay::ReplayCache>,
    /// Configuration entities for admin (identity resources, API scopes, API
    /// resources, clients); `resources` serves the same data.
    pub configuration: Arc<dyn ConfigurationStore>,
    /// Not a store, but injected the same way: the default profile service,
    /// or hooks replacing it.
    pub profile: Arc<dyn crate::profile::ProfileService>,
    /// Likewise: the custom token request validator.
    pub token_request: Arc<dyn crate::token_request::TokenRequestValidator>,
    /// Likewise: how request objects are fetched by reference.
    pub request_uri: Arc<dyn crate::request_uri::RequestUriFetcher>,
    /// Likewise: how back-channel logout tokens are posted.
    pub back_channel: Arc<dyn crate::logout::BackChannelSender>,
    /// Likewise: the CIBA user validator, notification and custom validator.
    pub ciba: Arc<dyn crate::ciba::CibaService>,
    /// Likewise: the password and extension grant validators.
    pub grant_validation: Arc<dyn crate::grant_validation::GrantValidator>,
    /// Server-side sessions, when enabled.
    pub sessions: Option<Arc<crate::server_side_sessions::ServerSideSessions>>,
}

impl std::fmt::Debug for Stores {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Stores { .. }")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Full timestamps are compared: polls a fraction of a second
    /// apart across a second boundary are still too fast, and a poll a full
    /// interval later is not.
    #[tokio::test]
    async fn throttling_is_not_rounded_to_seconds() {
        let throttling = InMemoryDeviceFlowThrottling::default();
        let t0 = chrono::DateTime::from_timestamp_millis(10_900).unwrap();
        let t1 = chrono::DateTime::from_timestamp_millis(11_050).unwrap();
        let t2 = chrono::DateTime::from_timestamp_millis(12_100).unwrap();
        assert!(!throttling.should_slow_down("c", 1, 60, t0).await.unwrap());
        assert!(throttling.should_slow_down("c", 1, 60, t1).await.unwrap());
        assert!(!throttling.should_slow_down("c", 1, 60, t2).await.unwrap());
    }
}
