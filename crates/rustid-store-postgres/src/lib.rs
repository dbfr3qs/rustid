#![forbid(unsafe_code)]

//! Postgres implementations of the store traits, with embedded migrations.
//!
//! Clients and resources are stored as the fixture-format JSON they were
//! imported with, next to typed columns for lookups, so later phases can read
//! more properties without a data migration.

mod configuration;
mod device_flow;
mod outbox;
mod replay;
mod saml;
mod sessions;
mod throttling;

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rustid_core::clients::{Client, url_origin};
use rustid_core::grants::{GrantFilter, PersistedGrant};
use rustid_core::resources::{ApiResource, ApiScope, IdentityResource, Resources};
use rustid_core::stores::{ClientStore, PersistedGrantStore, ResourceStore, StoreError};
use serde_json::Value;
use sqlx::migrate::MigrateDatabase;
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::{Postgres, Row};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[derive(Debug, thiserror::Error)]
pub enum PgError {
    #[error("database: {0}")]
    Database(#[from] sqlx::Error),
    #[error("migrating the database: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("{kind} {index} in the import is not a valid model: {source}")]
    InvalidModel {
        kind: &'static str,
        index: usize,
        source: serde_json::Error,
    },
    #[error("the import names {kind} {name} more than once")]
    Duplicate { kind: &'static str, name: String },
    #[error("the resources are not in the resources file format: {0}")]
    InvalidResources(serde_json::Error),
}

fn backend(error: impl std::fmt::Display) -> StoreError {
    StoreError::Backend(error.to_string())
}

/// One connection pool serving every store.
#[derive(Debug, Clone)]
pub struct PgStore {
    pool: PgPool,
}

impl PgStore {
    /// Connects, creating the database first when `create_database` is set
    /// and it doesn't exist.
    pub async fn connect(
        url: &str,
        max_connections: u32,
        create_database: bool,
    ) -> Result<Self, PgError> {
        if create_database && !Postgres::database_exists(url).await? {
            Postgres::create_database(url).await?;
        }
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .connect(url)
            .await?;
        Ok(PgStore { pool })
    }

    /// Applies the embedded migrations that haven't run yet.
    pub async fn migrate(&self) -> Result<(), PgError> {
        MIGRATOR.run(&self.pool).await?;
        Ok(())
    }

    pub async fn close(&self) {
        self.pool.close().await;
    }

    /// Inserts or replaces clients given as fixture-format JSON objects, in
    /// one transaction. Each must deserialize as a `Client`.
    pub async fn import_clients(&self, clients: &[Value]) -> Result<(), PgError> {
        let mut seen = std::collections::HashSet::new();
        for raw in clients {
            if let Some(id) = raw.get("clientId").and_then(Value::as_str)
                && !seen.insert(id)
            {
                return Err(PgError::Duplicate {
                    kind: "client",
                    name: id.to_owned(),
                });
            }
        }
        let mut tx = self.pool.begin().await?;
        for (index, raw) in clients.iter().enumerate() {
            let client: Client =
                serde_json::from_value(raw.clone()).map_err(|source| PgError::InvalidModel {
                    kind: "client",
                    index,
                    source,
                })?;
            sqlx::query(
                "INSERT INTO clients (client_id, enabled, data, id) VALUES ($1, $2, $3, $4::uuid)
                 ON CONFLICT (client_id) DO UPDATE
                 SET enabled = EXCLUDED.enabled, data = EXCLUDED.data, updated = now(),
                     version = CASE WHEN clients.data IS DISTINCT FROM EXCLUDED.data
                                    THEN clients.version + 1 ELSE clients.version END",
            )
            .bind(&client.client_id)
            .bind(client.enabled)
            .bind(raw)
            .bind(rustid_core::admin::EntityId::new_v7().to_string())
            .execute(&mut *tx)
            .await?;
            sqlx::query("DELETE FROM client_cors_origins WHERE client_id = $1")
                .bind(&client.client_id)
                .execute(&mut *tx)
                .await?;
            let mut origins: Vec<String> = client
                .allowed_cors_origins
                .iter()
                .filter_map(|url| url_origin(url))
                .map(|origin| origin.to_ascii_lowercase())
                .collect();
            origins.sort();
            origins.dedup();
            for origin in origins {
                sqlx::query("INSERT INTO client_cors_origins (client_id, origin) VALUES ($1, $2)")
                    .bind(&client.client_id)
                    .bind(origin)
                    .execute(&mut *tx)
                    .await?;
            }
        }
        tx.commit().await?;
        Ok(())
    }

    /// Inserts or replaces resources given in the resources file format
    /// (`identityResources`, `apiScopes`, `apiResources`), in one
    /// transaction. Their order in the file becomes their store order.
    pub async fn import_resources(&self, resources: &Value) -> Result<(), PgError> {
        if !resources.is_object() {
            return Err(PgError::InvalidResources(serde::de::Error::custom(
                "expected a JSON object",
            )));
        }
        let parsed: Resources =
            serde_json::from_value(resources.clone()).map_err(PgError::InvalidResources)?;
        if let Some((kind, name)) = parsed.first_duplicate() {
            return Err(PgError::Duplicate {
                kind,
                name: name.to_owned(),
            });
        }
        let mut tx = self.pool.begin().await?;
        for (table, key, kind, upsert) in [
            (
                "identity_resources",
                "identityResources",
                "identity resource",
                "INSERT INTO identity_resources (name, enabled, ordinal, data, id) VALUES ($1, $2, $3, $4, $5::uuid)
                 ON CONFLICT (name) DO UPDATE SET enabled = EXCLUDED.enabled,
                     ordinal = EXCLUDED.ordinal, data = EXCLUDED.data, updated = now(),
                     version = CASE WHEN identity_resources.data IS DISTINCT FROM EXCLUDED.data
                                    THEN identity_resources.version + 1 ELSE identity_resources.version END",
            ),
            (
                "api_scopes",
                "apiScopes",
                "API scope",
                "INSERT INTO api_scopes (name, enabled, ordinal, data, id) VALUES ($1, $2, $3, $4, $5::uuid)
                 ON CONFLICT (name) DO UPDATE SET enabled = EXCLUDED.enabled,
                     ordinal = EXCLUDED.ordinal, data = EXCLUDED.data, updated = now(),
                     version = CASE WHEN api_scopes.data IS DISTINCT FROM EXCLUDED.data
                                    THEN api_scopes.version + 1 ELSE api_scopes.version END",
            ),
            (
                "api_resources",
                "apiResources",
                "API resource",
                "INSERT INTO api_resources (name, enabled, ordinal, data, id) VALUES ($1, $2, $3, $4, $5::uuid)
                 ON CONFLICT (name) DO UPDATE SET enabled = EXCLUDED.enabled,
                     ordinal = EXCLUDED.ordinal, data = EXCLUDED.data, updated = now(),
                     version = CASE WHEN api_resources.data IS DISTINCT FROM EXCLUDED.data
                                    THEN api_resources.version + 1 ELSE api_resources.version END",
            ),
        ] {
            let empty = Vec::new();
            let items = resources.get(key).and_then(Value::as_array).unwrap_or(&empty);
            for (index, raw) in items.iter().enumerate() {
                let (name, enabled) = name_and_enabled(table, raw).map_err(|source| {
                    PgError::InvalidModel {
                        kind,
                        index,
                        source,
                    }
                })?;
                sqlx::query(upsert)
                .bind(name)
                .bind(enabled)
                .bind(i32::try_from(index).unwrap_or(i32::MAX))
                .bind(raw)
                .bind(rustid_core::admin::EntityId::new_v7().to_string())
                .execute(&mut *tx)
                .await?;
            }
        }
        tx.commit().await?;
        Ok(())
    }
}

/// Validates a resource against its model and returns its name and flag.
fn name_and_enabled(table: &str, raw: &Value) -> Result<(String, bool), serde_json::Error> {
    Ok(match table {
        "identity_resources" => {
            let r: IdentityResource = serde_json::from_value(raw.clone())?;
            (r.name, r.enabled)
        }
        "api_scopes" => {
            let r: ApiScope = serde_json::from_value(raw.clone())?;
            (r.name, r.enabled)
        }
        _ => {
            let r: ApiResource = serde_json::from_value(raw.clone())?;
            (r.name, r.enabled)
        }
    })
}

fn model<T: serde::de::DeserializeOwned>(data: Value) -> Result<T, StoreError> {
    serde_json::from_value(data).map_err(backend)
}

#[async_trait]
impl ClientStore for PgStore {
    async fn find_client_by_id(&self, client_id: &str) -> Result<Option<Arc<Client>>, StoreError> {
        let row = sqlx::query("SELECT data FROM clients WHERE client_id = $1")
            .bind(client_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(backend)?;
        row.map(|row| model(row.get("data")).map(Arc::new))
            .transpose()
    }

    async fn is_cors_origin_allowed(&self, origin: &str) -> Result<bool, StoreError> {
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM client_cors_origins WHERE origin = $1)")
            .bind(origin.to_ascii_lowercase())
            .fetch_one(&self.pool)
            .await
            .map_err(backend)
    }
}

impl PgStore {
    async fn enabled<T: serde::de::DeserializeOwned>(
        &self,
        select: &'static str,
    ) -> Result<Vec<T>, StoreError> {
        sqlx::query(select)
            .fetch_all(&self.pool)
            .await
            .map_err(backend)?
            .into_iter()
            .map(|row| model(row.get("data")))
            .collect()
    }
}

#[async_trait]
impl ResourceStore for PgStore {
    async fn get_all_enabled_resources(&self) -> Result<Arc<Resources>, StoreError> {
        Ok(Arc::new(Resources {
            identity_resources: self
                .enabled("SELECT data FROM identity_resources WHERE enabled ORDER BY ordinal, name")
                .await?,
            api_scopes: self
                .enabled("SELECT data FROM api_scopes WHERE enabled ORDER BY ordinal, name")
                .await?,
            api_resources: self
                .enabled("SELECT data FROM api_resources WHERE enabled ORDER BY ordinal, name")
                .await?,
        }))
    }

    async fn get_all_resources(&self) -> Result<Arc<Resources>, StoreError> {
        Ok(Arc::new(Resources {
            identity_resources: self
                .enabled("SELECT data FROM identity_resources ORDER BY ordinal, name")
                .await?,
            api_scopes: self
                .enabled("SELECT data FROM api_scopes ORDER BY ordinal, name")
                .await?,
            api_resources: self
                .enabled("SELECT data FROM api_resources ORDER BY ordinal, name")
                .await?,
        }))
    }

    async fn find_api_resources_by_name(
        &self,
        names: &[String],
    ) -> Result<Vec<ApiResource>, StoreError> {
        sqlx::query("SELECT data FROM api_resources WHERE name = ANY($1) ORDER BY ordinal, name")
            .bind(names)
            .fetch_all(&self.pool)
            .await
            .map_err(backend)?
            .into_iter()
            .map(|row| model(row.get("data")))
            .collect()
    }
}

/// The filter matches every criterion that is set; unset ones (`NULL`)
/// match anything. Clients and types are sets (`client_id` merged with
/// `client_ids`, and so on), never empty: an unset one binds as `NULL`.
const SELECT_FILTERED_GRANTS: &str = "SELECT key, type, client_id, subject_id, session_id,
         description, creation_time, expiration, consumed_time, data
     FROM persisted_grants
     WHERE ($1::text IS NULL OR subject_id = $1)
       AND ($2::text IS NULL OR session_id = $2)
       AND ($3::text[] IS NULL OR client_id = ANY($3))
       AND ($4::text[] IS NULL OR type = ANY($4))";

const DELETE_FILTERED_GRANTS: &str = "DELETE FROM persisted_grants
     WHERE ($1::text IS NULL OR subject_id = $1)
       AND ($2::text IS NULL OR session_id = $2)
       AND ($3::text[] IS NULL OR client_id = ANY($3))
       AND ($4::text[] IS NULL OR type = ANY($4))";

fn grant(row: &sqlx::postgres::PgRow) -> PersistedGrant {
    PersistedGrant {
        key: row.get("key"),
        grant_type: row.get("type"),
        client_id: row.get("client_id"),
        subject_id: row.get("subject_id"),
        session_id: row.get("session_id"),
        description: row.get("description"),
        creation_time: row.get::<DateTime<Utc>, _>("creation_time"),
        expiration: row.get("expiration"),
        consumed_time: row.get("consumed_time"),
        data: row.get("data"),
    }
}

fn filtered<'q>(
    sql: &'static str,
    filter: &'q GrantFilter,
) -> sqlx::query::Query<'q, Postgres, sqlx::postgres::PgArguments> {
    sqlx::query(sql)
        .bind(filter.subject_id.as_deref())
        .bind(filter.session_id.as_deref())
        .bind(filter.client_set())
        .bind(filter.type_set())
}

#[async_trait]
impl PersistedGrantStore for PgStore {
    async fn store(&self, grant: PersistedGrant) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO persisted_grants (key, type, client_id, subject_id, session_id,
                 description, creation_time, expiration, consumed_time, data)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
             ON CONFLICT (key) DO UPDATE SET
                 type = EXCLUDED.type, client_id = EXCLUDED.client_id,
                 subject_id = EXCLUDED.subject_id, session_id = EXCLUDED.session_id,
                 description = EXCLUDED.description, creation_time = EXCLUDED.creation_time,
                 expiration = EXCLUDED.expiration, consumed_time = EXCLUDED.consumed_time,
                 data = EXCLUDED.data",
        )
        .bind(&grant.key)
        .bind(&grant.grant_type)
        .bind(&grant.client_id)
        .bind(&grant.subject_id)
        .bind(&grant.session_id)
        .bind(&grant.description)
        .bind(grant.creation_time)
        .bind(grant.expiration)
        .bind(grant.consumed_time)
        .bind(&grant.data)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<PersistedGrant>, StoreError> {
        Ok(sqlx::query(
            "SELECT key, type, client_id, subject_id, session_id, description,
                 creation_time, expiration, consumed_time, data
             FROM persisted_grants WHERE key = $1",
        )
        .bind(key)
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?
        .as_ref()
        .map(grant))
    }

    async fn get_all(&self, filter: &GrantFilter) -> Result<Vec<PersistedGrant>, StoreError> {
        if filter.is_empty() {
            return Err(StoreError::EmptyFilter);
        }
        Ok(filtered(SELECT_FILTERED_GRANTS, filter)
            .fetch_all(&self.pool)
            .await
            .map_err(backend)?
            .iter()
            .map(grant)
            .collect())
    }

    async fn remove(&self, key: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM persisted_grants WHERE key = $1")
            .bind(key)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        Ok(())
    }

    async fn take(&self, key: &str) -> Result<Option<PersistedGrant>, StoreError> {
        Ok(sqlx::query(
            "DELETE FROM persisted_grants WHERE key = $1
             RETURNING key, type, client_id, subject_id, session_id, description,
                 creation_time, expiration, consumed_time, data",
        )
        .bind(key)
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?
        .as_ref()
        .map(grant))
    }

    async fn remove_all(&self, filter: &GrantFilter) -> Result<(), StoreError> {
        if filter.is_empty() {
            return Err(StoreError::EmptyFilter);
        }
        filtered(DELETE_FILTERED_GRANTS, filter)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        Ok(())
    }

    async fn remove_expired(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        batch: usize,
        consumed_before: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<u64, StoreError> {
        let removed = sqlx::query(
            "DELETE FROM persisted_grants WHERE key IN
                 (SELECT key FROM persisted_grants
                  WHERE expiration < $1 OR consumed_time < $2
                  ORDER BY key LIMIT $3 FOR UPDATE SKIP LOCKED)",
        )
        .bind(now)
        .bind(consumed_before)
        .bind(i64::try_from(batch).unwrap_or(i64::MAX))
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(removed.rows_affected())
    }
}

#[async_trait]
impl rustid_core::stores::SigningKeyStore for PgStore {
    async fn load_keys(&self) -> Result<Vec<rustid_core::stores::SerializedKey>, StoreError> {
        Ok(sqlx::query(
            "SELECT id, version, created, algorithm, is_x509_certificate, data, data_protected
             FROM signing_keys ORDER BY created, id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?
        .iter()
        .map(|row| rustid_core::stores::SerializedKey {
            version: row.get("version"),
            id: row.get("id"),
            created: row.get("created"),
            algorithm: row.get("algorithm"),
            is_x509_certificate: row.get("is_x509_certificate"),
            data: row.get("data"),
            data_protected: row.get("data_protected"),
        })
        .collect())
    }

    async fn store_key(&self, key: rustid_core::stores::SerializedKey) -> Result<(), StoreError> {
        let result = sqlx::query(
            "INSERT INTO signing_keys (id, version, created, algorithm, is_x509_certificate,
                 data, data_protected)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(&key.id)
        .bind(key.version)
        .bind(key.created)
        .bind(&key.algorithm)
        .bind(key.is_x509_certificate)
        .bind(&key.data)
        .bind(key.data_protected)
        .execute(&self.pool)
        .await;
        match result {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
                Err(StoreError::DuplicateKey(key.id))
            }
            Err(e) => Err(backend(e)),
        }
    }

    async fn delete_key(&self, id: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM signing_keys WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        Ok(())
    }
}
