//! The configuration store admin writes through, over the tables the
//! runtime stores read: `identity_resources`, `api_scopes` and
//! `api_resources` (keyed by `name`) and `clients` (by `client_id`, with
//! its derived `client_cors_origins`), and `data_extension_schemas` (by
//! lower-cased schema id).

use async_trait::async_trait;
use rustid_core::admin::EntityId;
use rustid_core::stores::{
    ConfigurationStore, CreateOutcome, EntityKind, StoreError, StoredEntity, UpdateOutcome,
};
use serde_json::Value;
use sqlx::Row;
use sqlx::postgres::PgRow;

use crate::{PgStore, backend};

/// The table and its key column.
fn table(kind: EntityKind) -> (&'static str, &'static str) {
    match kind {
        EntityKind::IdentityResource => ("identity_resources", "name"),
        EntityKind::ApiScope => ("api_scopes", "name"),
        EntityKind::ApiResource => ("api_resources", "name"),
        EntityKind::Client => ("clients", "client_id"),
        EntityKind::Schema => ("data_extension_schemas", "name"),
        EntityKind::SamlServiceProvider => ("saml_service_providers", "entity_id"),
    }
}

fn enabled(data: &Value) -> bool {
    data.get("enabled").and_then(Value::as_bool).unwrap_or(true)
}

fn entity(row: &PgRow) -> Result<StoredEntity, StoreError> {
    let id: String = row.get("id");
    Ok(StoredEntity {
        id: id
            .parse()
            .map_err(|_| StoreError::Backend(format!("stored id {id} is not a UUID")))?,
        key: row.get("key"),
        version: row.get("version"),
        data: row.get("data"),
    })
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    matches!(error, sqlx::Error::Database(db) if db.code().as_deref() == Some("23505"))
}

/// Replaces a client's derived CORS origins (as the importer does).
async fn write_cors_origins(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    client_id: &str,
    data: &Value,
) -> Result<(), StoreError> {
    let mut origins: Vec<String> = data
        .get("allowedCorsOrigins")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter_map(rustid_core::clients::url_origin)
        .map(|origin| origin.to_ascii_lowercase())
        .collect();
    origins.sort();
    origins.dedup();
    for origin in origins {
        sqlx::query("INSERT INTO client_cors_origins (client_id, origin) VALUES ($1, $2)")
            .bind(client_id)
            .bind(origin)
            .execute(&mut **tx)
            .await
            .map_err(backend)?;
    }
    Ok(())
}

#[async_trait]
impl ConfigurationStore for PgStore {
    async fn create(
        &self,
        kind: EntityKind,
        entity: &StoredEntity,
    ) -> Result<CreateOutcome, StoreError> {
        let (table, key) = table(kind);
        let mut tx = self.pool.begin().await.map_err(backend)?;
        let sql = if kind == EntityKind::Client {
            format!(
                "INSERT INTO {table} (id, {key}, enabled, data, version)
                 VALUES ($1::uuid, $2, $3, $4, 1) ON CONFLICT ({key}) DO NOTHING"
            )
        } else {
            format!(
                "INSERT INTO {table} (id, {key}, enabled, ordinal, data, version)
                 VALUES ($1::uuid, $2, $3, (SELECT COALESCE(MAX(ordinal), 0) + 1 FROM {table}), $4, 1)
                 ON CONFLICT ({key}) DO NOTHING"
            )
        };
        let inserted = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(entity.id.to_string())
            .bind(&entity.key)
            .bind(enabled(&entity.data))
            .bind(&entity.data)
            .execute(&mut *tx)
            .await
            .map_err(backend)?;
        if inserted.rows_affected() == 0 {
            return Ok(CreateOutcome::KeyExists);
        }
        if kind == EntityKind::Client {
            write_cors_origins(&mut tx, &entity.key, &entity.data).await?;
        }
        tx.commit().await.map_err(backend)?;
        Ok(CreateOutcome::Created)
    }

    async fn read(
        &self,
        kind: EntityKind,
        id: &EntityId,
    ) -> Result<Option<StoredEntity>, StoreError> {
        let (table, key) = table(kind);
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT id::text AS id, {key} AS key, version, data FROM {table} WHERE id = $1::uuid"
        )))
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?
        .as_ref()
        .map(entity)
        .transpose()
    }

    async fn read_by_key(
        &self,
        kind: EntityKind,
        key_value: &str,
    ) -> Result<Option<StoredEntity>, StoreError> {
        let (table, key) = table(kind);
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT id::text AS id, {key} AS key, version, data FROM {table} WHERE {key} = $1"
        )))
        .bind(key_value)
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?
        .as_ref()
        .map(entity)
        .transpose()
    }

    async fn update(
        &self,
        kind: EntityKind,
        entity: &StoredEntity,
    ) -> Result<UpdateOutcome, StoreError> {
        let (table, key) = table(kind);
        let mut tx = self.pool.begin().await.map_err(backend)?;
        // Lock the row, so the version check and the write are one step.
        let current: Option<(i32, String)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT version, {key} FROM {table} WHERE id = $1::uuid FOR UPDATE"
        )))
        .bind(entity.id.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(backend)?;
        let Some((version, old_key)) = current else {
            return Ok(UpdateOutcome::DoesNotExist);
        };
        if version != entity.version {
            return Ok(UpdateOutcome::UnexpectedVersion);
        }
        if kind == EntityKind::Client {
            sqlx::query("DELETE FROM client_cors_origins WHERE client_id = $1")
                .bind(&old_key)
                .execute(&mut *tx)
                .await
                .map_err(backend)?;
        }
        let updated = sqlx::query(sqlx::AssertSqlSafe(format!(
            "UPDATE {table} SET {key} = $2, enabled = $3, data = $4, version = version + 1,
                 updated = now()
             WHERE id = $1::uuid"
        )))
        .bind(entity.id.to_string())
        .bind(&entity.key)
        .bind(enabled(&entity.data))
        .bind(&entity.data)
        .execute(&mut *tx)
        .await;
        match updated {
            Err(e) if is_unique_violation(&e) => return Ok(UpdateOutcome::KeyConflict),
            Err(e) => return Err(backend(e)),
            Ok(_) => {}
        }
        if kind == EntityKind::Client {
            write_cors_origins(&mut tx, &entity.key, &entity.data).await?;
        }
        tx.commit().await.map_err(backend)?;
        Ok(UpdateOutcome::Updated)
    }

    async fn delete(&self, kind: EntityKind, id: &EntityId) -> Result<(), StoreError> {
        let (table, _) = table(kind);
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DELETE FROM {table} WHERE id = $1::uuid"
        )))
        .bind(id.to_string())
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn list(&self, kind: EntityKind) -> Result<Vec<StoredEntity>, StoreError> {
        let (table, key) = table(kind);
        let order = match kind {
            EntityKind::Client => "client_id",
            EntityKind::SamlServiceProvider => "ordinal, entity_id",
            _ => "ordinal, name",
        };
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT id::text AS id, {key} AS key, version, data FROM {table} ORDER BY {order}"
        )))
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?
        .iter()
        .map(entity)
        .collect()
    }
}
