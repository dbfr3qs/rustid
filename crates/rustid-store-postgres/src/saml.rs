//! The SAML stores in Postgres: service providers (a configuration table,
//! imported from `saml_service_providers_file`), sign-in states and logout
//! sessions with their request index.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rustid_core::admin::EntityId;
use rustid_core::stores::StoreError;
use rustid_saml::model::ServiceProvider;
use rustid_saml::state::{AuthenticationState, LogoutSession, SpLogoutResponse};
use rustid_saml::stores::{
    LogoutSessionStore, MISSING_LOGOUT_EXPIRY, MISSING_SIGNIN_EXPIRY, ServiceProviderStore,
    SigninStateStore, is_v7,
};
use serde_json::Value;
use sqlx::Row;

use crate::{PgError, PgStore, backend};

fn provider(data: Value) -> Result<Arc<ServiceProvider>, StoreError> {
    serde_json::from_value(data).map(Arc::new).map_err(backend)
}

impl PgStore {
    /// Upserts the service providers by entity id, in file order: new ones
    /// get ids at version 1, changed ones a new version (as clients).
    pub async fn import_saml_service_providers(&self, providers: &[Value]) -> Result<(), PgError> {
        let mut seen = std::collections::HashSet::new();
        let mut parsed = Vec::with_capacity(providers.len());
        for (index, raw) in providers.iter().enumerate() {
            let sp: ServiceProvider =
                serde_json::from_value(raw.clone()).map_err(|source| PgError::InvalidModel {
                    kind: "SAML service provider",
                    index,
                    source,
                })?;
            if !seen.insert(sp.entity_id.clone()) {
                return Err(PgError::Duplicate {
                    kind: "SAML service provider",
                    name: sp.entity_id,
                });
            }
            parsed.push(sp);
        }
        let mut tx = self.pool.begin().await?;
        for (ordinal, sp) in parsed.iter().enumerate() {
            // Stored normalized, so an unchanged file keeps its versions.
            let data = serde_json::to_value(sp).expect("a service provider serialises");
            sqlx::query(
                "INSERT INTO saml_service_providers (entity_id, enabled, ordinal, data, id)
                 VALUES ($1, $2, $3, $4, $5::uuid)
                 ON CONFLICT (entity_id) DO UPDATE
                 SET enabled = EXCLUDED.enabled, ordinal = EXCLUDED.ordinal, data = EXCLUDED.data,
                     updated = now(),
                     version = CASE WHEN saml_service_providers.data IS DISTINCT FROM EXCLUDED.data
                                    THEN saml_service_providers.version + 1
                                    ELSE saml_service_providers.version END",
            )
            .bind(&sp.entity_id)
            .bind(sp.enabled)
            .bind(i32::try_from(ordinal).unwrap_or(i32::MAX))
            .bind(&data)
            .bind(EntityId::new_v7().to_string())
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }
}

#[async_trait]
impl ServiceProviderStore for PgStore {
    async fn find_by_entity_id(
        &self,
        entity_id: &str,
    ) -> Result<Option<Arc<ServiceProvider>>, StoreError> {
        sqlx::query("SELECT data FROM saml_service_providers WHERE entity_id = $1 AND enabled")
            .bind(entity_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(backend)?
            .map(|row| provider(row.get("data")))
            .transpose()
    }

    async fn get_all(&self) -> Result<Vec<Arc<ServiceProvider>>, StoreError> {
        sqlx::query("SELECT data FROM saml_service_providers ORDER BY ordinal, entity_id")
            .fetch_all(&self.pool)
            .await
            .map_err(backend)?
            .into_iter()
            .map(|row| provider(row.get("data")))
            .collect()
    }
}

#[async_trait]
impl SigninStateStore for PgStore {
    async fn store(&self, state: AuthenticationState) -> Result<EntityId, StoreError> {
        let Some(expires) = state.expires_at_utc else {
            return Err(StoreError::MissingExpiration(MISSING_SIGNIN_EXPIRY));
        };
        let id = EntityId::new_v7();
        sqlx::query(
            "INSERT INTO saml_signin_states (id, data, expires_at) VALUES ($1::uuid, $2, $3)",
        )
        .bind(id.to_string())
        .bind(serde_json::to_value(&state).map_err(backend)?)
        .bind(expires)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(id)
    }

    async fn retrieve(
        &self,
        id: &EntityId,
        now: DateTime<Utc>,
    ) -> Result<Option<AuthenticationState>, StoreError> {
        if !is_v7(id) {
            return Ok(None);
        }
        let Some(row) =
            sqlx::query("SELECT data, expires_at FROM saml_signin_states WHERE id = $1::uuid")
                .bind(id.to_string())
                .fetch_optional(&self.pool)
                .await
                .map_err(backend)?
        else {
            return Ok(None);
        };
        let expires: DateTime<Utc> = row.get("expires_at");
        if now > expires {
            self.remove_state(id).await?;
            return Ok(None);
        }
        serde_json::from_value(row.get("data"))
            .map(Some)
            .map_err(backend)
    }

    async fn update(
        &self,
        id: &EntityId,
        state: AuthenticationState,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        if !is_v7(id) {
            return Ok(());
        }
        // An expired state is removed rather than updated.
        sqlx::query("DELETE FROM saml_signin_states WHERE id = $1::uuid AND expires_at < $2")
            .bind(id.to_string())
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        // The stored expiry stands.
        let updated = sqlx::query(
            "UPDATE saml_signin_states
             SET data = jsonb_set($2, '{expiresAtUtc}', data -> 'expiresAtUtc')
             WHERE id = $1::uuid",
        )
        .bind(id.to_string())
        .bind(serde_json::to_value(&state).map_err(backend)?)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        if updated.rows_affected() == 0 {
            tracing::warn!(%id, "SAML signin state not found or expired; not updated");
        }
        Ok(())
    }

    async fn remove(&self, id: &EntityId) -> Result<(), StoreError> {
        self.remove_state(id).await
    }

    async fn remove_expired(&self, now: DateTime<Utc>, batch: usize) -> Result<u64, StoreError> {
        let removed = sqlx::query(
            "DELETE FROM saml_signin_states WHERE id IN
               (SELECT id FROM saml_signin_states WHERE expires_at < $1 LIMIT $2)",
        )
        .bind(now)
        .bind(i64::try_from(batch).unwrap_or(i64::MAX))
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(removed.rows_affected())
    }
}

impl PgStore {
    async fn remove_state(&self, id: &EntityId) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM saml_signin_states WHERE id = $1::uuid")
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        Ok(())
    }
}

#[async_trait]
impl LogoutSessionStore for PgStore {
    async fn store(&self, session: LogoutSession) -> Result<(), StoreError> {
        let Some(expires) = session.expires_at_utc else {
            return Err(StoreError::MissingExpiration(MISSING_LOGOUT_EXPIRY));
        };
        let mut tx = self.pool.begin().await.map_err(backend)?;
        let inserted = sqlx::query(
            "INSERT INTO saml_logout_sessions (logout_id, data, expires_at) VALUES ($1, $2, $3)
             ON CONFLICT (logout_id) DO NOTHING",
        )
        .bind(&session.logout_id)
        .bind(serde_json::to_value(&session).map_err(backend)?)
        .bind(expires)
        .execute(&mut *tx)
        .await
        .map_err(backend)?;
        if inserted.rows_affected() == 0 {
            return Err(StoreError::DuplicateLogoutId(session.logout_id));
        }
        for request in session.expected_responses.keys() {
            sqlx::query("INSERT INTO saml_logout_requests (request_id, logout_id) VALUES ($1, $2)")
                .bind(request)
                .bind(&session.logout_id)
                .execute(&mut *tx)
                .await
                .map_err(backend)?;
        }
        tx.commit().await.map_err(backend)?;
        Ok(())
    }

    async fn get(
        &self,
        logout_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<LogoutSession>, StoreError> {
        sqlx::query(
            "SELECT data FROM saml_logout_sessions WHERE logout_id = $1 AND expires_at > $2",
        )
        .bind(logout_id)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?
        .map(|row| serde_json::from_value(row.get("data")).map_err(backend))
        .transpose()
    }

    async fn try_record_response(
        &self,
        request_id: &str,
        issuer: &str,
        success: bool,
        now: DateTime<Utc>,
    ) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await.map_err(backend)?;
        // The session row is locked, so concurrent responses for one
        // session apply one after the other.
        let Some(row) = sqlx::query(
            "SELECT s.logout_id, s.data, s.expires_at
             FROM saml_logout_requests r JOIN saml_logout_sessions s USING (logout_id)
             WHERE r.request_id = $1
             FOR UPDATE OF s",
        )
        .bind(request_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(backend)?
        else {
            return Ok(false);
        };
        let expires: DateTime<Utc> = row.get("expires_at");
        if expires <= now {
            return Ok(false);
        }
        let logout_id: String = row.get("logout_id");
        let mut session: LogoutSession =
            serde_json::from_value(row.get("data")).map_err(backend)?;
        let Some(expected) = session.expected_responses.get_mut(request_id) else {
            return Ok(false);
        };
        if expected.sp_entity_id != issuer {
            tracing::warn!(request_id, expected = %expected.sp_entity_id, received = issuer, "SAML logout response issuer mismatch");
            return Ok(false);
        }
        expected.response = Some(SpLogoutResponse {
            success,
            received_utc: now,
        });
        sqlx::query("UPDATE saml_logout_sessions SET data = $2 WHERE logout_id = $1")
            .bind(&logout_id)
            .bind(serde_json::to_value(&session).map_err(backend)?)
            .execute(&mut *tx)
            .await
            .map_err(backend)?;
        tx.commit().await.map_err(backend)?;
        Ok(true)
    }

    async fn remove(&self, logout_id: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM saml_logout_sessions WHERE logout_id = $1")
            .bind(logout_id)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        Ok(())
    }

    async fn remove_expired(&self, now: DateTime<Utc>, batch: usize) -> Result<u64, StoreError> {
        let removed = sqlx::query(
            "DELETE FROM saml_logout_sessions WHERE logout_id IN
               (SELECT logout_id FROM saml_logout_sessions WHERE expires_at <= $1 LIMIT $2)",
        )
        .bind(now)
        .bind(i64::try_from(batch).unwrap_or(i64::MAX))
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(removed.rows_affected())
    }
}
