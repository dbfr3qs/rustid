//! The replay cache over the `replay_cache` table.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rustid_core::replay::ReplayCache;
use rustid_core::stores::StoreError;

use crate::{PgStore, backend};

fn at(seconds: i64) -> Result<DateTime<Utc>, StoreError> {
    DateTime::from_timestamp(seconds, 0)
        .ok_or_else(|| StoreError::Backend(format!("timestamp {seconds} out of range")))
}

#[async_trait]
impl ReplayCache for PgStore {
    /// One statement: inserts the entry, or replaces an expired one; a
    /// live one is left alone and returns no row, which is a replay.
    async fn add_if_absent(
        &self,
        purpose: &str,
        handle: &str,
        expires_at: i64,
        now: i64,
    ) -> Result<bool, StoreError> {
        let recorded = sqlx::query(
            "INSERT INTO replay_cache (key, expires) VALUES ($1, $2)
             ON CONFLICT (key) DO UPDATE SET expires = EXCLUDED.expires
             WHERE replay_cache.expires <= $3
             RETURNING key",
        )
        .bind(format!("{purpose}{handle}"))
        .bind(at(expires_at)?)
        .bind(at(now)?)
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        Ok(recorded.is_some())
    }

    async fn remove_expired(&self, now: i64, batch: usize) -> Result<u64, StoreError> {
        let removed = sqlx::query(
            "DELETE FROM replay_cache WHERE key IN
                 (SELECT key FROM replay_cache WHERE expires <= $1
                  ORDER BY key LIMIT $2 FOR UPDATE SKIP LOCKED)",
        )
        .bind(at(now)?)
        .bind(i64::try_from(batch).unwrap_or(i64::MAX))
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(removed.rows_affected())
    }

    async fn remove(&self, purpose: &str, handle: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM replay_cache WHERE key = $1")
            .bind(format!("{purpose}{handle}"))
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        Ok(())
    }
}
