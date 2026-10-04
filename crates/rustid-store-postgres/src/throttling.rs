//! The device flow throttling service over the `throttling` table, so every
//! instance sees the others' polls.

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use rustid_core::stores::{DeviceFlowThrottling, StoreError};

use crate::{PgStore, backend};

#[async_trait]
impl DeviceFlowThrottling for PgStore {
    /// Records this poll and reads the previous one, if not forgotten:
    /// an update returning the locked old row, or the first insert. A
    /// concurrent first poll that wins the insert sends this one back to
    /// the update.
    async fn should_slow_down(
        &self,
        key: &str,
        interval: i64,
        lifetime: i64,
        now: DateTime<Utc>,
    ) -> Result<bool, StoreError> {
        let forget = now + Duration::seconds(lifetime);
        for _ in 0..2 {
            let old: Option<(DateTime<Utc>, DateTime<Utc>)> = sqlx::query_as(
                "UPDATE throttling t SET last_seen = $2, forget = $3
                 FROM (SELECT key, last_seen, forget FROM throttling WHERE key = $1 FOR UPDATE) old
                 WHERE t.key = old.key
                 RETURNING old.last_seen, old.forget",
            )
            .bind(key)
            .bind(now)
            .bind(forget)
            .fetch_optional(&self.pool)
            .await
            .map_err(backend)?;
            if let Some((last, forgotten_at)) = old {
                return Ok(forgotten_at > now && now < last + Duration::seconds(interval));
            }
            let inserted = sqlx::query(
                "INSERT INTO throttling (key, last_seen, forget) VALUES ($1, $2, $3)
                 ON CONFLICT (key) DO NOTHING",
            )
            .bind(key)
            .bind(now)
            .bind(forget)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
            if inserted.rows_affected() == 1 {
                return Ok(false);
            }
        }
        Err(StoreError::Backend(format!(
            "throttling entry {key} kept changing under this poll"
        )))
    }

    async fn remove_expired(&self, now: DateTime<Utc>, batch: usize) -> Result<u64, StoreError> {
        let removed = sqlx::query(
            "DELETE FROM throttling WHERE key IN
                 (SELECT key FROM throttling WHERE forget <= $1 LIMIT $2)",
        )
        .bind(now)
        .bind(i64::try_from(batch).unwrap_or(i64::MAX))
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(removed.rows_affected())
    }
}
