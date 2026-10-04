//! The outbox over the `outbox` table: claims are leases taken with
//! `FOR UPDATE SKIP LOCKED`, so instances never share an event.

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use rustid_core::outbox::{OutboxEvent, OutboxStore};
use rustid_core::stores::StoreError;
use sqlx::Row;

use crate::{PgStore, backend};

/// Adds an event inside `executor` (a transaction moving sessions in).
pub(crate) async fn enqueue<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    event: &str,
    payload: &str,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO outbox (event, payload, created, next_attempt) VALUES ($1, $2, $3, $3)",
    )
    .bind(event)
    .bind(payload)
    .bind(now)
    .execute(executor)
    .await
    .map_err(backend)?;
    Ok(())
}

#[async_trait]
impl OutboxStore for PgStore {
    async fn enqueue(
        &self,
        event: &str,
        payload: &str,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        enqueue(&self.pool, event, payload, now).await
    }

    async fn claim(
        &self,
        batch: usize,
        now: DateTime<Utc>,
        lease: Duration,
    ) -> Result<Vec<OutboxEvent>, StoreError> {
        let mut events: Vec<OutboxEvent> = sqlx::query(
            "UPDATE outbox SET claimed_until = $3
             WHERE id IN (SELECT id FROM outbox
                          WHERE next_attempt <= $2
                            AND (claimed_until IS NULL OR claimed_until <= $2)
                          ORDER BY id LIMIT $1 FOR UPDATE SKIP LOCKED)
             RETURNING id, event, payload, attempts",
        )
        .bind(i64::try_from(batch).unwrap_or(i64::MAX))
        .bind(now)
        .bind(now + lease)
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?
        .iter()
        .map(|row| OutboxEvent {
            id: row.get("id"),
            event: row.get("event"),
            payload: row.get("payload"),
            attempts: row.get("attempts"),
        })
        .collect();
        events.sort_by_key(|e| e.id);
        Ok(events)
    }

    async fn complete(&self, id: i64) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM outbox WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        Ok(())
    }

    async fn retry(&self, id: i64, next_attempt: DateTime<Utc>) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE outbox SET attempts = attempts + 1, next_attempt = $2, claimed_until = NULL
             WHERE id = $1",
        )
        .bind(id)
        .bind(next_attempt)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }
}
