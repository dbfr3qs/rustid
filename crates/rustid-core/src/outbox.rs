//! The outbox: work that must survive failures and
//! restarts, today the expiration of server-side sessions. The session
//! store moves expired sessions into it (atomically, in Postgres); the
//! processor runs `process_expiration` for each, retrying failures with
//! backoff and dropping an event after `max_retries` failed attempts.
//!
//! Retry state lives in each event, not one processor's
//! memory, and a failing event doesn't hold up the ones after it, so
//! every instance can run the processor; claims are leased, so instances
//! don't handle the same event at once (delivery is at least once).

use std::sync::Mutex;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};

use crate::access_tokens::ValidationContext;
use crate::options::OutboxProcessorOptions;
use crate::server_side_sessions::{ServerSideSession, open_ticket, process_expiration};
use crate::stores::StoreError;

/// `EntityExpired` for a server-side session; the payload is the session.
pub const SESSION_EXPIRED: &str = "session_expired";

/// How long a claim holds an event before another instance may take it.
pub const LEASE_SECONDS: i64 = 300;

/// Get outbox events for subscriber accepts 1 to 1000.
const MAX_BATCH: usize = 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxEvent {
    pub id: i64,
    pub event: String,
    pub payload: String,
    /// Failed attempts so far.
    pub attempts: i32,
}

#[async_trait]
pub trait OutboxStore: Send + Sync {
    async fn enqueue(
        &self,
        event: &str,
        payload: &str,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError>;

    /// Leases up to `batch` due events (next attempt at or before `now`, no
    /// lease beyond `now`), oldest first, until `now + lease`.
    async fn claim(
        &self,
        batch: usize,
        now: DateTime<Utc>,
        lease: Duration,
    ) -> Result<Vec<OutboxEvent>, StoreError>;

    /// Deletes a handled or dropped event.
    async fn complete(&self, id: i64) -> Result<(), StoreError>;

    /// Releases the lease: due again at `next_attempt`, one more failed
    /// attempt counted.
    async fn retry(&self, id: i64, next_attempt: DateTime<Utc>) -> Result<(), StoreError>;
}

#[derive(Debug, Clone)]
struct Row {
    event: OutboxEvent,
    next_attempt: DateTime<Utc>,
    claimed_until: Option<DateTime<Utc>>,
}

#[derive(Debug, Default)]
pub struct InMemoryOutbox {
    rows: Mutex<(i64, Vec<Row>)>,
}

impl InMemoryOutbox {
    /// `enqueue` without waiting, for a store moving sessions in.
    pub fn push(&self, event: &str, payload: &str, now: DateTime<Utc>) {
        let mut rows = self.rows();
        rows.0 += 1;
        let id = rows.0;
        rows.1.push(Row {
            event: OutboxEvent {
                id,
                event: event.to_owned(),
                payload: payload.to_owned(),
                attempts: 0,
            },
            next_attempt: now,
            claimed_until: None,
        });
    }

    fn rows(&self) -> std::sync::MutexGuard<'_, (i64, Vec<Row>)> {
        self.rows
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[async_trait]
impl OutboxStore for InMemoryOutbox {
    async fn enqueue(
        &self,
        event: &str,
        payload: &str,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        self.push(event, payload, now);
        Ok(())
    }

    async fn claim(
        &self,
        batch: usize,
        now: DateTime<Utc>,
        lease: Duration,
    ) -> Result<Vec<OutboxEvent>, StoreError> {
        let mut rows = self.rows();
        let mut claimed = Vec::new();
        for row in rows.1.iter_mut() {
            if claimed.len() == batch {
                break;
            }
            if row.next_attempt <= now && row.claimed_until.is_none_or(|until| until <= now) {
                row.claimed_until = Some(now + lease);
                claimed.push(row.event.clone());
            }
        }
        Ok(claimed)
    }

    async fn complete(&self, id: i64) -> Result<(), StoreError> {
        self.rows().1.retain(|row| row.event.id != id);
        Ok(())
    }

    async fn retry(&self, id: i64, next_attempt: DateTime<Utc>) -> Result<(), StoreError> {
        if let Some(row) = self.rows().1.iter_mut().find(|row| row.event.id == id) {
            row.event.attempts += 1;
            row.next_attempt = next_attempt;
            row.claimed_until = None;
        }
        Ok(())
    }
}

/// `ComputeDelay`: `retry_delay` times `multiplier^(attempts - 1)`, at most
/// `max_retry_delay`; `retry_delay` when the multiplier is unusable.
pub fn retry_delay(options: &OutboxProcessorOptions, attempts: i32) -> Duration {
    let base = options.retry_delay.0 as f64;
    let max = options.max_retry_delay.0;
    let multiplier = options.retry_backoff_multiplier.powi(attempts.max(1) - 1);
    if !multiplier.is_finite() || multiplier <= 0.0 {
        return Duration::seconds(options.retry_delay.0.min(max));
    }
    let seconds = base * multiplier;
    if !seconds.is_finite() || seconds >= max as f64 {
        return Duration::seconds(max);
    }
    Duration::seconds(seconds as i64)
}

/// What one run did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Processed {
    pub handled: usize,
    pub retried: usize,
    pub dropped: usize,
}

/// One processor run over the due events.
pub async fn process(ctx: &ValidationContext<'_>) -> Result<Processed, StoreError> {
    let options = &ctx.options.outbox_processor;
    let mut processed = Processed::default();
    let Some(sessions) = &ctx.stores.sessions else {
        return Ok(processed);
    };
    if !options.enable_processor {
        return Ok(processed);
    }
    let batch = usize::try_from(options.batch_size)
        .unwrap_or(1)
        .clamp(1, MAX_BATCH);
    let events = sessions
        .outbox
        .claim(batch, ctx.now, Duration::seconds(LEASE_SECONDS))
        .await?;
    for event in events {
        let session = (event.event == SESSION_EXPIRED)
            .then(|| serde_json::from_str::<ServerSideSession>(&event.payload).ok())
            .flatten()
            .and_then(|record| open_ticket(&sessions.protector, &record));
        let Some(session) = session else {
            tracing::warn!(id = event.id, event = %event.event, "dropping an unreadable outbox event");
            sessions.outbox.complete(event.id).await?;
            processed.dropped += 1;
            continue;
        };
        match process_expiration(ctx, &session).await {
            Ok(()) => {
                sessions.outbox.complete(event.id).await?;
                processed.handled += 1;
            }
            Err(error) if event.attempts + 1 >= options.max_retries => {
                tracing::error!(id = event.id, %error, attempts = event.attempts + 1, "dropping a session expiration after its last retry");
                sessions.outbox.complete(event.id).await?;
                processed.dropped += 1;
            }
            Err(error) => {
                let next = ctx.now + retry_delay(options, event.attempts + 1);
                tracing::warn!(id = event.id, %error, %next, "session expiration failed; retrying");
                sessions.outbox.retry(event.id, next).await?;
                processed.retried += 1;
            }
        }
    }
    Ok(processed)
}
