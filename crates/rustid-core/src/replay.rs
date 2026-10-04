//! Remembers one-time values (client assertion and DPoP
//! proof `jti`s) until they expire. A store, so several instances share it
//! (in Postgres); the in-memory one serves a single instance.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;

use crate::stores::StoreError;

#[async_trait]
pub trait ReplayCache: Send + Sync {
    /// Records `purpose`/`handle` until `expires_at` (Unix seconds), in one
    /// atomic step. `Ok(false)` when it is already present and unexpired,
    /// which is a replay.
    async fn add_if_absent(
        &self,
        purpose: &str,
        handle: &str,
        expires_at: i64,
        now: i64,
    ) -> Result<bool, StoreError>;

    /// Removes up to `batch` entries expired at `now`; how many.
    async fn remove_expired(&self, now: i64, batch: usize) -> Result<u64, StoreError>;
}

#[derive(Debug, Default)]
pub struct InMemoryReplayCache {
    entries: Mutex<HashMap<String, i64>>,
}

impl InMemoryReplayCache {
    fn entries(&self) -> std::sync::MutexGuard<'_, HashMap<String, i64>> {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[async_trait]
impl ReplayCache for InMemoryReplayCache {
    async fn add_if_absent(
        &self,
        purpose: &str,
        handle: &str,
        expires_at: i64,
        now: i64,
    ) -> Result<bool, StoreError> {
        let mut entries = self.entries();
        // The purge job may be disabled; only this process can clear
        // memory, so expired entries go on every write.
        entries.retain(|_, expiry| *expiry > now);
        let key = format!("{purpose}{handle}");
        if entries.get(&key).is_some_and(|expiry| *expiry > now) {
            return Ok(false);
        }
        entries.insert(key, expires_at);
        Ok(true)
    }

    async fn remove_expired(&self, now: i64, batch: usize) -> Result<u64, StoreError> {
        let mut entries = self.entries();
        let expired: Vec<String> = entries
            .iter()
            .filter(|(_, expiry)| **expiry <= now)
            .map(|(k, _)| k.clone())
            .take(batch)
            .collect();
        for key in &expired {
            entries.remove(key);
        }
        Ok(expired.len() as u64)
    }
}
