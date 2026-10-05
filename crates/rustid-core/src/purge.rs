//! The storage purge (the storage purge host over the token cleanup service): in
//! batches, expired persisted grants (pushed authorization requests among
//! them) and, when configured, consumed ones; expired device codes; and
//! expired replay and throttling entries.

use chrono::{DateTime, Duration, Utc};

use crate::stores::{StoreError, Stores};

/// One run's settings: the batch size (clamped), whether consumed
/// tokens are removed too, and how long after consumption they are kept
/// (seconds).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurgeSettings {
    pub batch: usize,
    pub remove_consumed: bool,
    pub consumed_delay: i64,
}

/// What one run removed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Purged {
    pub grants: u64,
    pub device_codes: u64,
    pub replay: u64,
    pub throttling: u64,
}

/// Purge expired accepts batches of 1 to 1000.
pub const MAX_BATCH: usize = 1000;

/// Calls `remove` until a batch comes back short; the total.
async fn drain<F, Fut>(batch: usize, mut remove: F) -> Result<u64, StoreError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<u64, StoreError>>,
{
    let mut total = 0;
    loop {
        let removed = remove().await?;
        total += removed;
        if removed < batch as u64 {
            return Ok(total);
        }
    }
}

pub async fn run(
    stores: &Stores,
    settings: &PurgeSettings,
    now: DateTime<Utc>,
) -> Result<Purged, StoreError> {
    let batch = settings.batch.clamp(1, MAX_BATCH);
    let consumed_before = settings
        .remove_consumed
        .then(|| now - Duration::seconds(settings.consumed_delay.max(0)));
    Ok(Purged {
        grants: drain(batch, || {
            stores.grants.remove_expired(now, batch, consumed_before)
        })
        .await?,
        device_codes: drain(batch, || stores.device_flow.remove_expired(now, batch)).await?,
        replay: drain(batch, || {
            stores.replay.remove_expired(now.timestamp(), batch)
        })
        .await?,
        throttling: drain(batch, || {
            stores.device_throttling.remove_expired(now, batch)
        })
        .await?,
    })
}
