//! The device flow store over the `device_codes` table.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rustid_core::stores::{DeviceFlowStore, StoreError};

use crate::{PgStore, backend};

#[async_trait]
impl DeviceFlowStore for PgStore {
    async fn store_device_authorization(
        &self,
        device_code: &str,
        user_code: &str,
        client_id: &str,
        creation_time: DateTime<Utc>,
        expiration: DateTime<Utc>,
        data: &str,
    ) -> Result<(), StoreError> {
        let inserted = sqlx::query(
            "INSERT INTO device_codes
                 (device_code, user_code, client_id, creation_time, expiration, data)
             VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
        )
        .bind(device_code)
        .bind(user_code)
        .bind(client_id)
        .bind(creation_time)
        .bind(expiration)
        .bind(data)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        if inserted.rows_affected() == 0 {
            return Err(StoreError::DuplicateDeviceCode);
        }
        Ok(())
    }

    async fn find_by_user_code(&self, user_code: &str) -> Result<Option<String>, StoreError> {
        sqlx::query_scalar("SELECT data FROM device_codes WHERE user_code = $1")
            .bind(user_code)
            .fetch_optional(&self.pool)
            .await
            .map_err(backend)
    }

    async fn find_by_device_code(&self, device_code: &str) -> Result<Option<String>, StoreError> {
        sqlx::query_scalar("SELECT data FROM device_codes WHERE device_code = $1")
            .bind(device_code)
            .fetch_optional(&self.pool)
            .await
            .map_err(backend)
    }

    async fn update_by_user_code(
        &self,
        user_code: &str,
        subject_id: Option<&str>,
        data: &str,
    ) -> Result<(), StoreError> {
        let updated =
            sqlx::query("UPDATE device_codes SET subject_id = $2, data = $3 WHERE user_code = $1")
                .bind(user_code)
                .bind(subject_id)
                .bind(data)
                .execute(&self.pool)
                .await
                .map_err(backend)?;
        if updated.rows_affected() == 0 {
            return Err(StoreError::UnknownUserCode);
        }
        Ok(())
    }

    async fn remove_by_device_code(&self, device_code: &str) -> Result<bool, StoreError> {
        let removed = sqlx::query("DELETE FROM device_codes WHERE device_code = $1")
            .bind(device_code)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        Ok(removed.rows_affected() == 1)
    }

    async fn remove_expired(&self, now: DateTime<Utc>, batch: usize) -> Result<u64, StoreError> {
        let removed = sqlx::query(
            "DELETE FROM device_codes WHERE device_code IN
                 (SELECT device_code FROM device_codes WHERE expiration < $1 LIMIT $2)",
        )
        .bind(now)
        .bind(i64::try_from(batch).unwrap_or(i64::MAX))
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(removed.rows_affected())
    }
}
