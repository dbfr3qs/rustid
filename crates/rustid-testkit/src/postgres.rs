//! Throwaway Postgres databases for tests. Tests that need one call
//! [`ScratchDatabase::create`], which returns `None` (and the test skips)
//! when `TEST_POSTGRES_URL` is unset.

use std::sync::atomic::{AtomicU32, Ordering};

use sqlx::Postgres;
use sqlx::migrate::MigrateDatabase;

/// A connection URL to a Postgres server the tests may create and drop
/// databases on, for example `postgres://postgres:rustid@127.0.0.1:55432/postgres`.
pub const DATABASE_URL_ENV: &str = "TEST_POSTGRES_URL";

pub struct ScratchDatabase {
    pub url: String,
}

impl ScratchDatabase {
    /// Creates an empty database with a unique name on the server named by
    /// `TEST_POSTGRES_URL`; `None` when the variable is unset.
    pub async fn create() -> Option<Self> {
        let base = std::env::var(DATABASE_URL_ENV).ok()?;
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let name = format!(
            "rustid_test_{}_{}_{}",
            std::process::id(),
            nanos,
            COUNTER.fetch_add(1, Ordering::SeqCst)
        );
        let mut url = url::Url::parse(&base).expect("TEST_POSTGRES_URL is a URL");
        url.set_path(&name);
        let url = url.to_string();
        Postgres::create_database(&url)
            .await
            .unwrap_or_else(|e| panic!("creating {name}: {e}"));
        Some(ScratchDatabase { url })
    }

    /// Drops the database; close every pool on it first.
    pub async fn drop(self) {
        Postgres::force_drop_database(&self.url)
            .await
            .unwrap_or_else(|e| panic!("dropping {}: {e}", self.url));
    }
}
