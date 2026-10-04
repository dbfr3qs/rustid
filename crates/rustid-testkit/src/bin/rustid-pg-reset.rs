//! Drops and recreates a Postgres database, so a test run starts
//! from an empty schema: `rustid-pg-reset postgres://.../rustid_diff_default`.

use sqlx::Postgres;
use sqlx::migrate::MigrateDatabase;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: rustid-pg-reset <database url>"))?;
    Postgres::force_drop_database(&url).await?;
    Postgres::create_database(&url).await?;
    Ok(())
}
