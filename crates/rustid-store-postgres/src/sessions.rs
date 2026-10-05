//! The server side session store over the `server_side_sessions` table.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rustid_core::server_side_sessions::{
    PageSource, QueryResult, ServerSideSession, SessionFilter, SessionQuery, query_page,
};
use rustid_core::stores::{ServerSideSessionStore, StoreError};
use sqlx::Row;
use sqlx::postgres::PgRow;

use crate::{PgStore, backend};

const COLUMNS: &str =
    "key, scheme, subject_id, session_id, display_name, created, renewed, expires, data";

/// SQL assembled only from this module's constants.
fn dynamic(
    sql: String,
) -> sqlx::query::Query<'static, sqlx::Postgres, sqlx::postgres::PgArguments> {
    sqlx::query(sqlx::AssertSqlSafe(sql))
}

fn session(row: &PgRow) -> ServerSideSession {
    ServerSideSession {
        key: row.get("key"),
        scheme: row.get("scheme"),
        subject_id: row.get("subject_id"),
        session_id: row.get("session_id"),
        display_name: row.get("display_name"),
        created: row.get::<DateTime<Utc>, _>("created"),
        renewed: row.get::<DateTime<Utc>, _>("renewed"),
        expires: row.get("expires"),
        ticket: row.get("data"),
    }
}

/// `WHERE` over an exact filter; `$1` subject and `$2` session, either null.
const FILTER: &str =
    "($1::text IS NULL OR subject_id = $1) AND ($2::text IS NULL OR session_id = $2)";

#[async_trait]
impl ServerSideSessionStore for PgStore {
    async fn create_session(&self, s: ServerSideSession) -> Result<(), StoreError> {
        let inserted = dynamic(format!(
            "INSERT INTO server_side_sessions ({COLUMNS})
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (key) DO NOTHING"
        ))
        .bind(&s.key)
        .bind(&s.scheme)
        .bind(&s.subject_id)
        .bind(&s.session_id)
        .bind(&s.display_name)
        .bind(s.created)
        .bind(s.renewed)
        .bind(s.expires)
        .bind(&s.ticket)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        if inserted.rows_affected() == 0 {
            return Err(StoreError::DuplicateSession(s.key));
        }
        Ok(())
    }

    async fn get_session(&self, key: &str) -> Result<Option<ServerSideSession>, StoreError> {
        Ok(dynamic(format!(
            "SELECT {COLUMNS} FROM server_side_sessions WHERE key = $1"
        ))
        .bind(key)
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?
        .as_ref()
        .map(session))
    }

    async fn update_session(&self, s: ServerSideSession) -> Result<(), StoreError> {
        dynamic(format!(
            "INSERT INTO server_side_sessions ({COLUMNS})
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
             ON CONFLICT (key) DO UPDATE SET
                 scheme = EXCLUDED.scheme, subject_id = EXCLUDED.subject_id,
                 session_id = EXCLUDED.session_id, display_name = EXCLUDED.display_name,
                 created = EXCLUDED.created, renewed = EXCLUDED.renewed,
                 expires = EXCLUDED.expires, data = EXCLUDED.data"
        ))
        .bind(&s.key)
        .bind(&s.scheme)
        .bind(&s.subject_id)
        .bind(&s.session_id)
        .bind(&s.display_name)
        .bind(s.created)
        .bind(s.renewed)
        .bind(s.expires)
        .bind(&s.ticket)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn delete_session(&self, key: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM server_side_sessions WHERE key = $1")
            .bind(key)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        Ok(())
    }

    async fn get_sessions(
        &self,
        filter: &SessionFilter,
    ) -> Result<Vec<ServerSideSession>, StoreError> {
        if filter.is_empty() {
            return Err(StoreError::EmptyFilter);
        }
        Ok(dynamic(format!(
            "SELECT {COLUMNS} FROM server_side_sessions WHERE {FILTER}"
        ))
        .bind(&filter.subject_id)
        .bind(&filter.session_id)
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?
        .iter()
        .map(session)
        .collect())
    }

    async fn delete_sessions(&self, filter: &SessionFilter) -> Result<(), StoreError> {
        if filter.is_empty() {
            return Err(StoreError::EmptyFilter);
        }
        dynamic(format!("DELETE FROM server_side_sessions WHERE {FILTER}"))
            .bind(&filter.subject_id)
            .bind(&filter.session_id)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        Ok(())
    }

    /// One transaction: delete the expired sessions (locked, skipping any
    /// another instance holds) and add an outbox event for each, so a
    /// failure in between loses nothing.
    async fn move_expired_to_outbox(
        &self,
        count: usize,
        now: DateTime<Utc>,
    ) -> Result<usize, StoreError> {
        let mut tx = self.pool.begin().await.map_err(backend)?;
        let mut sessions: Vec<ServerSideSession> = dynamic(format!(
            "DELETE FROM server_side_sessions WHERE key IN (
                 SELECT key FROM server_side_sessions WHERE expires < $1
                 ORDER BY key LIMIT $2 FOR UPDATE SKIP LOCKED)
             RETURNING {COLUMNS}"
        ))
        .bind(now)
        .bind(i64::try_from(count).unwrap_or(i64::MAX))
        .fetch_all(&mut *tx)
        .await
        .map_err(backend)?
        .iter()
        .map(session)
        .collect();
        sessions.sort_by(|a, b| a.key.cmp(&b.key));
        for expired in &sessions {
            let payload =
                serde_json::to_string(expired).map_err(|e| StoreError::Backend(e.to_string()))?;
            crate::outbox::enqueue(
                &mut *tx,
                rustid_core::outbox::SESSION_EXPIRED,
                &payload,
                now,
            )
            .await?;
        }
        tx.commit().await.map_err(backend)?;
        Ok(sessions.len())
    }

    async fn query_sessions(
        &self,
        query: &SessionQuery,
    ) -> Result<QueryResult<ServerSideSession>, StoreError> {
        query_page(&Query { store: self, query }, query).await
    }
}

/// The sessions a query matches, read a page at a time.
struct Query<'a> {
    store: &'a PgStore,
    query: &'a SessionQuery,
}

/// `$1` subject, `$2` session and `$3` display name substrings, each null
/// or blank when unused (substring matches, case-sensitive), as the in-memory
/// store matches.
const MATCHES: &str =
    "(($1::text IS NULL OR btrim($1) = '') AND ($2::text IS NULL OR btrim($2) = '')
        AND ($3::text IS NULL OR btrim($3) = ''))
    OR (($1::text IS NULL OR strpos(subject_id, $1) > 0)
        AND ($2::text IS NULL OR strpos(session_id, $2) > 0)
        AND ($3::text IS NULL OR (display_name IS NOT NULL AND strpos(display_name, $3) > 0)))";

impl Query<'_> {
    fn bind<'q>(
        &'q self,
        sql: &'q str,
    ) -> sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments> {
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(&self.query.subject_id)
            .bind(&self.query.session_id)
            .bind(&self.query.display_name)
    }

    async fn count_where(&self, extra: &str, key: Option<&str>) -> Result<usize, StoreError> {
        let sql =
            format!("SELECT count(*) AS n FROM server_side_sessions WHERE ({MATCHES}) {extra}");
        let mut q = self.bind(&sql);
        if let Some(key) = key {
            q = q.bind(key);
        }
        let n: i64 = q
            .fetch_one(&self.store.pool)
            .await
            .map_err(backend)?
            .get("n");
        Ok(usize::try_from(n).unwrap_or(0))
    }

    async fn page(
        &self,
        extra: &str,
        key: &str,
        limit: usize,
    ) -> Result<Vec<ServerSideSession>, StoreError> {
        let sql = format!("SELECT {COLUMNS} FROM server_side_sessions WHERE ({MATCHES}) {extra}");
        Ok(self
            .bind(&sql)
            .bind(key)
            .bind(i64::try_from(limit).unwrap_or(i64::MAX))
            .fetch_all(&self.store.pool)
            .await
            .map_err(backend)?
            .iter()
            .map(session)
            .collect())
    }
}

#[async_trait]
impl PageSource for Query<'_> {
    async fn count(&self) -> Result<usize, StoreError> {
        self.count_where("", None).await
    }
    async fn count_before(&self, key: &str) -> Result<usize, StoreError> {
        self.count_where("AND key < $4", Some(key)).await
    }
    async fn count_after(&self, key: &str) -> Result<usize, StoreError> {
        self.count_where("AND key > $4", Some(key)).await
    }
    async fn after(&self, key: &str, limit: usize) -> Result<Vec<ServerSideSession>, StoreError> {
        self.page("AND key > $4 ORDER BY key LIMIT $5", key, limit)
            .await
    }
    async fn before(&self, key: &str, limit: usize) -> Result<Vec<ServerSideSession>, StoreError> {
        self.page("AND key < $4 ORDER BY key DESC LIMIT $5", key, limit)
            .await
    }
}
