//! Server-side sessions: the session ticket is
//! kept in a store and the `idsrv` cookie carries only its key. The record,
//! its filters and the key-ordered paging of query sessions.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::stores::StoreError;

/// `ServerSideSession`: one browser session's record (and, as JSON, an
/// expired session's outbox event).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerSideSession {
    /// 64 upper-case hex characters; the cookie carries it, sealed.
    pub key: String,
    /// The authentication scheme (`idsrv`).
    pub scheme: String,
    pub subject_id: String,
    pub session_id: String,
    pub display_name: Option<String>,
    pub created: DateTime<Utc>,
    /// When the session was last renewed: the ticket's issued time.
    pub renewed: DateTime<Utc>,
    /// The ticket's expiry; `None` never expires.
    pub expires: Option<DateTime<Utc>>,
    /// The sealed ticket.
    pub ticket: String,
}

/// `SessionFilter`: exact matches; at least one is required.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionFilter {
    pub subject_id: Option<String>,
    pub session_id: Option<String>,
}

impl SessionFilter {
    pub fn is_empty(&self) -> bool {
        self.subject_id.is_none() && self.session_id.is_none()
    }

    pub fn matches(&self, session: &ServerSideSession) -> bool {
        self.subject_id
            .as_deref()
            .is_none_or(|s| s == session.subject_id)
            && self
                .session_id
                .as_deref()
                .is_none_or(|s| s == session.session_id)
    }
}

/// `SessionQuery`: substring filters and a page of results.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionQuery {
    /// The previous page's `results_token`.
    pub results_token: Option<String>,
    /// The page before the token's instead of the one after.
    pub request_prior_results: bool,
    /// Results per page; 25 when zero.
    pub count_requested: usize,
    pub subject_id: Option<String>,
    pub session_id: Option<String>,
    pub display_name: Option<String>,
}

impl SessionQuery {
    /// Whether a session passes the query's substring filters
    /// (case-sensitive). With no filter set, every session does.
    pub fn matches(&self, session: &ServerSideSession) -> bool {
        let blank = |f: &Option<String>| f.as_deref().is_none_or(|v| v.trim().is_empty());
        if blank(&self.subject_id) && blank(&self.session_id) && blank(&self.display_name) {
            return true;
        }
        self.subject_id
            .as_deref()
            .is_none_or(|f| session.subject_id.contains(f))
            && self
                .session_id
                .as_deref()
                .is_none_or(|f| session.session_id.contains(f))
            && self.display_name.as_deref().is_none_or(|f| {
                session
                    .display_name
                    .as_deref()
                    .is_some_and(|name| name.contains(f))
            })
    }
}

/// `QueryResult<T>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryResult<T> {
    pub results_token: Option<String>,
    pub has_prev_results: bool,
    pub has_next_results: bool,
    pub total_count: usize,
    pub total_pages: usize,
    pub current_page: usize,
    pub results: Vec<T>,
}

/// What paging needs from a store, over the sessions a query matches.
#[async_trait]
pub trait PageSource: Send + Sync {
    async fn count(&self) -> Result<usize, StoreError>;
    /// Matching sessions with a key before `key`.
    async fn count_before(&self, key: &str) -> Result<usize, StoreError>;
    /// Matching sessions with a key after `key`.
    async fn count_after(&self, key: &str) -> Result<usize, StoreError>;
    /// Up to `limit` sessions with keys after `key`, in key order.
    async fn after(&self, key: &str, limit: usize) -> Result<Vec<ServerSideSession>, StoreError>;
    /// Up to `limit` sessions with keys before `key`, nearest first.
    async fn before(&self, key: &str, limit: usize) -> Result<Vec<ServerSideSession>, StoreError>;
}

/// The memory store's session paging: pages in
/// key order, the token naming a page's first and last keys.
pub async fn query_page(
    source: &dyn PageSource,
    query: &SessionQuery,
) -> Result<QueryResult<ServerSideSession>, StoreError> {
    let (first, last) = query
        .results_token
        .as_deref()
        .and_then(|t| {
            let parts: Vec<&str> = t.split(',').filter(|p| !p.is_empty()).collect();
            (parts.len() == 2).then(|| (parts[0].to_owned(), parts[1].to_owned()))
        })
        .unwrap_or_default();
    let count = if query.count_requested == 0 {
        25
    } else {
        query.count_requested
    };
    let mut total_count = source.count().await?;
    let mut total_pages = total_count.div_ceil(count).max(1);
    let mut current_page = 1;
    let mut has_next = false;
    let mut has_prev = false;
    let mut items;
    if query.request_prior_results {
        items = source.before(&first, count + 1).await?;
        items.reverse();
        has_prev = items.len() > count;
        if has_prev {
            items.remove(0);
        }
        if let Some(last_item) = items.last() {
            let post_count = source.count_after(&last_item.key).await?;
            has_next = post_count > 0;
            current_page = total_pages.saturating_sub(post_count.div_ceil(count));
        }
        if current_page == 1 && has_next && items.len() < count {
            let restart = SessionQuery {
                results_token: None,
                request_prior_results: false,
                ..query.clone()
            };
            return Box::pin(query_page(source, &restart)).await;
        }
    } else {
        items = source.after(&last, count + 1).await?;
        has_next = items.len() > count;
        if has_next {
            items.pop();
        }
        if let Some(first_item) = items.first() {
            let prior_count = source.count_before(&first_item.key).await?;
            has_prev = prior_count > 0;
            current_page = 1 + prior_count.div_ceil(count);
        }
    }
    if current_page <= 1 {
        current_page = 1;
        has_prev = false;
    }
    let results_token = match (items.first(), items.last()) {
        (Some(first), Some(last)) => Some(format!("{},{}", first.key, last.key)),
        _ => {
            has_prev = false;
            has_next = false;
            total_count = 0;
            total_pages = 0;
            current_page = 0;
            None
        }
    };
    Ok(QueryResult {
        results_token,
        has_prev_results: has_prev,
        has_next_results: has_next,
        total_count,
        total_pages,
        current_page,
        results: items,
    })
}

/// A [`PageSource`] over sessions already filtered and sorted by key.
pub struct SortedSessions(pub Vec<ServerSideSession>);

#[async_trait]
impl PageSource for SortedSessions {
    async fn count(&self) -> Result<usize, StoreError> {
        Ok(self.0.len())
    }
    async fn count_before(&self, key: &str) -> Result<usize, StoreError> {
        Ok(self.0.iter().filter(|s| s.key.as_str() < key).count())
    }
    async fn count_after(&self, key: &str) -> Result<usize, StoreError> {
        Ok(self.0.iter().filter(|s| s.key.as_str() > key).count())
    }
    async fn after(&self, key: &str, limit: usize) -> Result<Vec<ServerSideSession>, StoreError> {
        Ok(self
            .0
            .iter()
            .filter(|s| s.key.as_str() > key)
            .take(limit)
            .cloned()
            .collect())
    }
    async fn before(&self, key: &str, limit: usize) -> Result<Vec<ServerSideSession>, StoreError> {
        Ok(self
            .0
            .iter()
            .rev()
            .filter(|s| s.key.as_str() < key)
            .take(limit)
            .cloned()
            .collect())
    }
}

/// A new session key: 32 random bytes as upper-case hex.
pub fn new_key() -> String {
    use aws_lc_rs::rand::SecureRandom;
    let mut bytes = [0u8; 32];
    aws_lc_rs::rand::SystemRandom::new()
        .fill(&mut bytes)
        .expect("system random source");
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(key: &str) -> ServerSideSession {
        let at = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        ServerSideSession {
            key: key.into(),
            scheme: "idsrv".into(),
            subject_id: format!("sub-{key}"),
            session_id: format!("sid-{key}"),
            display_name: None,
            created: at,
            renewed: at,
            expires: None,
            ticket: String::new(),
        }
    }

    fn source(n: usize) -> SortedSessions {
        SortedSessions((0..n).map(|i| session(&format!("k{i:02}"))).collect())
    }

    fn keys(r: &QueryResult<ServerSideSession>) -> Vec<&str> {
        r.results.iter().map(|s| s.key.as_str()).collect()
    }

    #[tokio::test]
    async fn pages_forward_and_back_by_token() {
        let s = source(7);
        let q = SessionQuery {
            count_requested: 3,
            ..Default::default()
        };
        let p1 = query_page(&s, &q).await.unwrap();
        assert_eq!(keys(&p1), ["k00", "k01", "k02"]);
        assert_eq!((p1.current_page, p1.total_pages, p1.total_count), (1, 3, 7));
        assert!(p1.has_next_results && !p1.has_prev_results);
        assert_eq!(p1.results_token.as_deref(), Some("k00,k02"));

        let next = |r: &QueryResult<ServerSideSession>, prior: bool| SessionQuery {
            results_token: r.results_token.clone(),
            request_prior_results: prior,
            count_requested: 3,
            ..Default::default()
        };
        let p2 = query_page(&s, &next(&p1, false)).await.unwrap();
        assert_eq!(keys(&p2), ["k03", "k04", "k05"]);
        assert_eq!(p2.current_page, 2);
        assert!(p2.has_next_results && p2.has_prev_results);
        let p3 = query_page(&s, &next(&p2, false)).await.unwrap();
        assert_eq!(keys(&p3), ["k06"]);
        assert_eq!(p3.current_page, 3);
        assert!(!p3.has_next_results && p3.has_prev_results);

        let back = query_page(&s, &next(&p3, true)).await.unwrap();
        assert_eq!(keys(&back), ["k03", "k04", "k05"]);
        assert_eq!(back.current_page, 2);
        let first = query_page(&s, &next(&back, true)).await.unwrap();
        assert_eq!(keys(&first), ["k00", "k01", "k02"]);
        assert_eq!(first.current_page, 1);
        assert!(!first.has_prev_results);
    }

    #[tokio::test]
    async fn nothing_matching_is_page_zero() {
        let r = query_page(&source(0), &SessionQuery::default())
            .await
            .unwrap();
        assert_eq!(
            (
                r.total_count,
                r.total_pages,
                r.current_page,
                r.results_token
            ),
            (0, 0, 0, None)
        );
    }

    #[test]
    fn query_filters_are_substrings_and_display_names_must_exist() {
        let mut s = session("k1");
        s.display_name = Some("Alice Smith".into());
        let q = |sub: Option<&str>, name: Option<&str>| SessionQuery {
            subject_id: sub.map(Into::into),
            display_name: name.map(Into::into),
            ..Default::default()
        };
        assert!(q(None, None).matches(&s));
        assert!(q(Some("ub-k"), None).matches(&s));
        assert!(q(None, Some("Smith")).matches(&s));
        assert!(!q(None, Some("smith")).matches(&s), "case-sensitive");
        s.display_name = None;
        assert!(!q(None, Some("A")).matches(&s));
    }

    #[test]
    fn keys_are_64_hex_characters() {
        let k = new_key();
        assert_eq!(k.len(), 64);
        assert!(
            k.bytes()
                .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
        );
        assert_ne!(k, new_key());
    }
}

/// The purpose session tickets are sealed under in the store.
pub const TICKET_PURPOSE: &str = "rustid.session.ticket";
/// The purpose a session key is sealed under in the `idsrv` cookie.
pub const KEY_PURPOSE: &str = "rustid.session.key";
/// The scheme recorded with each session (`idsrv`).
pub const SCHEME: &str = crate::session::SESSION_COOKIE;

/// What a session's end takes with it.
pub const TOKEN_GRANT_TYPES: &[&str] = &[
    crate::refresh_tokens::REFRESH_TOKEN,
    crate::grants::REFERENCE_TOKEN,
    crate::authorize::code::AUTHORIZATION_CODE,
    "backchannel_authentication_request",
];

pub fn seal_key(protector: &crate::data_protection::DataProtector, key: &str) -> String {
    protector.protect(KEY_PURPOSE, key.as_bytes())
}

/// The session key in an `idsrv` cookie, when it holds one.
pub fn open_key(protector: &crate::data_protection::DataProtector, cookie: &str) -> Option<String> {
    let bytes = protector.unprotect(KEY_PURPOSE, cookie).ok()?;
    String::from_utf8(bytes).ok()
}

fn seal_ticket(
    protector: &crate::data_protection::DataProtector,
    session: &crate::session::UserSession,
) -> String {
    let json = serde_json::to_vec(session).expect("sessions serialize to JSON");
    protector.protect(TICKET_PURPOSE, &json)
}

/// `Deserialize`: the ticket in a record, with the record's `renewed` and
/// `expires` as its issued and expiry times (so extending the record
/// extends the session) and the record's key.
pub fn open_ticket(
    protector: &crate::data_protection::DataProtector,
    record: &ServerSideSession,
) -> Option<crate::session::UserSession> {
    let json = protector.unprotect(TICKET_PURPOSE, &record.ticket).ok()?;
    let mut session: crate::session::UserSession = serde_json::from_slice(&json).ok()?;
    session.issued = record.renewed;
    session.expires = record.expires.unwrap_or(DateTime::<Utc>::MAX_UTC);
    session.key = Some(record.key.clone());
    Some(session)
}

/// What a session key opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Loaded {
    /// No record, or one whose ticket wouldn't open (now deleted).
    Missing,
    Active(crate::session::UserSession),
    /// Expired, now deleted: for expiration processing.
    Expired(crate::session::UserSession),
}

/// Retrieve for the cookie handler: the session behind a key. A
/// ticket that won't open is deleted, as is an expired one.
pub async fn load_session(
    store: &dyn crate::stores::ServerSideSessionStore,
    protector: &crate::data_protection::DataProtector,
    key: &str,
    now: DateTime<Utc>,
) -> Result<Loaded, StoreError> {
    let Some(record) = store.get_session(key).await? else {
        return Ok(Loaded::Missing);
    };
    let Some(session) = open_ticket(protector, &record) else {
        tracing::warn!(
            key,
            "a server-side session's ticket won't open; deleting it"
        );
        store.delete_session(key).await?;
        return Ok(Loaded::Missing);
    };
    if record.expires.is_some_and(|e| e < now) {
        store.delete_session(key).await?;
        return Ok(Loaded::Expired(session));
    }
    Ok(Loaded::Active(session))
}

/// Writes the session's ticket under its key
/// (a new one when it has none) and returns the key. When the record held
/// another user or session, that session's token grants are revoked and
/// the session gets a new record and key.
pub async fn store_session(
    store: &dyn crate::stores::ServerSideSessionStore,
    grants: &dyn crate::stores::PersistedGrantStore,
    protector: &crate::data_protection::DataProtector,
    options: &crate::options::ProtocolOptions,
    session: &mut crate::session::UserSession,
    issuer: &str,
) -> Result<String, StoreError> {
    if session.issuer.is_none() {
        session.issuer = Some(issuer.to_owned());
    }
    let display_name = options
        .server_side_sessions
        .user_display_name_claim_type
        .as_deref()
        .filter(|t| !t.trim().is_empty())
        .and_then(|t| session.claim(t))
        .map(str::to_owned);
    let existing = match &session.key {
        Some(key) => store.get_session(key).await?,
        None => None,
    };
    // Another user or session: the old session's tokens go, and so does its
    // record and key, so a key planted in a browser before sign-in is never
    // adopted (the key isn't kept).
    if let Some(previous) = &existing
        && (previous.subject_id != session.subject_id || previous.session_id != session.session_id)
    {
        for grant_type in TOKEN_GRANT_TYPES {
            grants
                .remove_all(&crate::grants::GrantFilter {
                    subject_id: Some(previous.subject_id.clone()),
                    session_id: Some(previous.session_id.clone()),
                    client_id: None,
                    grant_type: Some((*grant_type).to_owned()),
                    ..Default::default()
                })
                .await?;
        }
        store.delete_session(&previous.key).await?;
        session.key = None;
    }
    let created = existing
        .as_ref()
        .filter(|p| session.key.as_deref() == Some(p.key.as_str()))
        .map(|p| p.created);
    let key = session.key.clone().unwrap_or_else(new_key);
    session.key = Some(key.clone());
    let issued = session.issued;
    let record = ServerSideSession {
        key: key.clone(),
        scheme: SCHEME.to_owned(),
        subject_id: session.subject_id.clone(),
        session_id: session.session_id.clone(),
        display_name,
        created: created.unwrap_or(issued),
        renewed: issued,
        expires: (session.expires != DateTime::<Utc>::MAX_UTC).then_some(session.expires),
        ticket: seal_ticket(protector, session),
    };
    // A renewal whose record is gone makes a new one.
    store.update_session(record).await?;
    Ok(key)
}

/// Server-side sessions as the server uses them: the store, and the data
/// protection ring its tickets and cookie keys are sealed with.
#[derive(Clone)]
pub struct ServerSideSessions {
    pub store: std::sync::Arc<dyn crate::stores::ServerSideSessionStore>,
    /// Where the store moves expired sessions for processing.
    pub outbox: std::sync::Arc<dyn crate::outbox::OutboxStore>,
    pub protector: std::sync::Arc<crate::data_protection::DataProtector>,
}

impl std::fmt::Debug for ServerSideSessions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ServerSideSessions { .. }")
    }
}

/// With server-side sessions, a coordinated client's
/// token is only good while its user's session lives. A good use extends
/// each matching session by its span; a persistent, refreshable session is
/// flagged so the browser's cookie is renewed too (when sliding).
pub async fn validate_session(
    ctx: &crate::access_tokens::ValidationContext<'_>,
    client: &crate::clients::Client,
    subject_id: &str,
    session_id: Option<&str>,
) -> Result<bool, StoreError> {
    let Some(sessions) = &ctx.stores.sessions else {
        return Ok(true);
    };
    if !crate::logout::coordinates(ctx.options, client) {
        return Ok(true);
    }
    let records = sessions
        .store
        .get_sessions(&SessionFilter {
            subject_id: Some(subject_id.to_owned()),
            session_id: session_id.map(str::to_owned),
        })
        .await?;
    if !records
        .iter()
        .any(|r| r.expires.is_none_or(|e| ctx.now < e))
    {
        return Ok(false);
    }
    let sliding = ctx.options.authentication.cookie_sliding_expiration;
    for mut record in records {
        let Some(expires) = record.expires else {
            continue;
        };
        let span = expires - record.renewed;
        record.renewed = ctx.now;
        record.expires = Some(ctx.now + span);
        let refreshable = sliding
            .then(|| open_ticket(&sessions.protector, &record))
            .flatten()
            .filter(|t| t.persistent && t.allow_refresh != Some(false));
        match refreshable {
            Some(mut ticket) => {
                ticket.force_renewal = true;
                store_session(
                    sessions.store.as_ref(),
                    ctx.stores.grants.as_ref(),
                    &sessions.protector,
                    ctx.options,
                    &mut ticket,
                    ctx.issuer,
                )
                .await?;
            }
            None => sessions.store.update_session(record).await?,
        }
    }
    Ok(true)
}

/// An expired session's coordinated clients lose
/// its tokens, and are told over the back channel (every client, when
/// `expired_sessions_trigger_backchannel_logout`), as the issuer that
/// signed the user in.
pub async fn process_expiration(
    ctx: &crate::access_tokens::ValidationContext<'_>,
    session: &crate::session::UserSession,
) -> Result<(), StoreError> {
    let coordinated = crate::logout::coordinated_clients(ctx, &session.client_ids).await?;
    for client_id in &coordinated {
        for grant_type in TOKEN_GRANT_TYPES {
            ctx.stores
                .grants
                .remove_all(&crate::grants::GrantFilter {
                    subject_id: Some(session.subject_id.clone()),
                    session_id: Some(session.session_id.clone()),
                    client_id: Some((*client_id).to_owned()),
                    grant_type: Some((*grant_type).to_owned()),
                    ..Default::default()
                })
                .await?;
        }
    }
    let everyone = ctx
        .options
        .server_side_sessions
        .expired_sessions_trigger_backchannel_logout;
    let contact: Vec<String> = session
        .client_ids
        .iter()
        .filter(|c| everyone || coordinated.contains(&c.as_str()))
        .cloned()
        .collect();
    if contact.is_empty() {
        return Ok(());
    }
    let issuer = session.issuer.as_deref().unwrap_or(ctx.issuer);
    let ctx = crate::access_tokens::ValidationContext { issuer, ..*ctx };
    let requests = crate::logout::back_channel_requests(
        ctx.stores.clients.as_ref(),
        &contact,
        Some(&session.subject_id),
        Some(&session.session_id),
        "session_expiration",
    )
    .await?;
    crate::logout::send_logout_tokens(&ctx, &requests).await
}

/// One run of the server side session cleanup host: moves expired sessions into
/// the outbox a batch at a time until none are left; the outbox processor
/// (`crate::outbox::process`) then processes each. Returns how many moved.
pub async fn expire_sessions(
    ctx: &crate::access_tokens::ValidationContext<'_>,
) -> Result<usize, StoreError> {
    let Some(sessions) = &ctx.stores.sessions else {
        return Ok(0);
    };
    let batch = ctx
        .options
        .server_side_sessions
        .remove_expired_sessions_batch_size
        .max(1);
    let mut moved = 0;
    loop {
        let count = sessions
            .store
            .move_expired_to_outbox(batch, ctx.now)
            .await?;
        if count == 0 {
            return Ok(moved);
        }
        moved += count;
    }
}

/// `UserSession` as session management shows it: a record whose ticket
/// opened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionInfo {
    pub subject_id: String,
    pub session_id: String,
    pub display_name: Option<String>,
    pub created: DateTime<Utc>,
    pub renewed: DateTime<Utc>,
    pub expires: Option<DateTime<Utc>>,
    pub issuer: Option<String>,
    pub client_ids: Vec<String>,
}

fn info(sessions: &ServerSideSessions, record: &ServerSideSession) -> Option<SessionInfo> {
    let ticket = open_ticket(&sessions.protector, record)?;
    Some(SessionInfo {
        subject_id: ticket.subject_id,
        session_id: ticket.session_id,
        display_name: record.display_name.clone(),
        created: record.created,
        renewed: record.renewed,
        expires: record.expires,
        issuer: ticket.issuer,
        client_ids: ticket.client_ids,
    })
}

/// A page of sessions, those whose tickets open.
pub async fn query_user_sessions(
    sessions: &ServerSideSessions,
    query: &SessionQuery,
) -> Result<QueryResult<SessionInfo>, StoreError> {
    let page = sessions.store.query_sessions(query).await?;
    Ok(QueryResult {
        results_token: page.results_token,
        has_prev_results: page.has_prev_results,
        has_next_results: page.has_next_results,
        total_count: page.total_count,
        total_pages: page.total_pages,
        current_page: page.current_page,
        results: page
            .results
            .iter()
            .filter_map(|r| info(sessions, r))
            .collect(),
    })
}

/// Which sessions, and what goes with them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoveSessions {
    pub subject_id: Option<String>,
    pub session_id: Option<String>,
    /// Limits token and consent revocation and notifications to these
    /// clients; `None` is every client.
    pub client_ids: Option<Vec<String>>,
    pub revoke_tokens: bool,
    pub revoke_consents: bool,
    pub remove_server_side_session: bool,
    pub send_backchannel_logout_notification: bool,
}

/// The session management service. `EmptyFilter`
/// without a subject or session.
pub async fn remove_sessions(
    ctx: &crate::access_tokens::ValidationContext<'_>,
    sessions: &ServerSideSessions,
    remove: &RemoveSessions,
) -> Result<(), StoreError> {
    let filter = SessionFilter {
        subject_id: remove.subject_id.clone(),
        session_id: remove.session_id.clone(),
    };
    if filter.is_empty() {
        return Err(StoreError::EmptyFilter);
    }
    if remove.revoke_tokens || remove.revoke_consents {
        // Both: every grant type; else consents, or tokens only.
        let types: Vec<Option<&str>> = match (remove.revoke_tokens, remove.revoke_consents) {
            (true, true) => vec![None],
            (false, true) => vec![Some(crate::consent::USER_CONSENT)],
            _ => TOKEN_GRANT_TYPES.iter().map(|t| Some(*t)).collect(),
        };
        let clients: Vec<Option<&str>> = match remove.client_ids.as_deref() {
            Some(ids) if !ids.is_empty() => ids.iter().map(|c| Some(c.as_str())).collect(),
            _ => vec![None],
        };
        for grant_type in &types {
            for client_id in &clients {
                ctx.stores
                    .grants
                    .remove_all(&crate::grants::GrantFilter {
                        subject_id: remove.subject_id.clone(),
                        session_id: remove.session_id.clone(),
                        client_id: client_id.map(str::to_owned),
                        grant_type: grant_type.map(str::to_owned),
                        ..Default::default()
                    })
                    .await?;
            }
        }
    }
    if remove.send_backchannel_logout_notification {
        for record in sessions.store.get_sessions(&filter).await? {
            let Some(session) = open_ticket(&sessions.protector, &record) else {
                continue;
            };
            let clients: Vec<String> = session
                .client_ids
                .iter()
                .filter(|c| remove.client_ids.as_ref().is_none_or(|ids| ids.contains(c)))
                .cloned()
                .collect();
            let issuer = session.issuer.as_deref().unwrap_or(ctx.issuer);
            let ctx = crate::access_tokens::ValidationContext { issuer, ..*ctx };
            let requests = crate::logout::back_channel_requests(
                ctx.stores.clients.as_ref(),
                &clients,
                Some(&session.subject_id),
                Some(&session.session_id),
                "terminated",
            )
            .await?;
            crate::logout::send_logout_tokens(&ctx, &requests).await?;
        }
    }
    if remove.remove_server_side_session {
        sessions.store.delete_sessions(&filter).await?;
    }
    Ok(())
}
