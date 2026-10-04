//! The session coordination service with server-side sessions:
//! validating (and extending) a session for token use, and processing an
//! expired session.

mod support;

use std::sync::{Arc, Mutex};

use chrono::{Duration, Utc};
use rustid_core::data_protection::DataProtector;
use rustid_core::grants::{GrantFilter, PersistedGrant};
use rustid_core::jwt::Jws;
use rustid_core::logout::BackChannelSender;
use rustid_core::server_side_sessions::{
    ServerSideSessions, SessionFilter, open_ticket, process_expiration, store_session,
    validate_session,
};
use rustid_core::session::{SignIn, UserSession};
use rustid_store_memory::InMemoryServerSideSessionStore;
use support::{Fixture, ISSUER};

#[derive(Default)]
struct Recorder(Mutex<Vec<(String, String)>>);

#[async_trait::async_trait]
impl BackChannelSender for Recorder {
    async fn send(&self, uri: &str, logout_token: &str) {
        self.0
            .lock()
            .unwrap()
            .push((uri.to_owned(), logout_token.to_owned()));
    }
}

struct Setup {
    f: Fixture,
    sessions: Arc<ServerSideSessions>,
    sent: Arc<Recorder>,
}

fn setup() -> Setup {
    let mut f = Fixture::new();
    let store = Arc::new(InMemoryServerSideSessionStore::default());
    let sessions = Arc::new(ServerSideSessions {
        outbox: store.outbox(),
        store,
        protector: Arc::new(DataProtector::new([("k", [3u8; 32].as_slice())]).unwrap()),
    });
    f.stores.sessions = Some(sessions.clone());
    let sent = Arc::new(Recorder::default());
    f.stores.back_channel = sent.clone();
    Setup { f, sessions, sent }
}

/// A stored session for subject "1" with `clients`, issued an hour ago
/// with three to go.
async fn stored(s: &Setup, clients: &[&str], persistent: bool) -> UserSession {
    let now = Utc::now();
    let mut session = UserSession::sign_in(
        SignIn {
            subject_id: "1".into(),
            persistent,
            ..Default::default()
        },
        None,
        now - Duration::hours(1),
        4 * 3600,
    );
    for c in clients {
        session.add_client(c);
    }
    store_session(
        s.sessions.store.as_ref(),
        s.f.stores.grants.as_ref(),
        &s.sessions.protector,
        &s.f.options,
        &mut session,
        ISSUER,
    )
    .await
    .unwrap();
    session
}

fn client(f: &Fixture, id: &str) -> rustid_core::clients::Client {
    f.clients
        .clients
        .iter()
        .find(|c| c.client_id == id)
        .unwrap()
        .clone()
}

fn grant(key: &str, client: &str, session: &UserSession) -> PersistedGrant {
    PersistedGrant {
        key: key.into(),
        grant_type: "refresh_token".into(),
        client_id: client.into(),
        subject_id: Some(session.subject_id.clone()),
        session_id: Some(session.session_id.clone()),
        description: None,
        creation_time: Utc::now(),
        expiration: None,
        consumed_time: None,
        data: "{}".into(),
    }
}

#[tokio::test]
async fn only_coordinated_clients_need_a_live_session() {
    let s = setup();
    let ctx = s.f.validation_ctx(Utc::now());
    let back = client(&s.f, "logout.back");
    let web = client(&s.f, "web");
    assert!(
        !validate_session(&ctx, &back, "1", Some("gone"))
            .await
            .unwrap()
    );
    assert!(
        validate_session(&ctx, &web, "1", Some("gone"))
            .await
            .unwrap()
    );

    // The global option coordinates every client that doesn't opt out.
    let mut f = setup().f;
    f.options
        .authentication
        .coordinate_client_lifetimes_with_user_session = true;
    let ctx = f.validation_ctx(Utc::now());
    assert!(
        !validate_session(&ctx, &web, "1", Some("gone"))
            .await
            .unwrap()
    );

    // Without server-side sessions nothing is checked.
    let f = Fixture::new();
    let ctx = f.validation_ctx(Utc::now());
    assert!(
        validate_session(&ctx, &back, "1", Some("gone"))
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn token_use_extends_the_session_and_flags_persistent_sliding_cookies() {
    let mut s = setup();
    s.f.options.authentication.cookie_sliding_expiration = true;
    let back = client(&s.f, "logout.back");
    for persistent in [false, true] {
        let session = stored(&s, &["logout.back"], persistent).await;
        let now = Utc::now();
        let ctx = s.f.validation_ctx(now);
        assert!(
            validate_session(&ctx, &back, "1", Some(&session.session_id))
                .await
                .unwrap()
        );
        let record = s
            .sessions
            .store
            .get_session(session.key.as_deref().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.renewed, now);
        assert_eq!(record.expires, Some(now + Duration::hours(4)));
        let ticket = open_ticket(&s.sessions.protector, &record).unwrap();
        assert_eq!(ticket.force_renewal, persistent, "persistent={persistent}");
        s.sessions
            .store
            .delete_sessions(&SessionFilter {
                subject_id: Some("1".into()),
                ..Default::default()
            })
            .await
            .unwrap();
    }

    // An expired session doesn't count.
    let session = stored(&s, &["logout.back"], false).await;
    let later = Utc::now() + Duration::hours(5);
    let ctx = s.f.validation_ctx(later);
    assert!(
        !validate_session(&ctx, &back, "1", Some(&session.session_id))
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn expiration_revokes_coordinated_tokens_and_notifies_coordinated_clients() {
    let s = setup();
    let session = stored(&s, &["web", "logout.back"], false).await;
    let grants = s.f.stores.grants.clone();
    grants
        .store(grant("back", "logout.back", &session))
        .await
        .unwrap();
    grants.store(grant("web", "web", &session)).await.unwrap();
    let ctx = s.f.validation_ctx(Utc::now());
    process_expiration(&ctx, &session).await.unwrap();
    assert!(grants.get("back").await.unwrap().is_none());
    assert!(grants.get("web").await.unwrap().is_some());
    let sent = s.sent.0.lock().unwrap().clone();
    assert_eq!(sent.len(), 1);
    let token = Jws::decode(&sent[0].1).unwrap();
    assert_eq!(token.payload["logout_reason"], "session_expiration");
    assert_eq!(token.payload["iss"], ISSUER);
}

#[tokio::test]
async fn expiration_notifies_every_client_only_when_configured() {
    let mut s = setup();
    // A back-channel client that isn't coordinated.
    s.f.edit_clients(|clients| {
        for c in clients.iter_mut() {
            if c.client_id == "logout.back" {
                c.coordinate_lifetime_with_user_session = Some(false);
            }
        }
    });
    let session = stored(&s, &["logout.back"], false).await;
    let ctx = s.f.validation_ctx(Utc::now());
    process_expiration(&ctx, &session).await.unwrap();
    assert!(s.sent.0.lock().unwrap().is_empty());

    s.f.options
        .server_side_sessions
        .expired_sessions_trigger_backchannel_logout = true;
    let ctx = s.f.validation_ctx(Utc::now());
    process_expiration(&ctx, &session).await.unwrap();
    assert_eq!(s.sent.0.lock().unwrap().len(), 1);
    let _ = GrantFilter::default();
}

#[tokio::test]
async fn the_cleanup_removes_expired_sessions_in_batches_and_processes_each() {
    let mut s = setup();
    s.f.options
        .server_side_sessions
        .remove_expired_sessions_batch_size = 1;
    let mut keys = Vec::new();
    for _ in 0..3 {
        let session = stored(&s, &["logout.back"], false).await;
        keys.push(session.key.clone().unwrap());
    }
    // Two of them expired.
    for key in &keys[..2] {
        let mut record = s.sessions.store.get_session(key).await.unwrap().unwrap();
        record.expires = Some(Utc::now() - Duration::minutes(1));
        s.sessions.store.update_session(record).await.unwrap();
    }
    let ctx = s.f.validation_ctx(Utc::now());
    let moved = rustid_core::server_side_sessions::expire_sessions(&ctx)
        .await
        .unwrap();
    assert_eq!(moved, 2);
    assert!(
        s.sent.0.lock().unwrap().is_empty(),
        "processing is the outbox's"
    );
    let processed = rustid_core::outbox::process(&ctx).await.unwrap();
    assert_eq!(processed.handled, 2);
    assert!(
        s.sessions
            .store
            .get_session(&keys[2])
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(s.sent.0.lock().unwrap().len(), 2, "each expiry notifies");
}

struct DownGrants;

#[async_trait::async_trait]
impl rustid_core::stores::PersistedGrantStore for DownGrants {
    async fn store(&self, _: PersistedGrant) -> Result<(), rustid_core::stores::StoreError> {
        Err(down())
    }
    async fn get(
        &self,
        _: &str,
    ) -> Result<Option<PersistedGrant>, rustid_core::stores::StoreError> {
        Err(down())
    }
    async fn get_all(
        &self,
        _: &GrantFilter,
    ) -> Result<Vec<PersistedGrant>, rustid_core::stores::StoreError> {
        Err(down())
    }
    async fn remove(&self, _: &str) -> Result<(), rustid_core::stores::StoreError> {
        Err(down())
    }
    async fn take(
        &self,
        _: &str,
    ) -> Result<Option<PersistedGrant>, rustid_core::stores::StoreError> {
        Err(down())
    }
    async fn remove_all(&self, _: &GrantFilter) -> Result<(), rustid_core::stores::StoreError> {
        Err(down())
    }
    async fn remove_expired(
        &self,
        _: chrono::DateTime<Utc>,
        _: usize,
        _: Option<chrono::DateTime<Utc>>,
    ) -> Result<u64, rustid_core::stores::StoreError> {
        Err(down())
    }
}

fn down() -> rustid_core::stores::StoreError {
    rustid_core::stores::StoreError::Backend("down".into())
}

/// A failing expiration is retried with backoff and
/// dropped after `max_retries` failed attempts, never blocking or looping.
#[tokio::test]
async fn failed_expirations_are_retried_then_dropped() {
    let mut s = setup();
    let session = stored(&s, &["logout.back"], false).await;
    let mut record = s
        .sessions
        .store
        .get_session(session.key.as_ref().unwrap())
        .await
        .unwrap()
        .unwrap();
    record.expires = Some(Utc::now() - Duration::minutes(1));
    s.sessions.store.update_session(record).await.unwrap();
    // Revoking the session's grants fails.
    s.f.stores.grants = Arc::new(DownGrants);
    let now = Utc::now();
    let ctx = s.f.validation_ctx(now);
    assert_eq!(
        rustid_core::server_side_sessions::expire_sessions(&ctx)
            .await
            .unwrap(),
        1
    );
    let options = s.f.options.outbox_processor.clone();
    let delay = |n| rustid_core::outbox::retry_delay(&options, n);
    let at = |t| s.f.validation_ctx(t);
    let first = rustid_core::outbox::process(&at(now)).await.unwrap();
    assert_eq!((first.retried, first.dropped), (1, 0));
    assert_eq!(
        rustid_core::outbox::process(&at(now + delay(1) - Duration::seconds(1)))
            .await
            .unwrap(),
        rustid_core::outbox::Processed::default(),
        "not due yet"
    );
    let second = rustid_core::outbox::process(&at(now + delay(1)))
        .await
        .unwrap();
    assert_eq!(second.retried, 1);
    let third = rustid_core::outbox::process(&at(now + delay(1) + delay(2)))
        .await
        .unwrap();
    assert_eq!((third.retried, third.dropped), (0, 1));
    assert_eq!(
        rustid_core::outbox::process(&at(now + Duration::days(1)))
            .await
            .unwrap(),
        rustid_core::outbox::Processed::default(),
        "gone"
    );
}

#[test]
fn retry_delays_back_off_to_the_maximum() {
    let options = rustid_core::options::OutboxProcessorOptions::default();
    let seconds: Vec<i64> = (1..=7)
        .map(|n| rustid_core::outbox::retry_delay(&options, n).num_seconds())
        .collect();
    assert_eq!(seconds, [60, 120, 240, 480, 960, 1800, 1800]);
}

#[tokio::test]
async fn an_unreadable_event_is_dropped() {
    let s = setup();
    let now = Utc::now();
    s.sessions
        .outbox
        .enqueue(rustid_core::outbox::SESSION_EXPIRED, "not a session", now)
        .await
        .unwrap();
    s.sessions
        .outbox
        .enqueue("unknown", "{}", now)
        .await
        .unwrap();
    let processed = rustid_core::outbox::process(&s.f.validation_ctx(now))
        .await
        .unwrap();
    assert_eq!(processed.dropped, 2);
}
