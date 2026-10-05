//! Behaviour every store implementation must share, run against each
//! backend by `tests/store_contract.rs`. The client and resource checks
//! expect the backend to hold `fixtures/clients.json` and
//! `fixtures/resources.json`; the grant checks expect an empty grant store.

use std::sync::Arc;

use chrono::{TimeZone, Utc};
use rustid_core::clients::Clients;
use rustid_core::grants::{GrantFilter, PersistedGrant};
use rustid_core::resources::Resources;
use rustid_core::stores::{
    ClientStore, PersistedGrantStore, ResourceStore, StoreError, find_enabled_client,
};

use crate::fixture;

pub async fn client_store(store: &dyn ClientStore) {
    let fixtures = Clients::load(&fixture("clients.json")).unwrap();
    for expected in &fixtures.clients {
        let found = store
            .find_client_by_id(&expected.client_id)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("{} not found", expected.client_id));
        assert_eq!(
            *found, *expected,
            "{} reads back unchanged",
            expected.client_id
        );
    }
    assert!(store.find_client_by_id("nobody").await.unwrap().is_none());
    assert!(
        store.find_client_by_id("CLIENT").await.unwrap().is_none(),
        "client ids are case-sensitive"
    );
    assert!(
        find_enabled_client(store, "client")
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .find_client_by_id("client.disabled")
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        find_enabled_client(store, "client.disabled")
            .await
            .unwrap()
            .is_none()
    );

    for (origin, allowed) in [
        ("https://client.test", true),
        ("https://CLIENT.TEST", true),
        ("https://client.test:443", false),
        ("http://client.test", false),
        ("https://other.test", false),
    ] {
        assert_eq!(
            store.is_cors_origin_allowed(origin).await.unwrap(),
            allowed,
            "{origin}"
        );
    }
}

pub async fn resource_store(store: &dyn ResourceStore) {
    let fixtures = Resources::load(&fixture("resources.json")).unwrap();
    let enabled = store.get_all_enabled_resources().await.unwrap();
    assert_eq!(
        *enabled,
        fixtures.enabled(),
        "enabled resources in store order"
    );
    let found = store
        .find_api_resources_by_name(&["api.disabled".into(), "other_api".into(), "nope".into()])
        .await
        .unwrap();
    let names: Vec<&str> = found.iter().map(|a| a.name.as_str()).collect();
    assert_eq!(
        names,
        ["other_api", "api.disabled"],
        "store order, disabled included"
    );
    let api = store
        .find_api_resources_by_name(&["api".into()])
        .await
        .unwrap();
    let expected: Vec<_> = fixtures
        .api_resources
        .iter()
        .filter(|a| a.name == "api")
        .cloned()
        .collect();
    assert_eq!(api, expected, "reads back unchanged, secrets included");
    assert!(
        store
            .find_api_resources_by_name(&[])
            .await
            .unwrap()
            .is_empty()
    );
}

fn grant(key: &str, client: &str, subject: Option<&str>, session: Option<&str>) -> PersistedGrant {
    PersistedGrant {
        key: key.into(),
        grant_type: "reference_token".into(),
        client_id: client.into(),
        subject_id: subject.map(Into::into),
        session_id: session.map(Into::into),
        description: None,
        creation_time: Utc.timestamp_opt(1_700_000_000, 123_456_000).unwrap(),
        expiration: None,
        consumed_time: None,
        data: "{}".into(),
    }
}

fn keys(grants: &[PersistedGrant]) -> Vec<&str> {
    let mut keys: Vec<&str> = grants.iter().map(|g| g.key.as_str()).collect();
    keys.sort();
    keys
}

pub async fn persisted_grant_store(store: Arc<dyn PersistedGrantStore>) {
    // Round trip with every optional field set.
    let full = PersistedGrant {
        key: "full".into(),
        grant_type: "refresh_token".into(),
        client_id: "c1".into(),
        subject_id: Some("alice".into()),
        session_id: Some("s1".into()),
        description: Some("laptop".into()),
        creation_time: Utc.timestamp_opt(1_700_000_000, 123_456_000).unwrap(),
        expiration: Some(Utc.timestamp_opt(1_700_003_600, 0).unwrap()),
        consumed_time: Some(Utc.timestamp_opt(1_700_000_100, 0).unwrap()),
        data: r#"{"a":1}"#.into(),
    };
    store.store(full.clone()).await.unwrap();
    assert_eq!(store.get("full").await.unwrap(), Some(full.clone()));
    let replaced = PersistedGrant {
        client_id: "c2".into(),
        consumed_time: None,
        ..full.clone()
    };
    store.store(replaced.clone()).await.unwrap();
    assert_eq!(
        store.get("full").await.unwrap(),
        Some(replaced),
        "store replaces"
    );
    store.remove("full").await.unwrap();
    assert_eq!(store.get("full").await.unwrap(), None);
    store.remove("full").await.unwrap();

    // Filters.
    store
        .store(grant("a", "c1", Some("alice"), Some("s1")))
        .await
        .unwrap();
    store
        .store(grant("b", "c1", Some("bob"), None))
        .await
        .unwrap();
    store
        .store(grant("c", "c2", Some("alice"), Some("s2")))
        .await
        .unwrap();
    store.store(grant("d", "c1", None, None)).await.unwrap();
    let empty = GrantFilter::default();
    assert_eq!(store.get_all(&empty).await, Err(StoreError::EmptyFilter));
    assert_eq!(store.remove_all(&empty).await, Err(StoreError::EmptyFilter));
    let by = |subject: Option<&str>, session: Option<&str>, client: Option<&str>| GrantFilter {
        subject_id: subject.map(Into::into),
        session_id: session.map(Into::into),
        client_id: client.map(Into::into),
        ..Default::default()
    };
    assert_eq!(
        keys(&store.get_all(&by(Some("alice"), None, None)).await.unwrap()),
        ["a", "c"]
    );
    assert_eq!(
        keys(&store.get_all(&by(None, None, Some("c1"))).await.unwrap()),
        ["a", "b", "d"]
    );
    assert_eq!(
        keys(
            &store
                .get_all(&by(Some("alice"), Some("s2"), None))
                .await
                .unwrap()
        ),
        ["c"]
    );
    let typed = GrantFilter {
        grant_type: Some("authorization_code".into()),
        ..Default::default()
    };
    assert!(store.get_all(&typed).await.unwrap().is_empty());
    store
        .remove_all(&by(Some("alice"), None, Some("c1")))
        .await
        .unwrap();
    assert_eq!(
        keys(&store.get_all(&by(None, None, Some("c1"))).await.unwrap()),
        ["b", "d"]
    );
    assert!(store.get("c").await.unwrap().is_some());
    store.remove_all(&by(None, None, Some("c1"))).await.unwrap();
    store.remove_all(&by(None, None, Some("c2"))).await.unwrap();

    // Take removes and returns, once.
    store.store(full.clone()).await.unwrap();
    assert_eq!(store.take("full").await.unwrap(), Some(full.clone()));
    assert_eq!(store.take("full").await.unwrap(), None);
    assert_eq!(store.get("full").await.unwrap(), None);

    // Of many concurrent takes of one grant, exactly one wins.
    for round in 0..5 {
        let key = format!("once{round}");
        store.store(grant(&key, "c1", None, None)).await.unwrap();
        let takers: Vec<_> = (0..8)
            .map(|_| {
                let store = store.clone();
                let key = key.clone();
                tokio::spawn(async move { store.take(&key).await.unwrap().is_some() })
            })
            .collect();
        let mut winners = 0;
        for taker in takers {
            winners += usize::from(taker.await.unwrap());
        }
        assert_eq!(winners, 1, "round {round}");
    }

    // Concurrent writers on overlapping keys.
    let workers: Vec<_> = (0..8)
        .map(|n| {
            let store = store.clone();
            tokio::spawn(async move {
                for i in 0..50 {
                    let key = format!("k{}", i % 5);
                    let client = format!("w{n}");
                    store.store(grant(&key, &client, None, None)).await.unwrap();
                    store.get(&key).await.unwrap();
                    store.remove(&key).await.unwrap();
                    store
                        .remove_all(&by(None, None, Some(&client)))
                        .await
                        .unwrap();
                }
            })
        })
        .collect();
    for worker in workers {
        worker.await.unwrap();
    }
}

fn serialized(id: &str, created_secs: i64) -> rustid_core::stores::SerializedKey {
    rustid_core::stores::SerializedKey {
        version: 1,
        id: id.into(),
        created: Utc.timestamp_opt(created_secs, 123_456_000).unwrap(),
        algorithm: "RS256".into(),
        is_x509_certificate: id.ends_with('X'),
        data: format!("data-{id}"),
        data_protected: true,
    }
}

/// Expects an empty signing key store.
pub async fn signing_key_store(store: &dyn rustid_core::stores::SigningKeyStore) {
    assert!(store.load_keys().await.unwrap().is_empty());
    let a = serialized("AAAA", 1_700_000_000);
    let b = serialized("BBBX", 1_700_000_100);
    store.store_key(b.clone()).await.unwrap();
    store.store_key(a.clone()).await.unwrap();
    let mut loaded = store.load_keys().await.unwrap();
    loaded.sort_by(|x, y| x.id.cmp(&y.id));
    assert_eq!(loaded, [a.clone(), b.clone()], "every field round-trips");
    assert_eq!(
        store.store_key(serialized("AAAA", 1)).await,
        Err(StoreError::DuplicateKey("AAAA".into()))
    );
    store.delete_key("AAAA").await.unwrap();
    store.delete_key("AAAA").await.unwrap();
    assert_eq!(store.load_keys().await.unwrap(), [b]);
}

fn server_side_session(
    key: &str,
    subject: &str,
    session: &str,
    expires: Option<i64>,
) -> rustid_core::server_side_sessions::ServerSideSession {
    rustid_core::server_side_sessions::ServerSideSession {
        key: key.into(),
        scheme: "idsrv".into(),
        subject_id: subject.into(),
        session_id: session.into(),
        display_name: Some(format!("{subject} display")),
        created: Utc.timestamp_opt(1_700_000_000, 123_456_000).unwrap(),
        renewed: Utc.timestamp_opt(1_700_000_100, 0).unwrap(),
        expires: expires.map(|e| Utc.timestamp_opt(e, 0).unwrap()),
        ticket: format!("ticket-{key}"),
    }
}

/// Create, read, update and delete by key,
/// filters, expired session removal and paged queries.
pub async fn server_side_session_store(
    store: Arc<dyn rustid_core::stores::ServerSideSessionStore>,
    outbox: Arc<dyn rustid_core::outbox::OutboxStore>,
) {
    use rustid_core::server_side_sessions::{SessionFilter, SessionQuery};

    let full = server_side_session("K1", "alice", "s1", Some(1_700_003_600));
    store.create_session(full.clone()).await.unwrap();
    assert_eq!(store.get_session("K1").await.unwrap(), Some(full.clone()));
    assert_eq!(
        store.create_session(full.clone()).await,
        Err(StoreError::DuplicateSession("K1".into()))
    );
    let updated = rustid_core::server_side_sessions::ServerSideSession {
        display_name: None,
        expires: None,
        ticket: "renewed".into(),
        ..full.clone()
    };
    store.update_session(updated.clone()).await.unwrap();
    assert_eq!(store.get_session("K1").await.unwrap(), Some(updated));
    let upserted = server_side_session("K9", "zed", "s9", None);
    store.update_session(upserted.clone()).await.unwrap();
    assert_eq!(store.get_session("K9").await.unwrap(), Some(upserted));
    store.delete_session("K9").await.unwrap();
    store.delete_session("K9").await.unwrap();
    assert_eq!(store.get_session("K9").await.unwrap(), None);

    // Filters: exact subject and session ids.
    store
        .create_session(server_side_session(
            "K2",
            "alice",
            "s2",
            Some(1_700_000_050),
        ))
        .await
        .unwrap();
    store
        .create_session(server_side_session("K3", "bob", "s3", Some(1_700_000_010)))
        .await
        .unwrap();
    let by = |sub: Option<&str>, sid: Option<&str>| SessionFilter {
        subject_id: sub.map(Into::into),
        session_id: sid.map(Into::into),
    };
    let keys = |sessions: Vec<rustid_core::server_side_sessions::ServerSideSession>| {
        let mut k: Vec<String> = sessions.into_iter().map(|s| s.key).collect();
        k.sort();
        k
    };
    assert_eq!(
        keys(store.get_sessions(&by(Some("alice"), None)).await.unwrap()),
        ["K1", "K2"]
    );
    assert_eq!(
        keys(
            store
                .get_sessions(&by(Some("alice"), Some("s2")))
                .await
                .unwrap()
        ),
        ["K2"]
    );
    assert!(
        store
            .get_sessions(&by(Some("ali"), None))
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store.get_sessions(&SessionFilter::default()).await,
        Err(StoreError::EmptyFilter)
    );
    assert_eq!(
        store.delete_sessions(&SessionFilter::default()).await,
        Err(StoreError::EmptyFilter)
    );

    // Expired sessions move into the outbox in key order, at most
    // `count`, once.
    let now = Utc.timestamp_opt(1_700_000_060, 0).unwrap();
    let expired_k2 = store.get_session("K2").await.unwrap().unwrap();
    let expired_k3 = store.get_session("K3").await.unwrap().unwrap();
    assert_eq!(store.move_expired_to_outbox(1, now).await.unwrap(), 1);
    assert_eq!(store.move_expired_to_outbox(10, now).await.unwrap(), 1);
    assert_eq!(
        store.move_expired_to_outbox(10, now).await.unwrap(),
        0,
        "K1 never expires now; nothing is left"
    );
    assert!(store.get_session("K2").await.unwrap().is_none());
    assert!(store.get_session("K3").await.unwrap().is_none());
    let events = outbox
        .claim(10, now, chrono::Duration::seconds(300))
        .await
        .unwrap();
    assert!(
        events
            .iter()
            .all(|e| e.event == rustid_core::outbox::SESSION_EXPIRED)
    );
    let moved: Vec<rustid_core::server_side_sessions::ServerSideSession> = events
        .iter()
        .map(|e| serde_json::from_str(&e.payload).unwrap())
        .collect();
    assert_eq!(moved, [expired_k2, expired_k3]);
    for e in &events {
        outbox.complete(e.id).await.unwrap();
    }

    store
        .delete_sessions(&by(Some("alice"), None))
        .await
        .unwrap();
    assert!(store.get_session("K1").await.unwrap().is_none());

    // Paged queries: substring filters, key order, tokens.
    for i in 0..5 {
        store
            .create_session(server_side_session(
                &format!("Q{i}"),
                if i % 2 == 0 { "carol" } else { "dave" },
                &format!("q{i}"),
                None,
            ))
            .await
            .unwrap();
    }
    let page = store
        .query_sessions(&SessionQuery {
            count_requested: 2,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(keys(page.results.clone()), ["Q0", "Q1"]);
    assert_eq!(
        (page.total_count, page.total_pages, page.current_page),
        (5, 3, 1)
    );
    let page = store
        .query_sessions(&SessionQuery {
            count_requested: 2,
            results_token: page.results_token,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(keys(page.results.clone()), ["Q2", "Q3"]);
    assert!(page.has_prev_results && page.has_next_results);
    let carol = store
        .query_sessions(&SessionQuery {
            subject_id: Some("aro".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(keys(carol.results), ["Q0", "Q2", "Q4"]);
    let named = store
        .query_sessions(&SessionQuery {
            display_name: Some("dave disp".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(named.total_count, 2);
    store
        .delete_sessions(&by(Some("carol"), None))
        .await
        .unwrap();
    store
        .delete_sessions(&by(Some("dave"), None))
        .await
        .unwrap();
}

/// Device authorizations by hashed device and user code.
pub async fn device_flow_store(store: Arc<dyn rustid_core::stores::DeviceFlowStore>) {
    let created = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
    let expires = created + chrono::Duration::seconds(300);
    store
        .store_device_authorization("DC1", "UC1", "client", created, expires, "d1")
        .await
        .unwrap();
    assert_eq!(
        store.find_by_user_code("UC1").await.unwrap().as_deref(),
        Some("d1")
    );
    assert_eq!(
        store.find_by_device_code("DC1").await.unwrap().as_deref(),
        Some("d1")
    );
    assert_eq!(store.find_by_user_code("DC1").await.unwrap(), None);
    assert_eq!(
        store
            .store_device_authorization("DC1", "UC2", "client", created, expires, "x")
            .await,
        Err(StoreError::DuplicateDeviceCode)
    );
    assert_eq!(
        store
            .store_device_authorization("DC2", "UC1", "client", created, expires, "x")
            .await,
        Err(StoreError::DuplicateDeviceCode)
    );
    store
        .update_by_user_code("UC1", Some("alice"), "d2")
        .await
        .unwrap();
    assert_eq!(
        store.find_by_device_code("DC1").await.unwrap().as_deref(),
        Some("d2")
    );
    assert_eq!(
        store.find_by_user_code("UC1").await.unwrap().as_deref(),
        Some("d2"),
        "found by user code after an update"
    );
    assert!(store.update_by_user_code("UC9", None, "x").await.is_err());
    assert!(store.remove_by_device_code("DC1").await.unwrap());
    assert!(!store.remove_by_device_code("DC1").await.unwrap());
    assert_eq!(store.find_by_user_code("UC1").await.unwrap(), None);
    assert_eq!(store.find_by_device_code("DC1").await.unwrap(), None);

    // Expired authorizations are purged; live ones stay.
    store
        .store_device_authorization("OLD", "UC-OLD", "client", created, expires, "old")
        .await
        .unwrap();
    let later = expires + chrono::Duration::seconds(3600);
    store
        .store_device_authorization(
            "NEW",
            "UC-NEW",
            "client",
            later,
            later + chrono::Duration::seconds(300),
            "new",
        )
        .await
        .unwrap();
    assert_eq!(store.remove_expired(later, 1000).await.unwrap(), 1);
    assert_eq!(store.find_by_device_code("OLD").await.unwrap(), None);
    assert!(store.find_by_device_code("NEW").await.unwrap().is_some());

    // In batches.
    for code in ["B1", "B2", "B3"] {
        store
            .store_device_authorization(
                code,
                &format!("U{code}"),
                "device",
                Utc.timestamp_opt(1_600_000_000, 0).unwrap(),
                Utc.timestamp_opt(1_600_000_300, 0).unwrap(),
                "{}",
            )
            .await
            .unwrap();
    }
    assert_eq!(store.remove_expired(later, 2).await.unwrap(), 2);
    assert_eq!(store.remove_expired(later, 2).await.unwrap(), 1);
    assert_eq!(store.remove_expired(later, 2).await.unwrap(), 0);
}

/// The storage purge's grant removal: expired grants, and consumed ones
/// before a cutoff when asked; never live, unexpiring or recently consumed
/// ones. Times precede every grant the other checks leave behind.
pub async fn persisted_grant_purge(store: Arc<dyn PersistedGrantStore>) {
    let t = |s| Utc.timestamp_opt(1_600_000_000 + s, 0).unwrap();
    let now = t(0);
    let make = |key: &str, expiration: Option<i64>, consumed: Option<i64>| PersistedGrant {
        key: key.into(),
        expiration: expiration.map(t),
        consumed_time: consumed.map(t),
        ..grant(key, "purge", None, None)
    };
    for g in [
        make("p-exp", Some(-1), None),
        make("p-live", Some(3600), None),
        make("p-forever", None, None),
        make("p-used-old", None, Some(-3600)),
        make("p-used-new", None, Some(-1)),
    ] {
        store.store(g).await.unwrap();
    }
    assert_eq!(store.remove_expired(now, 1000, None).await.unwrap(), 1);
    assert!(store.get("p-exp").await.unwrap().is_none());
    assert_eq!(
        store.remove_expired(now, 1000, Some(t(-60))).await.unwrap(),
        1
    );
    assert!(store.get("p-used-old").await.unwrap().is_none());
    for key in ["p-live", "p-forever", "p-used-new"] {
        assert!(store.get(key).await.unwrap().is_some(), "{key} survives");
    }
    // In batches.
    for i in 0..3 {
        store
            .store(make(&format!("p-batch-{i}"), Some(-1), None))
            .await
            .unwrap();
    }
    assert_eq!(store.remove_expired(now, 2, None).await.unwrap(), 2);
    assert_eq!(store.remove_expired(now, 2, None).await.unwrap(), 1);
    for key in ["p-live", "p-forever", "p-used-new"] {
        store.remove(key).await.unwrap();
    }
}

/// One atomic check-and-record per value, separated by
/// purpose, reusable once expired; concurrent first uses have one winner.
pub async fn replay_cache(cache: Arc<dyn rustid_core::replay::ReplayCache>) {
    let now = 1_000_000;
    assert!(cache.add_if_absent("p", "h1", now + 60, now).await.unwrap());
    assert!(
        !cache
            .add_if_absent("p", "h1", now + 60, now + 1)
            .await
            .unwrap(),
        "replay"
    );
    assert!(
        cache.add_if_absent("q", "h1", now + 60, now).await.unwrap(),
        "purpose separates"
    );
    assert!(
        cache
            .add_if_absent("p", "h1", now + 200, now + 61)
            .await
            .unwrap(),
        "an expired entry may be used again"
    );
    let wins = futures::future::join_all((0..8).map(|_| {
        let cache = cache.clone();
        async move {
            cache
                .add_if_absent("p", "race", now + 60, now)
                .await
                .unwrap()
        }
    }))
    .await;
    assert_eq!(wins.iter().filter(|w| **w).count(), 1, "one winner");
    cache.add_if_absent("p", "old", now + 1, now).await.unwrap();
    assert!(cache.remove_expired(now + 100, 1000).await.unwrap() >= 1);
    assert!(
        cache
            .add_if_absent("p", "old", now + 200, now + 100)
            .await
            .unwrap()
    );
}

/// Per key, compared at
/// millisecond precision, forgotten after the lifetime.
pub async fn throttling(t: Arc<dyn rustid_core::stores::DeviceFlowThrottling>) {
    let at = |ms| chrono::DateTime::from_timestamp_millis(ms).unwrap();
    assert!(!t.should_slow_down("c", 1, 60, at(10_900)).await.unwrap());
    assert!(
        t.should_slow_down("c", 1, 60, at(11_050)).await.unwrap(),
        "sub-second"
    );
    assert!(!t.should_slow_down("c", 1, 60, at(12_100)).await.unwrap());
    assert!(
        !t.should_slow_down("other", 1, 60, at(12_100))
            .await
            .unwrap(),
        "per key"
    );
    // The last poll is forgotten once its lifetime has passed.
    t.should_slow_down("short", 100, 1, at(13_000))
        .await
        .unwrap();
    assert!(
        !t.should_slow_down("short", 100, 1, at(14_500))
            .await
            .unwrap()
    );
    assert!(t.remove_expired(at(100_000), 1000).await.unwrap() >= 1);
}

/// The outbox (the storage): oldest first, leased so
/// no two claimers share an event, due again after a retry's delay or a
/// lapsed lease.
pub async fn outbox(o: Arc<dyn rustid_core::outbox::OutboxStore>) {
    let t0 = Utc.timestamp_opt(1_000_000, 0).unwrap();
    let s = chrono::Duration::seconds;
    let lease = s(300);
    o.enqueue("e", "a", t0).await.unwrap();
    o.enqueue("e", "b", t0).await.unwrap();
    let claimed = o.claim(10, t0, lease).await.unwrap();
    assert_eq!(
        claimed
            .iter()
            .map(|e| e.payload.as_str())
            .collect::<Vec<_>>(),
        ["a", "b"]
    );
    assert!(o.claim(10, t0, lease).await.unwrap().is_empty(), "leased");
    o.complete(claimed[0].id).await.unwrap();
    o.retry(claimed[1].id, t0 + s(60)).await.unwrap();
    assert!(o.claim(10, t0 + s(30), lease).await.unwrap().is_empty());
    let again = o.claim(10, t0 + s(61), lease).await.unwrap();
    assert_eq!((again[0].payload.as_str(), again[0].attempts), ("b", 1));
    // A crashed claimer's lease lapses: due again.
    let after = o.claim(10, t0 + s(61 + 301), lease).await.unwrap();
    assert_eq!(after.len(), 1);
    o.complete(after[0].id).await.unwrap();
    // Concurrent claimers never share an event.
    for i in 0..20 {
        o.enqueue("e", &i.to_string(), t0).await.unwrap();
    }
    let t1 = t0 + s(10_000);
    let (x, y) = tokio::join!(o.claim(15, t1, lease), o.claim(15, t1, lease));
    let (x, y) = (x.unwrap(), y.unwrap());
    assert_eq!(x.len() + y.len(), 20);
    assert!(x.iter().all(|e| y.iter().all(|f| f.id != e.id)));
    for e in x.iter().chain(&y) {
        o.complete(e.id).await.unwrap();
    }
}

/// The configuration store admin writes through, for the resource kinds:
/// Ids and keys, versions, key clashes, and the runtime resource store
/// seeing the same data. Keys are prefixed so the fixture data can share
/// the store.
pub async fn configuration_store(
    store: Arc<dyn rustid_core::stores::ConfigurationStore>,
    resources: Arc<dyn ResourceStore>,
) {
    use rustid_core::admin::EntityId;
    use rustid_core::stores::{CreateOutcome, EntityKind, StoredEntity, UpdateOutcome};

    let kind = EntityKind::ApiScope;
    let entity = |id: EntityId, key: &str, version: i32, enabled: bool| StoredEntity {
        id,
        key: key.to_owned(),
        version,
        data: serde_json::json!({ "name": key, "enabled": enabled, "displayName": key }),
    };
    let a = EntityId::new_v7();
    let b = EntityId::new_v7();
    assert_eq!(
        store
            .create(kind, &entity(a, "cs-a", 1, true))
            .await
            .unwrap(),
        CreateOutcome::Created
    );
    assert_eq!(
        store
            .create(kind, &entity(EntityId::new_v7(), "cs-a", 1, true))
            .await
            .unwrap(),
        CreateOutcome::KeyExists
    );
    store
        .create(kind, &entity(b, "cs-b", 1, true))
        .await
        .unwrap();
    let read = store.read(kind, &a).await.unwrap().unwrap();
    assert_eq!((read.key.as_str(), read.version), ("cs-a", 1));
    assert_eq!(read.data["displayName"], "cs-a");
    assert_eq!(
        store.read_by_key(kind, "cs-a").await.unwrap().unwrap().id,
        a
    );
    assert!(
        store
            .read(kind, &EntityId::new_v7())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .read(EntityKind::IdentityResource, &a)
            .await
            .unwrap()
            .is_none(),
        "kinds are separate"
    );

    // The runtime store sees what admin wrote.
    let names = |r: &rustid_core::resources::Resources| -> Vec<String> {
        r.api_scopes.iter().map(|s| s.name.clone()).collect()
    };
    assert!(
        names(&resources.get_all_enabled_resources().await.unwrap()).contains(&"cs-a".to_owned())
    );

    // Updates: versions, conflicts, renames.
    let mut renamed = entity(a, "cs-a2", 1, false);
    assert_eq!(
        store.update(kind, &renamed).await.unwrap(),
        UpdateOutcome::Updated
    );
    let read = store.read(kind, &a).await.unwrap().unwrap();
    assert_eq!((read.key.as_str(), read.version), ("cs-a2", 2));
    assert_eq!(read.data["enabled"], false);
    assert_eq!(
        store.update(kind, &renamed).await.unwrap(),
        UpdateOutcome::UnexpectedVersion
    );
    renamed.version = 2;
    renamed.key = "cs-b".into();
    assert_eq!(
        store.update(kind, &renamed).await.unwrap(),
        UpdateOutcome::KeyConflict
    );
    assert_eq!(
        store
            .update(kind, &entity(EntityId::new_v7(), "cs-x", 1, true))
            .await
            .unwrap(),
        UpdateOutcome::DoesNotExist
    );
    let enabled = names(&resources.get_all_enabled_resources().await.unwrap());
    assert!(
        !enabled.contains(&"cs-a2".to_owned()),
        "disabled: {enabled:?}"
    );
    assert!(
        !enabled.contains(&"cs-a".to_owned()),
        "renamed away: {enabled:?}"
    );

    // Concurrent updates at the same version: one wins.
    let race = entity(b, "cs-b", 1, true);
    let outcomes = futures::future::join_all((0..6).map(|_| {
        let store = store.clone();
        let race = race.clone();
        async move { store.update(kind, &race).await.unwrap() }
    }))
    .await;
    assert_eq!(
        outcomes
            .iter()
            .filter(|o| **o == UpdateOutcome::Updated)
            .count(),
        1,
        "{outcomes:?}"
    );

    let listed = store.list(kind).await.unwrap();
    assert!(listed.iter().any(|e| e.id == a) && listed.iter().any(|e| e.id == b));
    store.delete(kind, &a).await.unwrap();
    store.delete(kind, &a).await.unwrap();
    assert!(store.read(kind, &a).await.unwrap().is_none());
    store.delete(kind, &b).await.unwrap();
    let enabled = names(&resources.get_all_enabled_resources().await.unwrap());
    assert!(
        !enabled.contains(&"cs-b".to_owned()),
        "deleted: {enabled:?}"
    );
}

/// API scope and identity resource admin over a configuration store. Names carry a
/// fresh prefix, so the run can share the store with fixture data.
pub async fn resource_admin(
    store: Arc<dyn rustid_core::stores::ConfigurationStore>,
    admin: rustid_core::admin::resources::ResourceAdmin,
) {
    use rustid_core::admin::EntityId;
    use rustid_core::admin::query::{Direction, Range};
    use rustid_core::admin::resources::{ResourceConfiguration, ResourceFilter, ResourceSortField};

    let prefix = format!("ra{}-", &EntityId::new_v7().to_string()[24..]);
    let named = |name: &str| ResourceConfiguration {
        name: format!("{prefix}{name}"),
        ..Default::default()
    };
    let store = store.as_ref();
    let saved = |r: rustid_core::admin::SaveResult| r.unwrap().unwrap();
    let codes = |r: rustid_core::admin::SaveResult| -> Vec<&'static str> {
        r.unwrap().unwrap_err().iter().map(|e| e.code).collect()
    };

    // Every field round-trips; create returns version 1.
    let full = ResourceConfiguration {
        name: format!("{prefix}full"),
        enabled: false,
        display_name: Some("Test Resource".into()),
        description: Some("A description".into()),
        show_in_discovery_document: false,
        required: true,
        emphasize: true,
        user_claims: vec!["email".into(), "role".into()],
        extended_properties: Default::default(),
    };
    let created = saved(admin.create(store, full.clone()).await);
    assert_eq!(created.version, 1);
    let got = admin.get(store, &created.id).await.unwrap().unwrap();
    assert_eq!((got.id, got.version, &got.item), (created.id, 1, &full));
    let by_name = admin.get_by_name(store, &full.name).await.unwrap().unwrap();
    assert_eq!(by_name.id, created.id);
    assert!(
        admin
            .get(store, &EntityId::new_v7())
            .await
            .unwrap()
            .is_none()
    );

    // Duplicates and structure.
    assert_eq!(
        codes(admin.create(store, full.clone()).await),
        ["already_exists"]
    );
    let empty = admin
        .create(store, ResourceConfiguration::default())
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(
        (empty[0].code, empty[0].property_names.as_slice()),
        ("required", ["Name".to_owned()].as_slice())
    );
    let mut blank_claim = named("blank");
    blank_claim.user_claims = vec![" ".into()];
    assert_eq!(
        codes(admin.create(store, blank_claim).await),
        ["invalid_value"]
    );
    let mut extended = named("ext");
    extended
        .extended_properties
        .insert("owner".into(), serde_json::json!("team"));
    assert_eq!(
        codes(admin.create(store, extended).await),
        ["validation_failed"]
    );

    // Updates: applied on read, version increments, conflicts.
    let mut update = got.item.clone();
    update.display_name = Some("Updated".into());
    update.enabled = true;
    let updated = saved(admin.update(store, &created.id, update.clone(), 1).await);
    assert_eq!(updated.version, 2);
    let after = admin.get(store, &created.id).await.unwrap().unwrap();
    assert_eq!(
        (
            after.version,
            after.item.display_name.as_deref(),
            after.item.enabled
        ),
        (2, Some("Updated"), true)
    );
    assert_eq!(
        codes(admin.update(store, &created.id, update.clone(), 1).await),
        ["version_conflict"]
    );
    assert_eq!(
        codes(
            admin
                .update(store, &EntityId::new_v7(), update.clone(), 1)
                .await
        ),
        ["not_found"]
    );
    let other = saved(admin.create(store, named("other")).await);
    let mut rename = named("other");
    rename.name = full.name.clone();
    assert_eq!(
        codes(admin.update(store, &other.id, rename, 1).await),
        ["already_exists"]
    );

    // Queries: name substring, enabled, pages that don't overlap.
    for i in 0..4 {
        let mut item = named(&format!("page{i}"));
        item.enabled = i % 2 == 0;
        saved(admin.create(store, item).await);
    }
    let query = |filter: ResourceFilter, range: Range| {
        let admin = &admin;
        async move {
            admin
                .query(
                    store,
                    &filter,
                    Some((ResourceSortField::Name, Direction::Ascending)),
                    &range,
                )
                .await
                .unwrap()
                .unwrap()
        }
    };
    let pages = |page| Range::Page { page, size: 2 };
    let filter = |name: &str, enabled: Option<bool>| ResourceFilter {
        name: Some(format!("{prefix}{name}")),
        enabled,
    };
    let all = query(filter("page", None), pages(1)).await;
    assert_eq!(all.total_count, 4);
    let first: Vec<String> = all.items.iter().map(|i| i.name.clone()).collect();
    let second: Vec<String> = query(filter("page", None), pages(2))
        .await
        .items
        .iter()
        .map(|i| i.name.clone())
        .collect();
    assert_eq!(first.len(), 2);
    assert_eq!(second.len(), 2);
    assert!(first.iter().all(|n| !second.contains(n)));
    let enabled = query(filter("page", Some(true)), pages(1)).await;
    assert_eq!(enabled.total_count, 2);
    assert!(enabled.items.iter().all(|i| i.enabled));
    let descending = admin
        .query(
            store,
            &filter("page", None),
            Some((ResourceSortField::Name, Direction::Descending)),
            &Range::Page { page: 1, size: 10 },
        )
        .await
        .unwrap()
        .unwrap();
    assert!(descending.items[0].name.ends_with("page3"));

    // Delete: gone, and again is fine.
    let deleted = saved(admin.delete(store, &created.id).await);
    assert_eq!(deleted.version, 0);
    assert!(admin.get(store, &created.id).await.unwrap().is_none());
    saved(admin.delete(store, &created.id).await);
}

/// An identity resource and an API scope can't share a name, as
/// `resources_file` can't have them share one: the runtime would resolve the
/// name to the identity resource and never apply the scope.
pub async fn resource_names_span_both_kinds(
    store: Arc<dyn rustid_core::stores::ConfigurationStore>,
) {
    use rustid_core::admin::EntityId;
    use rustid_core::admin::resources::{ResourceAdmin, ResourceConfiguration};

    let name = format!("shared{}", &EntityId::new_v7().to_string()[24..]);
    let named = |n: &str| ResourceConfiguration {
        name: n.to_owned(),
        ..Default::default()
    };
    let store = store.as_ref();
    let identity = ResourceAdmin::identity_resources();
    let scopes = ResourceAdmin::api_scopes();
    identity.create(store, named(&name)).await.unwrap().unwrap();
    let clash = scopes
        .create(store, named(&name))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(clash[0].code, "already_exists");
    let scope = scopes
        .create(store, named(&format!("{name}-scope")))
        .await
        .unwrap()
        .unwrap();
    let rename = scopes
        .update(store, &scope.id, named(&name), 1)
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(rename[0].code, "already_exists");
}

/// API resource admin over a configuration store.
/// Expects the fixture resources (the `api` resource and its secret).
pub async fn api_resource_admin(store: Arc<dyn rustid_core::stores::ConfigurationStore>) {
    use rustid_core::admin::EntityId;
    use rustid_core::admin::api_resources::{
        ApiResourceAdmin, ApiResourceFilter, ApiResourceInput,
    };
    use rustid_core::admin::query::Range;
    use rustid_core::admin::resources::{ResourceAdmin, ResourceConfiguration};
    use rustid_core::admin::secrets::{CreateSecret, HashAlgorithm, hash_secret};
    use rustid_core::stores::EntityKind;

    let store_ref = store.as_ref();
    let p = format!("ar{}-", &EntityId::new_v7().to_string()[24..]);
    let admin = ApiResourceAdmin;
    let saved = |r: rustid_core::admin::SaveResult| r.unwrap().unwrap();
    let codes = |r: rustid_core::admin::SaveResult| -> Vec<&'static str> {
        r.unwrap().unwrap_err().iter().map(|e| e.code).collect()
    };
    let scope = |name: &str| ResourceConfiguration {
        name: format!("{p}{name}"),
        ..Default::default()
    };
    for name in ["s1", "s2", "s3"] {
        saved(
            ResourceAdmin::api_scopes()
                .create(store_ref, scope(name))
                .await,
        );
    }
    let input = |name: &str, scopes: &[&str]| ApiResourceInput {
        name: format!("{p}{name}"),
        scopes: scopes.iter().map(|s| format!("{p}{s}")).collect(),
        ..Default::default()
    };

    // Round trip.
    let full = ApiResourceInput {
        enabled: false,
        display_name: Some("Orders".into()),
        description: Some("The orders API".into()),
        show_in_discovery_document: false,
        require_resource_indicator: true,
        user_claims: vec!["role".into()],
        allowed_access_token_signing_algorithms: vec!["PS256".into()],
        ..input("full", &["s1", "s2"])
    };
    let created = saved(admin.create(store_ref, full.clone()).await);
    assert_eq!(created.version, 1);
    let got = admin.get(store_ref, &created.id).await.unwrap().unwrap();
    assert_eq!(got.item.name, full.name);
    assert_eq!(got.item.scopes, full.scopes);
    assert_eq!(got.item.allowed_access_token_signing_algorithms, ["PS256"]);
    assert!(got.item.require_resource_indicator && !got.item.enabled);
    assert!(got.item.api_secrets.is_empty());
    assert_eq!(
        admin
            .get_by_name(store_ref, &full.name)
            .await
            .unwrap()
            .unwrap()
            .id,
        created.id
    );

    // Validation.
    assert_eq!(
        codes(admin.create(store_ref, full.clone()).await),
        ["already_exists"]
    );
    assert_eq!(
        codes(admin.create(store_ref, ApiResourceInput::default()).await),
        ["required"]
    );
    let missing = admin
        .create(store_ref, input("missing", &["nope"]))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(
        (missing[0].code, missing[0].message.as_str()),
        (
            "invalid_value",
            format!("Scope '{p}nope' does not exist.").as_str()
        )
    );
    assert_eq!(
        codes(admin.create(store_ref, input("dup", &["s1", "s1"])).await),
        ["invalid_value"]
    );

    // Secrets: hashed, ids, no values on read.
    let secret = |value: &str, algorithm| CreateSecret {
        plaintext_value: value.into(),
        hash_algorithm: algorithm,
        description: Some("primary".into()),
        expiration: None,
        secret_type: None,
    };
    let s256 = saved(
        admin
            .create_secret(store_ref, &created.id, secret("one", None))
            .await,
    );
    assert_eq!(s256.version, 2);
    let s512 = saved(
        admin
            .create_secret(
                store_ref,
                &created.id,
                secret("two", Some(HashAlgorithm::Sha512)),
            )
            .await,
    );
    let stored = store
        .read(EntityKind::ApiResource, &created.id)
        .await
        .unwrap()
        .unwrap();
    let values: Vec<&str> = stored.data["apiSecrets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["value"].as_str().unwrap())
        .collect();
    assert_eq!(
        values,
        [
            hash_secret("one", HashAlgorithm::Sha256),
            hash_secret("two", HashAlgorithm::Sha512)
        ]
    );
    let got = admin.get(store_ref, &created.id).await.unwrap().unwrap();
    assert_eq!(got.version, 3);
    let ids: Vec<EntityId> = got.item.api_secrets.iter().map(|s| s.id).collect();
    assert_eq!(ids, [s256.id, s512.id]);
    assert_eq!(got.item.api_secrets[0].secret_type, "SharedSecret");
    assert!(
        !serde_json::to_string(&got.item)
            .unwrap()
            .contains(&hash_secret("one", HashAlgorithm::Sha256))
    );
    assert_eq!(
        codes(
            admin
                .create_secret(store_ref, &created.id, secret(" ", None))
                .await
        ),
        ["required"]
    );
    assert_eq!(
        codes(
            admin
                .create_secret(store_ref, &EntityId::new_v7(), secret("x", None))
                .await
        ),
        ["not_found"]
    );

    // Updates keep secrets, across a rename too; versions and conflicts.
    let mut update = full.clone();
    update.display_name = Some("Orders v2".into());
    update.name = format!("{p}renamed");
    update.scopes = vec![format!("{p}s3")];
    let updated = saved(
        admin
            .update(store_ref, &created.id, update.clone(), 3)
            .await,
    );
    assert_eq!(updated.version, 4);
    let after = admin.get(store_ref, &created.id).await.unwrap().unwrap();
    assert_eq!(after.item.display_name.as_deref(), Some("Orders v2"));
    assert_eq!(
        after
            .item
            .api_secrets
            .iter()
            .map(|s| s.id)
            .collect::<Vec<_>>(),
        ids
    );
    assert_eq!(
        codes(
            admin
                .update(store_ref, &created.id, update.clone(), 3)
                .await
        ),
        ["version_conflict"]
    );
    assert_eq!(
        codes(
            admin
                .update(store_ref, &EntityId::new_v7(), update.clone(), 1)
                .await
        ),
        ["not_found"]
    );
    let other = saved(admin.create(store_ref, input("other", &[])).await);
    assert_eq!(
        codes(admin.update(store_ref, &other.id, update.clone(), 1).await),
        ["already_exists"]
    );

    // Queries, including the scope filter (the back references, derived).
    let names = |filter: ApiResourceFilter| {
        let admin = &admin;
        async move {
            admin
                .query(
                    store_ref,
                    &filter,
                    None,
                    &Range::Page { page: 1, size: 100 },
                )
                .await
                .unwrap()
                .unwrap()
                .items
                .into_iter()
                .map(|i| (i.name, i.scope_count))
                .collect::<Vec<_>>()
        }
    };
    let by_scope = |s: &str| ApiResourceFilter {
        scope: Some(format!("{p}{s}")),
        ..Default::default()
    };
    assert_eq!(names(by_scope("s3")).await, [(format!("{p}renamed"), 1)]);
    assert!(names(by_scope("s1")).await.is_empty(), "scope changed away");
    assert_eq!(
        names(ApiResourceFilter {
            name: Some(p.clone()),
            enabled: Some(true),
            ..Default::default()
        })
        .await
        .len(),
        1
    );

    // Deleting secrets, and the resource.
    let deleted = saved(admin.delete_secret(store_ref, &created.id, &s256.id).await);
    assert_eq!(deleted.version, 5);
    assert_eq!(
        codes(admin.delete_secret(store_ref, &created.id, &s256.id).await),
        ["not_found"]
    );
    let left = admin.get(store_ref, &created.id).await.unwrap().unwrap();
    assert_eq!(
        left.item
            .api_secrets
            .iter()
            .map(|s| s.id)
            .collect::<Vec<_>>(),
        [s512.id]
    );
    saved(admin.delete(store_ref, &created.id).await);
    assert!(admin.get(store_ref, &created.id).await.unwrap().is_none());
    assert!(names(by_scope("s3")).await.is_empty());

    // An imported secret gets a stable id and can be deleted.
    let api = admin.get_by_name(store_ref, "api").await.unwrap().unwrap();
    let imported = api.item.api_secrets[0].id;
    assert_eq!(
        admin
            .get_by_name(store_ref, "api")
            .await
            .unwrap()
            .unwrap()
            .item
            .api_secrets[0]
            .id,
        imported
    );
    let after_delete = saved(admin.delete_secret(store_ref, &api.id, &imported).await);
    assert_eq!(after_delete.version, api.version + 1);
}

/// Client entities written through the configuration store are what the
/// runtime client store and CORS policy read, at once.
pub async fn client_configuration(
    store: Arc<dyn rustid_core::stores::ConfigurationStore>,
    clients: Arc<dyn ClientStore>,
) {
    use rustid_core::admin::EntityId;
    use rustid_core::stores::{CreateOutcome, EntityKind, StoredEntity, UpdateOutcome};

    let kind = EntityKind::Client;
    let entity = |id: EntityId, client_id: &str, version: i32, origin: &str| StoredEntity {
        id,
        key: client_id.to_owned(),
        version,
        data: serde_json::json!({
            "clientId": client_id,
            "allowedGrantTypes": ["client_credentials"],
            "allowedCorsOrigins": [origin],
        }),
    };
    let id = EntityId::new_v7();
    assert_eq!(
        store
            .create(kind, &entity(id, "cc-a", 1, "https://cc-one.example"))
            .await
            .unwrap(),
        CreateOutcome::Created
    );
    let found = clients.find_client_by_id("cc-a").await.unwrap().unwrap();
    assert_eq!(found.allowed_grant_types, ["client_credentials"]);
    assert!(
        clients
            .is_cors_origin_allowed("https://cc-one.example")
            .await
            .unwrap()
    );
    assert_eq!(
        store
            .create(
                kind,
                &entity(EntityId::new_v7(), "cc-a", 1, "https://x.example")
            )
            .await
            .unwrap(),
        CreateOutcome::KeyExists
    );

    // A rename with a new origin moves both lookups.
    assert_eq!(
        store
            .update(kind, &entity(id, "cc-b", 1, "https://cc-two.example"))
            .await
            .unwrap(),
        UpdateOutcome::Updated
    );
    assert!(clients.find_client_by_id("cc-a").await.unwrap().is_none());
    assert!(clients.find_client_by_id("cc-b").await.unwrap().is_some());
    assert!(
        !clients
            .is_cors_origin_allowed("https://cc-one.example")
            .await
            .unwrap()
    );
    assert!(
        clients
            .is_cors_origin_allowed("https://cc-two.example")
            .await
            .unwrap()
    );
    assert_eq!(
        store
            .read_by_key(kind, "cc-b")
            .await
            .unwrap()
            .unwrap()
            .version,
        2
    );

    store.delete(kind, &id).await.unwrap();
    assert!(clients.find_client_by_id("cc-b").await.unwrap().is_none());
    assert!(
        !clients
            .is_cors_origin_allowed("https://cc-two.example")
            .await
            .unwrap()
    );
    // The imported clients are entities too.
    let fixture_client = store.read_by_key(kind, "client").await.unwrap().unwrap();
    assert_eq!(fixture_client.data["clientId"], "client");
}

/// Clients with their secrets, through the admin
/// service.
pub async fn client_admin(store: Arc<dyn rustid_core::stores::ConfigurationStore>) {
    use rustid_core::admin::EntityId;
    use rustid_core::admin::clients::{ClientAdmin, ClientFilter, ClientInput, ClientSortField};
    use rustid_core::admin::query::{Direction, Range};
    use rustid_core::admin::secrets::{CreateSecret, HashAlgorithm, hash_secret};
    use rustid_core::clients::Client;
    use rustid_core::stores::EntityKind;

    let store_ref = store.as_ref();
    let p = format!("cl{}-", &EntityId::new_v7().to_string()[24..]);
    let admin = ClientAdmin::default();
    let saved = |r: rustid_core::admin::SaveResult| r.unwrap().unwrap();
    let errors = |r: rustid_core::admin::SaveResult| -> Vec<(&'static str, String, Vec<String>)> {
        r.unwrap()
            .unwrap_err()
            .into_iter()
            .map(|e| (e.code, e.message, e.property_names))
            .collect()
    };
    let secret = |value: &str, algorithm: Option<HashAlgorithm>| CreateSecret {
        plaintext_value: value.into(),
        hash_algorithm: algorithm,
        description: Some(format!("{value} secret")),
        expiration: None,
        secret_type: None,
    };
    // A machine client: client credentials with one secret.
    let machine = |name: &str| ClientInput {
        client: Client {
            client_id: format!("{p}{name}"),
            allowed_grant_types: vec!["client_credentials".into()],
            allowed_scopes: vec!["api1".into()],
            ..Default::default()
        },
        client_secrets: vec![secret("s3cret", None)],
        ..Default::default()
    };

    // Round trip of every field the runtime reads.
    let mut full = machine("full");
    full.client = Client {
        client_name: Some("Full".into()),
        client_uri: Some("https://full.example".into()),
        allowed_grant_types: vec!["authorization_code".into(), "client_credentials".into()],
        redirect_uris: vec!["https://full.example/cb".into()],
        post_logout_redirect_uris: vec!["https://full.example/out".into()],
        allowed_cors_origins: vec!["https://full.example".into()],
        access_token_lifetime: 120,
        access_token_type: rustid_core::clients::AccessTokenType::Reference,
        allow_offline_access: true,
        require_dpop: true,
        dpop_clock_skew: rustid_core::options::TimeSpan(30),
        claims: vec![rustid_core::clients::ClientClaim {
            claim_type: "tier".into(),
            value: "gold".into(),
            ..Default::default()
        }],
        ..full.client
    };
    let created = saved(admin.create(store_ref, full.clone()).await);
    assert_eq!(created.version, 1);
    let got = admin.get(store_ref, &created.id).await.unwrap().unwrap();
    assert_eq!((got.id, got.version), (created.id, 1));
    let mut expected = full.client.clone();
    expected.client_secrets = got.item.client.client_secrets.clone();
    assert_eq!(got.item.client, expected);
    assert!(
        got.item.client.client_secrets.is_empty(),
        "secret values are never read back"
    );
    assert_eq!(got.item.client_secrets.len(), 1);
    assert_eq!(got.item.client_secrets[0].secret_type, "SharedSecret");
    let json = serde_json::to_value(&got.item).unwrap();
    assert!(
        !json
            .to_string()
            .contains(&hash_secret("s3cret", HashAlgorithm::Sha256))
    );
    assert_eq!(json["clientSecrets"][0]["description"], "s3cret secret");
    assert_eq!(json["extendedProperties"], serde_json::json!({}));
    assert_eq!(
        admin
            .get_by_client_id(store_ref, &full.client.client_id)
            .await
            .unwrap()
            .unwrap()
            .id,
        created.id
    );
    // The stored secret is the hash, which the runtime reads.
    let stored = store_ref
        .read(EntityKind::Client, &created.id)
        .await
        .unwrap()
        .unwrap();
    let runtime: Client = serde_json::from_value(stored.data).unwrap();
    assert_eq!(
        runtime.client_secrets[0].value,
        hash_secret("s3cret", HashAlgorithm::Sha256)
    );

    // Create validation, in order.
    assert_eq!(
        errors(admin.create(store_ref, full.clone()).await)[0].0,
        "already_exists"
    );
    let with = |f: &dyn Fn(&mut ClientInput)| {
        let mut input = machine("v");
        f(&mut input);
        input
    };
    let cases: Vec<(ClientInput, &str, &str, &str)> = vec![
        (
            with(&|i| i.client_secrets = vec![secret(" ", None)]),
            "required",
            "A value is required.",
            "ClientSecrets.PlaintextValue",
        ),
        (
            with(&|i| i.client_secrets[0].secret_type = Some(" ".into())),
            "invalid_value",
            "Secret type must not be empty or whitespace.",
            "ClientSecrets.Type",
        ),
        (
            with(&|i| i.client.client_id = " ".into()),
            "required",
            "A value is required.",
            "ClientId",
        ),
        (
            with(&|i| i.client.client_name = Some("".into())),
            "invalid_value",
            "Client name must not be empty or whitespace.",
            "ClientName",
        ),
        (
            with(&|i| i.client.allowed_grant_types.push(" ".into())),
            "invalid_value",
            "Grant type must not be null or whitespace.",
            "AllowedGrantTypes",
        ),
        (
            with(&|i| i.client.allowed_grant_types.push("a b".into())),
            "invalid_value",
            "Grant type 'a b' contains spaces.",
            "AllowedGrantTypes",
        ),
        (
            with(&|i| {
                i.client
                    .allowed_grant_types
                    .push("client_credentials".into())
            }),
            "invalid_value",
            "Grant types list contains duplicate values.",
            "AllowedGrantTypes",
        ),
        (
            with(&|i| i.client.allowed_scopes.push("".into())),
            "invalid_value",
            "Scope must not be null or whitespace.",
            "AllowedScopes",
        ),
        (
            with(&|i| i.client.allowed_cors_origins.push(" ".into())),
            "invalid_value",
            "CORS origin must not be null or whitespace.",
            "AllowedCorsOrigins",
        ),
        (
            with(&|i| i.client.redirect_uris.push("".into())),
            "invalid_value",
            "Redirect URI must not be null or whitespace.",
            "RedirectUris",
        ),
        (
            with(&|i| i.client.post_logout_redirect_uris.push("".into())),
            "invalid_value",
            "Post-logout redirect URI must not be null or whitespace.",
            "PostLogoutRedirectUris",
        ),
    ];
    for (input, code, message, property) in cases {
        let found = errors(admin.create(store_ref, input).await);
        assert_eq!(
            found[0],
            (code, message.to_owned(), vec![property.to_owned()]),
            "{message}"
        );
    }
    let combined = with(&|i| {
        i.client.allowed_grant_types = vec!["implicit".into(), "authorization_code".into()];
        i.client.redirect_uris = vec!["https://x.example/cb".into()];
    });
    assert_eq!(
        errors(admin.create(store_ref, combined).await)[0],
        (
            "validation_failed",
            "Grant types list cannot contain both implicit and authorization_code.".to_owned(),
            vec!["AllowedGrantTypes".to_owned()]
        )
    );
    // The configuration validator.
    let no_redirect = with(&|i| i.client.allowed_grant_types = vec!["authorization_code".into()]);
    assert_eq!(
        errors(admin.create(store_ref, no_redirect).await)[0],
        (
            "validation_failed",
            "No redirect URI configured.".to_owned(),
            vec![]
        )
    );
    // Admin stores every client as oidc, so the validator always runs.
    let saml = with(&|i| {
        i.client.protocol_type = "saml2p".into();
        i.client.allowed_grant_types = vec!["authorization_code".into()];
    });
    assert_eq!(
        errors(admin.create(store_ref, saml).await)[0].1,
        "No redirect URI configured."
    );
    let mut other_protocol = machine("protocol");
    other_protocol.client.protocol_type = "wsfed".into();
    let protocol_id = saved(admin.create(store_ref, other_protocol).await).id;
    assert_eq!(
        admin
            .get(store_ref, &protocol_id)
            .await
            .unwrap()
            .unwrap()
            .item
            .client
            .protocol_type,
        "oidc"
    );
    let no_secret = with(&|i| i.client_secrets.clear());
    assert_eq!(
        errors(admin.create(store_ref, no_secret).await)[0].1,
        "Client secret is required for client_credentials, but no client secret is configured."
    );
    let extended = with(&|i| {
        i.extended_properties
            .insert("x".into(), serde_json::json!(1));
    });
    assert_eq!(
        errors(admin.create(store_ref, extended).await)[0].1,
        "Attribute 'x' is not defined in the schema."
    );
    // Nothing was stored by a failed create.
    assert!(
        admin
            .get_by_client_id(store_ref, &format!("{p}v"))
            .await
            .unwrap()
            .is_none()
    );

    // JSON input: strict, with null lists meaning empty.
    let parsed = ClientInput::from_json(
        serde_json::json!({
            "clientId": format!("{p}json"),
            "allowedGrantTypes": ["client_credentials"],
            "redirectUris": null,
            "allowedScopes": null,
            "clientSecrets": [{ "plaintextValue": "x" }],
            "dPoPClockSkew": "00:00:10",
        }),
        true,
    )
    .unwrap();
    assert!(parsed.client.redirect_uris.is_empty());
    assert_eq!(parsed.client_secrets[0].plaintext_value, "x");
    let json_created = saved(admin.create(store_ref, parsed).await);
    let unknown = ClientInput::from_json(
        serde_json::json!({ "clientId": "x", "noSuchSetting": true }),
        true,
    )
    .unwrap_err();
    assert_eq!(unknown.code, "invalid_value");
    assert_eq!(unknown.property_names, ["noSuchSetting"]);
    // A read sent back as an update parses, its secrets ignored.
    let read_back = serde_json::to_value(
        &admin
            .get(store_ref, &json_created.id)
            .await
            .unwrap()
            .unwrap()
            .item,
    )
    .unwrap();
    let back = ClientInput::from_json(read_back, false).unwrap();
    assert!(back.client_secrets.is_empty());
    assert_eq!(
        saved(admin.update(store_ref, &json_created.id, back, 1).await).version,
        2
    );

    // Update: applies, bumps the version, keeps secrets.
    let mut changed = full.clone();
    changed.client.client_name = Some("Renamed".into());
    changed.client.client_id = format!("{p}full2");
    changed.client_secrets.clear();
    // The update carries no secrets: the existing one satisfies the
    // configuration validator.
    let updated = saved(
        admin
            .update(store_ref, &created.id, changed.clone(), 1)
            .await,
    );
    assert_eq!((updated.id, updated.version), (created.id, 2));
    let got = admin.get(store_ref, &created.id).await.unwrap().unwrap();
    assert_eq!(got.item.client.client_name.as_deref(), Some("Renamed"));
    assert_eq!(got.item.client_secrets.len(), 1, "secrets survive updates");
    assert_eq!(
        errors(
            admin
                .update(store_ref, &created.id, changed.clone(), 1)
                .await
        )[0]
        .0,
        "version_conflict"
    );
    assert_eq!(
        errors(
            admin
                .update(store_ref, &EntityId::new_v7(), changed.clone(), 1)
                .await
        )[0]
        .0,
        "not_found"
    );
    let mut clash = changed.clone();
    clash.client.client_id = format!("{p}json");
    assert_eq!(
        errors(admin.update(store_ref, &created.id, clash, 2).await)[0].0,
        "already_exists"
    );
    let mut invalid = changed.clone();
    invalid.client.allowed_grant_types = vec!["authorization_code".into()];
    invalid.client.redirect_uris.clear();
    assert_eq!(
        errors(admin.update(store_ref, &created.id, invalid, 2).await)[0].0,
        "validation_failed"
    );

    // Secrets.
    let sha512 = saved(
        admin
            .create_secret(
                store_ref,
                &created.id,
                secret("other", Some(HashAlgorithm::Sha512)),
            )
            .await,
    );
    assert_eq!(sha512.version, 3);
    let stored = store_ref
        .read(EntityKind::Client, &created.id)
        .await
        .unwrap()
        .unwrap();
    let runtime: Client = serde_json::from_value(stored.data).unwrap();
    assert!(
        runtime
            .client_secrets
            .iter()
            .any(|s| s.value == hash_secret("other", HashAlgorithm::Sha512))
    );
    assert_eq!(
        errors(
            admin
                .create_secret(store_ref, &created.id, secret("", None))
                .await
        )[0],
        (
            "required",
            "A value is required.".to_owned(),
            vec!["PlaintextValue".to_owned()]
        )
    );
    let mut blank_type = secret("y", None);
    blank_type.secret_type = Some("".into());
    assert_eq!(
        errors(
            admin
                .create_secret(store_ref, &created.id, blank_type)
                .await
        )[0]
        .2,
        ["Type"]
    );
    assert_eq!(
        errors(
            admin
                .create_secret(store_ref, &EntityId::new_v7(), secret("y", None))
                .await
        )[0]
        .0,
        "not_found"
    );
    let removed = saved(
        admin
            .delete_secret(store_ref, &created.id, &sha512.id)
            .await,
    );
    assert_eq!(removed.version, 4);
    let got = admin.get(store_ref, &created.id).await.unwrap().unwrap();
    assert!(got.item.client_secrets.iter().all(|s| s.id != sha512.id));
    assert_eq!(
        errors(
            admin
                .delete_secret(store_ref, &created.id, &sha512.id)
                .await
        )[0]
        .0,
        "not_found"
    );

    // Query.
    for name in ["q1", "q2", "q3"] {
        saved(admin.create(store_ref, machine(name)).await);
    }
    let mut disabled = machine("q4");
    disabled.client.enabled = false;
    disabled.client.allowed_scopes = vec!["api2".into()];
    saved(admin.create(store_ref, disabled).await);
    let query = |filter: ClientFilter| {
        let admin = &admin;
        async move {
            admin
                .query(store_ref, &filter, None, &Range::default())
                .await
                .unwrap()
                .unwrap()
        }
    };
    let ids = |r: &rustid_core::admin::query::QueryResult<_>| -> Vec<String> {
        r.items
            .iter()
            .map(|i: &rustid_core::admin::clients::ClientListItem| i.client_id.clone())
            .collect()
    };
    let by_prefix = query(ClientFilter {
        client_id: Some(format!("{p}q")),
        ..Default::default()
    })
    .await;
    assert_eq!(
        ids(&by_prefix),
        ["q1", "q2", "q3", "q4"].map(|n| format!("{p}{n}"))
    );
    assert_eq!(by_prefix.items[0].allowed_scope_count, 1);
    assert_eq!(
        by_prefix.items[0].allowed_grant_types,
        ["client_credentials"]
    );
    let disabled = query(ClientFilter {
        client_id: Some(p.clone()),
        enabled: Some(false),
        ..Default::default()
    })
    .await;
    assert_eq!(ids(&disabled), [format!("{p}q4")]);
    let scoped = query(ClientFilter {
        client_id: Some(p.clone()),
        allowed_scope: Some("api2".into()),
        ..Default::default()
    })
    .await;
    assert_eq!(ids(&scoped), [format!("{p}q4")]);
    let granted = query(ClientFilter {
        client_id: Some(p.clone()),
        grant_type: Some("authorization_code".into()),
        ..Default::default()
    })
    .await;
    assert_eq!(ids(&granted), [format!("{p}full2")]);
    let named = query(ClientFilter {
        client_name: Some("Renam".into()),
        ..Default::default()
    })
    .await;
    assert_eq!(ids(&named), [format!("{p}full2")]);
    let page = |n: u32| {
        let admin = &admin;
        let p = p.clone();
        async move {
            admin
                .query(
                    store_ref,
                    &ClientFilter {
                        client_id: Some(format!("{p}q")),
                        ..Default::default()
                    },
                    Some((ClientSortField::ClientId, Direction::Descending)),
                    &Range::Page { page: n, size: 3 },
                )
                .await
                .unwrap()
                .unwrap()
        }
    };
    let (first, second) = (page(1).await, page(2).await);
    assert_eq!(first.total_count, 4);
    assert_eq!(ids(&first), ["q4", "q3", "q2"].map(|n| format!("{p}{n}")));
    assert_eq!(ids(&second), [format!("{p}q1")]);

    // Delete.
    saved(admin.delete(store_ref, &created.id).await);
    assert!(admin.get(store_ref, &created.id).await.unwrap().is_none());
    saved(admin.delete(store_ref, &created.id).await);
}

/// Data extension schemas through `SchemaAdmin`: ids
/// compare case-insensitively, versions guard updates.
pub async fn schema_admin(store: Arc<dyn rustid_core::stores::ConfigurationStore>) {
    use rustid_core::admin::schemas::{
        AttributeDefinition, SchemaAdmin, SchemaConfiguration, schema_for,
    };

    let store_ref = store.as_ref();
    let p = format!(
        "sc{}",
        &rustid_core::admin::EntityId::new_v7().to_string()[24..]
    );
    let schema = |id: &str, codes: &[&str]| SchemaConfiguration {
        schema_id: id.to_owned(),
        display_name: Some(format!("{id} schema")),
        attribute_definitions: codes
            .iter()
            .map(|c| AttributeDefinition {
                code: (*c).to_owned(),
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    };
    let saved = |r: rustid_core::admin::SaveResult| r.unwrap().unwrap();
    let code = |r: rustid_core::admin::SaveResult| r.unwrap().unwrap_err()[0].code;

    let id = format!("{p}-Kind");
    let created = saved(
        SchemaAdmin
            .create(store_ref, schema(&id, &["a", "b"]))
            .await,
    );
    assert_eq!(created.version, 1);
    assert_eq!(
        code(
            SchemaAdmin
                .create(store_ref, schema(&id.to_uppercase(), &["a"]))
                .await
        ),
        "already_exists"
    );
    assert_eq!(
        code(SchemaAdmin.create(store_ref, schema("a.b", &["a"])).await),
        "invalid_value"
    );
    let got = SchemaAdmin
        .get(store_ref, &id.to_lowercase())
        .await
        .unwrap()
        .unwrap();
    assert_eq!((got.id, got.version), (created.id, 1));
    assert_eq!(
        got.item,
        schema(&id, &["a", "b"]),
        "the id keeps its casing"
    );
    assert_eq!(
        schema_for(store_ref, &id.to_uppercase())
            .await
            .unwrap()
            .unwrap()
            .attribute_definitions
            .len(),
        2
    );

    // Updates.
    let updated = saved(
        SchemaAdmin
            .update(store_ref, &id, schema(&id, &["a", "b", "c"]), 1)
            .await,
    );
    assert_eq!(updated.version, 2);
    assert_eq!(
        code(
            SchemaAdmin
                .update(store_ref, &id, schema(&id, &["a"]), 1)
                .await
        ),
        "version_conflict"
    );
    let mismatch = SchemaAdmin
        .update(store_ref, &id, schema("other", &["a"]), 2)
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(
        (mismatch[0].code, mismatch[0].message.as_str()),
        (
            "invalid_value",
            "Schema ID in the body must match the route schema ID."
        )
    );
    assert_eq!(
        code(
            SchemaAdmin
                .update(
                    store_ref,
                    &format!("{p}-none"),
                    schema(&format!("{p}-none"), &[]),
                    1
                )
                .await
        ),
        "not_found"
    );

    // Query summaries, sorted by id.
    saved(
        SchemaAdmin
            .create(store_ref, schema(&format!("{p}-Another"), &["x"]))
            .await,
    );
    let summaries: Vec<_> = SchemaAdmin
        .query(store_ref)
        .await
        .unwrap()
        .into_iter()
        .filter(|s| s.schema_id.starts_with(&p))
        .collect();
    assert_eq!(
        summaries
            .iter()
            .map(|s| (s.schema_id.as_str(), s.attribute_count))
            .collect::<Vec<_>>(),
        [(format!("{p}-Another").as_str(), 1), (id.as_str(), 3)]
    );

    // Delete is idempotent.
    saved(SchemaAdmin.delete(store_ref, &id.to_uppercase()).await);
    assert!(SchemaAdmin.get(store_ref, &id).await.unwrap().is_none());
    saved(SchemaAdmin.delete(store_ref, &id).await);
}

/// `*ExtendedPropertiesTests`: extended properties on every kind, checked
/// against the kind's registered schema, round-tripped, and their string
/// values visible to the runtime stores as `properties`. Registers and then
/// removes the four kinds' schemas.
pub async fn extended_properties(
    store: Arc<dyn rustid_core::stores::ConfigurationStore>,
    clients: Arc<dyn ClientStore>,
    resources: Arc<dyn ResourceStore>,
) {
    use rustid_core::admin::EntityId;
    use rustid_core::admin::api_resources::{ApiResourceAdmin, ApiResourceInput};
    use rustid_core::admin::clients::{ClientAdmin, ClientInput};
    use rustid_core::admin::resources::{ResourceAdmin, ResourceConfiguration};
    use rustid_core::admin::schemas::SchemaAdmin;
    use serde_json::{Map, Value, json};

    let store_ref = store.as_ref();
    let p = format!("ep{}-", &EntityId::new_v7().to_string()[24..]);
    let saved = |r: rustid_core::admin::SaveResult| r.unwrap().unwrap();
    let failure = |r: rustid_core::admin::SaveResult| {
        let errors = r.unwrap().unwrap_err();
        (errors[0].code, errors[0].message.clone())
    };
    let props = |v: Value| match v {
        Value::Object(map) => map,
        _ => unreachable!(),
    };
    let department = || props(json!({ "department": "Engineering", "cost_center": 1042 }));
    let unknown = || props(json!({ "unknown_attribute": "value" }));
    let not_defined = (
        "validation_failed",
        "Attribute 'unknown_attribute' is not defined in the schema.".to_owned(),
    );

    // Without schemas, any extended property is refused.
    assert_eq!(
        failure(
            ResourceAdmin::api_scopes()
                .create(
                    store_ref,
                    ResourceConfiguration {
                        name: format!("{p}noschema"),
                        extended_properties: props(json!({ "department": "x" })),
                        ..Default::default()
                    },
                )
                .await
        ),
        (
            "validation_failed",
            "Attribute 'department' is not defined in the schema.".to_owned()
        )
    );

    for id in ["client", "api-resource", "api-scope", "identity-resource"] {
        let schema = serde_json::from_value(json!({
            "schemaId": id,
            "attributeDefinitions": [
                { "code": "department", "attributeType": { "kind": "scalar", "dataType": "String" } },
                { "code": "cost_center", "attributeType": { "kind": "scalar", "dataType": "Integer" } },
                { "code": "environment", "attributeType": { "kind": "scalar", "dataType": "String" } },
            ],
        }))
        .unwrap();
        saved(SchemaAdmin.create(store_ref, schema).await);
    }

    // Clients.
    let client = |name: &str, extended: Map<String, Value>| ClientInput {
        client: rustid_core::clients::Client {
            client_id: format!("{p}{name}"),
            allowed_grant_types: vec!["client_credentials".into()],
            ..Default::default()
        },
        client_secrets: vec![rustid_core::admin::secrets::CreateSecret {
            plaintext_value: "s".into(),
            hash_algorithm: None,
            description: None,
            expiration: None,
            secret_type: None,
        }],
        extended_properties: extended,
    };
    let admin = ClientAdmin::default();
    assert_eq!(
        failure(admin.create(store_ref, client("bad", unknown())).await),
        not_defined
    );
    let created = saved(admin.create(store_ref, client("c", department())).await);
    let got = admin.get(store_ref, &created.id).await.unwrap().unwrap();
    assert_eq!(got.item.extended_properties, department());
    let json = serde_json::to_value(&got.item).unwrap();
    assert_eq!(json["extendedProperties"]["cost_center"], 1042);
    assert!(
        json.get("properties").is_none(),
        "runtime properties aren't admin's"
    );
    let runtime = clients
        .find_client_by_id(&format!("{p}c"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        runtime.properties.get("department").map(String::as_str),
        Some("Engineering")
    );
    assert!(!runtime.properties.contains_key("cost_center"));
    let mut update = client("c", props(json!({ "department": "Finance" })));
    update.client_secrets.clear();
    saved(
        admin
            .update(store_ref, &created.id, update.clone(), 1)
            .await,
    );
    assert_eq!(
        admin
            .get(store_ref, &created.id)
            .await
            .unwrap()
            .unwrap()
            .item
            .extended_properties,
        props(json!({ "department": "Finance" }))
    );
    update.extended_properties = unknown();
    assert_eq!(
        failure(
            admin
                .update(store_ref, &created.id, update.clone(), 2)
                .await
        ),
        not_defined
    );
    update.extended_properties = Map::new();
    saved(admin.update(store_ref, &created.id, update, 2).await);
    assert!(
        admin
            .get(store_ref, &created.id)
            .await
            .unwrap()
            .unwrap()
            .item
            .extended_properties
            .is_empty()
    );
    assert!(
        clients
            .find_client_by_id(&format!("{p}c"))
            .await
            .unwrap()
            .unwrap()
            .properties
            .is_empty()
    );
    let plain = saved(admin.create(store_ref, client("plain", Map::new())).await);
    assert!(
        admin
            .get(store_ref, &plain.id)
            .await
            .unwrap()
            .unwrap()
            .item
            .extended_properties
            .is_empty()
    );
    saved(admin.delete(store_ref, &created.id).await);
    saved(admin.delete(store_ref, &plain.id).await);

    // API scopes and identity resources.
    for kind in [
        ResourceAdmin::api_scopes(),
        ResourceAdmin::identity_resources(),
    ] {
        let named = |name: &str, extended: Map<String, Value>| ResourceConfiguration {
            name: format!("{p}{name}"),
            extended_properties: extended,
            ..Default::default()
        };
        assert_eq!(
            failure(kind.create(store_ref, named("bad", unknown())).await),
            not_defined
        );
        let suffix = format!("{:?}", kind.kind()).to_lowercase();
        let created = saved(kind.create(store_ref, named(&suffix, department())).await);
        let got = kind.get(store_ref, &created.id).await.unwrap().unwrap();
        assert_eq!(got.item.extended_properties, department());
        let enabled = resources.get_all_enabled_resources().await.unwrap();
        let properties = match kind.kind() {
            rustid_core::stores::EntityKind::ApiScope => enabled
                .api_scopes
                .iter()
                .find(|s| s.name == format!("{p}{suffix}"))
                .map(|s| s.properties.clone()),
            _ => enabled
                .identity_resources
                .iter()
                .find(|s| s.name == format!("{p}{suffix}"))
                .map(|s| s.properties.clone()),
        }
        .unwrap();
        assert_eq!(
            properties.get("department").map(String::as_str),
            Some("Engineering")
        );
        let mut update = named(&suffix, unknown());
        assert_eq!(
            failure(kind.update(store_ref, &created.id, update.clone(), 1).await),
            not_defined
        );
        update.extended_properties = Map::new();
        saved(kind.update(store_ref, &created.id, update, 1).await);
        assert!(
            kind.get(store_ref, &created.id)
                .await
                .unwrap()
                .unwrap()
                .item
                .extended_properties
                .is_empty()
        );
        saved(kind.delete(store_ref, &created.id).await);
    }

    // API resources.
    let api = |name: &str, extended: Map<String, Value>| ApiResourceInput {
        name: format!("{p}{name}"),
        extended_properties: extended,
        ..Default::default()
    };
    assert_eq!(
        failure(
            ApiResourceAdmin
                .create(store_ref, api("bad", unknown()))
                .await
        ),
        not_defined
    );
    let created = saved(
        ApiResourceAdmin
            .create(store_ref, api("api", department()))
            .await,
    );
    assert_eq!(
        ApiResourceAdmin
            .get(store_ref, &created.id)
            .await
            .unwrap()
            .unwrap()
            .item
            .extended_properties,
        department()
    );
    let found = resources
        .find_api_resources_by_name(&[format!("{p}api")])
        .await
        .unwrap();
    assert_eq!(
        found[0].properties.get("department").map(String::as_str),
        Some("Engineering")
    );
    assert_eq!(
        failure(
            ApiResourceAdmin
                .update(store_ref, &created.id, api("api", unknown()), 1)
                .await
        ),
        not_defined
    );
    saved(
        ApiResourceAdmin
            .update(store_ref, &created.id, api("api", Map::new()), 1)
            .await,
    );
    saved(ApiResourceAdmin.delete(store_ref, &created.id).await);

    // A schema change hides the values it no longer accepts (reads
    // do), so an update sent back from a read succeeds and drops them.
    let scopes = ResourceAdmin::api_scopes();
    let scope = saved(
        scopes
            .create(
                store_ref,
                ResourceConfiguration {
                    name: format!("{p}changing"),
                    extended_properties: department(),
                    ..Default::default()
                },
            )
            .await,
    );
    let narrowed = serde_json::from_value(json!({
        "schemaId": "api-scope",
        "attributeDefinitions": [
            { "code": "department", "attributeType": { "kind": "scalar", "dataType": "Integer" } },
            { "code": "environment", "attributeType": { "kind": "scalar", "dataType": "String" } },
        ],
    }))
    .unwrap();
    saved(
        SchemaAdmin
            .update(store_ref, "api-scope", narrowed, 1)
            .await,
    );
    let read = scopes.get(store_ref, &scope.id).await.unwrap().unwrap();
    assert!(
        read.item.extended_properties.is_empty(),
        "{:?}",
        read.item.extended_properties
    );
    saved(scopes.update(store_ref, &scope.id, read.item, 1).await);
    saved(SchemaAdmin.delete(store_ref, "api-scope").await);
    let read = scopes.get(store_ref, &scope.id).await.unwrap().unwrap();
    saved(scopes.update(store_ref, &scope.id, read.item, 2).await);
    saved(scopes.delete(store_ref, &scope.id).await);

    for id in ["client", "api-resource", "api-scope", "identity-resource"] {
        saved(SchemaAdmin.delete(store_ref, id).await);
    }
}

/// Criteria AND together, while a single value
/// and a list of the same criterion (a client id and client ids, a type
/// and types) merge into one set.
pub async fn persisted_grant_filters(store: Arc<dyn PersistedGrantStore>) {
    let p = format!("pf{}-", Utc::now().timestamp_nanos_opt().unwrap());
    let make = |key: &str, subject: Option<&str>, client: &str, grant_type: &str| PersistedGrant {
        key: format!("{p}{key}"),
        grant_type: format!("{p}{grant_type}"),
        client_id: format!("{p}{client}"),
        subject_id: subject.map(|s| format!("{p}{s}")),
        session_id: None,
        description: Some("test grant".into()),
        creation_time: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
        expiration: None,
        consumed_time: None,
        data: r#"{"test":true}"#.into(),
    };
    let grants = [
        make("both", Some("alice"), "c1", "t1"),
        make("subject", Some("alice"), "other", "t2"),
        make("client", Some("bob"), "c1", "t3"),
        make("c2", None, "c2", "excluded"),
    ];
    for g in &grants {
        store.store(g.clone()).await.unwrap();
    }
    let p = |s: &str| format!("{p}{s}");
    let found = |filter: GrantFilter| {
        let store = store.clone();
        async move {
            let mut keys: Vec<String> = store
                .get_all(&filter)
                .await
                .unwrap()
                .into_iter()
                .map(|g| g.key)
                .collect();
            keys.sort();
            keys
        }
    };
    assert_eq!(
        found(GrantFilter {
            subject_id: Some(p("alice")),
            client_id: Some(p("c1")),
            ..Default::default()
        })
        .await,
        [p("both")],
        "different criteria AND"
    );
    assert_eq!(
        found(GrantFilter {
            client_ids: vec![p("c1"), p("c2")],
            ..Default::default()
        })
        .await,
        [p("both"), p("c2"), p("client")]
    );
    assert_eq!(
        found(GrantFilter {
            client_id: Some(p("other")),
            client_ids: vec![p("c2")],
            ..Default::default()
        })
        .await,
        [p("c2"), p("subject")],
        "ClientId and ClientIds merge"
    );
    assert_eq!(
        found(GrantFilter {
            grant_types: vec![p("t1"), p("t2")],
            ..Default::default()
        })
        .await,
        [p("both"), p("subject")]
    );
    assert_eq!(
        found(GrantFilter {
            grant_type: Some(p("t1")),
            grant_types: vec![p("t3")],
            ..Default::default()
        })
        .await,
        [p("both"), p("client")],
        "Type and Types merge"
    );
    assert_eq!(
        store
            .get_all(&GrantFilter {
                client_ids: Vec::new(),
                grant_types: Vec::new(),
                ..Default::default()
            })
            .await,
        Err(StoreError::EmptyFilter)
    );
    store
        .remove_all(&GrantFilter {
            grant_types: vec![p("t2"), p("t3")],
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        found(GrantFilter {
            client_ids: vec![p("c1"), p("c2"), p("other")],
            ..Default::default()
        })
        .await,
        [p("both"), p("c2")]
    );

    // Optional fields round trip as absent; a re-store sets the consumed
    // time.
    let bare = grants[3].clone();
    let read = store.get(&bare.key).await.unwrap().unwrap();
    assert_eq!(
        (read.subject_id, read.session_id, read.expiration),
        (None, None, None)
    );
    let consumed = PersistedGrant {
        consumed_time: Some(Utc.timestamp_opt(1_700_000_500, 0).unwrap()),
        ..bare.clone()
    };
    store.store(consumed.clone()).await.unwrap();
    assert_eq!(store.get(&bare.key).await.unwrap(), Some(consumed));
    store
        .remove_all(&GrantFilter {
            client_ids: vec![p("c1"), p("c2")],
            ..Default::default()
        })
        .await
        .unwrap();
}

/// The resource lookups, by name and by scope,
/// none of which filter on enabled. Expects the fixture resources.
pub async fn resource_store_lookups(store: &dyn ResourceStore) {
    let fixtures = Resources::load(&fixture("resources.json")).unwrap();
    let all = store.get_all_resources().await.unwrap();
    assert_eq!(
        *all, fixtures,
        "all resources, disabled included, in store order"
    );

    let disabled_scope = fixtures
        .api_scopes
        .iter()
        .find(|s| !s.enabled)
        .map(|s| s.name.clone());
    let wanted: Vec<String> = fixtures
        .api_scopes
        .iter()
        .take(2)
        .map(|s| s.name.clone())
        .chain(disabled_scope.clone())
        .chain(["nope".to_owned()])
        .collect();
    let found = store.find_api_scopes_by_name(&wanted).await.unwrap();
    let expected: Vec<_> = fixtures
        .api_scopes
        .iter()
        .filter(|s| wanted.contains(&s.name))
        .cloned()
        .collect();
    assert_eq!(found, expected);
    assert!(!found.is_empty());
    assert!(store.find_api_scopes_by_name(&[]).await.unwrap().is_empty());
    assert!(
        store
            .find_api_scopes_by_name(&["nope".into()])
            .await
            .unwrap()
            .is_empty()
    );

    let wanted: Vec<String> = ["openid", "profile", "nope"].map(String::from).to_vec();
    let found = store
        .find_identity_resources_by_scope_name(&wanted)
        .await
        .unwrap();
    let expected: Vec<_> = fixtures
        .identity_resources
        .iter()
        .filter(|r| wanted.contains(&r.name))
        .cloned()
        .collect();
    assert_eq!(found, expected);
    assert_eq!(found.len(), 2);
    assert!(
        store
            .find_identity_resources_by_scope_name(&[])
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .find_identity_resources_by_scope_name(&["nope".into()])
            .await
            .unwrap()
            .is_empty()
    );

    // By scope: every resource with any of the scopes, disabled included.
    // Two distinct scopes, each held by a different resource.
    let scopes: Vec<String> = ["api2", "other_api", "nope"].map(String::from).to_vec();
    let found = store
        .find_api_resources_by_scope_name(&scopes)
        .await
        .unwrap();
    let expected: Vec<_> = fixtures
        .api_resources
        .iter()
        .filter(|a| a.scopes.iter().any(|s| scopes.contains(s)))
        .cloned()
        .collect();
    assert_eq!(found, expected);
    assert_eq!(
        found.iter().map(|a| a.name.as_str()).collect::<Vec<_>>(),
        ["api", "other_api"]
    );
    assert!(
        fixtures.api_resources.len() > found.len(),
        "excludes resources without the scopes"
    );
    assert!(
        store
            .find_api_resources_by_scope_name(&[])
            .await
            .unwrap()
            .is_empty()
    );
    let disabled = fixtures.api_resources.iter().find(|a| !a.enabled).unwrap();
    let found = store
        .find_api_resources_by_scope_name(&disabled.scopes)
        .await
        .unwrap();
    assert!(found.iter().any(|a| a.name == disabled.name && !a.enabled));
}

/// Pushed requests live in the grant
/// store under their reference's hash, are read back with their expiry, and
/// are consumed once; requests are independent.
pub async fn pushed_requests(grants: Arc<dyn PersistedGrantStore>) {
    use rustid_core::pushed_authorization::{PushedRequest, consume, get, store};
    let grants = grants.as_ref();
    let now = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
    let request = |n: u32| PushedRequest {
        parameters: format!("client_id=c&state=s{n}"),
        expires_at: now + chrono::Duration::seconds(60 + i64::from(n)),
    };
    let reference = |n: u32| format!("urn:ietf:params:oauth:request_uri:contract-{n}");
    assert_eq!(get(grants, &reference(1)).await.unwrap(), None);
    store(grants, &reference(1), "c", &request(1), now)
        .await
        .unwrap();
    store(grants, &reference(2), "c", &request(2), now)
        .await
        .unwrap();
    assert_eq!(get(grants, &reference(1)).await.unwrap(), Some(request(1)));
    let stored = grants
        .get_all(&GrantFilter {
            client_id: Some("c".into()),
            grant_type: Some("pushed_authorization_request".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(
        stored.iter().all(|g| !g.key.contains("contract")),
        "the reference itself is never stored"
    );
    consume(grants, &reference(1)).await.unwrap();
    assert_eq!(get(grants, &reference(1)).await.unwrap(), None);
    consume(grants, &reference(1)).await.unwrap();
    let second = get(grants, &reference(2)).await.unwrap().unwrap();
    assert_eq!(second, request(2), "independent, expiry preserved");
    consume(grants, &reference(2)).await.unwrap();
}

/// Paging back and forth, malformed tokens,
/// empty and unfiltered queries, and expiry changes as the expired-session
/// sweep sees them.
pub async fn server_side_session_queries(
    store: Arc<dyn rustid_core::stores::ServerSideSessionStore>,
) {
    use rustid_core::server_side_sessions::SessionQuery;
    let subject = format!("pq{}", Utc::now().timestamp_nanos_opt().unwrap());
    for i in 0..6 {
        store
            .create_session(server_side_session(
                &format!("{subject}-{i}"),
                &subject,
                &format!("{subject}-s{i}"),
                Some(4_000_000_000),
            ))
            .await
            .unwrap();
    }
    let page = |token: Option<String>, prior: bool| {
        let store = store.clone();
        let subject = subject.clone();
        async move {
            store
                .query_sessions(&SessionQuery {
                    subject_id: Some(subject),
                    count_requested: 2,
                    results_token: token,
                    request_prior_results: prior,
                    ..Default::default()
                })
                .await
                .unwrap()
        }
    };
    let keys = |r: &rustid_core::server_side_sessions::QueryResult<
        rustid_core::server_side_sessions::ServerSideSession,
    >|
     -> Vec<String> { r.results.iter().map(|s| s.key.clone()).collect() };
    let page1 = page(None, false).await;
    assert_eq!((page1.total_count, page1.total_pages), (6, 3));
    let page2 = page(page1.results_token.clone(), false).await;
    let page3 = page(page2.results_token.clone(), false).await;
    assert!(!page3.has_next_results && page3.has_prev_results);
    let back2 = page(page3.results_token.clone(), true).await;
    assert_eq!(
        keys(&back2),
        keys(&page2),
        "backward pages keep forward order"
    );
    assert!(back2.has_next_results && back2.has_prev_results);
    let back1 = page(back2.results_token.clone(), true).await;
    assert_eq!(keys(&back1), keys(&page1));
    assert!(back1.has_next_results && !back1.has_prev_results);
    assert_eq!(
        keys(&page(back1.results_token.clone(), false).await),
        keys(&page2)
    );
    let forward3 = page(back2.results_token.clone(), false).await;
    assert_eq!(keys(&forward3), keys(&page3));
    assert!(!forward3.has_next_results && forward3.has_prev_results);
    assert_eq!(
        keys(&page(Some("not-a-token".into()), false).await),
        keys(&page1),
        "a malformed token means the first page"
    );

    // A session id alone is a filter.
    let by_session = store
        .get_sessions(&rustid_core::server_side_sessions::SessionFilter {
            session_id: Some(format!("{subject}-s2")),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        by_session.iter().map(|s| s.key.clone()).collect::<Vec<_>>(),
        [format!("{subject}-2")]
    );

    let none = store
        .query_sessions(&SessionQuery {
            subject_id: Some(format!("{subject}-nobody")),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(none.results.is_empty());
    assert_eq!(none.total_count, 0);
    let unfiltered = store
        .query_sessions(&SessionQuery::default())
        .await
        .unwrap();
    assert!(!unfiltered.results.is_empty());

    // Expiry changes as the sweep sees them.
    let now = Utc.timestamp_opt(1_800_000_000, 0).unwrap();
    let key = |n: &str| format!("{subject}-x{n}");
    store
        .create_session(server_side_session(&key("never"), &subject, "n", None))
        .await
        .unwrap();
    store
        .create_session(server_side_session(&key("cleared"), &subject, "c", Some(1)))
        .await
        .unwrap();
    store
        .update_session(server_side_session(&key("cleared"), &subject, "c", None))
        .await
        .unwrap();
    store
        .create_session(server_side_session(&key("set"), &subject, "t", None))
        .await
        .unwrap();
    store
        .update_session(server_side_session(&key("set"), &subject, "t", Some(1)))
        .await
        .unwrap();
    while store.move_expired_to_outbox(100, now).await.unwrap() > 0 {}
    assert!(store.get_session(&key("never")).await.unwrap().is_some());
    assert!(store.get_session(&key("cleared")).await.unwrap().is_some());
    assert!(store.get_session(&key("set")).await.unwrap().is_none());
    for i in 0..6 {
        assert!(
            store
                .get_session(&format!("{subject}-{i}"))
                .await
                .unwrap()
                .is_some(),
            "unexpired sessions stay"
        );
    }
    store
        .delete_sessions(&rustid_core::server_side_sessions::SessionFilter {
            subject_id: Some(subject.clone()),
            ..Default::default()
        })
        .await
        .unwrap();
}

fn saml_state(
    sp: &str,
    expires: Option<chrono::DateTime<Utc>>,
) -> rustid_saml::state::AuthenticationState {
    use rustid_saml::model::{Binding, IndexedEndpoint};
    use rustid_saml::state::{AuthenticationState, RequestedAuthnContext, StoredAuthnRequest};
    AuthenticationState {
        authn_request_data: Some(StoredAuthnRequest {
            request_id: Some("_req1".into()),
            force_authn: true,
            is_passive: false,
            name_id_policy_format: Some(rustid_saml::constants::NAME_ID_EMAIL.into()),
            subject_name_id_value: Some("alice@example.com".into()),
            idp_hint_provider_id: None,
            requested_authn_context: Some(RequestedAuthnContext {
                comparison: Some("exact".into()),
                authn_context_class_ref: vec![
                    rustid_saml::constants::AUTHN_CONTEXT_PASSWORD_PROTECTED.into(),
                ],
                authn_context_decl_ref: vec!["urn:decl".into()],
            }),
        }),
        service_provider_entity_id: sp.into(),
        relay_state: Some("relay é".into()),
        is_idp_initiated: false,
        created_utc: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
        assertion_consumer_service: IndexedEndpoint {
            location: format!("{sp}/acs"),
            binding: Binding::HttpPost,
            index: 0,
            is_default: true,
        },
        requested_claim_types: vec!["email".into()],
        expires_at_utc: expires,
        denial_error: Some("access_denied".into()),
        denial_error_description: Some("no".into()),
    }
}

/// The SAML sign-in state store contract.
pub async fn saml_signin_state_store(store: Arc<dyn rustid_saml::stores::SigninStateStore>) {
    use rustid_core::admin::EntityId;
    let t0 = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
    let expires = t0 + chrono::Duration::seconds(900);
    assert_eq!(
        store.store(saml_state("https://sp", None)).await,
        Err(StoreError::MissingExpiration(
            "ExpiresAtUtc must be set before storing SAML signin state."
        ))
    );
    let state = saml_state("https://sp", Some(expires));
    let id = store.store(state.clone()).await.unwrap();
    assert_eq!(id.to_string().as_bytes()[14], b'7', "a UUIDv7 id");
    assert_eq!(store.retrieve(&id, t0).await.unwrap(), Some(state.clone()));
    assert_eq!(
        store.retrieve(&id, expires).await.unwrap(),
        Some(state.clone()),
        "retrieving doesn't remove, and the expiry instant is still valid"
    );
    assert_eq!(store.retrieve(&EntityId::new_v7(), t0).await.unwrap(), None);
    let v4: EntityId = "6f1c2a3b-4d5e-4f60-8a9b-0c1d2e3f4a5b".parse().unwrap();
    assert_eq!(store.retrieve(&v4, t0).await.unwrap(), None);
    store.update(&v4, state.clone(), t0).await.unwrap();
    store.remove(&v4).await.unwrap();

    let mut changed = state.clone();
    changed.relay_state = Some("changed".into());
    store.update(&id, changed.clone(), t0).await.unwrap();
    assert_eq!(
        store.retrieve(&id, t0).await.unwrap(),
        Some(changed.clone())
    );
    store
        .update(&EntityId::new_v7(), changed.clone(), t0)
        .await
        .unwrap();
    // An update keeps the stored expiry.
    let mut extended = changed.clone();
    extended.expires_at_utc = Some(expires + chrono::Duration::days(1));
    store.update(&id, extended, t0).await.unwrap();
    assert_eq!(
        store.retrieve(&id, t0).await.unwrap(),
        Some(changed.clone()),
        "an update can't move the expiry"
    );

    // Expired: not found, and an update does nothing.
    let later = expires + chrono::Duration::seconds(1);
    store.update(&id, state.clone(), later).await.unwrap();
    assert_eq!(store.retrieve(&id, later).await.unwrap(), None);
    assert_eq!(
        store.retrieve(&id, t0).await.unwrap(),
        None,
        "an expired state is removed when seen"
    );

    let other = store.store(state.clone()).await.unwrap();
    assert_ne!(other, id);
    store.remove(&other).await.unwrap();
    assert_eq!(store.retrieve(&other, t0).await.unwrap(), None);
    store.remove(&other).await.unwrap();

    // The purge removes expired states in batches, and only those.
    let live = store
        .store(saml_state(
            "https://sp",
            Some(later + chrono::Duration::days(1)),
        ))
        .await
        .unwrap();
    for _ in 0..3 {
        store
            .store(saml_state("https://sp", Some(expires)))
            .await
            .unwrap();
    }
    let mut purged = 0;
    loop {
        let removed = store.remove_expired(later, 2).await.unwrap();
        purged += removed;
        if removed < 2 {
            break;
        }
    }
    assert!(purged >= 3, "{purged}");
    assert!(store.retrieve(&live, later).await.unwrap().is_some());
    store.remove(&live).await.unwrap();
}

/// `rustid_saml::stores::purge`: every expired sign-in state and logout
/// session goes, over several batches; live ones stay.
pub async fn saml_purge(stores: rustid_saml::stores::SamlStores) {
    let t0 = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
    let expires = t0 + chrono::Duration::seconds(60);
    let later = expires + chrono::Duration::seconds(1);
    let mut expired_states = Vec::new();
    for _ in 0..5 {
        expired_states.push(
            stores
                .signin_states
                .store(saml_state("https://sp", Some(expires)))
                .await
                .unwrap(),
        );
    }
    let live_state = stores
        .signin_states
        .store(saml_state(
            "https://sp",
            Some(later + chrono::Duration::days(1)),
        ))
        .await
        .unwrap();
    for n in 0..3 {
        stores
            .logout_sessions
            .store(logout_session(
                &format!("purge-expired-{n}"),
                &[(&format!("_purge-req-{n}"), "https://sp")],
                Some(expires),
            ))
            .await
            .unwrap();
    }
    stores
        .logout_sessions
        .store(logout_session(
            "purge-live",
            &[("_purge-req-live", "https://sp")],
            Some(later + chrono::Duration::days(1)),
        ))
        .await
        .unwrap();

    let purged = rustid_saml::stores::purge(&stores, later, 2).await.unwrap();
    assert!(purged >= 8, "{purged}");
    assert_eq!(
        rustid_saml::stores::purge(&stores, later, 2).await.unwrap(),
        0
    );
    for id in &expired_states {
        assert_eq!(stores.signin_states.retrieve(id, t0).await.unwrap(), None);
    }
    for n in 0..3 {
        assert_eq!(
            stores
                .logout_sessions
                .get(&format!("purge-expired-{n}"), t0)
                .await
                .unwrap(),
            None
        );
    }
    assert!(
        stores
            .signin_states
            .retrieve(&live_state, later)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        stores
            .logout_sessions
            .get("purge-live", later)
            .await
            .unwrap()
            .is_some()
    );
}

fn logout_session(
    logout_id: &str,
    requests: &[(&str, &str)],
    expires: Option<chrono::DateTime<Utc>>,
) -> rustid_saml::state::LogoutSession {
    use rustid_saml::state::{ExpectedSpLogout, LogoutSession};
    LogoutSession {
        logout_id: logout_id.into(),
        expected_responses: requests
            .iter()
            .map(|(request, sp)| {
                (
                    (*request).to_owned(),
                    ExpectedSpLogout {
                        sp_entity_id: (*sp).to_owned(),
                        response: None,
                    },
                )
            })
            .collect(),
        skipped_sp_count: 1,
        created_utc: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
        expires_at_utc: expires,
    }
}

/// The SAML logout session store contract.
pub async fn saml_logout_session_store(store: Arc<dyn rustid_saml::stores::LogoutSessionStore>) {
    let p = format!("ls{}-", Utc::now().timestamp_nanos_opt().unwrap());
    let id = |s: &str| format!("{p}{s}");
    let t0 = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
    let expires = t0 + chrono::Duration::seconds(300);
    assert_eq!(
        store.store(logout_session(&id("x"), &[], None)).await,
        Err(StoreError::MissingExpiration(
            "ExpiresAtUtc must be set before storing SAML logout session."
        ))
    );
    let session = logout_session(
        &id("one"),
        &[(&id("r1"), "https://sp1"), (&id("r2"), "https://sp2")],
        Some(expires),
    );
    store.store(session.clone()).await.unwrap();
    assert_eq!(
        store.get(&id("one"), t0).await.unwrap(),
        Some(session.clone())
    );
    assert_eq!(
        store.store(session.clone()).await,
        Err(StoreError::DuplicateLogoutId(id("one")))
    );
    assert_eq!(store.get(&id("none"), t0).await.unwrap(), None);

    // Recording responses.
    assert!(
        !store
            .try_record_response(&id("unknown"), "https://sp1", true, t0)
            .await
            .unwrap()
    );
    assert!(
        !store
            .try_record_response(&id("r1"), "https://sp2", true, t0)
            .await
            .unwrap(),
        "the issuer must be the expected SP"
    );
    let at = t0 + chrono::Duration::seconds(10);
    assert!(
        store
            .try_record_response(&id("r1"), "https://sp1", true, at)
            .await
            .unwrap()
    );
    assert!(
        store
            .try_record_response(&id("r2"), "https://sp2", false, at)
            .await
            .unwrap()
    );
    let got = store.get(&id("one"), at).await.unwrap().unwrap();
    let r1 = got.expected_responses[&id("r1")].response.clone().unwrap();
    let r2 = got.expected_responses[&id("r2")].response.clone().unwrap();
    assert_eq!((r1.success, r1.received_utc), (true, at));
    assert!(!r2.success, "a failure is recorded too");

    // Concurrent responses for one session both land.
    let concurrent = logout_session(
        &id("two"),
        &(0..8)
            .map(|i| (id(&format!("c{i}")), "https://sp"))
            .collect::<Vec<_>>()
            .iter()
            .map(|(r, s)| (r.as_str(), *s))
            .collect::<Vec<_>>(),
        Some(expires),
    );
    store.store(concurrent).await.unwrap();
    let writers: Vec<_> = (0..8)
        .map(|i| {
            let store = store.clone();
            let request = id(&format!("c{i}"));
            tokio::spawn(async move {
                store
                    .try_record_response(&request, "https://sp", true, t0)
                    .await
                    .unwrap()
            })
        })
        .collect();
    for writer in writers {
        assert!(writer.await.unwrap());
    }
    let got = store.get(&id("two"), t0).await.unwrap().unwrap();
    assert!(
        got.expected_responses
            .values()
            .all(|e| e.response.is_some())
    );

    // Expiry: at the instant itself the session is gone (expiry at or
    // before now).
    assert_eq!(store.get(&id("one"), expires).await.unwrap(), None);
    assert!(
        !store
            .try_record_response(&id("r1"), "https://sp1", true, expires)
            .await
            .unwrap()
    );

    // Remove: idempotent, and the request index goes too.
    store.remove(&id("two")).await.unwrap();
    assert_eq!(store.get(&id("two"), t0).await.unwrap(), None);
    assert!(
        !store
            .try_record_response(&id("c0"), "https://sp", true, t0)
            .await
            .unwrap()
    );
    store.remove(&id("two")).await.unwrap();
    store.remove(&id("one")).await.unwrap();

    // The purge removes expired sessions (and their requests).
    store
        .store(logout_session(
            &id("old"),
            &[(&id("o1"), "https://sp")],
            Some(t0),
        ))
        .await
        .unwrap();
    store
        .store(logout_session(
            &id("live"),
            &[(&id("l1"), "https://sp")],
            Some(expires),
        ))
        .await
        .unwrap();
    assert!(store.remove_expired(t0, 1000).await.unwrap() >= 1);
    assert_eq!(
        store
            .get(&id("live"), t0 - chrono::Duration::seconds(1))
            .await
            .unwrap()
            .map(|s| s.logout_id),
        Some(id("live"))
    );
    assert!(
        !store
            .try_record_response(
                &id("o1"),
                "https://sp",
                true,
                t0 - chrono::Duration::seconds(1)
            )
            .await
            .unwrap()
    );
    store.remove(&id("live")).await.unwrap();
}

/// By entity id (enabled only,
/// exact) and all. Expects the fixture service providers.
pub async fn saml_service_provider_store(store: &dyn rustid_saml::stores::ServiceProviderStore) {
    let fixtures =
        rustid_saml::model::load_service_providers(&fixture("saml-service-providers.json"))
            .unwrap();
    let found = store
        .find_by_entity_id("https://sp.example")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(*found, fixtures[0], "every field, collections included");
    assert!(
        store
            .find_by_entity_id("https://SP.example")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .find_by_entity_id("https://nobody.example")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .find_by_entity_id("https://disabled.example")
            .await
            .unwrap()
            .is_none(),
        "disabled providers aren't found"
    );
    let mut all: Vec<String> = store
        .get_all()
        .await
        .unwrap()
        .iter()
        .map(|sp| sp.entity_id.clone())
        .collect();
    all.sort();
    let mut expected: Vec<String> = fixtures.iter().map(|sp| sp.entity_id.clone()).collect();
    expected.sort();
    assert_eq!(all, expected, "all, disabled included");
}

/// SAML service providers written to the configuration store (as admin
/// writes them) reach the runtime store at once: created, disabled and
/// deleted.
pub async fn saml_configuration_reaches_runtime(
    configuration: Arc<dyn rustid_core::stores::ConfigurationStore>,
    runtime: &dyn rustid_saml::stores::ServiceProviderStore,
) {
    use rustid_core::stores::{CreateOutcome, EntityKind, StoredEntity, UpdateOutcome};
    let entity_id = format!(
        "https://runtime-{}.example",
        rustid_core::admin::EntityId::new_v7()
    );
    let sp: rustid_saml::model::ServiceProvider = serde_json::from_value(serde_json::json!({
        "entityId": entity_id,
        "assertionConsumerServiceUrls": [{"location": "https://runtime.example/acs", "binding": "HttpPost"}],
        "allowedScopes": ["openid"],
    }))
    .unwrap();
    let mut entity = StoredEntity {
        id: rustid_core::admin::EntityId::new_v7(),
        key: entity_id.clone(),
        version: 1,
        data: serde_json::to_value(&sp).unwrap(),
    };
    assert!(
        runtime
            .find_by_entity_id(&entity_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        configuration
            .create(EntityKind::SamlServiceProvider, &entity)
            .await
            .unwrap(),
        CreateOutcome::Created
    );
    let found = runtime
        .find_by_entity_id(&entity_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(*found, sp);
    assert!(
        runtime
            .get_all()
            .await
            .unwrap()
            .iter()
            .any(|p| p.entity_id == entity_id)
    );
    let disabled = rustid_saml::model::ServiceProvider {
        enabled: false,
        ..sp.clone()
    };
    entity.data = serde_json::to_value(&disabled).unwrap();
    assert_eq!(
        configuration
            .update(EntityKind::SamlServiceProvider, &entity)
            .await
            .unwrap(),
        UpdateOutcome::Updated
    );
    assert!(
        runtime
            .find_by_entity_id(&entity_id)
            .await
            .unwrap()
            .is_none(),
        "disabled at once"
    );
    configuration
        .delete(EntityKind::SamlServiceProvider, &entity.id)
        .await
        .unwrap();
    assert!(
        !runtime
            .get_all()
            .await
            .unwrap()
            .iter()
            .any(|p| p.entity_id == entity_id),
        "deleted at once"
    );
}

/// SAML service provider admin: the admin's rules over this
/// configuration, and its writes as `runtime` serves them.
pub async fn saml_service_provider_admin(
    store: Arc<dyn rustid_core::stores::ConfigurationStore>,
    runtime: &dyn rustid_saml::stores::ServiceProviderStore,
) {
    use base64::Engine;
    use rustid_core::admin::EntityId;
    use rustid_core::admin::query::{Direction, Range};
    use rustid_core::admin::schemas::SchemaAdmin;
    use rustid_saml::admin::{
        SamlServiceProviderAdmin, SamlServiceProviderFilter, SamlServiceProviderInput,
        SamlServiceProviderSortField,
    };
    use serde_json::{Value, json};

    let store_ref = store.as_ref();
    let admin = SamlServiceProviderAdmin;
    let tag = EntityId::new_v7().to_string()[24..].to_owned();
    let entity = |name: &str| format!("https://{name}-{tag}.example.com");
    let b64 = |path: &str| {
        let der = rustid_saml::model::decode_certificate(
            &std::fs::read_to_string(crate::fixture(path)).unwrap(),
        )
        .unwrap();
        base64::engine::general_purpose::STANDARD.encode(der)
    };
    let sp_cert = b64("saml/sp/sp-signing.cert.pem");
    let idp_cert = b64("saml/idp/idp-rsa.cert.pem");
    let minimal = |entity_id: &str| {
        json!({
            "entityId": entity_id,
            "assertionConsumerServiceUrls": [
                { "location": "https://sp.example.com/acs", "binding": "HttpPost", "index": 0, "isDefault": true }
            ],
            "allowedScopes": ["openid"],
        })
    };
    let input = |v: Value| SamlServiceProviderInput::from_json(v).unwrap();
    let saved = |r: rustid_core::admin::SaveResult| r.unwrap().unwrap();
    let failure = |r: rustid_core::admin::SaveResult| {
        let errors = r.unwrap().unwrap_err();
        (errors[0].code, errors[0].message.clone())
    };
    let with = |mut v: Value, key: &str, value: Value| {
        v[key] = value;
        v
    };

    // Create_and_get_by_id_round_trips_all_fields
    let full_id = entity("full");
    let full = json!({
        "entityId": full_id,
        "enabled": true,
        "displayName": "Test SP",
        "description": "A test service provider",
        "clockSkew": "00:05:00",
        "requestMaxAge": "00:10:00",
        "assertionLifetime": "00:15:00",
        "assertionConsumerServiceUrls": [
            { "location": "https://sp.example.com/acs", "binding": "HttpPost", "index": 0, "isDefault": true },
            { "location": "https://sp.example.com/acs2", "binding": "HttpPost", "index": 1 }
        ],
        "singleLogoutServiceUrls": [
            { "location": "https://sp.example.com/slo", "binding": "HttpRedirect" }
        ],
        "requireSignedAuthnRequests": true,
        "requireSignedLogoutResponses": false,
        "certificates": [ { "base64Data": sp_cert, "use": "Signing" } ],
        "allowIdpInitiated": true,
        "allowedScopes": ["openid", "profile"],
        "claimMappings": { "email": "mail" },
        "authnContextMappings": { "pwd": "urn:oasis:names:tc:SAML:2.0:ac:classes:Password" },
        "requestedClaimTypes": ["email"],
        "defaultNameIdFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        "emailNameIdClaimType": "email",
        "signingBehavior": "SignAssertion",
        "allowedSignatureAlgorithms": ["http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"],
    });
    let created = saved(admin.create(store_ref, input(full.clone())).await);
    assert_eq!(created.version, 1);
    let loaded = admin.get(store_ref, &created.id).await.unwrap().unwrap();
    assert_eq!((loaded.id, loaded.version), (created.id, 1));
    let read = serde_json::to_value(&loaded.item).unwrap();
    for key in [
        "entityId",
        "enabled",
        "displayName",
        "description",
        "clockSkew",
        "requestMaxAge",
        "assertionLifetime",
        "requireSignedAuthnRequests",
        "requireSignedLogoutResponses",
        "allowIdpInitiated",
        "allowedScopes",
        "claimMappings",
        "authnContextMappings",
        "requestedClaimTypes",
        "defaultNameIdFormat",
        "emailNameIdClaimType",
        "signingBehavior",
        "allowedSignatureAlgorithms",
    ] {
        assert_eq!(read[key], full[key], "{key}");
    }
    assert_eq!(
        read["assertionConsumerServiceUrls"],
        json!([
            { "location": "https://sp.example.com/acs", "binding": "HttpPost", "index": 0, "isDefault": true },
            { "location": "https://sp.example.com/acs2", "binding": "HttpPost", "index": 1, "isDefault": false }
        ])
    );
    assert_eq!(
        read["singleLogoutServiceUrls"],
        full["singleLogoutServiceUrls"]
    );
    // Certificates_get_assigned_ids_on_create
    let cert = &read["certificates"][0];
    assert!(cert["id"].as_str().unwrap().parse::<EntityId>().is_ok());
    assert_eq!(cert["base64Data"], json!(sp_cert));
    assert_eq!(cert["use"], "Signing");
    assert!(!cert["subject"].as_str().unwrap().is_empty());
    let thumbprint = cert["thumbprint"].as_str().unwrap();
    assert!(
        thumbprint.len() == 40
            && thumbprint
                .chars()
                .all(|c| c.is_ascii_digit() || c.is_ascii_uppercase())
    );
    assert!(cert["notAfter"].as_str().is_some());
    assert_eq!(read["extendedProperties"], json!({}));

    // Create_and_get_by_entity_id_returns_same
    let by_entity = admin
        .get_by_entity_id(store_ref, &full_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(by_entity, loaded);
    // Get_by_entity_id_nonexistent_returns_not_found
    assert!(
        admin
            .get_by_entity_id(store_ref, &entity("nobody"))
            .await
            .unwrap()
            .is_none()
    );

    // Created via the admin, then found in the runtime store.
    let sp = runtime.find_by_entity_id(&full_id).await.unwrap().unwrap();
    assert_eq!(sp.display_name.as_deref(), Some("Test SP"));
    assert_eq!(sp.clock_skew, Some(rustid_core::options::TimeSpan(300)));
    assert_eq!(sp.assertion_consumer_service_urls.len(), 2);
    assert_eq!(sp.single_logout_service_urls.len(), 1);
    assert_eq!(sp.certificates.len(), 1);
    assert_eq!(
        base64::engine::general_purpose::STANDARD.encode(&sp.certificates[0].der),
        sp_cert
    );
    assert!(sp.allow_idp_initiated);
    assert_eq!(sp.allowed_scopes, ["openid", "profile"]);
    assert_eq!(sp.claim_mappings["email"], "mail");
    assert_eq!(
        sp.signing_behavior,
        Some(rustid_saml::model::SigningBehavior::SignAssertion)
    );
    assert!(
        runtime
            .find_by_entity_id("https://nonexistent.example.com")
            .await
            .unwrap()
            .is_none()
    );

    // The minimal input's defaults.
    let minimal_id = entity("minimal");
    let m = saved(admin.create(store_ref, input(minimal(&minimal_id))).await);
    let read =
        serde_json::to_value(admin.get(store_ref, &m.id).await.unwrap().unwrap().item).unwrap();
    assert_eq!(read["enabled"], true);
    assert_eq!(
        read["defaultNameIdFormat"],
        "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
    );
    assert_eq!(read["allowIdpInitiated"], false);
    assert_eq!(read["certificates"], json!([]));
    assert_eq!(read["allowedSignatureAlgorithms"], json!([]));
    assert_eq!(read["clockSkew"], Value::Null);
    assert_eq!(read["signingBehavior"], Value::Null);
    // Get_all_returns_all_created_service_providers
    let all: Vec<String> = runtime
        .get_all()
        .await
        .unwrap()
        .iter()
        .map(|sp| sp.entity_id.clone())
        .collect();
    assert!(all.contains(&full_id) && all.contains(&minimal_id));

    // Create_duplicate_entity_id_returns_already_exists
    assert_eq!(
        failure(admin.create(store_ref, input(minimal(&minimal_id))).await),
        (
            "already_exists",
            format!("samlServiceProvider '{minimal_id}' already exists.")
        )
    );
    // The structure checks, in their words.
    let refused = |v: Value| {
        let admin = &admin;
        async move { failure(admin.create(store_ref, input(v)).await) }
    };
    let invalid = |m: &str| ("invalid_value", m.to_owned());
    let x = entity("x");
    // Create_with_empty_entity_id_returns_required
    assert_eq!(
        refused(minimal("  ")).await,
        ("required", "A value is required.".to_owned())
    );
    assert_eq!(
        refused(with(minimal(&x), "displayName", json!(" "))).await,
        invalid("Display name must not be empty or whitespace.")
    );
    // Create_with_null_acs_entry_returns_error
    assert_eq!(
        refused(with(
            minimal(&x),
            "assertionConsumerServiceUrls",
            json!([null])
        ))
        .await,
        invalid("ACS endpoint list must not contain null entries.")
    );
    assert_eq!(
        refused(with(
            minimal(&x),
            "assertionConsumerServiceUrls",
            json!([{ "location": " ", "binding": "HttpPost" }])
        ))
        .await,
        invalid("ACS endpoint location must not be empty.")
    );
    // Create_with_invalid_acs_url_returns_error
    assert_eq!(
        refused(with(
            minimal(&x),
            "assertionConsumerServiceUrls",
            json!([{ "location": "not-a-url", "binding": "HttpPost" }])
        ))
        .await,
        invalid("ACS endpoint location 'not-a-url' is not a valid absolute URI.")
    );
    // Create_with_duplicate_acs_index_returns_error
    assert_eq!(
        refused(with(
            minimal(&x),
            "assertionConsumerServiceUrls",
            json!([
                { "location": "https://sp.example.com/a", "binding": "HttpPost", "index": 1 },
                { "location": "https://sp.example.com/b", "binding": "HttpPost", "index": 1 }
            ])
        ))
        .await,
        invalid("ACS endpoint list contains duplicate Index values.")
    );
    // Create_with_null_slo_entry_returns_error
    assert_eq!(
        refused(with(minimal(&x), "singleLogoutServiceUrls", json!([null]))).await,
        invalid("SLO endpoint list must not contain null entries.")
    );
    assert_eq!(
        refused(with(
            minimal(&x),
            "singleLogoutServiceUrls",
            json!([{ "location": "/relative", "binding": "HttpRedirect" }])
        ))
        .await,
        invalid("SLO endpoint location '/relative' is not a valid absolute URI.")
    );
    // Create_with_null_certificate_entry_returns_error
    assert_eq!(
        refused(with(minimal(&x), "certificates", json!([null]))).await,
        invalid("Certificate list must not contain null entries.")
    );
    assert_eq!(
        refused(with(
            minimal(&x),
            "certificates",
            json!([{ "base64Data": "" }])
        ))
        .await,
        invalid("Certificate Base64Data must not be empty.")
    );
    assert_eq!(
        refused(with(
            minimal(&x),
            "certificates",
            json!([{ "base64Data": "@@" }])
        ))
        .await,
        invalid("Certificate Base64Data is not valid base64.")
    );
    assert_eq!(
        refused(with(
            minimal(&x),
            "certificates",
            json!([{ "base64Data": "AAAA" }])
        ))
        .await,
        invalid("Certificate Base64Data does not contain a valid X.509 certificate.")
    );
    // A private key is not a certificate, and is never stored.
    let key_der = {
        let pem = std::fs::read_to_string(crate::fixture("saml/sp/sp-signing.key.pem")).unwrap();
        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        body
    };
    assert_eq!(
        refused(with(
            minimal(&x),
            "certificates",
            json!([{ "base64Data": key_der }])
        ))
        .await,
        invalid("Certificate Base64Data does not contain a valid X.509 certificate.")
    );
    // A certificate in the file's shape names the member it doesn't know.
    let file_shaped = SamlServiceProviderInput::from_json(with(
        minimal(&x),
        "certificates",
        json!([{ "certificate": "-----BEGIN CERTIFICATE-----", "use": "Signing" }]),
    ))
    .unwrap_err();
    assert_eq!(
        (file_shaped.code, file_shaped.message.as_str()),
        (
            "invalid_value",
            "'certificate' is not a SAML service provider setting."
        )
    );
    let same = "0190c8e4-0000-7000-8000-000000000001";
    assert_eq!(
        refused(with(
            minimal(&x),
            "certificates",
            json!([{ "id": same, "base64Data": sp_cert }, { "id": same, "base64Data": idp_cert }])
        ))
        .await,
        invalid("Certificate list contains duplicate IDs.")
    );
    assert_eq!(
        refused(with(minimal(&x), "allowedScopes", json!(["openid", " "]))).await,
        invalid("Scope must not be null or whitespace.")
    );
    // Then the configuration validator.
    assert_eq!(
        refused(with(minimal(&x), "allowedScopes", json!([]))).await,
        (
            "validation_failed",
            "at least one allowed scope is required".to_owned()
        )
    );
    assert_eq!(
        refused(with(
            minimal(&x),
            "assertionConsumerServiceUrls",
            json!([{ "location": "https://sp.example.com/acs", "binding": "HttpRedirect" }])
        ))
        .await
        .0,
        "validation_failed"
    );
    // Unknown members are refused.
    assert_eq!(
        SamlServiceProviderInput::from_json(with(minimal(&x), "bogus", json!(1)))
            .unwrap_err()
            .code,
        "invalid_value"
    );

    // Update_with_correct_version_succeeds
    let current = admin.get(store_ref, &m.id).await.unwrap().unwrap();
    let mut update = serde_json::to_value(&current.item).unwrap();
    update["displayName"] = json!("Updated Name");
    update["allowIdpInitiated"] = json!(true);
    let updated = saved(
        admin
            .update(store_ref, &m.id, input(update.clone()), 1)
            .await,
    );
    assert_eq!((updated.id, updated.version), (m.id, 2));
    let reloaded = admin.get(store_ref, &m.id).await.unwrap().unwrap();
    assert_eq!(reloaded.item.display_name.as_deref(), Some("Updated Name"));
    assert!(reloaded.item.allow_idp_initiated);
    // Update_with_wrong_version_returns_conflict
    assert_eq!(
        failure(
            admin
                .update(store_ref, &m.id, input(update.clone()), 1)
                .await
        )
        .0,
        "version_conflict"
    );
    // Update_nonexistent_returns_not_found
    let nobody = EntityId::new_v7();
    assert_eq!(
        failure(
            admin
                .update(store_ref, &nobody, input(minimal(&x)), 1)
                .await
        ),
        (
            "not_found",
            format!("samlServiceProvider '{nobody}' was not found.")
        )
    );
    // Update_entity_id_to_existing_returns_already_exists
    let mut collide = update.clone();
    collide["entityId"] = json!(full_id);
    assert_eq!(
        failure(admin.update(store_ref, &m.id, input(collide), 2).await).0,
        "already_exists"
    );

    // Update_replaces_certificate_list; ids survive only when sent back.
    let c = saved(
        admin
            .create(
                store_ref,
                input(with(
                    minimal(&entity("certs")),
                    "certificates",
                    json!([{ "base64Data": sp_cert }, { "base64Data": idp_cert }]),
                )),
            )
            .await,
    );
    let item =
        serde_json::to_value(admin.get(store_ref, &c.id).await.unwrap().unwrap().item).unwrap();
    let kept = item["certificates"][0]["id"].clone();
    let replaced = with(
        item.clone(),
        "certificates",
        json!([{ "id": kept, "base64Data": sp_cert, "use": "Encryption" }, { "base64Data": idp_cert }]),
    );
    saved(admin.update(store_ref, &c.id, input(replaced), 1).await);
    let after =
        serde_json::to_value(admin.get(store_ref, &c.id).await.unwrap().unwrap().item).unwrap();
    assert_eq!(after["certificates"][0]["id"], kept);
    assert_eq!(after["certificates"][0]["use"], "Encryption");
    assert_ne!(
        after["certificates"][1]["id"],
        item["certificates"][1]["id"]
    );
    saved(
        admin
            .update(
                store_ref,
                &c.id,
                input(with(
                    after,
                    "certificates",
                    json!([{ "base64Data": idp_cert, "use": "Encryption" }]),
                )),
                2,
            )
            .await,
    );
    let one = admin.get(store_ref, &c.id).await.unwrap().unwrap();
    assert_eq!(one.item.certificates.len(), 1);
    // A create assigns new ids even when ids are sent.
    let sent = saved(
        admin
            .create(
                store_ref,
                input(with(
                    minimal(&entity("sentid")),
                    "certificates",
                    json!([{ "id": same, "base64Data": sp_cert }]),
                )),
            )
            .await,
    );
    let sent =
        serde_json::to_value(admin.get(store_ref, &sent.id).await.unwrap().unwrap().item).unwrap();
    assert_ne!(sent["certificates"][0]["id"], json!(same));
    // Certificate_normalization_produces_deterministic_output: the DER
    // as given, whatever surrounds it in the base64.
    let spaced = sp_cert
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    let n = saved(
        admin
            .create(
                store_ref,
                input(with(
                    minimal(&entity("normal")),
                    "certificates",
                    json!([{ "base64Data": spaced }]),
                )),
            )
            .await,
    );
    let n = admin.get(store_ref, &n.id).await.unwrap().unwrap();
    assert_eq!(n.item.certificates[0].base64_data, sp_cert);
    assert_eq!(
        n.item.certificates[0].thumbprint,
        loaded.item.certificates[0].thumbprint
    );
    // Bytes after the certificate are cut off.
    let trailing = {
        let engine = base64::engine::general_purpose::STANDARD;
        let mut der = engine.decode(&sp_cert).unwrap();
        der.extend_from_slice(&[0x30, 0x03, 0x02, 0x01, 0x01]);
        engine.encode(der)
    };
    let t = saved(
        admin
            .create(
                store_ref,
                input(with(
                    minimal(&entity("trailing")),
                    "certificates",
                    json!([{ "base64Data": trailing }]),
                )),
            )
            .await,
    );
    let t = admin.get(store_ref, &t.id).await.unwrap().unwrap();
    assert_eq!(t.item.certificates[0].base64_data, sp_cert);

    // Query_returns_matching_items
    let result = admin
        .query(
            store_ref,
            &SamlServiceProviderFilter {
                entity_id: Some(tag.clone()),
                ..Default::default()
            },
            Some((SamlServiceProviderSortField::EntityId, Direction::Ascending)),
            &Range::Page { page: 1, size: 100 },
        )
        .await
        .unwrap()
        .unwrap();
    assert!(result.items.len() >= 5);
    let first = result
        .items
        .iter()
        .find(|i| i.entity_id == full_id)
        .unwrap();
    assert_eq!((first.certificate_count, first.allowed_scope_count), (1, 2));
    assert_eq!(first.display_name.as_deref(), Some("Test SP"));
    let named = admin
        .query(
            store_ref,
            &SamlServiceProviderFilter {
                display_name: Some("Updated".into()),
                enabled: Some(true),
                ..Default::default()
            },
            None,
            &Range::Page { page: 1, size: 100 },
        )
        .await
        .unwrap()
        .unwrap();
    assert!(named.items.iter().any(|i| i.entity_id == minimal_id));
    assert!(named.items.iter().all(|i| i.entity_id != full_id));

    // Delete_existing_succeeds (idempotent), and the runtime forgets it.
    let deleted = saved(admin.delete(store_ref, &m.id).await);
    assert_eq!(deleted.version, 0);
    assert!(admin.get(store_ref, &m.id).await.unwrap().is_none());
    assert!(
        runtime
            .find_by_entity_id(&minimal_id)
            .await
            .unwrap()
            .is_none()
    );
    saved(admin.delete(store_ref, &m.id).await);

    // Extended properties.
    let props = |v: Value| {
        with(
            minimal(&entity(&format!("ep{}", EntityId::new_v7()))),
            "extendedProperties",
            v,
        )
    };
    // Create_with_empty_extended_properties_and_no_schema_succeeds
    saved(admin.create(store_ref, input(props(json!({})))).await);
    // Create_with_extended_properties_fails_when_no_schema_configured
    assert_eq!(
        failure(
            admin
                .create(store_ref, input(props(json!({ "some_attr": "value" }))))
                .await
        ),
        (
            "validation_failed",
            "Attribute 'some_attr' is not defined in the schema.".to_owned()
        )
    );
    saved(
        SchemaAdmin
            .create(
                store_ref,
                serde_json::from_value(json!({
                    "schemaId": "saml-service-provider",
                    "attributeDefinitions": [
                        { "code": "environment", "attributeType": { "kind": "scalar", "dataType": "String" } },
                        { "code": "priority", "attributeType": { "kind": "scalar", "dataType": "Integer" } },
                    ],
                }))
                .unwrap(),
            )
            .await,
    );
    // Create_with_valid_extended_properties_round_trips_correctly
    let e = saved(
        admin
            .create(
                store_ref,
                input(props(json!({ "environment": "production" }))),
            )
            .await,
    );
    let item =
        serde_json::to_value(admin.get(store_ref, &e.id).await.unwrap().unwrap().item).unwrap();
    assert_eq!(
        item["extendedProperties"],
        json!({ "environment": "production" })
    );
    // Create_with_unknown_attribute_returns_validation_error
    assert_eq!(
        failure(
            admin
                .create(store_ref, input(props(json!({ "unknown_attr": "value" }))))
                .await
        )
        .0,
        "validation_failed"
    );
    // Update_with_valid_extended_properties_round_trips_correctly
    saved(
        admin
            .update(
                store_ref,
                &e.id,
                input(with(
                    item.clone(),
                    "extendedProperties",
                    json!({ "environment": "staging" }),
                )),
                1,
            )
            .await,
    );
    let item =
        serde_json::to_value(admin.get(store_ref, &e.id).await.unwrap().unwrap().item).unwrap();
    assert_eq!(
        item["extendedProperties"],
        json!({ "environment": "staging" })
    );
    // Update_with_invalid_attribute_returns_validation_error
    assert_eq!(
        failure(
            admin
                .update(
                    store_ref,
                    &e.id,
                    input(with(
                        item,
                        "extendedProperties",
                        json!({ "bad_attr": "value" })
                    )),
                    2
                )
                .await
        )
        .0,
        "validation_failed"
    );
}

/// Clients and SAML service providers
/// created by admin, by identifier (the client first) and all together
/// (clients first).
pub async fn connected_application_store(store: Arc<dyn rustid_core::stores::ConfigurationStore>) {
    use rustid_core::admin::EntityId;
    use rustid_core::admin::clients::{ClientAdmin, ClientInput};
    use rustid_saml::admin::{SamlServiceProviderAdmin, SamlServiceProviderInput};
    use rustid_saml::connected::ConnectedApplicationStore;
    use serde_json::json;

    let connected = ConnectedApplicationStore::new(store.clone());
    let tag = EntityId::new_v7().to_string()[24..].to_owned();
    let client = |id: &str, name: &str| {
        ClientInput::from_json(
            json!({
                "clientId": id,
                "clientName": name,
                "allowedGrantTypes": ["client_credentials"],
                "allowedScopes": ["api1"],
                "clientSecrets": [{ "plaintextValue": "secret" }],
            }),
            true,
        )
        .unwrap()
    };
    let sp = |id: &str, name: &str| {
        SamlServiceProviderInput::from_json(json!({
            "entityId": id,
            "displayName": name,
            "assertionConsumerServiceUrls": [
                { "location": "https://sp.example.com/acs", "binding": "HttpPost", "index": 0, "isDefault": true }
            ],
            "allowedScopes": ["openid"],
        }))
        .unwrap()
    };
    let ok = |r: rustid_core::admin::SaveResult| r.unwrap().unwrap();

    // Find_by_identifier_returns_client_created_via_admin
    let client_id = format!("client_{tag}");
    ok(ClientAdmin::default()
        .create(
            store.as_ref(),
            client(&client_id, "Connected App Test Client"),
        )
        .await);
    let found = connected
        .find_by_identifier(&client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.identifier, client_id);
    assert_eq!(
        found.display_name.as_deref(),
        Some("Connected App Test Client")
    );
    assert_eq!(found.protocol_type, "oidc");
    assert!(found.enabled);

    // Find_by_identifier_returns_saml_sp_created_via_admin
    let entity_id = format!("https://sp-{tag}.example.com");
    ok(SamlServiceProviderAdmin
        .create(store.as_ref(), sp(&entity_id, "Connected App Test SP"))
        .await);
    let found = connected
        .find_by_identifier(&entity_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.identifier, entity_id);
    assert_eq!(found.display_name.as_deref(), Some("Connected App Test SP"));
    assert_eq!(found.protocol_type, "saml2p");
    assert!(found.enabled);
    assert!(!found.require_consent);

    // Find_by_identifier_returns_null_for_nonexistent
    assert!(
        connected
            .find_by_identifier("nonexistent-app")
            .await
            .unwrap()
            .is_none()
    );

    // Find_by_identifier_returns_client_when_both_protocols_share_identifier
    let shared = format!("shared-{tag}");
    ok(ClientAdmin::default()
        .create(store.as_ref(), client(&shared, "OIDC Winner"))
        .await);
    ok(SamlServiceProviderAdmin
        .create(store.as_ref(), sp(&shared, "SAML Loser"))
        .await);
    let found = connected
        .find_by_identifier(&shared)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.display_name.as_deref(), Some("OIDC Winner"));
    assert_eq!(found.protocol_type, "oidc");

    // Get_all_returns_both_clients_and_saml_sps, get_all_yields_clients_before_saml_sps
    let all = connected.get_all().await.unwrap();
    assert!(all.iter().any(|a| a.identifier == client_id));
    assert!(all.iter().any(|a| a.identifier == entity_id));
    let at = |id: &str, name: &str| {
        all.iter()
            .position(|a| a.identifier == id && a.display_name.as_deref() == Some(name))
            .unwrap()
    };
    let newest_client = at(&shared, "OIDC Winner");
    let oldest_sp = at(&entity_id, "Connected App Test SP");
    assert!(newest_client < oldest_sp, "clients come first");
}

/// Identity providers through the admin service, and the configuration
/// file's import: secrets stored encrypted, unchanged providers keep their
/// version on re-import, changed ones bump it, admin-created ones stay.
pub async fn identity_provider_admin(store: Arc<dyn rustid_core::stores::ConfigurationStore>) {
    use rustid_core::admin::identity_providers::{
        IdentityProviderAdmin, IdentityProviderInput, import,
    };
    use rustid_core::federation::provider::IdentityProvider;
    use rustid_core::stores::EntityKind;
    let protector = Arc::new(
        rustid_core::data_protection::DataProtector::new([("k", [9u8; 32].as_slice())]).unwrap(),
    );
    let admin = IdentityProviderAdmin::new(protector.clone());
    let p = format!("idp{}-", Utc::now().timestamp_nanos_opt().unwrap());
    let provider = |scheme: &str, name: &str| -> serde_json::Value {
        serde_json::json!({ "scheme": scheme, "displayName": name, "authority": "https://up.example",
                "clientId": "rustid", "clientAuthentication": { "secret": "s3cret" } })
    };
    let admin_made = format!("{p}admin");
    let saved = admin
        .create(
            store.as_ref(),
            IdentityProviderInput::from_json(provider(&admin_made, "Admin")).unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    let raw = store
        .read(EntityKind::IdentityProvider, &saved.id)
        .await
        .unwrap()
        .unwrap();
    assert!(!raw.data.to_string().contains("s3cret"), "stored encrypted");
    assert_eq!(raw.key, admin_made);

    let from_file = format!("{p}file");
    let file = |name: &str| -> Vec<IdentityProvider> {
        vec![serde_json::from_value(provider(&from_file, name)).unwrap()]
    };
    import(store.as_ref(), &protector, &file("File"))
        .await
        .unwrap();
    let first = store
        .read_by_key(EntityKind::IdentityProvider, &from_file)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.version, 1);
    // The same file again: unchanged, though its secret is sealed afresh.
    import(store.as_ref(), &protector, &file("File"))
        .await
        .unwrap();
    let again = store
        .read_by_key(EntityKind::IdentityProvider, &from_file)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((again.id, again.version), (first.id, 1));
    // A changed entry: the same id, the next version.
    import(store.as_ref(), &protector, &file("File, renamed"))
        .await
        .unwrap();
    let changed = store
        .read_by_key(EntityKind::IdentityProvider, &from_file)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((changed.id, changed.version), (first.id, 2));
    assert_eq!(changed.data["displayName"], "File, renamed");
    // The admin-made provider is untouched.
    let kept = store
        .read_by_key(EntityKind::IdentityProvider, &admin_made)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(kept.version, 1);
    // Listed in creation order, both present.
    let listed: Vec<String> = store
        .list(EntityKind::IdentityProvider)
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.key)
        .filter(|k| k.starts_with(&p))
        .collect();
    assert_eq!(listed, [admin_made.clone(), from_file.clone()]);
    admin
        .delete(store.as_ref(), &saved.id)
        .await
        .unwrap()
        .unwrap();
    assert!(
        store
            .read_by_key(EntityKind::IdentityProvider, &admin_made)
            .await
            .unwrap()
            .is_none()
    );
}
