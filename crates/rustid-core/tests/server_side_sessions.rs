//! Session tickets in the server-side session store:
//! storing, renewing (re-keying on a change of user), loading, expiry and
//! corrupt tickets.

mod support;

use std::sync::Arc;

use chrono::{Duration, Utc};
use rustid_core::data_protection::DataProtector;
use rustid_core::grants::{GrantFilter, PersistedGrant};
use rustid_core::server_side_sessions::{Loaded, SessionFilter, load_session, store_session};
use rustid_core::session::{SignIn, UserSession};
use rustid_core::stores::ServerSideSessionStore;
use rustid_core::tokens::Claim;
use rustid_store_memory::InMemoryServerSideSessionStore;
use support::{Fixture, ISSUER};

fn protector() -> DataProtector {
    DataProtector::new([("k", [9u8; 32].as_slice())]).unwrap()
}

fn signed_in(subject: &str, current: Option<&UserSession>) -> UserSession {
    UserSession::sign_in(
        SignIn {
            subject_id: subject.into(),
            claims: vec![Claim::string("name", &format!("{subject} name"))],
            ..Default::default()
        },
        current,
        Utc::now(),
        3600,
    )
}

fn refresh_grant(key: &str, session: &UserSession, grant_type: &str) -> PersistedGrant {
    PersistedGrant {
        key: key.into(),
        grant_type: grant_type.into(),
        client_id: "web".into(),
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
async fn a_new_session_gets_a_record_whose_ticket_opens_back() {
    let mut f = Fixture::new();
    f.options.server_side_sessions.user_display_name_claim_type = Some("name".into());
    let store: Arc<dyn ServerSideSessionStore> =
        Arc::new(InMemoryServerSideSessionStore::default());
    let p = protector();
    let mut session = signed_in("alice", None);
    let key = store_session(
        store.as_ref(),
        f.stores.grants.as_ref(),
        &p,
        &f.options,
        &mut session,
        ISSUER,
    )
    .await
    .unwrap();
    assert_eq!(key.len(), 64);
    assert_eq!(session.key.as_deref(), Some(key.as_str()));
    assert_eq!(session.issuer.as_deref(), Some(ISSUER));
    let record = store.get_session(&key).await.unwrap().unwrap();
    assert_eq!(record.subject_id, "alice");
    assert_eq!(record.session_id, session.session_id);
    assert_eq!(record.display_name.as_deref(), Some("alice name"));
    assert_eq!(record.created, record.renewed);
    assert_eq!(record.renewed, session.issued);
    assert_eq!(record.expires, Some(session.expires));
    match load_session(store.as_ref(), &p, &key, Utc::now())
        .await
        .unwrap()
    {
        Loaded::Active(loaded) => assert_eq!(loaded, session),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn signing_in_again_keeps_the_key_and_a_new_user_revokes_the_old_grants() {
    let f = Fixture::new();
    let store: Arc<dyn ServerSideSessionStore> =
        Arc::new(InMemoryServerSideSessionStore::default());
    let p = protector();
    let grants = f.stores.grants.as_ref();
    let mut bob = signed_in("bob", None);
    let key = store_session(store.as_ref(), grants, &p, &f.options, &mut bob, ISSUER)
        .await
        .unwrap();
    let created = store.get_session(&key).await.unwrap().unwrap().created;

    // The same user again: same key and session, the record renewed.
    let mut again = signed_in("bob", Some(&bob));
    assert_eq!(again.key, bob.key);
    let later = Utc::now() + Duration::seconds(5);
    assert_eq!(
        store_session(store.as_ref(), grants, &p, &f.options, &mut again, ISSUER)
            .await
            .unwrap(),
        key
    );
    let record = store.get_session(&key).await.unwrap().unwrap();
    assert_eq!(record.created, created);
    assert_eq!(record.session_id, bob.session_id);

    // Another user in the same browser: a new key (a planted cookie's key
    // is never adopted), a new session, bob's record gone, and
    // bob's session's tokens revoked (consents kept).
    grants
        .store(refresh_grant("rt", &bob, "refresh_token"))
        .await
        .unwrap();
    grants
        .store(refresh_grant("consent", &bob, "user_consent"))
        .await
        .unwrap();
    let mut alice = signed_in("alice", Some(&bob));
    alice.issued = later;
    let alice_key = store_session(store.as_ref(), grants, &p, &f.options, &mut alice, ISSUER)
        .await
        .unwrap();
    assert_ne!(alice_key, key);
    assert_eq!(alice.key.as_deref(), Some(alice_key.as_str()));
    assert!(
        store.get_session(&key).await.unwrap().is_none(),
        "old key gone"
    );
    let record = store.get_session(&alice_key).await.unwrap().unwrap();
    assert_eq!(record.subject_id, "alice");
    assert_ne!(record.session_id, bob.session_id);
    assert!(record.created > created);
    let left = grants
        .get_all(&GrantFilter {
            subject_id: Some("bob".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].grant_type, "user_consent");
    assert_eq!(
        store
            .get_sessions(&SessionFilter {
                subject_id: Some("bob".into()),
                ..Default::default()
            })
            .await
            .unwrap()
            .len(),
        0
    );
}

#[tokio::test]
async fn missing_corrupt_and_expired_records_open_no_session() {
    let f = Fixture::new();
    let store: Arc<dyn ServerSideSessionStore> =
        Arc::new(InMemoryServerSideSessionStore::default());
    let p = protector();
    assert!(matches!(
        load_session(store.as_ref(), &p, "nope", Utc::now())
            .await
            .unwrap(),
        Loaded::Missing
    ));

    let mut session = signed_in("alice", None);
    let key = store_session(
        store.as_ref(),
        f.stores.grants.as_ref(),
        &p,
        &f.options,
        &mut session,
        ISSUER,
    )
    .await
    .unwrap();
    let mut record = store.get_session(&key).await.unwrap().unwrap();
    record.ticket = "invalid".into();
    store.update_session(record).await.unwrap();
    assert!(matches!(
        load_session(store.as_ref(), &p, &key, Utc::now())
            .await
            .unwrap(),
        Loaded::Missing
    ));
    assert!(store.get_session(&key).await.unwrap().is_none(), "deleted");

    // The record's times rule: expired a minute ago.
    let mut session = signed_in("alice", None);
    let key = store_session(
        store.as_ref(),
        f.stores.grants.as_ref(),
        &p,
        &f.options,
        &mut session,
        ISSUER,
    )
    .await
    .unwrap();
    let mut record = store.get_session(&key).await.unwrap().unwrap();
    record.expires = Some(Utc::now() - Duration::minutes(1));
    store.update_session(record).await.unwrap();
    match load_session(store.as_ref(), &p, &key, Utc::now())
        .await
        .unwrap()
    {
        Loaded::Expired(expired) => assert_eq!(expired.subject_id, "alice"),
        other => panic!("{other:?}"),
    }
    assert!(store.get_session(&key).await.unwrap().is_none(), "deleted");
}
