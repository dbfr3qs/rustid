use chrono::{DateTime, Utc};
use rustid_core::authorize::login::{CONTINUATION, Continuation};
use rustid_core::grants::hashed_key;
use rustid_core::session::SignIn;
use rustid_core::stores::PersistedGrantStore;
use rustid_core::tokens::Claim;
use rustid_store_memory::InMemoryPersistedGrantStore;

fn now() -> DateTime<Utc> {
    DateTime::from_timestamp(1_800_000_000, 0).unwrap()
}

fn continuation() -> Continuation {
    Continuation::new(
        "/connect/authorize/callback?client_id=web",
        SignIn {
            subject_id: "1".into(),
            claims: vec![Claim::string("name", "Alice")],
            ..Default::default()
        },
    )
}

#[tokio::test]
async fn continuations_redeem_once_within_five_minutes() {
    let grants = InMemoryPersistedGrantStore::default();
    let token = continuation().store(&grants, now()).await.unwrap();
    assert!(token.ends_with("-1") && token.len() == 66);
    let stored = grants
        .get(&hashed_key(&token, CONTINUATION))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.grant_type, CONTINUATION);
    assert_eq!(
        stored.expiration,
        Some(now() + chrono::Duration::minutes(5))
    );
    assert_eq!(stored.subject_id.as_deref(), Some("1"));

    let redeemed = Continuation::redeem(&grants, &token, now()).await.unwrap();
    assert_eq!(redeemed, Some(continuation()));
    assert_eq!(
        Continuation::redeem(&grants, &token, now()).await.unwrap(),
        None
    );
}

#[tokio::test]
async fn expired_or_foreign_tokens_redeem_nothing() {
    let grants = InMemoryPersistedGrantStore::default();
    let token = continuation().store(&grants, now()).await.unwrap();
    let late = now() + chrono::Duration::minutes(5);
    assert_eq!(
        Continuation::redeem(&grants, &token, late).await.unwrap(),
        None
    );
    assert_eq!(
        Continuation::redeem(&grants, "nope", now()).await.unwrap(),
        None
    );
}
