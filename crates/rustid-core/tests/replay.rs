use rustid_core::replay::{InMemoryReplayCache, ReplayCache};

#[tokio::test]
async fn a_handle_is_accepted_once_until_it_expires() {
    let cache = InMemoryReplayCache::default();
    assert!(cache.add_if_absent("p", "jti-1", 200, 100).await.unwrap());
    assert!(
        !cache.add_if_absent("p", "jti-1", 200, 150).await.unwrap(),
        "replay before expiry"
    );
    assert!(
        cache
            .add_if_absent("other", "jti-1", 200, 150)
            .await
            .unwrap(),
        "purposes are separate"
    );
    assert!(
        cache.add_if_absent("p", "jti-1", 400, 200).await.unwrap(),
        "expired entries may be used again"
    );
}

/// Without the purge job (it may be disabled), recording a value clears
/// the expired ones, so the cache can't grow without bound.
#[tokio::test]
async fn expired_entries_are_cleared_without_the_purge() {
    let cache = InMemoryReplayCache::default();
    for i in 0..10 {
        cache
            .add_if_absent("p", &format!("old-{i}"), 110, 100)
            .await
            .unwrap();
    }
    cache.add_if_absent("p", "new", 400, 200).await.unwrap();
    assert_eq!(
        cache.remove_expired(200, 1000).await.unwrap(),
        0,
        "nothing expired is left to purge"
    );
}
