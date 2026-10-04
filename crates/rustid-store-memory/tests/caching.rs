use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use rustid_core::clients::Client;
use rustid_core::resources::{ApiResource, Resources};
use rustid_core::stores::{ClientStore, ResourceStore, StoreError};
use rustid_store_memory::{CacheDurations, CachingClientStore, CachingResourceStore};

/// Counts calls and answers from fixed data.
#[derive(Default)]
struct Counting {
    calls: AtomicUsize,
    fail: bool,
}

impl Counting {
    fn hit(&self) -> Result<(), StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            Err(StoreError::Backend("down".into()))
        } else {
            Ok(())
        }
    }
}

#[async_trait]
impl ClientStore for Counting {
    async fn find_client_by_id(&self, client_id: &str) -> Result<Option<Arc<Client>>, StoreError> {
        self.hit()?;
        Ok((client_id == "known").then(|| {
            Arc::new(Client {
                client_id: "known".into(),
                ..Default::default()
            })
        }))
    }

    async fn is_cors_origin_allowed(&self, origin: &str) -> Result<bool, StoreError> {
        self.hit()?;
        Ok(origin == "https://ok.test")
    }
}

#[async_trait]
impl ResourceStore for Counting {
    async fn get_all_enabled_resources(&self) -> Result<Arc<Resources>, StoreError> {
        self.hit()?;
        Ok(Arc::new(Resources::default()))
    }

    async fn get_all_resources(&self) -> Result<Arc<Resources>, StoreError> {
        self.hit()?;
        Ok(Arc::new(Resources::default()))
    }

    async fn find_api_resources_by_name(
        &self,
        names: &[String],
    ) -> Result<Vec<ApiResource>, StoreError> {
        self.hit()?;
        Ok(names
            .iter()
            .map(|n| ApiResource {
                name: n.clone(),
                ..Default::default()
            })
            .collect())
    }
}

fn durations(ttl: Duration) -> CacheDurations {
    CacheDurations {
        client_store: ttl,
        resource_store: ttl,
        cors: ttl,
    }
}

#[tokio::test]
async fn found_clients_are_cached_and_missing_ones_are_not() {
    let inner = Arc::new(Counting::default());
    let store = CachingClientStore::new(inner.clone(), durations(Duration::from_secs(60)));
    for _ in 0..3 {
        assert!(store.find_client_by_id("known").await.unwrap().is_some());
        assert!(store.find_client_by_id("missing").await.unwrap().is_none());
    }
    // One lookup for the known client, three for the missing one.
    assert_eq!(inner.calls.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn cors_answers_are_cached_either_way() {
    let inner = Arc::new(Counting::default());
    let store = CachingClientStore::new(inner.clone(), durations(Duration::from_secs(60)));
    for _ in 0..3 {
        assert!(
            store
                .is_cors_origin_allowed("https://ok.test")
                .await
                .unwrap()
        );
        assert!(
            !store
                .is_cors_origin_allowed("https://no.test")
                .await
                .unwrap()
        );
    }
    assert_eq!(inner.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn resources_are_cached_per_lookup() {
    let inner = Arc::new(Counting::default());
    let store = CachingResourceStore::new(inner.clone(), durations(Duration::from_secs(60)));
    for _ in 0..3 {
        store.get_all_enabled_resources().await.unwrap();
        store
            .find_api_resources_by_name(&["a b".into()])
            .await
            .unwrap();
        let split = store
            .find_api_resources_by_name(&["a".into(), "b".into()])
            .await
            .unwrap();
        assert_eq!(split.len(), 2, "different name lists never share an entry");
    }
    assert_eq!(inner.calls.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn entries_expire_and_failures_are_not_cached() {
    let inner = Arc::new(Counting::default());
    let store = CachingClientStore::new(inner.clone(), durations(Duration::from_millis(50)));
    store.find_client_by_id("known").await.unwrap();
    tokio::time::sleep(Duration::from_millis(120)).await;
    store.find_client_by_id("known").await.unwrap();
    assert_eq!(inner.calls.load(Ordering::SeqCst), 2);

    let failing = Arc::new(Counting {
        fail: true,
        ..Default::default()
    });
    let store = CachingClientStore::new(failing.clone(), durations(Duration::from_secs(60)));
    for _ in 0..2 {
        assert!(store.find_client_by_id("known").await.is_err());
        assert!(
            store
                .is_cors_origin_allowed("https://ok.test")
                .await
                .is_err()
        );
    }
    assert_eq!(failing.calls.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn keys_longer_than_the_limit_bypass_the_cache() {
    // HybridCache doesn't cache keys over 1024 characters; neither do we, so
    // request input such as a huge Origin header can't pin memory.
    let inner = Arc::new(Counting::default());
    let store = CachingClientStore::new(inner.clone(), durations(Duration::from_secs(60)));
    let origin = format!("https://{}.test", "x".repeat(1100));
    for _ in 0..3 {
        assert!(!store.is_cors_origin_allowed(&origin).await.unwrap());
    }
    assert_eq!(inner.calls.load(Ordering::SeqCst), 3);

    let resources = CachingResourceStore::new(inner.clone(), durations(Duration::from_secs(60)));
    let long_name = "n".repeat(1100);
    for _ in 0..2 {
        resources
            .find_api_resources_by_name(std::slice::from_ref(&long_name))
            .await
            .unwrap();
    }
    assert_eq!(inner.calls.load(Ordering::SeqCst), 5);
}
