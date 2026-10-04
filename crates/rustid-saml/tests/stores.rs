//! An invalid provider is never
//! returned by lookup.

use std::sync::Arc;

use async_trait::async_trait;
use rustid_core::stores::StoreError;
use rustid_saml::model::{ServiceProvider, load_service_providers};
use rustid_saml::stores::{ServiceProviderStore, ValidatingServiceProviderStore};

struct Fixed(Vec<Arc<ServiceProvider>>);

#[async_trait]
impl ServiceProviderStore for Fixed {
    async fn find_by_entity_id(
        &self,
        entity_id: &str,
    ) -> Result<Option<Arc<ServiceProvider>>, StoreError> {
        Ok(self.0.iter().find(|sp| sp.entity_id == entity_id).cloned())
    }

    async fn get_all(&self) -> Result<Vec<Arc<ServiceProvider>>, StoreError> {
        Ok(self.0.clone())
    }
}

#[tokio::test]
async fn invalid_service_providers_are_not_found() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/saml-service-providers.json");
    let mut sps = load_service_providers(&path).unwrap();
    sps[1].allowed_scopes.clear();
    let total = sps.len();
    let store = ValidatingServiceProviderStore::new(Fixed(sps.into_iter().map(Arc::new).collect()));
    assert!(
        store
            .find_by_entity_id("https://sp.example")
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .find_by_entity_id("https://idp-initiated.example")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store.get_all().await.unwrap().len(),
        total - 2,
        "get_all leaves out invalid providers (this one and noacs.example)"
    );
}
