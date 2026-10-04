//! Grant validation runs inside the `TokenRequestValidator.ValidateRequest`
//! span. Its own test binary: tracing caches callsite interest process-wide,
//! so a concurrent test creating the same spans with no subscriber could
//! disable them for this one.

mod support;

use chrono::Utc;
use rustid_core::form::Form;
use rustid_core::resources::Resources;
use rustid_core::token::process;
use support::Fixture;

/// Records the span current when resources are loaded.
struct SpyResources {
    inner: std::sync::Arc<dyn rustid_core::stores::ResourceStore>,
    spans: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

#[async_trait::async_trait]
impl rustid_core::stores::ResourceStore for SpyResources {
    async fn get_all_enabled_resources(
        &self,
    ) -> Result<std::sync::Arc<Resources>, rustid_core::stores::StoreError> {
        let name = tracing::Span::current()
            .metadata()
            .map(|m| m.name().to_owned())
            .unwrap_or_default();
        self.spans.lock().unwrap().push(name);
        self.inner.get_all_enabled_resources().await
    }

    async fn find_api_resources_by_name(
        &self,
        names: &[String],
    ) -> Result<Vec<rustid_core::resources::ApiResource>, rustid_core::stores::StoreError> {
        self.inner.find_api_resources_by_name(names).await
    }

    async fn get_all_resources(
        &self,
    ) -> Result<std::sync::Arc<Resources>, rustid_core::stores::StoreError> {
        self.inner.get_all_resources().await
    }
}

#[tokio::test]
async fn grant_validation_runs_in_the_validate_request_span() {
    let _guard = tracing::subscriber::set_default(tracing_subscriber::registry());
    let mut f = Fixture::new();
    let dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/resource-indicators");
    f.clients = rustid_core::clients::Clients::load(&dir.join("clients.json")).unwrap();
    f.resources = Resources::load(&dir.join("token-resources.json")).unwrap();
    f.stores = rustid_store_memory::stores(f.clients.clone(), f.resources.clone());
    let spans = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    f.stores.resources = std::sync::Arc::new(SpyResources {
        inner: f.stores.resources.clone(),
        spans: spans.clone(),
    });
    let pairs = [
        ("grant_type", "client_credentials"),
        ("client_id", "client"),
        ("client_secret", "secret"),
        ("resource", "urn:api1"),
    ];
    process(&f.ctx(Utc::now()), None, &Form::from_pairs(&pairs))
        .await
        .unwrap();
    assert_eq!(
        spans.lock().unwrap().first().map(String::as_str),
        Some("token.validate_request")
    );
}
