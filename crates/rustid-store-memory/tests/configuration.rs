//! The in-memory configuration store's runtime views.

use rustid_core::admin::EntityId;
use rustid_core::clients::Clients;
use rustid_core::resources::Resources;
use rustid_core::stores::{ClientStore, ConfigurationStore, EntityKind, StoredEntity};
use rustid_store_memory::InMemoryConfiguration;

fn fixture(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

#[tokio::test]
async fn one_client_that_wont_decode_leaves_the_others_working() {
    let clients = Clients::load(&fixture("clients.json")).unwrap();
    let known = clients.clients[0].client_id.clone();
    let store = InMemoryConfiguration::new(
        &clients,
        &Resources::load(&fixture("resources.json")).unwrap(),
    );
    store
        .create(
            EntityKind::Client,
            &StoredEntity {
                id: EntityId::new_v7(),
                key: "broken".into(),
                version: 1,
                data: serde_json::json!({ "clientId": "broken", "allowedGrantTypes": "not a list" }),
            },
        )
        .await
        .unwrap();
    assert!(store.find_client_by_id(&known).await.unwrap().is_some());
    assert!(store.find_client_by_id("broken").await.unwrap().is_none());
}
