use std::sync::Arc;

use rustid_core::clients::Clients;
use rustid_core::resources::Resources;
use rustid_store_memory::{
    InMemoryClientStore, InMemoryPersistedGrantStore, InMemoryResourceStore,
};
use rustid_store_postgres::PgStore;
use rustid_testkit::fixture;
use rustid_testkit::postgres::ScratchDatabase;
use rustid_testkit::store_contract;

fn raw(name: &str) -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(fixture(name)).unwrap()).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn memory_stores_meet_the_contract() {
    store_contract::client_store(&InMemoryClientStore::new(
        Clients::load(&fixture("clients.json")).unwrap(),
    ))
    .await;
    store_contract::resource_store(&InMemoryResourceStore::new(
        Resources::load(&fixture("resources.json")).unwrap(),
    ))
    .await;
    store_contract::resource_store_lookups(&InMemoryResourceStore::new(
        Resources::load(&fixture("resources.json")).unwrap(),
    ))
    .await;
    store_contract::persisted_grant_store(Arc::new(InMemoryPersistedGrantStore::default())).await;
    store_contract::persisted_grant_purge(Arc::new(InMemoryPersistedGrantStore::default())).await;
    store_contract::persisted_grant_filters(Arc::new(InMemoryPersistedGrantStore::default())).await;
    store_contract::pushed_requests(Arc::new(InMemoryPersistedGrantStore::default())).await;
    let sessions = Arc::new(rustid_store_memory::InMemoryServerSideSessionStore::default());
    store_contract::server_side_session_store(sessions.clone(), sessions.outbox()).await;
    store_contract::server_side_session_queries(sessions.clone()).await;
    store_contract::outbox(Arc::new(rustid_core::outbox::InMemoryOutbox::default())).await;
    store_contract::saml_signin_state_store(Arc::new(
        rustid_store_memory::saml::InMemorySigninStateStore::default(),
    ))
    .await;
    store_contract::saml_logout_session_store(Arc::new(
        rustid_store_memory::saml::InMemoryLogoutSessionStore::default(),
    ))
    .await;
    store_contract::saml_purge(rustid_saml::stores::SamlStores {
        service_providers: Arc::new(
            rustid_store_memory::saml::InMemoryServiceProviderStore::default(),
        ),
        signin_states: Arc::new(rustid_store_memory::saml::InMemorySigninStateStore::default()),
        logout_sessions: Arc::new(rustid_store_memory::saml::InMemoryLogoutSessionStore::default()),
    })
    .await;
    store_contract::saml_service_provider_store(
        &rustid_store_memory::saml::InMemoryServiceProviderStore::new(
            rustid_saml::model::load_service_providers(&fixture("saml-service-providers.json"))
                .unwrap(),
        ),
    )
    .await;
    store_contract::signing_key_store(&rustid_store_memory::InMemorySigningKeyStore::default())
        .await;
    store_contract::device_flow_store(Arc::new(
        rustid_store_memory::InMemoryDeviceFlowStore::default(),
    ))
    .await;
    store_contract::replay_cache(Arc::new(rustid_core::replay::InMemoryReplayCache::default()))
        .await;
    let configuration = Arc::new(rustid_store_memory::InMemoryConfiguration::new(
        &Clients::load(&fixture("clients.json")).unwrap(),
        &Resources::load(&fixture("resources.json")).unwrap(),
    ));
    store_contract::configuration_store(configuration.clone(), configuration.clone()).await;
    let saml_configuration = Arc::new(
        rustid_store_memory::InMemoryConfiguration::new(&Clients::default(), &Resources::default())
            .with_saml_service_providers(
                &rustid_saml::model::load_service_providers(&fixture(
                    "saml-service-providers.json",
                ))
                .unwrap(),
            ),
    );
    store_contract::saml_service_provider_store(saml_configuration.as_ref()).await;
    store_contract::saml_configuration_reaches_runtime(
        saml_configuration.clone(),
        saml_configuration.as_ref(),
    )
    .await;
    store_contract::saml_service_provider_admin(
        saml_configuration.clone(),
        saml_configuration.as_ref(),
    )
    .await;
    store_contract::connected_application_store(saml_configuration.clone()).await;
    store_contract::identity_provider_admin(configuration.clone()).await;
    store_contract::resource_store_lookups(configuration.as_ref()).await;
    store_contract::client_store(configuration.as_ref()).await;
    store_contract::client_configuration(configuration.clone(), configuration.clone()).await;
    store_contract::dcr_registered_client(configuration.clone(), configuration.clone()).await;
    for admin in [
        rustid_core::admin::resources::ResourceAdmin::identity_resources(),
        rustid_core::admin::resources::ResourceAdmin::api_scopes(),
    ] {
        store_contract::resource_admin(configuration.clone(), admin).await;
    }
    store_contract::resource_names_span_both_kinds(configuration.clone()).await;
    store_contract::api_resource_admin(configuration.clone()).await;
    store_contract::client_admin(configuration.clone()).await;
    store_contract::schema_admin(configuration.clone()).await;
    store_contract::extended_properties(
        configuration.clone(),
        configuration.clone(),
        configuration.clone(),
    )
    .await;
    store_contract::throttling(Arc::new(
        rustid_core::stores::InMemoryDeviceFlowThrottling::default(),
    ))
    .await;
    let dir = tempfile::tempdir().unwrap();
    store_contract::signing_key_store(&rustid_store_memory::FileSystemSigningKeyStore::new(
        dir.path().join("keys"),
    ))
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_stores_meet_the_contract() {
    let Some(db) = ScratchDatabase::create().await else {
        eprintln!("skipped: TEST_POSTGRES_URL is not set");
        return;
    };
    let store = PgStore::connect(&db.url, 8, false).await.unwrap();
    store.migrate().await.unwrap();
    store
        .import_clients(raw("clients.json").as_array().unwrap())
        .await
        .unwrap();
    store
        .import_resources(&raw("resources.json"))
        .await
        .unwrap();
    store_contract::client_store(&store).await;
    store_contract::resource_store(&store).await;
    store_contract::resource_store_lookups(&store).await;
    store_contract::persisted_grant_store(Arc::new(store.clone())).await;
    store_contract::persisted_grant_purge(Arc::new(store.clone())).await;
    store_contract::persisted_grant_filters(Arc::new(store.clone())).await;
    store_contract::pushed_requests(Arc::new(store.clone())).await;
    store_contract::server_side_session_store(Arc::new(store.clone()), Arc::new(store.clone()))
        .await;
    store_contract::server_side_session_queries(Arc::new(store.clone())).await;
    store_contract::outbox(Arc::new(store.clone())).await;
    store_contract::saml_signin_state_store(Arc::new(store.clone())).await;
    store_contract::saml_logout_session_store(Arc::new(store.clone())).await;
    store_contract::saml_purge(rustid_saml::stores::SamlStores {
        service_providers: Arc::new(store.clone()),
        signin_states: Arc::new(store.clone()),
        logout_sessions: Arc::new(store.clone()),
    })
    .await;
    store
        .import_saml_service_providers(raw("saml-service-providers.json").as_array().unwrap())
        .await
        .unwrap();
    store_contract::saml_service_provider_store(&store).await;
    store_contract::saml_configuration_reaches_runtime(Arc::new(store.clone()), &store).await;
    store_contract::saml_service_provider_admin(Arc::new(store.clone()), &store).await;
    store_contract::connected_application_store(Arc::new(store.clone())).await;
    store_contract::identity_provider_admin(Arc::new(store.clone())).await;
    {
        // Imports give ids at version 1; a changed provider's version bumps.
        use rustid_core::stores::{ConfigurationStore, EntityKind};
        let first = store
            .read_by_key(EntityKind::SamlServiceProvider, "https://sp.example")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.version, 1);
        let mut changed = raw("saml-service-providers.json");
        changed[0]["displayName"] = serde_json::json!("Renamed");
        store
            .import_saml_service_providers(changed.as_array().unwrap())
            .await
            .unwrap();
        let bumped = store
            .read_by_key(EntityKind::SamlServiceProvider, "https://sp.example")
            .await
            .unwrap()
            .unwrap();
        assert_eq!((bumped.id, bumped.version), (first.id, 2));
        store
            .import_saml_service_providers(raw("saml-service-providers.json").as_array().unwrap())
            .await
            .unwrap();
    }
    store_contract::signing_key_store(&store).await;
    store_contract::device_flow_store(Arc::new(store.clone())).await;
    store_contract::replay_cache(Arc::new(store.clone())).await;
    store_contract::configuration_store(Arc::new(store.clone()), Arc::new(store.clone())).await;
    store_contract::client_configuration(Arc::new(store.clone()), Arc::new(store.clone())).await;
    store_contract::dcr_registered_client(Arc::new(store.clone()), Arc::new(store.clone())).await;
    for admin in [
        rustid_core::admin::resources::ResourceAdmin::identity_resources(),
        rustid_core::admin::resources::ResourceAdmin::api_scopes(),
    ] {
        store_contract::resource_admin(Arc::new(store.clone()), admin).await;
    }
    store_contract::resource_names_span_both_kinds(Arc::new(store.clone())).await;
    store_contract::api_resource_admin(Arc::new(store.clone())).await;
    store_contract::client_admin(Arc::new(store.clone())).await;
    store_contract::schema_admin(Arc::new(store.clone())).await;
    store_contract::extended_properties(
        Arc::new(store.clone()),
        Arc::new(store.clone()),
        Arc::new(store.clone()),
    )
    .await;
    // Imports give ids at version 1; re-importing keeps ids and unchanged
    // versions, and bumps a changed entity's version.
    {
        use rustid_core::stores::{ConfigurationStore, EntityKind};
        let first = store
            .read_by_key(EntityKind::ApiScope, "api1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.version, 1);
        store
            .import_resources(&raw("resources.json"))
            .await
            .unwrap();
        let again = store
            .read_by_key(EntityKind::ApiScope, "api1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!((again.id, again.version), (first.id, 1));
        let mut changed = raw("resources.json");
        for scope in changed["apiScopes"].as_array_mut().unwrap() {
            if scope["name"] == "api1" {
                scope["displayName"] = serde_json::json!("changed by import");
            }
        }
        store.import_resources(&changed).await.unwrap();
        let bumped = store
            .read_by_key(EntityKind::ApiScope, "api1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!((bumped.id, bumped.version), (first.id, 2));
        store
            .import_resources(&raw("resources.json"))
            .await
            .unwrap();
    }
    // Re-importing resources_file replaces what admin set on a file-defined
    // entity, extended properties included; the file's own `properties`
    // reach the runtime.
    {
        use rustid_core::admin::resources::ResourceAdmin;
        use rustid_core::admin::schemas::{SchemaAdmin, schema_for};
        use rustid_core::stores::{ConfigurationStore, EntityKind, ResourceStore};
        let schema = serde_json::from_value(serde_json::json!({
            "schemaId": "api-scope",
            "attributeDefinitions": [
                { "code": "owner", "attributeType": { "kind": "scalar", "dataType": "String" } },
            ],
        }))
        .unwrap();
        SchemaAdmin.create(&store, schema).await.unwrap().unwrap();
        let scopes = ResourceAdmin::api_scopes();
        let read = scopes.get_by_name(&store, "api1").await.unwrap().unwrap();
        let mut input = read.item.clone();
        input
            .extended_properties
            .insert("owner".into(), serde_json::json!("admin-team"));
        scopes
            .update(&store, &read.id, input, read.version)
            .await
            .unwrap()
            .unwrap();
        let mut with_properties = raw("resources.json");
        for scope in with_properties["apiScopes"].as_array_mut().unwrap() {
            if scope["name"] == "api1" {
                scope["properties"] = serde_json::json!({ "tier": "gold" });
            }
        }
        store.import_resources(&with_properties).await.unwrap();
        let stored = store
            .read_by_key(EntityKind::ApiScope, "api1")
            .await
            .unwrap()
            .unwrap();
        assert!(stored.data.get("extendedProperties").is_none());
        let enabled = store.get_all_enabled_resources().await.unwrap();
        let api1 = enabled
            .api_scopes
            .iter()
            .find(|s| s.name == "api1")
            .unwrap();
        assert_eq!(
            api1.properties.iter().collect::<Vec<_>>(),
            [(&"tier".to_owned(), &"gold".to_owned())]
        );
        store
            .import_resources(&raw("resources.json"))
            .await
            .unwrap();
        SchemaAdmin
            .delete(&store, "api-scope")
            .await
            .unwrap()
            .unwrap();
        assert!(schema_for(&store, "api-scope").await.unwrap().is_none());
    }
    store_contract::throttling(Arc::new(store.clone())).await;
    // Instances share it: what one records is a replay at another.
    let other = PgStore::connect(&db.url, 2, false).await.unwrap();
    use rustid_core::replay::ReplayCache;
    assert!(
        store
            .add_if_absent("p", "shared", 4_102_444_800, 1_000_000)
            .await
            .unwrap()
    );
    assert!(
        !other
            .add_if_absent("p", "shared", 4_102_444_800, 1_000_001)
            .await
            .unwrap()
    );
    other.close().await;
    store.close().await;
    db.drop().await;
}

#[test]
#[should_panic(expected = "duplicate SAML service provider entity id")]
fn the_memory_service_provider_store_refuses_duplicate_entity_ids() {
    let sps = rustid_saml::model::load_service_providers(&fixture("saml-service-providers.json"))
        .unwrap();
    let mut doubled = sps.clone();
    doubled.push(sps[0].clone());
    rustid_store_memory::saml::InMemoryServiceProviderStore::new(doubled);
}
