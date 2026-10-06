//! Identity providers as configuration entities: the admin service's
//! create, read, update, delete and query, secrets kept encrypted and never
//! read back, and resolving a stored provider into one ready to use.

use std::sync::Arc;

use rustid_core::admin::identity_providers::{
    IdentityProviderAdmin, IdentityProviderFilter, IdentityProviderInput, resolve,
};
use rustid_core::admin::query::Range;
use rustid_core::data_protection::DataProtector;
use rustid_core::federation::provider::Credential;
use rustid_core::stores::{ConfigurationStore, EntityKind};
use rustid_store_memory::InMemoryConfiguration;
use serde_json::{Value, json};

fn protector(keys: &[(&str, [u8; 32])]) -> Arc<DataProtector> {
    Arc::new(DataProtector::new(keys.iter().map(|(id, k)| (*id, k.as_slice()))).unwrap())
}

fn provider(scheme: &str) -> Value {
    json!({ "scheme": scheme, "displayName": format!("Provider {scheme}"),
            "authority": "https://up.example", "clientId": "rustid",
            "clientAuthentication": { "secret": "s3cret" } })
}

fn input(v: Value) -> IdentityProviderInput {
    IdentityProviderInput::from_json(v).unwrap()
}

fn no_env(_: &str) -> Option<String> {
    None
}

fn pem_key() -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/signing-key.pem"),
    )
    .unwrap()
}

#[tokio::test]
async fn create_read_and_the_secret_never_comes_back() {
    let store = InMemoryConfiguration::default();
    let admin = IdentityProviderAdmin::new(protector(&[("a", [1; 32])]));
    let saved = admin
        .create(&store, input(provider("up")))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(saved.version, 1);

    let read = admin.get(&store, &saved.id).await.unwrap().unwrap();
    let json = serde_json::to_value(&read.item).unwrap();
    assert_eq!(json["scheme"], "up");
    assert_eq!(json["clientAuthentication"]["hasSecret"], true);
    assert!(
        json["clientAuthentication"].get("secret").is_none(),
        "{json}"
    );
    assert!(!json.to_string().contains("s3cret"));
    let by_scheme = admin.get_by_scheme(&store, "up").await.unwrap().unwrap();
    assert_eq!(by_scheme.id, saved.id);

    // At rest: protected, not plain.
    let stored = store
        .read(EntityKind::IdentityProvider, &saved.id)
        .await
        .unwrap()
        .unwrap();
    assert!(
        !stored.data.to_string().contains("s3cret"),
        "{}",
        stored.data
    );
    assert!(stored.data["clientAuthentication"]["secretProtected"].is_string());

    let errors = admin
        .create(&store, input(provider("up")))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(errors[0].code, "already_exists");
}

#[tokio::test]
async fn updates_keep_the_secret_unless_the_method_changes() {
    let store = InMemoryConfiguration::default();
    let p = protector(&[("a", [1; 32])]);
    let admin = IdentityProviderAdmin::new(p.clone());
    let saved = admin
        .create(&store, input(provider("up")))
        .await
        .unwrap()
        .unwrap();

    // No secret sent, same method: the stored one stays.
    let mut renamed = provider("up");
    renamed["displayName"] = "Renamed".into();
    renamed["clientAuthentication"] = json!({});
    let v2 = admin
        .update(&store, &saved.id, input(renamed), 1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(v2.version, 2);
    let stored = store
        .read(EntityKind::IdentityProvider, &saved.id)
        .await
        .unwrap()
        .unwrap();
    let resolved = resolve(&stored, &p, &no_env).unwrap();
    assert!(matches!(&resolved.credential, Credential::Basic(s) if s == "s3cret"));
    assert_eq!(resolved.config.display_name, "Renamed");

    // A new method without its key: refused.
    let mut jwt = provider("up");
    jwt["clientAuthentication"] = json!({ "method": "private_key_jwt", "keyId": "k1" });
    let errors = admin
        .update(&store, &saved.id, input(jwt.clone()), 2)
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(errors[0].code, "validation_failed", "{errors:?}");
    // With an inline key: resolves to private_key_jwt, and the key never reads back.
    jwt["clientAuthentication"]["key"] = pem_key().into();
    admin
        .update(&store, &saved.id, input(jwt), 2)
        .await
        .unwrap()
        .unwrap();
    let stored = store
        .read(EntityKind::IdentityProvider, &saved.id)
        .await
        .unwrap()
        .unwrap();
    assert!(!stored.data.to_string().contains("PRIVATE KEY"));
    assert!(matches!(
        resolve(&stored, &p, &no_env).unwrap().credential,
        Credential::PrivateKeyJwt(_)
    ));
    let read =
        serde_json::to_value(admin.get(&store, &saved.id).await.unwrap().unwrap().item).unwrap();
    assert_eq!(read["clientAuthentication"]["hasKey"], true);
    assert!(!read.to_string().contains("PRIVATE KEY"));

    // The scheme can't change, and a stale version conflicts.
    let errors = admin
        .update(&store, &saved.id, input(provider("other")), 3)
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(errors[0].code, "invalid_value", "{errors:?}");
    let errors = admin
        .update(&store, &saved.id, input(provider("up")), 1)
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(errors[0].code, "version_conflict");
}

#[tokio::test]
async fn validation_and_credentials_are_checked_on_write() {
    let store = InMemoryConfiguration::default();
    let admin = IdentityProviderAdmin::new(protector(&[("a", [1; 32])]));
    let mut bad = provider("up");
    bad["authority"] = "http://up.example".into();
    assert_eq!(
        admin.create(&store, input(bad)).await.unwrap().unwrap_err()[0].code,
        "validation_failed"
    );
    let mut garbage = provider("jwt");
    garbage["clientAuthentication"] =
        json!({ "method": "private_key_jwt", "keyId": "k", "key": "not a key" });
    assert_eq!(
        admin
            .create(&store, input(garbage))
            .await
            .unwrap()
            .unwrap_err()[0]
            .code,
        "validation_failed"
    );
    assert!(IdentityProviderInput::from_json(json!({ "scheme": "x", "nope": 1 })).is_err());
}

#[tokio::test]
async fn delete_and_query() {
    let store = InMemoryConfiguration::default();
    let admin = IdentityProviderAdmin::new(protector(&[("a", [1; 32])]));
    let a = admin
        .create(&store, input(provider("alpha")))
        .await
        .unwrap()
        .unwrap();
    admin
        .create(&store, input(provider("beta")))
        .await
        .unwrap()
        .unwrap();
    let found = admin
        .query(
            &store,
            &IdentityProviderFilter {
                display_name: Some("alpha".into()),
                ..Default::default()
            },
            None,
            &Range::default(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.items.len(), 1);
    assert_eq!(found.items[0].scheme, "alpha");
    assert!(
        !serde_json::to_string(&found.items)
            .unwrap()
            .contains("s3cret")
    );
    admin.delete(&store, &a.id).await.unwrap().unwrap();
    assert!(admin.get(&store, &a.id).await.unwrap().is_none());
    admin.delete(&store, &a.id).await.unwrap().unwrap();
}

#[tokio::test]
async fn secrets_protected_under_an_older_key_still_resolve() {
    let store = InMemoryConfiguration::default();
    let old = protector(&[("a", [1; 32])]);
    let saved = IdentityProviderAdmin::new(old)
        .create(&store, input(provider("up")))
        .await
        .unwrap()
        .unwrap();
    let rotated = protector(&[("b", [2; 32]), ("a", [1; 32])]);
    let stored = store
        .read(EntityKind::IdentityProvider, &saved.id)
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(resolve(&stored, &rotated, &no_env).unwrap().credential, Credential::Basic(s) if s == "s3cret")
    );
}

#[tokio::test]
async fn without_a_configured_key_ring_inline_secrets_are_refused() {
    let store = InMemoryConfiguration::default();
    let admin = IdentityProviderAdmin::new(protector(&[("a", [1; 32])])).with_inline_secrets(false);
    let errors = admin
        .create(&store, input(provider("up")))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(errors[0].code, "validation_failed");
    assert!(
        errors[0].message.contains("data_protection.keys"),
        "{}",
        errors[0].message
    );
}

#[tokio::test]
async fn a_recreated_provider_is_never_served_from_the_old_one() {
    use rustid_core::federation::Federation;
    use rustid_core::federation::upstream::NoUpstream;
    let store: Arc<dyn ConfigurationStore> = Arc::new(InMemoryConfiguration::default());
    let p = protector(&[("a", [1; 32])]);
    let admin = IdentityProviderAdmin::new(p.clone());
    let federation = Federation::from_store(store.clone(), p, Arc::new(NoUpstream), false);
    let mut old = provider("up");
    old["authority"] = "https://old.example".into();
    old["clientAuthentication"]["secret"] = "old".into();
    let saved = admin
        .create(store.as_ref(), input(old))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        federation
            .find("up")
            .await
            .unwrap()
            .unwrap()
            .config
            .authority,
        "https://old.example"
    );
    admin
        .delete(store.as_ref(), &saved.id)
        .await
        .unwrap()
        .unwrap();
    assert!(federation.find("up").await.unwrap().is_none());
    // The same scheme again, at version 1 again.
    let mut new = provider("up");
    new["authority"] = "https://new.example".into();
    new["clientAuthentication"]["secret"] = "new".into();
    admin
        .create(store.as_ref(), input(new))
        .await
        .unwrap()
        .unwrap();
    let found = federation.find("up").await.unwrap().unwrap();
    assert_eq!(found.config.authority, "https://new.example");
    assert!(matches!(&found.credential, Credential::Basic(s) if s == "new"));
}

#[tokio::test]
async fn the_admin_api_never_reads_environment_variables_or_files() {
    let store = InMemoryConfiguration::default();
    let admin = IdentityProviderAdmin::new(protector(&[("a", [1; 32])]));
    for auth in [
        json!({ "secretEnv": "PATH" }),
        json!({ "method": "private_key_jwt", "keyId": "k", "keyFile": "/etc/hostname" }),
        json!({ "method": "private_key_jwt", "keyId": "k", "key": pem_key(), "certificateFile": "/etc/hostname" }),
    ] {
        let mut p = provider("up");
        p["clientAuthentication"] = auth.clone();
        let errors = admin.create(&store, input(p)).await.unwrap().unwrap_err();
        assert_eq!(errors[0].code, "validation_failed", "{auth}");
        assert!(
            errors[0].message.contains("identity_providers_file"),
            "{}",
            errors[0].message
        );
    }
}

#[tokio::test]
async fn the_registered_id_token_algorithm_round_trips_and_is_validated() {
    let store = InMemoryConfiguration::default();
    let p = protector(&[("a", [1; 32])]);
    let admin = IdentityProviderAdmin::new(p.clone());
    let mut with_alg = provider("up");
    with_alg["idTokenSignedResponseAlg"] = "ES256".into();
    let saved = admin
        .create(&store, input(with_alg))
        .await
        .unwrap()
        .unwrap();
    let read = admin.get(&store, &saved.id).await.unwrap().unwrap();
    assert_eq!(
        serde_json::to_value(&read.item).unwrap()["idTokenSignedResponseAlg"],
        "ES256"
    );
    let stored = store
        .read(EntityKind::IdentityProvider, &saved.id)
        .await
        .unwrap()
        .unwrap();
    let resolved = resolve(&stored, &p, &no_env).unwrap();
    assert_eq!(
        resolved.config.id_token_signed_response_alg.as_deref(),
        Some("ES256")
    );

    // Cleared by an update without it; a symmetric algorithm is refused.
    let v2 = admin
        .update(&store, &saved.id, input(provider("up")), 1)
        .await
        .unwrap()
        .unwrap();
    let read = admin.get(&store, &v2.id).await.unwrap().unwrap();
    assert!(
        serde_json::to_value(&read.item)
            .unwrap()
            .get("idTokenSignedResponseAlg")
            .is_none()
    );
    let mut hs = provider("up");
    hs["idTokenSignedResponseAlg"] = "HS256".into();
    let errors = admin
        .update(&store, &saved.id, input(hs), 2)
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(errors[0].code, "validation_failed", "{errors:?}");
}
