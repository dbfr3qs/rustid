//! Pairwise clients through the admin service: only on a server with a
//! pairwise salt, and their subject settings round-trip.

use rustid_core::admin::clients::{ClientAdmin, ClientInput};
use rustid_core::admin::secrets::CreateSecret;
use rustid_core::clients::{Client, SubjectType};
use rustid_store_memory::InMemoryConfiguration;

fn pairwise() -> ClientInput {
    ClientInput {
        client: Client {
            client_id: "pw".into(),
            allowed_grant_types: vec!["authorization_code".into()],
            redirect_uris: vec!["https://a.example/cb".into(), "https://b.example/cb".into()],
            subject_type: SubjectType::Pairwise,
            sector_identifier_uri: Some("https://a.example/uris.json".into()),
            ..Default::default()
        },
        client_secrets: vec![CreateSecret {
            plaintext_value: "s3cret".into(),
            hash_algorithm: None,
            description: None,
            expiration: None,
            secret_type: None,
        }],
        ..Default::default()
    }
}

#[tokio::test]
async fn pairwise_clients_need_a_pairwise_salt_and_round_trip() {
    let store = InMemoryConfiguration::default();
    let without = ClientAdmin::default();
    let errors = without
        .create(&store, pairwise())
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(errors[0].code, "validation_failed", "{errors:?}");
    assert!(errors[0].message.contains("pairwise"), "{errors:?}");

    let with = ClientAdmin {
        pairwise_supported: true,
        ..Default::default()
    };
    let saved = with.create(&store, pairwise()).await.unwrap().unwrap();
    let read = with.get(&store, &saved.id).await.unwrap().unwrap();
    let json = serde_json::to_value(&read.item).unwrap();
    assert_eq!(json["subjectType"], "pairwise");
    assert_eq!(json["sectorIdentifierUri"], "https://a.example/uris.json");
}

#[tokio::test]
async fn the_userinfo_signing_algorithm_round_trips() {
    let store = InMemoryConfiguration::default();
    let admin = ClientAdmin::default();
    let mut input = pairwise();
    input.client.subject_type = SubjectType::Public;
    input.client.sector_identifier_uri = None;
    input.client.redirect_uris = vec!["https://a.example/cb".into()];
    input.client.userinfo_signed_response_alg = Some("PS256".into());
    let saved = admin.create(&store, input).await.unwrap().unwrap();
    let read = admin.get(&store, &saved.id).await.unwrap().unwrap();
    assert_eq!(
        serde_json::to_value(&read.item).unwrap()["userinfoSignedResponseAlg"],
        "PS256"
    );
}
