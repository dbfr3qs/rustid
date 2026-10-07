//! Pairwise subject identifiers (OpenID Connect Core 1.0 §8): the sector,
//! the subject a client sees, and which clients are valid.

use rustid_core::clients::{Client, SubjectType, validate_client};
use rustid_core::options::ProtocolOptions;
use rustid_core::pairwise;
use serde_json::json;

const SALT: &str = "server-salt-0123456789";

fn options(salt: Option<&str>) -> ProtocolOptions {
    let mut options = ProtocolOptions::default();
    options.pairwise.salt = salt.map(str::to_owned);
    options
}

fn client(value: serde_json::Value) -> Client {
    let mut base = json!({
        "clientId": "rp",
        "allowedGrantTypes": ["authorization_code"],
        "redirectUris": ["https://rp.example/cb"],
        "subjectType": "pairwise",
        "requireClientSecret": false,
    });
    base.as_object_mut()
        .unwrap()
        .extend(value.as_object().unwrap().clone());
    serde_json::from_value(base).unwrap()
}

#[test]
fn the_sector_is_the_sector_uri_host_else_the_redirect_host_else_the_client() {
    assert_eq!(pairwise::sector(&client(json!({}))), "rp.example");
    assert_eq!(
        pairwise::sector(&client(
            json!({ "redirectUris": ["https://RP.Example/a", "https://rp.example/b"] })
        )),
        "rp.example"
    );
    assert_eq!(
        pairwise::sector(&client(
            json!({ "sectorIdentifierUri": "https://Sector.Example/uris.json" })
        )),
        "sector.example"
    );
    assert_eq!(
        pairwise::sector(&client(json!({ "redirectUris": [] }))),
        "rp"
    );
}

#[test]
fn the_subject_is_the_specified_hash() {
    let options = options(Some(SALT));
    assert_eq!(
        pairwise::subject_for(&options, &client(json!({})), "alice"),
        "xWPHM_bUnONzLWg2c5xFiwO9NHR9XOgz8cjipQCY9q0"
    );
    assert_eq!(
        pairwise::subject_for(
            &options,
            &client(json!({ "pairWiseSubjectSalt": "client-salt" })),
            "alice"
        ),
        "fZ544UgET2VuzLoC-xe4YQA3nGoT7XIiQXo5e5dnSxg"
    );
}

#[test]
fn clients_share_a_subject_only_within_a_sector() {
    let options = options(Some(SALT));
    let one = client(json!({ "clientId": "one" }));
    let same_sector = client(json!({ "clientId": "two" }));
    let other =
        client(json!({ "clientId": "three", "redirectUris": ["https://other.example/cb"] }));
    let a = pairwise::subject_for(&options, &one, "alice");
    assert_eq!(a, pairwise::subject_for(&options, &same_sector, "alice"));
    assert_ne!(a, pairwise::subject_for(&options, &other, "alice"));
    assert_ne!(a, pairwise::subject_for(&options, &one, "bob"));
}

#[test]
fn public_clients_and_a_server_without_salt_see_the_local_subject() {
    let public = client(json!({ "subjectType": "public" }));
    assert_eq!(public.subject_type, SubjectType::Public);
    assert_eq!(
        pairwise::subject_for(&options(Some(SALT)), &public, "alice"),
        "alice"
    );
    assert_eq!(
        pairwise::subject(&options(Some(SALT)), &public, "alice"),
        None
    );
    // The default is public.
    let default: Client = serde_json::from_value(json!({ "clientId": "d" })).unwrap();
    assert_eq!(default.subject_type, SubjectType::Public);
}

#[test]
fn a_pairwise_client_needs_one_sector() {
    assert_eq!(validate_client(&client(json!({})), false), Ok(()));
    let spread =
        client(json!({ "redirectUris": ["https://a.example/cb", "https://b.example/cb"] }));
    assert!(
        validate_client(&spread, false)
            .unwrap_err()
            .contains("sectorIdentifierUri")
    );
    let named = client(json!({
        "redirectUris": ["https://a.example/cb", "https://b.example/cb"],
        "sectorIdentifierUri": "https://a.example/uris.json",
    }));
    assert_eq!(validate_client(&named, false), Ok(()));
    let insecure = client(json!({ "sectorIdentifierUri": "http://a.example/uris.json" }));
    assert!(
        validate_client(&insecure, false)
            .unwrap_err()
            .contains("https")
    );
}

#[test]
fn the_salt_never_shows_in_debug_output() {
    let options = options(Some(SALT));
    assert!(!format!("{options:?}").contains(SALT));
}
