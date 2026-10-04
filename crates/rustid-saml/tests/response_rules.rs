//! The saml name id generator, claim-to-attribute mapping and the authn
//! context class.

use std::path::Path;

use rustid_saml::constants::{NAME_ID_EMAIL, NAME_ID_PERSISTENT, NAME_ID_UNSPECIFIED};
use rustid_saml::model::{ServiceProvider, load_service_providers};
use rustid_saml::options::SamlOptions;
use rustid_saml::response::{
    authn_context_class, generate_name_id, map_attributes, name_id_format,
};

fn sp(id: &str) -> ServiceProvider {
    load_service_providers(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/saml-service-providers.json"),
    )
    .unwrap()
    .into_iter()
    .find(|s| s.entity_id == id)
    .unwrap()
}

fn claims(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(t, v)| ((*t).into(), (*v).into()))
        .collect()
}

#[test]
fn the_name_id_format_comes_from_the_request_the_sp_or_unspecified() {
    let signed = sp("https://sp.example"); // default: email
    assert_eq!(
        name_id_format(Some(NAME_ID_PERSISTENT), &signed),
        NAME_ID_PERSISTENT
    );
    assert_eq!(name_id_format(None, &signed), NAME_ID_EMAIL);
    let mut none = signed.clone();
    none.default_name_id_format = None;
    assert_eq!(name_id_format(None, &none), NAME_ID_UNSPECIFIED);
}

#[test]
fn name_ids() {
    let options = SamlOptions::default();
    let sp = sp("https://sp.example");
    let user = claims(&[
        ("sub", "818727"),
        ("email", "alice@example.com"),
        ("mail", "a@corp"),
    ]);
    let email = generate_name_id(NAME_ID_EMAIL, &sp, &options, &user).unwrap();
    assert_eq!(
        (email.value.as_str(), email.format.as_deref()),
        ("alice@example.com", Some(NAME_ID_EMAIL))
    );
    let mut custom = sp.clone();
    custom.email_name_id_claim_type = Some("mail".into());
    assert_eq!(
        generate_name_id(NAME_ID_EMAIL, &custom, &options, &user)
            .unwrap()
            .value,
        "a@corp"
    );
    assert_eq!(
        generate_name_id(
            NAME_ID_EMAIL,
            &sp,
            &options,
            &claims(&[("sub", "1"), ("email", " ")])
        )
        .unwrap_err(),
        "Email claim is required for email NameID format but was not found."
    );
    // Any other format is the subject id, with the format named.
    let other = generate_name_id(NAME_ID_PERSISTENT, &sp, &options, &user).unwrap();
    assert_eq!(
        (other.value.as_str(), other.format.as_deref()),
        ("818727", Some(NAME_ID_PERSISTENT))
    );
    assert_eq!(
        generate_name_id(
            NAME_ID_UNSPECIFIED,
            &sp,
            &options,
            &claims(&[("email", "x")])
        )
        .unwrap_err(),
        "Subject identifier (sub) claim is missing or empty."
    );
}

#[test]
fn attributes_map_claim_types_and_merge_values() {
    let options = SamlOptions::default();
    let issued = claims(&[
        ("name", "Alice"),
        ("department", "eng"),
        ("department", "ops"),
        ("email", "alice@example.com"),
    ]);
    // sp.example maps department; its own mappings replace the defaults.
    assert_eq!(
        map_attributes(&issued, &sp("https://sp.example"), &options),
        [
            ("name".to_owned(), vec!["Alice".to_owned()]),
            (
                "urn:example:department".to_owned(),
                vec!["eng".to_owned(), "ops".to_owned()]
            ),
            ("email".to_owned(), vec!["alice@example.com".to_owned()]),
        ]
    );
    // Without its own mappings the defaults apply.
    assert_eq!(
        map_attributes(&issued[..1], &sp("https://unsigned.example"), &options),
        [(
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name".to_owned(),
            vec!["Alice".to_owned()]
        )]
    );
}

#[test]
fn the_authn_context_class_maps_acr_then_amr() {
    let options = SamlOptions::default();
    let plain = sp("https://unsigned.example"); // default mappings: pwd, external
    let unspecified = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified";
    let password = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
    assert_eq!(
        authn_context_class(None, &[], &plain, &options),
        unspecified
    );
    assert_eq!(
        authn_context_class(None, &["mfa".into(), "pwd".into()], &plain, &options),
        password
    );
    assert_eq!(
        authn_context_class(Some("pwd"), &[], &plain, &options),
        password
    );
    assert_eq!(
        authn_context_class(Some("nope"), &["external".into()], &plain, &options),
        unspecified
    );
    // sp.example's own mappings replace the defaults.
    let signed = sp("https://sp.example");
    assert_eq!(
        authn_context_class(None, &["pwd".into()], &signed, &options),
        unspecified
    );
    assert_eq!(
        authn_context_class(None, &["mfa".into()], &signed, &options),
        "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract"
    );
}
