//! Unbinding an inbound message (`HttpRedirectBinding` and
//! `HttpPostBinding`): which binding applies, what is a base64 error (an
//! error page), what isn't handled (a 500), and redirect trust.

use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rustid_saml::bindings::{MessageName, redirect};
use rustid_saml::model::load_service_providers;
use rustid_saml::protocol::TrustLevel;
use rustid_saml::sso::{
    InboundBinding, UnbindError, redirect_trust, select_binding, signing_entity, unbind_post,
    unbind_redirect,
};
use rustid_saml::xml::dsig::Credential;

const XML: &str = r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r" Version="2.0" IssueInstant="2026-10-02T10:00:00Z"><saml:Issuer>https://sp.example</saml:Issuer></samlp:AuthnRequest>"#;

fn credential() -> Credential {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/saml/sp");
    Credential::from_pem(
        &std::fs::read_to_string(dir.join("sp-signing.cert.pem")).unwrap(),
        &std::fs::read_to_string(dir.join("sp-signing.key.pem")).unwrap(),
    )
    .unwrap()
}

fn sp(entity_id: &str) -> rustid_saml::model::ServiceProvider {
    load_service_providers(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/saml-service-providers.json"),
    )
    .unwrap()
    .into_iter()
    .find(|s| s.entity_id == entity_id)
    .unwrap()
}

const MAX: usize = 1_048_576;

#[test]
fn bindings_are_chosen_by_method_and_parameter() {
    assert_eq!(
        select_binding("GET", "SAMLRequest=x", &[]),
        Some(InboundBinding::Redirect)
    );
    assert_eq!(
        select_binding("GET", "a=1&SAMLResponse=x", &[]),
        Some(InboundBinding::Redirect)
    );
    assert_eq!(
        select_binding("GET", "samlrequest=x", &[]),
        None,
        "names are exact"
    );
    assert_eq!(select_binding("GET", "", &["SAMLRequest"]), None);
    assert_eq!(
        select_binding("POST", "", &["SAMLRequest"]),
        Some(InboundBinding::Post)
    );
    assert_eq!(select_binding("POST", "SAMLRequest=x", &[]), None);
    assert_eq!(
        select_binding("PUT", "SAMLRequest=x", &["SAMLRequest"]),
        None
    );
}

#[test]
fn redirect_messages_unbind_and_their_signatures_are_trusted_by_the_sps_keys() {
    let cred = credential();
    let signed = redirect::encode(MessageName::SamlRequest, XML, Some("rs"), Some(&cred)).unwrap();
    let inbound = unbind_redirect(&signed, MAX, 80).unwrap();
    assert_eq!(inbound.name, MessageName::SamlRequest);
    assert_eq!(inbound.relay_state.as_deref(), Some("rs"));
    assert_eq!(inbound.document().root.local, "AuthnRequest");
    let entity = signing_entity(&sp("https://sp.example"));
    assert_eq!(
        redirect_trust(&inbound, entity.as_ref()),
        TrustLevel::ConfiguredKey
    );
    assert_eq!(redirect_trust(&inbound, None), TrustLevel::None);
    // sp.example allows RSA-SHA256 only; an SP limited to SHA-512 doesn't trust it.
    let mut strict = entity.clone().unwrap();
    strict.allowed_algorithms = vec!["http://www.w3.org/2001/04/xmldsig-more#rsa-sha512".into()];
    assert_eq!(redirect_trust(&inbound, Some(&strict)), TrustLevel::None);
    // Unsigned.
    let unsigned = redirect::encode(MessageName::SamlRequest, XML, None, None).unwrap();
    let inbound = unbind_redirect(&unsigned, MAX, 80).unwrap();
    assert_eq!(redirect_trust(&inbound, entity.as_ref()), TrustLevel::None);
    // A tampered relay state breaks the signature.
    let tampered = signed.replace("RelayState=rs", "RelayState=rt");
    let inbound = unbind_redirect(&tampered, MAX, 80).unwrap();
    assert_eq!(redirect_trust(&inbound, entity.as_ref()), TrustLevel::None);
}

#[test]
fn an_sp_without_signing_certificates_has_no_entity() {
    let mut bare = sp("https://sp.example");
    bare.certificates.clear();
    assert!(signing_entity(&bare).is_none());
    let mut encryption_only = sp("https://sp.example");
    encryption_only.certificates[0].key_use = rustid_saml::model::KeyUse::Encryption;
    assert!(signing_entity(&encryption_only).is_none());
    let entity = signing_entity(&sp("https://sp.example")).unwrap();
    assert_eq!(
        entity.allowed_algorithms,
        sp("https://sp.example")
            .allowed_signature_algorithms
            .unwrap()
    );
}

#[test]
fn redirect_failures() {
    assert_eq!(
        unbind_redirect("?SAMLRequest=%%%", MAX, 80).unwrap_err(),
        UnbindError::Base64
    );
    // Valid base64 that isn't DEFLATE, incomplete signature parameters,
    // and relay state over the limit: failures that aren't handled.
    let not_deflate = format!(
        "?SAMLRequest={}",
        redirect::escape(&STANDARD.encode("plain"))
    );
    assert!(matches!(
        unbind_redirect(&not_deflate, MAX, 80),
        Err(UnbindError::Unhandled(_))
    ));
    let unsigned = redirect::encode(MessageName::SamlRequest, XML, None, None).unwrap();
    assert!(matches!(
        unbind_redirect(&format!("{unsigned}&SigAlg=x"), MAX, 80),
        Err(UnbindError::Unhandled(_))
    ));
    let long =
        redirect::encode(MessageName::SamlRequest, XML, Some(&"x".repeat(81)), None).unwrap();
    assert!(matches!(
        unbind_redirect(&long, MAX, 80),
        Err(UnbindError::Unhandled(_))
    ));
    let not_xml = redirect::encode(MessageName::SamlRequest, "not xml", None, None).unwrap();
    assert!(matches!(
        unbind_redirect(&not_xml, MAX, 80),
        Err(UnbindError::Unhandled(_))
    ));
}

#[test]
fn post_messages_unbind() {
    let encoded = STANDARD.encode(XML);
    let form = vec![
        ("SAMLRequest".to_owned(), encoded.clone()),
        ("RelayState".to_owned(), "rs".to_owned()),
    ];
    let inbound = unbind_post(&form, MAX, 80).unwrap();
    assert_eq!(inbound.name, MessageName::SamlRequest);
    assert_eq!(inbound.relay_state.as_deref(), Some("rs"));
    assert_eq!(
        unbind_post(&[("SAMLRequest".into(), "!!".into())], MAX, 80).unwrap_err(),
        UnbindError::Base64
    );
    for form in [
        vec![
            ("SAMLRequest".into(), encoded.clone()),
            ("SAMLResponse".into(), encoded.clone()),
        ],
        vec![
            ("SAMLRequest".into(), encoded.clone()),
            ("SAMLRequest".into(), encoded.clone()),
        ],
        vec![("SAMLRequest".into(), STANDARD.encode("not xml"))],
        vec![
            ("SAMLRequest".into(), encoded.clone()),
            ("RelayState".into(), "x".repeat(81)),
        ],
        vec![("SAMLRequest".into(), "A".repeat(20))],
    ] {
        assert!(
            matches!(unbind_post(&form, 10, 80), Err(UnbindError::Unhandled(_))),
            "{form:?}"
        );
    }
}
