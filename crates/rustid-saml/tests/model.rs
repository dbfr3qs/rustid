//! The SAML service provider model, its
//! configuration validator, and the SAML options.

use std::path::{Path, PathBuf};

use rustid_saml::model::{
    Binding, KeyUse, ServiceProvider, SigningBehavior, load_service_providers,
    parse_service_providers,
};
use rustid_saml::options::SamlOptions;
use rustid_saml::validation::validate_service_provider;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/saml-service-providers.json")
}

#[test]
fn the_fixture_file_loads_every_field() {
    let sps = load_service_providers(&fixture()).unwrap();
    assert_eq!(sps.len(), 14);
    let sp = &sps[0];
    assert_eq!(sp.entity_id, "https://sp.example");
    assert!(sp.enabled);
    assert_eq!(sp.clock_skew.map(|t| t.0), Some(120));
    assert_eq!(sp.request_max_age.map(|t| t.0), Some(600));
    assert_eq!(sp.assertion_consumer_service_urls.len(), 2);
    let acs = &sp.assertion_consumer_service_urls[0];
    assert_eq!(
        (
            acs.location.as_str(),
            acs.binding,
            acs.index,
            acs.is_default
        ),
        ("https://sp.example/acs", Binding::HttpPost, 0, true)
    );
    assert!(!sp.assertion_consumer_service_urls[1].is_default);
    assert_eq!(
        sp.single_logout_service_urls[0].binding,
        Binding::HttpRedirect
    );
    assert_eq!(sp.require_signed_authn_requests, Some(true));
    assert_eq!(sp.certificates.len(), 1);
    assert_eq!(sp.certificates[0].key_use, KeyUse::Signing);
    let pem_der = pem::parse(
        std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../fixtures/saml/sp/sp-signing.cert.pem"),
        )
        .unwrap(),
    )
    .unwrap()
    .into_contents();
    assert_eq!(sp.certificates[0].der, pem_der, "PEM certificates decode");
    assert_eq!(
        sps[1].certificates[0].der, pem_der,
        "base64 DER certificates decode"
    );
    assert_eq!(sp.signing_behavior, Some(SigningBehavior::SignBoth));
    assert_eq!(
        sps[1].signing_behavior,
        Some(SigningBehavior::SignAssertion),
        "flag numbers"
    );
    assert!(sps[1].allow_idp_initiated && !sp.allow_idp_initiated);
    assert_eq!(
        sp.claim_mappings.get("department").map(String::as_str),
        Some("urn:example:department")
    );
    assert_eq!(sp.requested_claim_types, ["name", "preferred_username"]);
    assert!(!sps[2].enabled);
    // The name ID format defaults to `unspecified`; an
    // explicit null clears it.
    assert_eq!(
        sps[1].default_name_id_format.as_deref(),
        Some("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified")
    );
    let cleared =
        parse_service_providers(r#"[{"entityId":"n","defaultNameIdFormat":null}]"#).unwrap();
    assert_eq!(cleared[0].default_name_id_format, None);
    // Serialization round-trips (the stored form, and admin's).
    let json = serde_json::to_value(sp).unwrap();
    let back: ServiceProvider = serde_json::from_value(json).unwrap();
    assert_eq!(&back, sp);
}

#[test]
fn malformed_service_providers_are_refused_with_their_entity_id() {
    let err = parse_service_providers(r#"[{"entityId":"a","assertionConsumerServiceUrls":[],"allowedScopes":[]},{"entityId":"a"}]"#)
        .unwrap_err()
        .to_string();
    assert!(err.contains("duplicate entity IDs"), "{err}");
    let err = parse_service_providers(r#"[{"entityId":"https://bad.example","certificates":[{"certificate":"not a certificate"}]}]"#)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("https://bad.example") && err.contains("certificate"),
        "{err}"
    );
    let err = parse_service_providers(r#"[{"entityId":"https://pem.example","certificates":[{"certificate":"-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----"}]}]"#)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("https://pem.example") && err.contains("certificate"),
        "malformed PEM: {err}"
    );
    let key = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/saml/sp/sp-signing.key.pem"),
    )
    .unwrap();
    let json = serde_json::json!([{"entityId": "https://key.example", "certificates": [{"certificate": key}]}]);
    let err = parse_service_providers(&json.to_string())
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("https://key.example") && err.contains("X.509"),
        "a PEM private key isn't a certificate: {err}"
    );
    let err = parse_service_providers(r#"[{"entityId":"x","signingBehavior":"Sometimes"}]"#)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("signingBehavior") || err.contains("Sometimes"),
        "{err}"
    );
}

#[test]
fn the_validator_checks_in_order() {
    let valid = || load_service_providers(&fixture()).unwrap().remove(0);
    assert_eq!(validate_service_provider(&valid()), Ok(()));
    type Change = Box<dyn Fn(&mut ServiceProvider)>;
    let cases: Vec<(Change, &str)> = vec![
        (
            Box::new(|sp| sp.entity_id = " ".into()),
            "EntityId is required",
        ),
        (
            Box::new(|sp| sp.assertion_consumer_service_urls.clear()),
            "at least one Assertion Consumer Service URL is required",
        ),
        (
            Box::new(|sp| sp.assertion_consumer_service_urls[1].binding = Binding::HttpRedirect),
            "Assertion Consumer Service at index 1 uses an unsupported binding 'HttpRedirect'. Only HTTP-POST is supported for SAML Response delivery.",
        ),
        (
            Box::new(|sp| sp.allowed_scopes.clear()),
            "at least one allowed scope is required",
        ),
        (
            Box::new(|sp| sp.assertion_lifetime = Some(rustid_core::options::TimeSpan(0))),
            "AssertionLifetime must be positive",
        ),
        (
            Box::new(|sp| sp.clock_skew = Some(rustid_core::options::TimeSpan(-1))),
            "ClockSkew must be non-negative",
        ),
        (
            Box::new(|sp| sp.request_max_age = Some(rustid_core::options::TimeSpan(0))),
            "RequestMaxAge must be positive",
        ),
    ];
    for (change, message) in cases {
        let mut sp = valid();
        change(&mut sp);
        assert_eq!(validate_service_provider(&sp), Err(message.to_owned()));
    }
    let mut sp = valid();
    sp.clock_skew = Some(rustid_core::options::TimeSpan(0));
    assert_eq!(
        validate_service_provider(&sp),
        Ok(()),
        "zero clock skew is allowed"
    );
}

#[test]
fn options_have_their_defaults_and_read_snake_case() {
    let o = SamlOptions::default();
    assert_eq!(o.entity_id, None);
    assert_eq!(o.entity_id_path, "/Saml2");
    assert!(o.want_authn_requests_signed && o.require_signed_logout_responses);
    assert_eq!(
        o.default_claim_mappings.get("email").map(String::as_str),
        Some("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress")
    );
    assert_eq!(
        o.default_authn_context_mappings
            .get("pwd")
            .map(String::as_str),
        Some("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")
    );
    assert_eq!(
        o.supported_name_id_formats,
        [
            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
        ]
    );
    assert_eq!(o.email_name_id_claim_type, "email");
    assert_eq!(
        (
            o.default_clock_skew.0,
            o.default_request_max_age.0,
            o.default_assertion_lifetime.0
        ),
        (300, 300, 300)
    );
    assert_eq!(
        (o.signin_state_lifetime.0, o.logout_session_lifetime.0),
        (900, 300)
    );
    assert_eq!(o.default_signing_behavior, SigningBehavior::SignAssertion);
    assert_eq!(
        (o.max_relay_state_length, o.max_message_size),
        (80, 1_048_576)
    );
    assert_eq!(o.endpoints.single_sign_on_service_path, "/Saml2/SSO");
    assert_eq!(
        o.endpoints.single_sign_on_callback_path,
        "/Saml2/SSO/Callback"
    );
    assert_eq!(o.endpoints.single_logout_service_path, "/Saml2/SLO");
    assert_eq!(
        o.endpoints.single_logout_callback_path,
        "/Saml2/SLO/Callback"
    );
    assert_eq!(o.endpoints.state_id_parameter_name, "samlStateId");
    assert_eq!(o.endpoints.single_sign_on_service_bindings.len(), 2);
    assert_eq!(
        (o.metadata.cache_duration.0, o.metadata.expiry_duration.0),
        (43_200, 432_000)
    );
    let custom: SamlOptions = serde_json::from_value(serde_json::json!({
        "entity_id": "urn:idp",
        "want_authn_requests_signed": false,
        "default_signing_behavior": "SignBoth",
        "endpoints": { "single_sign_on_service_path": "/custom/sso" },
        "metadata": { "cache_duration": "01:00:00" },
    }))
    .unwrap();
    assert_eq!(custom.entity_id.as_deref(), Some("urn:idp"));
    assert!(!custom.want_authn_requests_signed);
    assert_eq!(custom.default_signing_behavior, SigningBehavior::SignBoth);
    assert_eq!(custom.endpoints.single_sign_on_service_path, "/custom/sso");
    assert_eq!(
        custom.endpoints.single_logout_service_path, "/Saml2/SLO",
        "the rest default"
    );
    assert_eq!(custom.metadata.cache_duration.0, 3600);
}
