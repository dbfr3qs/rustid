//! The authn request validator, `DefaultSamlResourceResolver` and
//! the decision.

use std::path::Path;

use chrono::{DateTime, Duration, TimeZone, Utc};
use rustid_core::resources::IdentityResource;
use rustid_saml::constants::{BINDING_POST, BINDING_REDIRECT};
use rustid_saml::model::{Binding, IndexedEndpoint, ServiceProvider, load_service_providers};
use rustid_saml::options::SamlOptions;
use rustid_saml::protocol::{AuthnRequest, NameId, NameIdPolicy, Scoping, TrustLevel};
use rustid_saml::sso::{
    Interaction, STATUS_REQUESTER, STATUS_RESPONDER, STATUS_VERSION_MISMATCH, Validation,
    interaction, validate_authn_request,
};

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 2, 10, 0, 0).unwrap()
}

fn sps() -> Vec<ServiceProvider> {
    load_service_providers(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/saml-service-providers.json"),
    )
    .unwrap()
}

/// sp.example without its signing requirement, so most checks can run
/// unsigned.
fn sp() -> ServiceProvider {
    let mut sp = sps()
        .into_iter()
        .find(|s| s.entity_id == "https://sp.example")
        .unwrap();
    sp.require_signed_authn_requests = Some(false);
    sp
}

fn request() -> AuthnRequest {
    AuthnRequest {
        id: "_r".into(),
        issue_instant: now(),
        version: "2.0".into(),
        destination: None,
        consent: None,
        issuer: Some(NameId {
            value: "https://sp.example".into(),
            format: None,
            sp_name_qualifier: None,
            name_qualifier: None,
        }),
        trust: TrustLevel::None,
        subject_name_id: None,
        name_id_policy: None,
        requested_authn_context: None,
        scoping: None,
        force_authn: false,
        is_passive: false,
        acs_index: None,
        acs_url: None,
        protocol_binding: None,
        attribute_consuming_service_index: None,
        provider_name: None,
    }
}

fn identity_resources() -> Vec<IdentityResource> {
    let resource = |name: &str, claims: &[&str]| IdentityResource {
        name: name.into(),
        display_name: None,
        description: None,
        enabled: true,
        required: false,
        emphasize: false,
        show_in_discovery_document: true,
        user_claims: claims.iter().map(|c| (*c).to_owned()).collect(),
        properties: Default::default(),
    };
    vec![
        resource("openid", &["sub"]),
        resource("profile", &["name", "family_name", "preferred_username"]),
        resource("email", &["email", "email_verified"]),
    ]
}

fn validate(sp: Option<&ServiceProvider>, request: &AuthnRequest) -> Validation {
    validate_authn_request(&rustid_saml::sso::ValidationInput {
        options: &SamlOptions::default(),
        now: now(),
        base_url: "https://idp.test",
        sp,
        request,
        enabled_identity_resources: &identity_resources(),
    })
}

fn failure(sp: Option<&ServiceProvider>, request: &AuthnRequest) -> (&'static str, String) {
    match validate(sp, request) {
        Err(f) => (f.status, f.description),
        Ok(v) => panic!("expected a failure, got {v:?}"),
    }
}

#[test]
fn a_valid_request_resolves_the_default_acs_and_claim_types() {
    let v = validate(Some(&sp()), &request()).unwrap();
    assert_eq!(v.acs.location, "https://sp.example/acs");
    assert_eq!(v.requested_claim_types, ["name", "preferred_username"]);
    let mut all = sp();
    all.requested_claim_types.clear();
    let v = validate(Some(&all), &request()).unwrap();
    assert_eq!(
        v.requested_claim_types,
        ["sub", "name", "family_name", "preferred_username"]
    );
}

#[test]
fn the_sp_checks() {
    let mut r = request();
    r.issuer = None;
    assert_eq!(
        failure(Some(&sp()), &r),
        (
            STATUS_REQUESTER,
            "Missing SP EntityID in AuthnRequest".into()
        )
    );
    assert_eq!(
        failure(None, &request()),
        (STATUS_REQUESTER, "Invalid SP EntityId.".into())
    );
    let mut disabled = sp();
    disabled.enabled = false;
    assert_eq!(
        failure(Some(&disabled), &request()).1,
        "Invalid SP EntityId."
    );
    let mut no_acs = sp();
    no_acs.assertion_consumer_service_urls.clear();
    assert_eq!(
        failure(Some(&no_acs), &request()),
        (
            STATUS_RESPONDER,
            "No Assertion Consumer Service URLs found.".into()
        )
    );
}

#[test]
fn signatures_are_required_by_the_sp_or_the_options() {
    let mut signed = sp();
    signed.require_signed_authn_requests = Some(true);
    assert_eq!(
        failure(Some(&signed), &request()),
        (
            STATUS_REQUESTER,
            "The AuthnRequest signature is missing or not trusted".into()
        )
    );
    let mut default = sp();
    default.require_signed_authn_requests = None; // want_authn_requests_signed: true
    assert_eq!(
        failure(Some(&default), &request()).1,
        "The AuthnRequest signature is missing or not trusted"
    );
    let mut trusted = request();
    trusted.trust = TrustLevel::ConfiguredKey;
    trusted.destination = Some("https://idp.test/Saml2/SSO".into());
    assert!(validate(Some(&signed), &trusted).is_ok());
    // Checked before the version.
    trusted.trust = TrustLevel::None;
    trusted.version = "1.1".into();
    assert_eq!(
        failure(Some(&signed), &trusted).1,
        "The AuthnRequest signature is missing or not trusted"
    );
}

#[test]
fn version_and_instants() {
    let mut r = request();
    r.version = "1.1".into();
    assert_eq!(
        failure(Some(&sp()), &r),
        (
            STATUS_VERSION_MISMATCH,
            "Only Version 2.0 is supported".into()
        )
    );
    // sp.example: clock skew 2 minutes, max age 10 minutes; boundaries are valid.
    let at = |offset: i64| {
        let mut r = request();
        r.issue_instant = now() + Duration::seconds(offset);
        validate(Some(&sp()), &r)
    };
    assert!(at(120).is_ok());
    assert_eq!(
        at(121).unwrap_err().description,
        "Request IssueInstant is in the future"
    );
    assert!(at(-600).is_ok());
    assert_eq!(
        at(-601).unwrap_err().description,
        "Request has expired (IssueInstant too old)"
    );
    // The defaults (5 minutes each) when the SP sets none.
    let mut plain = sp();
    plain.clock_skew = None;
    plain.request_max_age = None;
    let mut r = request();
    r.issue_instant = now() + Duration::seconds(301);
    assert_eq!(
        failure(Some(&plain), &r).1,
        "Request IssueInstant is in the future"
    );
    r.issue_instant = now() - Duration::seconds(300);
    assert!(validate(Some(&plain), &r).is_ok());
}

#[test]
fn destinations() {
    let mut r = request();
    r.destination = Some("https://IDP.test/saml2/sso".into());
    assert!(validate(Some(&sp()), &r).is_ok(), "case-insensitive");
    r.destination = Some("https://idp.test/other".into());
    assert_eq!(
        failure(Some(&sp()), &r),
        (STATUS_REQUESTER, "Invalid destination".into())
    );
    r.destination = None;
    r.trust = TrustLevel::ConfiguredKey;
    assert_eq!(
        failure(Some(&sp()), &r).1,
        "Signed AuthnRequests must include a Destination"
    );
    r.destination = Some(String::new());
    assert_eq!(
        failure(Some(&sp()), &r).1,
        "Signed AuthnRequests must include a Destination"
    );
}

#[test]
fn acs_resolution() {
    let mut r = request();
    r.acs_url = Some("https://sp.example/acs2".into());
    assert_eq!(validate(Some(&sp()), &r).unwrap().acs.index, 1);
    r.acs_index = Some(0);
    assert_eq!(
        failure(Some(&sp()), &r).1,
        "Both ACS Url and Index were provided in the request"
    );
    r.acs_index = None;
    r.acs_url = Some("/relative".into());
    assert_eq!(
        failure(Some(&sp()), &r).1,
        "AssertionConsumerServiceUrl is not a valid absolute URI"
    );
    r.acs_url = Some("https://evil.example/acs".into());
    assert_eq!(
        failure(Some(&sp()), &r).1,
        "AssertionConsumerServiceUrl is not registered for this Service Provider"
    );
    // AbsoluteUri normalizes the scheme and host.
    r.acs_url = Some("HTTPS://SP.EXAMPLE/acs2".into());
    assert_eq!(validate(Some(&sp()), &r).unwrap().acs.index, 1);
    r.acs_url = None;
    r.acs_index = Some(7);
    assert_eq!(
        failure(Some(&sp()), &r).1,
        "No AssertionConsumerServiceUrl registered for this Service Provider with the provided index"
    );
    r.acs_index = Some(1);
    assert_eq!(
        validate(Some(&sp()), &r).unwrap().acs.location,
        "https://sp.example/acs2"
    );
    // Same location, two bindings: ProtocolBinding picks, else the default.
    let mut two = sp();
    two.assertion_consumer_service_urls = vec![
        IndexedEndpoint {
            location: "https://sp.example/acs".into(),
            binding: Binding::HttpRedirect,
            index: 0,
            is_default: false,
        },
        IndexedEndpoint {
            location: "https://sp.example/acs".into(),
            binding: Binding::HttpPost,
            index: 1,
            is_default: true,
        },
    ];
    let mut r = request();
    r.acs_url = Some("https://sp.example/acs".into());
    assert_eq!(validate(Some(&two), &r).unwrap().acs.index, 1);
    r.protocol_binding = Some(BINDING_REDIRECT.into());
    assert_eq!(validate(Some(&two), &r).unwrap().acs.index, 0);
    r.protocol_binding = Some(BINDING_POST.into());
    assert_eq!(validate(Some(&two), &r).unwrap().acs.index, 1);
    // No default: the first.
    two.assertion_consumer_service_urls[1].is_default = false;
    assert_eq!(validate(Some(&two), &request()).unwrap().acs.index, 0);
}

#[test]
fn name_id_formats_and_scoping() {
    let mut r = request();
    r.name_id_policy = Some(NameIdPolicy {
        format: Some("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent".into()),
        sp_name_qualifier: None,
        allow_create: None,
    });
    assert_eq!(
        failure(Some(&sp()), &r).1,
        "Requested NameID format 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent' is not supported by this IdP"
    );
    r.name_id_policy.as_mut().unwrap().format = None;
    assert!(
        validate(Some(&sp()), &r).is_ok(),
        "the SP default (email) is supported"
    );
    let mut r = request();
    r.scoping = Some(Scoping::default());
    assert_eq!(failure(Some(&sp()), &r).1, "Scoping is not supported");
}

#[test]
fn resources() {
    for change in [
        |sp: &mut ServiceProvider| sp.allowed_scopes.clear(),
        |sp: &mut ServiceProvider| sp.allowed_scopes.push("api1".into()),
        |sp: &mut ServiceProvider| sp.requested_claim_types.push("phone".into()),
    ] {
        let mut bad = sp();
        change(&mut bad);
        assert_eq!(
            failure(Some(&bad), &request()),
            (
                STATUS_RESPONDER,
                "Service provider configuration error".into()
            )
        );
    }
}

#[test]
fn the_interaction_decision() {
    assert_eq!(interaction(false, false, false), Interaction::Login);
    assert_eq!(
        interaction(false, false, true),
        Interaction::NoPassive("Cannot passively authenticate user")
    );
    assert_eq!(interaction(true, false, false), Interaction::Respond);
    assert_eq!(interaction(true, false, true), Interaction::Respond);
    assert_eq!(interaction(true, true, false), Interaction::Login);
    assert_eq!(
        interaction(true, true, true),
        Interaction::NoPassive("Cannot passively authenticate user when force auth is required")
    );
}
