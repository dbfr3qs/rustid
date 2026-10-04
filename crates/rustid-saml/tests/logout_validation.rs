//! The logout request validator.

use std::path::Path;

use chrono::{Duration, TimeZone, Utc};
use rustid_core::session::SamlSpSession;
use rustid_saml::logout::{LogoutValidationInput, slo_redirect_endpoint, validate_logout_request};
use rustid_saml::model::{ServiceProvider, load_service_providers};
use rustid_saml::options::SamlOptions;
use rustid_saml::protocol::{LogoutRequest, NameId, TrustLevel};
use rustid_saml::sso::{STATUS_REQUESTER, STATUS_VERSION_MISMATCH};

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 2, 10, 0, 0).unwrap()
}

fn sp() -> ServiceProvider {
    load_service_providers(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/saml-service-providers.json"),
    )
    .unwrap()
    .into_iter()
    .find(|s| s.entity_id == "https://sp.example")
    .unwrap()
}

fn request() -> LogoutRequest {
    LogoutRequest {
        id: "_l".into(),
        issue_instant: now(),
        version: "2.0".into(),
        destination: Some("https://idp.test/Saml2/SLO".into()),
        issuer: Some(NameId {
            value: "https://sp.example".into(),
            format: None,
            sp_name_qualifier: None,
            name_qualifier: None,
        }),
        trust: TrustLevel::ConfiguredKey,
        name_id: Some(NameId {
            value: "alice@example.com".into(),
            format: None,
            sp_name_qualifier: None,
            name_qualifier: None,
        }),
        session_index: Some("s1".into()),
        reason: None,
        not_on_or_after: None,
    }
}

fn session(index: &str, name_id: &str) -> SamlSpSession {
    SamlSpSession {
        entity_id: "https://sp.example".into(),
        session_index: index.into(),
        name_id: name_id.into(),
        name_id_format: None,
    }
}

fn validate(
    sp: Option<&ServiceProvider>,
    r: &LogoutRequest,
    sessions: Option<&[SamlSpSession]>,
) -> Result<bool, (&'static str, String)> {
    validate_logout_request(&LogoutValidationInput {
        options: &SamlOptions::default(),
        now: now(),
        base_url: "https://idp.test",
        sp,
        request: r,
        user_saml_sessions: sessions,
    })
    .map_err(|f| (f.status, f.description))
}

#[test]
fn the_sp_signature_version_destination_and_expiry() {
    let mut r = request();
    r.issuer = None;
    assert_eq!(
        validate(Some(&sp()), &r, None).unwrap_err(),
        (
            STATUS_REQUESTER,
            "Missing SP EntityID in LogoutRequest".into()
        )
    );
    assert_eq!(
        validate(None, &request(), None).unwrap_err().1,
        "Invalid SP EntityId"
    );
    let mut no_slo = sp();
    no_slo.single_logout_service_urls.clear();
    assert_eq!(
        validate(Some(&no_slo), &request(), None).unwrap_err().1,
        "SP does not have any SingleLogoutServiceUrls configured"
    );
    let mut r = request();
    r.trust = TrustLevel::None;
    assert_eq!(
        validate(Some(&sp()), &r, None).unwrap_err().1,
        "The LogoutRequest signature is missing or not trusted"
    );
    let mut r = request();
    r.version = "1.1".into();
    assert_eq!(
        validate(Some(&sp()), &r, None).unwrap_err(),
        (
            STATUS_VERSION_MISMATCH,
            "Only Version 2.0 is supported".into()
        )
    );
    let mut r = request();
    r.destination = None;
    assert_eq!(
        validate(Some(&sp()), &r, None).unwrap_err().1,
        "Signed LogoutRequests must include a Destination"
    );
    r.destination = Some("https://IDP.test/saml2/slo".into());
    assert!(validate(Some(&sp()), &r, None).is_ok(), "case-insensitive");
    r.destination = Some("https://elsewhere/".into());
    assert_eq!(
        validate(Some(&sp()), &r, None).unwrap_err().1,
        "Invalid destination"
    );
    // NotOnOrAfter, with the SP's two minutes of skew; the boundary is valid.
    let mut r = request();
    r.not_on_or_after = Some(now() - Duration::seconds(120));
    assert!(validate(Some(&sp()), &r, None).is_ok());
    r.not_on_or_after = Some(now() - Duration::seconds(121));
    assert_eq!(
        validate(Some(&sp()), &r, None).unwrap_err().1,
        "LogoutRequest has expired (NotOnOrAfter)"
    );
}

#[test]
fn sessions() {
    // No user: valid (the endpoint answers at once).
    assert_eq!(validate(Some(&sp()), &request(), None), Ok(true));
    let mine = [session("s1", "alice@example.com")];
    assert_eq!(validate(Some(&sp()), &request(), Some(&mine)), Ok(true));
    // No session for this SP: valid, not found.
    assert_eq!(validate(Some(&sp()), &request(), Some(&[])), Ok(false));
    // Another NameID: an error.
    let other = [session("s1", "bob@example.com")];
    assert_eq!(
        validate(Some(&sp()), &request(), Some(&other))
            .unwrap_err()
            .1,
        "NameID does not match any active session"
    );
    // Another session index: not found.
    let older = [session("s0", "alice@example.com")];
    assert_eq!(validate(Some(&sp()), &request(), Some(&older)), Ok(false));
    // No session index: the NameID suffices.
    let mut r = request();
    r.session_index = None;
    assert_eq!(validate(Some(&sp()), &r, Some(&older)), Ok(true));
    // A signed-in user's request must name someone.
    let mut r = request();
    r.name_id = None;
    assert_eq!(
        validate(Some(&sp()), &r, Some(&mine)).unwrap_err().1,
        "LogoutRequest must contain a NameID"
    );
}

#[test]
fn front_channel_logout_uses_the_first_redirect_endpoint() {
    let sp = sp();
    assert_eq!(
        slo_redirect_endpoint(&sp).unwrap().location,
        "https://sp.example/slo"
    );
    let mut post_only = sp.clone();
    post_only.single_logout_service_urls[0].binding = rustid_saml::model::Binding::HttpPost;
    assert!(slo_redirect_endpoint(&post_only).is_none());
}
