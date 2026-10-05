//! LogoutRequest and LogoutResponse: read,
//! written, and redirect-signed.

use chrono::{TimeZone, Utc};
use rustid_saml::bindings::{MessageName, redirect};
use rustid_saml::logout::{
    LogoutRequestOut, LogoutResponseOut, write_logout_request, write_logout_response,
};
use rustid_saml::protocol::{ReadError, TrustLevel, read_logout_request, read_logout_response};
use rustid_saml::response::Status;
use rustid_saml::xml::dom::{Limits, parse};

const P: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const A: &str = "urn:oasis:names:tc:SAML:2.0:assertion";

fn limits() -> Limits {
    Limits {
        ignore_processing_instructions: true,
        ..Limits::default()
    }
}

#[test]
fn logout_requests_are_read() {
    let xml = format!(
        r#"<samlp:LogoutRequest xmlns:samlp="{P}" xmlns:saml="{A}" ID="_l1" Version="2.0" IssueInstant="2026-10-02T10:00:00Z" Destination="https://idp/Saml2/SLO" Reason="urn:oasis:names:tc:SAML:2.0:logout:user"><saml:Issuer>https://sp.example</saml:Issuer><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@example.com</saml:NameID><samlp:SessionIndex>abc</samlp:SessionIndex></samlp:LogoutRequest>"#
    );
    let r = read_logout_request(&parse(&xml, &limits()).unwrap(), TrustLevel::None, None).unwrap();
    assert_eq!(r.id, "_l1");
    assert_eq!(r.issuer.unwrap().value, "https://sp.example");
    let name_id = r.name_id.unwrap();
    assert_eq!(name_id.value, "alice@example.com");
    assert_eq!(r.session_index.as_deref(), Some("abc"));
    assert_eq!(r.destination.as_deref(), Some("https://idp/Saml2/SLO"));
    // A missing NameID isn't a reading error (the name check at the end of
    // the children adds none); the validator refuses it.
    let missing = format!(
        r#"<samlp:LogoutRequest xmlns:samlp="{P}" xmlns:saml="{A}" ID="_l1" Version="2.0" IssueInstant="2026-10-02T10:00:00Z"><saml:Issuer>x</saml:Issuer></samlp:LogoutRequest>"#
    );
    let r =
        read_logout_request(&parse(&missing, &limits()).unwrap(), TrustLevel::None, None).unwrap();
    assert!(r.name_id.is_none());
    // Another element where the NameID belongs is.
    let other = format!(
        r#"<samlp:LogoutRequest xmlns:samlp="{P}" xmlns:saml="{A}" ID="_l1" Version="2.0" IssueInstant="2026-10-02T10:00:00Z"><saml:Issuer>x</saml:Issuer><samlp:SessionIndex>s</samlp:SessionIndex></samlp:LogoutRequest>"#
    );
    assert!(matches!(
        read_logout_request(&parse(&other, &limits()).unwrap(), TrustLevel::None, None),
        Err(ReadError::Invalid(_))
    ));
    // A different root: an InvalidOperationException (which the SLO
    // endpoint catches), not a parse error.
    let wrong = format!(
        r#"<samlp:AuthnRequest xmlns:samlp="{P}" ID="_x" Version="2.0" IssueInstant="2026-10-02T10:00:00Z"/>"#
    );
    match read_logout_request(&parse(&wrong, &limits()).unwrap(), TrustLevel::None, None) {
        Err(ReadError::Unhandled(detail)) => {
            assert!(detail.starts_with("InvalidOperationException"), "{detail}")
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn logout_responses_are_read() {
    let xml = format!(
        r#"<samlp:LogoutResponse xmlns:samlp="{P}" xmlns:saml="{A}" ID="_r1" Version="2.0" IssueInstant="2026-10-02T10:00:00Z" InResponseTo="_l1"><saml:Issuer>https://sp.example</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:PartialLogout"/></samlp:StatusCode><samlp:StatusMessage>m</samlp:StatusMessage></samlp:Status></samlp:LogoutResponse>"#
    );
    let r = read_logout_response(&parse(&xml, &limits()).unwrap(), TrustLevel::None, None).unwrap();
    assert_eq!(r.in_response_to.as_deref(), Some("_l1"));
    assert_eq!(r.issuer.unwrap().value, "https://sp.example");
    assert_eq!(
        r.status_code.as_deref(),
        Some("urn:oasis:names:tc:SAML:2.0:status:Success")
    );
    assert_eq!(
        r.nested_status_code.as_deref(),
        Some("urn:oasis:names:tc:SAML:2.0:status:PartialLogout")
    );
    // Status is required.
    let no_status = format!(
        r#"<samlp:LogoutResponse xmlns:samlp="{P}" xmlns:saml="{A}" ID="_r1" Version="2.0" IssueInstant="2026-10-02T10:00:00Z"><saml:Issuer>x</saml:Issuer></samlp:LogoutResponse>"#
    );
    assert!(
        read_logout_response(
            &parse(&no_status, &limits()).unwrap(),
            TrustLevel::None,
            None
        )
        .is_err()
    );
}

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 2, 10, 0, 0).unwrap()
}

#[test]
fn logout_messages_are_written_exactly() {
    let request = LogoutRequestOut {
        id: "_l".into(),
        issue_instant: now(),
        destination: "https://sp.example/slo".into(),
        issuer: "https://idp/Saml2".into(),
        name_id: "alice@example.com".into(),
        name_id_format: Some("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".into()),
        session_index: "abc".into(),
    };
    assert_eq!(
        write_logout_request(&request),
        concat!(
            r#"<samlp:LogoutRequest ID="_l" IssueInstant="2026-10-02T10:00:00Z" Version="2.0" Destination="https://sp.example/slo" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">"#,
            r#"<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://idp/Saml2</saml:Issuer>"#,
            r#"<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">alice@example.com</saml:NameID>"#,
            r#"<samlp:SessionIndex>abc</samlp:SessionIndex></samlp:LogoutRequest>"#
        )
    );
    let response = LogoutResponseOut {
        id: "_r".into(),
        issue_instant: now(),
        destination: "https://sp.example/slo".into(),
        in_response_to: Some("_l".into()),
        issuer: "https://idp/Saml2".into(),
        status: Status::nested(
            "urn:oasis:names:tc:SAML:2.0:status:Success",
            "urn:oasis:names:tc:SAML:2.0:status:PartialLogout",
        ),
    };
    assert_eq!(
        write_logout_response(&response),
        concat!(
            r#"<samlp:LogoutResponse ID="_r" Version="2.0" IssueInstant="2026-10-02T10:00:00Z" Destination="https://sp.example/slo" InResponseTo="_l" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">"#,
            r#"<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://idp/Saml2</saml:Issuer>"#,
            r#"<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:PartialLogout" /></samlp:StatusCode></samlp:Status>"#,
            r#"</samlp:LogoutResponse>"#
        )
    );
}

#[test]
fn redirect_encoding_signs_with_any_xml_signer() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/saml/idp");
    let credential = rustid_saml::xml::dsig::Credential::from_pem(
        &std::fs::read_to_string(dir.join("idp-rsa.cert.pem")).unwrap(),
        &std::fs::read_to_string(dir.join("idp-rsa.key.pem")).unwrap(),
    )
    .unwrap();
    let signer: &dyn rustid_saml::xml::dsig::XmlSigner = &credential;
    let query =
        redirect::encode(MessageName::SamlResponse, "<x/>", Some("rs"), Some(signer)).unwrap();
    let parsed = redirect::parse_parameters(&query).unwrap();
    assert!(redirect::verify_signature(
        &parsed,
        &[credential.certificate().to_vec()],
        rustid_saml::xml::dsig::DEFAULT_ALLOWED
    ));
}
