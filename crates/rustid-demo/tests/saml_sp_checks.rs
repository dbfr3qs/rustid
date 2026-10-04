//! The demo SP's checks on a SAML response: signatures against the IdP's
//! metadata certificates, the request it answers, destination, audience
//! and expiry.

use std::path::Path;

use chrono::{Duration, TimeZone, Utc};
use rustid_demo::saml_sp::{Expect, check_response, metadata_certificates};
use rustid_saml::response::{
    Assertion, AuthnStatement, Response, Status, SubjectNameId, sign_response, write_response,
};
use rustid_saml::xml::dsig::Credential;

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 2, 10, 0, 0).unwrap()
}

fn idp() -> Credential {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/saml/idp");
    Credential::from_pem(
        &std::fs::read_to_string(dir.join("idp-rsa.cert.pem")).unwrap(),
        &std::fs::read_to_string(dir.join("idp-rsa.key.pem")).unwrap(),
    )
    .unwrap()
}

const ACS: &str = "http://localhost:5002/saml/acs";
const SP: &str = "http://localhost:5002/saml";

fn response() -> Response {
    Response {
        id: "_resp".into(),
        issue_instant: now(),
        destination: Some(ACS.into()),
        in_response_to: Some("_req".into()),
        issuer: "https://idp/Saml2".into(),
        status: Status::success(),
        assertion: Some(Assertion {
            id: "_a".into(),
            issue_instant: now(),
            issuer: "https://idp/Saml2".into(),
            name_id: SubjectNameId {
                value: "alice@example.com".into(),
                format: Some("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".into()),
                sp_name_qualifier: None,
                name_qualifier: None,
            },
            not_before: now(),
            not_on_or_after: now() + Duration::seconds(300),
            recipient: ACS.into(),
            in_response_to: Some("_req".into()),
            audience: SP.into(),
            authn: AuthnStatement {
                authn_instant: now(),
                session_index: Some("idx".into()),
                class_ref: "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified".into(),
            },
            attributes: vec![("name".into(), vec!["Alice".into()])],
        }),
    }
}

fn signed(r: &Response, assertion: bool, whole: bool) -> String {
    sign_response(&write_response(r), r, assertion, whole, &idp()).unwrap()
}

fn expect(certs: &[Vec<u8>]) -> Expect<'_> {
    Expect {
        acs: ACS,
        audience: SP,
        pending: &["_req"],
        now: now(),
        certificates: certs,
        issuer: "https://idp/Saml2",
    }
}

/// The unsigned `<saml:Assertion>` element of `r`, as written.
fn unsigned_assertion(r: &Response) -> String {
    let xml = write_response(r);
    let start = xml.find("<saml:Assertion").unwrap();
    let end = xml.rfind("</saml:Assertion>").unwrap() + "</saml:Assertion>".len();
    xml[start..end].to_owned()
}

fn mallory() -> Response {
    let mut r = response();
    let a = r.assertion.as_mut().unwrap();
    a.id = "_evil".into();
    a.name_id.value = "mallory@example.com".into();
    r
}

#[test]
fn a_wrapped_unsigned_assertion_is_refused() {
    let certs = vec![idp().certificate().to_vec()];
    let genuine = signed(&response(), true, false);
    let at = genuine.find("<saml:Assertion").unwrap();
    // Mallory's unsigned assertion first, the genuine signed one after it.
    let before = format!(
        "{}{}{}",
        &genuine[..at],
        unsigned_assertion(&mallory()),
        &genuine[at..]
    );
    let err = check_response(&before, &expect(&certs)).unwrap_err();
    assert!(err.contains("one Assertion"), "{err}");
    // The genuine signed assertion hidden away inside Mallory's.
    let evil = unsigned_assertion(&mallory());
    let close = evil.rfind("</saml:Assertion>").unwrap();
    let signed_assertion = &genuine[at..genuine.rfind("</saml:Assertion>").unwrap() + 17];
    let hidden = format!(
        "{}{}{}</saml:Assertion>{}",
        &genuine[..at],
        &evil[..close],
        signed_assertion,
        &genuine[at + signed_assertion.len()..]
    );
    let err = check_response(&hidden, &expect(&certs)).unwrap_err();
    assert!(err.contains("not signed"), "{err}");
}

#[test]
fn an_assertion_from_another_issuer_is_refused() {
    let certs = vec![idp().certificate().to_vec()];
    let mut r = response();
    r.assertion.as_mut().unwrap().issuer = "https://other/Saml2".into();
    let err = check_response(&signed(&r, true, true), &expect(&certs)).unwrap_err();
    assert!(err.contains("Issuer"), "{err}");
}

#[test]
fn a_signed_response_for_a_pending_request_signs_in() {
    let certs = vec![idp().certificate().to_vec()];
    let signed_in = check_response(&signed(&response(), true, true), &expect(&certs)).unwrap();
    assert_eq!(signed_in.name_id, "alice@example.com");
    assert_eq!(signed_in.session_index.as_deref(), Some("idx"));
    assert_eq!(
        signed_in.attributes,
        [("name".to_owned(), vec!["Alice".to_owned()])]
    );
    assert_eq!(signed_in.in_response_to, "_req");
    // The response's signature alone covers the assertion too.
    assert!(check_response(&signed(&response(), false, true), &expect(&certs)).is_ok());
}

#[test]
fn what_is_refused() {
    let certs = vec![idp().certificate().to_vec()];
    let refused = |xml: &str| check_response(xml, &expect(&certs)).unwrap_err();
    assert!(refused(&write_response(&response())).contains("not signed"));
    // Tampered after signing.
    let tampered =
        signed(&response(), true, true).replace("alice@example.com", "mallory@example.com");
    assert!(
        refused(&tampered).contains("signature"),
        "{}",
        refused(&tampered)
    );
    // Signed by someone else.
    let other = vec![
        pem::parse(
            std::fs::read_to_string(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../fixtures/saml/sp/sp-signing.cert.pem"),
            )
            .unwrap(),
        )
        .unwrap()
        .into_contents(),
    ];
    assert!(check_response(&signed(&response(), true, true), &expect(&other)).is_err());
    let with = |change: fn(&mut Response)| {
        let mut r = response();
        change(&mut r);
        refused(&signed(&r, true, true))
    };
    assert!(with(|r| r.in_response_to = Some("_other".into())).contains("InResponseTo"));
    assert!(with(|r| r.destination = Some("https://evil/acs".into())).contains("Destination"));
    assert!(
        with(|r| r.assertion.as_mut().unwrap().audience = "https://other".into())
            .contains("Audience")
    );
    assert!(
        with(|r| r.assertion.as_mut().unwrap().recipient = "https://evil/acs".into())
            .contains("Recipient")
    );
    assert!(
        with(|r| r.assertion.as_mut().unwrap().not_on_or_after = now() - Duration::seconds(1))
            .contains("expired")
    );
    assert!(
        with(|r| {
            r.status = Status::nested(
                "urn:oasis:names:tc:SAML:2.0:status:Responder",
                "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
            );
            r.assertion = None;
        })
        .contains("AuthnFailed")
    );
}

#[test]
fn metadata_certificates_are_read() {
    let cert = idp().certificate().to_vec();
    let xml = rustid_saml::metadata::write_metadata(
        &rustid_saml::options::SamlOptions::default(),
        "https://idp/Saml2",
        std::slice::from_ref(&cert),
        "https://idp",
        now(),
    );
    assert_eq!(metadata_certificates(&xml).unwrap(), [cert]);
}
