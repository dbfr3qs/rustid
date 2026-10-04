//! SAML responses as the XML writer writes them, and signed as
//! the signed xml helper signs them (after the Issuer, assertion first).

use std::path::Path;

use chrono::{TimeZone, Utc};
use rustid_saml::response::{
    Assertion, AuthnStatement, Response, Status, SubjectNameId, sign_response, write_response,
};
use rustid_saml::xml::dom::{Limits, parse};
use rustid_saml::xml::dsig::{Credential, DEFAULT_ALLOWED, DSIG, verify};

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 2, 10, 0, 0).unwrap()
}

fn credential() -> Credential {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/saml/idp");
    Credential::from_pem(
        &std::fs::read_to_string(dir.join("idp-rsa.cert.pem")).unwrap(),
        &std::fs::read_to_string(dir.join("idp-rsa.key.pem")).unwrap(),
    )
    .unwrap()
}

fn success() -> Response {
    Response {
        id: "_resp".into(),
        issue_instant: now(),
        destination: Some("https://sp.example/acs".into()),
        in_response_to: Some("_req".into()),
        issuer: "https://idp.test/Saml2".into(),
        status: Status::success(),
        assertion: Some(Assertion {
            id: "_assert".into(),
            issue_instant: now(),
            issuer: "https://idp.test/Saml2".into(),
            name_id: SubjectNameId {
                value: "alice@example.com".into(),
                format: Some("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".into()),
                sp_name_qualifier: None,
                name_qualifier: None,
            },
            not_before: now(),
            not_on_or_after: now() + chrono::Duration::seconds(300),
            recipient: "https://sp.example/acs".into(),
            in_response_to: Some("_req".into()),
            audience: "https://sp.example".into(),
            authn: AuthnStatement {
                authn_instant: now(),
                session_index: Some("0123abcd".into()),
                class_ref: "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified".into(),
            },
            attributes: vec![
                ("name".into(), vec!["Alice & Co".into()]),
                ("roles".into(), vec!["a".into(), "".into()]),
            ],
        }),
    }
}

#[test]
fn a_success_response_is_written_exactly() {
    let xml = write_response(&success());
    assert_eq!(
        xml,
        concat!(
            r#"<samlp:Response ID="_resp" Version="2.0" IssueInstant="2026-10-02T10:00:00Z" Destination="https://sp.example/acs" InResponseTo="_req" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">"#,
            r#"<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.test/Saml2</saml:Issuer>"#,
            r#"<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" /></samlp:Status>"#,
            r#"<saml:Assertion ID="_assert" Version="2.0" IssueInstant="2026-10-02T10:00:00Z" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">"#,
            r#"<saml:Issuer>https://idp.test/Saml2</saml:Issuer>"#,
            r#"<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@example.com</saml:NameID>"#,
            r#"<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2026-10-02T10:05:00Z" Recipient="https://sp.example/acs" InResponseTo="_req" /></saml:SubjectConfirmation></saml:Subject>"#,
            r#"<saml:Conditions NotBefore="2026-10-02T10:00:00Z" NotOnOrAfter="2026-10-02T10:05:00Z"><saml:AudienceRestriction><saml:Audience>https://sp.example</saml:Audience></saml:AudienceRestriction></saml:Conditions>"#,
            r#"<saml:AuthnStatement AuthnInstant="2026-10-02T10:00:00Z" SessionIndex="0123abcd"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>"#,
            r#"<saml:AttributeStatement><saml:Attribute Name="name"><saml:AttributeValue>Alice &amp; Co</saml:AttributeValue></saml:Attribute>"#,
            r#"<saml:Attribute Name="roles"><saml:AttributeValue>a</saml:AttributeValue><saml:AttributeValue /></saml:Attribute></saml:AttributeStatement>"#,
            r#"</saml:Assertion></samlp:Response>"#
        )
    );
}

#[test]
fn an_error_response_has_a_nested_status_and_no_assertion() {
    let response = Response {
        status: Status::nested(
            "urn:oasis:names:tc:SAML:2.0:status:Responder",
            "urn:oasis:names:tc:SAML:2.0:status:NoPassive",
        ),
        assertion: None,
        ..success()
    };
    assert_eq!(
        write_response(&response),
        concat!(
            r#"<samlp:Response ID="_resp" Version="2.0" IssueInstant="2026-10-02T10:00:00Z" Destination="https://sp.example/acs" InResponseTo="_req" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">"#,
            r#"<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.test/Saml2</saml:Issuer>"#,
            r#"<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:NoPassive" /></samlp:StatusCode></samlp:Status>"#,
            r#"</samlp:Response>"#
        )
    );
}

fn signatures_after_issuers(xml: &str) -> (bool, bool) {
    let doc = parse(xml, &Limits::default()).unwrap();
    let after_issuer = |e: &rustid_saml::xml::dom::Element| {
        let names: Vec<&str> = e.elements().map(|c| c.local.as_str()).collect();
        names.len() > 1 && names[0] == "Issuer" && names[1] == "Signature"
    };
    let response = &doc.root;
    let assertion = response
        .elements()
        .find(|e| e.local == "Assertion")
        .unwrap();
    (after_issuer(response), after_issuer(assertion))
}

#[test]
fn signing_behaviours_place_and_verify_signatures() {
    let cred = credential();
    let cert = vec![cred.certificate().to_vec()];
    let xml = write_response(&success());
    for (assertion, response) in [(false, false), (true, false), (false, true), (true, true)] {
        let signed = sign_response(&xml, &success(), assertion, response, &cred).unwrap();
        assert_eq!(
            signatures_after_issuers(&signed),
            (response, assertion),
            "assertion {assertion}, response {response}"
        );
        let doc = parse(&signed, &Limits::default()).unwrap();
        if response {
            verify(&doc, &doc.root, &cert, DEFAULT_ALLOWED).unwrap();
        }
        if assertion {
            let a = doc
                .root
                .elements()
                .find(|e| e.local == "Assertion")
                .unwrap();
            verify(&doc, a, &cert, DEFAULT_ALLOWED).unwrap();
        }
        assert_eq!(
            signed.matches(&format!("xmlns=\"{DSIG}\"")).count(),
            assertion as usize + response as usize
        );
    }
}

#[test]
fn the_auto_post_page() {
    use rustid_saml::response::{auto_post_html, html_encode};
    let html = auto_post_html(
        "https://sp.example/acs?a=1&b=2",
        "SAMLResponse",
        "<x/>",
        Some("r'1é"),
    );
    assert!(html.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE html"));
    assert!(html.contains(
        "<form action=\"https://sp.example/acs?a=1&amp;b=2\" method=\"post\" name=\"samlPostBindingSubmit\">\n<div>\n<input type=\"hidden\" name=\"RelayState\" value=\"r&#39;1&#233;\"/>\n<input type=\"hidden\" name=\"SAMLResponse\"\nvalue=\"PHgvPg==\"/>\n</div>"
    ), "{html}");
    let bare = auto_post_html("https://sp/acs", "SAMLResponse", "<x/>", None);
    assert!(bare.contains("<div>\n<input type=\"hidden\" name=\"SAMLResponse\""));
    assert_eq!(html_encode("😀"), "&#128512;");
}
