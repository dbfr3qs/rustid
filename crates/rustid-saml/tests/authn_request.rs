//! Reading an AuthnRequest, with
//! `XmlTraverser`'s rules: required attributes, element order, unprocessed
//! children, and an enveloped signature checked against the issuer's keys.

use std::path::Path;

use rustid_saml::protocol::{ReadError, SigningEntity, TrustLevel, issuer_of, read_authn_request};
use rustid_saml::xml::dom::{Limits, parse};
use rustid_saml::xml::dsig::{Credential, DEFAULT_ALLOWED, sign};

const P: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const A: &str = "urn:oasis:names:tc:SAML:2.0:assertion";

fn limits() -> Limits {
    Limits {
        ignore_processing_instructions: true,
        ..Limits::default()
    }
}

fn request(attrs: &str, children: &str) -> String {
    format!(
        r#"<samlp:AuthnRequest xmlns:samlp="{P}" xmlns:saml="{A}" {attrs}>{children}</samlp:AuthnRequest>"#
    )
}

const ATTRS: &str = r#"ID="_r1" Version="2.0" IssueInstant="2026-10-02T10:00:00Z""#;
const ISSUER: &str = "<saml:Issuer>https://sp.example</saml:Issuer>";

fn read(xml: &str) -> Result<rustid_saml::protocol::AuthnRequest, ReadError> {
    let doc = parse(xml, &limits()).unwrap();
    read_authn_request(&doc, TrustLevel::None, None)
}

fn invalid(xml: &str) -> Vec<String> {
    match read(xml) {
        Err(ReadError::Invalid(errors)) => errors,
        other => panic!("expected invalid, got {other:?}"),
    }
}

fn credential() -> Credential {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/saml/sp");
    Credential::from_pem(
        &std::fs::read_to_string(dir.join("sp-signing.cert.pem")).unwrap(),
        &std::fs::read_to_string(dir.join("sp-signing.key.pem")).unwrap(),
    )
    .unwrap()
}

#[test]
fn every_part_is_read() {
    let xml = request(
        &format!(
            r#"{ATTRS} Destination="https://idp/Saml2/SSO" Consent="urn:c" ForceAuthn="1" IsPassive="false" AssertionConsumerServiceIndex=" 2 " AssertionConsumerServiceURL="https://sp.example/acs" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AttributeConsumingServiceIndex="3" ProviderName="SP""#
        ),
        &format!(
            r#"
  {ISSUER}
  <samlp:Extensions><x:y xmlns:x="urn:x">anything</x:y></samlp:Extensions>
  <saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@example.com</saml:NameID></saml:Subject>
  <!-- a comment -->
  <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" AllowCreate="true" SPNameQualifier="q"/>
  <saml:Conditions NotOnOrAfter="2026-10-02T11:00:00Z"/>
  <samlp:RequestedAuthnContext Comparison="minimum"><saml:AuthnContextClassRef>urn:a</saml:AuthnContextClassRef><saml:AuthnContextClassRef>urn:b</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>
  <samlp:Scoping ProxyCount="1"><samlp:IDPList><samlp:IDPEntry ProviderID="https://idp.one"/></samlp:IDPList><samlp:RequesterID>https://req</samlp:RequesterID></samlp:Scoping>
"#
        ),
    );
    let r = read(&xml).unwrap();
    assert_eq!(r.id, "_r1");
    assert_eq!(r.version, "2.0");
    assert_eq!(r.issue_instant.to_rfc3339(), "2026-10-02T10:00:00+00:00");
    assert_eq!(r.destination.as_deref(), Some("https://idp/Saml2/SSO"));
    assert_eq!(r.issuer.as_ref().unwrap().value, "https://sp.example");
    assert!(r.force_authn && !r.is_passive);
    assert_eq!(r.acs_index, Some(2));
    assert_eq!(r.acs_url.as_deref(), Some("https://sp.example/acs"));
    assert_eq!(
        r.protocol_binding.as_deref(),
        Some("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
    );
    assert_eq!(
        r.subject_name_id.as_ref().unwrap().value,
        "alice@example.com"
    );
    let policy = r.name_id_policy.as_ref().unwrap();
    assert_eq!(
        policy.format.as_deref(),
        Some("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent")
    );
    assert_eq!(policy.allow_create, Some(true));
    let rac = r.requested_authn_context.as_ref().unwrap();
    assert_eq!(rac.comparison.as_deref(), Some("minimum"));
    assert_eq!(rac.authn_context_class_ref, ["urn:a", "urn:b"]);
    let scoping = r.scoping.as_ref().unwrap();
    assert_eq!(scoping.idp_entries, ["https://idp.one"]);
    assert_eq!(r.trust, TrustLevel::None);
}

#[test]
fn required_attributes_and_their_formats() {
    let missing = invalid(&request(
        r#"Version="2.0" IssueInstant="2026-10-02T10:00:00Z""#,
        ISSUER,
    ));
    assert_eq!(
        missing,
        ["Required attribute ID not found on samlp:AuthnRequest."]
    );
    let missing = invalid(&request(r#"ID="_x" Version="2.0""#, ISSUER));
    assert_eq!(
        missing,
        ["Required attribute IssueInstant not found on samlp:AuthnRequest."]
    );
    let bad = invalid(&request(
        r#"ID="_x" Version="2.0" IssueInstant="yesterday""#,
        ISSUER,
    ));
    assert_eq!(bad, ["Conversion to DateTimeUtc failed for yesterday."]);
    let bad = invalid(&request(&format!(r#"{ATTRS} ForceAuthn="yes""#), ISSUER));
    assert_eq!(bad, ["Conversion to Boolean failed for yes."]);
    let bad = invalid(&request(
        &format!(r#"{ATTRS} ProtocolBinding="not a uri""#),
        ISSUER,
    ));
    assert_eq!(
        bad,
        ["Attribute \"ProtocolBinding\" should be an absolute Uri, but \"not a uri\" isn't."]
    );
    // An empty ID is present, so not a reading error.
    let r = read(&request(
        r#"ID="" Version="2.0" IssueInstant="2026-10-02T10:00:00Z""#,
        ISSUER,
    ))
    .unwrap();
    assert_eq!(r.id, "");
    // Instants without a zone are UTC; fractions are kept.
    let r = read(&request(
        r#"ID="_x" Version="2.0" IssueInstant="2026-10-02T10:00:00.1234567""#,
        ISSUER,
    ))
    .unwrap();
    assert_eq!(r.issue_instant.timestamp_subsec_nanos(), 123_456_700);
    let r = read(&request(
        r#"ID="_x" Version="2.0" IssueInstant="2026-10-02T12:00:00+02:00""#,
        ISSUER,
    ))
    .unwrap();
    assert_eq!(r.issue_instant.to_rfc3339(), "2026-10-02T10:00:00+00:00");
}

#[test]
fn structure_errors() {
    // Unprocessed content: whitespace inside an element the reader doesn't read.
    let errors = invalid(&request(
        ATTRS,
        &format!("{ISSUER}<samlp:NameIDPolicy> </samlp:NameIDPolicy>"),
    ));
    assert_eq!(
        errors,
        ["All child nodes under NameIDPolicy have not been processed."]
    );
    // Text between elements.
    let errors = invalid(&request(ATTRS, &format!("{ISSUER}stray")));
    assert_eq!(errors, ["Unsupported node type Text."]);
    // An element in the issuer.
    let errors = invalid(&request(ATTRS, "<saml:Issuer>a<b/></saml:Issuer>"));
    assert_eq!(
        errors,
        ["Element \"Issuer\" should only contain text but has unexpected child element \"b\"."]
    );
    // Both class and declaration references.
    let errors = invalid(&request(
        ATTRS,
        &format!(
            "{ISSUER}<samlp:RequestedAuthnContext><saml:AuthnContextClassRef>a</saml:AuthnContextClassRef><saml:AuthnContextDeclRef>b</saml:AuthnContextDeclRef></samlp:RequestedAuthnContext>"
        ),
    ));
    assert_eq!(
        errors,
        [
            "RequestedAuthnContext must contain either AuthnContextClassRef or AuthnContextDeclRef elements, but not both"
        ]
    );
}

#[test]
fn what_the_reader_does_not_handle() {
    // An element out of order (or unknown) leaves the root's children
    // unprocessed, which isn't handled (a 500).
    let xml = request(ATTRS, &format!("<saml:Conditions/>{ISSUER}"));
    assert!(
        matches!(read(&xml), Err(ReadError::Unhandled(_))),
        "{:?}",
        read(&xml)
    );
    // A different root: the traversal never completes (a 500).
    let doc = parse(
        &format!(r#"<samlp:LogoutRequest xmlns:samlp="{P}" {ATTRS}/>"#),
        &limits(),
    )
    .unwrap();
    assert!(matches!(
        read_authn_request(&doc, TrustLevel::None, None),
        Err(ReadError::Unhandled(_))
    ));
    // An integer out of range (OverflowException).
    let xml = request(
        &format!(r#"{ATTRS} AssertionConsumerServiceIndex="99999999999""#),
        ISSUER,
    );
    assert!(matches!(read(&xml), Err(ReadError::Unhandled(_))));
}

#[test]
fn enveloped_signatures_give_trust_only_with_the_issuers_keys() {
    let cred = credential();
    let xml = request(ATTRS, ISSUER);
    let signed = sign(&xml, "_r1", &cred, &limits()).unwrap();
    let doc = parse(&signed, &limits()).unwrap();
    assert_eq!(issuer_of(&doc).as_deref(), Some("https://sp.example"));
    let entity = SigningEntity {
        certificates: vec![cred.certificate().to_vec()],
        allowed_algorithms: DEFAULT_ALLOWED.iter().map(|s| s.to_string()).collect(),
    };
    let trusted = read_authn_request(&doc, TrustLevel::None, Some(&entity)).unwrap();
    assert_eq!(trusted.trust, TrustLevel::ConfiguredKey);
    // Without keys the signature is skipped, untrusted, and no error.
    let untrusted = read_authn_request(&doc, TrustLevel::None, None).unwrap();
    assert_eq!(untrusted.trust, TrustLevel::None);
    // A tampered message fails to read.
    let tampered = parse(
        &signed
            .replace("_r1\"", "_r2\"")
            .replace("#_r1", "#_r2")
            .replace("https://sp.example<", "https://evil.example<"),
        &limits(),
    )
    .unwrap();
    assert!(matches!(
        read_authn_request(&tampered, TrustLevel::None, Some(&entity)),
        Err(ReadError::Invalid(_))
    ));
    // A disallowed algorithm fails.
    let strict = SigningEntity {
        allowed_algorithms: vec!["http://www.w3.org/2001/04/xmldsig-more#rsa-sha512".into()],
        ..entity.clone()
    };
    assert!(matches!(
        read_authn_request(&doc, TrustLevel::None, Some(&strict)),
        Err(ReadError::Invalid(_))
    ));
    // A signature where the issuer should be.
    let no_issuer = request(
        ATTRS,
        r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/>"#,
    );
    let doc = parse(&no_issuer, &limits()).unwrap();
    let Err(ReadError::Invalid(errors)) = read_authn_request(&doc, TrustLevel::None, Some(&entity))
    else {
        panic!()
    };
    assert!(
        errors[0].starts_with("A signature was found, but there was no Issuer specified."),
        "{errors:?}"
    );
    // Signed with no issuer, the signature follows the subject, where
    // the reader never reads it (a 500).
    let signed = sign(&request(ATTRS, "<saml:Subject/>"), "_r1", &cred, &limits()).unwrap();
    let doc = parse(&signed, &limits()).unwrap();
    assert!(matches!(
        read_authn_request(&doc, TrustLevel::None, Some(&entity)),
        Err(ReadError::Unhandled(_))
    ));
    // Redirect trust carries over.
    let doc = parse(&xml, &limits()).unwrap();
    let r = read_authn_request(&doc, TrustLevel::ConfiguredKey, None).unwrap();
    assert_eq!(r.trust, TrustLevel::ConfiguredKey);
}

#[test]
fn audiences_are_plain_text() {
    // An Audience is read as text content: a bare name is fine.
    let xml = request(
        ATTRS,
        &format!(
            "{ISSUER}<saml:Conditions><saml:AudienceRestriction><saml:Audience>sp-name</saml:Audience></saml:AudienceRestriction></saml:Conditions>"
        ),
    );
    assert!(read(&xml).is_ok(), "{:?}", read(&xml));
    // Another element in the restriction is an EnsureName error.
    let xml = request(
        ATTRS,
        &format!(
            "{ISSUER}<saml:Conditions><saml:AudienceRestriction><saml:Other/></saml:AudienceRestriction></saml:Conditions>"
        ),
    );
    assert!(matches!(read(&xml), Err(ReadError::Invalid(_))));
}
