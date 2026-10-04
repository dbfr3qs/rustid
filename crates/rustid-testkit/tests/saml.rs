//! The harness's SAML support: building signed requests as an SP does,
//! decoding what an IdP sends, and normalizing SAML XML for comparison.

use rustid_saml::bindings::redirect;
use rustid_testkit::normalize::{MASK, Normalizer};
use rustid_testkit::recorded::{Body, Recorded};
use rustid_testkit::saml::{
    AuthnRequest, LogoutRequest, decode_post_form, decode_redirect, mask_saml_xml, post_form,
    redirect_url, sp_credential, verify_saml_signatures,
};

const SIGNED: &str = r##"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_abc" InResponseTo="_req" IssueInstant="2026-10-02T10:00:00Z" Destination="https://sp/acs"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">idp</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:Reference URI="#_abc"><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>
BBBB
</ds:SignatureValue></ds:Signature><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_as" IssueInstant="2026-10-02T10:00:00Z"><saml:Conditions NotBefore="a" NotOnOrAfter="b" /><saml:AuthnStatement AuthnInstant="c" SessionIndex="d" /></saml:Assertion></samlp:Response>"##;

#[test]
fn saml_xml_masks_ids_instants_and_signature_values_only() {
    let masked = mask_saml_xml(SIGNED);
    for attr in [
        "ID",
        "InResponseTo",
        "IssueInstant",
        "NotBefore",
        "NotOnOrAfter",
        "AuthnInstant",
        "SessionIndex",
    ] {
        assert!(
            masked.contains(&format!(" {attr}=\"{MASK}\"")),
            "{attr}: {masked}"
        );
    }
    assert!(masked.contains(&format!("URI=\"#{MASK}\"")), "{masked}");
    assert!(masked.contains(&format!("<ds:DigestValue>{MASK}</ds:DigestValue>")));
    assert!(masked.contains(&format!("<ds:SignatureValue>{MASK}</ds:SignatureValue>")));
    assert!(
        masked.contains(r#"Destination="https://sp/acs""#),
        "kept: {masked}"
    );
    assert!(masked.contains(">idp</saml:Issuer>"));
    assert!(
        mask_saml_xml("<md:EntityDescriptor validUntil=\"x\" entityID=\"e\" />")
            .contains(&format!("validUntil=\"{MASK}\" entityID=\"e\""))
    );
}

#[test]
fn saml_xml_masking_leaves_closing_tags_and_what_follows_alone() {
    let xml = "<ds:Signature><ds:SignedInfo><ds:Reference URI=\"#_a\"><ds:DigestValue>AAAA</ds:DigestValue>tail</ds:Reference></ds:SignedInfo><ds:SignatureValue>BBBB</ds:SignatureValue>kept<ds:KeyInfo /><DigestValue>C</DigestValue>after</ds:Signature>";
    assert_eq!(
        mask_saml_xml(xml),
        format!(
            "<ds:Signature><ds:SignedInfo><ds:Reference URI=\"#{MASK}\"><ds:DigestValue>{MASK}</ds:DigestValue>tail</ds:Reference></ds:SignedInfo><ds:SignatureValue>{MASK}</ds:SignatureValue>kept<ds:KeyInfo /><DigestValue>{MASK}</DigestValue>after</ds:Signature>"
        )
    );
}

#[test]
fn redirect_requests_are_deflated_signed_and_decodable() {
    let sp = sp_credential();
    let request = AuthnRequest {
        destination: Some("https://idp/Saml2/SSO".into()),
        acs_url: Some("https://sp.example/acs".into()),
        ..AuthnRequest::new("https://sp.example")
    };
    let xml = request.to_xml();
    assert!(xml.starts_with("<samlp:AuthnRequest "), "{xml}");
    assert!(
        xml.contains(r#"Version="2.0""#)
            && xml.contains(r#"AssertionConsumerServiceURL="https://sp.example/acs""#)
    );
    let url = redirect_url(
        "https://idp/Saml2/SSO",
        "SAMLRequest",
        &xml,
        Some("state 1"),
        Some(&sp),
    );
    let decoded = decode_redirect(&url).unwrap();
    assert_eq!(decoded.name, "SAMLRequest");
    assert_eq!(decoded.xml, xml);
    assert_eq!(decoded.relay_state.as_deref(), Some("state 1"));
    let query = url.split_once('?').unwrap().1;
    let parsed = redirect::parse_parameters(query).unwrap();
    assert!(redirect::verify_signature(
        &parsed,
        &[sp.certificate().to_vec()],
        &["http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"]
    ));
    let unsigned = redirect_url("https://idp/x", "SAMLRequest", &xml, None, None);
    assert!(!unsigned.contains("Signature="));
}

#[test]
fn post_requests_carry_an_enveloped_signature() {
    let sp = sp_credential();
    let xml = LogoutRequest {
        name_id: "alice".into(),
        session_index: Some("s1".into()),
        ..LogoutRequest::new("https://sp.example")
    }
    .to_xml();
    let (body, signed) = post_form("SAMLRequest", &xml, Some("rs"), Some(&sp));
    assert!(body.contains("SAMLRequest=") && body.contains("RelayState=rs"));
    assert_eq!(
        verify_saml_signatures(&signed, &[sp.certificate().to_vec()]),
        Ok(1)
    );
    let tampered = signed.replace(">alice<", ">mallory<");
    assert!(verify_saml_signatures(&tampered, &[sp.certificate().to_vec()]).is_err());
    assert_eq!(verify_saml_signatures(&xml, &[]), Ok(0), "unsigned");
}

#[test]
fn auto_post_forms_decode() {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode("<samlp:Response ID=\"_1\" />");
    let html = format!(
        "<html><body><form method=\"post\" action=\"https://sp.example/acs\"><input type=\"hidden\" name=\"SAMLResponse\" value=\"{encoded}\" /><input type=\"hidden\" name=\"RelayState\" value=\"a&amp;b\" /></form></body></html>"
    );
    let form = decode_post_form(&html).unwrap();
    assert_eq!(form.action, "https://sp.example/acs");
    assert_eq!(form.name, "SAMLResponse");
    assert_eq!(form.xml, "<samlp:Response ID=\"_1\" />");
    assert_eq!(form.relay_state.as_deref(), Some("a&b"));
}

#[test]
fn the_normalizer_reads_saml_bodies_forms_and_redirects() {
    use base64::Engine;
    let n = Normalizer::new("http://127.0.0.1:5000");
    let metadata = Recorded {
        status: 200,
        headers: Default::default(),
        set_cookies: vec![],
        body: Body::Text(
            r#"<md:EntityDescriptor ID="_x" entityID="http://127.0.0.1:5000/Saml2" validUntil="v" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" />"#.into(),
        ),
    };
    let Body::Text(text) = n.normalize(&metadata).body else {
        panic!()
    };
    assert_eq!(
        text,
        format!(
            r#"<md:EntityDescriptor ID="{MASK}" entityID="{{base}}/Saml2" validUntil="{MASK}" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" />"#
        )
    );

    let encoded = base64::engine::general_purpose::STANDARD
        .encode("<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"_1\" Destination=\"http://127.0.0.1:5000/acs\" />");
    let html = format!(
        "<form action=\"x\"><input type=\"hidden\" name=\"SAMLResponse\" value=\"{encoded}\" /></form>"
    );
    let form = Recorded {
        body: Body::Text(html),
        ..metadata.clone()
    };
    let Body::Text(text) = n.normalize(&form).body else {
        panic!()
    };
    assert!(
        text.contains("value=\"&lt;samlp:Response xmlns:samlp=&quot;urn:oasis:names:tc:SAML:2.0:protocol&quot; ID=&quot;&lt;masked&gt;&quot; Destination=&quot;{base}/acs&quot; /&gt;\""),
        "{text}"
    );

    let sp = sp_credential();
    let xml = AuthnRequest::new("http://127.0.0.1:5000/sp").to_xml();
    let url = redirect_url(
        "http://127.0.0.1:5000/Saml2/SSO",
        "SAMLRequest",
        &xml,
        None,
        Some(&sp),
    );
    let mut redirect = metadata.clone();
    redirect.body = Body::Empty;
    redirect.headers.insert("location".into(), url);
    let location = n.normalize(&redirect).headers["location"].clone();
    assert!(
        location.contains(&format!(
            "Signature={}",
            MASK.replace('<', "%3C").replace('>', "%3E")
        )),
        "{location}"
    );
    assert!(
        location.contains("SAMLRequest=%3Csamlp%3AAuthnRequest"),
        "decoded: {location}"
    );
    assert!(
        location.contains("%7Bbase%7D%2Fsp"),
        "base replaced inside: {location}"
    );
}

#[test]
fn saml_state_ids_are_masked_wherever_they_appear() {
    let n = Normalizer::new("http://127.0.0.1:5000");
    let mut login = Recorded {
        status: 303,
        headers: Default::default(),
        set_cookies: vec![],
        body: Body::Empty,
    };
    login.headers.insert(
        "location".into(),
        "http://127.0.0.1:5000/Account/Login?ReturnUrl=%2FSaml2%2FSSO%2FCallback%3FsamlStateId%3D0192f0a1-2b3c-7d4e-8f90-a1b2c3d4e5f6".into(),
    );
    let location = n.normalize(&login).headers["location"].clone();
    assert_eq!(
        location,
        "{base}/Account/Login?ReturnUrl=%2FSaml2%2FSSO%2FCallback%3FsamlStateId%3D%3Cmasked%3E"
    );
}

#[test]
fn session_index_elements_are_masked() {
    let masked = mask_saml_xml(
        "<samlp:LogoutRequest><samlp:SessionIndex>abc123</samlp:SessionIndex>kept</samlp:LogoutRequest>",
    );
    assert_eq!(
        masked,
        format!(
            "<samlp:LogoutRequest><samlp:SessionIndex>{MASK}</samlp:SessionIndex>kept</samlp:LogoutRequest>"
        )
    );
}
