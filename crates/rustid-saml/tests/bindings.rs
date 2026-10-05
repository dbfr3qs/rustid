//! The HTTP-Redirect and HTTP-POST binding codecs.

use std::path::{Path, PathBuf};

use base64::Engine;
use rustid_saml::bindings::{MessageName, post, redirect};
use rustid_saml::xml::dsig::{Credential, DEFAULT_ALLOWED};

fn oracle() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/saml/oracle")
}

fn read(name: &str) -> String {
    std::fs::read_to_string(oracle().join(name)).unwrap()
}

fn cert(name: &str) -> Vec<u8> {
    pem::parse(read(&format!("{name}.cert.pem")))
        .unwrap()
        .into_contents()
}

fn credential(name: &str) -> Credential {
    Credential::from_pem(
        &read(&format!("{name}.cert.pem")),
        &read(&format!("{name}.key.pem")),
    )
    .unwrap()
}

const XML: &str =
    "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"_a\"/>";

#[test]
fn redirect_messages_round_trip_signed_and_unsigned() {
    for signer in [None, Some(credential("rsa")), Some(credential("ec256"))] {
        let query = redirect::encode(
            MessageName::SamlRequest,
            XML,
            Some("state é/&x"),
            signer
                .as_ref()
                .map(|s| s as &dyn rustid_saml::xml::dsig::XmlSigner),
        )
        .unwrap();
        assert!(query.starts_with("?SAMLRequest="), "{query}");
        let parsed = redirect::parse(&query, 1_048_576, 80).unwrap();
        assert_eq!(parsed.name, MessageName::SamlRequest);
        assert_eq!(parsed.xml, XML);
        assert_eq!(parsed.relay_state.as_deref(), Some("state é/&x"));
        match &signer {
            None => assert!(parsed.signature.is_none() && parsed.signed_content.is_none()),
            Some(c) => {
                let content = parsed.signed_content.as_deref().unwrap();
                assert!(
                    content.starts_with("SAMLRequest=")
                        && content.contains("&RelayState=")
                        && content.contains("&SigAlg=")
                );
                assert!(redirect::verify_signature(
                    &parsed,
                    &[c.certificate().to_vec()],
                    DEFAULT_ALLOWED
                ));
                assert!(!redirect::verify_signature(
                    &parsed,
                    &[cert("ec384")],
                    DEFAULT_ALLOWED
                ));
                assert!(!redirect::verify_signature(
                    &parsed,
                    &[c.certificate().to_vec()],
                    &["http://www.w3.org/2001/04/xmlenc#sha256"]
                ));
            }
        }
    }
}

#[test]
fn oracle_signed_queries_verify_with_their_raw_encoding() {
    let query = read("redirect-rsa.query");
    let parsed = redirect::parse_parameters(&query).unwrap();
    assert!(redirect::verify_signature(
        &parsed,
        &[cert("rsa")],
        DEFAULT_ALLOWED
    ));
    // Reordered parameters parse the same, and sign the same content.
    let mut parts: Vec<&str> = query.split('&').collect();
    parts.reverse();
    let reordered = parse_reordered(&parts.join("&"));
    assert_eq!(reordered.signed_content, parsed.signed_content);
    // An SP's lower-case escapes are what it signed: kept as sent.
    let lower = query.replace("%2F", "%2f");
    let lowered = redirect::parse_parameters(&lower).unwrap();
    assert_ne!(lowered.signed_content, parsed.signed_content);
    assert!(
        !redirect::verify_signature(&lowered, &[cert("rsa")], DEFAULT_ALLOWED),
        "the SP signed upper case"
    );
}

fn parse_reordered(query: &str) -> redirect::Parameters {
    redirect::parse_parameters(query).unwrap()
}

#[test]
fn redirect_errors_have_their_messages() {
    let error = |query: &str| {
        redirect::parse(query, 1_048_576, 80)
            .unwrap_err()
            .to_string()
    };
    assert_eq!(
        error("?RelayState=x"),
        "SAMLResponse or SAMLRequest parameter not found"
    );
    assert_eq!(
        error("?SAMLRequest=a&SAMLResponse=b"),
        "Duplicate message parameters found: SAMLRequest, SAMLResponse"
    );
    let ok = redirect::encode(MessageName::SamlRequest, XML, None, None).unwrap();
    assert_eq!(
        error(&format!("{ok}&RelayState=a&RelayState=b")),
        "Duplicate RelayState parameters found"
    );
    assert_eq!(
        error(&format!("{ok}&SigAlg=a&SigAlg=b")),
        "Duplicate SigAlg parameters found"
    );
    assert_eq!(
        error(&format!("{ok}&Signature=a&Signature=b")),
        "Duplicate Signature parameters found"
    );
    assert_eq!(
        error(&format!("{ok}&Signature=abc")),
        "Incomplete redirect binding signature parameters"
    );
    assert!(
        redirect::parse(&format!("{ok}&Signature=&SigAlg="), 1_048_576, 80).is_ok(),
        "empty means absent"
    );
    assert_eq!(
        error(&format!("{ok}&RelayState={}", "x".repeat(81))),
        "RelayState exceeds maximum allowed size of 80 bytes."
    );
    assert!(error("?SAMLRequest=!!!notbase64").contains("Base-64"));
    assert!(error("?SAMLRequest=bm90IGRlZmxhdGU%3D").contains("inflate"));
    // A deflate bomb stops at the limit.
    let bomb =
        redirect::encode(MessageName::SamlRequest, &"a".repeat(100_000), None, None).unwrap();
    assert!(bomb.len() < 2_000);
    assert_eq!(
        redirect::parse(&bomb, 10_000, 80).unwrap_err().to_string(),
        "Maximum stream size exceeded."
    );
}

#[test]
fn plus_signs_are_spaces() {
    // Query decoding turns '+' into a space and decodes
    // escapes; the signed content keeps the raw text.
    let p = redirect::parse_parameters("?SAMLRequest=ab+cd%2B&SigAlg=x&Signature=y").unwrap();
    assert_eq!(p.message, "ab cd+");
    assert_eq!(
        p.signed_content.as_deref(),
        Some("SAMLRequest=ab+cd%2B&SigAlg=x")
    );
}

#[test]
fn post_messages_decode_within_limits() {
    let encoded = base64::engine::general_purpose::STANDARD.encode(XML);
    assert_eq!(post::decode(&encoded, 1_048_576).unwrap(), XML);
    let wrapped: String = encoded
        .as_bytes()
        .chunks(20)
        .map(|c| format!("{}\r\n", std::str::from_utf8(c).unwrap()))
        .collect();
    assert_eq!(
        post::decode(&wrapped, 1_048_576).unwrap(),
        XML,
        "line breaks are tolerated"
    );
    assert_eq!(
        post::decode(&encoded, 10).unwrap_err().to_string(),
        "SAML message exceeds maximum allowed size of 10 characters."
    );
    assert!(
        post::decode("***", 1_048_576)
            .unwrap_err()
            .to_string()
            .contains("Base-64")
    );
}

#[test]
fn ecdsa_queries_signed_with_sha256_verify() {
    // ECDSA P-384 with SHA-256, as every ECDSA query is signed.
    let ec = redirect::parse_parameters(&read("redirect-ec384.query")).unwrap();
    assert!(redirect::verify_signature(
        &ec,
        &[cert("ec384")],
        DEFAULT_ALLOWED
    ));
    // A 1024-bit RSA key.
    let weak = redirect::parse_parameters(&read("redirect-rsa1024.query")).unwrap();
    assert!(redirect::verify_signature(
        &weak,
        &[cert("rsa1024")],
        DEFAULT_ALLOWED
    ));
    // Algorithm confusion: an ECDSA query never checks against an RSA key.
    assert!(!redirect::verify_signature(
        &ec,
        &[cert("rsa")],
        DEFAULT_ALLOWED
    ));
}
