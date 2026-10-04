#![forbid(unsafe_code)]
//! Fuzz target bodies: each takes arbitrary bytes and panics only on a
//! bug. `fuzz/` wraps them for libFuzzer; `tests/corpus.rs` runs them on
//! the committed seeds and past crashes.

use std::sync::OnceLock;

pub mod http;

use rustid_saml::xml::{c14n, dom, dsig};

pub type Target = fn(&[u8]);

pub const TARGETS: &[(&str, Target)] = &[
    ("jws", jws),
    ("form", form),
    ("xml", xml),
    ("saml_redirect", saml_redirect),
    ("saml_post", saml_post),
    ("certificate", certificate),
    ("http", http::http),
];

fn text(data: &[u8]) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(data)
}

/// Compact JWS decoding, claim access and verification by the header's
/// own key (client assertions, request objects, DPoP proofs, hints).
pub fn jws(data: &[u8]) {
    let token = text(data);
    if let Some(jws) = rustid_core::jwt::Jws::decode(&token) {
        let _ = jws.header_str("alg");
        let _ = jws.claim_str("iss");
        let _ = jws.numeric_date("exp");
        let _ = jws.claim_i64("iat");
        if let Some(jwk) = jws.header.get("jwk")
            && let Some(key) = rustid_core::jwt::PublicJwk::parse(&jwk.to_string())
        {
            let _ = jws.verify(&key);
        }
    }
    let _ = rustid_core::jwt::PublicJwk::parse(&token);
}

/// Form bodies and query strings, as every endpoint reads them, and the
/// client secrets read from them.
pub fn form(data: &[u8]) {
    let limits = rustid_core::options::InputLengthRestrictions::default();
    if let Ok(form) = rustid_core::form::Form::parse(data) {
        let params = rustid_core::params::Params::from_form(&form);
        let _ = params.to_query_string();
        let _ = rustid_core::secrets::parse_post_body(&form, &limits);
        let _ = rustid_core::secrets::parse_jwt_bearer(&form, &limits);
    }
    let text = text(data);
    let _ = rustid_core::params::Params::parse_query(&text).to_query_string();
    let _ = rustid_core::secrets::parse_basic(Some(&text), &limits);
}

/// The oracle's RSA certificate (DER): signed seeds verify with it.
fn trusted() -> &'static [Vec<u8>] {
    static TRUSTED: OnceLock<Vec<Vec<u8>>> = OnceLock::new();
    TRUSTED.get_or_init(|| {
        vec![
            rustid_saml::model::decode_certificate(include_str!(
                "../../../fixtures/saml/oracle/rsa.cert.pem"
            ))
            .expect("the oracle certificate"),
        ]
    })
}

/// The XML DOM, both canonicalizations of its root, and signature
/// verification of the root against a trusted certificate.
pub fn xml(data: &[u8]) {
    let Ok(doc) = dom::parse(&text(data), &dom::Limits::default()) else {
        return;
    };
    for all_namespaces in [false, true] {
        let options = c14n::Options {
            comments: false,
            inclusive: &[],
            exclude: None,
            all_namespaces,
        };
        let _ = c14n::canonicalize_in(&doc, &doc.root, &options);
    }
    let _ = dsig::verify(
        &doc,
        &doc.root,
        trusted(),
        &[dsig::algorithms::RSA_SHA256, dsig::algorithms::ECDSA_SHA256],
    );
}

/// The redirect binding: query parsing, inflate, the XML, then the three
/// message readers.
pub fn saml_redirect(data: &[u8]) {
    let Ok(inbound) = rustid_saml::sso::unbind_redirect(&text(data), 256 * 1024, 80) else {
        return;
    };
    read_messages(&inbound.xml);
}

/// The POST binding: form fields, base64, the XML, the readers.
pub fn saml_post(data: &[u8]) {
    let Ok(form) = rustid_core::form::Form::parse(data) else {
        return;
    };
    let fields: Vec<(String, String)> = form
        .pairs()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
    let Ok(inbound) = rustid_saml::sso::unbind_post(&fields, 256 * 1024, 80) else {
        return;
    };
    read_messages(&inbound.xml);
}

fn read_messages(xml: &str) {
    use rustid_saml::protocol::{self, TrustLevel};
    let limits = dom::Limits {
        ignore_processing_instructions: true,
        ..dom::Limits::default()
    };
    let Ok(doc) = dom::parse(xml, &limits) else {
        return;
    };
    let _ = protocol::read_authn_request(&doc, TrustLevel::None, None);
    let _ = protocol::read_logout_request(&doc, TrustLevel::None, None);
    let _ = protocol::read_logout_response(&doc, TrustLevel::None, None);
}

/// Client certificates: DER, PEM bundles, the forwarded header and SAML
/// certificate text.
pub fn certificate(data: &[u8]) {
    use rustid_core::client_certificate::{ClientCaRoots, ClientCertificate};
    let _ = ClientCertificate::parse(data, None);
    let _ = ClientCaRoots::from_pem(data);
    let text = text(data);
    if let Some(der) = rustid_server::forwarded::decode_certificate(&text) {
        let _ = ClientCertificate::parse(&der, None);
    }
    let _ = rustid_saml::model::decode_certificate(&text);
}
