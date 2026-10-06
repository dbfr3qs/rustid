//! Enveloped signatures, made and checked,
//! against independently signed documents (`fixtures/saml/oracle`).

use std::path::{Path, PathBuf};

use rustid_saml::xml::dom::{Document, Element, Limits, parse};
use rustid_saml::xml::dsig::{Credential, DEFAULT_ALLOWED, sign, verify};

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

fn doc(text: &str) -> Document {
    parse(text, &Limits::default()).unwrap()
}

fn by_id<'a>(doc: &'a Document, id: &str) -> &'a Element {
    doc.root
        .descendants()
        .into_iter()
        .find(|e| e.attr("ID") == Some(id))
        .unwrap()
}

fn check(text: &str, id: &str, key: &str) -> Result<(), String> {
    let d = doc(text);
    let signed = by_id(&d, id);
    verify(&d, signed, &[cert(key)], DEFAULT_ALLOWED).map(|verified| {
        assert!(
            std::ptr::eq(verified, signed),
            "the verified element is returned"
        );
    })
}

#[test]
fn every_oracle_signed_document_verifies() {
    for (file, key, ids) in [
        ("signed-rsa.xml", "rsa", &["_assert1", "_resp1"][..]),
        ("signed-ec256.xml", "ec256", &["_assert1", "_resp1"]),
        ("signed-ec384.xml", "ec384", &["_assert1", "_resp1"]),
        ("signed-prefixlist.xml", "rsa", &["_assert1", "_resp1"]),
        ("signed-crlf.xml", "rsa", &["_assert1", "_resp1"]),
        ("signed-cdata.xml", "rsa", &["_assert1", "_resp1"]),
        ("signed-authn-exc.xml", "rsa", &["_authn1"]),
        ("signed-authn-exc-comments.xml", "rsa", &["_authn1"]),
        ("signed-authn-xmllang.xml", "rsa", &["_authn1"]),
    ] {
        let text = read(file);
        for id in ids {
            assert_eq!(check(&text, id, key), Ok(()), "{file} {id}");
        }
    }
}

#[test]
fn the_reference_must_name_the_parent_by_id() {
    let signed = read("signed-rsa.xml");
    // Duplicate ID: signature wrapping.
    let duplicate = signed.replacen(
        "<samlp:Status>",
        "<saml:Assertion ID=\"_assert1\"/><samlp:Status>",
        1,
    );
    let d = doc(&duplicate);
    let real = d
        .root
        .descendants()
        .into_iter()
        .find(|e| {
            e.attr("ID") == Some("_assert1")
                && e.child(rustid_saml::xml::dsig::DSIG, "Signature").is_some()
        })
        .unwrap();
    assert_eq!(
        verify(&d, real, &[cert("rsa")], DEFAULT_ALLOWED).map(|_| ()),
        Err("Reference target should resolve to exactly one node".into())
    );
    assert_eq!(
        check(&duplicate, "_resp1", "rsa"),
        Err("Signature didn't verify for any of the the specified keys.".into()),
        "the response's own content changed"
    );
    // Only a lower-case id matches.
    let lower = signed.replace("ID=\"_assert1\"", "id=\"_assert1\"");
    let d = doc(&lower);
    let assertion = d
        .root
        .descendants()
        .into_iter()
        .find(|e| e.attr("id") == Some("_assert1"))
        .unwrap();
    assert_eq!(
        verify(&d, assertion, &[cert("rsa")], DEFAULT_ALLOWED).map(|_| ()),
        Err("Reference target ID attribute must be named ID with uppercase letters".into())
    );
    // The assertion's signature moved under the response: its digest still
    // holds, but it doesn't sign its parent.
    let assertion_sig = &signed[signed.find("<saml:Assertion").unwrap()..];
    let start = assertion_sig.find("<Signature").unwrap();
    let end = assertion_sig.find("</Signature>").unwrap() + "</Signature>".len();
    let moved_sig = &assertion_sig[start..end];
    let without = signed.replacen(moved_sig, "", 1);
    let response_sig_start = without.find("<Signature").unwrap();
    let response_sig_end = without.find("</Signature>").unwrap() + "</Signature>".len();
    let moved = format!(
        "{}{}{}",
        &without[..response_sig_start],
        moved_sig,
        &without[response_sig_end..]
    );
    assert_eq!(
        check(&moved, "_resp1", "rsa"),
        Err("Incorrect reference on Xml Signature, the reference must be to the parent element of the signature.".into())
    );
    assert_eq!(
        check(&read("signed-authn-empty-uri.xml"), "_authn1", "rsa"),
        Err(
            "Empty reference URI (implying the whole document is signed) is not allowed in Saml2."
                .into()
        )
    );
}

#[test]
fn tampering_and_untrusted_keys_are_refused() {
    let signed = read("signed-rsa.xml");
    let failed =
        Err::<(), String>("Signature didn't verify for any of the the specified keys.".into());
    let text = signed.replace("alice &amp; co", "mallory &amp; co");
    assert_eq!(check(&text, "_assert1", "rsa"), failed);
    let first_digest = signed.find("<DigestValue>").unwrap() + "<DigestValue>".len();
    let mut digest = signed.clone();
    digest.replace_range(first_digest..first_digest + 4, "AAAA");
    // The first DigestValue is the response's (its signature follows the
    // response's Issuer).
    assert_eq!(check(&digest, "_resp1", "rsa"), failed.clone());
    let comment = signed.replace("alice &amp; co", "alice<!-- injected --> &amp; co");
    assert_eq!(
        check(&comment, "_assert1", "rsa"),
        Ok(()),
        "comments aren't signed content (a #id reference drops them)"
    );
    assert_eq!(
        check(&signed, "_assert1", "ec256"),
        Err("Signature validated with the contained key, but that is not configured as a trusted key.".into()),
        "only another key is trusted; the embedded certificate verifies"
    );
    assert_eq!(
        check(&read("signed-authn-untrusted.xml"), "_authn1", "rsa"),
        Err("Signature validated with the contained key, but that is not configured as a trusted key.".into())
    );
}

#[test]
fn references_transforms_and_algorithms_are_restricted() {
    let signed = read("signed-authn-exc.xml");
    let reference_start = signed.find("<Reference").unwrap();
    let reference_end = signed.find("</Reference>").unwrap() + "</Reference>".len();
    let reference = &signed[reference_start..reference_end];
    let two = signed.replacen(reference, &format!("{reference}{reference}"), 1);
    assert_eq!(
        check(&two, "_authn1", "rsa"),
        Err("The Signature should contain exactly one reference.".into())
    );
    let xpath = signed.replace(
        "http://www.w3.org/2001/10/xml-exc-c14n#\"",
        "http://www.w3.org/TR/1999/REC-xpath-19991116\"",
    );
    assert_eq!(
        check(&xpath, "_authn1", "rsa"),
        Err("Signature didn't verify for any of the the specified keys. Transform http://www.w3.org/TR/1999/REC-xpath-19991116 is not allowed in SAML2.".into())
    );
    let d = doc(&signed);
    let only_ecdsa = [
        "http://www.w3.org/2001/04/xmldsig-more#sha384",
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
    ];
    assert_eq!(
        verify(&d, &d.root, &[cert("rsa")], &only_ecdsa).map(|_| ()),
        Err(format!(
            "Digest algorithm http://www.w3.org/2001/04/xmlenc#sha256 does not match configured [{0}]. Signature algorithm http://www.w3.org/2001/04/xmldsig-more#rsa-sha256 does not match configured [{0}].",
            only_ecdsa.join(", ")
        ))
    );
}

#[test]
fn rustid_signatures_round_trip() {
    let unsigned = read("signed-rsa.xml");
    let unsigned = strip_signatures(&unsigned);
    for key in ["rsa", "ec256", "ec384"] {
        let credential = credential(key);
        let once = sign(&unsigned, "_assert1", &credential, &Limits::default()).unwrap();
        let twice = sign(&once, "_resp1", &credential, &Limits::default()).unwrap();
        assert_eq!(check(&twice, "_assert1", key), Ok(()), "{key}");
        assert_eq!(check(&twice, "_resp1", key), Ok(()), "{key}");
        let d = doc(&twice);
        let assertion = by_id(&d, "_assert1");
        assert_eq!(
            assertion.elements().nth(1).map(|e| e.local.as_str()),
            Some("Signature"),
            "inserted after the Issuer"
        );
    }
}

fn strip_signatures(text: &str) -> String {
    let mut out = text.to_owned();
    while let Some(start) = out.find("<Signature") {
        let end = out.find("</Signature>").unwrap() + "</Signature>".len();
        out.replace_range(start..end, "");
    }
    out
}

#[test]
fn content_canonicalized_differently_is_not_signed() {
    let credential = credential("rsa");
    let unsigned = strip_signatures(&read("signed-rsa.xml"));
    let cr = unsigned.replace("alice &amp; co", "alice&#13;co");
    let error = sign(&cr, "_assert1", &credential, &Limits::default()).unwrap_err();
    assert!(error.to_string().contains("carriage return"), "{error}");
    let tab = unsigned.replace("Format=\"", "Note=\"a&#9;b\" Format=\"");
    let error = sign(&tab, "_assert1", &credential, &Limits::default()).unwrap_err();
    assert!(error.to_string().contains("tab"), "{error}");
    // Line feeds in text and attributes are fine for both.
    let lf = unsigned.replace("alice &amp; co", "alice\nco");
    assert!(sign(&lf, "_assert1", &credential, &Limits::default()).is_ok());
}

#[test]
fn a_signature_with_two_of_anything_is_refused() {
    let unsigned = strip_signatures(&read("signed-rsa.xml"));
    let signed = sign(
        &unsigned,
        "_assert1",
        &credential("rsa"),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(check(&signed, "_assert1", "rsa"), Ok(()));
    let doubled = |open: &str, close: &str| {
        let start = signed.find(open).unwrap();
        let end = signed[start..].find(close).unwrap() + start + close.len();
        format!(
            "{}{}{}",
            &signed[..end],
            &signed[start..end],
            &signed[end..]
        )
    };
    for (what, text) in [
        ("SignedInfo", doubled("<SignedInfo>", "</SignedInfo>")),
        (
            "SignatureValue",
            doubled("<SignatureValue>", "</SignatureValue>"),
        ),
        ("Signature", doubled("<Signature ", "</Signature>")),
    ] {
        assert!(check(&text, "_assert1", "rsa").is_err(), "two {what}");
    }
}
