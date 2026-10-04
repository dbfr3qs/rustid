//! The SAML XML parser: safe by construction (no DTDs, bounded size, depth
//! and attributes) and normalizing as XML 1.0 requires.

use rustid_saml::xml::dom::{Limits, Node, parse};

fn refuses(xml: &str, needle: &str) {
    let err = parse(xml, &Limits::default()).unwrap_err().to_string();
    assert!(err.contains(needle), "{xml}: {err}");
}

#[test]
fn unsafe_and_malformed_documents_are_refused() {
    refuses("<!DOCTYPE r [<!ENTITY x \"y\">]><r>&x;</r>", "DTD");
    refuses("<r>&unknown;</r>", "entity");
    refuses("<p:r/>", "undeclared prefix p");
    refuses("<r xmlns:p=\"\"/>", "undeclaration");
    refuses("<r a=\"1\" a=\"2\"/>", "duplicate");
    refuses(
        "<r xmlns:a=\"urn:x\" xmlns:b=\"urn:x\" a:k=\"1\" b:k=\"2\"/>",
        "duplicate",
    );
    refuses("<r/><s/>", "after the document element");
    refuses("text<r/>", "outside the document element");
    refuses("<r><a></r>", "");
    refuses("", "no document element");
    refuses(
        "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><r/>",
        "encoding",
    );
}

#[test]
fn limits_are_enforced() {
    let limits = Limits {
        max_size: 100,
        max_depth: 3,
        max_attributes: 2,
        ..Limits::default()
    };
    let err = |xml: &str| parse(xml, &limits).unwrap_err().to_string();
    assert!(err(&format!("<r>{}</r>", "x".repeat(200))).contains("size"));
    assert!(err("<a><b><c><d/></c></b></a>").contains("depth"));
    assert!(err("<r a=\"1\" b=\"2\" c=\"3\"/>").contains("attributes"));
    assert!(parse("<a><b><c/></b></a>", &limits).is_ok());
    let defaults = Limits::default();
    assert_eq!(
        (
            defaults.max_size,
            defaults.max_depth,
            defaults.max_attributes
        ),
        (1_048_576, 64, 256)
    );
}

#[test]
fn line_endings_and_attribute_values_are_normalized() {
    let doc = parse(
        "<r a=\"x\r\n\ty&#13;&#10;&#9;z\">one\r\ntwo\rthree &#13;</r>",
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(doc.root.attr("a"), Some("x  y\r\n\tz"));
    assert_eq!(doc.root.text(), "one\ntwo\nthree \r");
}

#[test]
fn text_cdata_and_references_merge_and_a_bom_is_skipped() {
    let doc = parse(
        "\u{feff}<?xml version=\"1.0\" encoding=\"utf-8\"?><r>a<![CDATA[<b>]]>&amp;&#x41;<!--c--><?p d?></r>",
        &Limits::default(),
    )
    .unwrap();
    assert!(matches!(&doc.root.children[0], Node::Text(t) if t == "a<b>&A"));
    assert!(matches!(&doc.root.children[1], Node::Comment(c) if c == "c"));
    assert!(
        matches!(&doc.root.children[2], Node::Pi { target, data } if target == "p" && data == "d")
    );
}

#[test]
fn namespaces_resolve_through_scopes() {
    let doc = parse(
        "<a:r xmlns:a=\"urn:a\" xmlns=\"urn:d\"><c a:x=\"1\" y=\"2\"><d xmlns=\"\"/></c></a:r>",
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(
        (doc.root.ns.as_str(), doc.root.local.as_str()),
        ("urn:a", "r")
    );
    let c = doc.root.elements().next().unwrap();
    assert_eq!(c.ns, "urn:d");
    assert_eq!(c.attrs[0].ns, "urn:a");
    assert_eq!(c.attrs[1].ns, "", "unprefixed attributes have no namespace");
    let d = c.elements().next().unwrap();
    assert_eq!(d.ns, "");
}

#[test]
fn element_spans_splice_into_the_normalized_text() {
    let doc = parse("<r>\r\n<a x=\"1\">t</a><b/></r>", &Limits::default()).unwrap();
    let a = doc.root.elements().next().unwrap();
    assert_eq!(&doc.text[a.start..a.end], "<a x=\"1\">t</a>");
    let b = doc.root.elements().nth(1).unwrap();
    assert_eq!(&doc.text[b.start..b.end], "<b/>");
}

#[test]
fn processing_instructions_can_be_dropped() {
    let limits = Limits {
        ignore_processing_instructions: true,
        ..Limits::default()
    };
    let doc = parse("<r><?pi x?><a/></r>", &limits).unwrap();
    assert_eq!(doc.root.children.len(), 1);
    let kept = parse("<r><?pi x?><a/></r>", &Limits::default()).unwrap();
    assert_eq!(kept.root.children.len(), 2);
}

#[test]
fn namespace_scopes_are_shared_and_declarations_count_as_attributes() {
    // Many declarations on the root and many children: each child without
    // declarations shares its parent's scope instead of copying it.
    let decls: String = (0..50)
        .map(|i| format!(" xmlns:n{i}=\"urn:{i}\""))
        .collect();
    let children = "<c/>".repeat(1000);
    let doc = parse(&format!("<r{decls}>{children}</r>"), &Limits::default()).unwrap();
    for child in doc.root.elements() {
        assert!(std::rc::Rc::ptr_eq(&child.scope, &doc.root.scope));
    }
    let limits = Limits {
        max_attributes: 3,
        ..Limits::default()
    };
    let err = parse(
        "<r xmlns:a=\"urn:a\" xmlns:b=\"urn:b\" xmlns:c=\"urn:c\" x=\"1\"/>",
        &limits,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("attributes"), "{err}");
}
