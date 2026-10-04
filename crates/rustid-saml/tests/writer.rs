//! The XML writer serializes exactly (what the
//! SAML IdP sends).

use rustid_saml::ids::create_id;
use rustid_saml::xml::writer::{XmlElement, write};

#[test]
fn namespaces_are_declared_after_attributes_where_first_needed() {
    let tree = XmlElement::new("md", "A", "urn:md")
        .attr("ID", "x")
        .child(XmlElement::new("md", "B", "urn:md"))
        .child(
            XmlElement::new("ds", "K", "urn:ds")
                .child(XmlElement::new("ds", "X", "urn:ds").text("")),
        )
        .child(XmlElement::new("", "N", "urn:n").attr("a", "1"))
        .child(XmlElement::new("", "E", ""));
    assert_eq!(
        write(&tree),
        r#"<md:A ID="x" xmlns:md="urn:md"><md:B /><ds:K xmlns:ds="urn:ds"><ds:X></ds:X></ds:K><N a="1" xmlns="urn:n" /><E /></md:A>"#
    );
}

#[test]
fn an_undeclared_default_namespace_is_reset_inside_a_default_one() {
    let tree = XmlElement::new("", "N", "urn:n").child(XmlElement::new("", "E", ""));
    assert_eq!(write(&tree), r#"<N xmlns="urn:n"><E xmlns="" /></N>"#);
}

#[test]
fn escaping_is_exact() {
    let tree = XmlElement::new("", "A", "")
        .attr("b", "a&b<c>d\"e'f\ng")
        .text("t&<>\"'\n x");
    assert_eq!(
        write(&tree),
        "<A b=\"a&amp;b&lt;c&gt;d&quot;e'f&#xA;g\">t&amp;&lt;&gt;\"'\n x</A>"
    );
}

#[test]
fn text_cr_and_attribute_tab_are_normalized() {
    // Some writers write both raw, and their verifiers then disagree with the
    // XML-DSig spec over them (5a's interop ruling); the writer avoids them.
    let tree = XmlElement::new("", "A", "")
        .attr("b", "x\ty\r\nz")
        .text("one\r\ntwo\rthree");
    assert_eq!(write(&tree), "<A b=\"x y&#xD;&#xA;z\">one\ntwo\nthree</A>");
}

#[test]
fn ids_have_their_shape() {
    for _ in 0..200 {
        let id = create_id();
        assert_eq!(id.len(), 27, "{id}");
        let first = id.chars().next().unwrap();
        assert!(
            first.is_ascii_uppercase() || ('a'..='f').contains(&first),
            "starts with a letter: {id}"
        );
        assert!(
            id.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "{id}"
        );
    }
    assert_ne!(create_id(), create_id());
}
