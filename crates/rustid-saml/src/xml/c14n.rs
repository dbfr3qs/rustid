//! Exclusive XML Canonicalization 1.0 (`xml-exc-c14n#`, with or without
//! comments) of an element subtree: the apex element and its descendants,
//! optionally without one descendant (an enveloped signature), with an
//! `InclusiveNamespaces` prefix list. Inclusive Canonical XML 1.0
//! (`REC-xml-c14n-20010315`, the default for `SignedInfo`) renders every
//! namespace in scope instead; it doesn't import ancestors' `xml:`
//! attributes, which no SAML message rustid canonicalizes inclusively has.

use std::collections::BTreeMap;

use super::dom::{Attr, Document, Element, Node, XML_NS};

pub struct Options<'a> {
    pub comments: bool,
    /// Prefixes rendered wherever in scope, as inclusive canonicalization
    /// would (`#default` for the default namespace).
    pub inclusive: &'a [String],
    /// A descendant left out, with its subtree, by its start offset.
    pub exclude: Option<usize>,
    /// Inclusive canonicalization: every namespace in scope is rendered.
    pub all_namespaces: bool,
}

/// The apex without context: nothing is imported from ancestors.
pub fn canonicalize(apex: &Element, options: &Options) -> String {
    let mut out = String::new();
    render(apex, &[], &BTreeMap::new(), options, &mut out);
    out
}

/// The apex in its document. As the transforms do (exclusive and
/// inclusive alike), the nearest ancestors' `xml:` attributes that the apex
/// doesn't carry are rendered on it.
pub fn canonicalize_in(doc: &Document, apex: &Element, options: &Options) -> String {
    let mut inherited: Vec<Attr> = Vec::new();
    let mut at = &doc.root;
    while at.start != apex.start {
        for a in at.attrs.iter().filter(|a| a.ns == XML_NS) {
            inherited.retain(|i| i.local != a.local);
            inherited.push(a.clone());
        }
        match at
            .elements()
            .find(|c| c.start <= apex.start && apex.end <= c.end)
        {
            Some(next) => at = next,
            None => break,
        }
    }
    inherited.retain(|i| {
        !apex
            .attrs
            .iter()
            .any(|a| a.ns == XML_NS && a.local == i.local)
    });
    let mut out = String::new();
    render(apex, &inherited, &BTreeMap::new(), options, &mut out);
    out
}

fn escape_text(text: &str, out: &mut String) {
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
}

fn escape_attr(text: &str, out: &mut String) {
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
}

/// `rendered`: the namespace declarations in effect in the output, by
/// prefix.
fn render(
    e: &Element,
    imported: &[Attr],
    rendered: &BTreeMap<String, String>,
    o: &Options,
    out: &mut String,
) {
    // The visibly utilized prefixes, and the listed ones in scope.
    let mut wanted: Vec<String> = vec![e.prefix.clone()];
    for a in &e.attrs {
        if !a.prefix.is_empty() && a.ns != XML_NS {
            wanted.push(a.prefix.clone());
        }
    }
    if o.all_namespaces {
        wanted.extend(e.scope.keys().cloned());
    }
    for p in o.inclusive {
        let p = if p == "#default" {
            String::new()
        } else {
            p.clone()
        };
        if e.scope.contains_key(&p) {
            wanted.push(p);
        }
    }
    wanted.sort();
    wanted.dedup();
    let mut now = rendered.clone();
    let mut decls = Vec::new();
    for p in wanted {
        if p == "xml" {
            continue;
        }
        let uri = e.scope.get(&p).cloned().unwrap_or_default();
        let shown = rendered.get(&p);
        // No default namespace, and none in effect in the output.
        if p.is_empty() && uri.is_empty() && shown.is_none_or(String::is_empty) {
            continue;
        }
        if shown != Some(&uri) {
            decls.push((p.clone(), uri.clone()));
            now.insert(p, uri);
        }
    }
    let qname = if e.prefix.is_empty() {
        e.local.clone()
    } else {
        format!("{}:{}", e.prefix, e.local)
    };
    out.push('<');
    out.push_str(&qname);
    for (p, uri) in &decls {
        if p.is_empty() {
            out.push_str(" xmlns=\"");
        } else {
            out.push_str(" xmlns:");
            out.push_str(p);
            out.push_str("=\"");
        }
        escape_attr(uri, out);
        out.push('"');
    }
    let mut attrs: Vec<_> = e.attrs.iter().chain(imported).collect();
    attrs.sort_by(|a, b| (&a.ns, &a.local).cmp(&(&b.ns, &b.local)));
    for a in attrs {
        out.push(' ');
        if !a.prefix.is_empty() {
            out.push_str(&a.prefix);
            out.push(':');
        }
        out.push_str(&a.local);
        out.push_str("=\"");
        escape_attr(&a.value, out);
        out.push('"');
    }
    out.push('>');
    for child in &e.children {
        match child {
            Node::Element(c) if Some(c.start) == o.exclude => {}
            Node::Element(c) => render(c, &[], &now, o, out),
            Node::Text(t) => escape_text(t, out),
            Node::Comment(c) if o.comments => {
                out.push_str("<!--");
                out.push_str(c);
                out.push_str("-->");
            }
            Node::Comment(_) => {}
            Node::Pi { target, data } => {
                out.push_str("<?");
                out.push_str(target);
                if !data.is_empty() {
                    out.push(' ');
                    out.push_str(data);
                }
                out.push_str("?>");
            }
        }
    }
    out.push_str("</");
    out.push_str(&qname);
    out.push('>');
}
