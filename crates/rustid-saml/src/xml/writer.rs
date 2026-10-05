//! Builds XML and serializes it, which
//! is what the SAML IdP sends: attributes in insertion order,
//! each namespace declared after the attributes of the first element that
//! needs it, and empty elements written `<x />`.
//!
//! Text CR (and CRLF) becomes LF, and an attribute TAB a space: some writers write
//! both raw, and its verifier then disagrees with the XML-DSig spec over
//! them (5a's interop ruling).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XmlElement {
    pub prefix: String,
    pub local: String,
    pub ns: String,
    /// Unprefixed attributes, in order.
    pub attrs: Vec<(String, String)>,
    pub children: Vec<XmlChild>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum XmlChild {
    Element(XmlElement),
    Text(String),
}

impl XmlElement {
    pub fn new(prefix: &str, local: &str, ns: &str) -> Self {
        XmlElement {
            prefix: prefix.into(),
            local: local.into(),
            ns: ns.into(),
            attrs: Vec::new(),
            children: Vec::new(),
        }
    }

    pub fn attr(mut self, name: &str, value: impl Into<String>) -> Self {
        self.attrs.push((name.into(), value.into()));
        self
    }

    /// The attribute when there's a value.
    pub fn attr_opt(self, name: &str, value: Option<impl Into<String>>) -> Self {
        match value {
            Some(v) => self.attr(name, v),
            None => self,
        }
    }

    pub fn child(mut self, element: XmlElement) -> Self {
        self.children.push(XmlChild::Element(element));
        self
    }

    pub fn children(mut self, elements: impl IntoIterator<Item = XmlElement>) -> Self {
        self.children
            .extend(elements.into_iter().map(XmlChild::Element));
        self
    }

    /// A text child; an empty one still writes an end tag.
    pub fn text(mut self, text: impl Into<String>) -> Self {
        self.children.push(XmlChild::Text(text.into()));
        self
    }
}

/// The element serialized as XML.
pub fn write(root: &XmlElement) -> String {
    let mut out = String::new();
    write_element(root, &BTreeMap::new(), &mut out);
    out
}

fn write_element(e: &XmlElement, scope: &BTreeMap<String, String>, out: &mut String) {
    let name = if e.prefix.is_empty() {
        e.local.clone()
    } else {
        format!("{}:{}", e.prefix, e.local)
    };
    out.push('<');
    out.push_str(&name);
    for (attr, value) in &e.attrs {
        out.push(' ');
        out.push_str(attr);
        out.push_str("=\"");
        escape_attr(value, out);
        out.push('"');
    }
    let in_scope = scope.get(&e.prefix).map(String::as_str).unwrap_or("");
    let mut inner = scope.clone();
    if in_scope != e.ns {
        if e.prefix.is_empty() {
            out.push_str(" xmlns=\"");
        } else {
            out.push_str(" xmlns:");
            out.push_str(&e.prefix);
            out.push_str("=\"");
        }
        escape_attr(&e.ns, out);
        out.push('"');
        inner.insert(e.prefix.clone(), e.ns.clone());
    }
    if e.children.is_empty() {
        out.push_str(" />");
        return;
    }
    out.push('>');
    for child in &e.children {
        match child {
            XmlChild::Element(c) => write_element(c, &inner, out),
            XmlChild::Text(t) => escape_text(t, out),
        }
    }
    out.push_str("</");
    out.push_str(&name);
    out.push('>');
}

fn escape_text(text: &str, out: &mut String) {
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                out.push('\n');
            }
            c => out.push(c),
        }
    }
}

fn escape_attr(value: &str, out: &mut String) {
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            '\t' => out.push(' '),
            c => out.push(c),
        }
    }
}
