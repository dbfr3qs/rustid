//! A minimal XML tree for untrusted SAML messages. Safe by construction: no
//! DTDs (so no custom or external entities), bounded size, depth and
//! attribute count, and only UTF-8. Line endings and attribute values are
//! normalized as XML 1.0 requires, and every element keeps its byte span in
//! the normalized text, so a signature can be spliced in.

use std::collections::BTreeMap;
use std::rc::Rc;

use quick_xml::events::Event;
use quick_xml::reader::Reader;

pub const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";

/// A refused or malformed document.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct XmlError(pub String);

fn err(message: impl Into<String>) -> XmlError {
    XmlError(message.into())
}

/// What a parse accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Characters of input (`SamlOptions.MaxMessageSize`).
    pub max_size: usize,
    pub max_depth: usize,
    pub max_attributes: usize,
    /// Leave processing instructions out of the tree, as inbound
    /// messages are parsed.
    pub ignore_processing_instructions: bool,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_size: 1_048_576,
            max_depth: 64,
            max_attributes: 256,
            ignore_processing_instructions: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    Element(Element),
    Text(String),
    Comment(String),
    Pi { target: String, data: String },
}

/// Namespaces in scope: prefix (empty for the default) to URI (empty when
/// the default namespace is undeclared).
pub type Scope = Rc<BTreeMap<String, String>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attr {
    pub prefix: String,
    pub local: String,
    pub ns: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Element {
    pub prefix: String,
    pub local: String,
    pub ns: String,
    pub attrs: Vec<Attr>,
    pub scope: Scope,
    pub children: Vec<Node>,
    /// Byte offsets in [`Document::text`]: the start of the start tag, and
    /// just past the end tag.
    pub start: usize,
    pub end: usize,
}

impl Element {
    /// An unprefixed attribute's value.
    pub fn attr(&self, local: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|a| a.prefix.is_empty() && a.local == local)
            .map(|a| a.value.as_str())
    }

    pub fn elements(&self) -> impl Iterator<Item = &Element> {
        self.children.iter().filter_map(|c| match c {
            Node::Element(e) => Some(e),
            _ => None,
        })
    }

    pub fn child(&self, ns: &str, local: &str) -> Option<&Element> {
        self.elements().find(|e| e.ns == ns && e.local == local)
    }

    /// The element and every descendant element, in document order.
    pub fn descendants(&self) -> Vec<&Element> {
        let mut all = Vec::new();
        self.collect(&mut all);
        all
    }

    fn collect<'a>(&'a self, out: &mut Vec<&'a Element>) {
        out.push(self);
        for e in self.elements() {
            e.collect(out);
        }
    }

    /// The element's own text (not its descendants').
    pub fn text(&self) -> String {
        self.children
            .iter()
            .filter_map(|c| match c {
                Node::Text(t) => Some(t.as_str()),
                _ => None,
            })
            .collect()
    }
}

/// A parsed document: the normalized text the spans index, and its root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    pub text: String,
    pub root: Element,
}

/// XML 1.0 section 2.11: CRLF and lone CR become LF.
fn normalize_line_endings(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\r', "\n")
}

fn split(qname: &str) -> (String, String) {
    match qname.split_once(':') {
        Some((p, l)) => (p.to_owned(), l.to_owned()),
        None => (String::new(), qname.to_owned()),
    }
}

fn utf8(bytes: &[u8]) -> Result<&str, XmlError> {
    std::str::from_utf8(bytes).map_err(|e| err(e.to_string()))
}

fn unescape(text: &str) -> Result<String, XmlError> {
    quick_xml::escape::unescape(text)
        .map(|t| t.into_owned())
        .map_err(|e| err(format!("invalid entity or character reference: {e}")))
}

fn add_child(stack: &mut [Element], node: Node) {
    if let Some(parent) = stack.last_mut() {
        parent.children.push(node);
    }
}

pub fn parse(input: &str, limits: &Limits) -> Result<Document, XmlError> {
    if input.chars().count() > limits.max_size {
        return Err(err(format!(
            "the message exceeds the maximum size of {} characters",
            limits.max_size
        )));
    }
    let text = normalize_line_endings(input.strip_prefix('\u{feff}').unwrap_or(input));
    let root = parse_normalized(&text, limits)?;
    Ok(Document { text, root })
}

fn parse_normalized(text: &str, limits: &Limits) -> Result<Element, XmlError> {
    let mut reader = Reader::from_str(text);
    reader.config_mut().trim_text(false);
    reader.config_mut().check_end_names = true;
    let mut stack: Vec<Element> = Vec::new();
    let mut root: Option<Element> = None;
    let base: Scope = Rc::new(BTreeMap::from([("xml".to_owned(), XML_NS.to_owned())]));
    loop {
        let before = reader.buffer_position() as usize;
        let event = reader.read_event().map_err(|e| err(e.to_string()))?;
        let after = reader.buffer_position() as usize;
        match event {
            Event::DocType(_) => return Err(err("DTDs are not allowed")),
            Event::Decl(decl) => {
                if let Some(encoding) = decl.encoding() {
                    let encoding = encoding.map_err(|e| err(e.to_string()))?;
                    let name = utf8(&encoding)?.to_ascii_lowercase();
                    if name != "utf-8" && name != "utf8" {
                        return Err(err(format!("the encoding {name} is not supported")));
                    }
                }
            }
            Event::Start(_) | Event::Empty(_) if root.is_some() => {
                return Err(err("content after the document element"));
            }
            Event::Start(e) | Event::Empty(e) if stack.len() >= limits.max_depth => {
                let _ = e;
                return Err(err(format!(
                    "the document exceeds the maximum depth of {}",
                    limits.max_depth
                )));
            }
            ref ev @ (Event::Start(ref e) | Event::Empty(ref e)) => {
                let empty = matches!(ev, Event::Empty(_));
                let parent_scope = stack
                    .last()
                    .map(|p| p.scope.clone())
                    .unwrap_or(base.clone());
                let mut declared: Vec<(String, String)> = Vec::new();
                let mut raw_attrs = Vec::new();
                for a in e.attributes().with_checks(true) {
                    let a = a.map_err(|e| err(e.to_string()))?;
                    let key = utf8(a.key.as_ref())?.to_owned();
                    // Attribute-value normalization: literal whitespace
                    // becomes a space; character references stay.
                    let raw = utf8(&a.value)?.replace(['\t', '\n'], " ");
                    let value = unescape(&raw)?;
                    if key == "xmlns" {
                        declared.push((String::new(), value));
                    } else if let Some(p) = key.strip_prefix("xmlns:") {
                        if value.is_empty() {
                            return Err(err("namespace prefix undeclaration is not allowed"));
                        }
                        declared.push((p.to_owned(), value));
                    } else {
                        raw_attrs.push((key, value));
                    }
                }
                // Declarations count too: each widens every descendant's
                // scope.
                if raw_attrs.len() + declared.len() > limits.max_attributes {
                    return Err(err(format!(
                        "an element exceeds the maximum of {} attributes",
                        limits.max_attributes
                    )));
                }
                // An element that declares nothing shares its parent's
                // scope; copying it per element would cost memory
                // proportional to elements times namespaces.
                let scope: Scope = if declared.is_empty() {
                    parent_scope
                } else {
                    let mut scope = (*parent_scope).clone();
                    scope.extend(declared);
                    Rc::new(scope)
                };
                let qname = utf8(e.name().as_ref())?.to_owned();
                let (prefix, local) = split(&qname);
                let ns = scope.get(&prefix).cloned().unwrap_or_default();
                if !prefix.is_empty() && ns.is_empty() {
                    return Err(err(format!("undeclared prefix {prefix}")));
                }
                let mut attrs: Vec<Attr> = Vec::new();
                for (key, value) in raw_attrs {
                    let (p, l) = split(&key);
                    let ans = if p.is_empty() {
                        String::new()
                    } else {
                        scope
                            .get(&p)
                            .cloned()
                            .ok_or_else(|| err(format!("undeclared prefix {p}")))?
                    };
                    if attrs.iter().any(|x| x.local == l && x.ns == ans) {
                        return Err(err(format!("duplicate attribute {key}")));
                    }
                    attrs.push(Attr {
                        prefix: p,
                        local: l,
                        ns: ans,
                        value,
                    });
                }
                let element = Element {
                    prefix,
                    local,
                    ns,
                    attrs,
                    scope,
                    children: Vec::new(),
                    start: before,
                    end: after,
                };
                if empty {
                    match stack.last_mut() {
                        Some(p) => p.children.push(Node::Element(element)),
                        None => root = Some(element),
                    }
                } else {
                    stack.push(element);
                }
            }
            Event::End(_) => {
                let mut element = stack.pop().ok_or_else(|| err("unbalanced end tag"))?;
                element.end = after;
                match stack.last_mut() {
                    Some(p) => p.children.push(Node::Element(element)),
                    None => root = Some(element),
                }
            }
            Event::Text(t) => {
                let raw = utf8(&t)?;
                if stack.is_empty() {
                    if !raw.trim().is_empty() {
                        return Err(err(if root.is_some() {
                            "content after the document element"
                        } else {
                            "text outside the document element"
                        }));
                    }
                } else {
                    add_child(&mut stack, Node::Text(unescape(raw)?));
                }
            }
            Event::CData(c) => {
                if stack.is_empty() {
                    return Err(err("text outside the document element"));
                }
                add_child(&mut stack, Node::Text(utf8(&c)?.to_owned()));
            }
            Event::GeneralRef(r) => {
                if stack.is_empty() {
                    return Err(err("text outside the document element"));
                }
                let text = unescape(&format!("&{};", utf8(&r)?))?;
                add_child(&mut stack, Node::Text(text));
            }
            Event::Comment(c) => add_child(&mut stack, Node::Comment(utf8(&c)?.to_owned())),
            Event::PI(_) if limits.ignore_processing_instructions => {}
            Event::PI(pi) => {
                let raw = utf8(&pi)?;
                let (target, data) = match raw.split_once(char::is_whitespace) {
                    Some((t, d)) => (t.to_owned(), d.trim_start().to_owned()),
                    None => (raw.to_owned(), String::new()),
                };
                add_child(&mut stack, Node::Pi { target, data });
            }
            Event::Eof => break,
        }
    }
    if !stack.is_empty() {
        return Err(err("an element is not closed"));
    }
    let mut root = root.ok_or_else(|| err("no document element"))?;
    merge_text(&mut root);
    Ok(root)
}

/// Adjacent text, CDATA and references are one text node.
fn merge_text(e: &mut Element) {
    let mut merged: Vec<Node> = Vec::new();
    for child in std::mem::take(&mut e.children) {
        match (merged.last_mut(), child) {
            (Some(Node::Text(prev)), Node::Text(t)) => prev.push_str(&t),
            (_, Node::Element(mut c)) => {
                merge_text(&mut c);
                merged.push(Node::Element(c));
            }
            (_, other) => merged.push(other),
        }
    }
    e.children = merged;
}
