//! `XmlTraverser` over the safe DOM: a cursor over one level of
//! sibling nodes that records errors, including the rule
//! that every element's children must be processed.
//!
//! Where a malformed document can't be read as a protocol error (a null
//! dereference after unprocessed root children, an incomplete traversal,
//! an integer overflow), the traversal fails with [`Unhandled`]: the
//! endpoint answers 500, as an unhandled exception does.

use std::cell::RefCell;
use std::rc::Rc;

use chrono::{DateTime, NaiveDateTime, Utc};

use super::dom::{Element, Node};

/// A failure the endpoints don't handle (a 500).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unhandled(pub String);

pub type Errors = Rc<RefCell<Vec<String>>>;

#[derive(Clone, Copy)]
enum Current<'a> {
    Element(&'a Element),
    Other,
    None,
}

pub struct Traverser<'a> {
    nodes: Vec<&'a Node>,
    /// Index of the current node; `None` before the first.
    pos: Option<usize>,
    current: Current<'a>,
    children_handled: bool,
    /// The element whose children this level holds (for messages); `None`
    /// at the root.
    parent: Option<&'a Element>,
    /// Set when this level reached its end (then the parent's
    /// children handled); see [`Traverser::absorb`].
    reached_end: bool,
    pub errors: Errors,
}

fn qualified(e: &Element) -> String {
    if e.prefix.is_empty() {
        e.local.clone()
    } else {
        format!("{}:{}", e.prefix, e.local)
    }
}

fn is_xml_whitespace(text: &str) -> bool {
    text.chars().all(|c| matches!(c, ' ' | '\t' | '\r' | '\n'))
}

impl<'a> Traverser<'a> {
    /// A traverser positioned on the document element.
    pub fn root(root: &'a Element) -> Self {
        Traverser {
            nodes: Vec::new(),
            pos: Some(0),
            current: Current::Element(root),
            children_handled: root.children.is_empty(),
            parent: None,
            reached_end: false,
            errors: Rc::default(),
        }
    }

    pub fn current(&self) -> Option<&'a Element> {
        match self.current {
            Current::Element(e) => Some(e),
            _ => None,
        }
    }

    fn error(&self, message: String) {
        self.errors.borrow_mut().push(message);
    }

    /// `GetChildren`: a traverser before the current element's first child.
    pub fn children(&self) -> Traverser<'a> {
        let element = self.current().expect("children of an element");
        Traverser {
            nodes: element.children.iter().collect(),
            pos: None,
            current: Current::None,
            children_handled: true,
            parent: Some(element),
            reached_end: false,
            errors: self.errors.clone(),
        }
    }

    /// When a child traverser reaches its end, the
    /// parent's current element counts as processed.
    pub fn absorb(&mut self, child: &Traverser<'a>) {
        if child.reached_end {
            self.children_handled = true;
        }
    }

    /// `MoveNext`: to the next element, skipping whitespace and comments.
    pub fn move_next(&mut self, expect_end: bool) -> Result<bool, Unhandled> {
        loop {
            if !self.children_handled {
                match self.current {
                    Current::Element(e) if !e.children.is_empty() => self.error(format!(
                        "All child nodes under {} have not been processed.",
                        e.local
                    )),
                    Current::None => {
                        return Err(Unhandled(
                            "NullReferenceException in XmlTraverser.MoveNext".into(),
                        ));
                    }
                    _ => {}
                }
            }
            let next = match (self.parent, self.pos) {
                // The root has no siblings.
                (None, _) => None,
                (Some(_), None) => Some(0),
                (Some(_), Some(i)) => Some(i + 1),
            };
            let node = next.and_then(|i| self.nodes.get(i).copied());
            self.pos = next;
            let Some(node) = node else {
                self.current = Current::None;
                if !expect_end {
                    let parent = self.parent.map(|p| p.local.clone()).ok_or_else(|| {
                        Unhandled("NullReferenceException in XmlTraverser.MoveNext".into())
                    })?;
                    self.error(format!(
                        "There should be a child element here under {parent}, but found none."
                    ));
                }
                self.reached_end = true;
                return Ok(false);
            };
            match node {
                Node::Element(e) => {
                    self.current = Current::Element(e);
                    self.children_handled = e.children.is_empty();
                    return Ok(true);
                }
                Node::Text(t) if is_xml_whitespace(t) => self.current = Current::Other,
                Node::Comment(_) => self.current = Current::Other,
                Node::Text(_) => {
                    self.current = Current::Other;
                    self.error("Unsupported node type Text.".into());
                }
                Node::Pi { .. } => {
                    self.current = Current::Other;
                    self.error("Unsupported node type ProcessingInstruction.".into());
                }
            }
        }
    }

    /// The `ThrowOnErrors` precondition: the root traverser must have
    /// moved past the document element.
    pub fn finish(&self) -> Result<Vec<String>, Unhandled> {
        if !matches!(self.current, Current::None) {
            return Err(Unhandled(
                "InvalidOperationException: the traversal did not complete".into(),
            ));
        }
        Ok(self.errors.borrow().clone())
    }

    pub fn ignore_children(&mut self) {
        self.children_handled = true;
    }

    pub fn has_name(&self, local: &str, ns: &str) -> bool {
        self.current()
            .is_some_and(|e| e.local == local && e.ns == ns)
    }

    /// `EnsureName`.
    pub fn ensure_name(&self, local: &str, ns: &str) -> bool {
        let Some(e) = self.current() else {
            return false;
        };
        let mut ok = true;
        if e.ns != ns {
            self.error(format!(
                "Unexpected namespace \"{}\" for local name \"{}\", expected \"{ns}\".",
                e.ns,
                qualified(e)
            ));
            ok = false;
        }
        if e.local != local {
            self.error(format!(
                "Unexpected node name \"{}\", expected \"{local}\".",
                e.local
            ));
            return false;
        }
        ok
    }

    /// `GetTextContents`: the element's `InnerText`; only text, whitespace
    /// and comments may be inside.
    pub fn text_contents(&mut self) -> String {
        self.ignore_children();
        let e = self.current().expect("text of an element");
        for child in &e.children {
            match child {
                Node::Text(_) | Node::Comment(_) => {}
                Node::Element(c) => self.error(format!(
                    "Element \"{}\" should only contain text but has unexpected child element \"{}\".",
                    e.local, c.local
                )),
                Node::Pi { .. } => self.error(format!(
                    "Element \"{}\" should only contain text but has unsupported child node of type \"ProcessingInstruction\".",
                    e.local
                )),
            }
        }
        inner_text(e)
    }

    /// `GetAbsoluteUriContents`.
    pub fn absolute_uri_contents(&mut self) -> String {
        let value = self.text_contents();
        let local = self.current().map(|e| e.local.clone()).unwrap_or_default();
        if value.is_empty() {
            self.error(format!(
                "Contents of element \"{local}\" should be an absolute URI, but element is empty."
            ));
        } else if !is_absolute_uri(&value) {
            self.error(format!(
                "Contents of element \"{local}\" should be an absolute URI, but \"{value}\" isn't."
            ));
        }
        value
    }

    /// An unprefixed attribute (`GetNamedItem(localName)` matches the
    /// qualified name, so a prefixed attribute doesn't count).
    pub fn attribute(&self, name: &str) -> Option<String> {
        self.current()?
            .attrs
            .iter()
            .find(|a| a.prefix.is_empty() && a.local == name)
            .map(|a| a.value.clone())
    }

    pub fn required_attribute(&self, name: &str) -> Option<String> {
        let e = self.current()?;
        let value = self.attribute(name);
        if value.is_none() {
            self.error(format!(
                "Required attribute {name} not found on {}.",
                qualified(e)
            ));
        }
        value
    }

    fn check_absolute_uri(&self, name: &str, value: Option<String>) -> Option<String> {
        if let Some(v) = &value
            && !is_absolute_uri(v)
        {
            self.error(format!(
                "Attribute \"{name}\" should be an absolute Uri, but \"{v}\" isn't."
            ));
        }
        value
    }

    pub fn absolute_uri_attribute(&self, name: &str) -> Option<String> {
        self.check_absolute_uri(name, self.attribute(name))
    }

    pub fn required_absolute_uri_attribute(&self, name: &str) -> Option<String> {
        self.check_absolute_uri(name, self.required_attribute(name))
    }

    fn conversion_failed(&self, type_name: &str, value: &str) {
        self.error(format!("Conversion to {type_name} failed for {value}."));
    }

    pub fn datetime_attribute(&self, name: &str) -> Option<DateTime<Utc>> {
        let value = self.attribute(name)?;
        let parsed = parse_xs_datetime(&value);
        if parsed.is_none() {
            self.conversion_failed("DateTimeUtc", &value);
        }
        parsed
    }

    pub fn required_datetime_attribute(&self, name: &str) -> Option<DateTime<Utc>> {
        let value = self.required_attribute(name)?;
        let parsed = parse_xs_datetime(&value);
        if parsed.is_none() {
            self.conversion_failed("DateTimeUtc", &value);
        }
        parsed
    }

    pub fn bool_attribute(&self, name: &str) -> Option<bool> {
        let value = self.attribute(name)?;
        match value.trim_matches(|c| matches!(c, ' ' | '\t' | '\r' | '\n')) {
            "true" | "1" => Some(true),
            "false" | "0" => Some(false),
            _ => {
                self.conversion_failed("Boolean", &value);
                None
            }
        }
    }

    /// `int.Parse`: surrounding whitespace and a sign allowed; an overflow
    /// is an unhandled failure.
    pub fn int_attribute(&self, name: &str) -> Result<Option<i32>, Unhandled> {
        let Some(value) = self.attribute(name) else {
            return Ok(None);
        };
        let trimmed = value.trim();
        let digits = trimmed.strip_prefix(['+', '-']).unwrap_or(trimmed);
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            self.conversion_failed("Int32", &value);
            return Ok(None);
        }
        match trimmed.parse::<i32>() {
            Ok(n) => Ok(Some(n)),
            Err(_) => Err(Unhandled(format!(
                "OverflowException: {name} {value} is outside Int32"
            ))),
        }
    }
}

/// `XmlNode.InnerText`: the text of every descendant text node, in order.
pub fn inner_text(e: &Element) -> String {
    let mut out = String::new();
    for child in &e.children {
        match child {
            Node::Text(t) => out.push_str(t),
            Node::Element(c) => out.push_str(&inner_text(c)),
            _ => {}
        }
    }
    out
}

/// `Uri.TryCreate(value, UriKind.Absolute)`, near enough: a scheme and
/// something after it.
pub fn is_absolute_uri(value: &str) -> bool {
    url::Url::parse(value).is_ok()
}

/// `XmlConvert.ToDateTime(value, XmlDateTimeSerializationMode.Utc)` for
/// xs:dateTime: up to seven fraction digits; `Z`, an offset, or no zone
/// (taken as UTC). Surrounding whitespace is allowed.
pub fn parse_xs_datetime(value: &str) -> Option<DateTime<Utc>> {
    let value = value.trim_matches(|c| matches!(c, ' ' | '\t' | '\r' | '\n'));
    if let Ok(t) = DateTime::parse_from_rfc3339(value) {
        let fraction = value
            .split_once('.')
            .map(|(_, f)| f.chars().take_while(char::is_ascii_digit).count())
            .unwrap_or(0);
        return (fraction <= 7 && value.as_bytes().get(10) == Some(&b'T'))
            .then(|| t.with_timezone(&Utc));
    }
    let fraction = value.split_once('.').map(|(_, f)| f.len()).unwrap_or(0);
    if fraction > 7 {
        return None;
    }
    NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S%.f")
        .ok()
        .map(|t| t.and_utc())
}
