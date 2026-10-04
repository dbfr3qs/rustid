//! SAML for tests: requests built as an SP builds them
//! (signed with the fixture SP key), the IdP's messages decoded from
//! redirects and auto-post forms, and SAML XML masked for comparison.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::{DateTime, Utc};
use rustid_saml::bindings::{MessageName, redirect};
use rustid_saml::constants::{NS_ASSERTION, NS_PROTOCOL};
use rustid_saml::xml::dom::{self, Limits};
use rustid_saml::xml::dsig::{self, Credential};
use rustid_saml::xml::writer::{XmlElement, write};

use crate::normalize::MASK;

/// Attributes whose values vary per message (ids and instants).
pub const MASKED_ATTRIBUTES: &[&str] = &[
    "ID",
    "InResponseTo",
    "IssueInstant",
    "validUntil",
    "NotBefore",
    "NotOnOrAfter",
    "AuthnInstant",
    "SessionIndex",
];
/// Elements whose text varies per message.
pub const MASKED_ELEMENTS: &[&str] = &["SignatureValue", "DigestValue", "SessionIndex"];

/// The fixture SP's signing credential (`fixtures/saml/sp`).
pub fn sp_credential() -> Credential {
    let read = |name: &str| std::fs::read_to_string(crate::fixture(name)).expect("fixture");
    Credential::from_pem(
        &read("saml/sp/sp-signing.cert.pem"),
        &read("saml/sp/sp-signing.key.pem"),
    )
    .expect("the fixture SP credential")
}

/// Whether a body is SAML XML (rather than HTML or JSON).
pub fn is_saml_xml(text: &str) -> bool {
    let text = text.trim_start();
    text.starts_with('<')
        && !text.starts_with("<!")
        && !text.to_ascii_lowercase().starts_with("<html")
        && text.contains("urn:oasis:names:tc:SAML:")
}

/// Masks [`MASKED_ATTRIBUTES`], the `#id` of signature references and the
/// text of [`MASKED_ELEMENTS`]; everything else is kept byte for byte.
pub fn mask_saml_xml(xml: &str) -> String {
    let mut out = xml.to_owned();
    for attr in MASKED_ATTRIBUTES {
        out = replace_values(&out, &format!(" {attr}=\""), "\"", MASK);
    }
    out = replace_values(&out, " URI=\"#", "\"", MASK);
    mask_element_text(&out)
}

/// Replaces the text of each [`MASKED_ELEMENTS`] element (any prefix, any
/// attributes): only after its start tag, never after its end tag.
fn mask_element_text(xml: &str) -> String {
    let mut out = String::with_capacity(xml.len());
    let mut rest = xml;
    while let Some(i) = rest.find('<') {
        let Some(close) = rest[i..].find('>').map(|c| i + c) else {
            break;
        };
        let tag = &rest[i + 1..close];
        let name = tag
            .split(|c: char| c.is_whitespace() || c == '/')
            .next()
            .unwrap_or("");
        let local = name.rsplit(':').next().unwrap_or(name);
        let opening = !tag.starts_with('/') && !tag.ends_with('/');
        out.push_str(&rest[..=close]);
        rest = &rest[close + 1..];
        if opening && MASKED_ELEMENTS.contains(&local) {
            let len = rest.find('<').unwrap_or(rest.len());
            out.push_str(MASK);
            rest = &rest[len..];
        }
    }
    out.push_str(rest);
    out
}

/// Replaces the text between each `start` and the next `end` after it.
fn replace_values(text: &str, start: &str, end: &str, with: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find(start) {
        let from = i + start.len();
        let Some(len) = rest[from..].find(end) else {
            break;
        };
        out.push_str(&rest[..from]);
        out.push_str(with);
        rest = &rest[from + len..];
    }
    out.push_str(rest);
    out
}

/// Verifies every enveloped signature in the document against the
/// certificates (DER), as an SP would: how many there were, or the first
/// failure. Run before masking, so masking never hides a bad signature.
pub fn verify_saml_signatures(xml: &str, certificates: &[Vec<u8>]) -> Result<usize, String> {
    let doc = dom::parse(xml, &Limits::default()).map_err(|e| e.to_string())?;
    let mut count = 0;
    for element in doc.root.descendants() {
        if element.child(dsig::DSIG, "Signature").is_some() {
            dsig::verify(&doc, element, certificates, dsig::DEFAULT_ALLOWED)?;
            count += 1;
        }
    }
    Ok(count)
}

/// A message decoded from an HTTP-Redirect URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedirectMessage {
    /// `SAMLRequest` or `SAMLResponse`.
    pub name: String,
    pub xml: String,
    pub relay_state: Option<String>,
    pub sig_alg: Option<String>,
    pub signed: bool,
}

/// The SAML message in a redirect URL's query, if there is one.
pub fn decode_redirect(url: &str) -> Option<RedirectMessage> {
    let query = url.split_once('?')?.1;
    let query = query.split('#').next().unwrap_or(query);
    let parsed = redirect::parse(query, 1 << 24, usize::MAX).ok()?;
    Some(RedirectMessage {
        name: parsed.name.as_str().to_owned(),
        xml: parsed.xml,
        relay_state: parsed.relay_state,
        sig_alg: parsed.sig_alg,
        signed: parsed.signature.is_some(),
    })
}

/// A SAML message in an auto-post HTML form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostForm {
    pub action: String,
    /// `SAMLRequest` or `SAMLResponse`.
    pub name: String,
    pub xml: String,
    pub relay_state: Option<String>,
}

/// The SAML message in an auto-post form, if the page has one.
pub fn decode_post_form(html: &str) -> Option<PostForm> {
    let (name, encoded) = ["SAMLResponse", "SAMLRequest"]
        .into_iter()
        .find_map(|name| input_value(html, name).map(|v| (name, v)))?;
    let xml = String::from_utf8(STANDARD.decode(encoded.trim()).ok()?).ok()?;
    let action = attribute(&html[html.find("<form")?..], "action")?;
    Some(PostForm {
        action: html_unescape(&action),
        name: name.to_owned(),
        xml,
        relay_state: input_value(html, "RelayState").map(|v| html_unescape(&v)),
    })
}

/// The `value` of the `<input>` named `name`, raw.
pub(crate) fn input_value(html: &str, name: &str) -> Option<String> {
    input_value_span(html, name).map(|(start, end)| html[start..end].to_owned())
}

/// The byte range of the `value` of the `<input>` named `name`.
pub(crate) fn input_value_span(html: &str, name: &str) -> Option<(usize, usize)> {
    let mut from = 0;
    while let Some(i) = html[from..].find("<input") {
        let start = from + i;
        let end = start + html[start..].find('>')?;
        let tag = &html[start..end];
        if attribute(tag, "name").as_deref() == Some(name) {
            for quote in ['"', '\''] {
                let marker = format!("value={quote}");
                if let Some(v) = tag.find(&marker) {
                    let value_start = start + v + marker.len();
                    let len = html[value_start..].find(quote)?;
                    return Some((value_start, value_start + len));
                }
            }
        }
        from = end;
    }
    None
}

fn attribute(tag: &str, name: &str) -> Option<String> {
    for quote in ['"', '\''] {
        let marker = format!(" {name}={quote}");
        if let Some(i) = tag.find(&marker) {
            let start = i + marker.len();
            let len = tag[start..].find(quote)?;
            return Some(tag[start..start + len].to_owned());
        }
    }
    None
}

fn html_unescape(text: &str) -> String {
    text.replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&#x27;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

pub(crate) fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// An HTTP-Redirect URL carrying `xml` as `name` (`SAMLRequest` or
/// `SAMLResponse`), signed over the query when `signer` is given.
pub fn redirect_url(
    endpoint: &str,
    name: &str,
    xml: &str,
    relay_state: Option<&str>,
    signer: Option<&Credential>,
) -> String {
    let name = if name == "SAMLResponse" {
        MessageName::SamlResponse
    } else {
        MessageName::SamlRequest
    };
    let signer = signer.map(|s| s as &dyn rustid_saml::xml::dsig::XmlSigner);
    let query = redirect::encode(name, xml, relay_state, signer).expect("encodes");
    format!("{endpoint}{query}")
}

/// An HTTP-POST form body (`application/x-www-form-urlencoded`) carrying
/// `xml` as `name`, with an enveloped signature on its root when `signer`
/// is given; also the XML as sent.
pub fn post_form(
    name: &str,
    xml: &str,
    relay_state: Option<&str>,
    signer: Option<&Credential>,
) -> (String, String) {
    let xml = match signer {
        Some(signer) => {
            let id = attribute(xml, "ID").expect("the message has an ID");
            dsig::sign(xml, &id, signer, &Limits::default()).expect("signs")
        }
        None => xml.to_owned(),
    };
    let mut form = url::form_urlencoded::Serializer::new(String::new());
    form.append_pair(name, &STANDARD.encode(&xml));
    if let Some(relay_state) = relay_state {
        form.append_pair("RelayState", relay_state);
    }
    (form.finish(), xml)
}

fn instant(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn issuer(entity_id: &str) -> XmlElement {
    XmlElement::new("saml", "Issuer", NS_ASSERTION).text(entity_id)
}

/// An `AuthnRequest` as an SP sends it; unset fields are left out.
#[derive(Debug, Clone)]
pub struct AuthnRequest {
    pub id: String,
    pub issue_instant: DateTime<Utc>,
    pub issuer: String,
    pub destination: Option<String>,
    pub acs_url: Option<String>,
    pub acs_index: Option<u32>,
    pub protocol_binding: Option<String>,
    pub force_authn: Option<bool>,
    pub is_passive: Option<bool>,
    pub name_id_format: Option<String>,
    pub allow_create: Option<bool>,
    /// Comparison and class references.
    pub requested_authn_context: Option<(Option<String>, Vec<String>)>,
}

impl AuthnRequest {
    /// A request from `issuer`, with a fresh id, issued now.
    pub fn new(issuer: &str) -> Self {
        AuthnRequest {
            id: format!("_{}", rustid_saml::ids::create_id()),
            issue_instant: Utc::now(),
            issuer: issuer.to_owned(),
            destination: None,
            acs_url: None,
            acs_index: None,
            protocol_binding: None,
            force_authn: None,
            is_passive: None,
            name_id_format: None,
            allow_create: None,
            requested_authn_context: None,
        }
    }

    pub fn to_xml(&self) -> String {
        let samlp = |local: &str| XmlElement::new("samlp", local, NS_PROTOCOL);
        let mut root = samlp("AuthnRequest")
            .attr("ID", self.id.as_str())
            .attr("Version", "2.0")
            .attr("IssueInstant", instant(self.issue_instant))
            .attr_opt("Destination", self.destination.as_deref())
            .attr_opt("AssertionConsumerServiceURL", self.acs_url.as_deref())
            .attr_opt(
                "AssertionConsumerServiceIndex",
                self.acs_index.map(|i| i.to_string()),
            )
            .attr_opt("ProtocolBinding", self.protocol_binding.as_deref())
            .attr_opt("ForceAuthn", self.force_authn.map(|b| b.to_string()))
            .attr_opt("IsPassive", self.is_passive.map(|b| b.to_string()))
            .child(issuer(&self.issuer));
        if self.name_id_format.is_some() || self.allow_create.is_some() {
            root = root.child(
                samlp("NameIDPolicy")
                    .attr_opt("Format", self.name_id_format.as_deref())
                    .attr_opt("AllowCreate", self.allow_create.map(|b| b.to_string())),
            );
        }
        if let Some((comparison, classes)) = &self.requested_authn_context {
            root = root.child(
                samlp("RequestedAuthnContext")
                    .attr_opt("Comparison", comparison.as_deref())
                    .children(classes.iter().map(|c| {
                        XmlElement::new("saml", "AuthnContextClassRef", NS_ASSERTION)
                            .text(c.as_str())
                    })),
            );
        }
        write(&root)
    }
}

/// A `LogoutRequest` as an SP sends it.
#[derive(Debug, Clone)]
pub struct LogoutRequest {
    pub id: String,
    pub issue_instant: DateTime<Utc>,
    pub issuer: String,
    pub destination: Option<String>,
    pub name_id: String,
    pub name_id_format: Option<String>,
    pub session_index: Option<String>,
}

impl LogoutRequest {
    /// A request from `issuer`, with a fresh id, issued now.
    pub fn new(issuer: &str) -> Self {
        LogoutRequest {
            id: format!("_{}", rustid_saml::ids::create_id()),
            issue_instant: Utc::now(),
            issuer: issuer.to_owned(),
            destination: None,
            name_id: String::new(),
            name_id_format: None,
            session_index: None,
        }
    }

    pub fn to_xml(&self) -> String {
        let samlp = |local: &str| XmlElement::new("samlp", local, NS_PROTOCOL);
        let mut root = samlp("LogoutRequest")
            .attr("ID", self.id.as_str())
            .attr("Version", "2.0")
            .attr("IssueInstant", instant(self.issue_instant))
            .attr_opt("Destination", self.destination.as_deref())
            .child(issuer(&self.issuer))
            .child(
                XmlElement::new("saml", "NameID", NS_ASSERTION)
                    .attr_opt("Format", self.name_id_format.as_deref())
                    .text(self.name_id.as_str()),
            );
        if let Some(index) = &self.session_index {
            root = root.child(samlp("SessionIndex").text(index.as_str()));
        }
        write(&root)
    }
}
