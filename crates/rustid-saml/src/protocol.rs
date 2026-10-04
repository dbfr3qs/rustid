//! SAML protocol messages the IdP receives, read over [`Traverser`], with
//! its error rules.

use chrono::{DateTime, Utc};

use crate::constants::{NS_ASSERTION, NS_PROTOCOL};
use crate::state::RequestedAuthnContext;
use crate::xml::dom::{Document, Element};
use crate::xml::dsig::{self, DSIG};
use crate::xml::traverser::{Traverser, Unhandled, inner_text};

/// `TrustLevel`, as far as the IdP distinguishes it: a message is trusted
/// when a signature verified with a key configured for its issuer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustLevel {
    None,
    ConfiguredKey,
}

/// Why a message couldn't be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadError {
    /// `SamlXmlException`: the reader's errors, in order.
    Invalid(Vec<String>),
    /// Another failure, which the endpoints don't handle (a 500).
    Unhandled(String),
}

impl From<Unhandled> for ReadError {
    fn from(u: Unhandled) -> Self {
        ReadError::Unhandled(u.0)
    }
}

/// The issuer's signing certificates and allowed algorithms
/// (`ServiceProviderEntityResolver`); none when it has no signing
/// certificates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningEntity {
    pub certificates: Vec<Vec<u8>>,
    pub allowed_algorithms: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameId {
    pub value: String,
    pub format: Option<String>,
    pub sp_name_qualifier: Option<String>,
    pub name_qualifier: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameIdPolicy {
    pub format: Option<String>,
    pub sp_name_qualifier: Option<String>,
    pub allow_create: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Scoping {
    pub proxy_count: Option<i32>,
    /// `IDPList` entries' provider ids.
    pub idp_entries: Vec<String>,
    pub requester_ids: Vec<String>,
}

/// `Samlp.AuthnRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthnRequest {
    pub id: String,
    pub issue_instant: DateTime<Utc>,
    pub version: String,
    pub destination: Option<String>,
    pub consent: Option<String>,
    pub issuer: Option<NameId>,
    pub trust: TrustLevel,
    pub subject_name_id: Option<NameId>,
    pub name_id_policy: Option<NameIdPolicy>,
    pub requested_authn_context: Option<RequestedAuthnContext>,
    pub scoping: Option<Scoping>,
    pub force_authn: bool,
    pub is_passive: bool,
    pub acs_index: Option<i32>,
    pub acs_url: Option<String>,
    pub protocol_binding: Option<String>,
    pub attribute_consuming_service_index: Option<i32>,
    pub provider_name: Option<String>,
}

impl AuthnRequest {
    /// `HasTrustedSignature`.
    pub fn has_trusted_signature(&self) -> bool {
        self.trust >= TrustLevel::ConfiguredKey
    }
}

/// The text of the root's first child element when it is a SAML
/// `Issuer`: what both bindings resolve signing keys by.
pub fn issuer_of(doc: &Document) -> Option<String> {
    doc.root
        .elements()
        .next()
        .filter(|e| e.local == "Issuer" && e.ns == NS_ASSERTION)
        .map(inner_text)
        .filter(|s| !s.is_empty())
}

/// Read authn request. `trust` is what the binding established (a
/// redirect signature); `entity` holds the issuer's keys for an enveloped
/// signature.
pub fn read_authn_request(
    doc: &Document,
    trust: TrustLevel,
    entity: Option<&SigningEntity>,
) -> Result<AuthnRequest, ReadError> {
    let mut source = Traverser::root(&doc.root);
    let mut request = None;
    if source.ensure_name("AuthnRequest", NS_PROTOCOL) {
        request = Some(read_core(doc, &mut source, trust, entity)?);
        source.move_next(true)?;
    }
    let errors = source.finish()?;
    if !errors.is_empty() {
        return Err(ReadError::Invalid(errors));
    }
    request.ok_or_else(|| ReadError::Unhandled("no AuthnRequest read".into()))
}

fn read_core(
    doc: &Document,
    source: &mut Traverser<'_>,
    trust: TrustLevel,
    entity: Option<&SigningEntity>,
) -> Result<AuthnRequest, Unhandled> {
    let root = source.current().expect("on the root");
    // RequestAbstractType's attributes, then AuthnRequest's.
    let id = source.required_attribute("ID").unwrap_or_default();
    let issue_instant = source.required_datetime_attribute("IssueInstant");
    let version = source.required_attribute("Version").unwrap_or_default();
    let destination = source.attribute("Destination");
    let consent = source.attribute("Consent");
    let force_authn = source.bool_attribute("ForceAuthn").unwrap_or(false);
    let is_passive = source.bool_attribute("IsPassive").unwrap_or(false);
    let acs_index = source.int_attribute("AssertionConsumerServiceIndex")?;
    let acs_url = source.attribute("AssertionConsumerServiceURL");
    let protocol_binding = source.absolute_uri_attribute("ProtocolBinding");
    let attribute_consuming_service_index =
        source.int_attribute("AttributeConsumingServiceIndex")?;
    let provider_name = source.attribute("ProviderName");

    let mut children = source.children();
    let mut request = AuthnRequest {
        id,
        issue_instant: issue_instant.unwrap_or_default(),
        version,
        destination,
        consent,
        issuer: None,
        trust,
        subject_name_id: None,
        name_id_policy: None,
        requested_authn_context: None,
        scoping: None,
        force_authn,
        is_passive,
        acs_index,
        acs_url,
        protocol_binding,
        attribute_consuming_service_index,
        provider_name,
    };
    read_abstract_elements(doc, root, &mut children, &mut request, entity)?;
    if children.has_name("Subject", NS_ASSERTION) {
        request.subject_name_id = read_subject(&mut children)?;
        children.move_next(true)?;
    }
    if children.has_name("NameIDPolicy", NS_PROTOCOL) {
        request.name_id_policy = Some(NameIdPolicy {
            format: children.absolute_uri_attribute("Format"),
            sp_name_qualifier: children.attribute("SPNameQualifier"),
            allow_create: children.bool_attribute("AllowCreate"),
        });
        children.move_next(true)?;
    }
    if children.has_name("Conditions", NS_ASSERTION) {
        read_conditions(&mut children)?;
        children.move_next(true)?;
    }
    if children.has_name("RequestedAuthnContext", NS_PROTOCOL) {
        request.requested_authn_context = Some(read_requested_authn_context(&mut children)?);
        children.move_next(true)?;
    }
    if children.has_name("Scoping", NS_PROTOCOL) {
        request.scoping = Some(read_scoping(&mut children)?);
        children.move_next(true)?;
    }
    source.absorb(&children);
    source.move_next(true)?;
    Ok(request)
}

/// `RequestAbstractType`'s elements: the issuer, an optional signature
/// (checked when the issuer has keys), and extensions.
fn read_abstract_elements(
    doc: &Document,
    root: &Element,
    source: &mut Traverser<'_>,
    request: &mut AuthnRequest,
    entity: Option<&SigningEntity>,
) -> Result<(), Unhandled> {
    source.move_next(true)?;
    let (issuer, trust) =
        read_issuer_and_signature(doc, root, source, request.trust, entity, true)?;
    request.issuer = issuer;
    request.trust = trust;
    Ok(())
}

/// The issuer, an optional enveloped signature (verified when the issuer
/// has keys; the trust level it gives) and extensions. `expect_end` is how
/// the reader moves past each (requests: true; StatusResponseType: false).
fn read_issuer_and_signature(
    doc: &Document,
    root: &Element,
    source: &mut Traverser<'_>,
    mut trust: TrustLevel,
    entity: Option<&SigningEntity>,
    expect_end: bool,
) -> Result<(Option<NameId>, TrustLevel), Unhandled> {
    let mut issuer = None;
    if source.has_name("Issuer", NS_ASSERTION) {
        issuer = Some(read_name_id(source));
        source.move_next(expect_end)?;
    }
    if source.has_name("Signature", DSIG) {
        let mut keys = None;
        if issuer.is_none() {
            source.errors.borrow_mut().push(
                "A signature was found, but there was no Issuer specified. See profile spec 4.1.4.1, 4.1.4.2, 4.4.4.2".into(),
            );
        } else {
            keys = entity;
        }
        source.ignore_children();
        if let Some(entity) = keys.filter(|e| !e.certificates.is_empty()) {
            let allowed: Vec<&str> = entity
                .allowed_algorithms
                .iter()
                .map(String::as_str)
                .collect();
            match dsig::verify(doc, root, &entity.certificates, &allowed) {
                Ok(_) => trust = trust.max(TrustLevel::ConfiguredKey),
                Err(error) => source.errors.borrow_mut().push(error),
            }
        }
        source.move_next(expect_end)?;
    }
    if source.has_name("Extensions", NS_PROTOCOL) {
        source.ignore_children();
        source.move_next(expect_end)?;
    }
    Ok((issuer, trust))
}

/// `Samlp.LogoutRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoutRequest {
    pub id: String,
    pub issue_instant: DateTime<Utc>,
    pub version: String,
    pub destination: Option<String>,
    pub issuer: Option<NameId>,
    pub trust: TrustLevel,
    pub name_id: Option<NameId>,
    pub session_index: Option<String>,
    pub reason: Option<String>,
    pub not_on_or_after: Option<DateTime<Utc>>,
}

impl LogoutRequest {
    pub fn has_trusted_signature(&self) -> bool {
        self.trust >= TrustLevel::ConfiguredKey
    }
}

pub fn read_logout_request(
    doc: &Document,
    trust: TrustLevel,
    entity: Option<&SigningEntity>,
) -> Result<LogoutRequest, ReadError> {
    let mut source = Traverser::root(&doc.root);
    let mut request = None;
    if source.ensure_name("LogoutRequest", NS_PROTOCOL) {
        let root = source.current().expect("on the root");
        let id = source.required_attribute("ID").unwrap_or_default();
        let issue_instant = source.required_datetime_attribute("IssueInstant");
        let version = source.required_attribute("Version").unwrap_or_default();
        let destination = source.attribute("Destination");
        source.attribute("Consent");
        let reason = source.absolute_uri_attribute("Reason");
        let not_on_or_after = source.datetime_attribute("NotOnOrAfter");
        let mut children = source.children();
        children.move_next(true)?;
        let (issuer, trust) =
            read_issuer_and_signature(doc, root, &mut children, trust, entity, true)?;
        let mut name_id = None;
        if children.ensure_name("NameID", NS_ASSERTION) {
            name_id = Some(read_name_id(&mut children));
            children.move_next(true)?;
        }
        let mut session_index = None;
        if children.has_name("SessionIndex", NS_PROTOCOL) {
            session_index = Some(children.text_contents());
            children.move_next(true)?;
        }
        source.absorb(&children);
        request = Some(LogoutRequest {
            id,
            issue_instant: issue_instant.unwrap_or_default(),
            version,
            destination,
            issuer,
            trust,
            name_id,
            session_index,
            reason,
            not_on_or_after,
        });
        source.move_next(true)?;
    }
    let errors = source.finish()?;
    if !errors.is_empty() {
        return Err(ReadError::Invalid(errors));
    }
    request.ok_or_else(|| ReadError::Unhandled("no LogoutRequest read".into()))
}

/// `Samlp.LogoutResponse` (a StatusResponseType).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoutResponse {
    pub id: String,
    pub version: String,
    pub issue_instant: DateTime<Utc>,
    pub in_response_to: Option<String>,
    pub destination: Option<String>,
    pub issuer: Option<NameId>,
    pub trust: TrustLevel,
    pub status_code: Option<String>,
    pub nested_status_code: Option<String>,
    pub status_message: Option<String>,
}

/// `ReadStatusCode`: the value, and the first nested value.
fn read_status_code(
    source: &mut Traverser<'_>,
) -> Result<(Option<String>, Option<String>), Unhandled> {
    let value = source.required_absolute_uri_attribute("Value");
    let mut children = source.children();
    let mut nested = None;
    if children.move_next(true)? && children.has_name("StatusCode", NS_PROTOCOL) {
        nested = read_status_code(&mut children)?.0;
        children.move_next(true)?;
    }
    source.absorb(&children);
    Ok((value, nested))
}

pub fn read_logout_response(
    doc: &Document,
    trust: TrustLevel,
    entity: Option<&SigningEntity>,
) -> Result<LogoutResponse, ReadError> {
    let mut source = Traverser::root(&doc.root);
    let mut response = None;
    if source.ensure_name("LogoutResponse", NS_PROTOCOL) {
        let root = source.current().expect("on the root");
        let id = source.required_attribute("ID").unwrap_or_default();
        let version = source.required_attribute("Version").unwrap_or_default();
        let issue_instant = source.required_datetime_attribute("IssueInstant");
        let in_response_to = source.attribute("InResponseTo");
        let destination = source.attribute("Destination");
        let mut children = source.children();
        children.move_next(false)?;
        let (issuer, trust) =
            read_issuer_and_signature(doc, root, &mut children, trust, entity, false)?;
        let (mut status_code, mut nested_status_code, mut status_message) = (None, None, None);
        if children.ensure_name("Status", NS_PROTOCOL) {
            let mut status = children.children();
            status.move_next(false)?;
            if status.ensure_name("StatusCode", NS_PROTOCOL) {
                (status_code, nested_status_code) = read_status_code(&mut status)?;
                status.move_next(true)?;
            }
            if status.has_name("StatusMessage", NS_PROTOCOL) {
                status_message = Some(status.text_contents());
                status.move_next(true)?;
            }
            children.absorb(&status);
            children.move_next(true)?;
        }
        source.absorb(&children);
        response = Some(LogoutResponse {
            id,
            version,
            issue_instant: issue_instant.unwrap_or_default(),
            in_response_to,
            destination,
            issuer,
            trust,
            status_code,
            nested_status_code,
            status_message,
        });
        source.move_next(true)?;
    }
    let errors = source.finish()?;
    if !errors.is_empty() {
        return Err(ReadError::Invalid(errors));
    }
    response.ok_or_else(|| ReadError::Unhandled("no LogoutResponse read".into()))
}

fn read_name_id(source: &mut Traverser<'_>) -> NameId {
    let value = source.text_contents();
    NameId {
        value,
        format: source.absolute_uri_attribute("Format"),
        sp_name_qualifier: source.attribute("SPNameQualifier"),
        name_qualifier: source.attribute("NameQualifier"),
    }
}

fn read_subject(source: &mut Traverser<'_>) -> Result<Option<NameId>, Unhandled> {
    let mut children = source.children();
    let mut name_id = None;
    children.move_next(true)?;
    if children.has_name("NameID", NS_ASSERTION) {
        name_id = Some(read_name_id(&mut children));
        children.move_next(true)?;
    }
    if children.has_name("SubjectConfirmation", NS_ASSERTION) {
        children.required_absolute_uri_attribute("Method");
        let mut inner = children.children();
        inner.move_next(true)?;
        if inner.has_name("SubjectConfirmationData", NS_ASSERTION) {
            // Attributes only; any content is left unprocessed.
            inner.datetime_attribute("NotBefore");
            inner.datetime_attribute("NotOnOrAfter");
            inner.move_next(true)?;
        }
        children.absorb(&inner);
        children.move_next(true)?;
    }
    source.absorb(&children);
    Ok(name_id)
}

fn read_conditions(source: &mut Traverser<'_>) -> Result<(), Unhandled> {
    source.datetime_attribute("NotBefore");
    source.datetime_attribute("NotOnOrAfter");
    let mut children = source.children();
    children.move_next(true)?;
    while children.has_name("AudienceRestriction", NS_ASSERTION) {
        let mut audiences = children.children();
        // At least one audience.
        audiences.move_next(false)?;
        while audiences.ensure_name("Audience", NS_ASSERTION) {
            audiences.text_contents();
            audiences.move_next(true)?;
        }
        children.absorb(&audiences);
        children.move_next(true)?;
    }
    if children.has_name("OneTimeUse", NS_ASSERTION) {
        children.move_next(true)?;
    }
    source.absorb(&children);
    Ok(())
}

fn read_requested_authn_context(
    source: &mut Traverser<'_>,
) -> Result<RequestedAuthnContext, Unhandled> {
    let mut result = RequestedAuthnContext {
        comparison: None,
        authn_context_class_ref: Vec::new(),
        authn_context_decl_ref: Vec::new(),
    };
    let mut children = source.children();
    // At least one element.
    children.move_next(false)?;
    loop {
        if children.has_name("AuthnContextClassRef", NS_ASSERTION) {
            result
                .authn_context_class_ref
                .push(children.text_contents());
        } else if children.has_name("AuthnContextDeclRef", NS_ASSERTION) {
            result.authn_context_decl_ref.push(children.text_contents());
        }
        if !children.move_next(true)? {
            break;
        }
    }
    if !result.authn_context_class_ref.is_empty() && !result.authn_context_decl_ref.is_empty() {
        children.errors.borrow_mut().push(
            "RequestedAuthnContext must contain either AuthnContextClassRef or AuthnContextDeclRef elements, but not both".into(),
        );
    }
    source.absorb(&children);
    result.comparison = Some(source.attribute("Comparison").unwrap_or_default());
    Ok(result)
}

fn read_scoping(source: &mut Traverser<'_>) -> Result<Scoping, Unhandled> {
    let mut scoping = Scoping::default();
    let mut children = source.children();
    if children.move_next(false)? {
        loop {
            if children.has_name("IDPList", NS_PROTOCOL) {
                let mut list = children.children();
                list.move_next(false)?;
                if list.ensure_name("IDPEntry", NS_PROTOCOL) {
                    loop {
                        if let Some(provider) = list.required_absolute_uri_attribute("ProviderID") {
                            scoping.idp_entries.push(provider);
                        }
                        list.absolute_uri_attribute("Loc");
                        if !(list.move_next(true)? && list.has_name("IDPEntry", NS_PROTOCOL)) {
                            break;
                        }
                    }
                }
                if list.has_name("GetComplete", NS_PROTOCOL) {
                    list.text_contents();
                    list.move_next(true)?;
                }
                children.absorb(&list);
            } else if children.has_name("RequesterID", NS_PROTOCOL) {
                scoping.requester_ids.push(children.absolute_uri_contents());
            } else if let Some(e) = children.current() {
                children
                    .errors
                    .borrow_mut()
                    .push(format!("Unexpected element \"{}\" in Scoping.", e.local));
            }
            if !children.move_next(true)? {
                break;
            }
        }
    }
    source.absorb(&children);
    scoping.proxy_count = source.int_attribute("ProxyCount")?;
    Ok(scoping)
}
