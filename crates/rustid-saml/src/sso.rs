//! The SSO service endpoint's protocol work, independent of HTTP:
//! Unbinding, the signing keys
//! an issuer's signatures are checked with.

use crate::bindings::{BindingError, INVALID_BASE64, MessageName, post, redirect};
use crate::model::{KeyUse, ServiceProvider};
use crate::protocol::{SigningEntity, TrustLevel};
use crate::xml::dom::{self, Document, Limits};
use crate::xml::dsig::DEFAULT_ALLOWED;

/// The binding an inbound message arrived by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundBinding {
    Redirect,
    Post,
}

impl InboundBinding {
    pub fn urn(self) -> &'static str {
        match self {
            InboundBinding::Redirect => crate::constants::BINDING_REDIRECT,
            InboundBinding::Post => crate::constants::BINDING_POST,
        }
    }
}

/// Why a message couldn't be unbound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnbindError {
    /// Invalid base64, which the endpoints answer with an error page.
    Base64,
    /// Any other failure, which the endpoints don't handle (a 500).
    Unhandled(String),
}

impl From<BindingError> for UnbindError {
    fn from(e: BindingError) -> Self {
        if e.0 == INVALID_BASE64 {
            UnbindError::Base64
        } else {
            UnbindError::Unhandled(e.0)
        }
    }
}

/// An unbound message: its XML (checked to parse) and what came with it.
/// It holds no DOM, so it can be kept across awaits.
#[derive(Debug, Clone)]
pub struct Inbound {
    pub binding: InboundBinding,
    pub name: MessageName,
    pub xml: String,
    pub relay_state: Option<String>,
    max_size: usize,
    /// The redirect binding's signature parameters.
    signature: Option<redirect::Parsed>,
}

impl Inbound {
    /// The message's document (it parsed when it was unbound).
    pub fn document(&self) -> Document {
        load(&self.xml, self.max_size).expect("the message parsed when unbound")
    }
}

/// GET with a message in the query is the redirect binding,
/// POST with one in the form is the POST binding. Names are exact.
pub fn select_binding(method: &str, query: &str, form_keys: &[&str]) -> Option<InboundBinding> {
    let is_message = |name: &str| name == "SAMLRequest" || name == "SAMLResponse";
    match method {
        "POST" if form_keys.iter().any(|k| is_message(k)) => Some(InboundBinding::Post),
        "GET"
            if query
                .split('&')
                .any(|p| is_message(p.split_once('=').map_or(p, |(n, _)| n))) =>
        {
            Some(InboundBinding::Redirect)
        }
        _ => None,
    }
}

/// No DTDs, processing instructions
/// left out, the size limit in characters.
fn load(xml: &str, max_size: usize) -> Result<Document, UnbindError> {
    if xml.is_empty() {
        return Err(UnbindError::Unhandled(
            "ArgumentNullException: XML content cannot be null or empty".into(),
        ));
    }
    let limits = Limits {
        max_size,
        ignore_processing_instructions: true,
        ..Limits::default()
    };
    dom::parse(xml, &limits).map_err(|e| UnbindError::Unhandled(format!("XmlException: {e}")))
}

/// Unbinding the request's query (with or
/// without its `?`).
pub fn unbind_redirect(
    query: &str,
    max_size: usize,
    max_relay_state: usize,
) -> Result<Inbound, UnbindError> {
    let parsed = redirect::parse(query, max_size, max_relay_state)?;
    load(&parsed.xml, max_size)?;
    Ok(Inbound {
        binding: InboundBinding::Redirect,
        name: parsed.name,
        xml: parsed.xml.clone(),
        relay_state: parsed.relay_state.clone(),
        max_size,
        signature: Some(parsed),
    })
}

/// Unbinding the request's form fields.
pub fn unbind_post(
    form: &[(String, String)],
    max_size: usize,
    max_relay_state: usize,
) -> Result<Inbound, UnbindError> {
    let values = |name: &str| -> Vec<&str> {
        form.iter()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
            .collect()
    };
    let (requests, responses) = (values("SAMLRequest"), values("SAMLResponse"));
    let (name, encoded) = match (requests.as_slice(), responses.as_slice()) {
        ([], []) => {
            return Err(UnbindError::Unhandled(
                "no SAMLRequest or SAMLResponse in the form".into(),
            ));
        }
        (_, [_, ..]) if !requests.is_empty() => {
            return Err(UnbindError::Unhandled(
                "ArgumentException: Either SamlResponse or SamlRequest should be defined, not both."
                    .into(),
            ));
        }
        ([one], []) => (MessageName::SamlRequest, *one),
        ([], [one]) => (MessageName::SamlResponse, *one),
        _ => {
            return Err(UnbindError::Unhandled(
                "InvalidOperationException: Sequence contains more than one element".into(),
            ));
        }
    };
    let xml = post::decode(encoded, max_size)?;
    load(&xml, max_size)?;
    let relay_state = match values("RelayState").as_slice() {
        [] => None,
        [one] => Some((*one).to_owned()),
        _ => {
            return Err(UnbindError::Unhandled(
                "InvalidOperationException: Sequence contains more than one element".into(),
            ));
        }
    };
    if relay_state
        .as_ref()
        .is_some_and(|r| r.len() > max_relay_state)
    {
        return Err(UnbindError::Unhandled(format!(
            "RelayState exceeds maximum allowed size of {max_relay_state} bytes."
        )));
    }
    Ok(Inbound {
        binding: InboundBinding::Post,
        name,
        xml,
        relay_state,
        max_size,
        signature: None,
    })
}

/// Trusted when the query signature
/// verifies with one of the issuer's certificates by an algorithm it
/// allows. The POST binding's trust comes from reading the message.
pub fn redirect_trust(inbound: &Inbound, entity: Option<&SigningEntity>) -> TrustLevel {
    let (Some(parsed), Some(entity)) = (&inbound.signature, entity) else {
        return TrustLevel::None;
    };
    if parsed.signature.is_none() || entity.certificates.is_empty() {
        return TrustLevel::None;
    }
    let allowed: Vec<&str> = entity
        .allowed_algorithms
        .iter()
        .map(String::as_str)
        .collect();
    if redirect::verify_signature(parsed, &entity.certificates, &allowed) {
        TrustLevel::ConfiguredKey
    } else {
        TrustLevel::None
    }
}

/// Resolving a found provider: its
/// signing certificates and allowed algorithms (its own list when it has
/// one, else the defaults); none without signing certificates.
pub fn signing_entity(sp: &ServiceProvider) -> Option<SigningEntity> {
    let certificates: Vec<Vec<u8>> = sp
        .certificates
        .iter()
        .filter(|c| c.key_use == KeyUse::Signing)
        .map(|c| c.der.clone())
        .collect();
    if certificates.is_empty() {
        return None;
    }
    let allowed_algorithms = match &sp.allowed_signature_algorithms {
        Some(list) if !list.is_empty() => list.clone(),
        _ => DEFAULT_ALLOWED.iter().map(|s| (*s).to_owned()).collect(),
    };
    Some(SigningEntity {
        certificates,
        allowed_algorithms,
    })
}

/// SAML status codes.
pub const STATUS_REQUESTER: &str = "urn:oasis:names:tc:SAML:2.0:status:Requester";
pub const STATUS_RESPONDER: &str = "urn:oasis:names:tc:SAML:2.0:status:Responder";
pub const STATUS_VERSION_MISMATCH: &str = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch";
pub const STATUS_NO_PASSIVE: &str = "urn:oasis:names:tc:SAML:2.0:status:NoPassive";

fn binding_urn(binding: crate::model::Binding) -> &'static str {
    match binding {
        crate::model::Binding::HttpRedirect => crate::constants::BINDING_REDIRECT,
        crate::model::Binding::HttpPost => crate::constants::BINDING_POST,
    }
}

/// What validating an AuthnRequest needs.
pub struct ValidationInput<'a> {
    pub options: &'a crate::options::SamlOptions,
    pub now: chrono::DateTime<chrono::Utc>,
    /// The server's base URL (origin and path base), no trailing slash.
    pub base_url: &'a str,
    /// The provider the issuer names, when the store has it.
    pub sp: Option<&'a ServiceProvider>,
    pub request: &'a crate::protocol::AuthnRequest,
    /// The enabled identity resources (find enabled resources by scope
    /// filters them by the SP's allowed scopes).
    pub enabled_identity_resources: &'a [rustid_core::resources::IdentityResource],
}

/// A request that passed validation: what the interaction and the response
/// need.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedAuthnRequest {
    pub acs: crate::model::IndexedEndpoint,
    pub requested_claim_types: Vec<String>,
}

/// A status code and description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationFailure {
    pub status: &'static str,
    pub description: String,
}

pub type Validation = Result<ValidatedAuthnRequest, ValidationFailure>;

/// The authn request validator, in order.
pub fn validate_authn_request(input: &ValidationInput<'_>) -> Validation {
    let fail = |status, description: &str| ValidationFailure {
        status,
        description: description.to_owned(),
    };
    let request = input.request;
    let options = input.options;
    // The service provider.
    if request.issuer.is_none() {
        return Err(fail(
            STATUS_REQUESTER,
            "Missing SP EntityID in AuthnRequest",
        ));
    }
    let Some(sp) = input.sp.filter(|sp| sp.enabled) else {
        return Err(fail(STATUS_REQUESTER, "Invalid SP EntityId."));
    };
    if sp.assertion_consumer_service_urls.is_empty() {
        return Err(fail(
            STATUS_RESPONDER,
            "No Assertion Consumer Service URLs found.",
        ));
    }
    // Signature trust.
    let require_signed = sp
        .require_signed_authn_requests
        .unwrap_or(options.want_authn_requests_signed);
    if require_signed && !request.has_trusted_signature() {
        return Err(fail(
            STATUS_REQUESTER,
            "The AuthnRequest signature is missing or not trusted",
        ));
    }
    // Version.
    if request.version != "2.0" {
        return Err(fail(
            STATUS_VERSION_MISMATCH,
            "Only Version 2.0 is supported",
        ));
    }
    // Issue instant: the boundaries are valid.
    let skew = sp.clock_skew.unwrap_or(options.default_clock_skew).0;
    if request.issue_instant > input.now + chrono::Duration::seconds(skew) {
        return Err(fail(
            STATUS_REQUESTER,
            "Request IssueInstant is in the future",
        ));
    }
    let max_age = sp
        .request_max_age
        .unwrap_or(options.default_request_max_age)
        .0;
    if request.issue_instant < input.now - chrono::Duration::seconds(max_age) {
        return Err(fail(
            STATUS_REQUESTER,
            "Request has expired (IssueInstant too old)",
        ));
    }
    // Destination.
    match request.destination.as_deref() {
        None | Some("") if request.has_trusted_signature() => {
            return Err(fail(
                STATUS_REQUESTER,
                "Signed AuthnRequests must include a Destination",
            ));
        }
        None | Some("") => {}
        Some(destination) => {
            let expected = format!(
                "{}{}",
                input.base_url, options.endpoints.single_sign_on_service_path
            );
            if !destination.eq_ignore_ascii_case(&expected) {
                return Err(fail(STATUS_REQUESTER, "Invalid destination"));
            }
        }
    }
    // The assertion consumer service.
    let acs = resolve_acs(sp, request).map_err(|d| fail(STATUS_REQUESTER, d))?;
    // The name ID format.
    let format = request
        .name_id_policy
        .as_ref()
        .and_then(|p| p.format.clone())
        .or_else(|| sp.default_name_id_format.clone());
    if let Some(format) = format
        && !options.supported_name_id_formats.contains(&format)
    {
        return Err(fail(
            STATUS_REQUESTER,
            &format!("Requested NameID format '{format}' is not supported by this IdP"),
        ));
    }
    // Scoping.
    if request.scoping.is_some() {
        return Err(fail(STATUS_REQUESTER, "Scoping is not supported"));
    }
    // Resources.
    let requested_claim_types = resolve_claim_types(sp, input.enabled_identity_resources)
        .ok_or_else(|| fail(STATUS_RESPONDER, "Service provider configuration error"))?;
    Ok(ValidatedAuthnRequest {
        acs,
        requested_claim_types,
    })
}

/// The assertion consumer service a request may use.
fn resolve_acs(
    sp: &ServiceProvider,
    request: &crate::protocol::AuthnRequest,
) -> Result<crate::model::IndexedEndpoint, &'static str> {
    let all = &sp.assertion_consumer_service_urls;
    let default_or_first = |candidates: &[&crate::model::IndexedEndpoint]| {
        let chosen = candidates
            .iter()
            .find(|acs| acs.is_default)
            .unwrap_or(&candidates[0]);
        (*chosen).clone()
    };
    if let Some(url) = request.acs_url.as_deref().filter(|u| !u.is_empty()) {
        if request.acs_index.is_some() {
            return Err("Both ACS Url and Index were provided in the request");
        }
        // Normalised: scheme and host lower-cased, default port
        // dropped, an empty path made "/".
        let Ok(parsed) = url::Url::parse(url) else {
            return Err("AssertionConsumerServiceUrl is not a valid absolute URI");
        };
        let mut candidates: Vec<&crate::model::IndexedEndpoint> = all
            .iter()
            .filter(|acs| acs.location == parsed.as_str())
            .collect();
        if candidates.is_empty() {
            return Err("AssertionConsumerServiceUrl is not registered for this Service Provider");
        }
        if let Some(binding) = request
            .protocol_binding
            .as_deref()
            .filter(|b| !b.is_empty())
            && let Some(matched) = candidates
                .iter()
                .find(|acs| binding_urn(acs.binding) == binding)
        {
            candidates = vec![*matched];
        }
        return Ok(default_or_first(&candidates));
    }
    if let Some(index) = request.acs_index {
        let matching: Vec<_> = all.iter().filter(|acs| acs.index == index).collect();
        return match matching.as_slice() {
            [one] => Ok((*one).clone()),
            [] => Err(
                "No AssertionConsumerServiceUrl registered for this Service Provider with the provided index",
            ),
            // The configuration validator doesn't forbid duplicates, so
            // keep the first.
            [first, ..] => Ok((*first).clone()),
        };
    }
    Ok(default_or_first(&all.iter().collect::<Vec<_>>()))
}

/// The SP's allowed scopes must all be
/// enabled identity resources, and its requested claim types among their
/// claims; the claim types then are those, or all the resources' claims.
pub fn resolve_claim_types(
    sp: &ServiceProvider,
    enabled: &[rustid_core::resources::IdentityResource],
) -> Option<Vec<String>> {
    if sp.allowed_scopes.is_empty() {
        return None;
    }
    let resources: Vec<_> = enabled
        .iter()
        .filter(|r| r.enabled && sp.allowed_scopes.contains(&r.name))
        .collect();
    if sp
        .allowed_scopes
        .iter()
        .any(|scope| !resources.iter().any(|r| &r.name == scope))
    {
        return None;
    }
    let mut all: Vec<String> = Vec::new();
    for claim in resources.iter().flat_map(|r| &r.user_claims) {
        if !all.contains(claim) {
            all.push(claim.clone());
        }
    }
    if sp.requested_claim_types.is_empty() {
        return Some(all);
    }
    if sp.requested_claim_types.iter().any(|c| !all.contains(c)) {
        return None;
    }
    Some(sp.requested_claim_types.clone())
}

/// What the SAML 2 sso interaction response generator decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Interaction {
    /// Store the sign-in state and send the user to the login page.
    Login,
    /// A `Responder`/`NoPassive` status response to the SP, with this
    /// message.
    NoPassive(&'static str),
    /// Answer the SP at once.
    Respond,
}

/// The interaction decision: `active` is a user who is signed in and
/// active for the SP.
pub fn interaction(active: bool, force_authn: bool, is_passive: bool) -> Interaction {
    if !active {
        return if is_passive {
            Interaction::NoPassive("Cannot passively authenticate user")
        } else {
            Interaction::Login
        };
    }
    if force_authn {
        return if is_passive {
            Interaction::NoPassive("Cannot passively authenticate user when force auth is required")
        } else {
            Interaction::Login
        };
    }
    Interaction::Respond
}
