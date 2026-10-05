//! Single logout: the LogoutRequest and LogoutResponse the IdP sends,
//! written by the XML writer.

use chrono::{DateTime, Utc};

use crate::constants::{NS_ASSERTION, NS_PROTOCOL};
use crate::response::{Status, instant};
use crate::xml::writer::{XmlElement, write};

/// A front-channel LogoutRequest to an SP
///.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoutRequestOut {
    pub id: String,
    pub issue_instant: DateTime<Utc>,
    pub destination: String,
    pub issuer: String,
    pub name_id: String,
    pub name_id_format: Option<String>,
    pub session_index: String,
}

/// A LogoutResponse to the SP that asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoutResponseOut {
    pub id: String,
    pub issue_instant: DateTime<Utc>,
    pub destination: String,
    pub in_response_to: Option<String>,
    pub issuer: String,
    pub status: Status,
}

fn samlp(local: &str) -> XmlElement {
    XmlElement::new("samlp", local, NS_PROTOCOL)
}

fn saml(local: &str) -> XmlElement {
    XmlElement::new("saml", local, NS_ASSERTION)
}

/// A LogoutRequest as XML: RequestAbstractType's attributes (ID,
/// IssueInstant, Version, Destination), the Issuer, NameID and
/// SessionIndex.
pub fn write_logout_request(r: &LogoutRequestOut) -> String {
    let element = samlp("LogoutRequest")
        .attr("ID", r.id.as_str())
        .attr("IssueInstant", instant(r.issue_instant))
        .attr("Version", "2.0")
        .attr("Destination", r.destination.as_str())
        .child(saml("Issuer").text(r.issuer.as_str()))
        .child(
            saml("NameID")
                .text(r.name_id.as_str())
                .attr_opt("Format", r.name_id_format.as_deref()),
        )
        .child(samlp("SessionIndex").text(r.session_index.as_str()));
    write(&element)
}

/// `Write(LogoutResponse)`: StatusResponseType's attributes, the Issuer
/// and the Status.
pub fn write_logout_response(r: &LogoutResponseOut) -> String {
    let code = samlp("StatusCode").attr("Value", r.status.code.as_str());
    let code = match &r.status.nested {
        Some(nested) => code.child(samlp("StatusCode").attr("Value", nested.as_str())),
        None => code,
    };
    let element = samlp("LogoutResponse")
        .attr("ID", r.id.as_str())
        .attr("Version", "2.0")
        .attr("IssueInstant", instant(r.issue_instant))
        .attr("Destination", r.destination.as_str())
        .attr_opt("InResponseTo", r.in_response_to.as_deref())
        .child(saml("Issuer").text(r.issuer.as_str()))
        .child(samlp("Status").child(code));
    write(&element)
}

/// The first SLO endpoint
/// with the redirect binding (the only one front-channel logout and
/// LogoutResponses use).
pub fn slo_redirect_endpoint(
    sp: &crate::model::ServiceProvider,
) -> Option<&crate::model::Endpoint> {
    sp.single_logout_service_urls
        .iter()
        .find(|e| e.binding == crate::model::Binding::HttpRedirect)
}

/// What validating a LogoutRequest needs.
pub struct LogoutValidationInput<'a> {
    pub options: &'a crate::options::SamlOptions,
    pub now: DateTime<Utc>,
    /// The server's base URL (origin and path base), no trailing slash.
    pub base_url: &'a str,
    pub sp: Option<&'a crate::model::ServiceProvider>,
    pub request: &'a crate::protocol::LogoutRequest,
    /// The signed-in user's SAML sessions; `None` when nobody is signed in.
    pub user_saml_sessions: Option<&'a [rustid_core::session::SamlSpSession]>,
}

/// The logout request validator, in order: whether the
/// user's session for the SP was found, or why the
/// request is refused.
pub fn validate_logout_request(
    input: &LogoutValidationInput<'_>,
) -> Result<bool, crate::sso::ValidationFailure> {
    use crate::sso::{STATUS_REQUESTER, STATUS_VERSION_MISMATCH, ValidationFailure};
    let fail = |status, description: &str, sp_resolved| ValidationFailure {
        status,
        description: description.to_owned(),
        sp_resolved,
    };
    let request = input.request;
    if request.issuer.is_none() {
        return Err(fail(
            STATUS_REQUESTER,
            "Missing SP EntityID in LogoutRequest",
            false,
        ));
    }
    let Some(sp) = input.sp.filter(|sp| sp.enabled) else {
        return Err(fail(STATUS_REQUESTER, "Invalid SP EntityId", false));
    };
    if sp.single_logout_service_urls.is_empty() {
        return Err(fail(
            STATUS_REQUESTER,
            "SP does not have any SingleLogoutServiceUrls configured",
            false,
        ));
    }
    let fail = |status, description: &str| fail(status, description, true);
    if !request.has_trusted_signature() {
        return Err(fail(
            STATUS_REQUESTER,
            "The LogoutRequest signature is missing or not trusted",
        ));
    }
    if request.version != "2.0" {
        return Err(fail(
            STATUS_VERSION_MISMATCH,
            "Only Version 2.0 is supported",
        ));
    }
    match request.destination.as_deref() {
        None | Some("") => {
            // Signed (which validation required above).
            return Err(fail(
                STATUS_REQUESTER,
                "Signed LogoutRequests must include a Destination",
            ));
        }
        Some(destination) => {
            let expected = format!(
                "{}{}",
                input.base_url, input.options.endpoints.single_logout_service_path
            );
            if !destination.eq_ignore_ascii_case(&expected) {
                return Err(fail(STATUS_REQUESTER, "Invalid destination"));
            }
        }
    }
    if let Some(not_on_or_after) = request.not_on_or_after {
        let skew = sp.clock_skew.unwrap_or(input.options.default_clock_skew).0;
        if input.now > not_on_or_after + chrono::Duration::seconds(skew) {
            return Err(fail(
                STATUS_REQUESTER,
                "LogoutRequest has expired (NotOnOrAfter)",
            ));
        }
    }
    // The session: only for a signed-in user.
    let Some(sessions) = input.user_saml_sessions else {
        return Ok(true);
    };
    let Some(name_id) = request
        .name_id
        .as_ref()
        .map(|n| n.value.as_str())
        .filter(|v| !v.is_empty())
    else {
        return Err(fail(
            STATUS_REQUESTER,
            "LogoutRequest must contain a NameID",
        ));
    };
    let matching: Vec<_> = sessions
        .iter()
        .filter(|s| s.entity_id == sp.entity_id)
        .collect();
    if matching.is_empty() {
        return Ok(false);
    }
    if !matching.iter().any(|s| s.name_id == name_id) {
        return Err(fail(
            STATUS_REQUESTER,
            "NameID does not match any active session",
        ));
    }
    if let Some(index) = request.session_index.as_deref().filter(|i| !i.is_empty())
        && !matching
            .iter()
            .any(|s| s.session_index == index && s.name_id == name_id)
    {
        return Ok(false);
    }
    Ok(true)
}
