//! SAML Responses the IdP sends: the model the SAML response generator
//! builds, written by the XML writer, and signed as
//! the signed xml helper signs it.

use chrono::{DateTime, Utc};

use crate::constants::{NS_ASSERTION, NS_PROTOCOL};
use crate::xml::dom::{Limits, XmlError};
use crate::xml::dsig::{self, XmlSigner};
use crate::xml::writer::{XmlElement, write};

pub const STATUS_SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
pub const SUBJECT_CONFIRMATION_BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

/// `SamlStatus`: a status code, optionally nested once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub code: String,
    pub nested: Option<String>,
}

impl Status {
    pub fn success() -> Self {
        Status {
            code: STATUS_SUCCESS.into(),
            nested: None,
        }
    }

    pub fn nested(code: &str, nested: &str) -> Self {
        Status {
            code: code.into(),
            nested: Some(nested.into()),
        }
    }
}

/// The subject's `NameID`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectNameId {
    pub value: String,
    pub format: Option<String>,
    pub sp_name_qualifier: Option<String>,
    pub name_qualifier: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthnStatement {
    pub authn_instant: DateTime<Utc>,
    pub session_index: Option<String>,
    pub class_ref: String,
}

/// The assertion create assertion builds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assertion {
    pub id: String,
    pub issue_instant: DateTime<Utc>,
    pub issuer: String,
    pub name_id: SubjectNameId,
    pub not_before: DateTime<Utc>,
    pub not_on_or_after: DateTime<Utc>,
    /// `SubjectConfirmationData`: the ACS location and the request id.
    pub recipient: String,
    pub in_response_to: Option<String>,
    pub audience: String,
    pub authn: AuthnStatement,
    /// Attribute names and their values, in order.
    pub attributes: Vec<(String, Vec<String>)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub id: String,
    pub issue_instant: DateTime<Utc>,
    pub destination: Option<String>,
    pub in_response_to: Option<String>,
    pub issuer: String,
    pub status: Status,
    pub assertion: Option<Assertion>,
}

/// `DateTimeUtc.ToString()`: whole seconds, `Z`.
pub fn instant(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn samlp(local: &str) -> XmlElement {
    XmlElement::new("samlp", local, NS_PROTOCOL)
}

fn saml(local: &str) -> XmlElement {
    XmlElement::new("saml", local, NS_ASSERTION)
}

fn status_code(code: &str, nested: Option<&str>) -> XmlElement {
    let element = samlp("StatusCode").attr("Value", code);
    match nested {
        Some(n) => element.child(status_code(n, None)),
        None => element,
    }
}

fn assertion_element(a: &Assertion) -> XmlElement {
    let name_id = saml("NameID")
        .text(a.name_id.value.as_str())
        .attr_opt("Format", a.name_id.format.as_deref())
        .attr_opt("SPNameQualifier", a.name_id.sp_name_qualifier.as_deref())
        .attr_opt("NameQualifier", a.name_id.name_qualifier.as_deref());
    let subject = saml("Subject").child(name_id).child(
        saml("SubjectConfirmation")
            .attr("Method", SUBJECT_CONFIRMATION_BEARER)
            .child(
                saml("SubjectConfirmationData")
                    .attr("NotOnOrAfter", instant(a.not_on_or_after))
                    .attr("Recipient", a.recipient.as_str())
                    .attr_opt("InResponseTo", a.in_response_to.as_deref()),
            ),
    );
    let conditions = saml("Conditions")
        .attr("NotBefore", instant(a.not_before))
        .attr("NotOnOrAfter", instant(a.not_on_or_after))
        .child(saml("AudienceRestriction").child(saml("Audience").text(a.audience.as_str())));
    let authn = saml("AuthnStatement")
        .attr("AuthnInstant", instant(a.authn.authn_instant))
        .attr_opt("SessionIndex", a.authn.session_index.as_deref())
        .child(
            saml("AuthnContext")
                .child(saml("AuthnContextClassRef").text(a.authn.class_ref.as_str())),
        );
    let mut element = saml("Assertion")
        .attr("ID", a.id.as_str())
        .attr("Version", "2.0")
        .attr("IssueInstant", instant(a.issue_instant))
        .child(saml("Issuer").text(a.issuer.as_str()))
        .child(subject)
        .child(conditions)
        .child(authn);
    if !a.attributes.is_empty() {
        element = element.child(saml("AttributeStatement").children(a.attributes.iter().map(
            |(name, values)| {
                saml("Attribute")
                    .attr("Name", name.as_str())
                    .children(values.iter().map(|v| {
                        // An empty value gets no text node (`<x />`).
                        let value = saml("AttributeValue");
                        if v.is_empty() {
                            value
                        } else {
                            value.text(v.as_str())
                        }
                    }))
            },
        )));
    }
    element
}

/// The response's `OuterXml`, unsigned.
pub fn write_response(r: &Response) -> String {
    let mut element = samlp("Response")
        .attr("ID", r.id.as_str())
        .attr("Version", "2.0")
        .attr("IssueInstant", instant(r.issue_instant))
        .attr_opt("Destination", r.destination.as_deref())
        .attr_opt("InResponseTo", r.in_response_to.as_deref())
        .child(saml("Issuer").text(r.issuer.as_str()))
        .child(samlp("Status").child(status_code(&r.status.code, r.status.nested.as_deref())));
    if let Some(a) = &r.assertion {
        element = element.child(assertion_element(a));
    }
    write(&element)
}

/// Signs the written response: the assertion first (`SignAssertion`, as
/// the writer does), then the response (`SignResponse`, as the POST
/// binding does). Each signature follows its element's Issuer.
pub fn sign_response(
    xml: &str,
    response: &Response,
    sign_assertion: bool,
    sign_response: bool,
    signer: &dyn XmlSigner,
) -> Result<String, XmlError> {
    let limits = Limits::default();
    let mut xml = xml.to_owned();
    if sign_assertion && let Some(a) = &response.assertion {
        xml = dsig::sign(&xml, &a.id, signer, &limits)?;
    }
    if sign_response {
        xml = dsig::sign(&xml, &response.id, signer, &limits)?;
    }
    Ok(xml)
}

fn first_claim<'a>(claims: &'a [(String, String)], claim_type: &str) -> Option<&'a str> {
    claims
        .iter()
        .find(|(t, _)| t == claim_type)
        .map(|(_, v)| v.as_str())
}

/// Create subject name id's format: the request's policy format, the
/// SP's default, or unspecified.
pub fn name_id_format(policy_format: Option<&str>, sp: &crate::model::ServiceProvider) -> String {
    policy_format
        .map(str::to_owned)
        .or_else(|| sp.default_name_id_format.clone())
        .unwrap_or_else(|| crate::constants::NAME_ID_UNSPECIFIED.to_owned())
}

/// An email name ID from the SP's (or the
/// options') email claim type; any other format is the subject id. The
/// error is the message the error page shows.
pub fn generate_name_id(
    format: &str,
    sp: &crate::model::ServiceProvider,
    options: &crate::options::SamlOptions,
    claims: &[(String, String)],
) -> Result<SubjectNameId, &'static str> {
    let present = |v: Option<&str>| v.filter(|v| !v.trim().is_empty()).map(str::to_owned);
    let value = if format == crate::constants::NAME_ID_EMAIL {
        let claim_type = sp
            .email_name_id_claim_type
            .as_deref()
            .unwrap_or(&options.email_name_id_claim_type);
        present(first_claim(claims, claim_type))
            .ok_or("Email claim is required for email NameID format but was not found.")?
    } else {
        present(first_claim(claims, "sub"))
            .ok_or("Subject identifier (sub) claim is missing or empty.")?
    };
    Ok(SubjectNameId {
        value,
        format: Some(format.to_owned()),
        sp_name_qualifier: None,
        name_qualifier: None,
    })
}

/// `MapClaimsToAttributes`: each claim under its mapped name (the SP's
/// mappings, or the options' defaults when it has none), values of one
/// name together, in first-seen order.
pub fn map_attributes(
    issued: &[(String, String)],
    sp: &crate::model::ServiceProvider,
    options: &crate::options::SamlOptions,
) -> Vec<(String, Vec<String>)> {
    let mappings = if sp.claim_mappings.is_empty() {
        &options.default_claim_mappings
    } else {
        &sp.claim_mappings
    };
    let mut attributes: Vec<(String, Vec<String>)> = Vec::new();
    for (claim_type, value) in issued {
        let name = mappings.get(claim_type).unwrap_or(claim_type);
        match attributes.iter_mut().find(|(n, _)| n == name) {
            Some((_, values)) => values.push(value.clone()),
            None => attributes.push((name.clone(), vec![value.clone()])),
        }
    }
    attributes
}

/// `ResolveAuthnContextClassRef`: the mapped `acr`, else the first mapped
/// `amr`, else unspecified; the SP's mappings or the defaults.
pub fn authn_context_class(
    acr: Option<&str>,
    amrs: &[String],
    sp: &crate::model::ServiceProvider,
    options: &crate::options::SamlOptions,
) -> String {
    let mappings = if sp.authn_context_mappings.is_empty() {
        &options.default_authn_context_mappings
    } else {
        &sp.authn_context_mappings
    };
    if let Some(mapped) = acr
        .filter(|a| !a.trim().is_empty())
        .and_then(|a| mappings.get(a))
    {
        return mapped.clone();
    }
    amrs.iter()
        .find_map(|amr| mappings.get(amr))
        .cloned()
        .unwrap_or_else(|| crate::constants::AUTHN_CONTEXT_UNSPECIFIED.to_owned())
}

/// The CSP hash of the SAML auto-post page's script.
pub const AUTO_POST_SCRIPT_HASH: &str = "sha256-1cDf9gWlS6Mjg+iEJCbdzTerOHORw4iNiJr4endY8Ng=";

/// `WebUtility.HtmlEncode`: `<`, `>`, `&`, `"` and `'` as entities, and
/// characters 160-255 and those beyond the BMP as numeric references.
pub fn html_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c if ('\u{a0}'..='\u{ff}').contains(&c) || c as u32 > 0xFFFF => {
                out.push_str(&format!("&#{};", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// `HttpPostBinding.BuildAutoPostHtml`: the page that posts the message
/// (`SAMLResponse` or `SAMLRequest`, base64 of its UTF-8) to `destination`.
pub fn auto_post_html(
    destination: &str,
    name: &str,
    xml: &str,
    relay_state: Option<&str>,
) -> String {
    use base64::Engine;
    let relay_state = match relay_state.filter(|r| !r.is_empty()) {
        Some(r) => format!(
            "\n<input type=\"hidden\" name=\"RelayState\" value=\"{}\"/>",
            html_encode(r)
        ),
        None => String::new(),
    };
    let encoded = base64::engine::general_purpose::STANDARD.encode(xml.as_bytes());
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\"
\"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">
<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\">
<head/>
<body>
<noscript>
<p>
<strong>Note:</strong> Since your browser does not support JavaScript,
you must press the Continue button once to proceed.
</p>
</noscript>
<form action=\"{}\" method=\"post\" name=\"samlPostBindingSubmit\">
<div>{relay_state}
<input type=\"hidden\" name=\"{}\"
value=\"{encoded}\"/>
</div>
<noscript>
<div>
<input type=\"submit\" value=\"Continue\"/>
</div>
</noscript>
</form>
<script type=\"text/javascript\">
document.forms.samlPostBindingSubmit.submit();
</script>
</body>
</html>",
        html_encode(destination),
        html_encode(name)
    )
}
