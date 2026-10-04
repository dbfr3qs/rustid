//! A SAML 2.0 service provider in the demo client, built on `rustid-saml`:
//! it signs in at rustid with a signed AuthnRequest (HTTP-Redirect),
//! checks the posted response against the IdP's metadata certificates,
//! and logs out with SAML single logout in both directions.
//!
//! Routes: `GET /saml` (the page), `GET /saml/login`, `POST /saml/acs`,
//! `GET /saml/logout`, `GET /saml/slo` (rustid's LogoutResponse or its
//! front-channel LogoutRequest).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Form, RawQuery, State};
use axum::http::header::{COOKIE, LOCATION, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::{DateTime, Utc};
use rustid_saml::bindings::{MessageName, redirect};
use rustid_saml::constants::{BINDING_POST, NS_ASSERTION, NS_METADATA, NS_PROTOCOL};
use rustid_saml::xml::dom::{Document, Element, Limits, parse};
use rustid_saml::xml::dsig::{self, Credential, DEFAULT_ALLOWED, DSIG, XmlSigner};
use rustid_saml::xml::writer::{XmlElement, write};

use crate::html;

const SESSION_COOKIE: &str = "demo.saml";
const SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";

/// The SP's settings.
#[derive(Debug, Clone)]
pub struct SamlSpConfig {
    /// rustid's base URL; its metadata is `{idp}/Saml2`.
    pub idp: String,
    /// The SP's base URL (`{public_url}/saml`), also its entity id.
    pub entity_id: String,
    /// The SP's signing key and certificate (PEM).
    pub key_file: PathBuf,
    pub cert_file: PathBuf,
}

/// What a signed-in SAML session knows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedIn {
    pub name_id: String,
    pub name_id_format: Option<String>,
    pub session_index: Option<String>,
    pub attributes: Vec<(String, Vec<String>)>,
    pub in_response_to: String,
    /// Which elements carried a verified signature.
    pub signed: Vec<String>,
}

/// What a response must match.
pub struct Expect<'a> {
    pub acs: &'a str,
    pub audience: &'a str,
    /// AuthnRequest ids awaiting a response.
    pub pending: &'a [&'a str],
    pub now: DateTime<Utc>,
    /// The IdP's signing certificates (DER), from its metadata.
    pub certificates: &'a [Vec<u8>],
    /// The IdP's entity id, from its metadata.
    pub issuer: &'a str,
}

fn child<'a>(e: &'a Element, ns: &str, local: &str) -> Option<&'a Element> {
    e.child(ns, local)
}

fn text(e: &Element) -> String {
    rustid_saml::xml::traverser::inner_text(e)
}

fn instant(value: Option<&str>) -> Option<DateTime<Utc>> {
    value.and_then(rustid_saml::xml::traverser::parse_xs_datetime)
}

/// Checks a SAML response as an SP must: every signature verifies with an
/// IdP certificate, the one assertion is signed (itself or by the
/// response) and both name the IdP as issuer, the status is Success, it answers a pending request, and its
/// destination, recipient, audience and lifetime fit.
pub fn check_response(xml: &str, expect: &Expect<'_>) -> Result<SignedIn, String> {
    let doc: Document = parse(xml, &Limits::default()).map_err(|e| format!("not XML: {e}"))?;
    let root = &doc.root;
    if root.local != "Response" || root.ns != NS_PROTOCOL {
        return Err("not a SAML Response".into());
    }
    let mut signed = Vec::new();
    let mut verified: Vec<&Element> = Vec::new();
    for element in root.descendants() {
        if element.child(DSIG, "Signature").is_some() {
            let covered = dsig::verify(&doc, element, expect.certificates, DEFAULT_ALLOWED)
                .map_err(|e| format!("the {} signature doesn't verify: {e}", element.local))?;
            verified.push(covered);
            signed.push(element.local.clone());
        }
    }
    // Claims are read only from an element a signature covers: the one
    // assertion, signed itself or by the response it sits in. Asking only
    // whether *some* assertion was signed would let an unsigned one ride
    // alongside a signed one (signature wrapping).
    let covered = |e: &Element| verified.iter().any(|v| std::ptr::eq(*v, e));
    let status = child(root, NS_PROTOCOL, "Status")
        .and_then(|s| child(s, NS_PROTOCOL, "StatusCode"))
        .ok_or("no Status")?;
    let code = status.attr("Value").unwrap_or_default();
    if code != SUCCESS {
        let nested = child(status, NS_PROTOCOL, "StatusCode")
            .and_then(|n| n.attr("Value"))
            .unwrap_or_default();
        return Err(format!("the IdP answered {code} {nested}"));
    }
    let assertions: Vec<&Element> = root
        .elements()
        .filter(|e| e.ns == NS_ASSERTION && e.local == "Assertion")
        .collect();
    let [assertion] = assertions[..] else {
        return Err(format!(
            "the response must carry exactly one Assertion, not {}",
            assertions.len()
        ));
    };
    if !covered(root) && !covered(assertion) {
        return Err("the assertion is not signed".into());
    }
    for (what, element) in [("Response", root), ("Assertion", assertion)] {
        let issuer = child(element, NS_ASSERTION, "Issuer").map(text);
        if issuer.as_deref() != Some(expect.issuer) {
            return Err(format!("the {what} Issuer {issuer:?} isn't the IdP"));
        }
    }
    let in_response_to = root.attr("InResponseTo").unwrap_or_default().to_owned();
    if !expect.pending.contains(&in_response_to.as_str()) {
        return Err(format!(
            "InResponseTo {in_response_to:?} answers no request of ours"
        ));
    }
    if root.attr("Destination") != Some(expect.acs) {
        return Err(format!(
            "Destination {:?} isn't our ACS",
            root.attr("Destination")
        ));
    }
    let subject = child(assertion, NS_ASSERTION, "Subject").ok_or("no Subject")?;
    let name_id = child(subject, NS_ASSERTION, "NameID").ok_or("no NameID")?;
    let data = child(subject, NS_ASSERTION, "SubjectConfirmation")
        .and_then(|c| child(c, NS_ASSERTION, "SubjectConfirmationData"))
        .ok_or("no SubjectConfirmationData")?;
    if data.attr("Recipient") != Some(expect.acs) {
        return Err(format!(
            "Recipient {:?} isn't our ACS",
            data.attr("Recipient")
        ));
    }
    if instant(data.attr("NotOnOrAfter")).is_none_or(|t| expect.now >= t) {
        return Err("the subject confirmation has expired".into());
    }
    let conditions = child(assertion, NS_ASSERTION, "Conditions").ok_or("no Conditions")?;
    if instant(conditions.attr("NotOnOrAfter")).is_none_or(|t| expect.now >= t) {
        return Err("the assertion has expired".into());
    }
    let audience = child(conditions, NS_ASSERTION, "AudienceRestriction")
        .and_then(|r| child(r, NS_ASSERTION, "Audience"))
        .map(text);
    if audience.as_deref() != Some(expect.audience) {
        return Err(format!("Audience {audience:?} isn't us"));
    }
    let session_index = child(assertion, NS_ASSERTION, "AuthnStatement")
        .and_then(|a| a.attr("SessionIndex"))
        .map(str::to_owned);
    let attributes = child(assertion, NS_ASSERTION, "AttributeStatement")
        .map(|statement| {
            statement
                .elements()
                .filter(|a| a.local == "Attribute")
                .map(|a| {
                    let values = a.elements().map(text).collect();
                    (a.attr("Name").unwrap_or_default().to_owned(), values)
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(SignedIn {
        name_id: text(name_id),
        name_id_format: name_id.attr("Format").map(str::to_owned),
        session_index,
        attributes,
        in_response_to,
        signed,
    })
}

/// The signing certificates in an IdP's metadata document (DER).
pub fn metadata_certificates(xml: &str) -> Result<Vec<Vec<u8>>, String> {
    let doc = parse(xml, &Limits::default()).map_err(|e| format!("metadata isn't XML: {e}"))?;
    if doc.root.ns != NS_METADATA {
        return Err("not SAML metadata".into());
    }
    let certificates: Vec<Vec<u8>> = doc
        .root
        .descendants()
        .into_iter()
        .filter(|e| e.local == "X509Certificate" && e.ns == DSIG)
        .filter_map(|e| {
            let compact: String = text(e).split_whitespace().collect();
            STANDARD.decode(compact).ok()
        })
        .collect();
    if certificates.is_empty() {
        return Err("the metadata has no signing certificate".into());
    }
    Ok(certificates)
}

/// The entity id an IdP's metadata document names.
pub fn metadata_entity_id(xml: &str) -> Result<String, String> {
    let doc = parse(xml, &Limits::default()).map_err(|e| format!("metadata isn't XML: {e}"))?;
    doc.root
        .attr("entityID")
        .map(str::to_owned)
        .ok_or_else(|| "the metadata has no entityID".to_owned())
}

struct Sp {
    config: SamlSpConfig,
    credential: Credential,
    http: reqwest::Client,
    /// AuthnRequest ids awaiting responses (any browser: the response
    /// arrives cross-site, without our cookie), with when they were made.
    pending: Mutex<HashMap<String, DateTime<Utc>>>,
    sessions: Mutex<HashMap<String, SignedIn>>,
    /// What the last logout said, for the page.
    last_logout: Mutex<Option<String>>,
}

impl Sp {
    fn acs(&self) -> String {
        format!("{}/acs", self.config.entity_id)
    }

    fn idp(&self, path: &str) -> String {
        format!("{}{path}", self.config.idp.trim_end_matches('/'))
    }

    /// The IdP's entity id and signing certificates, from its metadata.
    async fn idp_metadata(&self) -> Result<(String, Vec<Vec<u8>>), String> {
        let url = self.idp("/Saml2");
        let response = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("{url}: {e}"))?;
        let xml = response.text().await.map_err(|e| format!("{url}: {e}"))?;
        Ok((metadata_entity_id(&xml)?, metadata_certificates(&xml)?))
    }

    fn session(&self, headers: &HeaderMap) -> Option<(String, SignedIn)> {
        let id = cookie(headers, SESSION_COOKIE)?;
        let session = self.sessions.lock().unwrap().get(id).cloned()?;
        Some((id.to_owned(), session))
    }
}

fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|pair| pair.trim().strip_prefix(name)?.strip_prefix('='))
}

fn redirect_to(location: &str) -> Response {
    match HeaderValue::from_str(location) {
        Ok(value) => (StatusCode::FOUND, [(LOCATION, value)]).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

fn error_page(message: &str) -> Response {
    html::page(
        StatusCode::BAD_REQUEST,
        "SAML",
        &format!(
            "<h1>SAML</h1><p class=\"error\">{}</p><a class=\"button\" href=\"/saml\">Back</a>",
            html::escape(message)
        ),
    )
}

/// The SAML SP's routes, to merge into the demo client's router.
pub fn router(config: SamlSpConfig, http: reqwest::Client) -> anyhow::Result<Router> {
    use anyhow::Context;
    let read = |p: &PathBuf| {
        std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))
    };
    let credential = Credential::from_pem(&read(&config.cert_file)?, &read(&config.key_file)?)
        .map_err(|e| anyhow::anyhow!("the SAML SP key: {e}"))?;
    let sp = Arc::new(Sp {
        config,
        credential,
        http,
        pending: Mutex::new(HashMap::new()),
        sessions: Mutex::new(HashMap::new()),
        last_logout: Mutex::new(None),
    });
    Ok(Router::new()
        .route("/saml", get(page))
        .route("/saml/login", get(login))
        .route("/saml/acs", post(acs))
        .route("/saml/logout", get(logout))
        .route("/saml/slo", get(slo))
        .with_state(sp))
}

async fn page(State(sp): State<Arc<Sp>>, headers: HeaderMap) -> Response {
    let last = sp.last_logout.lock().unwrap().clone();
    let Some((_, session)) = sp.session(&headers) else {
        let note = last
            .map(|m| format!("<p>{}</p>", html::escape(&m)))
            .unwrap_or_default();
        return html::page(
            StatusCode::OK,
            "rustid demo (SAML)",
            &format!(
                "<h1>rustid demo SAML service provider</h1>{note}\
                 <p>Entity <code>{}</code>. Signs in at <code>{}</code> over SAML 2.0: a signed \
                 AuthnRequest by redirect, and a response it checks against the IdP's metadata.</p>\
                 <a class=\"button\" href=\"/saml/login\">Sign in with SAML</a> \
                 <a class=\"button secondary\" href=\"/\">OIDC demo</a>",
                html::escape(&sp.config.entity_id),
                html::escape(&sp.idp("/Saml2")),
            ),
        );
    };
    let rows: String = session
        .attributes
        .iter()
        .map(|(name, values)| {
            format!(
                "<tr><th>{}</th><td>{}</td></tr>",
                html::escape(name),
                html::escape(&values.join(", "))
            )
        })
        .collect();
    html::page(
        StatusCode::OK,
        "rustid demo (SAML)",
        &format!(
            "<h1>Signed in over SAML as {name}</h1>\
             <p><span class=\"ok\">✓ signature verified</span> ({signed}) against the IdP's \
             metadata certificate; status, InResponseTo, destination, recipient, audience and \
             lifetime checked.</p>\
             <table><tr><th>NameID</th><td>{name}</td></tr>\
             <tr><th>Format</th><td>{format}</td></tr>\
             <tr><th>SessionIndex</th><td>{index}</td></tr></table>\
             <h2>Attributes</h2><table>{rows}</table>\
             <a class=\"button\" href=\"/saml/logout\">Log out (SAML SLO)</a>",
            name = html::escape(&session.name_id),
            signed = html::escape(&session.signed.join(" and ")),
            format = html::escape(session.name_id_format.as_deref().unwrap_or("")),
            index = html::escape(session.session_index.as_deref().unwrap_or("")),
        ),
    )
}

/// A signed AuthnRequest to rustid's SSO service, by redirect.
async fn login(State(sp): State<Arc<Sp>>) -> Response {
    let id = format!("_{}", rustid_saml::ids::create_id());
    let now = Utc::now();
    let request = XmlElement::new("samlp", "AuthnRequest", NS_PROTOCOL)
        .attr("ID", id.as_str())
        .attr("Version", "2.0")
        .attr("IssueInstant", rustid_saml::response::instant(now))
        .attr("Destination", sp.idp("/Saml2/SSO"))
        .attr("AssertionConsumerServiceURL", sp.acs())
        .attr("ProtocolBinding", BINDING_POST)
        .child(XmlElement::new("saml", "Issuer", NS_ASSERTION).text(sp.config.entity_id.as_str()));
    let signer: &dyn XmlSigner = &sp.credential;
    let query = match redirect::encode(
        MessageName::SamlRequest,
        &write(&request),
        None,
        Some(signer),
    ) {
        Ok(query) => query,
        Err(e) => return error_page(&e.to_string()),
    };
    {
        let mut pending = sp.pending.lock().unwrap();
        pending.retain(|_, made| now - *made < chrono::Duration::minutes(10));
        pending.insert(id, now);
    }
    redirect_to(&format!("{}{query}", sp.idp("/Saml2/SSO")))
}

#[derive(serde::Deserialize)]
struct AcsForm {
    #[serde(rename = "SAMLResponse")]
    saml_response: String,
}

/// The posted response: checked, then a session.
async fn acs(State(sp): State<Arc<Sp>>, Form(form): Form<AcsForm>) -> Response {
    let xml = match STANDARD.decode(form.saml_response.trim()) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(_) => return error_page("SAMLResponse isn't base64"),
    };
    let (issuer, certificates) = match sp.idp_metadata().await {
        Ok(m) => m,
        Err(e) => return error_page(&e),
    };
    let pending: Vec<String> = sp.pending.lock().unwrap().keys().cloned().collect();
    let pending: Vec<&str> = pending.iter().map(String::as_str).collect();
    let acs = sp.acs();
    let checked = check_response(
        &xml,
        &Expect {
            acs: &acs,
            audience: &sp.config.entity_id,
            pending: &pending,
            now: Utc::now(),
            certificates: &certificates,
            issuer: &issuer,
        },
    );
    let signed_in = match checked {
        Ok(signed_in) => signed_in,
        Err(e) => return error_page(&format!("The SAML response was refused: {e}")),
    };
    // One use per request.
    sp.pending.lock().unwrap().remove(&signed_in.in_response_to);
    let id = rustid_saml::ids::create_id();
    sp.sessions.lock().unwrap().insert(id.clone(), signed_in);
    *sp.last_logout.lock().unwrap() = None;
    let mut response = redirect_to("/saml");
    if let Ok(value) = HeaderValue::from_str(&format!(
        "{SESSION_COOKIE}={id}; Path=/; HttpOnly; SameSite=Lax"
    )) {
        response.headers_mut().append(SET_COOKIE, value);
    }
    response
}

/// A signed LogoutRequest to rustid's SLO service, by redirect.
async fn logout(State(sp): State<Arc<Sp>>, headers: HeaderMap) -> Response {
    let Some((_, session)) = sp.session(&headers) else {
        return redirect_to("/saml");
    };
    let request = rustid_saml::logout::LogoutRequestOut {
        id: format!("_{}", rustid_saml::ids::create_id()),
        issue_instant: Utc::now(),
        destination: sp.idp("/Saml2/SLO"),
        issuer: sp.config.entity_id.clone(),
        name_id: session.name_id.clone(),
        name_id_format: session.name_id_format.clone(),
        session_index: session.session_index.clone().unwrap_or_default(),
    };
    let xml = rustid_saml::logout::write_logout_request(&request);
    let signer: &dyn XmlSigner = &sp.credential;
    match redirect::encode(MessageName::SamlRequest, &xml, None, Some(signer)) {
        Ok(query) => redirect_to(&format!("{}{query}", sp.idp("/Saml2/SLO"))),
        Err(e) => error_page(&e.to_string()),
    }
}

/// rustid's LogoutResponse (our logout finished), or its front-channel
/// LogoutRequest (the user logged out elsewhere): both must carry a query
/// signature from a metadata certificate.
async fn slo(State(sp): State<Arc<Sp>>, headers: HeaderMap, RawQuery(query): RawQuery) -> Response {
    let query = query.unwrap_or_default();
    let parsed = match redirect::parse(&query, 1 << 20, 1 << 20) {
        Ok(parsed) => parsed,
        Err(e) => return error_page(&format!("Not a SAML redirect message: {e}")),
    };
    let certificates = match sp.idp_metadata().await {
        Ok((_, c)) => c,
        Err(e) => return error_page(&e),
    };
    if !redirect::verify_signature(&parsed, &certificates, DEFAULT_ALLOWED) {
        return error_page("The SAML logout message's signature doesn't verify");
    }
    let doc = match parse(&parsed.xml, &Limits::default()) {
        Ok(doc) => doc,
        Err(e) => return error_page(&format!("Not XML: {e}")),
    };
    match parsed.name {
        MessageName::SamlResponse => {
            let code = |e: &Element| {
                child(e, NS_PROTOCOL, "StatusCode").and_then(|c| c.attr("Value").map(str::to_owned))
            };
            let status = child(&doc.root, NS_PROTOCOL, "Status");
            let top = status.and_then(code).unwrap_or_default();
            let nested = status
                .and_then(|s| child(s, NS_PROTOCOL, "StatusCode"))
                .and_then(code)
                .unwrap_or_default();
            let outcome = match (top.as_str(), nested.as_str()) {
                (SUCCESS, n) if n.ends_with(":PartialLogout") => {
                    "Logged out (PartialLogout: not every service provider confirmed)."
                }
                (SUCCESS, _) => "Logged out (Success).",
                _ => "The logout failed.",
            };
            let mut response = redirect_to("/saml");
            if let Some((id, _)) = sp.session(&headers) {
                sp.sessions.lock().unwrap().remove(&id);
                if let Ok(value) =
                    HeaderValue::from_str(&format!("{SESSION_COOKIE}=; Path=/; Max-Age=0"))
                {
                    response.headers_mut().append(SET_COOKIE, value);
                }
            }
            *sp.last_logout.lock().unwrap() = Some(outcome.to_owned());
            response
        }
        MessageName::SamlRequest => {
            // In an iframe, without our cookie: find the session by its
            // NameID and SessionIndex.
            let name_id = child(&doc.root, NS_ASSERTION, "NameID").map(text);
            let index = child(&doc.root, NS_PROTOCOL, "SessionIndex").map(text);
            sp.sessions
                .lock()
                .unwrap()
                .retain(|_, s| !(Some(&s.name_id) == name_id.as_ref() && s.session_index == index));
            *sp.last_logout.lock().unwrap() =
                Some("Logged out by the identity provider.".to_owned());
            let response = rustid_saml::logout::LogoutResponseOut {
                id: format!("_{}", rustid_saml::ids::create_id()),
                issue_instant: Utc::now(),
                destination: sp.idp("/Saml2/SLO"),
                in_response_to: doc.root.attr("ID").map(str::to_owned),
                issuer: sp.config.entity_id.clone(),
                status: rustid_saml::response::Status::success(),
            };
            let xml = rustid_saml::logout::write_logout_response(&response);
            let signer: &dyn XmlSigner = &sp.credential;
            match redirect::encode(MessageName::SamlResponse, &xml, None, Some(signer)) {
                Ok(query) => redirect_to(&format!("{}{query}", sp.idp("/Saml2/SLO"))),
                Err(e) => error_page(&e.to_string()),
            }
        }
    }
}

/// The demo SP's registration at rustid (the fixture format).
pub fn registration(entity_id: &str, certificate_pem: &str) -> serde_json::Value {
    serde_json::json!([{
        "entityId": entity_id,
        "displayName": "rustid demo SAML service provider",
        "assertionConsumerServiceUrls": [
            { "location": format!("{entity_id}/acs"), "binding": "HttpPost", "index": 0, "isDefault": true }
        ],
        "singleLogoutServiceUrls": [
            { "location": format!("{entity_id}/slo"), "binding": "HttpRedirect" }
        ],
        "requireSignedAuthnRequests": true,
        "requireSignedLogoutResponses": true,
        "certificates": [{ "certificate": certificate_pem, "use": "Signing" }],
        "allowedScopes": ["openid", "profile", "email"],
        "signingBehavior": "SignBoth",
    }])
}
