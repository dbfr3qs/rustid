//! The SAML 2.0 IdP's endpoints.

use axum::http::header::{ACCEPT, CONTENT_TYPE};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use rustid_core::events::RequestInfo;
use rustid_saml::constants::CONTENT_TYPE_METADATA;
use rustid_saml::metadata::{saml_issuer, write_metadata};

use crate::ProtocolState;
use crate::endpoint::RequestUrls;
use crate::request::Route;

/// `MetadataEndpoint`: GET only. Browsers (an `Accept` naming `text/html`)
/// get `text/xml` so they display it; everything else the metadata media
/// type.
pub(crate) async fn metadata(
    state: &ProtocolState,
    saml: &rustid_saml::Saml,
    route: &Route,
    method: &Method,
    headers: &HeaderMap,
    info: &RequestInfo,
) -> Response {
    if method != Method::GET {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let urls = RequestUrls::new(state, route);
    let issuer = saml_issuer(&saml.options, urls.issuer());
    let certificates = match state.keys.saml_signing_certificates(&issuer).await {
        Ok(certificates) => certificates,
        Err(error) => {
            return crate::response::internal_error(
                state,
                info,
                "GetAllSigningCertificates",
                &error.to_string(),
            );
        }
    };
    let xml = write_metadata(
        &saml.options,
        &issuer,
        &certificates,
        urls.base_url(),
        chrono::Utc::now(),
    );
    let browser = headers
        .get(ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("text/html"));
    let content_type = if browser {
        "text/xml"
    } else {
        CONTENT_TYPE_METADATA
    };
    ([(CONTENT_TYPE, content_type)], xml).into_response()
}

/// A SAML front-channel error: the message sealed into the error page URL,
/// and a 302 to that URL as configured (not made absolute).
fn front_channel_error(
    state: &ProtocolState,
    description: &str,
    sp_entity_id: Option<&str>,
) -> Response {
    use rustid_core::authorize::messages::{self, ERROR_MESSAGE_PURPOSE, ErrorMessage};
    let message = ErrorMessage {
        error: "Saml2 error".to_owned(),
        error_description: Some(description.to_owned()),
        display_mode: None,
        ui_locales: None,
        request_id: Some(crate::request_id()),
        activity_id: crate::activity_id(),
        redirect_uri: None,
        response_mode: None,
        client_id: sp_entity_id.map(str::to_owned),
    };
    let id = messages::write(
        &state.interaction.protector,
        ERROR_MESSAGE_PURPOSE,
        message,
        chrono::Utc::now(),
    );
    let ui = &state.options.user_interaction;
    let url = rustid_core::params::add_query_param(&ui.error_url, &ui.error_id_parameter, &id);
    match axum::http::HeaderValue::from_str(&url) {
        Ok(location) => (
            StatusCode::FOUND,
            [(axum::http::header::LOCATION, location)],
        )
            .into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// `SingleSignOnServiceEndpoint`: unbind, read and validate the
/// AuthnRequest, then send the user to log in. Responses to the SP (a
/// signed-in user, `NoPassive`) arrive with 5e.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn single_sign_on(
    state: &ProtocolState,
    saml: &rustid_saml::Saml,
    route: &Route,
    method: &Method,
    headers: &HeaderMap,
    body: axum::body::Body,
    info: &RequestInfo,
    session: Option<&rustid_core::session::UserSession>,
) -> Response {
    use rustid_saml::protocol::{ReadError, read_authn_request};
    use rustid_saml::sso::{
        InboundBinding, Interaction, UnbindError, ValidationInput, interaction, redirect_trust,
        select_binding, signing_entity, unbind_post, unbind_redirect, validate_authn_request,
    };
    const OPERATION: &str = "SingleSignOnServiceEndpoint";
    let options = &saml.options;
    let unhandled = |detail: &str| crate::response::internal_error(state, info, OPERATION, detail);

    // Reading a POST's form throws unless it is a form.
    let mut form: Vec<(String, String)> = Vec::new();
    if method == Method::POST {
        if !crate::endpoint::is_form_content_type(headers) {
            return unhandled("InvalidOperationException: Incorrect Content-Type");
        }
        let Some(parsed) = crate::endpoint::read_form(body).await else {
            return unhandled("InvalidDataException: the form could not be read");
        };
        form = parsed
            .pairs()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();
    }
    let keys: Vec<&str> = form.iter().map(|(k, _)| k.as_str()).collect();
    let Some(binding) = select_binding(method.as_str(), &route.query, &keys) else {
        return front_channel_error(
            state,
            "No front channel bindings found to satisfy request",
            None,
        );
    };
    let unbound = match binding {
        InboundBinding::Redirect => unbind_redirect(
            &route.query,
            options.max_message_size,
            options.max_relay_state_length,
        ),
        InboundBinding::Post => unbind_post(
            &form,
            options.max_message_size,
            options.max_relay_state_length,
        ),
    };
    let inbound = match unbound {
        Ok(inbound) => inbound,
        Err(UnbindError::Base64) => {
            return front_channel_error(
                state,
                "Invalid base64 encoding in SAML signin request",
                None,
            );
        }
        Err(UnbindError::Unhandled(detail)) => return unhandled(&detail),
    };

    // The issuer's provider: its keys check signatures, and validation
    // needs it.
    let issuer = rustid_saml::protocol::issuer_of(&inbound.document());
    let find = |entity_id: String| async move {
        saml.stores
            .service_providers
            .find_by_entity_id(&entity_id)
            .await
    };
    let sp = match issuer.clone() {
        Some(entity_id) => match find(entity_id).await {
            Ok(sp) => sp,
            Err(e) => return unhandled(&e.to_string()),
        },
        None => None,
    };
    let entity = sp.as_deref().and_then(signing_entity);
    let trust = redirect_trust(&inbound, entity.as_ref());
    let read = read_authn_request(&inbound.document(), trust, entity.as_ref());
    let request = match read {
        Ok(request) => request,
        Err(ReadError::Invalid(errors)) => {
            tracing::warn!(?errors, "SAML AuthnRequest could not be read");
            return front_channel_error(state, "The SAML request could not be processed", None);
        }
        Err(ReadError::Unhandled(detail)) => return unhandled(&detail),
    };
    let issuer_value = request.issuer.as_ref().map(|i| i.value.clone());
    // The validator looks the issuer up itself (an empty one included).
    let sp = match &issuer_value {
        Some(value) if Some(value) != issuer.as_ref() => match find(value.clone()).await {
            Ok(sp) => sp,
            Err(e) => return unhandled(&e.to_string()),
        },
        _ => sp,
    };
    let resources = match state.stores.resources.get_all_enabled_resources().await {
        Ok(resources) => resources,
        Err(e) => return unhandled(&e.to_string()),
    };
    let base_url = route.origin.base_url();
    let validated = validate_authn_request(&ValidationInput {
        options,
        now: chrono::Utc::now(),
        base_url: &base_url,
        sp: sp.as_deref(),
        request: &request,
        enabled_identity_resources: &resources.identity_resources,
    });
    let validated = match validated {
        Ok(validated) => validated,
        Err(failure) => {
            state.events.raise(
                info,
                chrono::Utc::now(),
                rustid_core::events::Event::saml_authn_request_validation_failure(
                    issuer_value.as_deref(),
                    &failure.description,
                    Some(binding.urn()),
                ),
            );
            return front_channel_error(state, &failure.description, issuer_value.as_deref());
        }
    };
    let sp = sp.expect("validated requests have a provider");

    // An authenticated user must still be active for this SP.
    let active = match session {
        Some(user) => match is_active(state, &sp, user).await {
            Ok(active) => active,
            Err(e) => return unhandled(&e.to_string()),
        },
        None => false,
    };
    let response_request = ResponseRequest {
        sp: sp.clone(),
        acs: validated.acs.clone(),
        relay_state: inbound.relay_state.clone(),
        request_id: Some(request.id.clone()),
        name_id_policy_format: request
            .name_id_policy
            .as_ref()
            .and_then(|p| p.format.clone()),
        requested_claim_types: validated.requested_claim_types.clone(),
    };
    match interaction(active, request.force_authn, request.is_passive) {
        Interaction::Login => {}
        Interaction::NoPassive(message) => {
            state.events.raise(
                info,
                chrono::Utc::now(),
                rustid_core::events::Event::saml_sso_failure(
                    Some(&sp.entity_id),
                    message,
                    "SingleSignOnService",
                ),
            );
            let status = rustid_saml::response::Status::nested(
                rustid_saml::sso::STATUS_RESPONDER,
                rustid_saml::sso::STATUS_NO_PASSIVE,
            );
            return error_response(state, saml, route, info, &response_request, status).await;
        }
        Interaction::Respond => {
            let user = session.expect("an active user");
            return respond(state, saml, route, info, user, response_request).await;
        }
    }
    login_page(
        state,
        saml,
        route,
        headers,
        info,
        &request,
        &sp,
        inbound.relay_state,
        validated,
    )
    .await
}

/// The sign-in state stored, then a 303
/// to the login page with the SSO callback as its return URL.
#[allow(clippy::too_many_arguments)]
async fn login_page(
    state: &ProtocolState,
    saml: &rustid_saml::Saml,
    route: &Route,
    headers: &HeaderMap,
    info: &RequestInfo,
    request: &rustid_saml::protocol::AuthnRequest,
    sp: &rustid_saml::model::ServiceProvider,
    relay_state: Option<String>,
    validated: rustid_saml::sso::ValidatedAuthnRequest,
) -> Response {
    use rustid_saml::state::{AuthenticationState, StoredAuthnRequest};
    let now = chrono::Utc::now();
    let options = &saml.options;
    let scoping_hint = request
        .scoping
        .as_ref()
        .filter(|s| s.idp_entries.len() == 1)
        .map(|s| s.idp_entries[0].clone());
    let authn_state = AuthenticationState {
        authn_request_data: Some(StoredAuthnRequest {
            request_id: Some(request.id.clone()),
            force_authn: request.force_authn,
            is_passive: request.is_passive,
            name_id_policy_format: request
                .name_id_policy
                .as_ref()
                .and_then(|p| p.format.clone()),
            subject_name_id_value: request.subject_name_id.as_ref().map(|n| n.value.clone()),
            idp_hint_provider_id: scoping_hint,
            requested_authn_context: request.requested_authn_context.clone(),
        }),
        service_provider_entity_id: sp.entity_id.clone(),
        relay_state,
        is_idp_initiated: false,
        created_utc: now,
        assertion_consumer_service: validated.acs,
        requested_claim_types: validated.requested_claim_types,
        expires_at_utc: Some(now + chrono::Duration::seconds(options.signin_state_lifetime.0)),
        denial_error: None,
        denial_error_description: None,
    };
    let id = match saml.stores.signin_states.store(authn_state).await {
        Ok(id) => id,
        Err(e) => {
            return crate::response::internal_error(
                state,
                info,
                "Saml2LoginPageResultHttpWriter",
                &e.to_string(),
            );
        }
    };
    let endpoints = &options.endpoints;
    let return_url = format!(
        "{}/{}",
        route.origin.base_path.trim_end_matches('/'),
        endpoints
            .single_sign_on_callback_path
            .trim_start_matches('/')
    );
    let return_url = rustid_core::params::add_query_param(
        &return_url,
        &endpoints.state_id_parameter_name,
        &id.to_string(),
    );
    let ui = &state.options.user_interaction;
    let url = rustid_core::params::add_query_param(
        &ui.login_url,
        &ui.login_return_url_parameter,
        &return_url,
    );
    let mut response = crate::authorize::redirect(&crate::authorize::absolute_url(route, &url));
    // Bind the interaction to this browser, as the authorize endpoint does:
    // Only it can redeem the login continuation for this return URL.
    crate::authorize::bind_interaction(state, route, headers, &mut response, &return_url);
    response
}

/// What a response to the SP needs (`ValidatedAuthnRequest`'s fields).
pub(crate) struct ResponseRequest {
    pub sp: std::sync::Arc<rustid_saml::model::ServiceProvider>,
    pub acs: rustid_saml::model::IndexedEndpoint,
    pub relay_state: Option<String>,
    pub request_id: Option<String>,
    pub name_id_policy_format: Option<String>,
    pub requested_claim_types: Vec<String>,
}

const SSO_RESPONSE_PROFILE_CALLER: &str = "Saml2SsoResponseGenerator";
const SAML_SSO_IS_ACTIVE_CALLER: &str = "SamlSsoEndpoint";

/// The SP as the profile service's "client" (the SP is the
/// request's application).
fn sp_client(sp: &rustid_saml::model::ServiceProvider) -> rustid_core::clients::Client {
    rustid_core::clients::Client {
        client_id: sp.entity_id.clone(),
        client_name: sp.display_name.clone(),
        ..Default::default()
    }
}

/// The signed-in user's claims, in the principal's order: `sub`, `idp`,
/// `auth_time`, each `amr`, then the rest.
fn principal_claims(session: &rustid_core::session::UserSession) -> Vec<(String, String)> {
    let mut claims = vec![
        ("sub".to_owned(), session.subject_id.clone()),
        ("idp".to_owned(), session.idp.clone()),
        ("auth_time".to_owned(), session.auth_time.to_string()),
    ];
    claims.extend(session.amr.iter().map(|a| ("amr".to_owned(), a.clone())));
    claims.extend(
        session
            .claims
            .iter()
            .map(|c| (c.claim_type.clone(), c.value.clone())),
    );
    claims
}

/// The profile service's `IsActive` for the SAML SSO endpoint.
async fn is_active(
    state: &ProtocolState,
    sp: &rustid_saml::model::ServiceProvider,
    session: &rustid_core::session::UserSession,
) -> Result<bool, rustid_core::profile::ProfileError> {
    let client = sp_client(sp);
    state
        .stores
        .profile
        .is_active(&rustid_core::profile::ActiveRequest {
            caller: SAML_SSO_IS_ACTIVE_CALLER,
            client: &client,
            subject_id: &session.subject_id,
            subject_claims: &session.claims,
        })
        .await
}

/// A random UUID as 32 hex digits.
fn new_session_index() -> String {
    let mut bytes = [0u8; 16];
    aws_lc_rs::rand::fill(&mut bytes).expect("the system RNG");
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn signing_flags(
    saml: &rustid_saml::Saml,
    sp: &rustid_saml::model::ServiceProvider,
) -> (bool, bool) {
    use rustid_saml::model::SigningBehavior;
    match sp
        .signing_behavior
        .unwrap_or(saml.options.default_signing_behavior)
    {
        SigningBehavior::DoNotSign => (false, false),
        SigningBehavior::SignResponse => (false, true),
        SigningBehavior::SignAssertion => (true, false),
        SigningBehavior::SignBoth => (true, true),
    }
}

/// The POST binding's result: the signed message in the auto-post page.
#[allow(clippy::too_many_arguments)]
async fn post_response(
    state: &ProtocolState,
    saml: &rustid_saml::Saml,
    route: &Route,
    info: &RequestInfo,
    request: &ResponseRequest,
    response: &rustid_saml::response::Response,
    sign_assertion: bool,
    sign_response: bool,
) -> Result<Response, Response> {
    use rustid_saml::response::{
        AUTO_POST_SCRIPT_HASH, auto_post_html, sign_response as sign, write_response,
    };
    let fail = |detail: &str| {
        crate::response::internal_error(state, info, "Saml2SsoResponseGenerator", detail)
    };
    // Only HTTP-POST delivers responses.
    if request.acs.binding != rustid_saml::model::Binding::HttpPost {
        return Err(fail(&format!(
            "The ACS binding '{}' is not supported for SAML response delivery. Only HTTP-POST is supported.",
            request.acs.binding.name()
        )));
    }
    let mut xml = write_response(response);
    if sign_assertion || sign_response {
        let issuer = rustid_saml::metadata::saml_issuer(
            &saml.options,
            crate::endpoint::RequestUrls::new(state, route).issuer(),
        );
        let (key, certificate) = state
            .keys
            .saml_signing_key(&issuer)
            .await
            .map_err(|e| fail(&e.to_string()))?;
        let signer = rustid_saml::signing::SamlKey { key, certificate };
        xml = sign(&xml, response, sign_assertion, sign_response, &signer)
            .map_err(|e| fail(&e.to_string()))?;
    }
    let html = auto_post_html(
        &request.acs.location,
        "SAMLResponse",
        &xml,
        request.relay_state.as_deref(),
    );
    let csp = format!("script-src '{AUTO_POST_SCRIPT_HASH}'");
    Ok((
        [
            (CONTENT_TYPE, "text/html".to_owned()),
            (axum::http::header::CONTENT_SECURITY_POLICY, csp),
            (
                axum::http::header::CACHE_CONTROL,
                "no-cache, no-store".to_owned(),
            ),
        ],
        html,
    )
        .into_response())
}

/// The response for the signed-in user: the assertion,
/// the SP's SAML session recorded in the user's (cookie rewritten), and
/// the SSO success event. A name ID that can't be made goes to the error
/// page.
pub(crate) async fn respond(
    state: &ProtocolState,
    saml: &rustid_saml::Saml,
    route: &Route,
    info: &RequestInfo,
    session: &rustid_core::session::UserSession,
    request: ResponseRequest,
) -> Response {
    use rustid_saml::response::{
        Assertion, AuthnStatement, Response as SamlResponse, Status, authn_context_class,
        generate_name_id, map_attributes, name_id_format,
    };
    let options = &saml.options;
    let sp = request.sp.clone();
    let claims = principal_claims(session);
    let format = name_id_format(request.name_id_policy_format.as_deref(), &sp);
    let name_id = match generate_name_id(&format, &sp, options, &claims) {
        Ok(name_id) => name_id,
        Err(message) => return front_channel_error(state, message, None),
    };
    // The attributes: the profile service's claims of the requested types.
    let client = sp_client(&sp);
    let mut subject_claims = vec![rustid_core::tokens::Claim::string(
        "sub",
        &session.subject_id,
    )];
    subject_claims.extend(session.claims.iter().cloned());
    let issued = match state
        .stores
        .profile
        .profile_claims(&rustid_core::profile::ProfileRequest {
            caller: SSO_RESPONSE_PROFILE_CALLER,
            client: &client,
            subject_id: &session.subject_id,
            subject_claims: &subject_claims,
            requested_claim_types: &request.requested_claim_types,
        })
        .await
    {
        Ok(issued) => issued,
        Err(e) => {
            return crate::response::internal_error(state, info, "GetProfileData", &e.to_string());
        }
    };
    let issued: Vec<(String, String)> = issued
        .into_iter()
        .map(|c| (c.claim_type, c.value))
        .collect();
    let session_index = session
        .saml_sessions
        .iter()
        .find(|s| s.entity_id == sp.entity_id)
        .map(|s| s.session_index.clone())
        .unwrap_or_else(new_session_index);
    let now = chrono::Utc::now();
    let issuer = rustid_saml::metadata::saml_issuer(
        options,
        crate::endpoint::RequestUrls::new(state, route).issuer(),
    );
    let lifetime = sp
        .assertion_lifetime
        .unwrap_or(options.default_assertion_lifetime)
        .0;
    let destination = request.acs.location.clone();
    let response = SamlResponse {
        id: rustid_saml::ids::create_id(),
        issue_instant: now,
        destination: Some(destination.clone()),
        in_response_to: request.request_id.clone(),
        issuer: issuer.clone(),
        status: Status::success(),
        assertion: Some(Assertion {
            id: rustid_saml::ids::create_id(),
            issue_instant: now,
            issuer,
            name_id: name_id.clone(),
            not_before: now,
            not_on_or_after: now + chrono::Duration::seconds(lifetime),
            recipient: destination,
            in_response_to: request.request_id.clone(),
            audience: sp.entity_id.clone(),
            authn: AuthnStatement {
                authn_instant: now,
                session_index: Some(session_index.clone()),
                class_ref: authn_context_class(session.claim("acr"), &session.amr, &sp, options),
            },
            attributes: map_attributes(&issued, &sp, options),
        }),
    };
    let (sign_assertion, sign_response) = signing_flags(saml, &sp);
    let mut http = match post_response(
        state,
        saml,
        route,
        info,
        &request,
        &response,
        sign_assertion,
        sign_response,
    )
    .await
    {
        Ok(http) => http,
        Err(failure) => return failure,
    };
    // The user's session remembers this SP.
    let mut session = session.clone();
    session.add_saml_session(rustid_core::session::SamlSpSession {
        entity_id: sp.entity_id.clone(),
        session_index: session_index.clone(),
        name_id: name_id.value.clone(),
        name_id_format: name_id.format.clone(),
    });
    match crate::session_cookie::write(state, route, &mut session).await {
        Ok(cookie) => {
            crate::cookies::append(&mut http, &cookie);
            // Cookie responses are never cached (the binding then sets its
            // own Cache-Control).
            http.headers_mut().insert(
                axum::http::header::PRAGMA,
                axum::http::HeaderValue::from_static("no-cache"),
            );
        }
        Err(e) => {
            return crate::response::internal_error(state, info, "AddSamlSession", &e.to_string());
        }
    }
    state.events.raise(
        info,
        now,
        rustid_core::events::Event::saml_sso_success(
            &sp.entity_id,
            Some(&session.subject_id),
            &session_index,
            rustid_saml::constants::BINDING_POST,
            name_id.format.as_deref(),
        ),
    );
    http
}

/// A status response (no assertion), signed when
/// the SP's behaviour signs responses.
pub(crate) async fn error_response(
    state: &ProtocolState,
    saml: &rustid_saml::Saml,
    route: &Route,
    info: &RequestInfo,
    request: &ResponseRequest,
    status: rustid_saml::response::Status,
) -> Response {
    let issuer = rustid_saml::metadata::saml_issuer(
        &saml.options,
        crate::endpoint::RequestUrls::new(state, route).issuer(),
    );
    let response = rustid_saml::response::Response {
        id: rustid_saml::ids::create_id(),
        issue_instant: chrono::Utc::now(),
        destination: Some(request.acs.location.clone()),
        in_response_to: request.request_id.clone(),
        issuer,
        status,
        assertion: None,
    };
    let (_, sign_response) = signing_flags(saml, &request.sp);
    match post_response(
        state,
        saml,
        route,
        info,
        request,
        &response,
        false,
        sign_response,
    )
    .await
    {
        Ok(http) | Err(http) => http,
    }
}

/// `SingleSignOnCallbackEndpoint`: after login, answers the SP whose
/// request the stored state holds.
pub(crate) async fn callback(
    state: &ProtocolState,
    saml: &rustid_saml::Saml,
    route: &Route,
    method: &Method,
    headers: &HeaderMap,
    info: &RequestInfo,
    session: Option<&rustid_core::session::UserSession>,
) -> Response {
    use rustid_saml::sso::{STATUS_NO_PASSIVE, STATUS_RESPONDER};
    const ENDPOINT: &str = "SingleSignOnCallback";
    if method != Method::GET {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let options = &saml.options;
    let params = rustid_core::params::Params::parse_query(&route.query);
    let Some(id) = params
        .get(&options.endpoints.state_id_parameter_name)
        .and_then(|v| v.parse::<rustid_core::admin::EntityId>().ok())
    else {
        return front_channel_error(state, "Missing or invalid SAML state identifier", None);
    };
    let now = chrono::Utc::now();
    let authn_state = match saml.stores.signin_states.retrieve(&id, now).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return front_channel_error(
                state,
                "SAML authentication state not found or expired",
                None,
            );
        }
        Err(e) => return crate::response::internal_error(state, info, ENDPOINT, &e.to_string()),
    };
    let entity_id = authn_state.service_provider_entity_id.clone();
    let sp_failure = |error: &str, page: &str| {
        state.events.raise(
            info,
            now,
            rustid_core::events::Event::saml_sso_failure(Some(&entity_id), error, ENDPOINT),
        );
        front_channel_error(state, page, Some(&entity_id))
    };
    if authn_state.denial_error.is_none() {
        let Some(user) = session else {
            return login_redirect(state, route, headers);
        };
        // ForceAuthn: the user must have signed in after the request.
        if authn_state
            .authn_request_data
            .as_ref()
            .is_some_and(|d| d.force_authn)
            && user.auth_time < authn_state.created_utc.timestamp()
        {
            return login_redirect(state, route, headers);
        }
    }
    let sp = match saml
        .stores
        .service_providers
        .find_by_entity_id(&entity_id)
        .await
    {
        Ok(Some(sp)) => sp,
        Ok(None) => {
            return if authn_state.denial_error.is_some() {
                front_channel_error(state, "Service provider not found", Some(&entity_id))
            } else {
                sp_failure("Service provider not found", "Service provider not found")
            };
        }
        Err(e) => return crate::response::internal_error(state, info, ENDPOINT, &e.to_string()),
    };
    if !sp.enabled {
        return sp_failure(
            "Service provider is disabled",
            "Service provider is disabled",
        );
    }
    if !sp
        .assertion_consumer_service_urls
        .contains(&authn_state.assertion_consumer_service)
    {
        return sp_failure(
            "Assertion consumer service URL is no longer registered",
            "Assertion consumer service URL is no longer registered for this service provider",
        );
    }
    let data = authn_state.authn_request_data.clone();
    let request = ResponseRequest {
        sp: sp.clone(),
        acs: authn_state.assertion_consumer_service.clone(),
        relay_state: authn_state.relay_state.clone(),
        request_id: data.as_ref().and_then(|d| d.request_id.clone()),
        name_id_policy_format: data.as_ref().and_then(|d| d.name_id_policy_format.clone()),
        requested_claim_types: authn_state.requested_claim_types.clone(),
    };
    // A denial the login page recorded becomes a status response.
    if let Some(denial) = &authn_state.denial_error {
        let nested = match denial.as_str() {
            "InteractionRequired" => STATUS_NO_PASSIVE,
            "UnmetAuthenticationRequirements" => {
                "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext"
            }
            "ConsentRequired" => "urn:oasis:names:tc:SAML:2.0:status:RequestDenied",
            _ => "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
        };
        state.events.raise(
            info,
            now,
            rustid_core::events::Event::saml_sso_failure(
                Some(&sp.entity_id),
                &format!("access_denied ({denial})"),
                ENDPOINT,
            ),
        );
        let status = rustid_saml::response::Status::nested(STATUS_RESPONDER, nested);
        return error_response(state, saml, route, info, &request, status).await;
    }
    let user = session.expect("checked above");
    respond(state, saml, route, info, user, request).await
}

/// A 302 to the login page, the callback (path
/// and query, without the path base) as the return URL.
fn login_redirect(state: &ProtocolState, route: &Route, headers: &HeaderMap) -> Response {
    let ui = &state.options.user_interaction;
    let mut return_url = route.path.clone();
    if !route.query.is_empty() {
        return_url = format!("{return_url}?{}", route.query);
    }
    if !rustid_core::params::is_local_url(&ui.login_url) {
        return_url = crate::authorize::absolute_url(route, &return_url);
    }
    let url = rustid_core::params::add_query_param(
        &ui.login_url,
        &ui.login_return_url_parameter,
        &return_url,
    );
    let mut response = match axum::http::HeaderValue::from_str(&url) {
        Ok(location) => (
            StatusCode::FOUND,
            [(axum::http::header::LOCATION, location)],
        )
            .into_response(),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    // This browser may never have seen the SSO request (or its binding may
    // have expired): bind the return URL the login will continue to.
    crate::authorize::bind_interaction(state, route, headers, &mut response, &return_url);
    response
}

/// A local URL to the SSO callback
/// with a state id.
pub(crate) fn is_saml_return_url(state: &ProtocolState, return_url: &str) -> bool {
    let Some(saml) = state.saml.get() else {
        return false;
    };
    if !rustid_core::params::is_local_url(return_url) {
        return false;
    }
    let endpoints = &saml.options.endpoints;
    let (path, query) = match return_url.split_once('?') {
        Some((p, q)) => (p, q),
        None => return false,
    };
    if !path
        .to_ascii_lowercase()
        .ends_with(&endpoints.single_sign_on_callback_path.to_ascii_lowercase())
    {
        return false;
    }
    let query = query.split('#').next().unwrap_or_default();
    rustid_core::authorize::context::return_url_parameters(&format!("?{query}"))
        .get(&endpoints.state_id_parameter_name)
        .is_some()
}

/// Deny authentication for a SAML login: the denial is stored in the
/// sign-in state, and the callback answers the SP with it. An unknown or
/// expired state records nothing (the callback then sends the user to
/// login).
pub(crate) async fn record_denial(
    state: &ProtocolState,
    return_url: &str,
    error: rustid_core::consent::InteractionError,
    description: Option<String>,
) -> Result<(), rustid_core::stores::StoreError> {
    let Some(saml) = state.saml.get() else {
        return Ok(());
    };
    let query = return_url.split_once('?').map_or("", |(_, q)| q);
    let query = query.split('#').next().unwrap_or_default();
    let Some(id) = rustid_core::authorize::context::return_url_parameters(&format!("?{query}"))
        .get(&saml.options.endpoints.state_id_parameter_name)
        .and_then(|v| v.parse::<rustid_core::admin::EntityId>().ok())
    else {
        return Ok(());
    };
    let now = chrono::Utc::now();
    let Some(mut authn_state) = saml.stores.signin_states.retrieve(&id, now).await? else {
        tracing::warn!(%id, "SAML signin state not found or expired; the denial cannot be recorded");
        return Ok(());
    };
    // The interaction error names.
    authn_state.denial_error = Some(format!("{error:?}"));
    authn_state.denial_error_description = description;
    saml.stores
        .signin_states
        .update(&id, authn_state, now)
        .await
}

/// An enabled SP with an
/// HTTP-Redirect SLO endpoint.
pub(crate) struct SamlFrontChannelCheck<'a>(pub &'a rustid_saml::Saml);

#[async_trait::async_trait]
impl rustid_core::end_session::SamlFrontChannel for SamlFrontChannelCheck<'_> {
    async fn any_front_channel(
        &self,
        entity_ids: &[String],
    ) -> Result<bool, rustid_core::stores::StoreError> {
        for id in entity_ids {
            if let Some(sp) = self
                .0
                .stores
                .service_providers
                .find_by_entity_id(id)
                .await?
                && sp.enabled
                && rustid_saml::logout::slo_redirect_endpoint(&sp).is_some()
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// A front-channel LogoutRequest: its redirect URL (the iframe's `src`).
pub(crate) struct FrontChannelLogout {
    pub url: String,
    pub destination: String,
}

/// The saml 2 logout notification service and
/// A signed redirect-bound
/// LogoutRequest for each SAML session but the initiating SP's; unknown,
/// disabled and redirect-less SPs (and failures) count as skipped. When the
/// context names a SAML logout id, the logout session tracking the
/// responses is stored.
pub(crate) async fn front_channel_logouts(
    state: &ProtocolState,
    saml: &rustid_saml::Saml,
    route: &Route,
    context: &rustid_core::end_session::LogoutNotificationContext,
) -> Result<Vec<FrontChannelLogout>, String> {
    use rustid_saml::bindings::{MessageName, redirect};
    use rustid_saml::logout::{LogoutRequestOut, slo_redirect_endpoint, write_logout_request};
    // A reload of the page: the requests went out with the first load,
    // and the logout session tracking their answers is kept.
    if let Some(logout_id) = &context.saml_logout_id
        && saml
            .stores
            .logout_sessions
            .get(logout_id, chrono::Utc::now())
            .await
            .map_err(|e| e.to_string())?
            .is_some()
    {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let mut expected = std::collections::BTreeMap::new();
    let mut skipped = 0;
    if !context.saml_sessions.is_empty() {
        let issuer = rustid_saml::metadata::saml_issuer(
            &saml.options,
            crate::endpoint::RequestUrls::new(state, route).issuer(),
        );
        for session in &context.saml_sessions {
            if Some(&session.entity_id)
                == context.saml_initiating_service_provider_entity_id.as_ref()
            {
                continue;
            }
            let sp = saml
                .stores
                .service_providers
                .find_by_entity_id(&session.entity_id)
                .await
                .map_err(|e| e.to_string())?;
            let Some(sp) = sp.filter(|sp| sp.enabled) else {
                skipped += 1;
                continue;
            };
            let Some(endpoint) = slo_redirect_endpoint(&sp) else {
                skipped += 1;
                continue;
            };
            let request = LogoutRequestOut {
                id: rustid_saml::ids::create_id(),
                issue_instant: chrono::Utc::now(),
                destination: endpoint.location.clone(),
                issuer: issuer.clone(),
                name_id: session.name_id.clone(),
                name_id_format: session.name_id_format.clone(),
                session_index: session.session_index.clone(),
            };
            let built = async {
                let (key, certificate) = state
                    .keys
                    .saml_signing_key(&issuer)
                    .await
                    .map_err(|e| e.to_string())?;
                let signer = rustid_saml::signing::SamlKey { key, certificate };
                redirect::encode(
                    MessageName::SamlRequest,
                    &write_logout_request(&request),
                    None,
                    Some(&signer),
                )
                .map_err(|e| e.to_string())
            }
            .await;
            match built {
                Ok(query) => {
                    let separator = if request.destination.contains('?') {
                        "&"
                    } else {
                        "?"
                    };
                    out.push(FrontChannelLogout {
                        url: format!(
                            "{}{separator}{}",
                            request.destination,
                            query.trim_start_matches('?')
                        ),
                        destination: request.destination.clone(),
                    });
                    expected.insert(
                        request.id.clone(),
                        rustid_saml::state::ExpectedSpLogout {
                            sp_entity_id: sp.entity_id.clone(),
                            response: None,
                        },
                    );
                }
                Err(error) => {
                    tracing::warn!(entity_id = %sp.entity_id, %error, "failed to build a SAML logout request");
                    skipped += 1;
                }
            }
        }
    }
    if let Some(logout_id) = &context.saml_logout_id {
        let now = chrono::Utc::now();
        let session = rustid_saml::state::LogoutSession {
            logout_id: logout_id.clone(),
            expected_responses: expected,
            skipped_sp_count: skipped,
            created_utc: now,
            expires_at_utc: Some(
                now + chrono::Duration::seconds(saml.options.logout_session_lifetime.0),
            ),
        };
        saml.stores
            .logout_sessions
            .store(session)
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(out)
}

/// The saml 2 slo response generator and the front-channel result: a
/// LogoutResponse (Success, or Success/PartialLogout) to the SP's
/// HTTP-Redirect SLO endpoint (else the issuer), signed, by the binding
/// given (the request's, or the redirect binding from the callback).
#[allow(clippy::too_many_arguments)]
async fn logout_response(
    state: &ProtocolState,
    saml: &rustid_saml::Saml,
    route: &Route,
    info: &RequestInfo,
    sp: &rustid_saml::model::ServiceProvider,
    binding: rustid_saml::sso::InboundBinding,
    in_response_to: &str,
    relay_state: Option<&str>,
    partial: bool,
) -> Response {
    use rustid_saml::bindings::{MessageName, redirect};
    use rustid_saml::logout::{LogoutResponseOut, slo_redirect_endpoint, write_logout_response};
    use rustid_saml::response::{STATUS_SUCCESS, Status};
    let fail = |detail: &str| {
        crate::response::internal_error(state, info, "Saml2SloResponseGenerator", detail)
    };
    let issuer = rustid_saml::metadata::saml_issuer(
        &saml.options,
        crate::endpoint::RequestUrls::new(state, route).issuer(),
    );
    let destination = slo_redirect_endpoint(sp)
        .map(|e| e.location.clone())
        .unwrap_or_else(|| sp.entity_id.clone());
    let status = if partial {
        Status::nested(
            STATUS_SUCCESS,
            "urn:oasis:names:tc:SAML:2.0:status:PartialLogout",
        )
    } else {
        Status::success()
    };
    let response = LogoutResponseOut {
        id: rustid_saml::ids::create_id(),
        issue_instant: chrono::Utc::now(),
        destination: destination.clone(),
        in_response_to: Some(in_response_to.to_owned()),
        issuer: issuer.clone(),
        status,
    };
    let (key, certificate) = match state.keys.saml_signing_key(&issuer).await {
        Ok(found) => found,
        Err(e) => return fail(&e.to_string()),
    };
    let signer = rustid_saml::signing::SamlKey { key, certificate };
    let xml = write_logout_response(&response);
    match binding {
        rustid_saml::sso::InboundBinding::Redirect => {
            let query =
                match redirect::encode(MessageName::SamlResponse, &xml, relay_state, Some(&signer))
                {
                    Ok(query) => query,
                    Err(e) => return fail(&e.to_string()),
                };
            let separator = if destination.contains('?') { "&" } else { "?" };
            let location = format!("{destination}{separator}{}", query.trim_start_matches('?'));
            match axum::http::HeaderValue::from_str(&location) {
                Ok(value) => {
                    (StatusCode::FOUND, [(axum::http::header::LOCATION, value)]).into_response()
                }
                Err(_) => fail("invalid SLO destination"),
            }
        }
        rustid_saml::sso::InboundBinding::Post => {
            let signed = match rustid_saml::xml::dsig::sign(
                &xml,
                &response.id,
                &signer,
                &rustid_saml::xml::dom::Limits::default(),
            ) {
                Ok(signed) => signed,
                Err(e) => return fail(&e.to_string()),
            };
            let html = rustid_saml::response::auto_post_html(
                &destination,
                "SAMLResponse",
                &signed,
                relay_state,
            );
            (
                [
                    (CONTENT_TYPE, "text/html".to_owned()),
                    (
                        axum::http::header::CONTENT_SECURITY_POLICY,
                        format!(
                            "script-src '{}'",
                            rustid_saml::response::AUTO_POST_SCRIPT_HASH
                        ),
                    ),
                    (
                        axum::http::header::CACHE_CONTROL,
                        "no-cache, no-store".to_owned(),
                    ),
                ],
                html,
            )
                .into_response()
        }
    }
}

/// `SingleLogoutServiceEndpoint`: an SP's LogoutRequest (signs the user
/// out through the logout page, or answers at once when there's nothing to
/// sign out of) or LogoutResponse (recorded; always 200).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn single_logout(
    state: &ProtocolState,
    saml: &rustid_saml::Saml,
    route: &Route,
    method: &Method,
    headers: &HeaderMap,
    body: axum::body::Body,
    info: &RequestInfo,
    session: Option<&rustid_core::session::UserSession>,
) -> Response {
    use rustid_saml::bindings::MessageName;
    use rustid_saml::protocol::ReadError;
    use rustid_saml::sso::{
        InboundBinding, UnbindError, redirect_trust, select_binding, signing_entity, unbind_post,
        unbind_redirect,
    };
    const OPERATION: &str = "SingleLogoutServiceEndpoint";
    let options = &saml.options;
    let unhandled = |detail: &str| crate::response::internal_error(state, info, OPERATION, detail);
    if method != Method::GET && method != Method::POST {
        return front_channel_error(state, "Method not allowed", None);
    }
    let mut form: Vec<(String, String)> = Vec::new();
    if method == Method::POST {
        if !crate::endpoint::is_form_content_type(headers) {
            return unhandled("InvalidOperationException: Incorrect Content-Type");
        }
        let Some(parsed) = crate::endpoint::read_form(body).await else {
            return unhandled("InvalidDataException: the form could not be read");
        };
        form = parsed
            .pairs()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();
    }
    let keys: Vec<&str> = form.iter().map(|(k, _)| k.as_str()).collect();
    let Some(binding) = select_binding(method.as_str(), &route.query, &keys) else {
        return front_channel_error(
            state,
            "No front channel binding found to satisfy request",
            None,
        );
    };
    let unbound = match binding {
        InboundBinding::Redirect => unbind_redirect(
            &route.query,
            options.max_message_size,
            options.max_relay_state_length,
        ),
        InboundBinding::Post => unbind_post(
            &form,
            options.max_message_size,
            options.max_relay_state_length,
        ),
    };
    let inbound = match unbound {
        Ok(inbound) => inbound,
        Err(UnbindError::Base64) => {
            return front_channel_error(
                state,
                "Invalid base64 encoding in SAML logout message",
                None,
            );
        }
        Err(UnbindError::Unhandled(detail)) => return unhandled(&detail),
    };
    let issuer = rustid_saml::protocol::issuer_of(&inbound.document());
    let sp = match &issuer {
        Some(entity_id) => match saml
            .stores
            .service_providers
            .find_by_entity_id(entity_id)
            .await
        {
            Ok(sp) => sp,
            Err(e) => return unhandled(&e.to_string()),
        },
        None => None,
    };
    let entity = sp.as_deref().and_then(signing_entity);
    let trust = redirect_trust(&inbound, entity.as_ref());
    // Errors the endpoint answers with an error page, apart from the
    // rest.
    let caught = |e: &ReadError| match e {
        ReadError::Invalid(_) => true,
        ReadError::Unhandled(detail) => detail.starts_with("InvalidOperationException"),
    };

    if inbound.name == MessageName::SamlResponse {
        let read = rustid_saml::protocol::read_logout_response(
            &inbound.document(),
            trust,
            entity.as_ref(),
        );
        let response = match read {
            Ok(response) => response,
            Err(e) if caught(&e) => {
                tracing::warn!(error = ?e, "failed to parse a SAML LogoutResponse");
                return StatusCode::OK.into_response();
            }
            Err(ReadError::Unhandled(detail)) => return unhandled(&detail),
            Err(ReadError::Invalid(_)) => unreachable!(),
        };
        let (Some(in_response_to), Some(issuer)) = (
            response.in_response_to.as_deref().filter(|v| !v.is_empty()),
            response
                .issuer
                .as_ref()
                .map(|i| i.value.as_str())
                .filter(|v| !v.is_empty()),
        ) else {
            return StatusCode::OK.into_response();
        };
        let responder = match saml
            .stores
            .service_providers
            .find_by_entity_id(issuer)
            .await
        {
            Ok(sp) => sp,
            Err(e) => return unhandled(&e.to_string()),
        };
        let require_signed = responder
            .as_ref()
            .and_then(|sp| sp.require_signed_logout_responses)
            .unwrap_or(options.require_signed_logout_responses);
        if require_signed
            && response.trust.max(trust) < rustid_saml::protocol::TrustLevel::ConfiguredKey
        {
            tracing::warn!(issuer, "rejecting an unsigned SAML LogoutResponse");
            return StatusCode::OK.into_response();
        }
        let success = response.status_code.as_deref()
            == Some(rustid_saml::response::STATUS_SUCCESS)
            && response.nested_status_code.as_deref()
                != Some("urn:oasis:names:tc:SAML:2.0:status:PartialLogout");
        match saml
            .stores
            .logout_sessions
            .try_record_response(in_response_to, issuer, success, chrono::Utc::now())
            .await
        {
            Ok(true) => {}
            Ok(false) => tracing::warn!(in_response_to, issuer, "SAML LogoutResponse not recorded"),
            Err(e) => return unhandled(&e.to_string()),
        }
        return StatusCode::OK.into_response();
    }

    // A LogoutRequest.
    let read =
        rustid_saml::protocol::read_logout_request(&inbound.document(), trust, entity.as_ref());
    let request = match read {
        Ok(request) => request,
        Err(e) if caught(&e) => {
            tracing::warn!(error = ?e, "failed to parse a SAML LogoutRequest");
            return front_channel_error(
                state,
                "The SAML logout request could not be processed",
                None,
            );
        }
        Err(ReadError::Unhandled(detail)) => return unhandled(&detail),
        Err(ReadError::Invalid(_)) => unreachable!(),
    };
    let issuer_value = request.issuer.as_ref().map(|i| i.value.clone());
    let sp = match &issuer_value {
        Some(value) if Some(value) != issuer.as_ref() => {
            match saml.stores.service_providers.find_by_entity_id(value).await {
                Ok(sp) => sp,
                Err(e) => return unhandled(&e.to_string()),
            }
        }
        _ => sp,
    };
    let base_url = route.origin.base_url();
    let validated =
        rustid_saml::logout::validate_logout_request(&rustid_saml::logout::LogoutValidationInput {
            options,
            now: chrono::Utc::now(),
            base_url: &base_url,
            sp: sp.as_deref(),
            request: &request,
            user_saml_sessions: session.map(|s| s.saml_sessions.as_slice()),
        });
    let session_found = match validated {
        Ok(found) => found,
        Err(failure) => {
            state.events.raise(
                info,
                chrono::Utc::now(),
                rustid_core::events::Event::saml_logout_request_validation_failure(
                    issuer_value.as_deref(),
                    &failure.description,
                    Some(binding.urn()),
                ),
            );
            return front_channel_error(state, &failure.description, issuer_value.as_deref());
        }
    };
    let sp = sp.expect("validated requests have a provider");
    let relay_state = inbound.relay_state.clone();
    let Some(user) = session.filter(|_| session_found) else {
        state.events.raise(
            info,
            chrono::Utc::now(),
            rustid_core::events::Event::saml_slo_success(
                &sp.entity_id,
                request.session_index.as_deref(),
                "SP",
            ),
        );
        return logout_response(
            state,
            saml,
            route,
            info,
            &sp,
            binding,
            &request.id,
            relay_state.as_deref(),
            false,
        )
        .await;
    };
    // The logout page, which ends the session and
    // then comes back to the SLO callback.
    let callback = format!(
        "{}/{}",
        route.origin.base_path.trim_end_matches('/'),
        options
            .endpoints
            .single_logout_callback_path
            .trim_start_matches('/')
    );
    let message = rustid_core::end_session::LogoutMessage {
        subject_id: Some(user.subject_id.clone()),
        session_id: Some(user.session_id.clone()),
        client_ids: user.client_ids.clone(),
        post_logout_redirect_uri: Some(callback),
        saml_service_provider_entity_id: Some(sp.entity_id.clone()),
        saml_sessions: user.saml_sessions.clone(),
        saml_logout_request_id: Some(request.id.clone()),
        saml_relay_state: relay_state,
        ..Default::default()
    };
    let logout_id = rustid_core::authorize::messages::write(
        &state.interaction.protector,
        rustid_core::end_session::LOGOUT_MESSAGE_PURPOSE,
        message,
        chrono::Utc::now(),
    );
    let ui = &state.options.user_interaction;
    // The logout page, made absolute.
    let url =
        rustid_core::params::add_query_param(&ui.logout_url, &ui.logout_id_parameter, &logout_id);
    crate::authorize::redirect(&crate::authorize::absolute_url(route, &url))
}

/// `SingleLogoutCallbackEndpoint`: after the logout page, the LogoutResponse
/// to the SP that asked: Success when every other SP answered successfully
/// and none was skipped, else PartialLogout.
pub(crate) async fn single_logout_callback(
    state: &ProtocolState,
    saml: &rustid_saml::Saml,
    route: &Route,
    method: &Method,
    info: &RequestInfo,
) -> Response {
    const OPERATION: &str = "SingleLogoutCallbackEndpoint";
    if method != Method::GET {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let ui = &state.options.user_interaction;
    let params = rustid_core::params::Params::parse_query(&route.query);
    let Some(logout_id) = params
        .get(&ui.logout_id_parameter)
        .filter(|v| !v.trim().is_empty())
    else {
        return front_channel_error(
            state,
            "Missing or invalid SAML logout state identifier",
            None,
        );
    };
    let Some(message) = crate::end_session::read_logout_message(state, &logout_id) else {
        return front_channel_error(state, "SAML logout state not found or expired", None);
    };
    let Some(entity_id) = message
        .saml_service_provider_entity_id
        .clone()
        .filter(|v| !v.trim().is_empty())
    else {
        return front_channel_error(
            state,
            "SAML logout state is missing service provider information",
            None,
        );
    };
    let Some(request_id) = message
        .saml_logout_request_id
        .clone()
        .filter(|v| !v.trim().is_empty())
    else {
        return front_channel_error(
            state,
            "SAML logout state is missing request identifier",
            None,
        );
    };
    let sp = match saml
        .stores
        .service_providers
        .find_by_entity_id(&entity_id)
        .await
    {
        Ok(Some(sp)) => sp,
        Ok(None) => return front_channel_error(state, "SAML service provider not found", None),
        Err(e) => return crate::response::internal_error(state, info, OPERATION, &e.to_string()),
    };
    if !sp.enabled {
        return front_channel_error(state, "SAML service provider is disabled", None);
    }
    if sp.single_logout_service_urls.is_empty() {
        return front_channel_error(
            state,
            "SAML service provider has no logout endpoint configured",
            None,
        );
    }
    if rustid_saml::logout::slo_redirect_endpoint(&sp).is_none() {
        return front_channel_error(
            state,
            "SAML service provider has no HTTP-Redirect logout endpoint configured",
            None,
        );
    }
    let now = chrono::Utc::now();
    let session = match saml.stores.logout_sessions.get(&logout_id, now).await {
        Ok(session) => session,
        Err(e) => return crate::response::internal_error(state, info, OPERATION, &e.to_string()),
    };
    let all_succeeded = session.as_ref().is_some_and(|s| {
        s.skipped_sp_count == 0
            && s.expected_responses
                .values()
                .all(|e| e.response.as_ref().is_some_and(|r| r.success))
    });
    let response = logout_response(
        state,
        saml,
        route,
        info,
        &sp,
        rustid_saml::sso::InboundBinding::Redirect,
        &request_id,
        message.saml_relay_state.as_deref(),
        !all_succeeded,
    )
    .await;
    let event = if all_succeeded {
        rustid_core::events::Event::saml_slo_success(&sp.entity_id, None, "SP")
    } else {
        rustid_core::events::Event::saml_slo_failure(
            Some(&sp.entity_id),
            "Partial logout - not all SPs responded successfully",
        )
    };
    state.events.raise(info, now, event);
    if session.is_some()
        && let Err(e) = saml.stores.logout_sessions.remove(&logout_id).await
    {
        return crate::response::internal_error(state, info, OPERATION, &e.to_string());
    }
    response
}

/// The path of the IdP-initiated SSO continuation, under the path base.
pub const IDP_INITIATED_CONTINUE_PATH: &str = "/connect/interaction/saml/idp-initiated";

fn idp_initiated_refusal(message: &str) -> Response {
    crate::response::no_cache_json(
        StatusCode::BAD_REQUEST,
        &serde_json::json!({ "error": message }),
    )
}

/// The SP, checked as the idp initiated sso service checks it, with its
/// claim types; or the refusal.
async fn idp_initiated_target(
    state: &ProtocolState,
    saml: &rustid_saml::Saml,
    info: &RequestInfo,
    entity_id: &str,
    relay_state: Option<&str>,
    session: Option<&rustid_core::session::UserSession>,
) -> Result<ResponseRequest, Response> {
    let sp = if entity_id.trim().is_empty() {
        None
    } else {
        saml.stores
            .service_providers
            .find_by_entity_id(entity_id)
            .await
            .map_err(|e| {
                crate::response::internal_error(state, info, "IdpInitiatedSso", &e.to_string())
            })?
    };
    let target =
        rustid_saml::idp_initiated::check(sp.as_deref(), entity_id, relay_state, &saml.options)
            .map_err(|refusal| idp_initiated_refusal(&refusal.0))?;
    let sp = sp.expect("check refuses a missing SP");
    if session.is_none() {
        return Err(idp_initiated_refusal("User is not authenticated"));
    }
    let resources = state
        .stores
        .resources
        .get_all_enabled_resources()
        .await
        .map_err(|e| {
            crate::response::internal_error(state, info, "IdpInitiatedSso", &e.to_string())
        })?;
    let requested_claim_types =
        rustid_saml::sso::resolve_claim_types(&sp, &resources.identity_resources)
            .ok_or_else(|| idp_initiated_refusal("Service provider configuration error"))?;
    Ok(ResponseRequest {
        sp,
        acs: target.acs,
        relay_state: target.relay_state,
        request_id: None,
        name_id_policy_format: None,
        requested_claim_types,
    })
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct IdpInitiatedBody {
    #[serde(default)]
    sp_entity_id: String,
    #[serde(default)]
    relay_state: Option<String>,
}

/// `POST /interaction/saml/idp-initiated` (the UI's back end, with the
/// browser's cookies): the checks, then a one-time
/// continuation URL the browser visits for the response.
pub(crate) async fn idp_initiated(
    state: &ProtocolState,
    route: &Route,
    info: &RequestInfo,
    session: Option<&rustid_core::session::UserSession>,
    body: IdpInitiatedBody,
) -> Response {
    let Some(saml) = state.saml.get() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let request = match idp_initiated_target(
        state,
        saml,
        info,
        &body.sp_entity_id,
        body.relay_state.as_deref(),
        session,
    )
    .await
    {
        Ok(request) => request,
        Err(refusal) => return refusal,
    };
    let continuation = rustid_saml::idp_initiated::Continuation {
        entity_id: request.sp.entity_id.clone(),
        relay_state: request.relay_state,
        session_id: session.expect("checked above").session_id.clone(),
    };
    match continuation
        .store(state.stores.grants.as_ref(), chrono::Utc::now())
        .await
    {
        Ok(token) => crate::response::no_cache_json(
            StatusCode::OK,
            &serde_json::json!({
                "continueUrl": format!(
                    "{}{IDP_INITIATED_CONTINUE_PATH}?token={}",
                    route.origin.base_url(),
                    rustid_core::params::url_encode(&token)
                )
            }),
        ),
        Err(e) => crate::response::internal_error(state, info, "IdpInitiatedSso", &e.to_string()),
    }
}

/// `GET /connect/interaction/saml/idp-initiated?token=…` (the browser):
/// Redeems the continuation once, in the session that asked, checks the SP
/// again and answers with the auto-post page.
pub(crate) async fn continue_idp_initiated(
    state: &ProtocolState,
    route: &Route,
    info: &RequestInfo,
    session: Option<&rustid_core::session::UserSession>,
) -> Response {
    let Some(saml) = state.saml.get() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let params = rustid_core::params::Params::parse_query(&route.query);
    let Some(token) = params.get("token") else {
        return idp_initiated_refusal("invalid_continuation");
    };
    let continuation = match rustid_saml::idp_initiated::Continuation::redeem(
        state.stores.grants.as_ref(),
        &token,
        chrono::Utc::now(),
    )
    .await
    {
        Ok(Some(continuation)) => continuation,
        Ok(None) => return idp_initiated_refusal("invalid_continuation"),
        Err(e) => {
            return crate::response::internal_error(state, info, "IdpInitiatedSso", &e.to_string());
        }
    };
    let Some(session) = session else {
        return idp_initiated_refusal("User is not authenticated");
    };
    if session.session_id != continuation.session_id {
        return idp_initiated_refusal("invalid_continuation");
    }
    let request = match idp_initiated_target(
        state,
        saml,
        info,
        &continuation.entity_id,
        continuation.relay_state.as_deref(),
        Some(session),
    )
    .await
    {
        Ok(request) => request,
        Err(refusal) => return refusal,
    };
    // The service records the `sub` claim and the SP's default format
    // as the session's NameID here; `respond` records the NameID it issued,
    // so a later LogoutRequest names what the SP actually received.
    respond(state, saml, route, info, session, request).await
}

#[cfg(test)]
mod idp_initiated_body_tests {
    use super::IdpInitiatedBody;

    #[test]
    fn a_misspelt_member_is_refused() {
        let ok = serde_json::json!({ "spEntityId": "https://sp", "relayState": "r" });
        assert!(serde_json::from_value::<IdpInitiatedBody>(ok).is_ok());
        let misspelt = serde_json::json!({ "spEntityId": "https://sp", "relayStat": "r" });
        assert!(serde_json::from_value::<IdpInitiatedBody>(misspelt).is_err());
    }
}
