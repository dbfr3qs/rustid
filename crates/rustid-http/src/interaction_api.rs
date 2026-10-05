//! The interaction API: how a UI app reads interaction contexts and
//! completes interactions, authenticated with a bearer API key
//! (`interaction.api_keys`). Logout arrives with the flow that needs it. The continuation endpoint, which the browser visits, needs
//! no key: its one-time token and the browser binding are the credential.

use axum::body::Body;
use axum::http::header::{
    AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, LOCATION, PRAGMA, WWW_AUTHENTICATE,
};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use rustid_core::access_tokens::ValidationContext;
use rustid_core::authorize::AuthorizeContext;
use rustid_core::authorize::context::{
    AuthorizationContext, ConsentContext, is_valid_return_url, validated_return_url,
};
use rustid_core::authorize::login::{BINDING_COOKIE, Continuation, InteractionBinding};
use rustid_core::authorize::messages::{self, ERROR_MESSAGE_PURPOSE, ErrorMessage};
use rustid_core::consent::{self, ConsentResponse, InteractionError};
use rustid_core::events::RequestInfo;
use rustid_core::issuer::current_issuer;
use rustid_core::logout::{LogoutContinuation, process_logout};
use rustid_core::params::{Params, add_query_param, is_local_url, url_encode};
use rustid_core::secrets::constant_time_eq;
use rustid_core::session::{SESSION_COOKIE, SignIn, UserSession};
use rustid_core::tokens::Claim;
use serde::Deserialize;
use serde_json::json;

use crate::ProtocolState;
use crate::cookies;
use crate::request::{Incoming, Route};
use crate::response::{internal_error, no_cache_json};

/// The path of the continuation endpoint, under the path base.
pub const CONTINUE_PATH: &str = "/connect/interaction/continue";
/// The path of the logout continuation endpoint, under the path base.
pub const LOGOUT_CONTINUE_PATH: &str = "/connect/interaction/logout";

/// Paths the API serves, matched case-insensitively.
pub(crate) enum Call {
    Error,
    Login,
    Consent,
    Deny,
    Session,
    Logout,
    Sessions,
    RemoveSessions,
    Device,
    Ciba,
    Continue,
    ContinueLogout,
    /// `/interaction/saml/idp-initiated`: IdP-initiated SAML SSO.
    SamlIdpInitiated,
    /// Its continuation, which the browser visits.
    ContinueSamlIdpInitiated,
}

impl Call {
    pub(crate) fn find(lower_path: &str) -> Option<Call> {
        match lower_path {
            "/interaction/error" => Some(Call::Error),
            "/interaction/login" => Some(Call::Login),
            "/interaction/consent" => Some(Call::Consent),
            "/interaction/deny" => Some(Call::Deny),
            "/interaction/session" => Some(Call::Session),
            "/interaction/logout" => Some(Call::Logout),
            "/interaction/sessions" => Some(Call::Sessions),
            "/interaction/sessions/remove" => Some(Call::RemoveSessions),
            "/interaction/device" => Some(Call::Device),
            "/interaction/ciba" => Some(Call::Ciba),
            CONTINUE_PATH => Some(Call::Continue),
            LOGOUT_CONTINUE_PATH => Some(Call::ContinueLogout),
            "/interaction/saml/idp-initiated" => Some(Call::SamlIdpInitiated),
            "/connect/interaction/saml/idp-initiated" => Some(Call::ContinueSamlIdpInitiated),
            _ => None,
        }
    }
}

pub(crate) async fn handle(
    state: &ProtocolState,
    incoming: &Incoming<'_>,
    body: Body,
    call: &Call,
) -> Response {
    let Incoming {
        route,
        method,
        headers,
        info,
        session,
    } = *incoming;
    if let Call::Continue = call {
        return if method == Method::GET {
            continue_login(state, route, headers, info, session).await
        } else {
            StatusCode::METHOD_NOT_ALLOWED.into_response()
        };
    }
    if let Call::ContinueLogout = call {
        return if method == Method::GET {
            continue_logout(state, route, headers, info, session).await
        } else {
            StatusCode::METHOD_NOT_ALLOWED.into_response()
        };
    }
    if let Call::ContinueSamlIdpInitiated = call {
        return if method == Method::GET {
            continue_saml_idp_initiated(state, route, info, session).await
        } else {
            StatusCode::METHOD_NOT_ALLOWED.into_response()
        };
    }
    if !authorized(state, headers) {
        return (StatusCode::UNAUTHORIZED, [(WWW_AUTHENTICATE, "Bearer")]).into_response();
    }
    match (call, method) {
        (Call::Error, &Method::GET) => error_context(state, route),
        (Call::Login, &Method::GET) => login_context(state, route, info).await,
        (Call::Login, &Method::POST) => login(state, route, headers, body, info).await,
        (Call::Consent, &Method::GET) => consent_context(state, route, info).await,
        (Call::Consent, &Method::POST) => {
            answer_consent(state, route, headers, body, info, session, false).await
        }
        (Call::Deny, &Method::POST) => {
            answer_consent(state, route, headers, body, info, session, true).await
        }
        (Call::Session, &Method::GET) => session_info(session),
        (Call::Logout, &Method::GET) => logout_context(state, route, info, session).await,
        (Call::Logout, &Method::POST) => logout(state, route, headers, body, info, session).await,
        (Call::Sessions, &Method::GET) => query_sessions(state, route, info).await,
        (Call::RemoveSessions, &Method::POST) => {
            remove_sessions(state, route, headers, body, info).await
        }
        (Call::Device, &Method::GET) => device_context(state, route, info).await,
        (Call::Device, &Method::POST) => device_decision(state, headers, body, info, session).await,
        (Call::Ciba, &Method::GET) => ciba_requests(state, route, info, session).await,
        (Call::Ciba, &Method::POST) => ciba_completion(state, headers, body, info, session).await,
        (Call::SamlIdpInitiated, &Method::POST) => {
            saml_idp_initiated(state, route, headers, body, info, session).await
        }
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}

/// `Authorization: Bearer <key>` naming one of the configured keys.
fn authorized(state: &ProtocolState, headers: &HeaderMap) -> bool {
    let Some(presented) = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
        .map(|(_, key)| key.trim())
    else {
        return false;
    };
    // Every key is compared, so timing says nothing about which matched.
    state.interaction.api_keys.iter().fold(false, |found, key| {
        constant_time_eq(key.as_bytes(), presented.as_bytes()) | found
    })
}

fn bad_request(error: &str) -> Response {
    no_cache_json(StatusCode::BAD_REQUEST, &json!({ "error": error }))
}

/// `GET /interaction/error?errorId=…`: get error context.
fn error_context(state: &ProtocolState, route: &Route) -> Response {
    let params = Params::parse_query(&route.query);
    let message = params.get("errorId").and_then(|id| {
        messages::read::<ErrorMessage>(&state.interaction.protector, ERROR_MESSAGE_PURPOSE, &id)
    });
    match message {
        Some(message) => no_cache_json(StatusCode::OK, &json!(message.data)),
        None => no_cache_json(StatusCode::NOT_FOUND, &json!({ "error": "not_found" })),
    }
}

/// `GET /interaction/login?returnUrl=…`: get authorization context
/// for the request the login page is completing. The API caller is the
/// UI, not the browser, so the request is validated without a session.
async fn login_context(state: &ProtocolState, route: &Route, info: &RequestInfo) -> Response {
    let params = Params::parse_query(&route.query);
    let Some(return_url) = params.get("returnUrl") else {
        return bad_request("invalid_return_url");
    };
    let issuer = current_issuer(&state.options, &route.origin);
    let ctx = authorize_ctx(state, info, &issuer);
    match validated_return_url(&ctx, &return_url, None).await {
        Ok(Some(request)) => {
            let mut context = json!(AuthorizationContext::of(&request));
            let client = request
                .client
                .as_ref()
                .expect("validated request has a client");
            // The providers this client may sign in through, as buttons.
            let providers: Vec<serde_json::Value> = state
                .stores
                .federation
                .providers
                .allowed_for(client)
                .iter()
                .map(|p| {
                    json!({
                        "scheme": p.config.scheme,
                        "displayName": p.config.display_name,
                        "challengeUrl": crate::federation::challenge_url(route, &p.config.scheme, &return_url),
                    })
                })
                .collect();
            context["identityProviders"] = json!(providers);
            context["enableLocalLogin"] = json!(client.enable_local_login);
            no_cache_json(StatusCode::OK, &context)
        }
        Ok(None) => no_cache_json(StatusCode::NOT_FOUND, &json!({ "error": "not_found" })),
        Err(e) => internal_error(state, info, "GetAuthorizationContext", &e.to_string()),
    }
}

/// A JSON request body, or the response refusing it.
async fn read_json<T: serde::de::DeserializeOwned>(
    headers: &HeaderMap,
    body: Body,
) -> Result<T, Box<Response>> {
    let is_json = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|m| m.trim().eq_ignore_ascii_case("application/json"));
    if !is_json {
        return Err(Box::new(StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response()));
    }
    let Ok(bytes) = axum::body::to_bytes(body, 1024 * 1024).await else {
        return Err(Box::new(bad_request("invalid_body")));
    };
    serde_json::from_slice::<T>(&bytes).map_err(|_| Box::new(bad_request("invalid_body")))
}

fn authorize_ctx<'a>(
    state: &'a ProtocolState,
    info: &'a RequestInfo,
    issuer: &'a str,
) -> AuthorizeContext<'a> {
    AuthorizeContext {
        options: &state.options,
        issuer,
        stores: &state.stores,
        events: &state.events,
        request: info,
        now: chrono::Utc::now(),
    }
}

fn ciba_json(request: &rustid_core::ciba::CibaLoginRequest) -> serde_json::Value {
    json!({
        "id": request.internal_id,
        "subjectId": request.subject_id,
        "clientId": request.client.client_id,
        "clientName": request.client.client_name,
        "scopes": request.scopes,
        "resourceIndicators": request.resource_indicators,
        "bindingMessage": request.binding_message,
        "acrValues": request.acr_values,
        "properties": request.properties,
    })
}

/// `GET /interaction/ciba?id=…`: one backchannel authentication request
/// ; without `id`, the signed-in
/// user's pending ones.
async fn ciba_requests(
    state: &ProtocolState,
    route: &Route,
    info: &RequestInfo,
    session: Option<&UserSession>,
) -> Response {
    let params = Params::parse_query(&route.query);
    let result = match params.get("id") {
        Some(id) => rustid_core::ciba::login_request(&state.stores, &id)
            .await
            .map(|r| match r {
                Some(request) => no_cache_json(StatusCode::OK, &ciba_json(&request)),
                None => no_cache_json(StatusCode::NOT_FOUND, &json!({ "error": "not_found" })),
            }),
        None => {
            let Some(session) = session else {
                return no_cache_json(StatusCode::OK, &json!([]));
            };
            rustid_core::ciba::pending_for_subject(&state.stores, &session.subject_id)
                .await
                .map(|pending| {
                    let list: Vec<_> = pending.iter().map(ciba_json).collect();
                    no_cache_json(StatusCode::OK, &json!(list))
                })
        }
    };
    result.unwrap_or_else(|e| {
        internal_error(state, info, "GetBackchannelLoginRequests", &e.to_string())
    })
}

/// The CIBA completion's body: consented scopes, or an error to deny.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CibaBody {
    id: String,
    #[serde(default)]
    scopes: Option<Vec<String>>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

/// `POST /interaction/ciba`: the signed-in
/// user in the forwarded cookies consents, or with `error` denies.
async fn ciba_completion(
    state: &ProtocolState,
    headers: &HeaderMap,
    body: Body,
    info: &RequestInfo,
    session: Option<&UserSession>,
) -> Response {
    let body: CibaBody = match read_json(headers, body).await {
        Ok(body) => body,
        Err(response) => return *response,
    };
    let scopes = if body.error.is_some() {
        None
    } else {
        body.scopes
    };
    match rustid_core::ciba::complete(
        &state.stores,
        &body.id,
        session,
        scopes.as_deref(),
        body.description.as_deref(),
        chrono::Utc::now(),
    )
    .await
    {
        Ok(Ok(())) => no_cache_json(StatusCode::OK, &json!({})),
        Ok(Err(message)) => no_cache_json(
            StatusCode::BAD_REQUEST,
            &json!({ "error": "invalid_ciba_request", "errorDescription": message }),
        ),
        Err(e) => internal_error(
            state,
            info,
            "CompleteBackchannelLoginRequest",
            &e.to_string(),
        ),
    }
}

/// `GET /interaction/device?userCode=…`: the pending device authorization
/// a device page shows.
async fn device_context(state: &ProtocolState, route: &Route, info: &RequestInfo) -> Response {
    let params = Params::parse_query(&route.query);
    let user_code = params.get("userCode").unwrap_or_default();
    if user_code.len() > state.options.input_length_restrictions.user_code {
        return bad_request("invalid_user_code");
    }
    match rustid_core::device_flow::authorization_context(&state.stores, &user_code).await {
        Ok(Some(context)) => no_cache_json(
            StatusCode::OK,
            &json!({
                "clientId": context.client.client_id,
                "clientName": context.client.client_name,
                "scopes": context.scopes,
            }),
        ),
        Ok(None) => no_cache_json(StatusCode::NOT_FOUND, &json!({ "error": "not_found" })),
        Err(e) => internal_error(state, info, "GetDeviceAuthorizationContext", &e.to_string()),
    }
}

/// The device decision's body: consented scopes, or an error to deny.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeviceBody {
    user_code: String,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

/// `POST /interaction/device`: the signed-in user in
/// the forwarded cookies approves the consented scopes, or with `error`
/// denies.
async fn device_decision(
    state: &ProtocolState,
    headers: &HeaderMap,
    body: Body,
    info: &RequestInfo,
    session: Option<&UserSession>,
) -> Response {
    let body: DeviceBody = match read_json(headers, body).await {
        Ok(body) => body,
        Err(response) => return *response,
    };
    let scopes = if body.error.is_some() {
        Vec::new()
    } else {
        body.scopes
    };
    match rustid_core::device_flow::decide(
        &state.stores,
        &body.user_code,
        session,
        &scopes,
        body.description.as_deref(),
    )
    .await
    {
        Ok(Ok(())) => no_cache_json(StatusCode::OK, &json!({})),
        Ok(Err(message)) => no_cache_json(
            StatusCode::BAD_REQUEST,
            &json!({ "error": "invalid_device_request", "errorDescription": message }),
        ),
        Err(e) => internal_error(state, info, "HandleDeviceRequest", &e.to_string()),
    }
}

/// `GET /interaction/consent?returnUrl=…`: what a consent page shows for
/// the request (get authorization context with its resources).
async fn consent_context(state: &ProtocolState, route: &Route, info: &RequestInfo) -> Response {
    let params = Params::parse_query(&route.query);
    let Some(return_url) = params.get("returnUrl") else {
        return bad_request("invalid_return_url");
    };
    let issuer = current_issuer(&state.options, &route.origin);
    match validated_return_url(&authorize_ctx(state, info, &issuer), &return_url, None).await {
        Ok(Some(request)) => no_cache_json(StatusCode::OK, &json!(ConsentContext::of(&request))),
        Ok(None) => no_cache_json(StatusCode::NOT_FOUND, &json!({ "error": "not_found" })),
        Err(e) => internal_error(state, info, "GetAuthorizationContext", &e.to_string()),
    }
}

/// The consent and deny calls' body.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConsentBody {
    return_url: String,
    #[serde(default)]
    subject_id: Option<String>,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    remember_consent: bool,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

/// `POST /interaction/consent` and `POST
/// /interaction/deny`: keeps the answer for the
/// authorize callback and tells the UI where to send the browser. A grant
/// names the subject that consents; a denial may be anonymous and is
/// `access_denied` unless it names another error.
async fn answer_consent(
    state: &ProtocolState,
    route: &Route,
    headers: &HeaderMap,
    body: Body,
    info: &RequestInfo,
    session: Option<&UserSession>,
    deny: bool,
) -> Response {
    let body: ConsentBody = match read_json(headers, body).await {
        Ok(body) => body,
        Err(response) => return *response,
    };
    if deny && (!body.scopes.is_empty() || body.remember_consent || body.description.is_some()) {
        return bad_request("invalid_body");
    }
    let error = match body.error.as_deref() {
        Some(code) => match InteractionError::parse(code) {
            Some(error) => Some(error),
            None => return bad_request("invalid_error"),
        },
        None if deny => Some(InteractionError::AccessDenied),
        None => None,
    };
    // The body's subject, else the session in the cookies the UI
    // forwarded, as grant consent falls back to the current user.
    let subject = body
        .subject_id
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .or(session.map(|s| s.subject_id.as_str()));
    let response = ConsentResponse {
        error,
        error_description: body.error_description,
        remember_consent: body.remember_consent,
        scopes_values_consented: body.scopes,
        description: body.description,
    };
    match record_answer(state, route, info, &body.return_url, subject, response).await {
        Ok(redirect_url) => no_cache_json(StatusCode::OK, &json!({ "redirectUrl": redirect_url })),
        Err(response) => *response,
    }
}

/// Records a refusal of the request behind `return_url`, as the deny call
/// does, and returns where to send the browser: the return URL, which then
/// answers the client with the error.
pub(crate) async fn record_denial(
    state: &ProtocolState,
    route: &Route,
    info: &RequestInfo,
    return_url: &str,
    error: InteractionError,
    description: Option<String>,
) -> Result<String, Box<Response>> {
    let response = ConsentResponse {
        error: Some(error),
        error_description: description,
        remember_consent: false,
        scopes_values_consented: Vec::new(),
        description: None,
    };
    record_answer(state, route, info, return_url, None, response).await
}

/// Records the consent page's answer (or a refusal) for `return_url` and
/// returns the absolute URL to send the browser to. A SAML login records a
/// refusal in its state (there's no consent to grant).
async fn record_answer(
    state: &ProtocolState,
    route: &Route,
    info: &RequestInfo,
    return_url: &str,
    subject: Option<&str>,
    response: ConsentResponse,
) -> Result<String, Box<Response>> {
    let redirect_url = format!("{}{}", route.origin.origin(), return_url);
    if is_saml_return_url(state, return_url) {
        let Some(error) = response.error else {
            return Err(Box::new(bad_request("invalid_return_url")));
        };
        if let Err(e) =
            record_saml_denial(state, return_url, error, response.error_description).await
        {
            return Err(Box::new(internal_error(
                state,
                info,
                "DenyAuthentication",
                &e.to_string(),
            )));
        }
        return Ok(redirect_url);
    }
    if response.error.is_none() && subject.is_none() {
        return Err(Box::new(bad_request("invalid_subject")));
    }
    let issuer = current_issuer(&state.options, &route.origin);
    let ctx = authorize_ctx(state, info, &issuer);
    let request = match validated_return_url(&ctx, return_url, None).await {
        Ok(Some(request)) => request,
        Ok(None) => return Err(Box::new(bad_request("invalid_return_url"))),
        Err(e) => {
            return Err(Box::new(internal_error(
                state,
                info,
                "GrantConsent",
                &e.to_string(),
            )));
        }
    };
    let client_id = request.raw.get("client_id").unwrap_or_default();
    let id = consent::consent_request_id(
        &client_id,
        subject,
        request.raw.get("nonce").as_deref(),
        request.raw.get("scope").as_deref(),
    );
    match consent::store_response(
        state.stores.grants.as_ref(),
        &id,
        subject,
        &client_id,
        &response,
        ctx.now,
    )
    .await
    {
        Ok(()) => Ok(redirect_url),
        Err(e) => Err(Box::new(internal_error(
            state,
            info,
            "GrantConsent",
            &e.to_string(),
        ))),
    }
}

/// `GET /interaction/logout?logoutId=…`: get logout context, the
/// logout message with the iframe URL that signs the browser out of its
/// clients' front channels. A missing or unknown id is the session alone.
async fn logout_context(
    state: &ProtocolState,
    route: &Route,
    info: &RequestInfo,
    session: Option<&UserSession>,
) -> Response {
    let params = Params::parse_query(&route.query);
    let logout_id = params.get("logoutId");
    let message = logout_id
        .as_deref()
        .and_then(|id| crate::end_session::read_logout_message(state, id));
    let iframe = match crate::end_session::sign_out_iframe_url(
        state,
        route,
        message.as_ref(),
        logout_id.as_deref(),
        session,
    )
    .await
    {
        Ok(url) => url,
        Err(e) => return internal_error(state, info, "GetLogoutContext", &e.to_string()),
    };
    let mut message = message.unwrap_or_default();
    // A SAML-initiated logout: the SLO callback finds its logout session by
    // the logout id.
    if message.saml_service_provider_entity_id.is_some()
        && let (Some(uri), Some(id)) = (&message.post_logout_redirect_uri, &logout_id)
    {
        message.post_logout_redirect_uri = Some(add_query_param(
            uri,
            &state.options.user_interaction.logout_id_parameter,
            id,
        ));
    }
    // One value is a string, several an array.
    let parameters: serde_json::Map<String, serde_json::Value> = message
        .parameters
        .iter()
        .map(|(k, v)| {
            let value = match v.as_slice() {
                [one] => json!(one),
                many => json!(many),
            };
            (k.clone(), value)
        })
        .collect();
    let show_signout_prompt =
        message.client_id.as_deref().is_none_or(str::is_empty) || message.requires_confirmation;
    no_cache_json(
        StatusCode::OK,
        &json!({
            "clientId": message.client_id,
            "clientName": message.client_name,
            "postLogoutRedirectUri": message.post_logout_redirect_uri,
            "subjectId": message.subject_id,
            "sessionId": message.session_id,
            "clientIds": message.client_ids,
            "uiLocales": message.ui_locales,
            "parameters": parameters,
            "samlServiceProviderEntityId": message.saml_service_provider_entity_id,
            "samlLogoutRequestId": message.saml_logout_request_id,
            "samlRelayState": message.saml_relay_state,
            "samlSessions": message.saml_sessions,
            "signOutIFrameUrl": iframe,
            "showSignoutPrompt": show_signout_prompt,
        }),
    )
}

/// The logout call's body.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LogoutBody {
    return_url: String,
}

/// `POST /interaction/logout`: the UI has shown the logout page and the
/// user is signing out. Answers with the continuation URL that signs the
/// browser (whose cookies the UI forwarded) out and sends it to the local
/// `returnUrl`.
async fn logout(
    state: &ProtocolState,
    route: &Route,
    headers: &HeaderMap,
    body: Body,
    info: &RequestInfo,
    session: Option<&UserSession>,
) -> Response {
    let body: LogoutBody = match read_json(headers, body).await {
        Ok(body) => body,
        Err(response) => return *response,
    };
    if !is_local_url(&body.return_url) || body.return_url.starts_with('~') {
        return bad_request("invalid_return_url");
    }
    let continuation = LogoutContinuation {
        return_url: body.return_url,
        session_id: session.map(|s| s.session_id.clone()),
    };
    match continuation
        .store(state.stores.grants.as_ref(), chrono::Utc::now())
        .await
    {
        Ok(token) => no_cache_json(
            StatusCode::OK,
            &json!({
                "continueUrl": format!(
                    "{}{LOGOUT_CONTINUE_PATH}?token={}",
                    route.origin.base_url(),
                    url_encode(&token)
                )
            }),
        ),
        Err(e) => internal_error(state, info, "InteractionLogout", &e.to_string()),
    }
}

/// `GET /connect/interaction/logout?token=…`: in the browser whose session
/// the UI signed out, redeems the continuation once and signs out as
/// sign out does: coordinated clients' tokens removed, back-channel
/// notifications sent, both session cookies deleted.
async fn continue_logout(
    state: &ProtocolState,
    route: &Route,
    headers_in: &HeaderMap,
    info: &RequestInfo,
    session: Option<&UserSession>,
) -> Response {
    let now = chrono::Utc::now();
    let params = Params::parse_query(&route.query);
    let Some(token) = params.get("token") else {
        return bad_request("invalid_continuation");
    };
    let continuation =
        match LogoutContinuation::redeem(state.stores.grants.as_ref(), &token, now).await {
            Ok(Some(c)) => c,
            Ok(None) => return bad_request("invalid_continuation"),
            Err(e) => return internal_error(state, info, "InteractionLogout", &e.to_string()),
        };
    if continuation.session_id.as_deref() != session.map(|s| s.session_id.as_str()) {
        return bad_request("invalid_continuation");
    }
    if let Some(session) = session {
        let issuer = current_issuer(&state.options, &route.origin);
        let ctx = ValidationContext {
            options: &state.options,
            stores: &state.stores,
            keys: &state.keys,
            issuer: &issuer,
            now,
        };
        if let Err(e) = process_logout(&ctx, session).await {
            return internal_error(state, info, "InteractionLogout", &e.to_string());
        }
        if let Err(e) = crate::session_cookie::remove(state, session).await {
            return internal_error(state, info, "InteractionLogout", &e.to_string());
        }
    }
    let Ok(location) = HeaderValue::from_str(&continuation.return_url) else {
        return bad_request("invalid_continuation");
    };
    let mut response = (StatusCode::FOUND, [(LOCATION, location)]).into_response();
    // As the cookie handler signs out: never cached.
    let headers = response.headers_mut();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-cache,no-store"));
    headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
    let path = cookies::cookie_path(&route.origin.base_path);
    cookies::append(
        &mut response,
        &cookies::deleted(SESSION_COOKIE, path, route.is_https()),
    );
    // Only when the browser has one.
    let check_session = &state.options.authentication.check_session_cookie_name;
    if cookies::get(headers_in, check_session).is_some() {
        cookies::append(
            &mut response,
            &cookies::expired(check_session, path, route.is_https(), now),
        );
    }
    response
}

fn sessions_disabled() -> Response {
    no_cache_json(
        StatusCode::NOT_FOUND,
        &json!({ "error": "server_side_sessions_disabled" }),
    )
}

/// `GET /interaction/sessions?subjectId=&sessionId=&displayName=&count=&resultsToken=&prior=`:
/// Query sessions, a page of server-side sessions.
async fn query_sessions(state: &ProtocolState, route: &Route, info: &RequestInfo) -> Response {
    let Some(sessions) = &state.stores.sessions else {
        return sessions_disabled();
    };
    let params = Params::parse_query(&route.query);
    let text = |name: &str| params.get(name).filter(|v| !v.is_empty());
    let query = rustid_core::server_side_sessions::SessionQuery {
        results_token: text("resultsToken"),
        request_prior_results: params.get("prior").as_deref() == Some("true"),
        count_requested: params
            .get("count")
            .and_then(|c| c.parse().ok())
            .unwrap_or(0),
        subject_id: text("subjectId"),
        session_id: text("sessionId"),
        display_name: text("displayName"),
    };
    match rustid_core::server_side_sessions::query_user_sessions(sessions, &query).await {
        Ok(page) => no_cache_json(StatusCode::OK, &json!(page)),
        Err(e) => internal_error(state, info, "QuerySessions", &e.to_string()),
    }
}

/// The remove sessions call's body; each flag defaults to true.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RemoveSessionsBody {
    #[serde(default)]
    subject_id: Option<String>,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    client_ids: Option<Vec<String>>,
    #[serde(default = "yes")]
    revoke_tokens: bool,
    #[serde(default = "yes")]
    revoke_consents: bool,
    #[serde(default = "yes")]
    remove_server_side_session: bool,
    #[serde(default = "yes")]
    send_backchannel_logout_notification: bool,
}

fn yes() -> bool {
    true
}

/// `POST /interaction/sessions/remove`: remove sessions.
async fn remove_sessions(
    state: &ProtocolState,
    route: &Route,
    headers: &HeaderMap,
    body: Body,
    info: &RequestInfo,
) -> Response {
    let Some(sessions) = &state.stores.sessions else {
        return sessions_disabled();
    };
    let body: RemoveSessionsBody = match read_json(headers, body).await {
        Ok(body) => body,
        Err(response) => return *response,
    };
    let blank = |v: &Option<String>| v.as_deref().is_none_or(|s| s.trim().is_empty());
    if blank(&body.subject_id) && blank(&body.session_id) {
        return bad_request("invalid_filter");
    }
    let issuer = current_issuer(&state.options, &route.origin);
    let ctx = ValidationContext {
        options: &state.options,
        stores: &state.stores,
        keys: &state.keys,
        issuer: &issuer,
        now: chrono::Utc::now(),
    };
    let remove = rustid_core::server_side_sessions::RemoveSessions {
        subject_id: body.subject_id.filter(|s| !s.trim().is_empty()),
        session_id: body.session_id.filter(|s| !s.trim().is_empty()),
        client_ids: body.client_ids,
        revoke_tokens: body.revoke_tokens,
        revoke_consents: body.revoke_consents,
        remove_server_side_session: body.remove_server_side_session,
        send_backchannel_logout_notification: body.send_backchannel_logout_notification,
    };
    match rustid_core::server_side_sessions::remove_sessions(&ctx, sessions, &remove).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => internal_error(state, info, "RemoveSessions", &e.to_string()),
    }
}

/// `GET /interaction/session`: the session in the cookies the UI forwarded
/// from the browser.
fn session_info(session: Option<&UserSession>) -> Response {
    match session {
        Some(s) => no_cache_json(
            StatusCode::OK,
            &json!({
                "subjectId": s.subject_id,
                "sessionId": s.session_id,
                "authTime": s.auth_time,
                "idp": s.idp,
                "amr": s.amr,
                "claims": s.claims.iter().map(|c| json!({ "type": c.claim_type, "value": c.value })).collect::<Vec<_>>(),
            }),
        ),
        None => no_cache_json(StatusCode::NOT_FOUND, &json!({ "error": "no_session" })),
    }
}

/// The login call's body.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LoginBody {
    return_url: String,
    subject_id: String,
    #[serde(default)]
    idp: Option<String>,
    #[serde(default)]
    amr: Vec<String>,
    #[serde(default)]
    auth_time: Option<i64>,
    #[serde(default)]
    claims: Vec<ClaimBody>,
    /// A persistent cookie ("remember me").
    #[serde(default)]
    remember: bool,
    /// `false` stops sliding renewal of this session's cookie.
    #[serde(default)]
    allow_refresh: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ClaimBody {
    #[serde(rename = "type")]
    claim_type: String,
    value: String,
    #[serde(default)]
    value_type: Option<String>,
}

/// `POST /interaction/login`: signs a subject in for a return URL and
/// answers with the continuation URL to send the browser to.
async fn login(
    state: &ProtocolState,
    route: &Route,
    headers: &HeaderMap,
    body: Body,
    info: &RequestInfo,
) -> Response {
    let body: LoginBody = match read_json(headers, body).await {
        Ok(body) => body,
        Err(response) => return *response,
    };
    if !is_valid_return_url(&body.return_url) && !is_saml_return_url(state, &body.return_url) {
        return bad_request("invalid_return_url");
    }
    if body.subject_id.trim().is_empty() {
        return bad_request("invalid_subject");
    }
    let sign_in = SignIn {
        subject_id: body.subject_id,
        idp: body.idp,
        amr: body.amr,
        auth_time: body.auth_time,
        claims: body
            .claims
            .into_iter()
            .map(|c| Claim {
                claim_type: c.claim_type,
                value: c.value,
                value_type: c
                    .value_type
                    .unwrap_or_else(|| rustid_core::clients::CLAIM_VALUE_TYPE_STRING.to_owned()),
            })
            .collect(),
        persistent: body.remember,
        allow_refresh: body.allow_refresh,
        upstream_id_token: None,
    };
    let continuation = Continuation::new(&body.return_url, sign_in);
    match continuation
        .store(state.stores.grants.as_ref(), chrono::Utc::now())
        .await
    {
        Ok(token) => no_cache_json(
            StatusCode::OK,
            &json!({
                "continueUrl": format!(
                    "{}{CONTINUE_PATH}?token={}",
                    route.origin.base_url(),
                    url_encode(&token)
                )
            }),
        ),
        Err(e) => internal_error(state, info, "InteractionLogin", &e.to_string()),
    }
}

/// `GET /connect/interaction/continue?token=…`: in the browser that
/// started the interaction, redeems the continuation once, writes the
/// session cookies and sends the browser to the return
/// URL, as a login page would.
async fn continue_login(
    state: &ProtocolState,
    route: &Route,
    headers: &HeaderMap,
    info: &RequestInfo,
    current: Option<&UserSession>,
) -> Response {
    let now = chrono::Utc::now();
    let params = Params::parse_query(&route.query);
    let Some(token) = params.get("token") else {
        return bad_request("invalid_continuation");
    };
    let continuation = match Continuation::redeem(state.stores.grants.as_ref(), &token, now).await {
        Ok(Some(c)) => c,
        Ok(None) => return bad_request("invalid_continuation"),
        Err(e) => return internal_error(state, info, "InteractionContinue", &e.to_string()),
    };
    let protector = &state.interaction.protector;
    let binding = InteractionBinding::open(protector, cookies::get(headers, BINDING_COOKIE));
    if !binding.contains(&continuation.return_url, now) {
        return bad_request("invalid_continuation");
    }
    let lifetime = state.options.authentication.cookie_lifetime.0;
    let mut session = UserSession::sign_in(continuation.sign_in(), current, now, lifetime);
    let Ok(location) = HeaderValue::from_str(&continuation.return_url) else {
        return bad_request("invalid_continuation");
    };
    let mut response = (StatusCode::FOUND, [(LOCATION, location)]).into_response();
    let path = cookies::cookie_path(&route.origin.base_path);
    let check_session = &state.options.authentication.check_session_cookie_name;
    if state.options.endpoints.enable_check_session_endpoint
        && cookies::get(headers, check_session) != Some(session.session_id.as_str())
    {
        cookies::append(
            &mut response,
            &cookies::cookie(
                check_session,
                &session.session_id,
                path,
                route.is_https(),
                false,
            ),
        );
    }
    match crate::session_cookie::write(state, route, &mut session).await {
        Ok(cookie) => cookies::append(&mut response, &cookie),
        Err(e) => return internal_error(state, info, "InteractionContinue", &e.to_string()),
    }
    response
}

#[cfg(feature = "saml")]
async fn saml_idp_initiated(
    state: &ProtocolState,
    route: &Route,
    headers: &HeaderMap,
    body: Body,
    info: &RequestInfo,
    session: Option<&UserSession>,
) -> Response {
    match read_json(headers, body).await {
        Ok(body) => crate::saml::idp_initiated(state, route, info, session, body).await,
        Err(response) => *response,
    }
}

#[cfg(not(feature = "saml"))]
async fn saml_idp_initiated(
    _: &ProtocolState,
    _: &Route,
    _: &HeaderMap,
    _: Body,
    _: &RequestInfo,
    _: Option<&UserSession>,
) -> Response {
    StatusCode::NOT_FOUND.into_response()
}

#[cfg(feature = "saml")]
async fn continue_saml_idp_initiated(
    state: &ProtocolState,
    route: &Route,
    info: &RequestInfo,
    session: Option<&UserSession>,
) -> Response {
    crate::saml::continue_idp_initiated(state, route, info, session).await
}

#[cfg(not(feature = "saml"))]
async fn continue_saml_idp_initiated(
    _: &ProtocolState,
    _: &Route,
    _: &RequestInfo,
    _: Option<&UserSession>,
) -> Response {
    StatusCode::NOT_FOUND.into_response()
}

/// A SAML SSO callback is a return URL a login may continue to.
#[cfg(feature = "saml")]
pub(crate) fn is_saml_return_url(state: &ProtocolState, return_url: &str) -> bool {
    crate::saml::is_saml_return_url(state, return_url)
}

#[cfg(not(feature = "saml"))]
pub(crate) fn is_saml_return_url(_: &ProtocolState, _: &str) -> bool {
    false
}

#[cfg(feature = "saml")]
async fn record_saml_denial(
    state: &ProtocolState,
    return_url: &str,
    error: InteractionError,
    description: Option<String>,
) -> Result<(), rustid_core::stores::StoreError> {
    crate::saml::record_denial(state, return_url, error, description).await
}

#[cfg(not(feature = "saml"))]
async fn record_saml_denial(
    _: &ProtocolState,
    _: &str,
    _: InteractionError,
    _: Option<String>,
) -> Result<(), rustid_core::stores::StoreError> {
    Ok(())
}
