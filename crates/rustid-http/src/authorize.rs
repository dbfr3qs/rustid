//! `AuthorizeEndpoint` and `AuthorizeCallbackEndpoint`, and the response
//! writers for their results (the authorize HTTP writer,
//! the authorize interaction page HTTP writer).

use axum::body::Body;
use axum::http::header::{CONTENT_TYPE, LOCATION, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use rustid_core::authorize::code::{AuthorizationCode, code_response_parameters};
use rustid_core::authorize::implicit::{
    BrowserTokens, browser_response_parameters, browser_tokens,
};
use rustid_core::authorize::login::{BINDING_COOKIE, InteractionBinding};
use rustid_core::authorize::messages::{self, ERROR_MESSAGE_PURPOSE, ErrorMessage};
use rustid_core::authorize::return_url_query;
use rustid_core::authorize::validation::{AUTHORIZATION_CODE, HYBRID};
use rustid_core::authorize::{
    AuthorizeContext, AuthorizeFailure, Interaction, SAFE_ERRORS, ValidatedAuthorizeRequest,
    process_interaction, validate,
};
use rustid_core::clients::AccessTokenType;
use rustid_core::consent;
use rustid_core::events::{Event, EventDetails, IssuedToken, RequestInfo, obfuscate};
use rustid_core::issuance::Issuer;
use rustid_core::issuer::current_issuer;
use rustid_core::options::CspLevel;
use rustid_core::params::{
    Params, add_hash_fragment, add_query_param, add_query_string, is_local_url,
};
use rustid_core::session::UserSession;
use rustid_core::telemetry;
use rustid_core::token::TokenFailure;

use crate::ProtocolState;
use crate::cookies;
use crate::endpoint::{is_form_content_type, read_form};
use crate::request::Route;
use crate::response::{internal_error, set_no_cache};

/// The authorize callback's path, under the base URL.
const CALLBACK_PATH: &str = "connect/authorize/callback";
/// The form_post page script's hash, for its Content-Security-Policy.
const AUTHORIZE_SCRIPT_HASH: &str = "sha256-orD0/VhH8hLqrLxKHD/HUEMdwqX6/0ve7c5hspX5VJ8=";
/// The culture cookie's name (a wire name, kept for compatibility).
pub const CULTURE_COOKIE: &str = ".AspNetCore.Culture";

/// `/connect/authorize`: GET, or POST with a form body.
pub(crate) async fn authorize(
    state: &ProtocolState,
    route: &Route,
    method: &Method,
    headers: &HeaderMap,
    body: Body,
    info: &RequestInfo,
    session: Option<&UserSession>,
) -> Response {
    let params = if method == Method::GET {
        Params::parse_query(&route.query)
    } else if method == Method::POST {
        if !is_form_content_type(headers) {
            return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
        }
        match read_form(body).await {
            Some(form) => Params::from_form(&form),
            // A malformed form is an unhandled 500.
            None => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    } else {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    };
    process(state, route, headers, info, params, session, false).await
}

/// `/connect/authorize/callback`: GET only; the return URL the UI sends the
/// browser back to, validated again from scratch.
pub(crate) async fn callback(
    state: &ProtocolState,
    route: &Route,
    method: &Method,
    headers: &HeaderMap,
    info: &RequestInfo,
    session: Option<&UserSession>,
) -> Response {
    if method != Method::GET {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let params = Params::parse_query(&route.query);
    process(state, route, headers, info, params, session, true).await
}

/// Process authorize request for the browser's session. The callback
/// (`check_consent`) applies the consent page's response for this request
/// and subject, and deletes it whatever the outcome.
async fn process(
    state: &ProtocolState,
    route: &Route,
    headers: &HeaderMap,
    info: &RequestInfo,
    params: Params,
    session: Option<&UserSession>,
    check_consent: bool,
) -> Response {
    let now = chrono::Utc::now();
    let issuer = rustid_core::issuer::current_issuer(&state.options, &route.origin);
    let ctx = AuthorizeContext {
        options: &state.options,
        issuer: &issuer,
        stores: &state.stores,
        events: &state.events,
        request: info,
        now,
    };
    let mut request = match validate(&ctx, params, session).await {
        Ok(request) => request,
        Err(AuthorizeFailure::Server(message)) => {
            return internal_error(state, info, "AuthorizeEndpoint", &message);
        }
        Err(AuthorizeFailure::Invalid(e)) => {
            tracing::error!(error = e.error, description = ?e.description, "Request validation failed");
            consume_pushed(state, &e.request).await;
            return error_result(
                state,
                route,
                info,
                &e.request,
                e.error,
                e.description.as_deref(),
            )
            .await;
        }
    };
    let consent_id = check_consent.then(|| {
        consent::consent_request_id(
            request.raw.get("client_id").as_deref().unwrap_or_default(),
            session.map(|s| s.subject_id.as_str()),
            request.raw.get("nonce").as_deref(),
            request.raw.get("scope").as_deref(),
        )
    });
    let grants = state.stores.grants.as_ref();
    let response = match &consent_id {
        Some(id) => match consent::read_response(grants, id, now).await {
            Ok(response) => response,
            Err(e) => return internal_error(state, info, "AuthorizeEndpoint", &e.to_string()),
        },
        None => None,
    };
    let interaction = process_interaction(&mut request, &ctx, response.as_ref()).await;
    if let Some(id) = &consent_id
        && let Err(e) = consent::delete_response(grants, id).await
    {
        return internal_error(state, info, "AuthorizeEndpoint", &e.to_string());
    }
    let interaction = match interaction {
        Ok(interaction) => interaction,
        Err(e) => return internal_error(state, info, "AuthorizeEndpoint", &e.to_string()),
    };
    let ui = &state.options.user_interaction;
    let page = |url: &str, parameter: &str| {
        interaction_page(state, route, headers, &request, url, parameter)
    };
    // A response consumes a pushed request; pages don't.
    if matches!(interaction, Interaction::Error(..) | Interaction::None)
        || (matches!(interaction, Interaction::CreateAccount) && ui.create_account_url.is_none())
    {
        consume_pushed(state, &request).await;
    }
    match interaction {
        Interaction::Error(error, description) => {
            error_result(state, route, info, &request, error, description.as_deref()).await
        }
        Interaction::Login => page(&ui.login_url, &ui.login_return_url_parameter),
        Interaction::Consent => page(&ui.consent_url, &ui.consent_return_url_parameter),
        Interaction::CreateAccount => match &ui.create_account_url {
            Some(url) => page(url, &ui.create_account_return_url_parameter),
            None => error_result(state, route, info, &request, "server_error", None).await,
        },
        Interaction::UnsupportedPromptMode => internal_error(
            state,
            info,
            "AuthorizeInteractionResponseGenerator",
            "Invalid PromptMode",
        ),
        Interaction::None => success_response(state, route, info, request, now).await,
    }
}

/// The authorize response generator and its writer: stores
/// a code (code and hybrid flows), issues the tokens the response type asks
/// for (implicit and hybrid), sends them to the client, and records the
/// client in the session, writing the session cookie
/// again when it is new.
async fn success_response(
    state: &ProtocolState,
    route: &Route,
    info: &RequestInfo,
    request: ValidatedAuthorizeRequest,
    now: chrono::DateTime<chrono::Utc>,
) -> Response {
    let grant_type = request.grant_type.unwrap_or(AUTHORIZATION_CODE);
    let issuer_name = current_issuer(&state.options, &route.origin);
    let issuer = Issuer {
        options: &state.options,
        stores: &state.stores,
        keys: &state.keys,
        issuer: &issuer_name,
        now,
    };
    // A JARM response's key, resolved before anything is stored or raised:
    // A client whose algorithms no key can sign gets a 500 and no code.
    let jarm_key = if request.response_mode.is_some_and(|m| m.ends_with(".jwt")) {
        let algorithms = request
            .client
            .as_ref()
            .map(|c| c.allowed_identity_token_signing_algorithms.as_slice())
            .unwrap_or_default();
        match state.keys.signing_key(algorithms).await {
            Ok(Some(key)) => Some(key),
            Ok(None) => {
                return internal_error(state, info, "AuthorizeEndpoint", "no signing key for JARM");
            }
            Err(e) => return internal_error(state, info, "AuthorizeEndpoint", &e.to_string()),
        }
    } else {
        None
    };
    let code = if grant_type == AUTHORIZATION_CODE || grant_type == HYBRID {
        match store_code(&issuer, &request, now).await {
            Ok(handle) => Some(handle),
            Err(e) => return internal_error(state, info, "AuthorizeEndpoint", &e),
        }
    } else {
        None
    };
    let (params, tokens) = if grant_type == AUTHORIZATION_CODE {
        let handle = code.clone().unwrap_or_default();
        let params = code_response_parameters(
            &request,
            &handle,
            &issuer_name,
            state.options.emit_issuer_identification_response_parameter,
        );
        let tokens = BrowserTokens {
            code: Some(handle),
            id_token: None,
            access_token: None,
            expires_in: 0,
            scope: String::new(),
        };
        (params, tokens)
    } else {
        match browser_tokens(&issuer, &request, code.as_deref()).await {
            Ok(tokens) => (browser_response_parameters(&request, &tokens), tokens),
            Err(TokenFailure::Server(e)) => {
                return internal_error(state, info, "AuthorizeEndpoint", &e);
            }
            Err(TokenFailure::Protocol(e)) => {
                return internal_error(state, info, "AuthorizeEndpoint", &e.error);
            }
        }
    };
    let client = request
        .client
        .as_deref()
        .expect("validated request has a client");
    let session = request
        .subject
        .clone()
        .expect("responses are issued to signed-in users");
    raise_issued(
        state,
        info,
        &request,
        grant_type,
        &tokens,
        &session.subject_id,
    );
    let redirect_uri = request.redirect_uri.clone().unwrap_or_default();
    let mode = request.response_mode.unwrap_or("query");
    let jarm = Jarm {
        issuer: &issuer_name,
        client_id: &client.client_id,
        allowed_algorithms: &client.allowed_identity_token_signing_algorithms,
        key: jarm_key,
    };
    let mut response =
        match client_response(state, &redirect_uri, mode, &params, false, Some(jarm)).await {
            Ok(response) => response,
            Err(e) => return internal_error(state, info, "AuthorizeEndpoint", &e),
        };
    let mut session = session;
    if session.add_client(&client.client_id) {
        match crate::session_cookie::write(state, route, &mut session).await {
            Ok(cookie) => cookies::append(&mut response, &cookie),
            Err(e) => return internal_error(state, info, "AuthorizeEndpoint", &e.to_string()),
        }
    }
    response
}

/// Create code and store authorization code, with `s_hash` when
/// `emit_state_hash` is on.
async fn store_code(
    issuer: &Issuer<'_>,
    request: &ValidatedAuthorizeRequest,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<String, String> {
    let mut code = AuthorizationCode::for_request(request, now);
    if issuer.options.emit_state_hash
        && let Some(state_value) = request.state.as_deref().filter(|s| !s.trim().is_empty())
    {
        let client = request
            .client
            .as_deref()
            .expect("validated request has a client");
        let algorithm = issuer
            .identity_token_algorithm(client)
            .await
            .map_err(|e| match e {
                TokenFailure::Server(message) => message,
                TokenFailure::Protocol(e) => e.error.into_owned(),
            })?;
        code.state_hash = Some(rustid_core::tokens::hash_claim_value(
            state_value,
            &algorithm,
        ));
    }
    code.store(issuer.stores.grants.as_ref())
        .await
        .map_err(|e| e.to_string())
}

/// The token issued success event and metric (the event lists the identity
/// token, then the code, then the access token).
fn raise_issued(
    state: &ProtocolState,
    info: &RequestInfo,
    request: &ValidatedAuthorizeRequest,
    grant_type: &str,
    tokens: &BrowserTokens,
    subject_id: &str,
) {
    let client = request
        .client
        .as_deref()
        .expect("validated request has a client");
    let access_token_type = tokens
        .access_token
        .as_ref()
        .map(|_| match client.access_token_type {
            AccessTokenType::Jwt => "Jwt",
            AccessTokenType::Reference => "Reference",
        });
    telemetry::token_issued(&telemetry::TokenIssued {
        client: &client.client_id,
        grant_type,
        access_token_issued: tokens.access_token.is_some(),
        access_token_type,
        refresh_token_issued: false,
        proof_type: "None",
        id_token_issued: tokens.id_token.is_some(),
    });
    let mut issued = Vec::new();
    for (token_type, value) in [
        ("id_token", &tokens.id_token),
        ("code", &tokens.code),
        ("access_token", &tokens.access_token),
    ] {
        if let Some(value) = value {
            issued.push(IssuedToken {
                token_type,
                token_value: obfuscate(value),
            });
        }
    }
    state.events.raise(
        info,
        chrono::Utc::now(),
        Event::token_issued_success(EventDetails::TokenIssuedSuccess {
            client_id: client.client_id.clone(),
            client_name: client.client_name.clone(),
            redirect_uri: request.redirect_uri.clone(),
            endpoint: "Authorize",
            subject_id: Some(subject_id.to_owned()),
            scopes: request
                .resources
                .as_ref()
                .map(|r| r.scopes.join(" "))
                .unwrap_or_default(),
            grant_type: grant_type.to_owned(),
            tokens: issued,
        }),
    );
}

/// Create error result plus the authorize HTTP writer: raises the failure
/// event, then returns safe errors to the client and shows the error page
/// for the rest.
async fn error_result(
    state: &ProtocolState,
    route: &Route,
    info: &RequestInfo,
    request: &ValidatedAuthorizeRequest,
    error: &'static str,
    description: Option<&str>,
) -> Response {
    telemetry::token_issued_failure(request.client_id.as_deref(), request.grant_type, error);
    state.events.raise(
        info,
        chrono::Utc::now(),
        Event::token_issued_failure(EventDetails::TokenIssuedFailure {
            client_id: request.client_id.clone(),
            client_name: request.client_name().map(str::to_owned),
            endpoint: "Authorize",
            redirect_uri: request.redirect_uri.clone(),
            subject_id: request.subject.as_ref().map(|s| s.subject_id.clone()),
            scopes: Some(request.requested_scopes.join(" ")),
            grant_type: request.grant_type.map(str::to_owned),
            error: error.to_owned(),
            error_description: description.map(str::to_owned),
        }),
    );
    if SAFE_ERRORS.contains(&error)
        && let (Some(redirect_uri), Some(mode)) = (&request.redirect_uri, request.response_mode)
    {
        let mut response_params = Params::default();
        response_params.add("error", error);
        if let Some(description) = description.filter(|d| !d.trim().is_empty()) {
            response_params.add("error_description", description);
        }
        if let Some(state_value) = request.state.as_deref().filter(|s| !s.trim().is_empty()) {
            response_params.add("state", state_value);
        }
        if let Some(session_state) = request.session_state_value() {
            response_params.add("session_state", &session_state);
        }
        let issuer = current_issuer(&state.options, &route.origin);
        let jarm = request.client.as_deref().map(|client| Jarm {
            issuer: &issuer,
            client_id: &client.client_id,
            allowed_algorithms: &client.allowed_identity_token_signing_algorithms,
            key: None,
        });
        return match client_response(state, redirect_uri, mode, &response_params, true, jarm).await
        {
            Ok(response) => response,
            Err(e) => internal_error(state, info, "AuthorizeEndpoint", &e),
        };
    }
    error_page(state, route, request, error, description)
}

/// Who signs a JARM response and for whom.
struct Jarm<'a> {
    issuer: &'a str,
    client_id: &'a str,
    /// The client's id token algorithms: JARM signs with the same key.
    allowed_algorithms: &'a [String],
    /// That key, when already resolved.
    key: Option<std::sync::Arc<rustid_core::keys::LoadedKey>>,
}

/// A 303 with the parameters in the query
/// or fragment (plus `#_` on errors, so the browser drops any fragment it
/// would otherwise carry over), or an auto-posting form. A JARM mode
/// (`query.jwt`, ...) sends them as one signed JWT, `response`, the same
/// way. The error is a signing failure.
async fn client_response(
    state: &ProtocolState,
    redirect_uri: &str,
    mode: &str,
    params: &Params,
    is_error: bool,
    jarm: Option<Jarm<'_>>,
) -> Result<Response, String> {
    use rustid_core::authorize::jarm::{base_mode, response_jwt};
    let jarm_params;
    let (mode, params, is_error) = match jarm.filter(|_| mode.ends_with(".jwt")) {
        Some(jarm) => {
            let key = match jarm.key {
                Some(key) => key,
                None => state
                    .keys
                    .signing_key(jarm.allowed_algorithms)
                    .await
                    .map_err(|e| e.to_string())?
                    .ok_or("no signing key for JARM")?,
            };
            let jwt = response_jwt(
                &key,
                jarm.issuer,
                jarm.client_id,
                params,
                chrono::Utc::now().timestamp(),
                state.options.jarm.lifetime.0,
            )
            .map_err(|e| e.to_string())?;
            let mut wrapped = Params::default();
            wrapped.add("response", &jwt);
            jarm_params = wrapped;
            // The JWT is the whole response: no `#_` after it.
            (base_mode(mode), &jarm_params, false)
        }
        None if mode.ends_with(".jwt") => return Err("JARM response without a client".into()),
        None => (mode, params, is_error),
    };
    let mut response = if mode == "form_post" {
        let mut response = (
            StatusCode::OK,
            [(CONTENT_TYPE, "text/html; charset=UTF-8")],
            form_post_html(redirect_uri, params),
        )
            .into_response();
        let csp = match state.options.csp.level {
            CspLevel::One => {
                format!("default-src 'none'; script-src 'unsafe-inline' '{AUTHORIZE_SCRIPT_HASH}'")
            }
            CspLevel::Two => format!("default-src 'none'; script-src '{AUTHORIZE_SCRIPT_HASH}'"),
        };
        let csp = HeaderValue::from_str(&csp).expect("ascii");
        let headers = response.headers_mut();
        headers.insert("content-security-policy", csp.clone());
        if state.options.csp.add_deprecated_header {
            headers.insert("x-content-security-policy", csp);
        }
        headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
        response
    } else {
        let query = params.to_query_string();
        let mut url = if mode == "query" {
            add_query_string(redirect_uri, &query)
        } else {
            add_hash_fragment(redirect_uri, &query)
        };
        if is_error && !url.contains('#') {
            url.push_str("#_");
        }
        redirect(&url)
    };
    set_no_cache(&mut response);
    Ok(response)
}

/// The form_post response page.
fn form_post_html(redirect_uri: &str, params: &Params) -> String {
    let mut inputs = String::new();
    for (name, values) in params.iter() {
        let value = values.first().map(String::as_str).unwrap_or_default();
        inputs.push_str(&format!(
            "<input type='hidden' name='{name}' value='{}' />\n",
            html_encode(value)
        ));
    }
    format!(
        "<html><head><meta http-equiv='X-UA-Compatible' content='IE=edge' /><base target='_self'/></head>\
         <body><form method='post' action='{}'>{inputs}<noscript><button>Click to continue</button></noscript></form>\
         <script>window.addEventListener('load', function(){{document.forms[0].submit();}});</script></body></html>",
        html_encode(redirect_uri)
    )
}

/// `" & ' + < >`, controls and non-ASCII
/// become character references.
pub(crate) fn html_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '"' => out.push_str("&quot;"),
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\'' | '+' => out.push_str(&format!("&#x{:X};", c as u32)),
            c if c.is_ascii() && !c.is_ascii_control() => out.push(c),
            c => out.push_str(&format!("&#x{:X};", c as u32)),
        }
    }
    out
}

/// Seals the error message into the error page
/// URL, setting the culture cookie on the way.
fn error_page(
    state: &ProtocolState,
    route: &Route,
    request: &ValidatedAuthorizeRequest,
    error: &str,
    description: Option<&str>,
) -> Response {
    let message = ErrorMessage {
        error: error.to_owned(),
        error_description: description.map(str::to_owned),
        display_mode: request.display_mode.clone(),
        ui_locales: request.ui_locales.clone(),
        request_id: Some(crate::request_id()),
        activity_id: crate::activity_id(),
        redirect_uri: None,
        response_mode: None,
        client_id: request.client_id.clone(),
    };
    let id = messages::write(
        &state.interaction.protector,
        ERROR_MESSAGE_PURPOSE,
        message,
        chrono::Utc::now(),
    );
    let ui = &state.options.user_interaction;
    let url = add_query_param(&ui.error_url, &ui.error_id_parameter, &id);
    let mut response = redirect(&absolute_url(route, &url));
    add_culture_cookie(state, &mut response, request.ui_locales.as_deref());
    response
}

/// A 303 to a UI page with the
/// callback URL (carrying the request's parameters) as the return URL.
fn interaction_page(
    state: &ProtocolState,
    route: &Route,
    headers: &HeaderMap,
    request: &ValidatedAuthorizeRequest,
    page_url: &str,
    return_url_parameter: &str,
) -> Response {
    let base = format!(
        "{}/{CALLBACK_PATH}",
        route.origin.base_path.trim_end_matches('/')
    );
    let mut return_url = add_query_string(&base, &return_url_query(request));
    let local = is_local_url(page_url);
    if !local {
        return_url = format!("{}{return_url}", route.origin.origin());
    }
    let url = add_query_param(page_url, return_url_parameter, &return_url);
    let mut response = redirect(&absolute_url(route, &url));
    if local {
        add_culture_cookie(state, &mut response, request.ui_locales.as_deref());
    }
    // Bind the interaction to this browser: only it can redeem the
    // continuation the UI gets for this return URL.
    bind_interaction(state, route, headers, &mut response, &return_url);
    response
}

/// Adds `return_url` to the browser's interaction binding cookie, so only
/// this browser can redeem the login continuation for it.
pub(crate) fn bind_interaction(
    state: &ProtocolState,
    route: &Route,
    headers: &HeaderMap,
    response: &mut Response,
    return_url: &str,
) {
    let protector = &state.interaction.protector;
    let mut binding = InteractionBinding::open(protector, cookies::get(headers, BINDING_COOKIE));
    binding.add(return_url, chrono::Utc::now());
    cookies::append(
        response,
        &cookies::cookie(
            BINDING_COOKIE,
            &binding.seal(protector),
            cookies::cookie_path(&route.origin.base_path),
            route.is_https(),
            true,
        ),
    );
}

/// Consume for the pushed request an answer is going back for. A
/// failure is logged: the answer still goes to the client.
async fn consume_pushed(state: &ProtocolState, request: &ValidatedAuthorizeRequest) {
    if let Some(reference) = &request.pushed_reference
        && let Err(error) =
            rustid_core::pushed_authorization::consume(state.stores.grants.as_ref(), reference)
                .await
    {
        tracing::error!(%error, "consuming a pushed authorization request failed");
    }
}

/// Local paths are made absolute under the base URL.
pub(crate) fn absolute_url(route: &Route, url: &str) -> String {
    if !is_local_url(url) {
        return url.to_owned();
    }
    let path = url.strip_prefix('~').unwrap_or(url);
    format!("{}{path}", route.origin.base_url())
}

pub(crate) fn redirect(location: &str) -> Response {
    match HeaderValue::from_str(location) {
        Ok(value) => (StatusCode::SEE_OTHER, [(LOCATION, value)]).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// The first
/// `ui_locales` value that names a supported UI culture becomes the
/// culture cookie, which a UI's localization reads.
pub(crate) fn add_culture_cookie(
    state: &ProtocolState,
    response: &mut Response,
    ui_locales: Option<&str>,
) {
    let supported = &state.interaction.supported_ui_cultures;
    let Some(culture) = ui_locales.and_then(|locales| {
        locales
            .split(' ')
            .filter(|l| !l.is_empty())
            .find(|l| supported.iter().any(|s| s == l))
    }) else {
        return;
    };
    let value = rustid_core::params::url_encode(&format!("c={culture}|uic={culture}"));
    if let Ok(cookie) = HeaderValue::from_str(&format!("{CULTURE_COOKIE}={value}; path=/")) {
        response.headers_mut().append(SET_COOKIE, cookie);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_encoding_is_exact() {
        let ascii: String = (32u8..127).map(char::from).collect();
        assert_eq!(
            html_encode(&format!("{ascii}é€😀\u{a0}")),
            " !&quot;#$%&amp;&#x27;()*&#x2B;,-./0123456789:;&lt;=&gt;?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~&#xE9;&#x20AC;&#x1F600;&#xA0;"
        );
    }
}
