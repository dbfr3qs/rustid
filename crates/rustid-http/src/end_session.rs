//! `EndSessionEndpoint` and its result: RP-initiated logout sends the
//! browser to the logout page with a sealed `LogoutMessage`.

use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use rustid_core::access_tokens::ValidationContext;
use rustid_core::authorize::messages;
use rustid_core::end_session::{
    self, END_SESSION_CALLBACK_PURPOSE, LOGOUT_MESSAGE_PURPOSE, LogoutMessage,
    LogoutNotificationContext,
};
use rustid_core::events::RequestInfo;
use rustid_core::issuer::current_issuer;
use rustid_core::options::CspLevel;
use rustid_core::params::{Params, add_query_param, is_local_url};
use rustid_core::session::UserSession;
use rustid_core::stores::StoreError;

use crate::ProtocolState;
use crate::authorize::{absolute_url, add_culture_cookie, html_encode, redirect};
use crate::endpoint::{is_form_content_type, read_form};
use crate::request::Route;
use crate::response::{internal_error, set_no_cache};

/// `ProtocolRoutePaths.EndSessionCallback`.
pub(crate) const CALLBACK_PATH: &str = "connect/endsession/callback";

pub(crate) async fn end_session(
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
            // Read form throws `InvalidOperationException`: unhandled.
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        match read_form(body).await {
            Some(form) => Params::from_form(&form),
            // `InvalidDataException` is caught: a 400.
            None => return StatusCode::BAD_REQUEST.into_response(),
        }
    } else {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    };
    let issuer = current_issuer(&state.options, &route.origin);
    let now = chrono::Utc::now();
    let ctx = ValidationContext {
        options: &state.options,
        stores: &state.stores,
        keys: &state.keys,
        issuer: &issuer,
        now,
    };
    // Kept for the culture cookie when validation fails, as the result
    // keeps the partly validated request.
    let ui_locales = end_session::ui_locales(&ctx, &params);
    let request = match end_session::validate(&ctx, params, session).await {
        Ok(Ok(request)) => Some(request),
        Ok(Err(error)) => {
            tracing::error!(%error, "Error processing end session request");
            None
        }
        Err(e) => return internal_error(state, info, "EndSession", &e.to_string()),
    };
    let id = request
        .as_ref()
        .map(LogoutMessage::from_request)
        .filter(LogoutMessage::contains_payload)
        .map(|message| {
            messages::write(
                &state.interaction.protector,
                LOGOUT_MESSAGE_PURPOSE,
                message,
                now,
            )
        });
    let ui = &state.options.user_interaction;
    let local = is_local_url(&ui.logout_url);
    let mut url = ui.logout_url.clone();
    if let Some(id) = &id {
        url = add_query_param(&url, &ui.logout_id_parameter, id);
    }
    let mut response = redirect(&absolute_url(route, &url));
    if local {
        add_culture_cookie(state, &mut response, ui_locales.as_deref());
    }
    response
}

/// Opens a logout id; `None` for anything that isn't one of ours.
pub(crate) fn read_logout_message(state: &ProtocolState, id: &str) -> Option<LogoutMessage> {
    messages::read::<LogoutMessage>(&state.interaction.protector, LOGOUT_MESSAGE_PURPOSE, id)
        .map(|m| m.data)
}

/// The sign-out frame callback: the end session
/// callback's URL with the sealed notification context, when a client to
/// sign out of has a front-channel logout URI.
pub(crate) async fn sign_out_iframe_url(
    state: &ProtocolState,
    route: &Route,
    message: Option<&LogoutMessage>,
    logout_id: Option<&str>,
    session: Option<&UserSession>,
) -> Result<Option<String>, StoreError> {
    #[cfg(feature = "saml")]
    let saml_check = state.saml.get().map(crate::saml::SamlFrontChannelCheck);
    #[cfg(feature = "saml")]
    let saml = saml_check
        .as_ref()
        .map(|c| c as &dyn end_session::SamlFrontChannel);
    #[cfg(not(feature = "saml"))]
    let saml: Option<&dyn end_session::SamlFrontChannel> = None;
    let Some(context) = end_session::sign_out_iframe_context(
        state.stores.clients.as_ref(),
        saml,
        message,
        logout_id,
        session,
    )
    .await?
    else {
        return Ok(None);
    };
    let id = messages::write(
        &state.interaction.protector,
        END_SESSION_CALLBACK_PURPOSE,
        context,
        chrono::Utc::now(),
    );
    let base = format!("{}/{CALLBACK_PATH}", route.origin.base_url());
    Ok(Some(add_query_param(&base, "endSessionId", &id)))
}

/// The callback page's style (braces doubled).
const CALLBACK_STYLE: &str = "iframe{{display:none;width:0;height:0;}}";
const CALLBACK_SCRIPT: &str = include_str!("scripts/end-session-callback.js");
const CHECK_SESSION_SCRIPT: &str = include_str!("scripts/check-session.js");

/// A CSP source for inline content: `sha256-<base64>`.
fn csp_hash(content: &str) -> String {
    use base64::Engine;
    let hash = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, content.as_bytes());
    format!(
        "sha256-{}",
        base64::engine::general_purpose::STANDARD.encode(hash.as_ref())
    )
}

fn html(body: String) -> Response {
    (
        StatusCode::OK,
        [(CONTENT_TYPE, "text/html; charset=UTF-8")],
        body,
    )
        .into_response()
}

/// `AddCspHeaders`: the header, and the deprecated one when configured.
fn add_csp(state: &ProtocolState, response: &mut Response, csp: &str) {
    let Ok(value) = HeaderValue::from_str(csp) else {
        return;
    };
    let headers = response.headers_mut();
    headers.insert("content-security-policy", value.clone());
    if state.options.csp.add_deprecated_header {
        headers.insert("x-content-security-policy", value);
    }
}

fn csp_level_one(state: &ProtocolState) -> &'static str {
    match state.options.csp.level {
        CspLevel::One => "'unsafe-inline' ",
        CspLevel::Two => "",
    }
}

/// `EndSessionCallbackEndpoint`: GET only; the sealed notification context
/// becomes one hidden iframe per front-channel logout URL, then rustid's
/// completion script. A missing or unknown context is a bare 400.
pub(crate) async fn callback(
    state: &ProtocolState,
    route: &Route,
    method: &Method,
    info: &RequestInfo,
) -> Response {
    if method != Method::GET {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let params = Params::parse_query(&route.query);
    let context = params.get("endSessionId").and_then(|id| {
        messages::read::<LogoutNotificationContext>(
            &state.interaction.protector,
            END_SESSION_CALLBACK_PURPOSE,
            &id,
        )
    });
    let Some(context) = context
        .map(|m| m.data)
        .filter(|c| !c.client_ids.is_empty() || !c.saml_sessions.is_empty())
    else {
        tracing::error!("Error validating signout callback: no end session message");
        return StatusCode::BAD_REQUEST.into_response();
    };
    let issuer = current_issuer(&state.options, &route.origin);
    let urls =
        match end_session::front_channel_urls(state.stores.clients.as_ref(), &context, &issuer)
            .await
        {
            Ok(urls) => urls,
            Err(e) => return internal_error(state, info, "EndSessionCallback", &e.to_string()),
        };
    // The SAML SPs' LogoutRequests (and the logout session tracking them).
    #[cfg(feature = "saml")]
    let saml_logouts = match state.saml.get() {
        Some(saml) => {
            match crate::saml::front_channel_logouts(state, saml, route, &context).await {
                Ok(logouts) => logouts,
                Err(e) => return internal_error(state, info, "EndSessionCallback", &e),
            }
        }
        None => Vec::new(),
    };
    #[cfg(not(feature = "saml"))]
    let saml_logouts: Vec<SamlLogoutStub> = Vec::new();
    let mut body = format!("<!DOCTYPE html><html><style>{CALLBACK_STYLE}</style><body>");
    for url in &urls {
        body.push_str(&format!(
            "<iframe loading='eager' allow='' src='{}'></iframe>\n",
            html_encode(url)
        ));
    }
    for logout in &saml_logouts {
        body.push_str(&format!(
            "<iframe loading='eager' allow='' src='{}'></iframe>\n",
            html_encode(&logout.url)
        ));
    }
    body.push_str(&format!("<script>{CALLBACK_SCRIPT}</script>"));
    let mut response = html(body);
    set_no_cache(&mut response);
    if state
        .options
        .authentication
        .require_csp_frame_src_for_signout
    {
        let mut origins: Vec<String> = Vec::new();
        let saml_destinations = saml_logouts.iter().map(|l| l.destination.as_str());
        for url in urls.iter().map(String::as_str).chain(saml_destinations) {
            if let Ok(parsed) = url::Url::parse(url) {
                let origin = parsed.origin().ascii_serialization();
                if !origins.contains(&origin) {
                    origins.push(origin);
                }
            }
        }
        // SAML SPs answer in the iframe with a redirect back to this server.
        if !saml_logouts.is_empty() {
            origins.push("'self'".to_owned());
        }
        let unsafe_inline = csp_level_one(state);
        let mut csp = format!(
            "default-src 'none'; style-src {unsafe_inline}'{}'; script-src {unsafe_inline}'{}'",
            csp_hash(CALLBACK_STYLE),
            csp_hash(CALLBACK_SCRIPT)
        );
        if !origins.is_empty() {
            csp.push_str(&format!("; frame-src {}", origins.join(" ")));
        }
        add_csp(state, &mut response, &csp);
    }
    response
}

/// `CheckSessionEndpoint`: GET only; the check session iframe, with
/// rustid's script and the check session cookie's name.
pub(crate) fn check_session(state: &ProtocolState, method: &Method) -> Response {
    if method != Method::GET {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let cookie_name = html_encode(&state.options.authentication.check_session_cookie_name);
    let body = format!(
        "<!DOCTYPE html>\n<html>\n<head>\n    <meta http-equiv='X-UA-Compatible' content='IE=edge' />\n    <title>Check Session IFrame</title>\n</head>\n<body>\n    <script id='cookie-name' type='application/json'>{cookie_name}</script>\n    <script>{CHECK_SESSION_SCRIPT}</script>\n</body>\n</html>\n"
    );
    let mut response = html(body);
    let csp = format!(
        "default-src 'none'; script-src {}'{}'",
        csp_level_one(state),
        csp_hash(CHECK_SESSION_SCRIPT)
    );
    add_csp(state, &mut response, &csp);
    response
}

/// Stands in for SAML's front-channel logouts when the feature is off.
#[cfg(not(feature = "saml"))]
struct SamlLogoutStub {
    url: String,
    destination: String,
}
