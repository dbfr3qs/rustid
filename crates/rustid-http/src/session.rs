//! The browser session on every request: the session middleware reads
//! the `idsrv` cookie and keeps the check session cookie in step with it
//!  before anything else runs.

use axum::extract::{Request, State};
use axum::http::HeaderValue;
use axum::http::header::SET_COOKIE;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use rustid_core::session::UserSession;

use crate::cookies;
use crate::session_cookie;
use crate::{AppState, request};

/// The request's signed-in user, as the middleware found it.
#[derive(Debug, Clone, Default)]
pub struct CurrentSession(pub Option<UserSession>);

/// Opens the session and, when the check session cookie doesn't hold its
/// id, issues it; when there is no session but the request has one,
/// deletes it. That cookie comes before any the endpoint sets.
pub(crate) async fn ensure_session_id(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let state = state.0.clone();
    let now = chrono::Utc::now();
    let mut expired = None;
    let mut session = match session_cookie::open(&state, request.headers(), now).await {
        Ok(session_cookie::Opened::Active(session)) => Some(session),
        Ok(session_cookie::Opened::None) => None,
        Ok(session_cookie::Opened::Expired(session)) => {
            expired = Some(session);
            None
        }
        Err(error) => {
            tracing::error!(%error, "loading the browser's session failed");
            return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let https = request.extensions().get::<crate::Https>().is_some();
    let route = request::Route::parse(&state, request.headers(), request.uri(), https);
    // Sliding expiration: the renewed session is what the endpoint sees.
    let mut renewed = None;
    if let (Some(s), Some(route)) = (session.as_mut(), route.as_ref())
        && session_cookie::renew_if_due(&state, s, now)
    {
        match session_cookie::write(&state, route, s).await {
            Ok(cookie) => renewed = Some(cookie),
            Err(error) => {
                tracing::error!(%error, "renewing the browser's session failed");
                return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    }
    let route_origin = route.as_ref().map(|r| r.origin.clone());
    let base_path = route.map(|r| r.origin.base_path).unwrap_or_default();
    let path = cookies::cookie_path(&base_path).to_owned();
    let name = &state.options.authentication.check_session_cookie_name;
    let current = cookies::get(request.headers(), name).map(str::to_owned);
    let cookie = match &session {
        Some(s) if current.as_deref() != Some(s.session_id.as_str()) => state
            .options
            .endpoints
            .enable_check_session_endpoint
            .then(|| cookies::cookie(name, &s.session_id, &path, https, false)),
        Some(_) => None,
        None => current
            .is_some()
            .then(|| cookies::expired(name, &path, https, now)),
    };
    request.extensions_mut().insert(CurrentSession(session));
    let mut response = next.run(request).await;
    if let Some(cookie) = cookie.and_then(|c| HeaderValue::from_str(&c).ok()) {
        let later: Vec<HeaderValue> = response
            .headers_mut()
            .get_all(SET_COOKIE)
            .iter()
            .cloned()
            .collect();
        response.headers_mut().remove(SET_COOKIE);
        response.headers_mut().append(SET_COOKIE, cookie);
        for value in later {
            response.headers_mut().append(SET_COOKIE, value);
        }
    }
    // The session middleware: a server-side session found expired is
    // processed (coordinated tokens revoked, back-channel notifications)
    // before the response goes out.
    if let Some(expired) = expired {
        let issuer = route_origin
            .as_ref()
            .map(|o| rustid_core::issuer::current_issuer(&state.options, o))
            .unwrap_or_default();
        let ctx = rustid_core::access_tokens::ValidationContext {
            options: &state.options,
            stores: &state.stores,
            keys: &state.keys,
            issuer: &issuer,
            now,
        };
        if let Err(error) =
            rustid_core::server_side_sessions::process_expiration(&ctx, &expired).await
        {
            tracing::error!(%error, "processing an expired session failed");
        }
    }
    // Last, as the cookie handler writes it when the response starts, and
    // not when the endpoint signed in or out itself.
    if let Some(cookie) = renewed.and_then(|c| HeaderValue::from_str(&c).ok()) {
        let written = response
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .any(|v| v.as_bytes().starts_with(b"idsrv="));
        if !written {
            // The cookie handler's `ApplyHeaders`: never cached.
            let headers = response.headers_mut();
            headers.append(SET_COOKIE, cookie);
            headers.insert(
                axum::http::header::CACHE_CONTROL,
                HeaderValue::from_static("no-cache,no-store"),
            );
            headers.insert(
                axum::http::header::PRAGMA,
                HeaderValue::from_static("no-cache"),
            );
        }
    }
    response
}
