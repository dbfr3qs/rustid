//! CORS for the protocol's CORS endpoints, with the clients' allowed
//! origins.

use axum::http::header::{
    ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN,
    ACCESS_CONTROL_REQUEST_HEADERS, ACCESS_CONTROL_REQUEST_METHOD, ORIGIN,
};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::ProtocolState;
use crate::request::Route;

/// The endpoints that answer CORS requests.
const CORS_PATHS: &[&str] = &[
    "/.well-known/openid-configuration",
    "/.well-known/openid-configuration/jwks",
    "/connect/token",
    "/connect/userinfo",
    "/connect/revocation",
];

pub(crate) enum Cors {
    /// A preflight answered by the middleware without reaching an endpoint.
    Preflight(Response),
    /// An actual request: add `Access-Control-Allow-Origin` to the response.
    Allow(HeaderValue),
    /// The origin check itself failed (a store error): HTTP 500.
    Failed,
}

/// `None` when no CORS policy applies and the request continues unchanged.
pub(crate) async fn evaluate(
    state: &ProtocolState,
    headers: &HeaderMap,
    route: &Route,
    method: &Method,
) -> Option<Cors> {
    let origin = headers.get(ORIGIN)?.to_str().ok()?;
    // GetCorsOrigin: an Origin equal to this server's origin isn't CORS.
    if origin == route.origin.origin() {
        return None;
    }
    if !CORS_PATHS
        .iter()
        .any(|p| p.eq_ignore_ascii_case(&route.path))
    {
        return None;
    }
    match state.stores.clients.is_cors_origin_allowed(origin).await {
        Ok(true) => {}
        Ok(false) => return None,
        Err(error) => {
            // A failing origin check is a server error: 500.
            tracing::error!(%error, "CORS origin check failed");
            return Some(Cors::Failed);
        }
    }
    // The policy lists the origin normalised to lower case and the middleware then
    // compares exactly, so an origin that differs only in case gets no
    // CORS headers even though the policy exists.
    let matches_policy = origin == origin.to_ascii_lowercase();
    let origin_value = HeaderValue::from_str(origin).ok()?;
    if method == Method::OPTIONS
        && let Some(requested_method) = headers.get(ACCESS_CONTROL_REQUEST_METHOD)
    {
        let mut response = StatusCode::NO_CONTENT.into_response();
        if matches_policy {
            let h = response.headers_mut();
            h.insert(ACCESS_CONTROL_ALLOW_ORIGIN, origin_value);
            h.insert(ACCESS_CONTROL_ALLOW_METHODS, requested_method.clone());
            let requested_headers: Vec<&str> = headers
                .get_all(ACCESS_CONTROL_REQUEST_HEADERS)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .flat_map(|v| v.split(','))
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .collect();
            if !requested_headers.is_empty()
                && let Ok(value) = HeaderValue::from_str(&requested_headers.join(","))
            {
                h.insert(ACCESS_CONTROL_ALLOW_HEADERS, value);
            }
        }
        return Some(Cors::Preflight(response));
    }
    matches_policy.then_some(Cors::Allow(origin_value))
}
