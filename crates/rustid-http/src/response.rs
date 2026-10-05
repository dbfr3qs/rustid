use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, PRAGMA, VARY};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

/// The JSON content type (lower-case charset).
pub const JSON_UTF8: &str = "application/json; charset=utf-8";
/// The protocol endpoints' JSON content type (upper-case charset).
pub const JSON_UTF8_UPPER: &str = "application/json; charset=UTF-8";

/// A JSON body as the protocol endpoints write it, with
/// caching headers (varying by `Origin`) when a cache interval is configured.
pub(crate) fn json(body: &serde_json::Value, cache_interval: Option<i64>) -> Response {
    let mut response = (
        StatusCode::OK,
        [(CONTENT_TYPE, JSON_UTF8_UPPER)],
        body.to_string(),
    )
        .into_response();
    let headers = response.headers_mut();
    match cache_interval {
        Some(0) => {
            headers.insert(
                CACHE_CONTROL,
                HeaderValue::from_static("no-store, no-cache, max-age=0"),
            );
            headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
        }
        Some(seconds) if seconds > 0 => {
            headers.insert(
                CACHE_CONTROL,
                HeaderValue::from_str(&format!("max-age={seconds}")).expect("ascii"),
            );
            headers.insert(VARY, HeaderValue::from_static("Origin"));
        }
        _ => {}
    }
    response
}

/// JSON with no-cache headers, as the token endpoint results write it.
pub(crate) fn no_cache_json(status: StatusCode, body: &serde_json::Value) -> Response {
    let mut response = plain_json(status, body);
    set_no_cache(&mut response);
    response
}

/// JSON as write json writes it, with no cache headers.
pub(crate) fn plain_json(status: StatusCode, body: &serde_json::Value) -> Response {
    (status, [(CONTENT_TYPE, JSON_UTF8_UPPER)], body.to_string()).into_response()
}

/// Sets the no-cache headers.
pub(crate) fn set_no_cache(response: &mut Response) {
    let headers = response.headers_mut();
    headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, max-age=0"),
    );
    headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
}

/// A server-side failure (a store error): counted as an internal error,
/// raised as an unhandled exception event, answered 500 with no body.
pub(crate) fn internal_error(
    state: &crate::ProtocolState,
    info: &rustid_core::events::RequestInfo,
    operation: &str,
    detail: &str,
) -> Response {
    tracing::error!(operation, detail, "request failed");
    rustid_core::telemetry::internal_error("StoreError", operation);
    state.events.raise(
        info,
        chrono::Utc::now(),
        rustid_core::events::Event::unhandled_exception(detail),
    );
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}
