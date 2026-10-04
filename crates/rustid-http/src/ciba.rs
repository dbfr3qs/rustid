//! `BackchannelAuthenticationEndpoint`: `POST /connect/ciba`.

use axum::body::Body;
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::Response;
use rustid_core::ciba::authorize;
use rustid_core::events::RequestInfo;
use rustid_core::token::{INVALID_REQUEST, TokenError, TokenFailure};
use serde_json::{Map, Value, json};

use crate::ProtocolState;
use crate::endpoint::{RequestUrls, context, is_form_content_type, read_form};
use crate::request::Route;
use crate::response::{internal_error, no_cache_json};

/// the errors: 401 for
/// `invalid_client`, 403 for `access_denied`, else 400.
fn error(e: &TokenError) -> Response {
    let status = match e.error.as_ref() {
        "invalid_client" => StatusCode::UNAUTHORIZED,
        "access_denied" => StatusCode::FORBIDDEN,
        _ => StatusCode::BAD_REQUEST,
    };
    let mut body = Map::new();
    body.insert("error".into(), json!(e.error));
    if let Some(description) = &e.description {
        body.insert("error_description".into(), json!(description));
    }
    no_cache_json(status, &Value::Object(body))
}

pub(crate) async fn backchannel_authentication(
    state: &ProtocolState,
    route: &Route,
    method: &Method,
    headers: &HeaderMap,
    body: Body,
    info: &RequestInfo,
) -> Response {
    if method != Method::POST || !is_form_content_type(headers) {
        return error(&TokenError::new(INVALID_REQUEST));
    }
    let Some(form) = read_form(body).await else {
        return error(&TokenError::new(INVALID_REQUEST));
    };
    let urls = RequestUrls::new(state, route);
    let ctx = context(state, &urls, info);
    let authorization = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok());
    match authorize(&ctx, authorization, &form).await {
        Ok(response) => no_cache_json(
            StatusCode::OK,
            &json!({
                "auth_req_id": response.auth_req_id,
                "expires_in": response.expires_in,
                "interval": response.interval,
            }),
        ),
        Err(TokenFailure::Protocol(e)) => error(&e),
        Err(TokenFailure::Server(message)) => {
            internal_error(state, info, "BackchannelAuthenticationEndpoint", &message)
        }
    }
}
