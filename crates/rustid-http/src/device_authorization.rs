//! `DeviceAuthorizationEndpoint`: `POST /connect/deviceauthorization`
//! (RFC 8628).

use axum::body::Body;
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::Response;
use rustid_core::device_flow::authorize;
use rustid_core::events::RequestInfo;
use rustid_core::token::{INVALID_REQUEST, TokenError, TokenFailure};
use serde_json::{Map, Value, json};

use crate::ProtocolState;
use crate::endpoint::{RequestUrls, context, is_form_content_type, read_form};
use crate::request::Route;
use crate::response::{internal_error, no_cache_json};
use crate::token::error;

pub(crate) async fn device_authorization(
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
        Ok(response) => {
            let mut body = Map::new();
            body.insert("device_code".into(), json!(response.device_code));
            body.insert("user_code".into(), json!(response.user_code));
            body.insert("verification_uri".into(), json!(response.verification_uri));
            if let Some(complete) = response.verification_uri_complete {
                body.insert("verification_uri_complete".into(), json!(complete));
            }
            body.insert("expires_in".into(), json!(response.expires_in));
            body.insert("interval".into(), json!(response.interval));
            no_cache_json(StatusCode::OK, &Value::Object(body))
        }
        Err(TokenFailure::Protocol(e)) => error(&e),
        Err(TokenFailure::Server(message)) => {
            internal_error(state, info, "DeviceAuthorizationEndpoint", &message)
        }
    }
}
