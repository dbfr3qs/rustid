//! `TokenEndpoint`: HTTP checks, form reading and response writing around
//! the protocol logic in `rustid_core::token`.

use axum::body::Body;
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::Response;
use rustid_core::dpop;
use rustid_core::events::RequestInfo;
use rustid_core::token::{INVALID_REQUEST, TokenError, TokenFailure, process};
use serde_json::{Map, Value, json};

use crate::ProtocolState;
use crate::endpoint::{RequestUrls, context, is_form_content_type, read_form};
use crate::request::Route;
use crate::response::{internal_error, no_cache_json};

pub(crate) async fn token(
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
    let proofs = dpop_proofs(headers);
    let proofs: Vec<&str> = proofs.iter().map(String::as_str).collect();
    let mut ctx = context(state, &urls, info);
    ctx.dpop_proofs = &proofs;
    let authorization = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok());
    match process(&ctx, authorization, &form).await {
        Ok(response) => {
            let mut body = Map::new();
            if let Some(id_token) = response.id_token {
                body.insert("id_token".into(), Value::String(id_token));
            }
            body.insert("access_token".into(), Value::String(response.access_token));
            body.insert("expires_in".into(), json!(response.expires_in));
            body.insert("token_type".into(), json!(response.token_type));
            if let Some(refresh_token) = response.refresh_token {
                body.insert("refresh_token".into(), Value::String(refresh_token));
            }
            body.insert("scope".into(), Value::String(response.scope));
            merge_custom(&mut body, response.custom);
            no_cache_json(StatusCode::OK, &Value::Object(body))
        }
        Err(TokenFailure::Protocol(e)) => error(&e),
        Err(TokenFailure::Server(message)) => {
            internal_error(state, info, "TokenEndpoint", &message)
        }
    }
}

/// `[JsonExtensionData]`: custom fields after the standard ones, never
/// replacing one.
fn merge_custom(body: &mut Map<String, Value>, custom: Map<String, Value>) {
    for (k, v) in custom {
        body.entry(k).or_insert(v);
    }
}

/// The request's `DPoP` header values, one per header line.
pub(crate) fn dpop_proofs(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(dpop::DPOP_HEADER)
        .iter()
        .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
        .collect()
}

pub(crate) fn error(e: &TokenError) -> Response {
    let mut body = Map::new();
    body.insert("error".into(), Value::String(e.error.to_string()));
    if let Some(description) = &e.description {
        body.insert(
            "error_description".into(),
            Value::String(description.clone()),
        );
    }
    merge_custom(&mut body, e.custom.clone());
    let mut response = no_cache_json(StatusCode::BAD_REQUEST, &Value::Object(body));
    if let Some(nonce) = e
        .dpop_nonce
        .as_deref()
        .and_then(|n| HeaderValue::from_str(n).ok())
    {
        response.headers_mut().insert(dpop::NONCE_HEADER, nonce);
    }
    response
}
