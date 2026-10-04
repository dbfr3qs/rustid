//! `TokenRevocationEndpoint`: HTTP checks and response writing around
//! `rustid_core::revocation`.

use axum::body::Body;
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use rustid_core::events::RequestInfo;
use rustid_core::revocation::process;
use serde_json::json;

use crate::ProtocolState;
use crate::endpoint::{RequestUrls, context, is_form_content_type, read_form};
use crate::request::Route;
use crate::response::{internal_error, plain_json};

pub(crate) async fn revoke(
    state: &ProtocolState,
    route: &Route,
    method: &Method,
    headers: &HeaderMap,
    body: Body,
    info: &RequestInfo,
) -> Response {
    if method != Method::POST {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    if !is_form_content_type(headers) {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    let Some(form) = read_form(body).await else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let urls = RequestUrls::new(state, route);
    let ctx = context(state, &urls, info);
    let authorization = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok());
    match process(&ctx, authorization, &form).await {
        Ok(Ok(())) => StatusCode::OK.into_response(),
        Ok(Err(error)) => plain_json(StatusCode::BAD_REQUEST, &json!({ "error": error })),
        Err(error) => internal_error(state, info, "TokenRevocationEndpoint", &error.to_string()),
    }
}
