//! `IntrospectionEndpoint`: HTTP checks and response writing around
//! `rustid_core::introspection`.

use axum::body::Body;
use axum::http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use rustid_core::events::RequestInfo;
use rustid_core::introspection::{Introspection, JWT_RESPONSE_TYPE, jwt_response, process};
use serde_json::{Value, json};

use crate::ProtocolState;
use crate::endpoint::{RequestUrls, context, is_form_content_type, read_form};
use crate::request::Route;
use crate::response::{internal_error, no_cache_json, set_no_cache};

pub(crate) async fn introspect(
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
    let outcome = match process(&ctx, authorization, &form).await {
        Ok(outcome) => outcome,
        Err(error) => {
            return internal_error(state, info, "IntrospectionEndpoint", &error.to_string());
        }
    };
    match outcome {
        Introspection::Unauthorized => StatusCode::UNAUTHORIZED.into_response(),
        Introspection::Invalid(error) => {
            no_cache_json(StatusCode::BAD_REQUEST, &json!({ "error": error }))
        }
        Introspection::Response { entries, caller } if wants_jwt(headers) => {
            match jwt_response(&ctx, &entries, &caller).await {
                Ok(jwt) => {
                    let media = format!("application/{JWT_RESPONSE_TYPE}");
                    let mut response =
                        (StatusCode::OK, [(CONTENT_TYPE, media)], jwt).into_response();
                    set_no_cache(&mut response);
                    response
                }
                Err(message) => internal_error(state, info, "IntrospectionEndpoint", &message),
            }
        }
        Introspection::Response { entries, .. } => {
            no_cache_json(StatusCode::OK, &Value::Object(entries))
        }
    }
}

/// The whole `Accept` header must equal the JWT response media type,
/// ignoring case.
fn wants_jwt(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(ACCEPT).iter();
    let expected = format!("application/{JWT_RESPONSE_TYPE}");
    match (values.next(), values.next()) {
        (Some(value), None) => value
            .to_str()
            .is_ok_and(|v| v.eq_ignore_ascii_case(&expected)),
        _ => false,
    }
}
