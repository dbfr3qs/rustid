//! `UserInfoEndpoint`: the bearer token, and
//! the response or protected resource error around `rustid_core::userinfo`.

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use rustid_core::access_tokens::{EXPIRED_TOKEN, INVALID_TOKEN, ValidationContext};
use rustid_core::events::RequestInfo;
use rustid_core::userinfo::{INSUFFICIENT_SCOPE, UserInfoAnswer, userinfo_response as process};
use serde_json::Value;

use crate::ProtocolState;
use crate::endpoint::{RequestUrls, is_form_content_type, read_form};
use crate::request::Route;
use crate::response::{internal_error, no_cache_json, set_no_cache};

pub(crate) async fn userinfo(
    state: &ProtocolState,
    route: &Route,
    method: &Method,
    headers: &HeaderMap,
    body: Body,
    info: &RequestInfo,
) -> Response {
    if method != Method::GET && method != Method::POST {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let Some(token) = bearer_token(headers, body).await else {
        return error(INVALID_TOKEN);
    };
    let urls = RequestUrls::new(state, route);
    let ctx = ValidationContext {
        options: &state.options,
        stores: &state.stores,
        keys: &state.keys,
        issuer: urls.issuer(),
        now: chrono::Utc::now(),
    };
    match process(&ctx, &token).await {
        Ok(Ok(UserInfoAnswer::Json(claims))) => {
            no_cache_json(StatusCode::OK, &Value::Object(claims))
        }
        Ok(Ok(UserInfoAnswer::Jwt(jwt))) => {
            let mut response = (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/jwt")],
                jwt,
            )
                .into_response();
            set_no_cache(&mut response);
            response
        }
        Ok(Err(e)) => error(e),
        Err(e) => internal_error(state, info, "UserInfoEndpoint", &e.to_string()),
    }
}

/// `Authorization: Bearer <token>` (the scheme
/// matched case-sensitively, the rest trimmed), else an `access_token` field
/// in a form body.
async fn bearer_token(headers: &HeaderMap, body: Body) -> Option<String> {
    if let Some(token) = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .and_then(|v| v.strip_prefix("Bearer"))
        .map(str::trim)
        .filter(|t| !t.is_empty())
    {
        return Some(token.to_owned());
    }
    if is_form_content_type(headers) {
        let form = read_form(body).await?;
        return form
            .first("access_token")
            .filter(|t| !t.trim().is_empty())
            .map(str::to_owned);
    }
    None
}

/// 401 (403 for `insufficient_scope`),
/// no-cache, and the error in `WWW-Authenticate`; an expired token reads as
/// `invalid_token` with a description.
fn error(error: &str) -> Response {
    let status = match error {
        INSUFFICIENT_SCOPE => StatusCode::FORBIDDEN,
        "invalid_request" => StatusCode::BAD_REQUEST,
        _ => StatusCode::UNAUTHORIZED,
    };
    let (error, description) = if error == EXPIRED_TOKEN {
        (INVALID_TOKEN, Some("The access token expired"))
    } else {
        (error, None)
    };
    let mut value = format!("Bearer realm=\"rustid\",error=\"{error}\"");
    if let Some(description) = description {
        value.push_str(&format!(",error_description=\"{description}\""));
    }
    let mut response = status.into_response();
    set_no_cache(&mut response);
    if let Ok(value) = HeaderValue::from_str(&value) {
        response.headers_mut().insert(WWW_AUTHENTICATE, value);
    }
    response
}
