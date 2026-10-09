//! `UserInfoEndpoint`: the access token (a bearer token, or a DPoP-bound
//! one with its proof), and the response or protected resource error
//! around `rustid_core::userinfo`.

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use rustid_core::access_tokens::{EXPIRED_TOKEN, INVALID_TOKEN, ValidationContext};
use rustid_core::events::RequestInfo;
use rustid_core::protected_resource::Challenge;
use rustid_core::userinfo::{
    INSUFFICIENT_SCOPE, UserInfoAnswer, UserInfoRefusal, UserInfoRequest, userinfo_for_request,
};
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
    let Some((token, dpop)) = access_token(headers, body).await else {
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
    let proofs = crate::token::dpop_proofs(headers);
    let url = format!("{}{}", route.origin.base_url(), route.path);
    let request = UserInfoRequest {
        token: &token,
        dpop,
        dpop_proofs: &proofs,
        method: method.as_str(),
        url: &url,
        client_certificate: route.client_certificate.as_deref(),
    };
    match userinfo_for_request(&ctx, &request, &state.interaction.protector).await {
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
        Ok(Err(UserInfoRefusal::Error(e))) => error(e),
        Ok(Err(UserInfoRefusal::Challenge(challenge))) => challenged(&challenge),
        Err(e) => internal_error(state, info, "UserInfoEndpoint", &e.to_string()),
    }
}

/// The token from `Authorization: Bearer <token>` or `DPoP <token>` (the
/// scheme matched without regard to case, the rest trimmed), else a
/// bearer token in a form body's `access_token`; and whether the `DPoP`
/// scheme carried it.
async fn access_token(headers: &HeaderMap, body: Body) -> Option<(String, bool)> {
    let authorization = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::trim);
    if let Some(authorization) = authorization {
        for (scheme, dpop) in [("Bearer", false), ("DPoP", true)] {
            if let Some(token) = authorization
                .get(..scheme.len())
                .filter(|s| s.eq_ignore_ascii_case(scheme))
                .map(|_| authorization[scheme.len()..].trim())
                .filter(|t| !t.is_empty())
            {
                return Some((token.to_owned(), dpop));
            }
        }
    }
    if is_form_content_type(headers) {
        let form = read_form(body).await?;
        return form
            .first("access_token")
            .filter(|t| !t.trim().is_empty())
            .map(|t| (t.to_owned(), false));
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

/// 401 for a sender-constrained token used without its proof or
/// certificate: the challenge, and the nonce a DPoP proof must carry.
fn challenged(challenge: &Challenge) -> Response {
    let mut response = StatusCode::UNAUTHORIZED.into_response();
    set_no_cache(&mut response);
    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(&challenge.www_authenticate()) {
        headers.insert(WWW_AUTHENTICATE, value);
    }
    if let Some(nonce) = challenge
        .dpop_nonce
        .as_deref()
        .and_then(|n| HeaderValue::from_str(n).ok())
    {
        headers.insert(rustid_core::dpop::NONCE_HEADER, nonce);
    }
    response
}
