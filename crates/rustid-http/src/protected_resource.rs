//! `GET {protected_resource}`: a protected resource on the server itself,
//! for conformance runs (such as `/fapi2/resource`).

use axum::http::header::{AUTHORIZATION, CACHE_CONTROL, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use rustid_core::issuer::current_issuer;
use rustid_core::protected_resource::{ResourceRequest, authenticate};

use crate::ProtocolState;
use crate::request::Route;
use crate::token::dpop_proofs;

pub(crate) async fn handle(
    state: &ProtocolState,
    route: &Route,
    method: &axum::http::Method,
    headers: &HeaderMap,
) -> Response {
    let issuer = current_issuer(&state.options, &route.origin);
    let ctx = rustid_core::access_tokens::ValidationContext {
        options: &state.options,
        stores: &state.stores,
        keys: &state.keys,
        issuer: &issuer,
        now: chrono::Utc::now(),
    };
    let proofs = dpop_proofs(headers);
    let url = format!("{}{}", route.origin.base_url(), route.path);
    let request = ResourceRequest {
        authorization: headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok()),
        dpop_proofs: &proofs,
        method: method.as_str(),
        url: &url,
        client_certificate: route.client_certificate.as_deref(),
    };
    let mut response = match authenticate(&ctx, &request, &state.interaction.protector).await {
        Ok(Ok(sub)) => {
            crate::response::plain_json(StatusCode::OK, &serde_json::json!({ "sub": sub }))
        }
        Ok(Err(challenge)) => {
            let mut response = StatusCode::UNAUTHORIZED.into_response();
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
        Err(error) => {
            tracing::error!(%error, "the protected resource's store failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    };
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    // FAPI: the client's x-fapi-interaction-id back, or a fresh one.
    let interaction_id = headers.get(FAPI_INTERACTION_ID).cloned().or_else(|| {
        HeaderValue::from_str(&rustid_core::admin::EntityId::new_v7().to_string()).ok()
    });
    if let Some(id) = interaction_id {
        response.headers_mut().insert(FAPI_INTERACTION_ID, id);
    }
    response
}

const FAPI_INTERACTION_ID: &str = "x-fapi-interaction-id";
