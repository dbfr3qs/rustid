//! `PushedAuthorizationEndpoint`: `POST /connect/par` (RFC 9126).

use axum::body::Body;
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use rustid_core::authorize::AuthorizeContext;
use rustid_core::client_auth::authenticate_client;
use rustid_core::dpop;
use rustid_core::events::RequestInfo;
use rustid_core::issuer::current_issuer;
use rustid_core::params::Params;
use rustid_core::pushed_authorization::{PushProof, push};
use serde_json::json;

use crate::ProtocolState;
use crate::endpoint::{RequestUrls, context, is_form_content_type, read_form};
use crate::request::Route;
use crate::response::{internal_error, no_cache_json};
use crate::token::dpop_proofs;

fn error(error: &str, description: Option<&str>) -> Response {
    let mut body = serde_json::Map::new();
    body.insert("error".into(), json!(error));
    if let Some(description) = description {
        body.insert("error_description".into(), json!(description));
    }
    no_cache_json(StatusCode::BAD_REQUEST, &serde_json::Value::Object(body))
}

/// An error with a DPoP server nonce in `DPoP-Nonce`.
fn nonce_error(error: &str, description: Option<&str>, nonce: Option<&str>) -> Response {
    let mut response = self::error(error, description);
    if let Some(nonce) = nonce.and_then(|n| HeaderValue::from_str(n).ok()) {
        response.headers_mut().insert(dpop::NONCE_HEADER, nonce);
    }
    response
}

pub(crate) async fn par(
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
        return error("invalid_request", None);
    }
    let Some(form) = read_form(body).await else {
        return error("invalid_request", None);
    };
    let urls = RequestUrls::new(state, route);
    let token_ctx = context(state, &urls, info);
    let authorization = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok());
    let client = match authenticate_client(&token_ctx, authorization, &form).await {
        Ok(Ok(client)) => client,
        Ok(Err(e)) => return error(e, None),
        Err(e) => {
            return internal_error(state, info, "PushedAuthorizationEndpoint", &e.to_string());
        }
    };
    let proofs = dpop_proofs(headers);
    if proofs.len() > 1 {
        return error("invalid_request", None);
    }
    // With a client certificate, the proof names the mTLS alias.
    let par_url = match &route.client_certificate {
        Some(_) => rustid_core::client_certificate::mtls_endpoint(
            &state.options.mutual_tls,
            urls.base_url(),
            "connect/par",
        ),
        None => format!("{}/connect/par", urls.base_url()),
    };
    let proof = proofs.first().map(|proof| PushProof {
        proof,
        url: &par_url,
        replay: &*state.stores.replay,
        protector: &state.interaction.protector,
    });
    let issuer = current_issuer(&state.options, &route.origin);
    let ctx = AuthorizeContext {
        options: &state.options,
        issuer: &issuer,
        stores: &state.stores,
        events: &state.events,
        request: info,
        now: chrono::Utc::now(),
    };
    match push(&ctx, &client, Params::from_form(&form), proof.as_ref()).await {
        Ok((request_uri, expires_in)) => no_cache_json(
            StatusCode::CREATED,
            &json!({ "request_uri": request_uri, "expires_in": expires_in }),
        ),
        Err(e) if e.error == "server_error" => internal_error(
            state,
            info,
            "PushedAuthorizationEndpoint",
            e.description.as_deref().unwrap_or_default(),
        ),
        Err(e) => nonce_error(&e.error, e.description.as_deref(), e.dpop_nonce.as_deref()),
    }
}
