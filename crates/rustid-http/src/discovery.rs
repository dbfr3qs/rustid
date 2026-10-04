use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use rustid_core::discovery::{DiscoveryContext, discovery_document, jwks_document};
use rustid_core::events::RequestInfo;
use rustid_core::issuer::current_issuer;
use serde_json::Value;

use crate::ProtocolState;
use crate::request::Route;
use crate::response::{internal_error, json};

#[tracing::instrument(name = "discovery.document", skip_all)]
async fn document_response(
    state: &ProtocolState,
    base_url: &str,
    issuer: &str,
    info: &RequestInfo,
) -> Response {
    let resources = match state.stores.resources.get_all_enabled_resources().await {
        Ok(resources) => resources,
        Err(error) => {
            return internal_error(state, info, "DiscoveryEndpoint", &error.to_string());
        }
    };
    let keys = async {
        let validation = state.keys.validation_keys().await?;
        let algorithms = state.keys.signing_algorithms().await?;
        Ok::<_, rustid_core::stores::StoreError>((!validation.is_empty(), algorithms))
    };
    let (has_validation_keys, signing_algorithms) = match keys.await {
        Ok(keys) => keys,
        Err(error) => {
            return internal_error(state, info, "DiscoveryEndpoint", &error.to_string());
        }
    };
    let ctx = DiscoveryContext {
        options: &state.options,
        resources: &resources,
        has_validation_keys,
        signing_algorithms: &signing_algorithms,
        features: &state.features,
        base_url,
        issuer,
    };
    json(
        &Value::Object(discovery_document(&ctx)),
        state.options.discovery.response_cache_interval,
    )
}

/// `DiscoveryEndpoint`: disabled means the router never matches (404);
/// otherwise only GET is allowed.
pub(crate) async fn document(
    state: &ProtocolState,
    route: &Route,
    is_get: bool,
    info: &RequestInfo,
) -> Response {
    if !state.options.endpoints.enable_discovery_endpoint {
        return StatusCode::NOT_FOUND.into_response();
    }
    if !is_get {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let issuer = current_issuer(&state.options, &route.origin);
    document_response(state, &route.origin.base_url(), &issuer, info).await
}

/// `DiscoveryKeyEndpoint`: always routed; GET only; 404 when the key set is hidden.
pub(crate) async fn jwks(state: &ProtocolState, is_get: bool, info: &RequestInfo) -> Response {
    if !is_get {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    if !state.options.discovery.show_key_set {
        return StatusCode::NOT_FOUND.into_response();
    }
    jwk_document(state, info).await
}

#[tracing::instrument(name = "discovery.jwks", skip_all)]
async fn jwk_document(state: &ProtocolState, info: &RequestInfo) -> Response {
    let keys = match state.keys.validation_keys().await {
        Ok(keys) => keys,
        Err(error) => {
            return internal_error(state, info, "DiscoveryKeyEndpoint", &error.to_string());
        }
    };
    json(
        &jwks_document(&keys),
        state.options.discovery.response_cache_interval,
    )
}

/// `OAuthMetadataEndpoint`: RFC 8414 metadata at
/// `/.well-known/oauth-authorization-server{issuer path}`.
pub(crate) async fn oauth_metadata(
    state: &ProtocolState,
    route: &Route,
    sub_path: &str,
    is_get: bool,
    info: &RequestInfo,
) -> Response {
    let not_found = || StatusCode::NOT_FOUND.into_response();
    if !is_get {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    if !state.options.endpoints.enable_oauth2_metadata_endpoint {
        return not_found();
    }
    // Metadata must be requested at the host root, never under the path base.
    if !route.origin.base_path.is_empty() {
        return not_found();
    }
    // A sub-path must equal the issuer's path.
    if !sub_path.is_empty() {
        let issuer = current_issuer(&state.options, &route.origin);
        let matches =
            url::Url::parse(&issuer).is_ok_and(|u| u.path().eq_ignore_ascii_case(sub_path));
        if !matches {
            return not_found();
        }
    }
    let mut origin = route.origin.clone();
    // IServerUrls.BasePath setter applies RemoveTrailingSlash (one slash).
    origin.base_path = sub_path.strip_suffix('/').unwrap_or(sub_path).to_owned();
    let issuer = current_issuer(&state.options, &origin);
    if issuer != format!("{}://{}{}", origin.scheme, origin.host, sub_path) {
        return not_found();
    }
    document_response(state, &origin.base_url(), &issuer, info).await
}
