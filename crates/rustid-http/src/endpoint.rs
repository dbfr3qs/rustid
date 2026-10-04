//! What the form-posting endpoints (token, introspection, revocation) share:
//! Content-type checks, body reading and the per-request protocol context.

use axum::body::Body;
use axum::http::HeaderMap;
use axum::http::header::CONTENT_TYPE;
use rustid_core::events::RequestInfo;
use rustid_core::form::Form;
use rustid_core::issuer::current_issuer;
use rustid_core::token::TokenContext;

use crate::ProtocolState;
use crate::request::Route;

/// Largest request body read, a 4 MB form value limit.
const MAX_BODY: usize = 4 * 1024 * 1024;

/// `HasApplicationFormContentType`: the media type, ignoring parameters.
pub(crate) fn is_form_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|media| {
            media
                .trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
}

/// Read form; `None` for a malformed form.
pub(crate) async fn read_form(body: Body) -> Option<Form> {
    let bytes = axum::body::to_bytes(body, MAX_BODY).await.ok()?;
    Form::parse(&bytes).ok()
}

/// The request's issuer and base URL, which the protocol context borrows.
pub(crate) struct RequestUrls {
    issuer: String,
    base_url: String,
    client_certificate: Option<std::sync::Arc<rustid_core::client_certificate::ClientCertificate>>,
}

impl RequestUrls {
    pub(crate) fn new(state: &ProtocolState, route: &Route) -> Self {
        RequestUrls {
            issuer: current_issuer(&state.options, &route.origin),
            base_url: route.origin.base_url(),
            client_certificate: route.client_certificate.clone(),
        }
    }

    pub(crate) fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Origin plus path base, without a trailing slash.
    pub(crate) fn base_url(&self) -> &str {
        &self.base_url
    }
}

pub(crate) fn context<'a>(
    state: &'a ProtocolState,
    urls: &'a RequestUrls,
    request: &'a RequestInfo,
) -> TokenContext<'a> {
    TokenContext {
        options: &state.options,
        stores: &state.stores,
        keys: &state.keys,
        replay: &*state.stores.replay,
        events: &state.events,
        request,
        private_key_jwt: state.features.private_key_jwt,
        extension_grants: &state.features.extension_grants,
        issuer: &urls.issuer,
        base_url: &urls.base_url,
        dpop_proofs: &[],
        client_certificate: urls.client_certificate.as_deref(),
        protector: &state.interaction.protector,
        now: chrono::Utc::now(),
    }
}
