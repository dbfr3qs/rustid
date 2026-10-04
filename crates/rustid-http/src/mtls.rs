//! The mTLS endpoint aliases. A request to
//! the mTLS domain, the mTLS subdomain, or (with neither configured) a
//! path under `/connect/mtls` needs a client certificate; a path alias is
//! then served as `/connect/<rest>`.

use axum::http::StatusCode;
use axum::response::Response;
use serde_json::json;

use crate::ProtocolState;
use crate::request::{Route, strip_segment_prefix};
use crate::response::plain_json;

const MTLS_PATH_PREFIX: &str = "/connect/mtls";

/// Applies the mTLS alias rules to `route`, or answers the refusal.
pub(crate) fn apply(state: &ProtocolState, route: &mut Route) -> Result<(), Response> {
    let options = &state.options.mutual_tls;
    if !options.enabled {
        return Ok(());
    }
    // The certificate authentication handler validates the period.
    let authenticated = route
        .client_certificate
        .as_ref()
        .is_some_and(|c| c.valid_at(chrono::Utc::now()));
    let requires_certificate = match options.domain_name.as_deref().filter(|d| !d.is_empty()) {
        Some(domain) if domain.contains('.') => host_matches(&route.origin.host, domain),
        Some(label) => route
            .origin
            .host
            .to_ascii_lowercase()
            .starts_with(&format!("{}.", label.to_ascii_lowercase())),
        None => match strip_segment_prefix(&route.path, MTLS_PATH_PREFIX) {
            Some(rest) => {
                let rest = if rest.starts_with('/') {
                    rest.to_owned()
                } else {
                    format!("/{rest}")
                };
                if authenticated {
                    tracing::debug!(from = %route.path, "rewriting an mTLS request");
                    route.path = format!("/connect{rest}");
                }
                true
            }
            None => false,
        },
    };
    if requires_certificate && !authenticated {
        tracing::debug!("MTLS authentication failed: no client certificate");
        return Err(plain_json(
            StatusCode::BAD_REQUEST,
            &json!({ "error": "invalid_client", "error_description": "mTLS authentication failed." }),
        ));
    }
    Ok(())
}

/// `RequestedHostMatches`: the host without regard to case, and the port
/// (443 when either side leaves it out).
fn host_matches(request_host: &str, configured: &str) -> bool {
    let split = |host: &str| -> (String, Option<u16>) {
        // An IPv6 literal keeps its brackets; the port follows `]:`.
        let (name, port) = match host.strip_prefix('[') {
            Some(rest) => match rest.split_once("]:") {
                Some((literal, port)) => (format!("[{literal}]"), Some(port)),
                None => (host.to_owned(), None),
            },
            None => match host.rsplit_once(':') {
                Some((name, port)) => (name.to_owned(), Some(port)),
                None => (host.to_owned(), None),
            },
        };
        (name.to_ascii_lowercase(), port.and_then(|p| p.parse().ok()))
    };
    let (request_name, request_port) = split(request_host);
    let (configured_name, configured_port) = split(configured);
    request_name == configured_name && request_port.unwrap_or(443) == configured_port.unwrap_or(443)
}
