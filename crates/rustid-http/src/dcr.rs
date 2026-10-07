//! `POST {path}`: dynamic client registration (RFC 7591),
//! behind initial access tokens.

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use crate::ProtocolState;
use crate::request::Route;
use crate::response::JSON_UTF8;

/// The registration endpoint's settings (`[dynamic_client_registration]`).
#[derive(Debug, Clone, Default)]
pub struct DcrSettings {
    /// Where it is served, such as `/connect/dcr`.
    pub path: String,
    /// Anyone may register; otherwise an initial access token is needed.
    pub open: bool,
    /// Bearer tokens that may register clients (RFC 7591 §3).
    pub initial_access_tokens: Vec<String>,
    pub options: rustid_core::dcr::DcrOptions,
    /// RFC 7592 read and delete of registered clients.
    pub client_management: bool,
}

const MAX_BODY: usize = 1024 * 1024;

/// What a request under the registration path is for.
pub(crate) enum Target {
    /// `{path}`: registering.
    Registration,
    /// `{path}/{client_id}`: managing a registered client (RFC 7592).
    Client(String),
}

impl Target {
    pub(crate) fn find(dcr: &DcrSettings, path: &str) -> Option<Target> {
        if path.eq_ignore_ascii_case(&dcr.path) {
            return Some(Target::Registration);
        }
        let prefix = path.get(..dcr.path.len())?;
        let rest = path[dcr.path.len()..].strip_prefix('/')?;
        (prefix.eq_ignore_ascii_case(&dcr.path) && !rest.is_empty() && !rest.contains('/'))
            .then(|| Target::Client(rest.to_owned()))
    }
}

/// The registration endpoint's absolute URL: the request's base URL (path
/// base included) plus the path, as discovery's endpoint URLs.
fn endpoint_url(dcr: &DcrSettings, route: &Route) -> String {
    format!(
        "{}{}",
        route.origin.base_url().trim_end_matches('/'),
        dcr.path
    )
}

/// Whether reading the body failed on the size limit.
fn too_large(error: &axum::Error) -> bool {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(e) = source {
        if e.is::<http_body_util::LengthLimitError>() {
            return true;
        }
        source = e.source();
    }
    false
}

/// `Authorization: Bearer <token>`, or none.
pub(crate) fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then(|| token.trim())
}

/// Equal in constant time (for equal lengths).
pub(crate) fn same(a: &str, b: &str) -> bool {
    aws_lc_rs::constant_time::verify_slices_are_equal(a.as_bytes(), b.as_bytes()).is_ok()
}

/// RFC 6750's answer to a missing or wrong token.
pub(crate) fn invalid_token() -> Response {
    let mut response = StatusCode::UNAUTHORIZED.into_response();
    response.headers_mut().insert(
        WWW_AUTHENTICATE,
        HeaderValue::from_static(r#"Bearer error="invalid_token""#),
    );
    response
}

fn json_response(status: StatusCode, body: &Value) -> Response {
    (status, [(CONTENT_TYPE, JSON_UTF8)], body.to_string()).into_response()
}

/// The media type is `application/json`.
fn is_json(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
}

pub(crate) async fn handle(
    state: &ProtocolState,
    dcr: &DcrSettings,
    route: &Route,
    method: &Method,
    headers: &HeaderMap,
    body: Body,
    info: &rustid_core::events::RequestInfo,
) -> Response {
    if method != Method::POST {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    if !dcr.open {
        let allowed =
            bearer(headers).is_some_and(|t| dcr.initial_access_tokens.iter().any(|k| same(k, t)));
        if !allowed {
            return invalid_token();
        }
    }
    if !is_json(headers) {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    let bytes = match axum::body::to_bytes(body, MAX_BODY).await {
        Ok(bytes) => bytes,
        Err(e) if too_large(&e) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
        Err(_) => Default::default(),
    };
    let error = |e: rustid_core::dcr::RegistrationError| {
        json_response(
            StatusCode::BAD_REQUEST,
            // The error body's members are spelled `Error` and
            // `ErrorDescription`.
            &json!({ "Error": e.error, "ErrorDescription": e.error_description }),
        )
    };
    let request = match rustid_core::dcr::parse(&bytes) {
        Ok(request) => request,
        Err(e) => return error(e),
    };
    let admin = rustid_core::admin::clients::ClientAdmin {
        allow_unregistered_pushed_redirect_uris: state
            .options
            .pushed_authorization
            .allow_unregistered_pushed_redirect_uris,
        pairwise_supported: state.options.pairwise.salt.is_some(),
    };
    let options = rustid_core::dcr::DcrOptions {
        management: dcr
            .client_management
            .then(|| rustid_core::dcr::ManagementUri {
                base: endpoint_url(dcr, route),
            }),
        ..dcr.options.clone()
    };
    match rustid_core::dcr::register(
        state.stores.configuration.as_ref(),
        &admin,
        &options,
        request,
        chrono::Utc::now(),
    )
    .await
    {
        Ok(Ok(body)) => json_response(StatusCode::CREATED, &Value::Object(body)),
        Ok(Err(e)) => error(e),
        Err(e) => crate::response::internal_error(
            state,
            info,
            "DynamicClientRegistration",
            &e.to_string(),
        ),
    }
}

/// `GET` or `DELETE {path}/{client_id}` with the client's registration
/// access token (RFC 7592); 404 unless management is on. A wrong or
/// missing token, or an unknown client, is 401 (RFC 7592 §2.1).
pub(crate) async fn manage(
    state: &ProtocolState,
    dcr: &DcrSettings,
    route: &Route,
    method: &Method,
    headers: &HeaderMap,
    client_id: &str,
    info: &rustid_core::events::RequestInfo,
) -> Response {
    if !dcr.client_management {
        return StatusCode::NOT_FOUND.into_response();
    }
    let failed = |e: rustid_core::stores::StoreError| {
        crate::response::internal_error(state, info, "DynamicClientManagement", &e.to_string())
    };
    let client = match state.stores.clients.find_client_by_id(client_id).await {
        Ok(client) => client,
        Err(e) => return failed(e),
    };
    let Some(client) = client
        .filter(|c| bearer(headers).is_some_and(|t| rustid_core::dcr::authorize_management(c, t)))
    else {
        return invalid_token();
    };
    let uri = format!("{}/{}", endpoint_url(dcr, route), client.client_id);
    match *method {
        Method::GET => match rustid_core::dcr::read(&client, &uri) {
            Some(metadata) => {
                let mut response = json_response(StatusCode::OK, &Value::Object(metadata));
                response.headers_mut().insert(
                    axum::http::header::CACHE_CONTROL,
                    HeaderValue::from_static("no-store"),
                );
                response
            }
            None => invalid_token(),
        },
        Method::DELETE => {
            let admin = rustid_core::admin::clients::ClientAdmin::default();
            let store = state.stores.configuration.as_ref();
            match admin.get_by_client_id(store, &client.client_id).await {
                Ok(Some(found)) => match admin.delete(store, &found.id).await {
                    Ok(_) => StatusCode::NO_CONTENT.into_response(),
                    Err(e) => failed(e),
                },
                Ok(None) => invalid_token(),
                Err(e) => failed(e),
            }
        }
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}
