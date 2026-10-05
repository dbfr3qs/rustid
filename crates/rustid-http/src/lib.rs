#![forbid(unsafe_code)]

//! The axum layer: routing at the protocol's default paths and response
//! writing. Protocol decisions are made in `rustid-core`.

mod authorize;
mod ciba;
mod cookies;
mod cors;
mod dcr;
mod device_authorization;
mod discovery;
mod end_session;
mod endpoint;
mod federation;
mod interaction_api;
mod introspection;
mod mtls;
mod par;
mod protected_resource;
pub use dcr::DcrSettings;
mod request;
mod response;
mod revocation;
#[cfg(feature = "saml")]
mod saml;
mod session;
mod session_cookie;
mod token;
mod userinfo;

use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router, routing::get};
use rustid_core::data_protection::DataProtector;
use rustid_core::discovery::DiscoveryFeatures;
use rustid_core::events::{self, EventService};
use rustid_core::key_service::KeyService;
use rustid_core::options::ProtocolOptions;
use rustid_core::stores::Stores;
use rustid_core::telemetry;
use serde::Serialize;
use tracing::Instrument;

pub use request::is_valid_host;
pub use response::{JSON_UTF8, JSON_UTF8_UPPER};
pub use session::CurrentSession;

/// Everything a request handler needs, built once at startup and shared.
#[derive(Debug, Clone)]
pub struct ProtocolState {
    pub options: ProtocolOptions,
    /// Static and automatically managed signing keys.
    pub keys: KeyService,
    pub features: DiscoveryFeatures,
    /// Clients, resources and persisted grants.
    pub stores: Stores,
    /// Raises events enabled in `protocol.events`.
    pub events: EventService,
    /// Optional path prefix, matched case-insensitively.
    pub path_base: Option<String>,
    /// What browser interactions and the interaction API need.
    pub interaction: InteractionState,
    /// The path of a protected resource the server serves itself
    /// (`[protected_resource]`), for conformance runs; none when absent.
    pub protected_resource: Option<String>,
    /// Dynamic client registration (`[dynamic_client_registration]`); none
    /// when disabled.
    pub dcr: Option<DcrSettings>,
    /// The SAML 2.0 IdP, when enabled.
    pub saml: SamlState,
}

/// The SAML IdP's options and stores; none when SAML is disabled (or not
/// built: the `saml` feature).
#[derive(Clone, Default)]
pub struct SamlState(#[cfg(feature = "saml")] pub Option<rustid_saml::Saml>);

impl std::fmt::Debug for SamlState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SamlState(..)")
    }
}

impl SamlState {
    #[cfg(feature = "saml")]
    pub fn get(&self) -> Option<&rustid_saml::Saml> {
        self.0.as_ref()
    }
}

/// Settings and secrets for the authorize flow's browser interactions.
#[derive(Debug, Clone)]
pub struct InteractionState {
    /// Seals messages passed through URLs (error ids).
    pub protector: Arc<DataProtector>,
    /// Bearer keys accepted by the interaction API; none disables it.
    pub api_keys: Vec<String>,
    /// UI culture names `ui_locales` may select for the culture cookie.
    pub supported_ui_cultures: Vec<String>,
}

impl Default for InteractionState {
    /// A random, process-lifetime key; no API keys; no UI cultures.
    fn default() -> Self {
        let key = rustid_core::data_protection::generate_key();
        InteractionState {
            protector: Arc::new(
                DataProtector::new([("ephemeral", key.as_slice())]).expect("valid key"),
            ),
            api_keys: Vec::new(),
            supported_ui_cultures: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AppState(pub Arc<ProtocolState>);

impl AppState {
    pub fn new(state: ProtocolState) -> Self {
        AppState(Arc::new(state))
    }
}

#[derive(Serialize)]
struct Health {
    status: &'static str,
}

/// How long `/ready` waits for each probe (the store, then the signing key).
pub const READY_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

#[derive(Serialize)]
struct Readiness {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
}

/// The server's router: `/health`, `/ready` plus every protocol endpoint.
/// Whether a request for `path` (after any path base) reaches something
/// the protocol router serves: an endpoint, the interaction API, the
/// protected resource, or the health routes. A configurable path (dynamic
/// client registration's) must not shadow one.
pub fn shadows_route(state: &ProtocolState, path: &str) -> bool {
    let route = request::Route {
        origin: rustid_core::issuer::RequestOrigin {
            scheme: "https".into(),
            host: "localhost".into(),
            base_path: String::new(),
        },
        path: path.to_owned(),
        query: String::new(),
        client_certificate: None,
    };
    let lower = path.to_ascii_lowercase();
    Endpoint::find(state, &route).is_some()
        || interaction_api::Call::find(&lower).is_some()
        || federation::find(&lower).is_some()
        || state
            .protected_resource
            .as_deref()
            .is_some_and(|p| p.eq_ignore_ascii_case(path))
        || lower == "/health"
        || lower == "/ready"
}

pub fn router(state: AppState) -> Router {
    app(state, None)
}

/// The router with `extra` routes (the reference UI) in front of the
/// protocol endpoints; every request, extra ones included, goes through
/// the session middleware first.
pub fn app(state: AppState, extra: Option<Router>) -> Router {
    let mut router = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .fallback(protocol)
        .with_state(state.clone());
    if let Some(extra) = extra {
        router = extra.merge(router);
    }
    router.layer(axum::middleware::from_fn_with_state(
        state,
        session::ensure_session_id,
    ))
}

async fn health() -> impl IntoResponse {
    ([(CONTENT_TYPE, JSON_UTF8)], Json(Health { status: "ok" }))
}

/// Readiness: the persisted grant store answers (grants are never cached,
/// so this reaches the database) and a signing key is available (key
/// management creates one if needed). Failures are logged, not returned:
/// Store errors can carry connection details.
async fn ready(State(state): State<AppState>) -> Response {
    use tokio::time::timeout;
    let unavailable = |reason: &'static str| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            [(CONTENT_TYPE, JSON_UTF8)],
            Json(Readiness {
                status: "unavailable",
                reason: Some(reason),
            }),
        )
            .into_response()
    };
    match timeout(
        READY_PROBE_TIMEOUT,
        state.0.stores.grants.get("rustid:readiness-probe"),
    )
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => {
            tracing::warn!(%error, "readiness: the store failed");
            return unavailable("store");
        }
        Err(_) => {
            tracing::warn!("readiness: the store timed out");
            return unavailable("store");
        }
    }
    // Spawned so that a probe that times out doesn't cancel key management
    // creating the first key (slow for RSA); the next probe finds it.
    let keys = state.0.clone();
    let signing_key = tokio::spawn(async move { keys.keys.signing_key(&[]).await });
    match timeout(READY_PROBE_TIMEOUT, signing_key).await {
        Ok(Ok(Ok(Some(_)))) => {}
        Ok(Ok(Ok(None))) => {
            tracing::warn!("readiness: no signing key");
            return unavailable("signing_key");
        }
        Ok(Ok(Err(error))) => {
            tracing::warn!(%error, "readiness: the signing key failed");
            return unavailable("signing_key");
        }
        Ok(Err(error)) => {
            tracing::warn!(%error, "readiness: the signing key check panicked");
            return unavailable("signing_key");
        }
        Err(_) => {
            tracing::warn!("readiness: the signing key timed out");
            return unavailable("signing_key");
        }
    }
    (
        [(CONTENT_TYPE, JSON_UTF8)],
        Json(Readiness {
            status: "ready",
            reason: None,
        }),
    )
        .into_response()
}

/// The server's local address, added by the server as a request extension
/// so events can report it.
#[derive(Debug, Clone, Copy)]
pub struct LocalAddr(pub std::net::SocketAddr);

/// Added by the server to requests that arrived over TLS: URLs built from the request use `https`, and the
/// session cookies are `Secure`.
#[derive(Debug, Clone, Copy)]
pub struct Https;

/// Added by the server to requests that came with a TLS client certificate
/// (from its TLS listener or a trusted proxy's forwarded header).
#[derive(Debug, Clone)]
pub struct TlsClientCertificate(pub Arc<rustid_core::client_certificate::ClientCertificate>);

/// Routes protocol requests by path: exact,
/// case-insensitive path matches after the optional path base. CORS for
/// the CORS endpoints is applied first.
async fn protocol(State(state): State<AppState>, request: Request<Body>) -> Response {
    let state = &*state.0;
    let (parts, body) = request.into_parts();
    let method = parts.method.clone();
    let headers: &HeaderMap = &parts.headers;
    let session = parts
        .extensions
        .get::<CurrentSession>()
        .and_then(|s| s.0.clone());
    let Some(mut route) = request::Route::parse(
        state,
        headers,
        &parts.uri,
        parts.extensions.get::<Https>().is_some(),
    ) else {
        // A missing or invalid Host header (RFC 9112 §3.2).
        return StatusCode::BAD_REQUEST.into_response();
    };
    let info = events::RequestInfo {
        activity_id: None,
        local_ip_address: parts.extensions.get::<LocalAddr>().map(|a| a.0.to_string()),
        remote_ip_address: parts
            .extensions
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|c| c.0.to_string()),
    };
    let allow_origin = match cors::evaluate(state, headers, &route, &method).await {
        Some(cors::Cors::Preflight(response)) => return response,
        Some(cors::Cors::Allow(origin)) => Some(origin),
        Some(cors::Cors::Failed) => {
            return response::internal_error(
                state,
                &info,
                "IsOriginAllowed",
                "the CORS origin check failed",
            );
        }
        None => None,
    };
    route.client_certificate = parts
        .extensions
        .get::<TlsClientCertificate>()
        .map(|c| c.0.clone());
    if let Err(refused) = mtls::apply(state, &mut route) {
        return refused;
    }
    if state
        .protected_resource
        .as_deref()
        .is_some_and(|path| path.eq_ignore_ascii_case(&route.path))
        && method == axum::http::Method::GET
    {
        return protected_resource::handle(state, &route, &method, headers).await;
    }
    if let Some(settings) = &state.dcr {
        match dcr::Target::find(settings, &route.path) {
            Some(dcr::Target::Registration) => {
                return dcr::handle(state, settings, &route, &method, headers, body, &info).await;
            }
            // A route another endpoint serves stays that endpoint's, even
            // under a DCR path that is its parent (`/connect`).
            Some(dcr::Target::Client(client_id)) if !shadows_route(state, &route.path) => {
                return dcr::manage(state, settings, &route, &method, headers, &client_id, &info)
                    .await;
            }
            Some(dcr::Target::Client(_)) | None => {}
        }
    }
    if let Some((scheme, leg)) = federation::find(&route.path.to_ascii_lowercase()) {
        let incoming = request::Incoming {
            route: &route,
            method: &method,
            headers,
            info: &info,
            session: session.as_ref(),
        };
        return federation::handle(state, &incoming, &scheme, leg).await;
    }
    if let Some(call) = interaction_api::Call::find(&route.path.to_ascii_lowercase()) {
        let incoming = request::Incoming {
            route: &route,
            method: &method,
            headers,
            info: &info,
            session: session.as_ref(),
        };
        return interaction_api::handle(state, &incoming, body, &call).await;
    }
    let mut response = match Endpoint::find(state, &route) {
        // CORS applies outside endpoint routing, so a 404 on a CORS path
        // still gets the header below.
        None => StatusCode::NOT_FOUND.into_response(),
        Some(endpoint) => {
            let span = tracing::info_span!("ProtocolRequest", endpoint_type = endpoint.type_name());
            async {
                let info = events::RequestInfo {
                    activity_id: activity_id(),
                    ..info
                };
                let _active = ActiveRequest::start(endpoint.type_name(), &route.path);
                let incoming = request::Incoming {
                    route: &route,
                    method: &method,
                    headers,
                    info: &info,
                    session: session.as_ref(),
                };
                endpoint.handle(state, &incoming, body).await
            }
            .instrument(span)
            .await
        }
    };
    if let Some(origin) = allow_origin {
        response
            .headers_mut()
            .insert(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    }
    response
}

/// Counts a request in `tokenservice.active_requests` until dropped, so a
/// request abandoned mid-flight (client gone, panic) is counted out too, as
/// The count is decremented however the request ends.
struct ActiveRequest {
    endpoint: &'static str,
    path: String,
}

impl ActiveRequest {
    fn start(endpoint: &'static str, path: &str) -> Self {
        telemetry::active_requests(endpoint, path, 1);
        ActiveRequest {
            endpoint,
            path: path.to_owned(),
        }
    }
}

impl Drop for ActiveRequest {
    fn drop(&mut self) {
        telemetry::active_requests(self.endpoint, &self.path, -1);
    }
}

/// A per-request identifier (connection id, colon, request number), for
/// error messages.
pub(crate) fn request_id() -> String {
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicU64, Ordering};
    static PREFIX: OnceLock<String> = OnceLock::new();
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let prefix = PREFIX.get_or_init(|| {
        let key = rustid_core::data_protection::generate_key();
        key[..7].iter().map(|b| format!("{b:02X}")).collect()
    });
    format!(
        "{prefix}:{:08X}",
        COUNTER.fetch_add(1, Ordering::Relaxed) + 1
    )
}

/// The W3C `traceparent` of the current span when OpenTelemetry tracing is
/// on, for events.
pub(crate) fn activity_id() -> Option<String> {
    use opentelemetry::trace::TraceContextExt;
    use tracing_opentelemetry::OpenTelemetrySpanExt;
    let context = tracing::Span::current().context();
    let span = context.span();
    let sc = span.span_context();
    sc.is_valid().then(|| {
        format!(
            "00-{}-{}-{:02x}",
            sc.trace_id(),
            sc.span_id(),
            sc.trace_flags().to_u8()
        )
    })
}

/// The protocol endpoints.
enum Endpoint<'a> {
    Authorize,
    AuthorizeCallback,
    DiscoveryKey,
    Discovery,
    OAuthMetadata(&'a str),
    Token,
    Introspection,
    Revocation,
    UserInfo,
    PushedAuthorization,
    DeviceAuthorization,
    BackchannelAuthentication,
    EndSession,
    EndSessionCallback,
    CheckSession,
    #[cfg(feature = "saml")]
    SamlMetadata(&'a rustid_saml::Saml),
    #[cfg(feature = "saml")]
    SamlSingleSignOn(&'a rustid_saml::Saml),
    #[cfg(feature = "saml")]
    SamlSingleSignOnCallback(&'a rustid_saml::Saml),
    #[cfg(feature = "saml")]
    SamlSingleLogout(&'a rustid_saml::Saml),
    #[cfg(feature = "saml")]
    SamlSingleLogoutCallback(&'a rustid_saml::Saml),
}

impl<'a> Endpoint<'a> {
    fn find(state: &'a ProtocolState, route: &'a request::Route) -> Option<Self> {
        let e = &state.options.endpoints;
        let lower = route.path.to_ascii_lowercase();
        #[cfg(feature = "saml")]
        if let Some(saml) = state.saml.get()
            && lower == rustid_saml::metadata::metadata_path(&saml.options).to_ascii_lowercase()
        {
            return Some(Endpoint::SamlMetadata(saml));
        }
        #[cfg(feature = "saml")]
        if let Some(saml) = state.saml.get()
            && lower
                == saml
                    .options
                    .endpoints
                    .single_sign_on_service_path
                    .to_ascii_lowercase()
        {
            return Some(Endpoint::SamlSingleSignOn(saml));
        }
        #[cfg(feature = "saml")]
        if let Some(saml) = state.saml.get()
            && lower
                == saml
                    .options
                    .endpoints
                    .single_sign_on_callback_path
                    .to_ascii_lowercase()
        {
            return Some(Endpoint::SamlSingleSignOnCallback(saml));
        }
        #[cfg(feature = "saml")]
        if let Some(saml) = state.saml.get() {
            let endpoints = &saml.options.endpoints;
            if lower == endpoints.single_logout_service_path.to_ascii_lowercase() {
                return Some(Endpoint::SamlSingleLogout(saml));
            }
            if lower == endpoints.single_logout_callback_path.to_ascii_lowercase() {
                return Some(Endpoint::SamlSingleLogoutCallback(saml));
            }
        }
        if lower == "/.well-known/openid-configuration/jwks" {
            Some(Endpoint::DiscoveryKey)
        } else if lower == "/.well-known/openid-configuration" {
            Some(Endpoint::Discovery)
        } else if let Some(sub_path) =
            request::strip_segment_prefix(&route.path, "/.well-known/oauth-authorization-server")
        {
            Some(Endpoint::OAuthMetadata(sub_path))
        } else if lower == "/connect/authorize" && e.enable_authorize_endpoint {
            Some(Endpoint::Authorize)
        } else if lower == "/connect/authorize/callback" && e.enable_authorize_endpoint {
            Some(Endpoint::AuthorizeCallback)
        } else if lower == "/connect/token" && e.enable_token_endpoint {
            Some(Endpoint::Token)
        } else if lower == "/connect/introspect" && e.enable_introspection_endpoint {
            Some(Endpoint::Introspection)
        } else if lower == "/connect/revocation" && e.enable_token_revocation_endpoint {
            Some(Endpoint::Revocation)
        } else if lower == "/connect/userinfo" && e.enable_user_info_endpoint {
            Some(Endpoint::UserInfo)
        } else if lower == "/connect/par" && e.enable_pushed_authorization_endpoint {
            Some(Endpoint::PushedAuthorization)
        } else if lower == "/connect/deviceauthorization" && e.enable_device_authorization_endpoint
        {
            Some(Endpoint::DeviceAuthorization)
        } else if lower == "/connect/ciba" && e.enable_backchannel_authentication_endpoint {
            Some(Endpoint::BackchannelAuthentication)
        } else if lower == "/connect/endsession" && e.enable_end_session_endpoint {
            Some(Endpoint::EndSession)
        } else if lower == "/connect/endsession/callback" && e.enable_end_session_endpoint {
            Some(Endpoint::EndSessionCallback)
        } else if lower == "/connect/checksession" && e.enable_check_session_endpoint {
            Some(Endpoint::CheckSession)
        } else {
            None
        }
    }

    /// The endpoint handler's name, the `endpoint_type` of spans and metrics.
    fn type_name(&self) -> &'static str {
        match self {
            Endpoint::Authorize => "AuthorizeEndpoint",
            Endpoint::AuthorizeCallback => "AuthorizeCallbackEndpoint",
            Endpoint::DiscoveryKey => "DiscoveryKeyEndpoint",
            Endpoint::Discovery => "DiscoveryEndpoint",
            Endpoint::OAuthMetadata(_) => "OAuthMetadataEndpoint",
            Endpoint::Token => "TokenEndpoint",
            Endpoint::Introspection => "IntrospectionEndpoint",
            Endpoint::Revocation => "TokenRevocationEndpoint",
            Endpoint::UserInfo => "UserInfoEndpoint",
            Endpoint::PushedAuthorization => "PushedAuthorizationEndpoint",
            Endpoint::DeviceAuthorization => "DeviceAuthorizationEndpoint",
            Endpoint::BackchannelAuthentication => "BackchannelAuthenticationEndpoint",
            Endpoint::EndSession => "EndSessionEndpoint",
            Endpoint::EndSessionCallback => "EndSessionCallbackEndpoint",
            Endpoint::CheckSession => "CheckSessionEndpoint",
            #[cfg(feature = "saml")]
            Endpoint::SamlMetadata(_) => "MetadataEndpoint",
            #[cfg(feature = "saml")]
            Endpoint::SamlSingleSignOn(_) => "SingleSignOnServiceEndpoint",
            #[cfg(feature = "saml")]
            Endpoint::SamlSingleSignOnCallback(_) => "SingleSignOnCallbackEndpoint",
            #[cfg(feature = "saml")]
            Endpoint::SamlSingleLogout(_) => "SingleLogoutServiceEndpoint",
            #[cfg(feature = "saml")]
            Endpoint::SamlSingleLogoutCallback(_) => "SingleLogoutCallbackEndpoint",
        }
    }

    async fn handle(
        &self,
        state: &ProtocolState,
        incoming: &request::Incoming<'_>,
        body: Body,
    ) -> Response {
        let request::Incoming {
            route,
            method,
            headers,
            info,
            session,
        } = *incoming;
        let is_get = method == Method::GET;
        match self {
            Endpoint::Authorize => {
                authorize::authorize(state, route, method, headers, body, info, session).await
            }
            Endpoint::AuthorizeCallback => {
                authorize::callback(state, route, method, headers, info, session).await
            }
            Endpoint::DiscoveryKey => discovery::jwks(state, is_get, info).await,
            Endpoint::Discovery => discovery::document(state, route, is_get, info).await,
            Endpoint::OAuthMetadata(sub_path) => {
                discovery::oauth_metadata(state, route, sub_path, is_get, info).await
            }
            Endpoint::Token => token::token(state, route, method, headers, body, info).await,
            Endpoint::Introspection => {
                introspection::introspect(state, route, method, headers, body, info).await
            }
            Endpoint::Revocation => {
                revocation::revoke(state, route, method, headers, body, info).await
            }
            Endpoint::UserInfo => {
                userinfo::userinfo(state, route, method, headers, body, info).await
            }
            Endpoint::PushedAuthorization => {
                par::par(state, route, method, headers, body, info).await
            }
            Endpoint::BackchannelAuthentication => {
                ciba::backchannel_authentication(state, route, method, headers, body, info).await
            }
            Endpoint::DeviceAuthorization => {
                device_authorization::device_authorization(
                    state, route, method, headers, body, info,
                )
                .await
            }
            Endpoint::EndSession => {
                end_session::end_session(state, route, method, headers, body, info, session).await
            }
            Endpoint::EndSessionCallback => end_session::callback(state, route, method, info).await,
            Endpoint::CheckSession => end_session::check_session(state, method),
            #[cfg(feature = "saml")]
            Endpoint::SamlMetadata(saml) => {
                saml::metadata(state, saml, route, method, headers, info).await
            }
            #[cfg(feature = "saml")]
            Endpoint::SamlSingleSignOn(saml) => {
                saml::single_sign_on(state, saml, route, method, headers, body, info, session).await
            }
            #[cfg(feature = "saml")]
            Endpoint::SamlSingleSignOnCallback(saml) => {
                saml::callback(state, saml, route, method, headers, info, session).await
            }
            #[cfg(feature = "saml")]
            Endpoint::SamlSingleLogout(saml) => {
                saml::single_logout(state, saml, route, method, headers, body, info, session).await
            }
            #[cfg(feature = "saml")]
            Endpoint::SamlSingleLogoutCallback(saml) => {
                saml::single_logout_callback(state, saml, route, method, info).await
            }
        }
    }
}
