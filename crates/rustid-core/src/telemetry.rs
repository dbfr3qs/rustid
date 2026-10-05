//! Metrics with fixed instrument names and tags,
//! recorded through the global OpenTelemetry meter provider (a no-op until
//! the server installs one), and the span names of its activities.
//!
//! Instruments are created on first use, so a meter provider installed
//! before the first request is the one that records.

use std::sync::OnceLock;

use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, UpDownCounter};

/// The meter and tracer name.
pub const METER_NAME: &str = "rustid";

/// Counter instrument names.
pub mod counters {
    pub const OPERATION: &str = "tokenservice.operation";
    pub const ACTIVE_REQUESTS: &str = "tokenservice.active_requests";
    pub const API_SECRET_VALIDATION: &str = "tokenservice.api.secret_validation";
    pub const CLIENT_CONFIG_VALIDATION: &str = "tokenservice.client.config_validation";
    pub const CLIENT_SECRET_VALIDATION: &str = "tokenservice.client.secret_validation";
    pub const INTROSPECTION: &str = "tokenservice.introspection";
    pub const REVOCATION: &str = "tokenservice.revocation";
    pub const TOKEN_ISSUED: &str = "tokenservice.token_issued";
}

/// Span names.
pub mod spans {
    pub const PROTOCOL_REQUEST: &str = "ProtocolRequest";
    pub const CLIENT_SECRET_VALIDATOR: &str = "client.authenticate";
    pub const API_SECRET_VALIDATOR: &str = "api_resource.authenticate";
    pub const TOKEN_REQUEST_VALIDATOR: &str = "token.validate_request";
    pub const TOKEN_RESPONSE_GENERATOR: &str = "token.respond";
    pub const TOKEN_VALIDATOR: &str = "access_token.validate";
    pub const INTROSPECTION_REQUEST_VALIDATOR: &str = "IntrospectionRequestValidator.Validate";
    pub const INTROSPECTION_RESPONSE_GENERATOR: &str = "introspection.respond";
    pub const REVOCATION_REQUEST_VALIDATOR: &str = "revocation.validate_request";
    pub const REVOCATION_RESPONSE_GENERATOR: &str = "TokenRevocationResponseGenerator.Process";
    pub const DISCOVERY_DOCUMENT: &str = "discovery.document";
    pub const JWK_DOCUMENT: &str = "discovery.jwks";
    pub const KEY_MANAGER_CURRENT_KEYS: &str = "keys.current";
    pub const KEY_MANAGER_ALL_KEYS: &str = "keys.all";
}

struct Instruments {
    operation: Counter<u64>,
    active_requests: UpDownCounter<i64>,
    api_secret_validation: Counter<u64>,
    client_config_validation: Counter<u64>,
    client_secret_validation: Counter<u64>,
    introspection: Counter<u64>,
    revocation: Counter<u64>,
    token_issued: Counter<u64>,
}

fn instruments() -> &'static Instruments {
    static INSTRUMENTS: OnceLock<Instruments> = OnceLock::new();
    INSTRUMENTS.get_or_init(|| {
        let meter = opentelemetry::global::meter(METER_NAME);
        Instruments {
            operation: meter.u64_counter(counters::OPERATION).build(),
            active_requests: meter.i64_up_down_counter(counters::ACTIVE_REQUESTS).build(),
            api_secret_validation: meter.u64_counter(counters::API_SECRET_VALIDATION).build(),
            client_config_validation: meter
                .u64_counter(counters::CLIENT_CONFIG_VALIDATION)
                .build(),
            client_secret_validation: meter
                .u64_counter(counters::CLIENT_SECRET_VALIDATION)
                .build(),
            introspection: meter.u64_counter(counters::INTROSPECTION).build(),
            revocation: meter.u64_counter(counters::REVOCATION).build(),
            token_issued: meter.u64_counter(counters::TOKEN_ISSUED).build(),
        }
    })
}

fn tag(key: &'static str, value: &str) -> KeyValue {
    KeyValue::new(key, value.to_owned())
}

/// `Success`: an operation counted with `result=success`.
pub fn success(client: Option<&str>) {
    let mut tags = Vec::with_capacity(2);
    if let Some(client) = client {
        tags.push(tag("client", client));
    }
    tags.push(tag("result", "success"));
    instruments().operation.add(1, &tags);
}

/// `Failure`: an operation counted with `error` and `result=error`.
pub fn failure(error: &str, client: Option<&str>) {
    let mut tags = Vec::with_capacity(3);
    if let Some(client) = client {
        tags.push(tag("client", client));
    }
    tags.push(tag("error", error));
    tags.push(tag("result", "error"));
    instruments().operation.add(1, &tags);
}

/// A server-side failure, `result=internal_error`.
pub fn internal_error(kind: &str, method: &str) {
    instruments().operation.add(
        1,
        &[
            tag("type", kind),
            tag("method", method),
            tag("result", "internal_error"),
        ],
    );
}

/// Counts a request in (`delta` 1) or out (`delta` -1) of an endpoint.
pub fn active_requests(endpoint: &str, path: &str, delta: i64) {
    instruments()
        .active_requests
        .add(delta, &[tag("endpoint", endpoint), tag("path", path)]);
}

pub fn client_validation(client: &str) {
    success(Some(client));
    instruments()
        .client_config_validation
        .add(1, &[tag("client", client)]);
}

pub fn client_validation_failure(client: &str, error: &str) {
    failure(error, Some(client));
    instruments()
        .client_config_validation
        .add(1, &[tag("client", client), tag("error", error)]);
}

pub fn client_secret_validation(client: &str, auth_method: &str) {
    success(Some(client));
    instruments()
        .client_secret_validation
        .add(1, &[tag("client", client), tag("auth_method", auth_method)]);
}

pub fn client_secret_validation_failure(client: &str, message: &str) {
    failure(message, Some(client));
    instruments()
        .client_secret_validation
        .add(1, &[tag("client", client), tag("error", message)]);
}

pub fn api_secret_validation(api: &str, auth_method: &str) {
    success(Some(api));
    instruments()
        .api_secret_validation
        .add(1, &[tag("api", api), tag("auth_method", auth_method)]);
}

pub fn api_secret_validation_failure(client: &str, message: &str) {
    failure(message, Some(client));
    instruments()
        .api_secret_validation
        .add(1, &[tag("client", client), tag("error", message)]);
}

pub fn introspection(caller: &str, active: bool) {
    success(Some(caller));
    instruments()
        .introspection
        .add(1, &[tag("caller", caller), KeyValue::new("active", active)]);
}

pub fn introspection_failure(caller: &str, error: &str) {
    failure(error, Some(caller));
    instruments()
        .introspection
        .add(1, &[tag("caller", caller), tag("error", error)]);
}

pub fn revocation(client: &str) {
    success(Some(client));
    instruments().revocation.add(1, &[tag("client", client)]);
}

pub fn revocation_failure(client: Option<&str>, error: &str) {
    failure(error, client);
    let mut tags = Vec::with_capacity(2);
    if let Some(client) = client {
        tags.push(tag("client", client));
    }
    tags.push(tag("error", error));
    instruments().revocation.add(1, &tags);
}

/// `TokenIssued` at the token endpoint.
pub struct TokenIssued<'a> {
    pub client: &'a str,
    pub grant_type: &'a str,
    pub access_token_issued: bool,
    /// `Jwt` or `Reference`.
    pub access_token_type: Option<&'a str>,
    pub refresh_token_issued: bool,
    /// `None`, `DPoP` or `ClientCertificate`.
    pub proof_type: &'a str,
    pub id_token_issued: bool,
}

pub fn token_issued(issued: &TokenIssued<'_>) {
    success(Some(issued.client));
    let mut tags = vec![
        tag("client", issued.client),
        tag("grant_type", issued.grant_type),
        KeyValue::new("access_token_issued", issued.access_token_issued),
    ];
    if let Some(kind) = issued.access_token_type {
        tags.push(tag("access_token_type", kind));
    }
    tags.push(KeyValue::new(
        "refresh_token_issued",
        issued.refresh_token_issued,
    ));
    tags.push(tag("proof_type", issued.proof_type));
    tags.push(KeyValue::new("id_token_issued", issued.id_token_issued));
    instruments().token_issued.add(1, &tags);
}

pub fn token_issued_failure(client: Option<&str>, grant_type: Option<&str>, error: &str) {
    failure(error, client);
    let mut tags = Vec::with_capacity(3);
    if let Some(client) = client {
        tags.push(tag("client", client));
    }
    if let Some(grant_type) = grant_type {
        tags.push(tag("grant_type", grant_type));
    }
    tags.push(tag("error", error));
    instruments().token_issued.add(1, &tags);
}
