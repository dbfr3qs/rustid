#![forbid(unsafe_code)]
//! the admin HTTP API (scoping spec section 4.8): the operations of
//! the admin services (API scopes, identity resources, API resources, clients, …)
//! over HTTP under `/admin`, authenticated by bearer API keys.
//!
//! Each kind has `POST /` (create: 201 `{id, version}`), `GET /` (query),
//! `GET /{id}` and `GET /by-name/{name}` (`/by-client-id/{clientId}` for
//! clients) (the configuration with its `id`
//! and `version`, and `ETag`), `PUT /{id}` (needs `If-Match`), and
//! `DELETE /{id}` (204, idempotent). SAML service providers (the `saml`
//! feature) are read by entity id at `/by-entity-id/{entityId}`. Errors are
//! `{"errors": [{code, message, propertyNames}]}`.

use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Query, Request, State};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, ETAG, IF_MATCH, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use rustid_core::admin::query::{DEFAULT_PAGE_SIZE, Direction, Range};
use rustid_core::admin::resources::{
    ResourceAdmin, ResourceConfiguration, ResourceFilter, ResourceSortField,
};
use rustid_core::admin::{AdminError, EntityId, Saved, Versioned};
use rustid_core::stores::{ConfigurationStore, StoreError};
use serde_json::{Map, Value, json};

/// Request bodies larger than this are refused.
const MAX_BODY: usize = 1024 * 1024;

#[derive(Clone)]
pub struct AdminState {
    pub configuration: Arc<dyn ConfigurationStore>,
    /// Bearer keys that may call the API.
    pub api_keys: Vec<String>,
    /// The client admin, with the server's PAR option.
    pub clients: rustid_core::admin::clients::ClientAdmin,
    /// Schemas come from `schemas_file`: the schema routes only read.
    pub schemas_read_only: bool,
    /// The identity provider admin, with the data protection key ring
    /// secrets are stored under.
    pub identity_providers: Arc<rustid_core::admin::identity_providers::IdentityProviderAdmin>,
}

/// The routes under `/admin`, behind the API key check.
pub fn router(state: AdminState) -> Router {
    let mut admin = Router::new();
    for (path, kind) in [
        ("api-scopes", ResourceAdmin::api_scopes()),
        ("identity-resources", ResourceAdmin::identity_resources()),
    ] {
        admin = admin.nest(&format!("/{path}"), resource_routes(kind));
    }
    admin = admin.nest("/api-resources", api_resource_routes());
    admin = admin.nest("/clients", client_routes());
    admin = admin.nest("/schemas", schema_routes());
    admin = admin.nest("/identity-providers", identity_provider_routes());
    #[cfg(feature = "saml")]
    {
        admin = admin.nest("/saml-service-providers", saml_routes());
    }
    Router::new()
        .nest("/admin", admin)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            authenticate,
        ))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(state)
}

/// Constant-time equality (over the length of the presented key).
fn same(presented: &[u8], key: &[u8]) -> bool {
    presented.len() == key.len()
        && aws_lc_rs::constant_time::verify_slices_are_equal(presented, key).is_ok()
}

async fn authenticate(State(state): State<AdminState>, request: Request, next: Next) -> Response {
    let presented = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            let (scheme, key) = v.split_once(' ')?;
            scheme.eq_ignore_ascii_case("bearer").then_some(key)
        })
        .filter(|key| !key.is_empty());
    // Every key is compared, so timing doesn't tell which one matched.
    let authorized = presented.is_some_and(|presented| {
        state.api_keys.iter().fold(false, |found, key| {
            same(presented.as_bytes(), key.as_bytes()) | found
        })
    });
    if !authorized {
        return (
            StatusCode::UNAUTHORIZED,
            [(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"))],
        )
            .into_response();
    }
    next.run(request).await
}

fn json_response(status: StatusCode, body: &Value) -> Response {
    (
        status,
        [(CONTENT_TYPE, HeaderValue::from_static("application/json"))],
        body.to_string(),
    )
        .into_response()
}

fn errors(errors: Vec<AdminError>) -> Response {
    let status = match errors.first().map(|e| e.code) {
        Some("not_found") => StatusCode::NOT_FOUND,
        Some("already_exists" | "duplicate_value") => StatusCode::CONFLICT,
        Some("version_conflict") => StatusCode::PRECONDITION_FAILED,
        _ => StatusCode::BAD_REQUEST,
    };
    json_response(status, &json!({ "errors": errors }))
}

fn store_failure(error: StoreError) -> Response {
    tracing::error!(%error, "the admin API's store failed");
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}

fn not_found() -> Response {
    StatusCode::NOT_FOUND.into_response()
}

/// A request body as `T`, with `id` and `version` (which reads return)
/// ignored, so a body read back can be sent back.
fn body<T: serde::de::DeserializeOwned>(bytes: &Bytes) -> Result<T, Response> {
    let invalid = |message: String| errors(vec![AdminError::invalid_value("Body", message)]);
    let mut value: Value = serde_json::from_slice(bytes).map_err(|e| invalid(e.to_string()))?;
    if let Value::Object(object) = &mut value {
        // What reads add, and secrets (managed through their own routes).
        for read_only in ["id", "version", "apiSecrets", "clientSecrets"] {
            object.remove(read_only);
        }
    }
    serde_json::from_value(value).map_err(|e| invalid(e.to_string()))
}

fn saved(result: Result<Result<Saved, Vec<AdminError>>, StoreError>, created: bool) -> Response {
    match result {
        Ok(Ok(saved)) => json_response(
            if created {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            },
            &json!({ "id": saved.id, "version": saved.version }),
        ),
        Ok(Err(e)) => errors(e),
        Err(e) => store_failure(e),
    }
}

fn found<T: serde::Serialize>(result: Result<Option<Versioned<T>>, StoreError>) -> Response {
    match result {
        Ok(Some(versioned)) => {
            let mut body = match serde_json::to_value(&versioned.item) {
                Ok(Value::Object(object)) => object,
                _ => Map::new(),
            };
            body.insert("id".into(), json!(versioned.id));
            body.insert("version".into(), json!(versioned.version));
            let mut response = json_response(StatusCode::OK, &Value::Object(body));
            if let Ok(etag) = HeaderValue::from_str(&format!("\"{}\"", versioned.version)) {
                response.headers_mut().insert(ETAG, etag);
            }
            response
        }
        Ok(None) => not_found(),
        Err(e) => store_failure(e),
    }
}

/// `If-Match: "<version>"`.
fn expected_version(headers: &HeaderMap) -> Result<i32, Response> {
    let Some(value) = headers.get(IF_MATCH) else {
        return Err(json_response(
            StatusCode::PRECONDITION_REQUIRED,
            &json!({ "errors": [AdminError::required("If-Match")] }),
        ));
    };
    value
        .to_str()
        .ok()
        .map(|v| v.trim().trim_start_matches("W/").trim_matches('"'))
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| {
            errors(vec![AdminError::invalid_value(
                "If-Match",
                "Must be a quoted version number.",
            )])
        })
}

/// The query string's paging (`page`/`pageSize`, `skip`/`take`, or
/// `continuationToken`/`pageSize`).
fn range(params: &Map<String, Value>) -> Result<Range, AdminError> {
    let number = |name: &str| -> Result<Option<u64>, AdminError> {
        params
            .get(name)
            .and_then(Value::as_str)
            .map(|v| {
                v.parse::<u64>()
                    .map_err(|_| AdminError::invalid_value(name, "Must be a whole number."))
            })
            .transpose()
    };
    let size = |value: Option<u64>| {
        u32::try_from(value.unwrap_or(u64::from(DEFAULT_PAGE_SIZE))).unwrap_or(u32::MAX)
    };
    if let Some(token) = params.get("continuationToken").and_then(Value::as_str) {
        return Ok(Range::Token {
            token: Some(token.to_owned()),
            size: size(number("pageSize")?),
        });
    }
    if let Some(skip) = number("skip")? {
        return Ok(Range::Offset {
            skip,
            take: size(number("take")?),
        });
    }
    Ok(Range::Page {
        page: u32::try_from(number("page")?.unwrap_or(1)).unwrap_or(u32::MAX),
        size: size(number("pageSize")?),
    })
}

fn direction(params: &Map<String, Value>) -> Result<Direction, AdminError> {
    match params.get("direction").and_then(Value::as_str) {
        None | Some("asc") => Ok(Direction::Ascending),
        Some("desc") => Ok(Direction::Descending),
        Some(_) => Err(AdminError::invalid_value(
            "direction",
            "Must be asc or desc.",
        )),
    }
}

fn flag(params: &Map<String, Value>, name: &str) -> Result<Option<bool>, AdminError> {
    match params.get(name).and_then(Value::as_str) {
        None => Ok(None),
        Some("true") => Ok(Some(true)),
        Some("false") => Ok(Some(false)),
        Some(_) => Err(AdminError::invalid_value(name, "Must be true or false.")),
    }
}

fn resource_routes(admin: ResourceAdmin) -> Router<AdminState> {
    Router::new()
        .route(
            "/",
            get(move |State(s): State<AdminState>, Query(params): Query<Map<String, Value>>| async move {
                let query = || -> Result<_, AdminError> {
                    let sort = match params.get("sort").and_then(Value::as_str) {
                        None | Some("name") => ResourceSortField::Name,
                        Some("enabled") => ResourceSortField::Enabled,
                        Some(_) => {
                            return Err(AdminError::invalid_value("sort", "Must be name or enabled."));
                        }
                    };
                    let filter = ResourceFilter {
                        name: params.get("name").and_then(Value::as_str).map(str::to_owned),
                        enabled: flag(&params, "enabled")?,
                    };
                    Ok((filter, sort, direction(&params)?, range(&params)?))
                };
                let (filter, sort, direction, range) = match query() {
                    Ok(q) => q,
                    Err(e) => return errors(vec![e]),
                };
                match admin
                    .query(s.configuration.as_ref(), &filter, Some((sort, direction)), &range)
                    .await
                {
                    Ok(Ok(result)) => json_response(StatusCode::OK, &json!(result)),
                    Ok(Err(e)) => errors(vec![e]),
                    Err(e) => store_failure(e),
                }
            })
            .post(move |State(s): State<AdminState>, bytes: Bytes| async move {
                let input: ResourceConfiguration = match body(&bytes) {
                    Ok(input) => input,
                    Err(response) => return response,
                };
                let result = admin.create(s.configuration.as_ref(), input.clone()).await;
                if let Ok(Ok(saved)) = &result {
                    tracing::info!(kind = ?admin.kind(), id = %saved.id, key = %input.name, "admin created");
                }
                saved_response(result, true)
            }),
        )
        .route(
            "/by-name/{name}",
            get(move |State(s): State<AdminState>, Path(name): Path<String>| async move {
                found(admin.get_by_name(s.configuration.as_ref(), &name).await)
            }),
        )
        .route(
            "/{id}",
            get(move |State(s): State<AdminState>, Path(id): Path<String>| async move {
                let Ok(id) = id.parse::<EntityId>() else {
                    return not_found();
                };
                found(admin.get(s.configuration.as_ref(), &id).await)
            })
            .put(
                move |State(s): State<AdminState>,
                      Path(id): Path<String>,
                      headers: HeaderMap,
                      bytes: Bytes| async move {
                    let Ok(id) = id.parse::<EntityId>() else {
                        return not_found();
                    };
                    let version = match expected_version(&headers) {
                        Ok(v) => v,
                        Err(response) => return response,
                    };
                    let input: ResourceConfiguration = match body(&bytes) {
                        Ok(input) => input,
                        Err(response) => return response,
                    };
                    let result = admin
                        .update(s.configuration.as_ref(), &id, input.clone(), version)
                        .await;
                    if let Ok(Ok(saved)) = &result {
                        tracing::info!(kind = ?admin.kind(), id = %saved.id, key = %input.name, version = saved.version, "admin updated");
                    }
                    saved_response(result, false)
                },
            )
            .delete(move |State(s): State<AdminState>, Path(id): Path<String>| async move {
                let Ok(id) = id.parse::<EntityId>() else {
                    return StatusCode::NO_CONTENT.into_response();
                };
                match admin.delete(s.configuration.as_ref(), &id).await {
                    Ok(Ok(_)) => {
                        tracing::info!(kind = ?admin.kind(), %id, "admin deleted");
                        StatusCode::NO_CONTENT.into_response()
                    }
                    Ok(Err(e)) => errors(e),
                    Err(e) => store_failure(e),
                }
            }),
        )
}

fn saved_response(
    result: Result<Result<Saved, Vec<AdminError>>, StoreError>,
    created: bool,
) -> Response {
    saved(result, created)
}

/// The query string's sort (`name` or `enabled`).
fn resource_sort(params: &Map<String, Value>) -> Result<ResourceSortField, AdminError> {
    match params.get("sort").and_then(Value::as_str) {
        None | Some("name") => Ok(ResourceSortField::Name),
        Some("enabled") => Ok(ResourceSortField::Enabled),
        Some(_) => Err(AdminError::invalid_value(
            "sort",
            "Must be name or enabled.",
        )),
    }
}

fn parse_id(text: &str) -> Option<EntityId> {
    text.parse().ok()
}

fn api_resource_routes() -> Router<AdminState> {
    use rustid_core::admin::api_resources::{
        ApiResourceAdmin, ApiResourceFilter, ApiResourceInput,
    };
    use rustid_core::admin::secrets::CreateSecret;
    Router::new()
        .route(
            "/",
            get(|State(s): State<AdminState>, Query(params): Query<Map<String, Value>>| async move {
                let query = || -> Result<_, AdminError> {
                    let filter = ApiResourceFilter {
                        name: params.get("name").and_then(Value::as_str).map(str::to_owned),
                        enabled: flag(&params, "enabled")?,
                        scope: params.get("scope").and_then(Value::as_str).map(str::to_owned),
                    };
                    Ok((filter, resource_sort(&params)?, direction(&params)?, range(&params)?))
                };
                let (filter, sort, direction, range) = match query() {
                    Ok(q) => q,
                    Err(e) => return errors(vec![e]),
                };
                match ApiResourceAdmin
                    .query(s.configuration.as_ref(), &filter, Some((sort, direction)), &range)
                    .await
                {
                    Ok(Ok(result)) => json_response(StatusCode::OK, &json!(result)),
                    Ok(Err(e)) => errors(vec![e]),
                    Err(e) => store_failure(e),
                }
            })
            .post(|State(s): State<AdminState>, bytes: Bytes| async move {
                let input: ApiResourceInput = match body(&bytes) {
                    Ok(input) => input,
                    Err(response) => return response,
                };
                let result = ApiResourceAdmin.create(s.configuration.as_ref(), input.clone()).await;
                if let Ok(Ok(saved)) = &result {
                    tracing::info!(kind = "api_resource", id = %saved.id, key = %input.name, "admin created");
                }
                saved(result, true)
            }),
        )
        .route(
            "/by-name/{name}",
            get(|State(s): State<AdminState>, Path(name): Path<String>| async move {
                found(ApiResourceAdmin.get_by_name(s.configuration.as_ref(), &name).await)
            }),
        )
        .route(
            "/{id}",
            get(|State(s): State<AdminState>, Path(id): Path<String>| async move {
                let Some(id) = parse_id(&id) else {
                    return not_found();
                };
                found(ApiResourceAdmin.get(s.configuration.as_ref(), &id).await)
            })
            .put(
                |State(s): State<AdminState>, Path(id): Path<String>, headers: HeaderMap, bytes: Bytes| async move {
                    let Some(id) = parse_id(&id) else {
                        return not_found();
                    };
                    let version = match expected_version(&headers) {
                        Ok(v) => v,
                        Err(response) => return response,
                    };
                    let input: ApiResourceInput = match body(&bytes) {
                        Ok(input) => input,
                        Err(response) => return response,
                    };
                    let result = ApiResourceAdmin
                        .update(s.configuration.as_ref(), &id, input.clone(), version)
                        .await;
                    if let Ok(Ok(saved)) = &result {
                        tracing::info!(kind = "api_resource", id = %saved.id, key = %input.name, version = saved.version, "admin updated");
                    }
                    saved(result, false)
                },
            )
            .delete(|State(s): State<AdminState>, Path(id): Path<String>| async move {
                let Some(id) = parse_id(&id) else {
                    return StatusCode::NO_CONTENT.into_response();
                };
                match ApiResourceAdmin.delete(s.configuration.as_ref(), &id).await {
                    Ok(Ok(_)) => {
                        tracing::info!(kind = "api_resource", %id, "admin deleted");
                        StatusCode::NO_CONTENT.into_response()
                    }
                    Ok(Err(e)) => errors(e),
                    Err(e) => store_failure(e),
                }
            }),
        )
        .route(
            "/{id}/secrets",
            axum::routing::post(
                |State(s): State<AdminState>, Path(id): Path<String>, bytes: Bytes| async move {
                    let Some(id) = parse_id(&id) else {
                        return not_found();
                    };
                    let input: CreateSecret = match body(&bytes) {
                        Ok(input) => input,
                        Err(response) => return response,
                    };
                    let result = ApiResourceAdmin.create_secret(s.configuration.as_ref(), &id, input).await;
                    if let Ok(Ok(saved)) = &result {
                        tracing::info!(kind = "api_resource", %id, secret = %saved.id, "admin created a secret");
                    }
                    saved(result, true)
                },
            ),
        )
        .route(
            "/{id}/secrets/{secret_id}",
            axum::routing::delete(
                |State(s): State<AdminState>, Path((id, secret_id)): Path<(String, String)>| async move {
                    let (Some(id), Some(secret_id)) = (parse_id(&id), parse_id(&secret_id)) else {
                        return not_found();
                    };
                    let result = ApiResourceAdmin.delete_secret(s.configuration.as_ref(), &id, &secret_id).await;
                    if let Ok(Ok(_)) = &result {
                        tracing::info!(kind = "api_resource", %id, secret = %secret_id, "admin deleted a secret");
                    }
                    saved(result, false)
                },
            ),
        )
}

/// A client request body: `id` and `version` ignored, and `clientSecrets`
/// the secrets to create when `with_secrets` (create), else ignored.
fn client_body(
    bytes: &Bytes,
    with_secrets: bool,
) -> Result<rustid_core::admin::clients::ClientInput, Response> {
    let mut value: Value = serde_json::from_slice(bytes)
        .map_err(|e| errors(vec![AdminError::invalid_value("Body", e.to_string())]))?;
    if let Value::Object(object) = &mut value {
        object.remove("id");
        object.remove("version");
    }
    rustid_core::admin::clients::ClientInput::from_json(value, with_secrets)
        .map_err(|e| errors(vec![e]))
}

fn client_routes() -> Router<AdminState> {
    use rustid_core::admin::clients::{ClientFilter, ClientSortField};
    use rustid_core::admin::secrets::CreateSecret;
    let text = |params: &Map<String, Value>, name: &str| {
        params.get(name).and_then(Value::as_str).map(str::to_owned)
    };
    Router::new()
        .route(
            "/",
            get(move |State(s): State<AdminState>, Query(params): Query<Map<String, Value>>| async move {
                let query = || -> Result<_, AdminError> {
                    let sort = match params.get("sort").and_then(Value::as_str) {
                        None | Some("clientId") => ClientSortField::ClientId,
                        Some("clientName") => ClientSortField::ClientName,
                        Some("enabled") => ClientSortField::Enabled,
                        Some(_) => {
                            return Err(AdminError::invalid_value(
                                "sort",
                                "Must be clientId, clientName or enabled.",
                            ));
                        }
                    };
                    let filter = ClientFilter {
                        client_id: text(&params, "clientId"),
                        client_name: text(&params, "clientName"),
                        enabled: flag(&params, "enabled")?,
                        grant_type: text(&params, "grantType"),
                        allowed_scope: text(&params, "allowedScope"),
                    };
                    Ok((filter, sort, direction(&params)?, range(&params)?))
                };
                let (filter, sort, direction, range) = match query() {
                    Ok(q) => q,
                    Err(e) => return errors(vec![e]),
                };
                match s
                    .clients
                    .query(s.configuration.as_ref(), &filter, Some((sort, direction)), &range)
                    .await
                {
                    Ok(Ok(result)) => json_response(StatusCode::OK, &json!(result)),
                    Ok(Err(e)) => errors(vec![e]),
                    Err(e) => store_failure(e),
                }
            })
            .post(|State(s): State<AdminState>, bytes: Bytes| async move {
                let input = match client_body(&bytes, true) {
                    Ok(input) => input,
                    Err(response) => return response,
                };
                let client_id = input.client.client_id.clone();
                let result = s.clients.create(s.configuration.as_ref(), input).await;
                if let Ok(Ok(saved)) = &result {
                    tracing::info!(kind = "client", id = %saved.id, key = %client_id, "admin created");
                }
                saved(result, true)
            }),
        )
        .route(
            "/by-client-id/{client_id}",
            get(|State(s): State<AdminState>, Path(client_id): Path<String>| async move {
                found(s.clients.get_by_client_id(s.configuration.as_ref(), &client_id).await)
            }),
        )
        .route(
            "/{id}",
            get(|State(s): State<AdminState>, Path(id): Path<String>| async move {
                let Some(id) = parse_id(&id) else {
                    return not_found();
                };
                found(s.clients.get(s.configuration.as_ref(), &id).await)
            })
            .put(
                |State(s): State<AdminState>, Path(id): Path<String>, headers: HeaderMap, bytes: Bytes| async move {
                    let Some(id) = parse_id(&id) else {
                        return not_found();
                    };
                    let version = match expected_version(&headers) {
                        Ok(v) => v,
                        Err(response) => return response,
                    };
                    let input = match client_body(&bytes, false) {
                        Ok(input) => input,
                        Err(response) => return response,
                    };
                    let client_id = input.client.client_id.clone();
                    let result = s
                        .clients
                        .update(s.configuration.as_ref(), &id, input, version)
                        .await;
                    if let Ok(Ok(saved)) = &result {
                        tracing::info!(kind = "client", id = %saved.id, key = %client_id, version = saved.version, "admin updated");
                    }
                    saved(result, false)
                },
            )
            .delete(|State(s): State<AdminState>, Path(id): Path<String>| async move {
                let Some(id) = parse_id(&id) else {
                    return StatusCode::NO_CONTENT.into_response();
                };
                match s.clients.delete(s.configuration.as_ref(), &id).await {
                    Ok(Ok(_)) => {
                        tracing::info!(kind = "client", %id, "admin deleted");
                        StatusCode::NO_CONTENT.into_response()
                    }
                    Ok(Err(e)) => errors(e),
                    Err(e) => store_failure(e),
                }
            }),
        )
        .route(
            "/{id}/secrets",
            axum::routing::post(
                |State(s): State<AdminState>, Path(id): Path<String>, bytes: Bytes| async move {
                    let Some(id) = parse_id(&id) else {
                        return not_found();
                    };
                    let input: CreateSecret = match body(&bytes) {
                        Ok(input) => input,
                        Err(response) => return response,
                    };
                    let result = s.clients.create_secret(s.configuration.as_ref(), &id, input).await;
                    if let Ok(Ok(saved)) = &result {
                        tracing::info!(kind = "client", %id, secret = %saved.id, "admin created a secret");
                    }
                    saved(result, true)
                },
            ),
        )
        .route(
            "/{id}/secrets/{secret_id}",
            axum::routing::delete(
                |State(s): State<AdminState>, Path((id, secret_id)): Path<(String, String)>| async move {
                    let (Some(id), Some(secret_id)) = (parse_id(&id), parse_id(&secret_id)) else {
                        return not_found();
                    };
                    let result = s.clients.delete_secret(s.configuration.as_ref(), &id, &secret_id).await;
                    if let Ok(Ok(_)) = &result {
                        tracing::info!(kind = "client", %id, secret = %secret_id, "admin deleted a secret");
                    }
                    saved(result, false)
                },
            ),
        )
}

/// Schemas from `schemas_file` can't be changed (the file is the only source
/// of those schemas).
fn read_only() -> Response {
    let mut response = json_response(
        StatusCode::METHOD_NOT_ALLOWED,
        &json!({ "errors": [AdminError::validation_failed(
            "Schemas are read-only: they come from schemas_file.",
        )] }),
    );
    response.headers_mut().insert(
        axum::http::header::ALLOW,
        axum::http::HeaderValue::from_static("GET"),
    );
    response
}

fn schema_routes() -> Router<AdminState> {
    use rustid_core::admin::schemas::{SchemaAdmin, SchemaConfiguration};
    Router::new()
        .route(
            "/",
            get(|State(s): State<AdminState>| async move {
                match SchemaAdmin.query(s.configuration.as_ref()).await {
                    Ok(items) => json_response(
                        StatusCode::OK,
                        &json!({ "totalCount": items.len(), "items": items }),
                    ),
                    Err(e) => store_failure(e),
                }
            })
            .post(|State(s): State<AdminState>, bytes: Bytes| async move {
                if s.schemas_read_only {
                    return read_only();
                }
                let input: SchemaConfiguration = match body(&bytes) {
                    Ok(input) => input,
                    Err(response) => return response,
                };
                let schema_id = input.schema_id.clone();
                let result = SchemaAdmin.create(s.configuration.as_ref(), input).await;
                if let Ok(Ok(saved)) = &result {
                    tracing::info!(kind = "schema", id = %saved.id, key = %schema_id, "admin created");
                }
                saved(result, true)
            }),
        )
        .route(
            "/{schema_id}",
            get(|State(s): State<AdminState>, Path(schema_id): Path<String>| async move {
                found(SchemaAdmin.get(s.configuration.as_ref(), &schema_id).await)
            })
            .put(
                |State(s): State<AdminState>, Path(schema_id): Path<String>, headers: HeaderMap, bytes: Bytes| async move {
                    if s.schemas_read_only {
                        return read_only();
                    }
                    let version = match expected_version(&headers) {
                        Ok(v) => v,
                        Err(response) => return response,
                    };
                    let input: SchemaConfiguration = match body(&bytes) {
                        Ok(input) => input,
                        Err(response) => return response,
                    };
                    let result = SchemaAdmin
                        .update(s.configuration.as_ref(), &schema_id, input, version)
                        .await;
                    if let Ok(Ok(saved)) = &result {
                        tracing::info!(kind = "schema", id = %saved.id, key = %schema_id, version = saved.version, "admin updated");
                    }
                    saved(result, false)
                },
            )
            .delete(|State(s): State<AdminState>, Path(schema_id): Path<String>| async move {
                if s.schemas_read_only {
                    return read_only();
                }
                match SchemaAdmin.delete(s.configuration.as_ref(), &schema_id).await {
                    Ok(Ok(_)) => {
                        tracing::info!(kind = "schema", key = %schema_id, "admin deleted");
                        StatusCode::NO_CONTENT.into_response()
                    }
                    Ok(Err(e)) => errors(e),
                    Err(e) => store_failure(e),
                }
            }),
        )
}

/// A SAML service provider request body.
#[cfg(feature = "saml")]
fn saml_body(bytes: &Bytes) -> Result<rustid_saml::admin::SamlServiceProviderInput, Response> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|e| errors(vec![AdminError::invalid_value("Body", e.to_string())]))?;
    rustid_saml::admin::SamlServiceProviderInput::from_json(value).map_err(|e| errors(vec![e]))
}

#[cfg(feature = "saml")]
fn saml_routes() -> Router<AdminState> {
    use rustid_saml::admin::{
        SamlServiceProviderAdmin, SamlServiceProviderFilter, SamlServiceProviderSortField,
    };
    let admin = SamlServiceProviderAdmin;
    let text = |params: &Map<String, Value>, name: &str| {
        params.get(name).and_then(Value::as_str).map(str::to_owned)
    };
    Router::new()
        .route(
            "/",
            get(move |State(s): State<AdminState>, Query(params): Query<Map<String, Value>>| async move {
                let query = || -> Result<_, AdminError> {
                    let sort = match params.get("sort").and_then(Value::as_str) {
                        None | Some("entityId") => SamlServiceProviderSortField::EntityId,
                        Some("displayName") => SamlServiceProviderSortField::DisplayName,
                        Some("enabled") => SamlServiceProviderSortField::Enabled,
                        Some(_) => {
                            return Err(AdminError::invalid_value(
                                "sort",
                                "Must be entityId, displayName or enabled.",
                            ));
                        }
                    };
                    let filter = SamlServiceProviderFilter {
                        entity_id: text(&params, "entityId"),
                        display_name: text(&params, "displayName"),
                        enabled: flag(&params, "enabled")?,
                    };
                    Ok((filter, sort, direction(&params)?, range(&params)?))
                };
                let (filter, sort, direction, range) = match query() {
                    Ok(q) => q,
                    Err(e) => return errors(vec![e]),
                };
                match admin
                    .query(s.configuration.as_ref(), &filter, Some((sort, direction)), &range)
                    .await
                {
                    Ok(Ok(result)) => json_response(StatusCode::OK, &json!(result)),
                    Ok(Err(e)) => errors(vec![e]),
                    Err(e) => store_failure(e),
                }
            })
            .post(move |State(s): State<AdminState>, bytes: Bytes| async move {
                let input = match saml_body(&bytes) {
                    Ok(input) => input,
                    Err(response) => return response,
                };
                let entity_id = input.entity_id.clone();
                let result = admin.create(s.configuration.as_ref(), input).await;
                if let Ok(Ok(saved)) = &result {
                    tracing::info!(kind = "saml_service_provider", id = %saved.id, key = %entity_id, "admin created");
                }
                saved(result, true)
            }),
        )
        .route(
            "/by-entity-id/{entity_id}",
            get(move |State(s): State<AdminState>, Path(entity_id): Path<String>| async move {
                found(admin.get_by_entity_id(s.configuration.as_ref(), &entity_id).await)
            }),
        )
        .route(
            "/{id}",
            get(move |State(s): State<AdminState>, Path(id): Path<String>| async move {
                let Some(id) = parse_id(&id) else {
                    return not_found();
                };
                found(admin.get(s.configuration.as_ref(), &id).await)
            })
            .put(
                move |State(s): State<AdminState>, Path(id): Path<String>, headers: HeaderMap, bytes: Bytes| async move {
                    let Some(id) = parse_id(&id) else {
                        return not_found();
                    };
                    let version = match expected_version(&headers) {
                        Ok(v) => v,
                        Err(response) => return response,
                    };
                    let input = match saml_body(&bytes) {
                        Ok(input) => input,
                        Err(response) => return response,
                    };
                    let entity_id = input.entity_id.clone();
                    let result = admin.update(s.configuration.as_ref(), &id, input, version).await;
                    if let Ok(Ok(saved)) = &result {
                        tracing::info!(kind = "saml_service_provider", id = %saved.id, key = %entity_id, version = saved.version, "admin updated");
                    }
                    saved(result, false)
                },
            )
            .delete(move |State(s): State<AdminState>, Path(id): Path<String>| async move {
                let Some(id) = parse_id(&id) else {
                    return StatusCode::NO_CONTENT.into_response();
                };
                match admin.delete(s.configuration.as_ref(), &id).await {
                    Ok(Ok(_)) => {
                        tracing::info!(kind = "saml_service_provider", %id, "admin deleted");
                        StatusCode::NO_CONTENT.into_response()
                    }
                    Ok(Err(e)) => errors(e),
                    Err(e) => store_failure(e),
                }
            }),
        )
}

fn identity_provider_body(
    bytes: &Bytes,
) -> Result<rustid_core::admin::identity_providers::IdentityProviderInput, Response> {
    let value: Value = body(bytes)?;
    rustid_core::admin::identity_providers::IdentityProviderInput::from_json(value)
        .map_err(|e| errors(vec![e]))
}

fn identity_provider_routes() -> Router<AdminState> {
    use rustid_core::admin::identity_providers::{
        IdentityProviderFilter, IdentityProviderSortField,
    };
    let text = |params: &Map<String, Value>, name: &str| {
        params.get(name).and_then(Value::as_str).map(str::to_owned)
    };
    Router::new()
        .route(
            "/",
            get(move |State(s): State<AdminState>, Query(params): Query<Map<String, Value>>| async move {
                let query = || -> Result<_, AdminError> {
                    let sort = match params.get("sort").and_then(Value::as_str) {
                        None | Some("scheme") => IdentityProviderSortField::Scheme,
                        Some("displayName") => IdentityProviderSortField::DisplayName,
                        Some("enabled") => IdentityProviderSortField::Enabled,
                        Some(_) => {
                            return Err(AdminError::invalid_value(
                                "sort",
                                "Must be scheme, displayName or enabled.",
                            ));
                        }
                    };
                    let filter = IdentityProviderFilter {
                        scheme: text(&params, "scheme"),
                        display_name: text(&params, "displayName"),
                        enabled: flag(&params, "enabled")?,
                    };
                    Ok((filter, sort, direction(&params)?, range(&params)?))
                };
                let (filter, sort, direction, range) = match query() {
                    Ok(q) => q,
                    Err(e) => return errors(vec![e]),
                };
                match s
                    .identity_providers
                    .query(s.configuration.as_ref(), &filter, Some((sort, direction)), &range)
                    .await
                {
                    Ok(Ok(result)) => json_response(StatusCode::OK, &json!(result)),
                    Ok(Err(e)) => errors(vec![e]),
                    Err(e) => store_failure(e),
                }
            })
            .post(move |State(s): State<AdminState>, bytes: Bytes| async move {
                let input = match identity_provider_body(&bytes) {
                    Ok(input) => input,
                    Err(response) => return response,
                };
                let scheme = input.0.scheme.clone();
                let result = s.identity_providers.create(s.configuration.as_ref(), input).await;
                if let Ok(Ok(saved)) = &result {
                    tracing::info!(kind = "identity_provider", id = %saved.id, key = %scheme, "admin created");
                }
                saved(result, true)
            }),
        )
        .route(
            "/by-scheme/{scheme}",
            get(move |State(s): State<AdminState>, Path(scheme): Path<String>| async move {
                found(s.identity_providers.get_by_scheme(s.configuration.as_ref(), &scheme).await)
            }),
        )
        .route(
            "/{id}",
            get(move |State(s): State<AdminState>, Path(id): Path<String>| async move {
                let Some(id) = parse_id(&id) else {
                    return not_found();
                };
                found(s.identity_providers.get(s.configuration.as_ref(), &id).await)
            })
            .put(
                move |State(s): State<AdminState>, Path(id): Path<String>, headers: HeaderMap, bytes: Bytes| async move {
                    let Some(id) = parse_id(&id) else {
                        return not_found();
                    };
                    let version = match expected_version(&headers) {
                        Ok(v) => v,
                        Err(response) => return response,
                    };
                    let input = match identity_provider_body(&bytes) {
                        Ok(input) => input,
                        Err(response) => return response,
                    };
                    let scheme = input.0.scheme.clone();
                    let result = s
                        .identity_providers
                        .update(s.configuration.as_ref(), &id, input, version)
                        .await;
                    if let Ok(Ok(saved)) = &result {
                        tracing::info!(kind = "identity_provider", id = %saved.id, key = %scheme, version = saved.version, "admin updated");
                    }
                    saved(result, false)
                },
            )
            .delete(move |State(s): State<AdminState>, Path(id): Path<String>| async move {
                let Some(id) = parse_id(&id) else {
                    return StatusCode::NO_CONTENT.into_response();
                };
                match s.identity_providers.delete(s.configuration.as_ref(), &id).await {
                    Ok(Ok(_)) => {
                        tracing::info!(kind = "identity_provider", %id, "admin deleted");
                        StatusCode::NO_CONTENT.into_response()
                    }
                    Ok(Err(e)) => errors(e),
                    Err(e) => store_failure(e),
                }
            }),
        )
}
