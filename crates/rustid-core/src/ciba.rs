//! Client-Initiated Backchannel Authentication (OpenID CIBA Core, poll
//! mode): the backchannel authentication endpoint's request validation
//! and response, the stored request, and the seam the user validator,
//! notification service and custom validator plug into.

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::client_auth::authenticate_client;
use crate::clients::Client;
use crate::events::{Event, EventDetails};
use crate::form::Form;
use crate::grants::{PersistedGrant, hashed_key, new_handle};
use crate::params::utf16_len;
use crate::profile::ProfileError;
use crate::scopes::{ResourceValidationError, validate_requested_resources};
use crate::session::{LOCAL_IDP, UserSession};
use crate::stores::{PersistedGrantStore, StoreError};
use crate::token::{TokenContext, TokenError, TokenFailure};
use crate::tokens::Claim;

/// The CIBA grant type.
pub const GRANT_TYPE: &str = "urn:openid:params:grant-type:ciba";
/// The persisted grant type of backchannel authentication requests.
pub const CIBA_GRANT: &str = "ciba";

const INVALID_REQUEST: &str = "invalid_request";
const INVALID_REQUEST_OBJECT: &str = "invalid_request_object";
const UNAUTHORIZED_CLIENT: &str = "unauthorized_client";
const INVALID_TARGET: &str = "invalid_target";
const INVALID_SCOPE: &str = "invalid_scope";
const UNKNOWN_USER_ID: &str = "unknown_user_id";
const ACCESS_DENIED: &str = "access_denied";
const EXPIRED_LOGIN_HINT_TOKEN: &str = "expired_login_hint_token";
const MISSING_USER_CODE: &str = "missing_user_code";
const INVALID_USER_CODE: &str = "invalid_user_code";
const INVALID_BINDING_MESSAGE: &str = "invalid_binding_message";

/// A pending (or decided) request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CibaRequest {
    /// The stored key (the hash of the `auth_req_id`).
    pub internal_id: String,
    pub creation_time: DateTime<Utc>,
    /// Seconds from `creation_time`.
    pub lifetime: i32,
    pub client_id: String,
    pub requested_scopes: Vec<String>,
    pub requested_resource_indicators: Vec<String>,
    /// The user the login hint named.
    pub subject: UserSession,
    pub acr_values: Vec<String>,
    pub tenant: Option<String>,
    pub idp: Option<String>,
    pub binding_message: Option<String>,
    /// From the custom validator; the notification sees them, the client
    /// doesn't.
    pub properties: Map<String, Value>,
    pub is_complete: bool,
    /// Consented scopes, once decided (none when denied).
    pub authorized_scopes: Option<Vec<String>>,
    pub session_id: Option<String>,
    pub description: Option<String>,
}

impl CibaRequest {
    pub fn has_expired(&self, now: DateTime<Utc>) -> bool {
        self.creation_time + Duration::seconds(i64::from(self.lifetime)) < now
    }
}

/// What the user validator gets.
#[derive(Debug, Clone, Copy)]
pub struct CibaUserRequest<'a> {
    pub client: &'a Client,
    pub login_hint: Option<&'a str>,
    pub login_hint_token: Option<&'a str>,
    pub id_token_hint: Option<&'a str>,
    /// The validated `id_token_hint`'s claims.
    pub id_token_hint_claims: Option<&'a Map<String, Value>>,
    pub user_code: Option<&'a str>,
    pub binding_message: Option<&'a str>,
}

/// The user validator's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CibaUserResult {
    /// The user; without a subject id the request fails.
    Subject {
        subject_id: Option<String>,
        claims: Vec<Claim>,
    },
    Error {
        error: String,
        description: Option<String>,
    },
}

/// What the notification service gets.
#[derive(Debug, Clone, Copy)]
pub struct CibaNotification<'a> {
    pub internal_id: &'a str,
    pub subject_id: &'a str,
    pub client: &'a Client,
    pub scopes: &'a [String],
    pub resource_indicators: &'a [String],
    pub binding_message: Option<&'a str>,
    pub acr_values: &'a [String],
    pub tenant: Option<&'a str>,
    pub idp: Option<&'a str>,
    pub properties: &'a Map<String, Value>,
}

/// What the custom validator sees: the request's parameters (a request
/// object's included) and what validation made of them.
#[derive(Debug, Clone, Copy)]
pub struct CibaCustomRequest<'a> {
    pub client: &'a Client,
    pub parameters: &'a [(String, String)],
    pub subject_id: &'a str,
    pub scopes: &'a [String],
    pub binding_message: Option<&'a str>,
}

/// The custom validator's answer: an error refuses the request; properties
/// travel with it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CibaCustomAnswer {
    pub error: Option<String>,
    pub properties: Map<String, Value>,
}

/// The backchannel authentication user validator,
/// the backchannel authentication user notification service and
/// the custom backchannel authentication validator.
#[async_trait]
pub trait CibaService: Send + Sync {
    async fn validate_user(
        &self,
        request: &CibaUserRequest<'_>,
    ) -> Result<CibaUserResult, ProfileError>;

    async fn notify_user(&self, notification: &CibaNotification<'_>) -> Result<(), ProfileError>;

    async fn validate_request(
        &self,
        request: &CibaCustomRequest<'_>,
    ) -> Result<CibaCustomAnswer, ProfileError>;
}

/// The no-op services: no user is known, and the notification is a log
/// line pointing at the UI's CIBA page.
#[derive(Debug, Clone, Copy, Default)]
pub struct NopCibaService;

#[async_trait]
impl CibaService for NopCibaService {
    async fn validate_user(&self, _: &CibaUserRequest<'_>) -> Result<CibaUserResult, ProfileError> {
        Ok(CibaUserResult::Error {
            error: "not implemented".into(),
            description: None,
        })
    }

    async fn notify_user(&self, notification: &CibaNotification<'_>) -> Result<(), ProfileError> {
        tracing::warn!(
            internal_id = notification.internal_id,
            "no CIBA notification is configured; visit the UI's /ciba?id=<internal id> to complete the request"
        );
        Ok(())
    }

    async fn validate_request(
        &self,
        _: &CibaCustomRequest<'_>,
    ) -> Result<CibaCustomAnswer, ProfileError> {
        Ok(CibaCustomAnswer::default())
    }
}

/// The endpoint's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CibaResponse {
    pub auth_req_id: String,
    pub expires_in: i32,
    pub interval: i32,
}

/// The stored request by its `auth_req_id`.
pub async fn get_by_request_id(
    grants: &dyn PersistedGrantStore,
    auth_req_id: &str,
) -> Result<Option<CibaRequest>, StoreError> {
    get_by_internal_id(grants, &hashed_key(auth_req_id, CIBA_GRANT)).await
}

pub async fn get_by_internal_id(
    grants: &dyn PersistedGrantStore,
    internal_id: &str,
) -> Result<Option<CibaRequest>, StoreError> {
    Ok(grants
        .get(internal_id)
        .await?
        .filter(|g| g.grant_type == CIBA_GRANT)
        .and_then(|g| serde_json::from_str(&g.data).ok()))
}

pub async fn store(
    grants: &dyn PersistedGrantStore,
    request: &CibaRequest,
) -> Result<(), StoreError> {
    grants
        .store(PersistedGrant {
            key: request.internal_id.clone(),
            grant_type: CIBA_GRANT.to_owned(),
            client_id: request.client_id.clone(),
            subject_id: Some(request.subject.subject_id.clone()),
            session_id: request.session_id.clone(),
            description: request.description.clone(),
            creation_time: request.creation_time,
            expiration: Some(
                request.creation_time + Duration::seconds(i64::from(request.lifetime)),
            ),
            consumed_time: None,
            data: serde_json::to_string(request).expect("a CIBA request serialises"),
        })
        .await
}

/// A subject's requests.
pub async fn requests_for_subject(
    grants: &dyn PersistedGrantStore,
    subject_id: &str,
) -> Result<Vec<CibaRequest>, StoreError> {
    let filter = crate::grants::GrantFilter {
        subject_id: Some(subject_id.to_owned()),
        grant_type: Some(CIBA_GRANT.to_owned()),
        ..Default::default()
    };
    Ok(grants
        .get_all(&filter)
        .await?
        .into_iter()
        .filter_map(|g| serde_json::from_str(&g.data).ok())
        .collect())
}

/// A validated request, and what its failure event reports.
#[derive(Default)]
struct Draft {
    parameters: Vec<(String, String)>,
    scopes: Vec<String>,
    subject_id: Option<String>,
}

fn fail(error: &'static str, description: Option<&str>) -> TokenError {
    TokenError {
        description: description.map(str::to_owned),
        ..TokenError::new(error)
    }
}

/// The backchannel authentication endpoint after the HTTP checks.
pub async fn authorize(
    ctx: &TokenContext<'_>,
    authorization: Option<&str>,
    form: &Form,
) -> Result<CibaResponse, TokenFailure> {
    let client = match authenticate_client(ctx, authorization, form).await? {
        Ok(client) => client,
        Err(error) => return Err(TokenError::new(error).into()),
    };
    let mut draft = Draft {
        parameters: form
            .pairs()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect(),
        ..Default::default()
    };
    match validate(ctx, &client, &mut draft).await {
        Ok(Ok(response)) => {
            ctx.events.raise(
                ctx.request,
                ctx.now,
                Event::backchannel_authentication_success(
                    EventDetails::BackchannelAuthentication {
                        client_id: Some(client.client_id.clone()),
                        client_name: client.client_name.clone(),
                        endpoint: "BackchannelAuthentication",
                        subject_id: draft.subject_id.clone(),
                        scopes: Some(draft.scopes.join(" ")),
                        error: None,
                        error_description: None,
                    },
                ),
            );
            Ok(response)
        }
        Ok(Err(error)) => {
            ctx.events.raise(
                ctx.request,
                ctx.now,
                Event::backchannel_authentication_failure(
                    EventDetails::BackchannelAuthentication {
                        client_id: Some(client.client_id.clone()),
                        client_name: client.client_name.clone(),
                        endpoint: "BackchannelAuthentication",
                        subject_id: draft.subject_id.clone(),
                        scopes: (!draft.scopes.is_empty()).then(|| draft.scopes.join(" ")),
                        error: Some(error.error.to_string()),
                        error_description: error.description.clone(),
                    },
                ),
            );
            Err(error.into())
        }
        Err(failure) => Err(failure),
    }
}

/// Blank values dropped, the rest joined with commas.
fn param(draft: &Draft, name: &str) -> Option<String> {
    let values: Vec<&str> = draft
        .parameters
        .iter()
        .filter(|(k, v)| k == name && !v.trim().is_empty())
        .map(|(_, v)| v.as_str())
        .collect();
    (!values.is_empty()).then(|| values.join(","))
}

/// Validate request, then the response generator.
async fn validate(
    ctx: &TokenContext<'_>,
    client: &Client,
    draft: &mut Draft,
) -> Result<Result<CibaResponse, TokenError>, TokenFailure> {
    let limits = &ctx.options.input_length_restrictions;
    if !client.allows_grant(GRANT_TYPE) {
        return Ok(Err(fail(UNAUTHORIZED_CLIENT, Some("Unauthorized client"))));
    }

    // A signed request object's parameters join the request's.
    let mut from_request_object = false;
    if let Some(object) = param(draft, "request") {
        if utf16_len(&object) >= limits.jwt {
            return Ok(Err(fail(
                INVALID_REQUEST_OBJECT,
                Some("Invalid request value"),
            )));
        }
        let invalid = |d| Ok(Err(fail(INVALID_REQUEST_OBJECT, Some(d))));
        let Some(claims) = crate::authorize::request_object::validate_with(
            ctx.options,
            ctx.issuer,
            client,
            &object,
            ctx.now.timestamp(),
            false,
            true,
        ) else {
            return invalid("Invalid JWT request");
        };
        if claims
            .iter()
            .any(|(k, v)| k == "client_id" && !v.is_empty() && *v != client.client_id)
        {
            return invalid("Invalid client_id in JWT request");
        }
        if !claims.iter().any(|(k, v)| k == "jti" && !v.is_empty()) {
            return invalid("Missing jti in JWT request object");
        }
        for (name, value) in &claims {
            if name == "client_id" {
                continue;
            }
            if draft.parameters.iter().any(|(k, _)| k == name) {
                return invalid("Parameter from JWT request object also found in request body");
            }
            if name != "jti" {
                draft.parameters.push((name.clone(), value.clone()));
            }
        }
        from_request_object = true;
    }
    if client.require_request_object && !from_request_object {
        return Ok(Err(fail(INVALID_REQUEST, None)));
    }

    // Scopes.
    let Some(scope) = param(draft, "scope") else {
        return Ok(Err(fail(INVALID_REQUEST, Some("Missing scope"))));
    };
    if utf16_len(&scope) > limits.scope {
        return Ok(Err(fail(INVALID_REQUEST, Some("Invalid scope"))));
    }
    let mut scopes: Vec<String> = Vec::new();
    for s in scope.split(' ').filter(|s| !s.is_empty()) {
        if !scopes.iter().any(|x| x == s) {
            scopes.push(s.to_owned());
        }
    }
    draft.scopes.clone_from(&scopes);
    if !scopes.iter().any(|s| s == "openid") {
        return Ok(Err(fail(INVALID_REQUEST, Some("Missing the openid scope"))));
    }

    // Resource indicators, several allowed.
    let indicators: Vec<String> = draft
        .parameters
        .iter()
        .filter(|(k, v)| k == "resource" && !v.is_empty())
        .map(|(_, v)| v.clone())
        .collect();
    if indicators
        .iter()
        .any(|r| utf16_len(r) > limits.resource_indicator_max_length)
    {
        return Ok(Err(fail(
            INVALID_TARGET,
            Some("Resource indicator maximum length exceeded"),
        )));
    }
    if indicators
        .iter()
        .any(|r| !crate::authorize::validation::is_uri(r) || r.contains('#'))
    {
        return Ok(Err(fail(
            INVALID_TARGET,
            Some("Invalid resource indicator format"),
        )));
    }
    let enabled = ctx.stores.resources.get_all_enabled_resources().await?;
    let resources = match validate_requested_resources(client, &enabled, &scopes, &indicators) {
        Ok(resources) => resources,
        Err(ResourceValidationError::InvalidResourceIndicator(_)) => {
            return Ok(Err(fail(
                INVALID_TARGET,
                Some("Invalid resource indicator"),
            )));
        }
        Err(ResourceValidationError::InvalidScope(_)) => {
            return Ok(Err(fail(INVALID_SCOPE, Some("Invalid scope"))));
        }
    };

    // Lifetime.
    let lifetime = client
        .ciba_lifetime
        .unwrap_or(ctx.options.ciba.default_lifetime);
    let expiry = match param(draft, "requested_expiry") {
        Some(requested) => {
            // Surrounding white space is allowed.
            let valid = (requested.len() <= 9)
                .then(|| requested.trim().parse::<i32>().ok())
                .flatten()
                .filter(|e| *e > 0 && *e <= lifetime);
            match valid {
                Some(e) => e,
                None => return Ok(Err(fail(INVALID_REQUEST, Some("Invalid requested_expiry")))),
            }
        }
        None => lifetime,
    };

    // Acr_values, with tenant and idp extracted.
    let mut acr_values: Vec<String> = Vec::new();
    let mut tenant = None;
    let mut idp = None;
    if let Some(acr) = param(draft, "acr_values") {
        if utf16_len(&acr) > limits.acr_values {
            return Ok(Err(fail(INVALID_REQUEST, Some("Invalid acr_values"))));
        }
        for value in acr.split(' ').filter(|s| !s.is_empty()) {
            if !acr_values.iter().any(|x| x == value) {
                acr_values.push(value.to_owned());
            }
        }
        if let Some(i) = acr_values.iter().position(|v| v.starts_with("tenant:")) {
            tenant = Some(acr_values.remove(i)["tenant:".len()..].to_owned());
        }
        if let Some(i) = acr_values.iter().position(|v| v.starts_with("idp:")) {
            let requested = acr_values.remove(i)["idp:".len()..].to_owned();
            let restricted = !client.identity_provider_restrictions.is_empty()
                && !client.identity_provider_restrictions.contains(&requested);
            if restricted {
                tracing::warn!(idp = %requested, "idp requested is not in the client restriction list");
            } else {
                idp = Some(requested);
            }
        }
    }

    // Exactly one login hint.
    let login_hint = param(draft, "login_hint");
    let login_hint_token = param(draft, "login_hint_token");
    let id_token_hint = param(draft, "id_token_hint");
    let hints = [&login_hint, &login_hint_token, &id_token_hint]
        .iter()
        .filter(|h| h.is_some())
        .count();
    if hints == 0 {
        return Ok(Err(fail(
            INVALID_REQUEST,
            Some("Missing login_hint_token, id_token_hint, or login_hint"),
        )));
    }
    if hints > 1 {
        return Ok(Err(fail(
            INVALID_REQUEST,
            Some("Too many of login_hint_token, id_token_hint, or login_hint"),
        )));
    }
    if login_hint
        .as_ref()
        .is_some_and(|h| utf16_len(h) > limits.login_hint)
    {
        return Ok(Err(fail(INVALID_REQUEST, Some("Invalid login_hint"))));
    }
    if login_hint_token
        .as_ref()
        .is_some_and(|h| utf16_len(h) > limits.login_hint_token)
    {
        return Ok(Err(fail(INVALID_REQUEST, Some("Invalid login_hint_token"))));
    }
    let mut id_token_claims = None;
    if let Some(hint) = &id_token_hint {
        if utf16_len(hint) > limits.id_token_hint {
            return Ok(Err(fail(INVALID_REQUEST, Some("Invalid id_token_hint"))));
        }
        match crate::end_session::validate_identity_token_hint(&ctx.validation(), hint).await? {
            Some((claims, hint_client)) if hint_client.client_id == client.client_id => {
                id_token_claims = Some(claims);
            }
            _ => return Ok(Err(fail(INVALID_REQUEST, Some("Invalid id_token_hint")))),
        }
    }
    let user_code = param(draft, "user_code");
    if user_code
        .as_ref()
        .is_some_and(|c| utf16_len(c) > limits.user_code)
    {
        return Ok(Err(fail(INVALID_REQUEST, Some("Invalid user_code"))));
    }
    let binding_message = param(draft, "binding_message");
    if binding_message
        .as_ref()
        .is_some_and(|m| utf16_len(m) > limits.binding_message)
    {
        return Ok(Err(fail(
            INVALID_BINDING_MESSAGE,
            Some("Invalid binding_message"),
        )));
    }

    // The user.
    let answer = ctx
        .stores
        .ciba
        .validate_user(&CibaUserRequest {
            client,
            login_hint: login_hint.as_deref(),
            login_hint_token: login_hint_token.as_deref(),
            id_token_hint: id_token_hint.as_deref(),
            id_token_hint_claims: id_token_claims.as_ref(),
            user_code: user_code.as_deref(),
            binding_message: binding_message.as_deref(),
        })
        .await
        .map_err(|e| TokenFailure::Server(e.to_string()))?;
    let (subject_id, claims) = match answer {
        CibaUserResult::Error { error, description } => {
            let error = match error.as_str() {
                ACCESS_DENIED => ACCESS_DENIED,
                EXPIRED_LOGIN_HINT_TOKEN => {
                    return Ok(Err(fail(
                        EXPIRED_LOGIN_HINT_TOKEN,
                        Some(description.as_deref().unwrap_or("Expired login_hint_token")),
                    )));
                }
                UNKNOWN_USER_ID => UNKNOWN_USER_ID,
                MISSING_USER_CODE => MISSING_USER_CODE,
                INVALID_USER_CODE => INVALID_USER_CODE,
                INVALID_BINDING_MESSAGE => INVALID_BINDING_MESSAGE,
                other => {
                    tracing::error!(
                        error = other,
                        "unexpected error from the CIBA user validator"
                    );
                    return Ok(Err(fail(UNKNOWN_USER_ID, None)));
                }
            };
            return Ok(Err(fail(error, description.as_deref())));
        }
        CibaUserResult::Subject { subject_id, claims } => {
            match subject_id.filter(|s| !s.trim().is_empty()) {
                Some(sub) => (sub, claims),
                None => return Ok(Err(fail(UNKNOWN_USER_ID, None))),
            }
        }
    };
    draft.subject_id = Some(subject_id.clone());

    // The custom validator.
    let custom = ctx
        .stores
        .ciba
        .validate_request(&CibaCustomRequest {
            client,
            parameters: &draft.parameters,
            subject_id: &subject_id,
            scopes: &resources.scopes,
            binding_message: binding_message.as_deref(),
        })
        .await
        .map_err(|e| TokenFailure::Server(e.to_string()))?;
    if custom.error.is_some() {
        return Ok(Err(fail(INVALID_REQUEST, None)));
    }

    // The response generator: store, then notify.
    let handle = new_handle();
    let request = CibaRequest {
        internal_id: hashed_key(&handle, CIBA_GRANT),
        creation_time: ctx.now,
        lifetime: expiry,
        client_id: client.client_id.clone(),
        requested_scopes: resources.scopes.clone(),
        requested_resource_indicators: indicators.clone(),
        subject: subject(subject_id, claims, ctx.now),
        acr_values,
        tenant,
        idp,
        binding_message,
        properties: custom.properties,
        is_complete: false,
        authorized_scopes: None,
        session_id: None,
        description: None,
    };
    store(ctx.stores.grants.as_ref(), &request).await?;
    ctx.stores
        .ciba
        .notify_user(&CibaNotification {
            internal_id: &request.internal_id,
            subject_id: &request.subject.subject_id,
            client,
            scopes: &request.requested_scopes,
            resource_indicators: &request.requested_resource_indicators,
            binding_message: request.binding_message.as_deref(),
            acr_values: &request.acr_values,
            tenant: request.tenant.as_deref(),
            idp: request.idp.as_deref(),
            properties: &request.properties,
        })
        .await
        .map_err(|e| TokenFailure::Server(e.to_string()))?;
    let interval = client
        .polling_interval
        .unwrap_or(ctx.options.ciba.default_polling_interval);
    Ok(Ok(CibaResponse {
        auth_req_id: handle,
        expires_in: request.lifetime,
        interval,
    }))
}

/// The user the validator named, as the stored subject: its claims, with
/// `auth_time` and `idp` added at completion.
fn subject(subject_id: String, claims: Vec<Claim>, now: DateTime<Utc>) -> UserSession {
    UserSession {
        subject_id,
        session_id: String::new(),
        auth_time: 0,
        idp: LOCAL_IDP.to_owned(),
        amr: Vec::new(),
        claims,
        client_ids: Vec::new(),
        saml_sessions: Vec::new(),
        issued: now,
        expires: now,
        persistent: false,
        allow_refresh: None,
        force_renewal: false,
        issuer: None,
        key: None,
        upstream_id_token: None,
        upstream_sid: None,
    }
}

/// What a UI shows the user.
#[derive(Debug, Clone)]
pub struct CibaLoginRequest {
    pub internal_id: String,
    pub subject_id: String,
    pub client: std::sync::Arc<Client>,
    /// The requested scopes still valid for the client.
    pub scopes: Vec<String>,
    pub resource_indicators: Vec<String>,
    pub binding_message: Option<String>,
    pub acr_values: Vec<String>,
    pub properties: Map<String, Value>,
}

async fn login_request_of(
    stores: &crate::stores::Stores,
    request: CibaRequest,
) -> Result<Option<CibaLoginRequest>, StoreError> {
    let Some(client) =
        crate::stores::find_enabled_client(stores.clients.as_ref(), &request.client_id).await?
    else {
        return Ok(None);
    };
    let enabled = stores.resources.get_all_enabled_resources().await?;
    let scopes = validate_requested_resources(
        &client,
        &enabled,
        &request.requested_scopes,
        &request.requested_resource_indicators,
    )
    .map(|r| r.scopes)
    .unwrap_or_default();
    Ok(Some(CibaLoginRequest {
        internal_id: request.internal_id,
        subject_id: request.subject.subject_id,
        client,
        scopes,
        resource_indicators: request.requested_resource_indicators,
        binding_message: request.binding_message,
        acr_values: request.acr_values,
        properties: request.properties,
    }))
}

pub async fn login_request(
    stores: &crate::stores::Stores,
    internal_id: &str,
) -> Result<Option<CibaLoginRequest>, StoreError> {
    match get_by_internal_id(stores.grants.as_ref(), internal_id).await? {
        Some(request) => login_request_of(stores, request).await,
        None => Ok(None),
    }
}

/// The user's undecided
/// requests.
pub async fn pending_for_subject(
    stores: &crate::stores::Stores,
    subject_id: &str,
) -> Result<Vec<CibaLoginRequest>, StoreError> {
    let mut pending = Vec::new();
    for request in requests_for_subject(stores.grants.as_ref(), subject_id).await? {
        if !request.is_complete
            && let Some(login) = login_request_of(stores, request).await?
        {
            pending.push(login);
        }
    }
    Ok(pending)
}

/// The signed-in user decides their request,
/// consenting to `scopes` (none, or `None`, denies). The error is the
/// exception message.
pub async fn complete(
    stores: &crate::stores::Stores,
    internal_id: &str,
    session: Option<&UserSession>,
    scopes: Option<&[String]>,
    description: Option<&str>,
    now: DateTime<Utc>,
) -> Result<Result<(), String>, StoreError> {
    let Some(mut request) = get_by_internal_id(stores.grants.as_ref(), internal_id).await? else {
        return Ok(Err("Invalid backchannel authentication request id.".into()));
    };
    let Some(session) = session else {
        return Ok(Err("Invalid subject.".into()));
    };
    if session.subject_id != request.subject.subject_id {
        return Ok(Err(format!(
            "User's subject id: '{}' does not match subject id for backchannel authentication request: '{}'.",
            session.subject_id, request.subject.subject_id
        )));
    }
    if let Some(scopes) = scopes
        && scopes.iter().any(|s| !request.requested_scopes.contains(s))
    {
        return Ok(Err(
            "More scopes consented than originally requested.".into()
        ));
    }
    let mut subject = session.clone();
    if subject.auth_time == 0 {
        subject.auth_time = now.timestamp();
    }
    if subject.idp.trim().is_empty() {
        LOCAL_IDP.clone_into(&mut subject.idp);
    }
    request.is_complete = true;
    request.session_id = Some(session.session_id.clone()).filter(|s| !s.is_empty());
    request.subject = subject;
    request.authorized_scopes = scopes.map(<[String]>::to_vec);
    request.description = description.map(str::to_owned);
    store(stores.grants.as_ref(), &request).await?;
    Ok(Ok(()))
}
