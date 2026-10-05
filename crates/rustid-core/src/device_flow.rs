//! The device authorization grant (RFC 8628): the device authorization
//! endpoint (the device authorization request validator,
//! the device authorization response generator), numeric user codes and the
//! stored `DeviceCode`.

use aws_lc_rs::digest;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::client_auth::authenticate_client;
use crate::clients::Client;
use crate::events::{Event, EventDetails};
use crate::form::Form;
use crate::scopes::{OFFLINE_ACCESS, ResourceValidationError, validate_requested_resources};
use crate::session::UserSession;
use crate::stores::StoreError;
use crate::token::{
    INVALID_REQUEST, INVALID_SCOPE, TokenContext, TokenError, TokenFailure, UNAUTHORIZED_CLIENT,
};

/// The device code grant type.
pub const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// `DeviceCode`: a device authorization, as stored.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceCode {
    pub creation_time: DateTime<Utc>,
    /// Seconds from `creation_time`.
    pub lifetime: i32,
    pub client_id: String,
    pub description: Option<String>,
    pub is_open_id: bool,
    pub is_authorized: bool,
    pub requested_scopes: Vec<String>,
    /// Consented scopes, once the user decided (none when denied).
    pub authorized_scopes: Option<Vec<String>>,
    /// The user who approved.
    pub subject: Option<UserSession>,
    pub session_id: Option<String>,
}

impl DeviceCode {
    pub fn has_expired(&self, now: DateTime<Utc>) -> bool {
        self.creation_time + Duration::seconds(i64::from(self.lifetime)) < now
    }
}

/// Base64 of the UTF-8 SHA-256: how device and user codes are stored.
pub fn hash(code: &str) -> String {
    base64::engine::general_purpose::STANDARD
        .encode(digest::digest(&digest::SHA256, code.as_bytes()).as_ref())
}

/// What the device authorization endpoint answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceAuthorizationResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub expires_in: i32,
    pub interval: i32,
}

/// 32 random bytes as uppercase
/// hex.
fn new_device_code() -> String {
    use aws_lc_rs::rand::SecureRandom;
    let mut bytes = [0u8; 32];
    aws_lc_rs::rand::SystemRandom::new()
        .fill(&mut bytes)
        .expect("system random source");
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

/// Nine digits, without a leading zero.
fn numeric_user_code() -> String {
    use aws_lc_rs::rand::SecureRandom;
    const LOW: u32 = 100_000_000;
    const SPAN: u32 = 900_000_000;
    // Rejection sampling keeps the distribution uniform.
    let limit = u32::MAX - u32::MAX % SPAN;
    loop {
        let mut bytes = [0u8; 4];
        aws_lc_rs::rand::SystemRandom::new()
            .fill(&mut bytes)
            .expect("system random source");
        let n = u32::from_le_bytes(bytes);
        if n < limit {
            return (LOW + n % SPAN).to_string();
        }
    }
}

/// Only the numeric generator exists.
fn user_code_generator(user_code_type: &str) -> Option<(fn() -> String, u32)> {
    (user_code_type == "Numeric").then_some((numeric_user_code as fn() -> String, 5))
}

/// A validated request's client and scopes.
struct Validated {
    client: std::sync::Arc<Client>,
    scopes: Vec<String>,
    is_open_id: bool,
}

fn invalid(error: &'static str, description: Option<&str>) -> TokenError {
    match description {
        Some(d) => TokenError {
            description: Some(d.to_owned()),
            ..TokenError::new(error)
        },
        None => TokenError::new(error),
    }
}

/// The device authorization request validator; the requested
/// scopes come back with a failure, for its event.
async fn validate(
    ctx: &TokenContext<'_>,
    client: std::sync::Arc<Client>,
    form: &Form,
) -> Result<Result<Validated, (TokenError, Option<Vec<String>>)>, StoreError> {
    if client.protocol_type != "oidc" {
        return Ok(Err((
            invalid(UNAUTHORIZED_CLIENT, Some("Invalid protocol")),
            None,
        )));
    }
    if !client.allows_grant(GRANT_TYPE) {
        return Ok(Err((invalid(UNAUTHORIZED_CLIENT, None), None)));
    }
    let scope = match form.get("scope").filter(|s| !s.is_empty()) {
        Some(scope) => scope,
        None if client.allowed_scopes.is_empty() => {
            return Ok(Err((invalid(INVALID_SCOPE, None), None)));
        }
        None => {
            let mut scopes = client.allowed_scopes.clone();
            if client.allow_offline_access {
                scopes.push(OFFLINE_ACCESS.to_owned());
            }
            scopes.join(" ")
        }
    };
    if scope.len() > ctx.options.input_length_restrictions.scope {
        return Ok(Err((invalid(INVALID_REQUEST, Some("Invalid scope")), None)));
    }
    let mut scopes: Vec<String> = Vec::new();
    for s in scope.split(' ').filter(|s| !s.is_empty()) {
        if !scopes.iter().any(|x| x == s) {
            scopes.push(s.to_owned());
        }
    }
    let is_open_id = scopes.iter().any(|s| s == "openid");
    let enabled = ctx.stores.resources.get_all_enabled_resources().await?;
    let resources = match validate_requested_resources(&client, &enabled, &scopes, &[]) {
        Ok(resources) => resources,
        Err(ResourceValidationError::InvalidScope(_)) => {
            return Ok(Err((invalid(INVALID_SCOPE, None), Some(scopes))));
        }
        Err(ResourceValidationError::InvalidResourceIndicator(_)) => {
            return Ok(Err((
                invalid(UNAUTHORIZED_CLIENT, Some("Invalid scope")),
                Some(scopes),
            )));
        }
    };
    if !resources.identity_resources.is_empty() && !is_open_id {
        return Ok(Err((invalid(INVALID_SCOPE, None), Some(scopes))));
    }
    Ok(Ok(Validated {
        client,
        scopes: resources.scopes.clone(),
        is_open_id,
    }))
}

/// The device authorization endpoint after the HTTP checks: authenticates
/// the client, validates the request, and stores and answers the device
/// authorization. Raises the device authorization events.
pub async fn authorize(
    ctx: &TokenContext<'_>,
    authorization: Option<&str>,
    form: &Form,
) -> Result<DeviceAuthorizationResponse, TokenFailure> {
    let client = match authenticate_client(ctx, authorization, form).await? {
        Ok(client) => client,
        Err(error) => return Err(TokenError::new(error).into()),
    };
    let validated = match validate(ctx, client.clone(), form).await? {
        Ok(validated) => validated,
        Err((error, scopes)) => {
            ctx.events.raise(
                ctx.request,
                ctx.now,
                Event::device_authorization_failure(EventDetails::DeviceAuthorization {
                    client_id: Some(client.client_id.clone()),
                    client_name: client.client_name.clone(),
                    endpoint: "DeviceAuthorization",
                    scopes: scopes.map(|s| s.join(" ")),
                    error: Some(error.error.to_string()),
                    error_description: error.description.clone(),
                }),
            );
            return Err(error.into());
        }
    };
    let response = respond(ctx, &validated).await?;
    ctx.events.raise(
        ctx.request,
        ctx.now,
        Event::device_authorization_success(EventDetails::DeviceAuthorization {
            client_id: Some(validated.client.client_id.clone()),
            client_name: validated.client.client_name.clone(),
            endpoint: "DeviceAuthorization",
            scopes: Some(validated.scopes.join(" ")),
            error: None,
            error_description: None,
        }),
    );
    Ok(response)
}

/// The device authorization response generator.
async fn respond(
    ctx: &TokenContext<'_>,
    validated: &Validated,
) -> Result<DeviceAuthorizationResponse, TokenFailure> {
    let client = &validated.client;
    let code_type = client
        .user_code_type
        .as_deref()
        .unwrap_or(&ctx.options.device_flow.default_user_code_type);
    let (generate, retries) = user_code_generator(code_type)
        .ok_or_else(|| TokenFailure::Server(format!("no user code generator for {code_type}")))?;
    let mut user_code = None;
    for _ in 0..retries {
        let candidate = generate();
        if ctx
            .stores
            .device_flow
            .find_by_user_code(&hash(&candidate))
            .await?
            .is_none()
        {
            user_code = Some(candidate);
            break;
        }
    }
    let user_code = user_code.ok_or_else(|| {
        TokenFailure::Server("Unable to create unique device flow user code".into())
    })?;
    let interaction = &ctx.options.user_interaction;
    let mut verification_uri = interaction.device_verification_url.clone();
    if verification_uri.starts_with('/') && !verification_uri.starts_with("//") {
        verification_uri = format!("{}{verification_uri}", ctx.base_url.trim_end_matches('/'));
    }
    let parameter = &interaction.device_verification_user_code_parameter;
    let verification_uri_complete = (!parameter.trim().is_empty())
        .then(|| format!("{verification_uri}?{parameter}={user_code}"));
    let lifetime = client.device_code_lifetime;
    let device_code = new_device_code();
    let data = DeviceCode {
        creation_time: ctx.now,
        lifetime,
        client_id: client.client_id.clone(),
        description: None,
        is_open_id: validated.is_open_id,
        is_authorized: false,
        requested_scopes: validated.scopes.clone(),
        authorized_scopes: None,
        subject: None,
        session_id: None,
    };
    ctx.stores
        .device_flow
        .store_device_authorization(
            &hash(&device_code),
            &hash(&user_code),
            &client.client_id,
            ctx.now,
            ctx.now + Duration::seconds(i64::from(lifetime)),
            &serde_json::to_string(&data).expect("a device code serialises"),
        )
        .await?;
    Ok(DeviceAuthorizationResponse {
        device_code,
        user_code,
        verification_uri,
        verification_uri_complete,
        expires_in: lifetime,
        interval: ctx.options.device_flow.interval,
    })
}

/// What a device page shows.
#[derive(Debug, Clone)]
pub struct DeviceAuthorizationContext {
    pub client: std::sync::Arc<Client>,
    /// The requested scopes that are still valid for the client.
    pub scopes: Vec<String>,
}

/// The
/// pending authorization for `user_code`, when its client is enabled.
pub async fn authorization_context(
    stores: &crate::stores::Stores,
    user_code: &str,
) -> Result<Option<DeviceAuthorizationContext>, StoreError> {
    let Some(data) = stores
        .device_flow
        .find_by_user_code(&hash(user_code))
        .await?
    else {
        return Ok(None);
    };
    let Ok(code) = serde_json::from_str::<DeviceCode>(&data) else {
        return Ok(None);
    };
    let Some(client) =
        crate::stores::find_enabled_client(stores.clients.as_ref(), &code.client_id).await?
    else {
        return Ok(None);
    };
    let enabled = stores.resources.get_all_enabled_resources().await?;
    let scopes = validate_requested_resources(&client, &enabled, &code.requested_scopes, &[])
        .map(|r| r.scopes)
        .unwrap_or_default();
    Ok(Some(DeviceAuthorizationContext { client, scopes }))
}

/// Records the signed-in
/// user's decision for `user_code` (no scopes denies). The error is the
/// failure message.
pub async fn decide(
    stores: &crate::stores::Stores,
    user_code: &str,
    session: Option<&UserSession>,
    scopes: &[String],
    description: Option<&str>,
) -> Result<Result<(), &'static str>, StoreError> {
    let key = hash(user_code);
    let Some(data) = stores.device_flow.find_by_user_code(&key).await? else {
        return Ok(Err("Invalid user code"));
    };
    let Ok(mut code) = serde_json::from_str::<DeviceCode>(&data) else {
        return Ok(Err("Invalid user code"));
    };
    if crate::stores::find_enabled_client(stores.clients.as_ref(), &code.client_id)
        .await?
        .is_none()
    {
        return Ok(Err("Invalid client"));
    }
    let Some(session) = session else {
        return Ok(Err("No user present in device flow request"));
    };
    code.is_authorized = true;
    code.subject = Some(session.clone());
    code.session_id = Some(session.session_id.clone()).filter(|s| !s.is_empty());
    code.description = description.map(str::to_owned);
    code.authorized_scopes = Some(scopes.to_vec());
    stores
        .device_flow
        .update_by_user_code(
            &key,
            Some(&session.subject_id),
            &serde_json::to_string(&code).expect("a device code serialises"),
        )
        .await?;
    Ok(Ok(()))
}
