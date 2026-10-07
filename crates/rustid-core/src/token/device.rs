//! The device code grant (validate device code request,
//! the device code validator) and its tokens.

use super::*;
use crate::device_flow::{DeviceCode, GRANT_TYPE, hash};

const AUTHORIZATION_PENDING: &str = "authorization_pending";
const SLOW_DOWN: &str = "slow_down";
const EXPIRED_TOKEN: &str = "expired_token";
const ACCESS_DENIED: &str = "access_denied";

/// Validate device code request with the device code validator: the code
/// is removed once it yields tokens.
pub(super) async fn validate_device_code(
    ctx: &TokenContext<'_>,
    client: &Client,
    form: &Form,
    subject_id: &mut Option<String>,
    resource: Option<&str>,
) -> Result<Validated, TokenFailure> {
    let invalid_grant = || TokenFailure::Protocol(TokenError::new(INVALID_GRANT));
    if resource.is_some() {
        tracing::error!("Resource indicators not supported for device flow");
        return Err(TokenError::new(INVALID_TARGET).into());
    }
    if !client.allows_grant(GRANT_TYPE) {
        return Err(TokenError::new(UNAUTHORIZED_CLIENT).into());
    }
    let device_code = form
        .get("device_code")
        .filter(|c| !c.is_empty())
        .ok_or(TokenError::new(INVALID_REQUEST))?;
    if utf16_len(&device_code) > ctx.options.input_length_restrictions.device_code {
        return Err(invalid_grant());
    }
    let key = hash(&device_code);
    let data = ctx
        .stores
        .device_flow
        .find_by_device_code(&key)
        .await?
        .ok_or_else(invalid_grant)?;
    let code: DeviceCode = serde_json::from_str(&data).map_err(|_| invalid_grant())?;
    if code.client_id != client.client_id {
        tracing::error!(client_id = %client.client_id, "a device code from another client");
        return Err(invalid_grant());
    }
    let interval = client
        .polling_interval
        .unwrap_or(ctx.options.device_flow.interval);
    if ctx
        .stores
        .device_throttling
        .should_slow_down(
            &device_code,
            i64::from(interval),
            i64::from(code.lifetime),
            ctx.now,
        )
        .await?
    {
        return Err(TokenError::new(SLOW_DOWN).into());
    }
    if code.has_expired(ctx.now) {
        return Err(TokenError::new(EXPIRED_TOKEN).into());
    }
    let authorized_scopes = code.authorized_scopes.clone().unwrap_or_default();
    if code.is_authorized && authorized_scopes.is_empty() {
        return Err(TokenError::new(ACCESS_DENIED).into());
    }
    let Some(subject) = code.subject.as_ref().filter(|_| code.is_authorized) else {
        return Err(TokenError::new(AUTHORIZATION_PENDING).into());
    };
    let active = ctx
        .stores
        .profile
        .is_active(&crate::profile::ActiveRequest {
            caller: crate::profile::active_callers::DEVICE_CODE,
            client,
            subject_id: &subject.subject_id,
            subject_claims: &subject.claims,
        })
        .await
        .map_err(|e| TokenFailure::Server(e.to_string()))?;
    if !active {
        tracing::error!(subject_id = %subject.subject_id, "User has been disabled");
        return Err(invalid_grant());
    }
    *subject_id = Some(subject.subject_id.clone());
    // Removed atomically: of two concurrent redemptions only one proceeds.
    if !ctx.stores.device_flow.remove_by_device_code(&key).await? {
        return Err(invalid_grant());
    }
    let enabled = ctx.stores.resources.get_all_enabled_resources().await?;
    let resources = validate_requested_resources(client, &enabled, &authorized_scopes, &[])
        .map_err(|e| match e {
            ResourceValidationError::InvalidResourceIndicator(_) => {
                TokenError::described(INVALID_TARGET, "Invalid resource indicator.")
            }
            ResourceValidationError::InvalidScope(_) => {
                TokenError::described(INVALID_SCOPE, "Invalid scope.")
            }
        })?;
    Ok(Validated::DeviceCode(Box::new(code), resources))
}

/// As for an authorization code, with an
/// identity token when the device request asked for `openid`.
pub(super) async fn issue_for_device(
    ctx: &TokenContext<'_>,
    client: &Client,
    code: &DeviceCode,
    resources: &ValidatedResources,
    proof: &RequestProof,
) -> Result<TokenResponse, TokenFailure> {
    let subject = code
        .subject
        .as_ref()
        .ok_or_else(|| TokenFailure::Server("an approved device code has no subject".into()))?;
    let issuer = ctx.issuer();
    let session_id = code.session_id.as_deref().filter(|s| !s.is_empty());
    let mut record = issuer
        .user_access_token_record(client, resources, subject, session_id)
        .await?;
    record.token.confirmation.clone_from(&proof.confirmation);
    let access_token = issuer
        .serialize_access_token(
            client,
            resources,
            &record,
            &subject.subject_id,
            session_id,
            code.description.as_deref(),
        )
        .await?;
    let refresh_token = if resources.offline_access {
        let mut token = RefreshToken {
            client_id: client.client_id.clone(),
            subject: subject.clone(),
            session_id: session_id.map(str::to_owned),
            description: code.description.clone(),
            authorized_scopes: resources.scopes.clone(),
            authorized_resource_indicators: None,
            access_token: None,
            resource_access_tokens: Default::default(),
            creation_time: ctx.now,
            lifetime: refresh_tokens::initial_lifetime(client),
            consumed_time: None,
            proof_type: Some(proof.proof_type),
        };
        token.set_access_token(record, None);
        Some(refresh_tokens::create(ctx.stores.grants.as_ref(), &token).await?)
    } else {
        None
    };
    let id_token = if code.is_open_id {
        let request = IdentityTokenRequest {
            subject: None,
            nonce: None,
            access_token: Some(&access_token),
            authorization_code: None,
            state_hash: None,
            session_id,
            include_all_identity_claims: false,
        };
        Some(
            issuer
                .identity_token(client, resources, subject, &request)
                .await?,
        )
    } else {
        None
    };
    Ok(TokenResponse {
        id_token,
        access_token,
        expires_in: i64::from(client.access_token_lifetime),
        token_type: "Bearer",
        refresh_token,
        scope: resources.scopes.join(" "),
        custom: Default::default(),
    })
}
