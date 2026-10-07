//! The CIBA grant (validate ciba request request,
//! the backchannel authentication request id validator) and its tokens
//! .

use super::*;
use crate::ciba::{CIBA_GRANT, CibaRequest, GRANT_TYPE, get_by_request_id};

const AUTHORIZATION_PENDING: &str = "authorization_pending";
const SLOW_DOWN: &str = "slow_down";
const EXPIRED_TOKEN: &str = "expired_token";
const ACCESS_DENIED: &str = "access_denied";

/// The request is removed once it is
/// denied or yields tokens.
pub(super) async fn validate_ciba(
    ctx: &TokenContext<'_>,
    client: &Client,
    form: &Form,
    subject_id: &mut Option<String>,
    resource: Option<String>,
) -> Result<Validated, TokenFailure> {
    let invalid_grant = || TokenFailure::Protocol(TokenError::new(INVALID_GRANT));
    if !client.allows_grant(GRANT_TYPE) {
        return Err(TokenError::new(UNAUTHORIZED_CLIENT).into());
    }
    let id = form
        .get("auth_req_id")
        .filter(|id| !id.trim().is_empty())
        .ok_or(TokenError::new(INVALID_REQUEST))?;
    if utf16_len(&id)
        > ctx
            .options
            .input_length_restrictions
            .authentication_request_id
    {
        return Err(invalid_grant());
    }
    let grants = ctx.stores.grants.as_ref();
    let request = get_by_request_id(grants, &id)
        .await?
        .ok_or_else(invalid_grant)?;
    if request.client_id != client.client_id {
        tracing::error!(client_id = %client.client_id, "an authentication request id from another client");
        return Err(invalid_grant());
    }
    let interval = client
        .polling_interval
        .unwrap_or(ctx.options.ciba.default_polling_interval);
    if ctx
        .stores
        .device_throttling
        .should_slow_down(
            &format!("{CIBA_GRANT}:{id}"),
            i64::from(interval),
            i64::from(request.lifetime),
            ctx.now,
        )
        .await?
    {
        return Err(TokenError::new(SLOW_DOWN).into());
    }
    if request.has_expired(ctx.now) {
        return Err(TokenError::new(EXPIRED_TOKEN).into());
    }
    let authorized_scopes = request.authorized_scopes.clone().unwrap_or_default();
    if request.is_complete && authorized_scopes.is_empty() {
        grants.remove(&request.internal_id).await?;
        return Err(TokenError::new(ACCESS_DENIED).into());
    }
    if !request.is_complete {
        return Err(TokenError::new(AUTHORIZATION_PENDING).into());
    }
    let active = ctx
        .stores
        .profile
        .is_active(&crate::profile::ActiveRequest {
            caller: crate::profile::active_callers::BACKCHANNEL_AUTHENTICATION,
            client,
            subject_id: &request.subject.subject_id,
            subject_claims: &request.subject.claims,
        })
        .await
        .map_err(|e| TokenFailure::Server(e.to_string()))?;
    if !active {
        tracing::error!(subject_id = %request.subject.subject_id, "User has been disabled");
        return Err(invalid_grant());
    }
    *subject_id = Some(request.subject.subject_id.clone());
    // Removed atomically: of two concurrent redemptions only one proceeds.
    if grants.take(&request.internal_id).await?.is_none() {
        return Err(invalid_grant());
    }
    if let Some(requested) = &resource
        && !request.requested_resource_indicators.is_empty()
        && !request.requested_resource_indicators.contains(requested)
    {
        return Err(TokenError::described(
            INVALID_TARGET,
            "Resource indicator does not match any resource indicator in the original backchannel authentication request.",
        )
        .into());
    }
    let enabled = ctx.stores.resources.get_all_enabled_resources().await?;
    let resources = validate_requested_resources(
        client,
        &enabled,
        &authorized_scopes,
        &request.requested_resource_indicators,
    )
    .map_err(|e| match e {
        ResourceValidationError::InvalidResourceIndicator(_) => {
            TokenError::described(INVALID_TARGET, "Invalid resource indicator.")
        }
        ResourceValidationError::InvalidScope(_) => {
            TokenError::described(INVALID_SCOPE, "Invalid scope.")
        }
    })?
    .filter_by_resource_indicator(resource.as_deref());
    Ok(Validated::Ciba(Box::new(request), resources, resource))
}

/// As for an authorization code, with an
/// identity token always.
pub(super) async fn issue_for_ciba(
    ctx: &TokenContext<'_>,
    client: &Client,
    request: &CibaRequest,
    resources: &ValidatedResources,
    resource: Option<&str>,
    proof: &RequestProof,
) -> Result<TokenResponse, TokenFailure> {
    let subject = &request.subject;
    let issuer = ctx.issuer();
    let session_id = request.session_id.as_deref().filter(|s| !s.is_empty());
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
            request.description.as_deref(),
        )
        .await?;
    let refresh_token = if resources.offline_access {
        let mut token = RefreshToken {
            client_id: client.client_id.clone(),
            subject: subject.clone(),
            session_id: session_id.map(str::to_owned),
            description: request.description.clone(),
            authorized_scopes: resources.scopes.clone(),
            authorized_resource_indicators: Some(request.requested_resource_indicators.clone()),
            access_token: None,
            resource_access_tokens: Default::default(),
            creation_time: ctx.now,
            lifetime: refresh_tokens::initial_lifetime(client),
            consumed_time: None,
            proof_type: Some(proof.proof_type),
        };
        token.set_access_token(record, resource);
        Some(refresh_tokens::create(ctx.stores.grants.as_ref(), &token).await?)
    } else {
        None
    };
    let identity_request = IdentityTokenRequest {
        subject: None,
        nonce: None,
        access_token: Some(&access_token),
        authorization_code: None,
        state_hash: None,
        session_id,
        include_all_identity_claims: false,
    };
    let id_token = issuer
        .identity_token(client, resources, subject, &identity_request)
        .await?;
    Ok(TokenResponse {
        id_token: Some(id_token),
        access_token,
        expires_in: i64::from(client.access_token_lifetime),
        token_type: "Bearer",
        refresh_token,
        scope: resources.scopes.join(" "),
        custom: Default::default(),
    })
}
