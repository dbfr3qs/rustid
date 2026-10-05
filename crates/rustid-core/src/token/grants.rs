//! The password and extension grants (validate resource owner credential request,
//! validate extension grant request) and their tokens
//! .

use super::*;
use crate::clients::ClientClaim;
use crate::grant_validation::{
    ExtensionRequest, GrantAnswer, GrantResult, PasswordRequest, RequestChanges,
};
use crate::issuance::AccessTokenRecord;
use crate::scopes::OFFLINE_ACCESS;
use crate::session::{LOCAL_IDP, UserSession};

/// The requested scopes, or by
/// default every allowed scope that exists (identity scopes unless
/// `ignore_identity`) and `offline_access` (unless `ignore_offline`), with
/// the resources they need, narrowed to `resource`.
pub(super) async fn scopes_and_resources(
    ctx: &TokenContext<'_>,
    client: &Client,
    form: &Form,
    resource: Option<&str>,
    ignore_identity: bool,
    ignore_offline: bool,
) -> Result<ValidatedResources, TokenFailure> {
    let enabled = ctx.stores.resources.get_all_enabled_resources().await?;
    let scopes = match form.get("scope").filter(|s| !s.trim().is_empty()) {
        Some(scopes) => scopes,
        None => {
            if client.allowed_scopes.is_empty() {
                return Err(TokenError::new(INVALID_SCOPE).into());
            }
            let allowed = |name: &String| client.allowed_scopes.contains(name);
            let mut defaults: Vec<&str> = Vec::new();
            let identity = enabled
                .identity_resources
                .iter()
                .filter(|_| !ignore_identity)
                .map(|r| &r.name);
            for name in identity.chain(enabled.api_scopes.iter().map(|s| &s.name)) {
                if allowed(name) && !defaults.contains(&name.as_str()) {
                    defaults.push(name);
                }
            }
            if !ignore_offline && client.allow_offline_access {
                defaults.push(OFFLINE_ACCESS);
            }
            defaults.join(" ")
        }
    };
    if scopes.len() > ctx.options.input_length_restrictions.scope {
        return Err(TokenError::new(INVALID_SCOPE).into());
    }
    let requested = parse_scopes_string(&scopes).ok_or(TokenError::new(INVALID_SCOPE))?;
    let indicators: Vec<String> = resource.iter().map(|r| (*r).to_owned()).collect();
    let resources = validate_requested_resources(client, &enabled, &requested, &indicators)
        .map_err(|e| match e {
            ResourceValidationError::InvalidResourceIndicator(_) => TokenError::new(INVALID_TARGET),
            ResourceValidationError::InvalidScope(_) => TokenError::new(INVALID_SCOPE),
        })?;
    Ok(resources.filter_by_resource_indicator(resource))
}

/// The request's parameters a grant validator may see.
fn parameters(form: &Form) -> Vec<(String, String)> {
    form.pairs()
        .filter(|(k, _)| !crate::token_request::WITHHELD_PARAMETERS.contains(k))
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
}

/// The user a grant authenticated, as a token subject: `amr` the
/// authentication method, `idp` local by default, `auth_time` now.
fn subject(answer: crate::grant_validation::GrantSubject, now: DateTime<Utc>) -> UserSession {
    UserSession {
        subject_id: answer.subject_id,
        session_id: String::new(),
        auth_time: now.timestamp(),
        idp: answer
            .idp
            .filter(|i| !i.trim().is_empty())
            .unwrap_or_else(|| LOCAL_IDP.to_owned()),
        amr: vec![answer.authentication_method],
        claims: answer.claims,
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
    }
}

/// A validator's error as the token endpoint answers it.
fn refused(answer: GrantAnswer, default_description: Option<&str>) -> TokenFailure {
    let GrantResult::Error { error, description } = answer.result else {
        unreachable!("only errors are refused");
    };
    TokenFailure::Protocol(TokenError {
        error: std::borrow::Cow::Owned(error.unwrap_or_else(|| INVALID_GRANT.to_owned())),
        description: description.or(default_description.map(str::to_owned)),
        custom: answer.custom,
        dpop_nonce: None,
    })
}

async fn is_active(
    ctx: &TokenContext<'_>,
    client: &Client,
    user: &UserSession,
    caller: &str,
) -> Result<bool, TokenFailure> {
    ctx.stores
        .profile
        .is_active(&crate::profile::ActiveRequest {
            caller,
            client,
            subject_id: &user.subject_id,
            subject_claims: &user.claims,
        })
        .await
        .map_err(|e| TokenFailure::Server(e.to_string()))
}

pub(super) async fn validate_password(
    ctx: &TokenContext<'_>,
    client: &Client,
    form: &Form,
    resource: Option<String>,
) -> Result<Validated, TokenFailure> {
    if !client.allows_grant("password") {
        return Err(TokenError::new(UNAUTHORIZED_CLIENT).into());
    }
    let resources =
        scopes_and_resources(ctx, client, form, resource.as_deref(), false, false).await?;
    let limits = &ctx.options.input_length_restrictions;
    let Some(username) = form.get("username").filter(|u| !u.trim().is_empty()) else {
        return Err(TokenError::new(INVALID_GRANT).into());
    };
    let password = form.get("password").unwrap_or_default();
    if utf16_len(&username) > limits.user_name || utf16_len(&password) > limits.password {
        return Err(TokenError::new(INVALID_GRANT).into());
    }
    let parameters = parameters(form);
    let answer = ctx
        .stores
        .grant_validation
        .validate_password(&PasswordRequest {
            client,
            username: &username,
            password: &password,
            parameters: &parameters,
        })
        .await
        .map_err(|e| TokenFailure::Server(e.to_string()))?;
    let user = match answer.result {
        GrantResult::Subject(ref s) => subject(s.clone(), ctx.now),
        GrantResult::Error { ref error, .. }
            if error.as_deref() == Some(UNSUPPORTED_GRANT_TYPE) =>
        {
            let GrantAnswer { custom, .. } = answer;
            return Err(TokenFailure::Protocol(TokenError {
                error: UNSUPPORTED_GRANT_TYPE.into(),
                description: None,
                custom,
                dpop_nonce: None,
            }));
        }
        GrantResult::Error { .. } => {
            return Err(refused(answer, Some("invalid_username_or_password")));
        }
        GrantResult::NoSubject => return Err(TokenError::new(INVALID_GRANT).into()),
    };
    if !is_active(
        ctx,
        client,
        &user,
        crate::profile::active_callers::RESOURCE_OWNER,
    )
    .await?
    {
        return Err(TokenError::new(INVALID_GRANT).into());
    }
    Ok(Validated::Grant {
        subject: Some(Box::new(user)),
        resources,
        custom: answer.custom,
        changes: RequestChanges::default(),
        resource,
    })
}

pub(super) async fn validate_extension(
    ctx: &TokenContext<'_>,
    client: &Client,
    form: &Form,
    grant_type: &str,
    resource: Option<String>,
) -> Result<Validated, TokenFailure> {
    let validator = &ctx.stores.grant_validation;
    if !client.allows_grant(grant_type)
        || !validator
            .extension_grant_types()
            .iter()
            .any(|g| g == grant_type)
    {
        return Err(TokenError::new(UNSUPPORTED_GRANT_TYPE).into());
    }
    let resources =
        scopes_and_resources(ctx, client, form, resource.as_deref(), false, false).await?;
    let parameters = parameters(form);
    // The extension grant validator catches a validator's exception: the
    // request is `invalid_grant`.
    let answer = match validator
        .validate_extension(&ExtensionRequest {
            grant_type,
            client,
            parameters: &parameters,
        })
        .await
    {
        Ok(answer) => answer,
        Err(e) => {
            tracing::error!(grant_type, error = %e, "Grant validation error");
            return Err(TokenError::new(INVALID_GRANT).into());
        }
    };
    let user = match answer.result {
        GrantResult::Subject(ref s) => Some(subject(s.clone(), ctx.now)),
        GrantResult::NoSubject => None,
        GrantResult::Error { .. } => return Err(refused(answer, None)),
    };
    if let Some(user) = &user
        && !is_active(
            ctx,
            client,
            user,
            crate::profile::active_callers::EXTENSION_GRANT,
        )
        .await?
    {
        return Err(TokenError::new(INVALID_GRANT).into());
    }
    Ok(Validated::Grant {
        subject: user.map(Box::new),
        resources,
        custom: answer.custom,
        changes: answer.changes,
        resource,
    })
}

/// The client as a validator's changes leave it, for this token only.
fn effective_client(client: &Client, changes: &RequestChanges) -> Client {
    let mut effective = client.clone();
    if let Some(id) = &changes.client_id {
        effective.client_id = id.clone();
    }
    if let Some(lifetime) = changes.access_token_lifetime {
        effective.access_token_lifetime = i32::try_from(lifetime).unwrap_or(i32::MAX);
    }
    if let Some(token_type) = changes.access_token_type {
        effective.access_token_type = token_type;
    }
    effective
        .claims
        .extend(changes.client_claims.iter().map(|c| ClientClaim {
            claim_type: c.claim_type.clone(),
            value: c.value.clone(),
            value_type: c.value_type.clone(),
        }));
    effective
}

/// Stores a refresh token for `subject`, carrying the access token's
/// record when there is one.
async fn refresh_token(
    ctx: &TokenContext<'_>,
    client: &Client,
    subject: UserSession,
    resources: &ValidatedResources,
    record: Option<AccessTokenRecord>,
    resource: Option<&str>,
    proof: &super::RequestProof,
) -> Result<String, TokenFailure> {
    let mut token = RefreshToken {
        client_id: client.client_id.clone(),
        subject,
        session_id: None,
        description: None,
        authorized_scopes: resources.scopes.clone(),
        authorized_resource_indicators: None,
        access_token: None,
        resource_access_tokens: Default::default(),
        creation_time: ctx.now,
        lifetime: refresh_tokens::initial_lifetime(client),
        consumed_time: None,
        proof_type: Some(proof.proof_type),
    };
    if let Some(record) = record {
        token.set_access_token(record, resource);
    }
    Ok(refresh_tokens::create(ctx.stores.grants.as_ref(), &token).await?)
}

/// Process token request for the password and extension grants: a
/// user token (with a refresh token for `offline_access`), or a client
/// token when the grant has no subject. No identity token.
///
/// Without a subject, `offline_access` still gets a refresh token,
/// issues one; it has no subject, so redeeming it is refused. Tokens
/// belong to the requesting client even when a validator impersonates
/// another.
pub(super) async fn issue_for_grant(
    ctx: &TokenContext<'_>,
    client: &Client,
    user: Option<&UserSession>,
    resources: &ValidatedResources,
    changes: &RequestChanges,
    resource: Option<&str>,
    proof: &super::RequestProof,
) -> Result<TokenResponse, TokenFailure> {
    let effective = effective_client(client, changes);
    let Some(user) = user else {
        let mut response =
            issue(ctx, &effective, resources, Some(&client.client_id), proof).await?;
        if resources.offline_access {
            let nobody = subject(
                crate::grant_validation::GrantSubject {
                    subject_id: String::new(),
                    authentication_method: String::new(),
                    idp: None,
                    claims: Vec::new(),
                },
                ctx.now,
            );
            response.refresh_token =
                Some(refresh_token(ctx, client, nobody, resources, None, resource, proof).await?);
        }
        return Ok(response);
    };
    let issuer = ctx.issuer();
    let mut record = issuer
        .user_access_token_record(&effective, resources, user, None)
        .await?;
    // The token's `client_id` claim names the impersonated client, but it
    // belongs to the one that asked.
    record.token.client_id.clone_from(&client.client_id);
    record.token.confirmation.clone_from(&proof.confirmation);
    let access_token = issuer
        .serialize_access_token(&effective, resources, &record, &user.subject_id, None, None)
        .await?;
    let refresh_token = if resources.offline_access {
        Some(
            refresh_token(
                ctx,
                client,
                user.clone(),
                resources,
                Some(record),
                resource,
                proof,
            )
            .await?,
        )
    } else {
        None
    };
    Ok(TokenResponse {
        id_token: None,
        access_token,
        expires_in: i64::from(effective.access_token_lifetime),
        token_type: "Bearer",
        refresh_token,
        scope: resources.scopes.join(" "),
        custom: Default::default(),
    })
}
