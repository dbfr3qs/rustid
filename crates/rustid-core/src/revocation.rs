//! The revocation endpoint's protocol logic (RFC 7009):
//! `TokenRevocationEndpoint`, the token revocation request validator and
//! the token revocation response generator, without HTTP types.

use crate::client_auth::authenticate_client;
use crate::form::Form;
use crate::grants::GrantFilter;
use crate::introspection::SUPPORTED_TOKEN_TYPE_HINTS;
use crate::reference_tokens;
use crate::refresh_tokens;
use tracing::Instrument;

use crate::events::Event;
use crate::stores::StoreError;
use crate::telemetry;
use crate::token::{INVALID_REQUEST, TokenContext};

pub const UNSUPPORTED_TOKEN_TYPE: &str = "unsupported_token_type";

/// Processes a revocation request. `Ok(Ok(()))` is HTTP 200 with no body
/// whether or not anything was revoked; `Ok(Err(code))` is HTTP 400 with the
/// error code; the outer error is a store failure. Records
/// `tokenservice.revocation` and raises the token revoked event.
pub async fn process(
    ctx: &TokenContext<'_>,
    authorization: Option<&str>,
    form: &Form,
) -> Result<Result<(), &'static str>, StoreError> {
    let client = match authenticate_client(ctx, authorization, form).await? {
        Ok(client) => client,
        Err(error) => {
            telemetry::revocation_failure(None, error);
            return Ok(Err(error));
        }
    };
    let (token, hint) = match validate_request(form) {
        Ok(request) => request,
        Err(error) => {
            telemetry::revocation_failure(Some(&client.client_id), error);
            return Ok(Err(error));
        }
    };
    let found = generate(ctx, &client.client_id, &token, hint.as_deref())
        .instrument(tracing::info_span!(
            "TokenRevocationResponseGenerator.Process"
        ))
        .await?;
    if let Some(token_type) = found {
        telemetry::revocation(&client.client_id);
        ctx.events.raise(
            ctx.request,
            ctx.now,
            Event::token_revoked_success(
                &client.client_id,
                client.client_name.as_deref(),
                Some(token_type),
                &token,
            ),
        );
    }
    Ok(Ok(()))
}

/// The token and its supported hint.
#[tracing::instrument(name = "revocation.validate_request", skip_all)]
fn validate_request(form: &Form) -> Result<(String, Option<String>), &'static str> {
    let token = form.get("token").ok_or(INVALID_REQUEST)?;
    let hint = form.get("token_type_hint");
    if let Some(hint) = &hint
        && !SUPPORTED_TOKEN_TYPE_HINTS.contains(&hint.as_str())
    {
        return Err(UNSUPPORTED_TOKEN_TYPE);
    }
    Ok((token, hint))
}

/// The type of the token found (and
/// revoked when the client owns it), if any. A hint limits the search to
/// its type; without one, access tokens are tried first.
async fn generate(
    ctx: &TokenContext<'_>,
    client_id: &str,
    token: &str,
    hint: Option<&str>,
) -> Result<Option<&'static str>, StoreError> {
    const ACCESS: &str = "access_token";
    const REFRESH: &str = "refresh_token";
    let found = match hint {
        Some(REFRESH) => revoke_refresh_token(ctx, client_id, token)
            .await?
            .then_some(REFRESH),
        Some(_) => revoke_reference_token(ctx, client_id, token)
            .await?
            .then_some(ACCESS),
        None => {
            if revoke_reference_token(ctx, client_id, token).await? {
                Some(ACCESS)
            } else {
                revoke_refresh_token(ctx, client_id, token)
                    .await?
                    .then_some(REFRESH)
            }
        }
    };
    Ok(found)
}

/// Removes the refresh token when `client_id`
/// owns it, with the client's reference tokens for the same subject and
/// session; `true` when a refresh token was found.
async fn revoke_refresh_token(
    ctx: &TokenContext<'_>,
    client_id: &str,
    handle: &str,
) -> Result<bool, StoreError> {
    let grants = ctx.stores.grants.as_ref();
    let Some(token) = refresh_tokens::get(grants, handle).await? else {
        return Ok(false);
    };
    if token.client_id == client_id {
        refresh_tokens::remove(grants, handle).await?;
        grants
            .remove_all(&GrantFilter {
                subject_id: Some(token.subject.subject_id.clone()),
                session_id: token.session_id.clone(),
                client_id: Some(token.client_id.clone()),
                grant_type: Some(crate::grants::REFERENCE_TOKEN.to_owned()),
                ..Default::default()
            })
            .await?;
    }
    Ok(true)
}

/// Removes the reference token when `client_id` owns it; `true` when a
/// token was found. Another client's token is left alone; the response is
/// the same either way.
async fn revoke_reference_token(
    ctx: &TokenContext<'_>,
    client_id: &str,
    handle: &str,
) -> Result<bool, StoreError> {
    let grants = ctx.stores.grants.as_ref();
    let Some(stored) = reference_tokens::get(grants, handle).await? else {
        return Ok(false);
    };
    if stored.client_id == client_id {
        reference_tokens::remove(grants, handle).await?;
    }
    Ok(true)
}
