//! The userinfo endpoint's protocol logic: the user info request validator and
//! the user info response generator with the default profile service.

use serde_json::{Map, Value};

use crate::access_tokens::{self, INVALID_TOKEN, ValidationContext};
use crate::claims;

use crate::profile::{ActiveRequest, ProfileRequest, active_callers, callers};
use crate::stores::{StoreError, find_enabled_client};
use crate::tokens::Claim;

pub const INSUFFICIENT_SCOPE: &str = "insufficient_scope";

/// Claims of the access token that
/// don't describe the user.
pub const PROTOCOL_CLAIMS_FILTER: &[&str] = &[
    "at_hash",
    "aud",
    "azp",
    "c_hash",
    "client_id",
    "exp",
    "iat",
    "iss",
    "jti",
    "nonce",
    "nbf",
    "reference_token_id",
    "sid",
    "scope",
];

/// Validates the access token (it must carry the `openid` scope and exactly
/// one `sub`) and returns the userinfo claims as `claims::to_dictionary`
/// writes them. The user is the token's non-protocol claims; the default
/// profile service returns those of the types the token's identity scopes
/// ask for, and `sub` is always included. The verdict's error is a
/// protected resource error (`invalid_token`, `expired_token`,
/// `insufficient_scope`).
#[tracing::instrument(name = "userinfo.validate_request", skip_all)]
pub async fn userinfo(
    ctx: &ValidationContext<'_>,
    token: &str,
) -> Result<Result<Map<String, Value>, &'static str>, StoreError> {
    let validated = match access_tokens::validate(ctx, token).await? {
        Ok(validated) => validated,
        Err(error) => return Ok(Err(error)),
    };
    let has_openid = validated
        .claims
        .iter()
        .any(|c| c.claim_type == "scope" && c.value == "openid");
    if !has_openid {
        return Ok(Err(INSUFFICIENT_SCOPE));
    }
    let subs: Vec<&Claim> = validated
        .claims
        .iter()
        .filter(|c| c.claim_type == "sub")
        .collect();
    let [sub] = subs.as_slice() else {
        return Ok(Err(INVALID_TOKEN));
    };
    let subject: Vec<Claim> = validated
        .claims
        .iter()
        .filter(|c| !PROTOCOL_CLAIMS_FILTER.contains(&c.claim_type.as_str()))
        .cloned()
        .collect();
    let client_id = validated.first("client_id").unwrap_or_default();
    let Some(client) = find_enabled_client(ctx.stores.clients.as_ref(), client_id).await? else {
        return Ok(Err(INVALID_TOKEN));
    };
    if crate::pairwise::unavailable(ctx.options, &client) {
        return Err(StoreError::Backend(crate::pairwise::unavailable_message(
            &client,
        )));
    }
    let profile = ctx.stores.profile.as_ref();
    let active = profile
        .is_active(&ActiveRequest {
            caller: active_callers::USERINFO_REQUEST,
            client: &client,
            subject_id: &sub.value,
            subject_claims: &subject,
        })
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
    if !active {
        tracing::error!(sub = %sub.value, "User is not active");
        return Ok(Err(INVALID_TOKEN));
    }
    let scopes: Vec<&str> = validated
        .claims
        .iter()
        .filter(|c| c.claim_type == "scope")
        .map(|c| c.value.as_str())
        .collect();
    let resources = ctx.stores.resources.get_all_enabled_resources().await?;
    let mut requested: Vec<String> = Vec::new();
    for claim_type in resources
        .identity_resources
        .iter()
        .filter(|r| scopes.contains(&r.name.as_str()))
        .flat_map(|r| &r.user_claims)
    {
        if !requested.contains(claim_type) {
            requested.push(claim_type.clone());
        }
    }
    let mut outgoing = profile
        .profile_claims(&ProfileRequest {
            caller: callers::USERINFO_ENDPOINT,
            client: &client,
            subject_id: &sub.value,
            subject_claims: &subject,
            requested_claim_types: &requested,
        })
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
    match outgoing.iter().find(|c| c.claim_type == "sub") {
        None => outgoing.push((*sub).clone()),
        Some(returned) if returned.value != sub.value => {
            return Err(StoreError::Backend(
                "Profile service returned incorrect subject value".to_owned(),
            ));
        }
        Some(_) => {}
    }
    // A pairwise client sees its own subject; the lookups above used the
    // user's.
    if let Some(pairwise) = crate::pairwise::subject(ctx.options, &client, &sub.value) {
        for claim in outgoing.iter_mut().filter(|c| c.claim_type == "sub") {
            claim.value = pairwise.clone();
        }
    }
    Ok(Ok(claims::to_dictionary(&outgoing)))
}
