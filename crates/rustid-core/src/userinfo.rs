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
    "userinfo_claims",
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
    Ok(answer(ctx, token).await?.map(|(claims, _)| claims))
}

/// A userinfo request as the endpoint received it.
#[derive(Debug, Clone, Copy)]
pub struct UserInfoRequest<'a> {
    pub token: &'a str,
    /// The token came with the `DPoP` scheme.
    pub dpop: bool,
    /// The `DPoP` headers.
    pub dpop_proofs: &'a [String],
    pub method: &'a str,
    /// The endpoint's URL, which a proof's `htu` must name.
    pub url: &'a str,
    pub client_certificate: Option<&'a crate::client_certificate::ClientCertificate>,
}

/// Why a userinfo request was refused: a protected resource error
/// (`invalid_token`, `expired_token`, `insufficient_scope`), or a
/// sender-constrained token used without its proof or certificate.
#[derive(Debug, Clone, PartialEq)]
pub enum UserInfoRefusal {
    Error(&'static str),
    Challenge(crate::protected_resource::Challenge),
}

/// [`userinfo_response`] for a request whose token may be sender-
/// constrained: a DPoP-bound token needs the `DPoP` scheme and a proof
/// bound to it (RFC 9449 §7), and a certificate-bound token the
/// certificate it's bound to (RFC 8705).
#[tracing::instrument(name = "userinfo.request", skip_all)]
pub async fn userinfo_for_request(
    ctx: &ValidationContext<'_>,
    request: &UserInfoRequest<'_>,
    protector: &crate::data_protection::DataProtector,
) -> Result<Result<UserInfoAnswer, UserInfoRefusal>, StoreError> {
    let validated = match access_tokens::validate(ctx, request.token).await? {
        Ok(validated) => validated,
        Err(error) => return Ok(Err(UserInfoRefusal::Error(error))),
    };
    {
        let resource = crate::protected_resource::ResourceRequest {
            authorization: None,
            dpop_proofs: request.dpop_proofs,
            method: request.method,
            url: request.url,
            client_certificate: request.client_certificate,
        };
        if let Err(challenge) = crate::protected_resource::check_binding(
            ctx,
            &validated,
            request.token,
            request.dpop,
            &resource,
            protector,
        )
        .await?
        {
            return Ok(Err(UserInfoRefusal::Challenge(challenge)));
        }
    }
    Ok(respond(ctx, &validated)
        .await?
        .map_err(UserInfoRefusal::Error))
}

/// What the userinfo endpoint answers: the claims as JSON, or, for a client
/// with `userinfoSignedResponseAlg`, a JWT of them (OIDC Core §5.3.2).
#[derive(Debug, Clone, PartialEq)]
pub enum UserInfoAnswer {
    Json(Map<String, Value>),
    Jwt(String),
}

/// [`userinfo`], signed for a client that asks: its claims plus `iss` and
/// `aud` (the client), signed with the server's key for the client's
/// algorithm. No such key is a server error, never an unsigned answer.
#[tracing::instrument(name = "userinfo.validate_request", skip_all)]
pub async fn userinfo_response(
    ctx: &ValidationContext<'_>,
    token: &str,
) -> Result<Result<UserInfoAnswer, &'static str>, StoreError> {
    match access_tokens::validate(ctx, token).await? {
        Ok(validated) => respond(ctx, &validated).await,
        Err(error) => Ok(Err(error)),
    }
}

/// The answer for a validated token: JSON, or a JWT for a client that asks.
async fn respond(
    ctx: &ValidationContext<'_>,
    validated: &access_tokens::ValidatedToken,
) -> Result<Result<UserInfoAnswer, &'static str>, StoreError> {
    let (mut claims, client) = match answer_for(ctx, validated).await? {
        Ok(found) => found,
        Err(error) => return Ok(Err(error)),
    };
    let Some(alg) = client.userinfo_signed_response_alg.as_deref() else {
        return Ok(Ok(UserInfoAnswer::Json(claims)));
    };
    let Some(key) = ctx.keys.signing_key(&[alg.to_owned()]).await? else {
        return Err(StoreError::Backend(format!(
            "client {} asks for userinfo signed with {alg}, and there is no signing key for it",
            client.client_id
        )));
    };
    claims.insert("iss".into(), Value::String(ctx.issuer.to_owned()));
    claims.insert("aud".into(), Value::String(client.client_id.clone()));
    let jwt = crate::jwt::encode(&key, &[], &claims)
        .map_err(|e| StoreError::Backend(format!("signing userinfo: {e}")))?;
    Ok(Ok(UserInfoAnswer::Jwt(jwt)))
}

/// The claims and the client the token was issued to.
async fn answer(
    ctx: &ValidationContext<'_>,
    token: &str,
) -> Result<
    Result<(Map<String, Value>, std::sync::Arc<crate::clients::Client>), &'static str>,
    StoreError,
> {
    match access_tokens::validate(ctx, token).await? {
        Ok(validated) => answer_for(ctx, &validated).await,
        Err(error) => Ok(Err(error)),
    }
}

/// [`answer`] for a validated token.
async fn answer_for(
    ctx: &ValidationContext<'_>,
    validated: &access_tokens::ValidatedToken,
) -> Result<
    Result<(Map<String, Value>, std::sync::Arc<crate::clients::Client>), &'static str>,
    StoreError,
> {
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
    // What the scopes ask for, then what the `claims` parameter did, as far
    // as the client's scopes still allow.
    let asked = crate::claims_request::RequestedClaims {
        userinfo: validated
            .claims
            .iter()
            .filter(|c| c.claim_type == crate::claims_request::USERINFO_CLAIMS)
            .map(|c| c.value.clone())
            .collect(),
        id_token: Vec::new(),
    }
    .allowed(&client, &resources.identity_resources)
    .userinfo;
    for claim_type in resources
        .identity_resources
        .iter()
        .filter(|r| scopes.contains(&r.name.as_str()))
        .flat_map(|r| &r.user_claims)
        .chain(&asked)
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
    Ok(Ok((claims::to_dictionary(&outgoing), client)))
}
