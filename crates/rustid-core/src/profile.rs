//! The profile service: which claims describe a subject
//! in tokens and userinfo, and whether the subject is still active. The
//! default filters the subject's own claims; hooks can replace it.

use async_trait::async_trait;

use crate::clients::Client;
use crate::tokens::{Claim, PROTOCOL_CLAIM_TYPES};

/// Who asks the profile service for claims.
pub mod callers {
    pub const USERINFO_ENDPOINT: &str = "UserInfoEndpoint";
    pub const IDENTITY_TOKEN: &str = "ClaimsProviderIdentityToken";
    pub const ACCESS_TOKEN: &str = "ClaimsProviderAccessToken";
}

/// Who asks the profile service whether a user is active.
pub mod active_callers {
    pub const AUTHORIZE_ENDPOINT: &str = "AuthorizeEndpoint";
    pub const AUTHORIZATION_CODE: &str = "AuthorizationCodeValidation";
    pub const ACCESS_TOKEN: &str = "AccessTokenValidation";
    pub const USERINFO_REQUEST: &str = "UserInfoRequestValidation";
    pub const REFRESH_TOKEN: &str = "RefreshTokenValidation";
    pub const RESOURCE_OWNER: &str = "ResourceOwnerValidation";
    pub const EXTENSION_GRANT: &str = "ExtensionGrantValidation";
    pub const DEVICE_CODE: &str = "DeviceCodeValidation";
    pub const BACKCHANNEL_AUTHENTICATION: &str = "BackchannelAuthenticationRequestIdValidation";
}

/// Who asks, for which client and subject,
/// and which claim types the resources request.
#[derive(Debug, Clone, Copy)]
pub struct ProfileRequest<'a> {
    pub caller: &'a str,
    pub client: &'a Client,
    pub subject_id: &'a str,
    /// The subject's claims besides `sub`.
    pub subject_claims: &'a [Claim],
    pub requested_claim_types: &'a [String],
}

/// What the profile service is asked when checking a subject is active.
#[derive(Debug, Clone, Copy)]
pub struct ActiveRequest<'a> {
    pub caller: &'a str,
    pub client: &'a Client,
    pub subject_id: &'a str,
    pub subject_claims: &'a [Claim],
}

/// A profile service failure; the request fails with a server error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("profile service: {0}")]
pub struct ProfileError(pub String);

#[async_trait]
pub trait ProfileService: Send + Sync {
    /// The claims to issue. Protocol claims among
    /// them are dropped by the caller.
    async fn profile_claims(
        &self,
        request: &ProfileRequest<'_>,
    ) -> Result<Vec<Claim>, ProfileError>;

    async fn is_active(&self, request: &ActiveRequest<'_>) -> Result<bool, ProfileError>;
}

/// `DefaultProfileService`: the subject's claims of the requested types
///; every subject is active.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultProfileService;

#[async_trait]
impl ProfileService for DefaultProfileService {
    async fn profile_claims(
        &self,
        request: &ProfileRequest<'_>,
    ) -> Result<Vec<Claim>, ProfileError> {
        Ok(requested_claims(
            request.subject_claims,
            request.requested_claim_types,
        ))
    }

    async fn is_active(&self, _: &ActiveRequest<'_>) -> Result<bool, ProfileError> {
        Ok(true)
    }
}

/// The claims whose type was requested.
pub fn requested_claims(claims: &[Claim], requested: &[String]) -> Vec<Claim> {
    claims
        .iter()
        .filter(|c| requested.contains(&c.claim_type))
        .cloned()
        .collect()
}

/// What a profile service may not set.
pub fn without_protocol_claims(claims: Vec<Claim>) -> Vec<Claim> {
    claims
        .into_iter()
        .filter(|c| !PROTOCOL_CLAIM_TYPES.contains(&c.claim_type.as_str()))
        .collect()
}
