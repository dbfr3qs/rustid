//! The password and extension grant validators (the resource owner password validator,
//! the extension grant validator). The server supplies hooks; the default
//! supports neither grant.

use async_trait::async_trait;
use serde_json::{Map, Value};

use crate::clients::{AccessTokenType, Client};
use crate::profile::ProfileError;
use crate::tokens::Claim;

/// A password grant request, as the validator sees it.
#[derive(Debug, Clone, Copy)]
pub struct PasswordRequest<'a> {
    pub client: &'a Client,
    pub username: &'a str,
    pub password: &'a str,
    /// The request's parameters, without credentials and the password.
    pub parameters: &'a [(String, String)],
}

/// An extension grant request.
#[derive(Debug, Clone, Copy)]
pub struct ExtensionRequest<'a> {
    pub grant_type: &'a str,
    pub client: &'a Client,
    /// The request's parameters, without credentials.
    pub parameters: &'a [(String, String)],
}

/// The user a grant authenticated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantSubject {
    pub subject_id: String,
    /// The authentication method, the token's `amr`.
    pub authentication_method: String,
    /// `local` when absent.
    pub idp: Option<String>,
    pub claims: Vec<Claim>,
}

/// A validator's verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantResult {
    Subject(GrantSubject),
    /// Valid, with no user: a client token (extension grants only).
    NoSubject,
    Error {
        /// `invalid_grant` when absent.
        error: Option<String>,
        description: Option<String>,
    },
}

/// Changes an extension grant validator makes to the request,
/// which the token request applies after validation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestChanges {
    /// Issue the token to this client instead (impersonation).
    pub client_id: Option<String>,
    pub access_token_lifetime: Option<i64>,
    pub access_token_type: Option<AccessTokenType>,
    /// Added to the client's claims.
    pub client_claims: Vec<Claim>,
}

/// A validator's full answer.
#[derive(Debug, Clone, PartialEq)]
pub struct GrantAnswer {
    pub result: GrantResult,
    /// Custom response parameters, on success and on error.
    pub custom: Map<String, Value>,
    pub changes: RequestChanges,
}

impl GrantAnswer {
    pub fn error(error: &str) -> GrantAnswer {
        GrantAnswer {
            result: GrantResult::Error {
                error: Some(error.to_owned()),
                description: None,
            },
            custom: Map::new(),
            changes: RequestChanges::default(),
        }
    }
}

#[async_trait]
pub trait GrantValidator: Send + Sync {
    /// Whether the password grant is supported (discovery).
    fn supports_password(&self) -> bool;

    /// The extension grant types there are validators for.
    fn extension_grant_types(&self) -> Vec<String>;

    async fn validate_password(
        &self,
        request: &PasswordRequest<'_>,
    ) -> Result<GrantAnswer, ProfileError>;

    async fn validate_extension(
        &self,
        request: &ExtensionRequest<'_>,
    ) -> Result<GrantAnswer, ProfileError>;
}

/// No password validator and
/// no extension grants.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoGrantValidator;

#[async_trait]
impl GrantValidator for NoGrantValidator {
    fn supports_password(&self) -> bool {
        false
    }

    fn extension_grant_types(&self) -> Vec<String> {
        Vec::new()
    }

    async fn validate_password(
        &self,
        _: &PasswordRequest<'_>,
    ) -> Result<GrantAnswer, ProfileError> {
        Ok(GrantAnswer::error("unsupported_grant_type"))
    }

    async fn validate_extension(
        &self,
        _: &ExtensionRequest<'_>,
    ) -> Result<GrantAnswer, ProfileError> {
        Ok(GrantAnswer::error("unsupported_grant_type"))
    }
}
