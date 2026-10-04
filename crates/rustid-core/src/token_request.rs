//! The custom token request validator:
//! consulted after a token request passed the standard validation, it may
//! refuse the request and may add fields to the response or the error.
//! Hooks can replace the default, which accepts everything.

use async_trait::async_trait;
use serde_json::{Map, Value};

use crate::clients::Client;
use crate::profile::ProfileError;

/// What the validator is told about a request that passed validation.
#[derive(Debug, Clone, Copy)]
pub struct TokenRequest<'a> {
    pub grant_type: &'a str,
    pub client: &'a Client,
    /// The user the tokens are for, when there is one.
    pub subject_id: Option<&'a str>,
    /// The scopes the tokens would carry.
    pub scopes: &'a [String],
    /// The request's parameters, without credentials, codes, verifiers and
    /// refresh tokens.
    pub parameters: &'a [(String, String)],
}

/// The validator's answer.
#[derive(Debug, Clone, PartialEq)]
pub enum TokenRequestVerdict {
    /// Issue the tokens, adding `custom` to the response.
    Accept { custom: Map<String, Value> },
    /// Refuse with this OAuth error (HTTP 400), adding `custom` to it.
    Reject {
        error: String,
        description: Option<String>,
        custom: Map<String, Value>,
    },
}

#[async_trait]
pub trait TokenRequestValidator: Send + Sync {
    async fn validate(
        &self,
        request: &TokenRequest<'_>,
    ) -> Result<TokenRequestVerdict, ProfileError>;
}

/// Accepts every request as it is.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultTokenRequestValidator;

#[async_trait]
impl TokenRequestValidator for DefaultTokenRequestValidator {
    async fn validate(&self, _: &TokenRequest<'_>) -> Result<TokenRequestVerdict, ProfileError> {
        Ok(TokenRequestVerdict::Accept { custom: Map::new() })
    }
}

/// Parameters never passed to the validator.
pub const WITHHELD_PARAMETERS: &[&str] = &[
    "client_secret",
    "client_assertion",
    "code",
    "code_verifier",
    "refresh_token",
    "password",
];
