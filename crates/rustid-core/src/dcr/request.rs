//! `DynamicClientRegistrationRequest`: the registration body.

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The client's metadata (RFC 7591 and the server's own members). Members it doesn't
/// know are kept in `extensions` (`[JsonExtensionData]`) and echoed back.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct RegistrationRequest {
    pub redirect_uris: Option<Vec<String>>,
    #[serde(default, deserialize_with = "null_as_empty")]
    pub grant_types: Vec<String>,
    pub client_name: Option<String>,
    pub logo_uri: Option<String>,
    pub client_uri: Option<String>,
    pub jwks_uri: Option<String>,
    pub jwks: Option<KeySet>,
    pub scope: Option<String>,
    pub post_logout_redirect_uris: Option<Vec<String>>,
    pub frontchannel_logout_uri: Option<String>,
    pub frontchannel_logout_session_required: Option<bool>,
    pub backchannel_logout_uri: Option<String>,
    pub backchannel_logout_session_required: Option<bool>,
    pub software_statement: Option<String>,
    pub software_id: Option<String>,
    pub software_version: Option<String>,
    pub require_signed_request_object: Option<bool>,
    pub token_endpoint_auth_method: Option<String>,
    pub default_max_age: Option<i32>,
    pub initiate_login_uri: Option<String>,
    pub identity_token_lifetime: Option<i32>,
    pub access_token_lifetime: Option<i32>,
    pub authorization_code_lifetime: Option<i32>,
    pub absolute_refresh_token_lifetime: Option<i32>,
    pub sliding_refresh_token_lifetime: Option<i32>,
    pub refresh_token_expiration: Option<String>,
    pub refresh_token_usage: Option<String>,
    pub update_access_token_claims_on_refresh: Option<bool>,
    pub require_consent: Option<bool>,
    pub allow_remember_consent: Option<bool>,
    pub consent_lifetime: Option<i32>,
    pub access_token_type: Option<String>,
    pub allowed_cors_origins: Option<Vec<String>>,
    pub require_client_secret: Option<bool>,
    pub enable_local_login: Option<bool>,
    pub identity_provider_restrictions: Option<Vec<String>>,
    pub coordinate_lifetime_with_user_session: Option<bool>,
    pub allowed_identity_token_signing_algorithms: Option<Vec<String>>,
    #[serde(flatten)]
    pub extensions: IndexMap<String, Value>,
}

/// `KeySet`: `{"keys": [...]}`, each key any JSON.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
pub struct KeySet {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<Vec<Value>>,
}

/// A null `grant_types` is no grant types.
fn null_as_empty<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    Ok(Option::<Vec<String>>::deserialize(d)?.unwrap_or_default())
}
