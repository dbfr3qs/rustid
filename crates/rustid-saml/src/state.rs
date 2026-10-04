//! What the SAML IdP keeps between requests: sign-in state across the login
//! round trip (`SamlAuthenticationState`) and logout sessions collecting
//! service providers' logout responses (`SamlLogoutSession`).

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::model::IndexedEndpoint;

/// `StoredRequestedAuthnContext`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestedAuthnContext {
    pub comparison: Option<String>,
    #[serde(default)]
    pub authn_context_class_ref: Vec<String>,
    #[serde(default)]
    pub authn_context_decl_ref: Vec<String>,
}

/// `StoredAuthnRequestData`: what the callback needs from the AuthnRequest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredAuthnRequest {
    pub request_id: Option<String>,
    #[serde(default)]
    pub force_authn: bool,
    #[serde(default)]
    pub is_passive: bool,
    pub name_id_policy_format: Option<String>,
    pub subject_name_id_value: Option<String>,
    pub idp_hint_provider_id: Option<String>,
    pub requested_authn_context: Option<RequestedAuthnContext>,
}

/// `SamlAuthenticationState`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationState {
    pub authn_request_data: Option<StoredAuthnRequest>,
    pub service_provider_entity_id: String,
    pub relay_state: Option<String>,
    #[serde(default)]
    pub is_idp_initiated: bool,
    pub created_utc: DateTime<Utc>,
    pub assertion_consumer_service: IndexedEndpoint,
    #[serde(default)]
    pub requested_claim_types: Vec<String>,
    /// Required when storing.
    pub expires_at_utc: Option<DateTime<Utc>>,
    /// An interaction denial (`InteractionError`), by name.
    pub denial_error: Option<String>,
    pub denial_error_description: Option<String>,
}

/// `SamlSpLogoutResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpLogoutResponse {
    pub success: bool,
    pub received_utc: DateTime<Utc>,
}

/// `ExpectedSpLogout`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExpectedSpLogout {
    pub sp_entity_id: String,
    pub response: Option<SpLogoutResponse>,
}

/// `SamlLogoutSession`: the LogoutRequests sent, by request id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogoutSession {
    pub logout_id: String,
    pub expected_responses: BTreeMap<String, ExpectedSpLogout>,
    #[serde(default)]
    pub skipped_sp_count: i32,
    pub created_utc: DateTime<Utc>,
    /// Required when storing.
    pub expires_at_utc: Option<DateTime<Utc>>,
}
