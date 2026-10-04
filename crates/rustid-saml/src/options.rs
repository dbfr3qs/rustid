//! `SamlOptions`, with their defaults, read from the server's `[saml]` section
//! (in snake_case).

use std::collections::BTreeMap;

use rustid_core::options::TimeSpan;
use serde::Deserialize;

use crate::constants::*;
use crate::model::SigningBehavior;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SamlOptions {
    /// The IdP's entity id; unset, the issuer plus `entity_id_path`.
    pub entity_id: Option<String>,
    pub entity_id_path: String,
    pub want_authn_requests_signed: bool,
    pub default_claim_mappings: BTreeMap<String, String>,
    pub default_authn_context_mappings: BTreeMap<String, String>,
    pub supported_name_id_formats: Vec<String>,
    pub email_name_id_claim_type: String,
    pub default_clock_skew: TimeSpan,
    pub require_signed_logout_responses: bool,
    pub default_request_max_age: TimeSpan,
    pub default_assertion_lifetime: TimeSpan,
    pub signin_state_lifetime: TimeSpan,
    pub logout_session_lifetime: TimeSpan,
    pub default_signing_behavior: SigningBehavior,
    /// UTF-8 bytes.
    pub max_relay_state_length: usize,
    /// Characters.
    pub max_message_size: usize,
    pub endpoints: SamlEndpointOptions,
    pub metadata: SamlMetadataOptions,
}

impl Default for SamlOptions {
    fn default() -> Self {
        let map = |pairs: &[(&str, &str)]| {
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect()
        };
        SamlOptions {
            entity_id: None,
            entity_id_path: "/Saml2".into(),
            want_authn_requests_signed: true,
            default_claim_mappings: map(&[
                (
                    "name",
                    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
                ),
                (
                    "email",
                    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
                ),
                (
                    "role",
                    "http://schemas.xmlsoap.org/ws/2005/05/identity/role",
                ),
            ]),
            default_authn_context_mappings: map(&[
                ("pwd", AUTHN_CONTEXT_PASSWORD_PROTECTED),
                ("external", AUTHN_CONTEXT_UNSPECIFIED),
            ]),
            supported_name_id_formats: vec![NAME_ID_EMAIL.into(), NAME_ID_UNSPECIFIED.into()],
            email_name_id_claim_type: "email".into(),
            default_clock_skew: TimeSpan(300),
            require_signed_logout_responses: true,
            default_request_max_age: TimeSpan(300),
            default_assertion_lifetime: TimeSpan(300),
            signin_state_lifetime: TimeSpan(900),
            logout_session_lifetime: TimeSpan(300),
            default_signing_behavior: SigningBehavior::SignAssertion,
            max_relay_state_length: 80,
            max_message_size: 1_048_576,
            endpoints: SamlEndpointOptions::default(),
            metadata: SamlMetadataOptions::default(),
        }
    }
}

/// `SamlEndpointOptions`: paths and the bindings each endpoint accepts
/// (binding URIs; empty disables the endpoint).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SamlEndpointOptions {
    pub single_sign_on_service_path: String,
    pub single_sign_on_service_bindings: Vec<String>,
    pub single_sign_on_callback_path: String,
    pub single_logout_service_bindings: Vec<String>,
    pub single_logout_service_path: String,
    pub single_logout_callback_path: String,
    pub state_id_parameter_name: String,
}

impl Default for SamlEndpointOptions {
    fn default() -> Self {
        SamlEndpointOptions {
            single_sign_on_service_path: "/Saml2/SSO".into(),
            single_sign_on_service_bindings: vec![BINDING_REDIRECT.into(), BINDING_POST.into()],
            single_sign_on_callback_path: "/Saml2/SSO/Callback".into(),
            single_logout_service_bindings: vec![BINDING_REDIRECT.into(), BINDING_POST.into()],
            single_logout_service_path: "/Saml2/SLO".into(),
            single_logout_callback_path: "/Saml2/SLO/Callback".into(),
            state_id_parameter_name: "samlStateId".into(),
        }
    }
}

/// `SamlMetadataOptions`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SamlMetadataOptions {
    pub cache_duration: TimeSpan,
    pub expiry_duration: TimeSpan,
}

impl Default for SamlMetadataOptions {
    fn default() -> Self {
        SamlMetadataOptions {
            cache_duration: TimeSpan(43_200),
            expiry_duration: TimeSpan(432_000),
        }
    }
}
