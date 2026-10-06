//! Events: `Event`, their ids, the event service gating by
//! `EventsOptions`, and a sink that writes events to the log.
//! Phase 2 adds the events hook as another sink.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::options::EventsOptions;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum EventType {
    Success,
    Failure,
    Information,
    Error,
}

/// Event ids.
pub mod ids {
    pub const USER_LOGIN_SUCCESS: i32 = 1000;
    pub const USER_LOGIN_FAILURE: i32 = 1001;
    pub const USER_LOGOUT_SUCCESS: i32 = 1002;
    pub const USER_LOGOUT_FAILURE: i32 = 1003;
    pub const CLIENT_AUTHENTICATION_SUCCESS: i32 = 1010;
    pub const CLIENT_AUTHENTICATION_FAILURE: i32 = 1011;
    pub const API_AUTHENTICATION_SUCCESS: i32 = 1020;
    pub const API_AUTHENTICATION_FAILURE: i32 = 1021;
    pub const TOKEN_ISSUED_SUCCESS: i32 = 2000;
    pub const TOKEN_ISSUED_FAILURE: i32 = 2001;
    pub const TOKEN_REVOKED_SUCCESS: i32 = 2010;
    pub const TOKEN_INTROSPECTION_SUCCESS: i32 = 2020;
    pub const TOKEN_INTROSPECTION_FAILURE: i32 = 2021;
    pub const DEVICE_AUTHORIZATION_SUCCESS: i32 = 5000;
    pub const DEVICE_AUTHORIZATION_FAILURE: i32 = 5001;
    pub const BACKCHANNEL_AUTHENTICATION_SUCCESS: i32 = 6000;
    pub const BACKCHANNEL_AUTHENTICATION_FAILURE: i32 = 6001;
    pub const UNHANDLED_EXCEPTION: i32 = 3000;
    pub const INVALID_CLIENT_CONFIGURATION: i32 = 3001;
    pub const SAML_SSO_SUCCESS: i32 = 8000;
    pub const SAML_SSO_FAILURE: i32 = 8001;
    pub const SAML_SLO_SUCCESS: i32 = 8010;
    pub const SAML_SLO_FAILURE: i32 = 8011;
    pub const SAML_AUTHN_REQUEST_VALIDATION_FAILURE: i32 = 8020;
    pub const SAML_LOGOUT_REQUEST_VALIDATION_FAILURE: i32 = 8021;
}

/// An event as it is serialised: common properties, then the event's own.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Event {
    pub category: &'static str,
    pub name: &'static str,
    pub event_type: EventType,
    pub id: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activity_id: Option<String>,
    pub time_stamp: DateTime<Utc>,
    pub process_id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_ip_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_ip_address: Option<String>,
    #[serde(flatten)]
    pub details: EventDetails,
}

/// An issued token in the token issued success event, its value obfuscated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct IssuedToken {
    pub token_type: &'static str,
    pub token_value: String,
}

/// Each event's own properties, serialised beside the common ones.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged, rename_all_fields = "PascalCase")]
pub enum EventDetails {
    UserLoginSuccess {
        provider: String,
        provider_user_id: String,
        subject_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        client_id: Option<String>,
    },
    UserLogoutSuccess {
        provider: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        sub: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        sid: Option<String>,
        channel: &'static str,
    },
    UserLogoutFailure {
        provider: String,
        reason: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
        channel: &'static str,
    },
    UserLoginFailure {
        provider: String,
        reason: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        client_id: Option<String>,
    },
    ClientAuthenticationSuccess {
        client_id: String,
        authentication_method: String,
    },
    ClientAuthenticationFailure {
        client_id: String,
    },
    ApiAuthenticationSuccess {
        api_name: String,
        authentication_method: String,
    },
    ApiAuthenticationFailure {
        api_name: String,
    },
    TokenIssuedSuccess {
        client_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        client_name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        redirect_uri: Option<String>,
        endpoint: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        subject_id: Option<String>,
        scopes: String,
        grant_type: String,
        tokens: Vec<IssuedToken>,
    },
    BackchannelAuthentication {
        #[serde(skip_serializing_if = "Option::is_none")]
        client_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        client_name: Option<String>,
        endpoint: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        subject_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        scopes: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error_description: Option<String>,
    },
    DeviceAuthorization {
        #[serde(skip_serializing_if = "Option::is_none")]
        client_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        client_name: Option<String>,
        endpoint: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        scopes: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error_description: Option<String>,
    },
    TokenIssuedFailure {
        #[serde(skip_serializing_if = "Option::is_none")]
        client_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        client_name: Option<String>,
        endpoint: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        redirect_uri: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        subject_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        scopes: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        grant_type: Option<String>,
        error: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        error_description: Option<String>,
    },
    TokenIntrospectionSuccess {
        #[serde(skip_serializing_if = "Option::is_none")]
        api_name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        client_name: Option<String>,
        is_active: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        token: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        claim_types: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        token_scopes: Option<Vec<String>>,
    },
    TokenIntrospectionFailure {
        api_name: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        token: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        api_scopes: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        token_scopes: Option<Vec<String>>,
    },
    TokenRevokedSuccess {
        client_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        client_name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        token_type: Option<String>,
        token: String,
    },
    UnhandledException {
        details: String,
    },
    InvalidClientConfiguration {
        client_id: String,
        client_name: String,
    },
    SamlSsoSuccess {
        sp_entity_id: String,
        subject_id: Option<String>,
        session_index: String,
        binding: String,
        name_id_format: Option<String>,
    },
    SamlSsoFailure {
        sp_entity_id: Option<String>,
        error: String,
        endpoint: String,
    },
    SamlSloSuccess {
        sp_entity_id: String,
        session_index: Option<String>,
        initiator: String,
    },
    SamlSloFailure {
        sp_entity_id: Option<String>,
        error: String,
    },
    SamlLogoutRequestValidationFailure {
        sp_entity_id: Option<String>,
        error: String,
        binding: Option<String>,
    },
    SamlAuthnRequestValidationFailure {
        sp_entity_id: Option<String>,
        error: String,
        binding: Option<String>,
    },
}

/// Obfuscated: `****` and the last four characters.
pub fn obfuscate(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let last4: String = if chars.len() > 4 {
        chars[chars.len() - 4..].iter().collect()
    } else {
        "****".into()
    };
    format!("****{last4}")
}

impl Event {
    fn new(
        category: &'static str,
        name: &'static str,
        event_type: EventType,
        id: i32,
        message: Option<String>,
        details: EventDetails,
    ) -> Self {
        Event {
            category,
            name,
            event_type,
            id,
            message,
            activity_id: None,
            time_stamp: DateTime::<Utc>::MIN_UTC,
            process_id: 0,
            local_ip_address: None,
            remote_ip_address: None,
            details,
        }
    }

    pub fn client_authentication_success(client_id: &str, method: &str) -> Self {
        Event::new(
            "Authentication",
            "Client Authentication Success",
            EventType::Success,
            ids::CLIENT_AUTHENTICATION_SUCCESS,
            None,
            EventDetails::ClientAuthenticationSuccess {
                client_id: client_id.to_owned(),
                authentication_method: method.to_owned(),
            },
        )
    }

    pub fn client_authentication_failure(client_id: &str, message: &str) -> Self {
        Event::new(
            "Authentication",
            "Client Authentication Failure",
            EventType::Failure,
            ids::CLIENT_AUTHENTICATION_FAILURE,
            Some(message.to_owned()),
            EventDetails::ClientAuthenticationFailure {
                client_id: client_id.to_owned(),
            },
        )
    }

    pub fn api_authentication_success(api_name: &str, method: &str) -> Self {
        Event::new(
            "Authentication",
            "API Authentication Success",
            EventType::Success,
            ids::API_AUTHENTICATION_SUCCESS,
            None,
            EventDetails::ApiAuthenticationSuccess {
                api_name: api_name.to_owned(),
                authentication_method: method.to_owned(),
            },
        )
    }

    pub fn api_authentication_failure(api_name: &str, message: &str) -> Self {
        Event::new(
            "Authentication",
            "API Authentication Failure",
            EventType::Failure,
            ids::API_AUTHENTICATION_FAILURE,
            Some(message.to_owned()),
            EventDetails::ApiAuthenticationFailure {
                api_name: api_name.to_owned(),
            },
        )
    }

    /// A user signed in through an upstream provider.
    pub fn user_login_success(details: EventDetails) -> Self {
        Event::new(
            "Authentication",
            "User Login Success",
            EventType::Success,
            ids::USER_LOGIN_SUCCESS,
            None,
            details,
        )
    }

    /// An upstream sign-in failed.
    pub fn user_login_failure(details: EventDetails) -> Self {
        Event::new(
            "Authentication",
            "User Login Failure",
            EventType::Failure,
            ids::USER_LOGIN_FAILURE,
            None,
            details,
        )
    }

    /// An upstream provider signed the user out of rustid.
    pub fn user_logout_success(details: EventDetails) -> Self {
        Event::new(
            "Authentication",
            "User Logout Success",
            EventType::Success,
            ids::USER_LOGOUT_SUCCESS,
            None,
            details,
        )
    }

    /// An upstream provider's logout request was refused.
    pub fn user_logout_failure(details: EventDetails) -> Self {
        Event::new(
            "Authentication",
            "User Logout Failure",
            EventType::Failure,
            ids::USER_LOGOUT_FAILURE,
            None,
            details,
        )
    }

    /// A CIBA request was allowed.
    pub fn backchannel_authentication_success(details: EventDetails) -> Self {
        Event::new(
            "BackchannelAuthentication",
            "Backchannel Authentication Success",
            EventType::Success,
            ids::BACKCHANNEL_AUTHENTICATION_SUCCESS,
            None,
            details,
        )
    }

    /// A CIBA request was refused or failed.
    pub fn backchannel_authentication_failure(details: EventDetails) -> Self {
        Event::new(
            "BackchannelAuthentication",
            "Backchannel Authentication Failure",
            EventType::Failure,
            ids::BACKCHANNEL_AUTHENTICATION_FAILURE,
            None,
            details,
        )
    }

    /// A device authorization was approved.
    pub fn device_authorization_success(details: EventDetails) -> Self {
        Event::new(
            "Device",
            "Device Authorization Success",
            EventType::Success,
            ids::DEVICE_AUTHORIZATION_SUCCESS,
            None,
            details,
        )
    }

    /// A device authorization was denied or failed.
    pub fn device_authorization_failure(details: EventDetails) -> Self {
        Event::new(
            "Device",
            "Device Authorization Failure",
            EventType::Failure,
            ids::DEVICE_AUTHORIZATION_FAILURE,
            None,
            details,
        )
    }

    pub fn token_issued_success(details: EventDetails) -> Self {
        Event::new(
            "Token",
            "Token Issued Success",
            EventType::Success,
            ids::TOKEN_ISSUED_SUCCESS,
            None,
            details,
        )
    }

    pub fn token_issued_failure(details: EventDetails) -> Self {
        Event::new(
            "Token",
            "Token Issued Failure",
            EventType::Failure,
            ids::TOKEN_ISSUED_FAILURE,
            None,
            details,
        )
    }

    pub fn token_introspection_success(details: EventDetails) -> Self {
        Event::new(
            "Token",
            "Token Introspection Success",
            EventType::Success,
            ids::TOKEN_INTROSPECTION_SUCCESS,
            None,
            details,
        )
    }

    pub fn token_introspection_failure(message: &str, details: EventDetails) -> Self {
        Event::new(
            "Token",
            "Token Introspection Failure",
            EventType::Failure,
            ids::TOKEN_INTROSPECTION_FAILURE,
            Some(message.to_owned()),
            details,
        )
    }

    pub fn token_revoked_success(
        client_id: &str,
        client_name: Option<&str>,
        token_type: Option<&str>,
        token: &str,
    ) -> Self {
        Event::new(
            "Token",
            "Token Revoked Success",
            EventType::Success,
            ids::TOKEN_REVOKED_SUCCESS,
            None,
            EventDetails::TokenRevokedSuccess {
                client_id: client_id.to_owned(),
                client_name: client_name.map(str::to_owned),
                token_type: token_type.map(str::to_owned),
                token: obfuscate(token),
            },
        )
    }

    pub fn unhandled_exception(message: &str) -> Self {
        Event::new(
            "Error",
            "Unhandled Exception",
            EventType::Error,
            ids::UNHANDLED_EXCEPTION,
            Some(message.to_owned()),
            EventDetails::UnhandledException {
                details: message.to_owned(),
            },
        )
    }

    /// A SAML response was issued to a service provider.
    pub fn saml_sso_success(
        sp_entity_id: &str,
        subject_id: Option<&str>,
        session_index: &str,
        binding: &str,
        name_id_format: Option<&str>,
    ) -> Self {
        Event::new(
            "Saml",
            "SAML SSO Success",
            EventType::Success,
            ids::SAML_SSO_SUCCESS,
            None,
            EventDetails::SamlSsoSuccess {
                sp_entity_id: sp_entity_id.to_owned(),
                subject_id: subject_id.map(str::to_owned),
                session_index: session_index.to_owned(),
                binding: binding.to_owned(),
                name_id_format: name_id_format.map(str::to_owned),
            },
        )
    }

    /// SAML single sign-on failed.
    pub fn saml_sso_failure(sp_entity_id: Option<&str>, error: &str, endpoint: &str) -> Self {
        Event::new(
            "Saml",
            "SAML SSO Failure",
            EventType::Failure,
            ids::SAML_SSO_FAILURE,
            None,
            EventDetails::SamlSsoFailure {
                sp_entity_id: sp_entity_id.map(str::to_owned),
                error: error.to_owned(),
                endpoint: endpoint.to_owned(),
            },
        )
    }

    /// SAML single logout completed for a service provider.
    pub fn saml_slo_success(
        sp_entity_id: &str,
        session_index: Option<&str>,
        initiator: &str,
    ) -> Self {
        Event::new(
            "Saml",
            "SAML SLO Success",
            EventType::Success,
            ids::SAML_SLO_SUCCESS,
            None,
            EventDetails::SamlSloSuccess {
                sp_entity_id: sp_entity_id.to_owned(),
                session_index: session_index.map(str::to_owned),
                initiator: initiator.to_owned(),
            },
        )
    }

    /// SAML single logout failed.
    pub fn saml_slo_failure(sp_entity_id: Option<&str>, error: &str) -> Self {
        Event::new(
            "Saml",
            "SAML SLO Failure",
            EventType::Failure,
            ids::SAML_SLO_FAILURE,
            None,
            EventDetails::SamlSloFailure {
                sp_entity_id: sp_entity_id.map(str::to_owned),
                error: error.to_owned(),
            },
        )
    }

    /// A SAML logout request failed validation.
    pub fn saml_logout_request_validation_failure(
        sp_entity_id: Option<&str>,
        error: &str,
        binding: Option<&str>,
    ) -> Self {
        Event::new(
            "Saml",
            "SAML LogoutRequest Validation Failure",
            EventType::Failure,
            ids::SAML_LOGOUT_REQUEST_VALIDATION_FAILURE,
            None,
            EventDetails::SamlLogoutRequestValidationFailure {
                sp_entity_id: sp_entity_id.map(str::to_owned),
                error: error.to_owned(),
                binding: binding.map(str::to_owned),
            },
        )
    }

    /// A SAML AuthnRequest failed validation.
    pub fn saml_authn_request_validation_failure(
        sp_entity_id: Option<&str>,
        error: &str,
        binding: Option<&str>,
    ) -> Self {
        Event::new(
            "Saml",
            "SAML AuthnRequest Validation Failure",
            EventType::Failure,
            ids::SAML_AUTHN_REQUEST_VALIDATION_FAILURE,
            None,
            EventDetails::SamlAuthnRequestValidationFailure {
                sp_entity_id: sp_entity_id.map(str::to_owned),
                error: error.to_owned(),
                binding: binding.map(str::to_owned),
            },
        )
    }

    pub fn invalid_client_configuration(
        client_id: &str,
        client_name: Option<&str>,
        message: &str,
    ) -> Self {
        Event::new(
            "Error",
            "Invalid Client Configuration",
            EventType::Error,
            ids::INVALID_CLIENT_CONFIGURATION,
            Some(message.to_owned()),
            EventDetails::InvalidClientConfiguration {
                client_id: client_id.to_owned(),
                client_name: client_name.unwrap_or("unknown name").to_owned(),
            },
        )
    }
}

/// Where raised events go.
pub trait EventSink: Send + Sync {
    fn persist(&self, event: &Event);
}

/// Each event as JSON in an information log line.
#[derive(Debug, Default, Clone, Copy)]
pub struct LogEventSink;

impl EventSink for LogEventSink {
    fn persist(&self, event: &Event) {
        match serde_json::to_string(event) {
            Ok(json) => tracing::info!(target: "rustid::events", event = %json, "{}", event.name),
            Err(error) => tracing::error!(%error, "serialising an event failed"),
        }
    }
}

/// Where the request came from, for events.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestInfo {
    /// The W3C trace context id of the request, when traced.
    pub activity_id: Option<String>,
    pub local_ip_address: Option<String>,
    pub remote_ip_address: Option<String>,
}

/// Raises an event when its type is enabled.
#[derive(Clone)]
pub struct EventService {
    options: EventsOptions,
    sink: Arc<dyn EventSink>,
}

impl std::fmt::Debug for EventService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventService")
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

impl Default for EventService {
    /// Every event type off, logging when enabled.
    fn default() -> Self {
        EventService::new(EventsOptions::default(), Arc::new(LogEventSink))
    }
}

impl EventService {
    pub fn new(options: EventsOptions, sink: Arc<dyn EventSink>) -> Self {
        EventService { options, sink }
    }

    /// Whether events of this type are raised, by the options.
    pub fn can_raise(&self, event_type: EventType) -> bool {
        match event_type {
            EventType::Success => self.options.raise_success_events,
            EventType::Failure => self.options.raise_failure_events,
            EventType::Information => self.options.raise_information_events,
            EventType::Error => self.options.raise_error_events,
        }
    }

    /// Stamps the event with the request, time and process and persists it
    /// when its type is enabled.
    pub fn raise(&self, request: &RequestInfo, now: DateTime<Utc>, mut event: Event) {
        if !self.can_raise(event.event_type) {
            return;
        }
        event.activity_id = request.activity_id.clone();
        event.local_ip_address = request.local_ip_address.clone();
        event.remote_ip_address = request.remote_ip_address.clone();
        event.time_stamp = now;
        event.process_id = std::process::id();
        self.sink.persist(&event);
    }
}
