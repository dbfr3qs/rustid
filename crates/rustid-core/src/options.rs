//! Protocol options (`[protocol]`), with their defaults.
//!
//! Field names are snake_case. Unknown fields are rejected.

use indexmap::IndexMap;
use serde::{Deserialize, Deserializer};

/// The RS, PS and ES families, in their default order.
pub const DEFAULT_SIGNING_ALGORITHMS: &[&str] = &[
    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512",
];

/// The supported prompt modes.
pub const DEFAULT_PROMPT_VALUES: &[&str] = &["none", "login", "consent", "select_account"];

fn owned(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| (*v).to_owned()).collect()
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProtocolOptions {
    /// Fixed issuer. When absent the issuer is derived from each request.
    pub issuer_uri: Option<String>,
    pub lower_case_issuer_uri: bool,
    pub emit_issuer_identification_response_parameter: bool,
    /// Adds `s_hash` (the state's hash) to identity tokens.
    pub emit_state_hash: bool,
    /// Sends the user to login when `acr_values` asks for a tenant other
    /// than the session's.
    pub validate_tenant_on_authorization: bool,
    pub endpoints: EndpointsOptions,
    /// The browser session: its cookie lifetime and the check session cookie.
    pub authentication: AuthenticationOptions,
    /// Content Security Policy headers on the pages the server renders.
    pub csp: CspOptions,
    pub discovery: DiscoveryOptions,
    pub user_interaction: UserInteractionOptions,
    pub pushed_authorization: PushedAuthorizationOptions,
    pub dpop: DPoPOptions,
    pub mutual_tls: MutualTlsOptions,
    pub device_flow: DeviceFlowOptions,
    pub ciba: CibaOptions,
    pub storage_purge: StoragePurgeOptions,
    pub outbox_processor: OutboxProcessorOptions,
    pub supported_client_assertion_signing_algorithms: Vec<String>,
    pub supported_request_object_signing_algorithms: Vec<String>,
    /// Request objects must be typed `oauth-authz-req+jwt`, and fetched ones
    /// served as `application/oauth-authz-req+jwt` (RFC 9101 strictness).
    pub strict_jar_validation: bool,
    pub input_length_restrictions: InputLengthRestrictions,
    /// `typ` header of JWT access tokens. Empty omits the header.
    pub access_token_jwt_type: String,
    /// The `typ` of back-channel logout tokens.
    pub logout_token_jwt_type: String,
    /// Server-side sessions, when enabled.
    pub server_side_sessions: ServerSideSessionOptions,
    /// Adds `{issuer}/resources` to every access token's audiences.
    pub emit_static_audience_claim: bool,
    /// Emits `scope` in JWTs as one space-delimited string instead of an array.
    pub emit_scopes_as_space_delimited_string_in_jwt: bool,
    /// Clock skew allowed when validating client assertions and other JWTs.
    pub jwt_validation_clock_skew: TimeSpan,
    /// Requires client assertions to use `typ: client-authentication+jwt`
    /// and the issuer as their only audience.
    pub strict_client_assertion_audience_validation: bool,
    /// JWT Secured Authorization Responses (JARM); off by default.
    pub jarm: JarmOptions,
    /// FAPI 2 Message Signing (5.3.1): request objects need `nbf`, may live
    /// at most this long after it, and `nbf` may be at most this old. Unset
    /// (the default), only `exp` is required.
    /// It governs CIBA's signed authentication requests too.
    pub request_object_max_lifetime: Option<TimeSpan>,
    /// How long cached store lookups live (used with the Postgres store).
    pub caching: CachingOptions,
    /// Automatic creation, rotation and retirement of signing keys.
    pub key_management: KeyManagementOptions,
    /// Which event types are raised (all off by default).
    pub events: EventsOptions,
    /// How persisted grants behave (`PersistentGrantOptions`).
    pub persistent_grants: PersistentGrantOptions,
}

/// Persisted grant options.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PersistentGrantOptions {
    /// One-time-only refresh tokens are deleted when used, rather than
    /// marked consumed.
    pub delete_one_time_only_refresh_tokens_on_use: bool,
}

impl Default for PersistentGrantOptions {
    fn default() -> Self {
        Self {
            delete_one_time_only_refresh_tokens_on_use: true,
        }
    }
}

impl Default for ProtocolOptions {
    fn default() -> Self {
        Self {
            issuer_uri: None,
            lower_case_issuer_uri: true,
            emit_issuer_identification_response_parameter: true,
            emit_state_hash: false,
            validate_tenant_on_authorization: false,
            endpoints: EndpointsOptions::default(),
            authentication: AuthenticationOptions::default(),
            csp: CspOptions::default(),
            discovery: DiscoveryOptions::default(),
            user_interaction: UserInteractionOptions::default(),
            pushed_authorization: PushedAuthorizationOptions::default(),
            dpop: DPoPOptions::default(),
            mutual_tls: MutualTlsOptions::default(),
            device_flow: DeviceFlowOptions::default(),
            ciba: CibaOptions::default(),
            storage_purge: StoragePurgeOptions::default(),
            outbox_processor: OutboxProcessorOptions::default(),
            supported_client_assertion_signing_algorithms: owned(DEFAULT_SIGNING_ALGORITHMS),
            supported_request_object_signing_algorithms: owned(DEFAULT_SIGNING_ALGORITHMS),
            strict_jar_validation: false,
            input_length_restrictions: InputLengthRestrictions::default(),
            access_token_jwt_type: "at+jwt".to_owned(),
            logout_token_jwt_type: "logout+jwt".to_owned(),
            server_side_sessions: ServerSideSessionOptions::default(),
            emit_static_audience_claim: false,
            emit_scopes_as_space_delimited_string_in_jwt: false,
            jwt_validation_clock_skew: TimeSpan(300),
            strict_client_assertion_audience_validation: false,
            jarm: JarmOptions::default(),
            request_object_max_lifetime: None,
            caching: CachingOptions::default(),
            key_management: KeyManagementOptions::default(),
            events: EventsOptions::default(),
            persistent_grants: PersistentGrantOptions::default(),
        }
    }
}

impl ProtocolOptions {
    /// Applies the startup adjustments. Setting
    /// `create_account_url` adds `create` to the supported prompt values.
    pub fn finalize(mut self) -> Self {
        let has_create = self
            .user_interaction
            .prompt_values_supported
            .iter()
            .any(|p| p == "create");
        if self.user_interaction.create_account_url.is_some() && !has_create {
            self.user_interaction
                .prompt_values_supported
                .push("create".to_owned());
        }
        self
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EndpointsOptions {
    pub enable_authorize_endpoint: bool,
    pub enable_jwt_request_uri: bool,
    pub enable_token_endpoint: bool,
    pub enable_user_info_endpoint: bool,
    pub enable_discovery_endpoint: bool,
    pub enable_end_session_endpoint: bool,
    pub enable_check_session_endpoint: bool,
    pub enable_token_revocation_endpoint: bool,
    pub enable_introspection_endpoint: bool,
    pub enable_device_authorization_endpoint: bool,
    pub enable_backchannel_authentication_endpoint: bool,
    pub enable_pushed_authorization_endpoint: bool,
    pub enable_oauth2_metadata_endpoint: bool,
}

impl Default for EndpointsOptions {
    fn default() -> Self {
        Self {
            enable_authorize_endpoint: true,
            enable_jwt_request_uri: false,
            enable_token_endpoint: true,
            enable_user_info_endpoint: true,
            enable_discovery_endpoint: true,
            enable_end_session_endpoint: true,
            enable_check_session_endpoint: true,
            enable_token_revocation_endpoint: true,
            enable_introspection_endpoint: true,
            enable_device_authorization_endpoint: true,
            enable_backchannel_authentication_endpoint: true,
            enable_pushed_authorization_endpoint: true,
            enable_oauth2_metadata_endpoint: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DiscoveryOptions {
    pub show_endpoints: bool,
    pub show_key_set: bool,
    pub show_identity_scopes: bool,
    pub show_api_scopes: bool,
    pub show_claims: bool,
    pub show_response_types: bool,
    pub show_response_modes: bool,
    pub show_grant_types: bool,
    pub show_extension_grant_types: bool,
    pub show_token_endpoint_authentication_methods: bool,
    pub show_revocation_endpoint_authentication_methods: bool,
    pub show_introspection_endpoint_authentication_methods: bool,
    pub expand_relative_paths_in_custom_entries: bool,
    /// Seconds for `Cache-Control: max-age`. Absent means no cache headers.
    pub response_cache_interval: Option<i64>,
    /// Extra entries appended to the document. Keys that collide with a
    /// standard entry are ignored.
    pub custom_entries: IndexMap<String, serde_json::Value>,
    /// `DynamicClientRegistrationDiscoveryOptions`: the `registration_endpoint`
    /// entry.
    pub dynamic_client_registration: DynamicClientRegistrationDiscoveryOptions,
}

/// `RegistrationEndpointMode`: whether and how discovery names the dynamic
/// client registration endpoint.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
pub enum RegistrationEndpointMode {
    #[default]
    None,
    /// `static_registration_endpoint`, when set.
    Static,
    /// `{base}/connect/dcr`.
    Inferred,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DynamicClientRegistrationDiscoveryOptions {
    pub registration_endpoint_mode: RegistrationEndpointMode,
    pub static_registration_endpoint: Option<String>,
}

impl Default for DiscoveryOptions {
    fn default() -> Self {
        Self {
            show_endpoints: true,
            show_key_set: true,
            show_identity_scopes: true,
            show_api_scopes: true,
            show_claims: true,
            show_response_types: true,
            show_response_modes: true,
            show_grant_types: true,
            show_extension_grant_types: true,
            show_token_endpoint_authentication_methods: true,
            show_revocation_endpoint_authentication_methods: true,
            show_introspection_endpoint_authentication_methods: true,
            expand_relative_paths_in_custom_entries: true,
            response_cache_interval: None,
            custom_entries: IndexMap::new(),
            dynamic_client_registration: Default::default(),
        }
    }
}

/// Authentication options: the parts the session uses.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthenticationOptions {
    /// How long a session lasts after sign-in (10 hours).
    pub cookie_lifetime: TimeSpan,
    /// The check session cookie, holding the session id for JavaScript
    /// clients (`idsrv.session`).
    pub check_session_cookie_name: String,
    /// End session parameters are ignored for anonymous users.
    pub require_authenticated_user_for_sign_out_message: bool,
    /// Every client's refresh tokens end with the user's session (clients
    /// can opt in or out with `coordinateLifetimeWithUserSession`).
    pub coordinate_client_lifetimes_with_user_session: bool,
    /// The end session callback sends a CSP `frame-src` for its iframes.
    pub require_csp_frame_src_for_signout: bool,
    /// Renews the session cookie once more of its lifetime has passed than
    /// remains.
    pub cookie_sliding_expiration: bool,
}

impl Default for AuthenticationOptions {
    fn default() -> Self {
        Self {
            cookie_lifetime: TimeSpan(10 * 3600),
            check_session_cookie_name: "idsrv.session".to_owned(),
            require_authenticated_user_for_sign_out_message: false,
            coordinate_client_lifetimes_with_user_session: false,
            require_csp_frame_src_for_signout: true,
            cookie_sliding_expiration: false,
        }
    }
}

/// Server-side session options.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerSideSessionOptions {
    /// The claim whose value is a session's display name.
    pub user_display_name_claim_type: Option<String>,
    /// Runs the job that removes expired sessions.
    pub remove_expired_sessions: bool,
    /// Expired sessions notify all their clients over the back channel, not
    /// only the coordinated ones.
    pub expired_sessions_trigger_backchannel_logout: bool,
    pub remove_expired_sessions_frequency: TimeSpan,
    /// Starts the job after a random part of the frequency.
    pub fuzz_expired_session_removal_start: bool,
    pub remove_expired_sessions_batch_size: usize,
}

impl Default for ServerSideSessionOptions {
    fn default() -> Self {
        Self {
            user_display_name_claim_type: None,
            remove_expired_sessions: true,
            expired_sessions_trigger_backchannel_logout: false,
            remove_expired_sessions_frequency: TimeSpan(10 * 60),
            fuzz_expired_session_removal_start: true,
            remove_expired_sessions_batch_size: 100,
        }
    }
}

/// Content Security Policy options.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CspOptions {
    pub level: CspLevel,
    /// Also send `X-Content-Security-Policy` for older browsers.
    pub add_deprecated_header: bool,
}

impl Default for CspOptions {
    fn default() -> Self {
        Self {
            level: CspLevel::Two,
            add_deprecated_header: true,
        }
    }
}

/// `CspLevel`: level one adds `'unsafe-inline'` for browsers without hash
/// support. Accepts the enum name or number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CspLevel {
    One,
    #[default]
    Two,
}

impl<'de> Deserialize<'de> for CspLevel {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Number(u8),
            Text(String),
        }
        match Raw::deserialize(deserializer)? {
            Raw::Number(0) => Ok(CspLevel::One),
            Raw::Number(1) => Ok(CspLevel::Two),
            Raw::Text(t) if t.eq_ignore_ascii_case("one") => Ok(CspLevel::One),
            Raw::Text(t) if t.eq_ignore_ascii_case("two") => Ok(CspLevel::Two),
            _ => Err(serde::de::Error::custom("csp.level must be One or Two")),
        }
    }
}

/// User interaction options. The login and logout defaults are the
/// cookie handler's, used when they are unset.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UserInteractionOptions {
    pub login_url: String,
    pub login_return_url_parameter: String,
    pub logout_url: String,
    pub logout_id_parameter: String,
    pub consent_url: String,
    pub consent_return_url_parameter: String,
    /// When set, `prompt=create` redirects here and is advertised.
    pub create_account_url: Option<String>,
    pub create_account_return_url_parameter: String,
    pub error_url: String,
    pub error_id_parameter: String,
    pub custom_redirect_return_url_parameter: String,
    pub prompt_values_supported: Vec<String>,
    /// Where users enter a device flow user code (local paths are made
    /// absolute with the request's base URL).
    pub device_verification_url: String,
    /// The user code's parameter in `verification_uri_complete`.
    pub device_verification_user_code_parameter: String,
}

impl Default for UserInteractionOptions {
    fn default() -> Self {
        Self {
            login_url: "/Account/Login".to_owned(),
            login_return_url_parameter: "ReturnUrl".to_owned(),
            logout_url: "/Account/Logout".to_owned(),
            logout_id_parameter: "logoutId".to_owned(),
            consent_url: "/consent".to_owned(),
            consent_return_url_parameter: "returnUrl".to_owned(),
            create_account_url: None,
            create_account_return_url_parameter: "returnUrl".to_owned(),
            error_url: "/home/error".to_owned(),
            error_id_parameter: "errorId".to_owned(),
            custom_redirect_return_url_parameter: "returnUrl".to_owned(),
            prompt_values_supported: owned(DEFAULT_PROMPT_VALUES),
            device_verification_url: "/device".to_owned(),
            device_verification_user_code_parameter: "userCode".to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PushedAuthorizationOptions {
    pub required: bool,
    /// Seconds a pushed request stays usable, unless the client says.
    pub lifetime: i64,
    /// Clients with a secret may push redirect URIs they did not register.
    pub allow_unregistered_pushed_redirect_uris: bool,
}

impl Default for PushedAuthorizationOptions {
    fn default() -> Self {
        Self {
            required: false,
            lifetime: 600,
            allow_unregistered_pushed_redirect_uris: false,
        }
    }
}

/// Event options.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EventsOptions {
    pub raise_success_events: bool,
    pub raise_failure_events: bool,
    pub raise_information_events: bool,
    pub raise_error_events: bool,
}

/// Key management options.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct KeyManagementOptions {
    pub enabled: bool,
    pub rsa_key_size: u32,
    /// Algorithms to keep a key for; empty means `RS256`. The first is the
    /// default signing algorithm.
    pub signing_algorithms: Vec<SigningAlgorithmOptions>,
    pub initialization_duration: TimeSpan,
    pub initialization_synchronization_delay: TimeSpan,
    pub initialization_key_cache_duration: TimeSpan,
    pub key_cache_duration: TimeSpan,
    /// How long a new key is announced before it signs.
    pub propagation_time: TimeSpan,
    /// How long a key signs before a new one takes over.
    pub rotation_interval: TimeSpan,
    /// How long a rotated-out key stays published for validation.
    pub retention_duration: TimeSpan,
    pub delete_retired_keys: bool,
    /// Protect stored keys with the data protection key ring.
    pub data_protect_keys: bool,
    /// Directory of the file system key store (the memory store kind). A
    /// relative path set in a configuration file is relative to that file;
    /// unset means `keys` in the working directory.
    pub key_path: Option<std::path::PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningAlgorithmOptions {
    pub name: String,
    #[serde(default)]
    pub use_x509_certificate: bool,
}

impl SigningAlgorithmOptions {
    pub fn is_rsa(&self) -> bool {
        self.name.starts_with('R') || self.name.starts_with('P')
    }

    pub fn is_ec(&self) -> bool {
        self.name.starts_with('E')
    }
}

impl Default for KeyManagementOptions {
    fn default() -> Self {
        const DAY: i64 = 24 * 60 * 60;
        Self {
            enabled: true,
            rsa_key_size: 2048,
            signing_algorithms: Vec::new(),
            initialization_duration: TimeSpan(5 * 60),
            initialization_synchronization_delay: TimeSpan(5),
            initialization_key_cache_duration: TimeSpan(60),
            key_cache_duration: TimeSpan(DAY),
            propagation_time: TimeSpan(14 * DAY),
            rotation_interval: TimeSpan(90 * DAY),
            retention_duration: TimeSpan(14 * DAY),
            delete_retired_keys: true,
            data_protect_keys: true,
            key_path: None,
        }
    }
}

impl KeyManagementOptions {
    /// `KeyManagementOptions.Validate`: defaults `RS256`, rejects bad values,
    /// and caps the key cache at half the propagation time.
    pub fn validated(mut self) -> Result<Self, String> {
        if self.signing_algorithms.is_empty() {
            self.signing_algorithms = vec![SigningAlgorithmOptions {
                name: "RS256".into(),
                use_x509_certificate: false,
            }];
        }
        let mut names: Vec<&str> = Vec::new();
        for alg in &self.signing_algorithms {
            if names.contains(&alg.name.as_str()) {
                return Err(format!(
                    "Duplicate signing algorithms not allowed: '{}'.",
                    alg.name
                ));
            }
            names.push(&alg.name);
        }
        let invalid: Vec<&str> = names
            .iter()
            .copied()
            .filter(|n| !DEFAULT_SIGNING_ALGORITHMS.contains(n))
            .collect();
        if !invalid.is_empty() {
            return Err(format!(
                "Invalid signing algorithm(s): '{}'.",
                invalid.join(", ")
            ));
        }
        if let Some(ec) = self
            .signing_algorithms
            .iter()
            .find(|a| a.is_ec() && a.use_x509_certificate)
        {
            return Err(format!(
                "UseX509Certificate not currently supported for EC keys. Signing algorithm(s): '{}'.",
                ec.name
            ));
        }
        if ![2048, 3072, 4096, 8192].contains(&self.rsa_key_size) {
            return Err(format!(
                "rsa_key_size must be 2048, 3072, 4096 or 8192, got {}",
                self.rsa_key_size
            ));
        }
        // Bounded so key ages and expiry instants can't overflow.
        const MAX_DAYS: i64 = 36_500;
        for (name, value) in [
            ("initialization_duration", self.initialization_duration),
            (
                "initialization_synchronization_delay",
                self.initialization_synchronization_delay,
            ),
            (
                "initialization_key_cache_duration",
                self.initialization_key_cache_duration,
            ),
            ("key_cache_duration", self.key_cache_duration),
            ("propagation_time", self.propagation_time),
            ("rotation_interval", self.rotation_interval),
            ("retention_duration", self.retention_duration),
        ] {
            if value.0 > MAX_DAYS * 24 * 60 * 60 {
                return Err(format!("{name} must be at most {MAX_DAYS} days."));
            }
        }
        for (name, value) in [
            ("initialization_duration", self.initialization_duration),
            (
                "initialization_synchronization_delay",
                self.initialization_synchronization_delay,
            ),
            (
                "initialization_key_cache_duration",
                self.initialization_key_cache_duration,
            ),
            ("key_cache_duration", self.key_cache_duration),
        ] {
            if value.0 < 0 {
                return Err(format!("{name} must be greater than or equal to zero."));
            }
        }
        for (name, value) in [
            ("propagation_time", self.propagation_time),
            ("rotation_interval", self.rotation_interval),
            ("retention_duration", self.retention_duration),
        ] {
            if value.0 <= 0 {
                return Err(format!("{name} must be greater than zero."));
            }
        }
        if self.key_cache_duration.0 > self.propagation_time.0 / 2 {
            self.key_cache_duration = TimeSpan(self.propagation_time.0 / 2);
        }
        if self.rotation_interval.0 <= self.propagation_time.0 {
            return Err("rotation_interval must be longer than propagation_time".into());
        }
        Ok(self)
    }

    /// The file system key store's directory.
    pub fn key_path(&self) -> std::path::PathBuf {
        self.key_path.clone().unwrap_or_else(|| "keys".into())
    }

    /// Rotation interval plus retention: after this age a key is deleted.
    pub fn key_retirement_age(&self) -> i64 {
        self.rotation_interval
            .0
            .saturating_add(self.retention_duration.0)
    }
}

/// Caching options: lifetimes of cached store lookups.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CachingOptions {
    pub client_store_expiration: TimeSpan,
    pub resource_store_expiration: TimeSpan,
    pub cors_expiration: TimeSpan,
}

impl Default for CachingOptions {
    fn default() -> Self {
        Self {
            client_store_expiration: TimeSpan(15 * 60),
            resource_store_expiration: TimeSpan(15 * 60),
            cors_expiration: TimeSpan(15 * 60),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DPoPOptions {
    /// How long a proof (by `iat`) or a server nonce is valid.
    pub proof_token_validity_duration: TimeSpan,
    /// Clock skew allowed for server nonces.
    pub server_clock_skew: TimeSpan,
    pub supported_dpop_signing_algorithms: Vec<String>,
}

impl Default for DPoPOptions {
    fn default() -> Self {
        Self {
            proof_token_validity_duration: TimeSpan(60),
            server_clock_skew: TimeSpan(0),
            supported_dpop_signing_algorithms: owned(DEFAULT_SIGNING_ALGORITHMS),
        }
    }
}

/// `StoragePurgeOptions`: the background job that removes expired grants,
/// device codes, and replay and throttling entries.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StoragePurgeOptions {
    pub enable_purge: bool,
    /// Between runs; at least one second.
    pub purge_interval: TimeSpan,
    /// Removed per batch, clamped to 1-1000.
    pub batch_size: i32,
    /// The first run comes after a random part of the interval.
    pub fuzz_startup: bool,
}

impl Default for StoragePurgeOptions {
    fn default() -> Self {
        Self {
            enable_purge: true,
            purge_interval: TimeSpan(3600),
            batch_size: 100,
            fuzz_startup: true,
        }
    }
}

/// `OutboxProcessorOptions`: the background job that delivers outbox work
/// (session expiration).
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OutboxProcessorOptions {
    pub enable_processor: bool,
    /// Between runs; at least one second.
    pub process_interval: TimeSpan,
    /// Events claimed per run, clamped to 1-1000.
    pub batch_size: i32,
    /// Failed attempts after which an event is dropped.
    pub max_retries: i32,
    /// The first retry's delay, multiplied for each later one.
    pub retry_delay: TimeSpan,
    pub retry_backoff_multiplier: f64,
    pub max_retry_delay: TimeSpan,
    /// The first run comes after a random part of the interval.
    pub fuzz_startup: bool,
}

impl Default for OutboxProcessorOptions {
    fn default() -> Self {
        Self {
            enable_processor: true,
            process_interval: TimeSpan(30),
            batch_size: 100,
            max_retries: 3,
            retry_delay: TimeSpan(60),
            retry_backoff_multiplier: 2.0,
            max_retry_delay: TimeSpan(1800),
            fuzz_startup: true,
        }
    }
}

/// `CibaOptions`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CibaOptions {
    /// Seconds a backchannel authentication request lives.
    pub default_lifetime: i32,
    /// Seconds a client waits between polls.
    pub default_polling_interval: i32,
}

impl Default for CibaOptions {
    fn default() -> Self {
        Self {
            default_lifetime: 300,
            default_polling_interval: 5,
        }
    }
}

/// JARM (JWT Secured Authorization Response Mode).
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct JarmOptions {
    /// Accept the `jwt`, `query.jwt`, `fragment.jwt` and `form_post.jwt`
    /// response modes and advertise them.
    pub enabled: bool,
    /// How long a response JWT is valid (`exp`).
    pub lifetime: TimeSpan,
}

impl Default for JarmOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            lifetime: TimeSpan(300),
        }
    }
}

/// `DeviceFlowOptions`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DeviceFlowOptions {
    /// The user code generator for clients that don't name one.
    pub default_user_code_type: String,
    /// Seconds a client waits between polls.
    pub interval: i32,
}

impl Default for DeviceFlowOptions {
    fn default() -> Self {
        Self {
            default_user_code_type: "Numeric".to_owned(),
            interval: 5,
        }
    }
}

/// `MutualTlsOptions`: mTLS (RFC 8705) client authentication, endpoint
/// aliases and certificate-bound tokens.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MutualTlsOptions {
    pub enabled: bool,
    /// Accepted for compatibility; there are no authentication schemes.
    pub client_certificate_authentication_scheme: String,
    /// The mTLS domain (`mtls.example.com`, with a dot) or subdomain label
    /// (`mtls`); path-based aliases (`/connect/mtls/*`) when absent.
    pub domain_name: Option<String>,
    /// Binds tokens to a certificate that didn't authenticate the client.
    pub always_emit_confirmation_claim: bool,
}

impl Default for MutualTlsOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            client_certificate_authentication_scheme: "Certificate".to_owned(),
            domain_name: None,
            always_emit_confirmation_claim: false,
        }
    }
}

/// Input length restrictions: maximum lengths of request inputs.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct InputLengthRestrictions {
    pub client_id: usize,
    pub client_secret: usize,
    pub scope: usize,
    pub grant_type: usize,
    pub redirect_uri: usize,
    pub nonce: usize,
    pub ui_locale: usize,
    pub login_hint: usize,
    pub acr_values: usize,
    pub dpop_key_thumbprint: usize,
    pub dpop_proof_token: usize,
    pub device_code: usize,
    pub user_code: usize,
    pub login_hint_token: usize,
    pub id_token_hint: usize,
    pub binding_message: usize,
    pub authentication_request_id: usize,
    pub authorization_code: usize,
    pub jwt: usize,
    pub resource_indicator_max_length: usize,
    /// Reference token handles.
    pub token_handle: usize,
    /// Refresh token handles.
    pub refresh_token: usize,
    /// The password grant's `username` and `password`.
    pub user_name: usize,
    pub password: usize,
}

impl InputLengthRestrictions {
    /// Fixed lengths (RFC 7636: 43 to 128).
    pub const CODE_CHALLENGE_MIN_LENGTH: usize = 43;
    pub const CODE_CHALLENGE_MAX_LENGTH: usize = 128;
    pub const CODE_VERIFIER_MIN_LENGTH: usize = 43;
    pub const CODE_VERIFIER_MAX_LENGTH: usize = 128;
}

impl Default for InputLengthRestrictions {
    fn default() -> Self {
        Self {
            client_id: 100,
            client_secret: 100,
            scope: 300,
            grant_type: 100,
            redirect_uri: 400,
            nonce: 300,
            ui_locale: 100,
            login_hint: 100,
            acr_values: 300,
            dpop_key_thumbprint: 100,
            dpop_proof_token: 4000,
            device_code: 100,
            user_code: 100,
            login_hint_token: 4000,
            id_token_hint: 4000,
            binding_message: 100,
            authentication_request_id: 100,
            authorization_code: 100,
            jwt: 51200,
            resource_indicator_max_length: 512,
            token_handle: 100,
            refresh_token: 100,
            user_name: 100,
            password: 100,
        }
    }
}

/// A time span in whole seconds. Deserializes the `[d.]hh:mm:ss` text
/// form, or a plain number of seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeSpan(pub i64);

impl<'de> Deserialize<'de> for TimeSpan {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Seconds(i64),
            Text(String),
        }
        match Raw::deserialize(deserializer)? {
            Raw::Seconds(s) => Ok(TimeSpan(s)),
            Raw::Text(t) => parse_timespan(&t).map(TimeSpan).ok_or_else(|| {
                serde::de::Error::custom(format!("invalid TimeSpan {t:?}, expected [d.]hh:mm:ss"))
            }),
        }
    }
}

impl serde::Serialize for TimeSpan {
    /// The `[-][d.]hh:mm:ss` text form.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let sign = if self.0 < 0 { "-" } else { "" };
        let total = self.0.unsigned_abs();
        let (days, rest) = (total / 86_400, total % 86_400);
        let clock = format!(
            "{:02}:{:02}:{:02}",
            rest / 3_600,
            rest % 3_600 / 60,
            rest % 60
        );
        let text = if days > 0 {
            format!("{sign}{days}.{clock}")
        } else {
            format!("{sign}{clock}")
        };
        serializer.serialize_str(&text)
    }
}

fn parse_timespan(text: &str) -> Option<i64> {
    if let Some(positive) = text.strip_prefix('-') {
        return parse_timespan(positive).map(|s| -s);
    }
    let (days, clock) = match text.split_once('.') {
        Some((d, rest)) if rest.contains(':') => (d.parse::<i64>().ok()?, rest),
        _ => (0, text),
    };
    let parts: Vec<i64> = clock
        .split(':')
        .map(|p| p.parse().ok())
        .collect::<Option<_>>()?;
    let [h, m, s] = parts.as_slice() else {
        return None;
    };
    Some(days * 86_400 + h * 3_600 + m * 60 + s)
}
