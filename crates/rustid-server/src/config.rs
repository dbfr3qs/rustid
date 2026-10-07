use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use figment::Figment;
use figment::providers::{Env, Format, Json, Toml};
use rustid_core::keys::KeyConfig;
use rustid_core::options::ProtocolOptions;
use serde::Deserialize;
use url::Url;

pub const ENV_PREFIX: &str = "RUSTID_";
pub const ENV_NESTING: &str = "__";

/// Unknown keys are rejected so a misspelled setting fails loudly instead of
/// silently falling back to a default.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Socket address to bind.
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// Serve HTTPS on `listen` with this certificate. Requests then count
    /// as HTTPS: URLs built from them use `https` and the session cookies
    /// are `Secure`, which browsers need for `SameSite=None` cookies.
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    #[serde(default)]
    pub log: LogConfig,
    /// Server-side sessions: the session lives in
    /// the store and the cookie holds its key. Options are in
    /// `protocol.server_side_sessions`.
    #[serde(default)]
    pub server_side_sessions: ServerSideSessionsConfig,
    /// Back-channel logout delivery.
    #[serde(default)]
    pub back_channel_logout: BackChannelLogoutConfig,
    /// Fetching request objects by reference (`request_uri`).
    #[serde(default)]
    pub request_uri: RequestUriConfig,
    /// A protected resource the server serves itself (bearer and
    /// DPoP-bound tokens), for conformance runs; none when absent.
    #[serde(default)]
    pub protected_resource: Option<ProtectedResourceConfig>,
    /// The admin HTTP API under `/admin`; off unless enabled.
    #[serde(default)]
    pub admin: AdminConfig,
    /// Dynamic client registration (RFC 7591) at `/connect/dcr`; off
    /// unless enabled.
    #[serde(default)]
    pub dynamic_client_registration: DynamicClientRegistrationConfig,
    /// The SAML 2.0 IdP.
    #[serde(default)]
    pub saml: SamlConfig,
    /// Reverse proxies whose `X-Forwarded-*` headers are trusted.
    #[serde(default)]
    pub forwarded_headers: crate::forwarded::ForwardedHeadersConfig,
    /// Client certificate sources and trust (mTLS). Protocol options are in
    /// `protocol.mutual_tls`.
    #[serde(default)]
    pub mutual_tls: MutualTlsConfig,
    /// Optional path prefix: requests may
    /// arrive with or without it. Must start with `/` and not end with `/`.
    #[serde(default)]
    pub path_base: Option<String>,
    /// Protocol options, in snake_case.
    #[serde(default)]
    pub protocol: ProtocolOptions,
    #[serde(default)]
    pub signing_keys: Vec<KeyConfig>,
    /// Keys published in JWKS but never used to sign.
    #[serde(default)]
    pub validation_keys: Vec<KeyConfig>,
    /// Identity resources, API scopes and API resources in the fixture format.
    #[serde(default)]
    pub resources_file: Option<PathBuf>,
    /// Clients in the fixture format. Loaded from Phase 1b onward.
    #[serde(default)]
    pub clients_file: Option<PathBuf>,
    /// Upstream identity providers (a JSON array): signing in through
    /// other OpenID Connect providers (`docs/federation.md`).
    #[serde(default)]
    pub identity_providers_file: Option<PathBuf>,
    /// How upstream providers are reached.
    #[serde(default)]
    pub federation: FederationConfig,
    /// Pairwise subjects: the salt, shared by every instance.
    #[serde(default)]
    pub pairwise: PairwiseConfig,
    #[serde(default)]
    pub client_authentication: ClientAuthenticationConfig,
    #[serde(default)]
    pub placeholders: PlaceholderConfig,
    #[serde(default)]
    pub store: StoreConfig,
    #[serde(default)]
    pub data_protection: DataProtectionConfig,
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    #[serde(default)]
    pub localization: LocalizationConfig,
    #[serde(default)]
    pub interaction: InteractionConfig,
    #[serde(default)]
    pub reference_ui: ReferenceUiConfig,
    /// Hooks replacing the profile service (`profile_claims`,
    /// `subject_active`); see `rustid-hooks`.
    #[serde(default)]
    pub hooks: rustid_hooks::HooksConfig,
}

/// The server's TLS certificate, both PEM files.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// The certificate chain, leaf first.
    pub cert_file: PathBuf,
    /// The certificate's private key (PKCS#8, PKCS#1 or SEC1).
    pub key_file: PathBuf,
    /// Whether the TLS handshake asks clients for a certificate (mTLS).
    #[serde(default)]
    pub client_certificates: ClientCertificateMode,
    /// Which cipher suites the listener offers.
    #[serde(default)]
    pub cipher_suites: CipherSuites,
}

/// `tls.cipher_suites`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CipherSuites {
    /// Rustls's safe defaults.
    #[default]
    Default,
    /// FAPI 2.0 (FAPI2-SP-ID2-5.2.2): TLS 1.2 limited to
    /// `TLS_ECDHE_RSA_WITH_AES_{128,256}_GCM_SHA{256,384}`, so it needs an
    /// RSA certificate; with another key only TLS 1.3 is offered.
    Fapi,
}

/// `tls.client_certificates`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientCertificateMode {
    /// No certificate is asked for.
    #[default]
    None,
    /// A certificate is asked for but not required; any certificate is
    /// accepted (the handshake proves its key), and client authentication
    /// decides what it's worth.
    Request,
}

/// Where client certificates come from besides the TLS listener, and the
/// roots that make a certificate's subject name believable.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MutualTlsConfig {
    /// A header carrying the client certificate (URL-encoded PEM, PEM or
    /// base64 DER), read only from `forwarded_headers.trusted_proxies`.
    pub forwarded_certificate_header: Option<String>,
    /// PEM roots a certificate must chain to for `X509Name` secrets.
    pub client_ca_file: Option<PathBuf>,
}

/// What `ui_locales` may select for the UI.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LocalizationConfig {
    /// UI culture names (`en-US`); the first `ui_locales` value naming one
    /// is sent to the UI in the culture cookie. Empty sends none.
    pub supported_ui_cultures: Vec<String>,
}

/// The interaction API a UI app completes logins and consents through.
#[derive(Clone, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct InteractionConfig {
    /// Bearer keys the UI presents; none disables the API (the reference
    /// UI uses a key of its own). Each at least 16 characters.
    pub api_keys: Vec<String>,
}

impl std::fmt::Debug for InteractionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InteractionConfig")
            .field("api_keys", &format!("<{} redacted>", self.api_keys.len()))
            .finish()
    }
}

/// The built-in reference UI: pages that complete every interaction
/// immediately, for automated tests and conformance runs, or, in
/// interactive mode, simple pages a person can use to try the server. Never
/// enable it for real users.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReferenceUiConfig {
    pub enabled: bool,
    /// Users the login page signs in, in the fixture format
    /// (`fixtures/users.json`).
    pub users_file: Option<PathBuf>,
    /// The user signed in when the login page gets no `user` parameter.
    pub default_user: String,
    /// The login page asks for a username and password from `users_file`,
    /// and the error page is HTML, instead of the scripted UI's behaviour.
    /// Otherwise (scripted, for automated tests) pages act on GET
    /// query parameters: the login page signs a user in, and the consent
    /// and device pages grant or deny, with no form and no password. Never
    /// expose the scripted mode to real browsers.
    pub interactive: bool,
    /// The users file also answers profile claims and whether a user is
    /// active, so userinfo and tokens carry the
    /// user's claims. Ignored when a profile hook is configured.
    pub users_profile_service: bool,
}

impl Default for ReferenceUiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            users_file: None,
            default_user: "alice".to_owned(),
            interactive: false,
            users_profile_service: false,
        }
    }
}

/// OpenTelemetry export. Logs always go to stdout.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TelemetryConfig {
    /// `service.name` of exported traces and metrics.
    pub service_name: String,
    /// How often metrics are exported.
    pub metrics_interval: rustid_core::options::TimeSpan,
    /// Export traces and metrics over OTLP/HTTP when set.
    pub otlp: Option<OtlpConfig>,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        TelemetryConfig {
            service_name: "rustid".into(),
            metrics_interval: rustid_core::options::TimeSpan(60),
            otlp: None,
        }
    }
}

#[derive(Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OtlpConfig {
    /// The collector's base URL; `/v1/traces` and `/v1/metrics` are added.
    pub endpoint: String,
    /// Extra request headers, for example an API key.
    #[serde(default)]
    pub headers: std::collections::BTreeMap<String, String>,
}

impl std::fmt::Debug for OtlpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OtlpConfig")
            .field("endpoint", &self.endpoint)
            .field("headers", &self.headers.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// The master key ring that protects data at rest (signing keys today).
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DataProtectionConfig {
    /// The first key protects new data; every key can unprotect. With none
    /// configured and the memory store, a key is generated and kept in
    /// `{key_management.key_path}/data-protection.key`.
    pub keys: Vec<DataProtectionKey>,
}

#[derive(Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataProtectionKey {
    pub id: String,
    /// 32 bytes, base64.
    pub secret: String,
}

impl std::fmt::Debug for DataProtectionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataProtectionKey")
            .field("id", &self.id)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// Where clients, resources and grants live.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AdminConfig {
    pub enabled: bool,
    /// Bearer keys that may call the API, each at least 32 characters.
    pub api_keys: Vec<String>,
    /// Data extension schemas (a JSON array), registered at start. The
    /// schema routes are then read-only.
    pub schemas_file: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DynamicClientRegistrationConfig {
    pub enabled: bool,
    /// Where the endpoint is served.
    pub path: String,
    /// Anyone may register. Otherwise callers need one of
    /// `initial_access_tokens`.
    pub open: bool,
    /// Bearer tokens that may register clients, each at least 32
    /// characters (RFC 7591 §3).
    pub initial_access_tokens: Vec<String>,
    /// How long generated client secrets last; unset, they never expire.
    pub secret_lifetime: Option<rustid_core::options::TimeSpan>,
    /// Scopes a client that asks for none gets;
    /// none by default.
    pub default_scopes: Vec<String>,
    /// Whether registered clients must use PKCE; unset, they must (the
    /// client default).
    pub require_pkce: Option<bool>,
    /// RFC 7592 read and delete of registered clients, each with its own
    /// registration access token.
    pub client_management: bool,
}

impl Default for DynamicClientRegistrationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: "/connect/dcr".into(),
            open: false,
            initial_access_tokens: Vec::new(),
            secret_lifetime: None,
            default_scopes: Vec::new(),
            require_pkce: None,
            client_management: false,
        }
    }
}

/// The shortest admin API key (or initial access token) the server accepts.
pub const MIN_ADMIN_KEY_LENGTH: usize = 32;

/// `[protected_resource]`: a resource on the server itself, which the
/// FAPI 2.0 conformance plans call with the tokens they get.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedResourceConfig {
    /// The resource's path, such as `/fapi2/resource`.
    pub path: String,
}

/// `[pairwise]`: pairwise subject identifiers. Without a salt only public
/// subjects are offered.
#[derive(Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PairwiseConfig {
    /// At least 16 characters; the same on every instance. Changing it
    /// changes every pairwise subject.
    pub salt: Option<String>,
}

impl std::fmt::Debug for PairwiseConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairwiseConfig")
            .field("salt", &self.salt.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BackChannelLogoutConfig {
    /// CA certificates (PEM) to trust, besides the system's, when posting
    /// logout tokens to clients.
    pub ca_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FederationConfig {
    /// Accept `http://localhost` and `http://127.0.0.1` authorities, for
    /// tests and local demos only.
    pub allow_insecure_loopback: bool,
    /// CA certificates (PEM) to trust, besides the system's, when reaching
    /// upstream providers.
    pub ca_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RequestUriConfig {
    /// CA certificates (PEM) to trust, besides the system's, when fetching
    /// request objects by reference.
    pub ca_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerSideSessionsConfig {
    pub enabled: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StoreConfig {
    pub kind: StoreKind,
    /// Required when `kind` is `postgres`; not allowed otherwise.
    pub postgres: Option<PostgresConfig>,
    /// The storage purge also removes consumed grants.
    pub remove_consumed_grants: bool,
    /// Seconds a consumed grant is kept before the purge may remove it.
    pub consumed_grant_cleanup_delay: i64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StoreKind {
    /// Clients and resources from `clients_file` and `resources_file`;
    /// grants in process memory.
    #[default]
    Memory,
    /// Everything in Postgres. `clients_file` and `resources_file`, when
    /// set, are upserted into the database at startup.
    Postgres,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostgresConfig {
    pub url: String,
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    /// Create the database when it doesn't exist (development convenience).
    #[serde(default)]
    pub create_database: bool,
    /// Apply pending schema migrations at startup.
    #[serde(default = "default_true")]
    pub run_migrations: bool,
}

fn default_max_connections() -> u32 {
    10
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClientAuthenticationConfig {
    /// Accept and advertise `private_key_jwt`.
    pub private_key_jwt: bool,
}

/// Values derived from registered services that the server does not
/// have yet. Each is replaced by the real derivation in the phase that builds
/// the service: the password grant and extension grants come from hooks.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PlaceholderConfig {
    pub password_grant: bool,
    pub extension_grants: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct LogConfig {
    #[serde(default)]
    pub format: LogFormat,
    #[serde(default = "default_level")]
    pub level: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            format: LogFormat::default(),
            level: default_level(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Pretty,
    Json,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("configuration error{key}: {0}", key = key_suffix(.0))]
    Invalid(Box<figment::Error>),
    #[error("configuration file not found: {}", .0.display())]
    MissingFile(PathBuf),
    /// A setting under a name rustid no longer reads.
    #[error("{0}")]
    Renamed(&'static str),
    #[error(
        "protocol.issuer_uri must be an absolute http(s) URL without query or fragment, got {0}"
    )]
    InvalidIssuer(String),
    #[error("path_base must start with '/' and must not end with '/', got {0:?}")]
    InvalidPathBase(String),
    #[error("store.kind is postgres but store.postgres.url is not set")]
    MissingPostgres,
    #[error("store.postgres is set but store.kind is memory")]
    UnusedPostgres,
    #[error("store.postgres.max_connections must be at least 1")]
    NoConnections,
    #[error("protocol.key_management: {0}")]
    KeyManagement(String),
    #[error("data_protection.keys: {0}")]
    DataProtection(String),
    #[error("telemetry: {0}")]
    Telemetry(String),
    #[error("interaction.api_keys: every key must be at least 16 characters")]
    WeakApiKey,
    #[error("{0}")]
    Setting(String),
    #[error(
        "mutual_tls.forwarded_certificate_header is only read from forwarded_headers.trusted_proxies, which is empty"
    )]
    UntrustedCertificateHeader,
}

impl From<figment::Error> for ConfigError {
    fn from(error: figment::Error) -> Self {
        ConfigError::Invalid(Box::new(error))
    }
}

impl ServerConfig {
    /// Loads configuration from an optional TOML or JSON file (by extension),
    /// then applies environment overrides (`RUSTID_` prefix, `__` for
    /// nesting). Relative file paths inside the file are resolved against
    /// the file's directory.
    pub fn load(path: Option<&Path>) -> Result<Self, ConfigError> {
        let mut figment = Figment::new();
        if let Some(path) = path {
            // Figment treats a missing file as empty; an explicit path that
            // doesn't exist is an operator mistake and must fail loudly.
            if !path.is_file() {
                return Err(ConfigError::MissingFile(path.to_path_buf()));
            }
            figment = match path.extension().and_then(|e| e.to_str()) {
                Some("json") => figment.merge(Json::file(path)),
                _ => figment.merge(Toml::file(path)),
            };
        }
        // The protocol options were once the [identity_server] section: say
        // where they went, rather than "unknown field".
        if figment.find_value("identity_server").is_ok() {
            return Err(ConfigError::Renamed(
                "the [identity_server] section is now [protocol]",
            ));
        }
        if std::env::vars_os().any(|(name, _)| {
            name.to_str().is_some_and(|n| {
                n.to_ascii_uppercase()
                    .starts_with("RUSTID_IDENTITY_SERVER__")
            })
        }) {
            return Err(ConfigError::Renamed(
                "RUSTID_IDENTITY_SERVER__* variables are now RUSTID_PROTOCOL__*",
            ));
        }
        let mut config: ServerConfig = figment
            // RUSTID_CONFIG is read by the command line parser, not here.
            .merge(
                Env::prefixed(ENV_PREFIX)
                    .split(ENV_NESTING)
                    .ignore(&["config"]),
            )
            .extract()?;
        if let Some(dir) = path.and_then(Path::parent) {
            config.resolve_paths(dir);
        }
        config.protocol = config.protocol.finalize();
        config.validate()?;
        Ok(config)
    }

    fn resolve_paths(&mut self, dir: &Path) {
        let resolve = |p: &mut PathBuf| {
            if p.is_relative() {
                *p = dir.join(&*p);
            }
        };
        for key in self
            .signing_keys
            .iter_mut()
            .chain(self.validation_keys.iter_mut())
        {
            resolve(&mut key.key_file);
            if let Some(cert) = key.cert_file.as_mut() {
                resolve(cert);
            }
        }
        for file in [
            self.resources_file.as_mut(),
            self.clients_file.as_mut(),
            self.identity_providers_file.as_mut(),
            self.federation.ca_file.as_mut(),
            self.reference_ui.users_file.as_mut(),
            self.back_channel_logout.ca_file.as_mut(),
            self.request_uri.ca_file.as_mut(),
            self.mutual_tls.client_ca_file.as_mut(),
            self.admin.schemas_file.as_mut(),
            self.saml.service_providers_file.as_mut(),
        ]
        .into_iter()
        .flatten()
        {
            resolve(file);
        }
        if let Some(key_path) = self.protocol.key_management.key_path.as_mut() {
            resolve(key_path);
        }
        if let Some(tls) = self.tls.as_mut() {
            resolve(&mut tls.cert_file);
            resolve(&mut tls.key_file);
        }
    }

    /// The configured key ring, `None` when no keys are configured.
    pub fn data_protector(
        &self,
    ) -> Result<Option<rustid_core::data_protection::DataProtector>, ConfigError> {
        use base64::Engine;
        if self.data_protection.keys.is_empty() {
            return Ok(None);
        }
        let mut decoded = Vec::new();
        for key in &self.data_protection.keys {
            let secret = base64::engine::general_purpose::STANDARD
                .decode(key.secret.trim())
                .map_err(|_| {
                    ConfigError::DataProtection(format!("key {} is not valid base64", key.id))
                })?;
            decoded.push((key.id.as_str(), secret));
        }
        rustid_core::data_protection::DataProtector::new(
            decoded.iter().map(|(id, secret)| (*id, secret.as_slice())),
        )
        .map(Some)
        .map_err(|e| ConfigError::DataProtection(e.to_string()))
    }

    fn validate(&mut self) -> Result<(), ConfigError> {
        if self.mutual_tls.forwarded_certificate_header.is_some()
            && self.forwarded_headers.trusted_proxies.is_empty()
        {
            return Err(ConfigError::UntrustedCertificateHeader);
        }
        if let Some(issuer) = &self.protocol.issuer_uri {
            let ok = Url::parse(issuer).is_ok_and(|u| {
                matches!(u.scheme(), "http" | "https")
                    && u.host().is_some()
                    && u.query().is_none()
                    && u.fragment().is_none()
            });
            if !ok {
                return Err(ConfigError::InvalidIssuer(issuer.clone()));
            }
        }
        if let Some(base) = &self.path_base
            && (!base.starts_with('/') || base.ends_with('/'))
        {
            return Err(ConfigError::InvalidPathBase(base.clone()));
        }
        self.protocol.key_management = self
            .protocol
            .key_management
            .clone()
            .validated()
            .map_err(ConfigError::KeyManagement)?;
        self.data_protector()?;
        if let Some(otlp) = &self.telemetry.otlp {
            let ok = Url::parse(&otlp.endpoint)
                .is_ok_and(|u| matches!(u.scheme(), "http" | "https") && u.host().is_some());
            if !ok {
                return Err(ConfigError::Telemetry(format!(
                    "otlp.endpoint must be an http(s) URL, got {:?}",
                    otlp.endpoint
                )));
            }
        }
        if self.telemetry.metrics_interval.0 <= 0 {
            return Err(ConfigError::Telemetry(
                "metrics_interval must be greater than zero".into(),
            ));
        }
        if self
            .interaction
            .api_keys
            .iter()
            .any(|k| k.trim().chars().count() < 16)
        {
            return Err(ConfigError::WeakApiKey);
        }
        if let Some(resource) = &self.protected_resource
            && (!resource.path.starts_with('/')
                || resource.path.starts_with("//")
                || resource.path.contains(['?', '#']))
        {
            return Err(ConfigError::Setting(format!(
                "protected_resource.path must be a path starting with '/', got {:?}",
                resource.path
            )));
        }
        if let Some(salt) = &self.pairwise.salt
            && salt.chars().count() < 16
        {
            return Err(ConfigError::Setting(
                "pairwise.salt must be at least 16 characters".into(),
            ));
        }
        self.protocol.pairwise.salt = self.pairwise.salt.clone();
        // Durations a timer adds to now: past a year they are mistakes, and
        // large enough ones overflow.
        const YEAR: i64 = 366 * 86_400;
        let outbox = &self.protocol.outbox_processor;
        for (name, value, minimum) in [
            ("process_interval", outbox.process_interval.0, 1),
            ("retry_delay", outbox.retry_delay.0, 0),
            ("max_retry_delay", outbox.max_retry_delay.0, 0),
        ] {
            if !(minimum..=YEAR).contains(&value) {
                return Err(ConfigError::Setting(format!(
                    "protocol.outbox_processor.{name} must be between {minimum} seconds and a year, got {value}"
                )));
            }
        }
        match (self.store.kind, &self.store.postgres) {
            (StoreKind::Postgres, None) => return Err(ConfigError::MissingPostgres),
            (StoreKind::Memory, Some(_)) => return Err(ConfigError::UnusedPostgres),
            (StoreKind::Postgres, Some(pg)) if pg.max_connections == 0 => {
                return Err(ConfigError::NoConnections);
            }
            _ => {}
        }
        Ok(())
    }
}

/// Names the configuration key an error refers to, in config-file form
/// (`log.level`), so env-var and file errors point at the same key.
fn key_suffix(error: &figment::Error) -> String {
    if error.path.is_empty() {
        String::new()
    } else {
        format!(" at `{}`", error.path.join(".").to_lowercase())
    }
}

fn default_listen() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8080))
}

fn default_level() -> String {
    "info".to_owned()
}

/// `[saml]`: whether the SAML IdP runs, the service providers file, and
/// `SamlOptions` (in snake_case) in the same table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SamlConfig {
    pub enabled: bool,
    pub service_providers_file: Option<PathBuf>,
    pub options: rustid_saml::options::SamlOptions,
}

impl<'de> Deserialize<'de> for SamlConfig {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let mut table = serde_json::Map::<String, serde_json::Value>::deserialize(deserializer)?;
        let enabled = match table.remove("enabled") {
            Some(v) => serde_json::from_value(v).map_err(D::Error::custom)?,
            None => false,
        };
        let service_providers_file = match table.remove("service_providers_file") {
            Some(v) => serde_json::from_value(v).map_err(D::Error::custom)?,
            None => None,
        };
        // The rest are options, which refuse unknown names.
        let options =
            serde_json::from_value(serde_json::Value::Object(table)).map_err(D::Error::custom)?;
        Ok(SamlConfig {
            enabled,
            service_providers_file,
            options,
        })
    }
}
