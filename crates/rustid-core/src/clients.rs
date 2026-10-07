//! OAuth clients in the fixture format (camelCase JSON).
//! Only the properties the implemented features read are modelled; unknown
//! properties are accepted so the shared fixture file can carry them.

use std::path::Path;

use chrono::{DateTime, NaiveDateTime, Utc};
use serde::{Deserialize, Deserializer};

pub const SECRET_TYPE_SHARED: &str = "SharedSecret";
pub const SECRET_TYPE_JWK: &str = "JWK";
pub const SECRET_TYPE_X509_BASE64: &str = "X509CertificateBase64";
/// A certificate's SHA-1 thumbprint.
pub const SECRET_TYPE_X509_THUMBPRINT: &str = "X509Thumbprint";
/// A certificate's subject name.
pub const SECRET_TYPE_X509_NAME: &str = "X509Name";

/// Which subject identifiers a client sees.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SubjectType {
    /// The user's own subject id.
    #[default]
    Public,
    /// A subject made for the client's sector.
    Pairwise,
}

#[derive(Debug, Clone, PartialEq, Deserialize, serde::Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Client {
    pub enabled: bool,
    pub client_id: String,
    pub client_name: Option<String>,
    /// Stored for admin; nothing at runtime reads it.
    pub description: Option<String>,
    /// The client's home page, for consent screens.
    pub client_uri: Option<String>,
    /// The client's logo, for consent screens.
    pub logo_uri: Option<String>,
    pub protocol_type: String,
    pub client_secrets: Vec<Secret>,
    pub require_client_secret: bool,
    pub allowed_grant_types: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub allow_offline_access: bool,
    /// Seconds. Lifetimes are 32-bit, so larger values don't load.
    pub access_token_lifetime: i32,
    pub access_token_type: AccessTokenType,
    pub include_jwt_id: bool,
    pub claims: Vec<ClientClaim>,
    /// `null` or `""` means no prefix; the default is `client_`.
    pub client_claims_prefix: Option<String>,
    pub always_send_client_claims: bool,
    pub allowed_cors_origins: Vec<String>,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    /// Loaded in a hidden iframe when the user signs out.
    pub front_channel_logout_uri: Option<String>,
    /// The front-channel URI gets `sid` and `iss`.
    pub front_channel_logout_session_required: bool,
    /// Posted a logout token when the user signs out.
    pub back_channel_logout_uri: Option<String>,
    /// The logout token carries `sid`.
    pub back_channel_logout_session_required: bool,
    /// Stored for admin; nothing at runtime reads it.
    pub initiate_login_uri: Option<String>,
    /// The client's tokens end with the user's session (overrides the
    /// global option either way).
    pub coordinate_lifetime_with_user_session: Option<bool>,
    pub identity_token_lifetime: i32,
    pub absolute_refresh_token_lifetime: i32,
    pub sliding_refresh_token_lifetime: i32,
    pub device_code_lifetime: i32,
    /// Algorithms identity tokens may be signed with; empty allows the
    /// server's default key.
    pub allowed_identity_token_signing_algorithms: Vec<String>,
    /// Put the identity scopes' user claims in identity tokens even when an
    /// access token is issued too.
    pub always_include_user_claims_in_id_token: bool,
    /// Seconds an authorization code stays redeemable.
    pub authorization_code_lifetime: i32,
    /// Whether a used refresh token is kept (`ReUse`, the default) or
    /// replaced (`OneTimeOnly`).
    pub refresh_token_usage: RefreshTokenUsage,
    /// Whether refresh tokens expire a fixed time after issue or slide.
    pub refresh_token_expiration: RefreshTokenExpiration,
    /// Build a new access token from the refresh token's subject on refresh,
    /// rather than reissue the stored one.
    pub update_access_token_claims_on_refresh: bool,
    /// Whether a user's consent may be remembered.
    pub allow_remember_consent: bool,
    /// Seconds a remembered consent lasts; `None` keeps it until revoked.
    pub consent_lifetime: Option<i32>,
    pub require_pkce: bool,
    pub allow_plain_text_pkce: bool,
    pub allow_access_tokens_via_browser: bool,
    pub require_request_object: bool,
    pub require_pushed_authorization: bool,
    /// Seconds this client's pushed requests stay usable.
    pub pushed_authorization_lifetime: Option<i32>,
    pub require_consent: bool,
    pub enable_local_login: bool,
    /// External providers the client accepts; empty allows any.
    pub identity_provider_restrictions: Vec<String>,
    /// Seconds since authentication after which the client forces a login.
    pub user_sso_lifetime: Option<i32>,
    /// Seconds a CIBA request lives; the options' default when absent.
    pub ciba_lifetime: Option<i32>,
    /// The device flow user code generator; the default type when absent.
    pub user_code_type: Option<String>,
    /// Seconds between device flow (and CIBA) polls; the options' when
    /// absent.
    pub polling_interval: Option<i32>,
    /// The subject this client sees: the user's own, or one made for its
    /// sector (OpenID Connect Core 1.0 §8, [`crate::pairwise`]).
    pub subject_type: SubjectType,
    /// Names the client's sector (its host) for pairwise subjects; required
    /// when its redirect URIs name more than one host.
    pub sector_identifier_uri: Option<String>,
    /// Joins the server's salt in this client's pairwise subjects.
    pub pair_wise_subject_salt: Option<String>,
    /// Token requests must carry a DPoP proof.
    #[serde(rename = "requireDPoP", alias = "requireDpop")]
    pub require_dpop: bool,
    #[serde(rename = "dPoPValidationMode", alias = "dpopValidationMode")]
    pub dpop_validation_mode: crate::dpop::DPoPValidationMode,
    /// Clock skew allowed for a proof's `iat`.
    #[serde(rename = "dPoPClockSkew", alias = "dpopClockSkew")]
    pub dpop_clock_skew: crate::options::TimeSpan,
    /// The string-typed extended properties (`Properties`).
    pub properties: std::collections::BTreeMap<String, String>,
}

impl Default for Client {
    fn default() -> Self {
        Self {
            enabled: true,
            client_id: String::new(),
            client_name: None,
            description: None,
            client_uri: None,
            logo_uri: None,
            protocol_type: "oidc".to_owned(),
            client_secrets: Vec::new(),
            require_client_secret: true,
            allowed_grant_types: Vec::new(),
            allowed_scopes: Vec::new(),
            allow_offline_access: false,
            access_token_lifetime: 3600,
            access_token_type: AccessTokenType::Jwt,
            include_jwt_id: true,
            claims: Vec::new(),
            client_claims_prefix: Some("client_".to_owned()),
            always_send_client_claims: false,
            allowed_cors_origins: Vec::new(),
            redirect_uris: Vec::new(),
            post_logout_redirect_uris: Vec::new(),
            front_channel_logout_uri: None,
            front_channel_logout_session_required: true,
            back_channel_logout_uri: None,
            back_channel_logout_session_required: true,
            initiate_login_uri: None,
            coordinate_lifetime_with_user_session: None,
            identity_token_lifetime: 300,
            absolute_refresh_token_lifetime: 2_592_000,
            sliding_refresh_token_lifetime: 1_296_000,
            device_code_lifetime: 300,
            allowed_identity_token_signing_algorithms: Vec::new(),
            always_include_user_claims_in_id_token: false,
            authorization_code_lifetime: 300,
            refresh_token_usage: RefreshTokenUsage::ReUse,
            refresh_token_expiration: RefreshTokenExpiration::Absolute,
            update_access_token_claims_on_refresh: false,
            allow_remember_consent: true,
            consent_lifetime: None,
            require_pkce: true,
            allow_plain_text_pkce: false,
            allow_access_tokens_via_browser: false,
            require_request_object: false,
            require_pushed_authorization: false,
            pushed_authorization_lifetime: None,
            require_consent: false,
            enable_local_login: true,
            identity_provider_restrictions: Vec::new(),
            user_sso_lifetime: None,
            ciba_lifetime: None,
            user_code_type: None,
            polling_interval: None,
            subject_type: SubjectType::Public,
            sector_identifier_uri: None,
            pair_wise_subject_salt: None,
            require_dpop: false,
            dpop_validation_mode: crate::dpop::DPoPValidationMode::Iat,
            dpop_clock_skew: crate::options::TimeSpan(300),
            properties: Default::default(),
        }
    }
}

impl Client {
    /// Implicit is the only allowed grant type.
    pub fn is_implicit_only(&self) -> bool {
        self.allowed_grant_types.len() == 1 && self.allowed_grant_types[0] == "implicit"
    }

    pub fn allows_grant(&self, grant_type: &str) -> bool {
        self.allowed_grant_types.iter().any(|g| g == grant_type)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AccessTokenType {
    #[default]
    Jwt,
    Reference,
}

impl<'de> Deserialize<'de> for AccessTokenType {
    /// Accepts the enum name (any case) or its number.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Number(u8),
            Text(String),
        }
        match Raw::deserialize(deserializer)? {
            Raw::Number(0) => Ok(AccessTokenType::Jwt),
            Raw::Number(1) => Ok(AccessTokenType::Reference),
            Raw::Text(t) if t.eq_ignore_ascii_case("jwt") => Ok(AccessTokenType::Jwt),
            Raw::Text(t) if t.eq_ignore_ascii_case("reference") => Ok(AccessTokenType::Reference),
            _ => Err(serde::de::Error::custom(
                "accessTokenType must be Jwt or Reference",
            )),
        }
    }
}

impl serde::Serialize for AccessTokenType {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(match self {
            Self::Jwt => "Jwt",
            Self::Reference => "Reference",
        })
    }
}

/// `ReUse` = 0 (the default), `OneTimeOnly` = 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RefreshTokenUsage {
    #[default]
    ReUse,
    OneTimeOnly,
}

/// `Sliding` = 0, `Absolute` = 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RefreshTokenExpiration {
    Sliding,
    #[default]
    Absolute,
}

/// An enum from its name (any case) or number.
fn enum_name_or_value<'de, D: Deserializer<'de>, T: Copy>(
    deserializer: D,
    variants: &[(&str, T)],
    what: &str,
) -> Result<T, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Raw {
        Number(usize),
        Text(String),
    }
    let found = match Raw::deserialize(deserializer)? {
        Raw::Number(n) => variants.get(n).map(|(_, v)| *v),
        Raw::Text(t) => variants
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(&t))
            .map(|(_, v)| *v),
    };
    found.ok_or_else(|| {
        let names: Vec<&str> = variants.iter().map(|(n, _)| *n).collect();
        serde::de::Error::custom(format!("{what} must be one of {}", names.join(", ")))
    })
}

impl serde::Serialize for RefreshTokenUsage {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(match self {
            Self::ReUse => "ReUse",
            Self::OneTimeOnly => "OneTimeOnly",
        })
    }
}

impl serde::Serialize for RefreshTokenExpiration {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(match self {
            Self::Sliding => "Sliding",
            Self::Absolute => "Absolute",
        })
    }
}

impl<'de> Deserialize<'de> for RefreshTokenUsage {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        enum_name_or_value(
            deserializer,
            &[("ReUse", Self::ReUse), ("OneTimeOnly", Self::OneTimeOnly)],
            "refreshTokenUsage",
        )
    }
}

impl<'de> Deserialize<'de> for RefreshTokenExpiration {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        enum_name_or_value(
            deserializer,
            &[("Sliding", Self::Sliding), ("Absolute", Self::Absolute)],
            "refreshTokenExpiration",
        )
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, serde::Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Secret {
    pub description: Option<String>,
    pub value: String,
    #[serde(deserialize_with = "deserialize_expiration")]
    pub expiration: Option<DateTime<Utc>>,
    #[serde(rename = "type")]
    pub secret_type: String,
}

impl Default for Secret {
    fn default() -> Self {
        Self {
            description: None,
            value: String::new(),
            expiration: None,
            secret_type: SECRET_TYPE_SHARED.to_owned(),
        }
    }
}

impl Secret {
    /// An expiration strictly before now.
    pub fn has_expired(&self, now: DateTime<Utc>) -> bool {
        self.expiration.is_some_and(|e| e < now)
    }
}

/// Accepts an ISO 8601 date-time with or without an offset; without one it
/// is taken as UTC, as the fixture files mean it.
fn deserialize_expiration<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<DateTime<Utc>>, D::Error> {
    let Some(text) = Option::<String>::deserialize(deserializer)? else {
        return Ok(None);
    };
    if let Ok(dt) = DateTime::parse_from_rfc3339(&text) {
        return Ok(Some(dt.with_timezone(&Utc)));
    }
    NaiveDateTime::parse_from_str(&text, "%Y-%m-%dT%H:%M:%S%.f")
        .map(|n| Some(n.and_utc()))
        .map_err(|_| serde::de::Error::custom(format!("invalid secret expiration {text:?}")))
}

#[derive(Debug, Clone, PartialEq, Deserialize, serde::Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ClientClaim {
    #[serde(rename = "type")]
    pub claim_type: String,
    pub value: String,
    pub value_type: String,
}

impl Default for ClientClaim {
    fn default() -> Self {
        Self {
            claim_type: String::new(),
            value: String::new(),
            value_type: CLAIM_VALUE_TYPE_STRING.to_owned(),
        }
    }
}

pub const CLAIM_VALUE_TYPE_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Clients {
    pub clients: Vec<Client>,
}

#[derive(Debug, thiserror::Error)]
pub enum ClientsError {
    #[error("reading clients file {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("parsing clients file {path}: {source}")]
    Parse {
        path: String,
        source: serde_json::Error,
    },
    /// `InMemoryClientStore` refuses duplicate ids.
    #[error("clients file {path}: clients must not contain duplicate ids ({client_id})")]
    Duplicate { path: String, client_id: String },
}

impl Clients {
    pub fn load(path: &Path) -> Result<Self, ClientsError> {
        let display = path.display().to_string();
        let json = std::fs::read_to_string(path).map_err(|source| ClientsError::Read {
            path: display.clone(),
            source,
        })?;
        let clients: Vec<Client> =
            serde_json::from_str(&json).map_err(|source| ClientsError::Parse {
                path: display.clone(),
                source,
            })?;
        let mut seen = std::collections::HashSet::new();
        if let Some(dup) = clients.iter().find(|c| !seen.insert(c.client_id.as_str())) {
            return Err(ClientsError::Duplicate {
                path: display,
                client_id: dup.client_id.clone(),
            });
        }
        Ok(Clients { clients })
    }

    /// Any client lists the
    /// origin (compared case-insensitively with each configured URL's origin).
    pub fn is_cors_origin_allowed(&self, origin: &str) -> bool {
        self.clients
            .iter()
            .flat_map(|c| &c.allowed_cors_origins)
            .filter_map(|url| url_origin(url))
            .any(|allowed| allowed.eq_ignore_ascii_case(origin))
    }
}

/// The scheme, host and non-default port of an absolute URL.
pub fn url_origin(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    let origin = parsed.origin();
    origin.is_tuple().then(|| origin.ascii_serialization())
}

/// Redirect URI prefixes that are never valid (not configurable).
pub const INVALID_REDIRECT_URI_PREFIXES: &[&str] = &[
    "javascript:",
    "file:",
    "data:",
    "mailto:",
    "ftp:",
    "blob:",
    "about:",
    "ssh:",
    "tel:",
    "view-source:",
    "ws:",
    "wss:",
];

/// The client configuration validator. A client that fails is treated as
/// unknown, because the validating client store returns no client.
pub fn validate_client(
    client: &Client,
    allow_unregistered_pushed_redirect_uris: bool,
) -> Result<(), String> {
    if client.protocol_type != "oidc" {
        return Ok(());
    }
    let grants = &client.allowed_grant_types;
    if grants.is_empty() {
        return Err("no allowed grant type specified".into());
    }
    if client.access_token_lifetime <= 0 {
        return Err("access token lifetime is 0 or negative".into());
    }
    if client.identity_token_lifetime <= 0 {
        return Err("identity token lifetime is 0 or negative".into());
    }
    if grants
        .iter()
        .any(|g| g == "urn:ietf:params:oauth:grant-type:device_code")
        && client.device_code_lifetime <= 0
    {
        return Err("device code lifetime is 0 or negative".into());
    }
    if client.absolute_refresh_token_lifetime < 0 {
        return Err("absolute refresh token lifetime is negative".into());
    }
    if client.sliding_refresh_token_lifetime < 0 {
        return Err("sliding refresh token lifetime is negative".into());
    }
    let needs_redirect = grants
        .iter()
        .any(|g| g == "authorization_code" || g == "hybrid" || g == "implicit");
    let allowed_by_par = allow_unregistered_pushed_redirect_uris && client.require_client_secret;
    if needs_redirect && client.redirect_uris.is_empty() && !allowed_by_par {
        return Err("No redirect URI configured.".into());
    }
    for origin in &client.allowed_cors_origins {
        let valid =
            url::Url::parse(origin).is_ok_and(|u| u.path() == "/" && !origin.ends_with('/'));
        if !valid {
            return Err(if origin.trim().is_empty() {
                "AllowedCorsOrigins contains invalid origin. There is an empty value.".to_owned()
            } else {
                format!("AllowedCorsOrigins contains invalid origin: {origin}")
            });
        }
    }
    let invalid_scheme = |uri: &str| {
        INVALID_REDIRECT_URI_PREFIXES
            .iter()
            .any(|p| uri.len() >= p.len() && uri[..p.len()].eq_ignore_ascii_case(p))
    };
    if let Some(uri) = client.redirect_uris.iter().find(|u| invalid_scheme(u)) {
        return Err(format!("RedirectUri '{uri}' uses invalid scheme."));
    }
    if let Some(uri) = client
        .post_logout_redirect_uris
        .iter()
        .find(|u| invalid_scheme(u))
    {
        return Err(format!(
            "PostLogoutRedirectUri '{uri}' uses invalid scheme."
        ));
    }
    if let Some(uri) = &client.sector_identifier_uri
        && !url::Url::parse(uri).is_ok_and(|u| u.scheme() == "https" && u.host().is_some())
    {
        return Err(format!("sectorIdentifierUri '{uri}' must be an https URL."));
    }
    if client.subject_type == SubjectType::Pairwise
        && client.sector_identifier_uri.is_none()
        && crate::pairwise::redirect_hosts(client).len() > 1
    {
        return Err(
            "A pairwise client whose redirect URIs name more than one host needs a sectorIdentifierUri."
                .into(),
        );
    }
    for grant in grants {
        if grant != "implicit" && client.require_client_secret && client.client_secrets.is_empty() {
            return Err(format!(
                "Client secret is required for {grant}, but no client secret is configured."
            ));
        }
        if grant == "client_credentials" && !client.require_client_secret {
            return Err(
                "RequireClientSecret is false, but client is using client credentials grant type."
                    .into(),
            );
        }
    }
    Ok(())
}
