#![forbid(unsafe_code)]
//! Hooks (spec section 7): HTTPS calls that replace an extension point of
//! the server. Every hook is a POST of a JSON body with
//! `version: 1`, authenticated with a short-lived JWT the server signs
//! with its signing key (audience: the hook URL), under a timeout and a
//! failure policy, optionally cached. This crate has the profile claims and
//! subject active hooks, which together replace the profile service, and the
//! token request hook, which replaces the custom token request validator, the
//! grant hooks, and the CIBA hooks.

use std::time::Duration;

use async_trait::async_trait;
use moka::future::Cache;
use rustid_core::ciba::{
    CibaCustomAnswer, CibaCustomRequest, CibaNotification, CibaService, CibaUserRequest,
    CibaUserResult, NopCibaService,
};
use rustid_core::grant_validation::{
    ExtensionRequest, GrantAnswer, GrantResult, GrantSubject, GrantValidator, PasswordRequest,
    RequestChanges,
};
use rustid_core::key_service::KeyService;
use rustid_core::options::TimeSpan;
use rustid_core::profile::{
    ActiveRequest, DefaultProfileService, ProfileError, ProfileRequest, ProfileService,
    requested_claims,
};
use rustid_core::token_request::{TokenRequest, TokenRequestValidator, TokenRequestVerdict};
use rustid_core::tokens::Claim;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use url::Url;

/// The protocol version both sides send.
pub const VERSION: u32 = 1;

/// The hook JWT's `typ`, so it is never taken for an access token.
pub const HOOK_TOKEN_TYPE: &str = "hook+jwt";

/// How long a hook JWT is valid.
const TOKEN_LIFETIME_SECONDS: i64 = 60;

/// What happens when a hook fails (times out, answers an error or
/// something unreadable).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailurePolicy {
    /// The request that needed the hook fails with a server error.
    #[default]
    FailClosed,
    /// The default behaviour is used instead, and a warning logged.
    FailOpen,
}

/// One hook.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HookConfig {
    /// HTTPS, or HTTP to a loopback address.
    pub url: Url,
    #[serde(default = "default_timeout")]
    pub timeout: TimeSpan,
    #[serde(default)]
    pub failure_policy: FailurePolicy,
    /// How long an answer is reused; zero (the default) never reuses one.
    #[serde(default = "no_cache")]
    pub cache_duration: TimeSpan,
}

fn default_timeout() -> TimeSpan {
    TimeSpan(5)
}

fn no_cache() -> TimeSpan {
    TimeSpan(0)
}

/// The hooks configured; an absent hook keeps the default behaviour.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HooksConfig {
    /// Replaces the profile service.
    pub profile_claims: Option<HookConfig>,
    /// Replaces the profile service.
    pub subject_active: Option<HookConfig>,
    /// Replaces the custom token request validator. Never cached.
    pub token_request: Option<HookConfig>,
    /// Replaces the resource owner password validator: the `password` grant.
    /// Never cached.
    pub password_grant: Option<HookConfig>,
    /// Replace the extension grant validator: one hook per extension grant
    /// type. Never cached.
    pub extension_grants: std::collections::BTreeMap<String, HookConfig>,
    /// Replaces the backchannel authentication user validator. Never cached.
    pub ciba_user: Option<HookConfig>,
    /// Replaces the backchannel authentication user notification service.
    pub ciba_notification: Option<HookConfig>,
    /// Replaces the custom backchannel authentication validator. Never cached.
    pub ciba_request: Option<HookConfig>,
}

#[derive(Debug, thiserror::Error)]
pub enum HookConfigError {
    #[error("hook URL {0} must be https (or http to a loopback address)")]
    InsecureUrl(Url),
    #[error("building the hook HTTP client: {0}")]
    Client(String),
}

/// Why a hook call failed.
#[derive(Debug, thiserror::Error)]
enum HookError {
    #[error("{0}")]
    Transport(String),
    #[error("answered {0}")]
    Status(u16),
    #[error("unreadable answer: {0}")]
    Body(String),
    #[error("answered version {0}, expected {VERSION}")]
    Version(u32),
    #[error("signing the request: {0}")]
    Signing(String),
}

struct Hook {
    config: HookConfig,
}

/// The profile service backed by the configured hooks.
pub struct Hooks {
    profile: Option<(Hook, Cache<String, Vec<Claim>>)>,
    active: Option<(Hook, Cache<String, bool>)>,
    token_request: Option<Hook>,
    password_grant: Option<Hook>,
    extension_grants: std::collections::BTreeMap<String, Hook>,
    ciba_user: Option<Hook>,
    ciba_notification: Option<Hook>,
    ciba_request: Option<Hook>,
    http: reqwest::Client,
    keys: KeyService,
    issuer: String,
}

impl std::fmt::Debug for Hooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hooks")
            .field(
                "profile_claims",
                &self.profile.as_ref().map(|(h, _)| h.config.url.as_str()),
            )
            .field(
                "subject_active",
                &self.active.as_ref().map(|(h, _)| h.config.url.as_str()),
            )
            .finish()
    }
}

fn check_url(url: &Url) -> Result<(), HookConfigError> {
    let loopback = match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        None => false,
    };
    match url.scheme() {
        "https" => Ok(()),
        "http" if loopback => Ok(()),
        _ => Err(HookConfigError::InsecureUrl(url.clone())),
    }
}

fn cache<V: Clone + Send + Sync + 'static>(hook: &HookConfig) -> Cache<String, V> {
    let ttl = u64::try_from(hook.cache_duration.0).unwrap_or(0);
    Cache::builder()
        .max_capacity(if ttl == 0 { 0 } else { 100_000 })
        .time_to_live(Duration::from_secs(ttl.max(1)))
        .build()
}

impl Hooks {
    /// `issuer` names the server in the hook JWT (`iss`).
    pub fn new(
        config: HooksConfig,
        keys: KeyService,
        issuer: String,
    ) -> Result<Hooks, HookConfigError> {
        for hook in [
            &config.profile_claims,
            &config.subject_active,
            &config.token_request,
            &config.password_grant,
            &config.ciba_user,
            &config.ciba_notification,
            &config.ciba_request,
        ]
        .into_iter()
        .flatten()
        .chain(config.extension_grants.values())
        {
            check_url(&hook.url)?;
        }
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| HookConfigError::Client(e.to_string()))?;
        Ok(Hooks {
            profile: config.profile_claims.map(|c| {
                let cache = cache(&c);
                (Hook { config: c }, cache)
            }),
            active: config.subject_active.map(|c| {
                let cache = cache(&c);
                (Hook { config: c }, cache)
            }),
            token_request: config.token_request.map(|c| Hook { config: c }),
            password_grant: config.password_grant.map(|c| Hook { config: c }),
            extension_grants: config
                .extension_grants
                .into_iter()
                .map(|(grant_type, c)| (grant_type, Hook { config: c }))
                .collect(),
            ciba_user: config.ciba_user.map(|c| Hook { config: c }),
            ciba_notification: config.ciba_notification.map(|c| Hook { config: c }),
            ciba_request: config.ciba_request.map(|c| Hook { config: c }),
            http,
            keys,
            issuer,
        })
    }

    /// Whether any hook is configured.
    pub fn is_empty(&self) -> bool {
        self.profile.is_none()
            && self.active.is_none()
            && self.token_request.is_none()
            && self.password_grant.is_none()
            && self.extension_grants.is_empty()
            && !self.has_ciba()
    }

    /// Whether any CIBA hook is configured.
    pub fn has_ciba(&self) -> bool {
        self.ciba_user.is_some() || self.ciba_notification.is_some() || self.ciba_request.is_some()
    }

    /// The bearer JWT for one call to `hook`.
    async fn token(&self, hook: &Hook) -> Result<String, HookError> {
        let key = self
            .keys
            .signing_key(&[])
            .await
            .map_err(|e| HookError::Signing(e.to_string()))?
            .ok_or_else(|| HookError::Signing("no signing key".into()))?;
        let now = chrono::Utc::now().timestamp();
        let mut payload = Map::new();
        payload.insert("iss".into(), json!(self.issuer));
        payload.insert("aud".into(), json!(hook.config.url.as_str()));
        payload.insert("iat".into(), json!(now));
        payload.insert("exp".into(), json!(now + TOKEN_LIFETIME_SECONDS));
        payload.insert("jti".into(), json!(rustid_core::tokens::new_jwt_id()));
        rustid_core::jwt::encode(&key, &[("typ", HOOK_TOKEN_TYPE)], &payload)
            .map_err(|e| HookError::Signing(e.to_string()))
    }

    /// POSTs `body` and returns the answer, checked for its version.
    async fn call(&self, hook: &Hook, body: &Value) -> Result<Value, HookError> {
        let token = self.token(hook).await?;
        let seconds = u64::try_from(hook.config.timeout.0).unwrap_or(5).max(1);
        let response = self
            .http
            .post(hook.config.url.clone())
            .bearer_auth(token)
            .json(body)
            .timeout(Duration::from_secs(seconds))
            .send()
            .await
            .map_err(|e| HookError::Transport(e.to_string()))?;
        if !response.status().is_success() {
            return Err(HookError::Status(response.status().as_u16()));
        }
        let answer: Value = response
            .json()
            .await
            .map_err(|e| HookError::Body(e.to_string()))?;
        match answer.get("version").and_then(Value::as_u64) {
            Some(v) if v == u64::from(VERSION) => Ok(answer),
            Some(v) => Err(HookError::Version(u32::try_from(v).unwrap_or(u32::MAX))),
            None => Err(HookError::Body("no version".into())),
        }
    }

    /// A hook failure under the hook's policy: an error, or `None` to fall
    /// back to the default.
    fn failed<T>(hook: &Hook, name: &str, error: HookError) -> Result<Option<T>, ProfileError> {
        match hook.config.failure_policy {
            FailurePolicy::FailClosed => Err(ProfileError(format!(
                "the {name} hook at {} failed: {error}",
                hook.config.url
            ))),
            FailurePolicy::FailOpen => {
                tracing::warn!(url = %hook.config.url, %error, "the {name} hook failed; using the default");
                Ok(None)
            }
        }
    }
}

/// A claim as hooks send and receive it.
#[derive(Debug, Serialize, Deserialize)]
struct HookClaim {
    #[serde(rename = "type")]
    claim_type: String,
    value: String,
    #[serde(default)]
    value_type: Option<String>,
}

impl HookClaim {
    fn into_claim(self) -> Claim {
        Claim {
            claim_type: self.claim_type,
            value: self.value,
            value_type: self
                .value_type
                .unwrap_or_else(|| rustid_core::clients::CLAIM_VALUE_TYPE_STRING.to_owned()),
        }
    }
}

fn subject(subject_id: &str, claims: &[Claim]) -> Value {
    json!({
        "sub": subject_id,
        "claims": claims.iter().map(|c| json!({
            "type": c.claim_type,
            "value": c.value,
            "value_type": c.value_type,
        })).collect::<Vec<_>>(),
    })
}

fn key(parts: &[&str]) -> String {
    parts.join("\u{0}")
}

#[async_trait]
impl ProfileService for Hooks {
    async fn profile_claims(
        &self,
        request: &ProfileRequest<'_>,
    ) -> Result<Vec<Claim>, ProfileError> {
        let Some((hook, cache)) = &self.profile else {
            return DefaultProfileService.profile_claims(request).await;
        };
        let requested = request.requested_claim_types.join(",");
        let cache_key = key(&[
            request.caller,
            &request.client.client_id,
            request.subject_id,
            &requested,
        ]);
        if let Some(claims) = cache.get(&cache_key).await {
            return Ok(claims);
        }
        let body = json!({
            "version": VERSION,
            "caller": request.caller,
            "client_id": request.client.client_id,
            "subject": subject(request.subject_id, request.subject_claims),
            "requested_claim_types": request.requested_claim_types,
        });
        let answer = match self.call(hook, &body).await {
            Ok(answer) => answer,
            Err(e) => {
                return match Self::failed(hook, "profile claims", e)? {
                    Some(claims) => Ok(claims),
                    None => DefaultProfileService.profile_claims(request).await,
                };
            }
        };
        // No claims (absent or null) means none, treating a null
        // `IssuedClaims`; anything else must be a list of claims.
        let parsed: Result<Vec<HookClaim>, _> = match answer.get("claims") {
            None | Some(Value::Null) => Ok(Vec::new()),
            Some(claims) => serde_json::from_value(claims.clone()),
        };
        let claims: Vec<Claim> = match parsed {
            Ok(claims) => claims
                .into_iter()
                .map(|c| Claim {
                    claim_type: c.claim_type,
                    value: c.value,
                    value_type: c.value_type.unwrap_or_else(|| {
                        rustid_core::clients::CLAIM_VALUE_TYPE_STRING.to_owned()
                    }),
                })
                .collect(),
            Err(e) => {
                return match Self::failed(hook, "profile claims", HookError::Body(e.to_string()))? {
                    Some(claims) => Ok(claims),
                    None => DefaultProfileService.profile_claims(request).await,
                };
            }
        };
        // `AddRequestedClaims`: only what was asked for.
        let claims = requested_claims(&claims, request.requested_claim_types);
        cache.insert(cache_key, claims.clone()).await;
        Ok(claims)
    }

    async fn is_active(&self, request: &ActiveRequest<'_>) -> Result<bool, ProfileError> {
        let Some((hook, cache)) = &self.active else {
            return DefaultProfileService.is_active(request).await;
        };
        let cache_key = key(&[
            request.caller,
            &request.client.client_id,
            request.subject_id,
        ]);
        if let Some(active) = cache.get(&cache_key).await {
            return Ok(active);
        }
        let body = json!({
            "version": VERSION,
            "caller": request.caller,
            "client_id": request.client.client_id,
            "subject": subject(request.subject_id, request.subject_claims),
        });
        let active = match self.call(hook, &body).await {
            Ok(answer) => match answer.get("active").and_then(Value::as_bool) {
                Some(active) => active,
                None => {
                    return Ok(Self::failed(
                        hook,
                        "subject active",
                        HookError::Body("no active".into()),
                    )?
                    .unwrap_or(true));
                }
            },
            Err(e) => return Ok(Self::failed(hook, "subject active", e)?.unwrap_or(true)),
        };
        cache.insert(cache_key, active).await;
        Ok(active)
    }
}

#[async_trait]
impl TokenRequestValidator for Hooks {
    async fn validate(
        &self,
        request: &TokenRequest<'_>,
    ) -> Result<TokenRequestVerdict, ProfileError> {
        let accept = || TokenRequestVerdict::Accept { custom: Map::new() };
        let Some(hook) = &self.token_request else {
            return Ok(accept());
        };
        let parameters: Map<String, Value> = request
            .parameters
            .iter()
            .map(|(k, v)| (k.clone(), Value::String(v.clone())))
            .collect();
        let body = json!({
            "version": VERSION,
            "grant_type": request.grant_type,
            "client_id": request.client.client_id,
            "subject_id": request.subject_id,
            "scopes": request.scopes,
            "parameters": parameters,
        });
        let answer = match self.call(hook, &body).await {
            Ok(answer) => answer,
            Err(e) => {
                return Ok(Self::failed(hook, "token request", e)?.unwrap_or_else(accept));
            }
        };
        let custom = match answer.get("custom_response") {
            None | Some(Value::Null) => Map::new(),
            Some(Value::Object(custom)) => custom.clone(),
            Some(_) => {
                let error = HookError::Body("custom_response is not an object".into());
                return Ok(Self::failed(hook, "token request", error)?.unwrap_or_else(accept));
            }
        };
        let error = answer.get("error").and_then(Value::as_str);
        if let Some(error) = error
            && !is_error_code(error)
        {
            let error = HookError::Body(format!("error {error:?} is not an OAuth error code"));
            return Ok(Self::failed(hook, "token request", error)?.unwrap_or_else(accept));
        }
        Ok(match error {
            Some(error) => TokenRequestVerdict::Reject {
                error: error.to_owned(),
                description: answer
                    .get("error_description")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                custom,
            },
            None => TokenRequestVerdict::Accept { custom },
        })
    }
}

/// RFC 6749 section 5.2: `error` is `1*NQSCHAR` (printable ASCII without
/// `"` and `\`); rustid also wants something besides spaces, and at most
/// 100 characters, since it becomes a metric tag.
fn is_error_code(error: &str) -> bool {
    error.len() <= 100
        && !error.trim().is_empty()
        && error
            .bytes()
            .all(|b| matches!(b, 0x20..=0x21 | 0x23..=0x5B | 0x5D..=0x7E))
}

/// A grant hook's answer as a grant result. Any failure (transport, an
/// unreadable answer) is an error whatever the failure policy: a grant
/// can't be let through without its validator.
fn grant_answer(
    name: &str,
    hook: &Hook,
    answer: Result<Value, HookError>,
) -> Result<GrantAnswer, ProfileError> {
    let fail = |error: HookError| {
        ProfileError(format!(
            "the {name} hook at {} failed: {error}",
            hook.config.url
        ))
    };
    let answer = answer.map_err(fail)?;
    let custom = match answer.get("custom_response") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(custom)) => custom.clone(),
        Some(_) => {
            return Err(fail(HookError::Body(
                "custom_response is not an object".into(),
            )));
        }
    };
    let text = |v: &Value, field: &str| v.get(field).and_then(Value::as_str).map(str::to_owned);
    let result = if let Some(error) = answer.get("error").filter(|e| !e.is_null()) {
        let error = error
            .as_str()
            .filter(|e| is_error_code(e))
            .ok_or_else(|| fail(HookError::Body("error is not an OAuth error code".into())))?;
        GrantResult::Error {
            error: Some(error.to_owned()),
            description: text(&answer, "error_description"),
        }
    } else {
        match answer.get("subject").filter(|s| !s.is_null()) {
            Some(subject) => {
                let subject_id = text(subject, "sub")
                    .filter(|s| !s.trim().is_empty())
                    .ok_or_else(|| fail(HookError::Body("subject without sub".into())))?;
                let claims: Vec<HookClaim> = match subject.get("claims") {
                    None | Some(Value::Null) => Vec::new(),
                    Some(claims) => serde_json::from_value(claims.clone())
                        .map_err(|e| fail(HookError::Body(e.to_string())))?,
                };
                // GrantValidationResult can't be built without one.
                let authentication_method =
                    text(subject, "amr")
                        .filter(|s| !s.trim().is_empty())
                        .ok_or_else(|| fail(HookError::Body("subject without amr".into())))?;
                GrantResult::Subject(GrantSubject {
                    subject_id,
                    authentication_method,
                    idp: text(subject, "idp"),
                    claims: claims.into_iter().map(HookClaim::into_claim).collect(),
                })
            }
            None => GrantResult::NoSubject,
        }
    };
    let client_claims: Vec<HookClaim> = match answer.get("client_claims") {
        None | Some(Value::Null) => Vec::new(),
        Some(claims) => serde_json::from_value(claims.clone())
            .map_err(|e| fail(HookError::Body(e.to_string())))?,
    };
    let access_token_type = match answer.get("access_token_type").and_then(Value::as_str) {
        None => None,
        Some("jwt") => Some(rustid_core::clients::AccessTokenType::Jwt),
        Some("reference") => Some(rustid_core::clients::AccessTokenType::Reference),
        Some(other) => {
            return Err(fail(HookError::Body(format!(
                "access_token_type {other:?} is not jwt or reference"
            ))));
        }
    };
    Ok(GrantAnswer {
        result,
        custom,
        changes: RequestChanges {
            client_id: text(&answer, "client_id").filter(|c| !c.trim().is_empty()),
            access_token_lifetime: answer.get("access_token_lifetime").and_then(Value::as_i64),
            access_token_type,
            client_claims: client_claims
                .into_iter()
                .map(HookClaim::into_claim)
                .collect(),
        },
    })
}

fn parameters_object(parameters: &[(String, String)]) -> Map<String, Value> {
    parameters
        .iter()
        .map(|(k, v)| (k.clone(), Value::String(v.clone())))
        .collect()
}

#[async_trait]
impl GrantValidator for Hooks {
    fn supports_password(&self) -> bool {
        self.password_grant.is_some()
    }

    fn extension_grant_types(&self) -> Vec<String> {
        self.extension_grants.keys().cloned().collect()
    }

    async fn validate_password(
        &self,
        request: &PasswordRequest<'_>,
    ) -> Result<GrantAnswer, ProfileError> {
        let Some(hook) = &self.password_grant else {
            return Ok(GrantAnswer::error("unsupported_grant_type"));
        };
        let body = json!({
            "version": VERSION,
            "client_id": request.client.client_id,
            "username": request.username,
            "password": request.password,
            "parameters": parameters_object(request.parameters),
        });
        grant_answer("password grant", hook, self.call(hook, &body).await)
    }

    async fn validate_extension(
        &self,
        request: &ExtensionRequest<'_>,
    ) -> Result<GrantAnswer, ProfileError> {
        let Some(hook) = self.extension_grants.get(request.grant_type) else {
            return Ok(GrantAnswer::error("unsupported_grant_type"));
        };
        let body = json!({
            "version": VERSION,
            "grant_type": request.grant_type,
            "client_id": request.client.client_id,
            "parameters": parameters_object(request.parameters),
        });
        grant_answer("extension grant", hook, self.call(hook, &body).await)
    }
}

/// A CIBA hook's failure: an error whatever the failure policy, as for the
/// grant hooks, since a request can't be let through without its validator.
fn ciba_failure(name: &str, hook: &Hook, error: HookError) -> ProfileError {
    ProfileError(format!(
        "the {name} hook at {} failed: {error}",
        hook.config.url
    ))
}

/// Parameters the custom validator never sees: client credentials and the
/// request object (whose claims are already among the parameters).
fn is_hidden_parameter(name: &str) -> bool {
    name == "client_secret" || name.starts_with("client_assertion") || name == "request"
}

#[async_trait]
impl CibaService for Hooks {
    async fn validate_user(
        &self,
        request: &CibaUserRequest<'_>,
    ) -> Result<CibaUserResult, ProfileError> {
        let Some(hook) = &self.ciba_user else {
            return NopCibaService.validate_user(request).await;
        };
        let body = json!({
            "version": VERSION,
            "client_id": request.client.client_id,
            "login_hint": request.login_hint,
            "login_hint_token": request.login_hint_token,
            "id_token_hint": request.id_token_hint,
            "id_token_hint_claims": request.id_token_hint_claims,
            "user_code": request.user_code,
            "binding_message": request.binding_message,
        });
        let fail = |error| ciba_failure("CIBA user", hook, error);
        let answer = self.call(hook, &body).await.map_err(fail)?;
        let text = |v: &Value, field: &str| v.get(field).and_then(Value::as_str).map(str::to_owned);
        if let Some(error) = answer.get("error").filter(|e| !e.is_null()) {
            let error = error
                .as_str()
                .ok_or_else(|| fail(HookError::Body("error is not a string".into())))?;
            return Ok(CibaUserResult::Error {
                error: error.to_owned(),
                description: text(&answer, "error_description"),
            });
        }
        // No subject, or one without `sub`, names no one: the endpoint
        // answers `unknown_user_id`.
        let Some(subject) = answer.get("subject").filter(|s| !s.is_null()) else {
            return Ok(CibaUserResult::Subject {
                subject_id: None,
                claims: Vec::new(),
            });
        };
        let claims: Vec<HookClaim> = match subject.get("claims") {
            None | Some(Value::Null) => Vec::new(),
            Some(claims) => serde_json::from_value(claims.clone())
                .map_err(|e| fail(HookError::Body(e.to_string())))?,
        };
        Ok(CibaUserResult::Subject {
            subject_id: text(subject, "sub"),
            claims: claims.into_iter().map(HookClaim::into_claim).collect(),
        })
    }

    async fn notify_user(&self, notification: &CibaNotification<'_>) -> Result<(), ProfileError> {
        let Some(hook) = &self.ciba_notification else {
            return NopCibaService.notify_user(notification).await;
        };
        let body = json!({
            "version": VERSION,
            "internal_id": notification.internal_id,
            "subject_id": notification.subject_id,
            "client_id": notification.client.client_id,
            "scopes": notification.scopes,
            "resource_indicators": notification.resource_indicators,
            "binding_message": notification.binding_message,
            "acr_values": notification.acr_values,
            "tenant": notification.tenant,
            "idp": notification.idp,
            "properties": notification.properties,
        });
        self.call(hook, &body)
            .await
            .map_err(|e| ciba_failure("CIBA notification", hook, e))?;
        Ok(())
    }

    async fn validate_request(
        &self,
        request: &CibaCustomRequest<'_>,
    ) -> Result<CibaCustomAnswer, ProfileError> {
        let Some(hook) = &self.ciba_request else {
            return NopCibaService.validate_request(request).await;
        };
        let parameters: Map<String, Value> = request
            .parameters
            .iter()
            .filter(|(k, _)| !is_hidden_parameter(k))
            .map(|(k, v)| (k.clone(), Value::String(v.clone())))
            .collect();
        let body = json!({
            "version": VERSION,
            "client_id": request.client.client_id,
            "subject_id": request.subject_id,
            "scopes": request.scopes,
            "binding_message": request.binding_message,
            "parameters": parameters,
        });
        let fail = |error| ciba_failure("CIBA request", hook, error);
        let answer = self.call(hook, &body).await.map_err(fail)?;
        let properties = match answer.get("properties") {
            None | Some(Value::Null) => Map::new(),
            Some(Value::Object(properties)) => properties.clone(),
            Some(_) => {
                return Err(fail(HookError::Body("properties is not an object".into())));
            }
        };
        let error = match answer.get("error") {
            None | Some(Value::Null) => None,
            Some(Value::String(error)) => Some(error.clone()),
            Some(_) => return Err(fail(HookError::Body("error is not a string".into()))),
        };
        Ok(CibaCustomAnswer { error, properties })
    }
}
