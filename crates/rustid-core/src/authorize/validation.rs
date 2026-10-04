//! The checks and their order, error codes and
//! descriptions are fixed, because the error page shows them.

use std::sync::Arc;

use chrono::{DateTime, Utc};

use super::request::ValidatedAuthorizeRequest;
use super::request_object;
use super::*;
use crate::clients::{Client, validate_client};
use crate::events::{Event, EventService, RequestInfo};
use crate::options::{InputLengthRestrictions, ProtocolOptions};
use crate::params::{Params, split_spaces, utf16_len};
use crate::scopes::{ResourceValidationError, validate_requested_resources};
use crate::session::UserSession;
use crate::stores::{StoreError, Stores};
use crate::telemetry;

/// `Constants.SupportedResponseTypes`, in order.
pub const RESPONSE_TYPES: &[&str] = &[
    "code",
    "token",
    "id_token",
    "id_token token",
    "code id_token",
    "code token",
    "code id_token token",
];

/// `Constants.SupportedDisplayModes`.
pub const DISPLAY_MODES: &[&str] = &["page", "popup", "touch", "wap"];

pub const AUTHORIZATION_CODE: &str = "authorization_code";
pub const IMPLICIT: &str = "implicit";
pub const HYBRID: &str = "hybrid";

/// `Constants.ResponseTypeToGrantTypeMapping`.
fn grant_type_for(response_type: &str) -> &'static str {
    match response_type {
        "code" => AUTHORIZATION_CODE,
        "token" | "id_token" | "id_token token" => IMPLICIT,
        _ => HYBRID,
    }
}

/// `Constants.AllowedResponseModesForGrantType`; the first is the default.
/// With JARM, the JWT forms of each (never `query.jwt` for responses that
/// carry tokens: JARM 2.3.1).
fn allowed_response_modes(grant_type: &str, jarm: bool) -> &'static [&'static str] {
    match (grant_type == AUTHORIZATION_CODE, jarm) {
        (true, false) => &["query", "form_post", "fragment"],
        (true, true) => &[
            "query",
            "form_post",
            "fragment",
            "query.jwt",
            "form_post.jwt",
            "fragment.jwt",
        ],
        (false, false) => &["fragment", "form_post"],
        (false, true) => &["fragment", "form_post", "fragment.jwt", "form_post.jwt"],
    }
}

/// `Constants.ScopeRequirement`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScopeRequirement {
    None,
    ResourceOnly,
    IdentityOnly,
    Identity,
}

fn scope_requirement(response_type: &str) -> ScopeRequirement {
    match response_type {
        "code" => ScopeRequirement::None,
        "token" => ScopeRequirement::ResourceOnly,
        "id_token" => ScopeRequirement::IdentityOnly,
        _ => ScopeRequirement::Identity,
    }
}

/// `ResponseTypeEqualityComparer`: the same space-separated values in any
/// order (an exact split on single spaces).
fn matching_response_type(value: &str) -> Option<&'static str> {
    let mut wanted: Vec<&str> = value.split(' ').collect();
    wanted.sort_unstable();
    RESPONSE_TYPES.iter().copied().find(|supported| {
        if supported.len() != value.len() {
            return false;
        }
        let mut have: Vec<&str> = supported.split(' ').collect();
        have.sort_unstable();
        have == wanted
    })
}

/// What validation needs from the server.
pub struct AuthorizeContext<'a> {
    pub options: &'a ProtocolOptions,
    /// The issuer for this request: request objects' audience.
    pub issuer: &'a str,
    pub stores: &'a Stores,
    pub events: &'a EventService,
    pub request: &'a RequestInfo,
    pub now: DateTime<Utc>,
}

/// A validation error: the partly validated request plus the OAuth error.
#[derive(Debug, Clone)]
pub struct AuthorizeError {
    pub request: Box<ValidatedAuthorizeRequest>,
    pub error: &'static str,
    pub description: Option<String>,
}

#[derive(Debug, Clone)]
pub enum AuthorizeFailure {
    Invalid(AuthorizeError),
    /// A store failed; HTTP 500.
    Server(String),
}

impl From<StoreError> for AuthorizeFailure {
    fn from(e: StoreError) -> Self {
        AuthorizeFailure::Server(e.to_string())
    }
}

type Step = Result<(), (&'static str, Option<&'static str>)>;

fn invalid(description: &'static str) -> Step {
    Err((INVALID_REQUEST, Some(description)))
}

/// Validate for the browser's session, if it has one. Mutates
/// nothing outside the returned request.
pub async fn validate(
    ctx: &AuthorizeContext<'_>,
    raw: Params,
    session: Option<&UserSession>,
) -> Result<ValidatedAuthorizeRequest, AuthorizeFailure> {
    let mut request = ValidatedAuthorizeRequest {
        raw,
        subject: session.cloned(),
        ..Default::default()
    };
    match run(ctx, &mut request).await? {
        Ok(()) => Ok(request),
        Err((error, description)) => Err(AuthorizeFailure::Invalid(AuthorizeError {
            request: Box::new(request),
            error,
            description: description.map(str::to_owned),
        })),
    }
}

/// Validate at the PAR endpoint: no session, and a pushed request
/// doesn't itself need pushing.
pub async fn validate_pushed(
    ctx: &AuthorizeContext<'_>,
    raw: Params,
) -> Result<ValidatedAuthorizeRequest, AuthorizeFailure> {
    let mut request = ValidatedAuthorizeRequest {
        raw,
        request_type: AuthorizeRequestType::PushedAuthorization,
        ..Default::default()
    };
    match run(ctx, &mut request).await? {
        Ok(()) => Ok(request),
        Err((error, description)) => Err(AuthorizeFailure::Invalid(AuthorizeError {
            request: Box::new(request),
            error,
            description: description.map(str::to_owned),
        })),
    }
}

async fn run(
    ctx: &AuthorizeContext<'_>,
    r: &mut ValidatedAuthorizeRequest,
) -> Result<Step, StoreError> {
    let limits = &ctx.options.input_length_restrictions;
    if let e @ Err(_) = validate_ui_locales(r, limits) {
        return Ok(e);
    }
    if let e @ Err(_) = load_client(ctx, r).await? {
        return Ok(e);
    }
    if let e @ Err(_) = load_request_object(ctx, r).await {
        return Ok(e);
    }
    if let e @ Err(_) = validate_request_object(ctx, r) {
        return Ok(e);
    }
    if let e @ Err(_) = validate_ui_locales(r, limits) {
        return Ok(e);
    }
    if let e @ Err(_) = validate_client_and_redirect_uri(r, limits) {
        return Ok(e);
    }
    if let e @ Err(_) = validate_core_parameters(ctx.options, r) {
        return Ok(e);
    }
    if let e @ Err(_) = validate_scope_and_resources(ctx, r).await? {
        return Ok(e);
    }
    Ok(validate_optional_parameters(ctx.options, r))
}

fn client(r: &ValidatedAuthorizeRequest) -> &Arc<Client> {
    r.client.as_ref().expect("client loaded before this step")
}

fn validate_ui_locales(
    r: &mut ValidatedAuthorizeRequest,
    limits: &InputLengthRestrictions,
) -> Step {
    if let Some(ui_locales) = r.raw.get("ui_locales") {
        if utf16_len(&ui_locales) > limits.ui_locale {
            return invalid("Invalid ui_locales");
        }
        r.ui_locales = Some(ui_locales);
    }
    Ok(())
}

/// A client whose
/// configuration is invalid counts as unknown.
async fn load_client(
    ctx: &AuthorizeContext<'_>,
    r: &mut ValidatedAuthorizeRequest,
) -> Result<Step, StoreError> {
    let limits = &ctx.options.input_length_restrictions;
    let Some(client_id) = r
        .raw
        .get("client_id")
        .filter(|id| !id.trim().is_empty() && utf16_len(id) <= limits.client_id)
    else {
        return Ok(invalid("Invalid client_id"));
    };
    r.client_id = Some(client_id.clone());
    let unknown = Err((
        UNAUTHORIZED_CLIENT,
        Some("Unknown client or client not enabled"),
    ));
    let Some(client) = ctx.stores.clients.find_client_by_id(&client_id).await? else {
        telemetry::client_validation_failure(&client_id, "Client not found");
        return Ok(unknown);
    };
    if let Err(problem) = validate_client(
        &client,
        ctx.options
            .pushed_authorization
            .allow_unregistered_pushed_redirect_uris,
    ) {
        tracing::error!(client_id = %client.client_id, %problem, "invalid client configuration");
        telemetry::client_validation_failure(&client.client_id, &problem);
        ctx.events.raise(
            ctx.request,
            ctx.now,
            Event::invalid_client_configuration(
                &client.client_id,
                client.client_name.as_deref(),
                &problem,
            ),
        );
        return Ok(unknown);
    }
    telemetry::client_validation(&client.client_id);
    if !client.enabled {
        return Ok(unknown);
    }
    r.client = Some(client);
    Ok(Ok(()))
}

/// At most one of
/// `request` and `request_uri`; pushed authorization when required; a PAR
/// `request_uri` loads the pushed request, another is fetched when request
/// URIs are enabled; the object is length-limited.
async fn load_request_object(
    ctx: &AuthorizeContext<'_>,
    r: &mut ValidatedAuthorizeRequest,
) -> Step {
    let options = ctx.options;
    let mut request_object = r.raw.get("request");
    let request_uri = r.raw.get("request_uri");
    if request_object.is_some() && request_uri.is_some() {
        return invalid("Only one request parameter is allowed");
    }
    let is_par = request_uri
        .as_deref()
        .is_some_and(|u| u.starts_with(PAR_REQUEST_URI_PREFIX));
    if r.request_type != AuthorizeRequestType::PushedAuthorization {
        let par_required =
            options.pushed_authorization.required || client(r).require_pushed_authorization;
        if par_required && !is_par {
            return invalid("Pushed authorization is required.");
        }
    }
    if let Some(uri) = &request_uri {
        if is_par {
            if let e @ Err(_) = load_pushed_request(ctx, r, uri).await {
                return e;
            }
            r.request_type = AuthorizeRequestType::AuthorizeWithPushedParameters;
            request_object = r.raw.get("request");
        } else {
            if !options.endpoints.enable_jwt_request_uri {
                return Err((REQUEST_URI_NOT_SUPPORTED, None));
            }
            if utf16_len(uri) > 512 {
                return Err((INVALID_REQUEST_URI, Some("request_uri is too long")));
            }
            // `DefaultJwtRequestUriHttpClient`: a 200, of the JAR media type
            // when validation is strict.
            let fetched = ctx.stores.request_uri.fetch(uri).await.filter(|f| {
                f.status == 200
                    && (!options.strict_jar_validation
                        || f.content_type.as_deref() == Some("application/oauth-authz-req+jwt"))
            });
            match fetched.map(|f| f.body).filter(|b| !b.trim().is_empty()) {
                Some(body) => request_object = Some(body),
                None => {
                    return Err((
                        INVALID_REQUEST_URI,
                        Some("no value returned from request_uri"),
                    ));
                }
            }
        }
    }
    if let Some(object) = &request_object
        && utf16_len(object) >= options.input_length_restrictions.jwt
    {
        return Err((INVALID_REQUEST_OBJECT, Some("Invalid request value")));
    }
    r.request_object = request_object;
    Ok(())
}

/// `ValidatePushedAuthorizationRequest`: the pushed request must exist,
/// PAR must still be enabled, the request must be the same client's and
/// unexpired; its parameters replace the query's, keeping the processed
/// prompt and `max_age` markers, which are never pushed.
async fn load_pushed_request(
    ctx: &AuthorizeContext<'_>,
    r: &mut ValidatedAuthorizeRequest,
    uri: &str,
) -> Step {
    if !ctx.options.endpoints.enable_pushed_authorization_endpoint {
        return Err((
            INVALID_REQUEST_URI,
            Some("Pushed authorization is disabled."),
        ));
    }
    let reference = uri
        .get(PAR_REQUEST_URI_PREFIX.len() + 1..)
        .unwrap_or_default();
    let reused = Err((
        INVALID_REQUEST_URI,
        Some("invalid or reused PAR request uri"),
    ));
    if reference.is_empty() {
        return reused;
    }
    let pushed = match crate::pushed_authorization::get(ctx.stores.grants.as_ref(), reference).await
    {
        Ok(Some(pushed)) => pushed,
        Ok(None) => return reused,
        Err(e) => {
            tracing::error!(error = %e, "reading a pushed authorization request failed");
            return reused;
        }
    };
    r.pushed_reference = Some(reference.to_owned());
    let processed_prompt = r.raw.get(PROCESSED_PROMPT);
    let processed_max_age = r.raw.get(PROCESSED_MAX_AGE);
    r.raw = Params::parse_query(&pushed.parameters);
    if let Some(prompt) = processed_prompt {
        r.raw.set(PROCESSED_PROMPT, &prompt);
    }
    if let Some(max_age) = processed_max_age {
        r.raw.set(PROCESSED_MAX_AGE, &max_age);
    }
    if r.raw.get("client_id") != r.client_id {
        return Err((
            INVALID_REQUEST_URI,
            Some("invalid client for pushed authorization request"),
        ));
    }
    if ctx.now > pushed.expires_at {
        return Err((
            INVALID_REQUEST_URI,
            Some("expired pushed authorization request"),
        ));
    }
    Ok(())
}

/// The return URL's query for the UI: a pushed
/// request by reference with the processed markers; a request with a
/// request object without the parameters the object carries
/// (`ToOptimizedQueryString`), always keeping `client_id` and
/// `response_type`; otherwise every parameter.
pub fn return_url_query(r: &ValidatedAuthorizeRequest) -> String {
    if let Some(reference) = &r.pushed_reference {
        let mut params = Params::default();
        params.add(
            "request_uri",
            &format!("{PAR_REQUEST_URI_PREFIX}:{reference}"),
        );
        params.add("client_id", r.client_id.as_deref().unwrap_or_default());
        for marker in [PROCESSED_PROMPT, PROCESSED_MAX_AGE] {
            if let Some(value) = r.raw.get(marker) {
                params.add(marker, &value);
            }
        }
        return params.to_query_string();
    }
    if r.raw.contains("request") {
        let mut params = Params::default();
        for (key, values) in r.raw.iter() {
            if key == "client_id"
                || key == "response_type"
                || !r.request_object_values.iter().any(|(k, _)| k == key)
            {
                for value in values {
                    params.add(key, value);
                }
            }
        }
        return params.to_query_string();
    }
    r.raw.to_query_string()
}

/// A client that
/// requires a request object must send one; the object must validate for
/// the client, name it in `client_id`, and agree on `response_type`; its
/// parameters then replace the query's (on a pushed request, a duplicate
/// other than client authentication is an error). On the authorize
/// endpoint a `request_uri` is replaced by `request`, so the return URL
/// carries the object itself.
fn validate_request_object(ctx: &AuthorizeContext<'_>, r: &mut ValidatedAuthorizeRequest) -> Step {
    const CLIENT_AUTHENTICATION: &[&str] = &[
        "client_id",
        "client_secret",
        "client_assertion",
        "client_assertion_type",
    ];
    if client(r).require_request_object && r.request_object.is_none() {
        return invalid(
            "Client must use request object, but no request or request_uri parameter present",
        );
    }
    let Some(object) = r.request_object.clone() else {
        return Ok(());
    };
    let invalid_object = Err((INVALID_REQUEST_OBJECT, Some("Invalid JWT request")));
    let Some(payload) = request_object::validate(
        ctx.options,
        ctx.issuer,
        client(r),
        &object,
        ctx.now.timestamp(),
    ) else {
        return invalid_object;
    };
    let first = |name: &str| {
        payload
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };
    if let Some(response_type) = r.raw.get("response_type")
        && let Some(object_type) = first("response_type").filter(|t| !t.is_empty())
        && object_type != response_type
    {
        return invalid("Invalid JWT request");
    }
    match first("client_id").filter(|id| !id.is_empty()) {
        Some(id) if id != client(r).client_id => return invalid("Invalid JWT request"),
        Some(_) => {}
        None => return invalid_object,
    }
    let mut names: Vec<&str> = Vec::new();
    for (name, _) in &payload {
        if !names.contains(&name.as_str()) {
            names.push(name);
        }
    }
    for name in names {
        if r.raw.contains(name) {
            if r.request_type == AuthorizeRequestType::PushedAuthorization
                && !CLIENT_AUTHENTICATION.contains(&name)
            {
                return invalid("Invalid request");
            }
            r.raw.remove(name);
        }
    }
    for (name, value) in &payload {
        r.raw.add(name, value);
    }
    if r.request_type == AuthorizeRequestType::Authorize && r.raw.contains("request_uri") {
        r.raw.remove("request_uri");
        r.raw.add("request", &object);
    }
    r.request_object_values = payload;
    Ok(())
}

/// Redirect URI presence, form, protocol and match.
fn validate_client_and_redirect_uri(
    r: &mut ValidatedAuthorizeRequest,
    limits: &InputLengthRestrictions,
) -> Step {
    let Some(redirect_uri) = r
        .raw
        .get("redirect_uri")
        .filter(|u| !u.trim().is_empty() && utf16_len(u) <= limits.redirect_uri)
    else {
        return invalid("Invalid redirect_uri");
    };
    if !is_uri(&redirect_uri) {
        return invalid("Invalid redirect_uri");
    }
    let client = client(r);
    if client.protocol_type != "oidc" {
        return Err((UNAUTHORIZED_CLIENT, Some("Invalid protocol")));
    }
    // Exact, case-insensitive match.
    let registered = client
        .redirect_uris
        .iter()
        .any(|u| u.to_lowercase() == redirect_uri.to_lowercase());
    if !registered {
        return invalid("Invalid redirect_uri");
    }
    r.redirect_uri = Some(redirect_uri);
    Ok(())
}

/// `string.IsUri()`: an absolute URI. A bare path (which reads as a
/// file URI) doesn't count.
pub fn is_uri(value: &str) -> bool {
    url::Url::parse(value)
        .is_ok_and(|u| u.scheme() != "file" || value.to_ascii_lowercase().starts_with("file"))
}

/// `ValidateCoreParameters`: state, response type, response mode, PKCE,
/// grant type and access tokens via the browser.
fn validate_core_parameters(options: &ProtocolOptions, r: &mut ValidatedAuthorizeRequest) -> Step {
    r.state = r.raw.get("state");
    let Some(response_type) = r.raw.get("response_type") else {
        return invalid("Missing response_type");
    };
    let Some(canonical) = matching_response_type(&response_type) else {
        return Err((
            UNSUPPORTED_RESPONSE_TYPE,
            Some("Response type not supported"),
        ));
    };
    r.response_type = Some(canonical);
    let grant_type = grant_type_for(canonical);
    r.grant_type = Some(grant_type);
    let jarm = options.jarm.enabled;
    let allowed = allowed_response_modes(grant_type, jarm);
    r.response_mode = Some(allowed[0]);
    if let Some(mode) = r.raw.get("response_mode") {
        // JARM 2.3.4: `jwt` is `query.jwt` for code, else `fragment.jwt`.
        let mode = match mode.as_str() {
            "jwt" if jarm && grant_type == AUTHORIZATION_CODE => "query.jwt".to_owned(),
            "jwt" if jarm => "fragment.jwt".to_owned(),
            _ => mode,
        };
        // Every mode some response type allows: the code flow's.
        let known = allowed_response_modes(AUTHORIZATION_CODE, jarm);
        match known.iter().copied().find(|m| *m == mode) {
            Some(supported) if allowed.contains(&supported) => r.response_mode = Some(supported),
            Some(_) => return invalid("Invalid response_mode for response_type"),
            None => return Err((UNSUPPORTED_RESPONSE_TYPE, Some("Invalid response_mode"))),
        }
    }
    if grant_type == AUTHORIZATION_CODE || grant_type == HYBRID {
        validate_pkce(r)?;
    }
    let client = client(r);
    if !client.allows_grant(grant_type) {
        return Err((UNAUTHORIZED_CLIENT, Some("Invalid grant type for client")));
    }
    if split_spaces(&response_type).iter().any(|t| t == "token")
        && !client.allow_access_tokens_via_browser
    {
        return invalid("Client not configured to receive access tokens via browser");
    }
    Ok(())
}

fn validate_pkce(r: &mut ValidatedAuthorizeRequest) -> Step {
    let Some(challenge) = r.raw.get("code_challenge") else {
        if client(r).require_pkce {
            return invalid("code challenge required");
        }
        return Ok(());
    };
    let len = utf16_len(&challenge);
    if !(InputLengthRestrictions::CODE_CHALLENGE_MIN_LENGTH
        ..=InputLengthRestrictions::CODE_CHALLENGE_MAX_LENGTH)
        .contains(&len)
    {
        return invalid("Invalid code_challenge");
    }
    r.code_challenge = Some(challenge);
    let method = r
        .raw
        .get("code_challenge_method")
        .unwrap_or_else(|| "plain".to_owned());
    if method != "plain" && method != "S256" {
        return invalid("Transform algorithm not supported");
    }
    if method == "plain" && !client(r).allow_plain_text_pkce {
        return invalid("Transform algorithm not supported");
    }
    r.code_challenge_method = Some(method);
    Ok(())
}

async fn validate_scope_and_resources(
    ctx: &AuthorizeContext<'_>,
    r: &mut ValidatedAuthorizeRequest,
) -> Result<Step, StoreError> {
    let Some(scope) = r.raw.get("scope").filter(|s| !s.trim().is_empty()) else {
        return Ok(invalid("Invalid scope"));
    };
    if utf16_len(&scope) > ctx.options.input_length_restrictions.scope {
        return Ok(invalid("Invalid scope"));
    }
    let mut requested: Vec<String> = Vec::new();
    for s in split_spaces(&scope) {
        if !requested.contains(&s) {
            requested.push(s);
        }
    }
    r.is_openid_request = requested.iter().any(|s| s == "openid");
    r.requested_scopes = requested;
    let requirement = scope_requirement(r.response_type.expect("set by core validation"));
    if matches!(
        requirement,
        ScopeRequirement::Identity | ScopeRequirement::IdentityOnly
    ) && !r.is_openid_request
    {
        return Ok(invalid("Missing openid scope"));
    }

    let indicators: Vec<String> = r.raw.values("resource").to_vec();
    if !indicators.is_empty() {
        let max = ctx
            .options
            .input_length_restrictions
            .resource_indicator_max_length;
        if indicators.iter().any(|i| utf16_len(i) > max) {
            return Ok(Err((
                INVALID_TARGET,
                Some("Resource indicator maximum length exceeded"),
            )));
        }
        if indicators.iter().any(|i| !is_uri(i) || i.contains('#')) {
            return Ok(Err((
                INVALID_TARGET,
                Some("Invalid resource indicator format"),
            )));
        }
        if r.grant_type == Some(IMPLICIT) {
            return Ok(Err((
                INVALID_TARGET,
                Some("Resource indicators not allowed for response_type 'token'."),
            )));
        }
    }
    r.resource_indicators = indicators;

    let enabled = ctx.stores.resources.get_all_enabled_resources().await?;
    let resources = match validate_requested_resources(
        client(r),
        &enabled,
        &r.requested_scopes,
        &r.resource_indicators,
    ) {
        Ok(resources) => resources,
        Err(ResourceValidationError::InvalidResourceIndicator(_)) => {
            return Ok(Err((INVALID_TARGET, Some("Invalid resource indicator"))));
        }
        Err(ResourceValidationError::InvalidScope(_)) => {
            return Ok(Err((INVALID_SCOPE, Some("Invalid scope"))));
        }
    };
    let has_identity = !resources.identity_resources.is_empty();
    let has_api = !resources.api_scopes.is_empty();
    if has_identity && !r.is_openid_request {
        return Ok(Err((
            INVALID_SCOPE,
            Some("Identity scopes requested, but openid scope is missing"),
        )));
    }
    r.is_api_resource_request = has_api;
    let plausible = match requirement {
        ScopeRequirement::Identity => has_identity,
        ScopeRequirement::IdentityOnly => has_identity && !has_api,
        ScopeRequirement::ResourceOnly => !has_identity && has_api,
        ScopeRequirement::None => true,
    };
    if !plausible {
        return Ok(Err((
            INVALID_SCOPE,
            Some("Invalid scope for response type"),
        )));
    }
    r.resources = Some(resources);
    Ok(Ok(()))
}

/// Prompt values: all supported, and `none` or `create` only alone.
fn parse_prompt(value: &str, supported: &[String]) -> Option<Result<Vec<String>, ()>> {
    // `Split(' ', RemoveEmptyEntries)`: no trimming of other whitespace.
    let prompts: Vec<String> = value
        .split(' ')
        .filter(|p| !p.is_empty())
        .map(str::to_owned)
        .collect();
    if !prompts.iter().all(|p| supported.contains(p)) {
        return None;
    }
    let alone = |v: &str| prompts.iter().any(|p| p == v) && prompts.len() > 1;
    if alone("none") || alone("create") {
        return Some(Err(()));
    }
    Some(Ok(prompts))
}

fn validate_optional_parameters(
    options: &ProtocolOptions,
    r: &mut ValidatedAuthorizeRequest,
) -> Step {
    let limits = &options.input_length_restrictions;
    match r.raw.get("nonce") {
        Some(nonce) => {
            if utf16_len(&nonce) > limits.nonce {
                return invalid("Invalid nonce");
            }
            r.nonce = Some(nonce);
        }
        None => {
            if r.response_type
                .is_some_and(|t| t.split(' ').any(|v| v == "id_token"))
            {
                return invalid("Invalid nonce");
            }
        }
    }

    let supported = &options.user_interaction.prompt_values_supported;
    if let Some(prompt) = r.raw.get("prompt") {
        match parse_prompt(&prompt, supported) {
            Some(Ok(prompts)) => r.original_prompt_modes = prompts,
            Some(Err(())) => return invalid("Invalid prompt"),
            None => return invalid("Unsupported prompt mode"),
        }
    }
    if let Some(processed) = r.raw.get(PROCESSED_PROMPT) {
        match parse_prompt(&processed, supported) {
            Some(Ok(prompts)) => r.processed_prompt_modes = prompts,
            _ => return invalid("Invalid prompt"),
        }
    }
    let mut remaining: Vec<String> = Vec::new();
    for p in &r.original_prompt_modes {
        if !r.processed_prompt_modes.contains(p) && !remaining.contains(p) {
            remaining.push(p.clone());
        }
    }
    r.prompt_modes = remaining;

    if let Some(display) = r.raw.get("display")
        && DISPLAY_MODES.contains(&display.as_str())
    {
        r.display_mode = Some(display);
    }

    if let Some(max_age) = r.raw.get("max_age") {
        match parse_lenient_int(&max_age) {
            Some(seconds) if seconds >= 0 => r.max_age = Some(seconds),
            _ => return invalid("Invalid max_age"),
        }
    }
    if r.raw.get(PROCESSED_MAX_AGE).is_some() {
        r.max_age = None;
    }

    if let Some(login_hint) = r.raw.get("login_hint") {
        if utf16_len(&login_hint) > limits.login_hint {
            return invalid("Invalid login_hint");
        }
        r.login_hint = Some(login_hint);
    }

    if let Some(acr_values) = r.raw.get("acr_values") {
        if utf16_len(&acr_values) > limits.acr_values {
            return invalid("Invalid acr_values");
        }
        let mut distinct: Vec<String> = Vec::new();
        for acr in split_spaces(&acr_values) {
            if !distinct.contains(&acr) {
                distinct.push(acr);
            }
        }
        r.acr_values = distinct;
    }

    if let Some(idp) = r.idp().map(str::to_owned) {
        let restrictions = &client(r).identity_provider_restrictions;
        if !restrictions.is_empty() && !restrictions.contains(&idp) {
            tracing::warn!(%idp, "idp requested is not in client restriction list");
            r.remove_idp();
        }
    }

    // The session's id; empty for anonymous users.
    r.session_id = Some(
        r.subject
            .as_ref()
            .map(|s| s.session_id.clone())
            .unwrap_or_default(),
    );

    if let Some(jkt) = r.raw.get("dpop_jkt") {
        if utf16_len(&jkt) > limits.dpop_key_thumbprint {
            return invalid("Invalid dpop_jkt");
        }
        r.dpop_key_thumbprint = Some(jkt);
    }
    Ok(())
}

/// `int.TryParse` with the invariant culture: optional surrounding
/// whitespace and sign, ASCII digits, within `Int32`.
pub fn parse_lenient_int(value: &str) -> Option<i32> {
    let t = value.trim_matches(|c: char| matches!(c, '\u{9}'..='\u{d}' | ' '));
    let digits = t.strip_prefix(['+', '-']).unwrap_or(t);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    t.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_types_match_in_any_order() {
        assert_eq!(
            matching_response_type("id_token code"),
            Some("code id_token")
        );
        assert_eq!(
            matching_response_type("token id_token code"),
            Some("code id_token token")
        );
        assert_eq!(matching_response_type("code  id_token"), None);
        assert_eq!(matching_response_type("code code"), None);
        assert_eq!(matching_response_type("CODE"), None);
    }

    #[test]
    fn lenient_int_parsing() {
        assert_eq!(parse_lenient_int(" 12 "), Some(12));
        assert_eq!(parse_lenient_int("+0"), Some(0));
        assert_eq!(parse_lenient_int("-1"), Some(-1));
        for bad in ["", "1.5", "0x10", "2147483648", "1e3", "- 1"] {
            assert_eq!(parse_lenient_int(bad), None, "{bad}");
        }
    }

    #[test]
    fn prompt_parsing() {
        let supported: Vec<String> = ["none", "login", "create"].map(String::from).to_vec();
        assert_eq!(parse_prompt("login  none", &supported), Some(Err(())));
        assert_eq!(parse_prompt("create login", &supported), Some(Err(())));
        assert_eq!(parse_prompt("consent", &supported), None);
        assert_eq!(
            parse_prompt(" login ", &supported),
            Some(Ok(vec!["login".to_owned()]))
        );
        assert_eq!(parse_prompt("login\t", &supported), None);
    }

    #[test]
    fn uris() {
        assert!(is_uri("https://client.test/cb?x=1"));
        assert!(is_uri("com.app:/cb"));
        assert!(!is_uri("/relative"));
        assert!(!is_uri("not a uri"));
    }
}
