//! The request becomes a `Client`,
//! step by step in a fixed order, each failure with its own description.

use serde_json::Value;

use super::{INVALID_REDIRECT_URI, RegistrationError, RegistrationRequest};
use crate::clients::{
    AccessTokenType, Client, RefreshTokenExpiration, RefreshTokenUsage, SECRET_TYPE_JWK, Secret,
};

const AUTHORIZATION_CODE: &str = "authorization_code";
const CLIENT_CREDENTIALS: &str = "client_credentials";
const REFRESH_TOKEN: &str = "refresh_token";

type Step = Result<(), RegistrationError>;

fn fail(description: &str) -> Step {
    Err(RegistrationError::metadata(description))
}

/// Validates `request` and builds the client it describes. It
/// writes the defaulted `token_endpoint_auth_method` back into the request,
/// which the response echoes.
pub fn validate(request: &mut RegistrationRequest) -> Result<Client, RegistrationError> {
    validate_with(request, &[])
}

/// [`validate`] with the scopes a client that asks for none gets.
pub fn validate_with(
    request: &mut RegistrationRequest,
    default_scopes: &[String],
) -> Result<Client, RegistrationError> {
    let mut client = Client::default();
    // ValidateSoftwareStatementAsync accepts any statement.
    grant_types(request, &mut client)?;
    redirect_uris(request, &mut client)?;
    scopes(request, default_scopes, &mut client);
    secrets(request, &mut client)?;
    client.client_name = request.client_name.clone();
    logout_parameters(request, &mut client)?;
    max_age(request, &mut client)?;
    user_interface(request, &mut client)?;
    public_client(request, &mut client);
    access_token(request, &mut client)?;
    id_token(request, &mut client)?;
    if let Some(coordinate) = request.coordinate_lifetime_with_user_session {
        client.coordinate_lifetime_with_user_session = Some(coordinate);
    }
    subject(request, &mut client)?;
    Ok(client)
}

/// `subject_type` and `sector_identifier_uri`; the sector document itself
/// is checked when the client is registered.
fn subject(request: &RegistrationRequest, client: &mut Client) -> Result<(), RegistrationError> {
    client.subject_type = match request.subject_type.as_deref() {
        None | Some("public") => crate::clients::SubjectType::Public,
        Some("pairwise") => crate::clients::SubjectType::Pairwise,
        Some(other) => {
            return Err(RegistrationError::metadata(&format!(
                "subject_type {other} is not supported"
            )));
        }
    };
    if let Some(uri) = &request.sector_identifier_uri {
        if !url::Url::parse(uri).is_ok_and(|u| u.scheme() == "https" && u.host().is_some()) {
            return Err(RegistrationError::metadata(
                "sector_identifier_uri must be an https URL",
            ));
        }
        client.sector_identifier_uri = Some(uri.clone());
    }
    if client.subject_type == crate::clients::SubjectType::Pairwise
        && client.sector_identifier_uri.is_none()
        && crate::pairwise::redirect_hosts(client).len() > 1
    {
        return Err(RegistrationError::metadata(
            "a pairwise client whose redirect URIs name more than one host needs a sector_identifier_uri",
        ));
    }
    Ok(())
}

/// Insertion order, no duplicates.
fn add(set: &mut Vec<String>, value: &str) {
    if !set.iter().any(|v| v == value) {
        set.push(value.to_owned());
    }
}

fn set_of(values: &[String]) -> Vec<String> {
    let mut set = Vec::new();
    for value in values {
        add(&mut set, value);
    }
    set
}

fn positive(value: i32, description: &str) -> Result<i32, RegistrationError> {
    if value <= 0 {
        return Err(RegistrationError::metadata(description));
    }
    Ok(value)
}

fn grant_types(request: &RegistrationRequest, client: &mut Client) -> Step {
    let requested = |g: &str| request.grant_types.iter().any(|t| t == g);
    if request.grant_types.is_empty() {
        return fail("grant type is required");
    }
    if requested(CLIENT_CREDENTIALS) {
        if request.require_client_secret == Some(false)
            || request.token_endpoint_auth_method.as_deref() == Some("none")
        {
            return fail("client secret is required for client credentials grant type");
        }
        add(&mut client.allowed_grant_types, CLIENT_CREDENTIALS);
    }
    if requested(AUTHORIZATION_CODE) {
        add(&mut client.allowed_grant_types, AUTHORIZATION_CODE);
        if let Some(lifetime) = request.authorization_code_lifetime {
            client.authorization_code_lifetime = positive(
                lifetime,
                "The authorization code lifetime must be greater than 0 if used",
            )?;
        }
    }
    if client.allowed_grant_types.is_empty() {
        return fail("unsupported grant type");
    }
    if requested(REFRESH_TOKEN) {
        if !client
            .allowed_grant_types
            .iter()
            .any(|g| g == AUTHORIZATION_CODE)
        {
            return fail(
                "Refresh token grant requested, but no grant that supports refresh tokens was requested",
            );
        }
        client.allow_offline_access = true;
        if let Some(expiration) = &request.refresh_token_expiration {
            client.refresh_token_expiration = match expiration.as_str() {
                "Absolute" => RefreshTokenExpiration::Absolute,
                "Sliding" => RefreshTokenExpiration::Sliding,
                _ => {
                    return fail(
                        "invalid refresh token expiration - use Absolute or Sliding (case-sensitive)",
                    );
                }
            };
        }
        if let Some(lifetime) = request.sliding_refresh_token_lifetime {
            client.sliding_refresh_token_lifetime = positive(
                lifetime,
                "The sliding refresh token lifetime must be greater than 0 if used",
            )?;
        }
        if let Some(lifetime) = request.absolute_refresh_token_lifetime {
            // 0 means unlimited.
            if lifetime < 0 {
                return fail("The absolute refresh token lifetime must be 0 or greater if used");
            }
            client.absolute_refresh_token_lifetime = lifetime;
        }
        if let Some(usage) = &request.refresh_token_usage {
            client.refresh_token_usage = match usage.as_str() {
                "OneTimeOnly" => RefreshTokenUsage::OneTimeOnly,
                "ReUse" => RefreshTokenUsage::ReUse,
                _ => {
                    return fail(
                        "invalid refresh token usage - use OneTimeOnly or ReUse (case-sensitive)",
                    );
                }
            };
        }
        if let Some(update) = request.update_access_token_claims_on_refresh {
            client.update_access_token_claims_on_refresh = update;
        }
    }
    Ok(())
}

/// An absolute URI in normalised form.
pub(crate) fn absolute_uri(value: &str) -> Option<String> {
    url::Url::parse(value).ok().map(String::from)
}

/// An absolute URI normalised, a relative one as given.
pub(crate) fn uri_string(value: &str) -> String {
    absolute_uri(value).unwrap_or_else(|| value.to_owned())
}

/// An absolute URI where one is required: a relative value
/// is a malformed document.
fn required_absolute(value: &Option<String>) -> Result<Option<String>, RegistrationError> {
    match value {
        None => Ok(None),
        Some(v) => absolute_uri(v)
            .map(Some)
            .ok_or_else(|| RegistrationError::metadata("malformed metadata document")),
    }
}

fn redirect_uris(request: &RegistrationRequest, client: &mut Client) -> Step {
    if client
        .allowed_grant_types
        .iter()
        .any(|g| g == AUTHORIZATION_CODE)
    {
        let Some(uris) = &request.redirect_uris else {
            return Err(RegistrationError::new(
                INVALID_REDIRECT_URI,
                "redirect URI required for authorization_code grant type",
            ));
        };
        for uri in uris {
            match absolute_uri(uri) {
                Some(uri) => add(&mut client.redirect_uris, &uri),
                None => {
                    return Err(RegistrationError::new(
                        INVALID_REDIRECT_URI,
                        "malformed redirect URI",
                    ));
                }
            }
        }
    }
    if client.allowed_grant_types == [CLIENT_CREDENTIALS]
        && request
            .redirect_uris
            .as_ref()
            .is_some_and(|u| !u.is_empty())
    {
        return Err(RegistrationError::new(
            INVALID_REDIRECT_URI,
            "redirect URI not compatible with client_credentials grant type",
        ));
    }
    Ok(())
}

/// Without `scope`, the client gets `default_scopes` (none by default);
/// `offline_access` comes from
/// the refresh_token grant instead.
fn scopes(request: &RegistrationRequest, default_scopes: &[String], client: &mut Client) {
    let Some(scope) = request.scope.as_deref().filter(|s| !s.is_empty()) else {
        client.allowed_scopes = set_of(default_scopes);
        return;
    };
    for scope in scope.split(' ').filter(|s| !s.is_empty()) {
        if scope != "offline_access" {
            add(&mut client.allowed_scopes, scope);
        }
    }
}

/// A private key: every RSA private member, or an EC `d`.
fn has_private_key(jwk: &serde_json::Map<String, Value>) -> bool {
    let has = |m: &str| jwk.get(m).is_some_and(|v| !v.is_null());
    match jwk.get("kty").and_then(Value::as_str) {
        Some("RSA") => ["d", "dp", "dq", "p", "q", "qi"].iter().all(|m| has(m)),
        Some("EC") => has("d"),
        _ => false,
    }
}

/// `new JsonWebKey(json)` binds these members as strings (and `x5c`,
/// `key_ops` as string lists); another JSON type throws there.
fn well_typed(jwk: &serde_json::Map<String, Value>) -> bool {
    const STRINGS: &[&str] = &[
        "kty", "use", "kid", "alg", "n", "e", "d", "dp", "dq", "p", "q", "qi", "x", "y", "crv",
        "k", "x5t", "x5t#S256", "x5u",
    ];
    const LISTS: &[&str] = &["x5c", "key_ops"];
    let string_or_null = |v: &Value| v.is_string() || v.is_null();
    STRINGS
        .iter()
        .all(|m| jwk.get(*m).is_none_or(string_or_null))
        && LISTS.iter().all(|m| {
            jwk.get(*m).is_none_or(|v| {
                v.is_null()
                    || v.as_array()
                        .is_some_and(|items| items.iter().all(Value::is_string))
            })
        })
}

fn secrets(request: &mut RegistrationRequest, client: &mut Client) -> Step {
    if request.jwks_uri.is_some() && request.jwks.is_some() {
        return fail("The jwks_uri and jwks parameters must not be used together");
    }
    if request.jwks.is_none()
        && request.token_endpoint_auth_method.as_deref() == Some("private_key_jwt")
    {
        return fail(
            "Missing jwks parameter - the private_key_jwt token_endpoint_auth_method requires the jwks parameter",
        );
    }
    request
        .token_endpoint_auth_method
        .get_or_insert_with(|| "client_secret_basic".to_owned());
    let keys = request.jwks.as_ref().and_then(|j| j.keys.as_ref());
    if keys.is_none() && request.require_signed_request_object == Some(true) {
        return fail("Jwks are required when the require signed request object flag is enabled");
    }
    if let Some(keys) = keys {
        client.require_request_object = request.require_signed_request_object.unwrap_or(false);
        for key in keys {
            let Value::Object(jwk) = key else {
                return fail("malformed jwk");
            };
            if !well_typed(jwk) {
                return fail("malformed jwk");
            }
            let alg = jwk.get("alg").and_then(Value::as_str).unwrap_or_default();
            if has_private_key(jwk) && alg.starts_with("HS") {
                return fail("unexpected private key in jwk");
            }
            client.client_secrets.push(Secret {
                value: key.to_string(),
                secret_type: SECRET_TYPE_JWK.to_owned(),
                ..Default::default()
            });
        }
    }
    Ok(())
}

fn logout_parameters(request: &RegistrationRequest, client: &mut Client) -> Step {
    client.post_logout_redirect_uris = request
        .post_logout_redirect_uris
        .iter()
        .flatten()
        .map(|u| uri_string(u))
        .collect();
    client.post_logout_redirect_uris = set_of(&client.post_logout_redirect_uris);
    client.front_channel_logout_uri = required_absolute(&request.frontchannel_logout_uri)?;
    client.front_channel_logout_session_required =
        request.frontchannel_logout_session_required.unwrap_or(true);
    client.back_channel_logout_uri = required_absolute(&request.backchannel_logout_uri)?;
    client.back_channel_logout_session_required =
        request.backchannel_logout_session_required.unwrap_or(true);
    Ok(())
}

fn max_age(request: &RegistrationRequest, client: &mut Client) -> Step {
    if let Some(max_age) = request.default_max_age {
        if !request.grant_types.iter().any(|g| g == AUTHORIZATION_CODE) {
            return fail("default_max_age requires authorization code grant type");
        }
        client.user_sso_lifetime = Some(positive(
            max_age,
            "default_max_age must be greater than 0 if used",
        )?);
    }
    Ok(())
}

fn user_interface(request: &RegistrationRequest, client: &mut Client) -> Step {
    client.logo_uri = request.logo_uri.as_deref().map(uri_string);
    client.initiate_login_uri = request.initiate_login_uri.as_deref().map(uri_string);
    if let Some(enable) = request.enable_local_login {
        client.enable_local_login = enable;
    }
    client.identity_provider_restrictions = set_of(
        request
            .identity_provider_restrictions
            .as_deref()
            .unwrap_or_default(),
    );
    if let Some(require) = request.require_consent {
        client.require_consent = require;
    }
    client.client_uri = required_absolute(&request.client_uri)?;
    if let Some(allow) = request.allow_remember_consent {
        client.allow_remember_consent = allow;
    }
    if let Some(lifetime) = request.consent_lifetime {
        client.consent_lifetime = Some(positive(
            lifetime,
            "The consent lifetime must be greater than 0 if used",
        )?);
    }
    Ok(())
}

fn public_client(request: &RegistrationRequest, client: &mut Client) {
    client.allowed_cors_origins =
        set_of(request.allowed_cors_origins.as_deref().unwrap_or_default());
    if let Some(require) = request.require_client_secret {
        client.require_client_secret = require;
    } else if request.token_endpoint_auth_method.as_deref() == Some("none") {
        client.require_client_secret = false;
    }
}

fn access_token(request: &RegistrationRequest, client: &mut Client) -> Step {
    if let Some(token_type) = &request.access_token_type {
        client.access_token_type = match token_type.as_str() {
            "Jwt" => AccessTokenType::Jwt,
            "Reference" => AccessTokenType::Reference,
            _ => return fail("invalid access token type - use Jwt or Reference (case-sensitive)"),
        };
    }
    if let Some(lifetime) = request.access_token_lifetime {
        client.access_token_lifetime = positive(
            lifetime,
            "The access token lifetime must be greater than 0 if used",
        )?;
    }
    Ok(())
}

fn id_token(request: &RegistrationRequest, client: &mut Client) -> Step {
    if let Some(lifetime) = request.identity_token_lifetime {
        client.identity_token_lifetime = positive(
            lifetime,
            "The identity token lifetime must be greater than 0 if used",
        )?;
    }
    client.allowed_identity_token_signing_algorithms = set_of(
        request
            .allowed_identity_token_signing_algorithms
            .as_deref()
            .unwrap_or_default(),
    );
    Ok(())
}
