//! The registration response: the registered client's metadata, null
//! members omitted.

use serde_json::{Map, Value, json};

use super::RegistrationRequest;
use crate::clients::{AccessTokenType, Client, RefreshTokenExpiration, RefreshTokenUsage};

const AUTHORIZATION_CODE: &str = "authorization_code";

/// A grant that sends the user to authorize.
fn interactive(client: &Client) -> bool {
    client
        .allowed_grant_types
        .iter()
        .any(|g| g == AUTHORIZATION_CODE || g == "implicit" || g == "hybrid")
}

/// The response body: the response's own members first
/// (`head`: client id, secret, expiry; then `response_types`), then the
/// request model's members in declaration order, and the request's
/// extension members last.
pub fn build(
    request: &RegistrationRequest,
    client: &Client,
    head: Map<String, Value>,
) -> Map<String, Value> {
    let interactive = interactive(client);
    let mut m = head;
    if interactive {
        m.insert("response_types".into(), json!(["code"]));
    }
    let mut put = |key: &str, value: Option<Value>| {
        if let Some(value) = value.filter(|v| !v.is_null()) {
            m.insert(key.to_owned(), value);
        }
    };
    let code = client
        .allowed_grant_types
        .iter()
        .any(|g| g == AUTHORIZATION_CODE);
    let offline = client.allow_offline_access;
    let openid = client.allowed_scopes.iter().any(|s| s == "openid");

    let mut grant_types = client.allowed_grant_types.clone();
    if offline && !grant_types.iter().any(|g| g == "refresh_token") {
        grant_types.push("refresh_token".into());
    }
    put(
        "redirect_uris",
        (!client.redirect_uris.is_empty()).then(|| json!(client.redirect_uris)),
    );
    put("grant_types", Some(json!(grant_types)));
    put("client_name", client.client_name.clone().map(Value::String));
    put("logo_uri", code.then(|| json!(client.logo_uri)));
    put("client_uri", code.then(|| json!(client.client_uri)));
    put("jwks_uri", request.jwks_uri.clone().map(Value::String));
    // The key set's keys have no JSON name: the response writes them `Keys`.
    put(
        "jwks",
        request.jwks.as_ref().map(|j| {
            j.keys
                .as_ref()
                .map_or(json!({}), |keys| json!({ "Keys": keys }))
        }),
    );
    put(
        "scope",
        Some(Value::String(client.allowed_scopes.join(" "))),
    );
    if code {
        put(
            "post_logout_redirect_uris",
            Some(json!(client.post_logout_redirect_uris)),
        );
        put(
            "frontchannel_logout_uri",
            Some(json!(client.front_channel_logout_uri)),
        );
        put(
            "frontchannel_logout_session_required",
            client
                .front_channel_logout_uri
                .as_ref()
                .map(|_| json!(client.front_channel_logout_session_required)),
        );
        put(
            "backchannel_logout_uri",
            Some(json!(client.back_channel_logout_uri)),
        );
        put(
            "backchannel_logout_session_required",
            client
                .back_channel_logout_uri
                .as_ref()
                .map(|_| json!(client.back_channel_logout_session_required)),
        );
    }
    put(
        "software_statement",
        request.software_statement.clone().map(Value::String),
    );
    put(
        "software_id",
        request.software_id.clone().map(Value::String),
    );
    put(
        "software_version",
        request.software_version.clone().map(Value::String),
    );
    put(
        "require_signed_request_object",
        interactive.then(|| json!(client.require_request_object)),
    );
    put(
        "token_endpoint_auth_method",
        request
            .token_endpoint_auth_method
            .clone()
            .map(Value::String),
    );
    put(
        "default_max_age",
        code.then(|| json!(client.user_sso_lifetime)),
    );
    put(
        "initiate_login_uri",
        code.then(|| json!(client.initiate_login_uri)),
    );
    put(
        "identity_token_lifetime",
        openid.then(|| json!(client.identity_token_lifetime)),
    );
    put(
        "access_token_lifetime",
        Some(json!(client.access_token_lifetime)),
    );
    put(
        "authorization_code_lifetime",
        code.then(|| json!(client.authorization_code_lifetime)),
    );
    if offline {
        put(
            "absolute_refresh_token_lifetime",
            Some(json!(client.absolute_refresh_token_lifetime)),
        );
        put(
            "sliding_refresh_token_lifetime",
            (client.refresh_token_expiration == RefreshTokenExpiration::Sliding)
                .then(|| json!(client.sliding_refresh_token_lifetime)),
        );
        put(
            "refresh_token_expiration",
            Some(json!(match client.refresh_token_expiration {
                RefreshTokenExpiration::Absolute => "Absolute",
                RefreshTokenExpiration::Sliding => "Sliding",
            })),
        );
        put(
            "refresh_token_usage",
            Some(json!(match client.refresh_token_usage {
                RefreshTokenUsage::ReUse => "ReUse",
                RefreshTokenUsage::OneTimeOnly => "OneTimeOnly",
            })),
        );
        put(
            "update_access_token_claims_on_refresh",
            Some(json!(client.update_access_token_claims_on_refresh)),
        );
    }
    if code {
        put("require_consent", Some(json!(client.require_consent)));
        if client.require_consent {
            put(
                "allow_remember_consent",
                Some(json!(client.allow_remember_consent)),
            );
            put("consent_lifetime", Some(json!(client.consent_lifetime)));
        }
    }
    put(
        "access_token_type",
        Some(json!(match client.access_token_type {
            AccessTokenType::Jwt => "Jwt",
            AccessTokenType::Reference => "Reference",
        })),
    );
    put(
        "allowed_cors_origins",
        interactive.then(|| json!(client.allowed_cors_origins)),
    );
    put(
        "require_client_secret",
        Some(json!(client.require_client_secret)),
    );
    if code {
        put("enable_local_login", Some(json!(client.enable_local_login)));
        put(
            "identity_provider_restrictions",
            Some(json!(client.identity_provider_restrictions)),
        );
    }
    put(
        "coordinate_lifetime_with_user_session",
        Some(json!(client.coordinate_lifetime_with_user_session)),
    );
    put(
        "allowed_identity_token_signing_algorithms",
        (openid && !client.allowed_identity_token_signing_algorithms.is_empty())
            .then(|| json!(client.allowed_identity_token_signing_algorithms)),
    );

    // Said back when asked about, or when not the default.
    if request.subject_type.is_some()
        || client.subject_type == crate::clients::SubjectType::Pairwise
    {
        put(
            "subject_type",
            Some(json!(match client.subject_type {
                crate::clients::SubjectType::Public => "public",
                crate::clients::SubjectType::Pairwise => "pairwise",
            })),
        );
    }
    put(
        "sector_identifier_uri",
        client.sector_identifier_uri.as_ref().map(|u| json!(u)),
    );

    for (key, value) in &request.extensions {
        if matches!(
            key.as_str(),
            // Members the response owns, which extensions never set.
            "client_secret"
                | "client_secret_expires_at"
                | "response_types"
                | "registration_client_uri"
                | "registration_access_token"
        ) {
            continue;
        }
        if !m.contains_key(key) && !value.is_null() {
            m.insert(key.clone(), value.clone());
        }
    }
    m
}
