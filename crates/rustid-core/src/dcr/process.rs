//! The dynamic client registration request processor and the endpoint's parsing:
//! The client id, a generated secret when one is needed, and the save.

use chrono::{DateTime, Duration, Utc};
use serde_json::{Map, Value};

use super::{RegistrationError, RegistrationRequest, response, validate};
use crate::admin::clients::ClientAdmin;
use crate::admin::secrets::{HashAlgorithm, hash_secret};
use crate::clients::{SECRET_TYPE_JWK, Secret};
use crate::stores::{ConfigurationStore, StoreError};

/// Dynamic client registration settings, and where clients are managed.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DcrOptions {
    /// In seconds: generated secrets expire after it.
    pub secret_lifetime: Option<i64>,
    /// RFC 7592 management, when on.
    pub management: Option<ManagementUri>,
    /// Scopes a client gets when it asks for none (empty by
    /// default).
    pub default_scopes: Vec<String>,
    /// Whether registered clients require PKCE; unset, the `Client` default
    /// (required).
    pub require_pkce: Option<bool>,
}

/// The registration endpoint's absolute URL, `{origin}{path}`: a client's
/// management URI is it plus `/{client_id}`.
#[derive(Debug, Clone, PartialEq)]
pub struct ManagementUri {
    pub base: String,
}

/// The body as read from json binds it; anything it can't bind
/// (invalid JSON, a member of the wrong type, `null`) is a malformed
/// document.
pub fn parse(body: &[u8]) -> Result<RegistrationRequest, RegistrationError> {
    serde_json::from_slice::<Option<RegistrationRequest>>(body)
        .ok()
        .flatten()
        .ok_or_else(|| RegistrationError::metadata("malformed metadata document"))
}

/// 32 random bytes, base64url.
pub(crate) fn unique_id() -> String {
    use aws_lc_rs::rand::SecureRandom;
    use base64::Engine;
    let mut bytes = [0u8; 32];
    aws_lc_rs::rand::SystemRandom::new()
        .fill(&mut bytes)
        .expect("system random source");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Validates, then registers: the 201 body, or the 400 error.
pub async fn register(
    store: &dyn ConfigurationStore,
    admin: &ClientAdmin,
    options: &DcrOptions,
    mut request: RegistrationRequest,
    now: DateTime<Utc>,
) -> Result<Result<Map<String, Value>, RegistrationError>, StoreError> {
    let mut client = match validate::validate_with(&mut request, &options.default_scopes) {
        Ok(client) => client,
        Err(e) => return Ok(Err(e)),
    };
    client.client_id = unique_id();
    if let Some(require) = options.require_pkce {
        client.require_pkce = require;
    }

    // AddClientSecret: none for `none` and private_key_jwt, nor when the
    // client sent a secret of its own; otherwise a generated one.
    let method = request.token_endpoint_auth_method.as_deref();
    let generated = if method == Some("none")
        || method == Some("private_key_jwt")
        || client
            .client_secrets
            .iter()
            .any(|s| s.secret_type != SECRET_TYPE_JWK)
    {
        None
    } else {
        let plain = unique_id();
        let secret = Secret {
            value: hash_secret(&plain, HashAlgorithm::Sha256),
            expiration: options.secret_lifetime.map(|s| now + Duration::seconds(s)),
            ..Default::default()
        };
        client.client_secrets.push(secret.clone());
        Some((plain, secret))
    };

    // RFC 7592: the client's registration access token, kept as its hash,
    // and the metadata a read returns.
    let management = match &options.management {
        Some(uri) => {
            let token = unique_id();
            let mut stored = Map::new();
            stored.insert("client_id".into(), Value::String(client.client_id.clone()));
            let metadata = response::build(&request, &client, stored);
            client.properties.insert(
                super::manage::TOKEN_PROPERTY.into(),
                hash_secret(&token, HashAlgorithm::Sha256),
            );
            client.properties.insert(
                super::manage::METADATA_PROPERTY.into(),
                Value::Object(metadata).to_string(),
            );
            Some((format!("{}/{}", uri.base, client.client_id), token))
        }
        None => None,
    };

    if let Err(errors) = admin.register(store, &client).await? {
        let message = errors
            .first()
            .map(|e| e.message.as_str())
            .unwrap_or_default();
        return Ok(Err(RegistrationError::metadata(message)));
    }

    let mut head = Map::new();
    head.insert("client_id".into(), Value::String(client.client_id.clone()));
    if let Some((plain, secret)) = generated {
        head.insert("client_secret".into(), Value::String(plain));
        head.insert(
            "client_secret_expires_at".into(),
            Value::from(secret.expiration.map_or(0, |e| e.timestamp())),
        );
    }
    if let Some((uri, token)) = management {
        head.insert("registration_client_uri".into(), Value::String(uri));
        head.insert("registration_access_token".into(), Value::String(token));
    }
    Ok(Ok(response::build(&request, &client, head)))
}
