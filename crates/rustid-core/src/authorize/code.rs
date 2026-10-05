//! Authorization codes (`AuthorizationCode`, create code flow response)
//! stored as persisted grants under a hashed key,
//! the authorization code store stores them.

use aws_lc_rs::digest;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::request::ValidatedAuthorizeRequest;
use crate::grants::{PersistedGrant, hashed_key, new_handle};
use crate::params::Params;
use crate::session::UserSession;
use crate::stores::{PersistedGrantStore, StoreError};

/// The persisted grant type of authorization codes.
pub const AUTHORIZATION_CODE: &str = "authorization_code";

/// What a code stands for until it is redeemed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationCode {
    pub creation_time: DateTime<Utc>,
    pub client_id: String,
    /// Seconds.
    pub lifetime: i32,
    /// The signed-in user when the code was issued.
    pub subject: UserSession,
    pub session_id: String,
    pub description: Option<String>,
    /// Base64(SHA-256(code_challenge)).
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub dpop_key_thumbprint: Option<String>,
    pub is_open_id: bool,
    /// The requested scopes, in request order.
    pub requested_scopes: Vec<String>,
    pub requested_resource_indicators: Vec<String>,
    pub redirect_uri: String,
    pub nonce: Option<String>,
    /// `s_hash`, when `emit_state_hash` is on (sub-plan 2c).
    pub state_hash: Option<String>,
    pub was_consent_shown: bool,
}

/// `string.Sha256()`: base64 of the UTF-8 SHA-256.
pub fn sha256_base64(value: &str) -> String {
    STANDARD.encode(digest::digest(&digest::SHA256, value.as_bytes()).as_ref())
}

impl AuthorizationCode {
    /// Create code for a validated request with a signed-in user.
    pub fn for_request(
        request: &ValidatedAuthorizeRequest,
        now: DateTime<Utc>,
    ) -> AuthorizationCode {
        let client = request
            .client
            .as_ref()
            .expect("validated request has a client");
        let subject = request
            .subject
            .clone()
            .expect("codes are issued to signed-in users");
        AuthorizationCode {
            creation_time: now,
            client_id: client.client_id.clone(),
            lifetime: client.authorization_code_lifetime,
            session_id: subject.session_id.clone(),
            subject,
            description: request.description.clone(),
            code_challenge: request.code_challenge.as_deref().map(sha256_base64),
            code_challenge_method: request.code_challenge_method.clone(),
            dpop_key_thumbprint: request.dpop_key_thumbprint.clone(),
            is_open_id: request.is_openid_request,
            requested_scopes: request
                .resources
                .as_ref()
                .map(|r| r.scopes.clone())
                .unwrap_or_default(),
            requested_resource_indicators: request.resource_indicators.clone(),
            redirect_uri: request.redirect_uri.clone().unwrap_or_default(),
            nonce: request.nonce.clone(),
            state_hash: None,
            was_consent_shown: request.was_consent_shown,
        }
    }

    /// Stores the code under the hash of a
    /// new handle and returns the handle.
    pub async fn store(&self, grants: &dyn PersistedGrantStore) -> Result<String, StoreError> {
        let handle = new_handle();
        grants
            .store(PersistedGrant {
                key: hashed_key(&handle, AUTHORIZATION_CODE),
                grant_type: AUTHORIZATION_CODE.to_owned(),
                client_id: self.client_id.clone(),
                subject_id: Some(self.subject.subject_id.clone()),
                session_id: Some(self.session_id.clone()),
                description: self.description.clone(),
                creation_time: self.creation_time,
                expiration: Some(
                    self.creation_time + chrono::Duration::seconds(i64::from(self.lifetime)),
                ),
                consumed_time: None,
                data: serde_json::to_string(self).expect("codes serialize to JSON"),
            })
            .await?;
        Ok(handle)
    }
}

/// The parameters of a code flow response:
/// `code`, `state`, `session_state`, then `iss` when the option is on.
pub fn code_response_parameters(
    request: &ValidatedAuthorizeRequest,
    code: &str,
    issuer: &str,
    emit_issuer: bool,
) -> Params {
    let mut params = Params::default();
    params.add("code", code);
    if let Some(state) = request.state.as_deref().filter(|s| !s.trim().is_empty()) {
        params.add("state", state);
    }
    if let Some(session_state) = request.session_state_value() {
        params.add("session_state", &session_state);
    }
    if emit_issuer && !issuer.trim().is_empty() {
        params.add("iss", issuer);
    }
    params
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenges_are_stored_as_base64_sha256() {
        assert_eq!(
            sha256_base64("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
            "DSmbHrVIcI0EU05+BQxCe1bt+hXRNjejSEvdYbq/g4Q="
        );
    }
}
