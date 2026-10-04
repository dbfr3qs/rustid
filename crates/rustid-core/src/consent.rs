//! Consent: the responses a consent page gives (`ConsentResponse`, kept
//! until the authorize callback reads them) and the consent a user asked to
//! be remembered (the consent service over the user consent store).

use aws_lc_rs::digest;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::clients::Client;
use crate::grants::{HANDLE_SUFFIX, PersistedGrant, hashed_key};
use crate::jwt::b64url;
use crate::scopes::{OFFLINE_ACCESS, parse_scopes_string};
use crate::stores::{PersistedGrantStore, StoreError};

/// The persisted grant type of remembered consent.
pub const USER_CONSENT: &str = "user_consent";
/// Consent responses waiting for the authorize callback. They are kept in
/// a message cookie; rustid keeps them server side.
pub const CONSENT_RESPONSE: &str = "consent_response";
/// How long a consent response waits for the callback.
pub const CONSENT_RESPONSE_LIFETIME: Duration = Duration::minutes(10);

/// `InteractionError`: why a user or UI refused an authorize request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InteractionError {
    AccessDenied,
    InteractionRequired,
    LoginRequired,
    AccountSelectionRequired,
    ConsentRequired,
    TemporarilyUnavailable,
    UnmetAuthenticationRequirements,
}

impl InteractionError {
    /// The OAuth error the client gets.
    pub fn error_code(self) -> &'static str {
        match self {
            InteractionError::AccessDenied => "access_denied",
            InteractionError::InteractionRequired => "interaction_required",
            InteractionError::LoginRequired => "login_required",
            InteractionError::AccountSelectionRequired => "account_selection_required",
            InteractionError::ConsentRequired => "consent_required",
            InteractionError::TemporarilyUnavailable => "temporarily_unavailable",
            InteractionError::UnmetAuthenticationRequirements => {
                "unmet_authentication_requirements"
            }
        }
    }

    /// The error named by its OAuth code, as UIs send it.
    pub fn parse(code: &str) -> Option<InteractionError> {
        serde_json::from_value(serde_json::Value::String(code.to_owned())).ok()
    }
}

/// `ConsentResponse`: the scopes a user granted, or why they refused.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentResponse {
    pub error: Option<InteractionError>,
    pub error_description: Option<String>,
    pub remember_consent: bool,
    pub scopes_values_consented: Vec<String>,
    /// Shown against the grant in a grants UI.
    pub description: Option<String>,
}

impl ConsentResponse {
    /// `Granted`: some scopes and no error.
    pub fn granted(&self) -> bool {
        !self.scopes_values_consented.is_empty() && self.error.is_none()
    }
}

/// `ConsentRequest.Id`: base64url SHA-256 of
/// `{client}:{subject}:{nonce}:{scopes}`, the scopes parsed, sorted,
/// de-duplicated and comma-joined; a missing part is empty.
pub fn consent_request_id(
    client_id: &str,
    subject: Option<&str>,
    nonce: Option<&str>,
    scope: Option<&str>,
) -> String {
    let scopes = scope
        .and_then(parse_scopes_string)
        .map(|s| s.join(","))
        .unwrap_or_default();
    let value = format!(
        "{client_id}:{}:{}:{scopes}",
        subject.unwrap_or_default(),
        nonce.unwrap_or_default()
    );
    b64url(digest::digest(&digest::SHA256, value.as_bytes()).as_ref())
}

fn response_key(id: &str) -> String {
    hashed_key(&format!("{id}{HANDLE_SUFFIX}"), CONSENT_RESPONSE)
}

/// Keeps the response for the callback.
pub async fn store_response(
    grants: &dyn PersistedGrantStore,
    id: &str,
    subject_id: Option<&str>,
    client_id: &str,
    response: &ConsentResponse,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    grants
        .store(PersistedGrant {
            key: response_key(id),
            grant_type: CONSENT_RESPONSE.to_owned(),
            client_id: client_id.to_owned(),
            subject_id: subject_id.map(str::to_owned),
            session_id: None,
            description: None,
            creation_time: now,
            expiration: Some(now + CONSENT_RESPONSE_LIFETIME),
            consumed_time: None,
            data: serde_json::to_string(response).expect("a consent response serialises"),
        })
        .await
}

/// The response for a consent request,
/// unless it has expired.
pub async fn read_response(
    grants: &dyn PersistedGrantStore,
    id: &str,
    now: DateTime<Utc>,
) -> Result<Option<ConsentResponse>, StoreError> {
    let Some(grant) = grants.get(&response_key(id)).await? else {
        return Ok(None);
    };
    if grant.expiration.is_some_and(|e| e <= now) {
        return Ok(None);
    }
    Ok(serde_json::from_str(&grant.data).ok())
}

/// The consent message store.
pub async fn delete_response(grants: &dyn PersistedGrantStore, id: &str) -> Result<(), StoreError> {
    grants.remove(&response_key(id)).await
}

/// `Consent`, serialised so
/// records migrated from the EF store read back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct UserConsent {
    pub subject_id: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub creation_time: DateTime<Utc>,
    pub expiration: Option<DateTime<Utc>>,
}

/// The user consent store in the current (hex) format.
fn consent_key(subject_id: &str, client_id: &str) -> String {
    hashed_key(
        &format!("{client_id}|{subject_id}{HANDLE_SUFFIX}"),
        USER_CONSENT,
    )
}

/// The user consent store.
pub async fn user_consent(
    grants: &dyn PersistedGrantStore,
    subject_id: &str,
    client_id: &str,
) -> Result<Option<UserConsent>, StoreError> {
    Ok(grants
        .get(&consent_key(subject_id, client_id))
        .await?
        .and_then(|g| serde_json::from_str(&g.data).ok()))
}

/// The user consent store.
pub async fn remove_user_consent(
    grants: &dyn PersistedGrantStore,
    subject_id: &str,
    client_id: &str,
) -> Result<(), StoreError> {
    grants.remove(&consent_key(subject_id, client_id)).await
}

/// Consent is needed for a
/// client that requires it, with scopes, unless the client may remember
/// consent and the user's remembered, unexpired consent covers every
/// requested scope; `offline_access` always asks.
pub async fn requires_consent(
    grants: &dyn PersistedGrantStore,
    client: &Client,
    subject_id: &str,
    scopes: &[String],
    now: DateTime<Utc>,
) -> Result<bool, StoreError> {
    if !client.require_consent || scopes.is_empty() {
        return Ok(false);
    }
    if !client.allow_remember_consent || scopes.iter().any(|s| s == OFFLINE_ACCESS) {
        return Ok(true);
    }
    let Some(consent) = user_consent(grants, subject_id, &client.client_id).await? else {
        return Ok(true);
    };
    if consent.expiration.is_some_and(|e| e <= now) {
        remove_user_consent(grants, subject_id, &client.client_id).await?;
        return Ok(true);
    }
    Ok(!scopes.iter().all(|s| consent.scopes.contains(s)))
}

/// Remembers the scopes (for
/// the client's consent lifetime), or forgets the consent when there are
/// none. Nothing is kept for a client that can't remember consent.
pub async fn update_consent(
    grants: &dyn PersistedGrantStore,
    client: &Client,
    subject_id: &str,
    scopes: &[String],
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    if !client.allow_remember_consent {
        return Ok(());
    }
    if scopes.is_empty() {
        return remove_user_consent(grants, subject_id, &client.client_id).await;
    }
    let expiration = client
        .consent_lifetime
        .map(|seconds| now + Duration::seconds(i64::from(seconds)));
    let consent = UserConsent {
        subject_id: subject_id.to_owned(),
        client_id: client.client_id.clone(),
        scopes: scopes.to_vec(),
        creation_time: now,
        expiration,
    };
    grants
        .store(PersistedGrant {
            key: consent_key(subject_id, &client.client_id),
            grant_type: USER_CONSENT.to_owned(),
            client_id: client.client_id.clone(),
            subject_id: Some(subject_id.to_owned()),
            session_id: None,
            description: None,
            creation_time: now,
            expiration,
            consumed_time: None,
            data: serde_json::to_string(&consent).expect("a consent serialises"),
        })
        .await
}
