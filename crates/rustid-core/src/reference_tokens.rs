//! Access tokens kept server-side and handed
//! to the client as an opaque handle.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::grants::{self, PersistedGrant, REFERENCE_TOKEN};
use crate::stores::{PersistedGrantStore, StoreError};
use crate::tokens::Claim;

/// What a stored token holds for an access token, serialised into the
/// grant's data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReferenceToken {
    pub issuer: String,
    pub client_id: String,
    pub audiences: Vec<String>,
    pub creation_time: DateTime<Utc>,
    /// Seconds.
    pub lifetime: i64,
    /// Every claim except iss, nbf, iat, exp and aud, in issue order.
    pub claims: Vec<Claim>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl ReferenceToken {
    /// `CreationTime.HasExceeded(Lifetime, now)`: no clock skew.
    pub fn has_expired(&self, now: DateTime<Utc>) -> bool {
        now > self.expiration()
    }

    /// Creation time plus lifetime, saturating at the earliest or latest
    /// representable instant so stored data can never make it panic.
    pub fn expiration(&self) -> DateTime<Utc> {
        Duration::try_seconds(self.lifetime)
            .and_then(|lifetime| self.creation_time.checked_add_signed(lifetime))
            .unwrap_or(if self.lifetime < 0 {
                DateTime::<Utc>::MIN_UTC
            } else {
                DateTime::<Utc>::MAX_UTC
            })
    }
}

/// Stores the token under a new handle and returns the handle.
pub async fn store(
    grants: &dyn PersistedGrantStore,
    token: &ReferenceToken,
) -> Result<String, StoreError> {
    let handle = grants::new_handle();
    grants
        .store(PersistedGrant {
            key: grants::hashed_key(&handle, REFERENCE_TOKEN),
            grant_type: REFERENCE_TOKEN.to_owned(),
            client_id: token.client_id.clone(),
            subject_id: token.subject_id.clone(),
            session_id: token.session_id.clone(),
            description: token.description.clone(),
            creation_time: token.creation_time,
            expiration: Some(token.expiration()),
            consumed_time: None,
            data: serde_json::to_string(token).expect("reference tokens serialise"),
        })
        .await?;
    Ok(handle)
}

/// The token for a handle, if one is stored and its data reads back.
pub async fn get(
    grants: &dyn PersistedGrantStore,
    handle: &str,
) -> Result<Option<ReferenceToken>, StoreError> {
    let Some(grant) = grants
        .get(&grants::hashed_key(handle, REFERENCE_TOKEN))
        .await?
    else {
        return Ok(None);
    };
    if grant.grant_type != REFERENCE_TOKEN {
        return Ok(None);
    }
    match serde_json::from_str(&grant.data) {
        Ok(token) => Ok(Some(token)),
        Err(error) => {
            tracing::error!(%error, "failed to deserialize reference token");
            Ok(None)
        }
    }
}

pub async fn remove(grants: &dyn PersistedGrantStore, handle: &str) -> Result<(), StoreError> {
    grants
        .remove(&grants::hashed_key(handle, REFERENCE_TOKEN))
        .await
}
