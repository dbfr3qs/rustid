//! Refresh tokens: the record (`RefreshToken`) kept as a persisted grant
//! of type `refresh_token`, and the rules for
//! their lifetimes, rotation and reuse.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::clients::{Client, RefreshTokenExpiration, RefreshTokenUsage};
use crate::grants::{PersistedGrant, hashed_key, new_handle};
use crate::issuance::AccessTokenRecord;
use crate::options::PersistentGrantOptions;
use crate::profile::{ActiveRequest, active_callers};
use crate::session::UserSession;
use crate::stores::{PersistedGrantStore, StoreError, Stores};

/// The persisted grant type of refresh tokens.
pub const REFRESH_TOKEN: &str = "refresh_token";

/// What a refresh token stands for.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RefreshToken {
    pub client_id: String,
    pub subject: UserSession,
    pub session_id: Option<String>,
    pub description: Option<String>,
    pub authorized_scopes: Vec<String>,
    pub authorized_resource_indicators: Option<Vec<String>>,
    /// The access token an unchanged refresh without a resource indicator
    /// reissues; `None` when the grant named one.
    #[serde(default)]
    pub access_token: Option<AccessTokenRecord>,
    /// The same per resource indicator (`access_tokens`).
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub resource_access_tokens: std::collections::BTreeMap<String, AccessTokenRecord>,
    pub creation_time: DateTime<Utc>,
    /// Seconds from `creation_time`.
    pub lifetime: i64,
    pub consumed_time: Option<DateTime<Utc>>,
    /// How the request that created it proved possession of a key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_type: Option<ProofType>,
}

/// `ProofType`: how a token request proved possession of a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ProofType {
    #[default]
    None,
    ClientCertificate,
    DPoP,
}

impl RefreshToken {
    /// `GetAccessToken(resourceIndicator)`.
    pub fn access_token_for(&self, resource: Option<&str>) -> Option<&AccessTokenRecord> {
        match resource.filter(|r| !r.is_empty()) {
            Some(r) => self.resource_access_tokens.get(r),
            None => self.access_token.as_ref(),
        }
    }

    /// `SetAccessToken(token, resourceIndicator)`.
    pub fn set_access_token(&mut self, record: AccessTokenRecord, resource: Option<&str>) {
        match resource.filter(|r| !r.is_empty()) {
            Some(r) => {
                self.resource_access_tokens.insert(r.to_owned(), record);
            }
            None => self.access_token = Some(record),
        }
    }

    /// The access tokens' distinct confirmations (`AccessTokens` values).
    fn confirmations(&self) -> Vec<&str> {
        let mut cnfs: Vec<&str> = Vec::new();
        let records = self
            .access_token
            .iter()
            .chain(self.resource_access_tokens.values());
        for cnf in records.filter_map(|r| r.token.confirmation.as_deref()) {
            if !cnf.is_empty() && !cnfs.contains(&cnf) {
                cnfs.push(cnf);
            }
        }
        cnfs
    }

    /// `GetProofKeyThumbprints`: the key thumbprints the access tokens are
    /// bound to (`jkt`, or a certificate's `x5t#S256`).
    pub fn proof_thumbprints(&self) -> Vec<String> {
        self.confirmations()
            .into_iter()
            .filter_map(|cnf| proof_key(cnf).map(|(_, thumbprint)| thumbprint))
            .collect()
    }

    /// The proof type recorded when the token was created, or for a record
    /// without one, the kind its access tokens are bound by.
    pub fn effective_proof_type(&self) -> ProofType {
        if let Some(proof_type) = self.proof_type {
            return proof_type;
        }
        self.confirmations()
            .into_iter()
            .find_map(proof_key)
            .map_or(ProofType::None, |(proof_type, _)| proof_type)
    }

    /// `CreationTime.HasExceeded(Lifetime)`.
    pub fn has_expired(&self, now: DateTime<Utc>) -> bool {
        self.creation_time + Duration::seconds(self.lifetime) < now
    }
}

/// Create refresh token's lifetime: the absolute lifetime, or the
/// sliding lifetime capped by a non-zero absolute lifetime.
pub fn initial_lifetime(client: &Client) -> i64 {
    let absolute = i64::from(client.absolute_refresh_token_lifetime);
    match client.refresh_token_expiration {
        RefreshTokenExpiration::Absolute => absolute,
        RefreshTokenExpiration::Sliding => {
            let sliding = i64::from(client.sliding_refresh_token_lifetime);
            if absolute > 0 && sliding > absolute {
                absolute
            } else {
                sliding
            }
        }
    }
}

/// Stores the record under `handle`, replacing any record there.
pub async fn store(
    grants: &dyn PersistedGrantStore,
    handle: &str,
    token: &RefreshToken,
) -> Result<(), StoreError> {
    grants
        .store(PersistedGrant {
            key: hashed_key(handle, REFRESH_TOKEN),
            grant_type: REFRESH_TOKEN.to_owned(),
            client_id: token.client_id.clone(),
            subject_id: Some(token.subject.subject_id.clone()),
            session_id: token.session_id.clone(),
            description: token.description.clone(),
            creation_time: token.creation_time,
            expiration: Some(token.creation_time + Duration::seconds(token.lifetime)),
            consumed_time: token.consumed_time,
            data: serde_json::to_string(token).expect("a refresh token serialises"),
        })
        .await
}

/// Stores the record under a new handle.
pub async fn create(
    grants: &dyn PersistedGrantStore,
    token: &RefreshToken,
) -> Result<String, StoreError> {
    let handle = new_handle();
    store(grants, &handle, token).await?;
    Ok(handle)
}

pub async fn get(
    grants: &dyn PersistedGrantStore,
    handle: &str,
) -> Result<Option<RefreshToken>, StoreError> {
    Ok(grants
        .get(&hashed_key(handle, REFRESH_TOKEN))
        .await?
        .filter(|g| g.grant_type == REFRESH_TOKEN)
        .and_then(|g| serde_json::from_str(&g.data).ok()))
}

/// The token when it exists, hasn't expired,
/// belongs to `client`, the client still allows offline access, it wasn't
/// consumed and its subject is active (`RefreshTokenValidation`). A token
/// without a subject (a subject-less extension grant's) is refused.
pub async fn validate(
    stores: &Stores,
    client: &Client,
    handle: &str,
    now: DateTime<Utc>,
) -> Result<Option<RefreshToken>, StoreError> {
    let Some(token) = get(stores.grants.as_ref(), handle).await? else {
        return Ok(None);
    };
    if token.has_expired(now)
        || token.client_id != client.client_id
        || !client.allow_offline_access
        || token.consumed_time.is_some()
        || token.subject.subject_id.is_empty()
    {
        return Ok(None);
    }
    let active = stores
        .profile
        .is_active(&ActiveRequest {
            caller: active_callers::REFRESH_TOKEN,
            client,
            subject_id: &token.subject.subject_id,
            subject_claims: &token.subject.claims,
        })
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
    Ok(active.then_some(token))
}

pub async fn remove(grants: &dyn PersistedGrantStore, handle: &str) -> Result<(), StoreError> {
    grants.remove(&hashed_key(handle, REFRESH_TOKEN)).await
}

/// A one-time-only token is deleted (or marked
/// consumed) and replaced by a new handle; a sliding token's lifetime grows
/// to its age plus the sliding lifetime, capped by a non-zero absolute
/// lifetime. Returns the handle the client gets, or `None` when another
/// request rotated the token first: deleting takes the record atomically,
/// so of two concurrent refreshes of a one-time-only token only one
/// succeeds. Marking consumed instead of
/// deleting is best-effort.
pub async fn update(
    grants: &dyn PersistedGrantStore,
    options: &PersistentGrantOptions,
    client: &Client,
    handle: &str,
    token: &mut RefreshToken,
    must_update: bool,
    now: DateTime<Utc>,
) -> Result<Option<String>, StoreError> {
    let mut needs_create = false;
    let mut needs_update = must_update;
    if client.refresh_token_usage == RefreshTokenUsage::OneTimeOnly {
        if options.delete_one_time_only_refresh_tokens_on_use {
            if grants
                .take(&hashed_key(handle, REFRESH_TOKEN))
                .await?
                .is_none()
            {
                return Ok(None);
            }
        } else if token.consumed_time.is_none() {
            let mut consumed = token.clone();
            consumed.consumed_time = Some(now);
            store(grants, handle, &consumed).await?;
        }
        needs_create = true;
    }
    if client.refresh_token_expiration == RefreshTokenExpiration::Sliding {
        let age = (now - token.creation_time).num_seconds();
        let absolute = i64::from(client.absolute_refresh_token_lifetime);
        let mut lifetime = age + i64::from(client.sliding_refresh_token_lifetime);
        if absolute > 0 && lifetime > absolute {
            lifetime = absolute;
        }
        token.lifetime = lifetime;
        needs_update = true;
    }
    if needs_create {
        token.consumed_time = None;
        return create(grants, token).await.map(Some);
    }
    if needs_update {
        store(grants, handle, token).await?;
    }
    Ok(Some(handle.to_owned()))
}

/// `GetProofKeyThumbprint`: a `cnf`'s kind and thumbprint.
fn proof_key(cnf: &str) -> Option<(ProofType, String)> {
    let value: serde_json::Value = serde_json::from_str(cnf).ok()?;
    let member = |name: &str| {
        value
            .get(name)
            .and_then(serde_json::Value::as_str)
            .filter(|t| !t.is_empty())
            .map(str::to_owned)
    };
    member("jkt")
        .map(|t| (ProofType::DPoP, t))
        .or_else(|| member("x5t#S256").map(|t| (ProofType::ClientCertificate, t)))
}
