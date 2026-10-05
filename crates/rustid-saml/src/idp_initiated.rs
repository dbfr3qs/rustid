//! IdP-initiated SSO: the checks made
//! before the user is consulted, in a fixed order with fixed words. The HTTP side
//! then requires a signed-in user and resolves the SP's claim types.

use crate::model::{IndexedEndpoint, ServiceProvider};
use crate::options::SamlOptions;

/// Where the response goes.
#[derive(Debug, Clone)]
pub struct Target {
    pub acs: IndexedEndpoint,
    /// `None` for an absent or empty relay state.
    pub relay_state: Option<String>,
}

/// Why the IdP won't start SSO to the SP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal(pub String);

fn refuse(message: impl Into<String>) -> Result<Target, Refusal> {
    Err(Refusal(message.into()))
}

/// `sp` is the store's answer for `entity_id`.
pub fn check(
    sp: Option<&ServiceProvider>,
    entity_id: &str,
    relay_state: Option<&str>,
    options: &SamlOptions,
) -> Result<Target, Refusal> {
    if entity_id.trim().is_empty() {
        return refuse("Missing required 'spEntityId' parameter");
    }
    let Some(sp) = sp else {
        return refuse("Service provider not found");
    };
    if !sp.enabled {
        return refuse("Service provider is disabled");
    }
    if !sp.allow_idp_initiated {
        return refuse("Service provider does not allow IdP-initiated SSO");
    }
    let relay_state = relay_state.filter(|r| !r.is_empty());
    if let Some(relay) = relay_state
        && relay.len() > options.max_relay_state_length
    {
        return refuse(format!(
            "RelayState exceeds maximum length of {} bytes",
            options.max_relay_state_length
        ));
    }
    let Some(acs) = sp
        .assertion_consumer_service_urls
        .iter()
        .find(|a| a.is_default)
        .or_else(|| sp.assertion_consumer_service_urls.first())
    else {
        return refuse("Service provider has no assertion consumer service URLs configured");
    };
    if url::Url::parse(&acs.location).is_err() {
        return refuse("Service provider has an invalid assertion consumer service URL configured");
    }
    Ok(Target {
        acs: acs.clone(),
        relay_state: relay_state.map(str::to_owned),
    })
}

/// The persisted grant type of an IdP-initiated SSO continuation.
pub const CONTINUATION: &str = "saml_idp_initiated_continuation";

/// What the interaction API checked, kept for the browser's visit: one
/// time, five minutes, and only in the browser whose session asked.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Continuation {
    pub entity_id: String,
    pub relay_state: Option<String>,
    pub session_id: String,
}

impl Continuation {
    /// Stores the continuation and returns its token.
    pub async fn store(
        &self,
        grants: &dyn rustid_core::stores::PersistedGrantStore,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<String, rustid_core::stores::StoreError> {
        use rustid_core::grants::{PersistedGrant, hashed_key, new_handle};
        let token = new_handle();
        grants
            .store(PersistedGrant {
                key: hashed_key(&token, CONTINUATION),
                grant_type: CONTINUATION.to_owned(),
                client_id: String::new(),
                subject_id: None,
                session_id: Some(self.session_id.clone()),
                description: None,
                creation_time: now,
                expiration: Some(
                    now + chrono::Duration::seconds(
                        rustid_core::authorize::login::CONTINUATION_LIFETIME_SECONDS,
                    ),
                ),
                consumed_time: None,
                data: serde_json::to_string(self).expect("continuations serialise"),
            })
            .await?;
        Ok(token)
    }

    /// Takes the continuation: once only, and only while unexpired.
    pub async fn redeem(
        grants: &dyn rustid_core::stores::PersistedGrantStore,
        token: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Option<Continuation>, rustid_core::stores::StoreError> {
        let key = rustid_core::grants::hashed_key(token, CONTINUATION);
        let Some(grant) = grants.take(&key).await? else {
            return Ok(None);
        };
        if grant.grant_type != CONTINUATION || grant.expiration.is_none_or(|e| e <= now) {
            return Ok(None);
        }
        Ok(serde_json::from_str(&grant.data).ok())
    }
}
