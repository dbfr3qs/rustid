//! Persisted grants and the handle/key scheme of the grant store.
//! Stores implement `stores::PersistedGrantStore`.

use aws_lc_rs::digest;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::{DateTime, Utc};

/// Persisted grant types.
pub const REFERENCE_TOKEN: &str = "reference_token";

/// Suffix marking the current handle format (hex, SHA-256 hex keys).
pub const HANDLE_SUFFIX: &str = "-1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedGrant {
    /// The hashed key, never the handle itself.
    pub key: String,
    pub grant_type: String,
    pub client_id: String,
    pub subject_id: Option<String>,
    pub session_id: Option<String>,
    pub description: Option<String>,
    pub creation_time: DateTime<Utc>,
    pub expiration: Option<DateTime<Utc>>,
    pub consumed_time: Option<DateTime<Utc>>,
    /// The serialised item.
    pub data: String,
}

/// Which grants `remove_all` deletes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GrantFilter {
    pub subject_id: Option<String>,
    pub session_id: Option<String>,
    pub client_id: Option<String>,
    pub grant_type: Option<String>,
    /// `ClientIds`: merged with `client_id` into one set to match.
    pub client_ids: Vec<String>,
    /// `Types`: merged with `grant_type` into one set to match.
    pub grant_types: Vec<String>,
}

impl GrantFilter {
    /// No criterion set: such a filter is rejected rather than matching all.
    pub fn is_empty(&self) -> bool {
        self == &GrantFilter::default()
    }

    /// The client ids to match (`client_id` with `client_ids`), or `None`
    /// for any.
    pub fn client_set(&self) -> Option<Vec<String>> {
        merged(&self.client_id, &self.client_ids)
    }

    /// The grant types to match (`grant_type` with `grant_types`), or
    /// `None` for any.
    pub fn type_set(&self) -> Option<Vec<String>> {
        merged(&self.grant_type, &self.grant_types)
    }

    /// Every criterion that is set holds for the grant: the subject and
    /// session equal it, and its client and type are in their sets.
    pub fn matches(&self, grant: &PersistedGrant) -> bool {
        let eq = |want: &Option<String>, have: Option<&str>| {
            want.as_deref().is_none_or(|w| have == Some(w))
        };
        let within = |set: Option<Vec<String>>, have: &str| {
            set.is_none_or(|set| set.iter().any(|v| v == have))
        };
        eq(&self.subject_id, grant.subject_id.as_deref())
            && eq(&self.session_id, grant.session_id.as_deref())
            && within(self.client_set(), &grant.client_id)
            && within(self.type_set(), &grant.grant_type)
    }
}

/// 32 random bytes as hex plus the format suffix: 64
/// upper-case hex characters then `-1`.
pub fn new_handle() -> String {
    use aws_lc_rs::rand::SecureRandom;
    let mut bytes = [0u8; 32];
    aws_lc_rs::rand::SystemRandom::new()
        .fill(&mut bytes)
        .expect("system random source");
    let hex: String = bytes.iter().map(|b| format!("{b:02X}")).collect();
    format!("{hex}{HANDLE_SUFFIX}")
}

/// SHA-256 of `handle:type`, upper-case
/// hex for current handles, base64 for legacy handles without the suffix.
pub fn hashed_key(handle: &str, grant_type: &str) -> String {
    let hash = digest::digest(&digest::SHA256, format!("{handle}:{grant_type}").as_bytes());
    if handle.ends_with(HANDLE_SUFFIX) {
        hash.as_ref().iter().map(|b| format!("{b:02X}")).collect()
    } else {
        STANDARD.encode(hash)
    }
}

/// One value and a list of the same criterion, as one set.
fn merged(one: &Option<String>, many: &[String]) -> Option<Vec<String>> {
    let mut set: Vec<String> = one.iter().chain(many).cloned().collect();
    set.dedup();
    (!set.is_empty()).then_some(set)
}
