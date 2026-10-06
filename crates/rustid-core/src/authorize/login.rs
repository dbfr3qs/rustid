//! Signing a user in through the interaction API: the UI's login call
//! becomes a one-time continuation the browser redeems for its session
//! cookie, and a sealed cookie binds continuations to the browser that
//! started the authorize request.

use aws_lc_rs::digest;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::data_protection::DataProtector;
use crate::grants::{PersistedGrant, hashed_key, new_handle};
use crate::session::SignIn;
use crate::stores::{PersistedGrantStore, StoreError};
use crate::tokens::Claim;

/// The persisted grant type of a pending continuation.
pub const CONTINUATION: &str = "interaction_continuation";
/// How long a continuation can be redeemed.
pub const CONTINUATION_LIFETIME_SECONDS: i64 = 300;
/// The browser-binding cookie.
pub const BINDING_COOKIE: &str = "idsrv.interaction";
const BINDING_PURPOSE: &str = "rustid.interaction";
/// How many pending interactions one browser can have at once.
pub const BINDING_ENTRIES: usize = 10;
/// How long a started interaction can be completed.
pub const BINDING_LIFETIME_SECONDS: i64 = 3600;

/// A login waiting for its browser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Continuation {
    pub return_url: String,
    pub subject_id: String,
    pub idp: Option<String>,
    pub amr: Vec<String>,
    pub auth_time: Option<i64>,
    pub claims: Vec<Claim>,
    #[serde(default)]
    pub persistent: bool,
    #[serde(default)]
    pub allow_refresh: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_id_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_sid: Option<String>,
}

impl Continuation {
    pub fn new(return_url: &str, sign_in: SignIn) -> Continuation {
        Continuation {
            return_url: return_url.to_owned(),
            subject_id: sign_in.subject_id,
            idp: sign_in.idp,
            amr: sign_in.amr,
            auth_time: sign_in.auth_time,
            claims: sign_in.claims,
            persistent: sign_in.persistent,
            allow_refresh: sign_in.allow_refresh,
            upstream_id_token: sign_in.upstream_id_token,
            upstream_sid: sign_in.upstream_sid,
        }
    }

    pub fn sign_in(&self) -> SignIn {
        SignIn {
            subject_id: self.subject_id.clone(),
            idp: self.idp.clone(),
            amr: self.amr.clone(),
            auth_time: self.auth_time,
            claims: self.claims.clone(),
            persistent: self.persistent,
            allow_refresh: self.allow_refresh,
            upstream_id_token: self.upstream_id_token.clone(),
            upstream_sid: self.upstream_sid.clone(),
        }
    }

    /// Stores the continuation for 5 minutes and returns its token.
    pub async fn store(
        &self,
        grants: &dyn PersistedGrantStore,
        now: DateTime<Utc>,
    ) -> Result<String, StoreError> {
        let token = new_handle();
        grants
            .store(PersistedGrant {
                key: hashed_key(&token, CONTINUATION),
                grant_type: CONTINUATION.to_owned(),
                client_id: String::new(),
                subject_id: Some(self.subject_id.clone()),
                session_id: None,
                description: None,
                creation_time: now,
                expiration: Some(now + chrono::Duration::seconds(CONTINUATION_LIFETIME_SECONDS)),
                consumed_time: None,
                data: serde_json::to_string(self).expect("continuations serialize to JSON"),
            })
            .await?;
        Ok(token)
    }

    /// Takes the continuation for a token: at most once, and only before
    /// it expires.
    pub async fn redeem(
        grants: &dyn PersistedGrantStore,
        token: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<Continuation>, StoreError> {
        let Some(grant) = grants.take(&hashed_key(token, CONTINUATION)).await? else {
            return Ok(None);
        };
        if grant.grant_type != CONTINUATION || grant.expiration.is_none_or(|e| e <= now) {
            return Ok(None);
        }
        Ok(serde_json::from_str(&grant.data).ok())
    }
}

/// The browser's pending interactions: the SHA-256 of each return URL the
/// authorize endpoint sent it to a UI page with, and when that expires.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InteractionBinding {
    entries: Vec<(String, i64)>,
}

fn url_hash(return_url: &str) -> String {
    URL_SAFE_NO_PAD.encode(digest::digest(&digest::SHA256, return_url.as_bytes()).as_ref())
}

impl InteractionBinding {
    /// The binding in a cookie value; empty when absent or unreadable.
    pub fn open(protector: &DataProtector, cookie: Option<&str>) -> InteractionBinding {
        cookie
            .and_then(|c| protector.unprotect(BINDING_PURPOSE, c).ok())
            .and_then(|json| serde_json::from_slice(&json).ok())
            .unwrap_or_default()
    }

    pub fn seal(&self, protector: &DataProtector) -> String {
        let json = serde_json::to_vec(self).expect("bindings serialize to JSON");
        protector.protect(BINDING_PURPOSE, &json)
    }

    /// Records a return URL, dropping expired entries and the oldest beyond
    /// [`BINDING_ENTRIES`].
    pub fn add(&mut self, return_url: &str, now: DateTime<Utc>) {
        let hash = url_hash(return_url);
        let now = now.timestamp();
        self.entries
            .retain(|(h, expires)| *expires > now && *h != hash);
        self.entries.push((hash, now + BINDING_LIFETIME_SECONDS));
        if self.entries.len() > BINDING_ENTRIES {
            let excess = self.entries.len() - BINDING_ENTRIES;
            self.entries.drain(..excess);
        }
    }

    /// Whether this browser started the interaction for the return URL.
    pub fn contains(&self, return_url: &str, now: DateTime<Utc>) -> bool {
        let hash = url_hash(return_url);
        self.entries
            .iter()
            .any(|(h, expires)| *h == hash && *expires > now.timestamp())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000, 0).unwrap()
    }

    fn protector() -> DataProtector {
        DataProtector::new([("k", [3u8; 32].as_slice())]).unwrap()
    }

    #[test]
    fn bindings_hold_recent_return_urls_sealed() {
        let p = protector();
        let mut b = InteractionBinding::default();
        b.add("/connect/authorize/callback?a=1", now());
        let sealed = b.seal(&p);
        let opened = InteractionBinding::open(&p, Some(&sealed));
        assert!(opened.contains("/connect/authorize/callback?a=1", now()));
        assert!(!opened.contains("/connect/authorize/callback?a=2", now()));
        let later = now() + chrono::Duration::seconds(BINDING_LIFETIME_SECONDS);
        assert!(!opened.contains("/connect/authorize/callback?a=1", later));
        assert_eq!(
            InteractionBinding::open(&p, Some("forged")),
            InteractionBinding::default()
        );
        let other = DataProtector::new([("k", [4u8; 32].as_slice())]).unwrap();
        assert_eq!(
            InteractionBinding::open(&other, Some(&sealed)),
            InteractionBinding::default()
        );
    }

    #[test]
    fn bindings_keep_only_the_newest_entries() {
        let mut b = InteractionBinding::default();
        for i in 0..=BINDING_ENTRIES {
            b.add(&format!("/connect/authorize/callback?n={i}"), now());
        }
        assert!(!b.contains("/connect/authorize/callback?n=0", now()));
        assert!(b.contains(
            &format!("/connect/authorize/callback?n={BINDING_ENTRIES}"),
            now()
        ));
        b.add("/connect/authorize/callback?n=5", now());
        assert_eq!(
            b.entries.len(),
            BINDING_ENTRIES,
            "re-adding doesn't duplicate"
        );
    }
}
