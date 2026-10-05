//! The browser session: who signed in, how and when, sealed into the
//! `idsrv` cookie as a sealed authentication ticket.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::data_protection::DataProtector;
use crate::tokens::Claim;

/// The authentication cookie's name.
pub const SESSION_COOKIE: &str = "idsrv";
/// The identity provider of users who sign in locally.
pub const LOCAL_IDP: &str = "local";
/// The purpose the session cookie is sealed under.
pub const SESSION_PURPOSE: &str = "rustid.session";

/// A signed-in user, as the `idsrv` cookie carries it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserSession {
    pub subject_id: String,
    /// The session id (`sid`): 32 upper-case hex characters.
    pub session_id: String,
    /// Seconds since the epoch.
    pub auth_time: i64,
    pub idp: String,
    pub amr: Vec<String>,
    /// Every other claim the login supplied (name, email, tenant, …).
    pub claims: Vec<Claim>,
    /// Clients that received a response in this session, for logout.
    pub client_ids: Vec<String>,
    /// SAML service providers that received an assertion in this session, for single logout.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub saml_sessions: Vec<SamlSpSession>,
    pub issued: DateTime<Utc>,
    pub expires: DateTime<Utc>,
    /// A persistent cookie ("remember me"): it has `expires`.
    #[serde(default)]
    pub persistent: bool,
    /// `Some(false)` stops sliding renewal.
    #[serde(default)]
    pub allow_refresh: Option<bool>,
    /// Token use extended the session: renew the cookie on the next request.
    #[serde(default)]
    pub force_renewal: bool,
    /// The issuer when the session was stored server side.
    #[serde(default)]
    pub issuer: Option<String>,
    /// The server-side session's key, when the cookie holds only that.
    #[serde(skip)]
    pub key: Option<String>,
    /// The upstream provider's id token, for `id_token_hint` when signing
    /// out there (kept only with server-side sessions).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_id_token: Option<String>,
}

/// A service provider's session within the user's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SamlSpSession {
    pub entity_id: String,
    pub session_index: String,
    pub name_id: String,
    pub name_id_format: Option<String>,
}

/// What a UI supplies when it signs a user in.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignIn {
    pub subject_id: String,
    pub idp: Option<String>,
    pub amr: Vec<String>,
    /// Seconds since the epoch; now when absent.
    pub auth_time: Option<i64>,
    pub claims: Vec<Claim>,
    /// A persistent cookie.
    pub persistent: bool,
    /// `Some(false)` stops sliding renewal.
    pub allow_refresh: Option<bool>,
    /// The upstream provider's id token, kept for signing out there.
    pub upstream_id_token: Option<String>,
}

impl UserSession {
    /// Missing claims filled in: `idp`
    /// defaults to `local`, `amr` to `pwd` for local users and `external`
    /// otherwise, `auth_time` to now. The session id is kept when the same
    /// subject signs in again in the same browser,
    /// with its client list; otherwise a new one is made.
    pub fn sign_in(
        sign_in: SignIn,
        current: Option<&UserSession>,
        now: DateTime<Utc>,
        lifetime_seconds: i64,
    ) -> UserSession {
        let idp = sign_in
            .idp
            .filter(|i| !i.trim().is_empty())
            .unwrap_or_else(|| LOCAL_IDP.to_owned());
        let amr = if sign_in.amr.is_empty() {
            vec![if idp == LOCAL_IDP { "pwd" } else { "external" }.to_owned()]
        } else {
            sign_in.amr
        };
        // The same browser keeps its server-side session key, whoever signs
        // in (the authenticated request's session key is reused).
        let key = current.and_then(|c| c.key.clone());
        let (session_id, client_ids) = match current {
            Some(c) if c.subject_id == sign_in.subject_id => {
                (c.session_id.clone(), c.client_ids.clone())
            }
            _ => (new_session_id(), Vec::new()),
        };
        UserSession {
            subject_id: sign_in.subject_id,
            session_id,
            auth_time: sign_in.auth_time.unwrap_or_else(|| now.timestamp()),
            idp,
            amr,
            claims: sign_in.claims,
            client_ids,
            saml_sessions: Vec::new(),
            issued: now,
            expires: now + chrono::Duration::seconds(lifetime_seconds.max(0)),
            persistent: sign_in.persistent,
            allow_refresh: sign_in.allow_refresh,
            force_renewal: false,
            issuer: None,
            key,
            upstream_id_token: sign_in.upstream_id_token,
        }
    }

    /// The first claim of a type among the session's other claims.
    pub fn claim(&self, claim_type: &str) -> Option<&str> {
        self.claims
            .iter()
            .find(|c| c.claim_type == claim_type)
            .map(|c| c.value.as_str())
    }

    /// Records the client; `true` when it was new, so
    /// the cookie must be written again.
    /// Records a SAML session, replacing the provider's earlier one.
    pub fn add_saml_session(&mut self, session: SamlSpSession) {
        self.saml_sessions
            .retain(|s| s.entity_id != session.entity_id);
        self.saml_sessions.push(session);
    }

    pub fn add_client(&mut self, client_id: &str) -> bool {
        if self.client_ids.iter().any(|c| c == client_id) {
            return false;
        }
        self.client_ids.push(client_id.to_owned());
        true
    }

    pub fn seal(&self, protector: &DataProtector) -> String {
        let json = serde_json::to_vec(self).expect("sessions serialize to JSON");
        protector.protect(SESSION_PURPOSE, &json)
    }

    /// The session in a cookie value, if it opens and hasn't expired.
    pub fn open(
        protector: &DataProtector,
        cookie: &str,
        now: DateTime<Utc>,
    ) -> Option<UserSession> {
        let json = protector.unprotect(SESSION_PURPOSE, cookie).ok()?;
        let session: UserSession = serde_json::from_slice(&json).ok()?;
        (session.expires > now).then_some(session)
    }
}

/// A new session id: 16 random bytes as upper-case hex.
pub fn new_session_id() -> String {
    crate::tokens::new_jwt_id()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000, 0).unwrap()
    }

    fn alice() -> SignIn {
        SignIn {
            subject_id: "1".into(),
            claims: vec![Claim::string("name", "Alice")],
            ..Default::default()
        }
    }

    #[test]
    fn missing_claims_are_added() {
        let s = UserSession::sign_in(alice(), None, now(), 3600);
        assert_eq!(
            (s.idp.as_str(), s.amr.as_slice()),
            ("local", &["pwd".to_owned()][..])
        );
        assert_eq!(s.auth_time, 1_800_000_000);
        assert_eq!(s.session_id.len(), 32);
        assert!(
            s.session_id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_lowercase())
        );
        assert_eq!(s.expires, now() + chrono::Duration::hours(1));
        let external = UserSession::sign_in(
            SignIn {
                idp: Some("google".into()),
                ..alice()
            },
            None,
            now(),
            3600,
        );
        assert_eq!(external.amr, ["external"]);
    }

    #[test]
    fn signing_in_again_keeps_the_session_id_only_for_the_same_subject() {
        let mut first = UserSession::sign_in(alice(), None, now(), 3600);
        first.add_client("web");
        let again = UserSession::sign_in(alice(), Some(&first), now(), 3600);
        assert_eq!(again.session_id, first.session_id);
        assert_eq!(again.client_ids, ["web"]);
        let bob = UserSession::sign_in(
            SignIn {
                subject_id: "2".into(),
                ..alice()
            },
            Some(&first),
            now(),
            3600,
        );
        assert_ne!(bob.session_id, first.session_id);
        assert!(bob.client_ids.is_empty());
    }

    #[test]
    fn sealed_sessions_open_until_they_expire() {
        let protector = DataProtector::new([("k", [1u8; 32].as_slice())]).unwrap();
        let s = UserSession::sign_in(alice(), None, now(), 60);
        let sealed = s.seal(&protector);
        assert_eq!(
            UserSession::open(&protector, &sealed, now()),
            Some(s.clone())
        );
        assert_eq!(
            UserSession::open(&protector, &sealed, now() + chrono::Duration::seconds(60)),
            None
        );
        assert_eq!(UserSession::open(&protector, "garbage", now()), None);
        let other = DataProtector::new([("k", [2u8; 32].as_slice())]).unwrap();
        assert_eq!(UserSession::open(&other, &sealed, now()), None);
    }

    #[test]
    fn clients_are_recorded_once() {
        let mut s = UserSession::sign_in(alice(), None, now(), 60);
        assert!(s.add_client("web"));
        assert!(!s.add_client("web"));
        assert_eq!(s.client_ids, ["web"]);
    }
}
