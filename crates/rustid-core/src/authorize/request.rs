//! `ValidatedAuthorizeRequest` and its helpers.

use std::sync::Arc;

use aws_lc_rs::digest;
use aws_lc_rs::rand::SecureRandom;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use super::{PROCESSED_MAX_AGE, PROCESSED_PROMPT};
use crate::clients::Client;
use crate::params::Params;
use crate::scopes::ValidatedResources;
use crate::session::UserSession;

/// `AuthorizeRequestType`: the authorize endpoint, the PAR endpoint, or the
/// authorize endpoint using a pushed request.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AuthorizeRequestType {
    #[default]
    Authorize,
    PushedAuthorization,
    AuthorizeWithPushedParameters,
}

/// The `acr_values` prefixes the server interprets (`idp:`, `tenant:`).
pub const ACR_IDP_PREFIX: &str = "idp:";
pub const ACR_TENANT_PREFIX: &str = "tenant:";

/// An authorize request as far as validation got. On failure the fields
/// validated before the error are set, so the error response
/// can use them.
#[derive(Debug, Clone, Default)]
pub struct ValidatedAuthorizeRequest {
    /// The request's parameters. Processing adds the processed-prompt
    /// markers and strips disallowed `idp:` values, and the return URL to
    /// the UI is built from this.
    pub raw: Params,
    /// The signed-in user, `None` when anonymous.
    pub subject: Option<UserSession>,
    pub client_id: Option<String>,
    pub client: Option<Arc<Client>>,
    pub redirect_uri: Option<String>,
    pub state: Option<String>,
    /// The supported response type the request's value matched.
    pub response_type: Option<&'static str>,
    pub grant_type: Option<&'static str>,
    pub response_mode: Option<&'static str>,
    pub requested_scopes: Vec<String>,
    pub is_openid_request: bool,
    pub is_api_resource_request: bool,
    pub resources: Option<ValidatedResources>,
    pub resource_indicators: Vec<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub original_prompt_modes: Vec<String>,
    pub processed_prompt_modes: Vec<String>,
    /// Prompt values still to act on: the original minus the processed.
    pub prompt_modes: Vec<String>,
    pub display_mode: Option<String>,
    pub max_age: Option<i32>,
    pub login_hint: Option<String>,
    /// `AuthenticationContextReferenceClasses`, de-duplicated.
    pub acr_values: Vec<String>,
    pub ui_locales: Option<String>,
    /// The session id: empty for anonymous users.
    pub session_id: Option<String>,
    pub dpop_key_thumbprint: Option<String>,
    pub request_object: Option<String>,
    /// Where the request is being validated (`AuthorizeRequestType`).
    pub request_type: AuthorizeRequestType,
    /// The request object's parameters (`RequestObjectValues`).
    pub request_object_values: Vec<(String, String)>,
    /// The pushed request this one uses (`PushedAuthorizationReferenceValue`).
    pub pushed_reference: Option<String>,
    /// The consent page was shown and answered (`WasConsentShown`).
    pub was_consent_shown: bool,
    /// What the consent page said the grant is for (`Description`).
    pub description: Option<String>,
}

impl ValidatedAuthorizeRequest {
    pub fn client_name(&self) -> Option<&str> {
        self.client.as_ref().and_then(|c| c.client_name.as_deref())
    }

    fn prefixed_acr_value(&self, prefix: &str) -> Option<&str> {
        self.acr_values
            .iter()
            .find_map(|acr| acr.strip_prefix(prefix))
    }

    /// `GetIdP()`: the value of the first `idp:` entry.
    pub fn idp(&self) -> Option<&str> {
        self.prefixed_acr_value(ACR_IDP_PREFIX)
    }

    /// `GetTenant()`: the value of the first `tenant:` entry.
    pub fn tenant(&self) -> Option<&str> {
        self.prefixed_acr_value(ACR_TENANT_PREFIX)
    }

    /// `RemoveIdP()`: drops every `idp:` entry, from the raw parameters too.
    pub fn remove_idp(&mut self) {
        self.acr_values
            .retain(|acr| !acr.starts_with(ACR_IDP_PREFIX));
        if self.acr_values.is_empty() {
            self.raw.remove("acr_values");
        } else {
            let joined = self.acr_values.join(" ");
            self.raw.set("acr_values", &joined);
        }
    }

    /// `RemovePrompt()`: records `login`, `select_account` and `create` as
    /// processed and stops acting on them.
    pub fn remove_prompt(&mut self) {
        let processed: Vec<&str> = ["login", "select_account", "create"]
            .into_iter()
            .filter(|p| self.prompt_modes.iter().any(|m| m == p))
            .collect();
        self.raw.add(PROCESSED_PROMPT, &processed.join(" "));
        self.prompt_modes
            .retain(|m| !matches!(m.as_str(), "login" | "select_account" | "create"));
    }

    /// `RemoveMaxAge()`: records `max_age` as processed and clears it.
    pub fn remove_max_age(&mut self) {
        if let Some(max_age) = self.max_age.take() {
            self.raw.add(PROCESSED_MAX_AGE, &max_age.to_string());
        }
    }

    /// `GenerateSessionStateValue()`: the OIDC session management value
    /// `base64url(sha256(client_id + origin + session_id + salt)).salt`,
    /// for OpenID requests with a known session id and redirect URI.
    pub fn session_state_value(&self) -> Option<String> {
        if !self.is_openid_request {
            return None;
        }
        let session_id = self.session_id.as_deref()?;
        let client_id = self.client_id.as_deref().filter(|c| !c.trim().is_empty())?;
        let redirect_uri = self.redirect_uri.as_deref()?;
        let origin = redirect_origin(redirect_uri)?;
        let mut salt = [0u8; 16];
        aws_lc_rs::rand::SystemRandom::new()
            .fill(&mut salt)
            .expect("system random source");
        let salt: String = salt.iter().map(|b| format!("{b:02X}")).collect();
        let input = format!("{client_id}{origin}{session_id}{salt}");
        let hash = digest::digest(&digest::SHA256, input.as_bytes());
        Some(format!("{}.{salt}", URL_SAFE_NO_PAD.encode(hash.as_ref())))
    }
}

/// `scheme://host[:port]` of a redirect URI, the port only when not the
/// scheme's default. Unlike a web origin this also covers custom schemes
/// (`com.example.app://callback`).
fn redirect_origin(uri: &str) -> Option<String> {
    let url = url::Url::parse(uri).ok()?;
    let host = url.host_str()?;
    Some(match url.port() {
        Some(port) => format!("{}://{host}:{port}", url.scheme()),
        None => format!("{}://{host}", url.scheme()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_acr(acr: &str) -> ValidatedAuthorizeRequest {
        ValidatedAuthorizeRequest {
            raw: Params::from_pairs([("client_id", "c"), ("acr_values", acr), ("x", "1")]),
            acr_values: crate::params::split_spaces(acr),
            ..Default::default()
        }
    }

    #[test]
    fn idp_and_tenant_come_from_prefixed_acr_values() {
        let r = with_acr("urn:x idp:google tenant:t1 idp:other");
        assert_eq!(r.idp(), Some("google"));
        assert_eq!(r.tenant(), Some("t1"));
    }

    #[test]
    fn removing_idp_rewrites_acr_values_in_place() {
        let mut r = with_acr("idp:google urn:x");
        r.remove_idp();
        assert_eq!(
            r.raw.to_query_string(),
            "client_id=c&acr_values=urn%3Ax&x=1"
        );
        let mut r = with_acr("idp:google");
        r.remove_idp();
        assert_eq!(r.raw.to_query_string(), "client_id=c&x=1");
    }

    #[test]
    fn remove_prompt_records_processed_values_in_fixed_order() {
        let mut r = ValidatedAuthorizeRequest {
            prompt_modes: vec!["consent".into(), "select_account".into(), "login".into()],
            ..Default::default()
        };
        r.remove_prompt();
        assert_eq!(
            r.raw.get(PROCESSED_PROMPT).as_deref(),
            Some("login select_account")
        );
        assert_eq!(r.prompt_modes, ["consent"]);
    }

    #[test]
    fn remove_max_age_records_the_value() {
        let mut r = ValidatedAuthorizeRequest {
            max_age: Some(0),
            ..Default::default()
        };
        r.remove_max_age();
        assert_eq!(r.max_age, None);
        assert_eq!(r.raw.get(PROCESSED_MAX_AGE).as_deref(), Some("0"));
    }

    #[test]
    fn session_state_hashes_client_origin_session_and_salt() {
        let r = ValidatedAuthorizeRequest {
            is_openid_request: true,
            client_id: Some("web".into()),
            redirect_uri: Some("https://client.test:8443/cb".into()),
            session_id: Some(String::new()),
            ..Default::default()
        };
        let value = r.session_state_value().unwrap();
        let (hash, salt) = value.split_once('.').unwrap();
        assert_eq!(salt.len(), 32);
        let expected = digest::digest(
            &digest::SHA256,
            format!("webhttps://client.test:8443{salt}").as_bytes(),
        );
        assert_eq!(hash, URL_SAFE_NO_PAD.encode(expected.as_ref()));
        let not_openid = ValidatedAuthorizeRequest {
            is_openid_request: false,
            ..r.clone()
        };
        assert_eq!(not_openid.session_state_value(), None);
    }

    #[test]
    fn redirect_origins_include_custom_schemes() {
        assert_eq!(
            redirect_origin("https://C.test:443/cb").as_deref(),
            Some("https://c.test")
        );
        assert_eq!(
            redirect_origin("http://c.test:8080/cb").as_deref(),
            Some("http://c.test:8080")
        );
        assert_eq!(
            redirect_origin("com.app://callback/x").as_deref(),
            Some("com.app://callback")
        );
    }
}
