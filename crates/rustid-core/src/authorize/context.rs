//! Return URLs and the authorization context a UI reads for them
//! (the OIDC return url parser, get authorization context,
//! `AuthorizationRequest`).

use serde::Serialize;

use super::request::{ACR_IDP_PREFIX, ACR_TENANT_PREFIX, ValidatedAuthorizeRequest};
use super::validation::{AuthorizeContext, AuthorizeFailure, validate};
use crate::form::Form;
use crate::params::{Params, is_local_url};
use crate::scopes::OFFLINE_ACCESS;
use crate::session::UserSession;
use crate::stores::StoreError;

/// `IsValidReturnUrl`: a local URL whose path ends with the authorize or
/// callback route (case-sensitive, compared ordinally).
pub fn is_valid_return_url(return_url: &str) -> bool {
    if !is_local_url(return_url) {
        return false;
    }
    let path = return_url.split(['?', '#']).next().unwrap_or_default();
    path.ends_with("/connect/authorize") || path.ends_with("/connect/authorize/callback")
}

/// `ReadQueryStringAsNameValueCollection`: the return URL's query, blank
/// values dropped, keys keeping their first casing.
pub fn return_url_parameters(return_url: &str) -> Params {
    let Some((_, query)) = return_url.split_once('?') else {
        return Params::default();
    };
    let query = query.split('#').next().unwrap_or_default();
    Params::from_pairs(query.split('&').filter(|p| !p.is_empty()).map(|pair| {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        (
            Form::decode_component(k.as_bytes()),
            Form::decode_component(v.as_bytes()),
        )
    }))
}

/// `AuthorizationRequest`: what the UI is told about the request it is
/// completing. Field names are camelCase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationContext {
    pub client_id: String,
    pub client_name: Option<String>,
    pub redirect_uri: String,
    pub display_mode: Option<String>,
    pub ui_locales: Option<String>,
    #[serde(rename = "idP")]
    pub idp: Option<String>,
    pub tenant: Option<String>,
    pub login_hint: Option<String>,
    /// The prompt values as requested (`OriginalPromptModes`).
    pub prompt_modes: Vec<String>,
    /// `GetAcrValues()`: without the `idp:` and `tenant:` entries.
    pub acr_values: Vec<String>,
    /// The requested scopes that validated (`RawScopeValues`).
    pub scopes: Vec<String>,
    /// Every request parameter, repeated values joined with commas.
    pub parameters: serde_json::Map<String, serde_json::Value>,
}

/// The request a valid return URL continues, validated again for the
/// browser's session; `None` when the URL or the request isn't valid.
pub async fn validated_return_url(
    ctx: &AuthorizeContext<'_>,
    return_url: &str,
    session: Option<&UserSession>,
) -> Result<Option<ValidatedAuthorizeRequest>, StoreError> {
    if !is_valid_return_url(return_url) {
        return Ok(None);
    }
    match validate(ctx, return_url_parameters(return_url), session).await {
        Ok(request) => Ok(Some(request)),
        Err(AuthorizeFailure::Invalid(_)) => Ok(None),
        Err(AuthorizeFailure::Server(message)) => Err(StoreError::Backend(message)),
    }
}

/// The context of a valid return URL whose
/// request still validates for the browser's session, `None` otherwise.
pub async fn authorization_context(
    ctx: &AuthorizeContext<'_>,
    return_url: &str,
    session: Option<&UserSession>,
) -> Result<Option<AuthorizationContext>, StoreError> {
    Ok(validated_return_url(ctx, return_url, session)
        .await?
        .map(|request| AuthorizationContext::of(&request)))
}

impl AuthorizationContext {
    /// `AuthorizationRequest`'s constructor.
    pub fn of(request: &ValidatedAuthorizeRequest) -> AuthorizationContext {
        let client = request
            .client
            .as_ref()
            .expect("validated request has a client");
        let mut acr_values: Vec<String> = Vec::new();
        for acr in &request.acr_values {
            if !acr.starts_with(ACR_IDP_PREFIX)
                && !acr.starts_with(ACR_TENANT_PREFIX)
                && !acr_values.contains(acr)
            {
                acr_values.push(acr.clone());
            }
        }
        let parameters = request
            .raw
            .iter()
            .map(|(k, v)| (k.to_owned(), serde_json::Value::String(v.join(","))))
            .collect();
        AuthorizationContext {
            client_id: client.client_id.clone(),
            client_name: client.client_name.clone(),
            redirect_uri: request.redirect_uri.clone().unwrap_or_default(),
            display_mode: request.display_mode.clone(),
            ui_locales: request.ui_locales.clone(),
            idp: request.idp().map(str::to_owned),
            tenant: request.tenant().map(str::to_owned),
            login_hint: request.login_hint.clone(),
            prompt_modes: request.original_prompt_modes.clone(),
            acr_values,
            scopes: request
                .resources
                .as_ref()
                .map(|r| r.scopes.clone())
                .unwrap_or_default(),
            parameters,
        }
    }
}

/// A scope as a consent page shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeDescription {
    pub name: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub required: bool,
    pub emphasize: bool,
}

/// What a consent page needs: the authorization context, the client's
/// display fields and the requested scopes described.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentContext {
    #[serde(flatten)]
    pub request: AuthorizationContext,
    pub client_uri: Option<String>,
    pub logo_uri: Option<String>,
    pub allow_remember_consent: bool,
    pub identity_scopes: Vec<ScopeDescription>,
    /// API scopes, then `offline_access` when requested.
    pub api_scopes: Vec<ScopeDescription>,
}

impl ConsentContext {
    pub fn of(request: &ValidatedAuthorizeRequest) -> ConsentContext {
        let client = request
            .client
            .as_ref()
            .expect("validated request has a client");
        let resources = request.resources.clone().unwrap_or_default();
        let mut api_scopes: Vec<ScopeDescription> = resources
            .api_scopes
            .iter()
            .map(|s| ScopeDescription {
                name: s.name.clone(),
                display_name: s.display_name.clone(),
                description: s.description.clone(),
                required: s.required,
                emphasize: s.emphasize,
            })
            .collect();
        if resources.offline_access {
            api_scopes.push(ScopeDescription {
                name: OFFLINE_ACCESS.to_owned(),
                display_name: Some("Offline access".to_owned()),
                description: Some(
                    "Access to your applications and resources, even when you are offline"
                        .to_owned(),
                ),
                required: false,
                emphasize: true,
            });
        }
        ConsentContext {
            request: AuthorizationContext::of(request),
            client_uri: client.client_uri.clone(),
            logo_uri: client.logo_uri.clone(),
            allow_remember_consent: client.allow_remember_consent,
            identity_scopes: resources
                .identity_resources
                .iter()
                .map(|r| ScopeDescription {
                    name: r.name.clone(),
                    display_name: r.display_name.clone(),
                    description: r.description.clone(),
                    required: r.required,
                    emphasize: r.emphasize,
                })
                .collect(),
            api_scopes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn return_urls_must_be_local_authorize_or_callback_paths() {
        for ok in [
            "/connect/authorize/callback?client_id=web",
            "/identity/connect/authorize?x=1",
            "/connect/authorize/callback#frag",
        ] {
            assert!(is_valid_return_url(ok), "{ok}");
        }
        for bad in [
            "https://evil.test/connect/authorize/callback",
            "//evil.test/connect/authorize/callback",
            "/connect/Authorize/callback",
            "/connect/token",
            "/connect/authorize/callback/extra",
        ] {
            assert!(!is_valid_return_url(bad), "{bad}");
        }
    }

    #[test]
    fn return_url_parameters_decode_and_keep_first_casing() {
        let p = return_url_parameters("/connect/authorize/callback?a=1&A=2&b=x%20y+z&c=&d#f=1");
        assert_eq!(p.to_query_string(), "a=1&a=2&b=x%20y%20z");
    }
}
