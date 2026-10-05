//! RP-initiated logout: the end session request validator, the `LogoutMessage`
//! the logout page's context comes from, and identity token hints
//! (the token validator without the lifetime).

use std::collections::BTreeMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::access_tokens::ValidationContext;
use crate::clients::Client;
use crate::jwt::Jws;
use crate::params::{Params, add_query_param, utf16_len};
use crate::session::UserSession;
use crate::stores::{StoreError, find_enabled_client};

/// A validated end session request.
#[derive(Debug, Clone, Default)]
pub struct EndSessionRequest {
    pub raw: Params,
    pub ui_locales: Option<String>,
    /// The client the identity token hint was issued to.
    pub client: Option<Arc<Client>>,
    /// The signed-in user being signed out.
    pub subject_id: Option<String>,
    pub session_id: Option<String>,
    /// The clients the session has signed in to.
    pub client_ids: Vec<String>,
    /// The SAML service providers the session has signed in to.
    pub saml_sessions: Vec<crate::session::SamlSpSession>,
    /// A post-logout redirect URI registered for the hint's client.
    pub post_logout_redirect_uri: Option<String>,
    pub state: Option<String>,
}

/// An identity token this
/// server issued (its signature and issuer), to an enabled client named by
/// its single audience; the lifetime isn't checked. The claims and client.
pub async fn validate_identity_token_hint(
    ctx: &ValidationContext<'_>,
    token: &str,
) -> Result<Option<(Map<String, Value>, Arc<Client>)>, StoreError> {
    if token.len() > ctx.options.input_length_restrictions.jwt {
        return Ok(None);
    }
    let Some(jws) = Jws::decode(token) else {
        return Ok(None);
    };
    let client_id = match jws.payload.get("aud") {
        Some(Value::String(aud)) => aud.clone(),
        Some(Value::Array(auds)) if auds.len() == 1 => match auds[0].as_str() {
            Some(aud) => aud.to_owned(),
            None => return Ok(None),
        },
        _ => return Ok(None),
    };
    let Some(client) = find_enabled_client(ctx.stores.clients.as_ref(), &client_id).await? else {
        return Ok(None);
    };
    if jws.claim_str("iss") != Some(ctx.issuer) {
        return Ok(None);
    }
    let keys = ctx.keys.validation_keys().await?;
    let named = jws
        .header_str("kid")
        .and_then(|kid| keys.iter().find(|k| k.kid == kid));
    let signed = match named {
        Some(key) => jws.verify(&key.public_jwk()),
        None => keys.iter().any(|k| jws.verify(&k.public_jwk())),
    };
    if !signed {
        return Ok(None);
    }
    Ok(Some((jws.payload, client)))
}

/// The request's `ui_locales`, unless over the length limit. Read first, so
/// a request that fails validation still has it (for the culture cookie).
pub fn ui_locales(ctx: &ValidationContext<'_>, raw: &Params) -> Option<String> {
    raw.get("ui_locales")
        .filter(|l| utf16_len(l) <= ctx.options.input_length_restrictions.ui_locale)
}

/// The end session request validator for the browser's session.
/// The error is the validation failure's description; the endpoint still
/// sends the browser to the logout page, without a message.
pub async fn validate(
    ctx: &ValidationContext<'_>,
    raw: Params,
    session: Option<&UserSession>,
) -> Result<Result<EndSessionRequest, String>, StoreError> {
    let mut request = EndSessionRequest {
        raw,
        ..Default::default()
    };
    request.ui_locales = ui_locales(ctx, &request.raw);
    if session.is_none()
        && ctx
            .options
            .authentication
            .require_authenticated_user_for_sign_out_message
    {
        return Ok(Err(
            "User is anonymous. Ignoring end session parameters".to_owned()
        ));
    }
    let Some(hint) = request.raw.get("id_token_hint").filter(|h| !h.is_empty()) else {
        // No token names a client, but the user's session says who to sign
        // out of.
        if let Some(session) = session {
            request.subject_id = Some(session.subject_id.clone());
            request.session_id = Some(session.session_id.clone());
            request.client_ids = session.client_ids.clone();
            request.saml_sessions = session.saml_sessions.clone();
        }
        return Ok(Ok(request));
    };
    let Some((claims, client)) = validate_identity_token_hint(ctx, &hint).await? else {
        return Ok(Err("Error validating id token hint".to_owned()));
    };
    if let Some(session) = session {
        // The session id when the hint has one,
        // else the subject.
        let claim = |name: &str| claims.get(name).and_then(Value::as_str);
        if let Some(sid) = claim("sid") {
            if sid != session.session_id {
                return Ok(Err(
                    "Session ID in id_token_hint does not match current session".to_owned(),
                ));
            }
        } else if let Some(sub) = claim("sub")
            && sub != session.subject_id
        {
            return Ok(Err("Current user does not match identity token".to_owned()));
        }
        request.subject_id = Some(session.subject_id.clone());
        request.session_id = Some(session.session_id.clone());
        request.client_ids = session.client_ids.clone();
        request.saml_sessions = session.saml_sessions.clone();
    }
    if let Some(uri) = request.raw.get("post_logout_redirect_uri")
        && client.post_logout_redirect_uris.iter().any(|u| u == &uri)
    {
        request.post_logout_redirect_uri = Some(uri);
        request.state = request.raw.get("state").filter(|s| !s.is_empty());
    }
    request.client = Some(client);
    Ok(Ok(request))
}

/// `LogoutMessage`: what the logout page's context is made from. The
/// hint, redirect, state and `ui_locales` are not among its parameters.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogoutMessage {
    pub client_id: Option<String>,
    pub client_name: Option<String>,
    /// With `state` added when one was sent.
    pub post_logout_redirect_uri: Option<String>,
    pub subject_id: Option<String>,
    pub session_id: Option<String>,
    pub client_ids: Vec<String>,
    pub ui_locales: Option<String>,
    pub requires_confirmation: bool,
    pub parameters: BTreeMap<String, Vec<String>>,
    /// The SAML SP whose LogoutRequest started this logout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saml_service_provider_entity_id: Option<String>,
    /// That LogoutRequest's id, for the LogoutResponse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saml_logout_request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saml_relay_state: Option<String>,
    /// The SAML SPs the session has signed in to.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub saml_sessions: Vec<crate::session::SamlSpSession>,
}

/// Parameters that travel in their own fields.
const SEPARATE: &[&str] = &[
    "id_token_hint",
    "post_logout_redirect_uri",
    "state",
    "ui_locales",
];

impl LogoutMessage {
    pub fn from_request(request: &EndSessionRequest) -> LogoutMessage {
        let parameters = request
            .raw
            .iter()
            .filter(|(k, _)| !SEPARATE.contains(k))
            .map(|(k, v)| (k.to_owned(), v.to_vec()))
            .collect();
        LogoutMessage {
            client_id: request.client.as_ref().map(|c| c.client_id.clone()),
            client_name: request.client.as_ref().and_then(|c| c.client_name.clone()),
            post_logout_redirect_uri: request.post_logout_redirect_uri.as_ref().map(|uri| {
                match &request.state {
                    Some(state) => add_query_param(uri, "state", state),
                    None => uri.clone(),
                }
            }),
            subject_id: request.subject_id.clone(),
            session_id: request.session_id.clone(),
            client_ids: request.client_ids.clone(),
            ui_locales: request.ui_locales.clone(),
            requires_confirmation: false,
            parameters,
            saml_sessions: request.saml_sessions.clone(),
            ..Default::default()
        }
    }

    /// Worth a `logoutId` on the logout page's URL.
    pub fn contains_payload(&self) -> bool {
        self.client_id.as_deref().is_some_and(|c| !c.is_empty())
            || !self.client_ids.is_empty()
            || self
                .saml_service_provider_entity_id
                .as_deref()
                .is_some_and(|e| !e.is_empty())
            || !self.saml_sessions.is_empty()
            || self.requires_confirmation
    }
}

/// The purpose logout messages are sealed for.
pub const LOGOUT_MESSAGE_PURPOSE: &str = "rustid.messages.logout";

/// The purpose end session callback contexts are sealed for.
pub const END_SESSION_CALLBACK_PURPOSE: &str = "rustid.messages.endsession";

/// `LogoutNotificationContext`: who is signing out of which clients, for
/// the end session callback's iframes and back-channel notifications.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogoutNotificationContext {
    pub subject_id: Option<String>,
    pub session_id: Option<String>,
    pub client_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub saml_sessions: Vec<crate::session::SamlSpSession>,
    /// The SP that started the logout: it gets a LogoutResponse instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saml_initiating_service_provider_entity_id: Option<String>,
    /// The logout id SP responses are tracked by.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saml_logout_id: Option<String>,
}

/// Whether any of the SAML SPs can be sent a front-channel LogoutRequest
///; the SAML IdP answers.
#[async_trait::async_trait]
pub trait SamlFrontChannel: Send + Sync {
    async fn any_front_channel(&self, entity_ids: &[String]) -> Result<bool, StoreError>;
}

async fn any_front_channel(
    clients: &dyn crate::stores::ClientStore,
    client_ids: &[String],
) -> Result<bool, StoreError> {
    for id in client_ids {
        if find_enabled_client(clients, id)
            .await?
            .is_some_and(|c| c.front_channel_logout_uri.is_some())
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The sign-out frame callback's context: the logout
/// message's clients and SAML sessions (with the current session's, when
/// it is the same subject's), else the current session's; `None` unless a
/// client has a front-channel logout URI or a SAML SP can be sent a
/// LogoutRequest. `logout_id` becomes the SAML logout id when there are
/// SAML sessions.
pub async fn sign_out_iframe_context(
    clients: &dyn crate::stores::ClientStore,
    saml: Option<&dyn SamlFrontChannel>,
    message: Option<&LogoutMessage>,
    logout_id: Option<&str>,
    session: Option<&UserSession>,
) -> Result<Option<LogoutNotificationContext>, StoreError> {
    let saml_front_channel = |sessions: &[crate::session::SamlSpSession]| {
        let ids: Vec<String> = sessions.iter().map(|s| s.entity_id.clone()).collect();
        async move {
            match saml {
                Some(saml) if !ids.is_empty() => saml.any_front_channel(&ids).await,
                _ => Ok(false),
            }
        }
    };
    if let Some(message) =
        message.filter(|m| !m.client_ids.is_empty() || !m.saml_sessions.is_empty())
    {
        let mut client_ids = message.client_ids.clone();
        let mut saml_sessions = message.saml_sessions.clone();
        if let Some(session) = session
            && message.subject_id.as_deref() == Some(session.subject_id.as_str())
        {
            for id in &session.client_ids {
                if !client_ids.contains(id) {
                    client_ids.push(id.clone());
                }
            }
            for s in &session.saml_sessions {
                if !saml_sessions.contains(s) {
                    saml_sessions.push(s.clone());
                }
            }
        }
        if !any_front_channel(clients, &client_ids).await?
            && !saml_front_channel(&saml_sessions).await?
        {
            return Ok(None);
        }
        let saml_logout_id = (!saml_sessions.is_empty())
            .then(|| logout_id.map(str::to_owned))
            .flatten();
        return Ok(Some(LogoutNotificationContext {
            subject_id: message.subject_id.clone(),
            session_id: message.session_id.clone(),
            client_ids,
            saml_sessions,
            saml_initiating_service_provider_entity_id: message
                .saml_service_provider_entity_id
                .clone(),
            saml_logout_id,
        }));
    }
    let Some(session) = session else {
        return Ok(None);
    };
    let clients_need =
        !session.client_ids.is_empty() && any_front_channel(clients, &session.client_ids).await?;
    let saml_need =
        !session.saml_sessions.is_empty() && saml_front_channel(&session.saml_sessions).await?;
    if !clients_need && !saml_need {
        return Ok(None);
    }
    Ok(Some(LogoutNotificationContext {
        subject_id: Some(session.subject_id.clone()),
        session_id: Some(session.session_id.clone()),
        client_ids: session.client_ids.clone(),
        saml_sessions: session.saml_sessions.clone(),
        saml_initiating_service_provider_entity_id: None,
        saml_logout_id: (!session.saml_sessions.is_empty())
            .then(|| logout_id.map(str::to_owned))
            .flatten(),
    }))
}

/// Each enabled client's
/// front-channel logout URI, with `sid` and `iss` when it asks for them.
pub async fn front_channel_urls(
    clients: &dyn crate::stores::ClientStore,
    context: &LogoutNotificationContext,
    issuer: &str,
) -> Result<Vec<String>, StoreError> {
    let mut urls = Vec::new();
    for id in &context.client_ids {
        let Some(client) = find_enabled_client(clients, id).await? else {
            continue;
        };
        let Some(uri) = &client.front_channel_logout_uri else {
            continue;
        };
        let mut url = uri.clone();
        if client.protocol_type == "oidc" && client.front_channel_logout_session_required {
            url = add_query_param(
                &url,
                "sid",
                context.session_id.as_deref().unwrap_or_default(),
            );
            url = add_query_param(&url, "iss", issuer);
        }
        urls.push(url);
    }
    Ok(urls)
}
