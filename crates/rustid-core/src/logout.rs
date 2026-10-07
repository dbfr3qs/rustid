//! Signing a user out:
//! Coordinated clients lose the session's tokens, and every client with a
//! back-channel logout URI gets a logout token
//! through the [`BackChannelSender`] seam.

use async_trait::async_trait;
use serde_json::Map;

use crate::access_tokens::ValidationContext;
use crate::grants::GrantFilter;
use crate::session::UserSession;
use crate::stores::{StoreError, find_enabled_client};
use crate::tokens::{AccessToken, CLAIM_VALUE_JSON, Claim, jwt_payload, new_jwt_id};

/// Five minutes.
pub const LOGOUT_TOKEN_LIFETIME_SECONDS: i64 = 300;

/// The back-channel logout token's event (OpenID Connect Back-Channel Logout 1.0).
pub const BACK_CHANNEL_LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";

/// Posts a logout token to a client's back-channel logout URI as the form
/// field `logout_token`. Failures are the sender's to log: a sign-out never
/// waits on or fails because of a client.
#[async_trait]
pub trait BackChannelSender: Send + Sync {
    async fn send(&self, uri: &str, logout_token: &str);
}

/// Sends nothing.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoBackChannelSender;

#[async_trait]
impl BackChannelSender for NoBackChannelSender {
    async fn send(&self, _: &str, _: &str) {}
}

/// One client to notify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackChannelRequest {
    pub client_id: String,
    pub logout_uri: String,
    pub subject_id: Option<String>,
    pub session_id: Option<String>,
    pub session_id_required: bool,
    /// `logout_reason`: `user_logout`, `session_expiration` or `terminated`.
    pub reason: &'static str,
}

/// The enabled clients among
/// `client_ids` with a back-channel logout URI.
pub async fn back_channel_requests(
    clients: &dyn crate::stores::ClientStore,
    client_ids: &[String],
    subject_id: Option<&str>,
    session_id: Option<&str>,
    reason: &'static str,
) -> Result<Vec<BackChannelRequest>, StoreError> {
    let mut out = Vec::new();
    for id in client_ids {
        let Some(client) = find_enabled_client(clients, id).await? else {
            continue;
        };
        let Some(uri) = client
            .back_channel_logout_uri
            .as_ref()
            .filter(|u| !u.trim().is_empty())
        else {
            continue;
        };
        out.push(BackChannelRequest {
            client_id: id.clone(),
            logout_uri: uri.clone(),
            subject_id: subject_id.map(str::to_owned),
            session_id: session_id.map(str::to_owned),
            session_id_required: client.back_channel_logout_session_required,
            reason,
        });
    }
    Ok(out)
}

/// The signed logout token, `typ`
/// `logout_token_jwt_type`, with the reason `user_logout`. `None` when the
/// request can't have one (no subject or session, or a required session
/// id missing), an unhandled failure.
pub async fn logout_token(
    ctx: &ValidationContext<'_>,
    request: &BackChannelRequest,
) -> Result<Option<String>, StoreError> {
    if (request.session_id_required && request.session_id.is_none())
        || (request.subject_id.is_none() && request.session_id.is_none())
    {
        return Ok(None);
    }
    let mut claims = vec![
        Claim::string("aud", &request.client_id),
        Claim::string("jti", &new_jwt_id()),
        Claim {
            claim_type: "events".into(),
            value: format!("{{\"{BACK_CHANNEL_LOGOUT_EVENT}\":{{}} }}"),
            value_type: CLAIM_VALUE_JSON.into(),
        },
    ];
    if let Some(sub) = &request.subject_id {
        // A pairwise client knows the user by its own subject.
        let client = find_enabled_client(ctx.stores.clients.as_ref(), &request.client_id).await?;
        let sub = match &client {
            Some(client) => crate::pairwise::subject_for(ctx.options, client, sub),
            None => sub.clone(),
        };
        claims.push(Claim::string("sub", &sub));
    }
    if let Some(sid) = &request.session_id {
        claims.push(Claim::string("sid", sid));
    }
    claims.push(Claim::string("logout_reason", request.reason));
    let token = AccessToken {
        issuer: ctx.issuer.to_owned(),
        client_id: request.client_id.clone(),
        lifetime: LOGOUT_TOKEN_LIFETIME_SECONDS,
        audiences: Vec::new(),
        claims,
        confirmation: None,
    };
    let payload: Map<String, serde_json::Value> =
        jwt_payload(ctx.options, &token, ctx.now.timestamp(), None)
            .map_err(|e| StoreError::Backend(e.to_string()))?;
    let Some(key) = ctx.keys.signing_key(&[]).await? else {
        return Err(StoreError::Backend("no signing key".into()));
    };
    crate::jwt::encode(
        &key,
        &[("typ", ctx.options.logout_token_jwt_type.as_str())],
        &payload,
    )
    .map(Some)
    .map_err(|e| StoreError::Backend(e.to_string()))
}

/// Whether a client's tokens live and die with the user's session.
pub fn coordinates(
    options: &crate::options::ProtocolOptions,
    client: &crate::clients::Client,
) -> bool {
    client.coordinate_lifetime_with_user_session.unwrap_or(
        options
            .authentication
            .coordinate_client_lifetimes_with_user_session,
    )
}

/// The clients among `client_ids` (enabled or not) that coordinate.
pub async fn coordinated_clients<'a>(
    ctx: &ValidationContext<'_>,
    client_ids: &'a [String],
) -> Result<Vec<&'a str>, StoreError> {
    let mut out = Vec::new();
    for id in client_ids {
        if let Some(client) = ctx.stores.clients.find_client_by_id(id).await?
            && coordinates(ctx.options, &client)
        {
            out.push(id.as_str());
        }
    }
    Ok(out)
}

/// Process logout for the session being signed out: its tokens for
/// coordinated clients (`coordinateLifetimeWithUserSession`, or the global
/// option unless the client opts out) are removed, then every client of the
/// session with a back-channel logout URI is sent a logout token, in
/// parallel.
pub async fn process_logout(
    ctx: &ValidationContext<'_>,
    session: &UserSession,
) -> Result<(), StoreError> {
    if session.client_ids.is_empty() {
        return Ok(());
    }
    for id in coordinated_clients(ctx, &session.client_ids).await? {
        for grant_type in crate::server_side_sessions::TOKEN_GRANT_TYPES {
            ctx.stores
                .grants
                .remove_all(&GrantFilter {
                    subject_id: Some(session.subject_id.clone()),
                    session_id: Some(session.session_id.clone()),
                    client_id: Some(id.to_owned()),
                    grant_type: Some((*grant_type).to_owned()),
                    ..Default::default()
                })
                .await?;
        }
    }
    let requests = back_channel_requests(
        ctx.stores.clients.as_ref(),
        &session.client_ids,
        Some(&session.subject_id),
        Some(&session.session_id),
        "user_logout",
    )
    .await?;
    send_logout_tokens(ctx, &requests).await
}

/// Tokens are made one at a time (key
/// loading), then posted together.
pub async fn send_logout_tokens(
    ctx: &ValidationContext<'_>,
    requests: &[BackChannelRequest],
) -> Result<(), StoreError> {
    let mut posts = Vec::new();
    for request in requests {
        match logout_token(ctx, request).await? {
            Some(token) => posts.push((request.logout_uri.as_str(), token)),
            None => tracing::warn!(
                client_id = %request.client_id,
                "no back-channel logout token: the client requires a session id"
            ),
        }
    }
    let sender = &ctx.stores.back_channel;
    futures::future::join_all(posts.iter().map(|(uri, token)| sender.send(uri, token))).await;
    Ok(())
}

/// The persisted grant type of a pending logout continuation.
pub const LOGOUT_CONTINUATION: &str = "logout_continuation";

/// A logout the UI completed, waiting for the browser: where to send it,
/// and the session it signs out (`None` for an anonymous browser), which
/// binds it to that browser.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LogoutContinuation {
    pub return_url: String,
    pub session_id: Option<String>,
}

impl LogoutContinuation {
    /// Stores the continuation for 5 minutes and returns its token.
    pub async fn store(
        &self,
        grants: &dyn crate::stores::PersistedGrantStore,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<String, StoreError> {
        use crate::grants::{PersistedGrant, hashed_key, new_handle};
        let token = new_handle();
        grants
            .store(PersistedGrant {
                key: hashed_key(&token, LOGOUT_CONTINUATION),
                grant_type: LOGOUT_CONTINUATION.to_owned(),
                client_id: String::new(),
                subject_id: None,
                session_id: self.session_id.clone(),
                description: None,
                creation_time: now,
                expiration: Some(
                    now + chrono::Duration::seconds(
                        crate::authorize::login::CONTINUATION_LIFETIME_SECONDS,
                    ),
                ),
                consumed_time: None,
                data: serde_json::to_string(self).expect("continuations serialize to JSON"),
            })
            .await?;
        Ok(token)
    }

    /// Takes the continuation: once only, and only while unexpired.
    pub async fn redeem(
        grants: &dyn crate::stores::PersistedGrantStore,
        token: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Option<LogoutContinuation>, StoreError> {
        let key = crate::grants::hashed_key(token, LOGOUT_CONTINUATION);
        let Some(grant) = grants.take(&key).await? else {
            return Ok(None);
        };
        if grant.grant_type != LOGOUT_CONTINUATION || grant.expiration.is_none_or(|e| e <= now) {
            return Ok(None);
        }
        Ok(serde_json::from_str(&grant.data).ok())
    }
}
