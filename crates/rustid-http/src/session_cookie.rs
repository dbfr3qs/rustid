//! The `idsrv` cookie in either mode: the whole session sealed into it, or,
//! with server-side sessions, only the key of its record in the store
//! (a cookie handler with a ticket store).

use axum::http::HeaderMap;
use chrono::{DateTime, Utc};
use rustid_core::issuer::current_issuer;
use rustid_core::server_side_sessions::{self, Loaded};
use rustid_core::session::{SESSION_COOKIE, UserSession};
use rustid_core::stores::StoreError;

use crate::ProtocolState;
use crate::cookies;
use crate::request::Route;

/// What the browser's `idsrv` cookie opened.
#[derive(Debug)]
pub(crate) enum Opened {
    None,
    Active(UserSession),
    /// A server-side session found expired, now deleted.
    Expired(UserSession),
}

/// Opens the browser's session. With server-side sessions only a key
/// cookie counts; its record decides.
pub(crate) async fn open(
    state: &ProtocolState,
    headers: &HeaderMap,
    now: DateTime<Utc>,
) -> Result<Opened, StoreError> {
    let Some(cookie) = cookies::get(headers, SESSION_COOKIE) else {
        return Ok(Opened::None);
    };
    let protector = &state.interaction.protector;
    let Some(sessions) = &state.stores.sessions else {
        return Ok(UserSession::open(protector, cookie, now).map_or(Opened::None, Opened::Active));
    };
    let Some(key) = server_side_sessions::open_key(protector, cookie) else {
        return Ok(Opened::None);
    };
    Ok(
        match server_side_sessions::load_session(
            sessions.store.as_ref(),
            &sessions.protector,
            &key,
            now,
        )
        .await?
        {
            Loaded::Missing => Opened::None,
            Loaded::Active(session) => Opened::Active(session),
            Loaded::Expired(session) => Opened::Expired(session),
        },
    )
}

/// Sign in for a new or changed session: stores it (server side) and
/// returns the `idsrv` cookie to set.
pub(crate) async fn write(
    state: &ProtocolState,
    route: &Route,
    session: &mut UserSession,
) -> Result<String, StoreError> {
    let protector = &state.interaction.protector;
    let value = match &state.stores.sessions {
        Some(sessions) => {
            let issuer = current_issuer(&state.options, &route.origin);
            let key = server_side_sessions::store_session(
                sessions.store.as_ref(),
                state.stores.grants.as_ref(),
                &sessions.protector,
                &state.options,
                session,
                &issuer,
            )
            .await?;
            server_side_sessions::seal_key(protector, &key)
        }
        None => session.seal(protector),
    };
    Ok(cookies::session_cookie(
        SESSION_COOKIE,
        &value,
        cookies::cookie_path(&route.origin.base_path),
        route.is_https(),
        session.persistent.then_some(session.expires),
    ))
}

/// The session's record goes.
pub(crate) async fn remove(state: &ProtocolState, session: &UserSession) -> Result<(), StoreError> {
    if let (Some(sessions), Some(key)) = (&state.stores.sessions, &session.key) {
        sessions.store.delete_session(key).await?;
    }
    Ok(())
}

/// `CheckForRefresh` with sliding expiration: renews the session when more
/// of its lifetime has passed than remains, or when token use flagged it
/// (`ForceCookieRenewalFlag`) and it hasn't expired. The span is kept:
/// Issued becomes now and the expiry now plus the span.
pub(crate) fn renew_if_due(
    state: &ProtocolState,
    session: &mut UserSession,
    now: DateTime<Utc>,
) -> bool {
    if !state.options.authentication.cookie_sliding_expiration
        || session.allow_refresh == Some(false)
    {
        return false;
    }
    let elapsed = now - session.issued;
    let remaining = session.expires - now;
    let forced = session.force_renewal && now < session.expires;
    if elapsed <= remaining && !forced {
        return false;
    }
    let span = session.expires - session.issued;
    session.issued = now;
    session.expires = now + span;
    session.force_renewal = false;
    true
}
