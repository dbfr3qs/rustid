//! Signing in through an upstream provider. The challenge binds a new
//! sign-in to the browser in the correlation cookie and sends it upstream;
//! the callback checks what comes back, redeems the code, and signs the
//! user in through a one-time continuation, which checks the interaction
//! binding and writes the session as a login page's sign-in does.

use axum::http::header::{CONTENT_TYPE, LOCATION};
use axum::http::{HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use rustid_core::authorize::context::{is_valid_return_url, validated_return_url};
use rustid_core::authorize::login::Continuation;
use rustid_core::authorize::validation::AuthorizeContext;
use rustid_core::consent::InteractionError;
use rustid_core::events::{Event, EventDetails, RequestInfo};
use rustid_core::federation::challenge::{
    CORRELATION_COOKIE, CORRELATION_LIFETIME_SECONDS, Correlation, SIGNOUT_COOKIE,
    SignoutCorrelation, authorization_url, end_session_url, store_signout_return,
    take_signout_return,
};
use rustid_core::federation::flow::Failure;
use rustid_core::federation::provider::Provider;
use rustid_core::federation::session::sign_in;
use rustid_core::issuer::current_issuer;
use rustid_core::params::{Params, url_encode};
use rustid_core::secrets::constant_time_eq;

use crate::ProtocolState;
use crate::authorize::html_encode;
use crate::interaction_api::{CONTINUE_PATH, is_saml_return_url, record_denial};
use crate::request::{Incoming, Route};

pub(crate) enum Leg {
    Challenge,
    Callback,
    SignoutCallback,
}

/// `/federation/{scheme}/challenge` or `/federation/{scheme}/callback`.
pub(crate) fn find(lower_path: &str) -> Option<(String, Leg)> {
    let rest = lower_path.strip_prefix("/federation/")?;
    let (scheme, leg) = rest.split_once('/')?;
    let leg = match leg {
        "challenge" => Leg::Challenge,
        "callback" => Leg::Callback,
        "signout-callback" => Leg::SignoutCallback,
        _ => return None,
    };
    (!scheme.is_empty()).then(|| (scheme.to_owned(), leg))
}

/// The challenge URL for a provider and a return URL, absolute under the
/// request's base URL.
pub(crate) fn challenge_url(route: &Route, scheme: &str, return_url: &str) -> String {
    format!(
        "{}/federation/{scheme}/challenge?returnUrl={}",
        route.origin.base_url(),
        url_encode(return_url)
    )
}

pub(crate) async fn handle(
    state: &ProtocolState,
    incoming: &Incoming<'_>,
    scheme: &str,
    leg: Leg,
) -> Response {
    if incoming.method != Method::GET {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    if let Leg::SignoutCallback = leg {
        return signout_callback(state, incoming, scheme).await;
    }
    let Some(provider) = state.stores.federation.providers.find(scheme) else {
        return page(StatusCode::NOT_FOUND, "There is no such sign-in provider.");
    };
    match leg {
        Leg::Challenge => challenge(state, incoming, provider).await,
        Leg::Callback => callback(state, incoming, provider).await,
        Leg::SignoutCallback => unreachable!("answered above"),
    }
}

fn cookie_path(route: &Route, scheme: &str) -> String {
    format!(
        "{}/federation/{scheme}/",
        route.origin.base_path.trim_end_matches('/')
    )
}

fn found(location: &str) -> Response {
    match HeaderValue::from_str(location) {
        Ok(value) => (StatusCode::FOUND, [(LOCATION, value)]).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

fn page(status: StatusCode, message: &str) -> Response {
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Sign-in</title></head>\
         <body><h1>Sign-in</h1><p>{}</p></body></html>",
        html_encode(message)
    );
    (status, [(CONTENT_TYPE, "text/html; charset=utf-8")], html).into_response()
}

/// The local form of a return URL: as given, or without the request's
/// origin when a UI on another origin received it absolute.
fn local_return_url<'a>(route: &Route, return_url: &'a str) -> &'a str {
    return_url
        .strip_prefix(&route.origin.origin())
        .filter(|rest| rest.starts_with('/'))
        .unwrap_or(return_url)
}

fn authorize_ctx<'a>(
    state: &'a ProtocolState,
    info: &'a RequestInfo,
    issuer: &'a str,
) -> AuthorizeContext<'a> {
    AuthorizeContext {
        options: &state.options,
        issuer,
        stores: &state.stores,
        events: &state.events,
        request: info,
        now: chrono::Utc::now(),
    }
}

struct Refusal<'a> {
    provider: &'a Provider,
    client_id: Option<String>,
}

impl Refusal<'_> {
    /// Records the failure: an event and a log line.
    fn record(
        &self,
        state: &ProtocolState,
        info: &RequestInfo,
        reason: &str,
        detail: Option<String>,
    ) {
        let scheme = &self.provider.config.scheme;
        tracing::warn!(%scheme, reason, detail = detail.as_deref().unwrap_or(""), "upstream sign-in failed");
        state.events.raise(
            info,
            chrono::Utc::now(),
            Event::user_login_failure(EventDetails::UserLoginFailure {
                provider: scheme.clone(),
                reason: reason.to_owned(),
                detail,
                client_id: self.client_id.clone(),
            }),
        );
    }

    /// Records the failure and answers the error page. The detail goes to
    /// the event and the log, never to the browser.
    fn answer(
        &self,
        state: &ProtocolState,
        info: &RequestInfo,
        status: StatusCode,
        reason: &str,
        detail: Option<String>,
    ) -> Response {
        self.record(state, info, reason, detail);
        let message = if matches!(reason, "expired" | "state_mismatch") {
            "Your sign-in expired. Start again from the application.".to_owned()
        } else {
            format!(
                "Sign-in with {} failed. Start again from the application.",
                self.provider.config.display_name
            )
        };
        page(status, &message)
    }

    fn failure(&self, state: &ProtocolState, info: &RequestInfo, failure: &Failure) -> Response {
        self.answer(
            state,
            info,
            StatusCode::BAD_GATEWAY,
            failure.reason(),
            Some(failure.detail()),
        )
    }
}

async fn challenge(
    state: &ProtocolState,
    incoming: &Incoming<'_>,
    provider: &Provider,
) -> Response {
    let Incoming { route, info, .. } = *incoming;
    let params = Params::parse_query(&route.query);
    let Some(return_url) = params.get("returnUrl") else {
        return page(
            StatusCode::BAD_REQUEST,
            "There is no sign-in request to complete.",
        );
    };
    let local = local_return_url(route, &return_url);
    let issuer = current_issuer(&state.options, &route.origin);
    let mut forward: Vec<(&str, String)> = Vec::new();
    let mut client_id = None;
    let mut max_age = None;
    if !is_saml_return_url(state, local) {
        if !is_valid_return_url(local) {
            return page(
                StatusCode::BAD_REQUEST,
                "There is no sign-in request to complete.",
            );
        }
        let ctx = authorize_ctx(state, info, &issuer);
        let request = match validated_return_url(&ctx, local, None).await {
            Ok(Some(request)) => request,
            Ok(None) => {
                return page(
                    StatusCode::BAD_REQUEST,
                    "There is no sign-in request to complete.",
                );
            }
            Err(e) => {
                return crate::response::internal_error(
                    state,
                    info,
                    "FederationChallenge",
                    &e.to_string(),
                );
            }
        };
        let client = request
            .client
            .as_ref()
            .expect("validated request has a client");
        if !state
            .stores
            .federation
            .providers
            .allowed_for(client)
            .iter()
            .any(|p| p.config.scheme == provider.config.scheme)
        {
            return page(
                StatusCode::BAD_REQUEST,
                "This application can't sign in with that provider.",
            );
        }
        client_id = Some(client.client_id.clone());
        if let Some(hint) = &request.login_hint {
            forward.push(("login_hint", hint.clone()));
        }
        // The authorize endpoint has already marked `prompt=login` and
        // `max_age` as processed by the time the browser gets here; the
        // provider still has to honour them.
        if request.original_prompt_modes.iter().any(|p| p == "login") {
            forward.push(("prompt", "login".to_owned()));
        }
        let requested = request.max_age.map(i64::from).or_else(|| {
            request
                .raw
                .get(rustid_core::authorize::PROCESSED_MAX_AGE)
                .and_then(|m| m.parse::<i64>().ok())
        });
        // A client's SSO lifetime is a max_age too: a staler upstream
        // session would send the browser straight back upstream.
        max_age = match (requested, client.user_sso_lifetime.map(i64::from)) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        if let Some(max_age) = max_age {
            forward.push(("max_age", max_age.to_string()));
        }
    }
    let refusal = Refusal {
        provider,
        client_id: client_id.clone(),
    };
    let now = chrono::Utc::now().timestamp();
    let metadata = match state.stores.federation.metadata(provider, now).await {
        Ok(metadata) => metadata,
        Err(failure) => return refusal.failure(state, info, &failure),
    };
    let mut correlation = Correlation::new(&provider.config.scheme, &return_url, now);
    correlation.client_id = client_id;
    correlation.max_age = max_age;
    let redirect_uri = format!("{issuer}/federation/{}/callback", provider.config.scheme);
    let location = authorization_url(
        &provider.config,
        &metadata,
        &redirect_uri,
        &correlation,
        &forward,
    );
    let mut response = found(&location);
    let mut cookie = format!(
        "{CORRELATION_COOKIE}={}; path={}; max-age={CORRELATION_LIFETIME_SECONDS}",
        correlation.seal(&state.interaction.protector),
        cookie_path(route, &provider.config.scheme)
    );
    if route.is_https() {
        cookie.push_str("; secure");
    }
    cookie.push_str("; samesite=lax; httponly");
    crate::cookies::append(&mut response, &cookie);
    response
}

async fn callback(state: &ProtocolState, incoming: &Incoming<'_>, provider: &Provider) -> Response {
    let mut response = callback_answer(state, incoming, provider).await;
    // A callback can be answered once: the correlation goes whatever the
    // outcome.
    let route = incoming.route;
    let mut deleted = format!(
        "{CORRELATION_COOKIE}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path={}; max-age=0",
        cookie_path(route, &provider.config.scheme)
    );
    if route.is_https() {
        deleted.push_str("; secure");
    }
    deleted.push_str("; samesite=lax; httponly");
    crate::cookies::append(&mut response, &deleted);
    response
}

async fn callback_answer(
    state: &ProtocolState,
    incoming: &Incoming<'_>,
    provider: &Provider,
) -> Response {
    let Incoming {
        route,
        headers,
        info,
        ..
    } = *incoming;
    let federation = &state.stores.federation;
    let now = chrono::Utc::now().timestamp();
    let params = Params::parse_query(&route.query);
    let correlation = crate::cookies::get(headers, CORRELATION_COOKIE)
        .and_then(|cookie| Correlation::open(&state.interaction.protector, cookie, now))
        .filter(|c| c.scheme == provider.config.scheme);
    let Some(correlation) = correlation else {
        let refusal = Refusal {
            provider,
            client_id: None,
        };
        return refusal.answer(state, info, StatusCode::BAD_REQUEST, "expired", None);
    };
    let refusal = Refusal {
        provider,
        client_id: correlation.client_id.clone(),
    };
    let state_matches = params
        .get("state")
        .is_some_and(|s| constant_time_eq(s.as_bytes(), correlation.state.as_bytes()));
    if !state_matches {
        return refusal.answer(state, info, StatusCode::BAD_REQUEST, "state_mismatch", None);
    }
    let metadata = match federation.metadata(provider, now).await {
        Ok(metadata) => metadata,
        Err(failure) => return refusal.failure(state, info, &failure),
    };
    let iss = params.get("iss");
    if (metadata.authorization_response_iss_parameter_supported || iss.is_some())
        && iss.as_deref() != Some(provider.config.authority.as_str())
    {
        return refusal.answer(state, info, StatusCode::BAD_REQUEST, "issuer_mismatch", iss);
    }
    let local = local_return_url(route, &correlation.return_url).to_owned();
    if let Some(error) = params.get("error") {
        if error == "access_denied" {
            refusal.record(state, info, "access_denied", None);
            return match record_denial(
                state,
                route,
                info,
                &local,
                InteractionError::AccessDenied,
                None,
            )
            .await
            {
                Ok(redirect_url) => found(&redirect_url),
                Err(response) => *response,
            };
        }
        return refusal.answer(
            state,
            info,
            StatusCode::BAD_GATEWAY,
            "upstream_error",
            Some(format!("the provider answered {error}")),
        );
    }
    let Some(code) = params.get("code") else {
        return refusal.answer(
            state,
            info,
            StatusCode::BAD_GATEWAY,
            "upstream_error",
            Some("the provider answered without a code".into()),
        );
    };
    let issuer = current_issuer(&state.options, &route.origin);
    let redirect_uri = format!("{issuer}/federation/{}/callback", provider.config.scheme);
    let skew = state.options.jwt_validation_clock_skew.0;
    let token = match federation
        .redeem(provider, &code, &redirect_uri, &correlation, skew, now)
        .await
    {
        Ok(token) => token,
        Err(failure) => return refusal.failure(state, info, &failure),
    };
    // With a max_age sent, the provider's auth_time is required (OIDC Core
    // 3.1.2.1) and must be recent enough.
    if let Some(max_age) = correlation.max_age {
        let fresh = token
            .payload
            .get("auth_time")
            .and_then(serde_json::Value::as_i64)
            .is_some_and(|t| now - t <= max_age + skew);
        if !fresh {
            return refusal.answer(
                state,
                info,
                StatusCode::BAD_GATEWAY,
                "stale_authentication",
                Some(format!(
                    "the provider's auth_time is missing or older than max_age {max_age}"
                )),
            );
        }
    }
    let mut sign_in = sign_in(&provider.config, &token, now);
    // The id token is the hint for signing out there; it is kept only in
    // server-side sessions, since it would outgrow a session cookie.
    if provider.config.sign_out && state.stores.sessions.is_some() {
        sign_in.upstream_id_token = Some(token.raw.clone());
    }
    let subject_id = sign_in.subject_id.clone();
    let continuation = Continuation::new(&correlation.return_url, sign_in);
    let handle = match continuation
        .store(state.stores.grants.as_ref(), chrono::Utc::now())
        .await
    {
        Ok(handle) => handle,
        Err(e) => {
            return crate::response::internal_error(
                state,
                info,
                "FederationCallback",
                &e.to_string(),
            );
        }
    };
    state.events.raise(
        info,
        chrono::Utc::now(),
        Event::user_login_success(EventDetails::UserLoginSuccess {
            provider: provider.config.scheme.clone(),
            provider_user_id: token.subject.clone(),
            subject_id,
            client_id: correlation.client_id.clone(),
        }),
    );
    found(&format!(
        "{}{CONTINUE_PATH}?token={}",
        route.origin.base_url(),
        url_encode(&handle)
    ))
}

fn signout_cookie(route: &Route, scheme: &str, value: Option<&str>) -> String {
    let mut cookie = match value {
        Some(value) => format!(
            "{SIGNOUT_COOKIE}={value}; path={}; max-age={CORRELATION_LIFETIME_SECONDS}",
            cookie_path(route, scheme)
        ),
        None => format!(
            "{SIGNOUT_COOKIE}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path={}; max-age=0",
            cookie_path(route, scheme)
        ),
    };
    if route.is_https() {
        cookie.push_str("; secure");
    }
    cookie.push_str("; samesite=lax; httponly");
    cookie
}

/// After rustid has signed `session` out: when it came from a provider
/// with sign-out enabled, the redirect that signs the browser out there
/// too (RP-Initiated Logout), coming back to `return_url` afterwards.
/// `None` when there is nothing to do upstream, or the provider can't be
/// reached; local sign-out stands either way.
pub(crate) async fn upstream_sign_out(
    state: &ProtocolState,
    route: &Route,
    session: &rustid_core::session::UserSession,
    return_url: &str,
) -> Option<Response> {
    let federation = &state.stores.federation;
    let provider = federation
        .providers
        .find(&session.idp)
        .filter(|p| p.config.sign_out)?;
    let scheme = &provider.config.scheme;
    let now = chrono::Utc::now().timestamp();
    let metadata = match federation.metadata(provider, now).await {
        Ok(metadata) => metadata,
        Err(failure) => {
            tracing::warn!(%scheme, detail = %failure.detail(), "signing out upstream skipped: the provider can't be reached");
            return None;
        }
    };
    let handle = match store_signout_return(
        state.stores.grants.as_ref(),
        return_url,
        chrono::Utc::now(),
    )
    .await
    {
        Ok(handle) => handle,
        Err(error) => {
            tracing::warn!(%scheme, %error, "signing out upstream skipped: the return URL couldn't be kept");
            return None;
        }
    };
    let correlation = SignoutCorrelation::new(scheme, &handle, now);
    let issuer = current_issuer(&state.options, &route.origin);
    let location = end_session_url(
        &provider.config,
        &metadata,
        session.upstream_id_token.as_deref(),
        &format!("{issuer}/federation/{scheme}/signout-callback"),
        &correlation.state,
    )?;
    let mut response = found(&location);
    crate::cookies::append(
        &mut response,
        &signout_cookie(
            route,
            scheme,
            Some(&correlation.seal(&state.interaction.protector)),
        ),
    );
    Some(response)
}

/// `GET /federation/{scheme}/signout-callback?state=…`: back from signing
/// out upstream, on to where the sign-out was going. A missing or wrong
/// state shows the signed-out page; it never redirects to a URL from the
/// query.
async fn signout_callback(
    state: &ProtocolState,
    incoming: &Incoming<'_>,
    scheme: &str,
) -> Response {
    let Incoming { route, headers, .. } = *incoming;
    let now = chrono::Utc::now().timestamp();
    let params = Params::parse_query(&route.query);
    let correlation = crate::cookies::get(headers, SIGNOUT_COOKIE)
        .and_then(|cookie| SignoutCorrelation::open(&state.interaction.protector, cookie, now))
        .filter(|c| c.scheme == scheme)
        .filter(|c| {
            params
                .get("state")
                .is_some_and(|s| constant_time_eq(s.as_bytes(), c.state.as_bytes()))
        });
    let return_url = match correlation {
        Some(c) => take_signout_return(state.stores.grants.as_ref(), &c.handle, chrono::Utc::now())
            .await
            .ok()
            .flatten(),
        None => None,
    };
    let mut response = match return_url {
        Some(url) => found(&url),
        None => page(StatusCode::OK, "You are signed out."),
    };
    crate::cookies::append(&mut response, &signout_cookie(route, scheme, None));
    response
}
