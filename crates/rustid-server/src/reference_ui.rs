//! The reference UI (`reference_ui.enabled`): login, consent, logout,
//! device and CIBA pages at the default paths, each completing its
//! interaction immediately (or, in interactive mode, through a form). Every page is a client of the interaction API, which it calls
//! through the server's protocol router with an API key of its own, so the
//! API is exercised end to end. Never enable it for real users.

use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use axum::Router;
use axum::body::Body;
use axum::extract::{Query, Request, State};
use axum::http::StatusCode;
use axum::http::header::{
    AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, COOKIE, HOST, LOCATION, PRAGMA, SET_COOKIE,
};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use rustid_core::params::{Params, url_encode};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::html;

/// JSON, as the scripted UI answers.
const JSON: &str = "application/json; charset=utf-8";

/// A user in the fixture format (`fixtures/users.json`).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub subject_id: String,
    pub username: String,
    /// Checked by the interactive login page.
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub claims: Vec<UserClaim>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UserClaim {
    #[serde(rename = "type")]
    pub claim_type: String,
    pub value: String,
    /// A claim value type (`json`, a boolean or integer XML Schema type);
    /// a string when absent.
    #[serde(default, rename = "valueType")]
    pub value_type: Option<String>,
}

/// Reads a users file.
pub fn load_users(path: &Path) -> anyhow::Result<Vec<User>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

/// The reference UI: its own interaction API key, generated at startup, and
/// the users its login page signs in.
#[derive(Clone)]
pub struct ReferenceUi {
    api_key: String,
    path_base: Option<String>,
    users: Vec<User>,
    default_user: String,
    interactive: bool,
    /// Server-side sessions, for the test-only session endpoints.
    sessions: Option<Arc<rustid_core::server_side_sessions::ServerSideSessions>>,
    /// The configuration admin edits, for the test-only SAML endpoints.
    configuration: Option<Arc<dyn rustid_core::stores::ConfigurationStore>>,
}

impl ReferenceUi {
    pub fn new(
        api_key: String,
        path_base: Option<String>,
        users: Vec<User>,
        default_user: String,
        interactive: bool,
    ) -> Self {
        ReferenceUi {
            api_key,
            path_base,
            users,
            default_user,
            interactive,
            sessions: None,
            configuration: None,
        }
    }

    /// The configuration the test-only SAML endpoints change through the
    /// SAML service provider admin.
    pub fn with_configuration(
        mut self,
        configuration: Arc<dyn rustid_core::stores::ConfigurationStore>,
    ) -> Self {
        self.configuration = Some(configuration);
        self
    }

    /// The server's server-side sessions, which the test-only session
    /// endpoints expire and corrupt directly.
    pub fn with_sessions(
        mut self,
        sessions: Option<Arc<rustid_core::server_side_sessions::ServerSideSessions>>,
    ) -> Self {
        self.sessions = sessions;
        self
    }

    /// The pages, at the root and under the path base; the login page also
    /// at the capitalised path the default login URL names.
    /// `protocol` is the server's protocol router, which serves the
    /// interaction API.
    pub fn routes(self, protocol: Router) -> Router {
        let base = self.path_base.clone().unwrap_or_default();
        let ui = Arc::new(Page {
            api_base: format!("{base}/interaction"),
            protocol,
            ui: self,
        });
        let mut router = Router::new();
        let prefixes: Vec<String> = if base.is_empty() {
            vec![String::new()]
        } else {
            vec![String::new(), base]
        };
        for prefix in prefixes {
            router = router
                .route(&format!("{prefix}/home/error"), get(error))
                .route(
                    &format!("{prefix}/account/login"),
                    get(login).post(login_submit),
                )
                .route(
                    &format!("{prefix}/Account/Login"),
                    get(login).post(login_submit),
                )
                .route(
                    &format!("{prefix}/consent"),
                    get(consent_page).post(consent_submit),
                )
                .route(
                    &format!("{prefix}/account/consent"),
                    get(consent_page).post(consent_submit),
                )
                .route(
                    &format!("{prefix}/account/logout"),
                    get(logout).post(logout_submit),
                )
                .route(
                    &format!("{prefix}/Account/Logout"),
                    get(logout).post(logout_submit),
                )
                .route(
                    &format!("{prefix}/device"),
                    get(device_page).post(device_submit),
                )
                .route(&format!("{prefix}/ciba"), get(ciba_page).post(ciba_submit))
                .route(
                    &format!("{prefix}/account/login/context"),
                    get(login_context),
                )
                .route(
                    &format!("{prefix}/Account/Login/context"),
                    get(login_context),
                );
        }
        if ui.ui.interactive {
            let mut prefixes = vec![String::new()];
            if let Some(base) = ui.ui.path_base.clone() {
                prefixes.push(base);
            }
            for prefix in prefixes {
                router = router.route(
                    &format!("{prefix}/sessions"),
                    get(sessions_page).post(end_session_row),
                );
            }
        }
        if !ui.ui.interactive {
            let base = ui.ui.path_base.clone().unwrap_or_default();
            router = router
                .route(&format!("{base}/test/sessions"), get(test_sessions))
                .route(
                    &format!("{base}/test/sessions/remove"),
                    get(test_remove_sessions),
                )
                .route(
                    &format!("{base}/test/sessions/expire"),
                    get(test_expire_sessions),
                )
                .route(
                    &format!("{base}/test/sessions/corrupt"),
                    get(test_corrupt_sessions),
                )
                .route(
                    &format!("{base}/test/saml/service-providers/disable"),
                    get(test_disable_service_provider),
                )
                .route(
                    &format!("{base}/test/saml/service-providers/remove"),
                    get(test_remove_service_provider),
                )
                .route(
                    &format!("{base}/test/saml/idp-initiated"),
                    get(test_idp_initiated),
                );
        }
        router.with_state(ui)
    }
}

struct Page {
    ui: ReferenceUi,
    /// The interaction API's path, under the path base.
    api_base: String,
    protocol: Router,
}

/// Who the API sees: the browser's host and scheme, so the URLs it returns
/// are the ones the browser uses.
struct Caller {
    host: Option<String>,
    https: bool,
    /// The browser's cookies, so `GET /interaction/session` sees its session.
    cookie: Option<String>,
}

impl Caller {
    fn of(request: &Request) -> Caller {
        Caller {
            host: request
                .headers()
                .get(HOST)
                .and_then(|h| h.to_str().ok())
                .map(str::to_owned),
            https: request.extensions().get::<rustid_http::Https>().is_some(),
            cookie: request
                .headers()
                .get(COOKIE)
                .and_then(|h| h.to_str().ok())
                .map(str::to_owned),
        }
    }
}

impl Page {
    /// Calls the API through the protocol router; the answer's body is
    /// JSON, or `null` when it has none.
    async fn api(
        &self,
        method: axum::http::Method,
        path_and_query: &str,
        caller: &Caller,
        body: Option<Value>,
    ) -> Result<(StatusCode, Value), String> {
        let mut request = axum::http::Request::builder()
            .method(method)
            .uri(format!("{}{path_and_query}", self.api_base))
            .header(AUTHORIZATION, format!("Bearer {}", self.ui.api_key));
        if let Some(host) = &caller.host {
            request = request.header(HOST, host);
        }
        if caller.https {
            request = request.extension(rustid_http::Https);
        }
        if let Some(cookie) = &caller.cookie {
            request = request.header(COOKIE, cookie);
        }
        let body = match body {
            Some(json) => {
                request = request.header(CONTENT_TYPE, "application/json");
                Body::from(json.to_string())
            }
            None => Body::empty(),
        };
        let request = request.body(body).map_err(|e| e.to_string())?;
        let response = tower::ServiceExt::oneshot(self.protocol.clone(), request)
            .await
            .map_err(|e| e.to_string())?;
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .map_err(|e| e.to_string())?;
        Ok((
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        ))
    }
}

impl Page {
    /// Visits a server URL as the browser would, with its cookies, through
    /// the protocol router: how the UI redeems a logout continuation itself.
    async fn visit(&self, url: &str, caller: &Caller) -> Result<Response, String> {
        let path = match url.find("://") {
            Some(i) => {
                let rest = &url[i + 3..];
                &rest[rest.find('/').unwrap_or(rest.len())..]
            }
            None => url,
        };
        let mut request = axum::http::Request::builder().uri(path);
        if let Some(host) = &caller.host {
            request = request.header(HOST, host);
        }
        if caller.https {
            request = request.extension(rustid_http::Https);
        }
        if let Some(cookie) = &caller.cookie {
            request = request.header(COOKIE, cookie);
        }
        let request = request.body(Body::empty()).map_err(|e| e.to_string())?;
        tower::ServiceExt::oneshot(self.protocol.clone(), request)
            .await
            .map_err(|e| e.to_string())
    }
}

/// A form POST from another site (a forged request riding the session
/// cookie, which is `SameSite=None`): the browser says so in
/// `Sec-Fetch-Site`, or its `Origin` isn't this page's.
fn cross_site(request: &Request) -> bool {
    let headers = request.headers();
    if headers
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("cross-site"))
    {
        return true;
    }
    let Some(origin) = headers.get("origin").and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let scheme = if request.extensions().get::<rustid_http::Https>().is_some() {
        "https"
    } else {
        "http"
    };
    let own = headers
        .get(HOST)
        .and_then(|h| h.to_str().ok())
        .map(|host| format!("{scheme}://{host}"));
    !own.is_some_and(|own| own.eq_ignore_ascii_case(origin))
}

fn forbidden() -> Response {
    StatusCode::FORBIDDEN.into_response()
}

fn json_response(status: StatusCode, body: Value) -> Response {
    (status, [(CONTENT_TYPE, JSON)], body.to_string()).into_response()
}

fn api_failure(what: &str, detail: &dyn std::fmt::Display) -> Response {
    tracing::error!(%detail, "interaction API {what} call failed");
    StatusCode::BAD_GATEWAY.into_response()
}

/// `/home/error?errorId=…`: the error context, as the scripted UI shows it
/// (as a page in interactive mode).
async fn error(State(page): State<Arc<Page>>, request: Request) -> Response {
    let params = Params::parse_query(request.uri().query().unwrap_or_default());
    let interactive = page.ui.interactive;
    let not_found = || {
        if interactive {
            return html::page(
                StatusCode::NOT_FOUND,
                "Error",
                "<h1>Something went wrong</h1><p>The error has expired or never existed.</p>",
            );
        }
        json_response(
            StatusCode::NOT_FOUND,
            json!({ "error": "unknown_error_id" }),
        )
    };
    let Some(id) = params.get("errorId") else {
        return not_found();
    };
    let path = format!("/error?errorId={}", url_encode(&id));
    match page
        .api(axum::http::Method::GET, &path, &Caller::of(&request), None)
        .await
    {
        Ok((StatusCode::OK, e)) if interactive => {
            let field = |name: &str| html::escape(e[name].as_str().unwrap_or("-"));
            html::page(
                StatusCode::OK,
                "Error",
                &format!(
                    "<h1>The request could not be completed</h1>\
                     <p class=\"error\"><code>{}</code></p><p>{}</p>\
                     <p class=\"note\">Client: <code>{}</code><br>Request id: <code>{}</code></p>",
                    field("error"),
                    field("errorDescription"),
                    field("clientId"),
                    field("requestId"),
                ),
            )
        }
        Ok((StatusCode::OK, e)) => json_response(
            StatusCode::OK,
            json!({
                "error": e["error"],
                "errorDescription": e["errorDescription"],
                "clientId": e["clientId"],
                "requestId": e["requestId"],
                "displayMode": e["displayMode"],
                "uiLocales": e["uiLocales"],
                "redirectUri": e["redirectUri"],
                "responseMode": e["responseMode"],
            }),
        ),
        Ok((StatusCode::NOT_FOUND, _)) => not_found(),
        Ok((status, _)) => api_failure("error", &status),
        Err(e) => api_failure("error", &e),
    }
}

/// `/account/login?ReturnUrl=…&user=…`: signs the user in (the profile's
/// default user when none is named) and sends the browser on; an invalid
/// return URL sends it to `/`. In interactive mode
/// the page asks for a username and password instead.
async fn login(State(page): State<Arc<Page>>, request: Request) -> Response {
    let params = Params::parse_query(request.uri().query().unwrap_or_default());
    let return_url = params.get("returnUrl").unwrap_or_default();
    let caller = Caller::of(&request);
    if page.ui.interactive {
        // Only a password signs anyone in here; `user` just fills the form.
        let user = params.get("user").unwrap_or_default();
        return login_form(&page, &caller, &return_url, &user, None).await;
    }
    let username = params
        .get("user")
        .unwrap_or_else(|| page.ui.default_user.clone());
    let Some(user) = page.ui.users.iter().find(|u| u.username == username) else {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({ "error": "unknown_user", "user": username }),
        );
    };
    let flag = |name: &str| params.get(name).map(|v| v.eq_ignore_ascii_case("true"));
    let remember = Remember {
        persistent: flag("remember").unwrap_or(false),
        allow_refresh: flag("allow_refresh"),
    };
    sign_in(&page, &caller, &return_url, user, remember).await
}

/// The interactive login form's fields.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoginForm {
    return_url: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    /// `cancel` denies the request instead of signing in.
    #[serde(default)]
    button: Option<String>,
    /// The "Remember me" box: a persistent cookie.
    #[serde(default)]
    remember: Option<String>,
}

/// `POST /account/login` (interactive mode): checks the password against
/// the users file and signs the user in, or shows the form again.
async fn login_submit(State(page): State<Arc<Page>>, request: Request) -> Response {
    if cross_site(&request) {
        return forbidden();
    }
    if !page.ui.interactive {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let caller = Caller::of(&request);
    let Ok(axum::Form(form)) =
        <axum::Form<LoginForm> as axum::extract::FromRequest<()>>::from_request(request, &()).await
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if form.button.as_deref() == Some("cancel") {
        let body = json!({ "returnUrl": form.return_url });
        return match page
            .api(axum::http::Method::POST, "/deny", &caller, Some(body))
            .await
        {
            Ok((StatusCode::OK, _)) => redirect(&form.return_url),
            Ok((StatusCode::BAD_REQUEST, _)) => redirect("/"),
            Ok((status, _)) => api_failure("deny", &status),
            Err(e) => api_failure("deny", &e),
        };
    }
    let user = page.ui.users.iter().find(|u| {
        u.username == form.username && u.password.as_deref() == Some(form.password.as_str())
    });
    match user {
        Some(user) => {
            let remember = Remember {
                persistent: form.remember.is_some(),
                allow_refresh: None,
            };
            sign_in(&page, &caller, &form.return_url, user, remember).await
        }
        None => {
            login_form(
                &page,
                &caller,
                &form.return_url,
                &form.username,
                Some("Invalid username or password."),
            )
            .await
        }
    }
}

/// The login form for the request the return URL continues, naming its
/// client and scopes.
async fn login_form(
    page: &Page,
    caller: &Caller,
    return_url: &str,
    username: &str,
    error: Option<&str>,
) -> Response {
    let path = format!("/login?returnUrl={}", url_encode(return_url));
    let context = match page.api(axum::http::Method::GET, &path, caller, None).await {
        Ok((StatusCode::OK, context)) => context,
        Ok((StatusCode::NOT_FOUND | StatusCode::BAD_REQUEST, _)) => {
            return html::page(
                StatusCode::BAD_REQUEST,
                "Sign in",
                "<h1>Sign in</h1><p>There is no sign-in request to complete. \
                 Start again from the application.</p>",
            );
        }
        Ok((status, _)) => return api_failure("login context", &status),
        Err(e) => return api_failure("login context", &e),
    };
    let client = context["clientName"]
        .as_str()
        .or(context["clientId"].as_str())
        .unwrap_or_default();
    let scopes: Vec<&str> = context["scopes"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let username = if username.is_empty() {
        context["loginHint"].as_str().unwrap_or_default()
    } else {
        username
    };
    let users: Vec<String> = page
        .ui
        .users
        .iter()
        .filter(|u| u.password.is_some())
        .map(|u| format!("<code>{}</code>", html::escape(&u.username)))
        .collect();
    let error = error
        .map(|e| format!("<p class=\"error\">{}</p>", html::escape(e)))
        .unwrap_or_default();
    // A button per upstream provider the client may sign in through.
    let providers: String = context["identityProviders"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|p| {
                    format!(
                        "<p><a class=\"button\" href=\"{}\">Sign in with {}</a></p>",
                        html::escape(p["challengeUrl"].as_str().unwrap_or_default()),
                        html::escape(p["displayName"].as_str().unwrap_or_default()),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    if context["enableLocalLogin"] == Value::Bool(false) {
        return html::page(
            StatusCode::OK,
            "Sign in",
            &format!(
                "<h1>Sign in</h1><p><strong>{client}</strong> asks for <code>{scopes}</code>.</p>{error}{providers}",
                client = html::escape(client),
                scopes = html::escape(&scopes.join(" ")),
            ),
        );
    }
    html::page(
        StatusCode::OK,
        "Sign in",
        &format!(
            "<h1>Sign in</h1><p><strong>{client}</strong> asks for <code>{scopes}</code>.</p>{error}{providers}\
             <form method=\"post\" autocomplete=\"off\">\
             <input type=\"hidden\" name=\"returnUrl\" value=\"{return_url}\">\
             <label for=\"username\">Username</label>\
             <input id=\"username\" name=\"username\" value=\"{username}\" required autofocus>\
             <label for=\"password\">Password</label>\
             <input id=\"password\" name=\"password\" type=\"password\" required>\
             <label class=\"scope\"><input type=\"checkbox\" name=\"remember\" value=\"yes\">\
             Remember me</label>\
             <button type=\"submit\" name=\"button\" value=\"login\">Sign in</button>\
             <button type=\"submit\" name=\"button\" value=\"cancel\" class=\"secondary\" \
             formnovalidate>Cancel</button></form>\
             <p class=\"note\">Test users: {users} (the password is the username).</p>",
            client = html::escape(client),
            scopes = html::escape(&scopes.join(" ")),
            return_url = html::escape(return_url),
            username = html::escape(username),
            users = users.join(", "),
        ),
    )
}

/// Signs `user` in for the return URL through the interaction API and sends
/// the browser to the continuation.
/// How long the sign-in lasts: a persistent cookie, and whether it slides.
#[derive(Debug, Clone, Copy, Default)]
struct Remember {
    persistent: bool,
    allow_refresh: Option<bool>,
}

async fn sign_in(
    page: &Page,
    caller: &Caller,
    return_url: &str,
    user: &User,
    remember: Remember,
) -> Response {
    let body = json!({
        "returnUrl": return_url,
        "subjectId": user.subject_id,
        "remember": remember.persistent,
        "allowRefresh": remember.allow_refresh,
        "claims": user.claims.iter().map(|c| json!({ "type": c.claim_type, "value": c.value, "valueType": c.value_type })).collect::<Vec<_>>(),
    });
    let location = match page
        .api(axum::http::Method::POST, "/login", caller, Some(body))
        .await
    {
        Ok((StatusCode::OK, r)) => r["continueUrl"].as_str().unwrap_or("/").to_owned(),
        Ok((StatusCode::BAD_REQUEST, _)) => "/".to_owned(),
        Ok((status, _)) => return api_failure("login", &status),
        Err(e) => return api_failure("login", &e),
    };
    (StatusCode::FOUND, [(LOCATION, location)]).into_response()
}

/// The logout context for a logout id (none when absent).
async fn logout_context(
    page: &Page,
    caller: &Caller,
    logout_id: Option<&str>,
) -> Result<Value, Box<Response>> {
    let path = match logout_id {
        Some(id) => format!("/logout?logoutId={}", url_encode(id)),
        None => "/logout".to_owned(),
    };
    match page.api(axum::http::Method::GET, &path, caller, None).await {
        Ok((StatusCode::OK, context)) => Ok(context),
        Ok((status, _)) => Err(Box::new(api_failure("logout context", &status))),
        Err(e) => Err(Box::new(api_failure("logout context", &e))),
    }
}

/// Signs the browser out: completes the logout through
/// the API and redeems the continuation with the browser's cookies, whose
/// `Set-Cookie` deletions go on `response`.
async fn sign_out(page: &Page, caller: &Caller, mut response: Response) -> Response {
    let body = json!({ "returnUrl": "/" });
    let continue_url = match page
        .api(axum::http::Method::POST, "/logout", caller, Some(body))
        .await
    {
        Ok((StatusCode::OK, r)) => r["continueUrl"].as_str().unwrap_or_default().to_owned(),
        Ok((status, _)) => return api_failure("logout", &status),
        Err(e) => return api_failure("logout", &e),
    };
    let signed_out = match page.visit(&continue_url, caller).await {
        Ok(r) if r.status() == StatusCode::FOUND => r,
        Ok(r) => return api_failure("logout continuation", &r.status()),
        Err(e) => return api_failure("logout continuation", &e),
    };
    for cookie in signed_out.headers().get_all(SET_COOKIE) {
        response.headers_mut().append(SET_COOKIE, cookie.clone());
    }
    for name in [CACHE_CONTROL, PRAGMA] {
        if let Some(value) = signed_out.headers().get(&name) {
            response.headers_mut().insert(name, value.clone());
        }
    }
    response
}

/// `/account/logout?logoutId=…`: as the scripted UI, reads the logout
/// context, signs out and answers the context's client, post-logout
/// redirect and iframe URL. In interactive mode it asks first, unless the
/// request came from a client that identified the user.
async fn logout(State(page): State<Arc<Page>>, request: Request) -> Response {
    let params = Params::parse_query(request.uri().query().unwrap_or_default());
    let logout_id = params.get("logoutId");
    let caller = Caller::of(&request);
    let context = match logout_context(&page, &caller, logout_id.as_deref()).await {
        Ok(context) => context,
        Err(response) => return *response,
    };
    if page.ui.interactive {
        if context["showSignoutPrompt"] == true {
            return logout_prompt(logout_id.as_deref());
        }
        return sign_out(&page, &caller, signed_out_page(&context)).await;
    }
    let answer = json_response(
        StatusCode::OK,
        json!({
            "clientId": context["clientId"],
            "postLogoutRedirectUri": context["postLogoutRedirectUri"],
            "signOutIFrameUrl": context["signOutIFrameUrl"],
        }),
    );
    sign_out(&page, &caller, answer).await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LogoutForm {
    #[serde(default)]
    logout_id: Option<String>,
}

/// `POST /account/logout` (interactive mode): the user confirmed.
async fn logout_submit(State(page): State<Arc<Page>>, request: Request) -> Response {
    if cross_site(&request) {
        return forbidden();
    }
    if !page.ui.interactive {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let caller = Caller::of(&request);
    let Ok(axum::Form(form)) =
        <axum::Form<LogoutForm> as axum::extract::FromRequest<()>>::from_request(request, &())
            .await
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let logout_id = form.logout_id.filter(|id| !id.is_empty());
    let context = match logout_context(&page, &caller, logout_id.as_deref()).await {
        Ok(context) => context,
        Err(response) => return *response,
    };
    sign_out(&page, &caller, signed_out_page(&context)).await
}

fn logout_prompt(logout_id: Option<&str>) -> Response {
    html::page(
        StatusCode::OK,
        "Sign out",
        &format!(
            "<h1>Sign out</h1><p>Do you want to sign out?</p>\
             <form method=\"post\"><input type=\"hidden\" name=\"logoutId\" value=\"{}\">\
             <button type=\"submit\">Yes, sign me out</button></form>",
            html::escape(logout_id.unwrap_or_default())
        ),
    )
}

/// The signed-out page: the front-channel iframe (hidden) and the way back
/// to the client, which it takes by itself once the iframe has loaded (or
/// after three seconds). The redirect URI is one the end session
/// endpoint validated for the client.
fn signed_out_page(context: &Value) -> Response {
    let mut body = "<h1>You are now signed out</h1>".to_owned();
    let redirect = context["postLogoutRedirectUri"].as_str();
    if let Some(uri) = redirect {
        let client = context["clientName"]
            .as_str()
            .or(context["clientId"].as_str())
            .unwrap_or("the application");
        body.push_str(&format!(
            "<p>Return to <a id=\"post-logout-redirect\" href=\"{}\">{}</a>.</p>",
            html::escape(uri),
            html::escape(client)
        ));
    } else {
        body.push_str("<p>You can close this window.</p>");
    }
    if let Some(iframe) = context["signOutIFrameUrl"].as_str() {
        body.push_str(&format!(
            "<iframe id=\"signout-iframe\" src=\"{}\" width=\"0\" height=\"0\" hidden></iframe>",
            html::escape(iframe)
        ));
    }
    if redirect.is_some() {
        body.push_str(
            "<script>(function () {\
             var link = document.getElementById(\"post-logout-redirect\");\
             var done = false;\
             function go() { if (!done) { done = true; window.location.href = link.href; } }\
             var frame = document.getElementById(\"signout-iframe\");\
             if (frame) { frame.addEventListener(\"load\", go); setTimeout(go, 3000); } else { go(); }\
             })();</script>",
        );
    }
    html::page(StatusCode::OK, "Signed out", &body)
}

/// `/account/login/context?returnUrl=…`: the authorization context the
/// login page would act on, as JSON.
async fn login_context(State(page): State<Arc<Page>>, request: Request) -> Response {
    let params = Params::parse_query(request.uri().query().unwrap_or_default());
    let return_url = params.get("returnUrl").unwrap_or_default();
    let path = format!("/login?returnUrl={}", url_encode(&return_url));
    match page
        .api(axum::http::Method::GET, &path, &Caller::of(&request), None)
        .await
    {
        Ok((StatusCode::OK, context)) => json_response(StatusCode::OK, context),
        Ok((StatusCode::NOT_FOUND | StatusCode::BAD_REQUEST, _)) => json_response(
            StatusCode::NOT_FOUND,
            json!({ "error": "no_authorization_context" }),
        ),
        Ok((status, _)) => api_failure("login context", &status),
        Err(e) => api_failure("login context", &e),
    }
}

fn redirect(location: &str) -> Response {
    (StatusCode::FOUND, [(LOCATION, location.to_owned())]).into_response()
}

/// The signed-in subject, from the session the browser's cookies carry.
async fn subject(page: &Page, caller: &Caller) -> Result<Option<String>, Box<Response>> {
    match page
        .api(axum::http::Method::GET, "/session", caller, None)
        .await
    {
        Ok((StatusCode::OK, s)) => Ok(s["subjectId"].as_str().map(str::to_owned)),
        Ok((StatusCode::NOT_FOUND, _)) => Ok(None),
        Ok((status, _)) => Err(Box::new(api_failure("session", &status))),
        Err(e) => Err(Box::new(api_failure("session", &e))),
    }
}

/// The consent context for a return URL, or the page answering that there
/// is none.
async fn consent_context(
    page: &Page,
    caller: &Caller,
    return_url: &str,
) -> Result<Value, Box<Response>> {
    let path = format!("/consent?returnUrl={}", url_encode(return_url));
    match page.api(axum::http::Method::GET, &path, caller, None).await {
        Ok((StatusCode::OK, context)) => Ok(context),
        Ok((StatusCode::NOT_FOUND | StatusCode::BAD_REQUEST, _)) => {
            Err(Box::new(if page.ui.interactive {
                html::page(
                    StatusCode::BAD_REQUEST,
                    "Consent",
                    "<h1>Consent</h1><p>There is no request to consent to. \
                 Start again from the application.</p>",
                )
            } else {
                json_response(
                    StatusCode::BAD_REQUEST,
                    json!({ "error": "no_authorization_context" }),
                )
            }))
        }
        Ok((status, _)) => Err(Box::new(api_failure("consent context", &status))),
        Err(e) => Err(Box::new(api_failure("consent context", &e))),
    }
}

/// Posts the consent answer and sends the browser back to the return URL.
async fn answer(page: &Page, caller: &Caller, return_url: &str, body: Value) -> Response {
    match page
        .api(axum::http::Method::POST, "/consent", caller, Some(body))
        .await
    {
        Ok((StatusCode::OK, _)) => redirect(return_url),
        Ok((StatusCode::BAD_REQUEST, e)) => json_response(StatusCode::BAD_REQUEST, e),
        Ok((status, _)) => api_failure("consent", &status),
        Err(e) => api_failure("consent", &e),
    }
}

/// `/consent?returnUrl=…`: as the scripted UI, grants the scopes named by
/// `scopes` (all requested ones when absent), remembering them with
/// `remember=true`, or refuses with `error` and `error_description`. In
/// interactive mode, a form listing the scopes instead.
async fn consent_page(State(page): State<Arc<Page>>, request: Request) -> Response {
    let params = Params::parse_query(request.uri().query().unwrap_or_default());
    let return_url = params.get("returnUrl").unwrap_or_default();
    let caller = Caller::of(&request);
    let context = match consent_context(&page, &caller, &return_url).await {
        Ok(context) => context,
        Err(response) => return *response,
    };
    if page.ui.interactive {
        return consent_form(&context, &return_url, None);
    }
    let subject = match subject(&page, &caller).await {
        Ok(subject) => subject,
        Err(response) => return *response,
    };
    let body = match params.get("error") {
        Some(error) => json!({
            "returnUrl": return_url,
            "subjectId": subject,
            "error": error,
            "errorDescription": params.get("error_description"),
        }),
        None => {
            let scopes: Vec<String> = match params.get("scopes") {
                Some(scopes) => scopes
                    .split(' ')
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect(),
                None => context["scopes"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default(),
            };
            json!({
                "returnUrl": return_url,
                "subjectId": subject,
                "scopes": scopes,
                "rememberConsent": params.get("remember").as_deref() == Some("true"),
            })
        }
    };
    answer(&page, &caller, &return_url, body).await
}

/// `POST /consent` (interactive mode): the person's choice. Required scopes
/// are always granted; `no` refuses with `access_denied`.
async fn consent_submit(State(page): State<Arc<Page>>, request: Request) -> Response {
    if cross_site(&request) {
        return forbidden();
    }
    if !page.ui.interactive {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let caller = Caller::of(&request);
    let Ok(bytes) = axum::body::to_bytes(request.into_body(), 64 * 1024).await else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let mut return_url = String::new();
    let mut button = String::new();
    let mut remember = false;
    let mut chosen: Vec<String> = Vec::new();
    for (k, v) in url::form_urlencoded::parse(&bytes) {
        match k.as_ref() {
            "returnUrl" => return_url = v.into_owned(),
            "button" => button = v.into_owned(),
            "remember" => remember = true,
            "scopes" => chosen.push(v.into_owned()),
            _ => {}
        }
    }
    let context = match consent_context(&page, &caller, &return_url).await {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let subject = match subject(&page, &caller).await {
        Ok(Some(subject)) => subject,
        Ok(None) => {
            return html::page(
                StatusCode::BAD_REQUEST,
                "Consent",
                "<h1>Consent</h1><p>You are not signed in. Start again from the application.</p>",
            );
        }
        Err(response) => return *response,
    };
    if button != "yes" {
        let body =
            json!({ "returnUrl": return_url, "subjectId": subject, "error": "access_denied" });
        return answer(&page, &caller, &return_url, body).await;
    }
    let mut scopes: Vec<String> = Vec::new();
    for scope in scope_list(&context) {
        let name = scope["name"].as_str().unwrap_or_default().to_owned();
        if scope["required"] == true || chosen.contains(&name) {
            scopes.push(name);
        }
    }
    if scopes.is_empty() {
        return consent_form(&context, &return_url, Some("Pick at least one permission."));
    }
    let body = json!({
        "returnUrl": return_url,
        "subjectId": subject,
        "scopes": scopes,
        "rememberConsent": remember && context["allowRememberConsent"] == true,
    });
    answer(&page, &caller, &return_url, body).await
}

fn scope_list(context: &Value) -> impl Iterator<Item = &Value> {
    ["identityScopes", "apiScopes"]
        .into_iter()
        .flat_map(|k| context[k].as_array().into_iter().flatten())
}

fn consent_form(context: &Value, return_url: &str, error: Option<&str>) -> Response {
    let client = context["clientName"]
        .as_str()
        .or(context["clientId"].as_str())
        .unwrap_or_default();
    let mut rows = String::new();
    for scope in scope_list(context) {
        let name = scope["name"].as_str().unwrap_or_default();
        let label = scope["displayName"].as_str().unwrap_or(name);
        let required = scope["required"] == true;
        let description = scope["description"]
            .as_str()
            .map(|d| format!("<br><span class=\"note\">{}</span>", html::escape(d)))
            .unwrap_or_default();
        let marker = if scope["emphasize"] == true {
            " <strong>!</strong>"
        } else {
            ""
        };
        rows.push_str(&format!(
            "<label class=\"scope\"><input type=\"checkbox\" name=\"scopes\" value=\"{name}\" checked{disabled}> \
             {label}{marker}{required}{description}</label>",
            name = html::escape(name),
            disabled = if required { " disabled" } else { "" },
            label = html::escape(label),
            required = if required { " <span class=\"note\">(required)</span>" } else { "" },
        ));
    }
    let remember = if context["allowRememberConsent"] == true {
        "<label class=\"scope\"><input type=\"checkbox\" name=\"remember\" checked> Remember my decision</label>"
    } else {
        ""
    };
    let error = error
        .map(|e| format!("<p class=\"error\">{}</p>", html::escape(e)))
        .unwrap_or_default();
    html::page(
        StatusCode::OK,
        "Consent",
        &format!(
            "<h1>{client} is asking for your permission</h1>{error}\
             <p>Uncheck anything you don't want to grant.</p>\
             <form method=\"post\">\
             <input type=\"hidden\" name=\"returnUrl\" value=\"{return_url}\">{rows}{remember}\
             <button type=\"submit\" name=\"button\" value=\"yes\">Yes, allow</button>\
             <button type=\"submit\" name=\"button\" value=\"no\" class=\"secondary\">No, don't allow</button>\
             </form>",
            client = html::escape(client),
            return_url = html::escape(return_url),
        ),
    )
}

/// The pending device authorization for `user_code`, or why there is none.
async fn device_context(page: &Page, caller: &Caller, user_code: &str) -> Result<Value, Response> {
    let path = format!("/device?userCode={}", url_encode(user_code));
    match page.api(axum::http::Method::GET, &path, caller, None).await {
        Ok((StatusCode::OK, context)) => Ok(context),
        Ok((StatusCode::NOT_FOUND | StatusCode::BAD_REQUEST, _)) => Err(if page.ui.interactive {
            device_form(None, Some("That code isn't valid. Check it and try again."))
        } else {
            json_response(
                StatusCode::BAD_REQUEST,
                json!({ "error": "invalid_user_code" }),
            )
        }),
        Ok((status, _)) => Err(api_failure("device context", &status)),
        Err(e) => Err(api_failure("device context", &e)),
    }
}

/// Records the signed-in user's decision for a device authorization.
async fn device_decision(page: &Page, caller: &Caller, body: Value) -> Result<(), Response> {
    match page
        .api(axum::http::Method::POST, "/device", caller, Some(body))
        .await
    {
        Ok((StatusCode::OK, _)) => Ok(()),
        Ok((StatusCode::BAD_REQUEST, e)) => Err(json_response(
            StatusCode::BAD_REQUEST,
            json!({ "error": e["errorDescription"] }),
        )),
        Ok((status, _)) => Err(api_failure("device decision", &status)),
        Err(e) => Err(api_failure("device decision", &e)),
    }
}

/// `/device?userCode=…`: as the scripted UI, approves the device
/// authorization for the signed-in user with the `scopes` named (all
/// requested ones when absent), or denies it with `error`. In interactive
/// mode, a form to enter the code, then to allow or deny.
async fn device_page(State(page): State<Arc<Page>>, request: Request) -> Response {
    let params = Params::parse_query(request.uri().query().unwrap_or_default());
    let caller = Caller::of(&request);
    let Some(user_code) = params.get("userCode").filter(|c| !c.trim().is_empty()) else {
        return if page.ui.interactive {
            device_form(None, None)
        } else {
            json_response(
                StatusCode::BAD_REQUEST,
                json!({ "error": "invalid_user_code" }),
            )
        };
    };
    let context = match device_context(&page, &caller, &user_code).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    if page.ui.interactive {
        return device_form(Some((&user_code, &context)), None);
    }
    let body = match params.get("error") {
        Some(error) => json!({ "userCode": user_code, "error": error }),
        None => {
            let scopes: Vec<String> = match params.get("scopes") {
                Some(scopes) => scopes
                    .split(' ')
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect(),
                None => context["scopes"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default(),
            };
            json!({ "userCode": user_code, "scopes": scopes })
        }
    };
    match device_decision(&page, &caller, body).await {
        Ok(()) => json_response(StatusCode::OK, json!({ "result": "ok" })),
        Err(response) => response,
    }
}

/// `POST /device` (interactive mode): the person's choice.
async fn device_submit(State(page): State<Arc<Page>>, request: Request) -> Response {
    if cross_site(&request) {
        return forbidden();
    }
    if !page.ui.interactive {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let caller = Caller::of(&request);
    let Ok(bytes) = axum::body::to_bytes(request.into_body(), 64 * 1024).await else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let mut user_code = String::new();
    let mut button = String::new();
    let mut scopes: Vec<String> = Vec::new();
    for (k, v) in url::form_urlencoded::parse(&bytes) {
        match k.as_ref() {
            "userCode" => user_code = v.into_owned(),
            "button" => button = v.into_owned(),
            "scopes" => scopes.push(v.into_owned()),
            _ => {}
        }
    }
    let body = if button == "yes" {
        json!({ "userCode": user_code, "scopes": scopes })
    } else {
        json!({ "userCode": user_code, "error": "access_denied" })
    };
    match device_decision(&page, &caller, body).await {
        Ok(()) => html::page(
            StatusCode::OK,
            "Device",
            if button == "yes" {
                "<h1>Done</h1><p>You can return to your device.</p>"
            } else {
                "<h1>Denied</h1><p>The device won't get access.</p>"
            },
        ),
        Err(_) => html::page(
            StatusCode::BAD_REQUEST,
            "Device",
            "<h1>Device</h1><p>Sign in first (open the application and sign in), then enter \
             the code again.</p>",
        ),
    }
}

/// Completes a backchannel authentication request for the signed-in user.
async fn ciba_completion(page: &Page, caller: &Caller, body: Value) -> Result<(), Response> {
    match page
        .api(axum::http::Method::POST, "/ciba", caller, Some(body))
        .await
    {
        Ok((StatusCode::OK, _)) => Ok(()),
        Ok((StatusCode::BAD_REQUEST, e)) => Err(json_response(
            StatusCode::BAD_REQUEST,
            json!({ "error": e["errorDescription"] }),
        )),
        Ok((status, _)) => Err(api_failure("CIBA completion", &status)),
        Err(e) => Err(api_failure("CIBA completion", &e)),
    }
}

/// `/ciba?id=…`: as the scripted UI, completes the backchannel
/// authentication request for the signed-in user with the `scopes` named
/// (all requested ones when absent), or denies it with `error`. In
/// interactive mode, the signed-in user's pending requests to allow or
/// deny.
async fn ciba_page(State(page): State<Arc<Page>>, request: Request) -> Response {
    let params = Params::parse_query(request.uri().query().unwrap_or_default());
    let caller = Caller::of(&request);
    if page.ui.interactive {
        // Signing in needs a request from an application (the sign-in is
        // bound to the browser that started it), so this page can't sign
        // anyone in itself.
        match current_session(&page, &caller).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return html::page(
                    StatusCode::OK,
                    "Requests",
                    "<h1>Requests</h1><p>You are not signed in. Sign in through an \
                     application that uses this server (in the demo, the client at \
                     <code>http://localhost:5002</code>), then reload this page.</p>",
                );
            }
            Err(response) => return *response,
        }
        return match page
            .api(axum::http::Method::GET, "/ciba", &caller, None)
            .await
        {
            Ok((StatusCode::OK, pending)) => ciba_list(&pending),
            Ok((status, _)) => api_failure("CIBA requests", &status),
            Err(e) => api_failure("CIBA requests", &e),
        };
    }
    let Some(id) = params.get("id").filter(|i| !i.trim().is_empty()) else {
        return json_response(StatusCode::BAD_REQUEST, json!({ "error": "invalid_id" }));
    };
    let context = match page
        .api(
            axum::http::Method::GET,
            &format!("/ciba?id={}", url_encode(&id)),
            &caller,
            None,
        )
        .await
    {
        Ok((StatusCode::OK, context)) => context,
        Ok((StatusCode::NOT_FOUND, _)) => {
            return json_response(StatusCode::BAD_REQUEST, json!({ "error": "invalid_id" }));
        }
        Ok((status, _)) => return api_failure("CIBA request", &status),
        Err(e) => return api_failure("CIBA request", &e),
    };
    let body = match params.get("error") {
        Some(error) => json!({ "id": id, "error": error }),
        None => {
            let scopes: Vec<String> = match params.get("scopes") {
                Some(scopes) => scopes
                    .split(' ')
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect(),
                None => context["scopes"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default(),
            };
            json!({ "id": id, "scopes": scopes })
        }
    };
    match ciba_completion(&page, &caller, body).await {
        Ok(()) => json_response(StatusCode::OK, json!({ "result": "ok" })),
        Err(response) => response,
    }
}

/// `POST /ciba` (interactive mode): allow or deny one request.
async fn ciba_submit(State(page): State<Arc<Page>>, request: Request) -> Response {
    if cross_site(&request) {
        return forbidden();
    }
    if !page.ui.interactive {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let caller = Caller::of(&request);
    let Ok(bytes) = axum::body::to_bytes(request.into_body(), 64 * 1024).await else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let mut id = String::new();
    let mut button = String::new();
    let mut scopes: Vec<String> = Vec::new();
    for (k, v) in url::form_urlencoded::parse(&bytes) {
        match k.as_ref() {
            "id" => id = v.into_owned(),
            "button" => button = v.into_owned(),
            "scopes" => scopes.push(v.into_owned()),
            _ => {}
        }
    }
    let body = if button == "yes" {
        json!({ "id": id, "scopes": scopes })
    } else {
        json!({ "id": id, "error": "access_denied" })
    };
    match ciba_completion(&page, &caller, body).await {
        Ok(()) => redirect_see_other("ciba"),
        Err(_) => html::page(
            StatusCode::BAD_REQUEST,
            "Requests",
            "<h1>Requests</h1><p>That request couldn't be completed. Sign in as the user it \
             is for, then try again.</p>",
        ),
    }
}

/// The interactive CIBA page: the signed-in user's pending requests.
fn ciba_list(pending: &Value) -> Response {
    let requests = pending.as_array().cloned().unwrap_or_default();
    if requests.is_empty() {
        return html::page(
            StatusCode::OK,
            "Requests",
            "<h1>Requests</h1><p>No application is waiting for you.</p>",
        );
    }
    let mut body = String::from("<h1>Applications waiting for you</h1>");
    for request in &requests {
        let client = request["clientName"]
            .as_str()
            .or(request["clientId"].as_str())
            .unwrap_or_default();
        let message = request["bindingMessage"]
            .as_str()
            .map(|m| format!("<p>It shows: <strong>{}</strong></p>", html::escape(m)))
            .unwrap_or_default();
        let rows: String = request["scopes"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(|s| {
                format!(
                    "<label class=\"scope\"><input type=\"checkbox\" name=\"scopes\" value=\"{s}\" checked> {s}</label>",
                    s = html::escape(s)
                )
            })
            .collect();
        body.push_str(&format!(
            "<h2>{client}</h2>{message}<form method=\"post\">\
             <input type=\"hidden\" name=\"id\" value=\"{id}\">{rows}\
             <button type=\"submit\" name=\"button\" value=\"yes\">Yes, allow</button>\
             <button type=\"submit\" name=\"button\" value=\"no\" class=\"secondary\">No, don't allow</button>\
             </form>",
            client = html::escape(client),
            id = html::escape(request["id"].as_str().unwrap_or_default()),
        ));
    }
    html::page(StatusCode::OK, "Requests", &body)
}

/// The interactive device page: a code entry form, or the request to
/// allow.
fn device_form(request: Option<(&str, &Value)>, error: Option<&str>) -> Response {
    let error = error
        .map(|e| format!("<p class=\"error\">{}</p>", html::escape(e)))
        .unwrap_or_default();
    let Some((user_code, context)) = request else {
        return html::page(
            StatusCode::OK,
            "Device",
            &format!(
                "<h1>Connect a device</h1>{error}\
                 <form method=\"get\"><label>Code shown on your device \
                 <input name=\"userCode\" autofocus autocomplete=\"off\"></label>\
                 <button type=\"submit\">Continue</button></form>"
            ),
        );
    };
    let client = context["clientName"]
        .as_str()
        .or(context["clientId"].as_str())
        .unwrap_or_default();
    let rows: String = context["scopes"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(|s| {
            format!(
                "<label class=\"scope\"><input type=\"checkbox\" name=\"scopes\" value=\"{s}\" checked> {s}</label>",
                s = html::escape(s)
            )
        })
        .collect();
    html::page(
        StatusCode::OK,
        "Device",
        &format!(
            "<h1>{client} on your device is asking for your permission</h1>{error}\
             <form method=\"post\"><input type=\"hidden\" name=\"userCode\" value=\"{code}\">{rows}\
             <button type=\"submit\" name=\"button\" value=\"yes\">Yes, allow</button>\
             <button type=\"submit\" name=\"button\" value=\"no\" class=\"secondary\">No, don't allow</button>\
             </form>",
            client = html::escape(client),
            code = html::escape(user_code),
        ),
    )
}

/// `/test/sessions?subjectId=` (tests only): the server-side sessions, as
/// the scripted UI shows them.
async fn test_sessions(State(page): State<Arc<Page>>, request: Request) -> Response {
    let params = Params::parse_query(request.uri().query().unwrap_or_default());
    let mut path = "/sessions?count=100".to_owned();
    if let Some(subject) = params.get("subjectId") {
        path.push_str(&format!("&subjectId={}", url_encode(&subject)));
    }
    match page
        .api(axum::http::Method::GET, &path, &Caller::of(&request), None)
        .await
    {
        Ok((StatusCode::OK, result)) => json_response(
            StatusCode::OK,
            json!({
                "count": result["totalCount"],
                "sessions": result["results"].as_array().unwrap_or(&Vec::new()).iter().map(|s| json!({
                    "subjectId": s["subjectId"],
                    "displayName": s["displayName"],
                    "clientIds": s["clientIds"],
                    "expires": !s["expires"].is_null(),
                })).collect::<Vec<_>>(),
            }),
        ),
        Ok((status, _)) => status.into_response(),
        Err(e) => api_failure("sessions", &e),
    }
}

/// `/test/sessions/remove?subjectId=&clientIds=a,b&revokeTokens=…` (tests
/// only): removes sessions through the API.
async fn test_remove_sessions(State(page): State<Arc<Page>>, request: Request) -> Response {
    let params = Params::parse_query(request.uri().query().unwrap_or_default());
    let flag = |name: &str| {
        params
            .get(name)
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(true)
    };
    let body = json!({
        "subjectId": params.get("subjectId"),
        "clientIds": params.get("clientIds").map(|c| c.split(',').filter(|c| !c.is_empty()).map(str::to_owned).collect::<Vec<_>>()),
        "revokeTokens": flag("revokeTokens"),
        "revokeConsents": flag("revokeConsents"),
        "removeServerSideSession": flag("removeServerSideSession"),
        "sendBackchannelLogoutNotification": flag("sendBackchannelLogoutNotification"),
    });
    match page
        .api(
            axum::http::Method::POST,
            "/sessions/remove",
            &Caller::of(&request),
            Some(body),
        )
        .await
    {
        Ok((status, _)) => status.into_response(),
        Err(e) => api_failure("remove sessions", &e),
    }
}

/// Rewrites a subject's session records (tests only).
async fn edit_sessions(
    page: &Page,
    query: &str,
    edit: impl Fn(&mut rustid_core::server_side_sessions::ServerSideSession),
) -> Response {
    let Some(sessions) = &page.ui.sessions else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let params = Params::parse_query(query);
    let Some(subject) = params.get("subjectId") else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let filter = rustid_core::server_side_sessions::SessionFilter {
        subject_id: Some(subject),
        session_id: None,
    };
    let records = match sessions.store.get_sessions(&filter).await {
        Ok(records) => records,
        Err(e) => return api_failure("sessions", &e),
    };
    for mut record in records {
        edit(&mut record);
        if let Err(e) = sessions.store.update_session(record).await {
            return api_failure("sessions", &e);
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

/// `/test/sessions/expire?subjectId=` (tests only): expired a minute ago.
async fn test_expire_sessions(State(page): State<Arc<Page>>, request: Request) -> Response {
    let past = chrono::Utc::now() - chrono::Duration::minutes(1);
    let query = request.uri().query().unwrap_or_default().to_owned();
    edit_sessions(&page, &query, |r| r.expires = Some(past)).await
}

/// `/test/sessions/corrupt?subjectId=` (tests only): a ticket that won't open.
async fn test_corrupt_sessions(State(page): State<Arc<Page>>, request: Request) -> Response {
    let query = request.uri().query().unwrap_or_default().to_owned();
    edit_sessions(&page, &query, |r| r.ticket = "invalid".to_owned()).await
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct EntityIdQuery {
    entity_id: String,
}

/// `/test/saml/service-providers/disable?entityId=` and `/remove` (tests
/// only): the SP changed through the admin, as an admin call would.
async fn change_service_provider(page: &Page, entity_id: &str, remove: bool) -> Response {
    use rustid_saml::admin::{SamlServiceProviderAdmin, SamlServiceProviderInput};
    let Some(configuration) = page.ui.configuration.as_deref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let admin = SamlServiceProviderAdmin;
    let found = match admin.get_by_entity_id(configuration, entity_id).await {
        Ok(Some(found)) => found,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => return api_failure("saml service provider", &e),
    };
    let result = if remove {
        admin.delete(configuration, &found.id).await
    } else {
        let mut body = serde_json::to_value(&found.item).expect("a configuration serialises");
        body["enabled"] = Value::Bool(false);
        match SamlServiceProviderInput::from_json(body) {
            Ok(input) => {
                admin
                    .update(configuration, &found.id, input, found.version)
                    .await
            }
            Err(e) => return api_failure("saml service provider", &e.message),
        }
    };
    match result {
        Ok(Ok(_)) => json_response(StatusCode::OK, json!({ "result": "ok" })),
        Ok(Err(errors)) => api_failure("saml service provider", &errors[0].message),
        Err(e) => api_failure("saml service provider", &e),
    }
}

async fn test_disable_service_provider(
    State(page): State<Arc<Page>>,
    Query(query): Query<EntityIdQuery>,
) -> Response {
    change_service_provider(&page, &query.entity_id, false).await
}

async fn test_remove_service_provider(
    State(page): State<Arc<Page>>,
    Query(query): Query<EntityIdQuery>,
) -> Response {
    change_service_provider(&page, &query.entity_id, true).await
}

/// The signed-in user's subject and session id, from the browser's cookies.
async fn current_session(
    page: &Page,
    caller: &Caller,
) -> Result<Option<(String, String)>, Box<Response>> {
    match page
        .api(axum::http::Method::GET, "/session", caller, None)
        .await
    {
        Ok((StatusCode::OK, s)) => Ok(match (s["subjectId"].as_str(), s["sessionId"].as_str()) {
            (Some(sub), Some(sid)) => Some((sub.to_owned(), sid.to_owned())),
            _ => None,
        }),
        Ok((StatusCode::NOT_FOUND, _)) => Ok(None),
        Ok((status, _)) => Err(Box::new(api_failure("session", &status))),
        Err(e) => Err(Box::new(api_failure("session", &e))),
    }
}

/// The user's server-side sessions (the API's filter is a substring, so
/// only exact subject matches are kept); `None` when they aren't enabled.
async fn sessions_of(
    page: &Page,
    caller: &Caller,
    subject: &str,
) -> Result<Option<Vec<Value>>, Box<Response>> {
    let path = format!("/sessions?count=100&subjectId={}", url_encode(subject));
    match page.api(axum::http::Method::GET, &path, caller, None).await {
        Ok((StatusCode::OK, result)) => Ok(Some(
            result["results"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter(|s| s["subjectId"].as_str() == Some(subject))
                .collect(),
        )),
        Ok((StatusCode::NOT_FOUND, _)) => Ok(None),
        Ok((status, _)) => Err(Box::new(api_failure("sessions", &status))),
        Err(e) => Err(Box::new(api_failure("sessions", &e))),
    }
}

/// `GET /sessions` (interactive mode): the signed-in user's sessions, each
/// with a button to end it.
async fn sessions_page(State(page): State<Arc<Page>>, request: Request) -> Response {
    let caller = Caller::of(&request);
    let (subject, current) = match current_session(&page, &caller).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return html::page(
                StatusCode::OK,
                "Sessions",
                "<h1>Your sessions</h1><p>You are not signed in.</p>",
            );
        }
        Err(response) => return *response,
    };
    let sessions = match sessions_of(&page, &caller, &subject).await {
        Ok(Some(sessions)) => sessions,
        Ok(None) => {
            return html::page(
                StatusCode::OK,
                "Sessions",
                "<h1>Your sessions</h1><p>Server-side sessions are not enabled.</p>",
            );
        }
        Err(response) => return *response,
    };
    let when = |v: &Value| {
        v.as_str()
            .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
            .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "-".to_owned())
    };
    let rows: String = sessions
        .iter()
        .map(|s| {
            let sid = s["sessionId"].as_str().unwrap_or_default();
            let this = if sid == current {
                " <strong>(This browser)</strong>"
            } else {
                ""
            };
            let clients: Vec<&str> = s["clientIds"]
                .as_array()
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            format!(
                "<form method=\"post\"><p>Session <code>{short}</code>{this}<br>\
                 Signed in {created}, renewed {renewed}, expires {expires}<br>\
                 Clients: {clients}</p>\
                 <input type=\"hidden\" name=\"sessionId\" value=\"{sid}\">\
                 <button type=\"submit\" class=\"secondary\">End this session</button></form>",
                short = html::escape(&sid.chars().take(8).collect::<String>()),
                created = when(&s["created"]),
                renewed = when(&s["renewed"]),
                expires = when(&s["expires"]),
                clients = if clients.is_empty() {
                    "none".to_owned()
                } else {
                    html::escape(&clients.join(", "))
                },
                sid = html::escape(sid),
            )
        })
        .collect();
    html::page(
        StatusCode::OK,
        "Sessions",
        &format!(
            "<h1>Your sessions</h1><p>Where you are signed in. Ending a session signs that \
             browser out, revokes its clients' tokens and tells them over the back channel.</p>\
             {rows}"
        ),
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EndSessionForm {
    session_id: String,
}

/// `POST /sessions` (interactive mode): ends one of the signed-in user's
/// sessions. Anyone else's session id changes nothing.
async fn end_session_row(State(page): State<Arc<Page>>, request: Request) -> Response {
    if cross_site(&request) {
        return forbidden();
    }
    let caller = Caller::of(&request);
    let Ok(axum::Form(form)) =
        <axum::Form<EndSessionForm> as axum::extract::FromRequest<()>>::from_request(request, &())
            .await
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let subject = match current_session(&page, &caller).await {
        Ok(Some((subject, _))) => subject,
        Ok(None) => return redirect_see_other("/sessions"),
        Err(response) => return *response,
    };
    let owned = match sessions_of(&page, &caller, &subject).await {
        Ok(Some(sessions)) => sessions
            .iter()
            .any(|s| s["sessionId"].as_str() == Some(form.session_id.as_str())),
        Ok(None) => false,
        Err(response) => return *response,
    };
    if owned {
        let body = json!({ "subjectId": subject, "sessionId": form.session_id });
        match page
            .api(
                axum::http::Method::POST,
                "/sessions/remove",
                &caller,
                Some(body),
            )
            .await
        {
            Ok((StatusCode::NO_CONTENT, _)) => {}
            Ok((status, _)) => return api_failure("remove sessions", &status),
            Err(e) => return api_failure("remove sessions", &e),
        }
    }
    redirect_see_other("/sessions")
}

fn redirect_see_other(location: &str) -> Response {
    (StatusCode::SEE_OTHER, [(LOCATION, location.to_owned())]).into_response()
}

#[cfg(test)]
mod signed_out_tests {
    use super::*;

    async fn body(response: Response) -> String {
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn the_signed_out_page_returns_to_the_client_after_the_iframe() {
        let html = body(signed_out_page(&json!({
            "clientId": "web",
            "postLogoutRedirectUri": "https://client.test/signout?state=a&b=\"x\"",
            "signOutIFrameUrl": "https://idp.test/connect/endsession/callback?endSessionId=1",
        })))
        .await;
        assert!(
            html.contains("id=\"post-logout-redirect\" href=\"https://client.test/signout?state=a&amp;b=&quot;x&quot;\""),
            "{html}"
        );
        assert!(html.contains("<iframe id=\"signout-iframe\""), "{html}");
        assert!(html.contains("<script>"), "{html}");

        // Nowhere to go: no script.
        let html = body(signed_out_page(&json!({ "signOutIFrameUrl": null }))).await;
        assert!(!html.contains("<script>"), "{html}");
    }
}

/// The users file's claims of the requested types for the file's users.
/// Subjects the file doesn't have (users signed in through an upstream
/// provider, or by another UI) are answered as the default profile service
/// answers them: their session's claims, and active.
#[derive(Debug, Clone)]
pub struct UsersProfileService {
    users: Vec<User>,
}

impl UsersProfileService {
    pub fn new(users: Vec<User>) -> Self {
        UsersProfileService { users }
    }

    fn user(&self, subject_id: &str) -> Option<&User> {
        self.users.iter().find(|u| u.subject_id == subject_id)
    }
}

#[async_trait::async_trait]
impl rustid_core::profile::ProfileService for UsersProfileService {
    async fn profile_claims(
        &self,
        request: &rustid_core::profile::ProfileRequest<'_>,
    ) -> Result<Vec<rustid_core::tokens::Claim>, rustid_core::profile::ProfileError> {
        let Some(user) = self.user(request.subject_id) else {
            return rustid_core::profile::DefaultProfileService
                .profile_claims(request)
                .await;
        };
        let claims: Vec<rustid_core::tokens::Claim> =
            user.claims
                .iter()
                .map(|c| rustid_core::tokens::Claim {
                    claim_type: c.claim_type.clone(),
                    value: c.value.clone(),
                    value_type: c.value_type.clone().unwrap_or_else(|| {
                        rustid_core::clients::CLAIM_VALUE_TYPE_STRING.to_owned()
                    }),
                })
                .collect();
        Ok(rustid_core::profile::requested_claims(
            &claims,
            request.requested_claim_types,
        ))
    }

    async fn is_active(
        &self,
        request: &rustid_core::profile::ActiveRequest<'_>,
    ) -> Result<bool, rustid_core::profile::ProfileError> {
        match self.user(request.subject_id) {
            Some(_) => Ok(true),
            None => {
                rustid_core::profile::DefaultProfileService
                    .is_active(request)
                    .await
            }
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct IdpInitiatedQuery {
    #[serde(default)]
    sp: String,
    #[serde(default)]
    relay_state: Option<String>,
}

/// `/test/saml/idp-initiated?sp=&relayState=` (tests only): what a UI does
/// to start IdP-initiated SAML SSO. It asks the interaction API with the
/// browser's cookies, then sends the browser to the continuation, or
/// relays the refusal.
async fn test_idp_initiated(
    State(page): State<Arc<Page>>,
    Query(query): Query<IdpInitiatedQuery>,
    request: Request,
) -> Response {
    let caller = Caller::of(&request);
    let body = json!({ "spEntityId": query.sp, "relayState": query.relay_state });
    match page
        .api(
            axum::http::Method::POST,
            "/saml/idp-initiated",
            &caller,
            Some(body),
        )
        .await
    {
        Ok((StatusCode::OK, answer)) => match answer["continueUrl"].as_str() {
            Some(url) => (
                StatusCode::FOUND,
                [(axum::http::header::LOCATION, url.to_owned())],
            )
                .into_response(),
            None => api_failure("idp-initiated", &"no continueUrl"),
        },
        Ok((status, answer)) => json_response(status, answer),
        Err(e) => api_failure("idp-initiated", &e),
    }
}

#[cfg(test)]
mod users_profile_tests {
    use rustid_core::profile::{ActiveRequest, ProfileRequest, ProfileService};
    use rustid_core::tokens::Claim;

    use super::*;

    #[tokio::test]
    async fn subjects_outside_the_file_are_answered_from_their_session() {
        let service = UsersProfileService::new(vec![User {
            subject_id: "1".into(),
            username: "alice".into(),
            password: None,
            claims: Vec::new(),
        }]);
        let client: rustid_core::clients::Client =
            serde_json::from_value(json!({ "clientId": "c" })).unwrap();
        let session = [
            Claim::string("name", "Carol"),
            Claim::string("email", "c@x"),
        ];
        // A federated user isn't in the file: active, with the session's claims.
        let active = ActiveRequest {
            caller: "test",
            client: &client,
            subject_id: "federated",
            subject_claims: &session,
        };
        assert!(service.is_active(&active).await.unwrap());
        let claims = service
            .profile_claims(&ProfileRequest {
                caller: "test",
                client: &client,
                subject_id: "federated",
                subject_claims: &session,
                requested_claim_types: &["name".to_owned()],
            })
            .await
            .unwrap();
        assert_eq!(claims, [Claim::string("name", "Carol")]);
        // A user in the file is answered from the file.
        assert!(
            service
                .is_active(&ActiveRequest {
                    subject_id: "1",
                    ..active
                })
                .await
                .unwrap()
        );
    }
}
