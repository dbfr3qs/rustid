//! The demo relying party: signs a person in with the authorization code
//! flow and PKCE, verifies the identity token against the server's JWKS,
//! calls userinfo, and shows everything it received.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context;
use axum::Json;
use axum::Router;
use axum::extract::{Query, State};
use axum::http::header::{COOKIE, LOCATION, SET_COOKIE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use rustid_core::jwt::{Jws, PublicJwk, b64url};
use rustid_core::params::url_encode;
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::html;
use crate::password_hook::{self, PasswordHook};

/// Where `scripts/demo.sh` runs the server and the client, and the client's
/// registration in `examples/demo/clients.json`.
pub const DEFAULT_AUTHORITY: &str = "https://localhost:5443";
pub const DEFAULT_PUBLIC_URL: &str = "http://localhost:5002";
pub const DEFAULT_CLIENT_ID: &str = "demo";
pub const DEFAULT_SCOPE: &str = "openid profile email api1 offline_access";

/// How the demo client reaches the server and presents itself.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// The server's base URL, where discovery lives.
    pub authority: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    /// The client's own base URL as the browser sees it; the redirect URI
    /// is `{public_url}/callback`.
    pub public_url: String,
    pub scope: String,
    /// A CA certificate to trust for the server, besides the system roots.
    pub ca_file: Option<PathBuf>,
    /// Host names to pin to addresses when calling the server.
    pub resolve: Vec<(String, SocketAddr)>,
    /// When set, the client also hosts the server's password grant hook at
    /// `{public_url}/hooks/password`, checking these users.
    pub users_file: Option<PathBuf>,
    /// When set, the client is also a SAML service provider at `/saml`.
    pub saml: Option<crate::saml_sp::SamlSpConfig>,
}

/// A sign-in in flight, keyed by `state`.
struct Pending {
    verifier: String,
    nonce: String,
    started: Instant,
}

/// What the client received for a signed-in browser.
struct Signed {
    id_token: String,
    id_claims: Map<String, Value>,
    access_token: String,
    access_claims: Option<Map<String, Value>>,
    token_response: Map<String, Value>,
    userinfo: Result<Value, String>,
    /// With `offline_access`.
    refresh_token: Option<String>,
    /// How many times the tokens were refreshed.
    refreshes: u32,
}

struct Demo {
    config: ClientConfig,
    http: reqwest::Client,
    pending: Mutex<HashMap<String, Pending>>,
    sessions: Mutex<HashMap<String, Arc<Signed>>>,
}

/// A sign-in that isn't completed within this time is forgotten.
const PENDING_LIFETIME: Duration = Duration::from_secs(600);
const FLOW_COOKIE: &str = "demo.flow";
const SESSION_COOKIE: &str = "demo.session";

/// The client's pages: `/`, `/login`, `/callback`, `/refresh`, `/signout`,
/// `/signed-out` and `/frontchannel-logout`, and `/hooks/password` and
/// `/hooks/ciba/user` with a users file.
pub fn router(config: ClientConfig) -> anyhow::Result<Router> {
    let mut http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15));
    if let Some(ca) = &config.ca_file {
        let pem = std::fs::read(ca).with_context(|| format!("reading {}", ca.display()))?;
        http = http.add_root_certificate(
            reqwest::Certificate::from_pem(&pem)
                .with_context(|| format!("parsing {}", ca.display()))?,
        );
    }
    for (host, addr) in &config.resolve {
        http = http.resolve(host, *addr);
    }
    let hooks = match &config.users_file {
        Some(file) => {
            let users = password_hook::load_users(file)?;
            let base = config.public_url.trim_end_matches('/');
            vec![
                (
                    "/hooks/password",
                    Arc::new(PasswordHook {
                        users: users.clone(),
                        url: format!("{base}/hooks/password"),
                    }),
                    password_hook::answer as fn(&[_], &_) -> _,
                ),
                (
                    "/hooks/ciba/user",
                    Arc::new(PasswordHook {
                        users,
                        url: format!("{base}/hooks/ciba/user"),
                    }),
                    password_hook::ciba_user_answer,
                ),
            ]
        }
        None => Vec::new(),
    };
    let http = http.build()?;
    let saml = match &config.saml {
        Some(saml) => Some(crate::saml_sp::router(saml.clone(), http.clone())?),
        None => None,
    };
    let demo = Arc::new(Demo {
        config,
        http,
        pending: Mutex::new(HashMap::new()),
        sessions: Mutex::new(HashMap::new()),
    });
    let mut router = Router::new();
    for (path, hook, answer) in hooks {
        let demo = demo.clone();
        router = router.route(
            path,
            post(move |headers: HeaderMap, Json(request): Json<Value>| {
                let demo = demo.clone();
                password_hook::handle(
                    hook.clone(),
                    move || demo.server_keys(),
                    headers,
                    request,
                    answer,
                )
            }),
        );
    }
    let app = router
        .route("/", get(home))
        .route("/login", get(login))
        .route("/callback", get(callback))
        .route("/refresh", get(refresh))
        .route("/signout", get(signout))
        .route("/signed-out", get(signed_out))
        .route("/frontchannel-logout", get(frontchannel_logout))
        .with_state(demo);
    Ok(match saml {
        Some(saml) => app.merge(saml),
        None => app,
    })
}

/// The discovery document's endpoints the client uses.
#[derive(Deserialize)]
struct Metadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: Option<String>,
    jwks_uri: String,
    /// Where requests are pushed (PAR), when the server supports it.
    pushed_authorization_request_endpoint: Option<String>,
    /// Where RP-initiated logout goes, when the server supports it.
    end_session_endpoint: Option<String>,
}

impl Demo {
    /// The server's issuer and JWKS, for the password hook.
    async fn server_keys(self: Arc<Self>) -> Result<(String, Value), String> {
        let metadata = self.metadata().await?;
        let jwks = self.get_json(&metadata.jwks_uri, None).await?;
        Ok((metadata.issuer, jwks))
    }

    async fn metadata(&self) -> Result<Metadata, String> {
        let url = format!(
            "{}/.well-known/openid-configuration",
            self.config.authority.trim_end_matches('/')
        );
        self.get_json(&url, None)
            .await
            .and_then(|v| serde_json::from_value(v).map_err(|e| format!("{url}: {e}")))
    }

    async fn get_json(&self, url: &str, bearer: Option<&str>) -> Result<Value, String> {
        let mut request = self.http.get(url);
        if let Some(token) = bearer {
            request = request.bearer_auth(token);
        }
        let response = request
            .send()
            .await
            .map_err(|e| format!("{url}: {}", error_chain(&e)))?;
        let status = response.status();
        if !status.is_success() {
            let challenge = response
                .headers()
                .get("www-authenticate")
                .and_then(|v| v.to_str().ok())
                .map(|v| format!(" ({v})"))
                .unwrap_or_default();
            return Err(format!("{url} answered {status}{challenge}"));
        }
        response
            .json()
            .await
            .map_err(|e| format!("{url}: {}", error_chain(&e)))
    }

    fn redirect_uri(&self) -> String {
        format!("{}/callback", self.config.public_url.trim_end_matches('/'))
    }

    fn session(&self, headers: &HeaderMap) -> Option<Arc<Signed>> {
        let id = cookie(headers, SESSION_COOKIE)?;
        self.sessions.lock().unwrap().get(id).cloned()
    }
}

/// `reqwest` errors with their causes, which say why TLS or DNS failed.
fn error_chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

fn random() -> String {
    let mut bytes = [0u8; 32];
    aws_lc_rs::rand::fill(&mut bytes).expect("the system random source");
    b64url(&bytes)
}

fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|pair| pair.trim().strip_prefix(name)?.strip_prefix('='))
}

fn set_cookie(name: &str, value: &str) -> String {
    format!("{name}={value}; Path=/; HttpOnly; SameSite=Lax")
}

fn clear_cookie(name: &str) -> String {
    format!("{name}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
}

fn redirect(location: &str, cookies: &[String]) -> Response {
    let mut response = (StatusCode::FOUND, [(LOCATION, location.to_owned())]).into_response();
    for c in cookies {
        if let Ok(value) = c.parse() {
            response.headers_mut().append(SET_COOKIE, value);
        }
    }
    response
}

fn problem(status: StatusCode, title: &str, detail: &str) -> Response {
    html::page(
        status,
        title,
        &format!(
            "<h1>{}</h1><p class=\"error\">{}</p><a class=\"button\" href=\"/\">Back</a>",
            html::escape(title),
            html::escape(detail)
        ),
    )
}

/// `/`: a sign-in link, or what the client knows about the signed-in user.
async fn home(State(demo): State<Arc<Demo>>, headers: HeaderMap) -> Response {
    let Some(signed) = demo.session(&headers) else {
        return html::page(
            StatusCode::OK,
            "rustid demo",
            &format!(
                "<h1>rustid demo client</h1>\
                 <p>Signs in at <code>{}</code> as <code>{}</code> with the authorization code \
                 flow, PKCE and a pushed authorization request, asking for <code>{}</code>.</p>\
                 <a class=\"button\" href=\"/login\">Sign in</a>",
                html::escape(&demo.config.authority),
                html::escape(&demo.config.client_id),
                html::escape(&demo.config.scope),
            ),
        );
    };
    // Code flow id tokens carry no profile claims unless the client asks
    // for them always; userinfo has them.
    let userinfo_name = signed
        .userinfo
        .as_ref()
        .ok()
        .and_then(|u| u.get("name"))
        .and_then(Value::as_str);
    let name = signed
        .id_claims
        .get("name")
        .and_then(Value::as_str)
        .or(userinfo_name)
        .or(signed.id_claims.get("sub").and_then(Value::as_str))
        .unwrap_or("?");
    let userinfo = match &signed.userinfo {
        Ok(v) => claims_table(v.as_object().unwrap_or(&Map::new())),
        Err(e) => format!("<p class=\"error\">{}</p>", html::escape(e)),
    };
    let access = match &signed.access_claims {
        Some(claims) => claims_table(claims),
        None => "<p>A reference token: its contents are only known to the server.</p>".to_owned(),
    };
    let mut response_fields = signed.token_response.clone();
    for secret in ["access_token", "id_token", "refresh_token"] {
        if response_fields.contains_key(secret) {
            response_fields.insert(secret.to_owned(), Value::String("(below)".to_owned()));
        }
    }
    html::page(
        StatusCode::OK,
        "rustid demo",
        &format!(
            "<h1>Signed in as {name}</h1>\
             <p><span class=\"ok\">✓ id token verified</span>: signature against the server's \
             JWKS, issuer, audience, nonce and expiry.</p>{refreshed}\
             <h2>Identity token claims</h2>{id}\
             <h2>Userinfo</h2>{userinfo}\
             <h2>Access token claims (as received)</h2>{access}\
             <h2>Token response</h2>{response}\
             <details><summary>Raw tokens</summary>\
             <h2>id_token</h2><pre>{id_token}</pre><h2>access_token</h2><pre>{access_token}</pre>\
             </details>\
             {refresh}\
             <a class=\"button\" href=\"/login?prompt=login\">Sign in again</a>\
             <a class=\"button secondary\" href=\"/signout\">Sign out</a>\
             <a class=\"button secondary\" href=\"{sessions}\">Your sessions at the server</a>\
             <p class=\"note\">Signing out forgets the tokens here and ends the server's \
             session too (RP-initiated logout). Signing out at the server signs this client \
             out over the front channel.</p>",
            name = html::escape(name),
            sessions = html::escape(&format!(
                "{}/sessions",
                demo.config.authority.trim_end_matches('/')
            )),
            refreshed = match signed.refreshes {
                0 => String::new(),
                1 => "<p class=\"ok\">Tokens refreshed 1 time.</p>".to_owned(),
                n => format!("<p class=\"ok\">Tokens refreshed {n} times.</p>"),
            },
            refresh = if signed.refresh_token.is_some() {
                "<a class=\"button\" href=\"/refresh\">Refresh tokens</a>"
            } else {
                ""
            },
            id = claims_table(&signed.id_claims),
            response = claims_table(&response_fields),
            id_token = html::escape(&signed.id_token),
            access_token = html::escape(&signed.access_token),
        ),
    )
}

fn claims_table(claims: &Map<String, Value>) -> String {
    let mut rows = String::from("<table>");
    for (name, value) in claims {
        let shown = match value {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        let hint = match name.as_str() {
            "exp" | "iat" | "nbf" | "auth_time" => value
                .as_i64()
                .and_then(utc)
                .map(|t| format!(" <span class=\"note\">({t})</span>"))
                .unwrap_or_default(),
            _ => String::new(),
        };
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{}{hint}</td></tr>",
            html::escape(name),
            html::escape(&shown)
        ));
    }
    rows.push_str("</table>");
    rows
}

/// A Unix time as `YYYY-MM-DD HH:MM:SS UTC`.
fn utc(seconds: i64) -> Option<String> {
    chrono::DateTime::from_timestamp(seconds, 0)
        .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
}

#[derive(Deserialize)]
struct LoginQuery {
    prompt: Option<String>,
}

/// `/login`: starts a sign-in with a fresh state, nonce and PKCE verifier.
async fn login(State(demo): State<Arc<Demo>>, Query(q): Query<LoginQuery>) -> Response {
    let metadata = match demo.metadata().await {
        Ok(m) => m,
        Err(e) => return problem(StatusCode::BAD_GATEWAY, "The server can't be reached", &e),
    };
    let state = random();
    let nonce = random();
    let verifier = random();
    let challenge =
        b64url(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, verifier.as_bytes()).as_ref());
    {
        let mut pending = demo.pending.lock().unwrap();
        pending.retain(|_, p| p.started.elapsed() < PENDING_LIFETIME);
        pending.insert(
            state.clone(),
            Pending {
                verifier,
                nonce: nonce.clone(),
                started: Instant::now(),
            },
        );
    }
    let mut parameters = vec![
        ("client_id", demo.config.client_id.clone()),
        ("redirect_uri", demo.redirect_uri()),
        ("response_type", "code".to_owned()),
        ("scope", demo.config.scope.clone()),
        ("state", state.clone()),
        ("nonce", nonce),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256".to_owned()),
    ];
    if let Some(prompt) = q.prompt.filter(|p| !p.is_empty()) {
        parameters.push(("prompt", prompt));
    }
    // Pushed authorization (RFC 9126): the parameters go to the server
    // directly, and the browser carries only a reference to them.
    let url = match &metadata.pushed_authorization_request_endpoint {
        Some(par) => match client_post(&demo, par, parameters).await {
            Ok(pushed) => match pushed.get("request_uri").and_then(Value::as_str) {
                Some(request_uri) => format!(
                    "{}?client_id={}&request_uri={}",
                    metadata.authorization_endpoint,
                    url_encode(&demo.config.client_id),
                    url_encode(request_uri)
                ),
                None => {
                    return problem(StatusCode::BAD_GATEWAY, "Pushing failed", "no request_uri");
                }
            },
            Err(e) => return problem(StatusCode::BAD_GATEWAY, "Pushing failed", &e),
        },
        None => {
            let query: Vec<String> = parameters
                .iter()
                .map(|(k, v)| format!("{k}={}", url_encode(v)))
                .collect();
            format!("{}?{}", metadata.authorization_endpoint, query.join("&"))
        }
    };
    redirect(&url, &[set_cookie(FLOW_COOKIE, &state)])
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

/// `/callback`: checks the state against this browser's sign-in, redeems
/// the code, verifies the identity token and calls userinfo.
async fn callback(
    State(demo): State<Arc<Demo>>,
    headers: HeaderMap,
    Query(q): Query<CallbackQuery>,
) -> Response {
    let state = q.state.unwrap_or_default();
    let ours = cookie(&headers, FLOW_COOKIE) == Some(state.as_str());
    let pending = if ours {
        demo.pending.lock().unwrap().remove(&state)
    } else {
        None
    };
    let Some(pending) = pending.filter(|p| p.started.elapsed() < PENDING_LIFETIME) else {
        return problem(
            StatusCode::BAD_REQUEST,
            "Sign-in not recognised",
            "The state doesn't match a sign-in started in this browser. Start again.",
        );
    };
    if let Some(error) = q.error {
        let detail = match q.error_description {
            Some(d) => format!("{error}: {d}"),
            None => error,
        };
        return problem(StatusCode::OK, "The server refused the sign-in", &detail);
    }
    let Some(code) = q.code else {
        return problem(
            StatusCode::BAD_REQUEST,
            "No code",
            "The callback has neither a code nor an error.",
        );
    };
    match complete(&demo, &code, &pending).await {
        Ok(signed) => {
            let id = random();
            demo.sessions
                .lock()
                .unwrap()
                .insert(id.clone(), Arc::new(signed));
            redirect(
                "/",
                &[clear_cookie(FLOW_COOKIE), set_cookie(SESSION_COOKIE, &id)],
            )
        }
        Err(e) => problem(StatusCode::BAD_GATEWAY, "Sign-in failed", &e),
    }
}

async fn complete(demo: &Demo, code: &str, pending: &Pending) -> Result<Signed, String> {
    let metadata = demo.metadata().await?;
    let token_response = token_request(
        demo,
        &metadata,
        vec![
            ("grant_type", "authorization_code".to_owned()),
            ("code", code.to_owned()),
            ("redirect_uri", demo.redirect_uri()),
            ("code_verifier", pending.verifier.clone()),
        ],
    )
    .await?;
    signed(demo, &metadata, token_response, Some(&pending.nonce), 0).await
}

/// A token request with the client's credentials; the JSON answer.
async fn token_request(
    demo: &Demo,
    metadata: &Metadata,
    form: Vec<(&str, String)>,
) -> Result<Map<String, Value>, String> {
    client_post(demo, &metadata.token_endpoint, form).await
}

/// A form POST with the client's credentials; the JSON answer.
async fn client_post(
    demo: &Demo,
    url: &str,
    mut form: Vec<(&str, String)>,
) -> Result<Map<String, Value>, String> {
    let mut request = demo.http.post(url);
    match &demo.config.client_secret {
        // RFC 6749 section 2.3.1: both parts form-encoded, then Basic.
        Some(secret) => {
            request =
                request.basic_auth(url_encode(&demo.config.client_id), Some(url_encode(secret)));
        }
        None => form.push(("client_id", demo.config.client_id.clone())),
    }
    let response = request
        .form(&form)
        .send()
        .await
        .map_err(|e| format!("{url}: {}", error_chain(&e)))?;
    let status = response.status();
    let body: Value = response
        .json()
        .await
        .map_err(|e| format!("{url}: {}", error_chain(&e)))?;
    let Value::Object(answer) = body else {
        return Err(format!(
            "{url} answered with something other than an object"
        ));
    };
    if !status.is_success() {
        return Err(format!(
            "{url} answered {status}: {}",
            Value::Object(answer)
        ));
    }
    Ok(answer)
}

/// Verifies the identity token (against `nonce` when the request sent one;
/// a refresh sends none) and calls userinfo with the new access token.
async fn signed(
    demo: &Demo,
    metadata: &Metadata,
    token_response: Map<String, Value>,
    nonce: Option<&str>,
    refreshes: u32,
) -> Result<Signed, String> {
    let text = |name: &str| {
        token_response
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| format!("the token response has no {name}"))
    };
    let id_token = text("id_token")?;
    let access_token = text("access_token")?;
    let refresh_token = text("refresh_token").ok();
    let id_claims = verify_id_token(demo, metadata, &id_token, nonce).await?;
    let access_claims = Jws::decode(&access_token).map(|jws| jws.payload);
    let userinfo = match &metadata.userinfo_endpoint {
        Some(url) => demo.get_json(url, Some(&access_token)).await,
        None => Err("the server has no userinfo endpoint".to_owned()),
    };
    Ok(Signed {
        id_token,
        id_claims,
        access_token,
        access_claims,
        token_response,
        userinfo,
        refresh_token,
        refreshes,
    })
}

/// `/refresh`: redeems the refresh token for new tokens.
async fn refresh(State(demo): State<Arc<Demo>>, headers: HeaderMap) -> Response {
    let Some(id) = cookie(&headers, SESSION_COOKIE).map(str::to_owned) else {
        return redirect("/", &[]);
    };
    let Some(current) = demo.sessions.lock().unwrap().get(&id).cloned() else {
        return redirect("/", &[]);
    };
    let Some(refresh_token) = current.refresh_token.clone() else {
        return problem(
            StatusCode::BAD_REQUEST,
            "No refresh token",
            "The sign-in didn't grant offline access.",
        );
    };
    let result = async {
        let metadata = demo.metadata().await?;
        let response = token_request(
            &demo,
            &metadata,
            vec![
                ("grant_type", "refresh_token".to_owned()),
                ("refresh_token", refresh_token.clone()),
            ],
        )
        .await?;
        let mut refreshed = signed(&demo, &metadata, response, None, current.refreshes + 1).await?;
        // A reused refresh token comes back in the response too; keep the
        // old one when the server sends none.
        refreshed.refresh_token = refreshed.refresh_token.or(Some(refresh_token));
        Ok::<Signed, String>(refreshed)
    }
    .await;
    match result {
        Ok(refreshed) => {
            demo.sessions
                .lock()
                .unwrap()
                .insert(id, Arc::new(refreshed));
            redirect("/", &[])
        }
        Err(e) => problem(StatusCode::BAD_GATEWAY, "Refreshing failed", &e),
    }
}

/// OpenID Connect Core 3.1.3.7: the signature with a key from the server's
/// JWKS, then `iss`, `aud`, `nonce` and `exp`.
async fn verify_id_token(
    demo: &Demo,
    metadata: &Metadata,
    token: &str,
    nonce: Option<&str>,
) -> Result<Map<String, Value>, String> {
    let jws = Jws::decode(token).ok_or("the id token is not a JWS")?;
    let jwks = demo.get_json(&metadata.jwks_uri, None).await?;
    let kid = jws.header_str("kid");
    let keys = jwks["keys"].as_array().ok_or("the JWKS has no keys")?;
    let verified = keys
        .iter()
        .filter(|k| kid.is_none() || k["kid"].as_str() == kid)
        .filter_map(|k| serde_json::from_value::<PublicJwk>(k.clone()).ok())
        .any(|key| jws.verify(&key));
    if !verified {
        return Err("the id token's signature doesn't verify with the server's keys".into());
    }
    let claims = jws.payload;
    if claims.get("iss").and_then(Value::as_str) != Some(metadata.issuer.as_str()) {
        return Err(format!(
            "the id token's issuer isn't {}: {:?}",
            metadata.issuer,
            claims.get("iss")
        ));
    }
    let client = demo.config.client_id.as_str();
    let audience_ok = match claims.get("aud") {
        Some(Value::String(aud)) => aud == client,
        Some(Value::Array(auds)) => auds.iter().any(|a| a.as_str() == Some(client)),
        _ => false,
    };
    if !audience_ok {
        return Err(format!("the id token isn't for {client}"));
    }
    if let Some(nonce) = nonce
        && claims.get("nonce").and_then(Value::as_str) != Some(nonce)
    {
        return Err("the id token's nonce isn't the one this sign-in sent".into());
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    match claims.get("exp").and_then(Value::as_i64) {
        Some(exp) if exp + 60 > now => Ok(claims),
        _ => Err("the id token has expired".into()),
    }
}

/// `/signout`: forgets this browser's tokens, then sends it to the server's
/// end session endpoint with the identity token as the hint, to come back
/// to `/signed-out`.
async fn signout(State(demo): State<Arc<Demo>>, headers: HeaderMap) -> Response {
    let signed =
        cookie(&headers, SESSION_COOKIE).and_then(|id| demo.sessions.lock().unwrap().remove(id));
    let clear = [clear_cookie(SESSION_COOKIE)];
    let (Some(signed), Ok(metadata)) = (signed, demo.metadata().await) else {
        return redirect("/", &clear);
    };
    let Some(end_session) = metadata.end_session_endpoint else {
        return redirect("/", &clear);
    };
    let separator = if end_session.contains('?') { '&' } else { '?' };
    let location = format!(
        "{end_session}{separator}id_token_hint={}&post_logout_redirect_uri={}&state={}",
        url_encode(&signed.id_token),
        url_encode(&format!("{}/signed-out", demo.config.public_url)),
        random(),
    );
    redirect(&location, &clear)
}

/// `/signed-out`: where the server sends the browser after logout.
async fn signed_out() -> Response {
    html::page(
        StatusCode::OK,
        "rustid demo",
        "<h1>Signed out</h1><p>You are signed out of the demo client and the server.</p>\
         <a class=\"button\" href=\"/login\">Sign in</a>",
    )
}

#[derive(Deserialize)]
struct FrontChannelQuery {
    sid: Option<String>,
    iss: Option<String>,
}

/// `/frontchannel-logout?sid=…&iss=…` (OpenID Connect Front-Channel Logout
/// 1.0): loaded in a hidden iframe when the person signs out at the server;
/// forgets every sign-in of that server session. The browser's cookies
/// aren't needed (nor sent, cross-site): `sid` and `iss` name the session.
async fn frontchannel_logout(
    State(demo): State<Arc<Demo>>,
    Query(q): Query<FrontChannelQuery>,
) -> Response {
    if let (Some(sid), Some(iss)) = (&q.sid, &q.iss) {
        let claim = |signed: &Signed, name: &str| {
            signed
                .id_claims
                .get(name)
                .and_then(Value::as_str)
                .map(str::to_owned)
        };
        demo.sessions.lock().unwrap().retain(|_, signed| {
            !(claim(signed, "sid").as_ref() == Some(sid)
                && claim(signed, "iss").as_ref() == Some(iss))
        });
    }
    (
        StatusCode::OK,
        [(axum::http::header::CACHE_CONTROL, "no-cache, no-store")],
        "",
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::utc;

    #[test]
    fn unix_times_are_shown_as_utc_dates() {
        assert_eq!(utc(0).unwrap(), "1970-01-01 00:00:00 UTC");
        assert_eq!(utc(1_790_723_492).unwrap(), "2026-09-29 23:11:32 UTC");
    }
}
