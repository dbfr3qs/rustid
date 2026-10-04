//! A browser for the HTTP layer's tests: the app state over the shared
//! fixtures, cookies kept across requests, and signing in through the
//! interaction API.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use http_body_util::BodyExt;
use rustid_core::clients::Clients;
use rustid_core::resources::Resources;
use rustid_http::{AppState, InteractionState, ProtocolState};
use tower::ServiceExt;

pub const API_KEY: &str = "test-interaction-api-key";
pub const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

pub fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

pub fn state() -> AppState {
    state_with(Default::default())
}

pub fn signing_keys() -> rustid_core::key_service::KeyService {
    let key = rustid_core::keys::KeyConfig {
        kid: "k1".into(),
        alg: "RS256".into(),
        key_file: fixture("signing-key.pem"),
        cert_file: None,
    };
    rustid_core::key_service::KeyService::new(
        rustid_core::keys::KeyMaterial::load(&[key], &[]).unwrap(),
        None,
    )
}

pub fn state_with(options: rustid_core::options::ProtocolOptions) -> AppState {
    AppState::new(protocol_state_with(options))
}

/// The default state with dynamic client registration at `/connect/dcr`.
#[allow(dead_code)]
pub fn state_with_dcr(
    open: bool,
    initial_access_tokens: Vec<String>,
    client_management: bool,
) -> AppState {
    AppState::new(ProtocolState {
        dcr: Some(rustid_http::DcrSettings {
            path: "/connect/dcr".into(),
            open,
            initial_access_tokens,
            options: Default::default(),
            client_management,
        }),
        ..protocol_state_with(Default::default())
    })
}

pub fn protocol_state_with(options: rustid_core::options::ProtocolOptions) -> ProtocolState {
    ProtocolState {
        options: rustid_core::options::ProtocolOptions {
            issuer_uri: Some("https://idsrv.test".into()),
            ..options
        },
        keys: signing_keys(),
        features: Default::default(),
        stores: rustid_store_memory::stores(
            Clients::load(&fixture("clients.json")).unwrap(),
            Resources::load(&fixture("resources.json")).unwrap(),
        ),
        events: Default::default(),
        path_base: None,
        protected_resource: None,
        dcr: None,
        saml: Default::default(),
        interaction: InteractionState {
            api_keys: vec![API_KEY.to_owned()],
            ..Default::default()
        },
    }
}

pub struct Reply {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: String,
}

impl Reply {
    pub fn location(&self) -> String {
        self.headers["location"].to_str().unwrap().to_owned()
    }

    /// `name=value` for each cookie set, in order.
    pub fn set_cookies(&self) -> Vec<String> {
        self.headers
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap().to_owned())
            .collect()
    }

    pub fn cookie(&self, name: &str) -> Option<String> {
        self.set_cookies().iter().find_map(|c| {
            c.split(';')
                .next()?
                .strip_prefix(&format!("{name}="))
                .map(str::to_owned)
        })
    }
}

/// A browser: remembers cookies across requests.
pub struct Browser {
    pub app: AppState,
    pub cookies: Vec<(String, String)>,
    /// Requests arrive over TLS, as the server marks them.
    pub https: bool,
}

impl Browser {
    pub fn new(app: &AppState) -> Browser {
        Browser {
            app: app.clone(),
            cookies: Vec::new(),
            https: false,
        }
    }

    pub async fn send(
        &mut self,
        method: Method,
        uri: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> Reply {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("host", "server");
        if !self.cookies.is_empty() {
            let cookie: Vec<String> = self
                .cookies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect();
            builder = builder.header("cookie", cookie.join("; "));
        }
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        if self.https {
            builder = builder.extension(rustid_http::Https);
        }
        let response = rustid_http::router(self.app.clone())
            .oneshot(builder.body(Body::from(body.to_owned())).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let reply = Reply {
            status,
            headers,
            body: String::from_utf8(bytes.to_vec()).unwrap(),
        };
        for set in reply.set_cookies() {
            let pair = set.split(';').next().unwrap();
            let (name, value) = pair.split_once('=').unwrap();
            self.cookies.retain(|(k, _)| k != name);
            // A cookie expiring in the past deletes it; a later one persists.
            let expired = set
                .split(';')
                .filter_map(|a| a.trim().strip_prefix("expires="))
                .filter_map(|d| chrono::DateTime::parse_from_rfc2822(d).ok())
                .any(|d| d < chrono::Utc::now());
            if !expired {
                self.cookies.push((name.to_owned(), value.to_owned()));
            }
        }
        reply
    }

    pub async fn get(&mut self, uri: &str) -> Reply {
        self.send(Method::GET, uri, &[], "").await
    }

    pub fn drop_cookie(&mut self, name: &str) {
        self.cookies.retain(|(k, _)| k != name);
    }
}

pub fn authorize_uri(extra: &str) -> String {
    format!(
        "/connect/authorize?client_id=web&redirect_uri=https%3A%2F%2Fclient.test%2Fcallback&response_type=code&scope=openid%20api1&state=s1&code_challenge={CHALLENGE}&code_challenge_method=S256{extra}"
    )
}

/// The return URL the login page was given.
pub fn return_url(login_location: &str) -> String {
    let url = url::Url::parse(login_location).unwrap();
    url.query_pairs()
        .find(|(k, _)| k == "ReturnUrl")
        .map(|(_, v)| v.into_owned())
        .unwrap()
}

pub async fn login_call(browser: &mut Browser, return_url: &str, subject: &str) -> Reply {
    let body = serde_json::json!({
        "returnUrl": return_url,
        "subjectId": subject,
        "claims": [{ "type": "name", "value": "Alice" }],
    })
    .to_string();
    let bearer = format!("Bearer {API_KEY}");
    // The UI calls the API itself, without the browser's cookies.
    let mut ui = Browser::new(&browser.app);
    ui.https = browser.https;
    ui.send(
        Method::POST,
        "/interaction/login",
        &[
            ("authorization", &bearer),
            ("content-type", "application/json"),
        ],
        &body,
    )
    .await
}

/// Starts an authorize request (with `prompt=login`, so a signed-in
/// browser sees the login page too), logs `subject` in through the API and
/// the continuation, and returns the callback URL.
pub async fn sign_in(browser: &mut Browser, subject: &str) -> String {
    let login = browser.get(&authorize_uri("&prompt=login")).await;
    let return_url = return_url(&login.location());
    let api = login_call(browser, &return_url, subject).await;
    assert_eq!(api.status, StatusCode::OK, "{}", api.body);
    let continue_url: serde_json::Value = serde_json::from_str(&api.body).unwrap();
    let continue_url = continue_url["continueUrl"].as_str().unwrap().to_owned();
    let path = continue_url
        .strip_prefix("http://server")
        .unwrap()
        .to_owned();
    let signed_in = browser.get(&path).await;
    assert_eq!(signed_in.status, StatusCode::FOUND, "{}", signed_in.body);
    assert_eq!(signed_in.location(), return_url);
    return_url
}
