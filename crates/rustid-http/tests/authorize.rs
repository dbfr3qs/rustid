use std::path::{Path, PathBuf};

use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use http_body_util::BodyExt;
use rustid_core::clients::Clients;
use rustid_core::options::ProtocolOptions;
use rustid_core::resources::Resources;
use rustid_http::{AppState, InteractionState, ProtocolState};
use tower::ServiceExt;

const API_KEY: &str = "test-interaction-api-key";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

fn state(options: ProtocolOptions, path_base: Option<&str>) -> AppState {
    AppState::new(ProtocolState {
        options,
        keys: Default::default(),
        features: Default::default(),
        stores: rustid_store_memory::stores(
            Clients::load(&fixture("clients.json")).unwrap(),
            Resources::load(&fixture("resources.json")).unwrap(),
        ),
        events: Default::default(),
        path_base: path_base.map(str::to_owned),
        protected_resource: None,
        dcr: None,
        saml: Default::default(),
        interaction: InteractionState {
            api_keys: vec![API_KEY.to_owned()],
            supported_ui_cultures: vec!["en-US".to_owned(), "nb-NO".to_owned()],
            ..Default::default()
        },
    })
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Reply {
    fn location(&self) -> &str {
        self.headers["location"].to_str().unwrap()
    }

    /// The Set-Cookie values whose cookie has this name.
    fn cookies(&self, name: &str) -> Vec<String> {
        self.headers
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap().to_owned())
            .filter(|c| c.starts_with(&format!("{name}=")))
            .collect()
    }
}

async fn send_to(
    app: &AppState,
    method: Method,
    uri: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Reply {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "server");
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let response = rustid_http::router(app.clone())
        .oneshot(builder.body(Body::from(body.to_owned())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    Reply {
        status,
        headers,
        body: String::from_utf8(bytes.to_vec()).unwrap(),
    }
}

async fn get(uri: &str) -> Reply {
    send_to(&state(Default::default(), None), Method::GET, uri, &[], "").await
}

fn web_query(extra: &str) -> String {
    format!(
        "client_id=web&redirect_uri=https%3A%2F%2Fclient.test%2Fcallback&response_type=code&scope=openid&state=s1&code_challenge={CHALLENGE}&code_challenge_method=S256{extra}"
    )
}

#[tokio::test]
async fn anonymous_users_are_sent_to_login_with_the_request_as_return_url() {
    let r = get(&format!(
        "/connect/authorize?{}",
        web_query("&prompt=login")
    ))
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(
        r.location(),
        format!(
            "http://server/Account/Login?ReturnUrl=%2Fconnect%2Fauthorize%2Fcallback%3Fclient_id%3Dweb%26redirect_uri%3Dhttps%253A%252F%252Fclient.test%252Fcallback%26response_type%3Dcode%26scope%3Dopenid%26state%3Ds1%26code_challenge%3D{CHALLENGE}%26code_challenge_method%3DS256%26prompt%3Dlogin%26suppressed_prompt%3Dlogin"
        )
    );
    assert!(r.cookies(".AspNetCore.Culture").is_empty());
    assert!(!r.headers.contains_key("cache-control"));
    let binding = r.cookies("idsrv.interaction");
    assert_eq!(binding.len(), 1, "the browser is bound to the interaction");
    assert!(
        binding[0].ends_with("; path=/; samesite=none; httponly"),
        "{}",
        binding[0]
    );
}

#[tokio::test]
async fn the_return_url_carries_the_path_base() {
    let app = state(Default::default(), Some("/identity"));
    let r = send_to(
        &app,
        Method::GET,
        &format!("/identity/connect/authorize?{}", web_query("")),
        &[],
        "",
    )
    .await;
    assert!(
        r.location().starts_with("http://server/identity/Account/Login?ReturnUrl=%2Fidentity%2Fconnect%2Fauthorize%2Fcallback%3F"),
        "{}",
        r.location()
    );
}

#[tokio::test]
async fn post_needs_a_form_and_other_methods_are_refused() {
    let app = state(Default::default(), None);
    let form = ("content-type", "application/x-www-form-urlencoded");
    let r = send_to(
        &app,
        Method::POST,
        "/connect/authorize",
        &[form],
        &web_query(""),
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert!(
        r.location()
            .starts_with("http://server/Account/Login?ReturnUrl=")
    );
    let r = send_to(
        &app,
        Method::POST,
        "/connect/authorize",
        &[("content-type", "application/json")],
        "{}",
    )
    .await;
    assert_eq!(r.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let r = send_to(&app, Method::PUT, "/connect/authorize", &[], "").await;
    assert_eq!(r.status, StatusCode::METHOD_NOT_ALLOWED);
    let r = send_to(
        &app,
        Method::POST,
        "/connect/authorize/callback",
        &[form],
        &web_query(""),
    )
    .await;
    assert_eq!(r.status, StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn invalid_requests_go_to_the_error_page_whose_context_the_api_returns() {
    let app = state(Default::default(), None);
    // Display is read after the scope, so this error comes late.
    let too_long = "x".repeat(301);
    let r = send_to(
        &app,
        Method::GET,
        &format!(
            "/connect/authorize?{}",
            web_query(&format!(
                "&display=popup&ui_locales=nb-NO&acr_values={too_long}"
            ))
        ),
        &[],
        "",
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    let location = r.location().to_owned();
    let error_id = location
        .strip_prefix("http://server/home/error?errorId=")
        .unwrap_or_else(|| panic!("{location}"));
    assert_eq!(
        r.headers["set-cookie"],
        ".AspNetCore.Culture=c%3Dnb-NO%7Cuic%3Dnb-NO; path=/"
    );

    let context_uri = format!("/interaction/error?errorId={error_id}");
    let bearer = format!("Bearer {API_KEY}");
    let r = send_to(
        &app,
        Method::GET,
        &context_uri,
        &[("authorization", &bearer)],
        "",
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    let context: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(context["error"], "invalid_request");
    assert_eq!(context["errorDescription"], "Invalid acr_values");
    assert_eq!(context["clientId"], "web");
    assert_eq!(context["displayMode"], "popup");
    assert_eq!(context["uiLocales"], "nb-NO");
    assert_eq!(context["redirectUri"], serde_json::Value::Null);
    assert!(context["requestId"].is_string());

    for authorization in [None, Some("Bearer wrong-key-wrong-key"), Some(API_KEY)] {
        let headers: Vec<(&str, &str)> = authorization
            .map(|a| ("authorization", a))
            .into_iter()
            .collect();
        let r = send_to(&app, Method::GET, &context_uri, &headers, "").await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{authorization:?}");
        assert_eq!(r.headers["www-authenticate"], "Bearer");
    }
    let r = send_to(
        &app,
        Method::GET,
        "/interaction/error?errorId=garbage",
        &[("authorization", &bearer)],
        "",
    )
    .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let other_server = state(Default::default(), None);
    let r = send_to(
        &other_server,
        Method::GET,
        &context_uri,
        &[("authorization", &bearer)],
        "",
    )
    .await;
    assert_eq!(
        r.status,
        StatusCode::NOT_FOUND,
        "another key ring can't read the message"
    );
}

#[tokio::test]
async fn prompt_none_errors_return_to_the_client_in_the_requested_mode() {
    let r = get(&format!("/connect/authorize?{}", web_query("&prompt=none"))).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    let location = r.location();
    assert!(
        location.starts_with(
            "https://client.test/callback?error=login_required&state=s1&session_state="
        ) && location.ends_with("#_"),
        "{location}"
    );
    assert_eq!(r.headers["cache-control"], "no-store, no-cache, max-age=0");
    assert_eq!(r.headers["pragma"], "no-cache");

    let r = get(&format!(
        "/connect/authorize?{}",
        web_query("&prompt=none&response_mode=fragment")
    ))
    .await;
    assert!(
        r.location().starts_with(
            "https://client.test/callback#error=login_required&state=s1&session_state="
        )
    );
    assert!(!r.location().ends_with("#_"));

    // A repeated parameter is joined with commas.
    let r = get(&format!(
        "/connect/authorize?{}",
        web_query("&prompt=none&response_mode=form_post&state=%3Cb%3E")
    ))
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.headers["content-type"], "text/html; charset=UTF-8");
    let csp =
        "default-src 'none'; script-src 'sha256-orD0/VhH8hLqrLxKHD/HUEMdwqX6/0ve7c5hspX5VJ8='";
    assert_eq!(r.headers["content-security-policy"], csp);
    assert_eq!(r.headers["x-content-security-policy"], csp);
    assert_eq!(r.headers["referrer-policy"], "no-referrer");
    assert!(r.body.contains("<form method='post' action='https://client.test/callback'><input type='hidden' name='error' value='login_required' />\n<input type='hidden' name='state' value='s1,&lt;b&gt;' />\n<input type='hidden' name='session_state' value='"), "{}", r.body);
}

#[tokio::test]
async fn csp_level_one_allows_inline_script() {
    let mut options = ProtocolOptions::default();
    options.csp.level = rustid_core::options::CspLevel::One;
    options.csp.add_deprecated_header = false;
    let app = state(options, None);
    let r = send_to(
        &app,
        Method::GET,
        &format!(
            "/connect/authorize?{}",
            web_query("&prompt=none&response_mode=form_post")
        ),
        &[],
        "",
    )
    .await;
    assert_eq!(
        r.headers["content-security-policy"],
        "default-src 'none'; script-src 'unsafe-inline' 'sha256-orD0/VhH8hLqrLxKHD/HUEMdwqX6/0ve7c5hspX5VJ8='"
    );
    assert!(!r.headers.contains_key("x-content-security-policy"));
}

#[tokio::test]
async fn the_culture_cookie_names_the_first_supported_ui_locale() {
    let r = get(&format!(
        "/connect/authorize?{}",
        web_query("&ui_locales=fr-FR%20en-US%20nb-NO")
    ))
    .await;
    assert_eq!(
        r.headers["set-cookie"],
        ".AspNetCore.Culture=c%3Den-US%7Cuic%3Den-US; path=/"
    );
    let r = get(&format!(
        "/connect/authorize?{}",
        web_query("&ui_locales=en-us")
    ))
    .await;
    assert!(
        r.cookies(".AspNetCore.Culture").is_empty(),
        "names match exactly"
    );
}

#[tokio::test]
async fn prompt_create_goes_to_the_create_account_page_when_configured() {
    let mut options = ProtocolOptions::default();
    options.user_interaction.create_account_url = Some("https://ui.test/register".into());
    let app = state(options.finalize(), None);
    let r = send_to(
        &app,
        Method::GET,
        &format!(
            "/connect/authorize?{}",
            web_query("&prompt=create&ui_locales=en-US")
        ),
        &[],
        "",
    )
    .await;
    assert!(
        r.location().starts_with("https://ui.test/register?returnUrl=http%3A%2F%2Fserver%2Fconnect%2Fauthorize%2Fcallback%3F"),
        "an external page gets an absolute return URL: {}",
        r.location()
    );
    assert!(r.location().ends_with("suppressed_prompt%3Dcreate"));
    assert!(
        r.cookies(".AspNetCore.Culture").is_empty(),
        "no culture cookie for another site"
    );
}

#[tokio::test]
async fn a_disabled_authorize_endpoint_is_not_found() {
    let mut options = ProtocolOptions::default();
    options.endpoints.enable_authorize_endpoint = false;
    let app = state(options, None);
    for path in ["/connect/authorize", "/connect/authorize/callback"] {
        let r = send_to(
            &app,
            Method::GET,
            &format!("{path}?{}", web_query("")),
            &[],
            "",
        )
        .await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{path}");
    }
}

#[tokio::test]
async fn a_registered_redirect_uri_with_a_query_gets_the_error_appended() {
    let r = get("/connect/authorize?client_id=web.query&redirect_uri=HTTPS%3A%2F%2FCLIENT.TEST%2FCB%3FFOO%3DBAR&response_type=code&scope=openid&state=s1&prompt=none").await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    let location = r.location();
    assert!(
        location.starts_with(
            "HTTPS://CLIENT.TEST/CB?FOO=BAR&error=login_required&state=s1&session_state="
        ) && location.ends_with("#_"),
        "{location}"
    );
}
