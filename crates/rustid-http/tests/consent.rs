//! The consent page's API and the authorize callback applying its answer.

mod browser;

use axum::http::{Method, StatusCode};
use browser::*;

fn consent_uri(scope: &str, extra: &str) -> String {
    format!(
        "/connect/authorize?client_id=web-consent&redirect_uri=https%3A%2F%2Fclient.test%2Fcallback&response_type=code&scope={scope}&state=s1&nonce=n1&code_challenge={CHALLENGE}&code_challenge_method=S256{extra}"
    )
}

/// Signs subject 1 in and requests `scope` from the consent client; returns
/// the return URL the consent page was given.
async fn at_consent_page(browser: &mut Browser, scope: &str) -> String {
    sign_in(browser, "1").await;
    let r = browser.get(&consent_uri(scope, "")).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    let location = r.location();
    assert!(
        location.starts_with("http://server/consent?returnUrl="),
        "{location}"
    );
    return_url_from(&location, "returnUrl")
}

fn return_url_from(location: &str, parameter: &str) -> String {
    url::Url::parse(location)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == parameter)
        .unwrap()
        .1
        .into_owned()
}

async fn api(browser: &Browser, method: Method, path: &str, body: serde_json::Value) -> Reply {
    let mut ui = Browser::new(&browser.app);
    let bearer = format!("Bearer {API_KEY}");
    let body = if method == Method::GET {
        String::new()
    } else {
        body.to_string()
    };
    ui.send(
        method,
        path,
        &[
            ("authorization", &bearer),
            ("content-type", "application/json"),
        ],
        &body,
    )
    .await
}

fn query_of(location: &str) -> Vec<(String, String)> {
    let url = url::Url::parse(location).unwrap();
    url.query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

#[tokio::test]
async fn the_consent_context_describes_the_client_and_scopes() {
    let app = state();
    let mut browser = Browser::new(&app);
    let return_url = at_consent_page(&mut browser, "openid%20profile%20api1").await;
    let r = api(
        &browser,
        Method::GET,
        &format!(
            "/interaction/consent?returnUrl={}",
            urlencoding(&return_url)
        ),
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let context: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(context["clientId"], "web-consent");
    assert_eq!(context["clientName"], "Web client with consent");
    assert_eq!(context["allowRememberConsent"], true);
    assert_eq!(
        context["scopes"],
        serde_json::json!(["openid", "profile", "api1"])
    );
    assert_eq!(context["identityScopes"][0]["name"], "openid");
    assert_eq!(context["identityScopes"][0]["required"], true);
    assert_eq!(context["identityScopes"][1]["displayName"], "User profile");
    assert_eq!(context["identityScopes"][1]["emphasize"], true);
    assert_eq!(context["apiScopes"][0]["name"], "api1");
    assert_eq!(context["apiScopes"][0]["displayName"], "API 1");

    let r = api(
        &browser,
        Method::GET,
        "/interaction/consent?returnUrl=%2Fconnect%2Ftoken",
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_granted_subset_is_applied_once_by_the_callback() {
    let app = state();
    let mut browser = Browser::new(&app);
    let return_url = at_consent_page(&mut browser, "openid%20profile%20api1").await;
    let r = api(
        &browser,
        Method::POST,
        "/interaction/consent",
        serde_json::json!({
            "returnUrl": return_url,
            "subjectId": "1",
            "scopes": ["openid", "api1"],
            "description": "demo",
        }),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let redirect: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(
        redirect["redirectUrl"],
        format!("http://server{return_url}")
    );

    // The callback issues a code for the granted scopes.
    let callback = browser.get(&return_url).await;
    assert_eq!(callback.status, StatusCode::SEE_OTHER, "{}", callback.body);
    let location = callback.location();
    assert!(
        location.starts_with("https://client.test/callback?code="),
        "{location}"
    );
    // Taken: the next callback shows the consent page again.
    let again = browser.get(&return_url).await;
    assert!(
        again.location().starts_with("http://server/consent?"),
        "{}",
        again.location()
    );
}

#[tokio::test]
async fn refusals_and_missing_required_scopes_reach_the_client() {
    let app = state();
    let mut browser = Browser::new(&app);
    let return_url = at_consent_page(&mut browser, "openid%20api1").await;
    for (body, error, description) in [
        (
            serde_json::json!({ "returnUrl": return_url, "subjectId": "1", "scopes": ["api1"] }),
            "access_denied",
            None,
        ),
        (
            serde_json::json!({
                "returnUrl": return_url,
                "subjectId": "1",
                "error": "temporarily_unavailable",
                "errorDescription": "some description",
            }),
            "temporarily_unavailable",
            Some("some description"),
        ),
    ] {
        let r = api(&browser, Method::POST, "/interaction/consent", body).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.body);
        let callback = browser.get(&return_url).await;
        let query = query_of(&callback.location());
        assert!(
            query.contains(&("error".to_owned(), error.to_owned())),
            "{query:?}"
        );
        assert_eq!(
            query
                .iter()
                .find(|(k, _)| k == "error_description")
                .map(|(_, v)| v.as_str()),
            description
        );
        assert!(query.contains(&("state".to_owned(), "s1".to_owned())));
    }
}

#[tokio::test]
async fn a_consent_for_another_subject_or_changed_request_is_not_applied() {
    let app = state();
    let mut browser = Browser::new(&app);
    let return_url = at_consent_page(&mut browser, "openid%20api1").await;
    let r = api(
        &browser,
        Method::POST,
        "/interaction/consent",
        serde_json::json!({ "returnUrl": return_url, "subjectId": "2", "scopes": ["openid", "api1"] }),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    let callback = browser.get(&return_url).await;
    assert!(callback.location().starts_with("http://server/consent?"));

    let r = api(
        &browser,
        Method::POST,
        "/interaction/consent",
        serde_json::json!({ "returnUrl": return_url, "subjectId": "1", "scopes": ["openid", "api1"] }),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    let tampered = return_url.replace("scope=openid%20api1", "scope=openid");
    assert_ne!(tampered, return_url);
    let callback = browser.get(&tampered).await;
    assert!(
        callback.location().starts_with("http://server/consent?"),
        "{}",
        callback.location()
    );
}

#[tokio::test]
async fn deny_answers_the_client_without_a_login() {
    let app = state();
    let mut browser = Browser::new(&app);
    let login = browser.get(&authorize_uri("")).await;
    let return_url = return_url(&login.location());
    let r = api(
        &browser,
        Method::POST,
        "/interaction/deny",
        serde_json::json!({ "returnUrl": return_url }),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let callback = browser.get(&return_url).await;
    let query = query_of(&callback.location());
    assert!(
        query.contains(&("error".to_owned(), "access_denied".to_owned())),
        "{query:?}"
    );
}

#[tokio::test]
async fn the_consent_and_deny_apis_check_key_body_and_return_url() {
    let app = state();
    let browser = Browser::new(&app);
    let mut anonymous = Browser::new(&app);
    let r = anonymous
        .send(
            Method::POST,
            "/interaction/consent",
            &[("content-type", "application/json")],
            "{}",
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    for (path, body, error) in [
        (
            "/interaction/consent",
            serde_json::json!({ "returnUrl": "/connect/token", "subjectId": "1", "scopes": ["openid"] }),
            "invalid_return_url",
        ),
        (
            "/interaction/consent",
            serde_json::json!({ "returnUrl": consent_uri("openid", ""), "scopes": ["openid"] }),
            "invalid_subject",
        ),
        (
            "/interaction/consent",
            serde_json::json!({ "returnUrl": consent_uri("openid", ""), "subjectId": "1", "error": "nope" }),
            "invalid_error",
        ),
        (
            "/interaction/consent",
            serde_json::json!({ "returnUrl": consent_uri("openid", ""), "subjectId": "1", "extra": 1 }),
            "invalid_body",
        ),
        (
            "/interaction/deny",
            serde_json::json!({ "returnUrl": "https://evil.test/connect/authorize" }),
            "invalid_return_url",
        ),
    ] {
        let r = api(&browser, Method::POST, path, body).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{path}: {}", r.body);
        let answer: serde_json::Value = serde_json::from_str(&r.body).unwrap();
        assert_eq!(answer["error"], error, "{path}");
    }
}

#[tokio::test]
async fn the_session_call_reads_the_forwarded_cookie() {
    let app = state();
    let mut browser = Browser::new(&app);
    let bearer = format!("Bearer {API_KEY}");
    let r = browser
        .send(
            Method::GET,
            "/interaction/session",
            &[("authorization", &bearer)],
            "",
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    sign_in(&mut browser, "1").await;
    let r = browser
        .send(
            Method::GET,
            "/interaction/session",
            &[("authorization", &bearer)],
            "",
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let session: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(session["subjectId"], "1");
    assert_eq!(session["sessionId"].as_str().unwrap().len(), 32);
    assert_eq!(session["idp"], "local");
}

fn urlencoding(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

#[tokio::test]
async fn a_signed_in_browser_denying_a_forced_login_reaches_the_client() {
    // The UI forwards the browser's cookies and names no subject, as the
    // reference UI's Cancel button does: the session's subject is used, as
    // grant consent falls back to the current user.
    let app = state();
    let mut browser = Browser::new(&app);
    sign_in(&mut browser, "1").await;
    let login = browser.get(&authorize_uri("&prompt=login")).await;
    let return_url = return_url(&login.location());
    let cookie: Vec<String> = browser
        .cookies
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    let bearer = format!("Bearer {API_KEY}");
    let mut ui = Browser::new(&app);
    let r = ui
        .send(
            Method::POST,
            "/interaction/deny",
            &[
                ("authorization", &bearer),
                ("content-type", "application/json"),
                ("cookie", &cookie.join("; ")),
            ],
            &serde_json::json!({ "returnUrl": return_url }).to_string(),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let callback = browser.get(&return_url).await;
    let query = query_of(&callback.location());
    assert!(
        query.contains(&("error".to_owned(), "access_denied".to_owned())),
        "{}",
        callback.location()
    );
}
