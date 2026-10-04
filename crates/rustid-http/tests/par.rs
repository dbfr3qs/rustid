//! `POST /connect/par`, and the authorize endpoint using what was pushed.

mod browser;

use axum::http::{Method, StatusCode};
use browser::*;

const FORM: (&str, &str) = ("content-type", "application/x-www-form-urlencoded");

fn pushed() -> String {
    format!(
        "client_id=web&redirect_uri=https%3A%2F%2Fclient.test%2Fcallback&response_type=code&scope=openid%20api1&state=pushed&code_challenge={CHALLENGE}&code_challenge_method=S256"
    )
}

#[tokio::test]
async fn a_pushed_request_is_used_once() {
    let app = state();
    let mut browser = Browser::new(&app);
    let r = browser
        .send(Method::POST, "/connect/par", &[FORM], &pushed())
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    assert_eq!(r.headers["cache-control"], "no-store, no-cache, max-age=0");
    let body: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(body["expires_in"], 600);
    let request_uri = body["request_uri"].as_str().unwrap().to_owned();
    let authorize = format!(
        "/connect/authorize?client_id=web&request_uri={}",
        url::form_urlencoded::byte_serialize(request_uri.as_bytes()).collect::<String>()
    );

    // The login page's return URL names the pushed request.
    let login = browser.get(&authorize).await;
    let return_url = return_url(&login.location());
    assert!(
        return_url.starts_with(
            "/connect/authorize/callback?request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3A"
        ),
        "{return_url}"
    );
    login_call(&mut browser, &return_url, "1").await;
    sign_in(&mut browser, "1").await;
    let callback = browser.get(&return_url).await;
    let location = callback.location();
    assert!(
        location.starts_with("https://client.test/callback?code="),
        "{location}"
    );
    assert!(location.contains("state=pushed"), "{location}");

    // Consumed: the same request_uri now fails.
    let again = browser.get(&authorize).await;
    assert!(
        again.location().contains("/home/error?errorId="),
        "{}",
        again.location()
    );
}

#[tokio::test]
async fn the_par_endpoint_refuses_other_methods_request_uris_and_invalid_parameters() {
    let app = state();
    let mut browser = Browser::new(&app);
    assert_eq!(
        browser.get("/connect/par").await.status,
        StatusCode::METHOD_NOT_ALLOWED
    );
    for (form, error, description) in [
        (
            format!("{}&request_uri=https%3A%2F%2Fx", pushed()),
            "invalid_request",
            Some("Pushed authorization cannot use request_uri"),
        ),
        (
            pushed().replace("client.test%2Fcallback", "evil.test%2Fcb"),
            "invalid_request",
            Some("Invalid redirect_uri"),
        ),
        (
            "client_id=nobody&response_type=code".to_owned(),
            "invalid_client",
            None,
        ),
    ] {
        let r = browser
            .send(Method::POST, "/connect/par", &[FORM], &form)
            .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{form}");
        let body: serde_json::Value = serde_json::from_str(&r.body).unwrap();
        assert_eq!(body["error"], error, "{form}");
        assert_eq!(body["error_description"].as_str(), description, "{form}");
    }
}

#[tokio::test]
async fn an_error_answer_consumes_the_pushed_request_too() {
    let app = state();
    let mut browser = Browser::new(&app);
    let r = browser
        .send(Method::POST, "/connect/par", &[FORM], &pushed())
        .await;
    let body: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    let request_uri: String =
        url::form_urlencoded::byte_serialize(body["request_uri"].as_str().unwrap().as_bytes())
            .collect();
    // Another client's use is an error answer...
    let wrong = browser
        .get(&format!(
            "/connect/authorize?client_id=spa&request_uri={request_uri}"
        ))
        .await;
    assert!(
        wrong.location().contains("/home/error?errorId="),
        "{}",
        wrong.location()
    );
    // ...which consumed it: its own client can't use it any more.
    let again = browser
        .get(&format!(
            "/connect/authorize?client_id=web&request_uri={request_uri}"
        ))
        .await;
    let error_id = url::Url::parse(&again.location())
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "errorId")
        .unwrap()
        .1
        .into_owned();
    let bearer = format!("Bearer {API_KEY}");
    let context = browser
        .send(
            Method::GET,
            &format!("/interaction/error?errorId={error_id}"),
            &[("authorization", &bearer)],
            "",
        )
        .await;
    assert!(
        context.body.contains("invalid or reused PAR request uri"),
        "{}",
        context.body
    );
}
