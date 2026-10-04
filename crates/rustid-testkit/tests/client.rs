use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Redirect};
use axum::routing::{get, post};
use axum::{Form, Router};
use rustid_testkit::client::Client;
use rustid_testkit::recorded::Body;
use serde::Deserialize;
use tokio::net::TcpListener;

#[derive(Deserialize)]
struct Echo {
    grant_type: String,
}

async fn start_stub() -> String {
    let app = Router::new()
        .route(
            "/json",
            get(|| async { axum::Json(serde_json::json!({ "a": 1 })) }),
        )
        .route(
            "/badjson",
            get(|| async { ([(header::CONTENT_TYPE, "application/json")], "not json") }),
        )
        .route(
            "/redirect",
            get(|| async { Redirect::to("https://client.test/cb?code=abc") }),
        )
        .route("/empty", get(|| async { StatusCode::NO_CONTENT }))
        .route(
            "/form",
            post(|Form(echo): Form<Echo>| async move {
                axum::Json(serde_json::json!({ "grant_type": echo.grant_type }))
            }),
        )
        .route(
            "/host",
            get(|headers: axum::http::HeaderMap| async move {
                headers
                    .get(header::HOST)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_owned()
            })
            .post(|| async { StatusCode::ACCEPTED }),
        )
        .route(
            "/setcookie",
            get(|| async { ([(header::SET_COOKIE, "session=1; Path=/")], "ok").into_response() }),
        )
        .route(
            "/needcookie",
            get(|headers: axum::http::HeaderMap| async move {
                if headers.get(header::COOKIE).is_some() {
                    "with-cookie"
                } else {
                    "no-cookie"
                }
            }),
        );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

#[tokio::test]
async fn records_json_body_and_allowlisted_headers() {
    let base = start_stub().await;
    let client = Client::new().unwrap();
    let r = client.get(&format!("{base}/json")).await.unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(r.body, Body::Json(serde_json::json!({ "a": 1 })));
    assert_eq!(
        r.headers.get("content-type").map(String::as_str),
        Some("application/json")
    );
    assert!(
        r.headers
            .keys()
            .all(|k| rustid_testkit::recorded::RECORDED_HEADERS.contains(&k.as_str()))
    );
}

#[tokio::test]
async fn records_invalid_json_body_as_text() {
    let base = start_stub().await;
    let client = Client::new().unwrap();
    let r = client.get(&format!("{base}/badjson")).await.unwrap();
    assert_eq!(r.body, Body::Text("not json".to_owned()));
}

#[tokio::test]
async fn does_not_follow_redirects() {
    let base = start_stub().await;
    let client = Client::new().unwrap();
    let r = client.get(&format!("{base}/redirect")).await.unwrap();
    assert_eq!(r.status, 303);
    assert_eq!(
        r.headers.get("location").map(String::as_str),
        Some("https://client.test/cb?code=abc")
    );
    assert_eq!(r.body, Body::Empty);
}

#[tokio::test]
async fn records_empty_body() {
    let base = start_stub().await;
    let client = Client::new().unwrap();
    let r = client.get(&format!("{base}/empty")).await.unwrap();
    assert_eq!(r.status, 204);
    assert_eq!(r.body, Body::Empty);
}

#[tokio::test]
async fn posts_form_encoded_bodies() {
    let base = start_stub().await;
    let client = Client::new().unwrap();
    let r = client
        .post_form(
            &format!("{base}/form"),
            &[("grant_type", "client_credentials")],
        )
        .await
        .unwrap();
    assert_eq!(
        r.body,
        Body::Json(serde_json::json!({ "grant_type": "client_credentials" }))
    );
}

#[tokio::test]
async fn keeps_cookies_between_requests() {
    let base = start_stub().await;
    let client = Client::new().unwrap();
    client.get(&format!("{base}/setcookie")).await.unwrap();
    let r = client.get(&format!("{base}/needcookie")).await.unwrap();
    assert_eq!(r.body, Body::Text("with-cookie".to_owned()));
}

#[tokio::test]
async fn host_header_can_be_overridden_for_virtual_hosts() {
    let base = start_stub().await;
    let client = Client::new().unwrap();
    let r = client
        .get_with_host(&format!("{base}/host"), "xn--80af5akm.xn--p1ai")
        .await
        .unwrap();
    assert_eq!(r.body, Body::Text("xn--80af5akm.xn--p1ai".to_owned()));
}

#[tokio::test]
async fn post_empty_sends_a_bodyless_post() {
    let base = start_stub().await;
    let client = Client::new().unwrap();
    let r = client.post_empty(&format!("{base}/host")).await.unwrap();
    assert_eq!(r.status, 202);
}

#[tokio::test]
async fn send_supports_any_method_headers_and_raw_bodies() {
    let base = start_stub().await;
    let client = Client::new().unwrap();
    let r = client
        .send(
            reqwest::Method::GET,
            &format!("{base}/host"),
            &[("host", "virtual.test")],
            None,
        )
        .await
        .unwrap();
    assert_eq!(r.body, Body::Text("virtual.test".to_owned()));
    let r = client
        .send(
            reqwest::Method::POST,
            &format!("{base}/form"),
            &[],
            Some((
                "application/x-www-form-urlencoded",
                b"grant_type=x".to_vec(),
            )),
        )
        .await
        .unwrap();
    assert_eq!(r.body, Body::Json(serde_json::json!({ "grant_type": "x" })));
}
