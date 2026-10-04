//! The reference UI's pages call the interaction API over loopback HTTP.

use rustid_testkit::profile_config;
use rustid_testkit::server::TestServer;

#[tokio::test]
async fn the_error_page_reads_the_error_context_through_the_api() {
    let mut config = profile_config("default");
    config.reference_ui.enabled = true;
    let server = TestServer::spawn(config).await.unwrap();
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let response = client
        .get(server.url("/connect/authorize?client_id=nope&ui_locales=nb-NO"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 303);
    let location = response.headers()["location"].to_str().unwrap().to_owned();
    assert!(
        location.starts_with(&server.url("/home/error?errorId=")),
        "{location}"
    );

    let page = client.get(&location).send().await.unwrap();
    assert_eq!(page.status(), 200);
    assert_eq!(
        page.headers()["content-type"],
        "application/json; charset=utf-8"
    );
    let body: serde_json::Value = page.json().await.unwrap();
    assert_eq!(body["error"], "unauthorized_client");
    assert_eq!(
        body["errorDescription"],
        "Unknown client or client not enabled"
    );
    assert_eq!(body["clientId"], "nope");
    assert_eq!(body["uiLocales"], "nb-NO");

    let missing = client
        .get(server.url("/home/error?errorId=nope"))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 404);
    let body: serde_json::Value = missing.json().await.unwrap();
    assert_eq!(body, serde_json::json!({ "error": "unknown_error_id" }));

    // The API itself refuses callers without the reference UI's key.
    let api = client
        .get(server.url("/interaction/error?errorId=x"))
        .send()
        .await
        .unwrap();
    assert_eq!(api.status(), 401);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn the_reference_ui_is_absent_unless_enabled() {
    let mut config = profile_config("default");
    config.reference_ui.enabled = false;
    let server = TestServer::spawn(config).await.unwrap();
    let page = reqwest::get(server.url("/home/error?errorId=x"))
        .await
        .unwrap();
    assert_eq!(page.status(), 404);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn the_login_page_signs_the_user_in_through_the_api() {
    let mut config = profile_config("default");
    config.reference_ui.enabled = true;
    let server = TestServer::spawn(config).await.unwrap();
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .cookie_store(true)
        .build()
        .unwrap();
    let authorize = server.url(
        "/connect/authorize?client_id=web&redirect_uri=https%3A%2F%2Fclient.test%2Fcallback\
         &response_type=code&scope=openid&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM\
         &code_challenge_method=S256",
    );
    let login = client.get(&authorize).send().await.unwrap();
    let login_url = login.headers()["location"].to_str().unwrap().to_owned();
    assert!(login_url.starts_with(&server.url("/Account/Login?ReturnUrl=")));

    let context_url = login_url.replace("/Account/Login?", "/account/login/context?");
    let context: serde_json::Value = client
        .get(&context_url)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(context["clientId"], "web");

    let unknown = client
        .get(format!("{login_url}&user=nobody"))
        .send()
        .await
        .unwrap();
    assert_eq!(unknown.status(), 400);

    let page = client.get(&login_url).send().await.unwrap();
    assert_eq!(page.status(), 302);
    let continue_url = page.headers()["location"].to_str().unwrap().to_owned();
    assert!(
        continue_url.starts_with(&server.url("/connect/interaction/continue?token=")),
        "{continue_url}"
    );
    let signed_in = client.get(&continue_url).send().await.unwrap();
    assert_eq!(signed_in.status(), 302);
    let callback = signed_in.headers()["location"].to_str().unwrap().to_owned();
    assert!(callback.starts_with("/connect/authorize/callback?"));
    let code = client.get(server.url(&callback)).send().await.unwrap();
    assert_eq!(code.status(), 303);
    assert!(
        code.headers()["location"]
            .to_str()
            .unwrap()
            .starts_with("https://client.test/callback?code=")
    );
    server.shutdown().await.unwrap();
}
