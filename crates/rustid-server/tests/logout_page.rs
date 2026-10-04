//! The reference UI's logout page: signs the browser out through the
//! interaction API, answering JSON as the scripted UI does, or a
//! signed-out page with the front-channel iframe in interactive mode.

use std::path::{Path, PathBuf};

use rustid_server::config::ServerConfig;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

async fn start(dir: &Path, interactive: bool) -> (String, tokio::sync::oneshot::Sender<()>) {
    let config = serde_json::json!({
        "signing_keys": [{ "kid": "k1", "alg": "RS256", "key_file": fixture("signing-key.pem") }],
        "clients_file": fixture("clients.json"),
        "resources_file": fixture("resources.json"),
        "protocol": { "key_management": { "enabled": false } },
        "reference_ui": {
            "enabled": true,
            "interactive": interactive,
            "users_file": fixture("users.json"),
        },
    });
    let path = dir.join("rustid.json");
    std::fs::write(&path, config.to_string()).unwrap();
    let config = ServerConfig::load(Some(&path)).unwrap();
    let app = rustid_server::build(&config).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(rustid_server::serve(listener, app, async move {
        let _ = stopped.await;
    }));
    (base, stop)
}

fn location(r: &reqwest::Response) -> String {
    r.headers()["location"].to_str().unwrap().to_owned()
}

fn browser() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .cookie_store(true)
        .build()
        .unwrap()
}

const AUTHORIZE: &str = "/connect/authorize?client_id=logout.front&redirect_uri=https%3A%2F%2Fclient.test%2Fcallback&response_type=code&scope=openid&state=s&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256";

/// Signs the default user in (non-interactive) and authorizes logout.front.
async fn signed_in(browser: &reqwest::Client, base: &str) {
    let authorize = browser
        .get(format!("{base}{AUTHORIZE}"))
        .send()
        .await
        .unwrap();
    let login = browser.get(location(&authorize)).send().await.unwrap();
    let continuation = browser.get(location(&login)).send().await.unwrap();
    let callback = browser
        .get(format!("{base}{}", location(&continuation)))
        .send()
        .await
        .unwrap();
    assert!(location(&callback).starts_with("https://client.test/callback?code="));
}

fn deletes(r: &reqwest::Response, name: &str) -> bool {
    r.headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|c| c.starts_with(&format!("{name}=")) && c.contains("expires="))
}

async fn is_signed_out(browser: &reqwest::Client, base: &str) -> bool {
    let r = browser
        .get(format!("{base}{AUTHORIZE}&prompt=none"))
        .send()
        .await
        .unwrap();
    location(&r).contains("error=login_required")
}

#[tokio::test]
async fn the_logout_page_signs_out_and_answers_the_context() {
    let dir = tempfile::tempdir().unwrap();
    let (base, _stop) = start(dir.path(), false).await;
    let browser = browser();
    signed_in(&browser, &base).await;
    let end = browser
        .get(format!("{base}/connect/endsession"))
        .send()
        .await
        .unwrap();
    assert_eq!(end.status(), 303);
    let page = browser.get(location(&end)).send().await.unwrap();
    assert_eq!(page.status(), 200);
    assert!(deletes(&page, "idsrv"));
    assert!(deletes(&page, "idsrv.session"));
    let body: serde_json::Value = page.json().await.unwrap();
    assert_eq!(body["clientId"], serde_json::Value::Null);
    assert_eq!(body["postLogoutRedirectUri"], serde_json::Value::Null);
    let iframe = body["signOutIFrameUrl"].as_str().unwrap();
    assert!(
        iframe.starts_with(&format!("{base}/connect/endsession/callback?endSessionId=")),
        "{iframe}"
    );
    assert!(is_signed_out(&browser, &base).await);
    let frames = browser
        .get(iframe)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        frames.contains("https://client.test/front?sid="),
        "{frames}"
    );
}

#[tokio::test]
async fn interactive_logout_asks_then_shows_the_signed_out_page() {
    let dir = tempfile::tempdir().unwrap();
    let (base, _stop) = start(dir.path(), true).await;
    let browser = browser();
    let authorize = browser
        .get(format!("{base}{AUTHORIZE}"))
        .send()
        .await
        .unwrap();
    let login_url = location(&authorize);
    let return_url = url::Url::parse(&login_url)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "ReturnUrl")
        .unwrap()
        .1
        .into_owned();
    let form = [
        ("returnUrl", return_url.as_str()),
        ("username", "alice"),
        ("password", "alice"),
    ];
    let submitted = browser.post(&login_url).form(&form).send().await.unwrap();
    let back = browser.get(location(&submitted)).send().await.unwrap();
    browser
        .get(format!("{base}{}", location(&back)))
        .send()
        .await
        .unwrap();

    let end = browser
        .get(format!("{base}/connect/endsession"))
        .send()
        .await
        .unwrap();
    let logout_url = location(&end);
    let prompt = browser.get(&logout_url).send().await.unwrap();
    assert_eq!(prompt.status(), 200);
    assert!(!deletes(&prompt, "idsrv"), "asking doesn't sign out");
    let html = prompt.text().await.unwrap();
    assert!(html.contains("<form method=\"post\""), "{html}");
    assert!(html.contains("name=\"logoutId\""), "{html}");
    assert!(!is_signed_out(&browser, &base).await);

    let logout_id = url::Url::parse(&logout_url)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "logoutId")
        .unwrap()
        .1
        .into_owned();
    let done = browser
        .post(&logout_url)
        .form(&[("logoutId", logout_id.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(done.status(), 200);
    assert!(deletes(&done, "idsrv"));
    let html = done.text().await.unwrap();
    assert!(html.contains("signed out"), "{html}");
    assert!(
        html.contains(&format!(
            "<iframe id=\"signout-iframe\" src=\"{base}/connect/endsession/callback?endSessionId="
        )),
        "{html}"
    );
    assert!(is_signed_out(&browser, &base).await);
}
