//! The reference UI's interactive mode: the login page asks for a username
//! and password from the users file instead of signing the default user in.

use std::path::{Path, PathBuf};

use rustid_server::config::ServerConfig;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

async fn start(dir: &Path) -> (String, tokio::sync::oneshot::Sender<()>) {
    let config = serde_json::json!({
        "signing_keys": [{ "kid": "k1", "alg": "RS256", "key_file": fixture("signing-key.pem") }],
        "clients_file": fixture("clients.json"),
        "resources_file": fixture("resources.json"),
        "protocol": { "key_management": { "enabled": false } },
        "reference_ui": {
            "enabled": true,
            "interactive": true,
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

#[tokio::test]
async fn the_login_page_asks_for_a_password_and_signs_the_user_in() {
    let dir = tempfile::tempdir().unwrap();
    let (base, _stop) = start(dir.path()).await;
    let browser = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .cookie_store(true)
        .build()
        .unwrap();

    let authorize = browser
        .get(format!("{base}/connect/authorize?client_id=web&redirect_uri=https%3A%2F%2Fclient.test%2Fcallback&response_type=code&scope=openid%20profile&state=s&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256"))
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

    // The page is a form naming the client, with the return URL escaped.
    let page = browser.get(&login_url).send().await.unwrap();
    assert_eq!(page.status(), 200);
    assert_eq!(page.headers()["content-type"], "text/html; charset=utf-8");
    let html = page.text().await.unwrap();
    assert!(html.contains("<form method=\"post\""), "{html}");
    assert!(html.contains("name=\"password\""), "{html}");
    assert!(html.contains("web"), "the client id is shown: {html}");
    assert!(
        html.contains(&return_url.replace('&', "&amp;")),
        "the return URL is HTML-escaped: {html}"
    );

    let submit = |password: &'static str| {
        let form = [
            ("returnUrl", return_url.as_str()),
            ("username", "alice"),
            ("password", password),
        ];
        browser.post(&login_url).form(&form).send()
    };
    let wrong = submit("nope").await.unwrap();
    assert_eq!(wrong.status(), 200);
    let html = wrong.text().await.unwrap();
    assert!(html.contains("Invalid username or password"), "{html}");

    let right = submit("alice").await.unwrap();
    assert_eq!(right.status(), 302);
    let continuation = location(&right);
    assert!(
        continuation.starts_with(&format!("{base}/connect/interaction/continue?token=")),
        "{continuation}"
    );
    let back = browser.get(&continuation).send().await.unwrap();
    assert_eq!(location(&back), return_url);
    let callback = browser
        .get(format!("{base}{return_url}"))
        .send()
        .await
        .unwrap();
    assert!(location(&callback).starts_with("https://client.test/callback?code="));
}

#[tokio::test]
async fn the_error_page_is_html_in_interactive_mode() {
    let dir = tempfile::tempdir().unwrap();
    let (base, _stop) = start(dir.path()).await;
    let browser = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    // An unknown client ends on the error page, which reads as a page.
    let authorize = browser
        .get(format!(
            "{base}/connect/authorize?client_id=nobody&redirect_uri=https%3A%2F%2Fx&response_type=code&scope=openid"
        ))
        .send()
        .await
        .unwrap();
    let error_page = browser.get(location(&authorize)).send().await.unwrap();
    assert_eq!(error_page.status(), 200);
    assert_eq!(
        error_page.headers()["content-type"],
        "text/html; charset=utf-8"
    );
    let html = error_page.text().await.unwrap();
    assert!(html.contains("unauthorized_client"), "{html}");
}

#[tokio::test]
async fn in_interactive_mode_the_user_parameter_does_not_skip_the_password() {
    let dir = tempfile::tempdir().unwrap();
    let (base, _stop) = start(dir.path()).await;
    let browser = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .cookie_store(true)
        .build()
        .unwrap();
    let authorize = browser
        .get(format!("{base}/connect/authorize?client_id=web&redirect_uri=https%3A%2F%2Fclient.test%2Fcallback&response_type=code&scope=openid&state=s&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256"))
        .send()
        .await
        .unwrap();
    let page = browser
        .get(format!("{}&user=alice", location(&authorize)))
        .send()
        .await
        .unwrap();
    assert_eq!(page.status(), 200, "no sign-in without a password");
    let html = page.text().await.unwrap();
    assert!(html.contains("name=\"password\""), "{html}");
}
