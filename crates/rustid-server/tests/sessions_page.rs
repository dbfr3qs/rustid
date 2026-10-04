//! The interactive reference UI with server-side sessions: "Remember me"
//! makes a persistent cookie, and `/sessions` lists the signed-in user's
//! sessions with a way to end each.

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
        "server_side_sessions": { "enabled": true },
        "protocol": { "key_management": { "enabled": false } },
        "reference_ui": {
            "enabled": true,
            "interactive": true,
            "users_file": fixture("users.json"),
        },
    });
    let path = dir.join("rustid.json");
    std::fs::write(&path, config.to_string()).unwrap();
    let app = rustid_server::build(&ServerConfig::load(Some(&path)).unwrap())
        .await
        .unwrap();
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

const AUTHORIZE: &str = "/connect/authorize?client_id=web&redirect_uri=https%3A%2F%2Fclient.test%2Fcallback&response_type=code&scope=openid&state=s&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256";

/// Signs alice in through the form; the continuation's `idsrv` cookie.
async fn sign_in(browser: &reqwest::Client, base: &str, remember: bool) -> String {
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
    let mut form = vec![
        ("returnUrl", return_url.as_str()),
        ("username", "alice"),
        ("password", "alice"),
    ];
    if remember {
        form.push(("remember", "yes"));
    }
    let submitted = browser.post(&login_url).form(&form).send().await.unwrap();
    let continued = browser.get(location(&submitted)).send().await.unwrap();
    let cookie = continued
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|c| c.starts_with("idsrv="))
        .unwrap()
        .to_owned();
    browser
        .get(format!("{base}{}", location(&continued)))
        .send()
        .await
        .unwrap();
    cookie
}

fn browser() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .cookie_store(true)
        .build()
        .unwrap()
}

#[tokio::test]
async fn remember_me_makes_the_cookie_persistent() {
    let dir = tempfile::tempdir().unwrap();
    let (base, _stop) = start(dir.path()).await;
    let page = browser()
        .get(format!("{base}{AUTHORIZE}"))
        .send()
        .await
        .unwrap();
    let form = browser().get(location(&page)).send().await.unwrap();
    let html = form.text().await.unwrap();
    assert!(html.contains("name=\"remember\""), "{html}");
    assert!(
        sign_in(&browser(), &base, true)
            .await
            .contains("; expires=")
    );
    assert!(!sign_in(&browser(), &base, false).await.contains("expires="));
}

#[tokio::test]
async fn the_sessions_page_lists_and_ends_the_users_sessions() {
    let dir = tempfile::tempdir().unwrap();
    let (base, _stop) = start(dir.path()).await;
    let anonymous = browser()
        .get(format!("{base}/sessions"))
        .send()
        .await
        .unwrap();
    assert_eq!(anonymous.status(), 200);
    assert!(anonymous.text().await.unwrap().contains("not signed in"));

    let laptop = browser();
    sign_in(&laptop, &base, false).await;
    let phone = browser();
    sign_in(&phone, &base, true).await;
    let page = laptop.get(format!("{base}/sessions")).send().await.unwrap();
    let html = page.text().await.unwrap();
    assert_eq!(html.matches("name=\"sessionId\"").count(), 2, "{html}");
    assert!(html.contains("This browser"), "{html}");

    // End the phone's session from the laptop.
    let phone_row = html
        .split("<form")
        .find(|f| f.contains("name=\"sessionId\"") && !f.contains("This browser"))
        .unwrap();
    let session_id = phone_row
        .split("name=\"sessionId\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    let ended = laptop
        .post(format!("{base}/sessions"))
        .form(&[("sessionId", session_id)])
        .send()
        .await
        .unwrap();
    assert_eq!(ended.status(), 303);
    let silent = phone
        .get(format!("{base}{AUTHORIZE}&prompt=none"))
        .send()
        .await
        .unwrap();
    assert!(location(&silent).contains("error=login_required"));
    let html = laptop
        .get(format!("{base}/sessions"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(html.matches("name=\"sessionId\"").count(), 1, "{html}");

    // Someone else's session id changes nothing.
    let r = laptop
        .post(format!("{base}/sessions"))
        .form(&[("sessionId", "not-mine")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 303);
    let silent = laptop
        .get(format!("{base}{AUTHORIZE}&prompt=none"))
        .send()
        .await
        .unwrap();
    assert!(location(&silent).contains("code="));
}

/// The CIBA page tells a signed-out visitor to sign in first, rather than
/// that nothing is waiting for them.
#[tokio::test]
async fn the_ciba_page_says_when_no_one_is_signed_in() {
    let dir = tempfile::tempdir().unwrap();
    let (base, _stop) = start(dir.path()).await;
    let anonymous = browser().get(format!("{base}/ciba")).send().await.unwrap();
    assert_eq!(anonymous.status(), 200);
    let html = anonymous.text().await.unwrap();
    assert!(html.contains("not signed in"), "{html}");
    assert!(!html.contains("No application is waiting"), "{html}");

    let alice = browser();
    sign_in(&alice, &base, false).await;
    let html = alice
        .get(format!("{base}/ciba"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(html.contains("No application is waiting"), "{html}");
}
