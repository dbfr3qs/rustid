//! Hooks configured in the server: the profile claims hook supplies the
//! identity token's claims, and the subject active hook can send a
//! signed-in user back to the login page.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rustid_server::config::ServerConfig;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

/// A hook receiver answering profile claims and activity; returns its base
/// URL and the callers it saw.
async fn receiver(active: bool) -> (String, Arc<Mutex<Vec<String>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    let app = axum::Router::new()
        .route(
            "/profile",
            axum::routing::post(move |body: String| {
                let log = log.clone();
                async move {
                    let request: serde_json::Value = serde_json::from_str(&body).unwrap();
                    log.lock()
                        .unwrap()
                        .push(request["caller"].as_str().unwrap().to_owned());
                    axum::Json(serde_json::json!({
                        "version": 1,
                        "claims": [{ "type": "name", "value": "Hooked Name" }],
                    }))
                }
            }),
        )
        .route(
            "/active",
            axum::routing::post(move || async move {
                axum::Json(serde_json::json!({ "version": 1, "active": active }))
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await });
    (base, seen)
}

async fn start(hooks: &str, dir: &Path) -> String {
    let config = serde_json::json!({
        "signing_keys": [{ "kid": "k1", "alg": "RS256", "key_file": fixture("signing-key.pem") }],
        "clients_file": fixture("clients.json"),
        "resources_file": fixture("resources.json"),
        "protocol": { "key_management": { "enabled": false } },
        "reference_ui": { "enabled": true, "users_file": fixture("users.json") },
        "hooks": {
            "profile_claims": { "url": format!("{hooks}/profile") },
            "subject_active": { "url": format!("{hooks}/active"), "failure_policy": "fail_closed" },
        },
    });
    let path = dir.join("rustid.json");
    std::fs::write(&path, config.to_string()).unwrap();
    let config = ServerConfig::load(Some(&path)).unwrap();
    let app = rustid_server::build(&config).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(rustid_server::serve(listener, app, std::future::pending()));
    base
}

const IMPLICIT: &str = "/connect/authorize?client_id=spa&redirect_uri=https%3A%2F%2Fspa.test%2Fcb&response_type=id_token&scope=openid%20profile&state=s&nonce=n";

fn browser() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .cookie_store(true)
        .build()
        .unwrap()
}

/// Follows redirects until one leaves the server; returns that location.
async fn follow(browser: &reqwest::Client, base: &str, path: &str) -> String {
    let mut url = format!("{base}{path}");
    loop {
        let r = browser.get(&url).send().await.unwrap();
        let location = r.headers()["location"].to_str().unwrap().to_owned();
        if !location.starts_with('/') && !location.starts_with(base) {
            return location;
        }
        url = if location.starts_with('/') {
            format!("{base}{location}")
        } else {
            location
        };
    }
}

#[tokio::test]
async fn the_profile_hook_supplies_identity_token_claims() {
    let dir = tempfile::tempdir().unwrap();
    let (hooks, seen) = receiver(true).await;
    let base = start(&hooks, dir.path()).await;
    let callback = follow(&browser(), &base, IMPLICIT).await;
    let fragment = url::Url::parse(&callback).unwrap();
    let id_token = url::form_urlencoded::parse(fragment.fragment().unwrap().as_bytes())
        .find(|(k, _)| k == "id_token")
        .unwrap()
        .1
        .into_owned();
    let jws = rustid_core::jwt::Jws::decode(&id_token).unwrap();
    assert_eq!(jws.payload["name"], "Hooked Name");
    assert_eq!(
        seen.lock().unwrap().as_slice(),
        ["ClaimsProviderIdentityToken"]
    );
}

#[tokio::test]
async fn an_inactive_subject_is_sent_to_log_in_again() {
    let dir = tempfile::tempdir().unwrap();
    let (hooks, _) = receiver(false).await;
    let base = start(&hooks, dir.path()).await;
    let browser = browser();
    // The reference UI signs alice in, but the hook says she is inactive,
    // so the callback sends the browser to the login page again.
    let r = browser
        .get(format!("{base}{IMPLICIT}"))
        .send()
        .await
        .unwrap();
    let login = r.headers()["location"].to_str().unwrap().to_owned();
    let r = browser.get(&login).send().await.unwrap();
    let continuation = r.headers()["location"].to_str().unwrap().to_owned();
    let r = browser.get(&continuation).send().await.unwrap();
    let callback = format!("{base}{}", r.headers()["location"].to_str().unwrap());
    let r = browser.get(&callback).send().await.unwrap();
    assert_eq!(r.status(), 303);
    assert!(
        r.headers()["location"]
            .to_str()
            .unwrap()
            .contains("/Account/Login?ReturnUrl="),
        "{:?}",
        r.headers()["location"]
    );
}
