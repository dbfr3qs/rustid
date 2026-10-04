//! `reference_ui.users_profile_service`: the users
//! file answers profile claims, so userinfo has the user's claims, not only
//! the access token's.

use std::path::{Path, PathBuf};

use rustid_server::config::ServerConfig;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

async fn userinfo(users_profile_service: bool) -> serde_json::Value {
    let dir = tempfile::tempdir().unwrap();
    let config = serde_json::json!({
        "signing_keys": [{ "kid": "k1", "alg": "RS256", "key_file": fixture("signing-key.pem") }],
        "clients_file": fixture("clients.json"),
        "resources_file": fixture("resources.json"),
        "protocol": { "key_management": { "enabled": false } },
        "reference_ui": {
            "enabled": true,
            "users_file": fixture("users.json"),
            "users_profile_service": users_profile_service,
        },
    });
    let path = dir.path().join("rustid.json");
    std::fs::write(&path, config.to_string()).unwrap();
    let app = rustid_server::build(&ServerConfig::load(Some(&path)).unwrap())
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(rustid_server::serve(listener, app, std::future::pending()));
    let browser = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .cookie_store(true)
        .build()
        .unwrap();
    let location = |r: &reqwest::Response| r.headers()["location"].to_str().unwrap().to_owned();
    // web asks for openid profile; the default user alice signs in.
    let authorize = browser
        .get(format!("{base}/connect/authorize?client_id=web&redirect_uri=https%3A%2F%2Fclient.test%2Fcallback&response_type=code&scope=openid%20profile&state=s&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256"))
        .send()
        .await
        .unwrap();
    let login = browser.get(location(&authorize)).send().await.unwrap();
    let continued = browser.get(location(&login)).send().await.unwrap();
    let callback = browser
        .get(format!("{base}{}", location(&continued)))
        .send()
        .await
        .unwrap();
    let code = url::Url::parse(&location(&callback))
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "code")
        .unwrap()
        .1
        .into_owned();
    let tokens: serde_json::Value = browser
        .post(format!("{base}/connect/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", "web"),
            ("code", &code),
            ("redirect_uri", "https://client.test/callback"),
            (
                "code_verifier",
                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            ),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    browser
        .get(format!("{base}/connect/userinfo"))
        .bearer_auth(tokens["access_token"].as_str().unwrap())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[tokio::test]
async fn the_users_file_answers_profile_claims_when_asked() {
    assert_eq!(
        userinfo(true).await,
        serde_json::json!({
            "sub": "1",
            "name": "Alice Smith",
            "given_name": "Alice",
            "family_name": "Smith",
        })
    );
    assert_eq!(
        userinfo(false).await,
        serde_json::json!({ "sub": "1" }),
        "by default, the token's claims"
    );
}
