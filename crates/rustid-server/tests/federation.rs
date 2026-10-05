//! Federation in the server: loading the providers file, the HTTP client
//! that reaches upstream providers, and a sign-in end to end through a
//! second rustid as the upstream provider, from the reference UI's button.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use rustid_core::federation::provider::Credential;
use rustid_core::federation::upstream::{FormPost, UpstreamClient};
use rustid_server::config::ServerConfig;
use rustid_server::federation::{HttpUpstreamClient, load_providers, unknown_restrictions};
use serde_json::json;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

fn write(dir: &Path, name: &str, value: &serde_json::Value) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, value.to_string()).unwrap();
    path
}

fn provider(scheme: &str, auth: serde_json::Value) -> serde_json::Value {
    json!({ "scheme": scheme, "displayName": "Up", "authority": "https://up.example",
            "clientId": "c", "clientAuthentication": auth })
}

#[test]
fn providers_load_with_secrets_from_the_environment_and_keys_from_files() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::copy(fixture("signing-key.pem"), dir.path().join("key.pem")).unwrap();
    let path = write(
        dir.path(),
        "providers.json",
        &json!([
            provider("env", json!({ "secretEnv": "UP_SECRET" })),
            provider(
                "post",
                json!({ "method": "client_secret_post", "secret": "s" })
            ),
            provider(
                "jwt",
                json!({ "method": "private_key_jwt", "keyFile": "key.pem", "keyId": "k1" })
            ),
        ]),
    );
    let env: HashMap<&str, &str> = [("UP_SECRET", "from-env")].into();
    let providers =
        load_providers(&path, false, &|name| env.get(name).map(|v| v.to_string())).unwrap();
    assert!(
        matches!(&providers.find("env").unwrap().credential, Credential::Basic(s) if s == "from-env")
    );
    assert!(matches!(&providers.find("post").unwrap().credential, Credential::Post(s) if s == "s"));
    assert!(
        matches!(&providers.find("jwt").unwrap().credential, Credential::PrivateKeyJwt(k) if k.kid == "k1" && k.alg == "RS256")
    );

    let error = load_providers(&path, false, &|_| None)
        .unwrap_err()
        .to_string();
    assert!(error.contains("UP_SECRET"), "{error}");
}

#[test]
fn bad_providers_files_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let env = |_: &str| Some("s".to_owned());
    let refuse = |value: serde_json::Value, needle: &str| {
        let path = write(dir.path(), "p.json", &value);
        let error = format!("{:#}", load_providers(&path, false, &env).unwrap_err());
        assert!(error.contains(needle), "{error} lacks {needle}");
    };
    refuse(
        json!([
            provider("a", json!({ "secret": "s" })),
            provider("a", json!({ "secret": "s" }))
        ]),
        "twice",
    );
    refuse(
        json!([provider(
            "a",
            json!({ "method": "private_key_jwt", "keyFile": "missing.pem", "keyId": "k" })
        )]),
        "missing.pem",
    );
    let mut http = provider("a", json!({ "secret": "s" }));
    http["authority"] = "http://localhost:1".into();
    refuse(json!([http.clone()]), "https");
    let path = write(dir.path(), "p.json", &json!([http]));
    load_providers(&path, true, &env).unwrap();
    refuse(json!({ "not": "an array" }), "p.json");
}

#[test]
fn unknown_restrictions_are_listed() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(
        dir.path(),
        "p.json",
        &json!([provider("up", json!({ "secret": "s" }))]),
    );
    let providers = load_providers(&path, false, &|_| None).unwrap();
    let clients: Vec<rustid_core::clients::Client> = serde_json::from_value(json!([
        { "clientId": "a", "identityProviderRestrictions": ["up", "gone"] },
        { "clientId": "b" },
    ]))
    .unwrap();
    assert_eq!(
        unknown_restrictions(&clients, &providers),
        [("a".to_owned(), "gone".to_owned())]
    );
}

async fn host() -> String {
    use axum::http::{HeaderMap, StatusCode};
    let app = axum::Router::new()
        .route(
            "/doc",
            axum::routing::get(|| async { axum::Json(json!({ "a": 1 })) }),
        )
        .route(
            "/missing",
            axum::routing::get(|| async { StatusCode::NOT_FOUND }),
        )
        .route(
            "/redirect",
            axum::routing::get(|| async { (StatusCode::FOUND, [("location", "/doc")], "") }),
        )
        .route(
            "/big",
            axum::routing::get(|| async { "x".repeat(2 * 1024 * 1024) }),
        )
        .route(
            "/token",
            axum::routing::post(|headers: HeaderMap, body: String| async move {
                let auth = headers
                    .get("authorization")
                    .map(|v| v.to_str().unwrap().to_owned());
                (
                    StatusCode::BAD_REQUEST,
                    axum::Json(json!({ "auth": auth, "body": body })),
                )
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await });
    base
}

#[tokio::test]
async fn the_http_client_reads_json_refuses_redirects_and_encodes_basic_credentials() {
    use base64::Engine;
    let base = host().await;
    let client = HttpUpstreamClient::with_ca_file(None).unwrap();
    assert_eq!(
        client.get_json(&format!("{base}/doc")).await.unwrap(),
        json!({ "a": 1 })
    );
    assert!(client.get_json(&format!("{base}/missing")).await.is_err());
    assert!(
        client.get_json(&format!("{base}/redirect")).await.is_err(),
        "not followed"
    );
    assert!(
        client.get_json(&format!("{base}/big")).await.is_err(),
        "over 1 MiB"
    );
    let (status, body) = client
        .post_form(&FormPost {
            url: format!("{base}/token"),
            form: vec![("code".into(), "a b".into())],
            basic: Some(("abc".into(), "a b:c".into())),
        })
        .await
        .unwrap();
    assert_eq!(status, 400);
    let expected = base64::engine::general_purpose::STANDARD.encode("abc:a+b%3Ac");
    assert_eq!(body["auth"], format!("Basic {expected}"));
    assert_eq!(body["body"], "code=a+b");
}

/// A server on `listener` with `config` (paths relative to `dir`).
async fn serve(
    dir: &Path,
    name: &str,
    listener: tokio::net::TcpListener,
    config: serde_json::Value,
) -> tokio::sync::oneshot::Sender<()> {
    let path = write(dir, name, &config);
    let config = ServerConfig::load(Some(&path)).unwrap();
    let app = rustid_server::build(&config).await.unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(rustid_server::serve(listener, app, async move {
        let _ = stopped.await;
    }));
    stop
}

fn location(r: &reqwest::Response) -> String {
    r.headers()["location"].to_str().unwrap().to_owned()
}

#[tokio::test]
async fn signing_in_through_a_second_rustid() {
    let dir = tempfile::tempdir().unwrap();
    let up_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let down_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    // The upstream is reached as localhost and the downstream as 127.0.0.1:
    // cookies aren't kept apart by port, and both servers set
    // `idsrv.interaction`.
    let up = format!(
        "http://localhost:{}",
        up_listener.local_addr().unwrap().port()
    );
    let down = format!("http://{}", down_listener.local_addr().unwrap());
    let key = json!([{ "kid": "k1", "alg": "RS256", "key_file": fixture("signing-key.pem") }]);

    let up_clients = write(
        dir.path(),
        "up-clients.json",
        &json!([{
            "clientId": "downstream",
            "clientSecrets": [{ "value": "K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=" }],
            "allowedGrantTypes": ["authorization_code"],
            "redirectUris": [format!("{down}/federation/up/callback")],
            "allowedScopes": ["openid", "profile"],
            "requireConsent": false,
            "alwaysIncludeUserClaimsInIdToken": true,
        }]),
    );
    let _up = serve(dir.path(), "up.json", up_listener, json!({
        "signing_keys": key,
        "clients_file": up_clients,
        "resources_file": fixture("resources.json"),
        "protocol": { "key_management": { "enabled": false } },
        "reference_ui": { "enabled": true, "interactive": true, "users_file": fixture("users.json") },
    }))
    .await;

    let providers = write(
        dir.path(),
        "providers.json",
        &json!([{
            "scheme": "up", "displayName": "Upstream IdP", "authority": up,
            "clientId": "downstream", "clientAuthentication": { "secret": "secret" },
            "scopes": ["openid", "profile"],
        }]),
    );
    let _down = serve(dir.path(), "down.json", down_listener, json!({
        "signing_keys": key,
        "clients_file": fixture("clients.json"),
        "resources_file": fixture("resources.json"),
        "identity_providers_file": providers,
        "federation": { "allow_insecure_loopback": true },
        "protocol": { "key_management": { "enabled": false } },
        "reference_ui": { "enabled": true, "interactive": true, "users_file": fixture("users.json") },
    }))
    .await;

    let browser = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .cookie_store(true)
        .build()
        .unwrap();
    let authorize = browser
        .get(format!("{down}/connect/authorize?client_id=web&redirect_uri=https%3A%2F%2Fclient.test%2Fcallback&response_type=code&scope=openid%20profile&state=s&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256"))
        .send()
        .await
        .unwrap();
    let login_url = location(&authorize);
    let page = browser
        .get(&login_url)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(page.contains("Sign in with Upstream IdP"), "{page}");
    let href = page
        .split("href=\"")
        .find(|s| s.contains("/federation/up/challenge"))
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .replace("&amp;", "&");
    // Upstream: the challenge, then the upstream's own login page.
    let to_upstream = browser.get(&href).send().await.unwrap();
    assert_eq!(to_upstream.status(), 302);
    let upstream_authorize = location(&to_upstream);
    assert!(
        upstream_authorize.starts_with(&format!("{up}/connect/authorize?")),
        "{upstream_authorize}"
    );
    let up_login = location(&browser.get(&upstream_authorize).send().await.unwrap());
    let up_login = if up_login.starts_with('/') {
        format!("{up}{up_login}")
    } else {
        up_login
    };
    let up_return = url::Url::parse(&up_login)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "ReturnUrl")
        .unwrap()
        .1
        .into_owned();
    let signed_in_up = browser
        .post(&up_login)
        .form(&[
            ("returnUrl", up_return.as_str()),
            ("username", "alice"),
            ("password", "alice"),
        ])
        .send()
        .await
        .unwrap();
    // Follow redirects by hand until the browser is back at the client,
    // resolving each against the URL that answered it.
    let mut url = url::Url::parse(&up_login).unwrap();
    let mut next = location(&signed_in_up);
    for _ in 0..10 {
        if next.starts_with("https://client.test/") {
            break;
        }
        url = url.join(&next).unwrap();
        let reply = browser.get(url.as_str()).send().await.unwrap();
        assert!(
            reply.status().is_redirection(),
            "{url}: {} {}",
            reply.status(),
            reply.text().await.unwrap()
        );
        next = location(&reply);
    }
    assert!(
        next.starts_with("https://client.test/callback?code="),
        "{next}"
    );
    let code = url::Url::parse(&next)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "code")
        .unwrap()
        .1
        .into_owned();
    let tokens: serde_json::Value = browser
        .post(format!("{down}/connect/token"))
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
    let id_token = rustid_core::jwt::Jws::decode(tokens["id_token"].as_str().unwrap()).unwrap();
    assert_eq!(id_token.claim_str("idp"), Some("up"));
    // The upstream's subject for alice is "1".
    assert_eq!(
        id_token.claim_str("sub"),
        Some(rustid_core::federation::session::subject_for(&up, "1").as_str())
    );
}
