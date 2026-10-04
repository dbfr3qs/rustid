//! The demo end to end: rustid-server over TLS with the interactive
//! reference UI, the demo client, and a browser signing alice in.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use rustid_demo::client::ClientConfig;

fn repo(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

struct Demo {
    server: String,
    client: String,
    browser: reqwest::Client,
    /// Pins `localhost` to the server's address.
    resolve: Vec<(String, SocketAddr)>,
}

async fn start(dir: &Path) -> Demo {
    let certs = rustid_demo::certs::write(dir, &["localhost".to_owned()], false).unwrap();

    // The client listens first, so the server's client list can name its
    // redirect URI.
    let client_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_port = client_listener.local_addr().unwrap().port();
    let client_base = format!("http://localhost:{client_port}");

    let server_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr: SocketAddr = server_listener.local_addr().unwrap();
    let server_base = format!("https://localhost:{}", server_addr.port());

    let clients = serde_json::json!([{
        "clientId": "demo",
        "clientName": "rustid demo client",
        "allowedGrantTypes": ["authorization_code"],
        "clientSecrets": [{ "value": "K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=" }],
        "requirePkce": true,
        "redirectUris": [format!("{client_base}/callback")],
        "postLogoutRedirectUris": [format!("{client_base}/signed-out")],
        "frontChannelLogoutUri": format!("{client_base}/frontchannel-logout"),
        "allowedScopes": ["openid", "profile", "email", "api1"],
        "allowOfflineAccess": true,
        "requireConsent": true,
    }, {
        "clientId": "demo.tv",
        "clientName": "rustid demo TV",
        "allowedGrantTypes": ["urn:ietf:params:oauth:grant-type:device_code"],
        "clientSecrets": [{ "value": "K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=" }],
        "allowedScopes": ["openid", "profile", "api1"],
    }, {
        "clientId": "demo.cli",
        "clientName": "rustid demo command line",
        "allowedGrantTypes": ["password"],
        "clientSecrets": [{ "value": "K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=" }],
        "allowedScopes": ["openid", "profile", "email", "api1"],
        "allowOfflineAccess": true,
    }, {
        "clientId": "demo.ciba",
        "clientName": "rustid demo backchannel app",
        "allowedGrantTypes": ["urn:openid:params:grant-type:ciba"],
        "clientSecrets": [{ "value": "K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=" }],
        "allowedScopes": ["openid", "profile", "api1"],
        "pollingInterval": 1,
    }]);
    std::fs::write(dir.join("clients.json"), clients.to_string()).unwrap();
    let config = serde_json::json!({
        "tls": { "cert_file": certs.cert, "key_file": certs.key },
        "signing_keys": [{ "kid": "demo", "alg": "RS256", "key_file": repo("fixtures/signing-key.pem") }],
        "clients_file": dir.join("clients.json"),
        "resources_file": repo("examples/demo/resources.json"),
        "server_side_sessions": { "enabled": true },
        "protocol": {
            // The password hook checks the hook JWT's issuer.
            "issuer_uri": server_base,
            "key_management": { "enabled": false },
            // Poll every second, so the device test is quick.
            "device_flow": { "interval": 1 },
            "authentication": { "cookie_sliding_expiration": true },
        },
        "reference_ui": {
            "enabled": true,
            "interactive": true,
            // As the demo: the users file answers profile claims.
            "users_profile_service": true,
            "users_file": repo("fixtures/users.json"),
        },
        // The demo client hosts the password grant and CIBA user hooks.
        "hooks": {
            "password_grant": { "url": format!("{client_base}/hooks/password") },
            "ciba_user": { "url": format!("{client_base}/hooks/ciba/user") },
        },
    });
    std::fs::write(dir.join("rustid.json"), config.to_string()).unwrap();
    let config = rustid_server::config::ServerConfig::load(Some(&dir.join("rustid.json"))).unwrap();
    let app = rustid_server::build(&config).await.unwrap();
    tokio::spawn(rustid_server::serve(
        server_listener,
        app,
        std::future::pending(),
    ));

    let client = rustid_demo::client::router(ClientConfig {
        authority: server_base.clone(),
        client_id: "demo".to_owned(),
        client_secret: Some("secret".to_owned()),
        public_url: client_base.clone(),
        scope: rustid_demo::client::DEFAULT_SCOPE.to_owned(),
        ca_file: Some(certs.ca.clone()),
        resolve: vec![("localhost".to_owned(), server_addr)],
        users_file: Some(repo("fixtures/users.json")),
        saml: None,
    })
    .unwrap();
    tokio::spawn(async move { axum::serve(client_listener, client).await });

    let ca = std::fs::read(&certs.ca).unwrap();
    let browser = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(&ca).unwrap())
        // The URL's port is used; this only pins localhost to IPv4.
        .resolve("localhost", server_addr)
        .redirect(reqwest::redirect::Policy::none())
        .cookie_store(true)
        .build()
        .unwrap();
    Demo {
        server: server_base,
        client: client_base,
        browser,
        resolve: vec![("localhost".to_owned(), server_addr)],
    }
}

impl Demo {
    /// Follows redirects by hand, resolving relative locations against the
    /// server, until a page answers.
    async fn browse(&self, mut url: String) -> (String, reqwest::Response) {
        for _ in 0..10 {
            let response = self.browser.get(&url).send().await.unwrap();
            if !response.status().is_redirection() {
                return (url, response);
            }
            let location = response.headers()["location"].to_str().unwrap().to_owned();
            url = match location.starts_with('/') {
                true => {
                    let origin = url::Url::parse(&url).unwrap();
                    format!("{}{location}", origin.origin().ascii_serialization())
                }
                false => location,
            };
        }
        panic!("too many redirects");
    }
}

#[tokio::test]
async fn a_person_signs_in_through_the_demo_client_and_sees_their_claims() {
    let dir = tempfile::tempdir().unwrap();
    let demo = start(dir.path()).await;

    let (_, home) = demo.browse(format!("{}/", demo.client)).await;
    let html = home.text().await.unwrap();
    assert!(html.contains("href=\"/login\""), "{html}");

    // Sign in: the client sends the browser to the server's login form.
    let (login_url, form) = demo.browse(format!("{}/login", demo.client)).await;
    assert!(
        login_url.starts_with(&format!("{}/Account/Login?", demo.server)),
        "{login_url}"
    );
    let html = form.text().await.unwrap();
    assert!(html.contains("rustid demo client"), "{html}");
    // The client pushed its request (PAR): the return URL names it.
    assert!(
        login_url.contains("request_uri%3Durn%253Aietf%253Aparams%253Aoauth%253Arequest_uri"),
        "{login_url}"
    );
    let return_url = url::Url::parse(&login_url)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "ReturnUrl")
        .unwrap()
        .1
        .into_owned();
    let submitted = demo
        .browser
        .post(&login_url)
        .form(&[
            ("returnUrl", return_url.as_str()),
            ("username", "alice"),
            ("password", "alice"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(submitted.status(), 302);
    let continuation = submitted.headers()["location"].to_str().unwrap().to_owned();

    // The continuation and the callback lead to the consent page.
    let (consent_url, consent) = demo.browse(continuation).await;
    assert!(consent_url.contains("/consent?returnUrl="), "{consent_url}");
    let html = consent.text().await.unwrap();
    assert!(
        html.contains("rustid demo client is asking for your permission"),
        "{html}"
    );
    assert!(html.contains("value=\"email\" checked"), "{html}");
    let consent_return = url::Url::parse(&consent_url)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "returnUrl")
        .unwrap()
        .1
        .into_owned();

    // Allowing everything but email: the code exchange ends on the client's
    // home page, showing what the tokens and userinfo said.
    let allowed = demo
        .browser
        .post(&consent_url)
        .form(&[
            ("returnUrl", consent_return.as_str()),
            ("button", "yes"),
            ("scopes", "profile"),
            ("scopes", "api1"),
            ("scopes", "offline_access"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(allowed.status(), 302);
    let back = format!(
        "{}{}",
        demo.server,
        allowed.headers()["location"].to_str().unwrap()
    );
    let (landed, page) = demo.browse(back).await;
    assert_eq!(landed, format!("{}/", demo.client));
    let html = page.text().await.unwrap();
    assert!(html.contains("Signed in as Alice Smith"), "{html}");
    assert!(html.contains("id token verified"), "{html}");
    assert!(
        !html.contains("alice@example.test"),
        "email wasn't granted: {html}"
    );
    assert!(
        html.contains("openid profile api1 offline_access"),
        "granted scopes: {html}"
    );

    // Refreshing replaces the tokens with new ones from the refresh token.
    assert!(html.contains("href=\"/refresh\""), "{html}");
    let (landed, page) = demo.browse(format!("{}/refresh", demo.client)).await;
    assert_eq!(landed, format!("{}/", demo.client));
    let html = page.text().await.unwrap();
    assert!(html.contains("Tokens refreshed 1 time"), "{html}");
    assert!(html.contains("id token verified"), "{html}");

    // Signing in again and refusing: the client shows the server's answer.
    let (consent_url, _) = demo.browse(format!("{}/login", demo.client)).await;
    assert!(consent_url.contains("/consent?returnUrl="), "{consent_url}");
    let consent_return = url::Url::parse(&consent_url)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "returnUrl")
        .unwrap()
        .1
        .into_owned();
    let denied = demo
        .browser
        .post(&consent_url)
        .form(&[("returnUrl", consent_return.as_str()), ("button", "no")])
        .send()
        .await
        .unwrap();
    let back = format!(
        "{}{}",
        demo.server,
        denied.headers()["location"].to_str().unwrap()
    );
    let (_, page) = demo.browse(back).await;
    let html = page.text().await.unwrap();
    assert!(html.contains("The server refused the sign-in"), "{html}");
    assert!(html.contains("access_denied"), "{html}");

    // Signing out ends the server's session too (RP-initiated logout): the
    // server's signed-out page links back to the client.
    let (signed_out, page) = demo.browse(format!("{}/signout", demo.client)).await;
    assert!(signed_out.starts_with(&demo.server), "{signed_out}");
    let html = page.text().await.unwrap();
    assert!(html.contains("You are now signed out"), "{html}");
    let back = format!("{}/signed-out?state=", demo.client);
    assert!(html.contains(&back), "{html}");
    let (_, page) = demo.browse(format!("{}/signed-out", demo.client)).await;
    let html = page.text().await.unwrap();
    assert!(html.contains("href=\"/login\""), "{html}");
    // Signing in again asks for the password.
    let (login_url, _) = demo.browse(format!("{}/login", demo.client)).await;
    assert!(login_url.contains("/Account/Login?"), "{login_url}");
}

impl Demo {
    /// Signs alice in through the client, consenting to everything.
    async fn sign_in(&self) {
        let (login_url, _) = self.browse(format!("{}/login", self.client)).await;
        let return_url = query(&login_url, "ReturnUrl");
        let submitted = self
            .browser
            .post(&login_url)
            .form(&[
                ("returnUrl", return_url.as_str()),
                ("username", "alice"),
                ("password", "alice"),
            ])
            .send()
            .await
            .unwrap();
        let continuation = submitted.headers()["location"].to_str().unwrap().to_owned();
        let (consent_url, _) = self.browse(continuation).await;
        let allowed = self
            .browser
            .post(&consent_url)
            .form(&[
                ("returnUrl", query(&consent_url, "returnUrl").as_str()),
                ("button", "yes"),
                ("scopes", "profile"),
            ])
            .send()
            .await
            .unwrap();
        let back = format!(
            "{}{}",
            self.server,
            allowed.headers()["location"].to_str().unwrap()
        );
        let (_, page) = self.browse(back).await;
        let html = page.text().await.unwrap();
        assert!(html.contains("Signed in as"), "{html}");
    }
}

fn query(url: &str, name: &str) -> String {
    url::Url::parse(url)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == name)
        .unwrap()
        .1
        .into_owned()
}

/// The `src` of the first iframe in a page.
fn iframe_src(html: &str) -> String {
    let src = html.split("<iframe ").nth(1).unwrap();
    let src = src.split("src=").nth(1).unwrap();
    let quote = &src[..1];
    src[1..].split(quote).next().unwrap().replace("&amp;", "&")
}

#[tokio::test]
async fn signing_out_at_the_server_signs_the_client_out_over_the_front_channel() {
    let dir = tempfile::tempdir().unwrap();
    let demo = start(dir.path()).await;
    demo.sign_in().await;

    // Sign out at the server directly: it asks, then shows the signed-out
    // page, whose hidden iframe loads the end session callback.
    let (logout_url, prompt) = demo
        .browse(format!("{}/connect/endsession", demo.server))
        .await;
    let html = prompt.text().await.unwrap();
    assert!(html.contains("Do you want to sign out?"), "{html}");
    let logout_id = query(&logout_url, "logoutId");
    let done = demo
        .browser
        .post(&logout_url)
        .form(&[("logoutId", logout_id.as_str())])
        .send()
        .await
        .unwrap();
    let html = done.text().await.unwrap();
    let callback = iframe_src(&html);
    assert!(
        callback.starts_with(&format!("{}/connect/endsession/callback?", demo.server)),
        "{callback}"
    );

    // The callback's iframe is the client's front-channel logout URI, with
    // the session id and issuer; loading it signs the client out.
    let (_, frames) = demo.browse(callback).await;
    let html = frames.text().await.unwrap();
    let front = iframe_src(&html);
    assert!(
        front.starts_with(&format!("{}/frontchannel-logout?sid=", demo.client)),
        "{front}"
    );
    let loaded = demo.browser.get(&front).send().await.unwrap();
    assert_eq!(loaded.status(), 200);
    let (_, home) = demo.browse(format!("{}/", demo.client)).await;
    let html = home.text().await.unwrap();
    assert!(html.contains("href=\"/login\""), "signed out: {html}");
}

#[tokio::test]
async fn a_forged_callback_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let demo = start(dir.path()).await;
    let r = demo
        .browser
        .get(format!("{}/callback?code=x&state=nope", demo.client))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    let html = r.text().await.unwrap();
    assert!(html.contains("state"), "{html}");
}

/// A password grant at the server, as the demo's command line client.
async fn password_grant(demo: &Demo, username: &str, password: &str) -> reqwest::Response {
    demo.browser
        .post(format!("{}/connect/token", demo.server))
        .form(&[
            ("grant_type", "password"),
            ("client_id", "demo.cli"),
            ("client_secret", "secret"),
            ("username", username),
            ("password", password),
            ("scope", "openid profile api1 offline_access"),
        ])
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn the_password_grant_is_checked_by_the_demo_clients_hook() {
    let dir = tempfile::tempdir().unwrap();
    let demo = start(dir.path()).await;

    let response = password_grant(&demo, "alice", "alice").await;
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert!(body["refresh_token"].is_string());
    let access = rustid_core::jwt::Jws::decode(body["access_token"].as_str().unwrap()).unwrap();
    assert_eq!(access.payload["sub"], "1");
    assert_eq!(access.payload["amr"], serde_json::json!(["pwd"]));

    let response = password_grant(&demo, "alice", "wrong").await;
    assert_eq!(response.status(), 400);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"], "invalid_grant");

    // The hook answers only the server: a request without its signed JWT
    // is refused.
    let direct = demo
        .browser
        .post(format!("{}/hooks/password", demo.client))
        .json(&serde_json::json!({ "version": 1, "username": "alice", "password": "alice" }))
        .send()
        .await
        .unwrap();
    assert_eq!(direct.status(), 401);
}

#[tokio::test]
async fn a_device_is_approved_on_the_servers_device_page() {
    let dir = tempfile::tempdir().unwrap();
    let demo = start(dir.path()).await;
    demo.sign_in().await;

    let device = rustid_demo::device::DeviceClient::new(rustid_demo::device::DeviceConfig {
        authority: demo.server.clone(),
        client_id: "demo.tv".to_owned(),
        client_secret: Some("secret".to_owned()),
        scope: "openid profile api1".to_owned(),
        ca_file: Some(dir.path().join("ca.pem")),
        resolve: demo.resolve.clone(),
    })
    .unwrap();
    let started = device.start().await.unwrap();
    assert_eq!(started.user_code.len(), 9);
    let complete = started.verification_uri_complete.clone().unwrap();
    assert!(complete.starts_with(&format!("{}/device?userCode=", demo.server)));

    // The signed-in browser opens the link and allows.
    let (_, page) = demo.browse(complete).await;
    let html = page.text().await.unwrap();
    assert!(html.contains("rustid demo TV"), "{html}");
    let allowed = demo
        .browser
        .post(format!("{}/device", demo.server))
        .form(&[
            ("userCode", started.user_code.as_str()),
            ("button", "yes"),
            ("scopes", "openid"),
            ("scopes", "profile"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(allowed.status(), 200);

    let tokens = device.wait(&started).await.unwrap();
    assert_eq!(tokens.scope, "openid profile");
    assert_eq!(tokens.id_claims["sub"], "1");
    // Profile claims come from userinfo, as for any code flow client.
    let userinfo = device.userinfo(&tokens).await.unwrap();
    assert_eq!(userinfo["name"], "Alice Smith");
}

#[tokio::test]
async fn a_backchannel_request_is_approved_on_the_servers_ciba_page() {
    let dir = tempfile::tempdir().unwrap();
    let demo = start(dir.path()).await;
    demo.sign_in().await;

    let app = rustid_demo::ciba::CibaClient::new(rustid_demo::ciba::CibaConfig {
        authority: demo.server.clone(),
        client_id: "demo.ciba".to_owned(),
        client_secret: "secret".to_owned(),
        scope: "openid profile".to_owned(),
        ca_file: Some(dir.path().join("ca.pem")),
        resolve: demo.resolve.clone(),
    })
    .unwrap();

    // The demo client's hook knows no one called nobody.
    let refused = app.start("nobody", Some("demo-42")).await.unwrap_err();
    assert!(refused.to_string().contains("unknown_user_id"), "{refused}");

    let started = app.start("alice", Some("demo-42")).await.unwrap();

    // Alice, signed in, sees the request on the server's CIBA page and
    // allows it.
    let (_, page) = demo.browse(format!("{}/ciba", demo.server)).await;
    let html = page.text().await.unwrap();
    assert!(html.contains("rustid demo backchannel app"), "{html}");
    assert!(html.contains("demo-42"), "{html}");
    let id = html
        .split("name=\"id\" value=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap()
        .to_owned();
    let allowed = demo
        .browser
        .post(format!("{}/ciba", demo.server))
        .header("origin", &demo.server)
        .form(&[
            ("id", id.as_str()),
            ("button", "yes"),
            ("scopes", "openid"),
            ("scopes", "profile"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(allowed.status(), 303);

    let tokens = app.wait(&started).await.unwrap();
    assert_eq!(tokens.scope, "openid profile");
    assert_eq!(tokens.id_claims["sub"], "1");
}
