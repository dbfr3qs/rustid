//! The demo's SAML service provider against rustid: a browser signs in
//! over SAML (signed AuthnRequest, checked response) and logs out with
//! SAML single logout.

use std::path::{Path, PathBuf};

use rustid_demo::client::ClientConfig;
use rustid_demo::saml_sp::SamlSpConfig;

fn repo(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

struct Running {
    server: String,
    client: String,
    browser: reqwest::Client,
}

async fn start(dir: &Path) -> Running {
    let client_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = format!(
        "http://localhost:{}",
        client_listener.local_addr().unwrap().port()
    );
    let server_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = format!(
        "http://127.0.0.1:{}",
        server_listener.local_addr().unwrap().port()
    );

    let entity_id = format!("{client}/saml");
    let sp_cert = std::fs::read_to_string(repo("fixtures/saml/sp/sp-signing.cert.pem")).unwrap();
    let sps = rustid_demo::saml_sp::registration(&entity_id, &sp_cert);
    std::fs::write(dir.join("sps.json"), sps.to_string()).unwrap();
    std::fs::write(dir.join("clients.json"), "[]").unwrap();
    let config = serde_json::json!({
        "signing_keys": [{ "kid": "demo-rsa", "alg": "RS256",
            "key_file": repo("fixtures/signing-key.pem"), "cert_file": repo("examples/demo/signing-cert.pem") }],
        "clients_file": dir.join("clients.json"),
        "resources_file": repo("examples/demo/resources.json"),
        "protocol": { "key_management": { "enabled": false } },
        "reference_ui": { "enabled": true, "users_file": repo("fixtures/users.json"), "default_user": "alice" },
        "saml": { "enabled": true, "service_providers_file": dir.join("sps.json") },
    });
    let path = dir.join("rustid.json");
    std::fs::write(&path, config.to_string()).unwrap();
    let app =
        rustid_server::build(&rustid_server::config::ServerConfig::load(Some(&path)).unwrap())
            .await
            .unwrap();
    tokio::spawn(rustid_server::serve(
        server_listener,
        app,
        std::future::pending(),
    ));

    let router = rustid_demo::client::router(ClientConfig {
        authority: server.clone(),
        client_id: "demo".into(),
        client_secret: None,
        public_url: client.clone(),
        scope: "openid".into(),
        ca_file: None,
        resolve: Vec::new(),
        users_file: None,
        saml: Some(SamlSpConfig {
            idp: server.clone(),
            entity_id,
            key_file: repo("fixtures/saml/sp/sp-signing.key.pem"),
            cert_file: repo("fixtures/saml/sp/sp-signing.cert.pem"),
        }),
    })
    .unwrap();
    tokio::spawn(async move { axum::serve(client_listener, router).await });
    let browser = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .cookie_store(true)
        .build()
        .unwrap();
    Running {
        server,
        client,
        browser,
    }
}

impl Running {
    /// Follows redirects until a page answers (relative ones against the
    /// URL that sent them).
    async fn follow(&self, mut url: String) -> reqwest::Response {
        for _ in 0..15 {
            let response = self.browser.get(&url).send().await.unwrap();
            if !response.status().is_redirection() {
                return response;
            }
            let location = response.headers()["location"].to_str().unwrap();
            url = url::Url::parse(&url)
                .unwrap()
                .join(location)
                .unwrap()
                .to_string();
        }
        panic!("too many redirects from {url}");
    }
}

fn form_value(html: &str, name: &str) -> String {
    let marker = format!("name=\"{name}\"");
    let at = html.find(&marker).unwrap();
    let start = at + html[at..].find("value=\"").unwrap() + 7;
    html[start..start + html[start..].find('"').unwrap()].to_owned()
}

#[tokio::test]
async fn sign_in_and_out_over_saml() {
    let dir = tempfile::tempdir().unwrap();
    let demo = start(dir.path()).await;

    // Sign in: the demo SP's AuthnRequest, rustid's login, the auto-post page.
    let page = demo.follow(format!("{}/saml/login", demo.client)).await;
    assert_eq!(page.status(), 200);
    let html = page.text().await.unwrap();
    assert!(
        html.contains(&format!("action=\"{}/saml/acs\"", demo.client)),
        "{html}"
    );
    let saml_response = form_value(&html, "SAMLResponse");
    let signed_in = demo
        .browser
        .post(format!("{}/saml/acs", demo.client))
        .form(&[("SAMLResponse", saml_response.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(signed_in.status(), 302, "{:?}", signed_in.text().await);
    let page = demo
        .follow(format!("{}/saml", demo.client))
        .await
        .text()
        .await
        .unwrap();
    assert!(page.contains("Signed in over SAML as"), "{page}");
    assert!(page.contains("signature verified"));

    // A replayed response is refused (its request was used).
    let replayed = demo
        .browser
        .post(format!("{}/saml/acs", demo.client))
        .form(&[("SAMLResponse", saml_response.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(replayed.status(), 400);

    // Log out: the demo SP's LogoutRequest, rustid's logout page (scripted:
    // its context), the SLO callback, the LogoutResponse back to the SP.
    let to_logout_page = demo.follow(format!("{}/saml/logout", demo.client)).await;
    let context: serde_json::Value = to_logout_page.json().await.unwrap();
    // The signed-out page loads its iframe (the end session callback,
    // which tracks the other SPs' logouts) before going back.
    let iframe = context["signOutIFrameUrl"].as_str().unwrap();
    assert_eq!(demo.browser.get(iframe).send().await.unwrap().status(), 200);
    let callback = context["postLogoutRedirectUri"].as_str().unwrap();
    let back = demo
        .follow(format!("{}{callback}", demo.server))
        .await
        .text()
        .await
        .unwrap();
    assert!(back.contains("Logged out (Success)."), "{back}");
    assert!(back.contains("Sign in with SAML"));
}
