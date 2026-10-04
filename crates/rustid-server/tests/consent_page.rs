//! The reference UI's consent page: scripted by query parameters, and a
//! form a person can use in interactive mode.

use std::path::{Path, PathBuf};

use rustid_server::config::ServerConfig;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

struct Server {
    base: String,
    browser: reqwest::Client,
    _stop: tokio::sync::oneshot::Sender<()>,
    _dir: tempfile::TempDir,
}

async fn start(interactive: bool) -> Server {
    let dir = tempfile::tempdir().unwrap();
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
    let path = dir.path().join("rustid.json");
    std::fs::write(&path, config.to_string()).unwrap();
    let config = ServerConfig::load(Some(&path)).unwrap();
    let app = rustid_server::build(&config).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(rustid_server::serve(listener, app, async move {
        let _ = stopped.await;
    }));
    let browser = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .cookie_store(true)
        .build()
        .unwrap();
    Server {
        base,
        browser,
        _stop: stop,
        _dir: dir,
    }
}

const AUTHORIZE: &str = "/connect/authorize?client_id=web-consent&redirect_uri=https%3A%2F%2Fclient.test%2Fcallback&response_type=code&scope=openid%20profile%20api1&state=s&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256";

fn location(r: &reqwest::Response) -> String {
    r.headers()["location"].to_str().unwrap().to_owned()
}

impl Server {
    async fn get(&self, url: &str) -> reqwest::Response {
        let url = if url.starts_with('/') {
            format!("{}{url}", self.base)
        } else {
            url.to_owned()
        };
        self.browser.get(url).send().await.unwrap()
    }

    /// Follows redirects on the server until one leaves it, returning the
    /// last response on the server.
    async fn follow(&self, mut url: String) -> reqwest::Response {
        loop {
            let r = self.get(&url).await;
            if !r.status().is_redirection() {
                return r;
            }
            let next = location(&r);
            if next.starts_with("https://client.test") || next.contains("/consent?") {
                return r;
            }
            url = next;
        }
    }

    /// Signs alice in (non-interactive mode) and returns the consent page URL.
    async fn consent_url(&self) -> String {
        let r = self.follow(AUTHORIZE.to_owned()).await;
        let consent = location(&r);
        assert!(consent.contains("/consent?returnUrl="), "{consent}");
        consent
    }
}

fn query(location: &str) -> Vec<(String, String)> {
    url::Url::parse(location)
        .unwrap()
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

#[tokio::test]
async fn the_scripted_consent_page_grants_or_refuses_as_asked() {
    let server = start(false).await;
    let consent = server.consent_url().await;

    // Everything requested, by default.
    let r = server.follow(consent.clone()).await;
    assert!(
        location(&r).starts_with("https://client.test/callback?code="),
        "{}",
        location(&r)
    );

    // A refusal with a description.
    let r = server
        .follow(format!(
            "{consent}&error=temporarily_unavailable&error_description=busy"
        ))
        .await;
    let q = query(&location(&r));
    assert!(
        q.contains(&("error".into(), "temporarily_unavailable".into())),
        "{q:?}"
    );
    assert!(
        q.contains(&("error_description".into(), "busy".into())),
        "{q:?}"
    );

    // A subset missing the required openid scope.
    let r = server.follow(format!("{consent}&scopes=api1")).await;
    let q = query(&location(&r));
    assert!(
        q.contains(&("error".into(), "access_denied".into())),
        "{q:?}"
    );

    // Remembered consent skips the page next time.
    let r = server.follow(format!("{consent}&remember=true")).await;
    assert!(location(&r).starts_with("https://client.test/callback?code="));
    let r = server.follow(AUTHORIZE.to_owned()).await;
    assert!(
        location(&r).starts_with("https://client.test/callback?code="),
        "{}",
        location(&r)
    );
}

async fn sign_in_interactively(server: &Server) -> String {
    let r = server.get(AUTHORIZE).await;
    let login = location(&r);
    let return_url = query(&login)
        .into_iter()
        .find(|(k, _)| k == "ReturnUrl")
        .unwrap()
        .1;
    let r = server
        .browser
        .post(&login)
        .form(&[
            ("returnUrl", return_url.as_str()),
            ("username", "alice"),
            ("password", "alice"),
        ])
        .send()
        .await
        .unwrap();
    let r = server.follow(location(&r)).await;
    let consent = location(&r);
    assert!(consent.contains("/consent?returnUrl="), "{consent}");
    consent
}

#[tokio::test]
async fn the_interactive_consent_page_lets_a_person_choose() {
    let server = start(true).await;
    let consent = sign_in_interactively(&server).await;
    let page = server.get(&consent).await;
    assert_eq!(page.status(), 200);
    let html = page.text().await.unwrap();
    assert!(html.contains("Web client with consent"), "{html}");
    assert!(
        html.contains("value=\"openid\" checked disabled"),
        "required scopes can't be unticked: {html}"
    );
    assert!(html.contains("value=\"profile\" checked"), "{html}");
    assert!(html.contains("name=\"remember\""), "{html}");
    let return_url = query(&consent)
        .into_iter()
        .find(|(k, _)| k == "returnUrl")
        .unwrap()
        .1;

    // Allowing nothing optional still grants the required scope.
    let post = |form: Vec<(&'static str, String)>| server.browser.post(&consent).form(&form).send();
    let r = post(vec![
        ("returnUrl", return_url.clone()),
        ("button", "yes".into()),
        ("scopes", "api1".into()),
    ])
    .await
    .unwrap();
    assert_eq!(r.status(), 302);
    let r = server.follow(location(&r)).await;
    assert!(
        location(&r).starts_with("https://client.test/callback?code="),
        "{}",
        location(&r)
    );

    // Deny.
    let consent = location(&server.follow(AUTHORIZE.to_owned()).await);
    let r = server
        .browser
        .post(&consent)
        .form(&[("returnUrl", return_url.as_str()), ("button", "no")])
        .send()
        .await
        .unwrap();
    let r = server.follow(location(&r)).await;
    let q = query(&location(&r));
    assert!(
        q.contains(&("error".into(), "access_denied".into())),
        "{q:?}"
    );
}

#[tokio::test]
async fn cancelling_the_login_page_denies_the_request() {
    let server = start(true).await;
    let r = server.get(AUTHORIZE).await;
    let login = location(&r);
    let return_url = query(&login)
        .into_iter()
        .find(|(k, _)| k == "ReturnUrl")
        .unwrap()
        .1;
    let page = server.get(&login).await.text().await.unwrap();
    assert!(page.contains("value=\"cancel\""), "{page}");
    let r = server
        .browser
        .post(&login)
        .form(&[("returnUrl", return_url.as_str()), ("button", "cancel")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 302);
    let r = server.follow(location(&r)).await;
    let q = query(&location(&r));
    assert!(
        q.contains(&("error".into(), "access_denied".into())),
        "{q:?}"
    );
}

#[tokio::test]
async fn interactive_forms_refuse_cross_site_posts() {
    let server = start(true).await;
    for path in [
        "/device",
        "/ciba",
        "/consent",
        "/Account/Login",
        "/Account/Logout",
    ] {
        let url = format!("{}{path}", server.base);
        let cross_origin = server
            .browser
            .post(&url)
            .header("origin", "https://evil.test")
            .form(&[("userCode", "123456789"), ("button", "yes")])
            .send()
            .await
            .unwrap();
        assert_eq!(cross_origin.status(), 403, "{path} with a foreign Origin");
        let cross_site = server
            .browser
            .post(&url)
            .header("sec-fetch-site", "cross-site")
            .form(&[("button", "yes")])
            .send()
            .await
            .unwrap();
        assert_eq!(cross_site.status(), 403, "{path} fetched cross-site");
        // The page's own origin is fine (the handler then decides).
        let same = server
            .browser
            .post(&url)
            .header("origin", &server.base)
            .header("sec-fetch-site", "same-origin")
            .form(&[("button", "no")])
            .send()
            .await
            .unwrap();
        assert_ne!(same.status(), 403, "{path} from its own origin");
    }
}
