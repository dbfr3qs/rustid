//! The server over TLS: URLs and the issuer follow the https scheme, the
//! session cookies are Secure, and the reference UI completes a login.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use rustid_server::config::ServerConfig;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

/// A CA and a certificate for `localhost` it signed; returns the CA's PEM.
fn write_certificates(dir: &Path) -> String {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = rcgen::CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .signed_by(&key, &ca)
        .unwrap();
    std::fs::write(dir.join("cert.pem"), cert.pem()).unwrap();
    std::fs::write(dir.join("key.pem"), key.serialize_pem()).unwrap();
    ca.pem()
}

struct Running {
    base: String,
    client: reqwest::Client,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    served: tokio::task::JoinHandle<anyhow::Result<()>>,
}

async fn start(dir: &Path) -> Running {
    let ca = write_certificates(dir);
    let config = serde_json::json!({
        "tls": {
            "cert_file": dir.join("cert.pem"),
            "key_file": dir.join("key.pem"),
        },
        "signing_keys": [{ "kid": "k1", "alg": "RS256", "key_file": fixture("signing-key.pem") }],
        "clients_file": fixture("clients.json"),
        "resources_file": fixture("resources.json"),
        "protocol": { "key_management": { "enabled": false } },
        "reference_ui": {
            "enabled": true,
            "users_file": fixture("users.json"),
            "default_user": "alice",
        },
    });
    let path = dir.join("rustid.json");
    std::fs::write(&path, config.to_string()).unwrap();
    let config = ServerConfig::load(Some(&path)).unwrap();
    let app = rustid_server::build(&config).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let served = tokio::spawn(rustid_server::serve(listener, app, async move {
        let _ = stopped.await;
    }));
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca.as_bytes()).unwrap())
        .resolve("localhost", addr)
        .redirect(reqwest::redirect::Policy::none())
        .cookie_store(true)
        .build()
        .unwrap();
    Running {
        base: format!("https://localhost:{}", addr.port()),
        client,
        stop: Some(stop),
        served,
    }
}

impl Running {
    async fn get(&self, url: &str) -> reqwest::Response {
        let url = if url.starts_with("https://") {
            url.to_owned()
        } else {
            format!("{}{url}", self.base)
        };
        self.client.get(url).send().await.unwrap()
    }

    async fn stop(mut self) {
        self.stop.take().unwrap().send(()).unwrap();
        self.served.await.unwrap().unwrap();
    }
}

fn location(r: &reqwest::Response) -> String {
    r.headers()["location"].to_str().unwrap().to_owned()
}

#[tokio::test]
async fn over_tls_the_issuer_is_https_and_the_reference_ui_signs_in() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(dir.path()).await;

    let discovery: serde_json::Value = server
        .get("/.well-known/openid-configuration")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(discovery["issuer"], server.base);

    let authorize = server
        .get("/connect/authorize?client_id=web&redirect_uri=https%3A%2F%2Fclient.test%2Fcallback&response_type=code&scope=openid&state=s&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256")
        .await;
    assert_eq!(authorize.status(), 303);
    let login = location(&authorize);
    assert!(
        login.starts_with(&format!("{}/Account/Login?", server.base)),
        "{login}"
    );

    // The reference UI signs alice in and hands the browser a continuation.
    let signed_in = server.get(&login).await;
    assert_eq!(signed_in.status(), 302, "{:?}", signed_in.text().await);
    let continuation = location(&signed_in);
    assert!(continuation.starts_with(&format!(
        "{}/connect/interaction/continue?token=",
        server.base
    )));
    let back = server.get(&continuation).await;
    assert_eq!(back.status(), 302);
    let cookies: Vec<String> = back
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect();
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with("idsrv=") && c.contains("; secure;")),
        "{cookies:?}"
    );

    let callback = server.get(&location(&back)).await;
    assert_eq!(callback.status(), 303);
    assert!(
        location(&callback).starts_with("https://client.test/callback?code="),
        "{}",
        location(&callback)
    );
    server.stop().await;
}
