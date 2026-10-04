//! mTLS certificate sources: the TLS listener asking for a client
//! certificate, and a trusted proxy's forwarded-certificate header.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use rustid_server::config::ServerConfig;
use serde_json::{Value, json};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

struct Pki {
    ca_pem: String,
    /// The server's certificate and key for `localhost`.
    server_cert: String,
    server_key: String,
    /// A client certificate the CA issued (CN=issued), with its key.
    issued_cert: String,
    issued_key: String,
    /// A self-signed client certificate, with its key.
    self_signed_cert: String,
    self_signed_key: String,
    self_signed_thumbprint: String,
}

fn pki() -> Pki {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let ca = rcgen::CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();

    let server_key = rcgen::KeyPair::generate().unwrap();
    let server = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .signed_by(&server_key, &ca)
        .unwrap();

    let client = |cn: &str| {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        params
    };
    let issued_key = rcgen::KeyPair::generate().unwrap();
    let issued = client("issued").signed_by(&issued_key, &ca).unwrap();
    let self_signed_key = rcgen::KeyPair::generate().unwrap();
    let self_signed = client("self-signed").self_signed(&self_signed_key).unwrap();
    let thumbprint =
        rustid_core::client_certificate::ClientCertificate::parse(self_signed.der(), None)
            .unwrap()
            .thumbprint;
    Pki {
        ca_pem: ca.pem(),
        server_cert: server.pem(),
        server_key: server_key.serialize_pem(),
        issued_cert: issued.pem(),
        issued_key: issued_key.serialize_pem(),
        self_signed_cert: self_signed.pem(),
        self_signed_key: self_signed_key.serialize_pem(),
        self_signed_thumbprint: thumbprint,
    }
}

fn clients(pki: &Pki) -> Value {
    json!([
        {
            "clientId": "by.thumbprint",
            "clientSecrets": [{ "type": "X509Thumbprint", "value": pki.self_signed_thumbprint }],
            "allowedGrantTypes": ["client_credentials"],
            "allowedScopes": ["api1"],
        },
        {
            "clientId": "by.name",
            "clientSecrets": [{ "type": "X509Name", "value": "CN=issued" }],
            "allowedGrantTypes": ["client_credentials"],
            "allowedScopes": ["api1"],
        },
        {
            "clientId": "by.name.self.signed",
            "clientSecrets": [{ "type": "X509Name", "value": "CN=self-signed" }],
            "allowedGrantTypes": ["client_credentials"],
            "allowedScopes": ["api1"],
        },
    ])
}

async fn start(
    dir: &Path,
    pki: &Pki,
    extra: Value,
) -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
    std::fs::write(dir.join("clients.json"), clients(pki).to_string()).unwrap();
    std::fs::write(dir.join("ca.pem"), &pki.ca_pem).unwrap();
    std::fs::write(dir.join("cert.pem"), &pki.server_cert).unwrap();
    std::fs::write(dir.join("key.pem"), &pki.server_key).unwrap();
    let mut config = json!({
        "signing_keys": [{ "kid": "k1", "alg": "RS256", "key_file": fixture("signing-key.pem") }],
        "clients_file": dir.join("clients.json"),
        "resources_file": fixture("resources.json"),
        "protocol": {
            "key_management": { "enabled": false },
            "mutual_tls": { "enabled": true },
        },
        "mutual_tls": { "client_ca_file": dir.join("ca.pem") },
    });
    for (k, v) in extra.as_object().unwrap() {
        match (config.get_mut(k), v) {
            (Some(Value::Object(existing)), Value::Object(more)) => {
                existing.extend(more.clone());
            }
            _ => {
                config[k] = v.clone();
            }
        }
    }
    let path = dir.join("rustid.json");
    std::fs::write(&path, config.to_string()).unwrap();
    let config = ServerConfig::load(Some(&path)).unwrap();
    let app = rustid_server::build(&config).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(rustid_server::serve(listener, app, async move {
        let _ = stopped.await;
    }));
    (addr, stop)
}

fn tls_client(pki: &Pki, addr: SocketAddr, identity: Option<(&str, &str)>) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(pki.ca_pem.as_bytes()).unwrap())
        .resolve("localhost", addr);
    if let Some((cert, key)) = identity {
        builder = builder
            .identity(reqwest::Identity::from_pem(format!("{cert}{key}").as_bytes()).unwrap());
    }
    builder.build().unwrap()
}

async fn token(
    client: &reqwest::Client,
    url: &str,
    client_id: &str,
    headers: &[(&str, String)],
) -> (u16, Value) {
    let mut request = client.post(url).form(&[
        ("grant_type", "client_credentials"),
        ("client_id", client_id),
        ("scope", "api1"),
    ]);
    for (name, value) in headers {
        request = request.header(*name, value);
    }
    let response = request.send().await.unwrap();
    let status = response.status().as_u16();
    (status, response.json().await.unwrap_or(Value::Null))
}

fn cnf(body: &Value) -> Value {
    let token = body["access_token"].as_str().unwrap();
    rustid_core::jwt::Jws::decode(token).unwrap().payload["cnf"].clone()
}

#[tokio::test]
async fn the_tls_listener_takes_client_certificates() {
    let dir = tempfile::tempdir().unwrap();
    let pki = pki();
    let (addr, _stop) = start(
        dir.path(),
        &pki,
        json!({
            "tls": {
                "cert_file": dir.path().join("cert.pem"),
                "key_file": dir.path().join("key.pem"),
                "client_certificates": "request",
            },
        }),
    )
    .await;
    let base = format!("https://localhost:{}", addr.port());

    // Without a certificate the server still answers; the mTLS alias
    // refuses.
    let anonymous = tls_client(&pki, addr, None);
    let (status, _) = token(
        &anonymous,
        &format!("{base}/connect/mtls/token"),
        "by.thumbprint",
        &[],
    )
    .await;
    assert_eq!(status, 400);

    let self_signed = tls_client(
        &pki,
        addr,
        Some((&pki.self_signed_cert, &pki.self_signed_key)),
    );
    let (status, body) = token(
        &self_signed,
        &format!("{base}/connect/mtls/token"),
        "by.thumbprint",
        &[],
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(cnf(&body)["x5t#S256"].is_string());
    // A self-signed certificate never matches a name.
    let (status, _) = token(
        &self_signed,
        &format!("{base}/connect/token"),
        "by.name.self.signed",
        &[],
    )
    .await;
    assert_eq!(status, 400);

    let issued = tls_client(&pki, addr, Some((&pki.issued_cert, &pki.issued_key)));
    let (status, body) = token(&issued, &format!("{base}/connect/token"), "by.name", &[]).await;
    assert_eq!(status, 200, "{body}");
}

#[tokio::test]
async fn a_trusted_proxy_forwards_the_certificate() {
    let pki = pki();
    let header = "X-Client-Cert";
    let encoded = rustid_core::params::url_encode(&pki.self_signed_cert);
    for (trusted, expected) in [("127.0.0.1", 200), ("10.9.9.9", 400)] {
        let dir = tempfile::tempdir().unwrap();
        let (addr, _stop) = start(
            dir.path(),
            &pki,
            json!({
                "forwarded_headers": { "trusted_proxies": [trusted] },
                "mutual_tls": {
                    "forwarded_certificate_header": header,
                    "client_ca_file": dir.path().join("ca.pem"),
                },
            }),
        )
        .await;
        let client = reqwest::Client::new();
        let url = format!("http://{addr}/connect/mtls/token");
        let (status, body) =
            token(&client, &url, "by.thumbprint", &[(header, encoded.clone())]).await;
        assert_eq!(status, expected, "proxy {trusted}: {body}");
    }
    // Base64 DER works as well as URL-encoded PEM.
    let dir = tempfile::tempdir().unwrap();
    let (addr, _stop) = start(
        dir.path(),
        &pki,
        json!({
            "forwarded_headers": { "trusted_proxies": ["127.0.0.1"] },
            "mutual_tls": { "forwarded_certificate_header": header },
        }),
    )
    .await;
    let der = pem::parse(pki.self_signed_cert.as_bytes())
        .unwrap()
        .into_contents();
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let (status, _) = token(
        &reqwest::Client::new(),
        &format!("http://{addr}/connect/token"),
        "by.thumbprint",
        &[(header, b64)],
    )
    .await;
    assert_eq!(status, 200);
}
