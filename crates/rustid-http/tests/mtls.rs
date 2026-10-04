//! mTLS endpoint aliases: `/connect/mtls/*`
//! needs a client certificate and is served as `/connect/*`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use rustid_core::client_certificate::ClientCertificate;
use rustid_core::clients::{Client, Clients};
use rustid_core::keys::{KeyConfig, KeyMaterial};
use rustid_core::options::ProtocolOptions;
use rustid_core::resources::Resources;
use rustid_http::{AppState, ProtocolState, TlsClientCertificate};
use serde_json::{Value, json};
use tower::ServiceExt;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

fn certificate() -> ClientCertificate {
    let key = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    let der = params.self_signed(&key).unwrap().der().to_vec();
    ClientCertificate::parse(&der, None).unwrap()
}

fn state(cert: &ClientCertificate, configure: impl FnOnce(&mut ProtocolOptions)) -> AppState {
    let key = KeyConfig {
        kid: "k1".into(),
        alg: "RS256".into(),
        key_file: fixture("signing-key.pem"),
        cert_file: None,
    };
    let mut clients = Clients::load(&fixture("clients.json")).unwrap();
    clients.clients.push(
        serde_json::from_value::<Client>(json!({
            "clientId": "mtls",
            "clientSecrets": [{ "type": "X509Thumbprint", "value": cert.thumbprint }],
            "allowedGrantTypes": ["client_credentials"],
            "allowedScopes": ["api1"],
        }))
        .unwrap(),
    );
    let mut options = ProtocolOptions {
        issuer_uri: Some("https://idsrv.test".into()),
        ..Default::default()
    };
    options.mutual_tls.enabled = true;
    configure(&mut options);
    AppState::new(ProtocolState {
        options,
        keys: rustid_core::key_service::KeyService::new(
            KeyMaterial::load(&[key], &[]).unwrap(),
            None,
        ),
        features: Default::default(),
        stores: rustid_store_memory::stores(
            clients,
            Resources::load(&fixture("resources.json")).unwrap(),
        ),
        events: Default::default(),
        path_base: None,
        protected_resource: None,
        dcr: None,
        saml: Default::default(),
        interaction: Default::default(),
    })
}

async fn post(
    state: AppState,
    host: &str,
    path: &str,
    cert: Option<&ClientCertificate>,
) -> (StatusCode, Option<Value>) {
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header("host", host)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "grant_type=client_credentials&client_id=mtls&scope=api1",
        ))
        .unwrap();
    if let Some(cert) = cert {
        request
            .extensions_mut()
            .insert(TlsClientCertificate(Arc::new(cert.clone())));
    }
    let response = rustid_http::router(state).oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).ok())
}

#[tokio::test]
async fn the_path_alias_needs_a_certificate() {
    let cert = certificate();
    let (status, body) = post(state(&cert, |_| {}), "server", "/connect/mtls/token", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body.unwrap(),
        json!({ "error": "invalid_client", "error_description": "mTLS authentication failed." })
    );
    let (status, body) = post(
        state(&cert, |_| {}),
        "server",
        "/connect/mtls/token",
        Some(&cert),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let token = body.unwrap()["access_token"].as_str().unwrap().to_owned();
    let payload = rustid_core::jwt::Jws::decode(&token).unwrap().payload;
    assert_eq!(payload["cnf"], json!({ "x5t#S256": cert.x5t_s256 }));
    // The plain path takes a certificate too.
    let (status, _) = post(
        state(&cert, |_| {}),
        "server",
        "/connect/token",
        Some(&cert),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // An alias of no endpoint.
    let (status, _) = post(
        state(&cert, |_| {}),
        "server",
        "/connect/mtls/nothing",
        Some(&cert),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // mTLS disabled: no aliases.
    let (status, _) = post(
        state(&cert, |o| o.mutual_tls.enabled = false),
        "server",
        "/connect/mtls/token",
        Some(&cert),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn domain_aliases_need_a_certificate_on_their_host() {
    let cert = certificate();
    let domain =
        |o: &mut ProtocolOptions| o.mutual_tls.domain_name = Some("mtls.idsrv.test".into());
    let (status, _) = post(
        state(&cert, domain),
        "mtls.idsrv.test",
        "/connect/token",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = post(
        state(&cert, domain),
        "mtls.idsrv.test",
        "/connect/token",
        Some(&cert),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // Another port isn't the mTLS domain; nor is the path alias used.
    let (status, _) = post(
        state(&cert, domain),
        "mtls.idsrv.test:8443",
        "/connect/mtls/token",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let label = |o: &mut ProtocolOptions| o.mutual_tls.domain_name = Some("mtls".into());
    let (status, _) = post(
        state(&cert, label),
        "MTLS.idsrv.test",
        "/connect/token",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = post(state(&cert, label), "idsrv.test", "/connect/token", None).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a secretless client without a certificate"
    );
}

#[tokio::test]
async fn an_expired_certificate_fails_mtls_authentication() {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2021, 1, 1);
    let der = params.self_signed(&key).unwrap().der().to_vec();
    let expired = ClientCertificate::parse(&der, None).unwrap();
    let (status, body) = post(
        state(&expired, |_| {}),
        "server",
        "/connect/mtls/token",
        Some(&expired),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body.unwrap()["error_description"],
        "mTLS authentication failed."
    );
}
