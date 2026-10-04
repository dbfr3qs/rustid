//! The server's back-channel logout sender: the token posted as the form
//! field `logout_token`, without holding up the sign-out on a slow client.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustid_core::logout::BackChannelSender;
use rustid_server::back_channel::HttpBackChannelSender;

type Received = Arc<Mutex<Vec<(String, String)>>>;

async fn receiver(delay: Duration) -> (String, Received) {
    let received: Received = Arc::default();
    let log = received.clone();
    let app = axum::Router::new().route(
        "/backchannel",
        axum::routing::post(move |headers: axum::http::HeaderMap, body: String| {
            let log = log.clone();
            async move {
                tokio::time::sleep(delay).await;
                let content_type = headers
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_owned();
                log.lock().unwrap().push((content_type, body));
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await });
    (base, received)
}

async fn wait_for(received: &Received, count: usize) {
    let start = Instant::now();
    while received.lock().unwrap().len() < count {
        assert!(start.elapsed() < Duration::from_secs(5), "nothing received");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn posts_the_logout_token_as_a_form() {
    let (base, received) = receiver(Duration::ZERO).await;
    let sender = HttpBackChannelSender::new().unwrap();
    sender.send(&format!("{base}/backchannel"), "a.b+c").await;
    wait_for(&received, 1).await;
    let (content_type, body) = received.lock().unwrap()[0].clone();
    assert_eq!(content_type, "application/x-www-form-urlencoded");
    assert_eq!(body, "logout_token=a.b%2Bc");
}

#[tokio::test]
async fn a_slow_or_unreachable_client_does_not_hold_up_the_sign_out() {
    let (base, received) = receiver(Duration::from_secs(2)).await;
    let sender = HttpBackChannelSender::new().unwrap();
    let start = Instant::now();
    sender.send(&format!("{base}/backchannel"), "t").await;
    sender.send("http://127.0.0.1:1/unreachable", "t").await;
    assert!(start.elapsed() < Duration::from_millis(500));
    wait_for(&received, 1).await;
}

/// A TLS receiver whose certificate a private CA signed; the CA's PEM file.
async fn tls_receiver(dir: &std::path::Path) -> (String, Received, std::path::PathBuf) {
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
    std::fs::write(dir.join("ca.pem"), ca.pem()).unwrap();
    let tls = rustid_server::tls::server_config(&rustid_server::config::TlsConfig {
        client_certificates: Default::default(),
        cipher_suites: Default::default(),
        cert_file: dir.join("cert.pem"),
        key_file: dir.join("key.pem"),
    })
    .unwrap();
    let received: Received = Arc::default();
    let log = received.clone();
    let app = axum::Router::new().route(
        "/backchannel",
        axum::routing::post(move |body: String| {
            let log = log.clone();
            async move {
                log.lock().unwrap().push((String::new(), body));
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let listener = rustid_server::tls::TlsListener::new(listener, tls).unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await });
    (
        format!("https://localhost:{port}"),
        received,
        dir.join("ca.pem"),
    )
}

#[tokio::test]
async fn a_configured_ca_is_trusted_for_https_receivers() {
    let dir = tempfile::tempdir().unwrap();
    let (base, received, ca) = tls_receiver(dir.path()).await;
    let uri = format!("{base}/backchannel");

    HttpBackChannelSender::new()
        .unwrap()
        .send(&uri, "untrusted")
        .await;
    HttpBackChannelSender::with_ca_file(Some(&ca))
        .unwrap()
        .send(&uri, "trusted")
        .await;
    wait_for(&received, 1).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let bodies: Vec<String> = received
        .lock()
        .unwrap()
        .iter()
        .map(|(_, b)| b.clone())
        .collect();
    assert_eq!(bodies, ["logout_token=trusted"]);
}
