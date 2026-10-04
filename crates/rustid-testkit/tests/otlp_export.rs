//! With `[telemetry.otlp]` configured, traces and metrics reach the
//! collector over OTLP/HTTP. One test per binary: exporters are global.

use std::sync::{Arc, Mutex};

use rustid_server::config::OtlpConfig;
use rustid_testkit::client::Client;
use rustid_testkit::server::TestServer;
use rustid_testkit::test_config;

/// Path, content type and `x-api-key` of a request the collector received.
type Received = (String, String, Option<String>);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn traces_and_metrics_are_exported_to_the_collector() {
    let received: Arc<Mutex<Vec<Received>>> = Arc::default();
    let seen = received.clone();
    let collector = axum::Router::new().fallback(move |request: axum::extract::Request| {
        let seen = seen.clone();
        async move {
            let header = |name: &str| {
                request
                    .headers()
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned)
            };
            seen.lock().unwrap().push((
                request.uri().path().to_owned(),
                header("content-type").unwrap_or_default(),
                header("x-api-key"),
            ));
            ""
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, collector).await.unwrap() });

    let mut config = test_config();
    // A quiet log must not silence traces.
    config.log.level = "error".into();
    config.telemetry.otlp = Some(OtlpConfig {
        endpoint: format!("http://{addr}/"),
        headers: [("x-api-key".to_owned(), "k".to_owned())].into(),
    });
    let server = TestServer::spawn(config).await.unwrap();
    Client::new()
        .unwrap()
        .post_form(
            &server.url("/connect/token"),
            &[
                ("grant_type", "client_credentials"),
                ("client_id", "client"),
                ("client_secret", "secret"),
            ],
        )
        .await
        .unwrap();
    // Shutting down flushes both exporters.
    server.shutdown().await.unwrap();
    let received = received.lock().unwrap().clone();
    for path in ["/v1/traces", "/v1/metrics"] {
        assert!(
            received.iter().any(|(p, content_type, key)| p == path
                && content_type == "application/x-protobuf"
                && key.as_deref() == Some("k")),
            "{path} missing from {received:?}"
        );
    }
}
