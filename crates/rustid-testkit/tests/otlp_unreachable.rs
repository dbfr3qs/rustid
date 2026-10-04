//! An unreachable collector costs requests nothing: exporters run in the
//! background and their failures are only logged. One test per binary.

use std::time::{Duration, Instant};

use rustid_server::config::OtlpConfig;
use rustid_testkit::client::Client;
use rustid_testkit::server::TestServer;
use rustid_testkit::test_config;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn requests_succeed_when_the_collector_is_down() {
    // Nothing listens on port 1.
    let mut config = test_config();
    config.telemetry.otlp = Some(OtlpConfig {
        endpoint: "http://127.0.0.1:1".into(),
        headers: Default::default(),
    });
    let server = TestServer::spawn(config).await.unwrap();
    let client = Client::new().unwrap();
    let started = Instant::now();
    for _ in 0..5 {
        let response = client
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
        assert_eq!(response.status, 200);
    }
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
    let stopping = Instant::now();
    server.shutdown().await.unwrap();
    assert!(
        stopping.elapsed() < Duration::from_secs(30),
        "{:?}",
        stopping.elapsed()
    );
}
