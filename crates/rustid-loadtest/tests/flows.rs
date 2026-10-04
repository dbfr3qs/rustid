//! Each flow against rustid in process: every request succeeds, and the
//! statistics are sane.

use std::time::Duration;

use rustid_loadtest::{Flow, percentile, run};

async fn server() -> String {
    let config = rustid_server::config::ServerConfig::load(Some(std::path::Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/profiles/default.json"
    ))))
    .unwrap();
    let app = rustid_server::build(&config).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(rustid_server::serve(listener, app, std::future::pending()));
    base
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_flow_succeeds_against_rustid() {
    let base = server().await;
    for flow in Flow::ALL {
        let result = run(
            &base,
            flow,
            2,
            Duration::from_millis(500),
            Some(std::process::id()),
        )
        .await
        .unwrap();
        assert_eq!(
            result.errors, 0,
            "{flow:?} had errors: {:?}",
            result.first_error
        );
        assert!(
            result.requests >= 2,
            "{flow:?} ran {} requests",
            result.requests
        );
        assert_eq!(result.latencies.len() as u64, result.requests);
        assert!(result.server.unwrap().peak_rss_kib > 0);
    }
}

#[test]
fn percentiles_pick_the_nearest_rank() {
    let sorted: Vec<Duration> = (1..=100).map(Duration::from_millis).collect();
    assert_eq!(percentile(&sorted, 50.0), Duration::from_millis(50));
    assert_eq!(percentile(&sorted, 99.0), Duration::from_millis(99));
    assert_eq!(percentile(&sorted, 100.0), Duration::from_millis(100));
    assert_eq!(percentile(&[], 50.0), Duration::ZERO);
}

#[test]
fn the_report_has_a_table_per_flow_and_the_ratio() {
    use rustid_loadtest::report::{FlowReport, LevelReport, Report, TargetRun};
    let result = |rps: u64, ms: u64| rustid_loadtest::RunResult {
        requests: rps * 10,
        errors: 0,
        first_error: None,
        latencies: vec![Duration::from_millis(ms); (rps * 10) as usize],
        wall: Duration::from_secs(10),
        server: Some(rustid_loadtest::Sample {
            cpu_seconds: 5.0,
            peak_rss_kib: 51200,
        }),
        harness: None,
    };
    let report = Report {
        header: "# Performance\n".into(),
        flows: vec![FlowReport {
            flow: Flow::Discovery,
            levels: vec![LevelReport {
                concurrency: 16,
                targets: vec![
                    TargetRun {
                        name: "rustid".into(),
                        median: result(2000, 2),
                        errors: 0,
                        runs: 3,
                    },
                    TargetRun {
                        name: "reference".into(),
                        median: result(1000, 4),
                        errors: 1,
                        runs: 3,
                    },
                ],
            }],
        }],
    };
    let text = rustid_loadtest::report::render(&report);
    assert!(text.starts_with("# Performance\n"));
    assert!(text.contains("## discovery"));
    assert!(text.contains("| 16 | rustid | 2000 | 2.0 |"), "{text}");
    assert!(text.contains("| 0.50 |"), "server CPU cores: {text}");
    assert!(text.contains("| 50 |"), "peak RSS MiB: {text}");
    assert!(
        text.contains("rustid ÷ reference at 16: 2.00× req/s, 0.50× p50"),
        "{text}"
    );
    // The reference side had errors: the ratio line says so.
    assert!(
        text.contains("rustid ÷ reference at 16: 2.00× req/s, 0.50× p50 (errors in the runs)"),
        "{text}"
    );
}

/// A server whose every answer is a quick 400.
async fn failing_server() -> String {
    let app =
        axum::Router::new().fallback(|| async { (axum::http::StatusCode::BAD_REQUEST, "no") });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    base
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn errors_count_apart_from_throughput_and_latency() {
    let base = failing_server().await;
    let result = run(&base, Flow::Discovery, 2, Duration::from_millis(300), None)
        .await
        .unwrap();
    assert!(result.errors > 0);
    assert_eq!(result.requests, 0, "failed operations aren't throughput");
    assert!(
        result.latencies.is_empty(),
        "failed operations aren't latency samples"
    );
    assert_eq!(result.requests_per_second(), 0.0);
    assert!(result.first_error.unwrap().contains("400"));
}
