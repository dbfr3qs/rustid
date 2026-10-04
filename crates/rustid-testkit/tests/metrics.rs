//! The metrics a running server records, read back through an in-memory
//! exporter. One test per binary: the meter provider is process-global and
//! must be installed before the first instrument is used.

use opentelemetry::{KeyValue, Value};
use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData};
use opentelemetry_sdk::metrics::{InMemoryMetricExporter, PeriodicReader, SdkMeterProvider};
use rustid_testkit::client::Client;
use rustid_testkit::server::TestServer;
use rustid_testkit::test_config;

/// Every data point of `name` as (attributes, value).
fn points(exporter: &InMemoryMetricExporter, name: &str) -> Vec<(Vec<(String, String)>, i64)> {
    let mut out = Vec::new();
    for resource in exporter.get_finished_metrics().unwrap() {
        for scope in resource.scope_metrics() {
            for metric in scope.metrics().filter(|m| m.name() == name) {
                let attrs = |kv: &mut dyn Iterator<Item = &KeyValue>| {
                    let mut v: Vec<(String, String)> = kv
                        .map(|kv| (kv.key.to_string(), value(&kv.value)))
                        .collect();
                    v.sort();
                    v
                };
                match metric.data() {
                    AggregatedMetrics::U64(MetricData::Sum(sum)) => {
                        for p in sum.data_points() {
                            out.push((attrs(&mut p.attributes()), p.value() as i64));
                        }
                    }
                    AggregatedMetrics::I64(MetricData::Sum(sum)) => {
                        for p in sum.data_points() {
                            out.push((attrs(&mut p.attributes()), p.value()));
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    out
}

fn value(v: &Value) -> String {
    match v {
        Value::Bool(b) => b.to_string(),
        other => other.as_str().into_owned(),
    }
}

fn has(points: &[(Vec<(String, String)>, i64)], tags: &[(&str, &str)], at_least: i64) -> bool {
    points.iter().any(|(attrs, v)| {
        *v >= at_least
            && tags
                .iter()
                .all(|(k, want)| attrs.iter().any(|(ak, av)| ak == k && av == want))
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn requests_record_the_instruments_and_tags() {
    let exporter = InMemoryMetricExporter::default();
    let provider = SdkMeterProvider::builder()
        .with_reader(PeriodicReader::builder(exporter.clone()).build())
        .build();
    opentelemetry::global::set_meter_provider(provider.clone());

    let server = TestServer::spawn(test_config()).await.unwrap();
    let client = Client::new().unwrap();
    let token = |id: &'static str, secret: &'static str| {
        let client = &client;
        let url = server.url("/connect/token");
        async move {
            client
                .post_form(
                    &url,
                    &[
                        ("grant_type", "client_credentials"),
                        ("client_id", id),
                        ("client_secret", secret),
                        ("scope", "api1"),
                    ],
                )
                .await
                .unwrap()
        }
    };
    let issued = token("client", "secret").await;
    let rustid_testkit::recorded::Body::Json(issued) = issued.body else {
        panic!("no token");
    };
    let jwt = issued["access_token"].as_str().unwrap().to_owned();
    token("client.reference", "secret").await;
    token("client", "wrong").await;
    // The validating client store: a missing client is a validation failure; a
    // disabled one validates, then is unknown to the secret validator.
    token("nope", "secret").await;
    token("client.disabled", "secret").await;
    let introspect = |form: Vec<(&'static str, String)>| {
        let client = &client;
        let url = server.url("/connect/introspect");
        async move {
            let pairs: Vec<(&str, &str)> = form.iter().map(|(k, v)| (*k, v.as_str())).collect();
            client.post_form(&url, &pairs).await.unwrap()
        }
    };
    introspect(vec![
        ("client_id", "api".into()),
        ("client_secret", "secret".into()),
        ("token", jwt.clone()),
    ])
    .await;
    introspect(vec![
        ("client_id", "api".into()),
        ("client_secret", "secret".into()),
    ])
    .await;
    // A client caller is tried as an API first.
    introspect(vec![
        ("client_id", "client".into()),
        ("client_secret", "secret".into()),
        ("token", jwt.clone()),
    ])
    .await;
    client
        .post_form(
            &server.url("/connect/revocation"),
            &[
                ("client_id", "client"),
                ("client_secret", "secret"),
                ("token", "x"),
                ("token_type_hint", "id_token"),
            ],
        )
        .await
        .unwrap();
    server.shutdown().await.unwrap();
    provider.force_flush().unwrap();

    let issued = points(&exporter, "tokenservice.token_issued");
    assert!(
        has(
            &issued,
            &[
                ("client", "client"),
                ("grant_type", "client_credentials"),
                ("access_token_issued", "true"),
                ("access_token_type", "Jwt"),
                ("refresh_token_issued", "false"),
                ("proof_type", "None"),
                ("id_token_issued", "false")
            ],
            1
        ),
        "{issued:?}"
    );
    assert!(
        has(
            &issued,
            &[
                ("client", "client.reference"),
                ("access_token_type", "Reference")
            ],
            1
        ),
        "{issued:?}"
    );
    assert!(
        issued
            .iter()
            .any(|(a, _)| a == &vec![("error".to_owned(), "invalid_client".to_owned())]),
        "a failed client authentication has no client tag: {issued:?}"
    );

    let secrets = points(&exporter, "tokenservice.client.secret_validation");
    // The token request and the revocation request.
    assert!(
        has(
            &secrets,
            &[("client", "client"), ("auth_method", "SharedSecret")],
            2
        ),
        "{secrets:?}"
    );
    assert!(
        has(
            &secrets,
            &[("client", "client"), ("error", "Invalid client secret")],
            1
        ),
        "{secrets:?}"
    );

    let api = points(&exporter, "tokenservice.api.secret_validation");
    assert!(
        has(&api, &[("api", "api"), ("auth_method", "SharedSecret")], 2),
        "{api:?}"
    );
    assert!(
        has(
            &api,
            &[("client", "client"), ("error", "Unknown API resource")],
            1
        ),
        "{api:?}"
    );

    let introspection = points(&exporter, "tokenservice.introspection");
    assert!(
        has(&introspection, &[("caller", "api"), ("active", "true")], 1),
        "{introspection:?}"
    );
    assert!(
        has(
            &introspection,
            &[("caller", "api"), ("error", "missing_token")],
            1
        ),
        "{introspection:?}"
    );

    let revocation = points(&exporter, "tokenservice.revocation");
    assert!(
        has(
            &revocation,
            &[("client", "client"), ("error", "unsupported_token_type")],
            1
        ),
        "{revocation:?}"
    );

    let config = points(&exporter, "tokenservice.client.config_validation");
    assert!(has(&config, &[("client", "client")], 1), "{config:?}");
    assert!(
        has(
            &config,
            &[("client", "nope"), ("error", "Client not found")],
            1
        ),
        "{config:?}"
    );
    assert!(
        config
            .iter()
            .any(|(a, _)| a == &vec![("client".to_owned(), "client.disabled".to_owned())]),
        "{config:?}"
    );

    let active = points(&exporter, "tokenservice.active_requests");
    assert!(
        active.iter().any(|(a, v)| *v == 0
            && a.contains(&("endpoint".into(), "TokenEndpoint".into()))
            && a.contains(&("path".into(), "/connect/token".into()))),
        "requests are counted in and out: {active:?}"
    );

    let operations = points(&exporter, "tokenservice.operation");
    assert!(
        has(
            &operations,
            &[("client", "client"), ("result", "success")],
            1
        ),
        "{operations:?}"
    );
    assert!(
        has(
            &operations,
            &[("result", "error"), ("error", "Invalid client secret")],
            1
        ),
        "{operations:?}"
    );
}
