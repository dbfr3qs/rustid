//! Spans carry stable names. One test per binary: the
//! tracing subscriber is process-global.

use std::sync::{Arc, Mutex};

use rustid_testkit::client::Client;
use rustid_testkit::server::TestServer;
use rustid_testkit::test_config;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;

/// A span's name and its `endpoint_type` field.
type SpanRecord = (String, Option<String>);

#[derive(Clone, Default)]
struct Recorder(Arc<Mutex<Vec<SpanRecord>>>);

struct EndpointType(Option<String>);

impl Visit for EndpointType {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "endpoint_type" {
            self.0 = Some(value.to_owned());
        }
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "endpoint_type" {
            self.0 = Some(format!("{value:?}").trim_matches('"').to_owned());
        }
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Recorder {
    fn on_new_span(&self, attrs: &Attributes<'_>, _: &Id, _: Context<'_, S>) {
        let mut endpoint = EndpointType(None);
        attrs.record(&mut endpoint);
        self.0
            .lock()
            .unwrap()
            .push((attrs.metadata().name().to_owned(), endpoint.0));
    }
}

#[tokio::test]
async fn spans_have_stable_names() {
    let recorder = Recorder::default();
    tracing_subscriber::registry().with(recorder.clone()).init();
    let server = TestServer::spawn(test_config()).await.unwrap();
    let client = Client::new().unwrap();
    client
        .post_form(
            &server.url("/connect/token"),
            &[
                ("grant_type", "client_credentials"),
                ("client_id", "client"),
                ("client_secret", "secret"),
                ("scope", "api1"),
            ],
        )
        .await
        .unwrap();
    client
        .get(&server.url("/.well-known/openid-configuration/jwks"))
        .await
        .unwrap();
    server.shutdown().await.unwrap();
    let spans = recorder.0.lock().unwrap().clone();
    let names: Vec<&str> = spans.iter().map(|(n, _)| n.as_str()).collect();
    for expected in [
        "ProtocolRequest",
        "client.authenticate",
        "token.validate_request",
        "token.respond",
        "discovery.jwks",
    ] {
        assert!(
            names.contains(&expected),
            "{expected} missing from {names:?}"
        );
    }
    let endpoints: Vec<&str> = spans
        .iter()
        .filter(|(n, _)| n == "ProtocolRequest")
        .filter_map(|(_, e)| e.as_deref())
        .collect();
    assert_eq!(endpoints, ["TokenEndpoint", "DiscoveryKeyEndpoint"]);
}
