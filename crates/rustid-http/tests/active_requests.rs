//! `tokenservice.active_requests` returns to zero when a request is
//! abandoned mid-flight, however the request ends. One test per
//! binary: the meter provider is process-global.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Method, Request};
use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData};
use opentelemetry_sdk::metrics::{InMemoryMetricExporter, PeriodicReader, SdkMeterProvider};
use rustid_core::clients::{Client, Clients};
use rustid_core::resources::Resources;
use rustid_core::stores::{ClientStore, StoreError};
use rustid_http::{AppState, ProtocolState};
use tower::ServiceExt;

/// A client store that never answers, like a hung database.
struct Hung;

#[async_trait]
impl ClientStore for Hung {
    async fn find_client_by_id(&self, _: &str) -> Result<Option<Arc<Client>>, StoreError> {
        std::future::pending().await
    }
    async fn is_cors_origin_allowed(&self, _: &str) -> Result<bool, StoreError> {
        std::future::pending().await
    }
}

#[tokio::test]
async fn an_abandoned_request_is_no_longer_counted_as_active() {
    let exporter = InMemoryMetricExporter::default();
    let provider = SdkMeterProvider::builder()
        .with_reader(PeriodicReader::builder(exporter.clone()).build())
        .build();
    opentelemetry::global::set_meter_provider(provider.clone());

    let mut stores = rustid_store_memory::stores(Clients::default(), Resources::default());
    stores.clients = Arc::new(Hung);
    let app = rustid_http::router(AppState::new(ProtocolState {
        options: Default::default(),
        keys: Default::default(),
        features: Default::default(),
        stores,
        events: Default::default(),
        path_base: None,
        protected_resource: None,
        dcr: None,
        saml: Default::default(),
        interaction: Default::default(),
    }));
    let request = Request::builder()
        .method(Method::POST)
        .uri("/connect/token")
        .header("host", "server")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "grant_type=client_credentials&client_id=c&client_secret=s",
        ))
        .unwrap();
    // The client gives up; the handler future is dropped mid-request.
    let abandoned = tokio::time::timeout(Duration::from_millis(100), app.oneshot(request)).await;
    assert!(abandoned.is_err(), "the store never answers");

    provider.force_flush().unwrap();
    let mut active = None;
    for resource in exporter.get_finished_metrics().unwrap() {
        for scope in resource.scope_metrics() {
            for metric in scope.metrics() {
                if metric.name() == "tokenservice.active_requests"
                    && let AggregatedMetrics::I64(MetricData::Sum(sum)) = metric.data()
                {
                    active = sum.data_points().map(|p| p.value()).last();
                }
            }
        }
    }
    assert_eq!(active, Some(0));
}
