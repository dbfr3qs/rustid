//! Logs, traces and metrics. Logs always go to stdout through `tracing`;
//! with `[telemetry.otlp]` configured, spans are exported as OpenTelemetry
//! traces and the metrics in `rustid_core::telemetry` are exported too, both
//! over OTLP/HTTP.

use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::{WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::config::{LogConfig, LogFormat, TelemetryConfig};

/// Flushes and stops the exporters when dropped (or on `shutdown`). Call
/// `shutdown` from a blocking context (for example `spawn_blocking`).
#[derive(Default)]
pub struct TelemetryGuard {
    tracer: Option<SdkTracerProvider>,
    meter: Option<SdkMeterProvider>,
}

impl TelemetryGuard {
    pub fn shutdown(mut self) {
        self.stop();
    }

    fn stop(&mut self) {
        if let Some(tracer) = self.tracer.take()
            && let Err(error) = tracer.shutdown()
        {
            eprintln!("stopping the trace exporter: {error}");
        }
        if let Some(meter) = self.meter.take()
            && let Err(error) = meter.shutdown()
        {
            eprintln!("stopping the metrics exporter: {error}");
        }
    }
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        // The exporters' blocking HTTP clients must not be shut down (or
        // dropped) on an async runtime thread.
        if tokio::runtime::Handle::try_current().is_ok() {
            let mut rest = std::mem::take(self);
            std::thread::spawn(move || rest.stop());
        } else {
            self.stop();
        }
    }
}

/// Installs the global tracing subscriber and, when OTLP is configured, the
/// global tracer and meter providers. Later calls in the same process keep
/// the first subscriber, so tests that spawn several servers don't panic.
pub fn init_telemetry(log: &LogConfig, telemetry: &TelemetryConfig) -> TelemetryGuard {
    let mut guard = TelemetryGuard::default();
    let mut otel_layer = None;
    if let Some(otlp) = &telemetry.otlp {
        let resource = Resource::builder()
            .with_service_name(telemetry.service_name.clone())
            .build();
        let base = otlp.endpoint.trim_end_matches('/');
        let spans = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_endpoint(format!("{base}/v1/traces"))
            .with_headers(otlp.headers.clone().into_iter().collect())
            .build();
        let metrics = opentelemetry_otlp::MetricExporter::builder()
            .with_http()
            .with_endpoint(format!("{base}/v1/metrics"))
            .with_headers(otlp.headers.clone().into_iter().collect())
            .build();
        match (spans, metrics) {
            (Ok(spans), Ok(metrics)) => {
                let tracer = SdkTracerProvider::builder()
                    .with_batch_exporter(spans)
                    .with_resource(resource.clone())
                    .build();
                otel_layer = Some(
                    tracing_opentelemetry::layer()
                        .with_tracer(tracer.tracer(rustid_core::telemetry::METER_NAME)),
                );
                let interval =
                    std::time::Duration::from_secs(telemetry.metrics_interval.0.unsigned_abs());
                let meter = SdkMeterProvider::builder()
                    .with_reader(
                        PeriodicReader::builder(metrics)
                            .with_interval(interval)
                            .build(),
                    )
                    .with_resource(resource)
                    .build();
                opentelemetry::global::set_meter_provider(meter.clone());
                guard.tracer = Some(tracer);
                guard.meter = Some(meter);
            }
            (Err(error), _) | (_, Err(error)) => {
                eprintln!("OTLP export disabled: {error}");
            }
        }
    }
    // `log.level` filters the log only; exported spans have their own
    // filter, so a quiet log doesn't silence traces.
    let filter = || EnvFilter::try_new(&log.level).unwrap_or_else(|_| EnvFilter::new("info"));
    let registry = tracing_subscriber::registry()
        .with(otel_layer.map(|layer| layer.with_filter(LevelFilter::INFO)));
    // A second call fails because a subscriber is already set; that's fine.
    let _ = match log.format {
        LogFormat::Json => registry
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_filter(filter()),
            )
            .try_init(),
        LogFormat::Pretty => registry
            .with(tracing_subscriber::fmt::layer().with_filter(filter()))
            .try_init(),
    };
    guard
}
