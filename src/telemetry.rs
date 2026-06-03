use opentelemetry::trace::TracerProvider;
use opentelemetry_otlp::{Protocol, WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::{
    Resource,
    logs::SdkLoggerProvider,
    trace::{Sampler, SdkTracerProvider},
};
use opentelemetry_semantic_conventions::resource::{SERVICE_NAME, SERVICE_VERSION};
use std::collections::HashMap;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

const DEFAULT_SERVICE_NAME: &str = env!("CARGO_PKG_NAME");
const DEFAULT_SERVICE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Determine the OTLP protocol from the `OTEL_EXPORTER_OTLP_PROTOCOL` env var.
/// Defaults to `grpc` when not set.
fn otlp_protocol() -> Option<Protocol> {
    match std::env::var("OTEL_EXPORTER_OTLP_PROTOCOL")
        .unwrap_or_default()
        .as_str()
    {
        "http/json" => Some(Protocol::HttpJson),
        "http/protobuf" => Some(Protocol::HttpBinary),
        "grpc" => Some(Protocol::Grpc),
        "" => None,
        other => {
            eprintln!("warning: OTEL_EXPORTER_OTLP_PROTOCOL={other:?} unrecognized");
            None
        }
    }
}

/// Parse `OTEL_EXPORTER_OTLP_HEADERS` into a `HashMap`.
///
/// The format is `key1=value1,key2=value2`.
fn otlp_headers() -> HashMap<String, String> {
    let raw = std::env::var("OTEL_EXPORTER_OTLP_HEADERS").unwrap_or_default();
    if raw.is_empty() {
        return HashMap::new();
    }
    raw.split(',')
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next()?.trim();
            let value = parts.next()?.trim();
            if key.is_empty() {
                return None;
            }
            Some((key.to_string(), value.to_string()))
        })
        .collect()
}

/// Build a tonic `MetadataMap` from header key-value pairs.
///
/// Only the `MetadataMap` type is re-exported by `opentelemetry_otlp::tonic_types`,
/// so we use its `from_headers` constructor with an `http::HeaderMap`.
fn build_tonic_metadata(
    headers: &HashMap<String, String>,
) -> opentelemetry_otlp::tonic_types::metadata::MetadataMap {
    let mut header_map = reqwest::header::HeaderMap::new();
    for (k, v) in headers {
        if let (Ok(name), Ok(val)) = (
            reqwest::header::HeaderName::from_bytes(k.as_bytes()),
            reqwest::header::HeaderValue::from_str(v),
        ) {
            header_map.insert(name, val);
        }
    }
    opentelemetry_otlp::tonic_types::metadata::MetadataMap::from_headers(header_map)
}

/// Build the shared `Resource` that identifies this service.
fn build_resource() -> Resource {
    Resource::builder()
        .with_attribute(opentelemetry::KeyValue::new(
            SERVICE_NAME,
            std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| DEFAULT_SERVICE_NAME.to_string()),
        ))
        .with_attribute(opentelemetry::KeyValue::new(
            SERVICE_VERSION,
            DEFAULT_SERVICE_VERSION,
        ))
        .build()
}

/// Build the OTLP span exporter for the given protocol.
fn build_span_exporter(
    protocol: Protocol,
    headers: &HashMap<String, String>,
) -> opentelemetry_otlp::SpanExporter {
    match protocol {
        Protocol::Grpc => {
            use opentelemetry_otlp::WithTonicConfig;

            let mut builder = opentelemetry_otlp::SpanExporter::builder().with_tonic();
            if let Ok(endpoint) = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT") {
                builder = builder.with_endpoint(endpoint);
            }
            if !headers.is_empty() {
                builder = builder.with_metadata(build_tonic_metadata(headers));
            }
            builder.build().expect("failed to build gRPC span exporter")
        }
        _ => {
            // http/json or http/protobuf
            let mut builder = opentelemetry_otlp::SpanExporter::builder()
                .with_http()
                .with_protocol(protocol);
            if let Ok(endpoint) = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT") {
                builder = builder.with_endpoint(format!("{endpoint}/v1/traces"));
            }
            if !headers.is_empty() {
                builder = builder.with_headers(headers.clone());
            }
            builder.build().expect("failed to build HTTP span exporter")
        }
    }
}

/// Build the OTLP log exporter for the given protocol.
fn build_log_exporter(
    protocol: Protocol,
    headers: &HashMap<String, String>,
) -> opentelemetry_otlp::LogExporter {
    match protocol {
        Protocol::Grpc => {
            use opentelemetry_otlp::WithTonicConfig;

            let mut builder = opentelemetry_otlp::LogExporter::builder().with_tonic();
            if let Ok(endpoint) = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT") {
                builder = builder.with_endpoint(endpoint);
            }
            if !headers.is_empty() {
                builder = builder.with_metadata(build_tonic_metadata(headers));
            }
            builder.build().expect("failed to build gRPC log exporter")
        }
        _ => {
            let mut builder = opentelemetry_otlp::LogExporter::builder()
                .with_http()
                .with_protocol(protocol);
            if let Ok(endpoint) = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT") {
                builder = builder.with_endpoint(format!("{endpoint}/v1/logs"));
            }
            if !headers.is_empty() {
                builder = builder.with_headers(headers.clone());
            }
            builder.build().expect("failed to build HTTP log exporter")
        }
    }
}

/// Guards that flush and shut down the OTLP providers on drop.
pub struct TelemetryGuard {
    tracer_provider: SdkTracerProvider,
    logger_provider: SdkLoggerProvider,
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if let Err(e) = self.tracer_provider.shutdown() {
            eprintln!("error shutting down tracer provider: {e}");
        }
        if let Err(e) = self.logger_provider.shutdown() {
            eprintln!("error shutting down logger provider: {e}");
        }
    }
}

/// Initialise the tracing/logging stack.
///
/// When `OTEL_EXPORTER_OTLP_PROTOCOL` is set to a recognized value,
/// OpenTelemetry OTLP export for both traces and logs is enabled on top of
/// `tracing-subscriber`.  Otherwise only the plain `fmt` layer is used so
/// that the binary works out-of-the-box without a collector.
///
/// The caller **must** hold on to the returned [`TelemetryGuard`] for the
/// entire lifetime of the application so that the providers are shut down
/// gracefully and all buffered telemetry is flushed.
///
/// # Environment variables
///
/// | Variable | Description | Default |
/// |---|---|---|
/// | `OTEL_EXPORTER_OTLP_PROTOCOL` | `grpc`, `http/json`, or `http/protobuf` | |
/// | `OTEL_EXPORTER_OTLP_ENDPOINT` | Collector base URL | SDK default |
/// | `OTEL_EXPORTER_OTLP_HEADERS` | `k1=v1,k2=v2` | (none) |
/// | `OTEL_SERVICE_NAME` | Logical service name | `nerve` |
/// | `RUST_LOG` | `tracing_subscriber` env-filter | `info` |
pub fn init_telemetry() -> Option<TelemetryGuard> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let fmt_layer = tracing_subscriber::fmt::layer();

    let Some(protocol) = otlp_protocol() else {
        // No OTLP env var – lightweight fmt-only setup.
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .init();

        return None;
    };
    let headers = otlp_headers();
    let resource = build_resource();

    // ── Traces ──────────────────────────────────────────────────────────
    let span_exporter = build_span_exporter(protocol, &headers);

    let tracer_provider = SdkTracerProvider::builder()
        .with_sampler(Sampler::AlwaysOn)
        .with_resource(resource.clone())
        .with_batch_exporter(span_exporter)
        .build();

    let tracer = tracer_provider.tracer(DEFAULT_SERVICE_NAME);

    // ── Logs ────────────────────────────────────────────────────────────
    let log_exporter = build_log_exporter(protocol, &headers);

    let logger_provider = SdkLoggerProvider::builder()
        .with_resource(resource)
        .with_batch_exporter(log_exporter)
        .build();

    // ── Subscriber assembly ─────────────────────────────────────────────
    let otel_trace_layer = tracing_opentelemetry::layer().with_tracer(tracer);
    let otel_log_layer =
        opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(&logger_provider);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .with(otel_trace_layer)
        .with(otel_log_layer)
        .init();

    Some(TelemetryGuard {
        tracer_provider,
        logger_provider,
    })
}
