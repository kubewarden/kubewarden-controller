use anyhow::{anyhow, Result};
use opentelemetry::trace::TracerProvider;
use opentelemetry_otlp::WithExportConfig;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

use crate::config;

// Setup the tracing system. This MUST be done inside of a tokio Runtime
// because some collectors rely on it and would panic otherwise.
pub fn setup_tracing(
    log_level: &str,
    log_fmt: &str,
    log_no_color: bool,
    otlp_endpoint: Option<&str>,
) -> Result<()> {
    // setup logging
    let filter_layer = EnvFilter::new(log_level)
        // some of our dependencies generate trace events too, but we don't care about them ->
        // let's filter them
        .add_directive("cranelift_codegen=off".parse().unwrap())
        .add_directive("cranelift_wasm=off".parse().unwrap())
        .add_directive("h2=off".parse().unwrap())
        .add_directive("hyper=off".parse().unwrap())
        .add_directive("rustls=off".parse().unwrap())
        .add_directive("regalloc=off".parse().unwrap())
        .add_directive("wasmtime_cranelift=off".parse().unwrap())
        .add_directive("wasmtime_jit=off".parse().unwrap());

    match log_fmt {
        "json" => tracing_subscriber::registry()
            .with(filter_layer)
            .with(fmt::layer().json())
            .init(),
        "text" => {
            let fmt_layer = fmt::layer().with_ansi(log_no_color);

            tracing_subscriber::registry()
                .with(filter_layer)
                .with(fmt_layer)
                .init()
        }
        "otlp" => {
            // Create a new OpenTelemetry pipeline sending events to a
            // OpenTelemetry collector using the OTLP format.
            // If no endpoint is provided, the default one is used.
            // The default endpoint is "http://localhost:4317".
            let mut otlp_exporter_builder =
                opentelemetry_otlp::SpanExporter::builder().with_tonic();

            if let Some(endpoint) = otlp_endpoint {
                otlp_exporter_builder = otlp_exporter_builder.with_endpoint(endpoint);
            }

            let otlp_exporter = otlp_exporter_builder.build()?;

            let tracer_provider = opentelemetry_sdk::trace::TracerProvider::builder()
                .with_resource(opentelemetry_sdk::Resource::new(vec![
                    opentelemetry::KeyValue::new("service.name", config::SERVICE_NAME),
                ]))
                .with_batch_exporter(otlp_exporter, opentelemetry_sdk::runtime::Tokio)
                .build();

            let tracer = tracer_provider.tracer(config::SERVICE_NAME);

            // Create a tracing layer with the configured tracer
            let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);
            tracing_subscriber::registry()
                .with(filter_layer)
                .with(telemetry)
                .with(fmt::layer())
                .init()
        }

        _ => return Err(anyhow!("Unknown log message format")),
    };

    Ok(())
}
