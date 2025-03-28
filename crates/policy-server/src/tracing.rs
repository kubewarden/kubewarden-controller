use anyhow::{anyhow, Result};
use opentelemetry::trace::TracerProvider;
use opentelemetry_otlp::WithTonicConfig;

use opentelemetry_sdk::Resource;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

use crate::config::{self, build_client_tls_config_from_env};

// Setup the tracing system. This MUST be done inside of a tokio Runtime
// because some collectors rely on it and would panic otherwise.
//
// The function returns an optional tracer provider that must be used to
// shut down the tracing system.
pub fn setup_tracing(
    log_level: &str,
    log_fmt: &str,
    log_no_color: bool,
) -> Result<Option<opentelemetry_sdk::trace::SdkTracerProvider>> {
    // setup logging
    let filter_layer = EnvFilter::new(log_level)
        // some of our dependencies generate trace events too, but we don't care about them ->
        // let's filter them
        .add_directive("cranelift_codegen=off".parse().unwrap())
        .add_directive("cranelift_wasm=off".parse().unwrap())
        .add_directive("h2=off".parse().unwrap())
        .add_directive("hyper=off".parse().unwrap())
        .add_directive("regalloc=off".parse().unwrap())
        .add_directive("wasmtime_cranelift=off".parse().unwrap())
        .add_directive("wasmtime_jit=off".parse().unwrap());

    let tracer = match log_fmt {
        "json" => {
            tracing_subscriber::registry()
                .with(filter_layer)
                .with(fmt::layer().json())
                .init();
            None
        }
        "text" => {
            let fmt_layer = fmt::layer().with_ansi(log_no_color);

            tracing_subscriber::registry()
                .with(filter_layer)
                .with(fmt_layer)
                .init();
            None
        }
        "otlp" => {
            // Create a new OpenTelemetry pipeline sending events to a
            // OpenTelemetry collector using the OTLP format.
            // If no endpoint is provided, the default one is used.
            // The default endpoint is "http://localhost:4317".
            //
            let otlp_exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_tonic()
                .with_tls_config(build_client_tls_config_from_env("OTLP")?)
                .build()?;

            let tracer_provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
                .with_resource(
                    Resource::builder()
                        .with_service_name(config::SERVICE_NAME)
                        .build(),
                )
                .with_batch_exporter(otlp_exporter)
                .build();

            let tracer = tracer_provider.tracer(config::SERVICE_NAME);

            // Create a tracing layer with the configured tracer
            let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);

            tracing_subscriber::registry()
                .with(filter_layer)
                .with(telemetry)
                .with(fmt::layer())
                .init();
            Some(tracer_provider)
        }

        _ => return Err(anyhow!("Unknown log message format")),
    };

    Ok(tracer)
}
