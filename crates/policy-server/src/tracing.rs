use anyhow::{anyhow, Result};
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

use crate::config;

// Setup the tracing system. This MUST be done inside of a tokio Runtime
// because some collectors rely on it and would panic otherwise.
pub fn setup_tracing(log_level: &str, log_fmt: &str, log_no_color: bool) -> Result<()> {
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
            // The collector must run on localhost (eg: use a sidecar inside of k8s)
            // using GRPC
            let tracer = opentelemetry_otlp::new_pipeline()
                .tracing()
                .with_exporter(opentelemetry_otlp::new_exporter().tonic())
                .with_trace_config(opentelemetry_sdk::trace::config().with_resource(
                    opentelemetry_sdk::Resource::new(vec![opentelemetry::KeyValue::new(
                        "service.name",
                        config::SERVICE_NAME,
                    )]),
                ))
                .install_batch(opentelemetry_sdk::runtime::Tokio)?;

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
