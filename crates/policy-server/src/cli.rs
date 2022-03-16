use crate::settings::{read_policies_file, Policy};
use anyhow::{anyhow, Result};
use clap::{crate_authors, crate_description, crate_name, crate_version, Arg, Command};
use itertools::Itertools;
use lazy_static::lazy_static;
use policy_evaluator::burrego::opa::builtins as opa_builtins;
use policy_fetcher::registry::config::{read_docker_config_json_file, DockerConfig};
use policy_fetcher::sources::{read_sources_file, Sources};
use policy_fetcher::verify::config::{read_verification_file, LatestVerificationConfig};
use std::{collections::HashMap, net::SocketAddr, path::Path};
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

static SERVICE_NAME: &str = "kubewarden-policy-server";

lazy_static! {
    static ref VERSION_AND_BUILTINS: String = {
        let builtins: String = opa_builtins::get_builtins()
            .keys()
            .sorted()
            .map(|builtin| format!("  - {}", builtin))
            .join("\n");

        format!(
            "{}\n\nOpen Policy Agent/Gatekeeper implemented builtins:\n{}",
            crate_version!(),
            builtins,
        )
    };
    pub(crate) static ref HOSTNAME: String =
        std::env::var("HOSTNAME").unwrap_or_else(|_| String::from("unknown"));
}

pub(crate) fn build_cli() -> Command<'static> {
    Command::new(crate_name!())
        .author(crate_authors!())
        .version(crate_version!())
        .about(crate_description!())
        .arg(
            Arg::new("log-level")
                .long("log-level")
                .takes_value(true)
                .env("KUBEWARDEN_LOG_LEVEL")
                .default_value("info")
                .possible_values(&["trace", "debug", "info", "warn", "error"])
                .help("Log level"),
        )
        .arg(
            Arg::new("log-fmt")
                .long("log-fmt")
                .takes_value(true)
                .env("KUBEWARDEN_LOG_FMT")
                .default_value("text")
                .possible_values(&["text", "json", "otlp"])
                .help("Log output format"),
        )
        .arg(
            Arg::new("address")
                .long("addr")
                .takes_value(true)
                .default_value("0.0.0.0")
                .env("KUBEWARDEN_BIND_ADDRESS")
                .help("Bind against ADDRESS"),
        )
        .arg(
            Arg::new("port")
                .long("port")
                .takes_value(true)
                .default_value("3000")
                .env("KUBEWARDEN_PORT")
                .help("Listen on PORT"),
        )
        .arg(
            Arg::new("workers")
                .long("workers")
                .takes_value(true)
                .env("KUBEWARDEN_WORKERS")
                .help("Number of workers thread to create"),
        )
        .arg(
            Arg::new("cert-file")
                .long("cert-file")
                .takes_value(true)
                .default_value("")
                .env("KUBEWARDEN_CERT_FILE")
                .help("Path to an X.509 certificate file for HTTPS"),
        )
        .arg(
            Arg::new("key-file")
                .long("key-file")
                .takes_value(true)
                .default_value("")
                .env("KUBEWARDEN_KEY_FILE")
                .help("Path to an X.509 private key file for HTTPS"),
        )
        .arg(
            Arg::new("policies")
                .long("policies")
                .takes_value(true)
                .env("KUBEWARDEN_POLICIES")
                .default_value("policies.yml")
                .help(
                    "YAML file holding the policies to be loaded and
                    their settings",
                ),
        )
        .arg(
            Arg::new("policies-download-dir")
                .long("policies-download-dir")
                .takes_value(true)
                .default_value(".")
                .env("KUBEWARDEN_POLICIES_DOWNLOAD_DIR")
                .help("Download path for the policies"),
        )
        .arg(
            Arg::new("sigstore-cache-dir")
                .long("sigstore-cache-dir")
                .takes_value(true)
                .default_value("sigstore-data")
                .env("KUBEWARDEN_SIGSTORE_CACHE_DIR")
                .help("Directory used to cache sigstore data"),
        )
        .arg(
            Arg::new("sources-path")
                .takes_value(true)
                .long("sources-path")
                .takes_value(true)
                .env("KUBEWARDEN_SOURCES_PATH")
                .help("YAML file holding source information (https, registry insecure hosts, custom CA's...)"),
        )
        .arg(
            Arg::new("verification-path")
                .env("KUBEWARDEN_VERIFICATION_CONFIG_PATH")
                .long("verification-path")
                .takes_value(true)
                .help("YAML file holding verification information (URIs, keys, annotations...)"),
        )
        .arg(
            Arg::new("docker-config-json-path")
                .env("KUBEWARDEN_DOCKER_CONFIG_JSON_PATH")
                .long("docker-config-json-path")
                .takes_value(true)
                .help("Path to a Docker config.json-like path. Can be used to indicate registry authentication details"),
        )
        .arg(
            Arg::new("enable-metrics")
                .long("enable-metrics")
                .takes_value(false)
                .env("KUBEWARDEN_ENABLE_METRICS")
                .required(false)
                .help("Enable metrics [env: KUBEWARDEN_ENABLE_METRICS=]"),
        )
        .arg(
            Arg::new("enable-verification")
                .long("enable-verification")
                .takes_value(false)
                .env("KUBEWARDEN_ENABLE_VERIFICATION")
                .required(false)
                .help("Enable Sigstore verification [env: KUBEWARDEN_ENABLE_VERIFICATION=]"),
        )
        .long_version(VERSION_AND_BUILTINS.as_str())
}

pub(crate) fn api_bind_address(matches: &clap::ArgMatches) -> Result<SocketAddr> {
    format!(
        "{}:{}",
        matches.value_of("address").unwrap(),
        matches.value_of("port").unwrap()
    )
    .parse()
    .map_err(|e| anyhow!("error parsing arguments: {}", e))
}

pub(crate) fn tls_files(matches: &clap::ArgMatches) -> Result<(String, String)> {
    let cert_file = String::from(matches.value_of("cert-file").unwrap());
    let key_file = String::from(matches.value_of("key-file").unwrap());
    if cert_file.is_empty() != key_file.is_empty() {
        Err(anyhow!("error parsing arguments: either both --cert-file and --key-file must be provided, or neither"))
    } else {
        Ok((cert_file, key_file))
    }
}

pub(crate) fn policies(matches: &clap::ArgMatches) -> Result<HashMap<String, Policy>> {
    let policies_file = Path::new(matches.value_of("policies").unwrap_or("."));
    read_policies_file(policies_file).map_err(|e| {
        anyhow!(
            "error while loading policies from {:?}: {}",
            policies_file,
            e
        )
    })
}

pub(crate) fn verification_config(matches: &clap::ArgMatches) -> Result<LatestVerificationConfig> {
    match matches.value_of("verification-path") {
        None => Err(anyhow!(
            "error parsing arguments: --verification-path must be provided"
        )),
        Some(path) => {
            let verification_file = Path::new(path);
            read_verification_file(verification_file)
        }
    }
}

// Setup the tracing system. This MUST be done inside of a tokio Runtime
// because some collectors rely on it and would panic otherwise.
pub(crate) fn setup_tracing(matches: &clap::ArgMatches) -> Result<()> {
    // setup logging
    let filter_layer = EnvFilter::new(matches.value_of("log-level").unwrap_or_default())
        // some of our dependencies generate trace events too, but we don't care about them ->
        // let's filter them
        .add_directive("cranelift_codegen=off".parse().unwrap())
        .add_directive("cranelift_wasm=off".parse().unwrap())
        .add_directive("regalloc=off".parse().unwrap())
        .add_directive("hyper=off".parse().unwrap())
        .add_directive("h2=off".parse().unwrap())
        .add_directive("tower=off".parse().unwrap());

    match matches.value_of("log-fmt").unwrap_or_default() {
        "json" => tracing_subscriber::registry()
            .with(filter_layer)
            .with(fmt::layer().json())
            .init(),
        "text" => tracing_subscriber::registry()
            .with(filter_layer)
            .with(fmt::layer())
            .init(),
        "otlp" => {
            // Create a new OpenTelemetry pipeline sending events to a
            // OpenTelemetry collector using the OTLP format.
            // The collector must run on localhost (eg: use a sidecar inside of k8s)
            // using GRPC
            let tracer = opentelemetry_otlp::new_pipeline()
                .tracing()
                .with_exporter(opentelemetry_otlp::new_exporter().tonic())
                .with_trace_config(opentelemetry::sdk::trace::config().with_resource(
                    opentelemetry::sdk::Resource::new(vec![opentelemetry::KeyValue::new(
                        "service.name",
                        SERVICE_NAME,
                    )]),
                ))
                .install_batch(opentelemetry::runtime::Tokio)?;

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

pub(crate) fn remote_server_options(
    matches: &clap::ArgMatches,
) -> Result<(Option<Sources>, Option<DockerConfig>)> {
    let sources = match matches.value_of("sources-path") {
        Some(sources_file) => Some(
            read_sources_file(Path::new(sources_file))
                .map_err(|e| anyhow!("error while loading sources from {}: {}", sources_file, e))?,
        ),
        None => None,
    };

    let docker_config = match matches.value_of("docker-config-json-path") {
        Some(docker_config_json_path_file) => Some(
            read_docker_config_json_file(Path::new(docker_config_json_path_file)).map_err(|e| {
                anyhow!(
                    "error while loading docker-config-json-like path from {}: {}",
                    docker_config_json_path_file,
                    e
                )
            })?,
        ),
        None => None,
    };

    Ok((sources, docker_config))
}
