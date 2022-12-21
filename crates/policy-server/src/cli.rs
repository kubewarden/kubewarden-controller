use crate::settings::{read_policies_file, Policy};
use anyhow::{anyhow, Result};
use clap::builder::PossibleValue;
use clap::{crate_authors, crate_description, crate_name, crate_version, Arg, Command};
use itertools::Itertools;
use lazy_static::lazy_static;
use policy_evaluator::burrego;
use policy_evaluator::policy_fetcher::{
    sources::{read_sources_file, Sources},
    verify::config::{read_verification_file, LatestVerificationConfig},
};
use std::{collections::HashMap, env, net::SocketAddr, path::Path};
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

static SERVICE_NAME: &str = "kubewarden-policy-server";
const DOCKER_CONFIG_ENV_VAR: &str = "DOCKER_CONFIG";

lazy_static! {
    static ref VERSION_AND_BUILTINS: String = {
        let builtins: String = burrego::get_builtins()
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

pub(crate) fn build_cli() -> Command {
    Command::new(crate_name!())
        .author(crate_authors!())
        .version(crate_version!())
        .about(crate_description!())
        .arg(
            Arg::new("log-level")
                .long("log-level")
                .value_name("LOG_LEVEL")
                .env("KUBEWARDEN_LOG_LEVEL")
                .default_value("info")
                .value_parser([
                    PossibleValue::new("trace"),
                    PossibleValue::new("debug"),
                    PossibleValue::new("info"),
                    PossibleValue::new("warn"),
                    PossibleValue::new("error"),
                ])
                .help("Log level"),
        )
        .arg(
            Arg::new("log-fmt")
                .long("log-fmt")
                .value_name("LOG_FMT")
                .env("KUBEWARDEN_LOG_FMT")
                .default_value("text")
                .value_parser([
                    PossibleValue::new("text"),
                    PossibleValue::new("json"),
                    PossibleValue::new("otlp"),
                ])
                .help("Log output format"),
        )
        .arg(
            Arg::new("log-no-color")
                .long("log-no-color")
                .env("NO_COLOR")
                .required(false)
                .help("Disable colored output for logs"),
        )
        .arg(
            Arg::new("address")
                .long("addr")
                .value_name("BIND_ADDRESS")
                .default_value("0.0.0.0")
                .env("KUBEWARDEN_BIND_ADDRESS")
                .help("Bind against ADDRESS"),
        )
        .arg(
            Arg::new("port")
                .long("port")
                .value_name("PORT")
                .default_value("3000")
                .env("KUBEWARDEN_PORT")
                .help("Listen on PORT"),
        )
        .arg(
            Arg::new("workers")
                .long("workers")
                .value_name("WORKERS_NUMBER")
                .env("KUBEWARDEN_WORKERS")
                .help("Number of workers thread to create"),
        )
        .arg(
            Arg::new("cert-file")
                .long("cert-file")
                .value_name("CERT_FILE")
                .default_value("")
                .env("KUBEWARDEN_CERT_FILE")
                .help("Path to an X.509 certificate file for HTTPS"),
        )
        .arg(
            Arg::new("key-file")
                .long("key-file")
                .value_name("KEY_FILE")
                .default_value("")
                .env("KUBEWARDEN_KEY_FILE")
                .help("Path to an X.509 private key file for HTTPS"),
        )
        .arg(
            Arg::new("policies")
                .long("policies")
                .value_name("POLICIES_FILE")
                .env("KUBEWARDEN_POLICIES")
                .default_value("policies.yml")
                .help("YAML file holding the policies to be loaded and their settings"),
        )
        .arg(
            Arg::new("policies-download-dir")
                .long("policies-download-dir")
                .value_name("POLICIES_DOWNLOAD_DIR")
                .default_value(".")
                .env("KUBEWARDEN_POLICIES_DOWNLOAD_DIR")
                .help("Download path for the policies"),
        )
        .arg(
            Arg::new("sigstore-cache-dir")
                .long("sigstore-cache-dir")
                .value_name("SIGSTORE_CACHE_DIR")
                .default_value("sigstore-data")
                .env("KUBEWARDEN_SIGSTORE_CACHE_DIR")
                .help("Directory used to cache sigstore data"),
        )
        .arg(
            Arg::new("sources-path")
                .long("sources-path")
                .value_name("SOURCES_PATH")
                .env("KUBEWARDEN_SOURCES_PATH")
                .help("YAML file holding source information (https, registry insecure hosts, custom CA's...)"),
        )
        .arg(
            Arg::new("verification-path")
                .long("verification-path")
                .value_name("VERIFICATION_CONFIG_PATH")
                .env("KUBEWARDEN_VERIFICATION_CONFIG_PATH")
                .help("YAML file holding verification information (URIs, keys, annotations...)"),
        )
        .arg(
            Arg::new("docker-config-json-path")
                .long("docker-config-json-path")
                .value_name("DOCKER_CONFIG")
                .env("KUBEWARDEN_DOCKER_CONFIG_JSON_PATH")
                .help("Path to a Docker config.json-like path. Can be used to indicate registry authentication details"),
        )
        .arg(
            Arg::new("enable-metrics")
                .long("enable-metrics")
                .env("KUBEWARDEN_ENABLE_METRICS")
                .required(false)
                .help("Enable metrics"),
        )
        .arg(
            Arg::new("enable-verification")
                .long("enable-verification")
                .env("KUBEWARDEN_ENABLE_VERIFICATION")
                .required(false)
                .help("Enable Sigstore verification"),
        )
        .arg(
            Arg::new("always-accept-admission-reviews-on-namespace")
                .long("always-accept-admission-reviews-on-namespace")
                .value_name("NAMESPACE")
                .env("KUBEWARDEN_ALWAYS_ACCEPT_ADMISSION_REVIEWS_ON_NAMESPACE")
                .required(false)
                .help("Always accept AdmissionReviews that target the given namespace"),
        )
        .arg(
            Arg::new("disable-timeout-protection")
                .long("disable-timeout-protection")
                .env("KUBEWARDEN_DISABLE_TIMEOUT_PROTECTION")
                .required(false)
                .help("Disable policy timeout protection"),
        )
        .arg(
            Arg::new("policy-timeout")
                .long("policy-timeout")
                .env("KUBEWARDEN_POLICY_TIMEOUT")
                .value_name("MAXIMUM_EXECUTION_TIME_SECONDS")
                .default_value("2")
                .help("Interrupt policy evaluation after the given time"),
        )
        .arg(
            Arg::new("daemon")
                .long("daemon")
                .env("KUBEWARDEN_DAEMON")
                .required(false)
                .help("If set, runs policy-server in detached mode as a daemon"),
        )
        .arg(
            Arg::new("daemon-pid-file")
                .long("daemon-pid-file")
                .env("KUBEWARDEN_DAEMON_PID_FILE")
                .default_value("policy-server.pid")
                .help("Path to pid file, used only when running in daemon mode"),
        )
        .arg(
            Arg::new("daemon-stdout-file")
                .long("daemon-stdout-file")
                .env("KUBEWARDEN_DAEMON_STDOUT_FILE")
                .required(false)
                .help("Path to file holding stdout, used only when running in daemon mode"),
        )
        .arg(
            Arg::new("daemon-stderr-file")
                .long("daemon-stderr-file")
                .env("KUBEWARDEN_DAEMON_STDERR_FILE")
                .required(false)
                .help("Path to file holding stderr, used only when running in daemon mode"),
        )
        .long_version(VERSION_AND_BUILTINS.as_str())
}

pub(crate) fn api_bind_address(matches: &clap::ArgMatches) -> Result<SocketAddr> {
    format!(
        "{}:{}",
        matches.get_one::<String>("address").unwrap(),
        matches.get_one::<String>("port").unwrap()
    )
    .parse()
    .map_err(|e| anyhow!("error parsing arguments: {}", e))
}

pub(crate) fn tls_files(matches: &clap::ArgMatches) -> Result<(String, String)> {
    let cert_file = matches.get_one::<String>("cert-file").unwrap().to_owned();
    let key_file = matches.get_one::<String>("key-file").unwrap().to_owned();
    if cert_file.is_empty() != key_file.is_empty() {
        Err(anyhow!("error parsing arguments: either both --cert-file and --key-file must be provided, or neither"))
    } else {
        Ok((cert_file, key_file))
    }
}

pub(crate) fn policies(matches: &clap::ArgMatches) -> Result<HashMap<String, Policy>> {
    let policies_file = Path::new(matches.get_one::<String>("policies").unwrap());
    read_policies_file(policies_file).map_err(|e| {
        anyhow!(
            "error while loading policies from {:?}: {}",
            policies_file,
            e
        )
    })
}

pub(crate) fn verification_config(
    matches: &clap::ArgMatches,
) -> Result<Option<LatestVerificationConfig>> {
    match matches.get_one::<String>("verification-path") {
        None => Ok(None),
        Some(path) => {
            let verification_file = Path::new(path);
            Ok(Some(read_verification_file(verification_file)?))
        }
    }
}

// Setup the tracing system. This MUST be done inside of a tokio Runtime
// because some collectors rely on it and would panic otherwise.
pub(crate) fn setup_tracing(matches: &clap::ArgMatches) -> Result<()> {
    // setup logging
    let filter_layer = EnvFilter::new(matches.get_one::<String>("log-level").unwrap())
        // some of our dependencies generate trace events too, but we don't care about them ->
        // let's filter them
        .add_directive("cranelift_codegen=off".parse().unwrap())
        .add_directive("cranelift_wasm=off".parse().unwrap())
        .add_directive("wasmtime_cranelift=off".parse().unwrap())
        .add_directive("regalloc=off".parse().unwrap())
        .add_directive("hyper=off".parse().unwrap())
        .add_directive("h2=off".parse().unwrap())
        .add_directive("tower=off".parse().unwrap());

    match matches.get_one::<String>("log-fmt").unwrap().as_str() {
        "json" => tracing_subscriber::registry()
            .with(filter_layer)
            .with(fmt::layer().json())
            .init(),
        "text" => {
            let enable_color = !matches.contains_id("log-no-color");
            let layer = fmt::layer().with_ansi(enable_color);

            tracing_subscriber::registry()
                .with(filter_layer)
                .with(layer)
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

pub(crate) fn remote_server_options(matches: &clap::ArgMatches) -> Result<Option<Sources>> {
    let sources = match matches.get_one::<String>("sources-path") {
        Some(sources_file) => Some(
            read_sources_file(Path::new(sources_file))
                .map_err(|e| anyhow!("error while loading sources from {}: {}", sources_file, e))?,
        ),
        None => None,
    };

    if let Some(docker_config_json_path) = matches.get_one::<String>("docker-config-json-path") {
        // docker_credential crate expects the config path in the $DOCKER_CONFIG. Keep docker-config-json-path parameter for backwards compatibility
        env::set_var(DOCKER_CONFIG_ENV_VAR, docker_config_json_path);
    }

    Ok(sources)
}
