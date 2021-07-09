extern crate k8s_openapi;
extern crate kube;

use kube::Client;
use std::{
    net::SocketAddr,
    process,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Barrier,
    },
    thread,
};
use tokio::sync::mpsc::channel;
use tracing::{debug, error, info};
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

mod admission_review;
mod api;
mod cli;
mod server;
mod settings;
mod utils;
mod worker;

mod worker_pool;
use worker_pool::WorkerPool;

use policy_evaluator::cluster_context::ClusterContext;
use policy_fetcher::registry::config::{read_docker_config_json_file, DockerConfig};
use policy_fetcher::sources::{read_sources_file, Sources};

use settings::read_policies_file;

use std::path::{Path, PathBuf};

mod communication;
use communication::EvalRequest;

fn main() {
    let matches = cli::build_cli().get_matches();

    // setup logging
    let filter_layer = EnvFilter::new(matches.value_of("log-level").unwrap_or_default())
        // some of our dependencies generate trace events too, but we don't care about them ->
        // let's filter them
        .add_directive("cranelift_codegen=off".parse().unwrap())
        .add_directive("cranelift_wasm=off".parse().unwrap())
        .add_directive("regalloc=off".parse().unwrap())
        .add_directive("hyper::proto=off".parse().unwrap());

    match matches.value_of("log-fmt").unwrap_or_default() {
        "json" => tracing_subscriber::registry()
            .with(filter_layer)
            .with(fmt::layer().json())
            .init(),
        "text" => tracing_subscriber::registry()
            .with(filter_layer)
            .with(fmt::layer())
            .init(),
        "jaeger" => {
            // Create a new OpenTelemetry pipeline sending events
            // to a jaeger instance
            // The Jaeger exporter can be configerd via environment
            // variables (https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/sdk-environment-variables.md#jaeger-exporter)
            let tracer = opentelemetry_jaeger::new_pipeline()
                .with_service_name("kubewarden-policy-server")
                .install_simple()
                .unwrap();

            // Create a tracing layer with the configured tracer
            let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);
            tracing_subscriber::registry()
                .with(filter_layer)
                .with(telemetry)
                .with(fmt::layer())
                .init()
        }
        "otlp" => {
            // Create a new OpenTelemetry pipeline sending events to a
            // OpenTelemetry collector using the OTLP format.
            // The collector must run on localhost (eg: use a sidecar inside of k8s)
            // using GRPC
            let tracer = opentelemetry_otlp::new_pipeline()
                .with_tonic()
                .install_simple()
                .unwrap();

            // Create a tracing layer with the configured tracer
            let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);
            tracing_subscriber::registry()
                .with(filter_layer)
                .with(telemetry)
                .with(fmt::layer())
                .init()
        }

        _ => fatal_error("Unknown log message format".to_string()),
    };

    let addr: SocketAddr = match format!(
        "{}:{}",
        matches.value_of("address").unwrap(),
        matches.value_of("port").unwrap()
    )
    .parse()
    {
        Ok(a) => a,
        Err(error) => {
            fatal_error(format!("error parsing arguments: {}", error));
            unreachable!();
        }
    };

    let cert_file = String::from(matches.value_of("cert-file").unwrap());
    let key_file = String::from(matches.value_of("key-file").unwrap());
    if cert_file.is_empty() != key_file.is_empty() {
        fatal_error("error parsing arguments: either both --cert-file and --key-file must be provided, or neither.".to_string());
    };

    let policies_file = Path::new(matches.value_of("policies").unwrap_or("."));
    let mut policies = match read_policies_file(policies_file) {
        Ok(policies) => policies,
        Err(err) => {
            fatal_error(format!(
                "error while loading policies from {:?}: {}",
                policies_file, err
            ));
            unreachable!();
        }
    };

    let (sources, docker_config) = remote_server_options(&matches);

    // Download policies
    let policies_download_dir = matches.value_of("policies-download-dir").unwrap();
    let policies_total = policies.len();
    info!(
        download_dir = policies_download_dir,
        policies_count = policies_total,
        "policies download started",
    );
    for (name, policy) in policies.iter_mut() {
        debug!(policy = name.as_str(), "download");
        let policy_path = policy_fetcher::fetch_policy(
            &policy.url,
            policy_fetcher::PullDestination::Store(PathBuf::from(policies_download_dir)),
            docker_config.clone(),
            sources.as_ref(),
        )
        .await;
        match policy_path {
            Ok(path) => policy.wasm_module_path = path,
            Err(e) => {
                fatal_error(format!(
                    "error while fetching policy {} from {}: {}",
                    name, policy.url, e
                ));
            }
        };
    }
    info!("policies download completed");

    let kubernetes_client = Client::try_default()
       .await
       .map_err(|e| anyhow!("could not initialize a cluster context because a Kubernetes client could not be created: {}", e));
    if let Ok(kubernetes_client) = kubernetes_client {
        // Ensure that we do an initial refresh before starting any policy
        let refresh = ClusterContext::get().refresh(&kubernetes_client).await;

        if let Err(err) = refresh {
            info!("error when refreshing the cluster context: {}", err);
        }

        info!("cluster context initialized");
    };
    thread::spawn(|| async {
        info!("spawning cluster context refresh loop");
        loop {
            let kubernetes_client = Client::try_default()
                .await
                .map_err(|e| anyhow!("could not initialize a cluster context because a Kubernetes client could not be created: {}", e));

            match kubernetes_client {
                Ok(kubernetes_client) => loop {
                    let refresh = ClusterContext::get().refresh(&kubernetes_client).await;

                    if let Err(err) = refresh {
                        info!("error when refreshing the cluster context: {}", err);
                    }

                    thread::sleep(std::time::Duration::from_secs(5));
                },
                Err(err) => {
                    info!(
                        "error when initializing the cluster context client: {}",
                        err
                    );
                    thread::sleep(std::time::Duration::from_secs(5));
                    continue;
                }
            }
        }
    });

    let (api_tx, api_rx) = channel::<EvalRequest>(32);
    let pool_size = matches.value_of("workers").map_or_else(num_cpus::get, |v| {
        v.parse::<usize>()
            .expect("error parsing the number of workers")
    });

    // Barrier used to wait for all the workers to be ready.
    // The barrier prevents the web server from starting before the workers are
    // ready to process the incoming requests send by the Kubernetes.
    // This mechanism is used to create a Kubernetes HTTP readiness probe
    let barrier = Arc::new(Barrier::new(pool_size + 1));
    let main_barrier = barrier.clone();

    // The boot canary is a boolean that is set to false when one of more
    // workers can't be started. This kind of failures can happen when a
    // Wasm module is broken.
    let boot_canary = Arc::new(AtomicBool::new(true));
    let main_boot_canary = boot_canary.clone();

    info!(pool_size, "starting workers pool");
    let wasm_thread = thread::spawn(move || {
        let worker_pool =
            WorkerPool::new(pool_size, policies.clone(), api_rx, barrier, boot_canary);
        worker_pool.run();
    });
    // wait for all the workers to be ready, then ensure none of them had issues
    // at boot time
    main_barrier.wait();
    if !main_boot_canary.load(Ordering::SeqCst) {
        fatal_error("could not init one of the workers".to_string());
    }

    // All is good, we can start listening for incoming requests through the
    // web server
    let tls_acceptor = if cert_file.is_empty() {
        None
    } else {
        match server::new_tls_acceptor(&cert_file, &key_file) {
            Ok(t) => Some(t),
            Err(e) => {
                fatal_error(format!("error while creating tls acceptor: {:?}", e));
                unreachable!();
            }
        }
    };
    server::run_server(&addr, tls_acceptor, api_tx).await;

    if let Err(e) = wasm_thread.join() {
        fatal_error(format!("error while waiting for worker threads: {:?}", e));
    };

    Ok(())
}

fn remote_server_options(matches: &clap::ArgMatches) -> (Option<Sources>, Option<DockerConfig>) {
    let sources = matches.value_of("sources-path").map(|sources_file| {
        match read_sources_file(Path::new(sources_file)) {
            Ok(sources) => sources,
            Err(err) => {
                fatal_error(format!(
                    "error while loading sources from {}: {}",
                    sources_file, err
                ));
                unreachable!();
            }
        }
    });

    let docker_config =
        matches
            .value_of("docker-config-json-path")
            .map(|docker_config_json_path_file| {
                match read_docker_config_json_file(Path::new(docker_config_json_path_file)) {
                    Ok(docker_config_json) => docker_config_json,
                    Err(err) => {
                        fatal_error(format!(
                            "error while loading docker-config-json-like path from {}: {}",
                            docker_config_json_path_file, err
                        ));
                        unreachable!();
                    }
                }
            });

    (sources, docker_config)
}

fn fatal_error(msg: String) {
    error!("{}", msg);
    process::exit(1);
}
