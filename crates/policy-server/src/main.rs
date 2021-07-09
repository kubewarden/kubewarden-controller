extern crate k8s_openapi;
extern crate kube;

use anyhow::{anyhow, Result};
use kube::Client;
use opentelemetry::global::shutdown_tracer_provider;
use std::{collections::HashMap, net::SocketAddr, process, thread};
use tokio::{runtime::Runtime, sync::mpsc, sync::oneshot};
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

use settings::{read_policies_file, Policy};

use std::path::{Path, PathBuf};

mod communication;
use communication::{EvalRequest, WorkerPoolBootRequest};

fn main() {
    let matches = cli::build_cli().get_matches();

    // init some variables based on the cli parameters
    let addr = api_bind_address(&matches);
    let (cert_file, key_file) = tls_files(&matches);
    let mut policies = policies(&matches);
    let (sources, docker_config) = remote_server_options(&matches);
    let pool_size = matches.value_of("workers").map_or_else(num_cpus::get, |v| {
        v.parse::<usize>()
            .expect("error parsing the number of workers")
    });

    ////////////////////////////////////////////////////////////////////////////
    //                                                                        //
    // Phase 1: setup the Wasm worker pool, this "lives" inside of a          //
    // dedicated system thread.                                               //
    //                                                                        //
    // The communication between the "synchronous world" (aka the Wasm worker //
    // pool) and the "asynchronous world" (aka the http server) happens via   //
    // tokio channels.                                                        //
    //                                                                        //
    ////////////////////////////////////////////////////////////////////////////

    // This is the channel used by the http server to communicate with the
    // Wasm workers
    let (api_tx, api_rx) = mpsc::channel::<EvalRequest>(32);

    // This is the channel used to have the asynchronous code trigger the
    // bootstrap of the worker pool. The bootstrap must be triggered
    // from within the asynchronous code because some of the tracing collectors
    // (e.g. jaeger, OpenTelemetry) require a tokio::Runtime to be available.
    let (worker_pool_bootstrap_req_tx, worker_pool_bootstrap_req_rx) =
        oneshot::channel::<WorkerPoolBootRequest>();

    // Spawn the system thread that runs the main loop of the worker pool manager
    let wasm_thread = thread::spawn(move || {
        let worker_pool = WorkerPool::new(worker_pool_bootstrap_req_rx, api_rx);
        worker_pool.run();
    });

    ////////////////////////////////////////////////////////////////////////////
    //                                                                        //
    // Phase 2: setup the asynchronous world.                                 //
    //                                                                        //
    // We setup the tokio Runtime manually, instead of relying on the the     //
    // `tokio::main` macro, because we don't want the "synchronous" world to  //
    // be spawned inside of one of the threads owned by the runtime.          //
    //                                                                        //
    ////////////////////////////////////////////////////////////////////////////

    let rt = match Runtime::new() {
        Ok(r) => r,
        Err(error) => {
            fatal_error(format!("error initializing tokio runtime: {}", error));
            unreachable!();
        }
    };
    rt.block_on(async {
        // Setup the tracing system. This MUST be done inside of a tokio Runtime
        // because some collectors rely on it and would panic otherwise.
        if let Err(err) = setup_tracing(&matches) {
            fatal_error(err.to_string());
        }

        // Download policies
        let policies_download_dir = matches.value_of("policies-download-dir").unwrap();
        let policies_total = policies.len();
        info!(
            download_dir = policies_download_dir,
            policies_count = policies_total,
            status = "init",
            "policies download",
        );
        for (name, policy) in policies.iter_mut() {
            debug!(policy = name.as_str(), "download");
            match policy_fetcher::fetch_policy(
                &policy.url,
                policy_fetcher::PullDestination::Store(PathBuf::from(policies_download_dir)),
                docker_config.clone(),
                sources.as_ref(),
            )
            .await
            {
                Ok(path) => policy.wasm_module_path = path,
                Err(e) => {
                    return fatal_error(format!(
                        "error while fetching policy {} from {}: {}",
                        name, policy.url, e
                    ));
                }
            };
        }
        info!(status = "done", "policies download");

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



        // Bootstrap the worker pool
        info!(status = "init", "worker pool bootstrap");
        let (worker_pool_bootstrap_res_tx, mut worker_pool_bootstrap_res_rx) =
            oneshot::channel::<Result<()>>();
        let bootstrap_data = WorkerPoolBootRequest {
            policies,
            pool_size,
            resp_chan: worker_pool_bootstrap_res_tx,
        };
        if worker_pool_bootstrap_req_tx.send(bootstrap_data).is_err() {
            fatal_error("Cannot send bootstrap data to worker pool".to_string());
        }

        // Wait for the worker pool to be fully bootstraped before moving on.
        //
        // It's really important to NOT start the web server before the workers are ready.
        // Our Kubernetes deployment exposes a readiness probe that relies on the web server
        // to be listening. The API server will start hitting the policy server as soon as the
        // readiness probe marks the instance as ready.
        // We don't want Kubernetes API server to send admission reviews before ALL the workers
        // are ready.
        loop {
            match worker_pool_bootstrap_res_rx.try_recv() {
                Ok(res) => match res {
                    Ok(_) => break,
                    Err(e) => fatal_error(e.to_string()),
                },
                Err(oneshot::error::TryRecvError::Empty) => {
                    // the channel is empty, keep waiting
                }
                _ => {
                    fatal_error("Cannot receive worker pool bootstrap result".to_string());
                    return;
                }
            }
        }
        info!(status = "done", "worker pool bootstrap");

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
    });

    if let Err(e) = wasm_thread.join() {
        fatal_error(format!("error while waiting for worker threads: {:?}", e));
    };

    Ok(())
}

// Setup the tracing system. This MUST be done inside of a tokio Runtime
// because some collectors rely on it and would panic otherwise.
fn setup_tracing(matches: &clap::ArgMatches) -> Result<()> {
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
                .install_simple()?;

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
                .install_simple()?;

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

fn api_bind_address(matches: &clap::ArgMatches) -> SocketAddr {
    match format!(
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
    }
}

fn tls_files(matches: &clap::ArgMatches) -> (String, String) {
    let cert_file = String::from(matches.value_of("cert-file").unwrap());
    let key_file = String::from(matches.value_of("key-file").unwrap());
    if cert_file.is_empty() != key_file.is_empty() {
        fatal_error("error parsing arguments: either both --cert-file and --key-file must be provided, or neither.".to_string());
    };
    (cert_file, key_file)
}

fn policies(matches: &clap::ArgMatches) -> HashMap<String, Policy> {
    let policies_file = Path::new(matches.value_of("policies").unwrap_or("."));
    match read_policies_file(policies_file) {
        Ok(policies) => policies,
        Err(err) => {
            fatal_error(format!(
                "error while loading policies from {:?}: {}",
                policies_file, err
            ));
            unreachable!();
        }
    }
}

fn fatal_error(msg: String) {
    error!("{}", msg);
    shutdown_tracer_provider();

    process::exit(1);
}
