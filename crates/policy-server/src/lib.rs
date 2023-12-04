mod admission_review;
mod api;
mod communication;
pub mod config;
mod metrics;
mod policy_downloader;
mod raw_review;
mod server;
mod worker;
mod worker_pool;

use anyhow::{anyhow, Result};
use lazy_static::lazy_static;
use opentelemetry::global::shutdown_tracer_provider;
use policy_evaluator::policy_fetcher::sigstore;
use policy_evaluator::policy_fetcher::verify::FulcioAndRekorData;
use policy_evaluator::{callback_handler::CallbackHandlerBuilder, kube};
use std::fs;
use std::{process, sync::RwLock, thread};
use tokio::{runtime::Runtime, sync::mpsc, sync::oneshot};
use tracing::{debug, error, info, warn};
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

use communication::{EvalRequest, WorkerPoolBootRequest};
use config::Config;
use policy_downloader::Downloader;
use worker_pool::WorkerPool;

lazy_static! {
    static ref TRACE_SYSTEM_INITIALIZED: RwLock<bool> = RwLock::new(false);
}

pub fn run(config: Config) -> Result<()> {
    // Run in daemon mode if specified by the user
    if config.daemon {
        println!("Running instance as a daemon");

        let mut daemonize = daemonize::Daemonize::new().pid_file(config.daemon_pid_file);
        if let Some(stdout_file) = config.daemon_stdout_file {
            let file = fs::File::create(stdout_file)
                .map_err(|e| anyhow!("Cannot create file for daemon stdout: {}", e))?;
            daemonize = daemonize.stdout(file);
        }
        if let Some(stderr_file) = config.daemon_stderr_file {
            let file = fs::File::create(stderr_file)
                .map_err(|e| anyhow!("Cannot create file for daemon stderr: {}", e))?;
            daemonize = daemonize.stderr(file);
        }

        daemonize
            .start()
            .map_err(|e| anyhow!("Cannot daemonize: {}", e))?;

        println!("Detached from shell, now running in background.");
    }

    ////////////////////////////////////////////////////////////////////////////
    //                                                                        //
    // Phase 1: setup the CallbackHandler. This is used by the synchronous    //
    // world (the waPC host_callback) to request the execution of code that   //
    // can be run only inside of asynchronous world.                          //
    // An example of that, is a policy that changes the container image       //
    // references to ensure they use immutable shasum instead of tags.        //
    // The act of retrieving the container image manifest digest requires a   //
    // network request, which is fulfilled using asynchronous code.           //
    //                                                                        //
    // The communication between the two worlds happens via tokio channels.   //
    //                                                                        //
    ////////////////////////////////////////////////////////////////////////////

    // This is a channel used to stop the tokio task that is run
    // inside of the CallbackHandler
    let (callback_handler_shutdown_channel_tx, callback_handler_shutdown_channel_rx) =
        oneshot::channel();

    let fulcio_and_rekor_data = match sigstore::tuf::SigstoreRepository::fetch(None) {
        Ok(repo) => Some(FulcioAndRekorData::FromTufRepository { repo }),
        Err(e) => {
            // We cannot rely on `tracing` yet, because the tracing system has not
            // been initialized, this has to be done inside of an async block, which
            // we cannot use yet
            eprintln!("Cannot fetch TUF repository: {e:?}");
            eprintln!("Sigstore Verifier created without Fulcio data: keyless signatures are going to be discarded because they cannot be verified");
            eprintln!(
                "Sigstore Verifier created without Rekor data: transparency log data won't be used"
            );
            eprintln!("Sigstore capabilities are going to be limited");
            None
        }
    };

    let mut callback_handler_builder =
        CallbackHandlerBuilder::new(callback_handler_shutdown_channel_rx)
            .registry_config(config.sources.clone())
            .fulcio_and_rekor_data(fulcio_and_rekor_data.as_ref());

    // Attempt to build kube::Client instance, this unfortunately needs an async context
    // for a really limited amount of time.
    //
    // Important: the tokio runtime used to create the `kube::Client` **must**
    // be the very same one used later on when the client is used.
    let rt = Runtime::new()?;

    let kube_client: Option<kube::Client> = rt.block_on(async {
        match kube::Client::try_default().await {
            Ok(client) => Some(client),
            Err(e) => {
                // We cannot rely on `tracing` yet, because the tracing system has not
                // been initialized yet
                eprintln!("Cannot connect to Kubernetes cluster: {e}");
                None
            }
        }
    });

    match kube_client {
        Some(client) => {
            callback_handler_builder = callback_handler_builder.kube_client(client);
        }
        None => {
            if config.ignore_kubernetes_connection_failure {
                // We cannot rely on `tracing` yet, because the tracing system has not
                // been initialized yet
                eprintln!(
                    "Cannot connect to Kubernetes, context aware policies will not work properly"
                );
            } else {
                return Err(anyhow!(
                    "Cannot connect to Kubernetes, context aware policies would not work properly"
                ));
            }
        }
    };

    let mut callback_handler = callback_handler_builder.build()?;
    let callback_sender_channel = callback_handler.sender_channel();

    ////////////////////////////////////////////////////////////////////////////
    //                                                                        //
    // Phase 2: setup the Wasm worker pool, this "lives" inside of a          //
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
    // (e.g. OpenTelemetry) require a tokio::Runtime to be available.
    let (worker_pool_bootstrap_req_tx, worker_pool_bootstrap_req_rx) =
        oneshot::channel::<WorkerPoolBootRequest>();

    // Spawn the system thread that runs the main loop of the worker pool manager
    let wasm_thread = thread::spawn(move || {
        let worker_pool = WorkerPool::new(
            worker_pool_bootstrap_req_rx,
            api_rx,
            callback_sender_channel,
            config.always_accept_admission_reviews_on_namespace,
            config.policy_evaluation_limit,
        );
        worker_pool.run();
    });

    ////////////////////////////////////////////////////////////////////////////
    //                                                                        //
    // Phase 3: setup the asynchronous world.                                 //
    //                                                                        //
    // We setup the tokio Runtime manually, instead of relying on the the     //
    // `tokio::main` macro, because we don't want the "synchronous" world to  //
    // be spawned inside of one of the threads owned by the runtime.          //
    //                                                                        //
    ////////////////////////////////////////////////////////////////////////////

    rt.block_on(async {
        // Setup the tracing system. This MUST be done inside of a tokio Runtime
        // because some collectors rely on it and would panic otherwise.
        match setup_tracing(&config.log_level, &config.log_fmt, config.log_no_color) {
            Err(err) => {
                fatal_error(err.to_string());
                unreachable!();
            }
            Ok(_) => {
                debug!("tracing system ready");
                let mut w = TRACE_SYSTEM_INITIALIZED.write().unwrap();
                *w = true;
            }
        };

        // The unused variable is required so the meter is not dropped early and
        // lives for the whole block lifetime, exporting metrics
        let _meter = if config.metrics_enabled {
            Some(metrics::init_meter())
        } else {
            None
        };

        // Download policies
        let mut downloader = match Downloader::new(
            config.sources.clone(),
            config.verification_config.is_some(),
            Some(config.sigstore_cache_dir.clone()),
        )
        .await
        {
            Ok(d) => d,
            Err(e) => {
                fatal_error(e.to_string());
                unreachable!()
            }
        };

        let fetched_policies = match downloader
            .download_policies(
                &config.policies,
                &config.policies_download_dir,
                config.verification_config.as_ref(),
            )
            .await
        {
            Ok(fp) => fp,
            Err(e) => {
                fatal_error(e.to_string());
                unreachable!()
            }
        };

        // Spawn the tokio task used by the CallbackHandler
        let callback_handle = tokio::spawn(async move {
            info!(status = "init", "CallbackHandler task");
            callback_handler.loop_eval().await;
            info!(status = "exit", "CallbackHandler task");
        });

        // Bootstrap the worker pool
        info!(status = "init", "worker pool bootstrap");
        let (worker_pool_bootstrap_res_tx, mut worker_pool_bootstrap_res_rx) =
            oneshot::channel::<Result<()>>();
        let bootstrap_data = WorkerPoolBootRequest {
            policies: config.policies,
            fetched_policies,
            pool_size: config.pool_size,
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
        memory_usage(config.pool_size);

        // All is good, we can start listening for incoming requests through the
        // web server
        server::run_server(&config.addr, config.tls_config, api_tx).await;

        // The evaluation is done, we can shutdown the tokio task that is running
        // the CallbackHandler
        if callback_handler_shutdown_channel_tx.send(()).is_err() {
            error!("Cannot shut down the CallbackHandler task");
        } else if let Err(e) = callback_handle.await {
            error!(
                error = e.to_string().as_str(),
                "Error waiting for the CallbackHandler task"
            );
        }
    });

    if let Err(e) = wasm_thread.join() {
        fatal_error(format!("error while waiting for worker threads: {e:?}"));
    };

    Ok(())
}

fn memory_usage(pool_size: usize) {
    let process = match procfs::process::Process::myself() {
        Ok(p) => p,
        Err(e) => {
            warn!(error =? e, "cannot access process stats");
            return;
        }
    };
    let mem_stats = match process.statm() {
        Ok(s) => s,
        Err(e) => {
            warn!(error =? e, "cannot access process memory stats");
            return;
        }
    };

    let formatter = humansize::make_format(humansize::DECIMAL);

    let vm_size = mem_stats.size * procfs::page_size();
    let vm_rss = mem_stats.resident * procfs::page_size();

    debug!(
        VmSize = formatter(vm_size),
        VmSizeBytes = vm_size,
        VmRSS = formatter(vm_rss),
        VmRSSBytes = vm_rss,
        pool_size,
        "memory usage"
    );
}

// Setup the tracing system. This MUST be done inside of a tokio Runtime
// because some collectors rely on it and would panic otherwise.
fn setup_tracing(log_level: &str, log_fmt: &str, log_no_color: bool) -> Result<()> {
    // setup logging
    let filter_layer = EnvFilter::new(log_level)
        // some of our dependencies generate trace events too, but we don't care about them ->
        // let's filter them
        .add_directive("cranelift_codegen=off".parse().unwrap())
        .add_directive("cranelift_wasm=off".parse().unwrap())
        .add_directive("h2=off".parse().unwrap())
        .add_directive("hyper=off".parse().unwrap())
        .add_directive("regalloc=off".parse().unwrap())
        .add_directive("tower=off".parse().unwrap())
        .add_directive("wasmtime_cranelift=off".parse().unwrap())
        .add_directive("wasmtime_jit=off".parse().unwrap());

    match log_fmt {
        "json" => tracing_subscriber::registry()
            .with(filter_layer)
            .with(fmt::layer().json())
            .init(),
        "text" => {
            let layer = fmt::layer().with_ansi(log_no_color);

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

pub fn fatal_error(msg: String) {
    let trace_system_ready = TRACE_SYSTEM_INITIALIZED.read().unwrap();
    if *trace_system_ready {
        error!("{}", msg);
        shutdown_tracer_provider();
    } else {
        eprintln!("{msg}");
    }

    process::exit(1);
}
