extern crate k8s_openapi;
extern crate policy_evaluator;

use anyhow::Result;
use lazy_static::lazy_static;
use opentelemetry::global::shutdown_tracer_provider;
use policy_evaluator::callback_handler::CallbackHandlerBuilder;
use policy_evaluator::policy_fetcher::sigstore;
use policy_evaluator::policy_fetcher::verify::FulcioAndRekorData;
use std::{path::PathBuf, process, sync::RwLock, thread};
use tokio::{runtime::Runtime, sync::mpsc, sync::oneshot};
use tracing::{debug, error, info};

mod admission_review;
mod api;
mod cli;
mod kube_poller;
mod metrics;
mod server;
mod settings;
mod worker;

mod policy_downloader;
use policy_downloader::Downloader;

mod worker_pool;
use worker_pool::WorkerPool;

mod communication;
use communication::{EvalRequest, KubePollerBootRequest, WorkerPoolBootRequest};

lazy_static! {
    static ref TRACE_SYSTEM_INITIALIZED: RwLock<bool> = RwLock::new(false);
}

fn main() -> Result<()> {
    let matches = cli::build_cli().get_matches();

    // init some variables based on the cli parameters
    let addr = cli::api_bind_address(&matches)?;
    let (cert_file, key_file) = cli::tls_files(&matches)?;
    let mut policies = cli::policies(&matches)?;
    let sources = cli::remote_server_options(&matches)?;
    let pool_size = matches.value_of("workers").map_or_else(num_cpus::get, |v| {
        v.parse::<usize>()
            .expect("error parsing the number of workers")
    });
    let always_accept_admission_reviews_on_namespace = matches
        .value_of("always-accept-admission-reviews-on-namespace")
        .map(str::to_string);

    let metrics_enabled = matches.is_present("enable-metrics");
    let verification_config = cli::verification_config(&matches).unwrap_or_else(|e| {
        fatal_error(format!(
            "Cannot create sigstore verification config: {:?}",
            e
        ));
        unreachable!()
    });
    let sigstore_cache_dir = matches
        .value_of("sigstore-cache-dir")
        .map(PathBuf::from)
        .expect("This should not happen, there's a default value for sigstore-cache-dir");

    ////////////////////////////////////////////////////////////////////////////
    //                                                                        //
    // Phase 1: setup the CallbackHandler. This is used by the synchronous    //
    // world (the waPC host_callback) to request the execution of code that   //
    // can be run only inside of asynchronous world.                          //
    // An example of that, is a policy that changes the container image       //
    // references to ensure they use immutable shasum instead of tags.   The  //
    // act of retrieving the container image manifest digest requires a       //
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
            eprintln!("Cannot fetch TUF repository: {:?}", e);
            eprintln!("Sigstore Verifier created without Fulcio data: keyless signatures are going to be discarded because they cannot be verified");
            eprintln!(
                "Sigstore Verifier created without Rekor data: transparency log data won't be used"
            );
            eprintln!("Sigstore capabilities are going to be limited");
            None
        }
    };

    let mut callback_handler = CallbackHandlerBuilder::default()
        .registry_config(sources.clone())
        .shutdown_channel(callback_handler_shutdown_channel_rx)
        .fulcio_and_rekor_data(fulcio_and_rekor_data.as_ref())
        .build()?;
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
            always_accept_admission_reviews_on_namespace,
        );
        worker_pool.run();
    });

    ////////////////////////////////////////////////////////////////////////////
    //                                                                        //
    // Phase 3: setup a dedicated thread that runs the Kubernetes poller      //
    //                                                                        //
    ////////////////////////////////////////////////////////////////////////////

    // This is the channel used to have the asynchronous code trigger the
    // bootstrap of the kubernetes poller. The bootstrap must be triggered
    // from within the asynchronous code because some of the tracing collectors
    // (e.g. OpenTelemetry) require a tokio::Runtime to be available.
    let (kube_poller_bootstrap_req_tx, kube_poller_bootstrap_req_rx) =
        oneshot::channel::<KubePollerBootRequest>();

    // Spawn the system thread that runs the main loop of the worker pool manager
    let kube_poller_thread = thread::spawn(move || {
        let poller = match kube_poller::Poller::new(kube_poller_bootstrap_req_rx) {
            Ok(p) => p,
            Err(e) => {
                fatal_error(format!(
                    "Cannot init dedicated tokio runtime for the Kubernetes poller: {:?}",
                    e
                ));
                unreachable!()
            }
        };
        poller.run();
    });

    ////////////////////////////////////////////////////////////////////////////
    //                                                                        //
    // Phase 4: setup the asynchronous world.                                 //
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
        match cli::setup_tracing(&matches) {
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
        let _meter = if metrics_enabled {
            Some(metrics::init_meter())
        } else {
            None
        };

        // Download policies
        let mut downloader = match Downloader::new(
            sources,
            verification_config.is_some(),
            Some(sigstore_cache_dir),
        )
        .await
        {
            Ok(d) => d,
            Err(e) => {
                fatal_error(e.to_string());
                unreachable!()
            }
        };

        let policies_download_dir = matches.value_of("policies-download-dir").unwrap();
        if let Err(e) = downloader
            .download_policies(
                &mut policies,
                policies_download_dir,
                verification_config.as_ref(),
            )
            .await
        {
            fatal_error(e.to_string());
            unreachable!()
        }

        // Start the kubernetes poller
        info!(status = "init", "kubernetes poller bootstrap");
        let (kube_poller_bootstrap_res_tx, mut kube_poller_bootstrap_res_rx) =
            oneshot::channel::<Result<()>>();
        let kube_poller_bootstrap_data = KubePollerBootRequest {
            resp_chan: kube_poller_bootstrap_res_tx,
        };
        if kube_poller_bootstrap_req_tx
            .send(kube_poller_bootstrap_data)
            .is_err()
        {
            fatal_error("Cannot send bootstrap data to kubernetes poller".to_string());
        }

        // Wait for the kubernetes poller to be fully bootstraped before moving on.
        //
        // The poller must be stated before policies can be evaluated, otherwise
        // context-aware policies could not have the right data at their disposal.
        loop {
            match kube_poller_bootstrap_res_rx.try_recv() {
                Ok(res) => match res {
                    Ok(_) => break,
                    Err(e) => fatal_error(e.to_string()),
                },
                Err(oneshot::error::TryRecvError::Empty) => {
                    // the channel is empty, keep waiting
                }
                _ => {
                    fatal_error("Cannot receive kubernetes poller bootstrap result".to_string());
                    return;
                }
            }
        }
        info!(status = "done", "kubernetes poller bootstrap");

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
        let tls_config = if cert_file.is_empty() {
            None
        } else {
            Some(crate::server::TlsConfig {
                cert_file: cert_file.to_string(),
                key_file: key_file.to_string(),
            })
        };
        server::run_server(&addr, tls_config, api_tx).await;

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
        fatal_error(format!("error while waiting for worker threads: {:?}", e));
    };

    if let Err(e) = kube_poller_thread.join() {
        fatal_error(format!("error while waiting for worker threads: {:?}", e));
    };

    Ok(())
}

fn fatal_error(msg: String) {
    let trace_system_ready = TRACE_SYSTEM_INITIALIZED.read().unwrap();
    if *trace_system_ready {
        error!("{}", msg);
        shutdown_tracer_provider();
    } else {
        eprintln!("{}", msg);
    }

    process::exit(1);
}
