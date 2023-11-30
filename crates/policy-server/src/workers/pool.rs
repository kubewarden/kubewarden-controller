use anyhow::{anyhow, Result};
use core::time;
use lazy_static::lazy_static;
use policy_evaluator::{callback_requests::CallbackRequest, wasmtime};
use rayon::prelude::*;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Barrier, RwLock,
    },
    thread,
    thread::JoinHandle,
    vec::Vec,
};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, warn};

use crate::communication::{EvalRequest, WorkerPoolBootRequest};
use crate::config;
use crate::policy_downloader::FetchedPolicies;
use crate::workers::EvaluationEnvironment;
use crate::workers::{
    precompiled_policy::{PrecompiledPolicies, PrecompiledPolicy},
    worker::Worker,
};

/// Coordinates a set of workers.
/// Each worker takes care of performing the evaluation of the requests received by Policy Server
/// API endpoints.
///
/// The HTTP API communicates with the worker pool via a dedicated chanel. The pool then assigns
/// the evaluation job to one of the workers. Currently this is done on a round-robin fashion.
pub(crate) struct WorkerPool {
    /// Channel used by the HTTP API to send to the pool the evaluation requests that have to be
    /// processed
    api_rx: mpsc::Receiver<EvalRequest>,

    /// A oneshot channel used during the bootstrap phase. It's being used by the `main` to send
    /// the data used to bootstrap of the workers.
    bootstrap_rx: oneshot::Receiver<WorkerPoolBootRequest>,

    /// The channel that connect the synchronous world of the workers with the tokio task that
    /// handles all the async requests that might originate during the policy evaluation process.
    /// For example, requesting Kubernetes resources, DNS resolution, Sigstore operations,...
    callback_handler_tx: mpsc::Sender<CallbackRequest>,

    /// When set, this is the Namespace where all the policies do not apply. This is usually set
    /// to be the Namespace where the Kubewarden is deployed; ensuring the user policies are not
    /// going to interfere with the Kubewarden stack.
    always_accept_admission_reviews_on_namespace: Option<String>,

    /// When set enables the policy timeout feature which prevents a rogue policy to enter an
    /// endless loop/consume all the resources of a worker
    policy_evaluation_limit_seconds: Option<u64>,
}

impl WorkerPool {
    /// Create a new `WorkerPool`, no bootstrap operation is done yet. This happens when invoking
    /// the `run` method.
    pub(crate) fn new(
        bootstrap_rx: oneshot::Receiver<WorkerPoolBootRequest>,
        api_rx: mpsc::Receiver<EvalRequest>,
        callback_handler_tx: mpsc::Sender<CallbackRequest>,
        always_accept_admission_reviews_on_namespace: Option<String>,
        policy_evaluation_limit_seconds: Option<u64>,
    ) -> WorkerPool {
        WorkerPool {
            api_rx,
            bootstrap_rx,
            callback_handler_tx,
            always_accept_admission_reviews_on_namespace,
            policy_evaluation_limit_seconds,
        }
    }

    /// Bootstrap the pool and then enter an endless loop that processes incoming requests.
    pub(crate) fn run(mut self) {
        // The WorkerPool communicates with each worker over dedicated `mpsc::channel` (one per worker).
        // This vector holds all the sender ends of these channels.
        let mut worker_tx_chans = Vec::<mpsc::Sender<EvalRequest>>::new();

        // All the join handles of the spawned worker threads
        let mut join_handles = Vec::<JoinHandle<Result<()>>>::new();

        // Phase 1: wait for bootstrap data to be received by the main
        // code running in the async block. Once the data is received
        // populate the worker pool

        let bootstrap_data = match self.bootstrap_rx.blocking_recv() {
            Ok(data) => data,
            Err(e) => {
                eprintln!("workers pool bootstrap: error receiving bootstrap data: {e:?}");
                std::process::exit(1);
            }
        };

        let mut wasmtime_config = wasmtime::Config::new();
        if self.policy_evaluation_limit_seconds.is_some() {
            wasmtime_config.epoch_interruption(true);
        }

        // We are going to share the same engine across all the workers
        let engine = match wasmtime::Engine::new(&wasmtime_config) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("workers pool bootstrap: cannot instantiate `wasmtime::Engine`: {e:?}");
                std::process::exit(1);
            }
        };

        let precompiled_policies =
            match precompile_policies(&engine, &bootstrap_data.fetched_policies) {
                Ok(pp) => pp,
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            };

        // EvaluationEnvironment instance that is going to be shared across all
        // the worker threads
        let evaluation_environment = match EvaluationEnvironment::new(
            &engine,
            &bootstrap_data.policies,
            &precompiled_policies,
            self.always_accept_admission_reviews_on_namespace,
            self.policy_evaluation_limit_seconds,
            self.callback_handler_tx.clone(),
        ) {
            Ok(ee) => Arc::new(ee),
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        };

        // For each policy defined by the user, ensure the given settings are valid
        // We exit with an error if one or more policies do not have valid
        // settings.
        if let Err(error) = verify_policy_settings(
            &engine,
            &bootstrap_data.policies,
            evaluation_environment.clone(),
            self.policy_evaluation_limit_seconds,
        ) {
            error!(?error, "cannot validate policy settings");
            match bootstrap_data.resp_chan.send(Err(error)) {
                Ok(_) => return,
                Err(_) => {
                    eprint!("worker bootstrap: cannot send back failure through channel");
                    std::process::exit(1);
                }
            };
        }

        let pool_size: usize = bootstrap_data.pool_size;
        let barrier = Arc::new(Barrier::new(pool_size + 1));
        let boot_canary = Arc::new(AtomicBool::new(true));

        if let Some(limit) = self.policy_evaluation_limit_seconds {
            info!(
                execution_limit_seconds = limit,
                "policy timeout protection is enabled"
            );
        } else {
            warn!("policy timeout protection is disabled");
        }

        for n in 1..=pool_size {
            let (tx, rx) = mpsc::channel::<EvalRequest>(32);
            worker_tx_chans.push(tx);

            let b = barrier.clone();
            let inner_evaluation_environment = evaluation_environment.clone();

            let join = thread::spawn(move || -> Result<()> {
                info!(spawned = n, total = pool_size, "spawning worker");

                let mut worker = Worker::new(rx, inner_evaluation_environment);
                b.wait();

                debug!(id = n, "worker loop start");
                worker.run();
                debug!(id = n, "worker loop exit");

                Ok(())
            });
            join_handles.push(join);
        }

        // Deallocate all the memory used by the precompiled policies since
        // they are no longer needed. Without this explicit cleanup
        // the reference would be dropped right before Policy Server exits,
        // meaning a lot of memory would have been consumed without a valid reason
        // during the whole execution time
        drop(precompiled_policies);
        barrier.wait();

        if !boot_canary.load(Ordering::SeqCst) {
            match bootstrap_data
                .resp_chan
                .send(Err(anyhow!("could not init one of the workers")))
            {
                Ok(_) => return,
                Err(_) => {
                    eprint!("worker bootstrap: cannot send back failure through channel");
                    std::process::exit(1);
                }
            };
        }

        // bootstrap went smoothly
        if bootstrap_data.resp_chan.send(Ok(())).is_err() {
            eprint!("worker bootstrap: cannot send back success message through channel");
            std::process::exit(1);
        }

        // Phase 2: the worker pool has been successfully bootstraped.
        // We can start waiting for admission review requests to be evaluated
        let mut next_worker_id = 0;

        if self.policy_evaluation_limit_seconds.is_some() {
            // start a dedicated thread that send tick events to all
            // the workers. This is used by the wasmtime's epoch_interruption
            // to keep track of the execution time of each wasm module
            let engine_timer_thread = engine.clone();
            thread::spawn(move || {
                let one_second = time::Duration::from_secs(1);
                loop {
                    thread::sleep(one_second);
                    engine_timer_thread.increment_epoch();
                }
            });
        }

        while let Some(req) = self.api_rx.blocking_recv() {
            let _ = worker_tx_chans[next_worker_id].blocking_send(req);
            next_worker_id += 1;
            if next_worker_id >= pool_size {
                next_worker_id = 0;
            }
        }

        for handle in join_handles {
            handle.join().unwrap().unwrap();
        }
    }
}

fn precompile_policies(
    engine: &wasmtime::Engine,
    fetched_policies: &FetchedPolicies,
) -> Result<PrecompiledPolicies> {
    debug!(
        wasm_modules_count = fetched_policies.len(),
        "instantiating wasmtime::Module objects"
    );

    let precompiled_policies: HashMap<String, Result<PrecompiledPolicy>> = fetched_policies
        .par_iter()
        .map(|(policy_url, wasm_module_path)| {
            let precompiled_policy = PrecompiledPolicy::new(engine, wasm_module_path);
            debug!(?policy_url, "module compiled");
            (policy_url.clone(), precompiled_policy)
        })
        .collect();

    let errors: Vec<String> = precompiled_policies
        .iter()
        .filter_map(|(url, result)| match result {
            Ok(_) => None,
            Err(e) => Some(format!(
                "[{url}] policy cannot be compiled to WebAssembly module: {e:?}"
            )),
        })
        .collect();
    if !errors.is_empty() {
        return Err(anyhow!(
            "workers pool bootstrap: cannot instantiate `wasmtime::Module` objects: {:?}",
            errors.join(", ")
        ));
    }

    Ok(precompiled_policies
        .iter()
        .filter_map(|(url, result)| match result {
            Ok(p) => Some((url.clone(), p.clone())),
            Err(_) => None,
        })
        .collect())
}

/// Ensure the user provided valid settings for all the policies
fn verify_policy_settings(
    engine: &wasmtime::Engine,
    policies: &HashMap<String, config::Policy>,
    evaluation_environment: Arc<EvaluationEnvironment>,
    policy_evaluation_limit_seconds: Option<u64>,
) -> Result<()> {
    let tick_thread_lock = Arc::new(RwLock::new(true));

    if policy_evaluation_limit_seconds.is_some() {
        // start a dedicated thread that send tick events to the
        // wasmtime engine.
        // This is used by the wasmtime's epoch_interruption
        // to keep track of the execution time of each wasm module

        let loop_engine = engine.clone();
        let keep_going_lock = tick_thread_lock.clone();

        thread::spawn(move || {
            let one_second = time::Duration::from_secs(1);
            loop {
                thread::sleep(one_second);
                loop_engine.increment_epoch();
                if !(*keep_going_lock.read().unwrap()) {
                    break;
                }
            }
        });
    }

    let mut errors = vec![];
    for (policy_id, _policy) in policies.iter() {
        let set_val_rep = evaluation_environment.validate_settings(policy_id)?;
        if !set_val_rep.valid {
            errors.push(format!(
                "[{}] settings are not valid: {:?}",
                policy_id, set_val_rep.message
            ));
            continue;
        }
    }

    if policy_evaluation_limit_seconds.is_some() {
        // Tell the ticker thread loop to stop
        let mut w = tick_thread_lock.write().unwrap();
        *w = false;
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(anyhow!("{}", errors.join(", ")))
    }
}
