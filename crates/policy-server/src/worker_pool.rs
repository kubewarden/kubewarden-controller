use anyhow::{anyhow, Result};
use policy_evaluator::{
    callback_requests::CallbackRequest,
    policy_evaluator::{PolicyEvaluator, PolicyExecutionMode},
    policy_evaluator_builder::PolicyEvaluatorBuilder,
    policy_metadata::Metadata,
    wasmtime,
};
use rayon::prelude::*;
use std::{
    collections::HashMap,
    fs,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Barrier,
    },
    thread,
    thread::JoinHandle,
    vec::Vec,
};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info};

use crate::communication::{EvalRequest, WorkerPoolBootRequest};
use crate::policy_downloader::FetchedPolicies;
use crate::worker::Worker;

/// This structure holds a precompiled WebAssembly module
/// representing a policy.
///
/// Compiling a WebAssembly module is an expensive operation. Each
/// worker thread needs to do that, for each policy defined by the user.
///
/// Precompiling the policies ahead of time reduces the bootstrap time by a lot.
///
/// **Warning:** when "rehydrating" the module, you have to use a `wasmtime::Engine`
/// that has been created with the same `wasmtime::Config` used at compilation time.
#[derive(Clone)]
pub(crate) struct PrecompiledPolicy {
    /// A precompiled [`wasmtime::Module`]
    pub precompiled_module: Vec<u8>,

    /// The execution mode of the policy
    pub execution_mode: PolicyExecutionMode,
}

impl PrecompiledPolicy {
    /// Load a WebAssembly module from the disk and compiles it
    fn new(engine: &wasmtime::Engine, wasm_module_path: &Path) -> Result<Self> {
        let policy_contents = fs::read(wasm_module_path)?;
        let policy_metadata = Metadata::from_contents(&policy_contents)?;
        let execution_mode = policy_metadata.unwrap_or_default().execution_mode;
        let precompiled_module = engine.precompile_module(&policy_contents)?;

        Ok(Self {
            precompiled_module,
            execution_mode,
        })
    }
}

/// A dictionary with:
/// * Key: the URL of the WebAssembly module
/// * value: the PrecompiledPolicy
pub(crate) type PrecompiledPolicies = HashMap<String, PrecompiledPolicy>;

pub(crate) struct WorkerPool {
    api_rx: mpsc::Receiver<EvalRequest>,
    bootstrap_rx: oneshot::Receiver<WorkerPoolBootRequest>,
    callback_handler_tx: mpsc::Sender<CallbackRequest>,
    always_accept_admission_reviews_on_namespace: Option<String>,
}

impl WorkerPool {
    pub(crate) fn new(
        bootstrap_rx: oneshot::Receiver<WorkerPoolBootRequest>,
        api_rx: mpsc::Receiver<EvalRequest>,
        callback_handler_tx: mpsc::Sender<CallbackRequest>,
        always_accept_admission_reviews_on_namespace: Option<String>,
    ) -> WorkerPool {
        WorkerPool {
            api_rx,
            bootstrap_rx,
            callback_handler_tx,
            always_accept_admission_reviews_on_namespace,
        }
    }

    pub(crate) fn run(mut self) {
        let mut worker_tx_chans = Vec::<mpsc::Sender<EvalRequest>>::new();
        let mut join_handles = Vec::<JoinHandle<Result<()>>>::new();

        // Phase 1: wait for bootstrap data to be received by the main
        // code running in the async block. Once the data is received
        // populate the worker pool

        let bootstrap_data = match self.bootstrap_rx.blocking_recv() {
            Ok(data) => data,
            Err(e) => {
                eprintln!(
                    "workers pool bootstrap: error receiving bootstrap data: {:?}",
                    e
                );
                std::process::exit(1);
            }
        };

        // To reduce bootstrap time, we will precompile all the WebAssembly
        // modules we are going to use.
        let wasmtime_config = wasmtime::Config::new();
        // TODO: enable epoch deadlines

        let engine = match wasmtime::Engine::new(&wasmtime_config) {
            Ok(e) => e,
            Err(e) => {
                eprintln!(
                    "workers pool bootstrap: cannot instantiate `wasmtime::Engine`: {:?}",
                    e
                );
                std::process::exit(1);
            }
        };

        let precompiled_policies =
            match precompile_policies(&engine, &bootstrap_data.fetched_policies) {
                Ok(pp) => pp,
                Err(e) => {
                    eprintln!("{}", e);
                    std::process::exit(1);
                }
            };

        if let Err(error) = verify_policy_settings(
            &engine,
            &bootstrap_data.policies,
            &precompiled_policies,
            self.callback_handler_tx.clone(),
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

        for n in 1..=pool_size {
            let (tx, rx) = mpsc::channel::<EvalRequest>(32);
            worker_tx_chans.push(tx);

            let policies = bootstrap_data.policies.clone();
            let modules = precompiled_policies.clone();
            let wasmtime_config = wasmtime_config.clone();
            let b = barrier.clone();
            let canary = boot_canary.clone();
            let callback_handler_tx = self.callback_handler_tx.clone();
            let always_accept_admission_reviews_on_namespace =
                self.always_accept_admission_reviews_on_namespace.clone();

            let join = thread::spawn(move || -> Result<()> {
                info!(spawned = n, total = pool_size, "spawning worker");
                let worker = match Worker::new(
                    rx,
                    &policies,
                    &modules,
                    &wasmtime_config,
                    callback_handler_tx,
                    always_accept_admission_reviews_on_namespace,
                ) {
                    Ok(w) => w,
                    Err(e) => {
                        error!(error = e.to_string().as_str(), "cannot spawn worker");
                        canary.store(false, Ordering::SeqCst);
                        b.wait();
                        return Err(anyhow!("Worker {} couldn't start: {}", n, e));
                    }
                };
                b.wait();

                debug!(id = n, "worker loop start");
                worker.run();
                debug!(id = n, "worker loop exit");

                Ok(())
            });
            join_handles.push(join);
        }
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

pub(crate) fn build_policy_evaluator(
    policy_id: &str,
    policy: &crate::settings::Policy,
    engine: &wasmtime::Engine,
    policy_modules: &PrecompiledPolicies,
    callback_handler_tx: mpsc::Sender<CallbackRequest>,
) -> Result<PolicyEvaluator> {
    let policy_module = policy_modules.get(policy.url.as_str()).ok_or_else(|| {
        anyhow!(
            "could not find preoptimized module for policy: {:?}",
            policy.url
        )
    })?;

    // See `wasmtime::Module::deserialize` to know why this method is `unsafe`.
    // However, in our context, nothing bad will happen because we have
    // full control of the precompiled module. This is generated by the
    // WorkerPool thred
    let module =
        unsafe { wasmtime::Module::deserialize(engine, &policy_module.precompiled_module) }
            .map_err(|e| {
                anyhow!(
                    "could not rehydrate wasmtime::Module {}: {:?}",
                    policy.url,
                    e
                )
            })?;

    let policy_evaluator_builder = PolicyEvaluatorBuilder::new(policy_id.to_string())
        .engine(engine.clone())
        .policy_module(module)
        .settings(policy.settings_to_json()?)
        .callback_channel(callback_handler_tx)
        .execution_mode(policy_module.execution_mode);

    policy_evaluator_builder.build()
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
                "[{}] policy cannot be compiled to WebAssembly module: {:?}",
                url, e
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

fn verify_policy_settings(
    engine: &wasmtime::Engine,
    policies: &HashMap<String, crate::settings::Policy>,
    policy_modules: &HashMap<String, PrecompiledPolicy>,
    callback_handler_tx: mpsc::Sender<CallbackRequest>,
) -> Result<()> {
    let mut errors = vec![];
    for (id, policy) in policies.iter() {
        let mut policy_evaluator = match build_policy_evaluator(
            id,
            policy,
            engine,
            policy_modules,
            callback_handler_tx.clone(),
        ) {
            Ok(pe) => pe,
            Err(e) => {
                errors.push(format!("[{}] cannot create PolicyEvaluator: {:?}", id, e));
                continue;
            }
        };
        let set_val_rep = policy_evaluator.validate_settings();
        if !set_val_rep.valid {
            errors.push(format!(
                "[{}] settings are not valid: {:?}",
                id, set_val_rep.message
            ));
            continue;
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(anyhow!("{}", errors.join(", ")))
    }
}
