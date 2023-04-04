use anyhow::{anyhow, Result};
use core::time;
use lazy_static::lazy_static;
use policy_evaluator::{
    callback_requests::CallbackRequest,
    policy_evaluator::{Evaluator, PolicyEvaluator, PolicyExecutionMode},
    policy_evaluator_builder::PolicyEvaluatorBuilder,
    policy_metadata::Metadata,
    wasmtime,
};
use rayon::prelude::*;
use semver::{BuildMetadata, Prerelease, Version};
use std::{
    collections::HashMap,
    fs,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Barrier, RwLock,
    },
    thread,
    thread::JoinHandle,
    vec::Vec,
};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, warn};

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
lazy_static! {
    static ref KUBEWARDEN_VERSION: Version = {
        let mut version = Version::parse(env!("CARGO_PKG_VERSION")).expect("Cannot parse CARGO_PKG_VERSION version");
        // Remove the patch, prerelease and build information to avoid rejections
        // like this: v1.6.0-rc4 < v1.6.0
        version.patch = 0;
        version.pre = Prerelease::EMPTY;
        version.build = BuildMetadata::EMPTY;
        version
    };
}

/// Check if policy server version is compatible with  minimum kubewarden
/// version required by the policy
fn has_minimum_kubewarden_version(metadata: &Metadata) -> Result<()> {
    if let Some(minimum_kubewarden_version) = &metadata.minimum_kubewarden_version {
        let sanitized_minimum_kubewarden_version = Version {
            major: minimum_kubewarden_version.major,
            minor: minimum_kubewarden_version.minor,
            // Kubewarden stack version ignore patch, prerelease and build version numbers
            patch: 0,
            pre: Prerelease::EMPTY,
            build: BuildMetadata::EMPTY,
        };
        if *KUBEWARDEN_VERSION < sanitized_minimum_kubewarden_version {
            return Err(anyhow!(
                "Policy required Kubewarden version {} but is running on {}",
                sanitized_minimum_kubewarden_version,
                KUBEWARDEN_VERSION.to_string(),
            ));
        }
    }
    Ok(())
}

impl PrecompiledPolicy {
    /// Load a WebAssembly module from the disk and compiles it
    fn new(engine: &wasmtime::Engine, wasm_module_path: &Path) -> Result<Self> {
        let policy_contents = fs::read(wasm_module_path)?;
        let policy_metadata = Metadata::from_contents(&policy_contents)?;
        let metadata = policy_metadata.unwrap_or_default();
        let execution_mode = metadata.execution_mode;
        has_minimum_kubewarden_version(&metadata)?;

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
    policy_evaluation_limit_seconds: Option<u64>,
}

impl WorkerPool {
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

    pub(crate) fn run(mut self) {
        let mut worker_tx_chans = Vec::<mpsc::Sender<EvalRequest>>::new();
        let mut worker_engines = Vec::<wasmtime::Engine>::new();
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

        // To reduce bootstrap time, we will precompile all the WebAssembly
        // modules we are going to use.
        let mut wasmtime_config = wasmtime::Config::new();
        if self.policy_evaluation_limit_seconds.is_some() {
            wasmtime_config.epoch_interruption(true);
        }

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

        if let Err(error) = verify_policy_settings(
            &engine,
            &bootstrap_data.policies,
            &precompiled_policies,
            self.callback_handler_tx.clone(),
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

            let engine = match wasmtime::Engine::new(&wasmtime_config) {
                Ok(e) => e,
                Err(e) => {
                    if bootstrap_data
                        .resp_chan
                        .send(Err(anyhow!(
                            "cannot create wasmtime engine for one of the workers: {}",
                            e
                        )))
                        .is_err()
                    {
                        eprint!("cannot create wasmtime engine for one of the workers: {e}");
                        std::process::exit(1);
                    };
                    return;
                }
            };
            worker_engines.push(engine.clone());

            let policies = bootstrap_data.policies.clone();
            let modules = precompiled_policies.clone();
            let b = barrier.clone();
            let canary = boot_canary.clone();
            let callback_handler_tx = self.callback_handler_tx.clone();
            let always_accept_admission_reviews_on_namespace =
                self.always_accept_admission_reviews_on_namespace.clone();

            let join = thread::spawn(move || -> Result<()> {
                info!(spawned = n, total = pool_size, "spawning worker");
                let mut worker = match Worker::new(
                    rx,
                    &policies,
                    &modules,
                    engine,
                    callback_handler_tx,
                    always_accept_admission_reviews_on_namespace,
                    self.policy_evaluation_limit_seconds,
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

        if self.policy_evaluation_limit_seconds.is_some() {
            // start a dedicated thread that send tick events to all
            // the workers. This is used by the wasmtime's epoch_interruption
            // to keep track of the execution time of each wasm module
            thread::spawn(move || {
                let one_second = time::Duration::from_secs(1);
                loop {
                    thread::sleep(one_second);
                    for engine in &worker_engines {
                        engine.increment_epoch();
                    }
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

pub(crate) fn build_policy_evaluator(
    policy_id: &str,
    policy: &crate::settings::Policy,
    engine: &wasmtime::Engine,
    policy_modules: &PrecompiledPolicies,
    callback_handler_tx: mpsc::Sender<CallbackRequest>,
    policy_evaluation_limit_seconds: Option<u64>,
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
    // WorkerPool thread
    let module =
        unsafe { wasmtime::Module::deserialize(engine, &policy_module.precompiled_module) }
            .map_err(|e| {
                anyhow!(
                    "could not rehydrate wasmtime::Module {}: {:?}",
                    policy.url,
                    e
                )
            })?;

    let mut policy_evaluator_builder = PolicyEvaluatorBuilder::new(policy_id.to_string())
        .engine(engine.clone())
        .policy_module(module)
        .settings(policy.settings_to_json()?)
        .context_aware_resources_allowed(policy.context_aware_resources.clone())
        .callback_channel(callback_handler_tx)
        .execution_mode(policy_module.execution_mode);

    if let Some(limit) = policy_evaluation_limit_seconds {
        policy_evaluator_builder =
            policy_evaluator_builder.enable_epoch_interruptions(limit, limit);
    }

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

fn verify_policy_settings(
    engine: &wasmtime::Engine,
    policies: &HashMap<String, crate::settings::Policy>,
    policy_modules: &HashMap<String, PrecompiledPolicy>,
    callback_handler_tx: mpsc::Sender<CallbackRequest>,
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
    for (id, policy) in policies.iter() {
        let mut policy_evaluator = match build_policy_evaluator(
            id,
            policy,
            engine,
            policy_modules,
            callback_handler_tx.clone(),
            policy_evaluation_limit_seconds,
        ) {
            Ok(pe) => pe,
            Err(e) => {
                errors.push(format!("[{id}] cannot create PolicyEvaluator: {e:?}"));
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

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn generate_metadata(major: u64, minor: u64, patch: u64) -> Metadata {
        let minimum_kubewarden_version = Version {
            major: major,
            minor: minor,
            patch: patch,
            pre: Prerelease::EMPTY,
            build: BuildMetadata::EMPTY,
        };
        Metadata {
            minimum_kubewarden_version: Some(minimum_kubewarden_version),
            ..Default::default()
        }
    }

    #[rstest]
    #[case(generate_metadata(KUBEWARDEN_VERSION.major -1, KUBEWARDEN_VERSION.minor, KUBEWARDEN_VERSION.patch))]
    #[case(generate_metadata(KUBEWARDEN_VERSION.major, KUBEWARDEN_VERSION.minor - 1, KUBEWARDEN_VERSION.patch))]
    fn recent_kubewarden_versions_test(#[case] metadata: Metadata) {
        assert!(has_minimum_kubewarden_version(&metadata).is_ok())
    }

    #[rstest]
    #[case(generate_metadata(KUBEWARDEN_VERSION.major +1, KUBEWARDEN_VERSION.minor, KUBEWARDEN_VERSION.patch))]
    #[case(generate_metadata(KUBEWARDEN_VERSION.major, KUBEWARDEN_VERSION.minor + 1, KUBEWARDEN_VERSION.patch))]
    fn old_kubewarden_versions_test(#[case] metadata: Metadata) {
        assert!(has_minimum_kubewarden_version(&metadata).is_err())
    }

    #[test]
    fn no_mininum_kubewarden_version_is_valid_test() {
        let metadata = Metadata {
            minimum_kubewarden_version: None,
            ..Default::default()
        };
        assert!(has_minimum_kubewarden_version(&metadata).is_ok())
    }

    #[rstest]
    #[case(generate_metadata(KUBEWARDEN_VERSION.major, KUBEWARDEN_VERSION.minor, KUBEWARDEN_VERSION.patch + 1))]
    fn ignore_patch_version_test(#[case] metadata: Metadata) {
        assert!(has_minimum_kubewarden_version(&metadata).is_ok())
    }
}
