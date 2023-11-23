use anyhow::{anyhow, Result};
use std::collections::BTreeSet;
use std::convert::TryInto;
use std::path::Path;
use tokio::sync::mpsc;
use wasmtime_provider::wasmtime;

use crate::callback_requests::CallbackRequest;
use crate::policy::Policy;
use crate::policy_evaluator::{PolicyEvaluator, PolicyExecutionMode};
use crate::policy_metadata::ContextAwareResource;
use crate::runtimes::wapc::WAPC_POLICY_MAPPING;
use crate::runtimes::{rego::BurregoStack, wapc::WapcStack, wasi_cli, Runtime};

/// Configure behavior of wasmtime [epoch-based interruptions](https://docs.rs/wasmtime/latest/wasmtime/struct.Config.html#method.epoch_interruption)
///
/// There are two kind of deadlines that apply to waPC modules:
///
/// * waPC initialization code: this is the code defined by the module inside
///   of the `wapc_init` or the `_start` functions
/// * user function: the actual waPC guest function written by an user
#[derive(Clone, Copy, Debug)]
pub(crate) struct EpochDeadlines {
    /// Deadline for waPC initialization code. Expressed in number of epoch ticks
    pub wapc_init: u64,

    /// Deadline for user-defined waPC function computation. Expressed in number of epoch ticks
    pub wapc_func: u64,
}

/// Helper Struct that creates a `PolicyEvaluator` object
#[derive(Default)]
pub struct PolicyEvaluatorBuilder {
    engine: Option<wasmtime::Engine>,
    policy_id: String,
    policy_file: Option<String>,
    policy_contents: Option<Vec<u8>>,
    policy_module: Option<wasmtime::Module>,
    execution_mode: Option<PolicyExecutionMode>,
    settings: Option<serde_json::Map<String, serde_json::Value>>,
    callback_channel: Option<mpsc::Sender<CallbackRequest>>,
    wasmtime_cache: bool,
    epoch_deadlines: Option<EpochDeadlines>,
    ctx_aware_resources_allow_list: BTreeSet<ContextAwareResource>,
}

impl PolicyEvaluatorBuilder {
    /// Create a new PolicyEvaluatorBuilder object. The `policy_id` must be
    /// specified.
    pub fn new(policy_id: String) -> PolicyEvaluatorBuilder {
        PolicyEvaluatorBuilder {
            policy_id,
            ..Default::default()
        }
    }

    /// [`wasmtime::Engine`] instance to be used when creating the
    /// policy evaluator
    ///
    /// **Warning:** when used, all the [`wasmtime::Engine`] specific settings
    /// must be set by the caller when creating the engine.
    /// This includes options like: cache, epoch counter
    pub fn engine(mut self, engine: wasmtime::Engine) -> Self {
        self.engine = Some(engine);
        self
    }

    /// Build the policy by reading the Wasm file from disk.
    /// Cannot be used at the same time as `policy_contents`
    pub fn policy_file(mut self, path: &Path) -> Result<PolicyEvaluatorBuilder> {
        let filename = path
            .to_str()
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("Cannot convert given path to String"))?;
        self.policy_file = Some(filename);
        Ok(self)
    }

    /// Build the policy by using the Wasm object given via the `data` array.
    /// Cannot be used at the same time as `policy_file`
    pub fn policy_contents(mut self, data: &[u8]) -> PolicyEvaluatorBuilder {
        self.policy_contents = Some(data.to_owned());
        self
    }

    /// Use a pre-built [`wasmtime::Module`] instance.
    /// **Warning:** you must provide also the [`wasmtime::Engine`] used
    /// to allocate the `Module`, otherwise the code will panic at runtime
    pub fn policy_module(mut self, module: wasmtime::Module) -> Self {
        self.policy_module = Some(module);
        self
    }

    /// Sets the policy execution mode
    pub fn execution_mode(mut self, mode: PolicyExecutionMode) -> PolicyEvaluatorBuilder {
        self.execution_mode = Some(mode);
        self
    }

    /// Enable Wasmtime cache feature
    pub fn enable_wasmtime_cache(mut self) -> PolicyEvaluatorBuilder {
        self.wasmtime_cache = true;
        self
    }

    /// Set the settings the policy will use at evaluation time
    pub fn settings(
        mut self,
        s: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> PolicyEvaluatorBuilder {
        self.settings = s;
        self
    }

    /// Set the list of Kubernetes resources the policy can have access to
    pub fn context_aware_resources_allowed(
        mut self,
        allowed_resources: BTreeSet<ContextAwareResource>,
    ) -> PolicyEvaluatorBuilder {
        self.ctx_aware_resources_allow_list = allowed_resources;
        self
    }

    /// Enable Wasmtime [epoch-based interruptions](wasmtime::Config::epoch_interruption) and set
    /// the deadlines to be enforced
    ///
    /// Two kind of deadlines have to be set:
    ///
    /// * `wapc_init_deadline`: the number of ticks the waPC initialization code can take before the
    ///   code is interrupted. This is the code usually defined inside of the `wapc_init`/`_start`
    ///   functions
    /// * `wapc_func_deadline`: the number of ticks any regular waPC guest function can run before
    ///   its terminated by the host
    ///
    /// Both these limits are expressed using the number of ticks that are allowed before the
    /// WebAssembly execution is interrupted.
    /// It's up to the embedder of waPC to define how much time a single tick is granted. This could
    /// be 1 second, 10 nanoseconds, or whatever the user prefers.
    ///
    /// **Warning:** when providing an instance of `wasmtime::Engine` via the
    /// `WasmtimeEngineProvider::engine` helper, ensure the `wasmtime::Engine`
    /// has been created with the `epoch_interruption` feature enabled
    #[must_use]
    pub fn enable_epoch_interruptions(
        mut self,
        wapc_init_deadline: u64,
        wapc_func_deadline: u64,
    ) -> Self {
        self.epoch_deadlines = Some(EpochDeadlines {
            wapc_init: wapc_init_deadline,
            wapc_func: wapc_func_deadline,
        });
        self
    }

    /// Specify the channel that is used by the synchronous world (the waPC `host_callback`
    /// function) to obtain information that can be computed only from within a
    /// tokio runtime.
    ///
    /// Note well: if no channel is given, the policy will still be created, but
    /// some waPC functions exposed by the host will not be available at runtime.
    /// The policy evaluation will not fail because of that, but the guest will
    /// get an error instead of the expected result.
    pub fn callback_channel(
        mut self,
        channel: mpsc::Sender<CallbackRequest>,
    ) -> PolicyEvaluatorBuilder {
        self.callback_channel = Some(channel);
        self
    }

    /// Ensure the configuration provided to the build is correct
    fn validate_user_input(&self) -> Result<()> {
        if self.policy_file.is_some() && self.policy_contents.is_some() {
            return Err(anyhow!(
                "Cannot specify 'policy_file' and 'policy_contents' at the same time"
            ));
        }
        if self.policy_file.is_some() && self.policy_module.is_some() {
            return Err(anyhow!(
                "Cannot specify 'policy_file' and 'policy_module' at the same time"
            ));
        }
        if self.policy_contents.is_some() && self.policy_module.is_some() {
            return Err(anyhow!(
                "Cannot specify 'policy_contents' and 'policy_module' at the same time"
            ));
        }

        if self.policy_file.is_none()
            && self.policy_contents.is_none()
            && self.policy_module.is_none()
        {
            return Err(anyhow!(
                "Must specify one among: `policy_file`, `policy_contents` and `policy_module`"
            ));
        }

        if self.engine.is_none() && self.policy_module.is_some() {
            return Err(anyhow!(
                "You must provide the `engine` that was used to instantiate the given `policy_module`"
            ));
        }

        if self.execution_mode.is_none() {
            return Err(anyhow!("Must specify execution mode"));
        }

        Ok(())
    }

    /// Create the instance of `PolicyEvaluator` to be used
    pub fn build(&self) -> Result<PolicyEvaluator> {
        self.validate_user_input()?;

        let engine = self
            .engine
            .as_ref()
            .map_or_else(
                || {
                    let mut wasmtime_config = wasmtime::Config::new();
                    if self.wasmtime_cache {
                        wasmtime_config.cache_config_load_default()?;
                    }
                    if self.epoch_deadlines.is_some() {
                        wasmtime_config.epoch_interruption(true);
                    }

                    wasmtime::Engine::new(&wasmtime_config)
                },
                |e| Ok(e.clone()),
            )
            .map_err(|e| anyhow!("cannot create wasmtime engine: {:?}", e))?;

        let module: wasmtime::Module = if let Some(m) = &self.policy_module {
            // it's fine to clone a Module, this is a cheap operation that just
            // copies its internal reference. See wasmtime docs
            m.clone()
        } else {
            match &self.policy_file {
                Some(file) => wasmtime::Module::from_file(&engine, file),
                None => wasmtime::Module::new(&engine, self.policy_contents.as_ref().unwrap()),
            }?
        };

        let execution_mode = self.execution_mode.unwrap();

        let (policy, runtime) = match execution_mode {
            PolicyExecutionMode::KubewardenWapc => {
                let wapc_stack = WapcStack::new(engine, module, self.epoch_deadlines)?;

                let policy = Self::from_contents_internal(
                    self.policy_id.clone(),
                    self.callback_channel.clone(),
                    Some(self.ctx_aware_resources_allow_list.clone()),
                    || Some(wapc_stack.wapc_host_id()),
                    Policy::new,
                    execution_mode,
                )?;

                let policy_runtime = Runtime::Wapc(wapc_stack);
                (policy, policy_runtime)
            }
            PolicyExecutionMode::Wasi => {
                let cli_stack = wasi_cli::Stack::new(engine, module, self.epoch_deadlines)?;

                let policy = Self::from_contents_internal(
                    self.policy_id.clone(),
                    None, // callback_channel is not used by WASI policies
                    None,
                    || None,
                    Policy::new,
                    execution_mode,
                )?;

                let policy_runtime = Runtime::Cli(cli_stack);
                (policy, policy_runtime)
            }
            PolicyExecutionMode::Opa | PolicyExecutionMode::OpaGatekeeper => {
                let policy = Self::from_contents_internal(
                    self.policy_id.clone(),
                    self.callback_channel.clone(),
                    Some(self.ctx_aware_resources_allow_list.clone()),
                    || None,
                    Policy::new,
                    execution_mode,
                )?;

                let mut builder = burrego::EvaluatorBuilder::default()
                    .engine(&engine)
                    .module(module)
                    .host_callbacks(crate::runtimes::rego::new_host_callbacks());

                if let Some(deadlines) = self.epoch_deadlines {
                    builder = builder.enable_epoch_interruptions(deadlines.wapc_func);
                }
                let evaluator = builder.build()?;

                let policy_runtime = Runtime::Burrego(BurregoStack {
                    evaluator,
                    entrypoint_id: 0, // currently hardcoded to this value
                    policy_execution_mode: execution_mode.try_into()?,
                });

                (policy, policy_runtime)
            }
        };

        Ok(PolicyEvaluator {
            runtime,
            policy,
            settings: self.settings.clone().unwrap_or_default(),
        })
    }

    fn from_contents_internal<E, P>(
        id: String,
        callback_channel: Option<mpsc::Sender<CallbackRequest>>,
        ctx_aware_resources_allow_list: Option<BTreeSet<ContextAwareResource>>,
        engine_initializer: E,
        policy_initializer: P,
        policy_execution_mode: PolicyExecutionMode,
    ) -> Result<Policy>
    where
        E: Fn() -> Option<u64>,
        P: Fn(
            String,
            Option<u64>,
            Option<mpsc::Sender<CallbackRequest>>,
            Option<BTreeSet<ContextAwareResource>>,
        ) -> Result<Policy>,
    {
        let instance_id = engine_initializer();
        let policy = policy_initializer(
            id,
            instance_id,
            callback_channel,
            ctx_aware_resources_allow_list,
        )?;
        if policy_execution_mode == PolicyExecutionMode::KubewardenWapc {
            WAPC_POLICY_MAPPING
                .write()
                .expect("cannot write to global WAPC_POLICY_MAPPING")
                .insert(
                    instance_id.ok_or_else(|| anyhow!("invalid policy id"))?,
                    policy.clone(),
                );
        }
        Ok(policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_is_registered_in_the_mapping() -> Result<()> {
        let policy_name = "policy_is_registered_in_the_mapping";

        // We cannot set policy.id at build time, because some attributes
        // of Policy are private.
        let mut policy = Policy::default();
        policy.id = policy_name.to_string();

        let policy_id = 1;

        PolicyEvaluatorBuilder::from_contents_internal(
            "mock_policy".to_string(),
            None,
            None,
            || Some(policy_id),
            |_, _, _, _| Ok(policy.clone()),
            PolicyExecutionMode::KubewardenWapc,
        )?;

        let policy_mapping = WAPC_POLICY_MAPPING.read().unwrap();
        let found = policy_mapping
            .iter()
            .find(|(_id, policy)| policy.id == policy_name);

        assert!(found.is_some());

        Ok(())
    }

    fn find_wapc_policy_id(policy: &Policy) -> Option<u64> {
        let map = WAPC_POLICY_MAPPING
            .read()
            .expect("cannot get READ access to WAPC_POLICY_MAPPING");
        map.iter()
            .find(|(_, v)| *v == policy)
            .map(|(k, _)| k.to_owned())
    }

    fn is_wapc_instance_registered(policy_id: u64) -> bool {
        let map = WAPC_POLICY_MAPPING
            .read()
            .expect("cannot get READ access to WAPC_POLICY_MAPPING");
        map.get(&policy_id).is_some()
    }

    #[test]
    fn policy_wapc_mapping_is_cleaned_when_the_evaluator_is_dropped() {
        // we need a real WASM module, we don't care about the contents yet

        let engine = wasmtime::Engine::default();
        let wat = include_bytes!("../test_data/endless_wasm/wapc_endless_loop.wat");
        let module = wasmtime::Module::new(&engine, wat).expect("cannot compile WAT to wasm");

        let builder = PolicyEvaluatorBuilder::new("test".to_string())
            .execution_mode(PolicyExecutionMode::KubewardenWapc)
            .engine(engine)
            .policy_module(module);

        let evaluator = builder.build().expect("cannot create evaluator");
        let policy_id =
            find_wapc_policy_id(&evaluator.policy).expect("cannot find the wapc we just created");

        drop(evaluator);
        assert!(!is_wapc_instance_registered(policy_id));
    }

    #[test]
    fn policy_is_not_registered_in_the_mapping_if_not_wapc() -> Result<()> {
        let policy_name = "policy_is_not_registered_in_the_mapping_if_not_wapc";

        // We cannot set policy.id at build time, because some attributes
        // of Policy are private.
        let mut policy = Policy::default();
        policy.id = policy_name.to_string();

        let policy_id = 1;

        PolicyEvaluatorBuilder::from_contents_internal(
            policy_name.to_string(),
            None,
            None,
            || Some(policy_id),
            |_, _, _, _| Ok(policy.clone()),
            PolicyExecutionMode::OpaGatekeeper,
        )?;

        let policy_mapping = WAPC_POLICY_MAPPING.read().unwrap();
        let found = policy_mapping
            .iter()
            .find(|(_id, policy)| policy.id == policy_name);

        assert!(found.is_none());
        Ok(())
    }
}
