use crate::builtins;
use crate::errors::{BurregoError, Result};
use crate::host_callbacks::HostCallbacks;
use crate::opa_host_functions;
use crate::policy::Policy;
use crate::stack_helper::StackHelper;

use itertools::Itertools;
use std::collections::{HashMap, HashSet};
use tracing::debug;
use wasmtime::{Engine, Instance, Linker, Memory, MemoryType, Module, Store};

macro_rules! set_epoch_deadline_and_call_guest {
    ($epoch_deadline:expr, $store:expr, $code:block) => {{
        if let Some(deadline) = $epoch_deadline {
            $store.set_epoch_deadline(deadline);
        }
        $code
    }};
}

struct EvaluatorStack {
    store: Store<Option<StackHelper>>,
    instance: Instance,
    memory: Memory,
    policy: Policy,
}

pub struct Evaluator {
    engine: Engine,
    module: Module,
    store: Store<Option<StackHelper>>,
    instance: Instance,
    memory: Memory,
    policy: Policy,
    host_callbacks: HostCallbacks,
    /// used to tune the [epoch
    /// interruption](https://docs.rs/wasmtime/latest/wasmtime/struct.Config.html#method.epoch_interruption)
    /// feature of wasmtime
    epoch_deadline: Option<u64>,
}

impl Evaluator {
    pub(crate) fn from_engine_and_module(
        engine: Engine,
        module: Module,
        host_callbacks: HostCallbacks,
        epoch_deadline: Option<u64>,
    ) -> Result<Evaluator> {
        let stack = Self::setup(engine.clone(), module.clone(), host_callbacks.clone())?;
        let mut store = stack.store;
        let instance = stack.instance;
        let memory = stack.memory;
        let policy = stack.policy;

        let used_builtins = set_epoch_deadline_and_call_guest!(epoch_deadline, store, {
            policy
                .builtins(&mut store, &memory)?
                .keys()
                .cloned()
                .collect::<Vec<String>>()
                .join(", ")
        });

        debug!(used = used_builtins.as_str(), "policy builtins");

        let mut evaluator = Evaluator {
            engine,
            module,
            store,
            instance,
            memory,
            policy,
            host_callbacks,
            epoch_deadline,
        };

        let not_implemented_builtins = evaluator.not_implemented_builtins()?;
        if !not_implemented_builtins.is_empty() {
            return Err(BurregoError::MissingRegoBuiltins(
                not_implemented_builtins.iter().join(", "),
            ));
        }

        Ok(evaluator)
    }

    fn setup(
        engine: Engine,
        module: Module,
        host_callbacks: HostCallbacks,
    ) -> Result<EvaluatorStack> {
        let mut linker = Linker::<Option<StackHelper>>::new(&engine);

        let opa_data_helper: Option<StackHelper> = None;
        let mut store = Store::new(&engine, opa_data_helper);

        let memory_ty = MemoryType::new(5, None);
        let memory = Memory::new(&mut store, memory_ty)
            .map_err(|e| BurregoError::WasmEngineError(format!("cannot create memory: {e}")))?;
        linker.define("env", "memory", memory).map_err(|e| {
            BurregoError::WasmEngineError(format!("linker cannot define memory: {e}"))
        })?;

        opa_host_functions::add_to_linker(&mut linker)?;

        let instance = linker.instantiate(&mut store, &module).map_err(|e| {
            BurregoError::WasmEngineError(format!("linker cannot create instance: {e}"))
        })?;

        let stack_helper = StackHelper::new(
            &instance,
            &memory,
            &mut store,
            host_callbacks.opa_abort,
            host_callbacks.opa_println,
        )?;
        let policy = Policy::new(&instance, &mut store, &memory)?;
        _ = store.data_mut().insert(stack_helper);

        Ok(EvaluatorStack {
            memory,
            store,
            instance,
            policy,
        })
    }

    pub fn reset(&mut self) -> Result<()> {
        let stack = Self::setup(
            self.engine.clone(),
            self.module.clone(),
            self.host_callbacks.clone(),
        )?;
        self.store = stack.store;
        self.instance = stack.instance;
        self.memory = stack.memory;
        self.policy = stack.policy;

        Ok(())
    }

    pub fn opa_abi_version(&mut self) -> Result<(i32, i32)> {
        let major = self
            .instance
            .get_global(&mut self.store, "opa_wasm_abi_version")
            .and_then(|g| g.get(&mut self.store).i32())
            .ok_or_else(|| {
                BurregoError::RegoWasmError("Cannot find OPA Wasm ABI major version".to_string())
            })?;
        let minor = self
            .instance
            .get_global(&mut self.store, "opa_wasm_abi_minor_version")
            .and_then(|g| g.get(&mut self.store).i32())
            .ok_or_else(|| {
                BurregoError::RegoWasmError("Cannot find OPA Wasm ABI minor version".to_string())
            })?;

        Ok((major, minor))
    }

    pub fn implemented_builtins() -> HashSet<String> {
        builtins::get_builtins()
            .keys()
            .map(|v| String::from(*v))
            .collect()
    }

    pub fn not_implemented_builtins(&mut self) -> Result<HashSet<String>> {
        let used_builtins: HashSet<String> = self
            .policy
            .builtins(&mut self.store, &self.memory)?
            .keys()
            .cloned()
            .collect();
        let supported_builtins: HashSet<String> = builtins::get_builtins()
            .keys()
            .map(|v| String::from(*v))
            .collect();
        Ok(used_builtins
            .difference(&supported_builtins)
            .cloned()
            .collect())
    }

    pub fn entrypoint_id(&mut self, entrypoint: &str) -> Result<i32> {
        let entrypoints = self.policy.entrypoints(&mut self.store, &self.memory)?;
        entrypoints
            .iter()
            .find(|(k, _v)| k == &entrypoint)
            .map(|(_k, v)| *v)
            .ok_or_else(|| {
                BurregoError::RegoWasmError(format!(
                    "Cannot find the specified entrypoint {entrypoint} inside of {entrypoints:?}"
                ))
            })
    }

    pub fn entrypoints(&mut self) -> Result<HashMap<String, i32>> {
        set_epoch_deadline_and_call_guest!(self.epoch_deadline, self.store, {
            self.policy.entrypoints(&mut self.store, &self.memory)
        })
    }

    pub fn evaluate(
        &mut self,
        entrypoint_id: i32,
        input: &serde_json::Value,
        data: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let entrypoints = self.policy.entrypoints(&mut self.store, &self.memory)?;
        entrypoints
            .iter()
            .find(|(_k, &v)| v == entrypoint_id)
            .ok_or_else(|| {
                BurregoError::RegoWasmError(format!(
                    "Cannot find the specified entrypoint {entrypoint_id} inside of {entrypoints:?}"
                ))
            })?;

        debug!(
            data = serde_json::to_string(&data)
                .expect("cannot convert data back to json")
                .as_str(),
            "setting policy data"
        );
        set_epoch_deadline_and_call_guest!(self.epoch_deadline, self.store, {
            self.policy.set_data(&mut self.store, &self.memory, data)
        })?;

        debug!(
            input = serde_json::to_string(&input)
                .expect("cannot convert input back to JSON")
                .as_str(),
            "attempting evaluation"
        );
        set_epoch_deadline_and_call_guest!(self.epoch_deadline, self.store, {
            self.policy
                .evaluate(entrypoint_id, &mut self.store, &self.memory, input)
        })
    }
}
