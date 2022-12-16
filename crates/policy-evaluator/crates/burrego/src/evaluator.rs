use crate::builtins;
use crate::host_callbacks::HostCallbacks;
use crate::opa_host_functions;
use crate::policy::Policy;
use crate::stack_helper::StackHelper;
use anyhow::{anyhow, Result};
use itertools::Itertools;
use std::collections::{HashMap, HashSet};
use tracing::debug;
use wasmtime::{Engine, Instance, Linker, Memory, MemoryType, Module, Store};

pub struct Evaluator {
    #[allow(dead_code)]
    engine: Engine,
    #[allow(dead_code)]
    linker: Linker<Option<StackHelper>>,
    store: Store<Option<StackHelper>>,
    instance: Instance,
    memory: Memory,
    policy: Policy,
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
        let mut linker = Linker::<Option<StackHelper>>::new(&engine);

        let opa_data_helper: Option<StackHelper> = None;
        let mut store = Store::new(&engine, opa_data_helper);

        let memory_ty = MemoryType::new(5, None);
        let memory = Memory::new(&mut store, memory_ty)?;
        linker.define("env", "memory", memory)?;

        opa_host_functions::add_to_linker(&mut linker)?;

        let instance = linker.instantiate(&mut store, &module)?;

        let stack_helper = StackHelper::new(
            &instance,
            &memory,
            &mut store,
            host_callbacks.opa_abort,
            host_callbacks.opa_println,
        )?;
        let policy = Policy::new(&instance, &mut store, &memory)?;
        _ = store.data_mut().insert(stack_helper);

        if let Some(deadline) = epoch_deadline {
            store.set_epoch_deadline(deadline);
        }
        let used_builtins: String = policy
            .builtins(&mut store, &memory)?
            .keys()
            .cloned()
            .collect::<Vec<String>>()
            .join(", ");
        debug!(used = used_builtins.as_str(), "policy builtins");

        let mut evaluator = Evaluator {
            engine,
            linker,
            store,
            instance,
            memory,
            policy,
            epoch_deadline,
        };

        let not_implemented_builtins = evaluator.not_implemented_builtins()?;
        if !not_implemented_builtins.is_empty() {
            return Err(anyhow!(
                "missing Rego builtins: {}. Aborting execution.",
                not_implemented_builtins.iter().join(", ")
            ));
        }

        Ok(evaluator)
    }

    pub fn opa_abi_version(&mut self) -> Result<(i32, i32)> {
        let major = self
            .instance
            .get_global(&mut self.store, "opa_wasm_abi_version")
            .and_then(|g| g.get(&mut self.store).i32())
            .ok_or_else(|| anyhow!("Cannot find OPA Wasm ABI major version"))?;
        let minor = self
            .instance
            .get_global(&mut self.store, "opa_wasm_abi_minor_version")
            .and_then(|g| g.get(&mut self.store).i32())
            .ok_or_else(|| anyhow!("Cannot find OPA Wasm ABI minor version"))?;

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
                anyhow!(
                    "Cannot find the specified entrypoint {} inside of {:?}",
                    entrypoint,
                    entrypoints
                )
            })
    }

    pub fn entrypoints(&mut self) -> Result<HashMap<String, i32>> {
        if let Some(deadline) = self.epoch_deadline {
            self.store.set_epoch_deadline(deadline);
        }
        self.policy.entrypoints(&mut self.store, &self.memory)
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
                anyhow!(
                    "Cannot find the specified entrypoint {} inside of {:?}",
                    entrypoint_id,
                    entrypoints
                )
            })?;

        debug!(
            data = serde_json::to_string(&data)?.as_str(),
            "setting policy data"
        );
        if let Some(deadline) = self.epoch_deadline {
            self.store.set_epoch_deadline(deadline);
        }
        self.policy.set_data(&mut self.store, &self.memory, data)?;

        debug!(
            input = serde_json::to_string(&input)?.as_str(),
            "attempting evaluation"
        );
        if let Some(deadline) = self.epoch_deadline {
            self.store.set_epoch_deadline(deadline);
        }
        self.policy
            .evaluate(entrypoint_id, &mut self.store, &self.memory, input)
            .map_err(|e| anyhow!("Evaluation error: {:?}", e))
    }
}
