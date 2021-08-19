use anyhow::{anyhow, Result};
use std::collections::{HashMap, HashSet};
use wasmtime::{
    AsContextMut, Caller, Engine, Func, Instance, Limits, Linker, Memory, MemoryType, Module, Store,
};

use crate::opa::{builtins, host_callbacks::HostCallbacks, Policy, StackHelper};
use std::path::Path;
use std::sync::RwLock;

use tracing::{debug, error};

type LookupTable = HashMap<i64, String>;

struct BuiltinsHelper {
    builtins: builtins::BuiltinFunctionsMap,
    pub lookup_tables: HashMap<usize, LookupTable>,
}

impl BuiltinsHelper {
    fn invoke(
        &self,
        policy_id: usize,
        builtin_id: i32,
        args: &[serde_json::Value],
    ) -> Result<serde_json::Value> {
        let lookup_table = self.lookup_tables.get(&policy_id).ok_or_else(|| {
            let policy = LOADED_POLICIES.read().unwrap().policy(policy_id).unwrap();
            anyhow!("Cannot find lookup table for policy {}", policy)
        })?;
        let builtin_name = lookup_table.get(&builtin_id.into()).ok_or_else(|| {
            anyhow!(
                "Cannot find builtin with id {} inside of builtins_lookup table",
                builtin_id
            )
        })?;

        let builtin_fn = self
            .builtins
            .get(builtin_name.as_str())
            .ok_or_else(|| anyhow!("Cannot find builtin function with name {}", builtin_name))?;

        debug!(
            builtin = builtin_name.as_str(),
            args = serde_json::to_string(&args)?.as_str(),
            "invoking builtin"
        );
        builtin_fn(args)
    }
}

struct LoadedPolicies {
    policies: Vec<String>,
}

impl LoadedPolicies {
    fn new() -> LoadedPolicies {
        LoadedPolicies {
            policies: Vec::new(),
        }
    }

    fn register(&mut self, policy_name: String) -> usize {
        self.policies.push(policy_name);
        self.policies.len() - 1
    }

    fn policy(&self, policy_id: usize) -> Option<String> {
        self.policies.get(policy_id).cloned()
    }
}

use lazy_static::lazy_static;
lazy_static! {
    static ref LOADED_POLICIES: RwLock<LoadedPolicies> = RwLock::new(LoadedPolicies::new());
    static ref BUILTINS_HELPER: RwLock<BuiltinsHelper> = {
        let lookup_tables: HashMap<usize, LookupTable> = HashMap::new();

        RwLock::new(BuiltinsHelper {
            builtins: builtins::get_builtins(),
            lookup_tables,
        })
    };
}

pub struct Evaluator {
    #[allow(dead_code)]
    engine: Engine,
    #[allow(dead_code)]
    linker: Linker<Option<StackHelper>>,
    store: Store<Option<StackHelper>>,
    instance: Instance,
    memory: Memory,
    policy: Policy,
}

impl Evaluator {
    pub fn from_path(
        policy_name: String,
        policy_path: &Path,
        host_callbacks: &'static HostCallbacks,
    ) -> Result<Evaluator> {
        Evaluator::new(policy_name, &std::fs::read(&policy_path)?, host_callbacks)
    }

    pub fn new(
        policy_name: String,
        policy_contents: &[u8],
        host_callbacks: &'static HostCallbacks,
    ) -> Result<Evaluator> {
        let engine = Engine::default();
        let mut linker = Linker::<Option<StackHelper>>::new(&engine);

        let opa_data_helper: Option<StackHelper> = None;
        let mut store = Store::new(&engine, opa_data_helper);

        let memory_ty = MemoryType::new(Limits::new(5, None));
        let memory = Memory::new(&mut store, memory_ty)?;
        linker.define("env", "memory", memory)?;

        // OPA host callbacks. Listed at https://www.openpolicyagent.org/docs/latest/wasm/#imports

        let opa_abort = Func::wrap(
            &mut store,
            move |mut caller: Caller<'_, Option<StackHelper>>, addr: i32| {
                let stack_helper = caller.data().unwrap();
                let msg = stack_helper
                    .read_string(caller.as_context_mut(), &memory, addr)
                    .map_or_else(
                        |e| format!("cannot decode opa_abort message: {:?}", e),
                        |data| String::from_utf8(data).unwrap_or_else(|e| format!("cannot decode opa_abort message: didn't read a valid string from memory - {:?}", e)),
                    );
                (host_callbacks.opa_abort)(msg);
            },
        );
        linker.define("env", "opa_abort", opa_abort)?;

        let opa_println = Func::wrap(
            &mut store,
            move |mut caller: Caller<'_, Option<StackHelper>>, addr: i32| {
                let stack_helper = caller.data_mut().unwrap();
                let msg = stack_helper
                    .read_string(caller.as_context_mut(), &memory, addr)
                    .map_or_else(
                        |e| format!("cannot decode opa_println message: {:?}", e),
                        |data| String::from_utf8(data).unwrap_or_else(|e| format!("cannot decode opa_println message: didn't read a valid string from memory - {:?}", e)),
                    );
                (host_callbacks.opa_println)(msg);
            },
        );
        linker.define("env", "opa_println", opa_println)?;

        //env.opa_builtin0 (builtin_id, ctx) addr
        //Called to dispatch the built-in function identified by the builtin_id.
        //The ctx parameter reserved for future use. The result addr must refer to a value in the shared-memory buffer. The function accepts 0 arguments.
        let opa_builtin0 = Func::wrap(
            &mut store,
            move |mut caller: Caller<'_, Option<StackHelper>>, builtin_id: i32, _ctx: i32| -> i32 {
                debug!(builtin_id, "opa_builtin0");

                let stack_helper = caller.data().unwrap();
                let args = vec![];

                BUILTINS_HELPER
                    .read()
                    .unwrap()
                    .invoke(stack_helper.policy_id, builtin_id, &args)
                    .map(|res| stack_helper.push_json(caller.as_context_mut(), &memory, &res))
                    .unwrap_or_else(|e| {
                        error!(error = e.to_string().as_str(), "something went wrong");
                        Ok(0)
                    })
                    .unwrap()
            },
        );
        linker.define("env", "opa_builtin0", opa_builtin0)?;

        //env.opa_builtin1(builtin_id, ctx, _1) addr
        //Same as previous except the function accepts 1 argument.
        let opa_builtin1 = Func::wrap(
            &mut store,
            move |mut caller: Caller<'_, Option<StackHelper>>,
                  builtin_id: i32,
                  _ctx: i32,
                  p1: i32|
                  -> i32 {
                debug!(builtin_id, p1, "opa_builtin1");

                let stack_helper = caller.data().unwrap();

                let p1 = stack_helper
                    .pull_json(caller.as_context_mut(), &memory, p1)
                    .unwrap();
                let args = vec![p1];

                BUILTINS_HELPER
                    .read()
                    .unwrap()
                    .invoke(stack_helper.policy_id, builtin_id, &args)
                    .map(|res| stack_helper.push_json(caller.as_context_mut(), &memory, &res))
                    .unwrap_or_else(|e| {
                        error!(error = e.to_string().as_str(), "something went wrong");
                        Ok(0)
                    })
                    .unwrap()
            },
        );
        linker.define("env", "opa_builtin1", opa_builtin1)?;

        //env.opa_builtin2 (builtin_id, ctx, _1, _2) addr
        //Same as previous except the function accepts 2 arguments.
        let opa_builtin2 = Func::wrap(
            &mut store,
            move |mut caller: Caller<'_, Option<StackHelper>>,
                  builtin_id: i32,
                  _ctx: i32,
                  p1: i32,
                  p2: i32|
                  -> i32 {
                debug!(builtin_id, p1, p2, "opa_builtin2");

                let stack_helper = caller.data().unwrap();

                let p1 = stack_helper
                    .pull_json(caller.as_context_mut(), &memory, p1)
                    .unwrap();
                let p2 = stack_helper
                    .pull_json(caller.as_context_mut(), &memory, p2)
                    .unwrap();
                let args = vec![p1, p2];

                BUILTINS_HELPER
                    .read()
                    .unwrap()
                    .invoke(stack_helper.policy_id, builtin_id, &args)
                    .map(|res| stack_helper.push_json(caller.as_context_mut(), &memory, &res))
                    .unwrap_or_else(|e| {
                        error!(error = e.to_string().as_str(), "something went wrong");
                        Ok(0)
                    })
                    .unwrap()
            },
        );
        linker.define("env", "opa_builtin2", opa_builtin2)?;

        //env.opa_builtin3 (builtin_id, ctx, _1, _2, _3) addr
        //Same as previous except the function accepts 3 arguments.
        let opa_builtin3 = Func::wrap(
            &mut store,
            move |mut caller: Caller<'_, Option<StackHelper>>,
                  builtin_id: i32,
                  _ctx: i32,
                  p1: i32,
                  p2: i32,
                  p3: i32|
                  -> i32 {
                debug!(builtin_id, p1, p2, p3, "opa_builtin3");

                let stack_helper = caller.data().unwrap();

                let p1 = stack_helper
                    .pull_json(caller.as_context_mut(), &memory, p1)
                    .unwrap();
                let p2 = stack_helper
                    .pull_json(caller.as_context_mut(), &memory, p2)
                    .unwrap();
                let p3 = stack_helper
                    .pull_json(caller.as_context_mut(), &memory, p3)
                    .unwrap();
                let args = vec![p1, p2, p3];

                BUILTINS_HELPER
                    .read()
                    .unwrap()
                    .invoke(stack_helper.policy_id, builtin_id, &args)
                    .map(|res| stack_helper.push_json(caller.as_context_mut(), &memory, &res))
                    .unwrap_or_else(|e| {
                        error!(error = e.to_string().as_str(), "something went wrong");
                        Ok(0)
                    })
                    .unwrap()
            },
        );
        linker.define("env", "opa_builtin3", opa_builtin3)?;

        //env.opa_builtin4 (builtin_id, ctx, _1, _2, _3, _4) addr
        //Same as previous except the function accepts 4 arguments.
        let opa_builtin4 = Func::wrap(
            &mut store,
            move |mut caller: Caller<'_, Option<StackHelper>>,
                  builtin_id: i32,
                  _ctx: i32,
                  p1: i32,
                  p2: i32,
                  p3: i32,
                  p4: i32|
                  -> i32 {
                debug!(builtin_id, p1, p2, p3, p4, "opa_builtin3");
                let stack_helper = caller.data().unwrap();

                let p1 = stack_helper
                    .pull_json(caller.as_context_mut(), &memory, p1)
                    .unwrap();
                let p2 = stack_helper
                    .pull_json(caller.as_context_mut(), &memory, p2)
                    .unwrap();
                let p3 = stack_helper
                    .pull_json(caller.as_context_mut(), &memory, p3)
                    .unwrap();
                let p4 = stack_helper
                    .pull_json(caller.as_context_mut(), &memory, p4)
                    .unwrap();

                let args = vec![p1, p2, p3, p4];

                BUILTINS_HELPER
                    .read()
                    .unwrap()
                    .invoke(stack_helper.policy_id, builtin_id, &args)
                    .map(|res| stack_helper.push_json(caller.as_context_mut(), &memory, &res))
                    .unwrap_or_else(|e| {
                        error!(error = e.to_string().as_str(), "something went wrong");
                        Ok(0)
                    })
                    .unwrap()
            },
        );
        linker.define("env", "opa_builtin4", opa_builtin4)?;

        let module = Module::from_binary(&engine, policy_contents)?;
        let instance = linker.instantiate(&mut store, &module)?;

        let policy_id = LOADED_POLICIES.write().unwrap().register(policy_name);
        let stack_helper = StackHelper::new(policy_id, &instance, &mut store)?;
        let policy = Policy::new(&instance, &mut store, &memory, stack_helper)?;
        store.data_mut().get_or_insert(stack_helper);

        let policy_lookup_table = policy.builtins_lookup(&mut store, &memory)?;
        BUILTINS_HELPER
            .write()
            .unwrap()
            .lookup_tables
            .insert(policy_id, policy_lookup_table);

        let used_builtins: String = policy
            .builtins(&mut store, &memory)?
            .keys()
            .cloned()
            .collect::<Vec<String>>()
            .join(", ");
        debug!(used = used_builtins.as_str(), "policy builtins");

        Ok(Evaluator {
            engine,
            linker,
            store,
            instance,
            memory,
            policy,
        })
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
        self.policy.set_data(&mut self.store, &self.memory, data)?;

        debug!(
            input = serde_json::to_string(&input)?.as_str(),
            "attempting evaluation"
        );
        let res = self
            .policy
            .evaluate(entrypoint_id, &mut self.store, &self.memory, input)
            .map_err(|e| anyhow!("Evaluation error: {:?}", e));

        res
    }
}
