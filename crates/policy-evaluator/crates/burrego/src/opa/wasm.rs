use anyhow::{anyhow, Result};
use std::collections::{HashMap, HashSet};
use wasmtime::{
    AsContextMut, Caller, Engine, Func, Instance, Limits, Linker, Memory, MemoryType, Module, Store,
};

use crate::opa::{builtins, Policy, StackHelper};
use std::sync::RwLock;

type LookupTable = HashMap<i64, String>;

struct BuiltinsHelper {
    builtins: HashMap<&'static str, fn(&Vec<serde_json::Value>) -> Result<serde_json::Value>>,
    pub lookup_tables: HashMap<usize, LookupTable>,
}

impl BuiltinsHelper {
    fn invoke(
        &self,
        policy_id: usize,
        builtin_id: i32,
        args: &Vec<serde_json::Value>,
    ) -> Result<serde_json::Value> {
        let lookup_table = self.lookup_tables.get(&policy_id).ok_or_else(|| {
            let policy = LOADED_POLICIES.read().unwrap().policy(&policy_id).unwrap();
            anyhow!("Cannot find lookup table for policy {}", policy)
        })?;
        let builtin_name = lookup_table.get(&builtin_id.into()).ok_or(anyhow!(
            "Cannot find builtin with id {} inside of builtins_lookup table",
            builtin_id
        ))?;
        let builtin_fn = self.builtins.get(builtin_name.as_str()).ok_or(anyhow!(
            "Cannot find builtin function with name {}",
            builtin_name
        ))?;
        builtin_fn(args)
    }
}

struct LoadedPolicies {
    policies: HashMap<usize, String>,
}

impl LoadedPolicies {
    fn new() -> LoadedPolicies {
        let policies: HashMap<usize, String> = HashMap::new();
        LoadedPolicies { policies }
    }

    fn register(&mut self, policy: String) -> usize {
        let policy_id = self.policies.len();
        self.policies.insert(policy_id, policy);
        policy_id
    }

    fn policy(&self, policy_id: &usize) -> Option<String> {
        match self.policies.get(policy_id) {
            Some(s) => Some(s.clone()),
            None => None,
        }
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
    pub fn new(policy_path: &str) -> Result<Evaluator> {
        let engine = Engine::default();
        let mut linker = Linker::<Option<StackHelper>>::new(&engine);

        let opa_data_helper: Option<StackHelper> = None;
        let mut store = Store::new(&engine, opa_data_helper);

        let memory_ty = MemoryType::new(Limits::new(5, None));
        let memory = Memory::new(&mut store, memory_ty)?;
        linker.define("env", "memory", memory)?;

        // env.opa_abort(addr) void
        // Called if an internal error occurs.
        // The addr refers to a null-terminated string in the shared memory buffer.
        let opa_abort = Func::wrap(
            &mut store,
            move |mut caller: Caller<'_, Option<StackHelper>>, addr: i32| {
                let stack_helper = caller.data().unwrap().clone();
                let msg = stack_helper
                    .pull_json(caller.as_context_mut(), &memory, addr)
                    .unwrap();
                println!("OPA abort with message: {:?}", msg);
                std::process::exit(1);
            },
        );
        linker.define("env", "opa_abort", opa_abort)?;

        //env.opa_println (addr) void
        //Called to emit a message from the policy evaluation.
        //The addr refers to a null-terminated string in the shared memory buffer.
        let opa_println = Func::wrap(
            &mut store,
            move |mut caller: Caller<'_, Option<StackHelper>>, addr: i32| {
                let stack_helper = caller.data().unwrap().clone();
                let msg = stack_helper
                    .pull_json(caller.as_context_mut(), &memory, addr)
                    .unwrap();
                println!("Message coming from the policy: {:?}", msg);
            },
        );
        linker.define("env", "opa_println", opa_println)?;

        //env.opa_builtin0 (builtin_id, ctx) addr
        //Called to dispatch the built-in function identified by the builtin_id.
        //The ctx parameter reserved for future use. The result addr must refer to a value in the shared-memory buffer. The function accepts 0 arguments.
        let opa_builtin0 = Func::wrap(
            &mut store,
            move |mut caller: Caller<'_, Option<StackHelper>>, builtin_id: i32, _ctx: i32| -> i32 {
                println!("opa_builtin0 with builtin_id: {}", builtin_id);

                let stack_helper = caller.data().unwrap().clone();
                let args = vec![];

                BUILTINS_HELPER
                    .read()
                    .unwrap()
                    .invoke(stack_helper.policy_id, builtin_id, &args)
                    .map(|res| stack_helper.push_json(caller.as_context_mut(), &memory, &res))
                    .unwrap_or_else(|e| {
                        println!("something went wrong: {:?}", e);
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
                println!("opa_builtin1 with builtin_id: {}  -  p1 {}", builtin_id, p1);

                let stack_helper = caller.data().unwrap().clone();

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
                        println!("something went wrong: {:?}", e);
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
                println!(
                    "opa_builtin2 with builtin_id: {}  -  p1 {}  -  p2 {}",
                    builtin_id, p1, p2
                );

                let stack_helper = caller.data().unwrap().clone();

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
                        println!("something went wrong: {:?}", e);
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
                println!(
                    "opa_builtin3 with builtin_id: {}  -  p1 {}  -  p2 {} - p3 {}",
                    builtin_id, p1, p2, p3
                );

                let stack_helper = caller.data().unwrap().clone();

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
                        println!("something went wrong: {:?}", e);
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
                println!(
                    "opa_builtin3 with builtin_id: {}  -  p1 {}  -  p2 {} - p3 {} - p4 {}",
                    builtin_id, p1, p2, p3, p4
                );
                let stack_helper = caller.data().unwrap().clone();

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
                        println!("something went wrong: {:?}", e);
                        Ok(0)
                    })
                    .unwrap()
            },
        );
        linker.define("env", "opa_builtin4", opa_builtin4)?;

        let module = Module::from_file(&engine, policy_path)?;
        let instance = linker.instantiate(&mut store, &module)?;

        let policy_id = LOADED_POLICIES
            .write()
            .unwrap()
            .register(String::from(policy_path));
        let stack_helper = StackHelper::new(policy_id, &instance, &mut store)?;
        let policy = Policy::new(&instance, &mut store, &memory, stack_helper)?;
        store.data_mut().get_or_insert(stack_helper);

        let policy_lookup_table = policy.builtins_lookup(&mut store, &memory)?;
        BUILTINS_HELPER
            .write()
            .unwrap()
            .lookup_tables
            .insert(policy_id, policy_lookup_table);

        return Ok(Evaluator {
            engine,
            linker,
            store,
            instance,
            policy,
            memory,
        });
    }

    pub fn opa_abi_version(&mut self) -> Result<(i32, i32)> {
        let major = self
            .instance
            .get_global(&mut self.store, "opa_wasm_abi_version")
            .and_then(|g| g.get(&mut self.store).i32())
            .ok_or(anyhow!("Cannot find OPA Wasm ABI major version"))?;
        let minor = self
            .instance
            .get_global(&mut self.store, "opa_wasm_abi_minor_version")
            .and_then(|g| g.get(&mut self.store).i32())
            .ok_or(anyhow!("Cannot find OPA Wasm ABI minor version"))?;

        Ok((major, minor))
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
            .difference(&&supported_builtins)
            .cloned()
            .collect())
    }

    pub fn entrypoint_id(&mut self, entrypoint: &String) -> Result<i32> {
        let entrypoints = self.policy.entrypoints(&mut self.store, &self.memory)?;
        entrypoints
            .iter()
            .find(|(k, _v)| k == &entrypoint)
            .map(|(_k, v)| v.clone())
            .ok_or(anyhow!(
                "Cannot find the specified entrypoint {} inside of {:?}",
                entrypoint,
                entrypoints
            ))
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
            .ok_or(anyhow!(
                "Cannot find the specified entrypoint {} inside of {:?}",
                entrypoint_id,
                entrypoints
            ))?;

        println!("\nsetting policy data: {:?}", data);
        self.policy.set_data(&mut self.store, &self.memory, &data)?;

        println!("\nattempting evaluation with input: {:?}", input);
        self.policy
            .evaluate(entrypoint_id, &mut self.store, &self.memory, &input)
            .map_err(|e| anyhow!("Cannot convert evaluation result back to JSON: {:?}", e))
    }
}
