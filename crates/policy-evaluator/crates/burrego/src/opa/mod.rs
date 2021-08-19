use anyhow::{anyhow, Result};
use serde_json::json;
use std::{collections::HashMap, convert::TryFrom, convert::TryInto};
use wasmtime::*;

pub mod builtins;
pub mod default_host_callbacks;
pub mod host_callbacks;
pub mod wasm;

/// StackHelper provides a set of helper methods to share data
/// between the host and the Rego Wasm guest
#[derive(Copy, Clone)]
pub struct StackHelper {
    opa_json_dump_fn: TypedFunc<i32, i32>,
    opa_malloc_fn: TypedFunc<i32, i32>,
    opa_json_parse_fn: TypedFunc<(i32, i32), i32>,
    policy_id: usize,
    // This signals whether the policy invoked the `opa_abort`
    // import. Right now, we continue execution and don't abort it as
    // the expectation is, but we use this information to know whether
    // to return an error result. If `opa_abort` was called, we want
    // to return an error from the policy execution. We should abort
    // the execution, but given Rego is not turing-complete, we might
    // not enter in endless loop due to the the lack of really
    // aborting the execution.
    //
    // TODO (ereslibre): abort execution when `opa_abort` is
    // called.
    pub policy_aborted_execution: bool,
}

impl StackHelper {
    pub fn new(
        policy_id: usize,
        instance: &Instance,
        mut store: impl AsContextMut,
    ) -> Result<StackHelper> {
        let opa_json_dump_fn = instance
            .get_typed_func::<i32, i32, _>(store.as_context_mut(), "opa_json_dump")
            .map_err(|e| anyhow!("Cannot access opa_json_dump fuction: {:?}", e))?;
        let opa_malloc_fn = instance
            .get_typed_func::<i32, i32, _>(store.as_context_mut(), "opa_malloc")
            .map_err(|e| anyhow!("Cannot access opa_malloc fuction: {:?}", e))?;
        let opa_json_parse_fn = instance
            .get_typed_func::<(i32, i32), i32, _>(store.as_context_mut(), "opa_json_parse")
            .map_err(|e| anyhow!("Cannot access opa_json_parse fuction: {:?}", e))?;

        Ok(StackHelper {
            opa_json_dump_fn,
            opa_malloc_fn,
            opa_json_parse_fn,
            policy_id,
            policy_aborted_execution: false,
        })
    }

    /// Read a string from the Wasm guest into the host
    /// # Arguments
    /// * `store` - the Store associated with the Wasm instance
    /// * `memory` - the Wasm linear memory used by the Wasm Instance
    /// * `addr` - address inside of the Wasm linear memory where the value is stored
    /// # Returns
    /// * The data read
    pub fn read_string(
        &self,
        store: impl AsContextMut,
        memory: &Memory,
        addr: i32,
    ) -> Result<Vec<u8>> {
        let mut buffer: [u8; 1] = [0u8];
        let mut data: Vec<u8> = vec![];
        let mut raw_addr = addr;

        loop {
            memory.read(&store, raw_addr.try_into().unwrap(), &mut buffer)?;
            if buffer[0] == 0 {
                break;
            }
            data.push(buffer[0]);
            raw_addr += 1;
        }
        Ok(data)
    }

    /// Pull a JSON data from the Wasm guest into the host
    /// # Arguments
    /// * `store` - the Store associated with the Wasm instance
    /// * `memory` - the Wasm linear memory used by the Wasm Instance
    /// * `addr` - address inside of the Wasm linear memory where the value is stored
    /// # Returns
    /// * The JSON data read
    pub fn pull_json(
        &self,
        mut store: impl AsContextMut,
        memory: &Memory,
        addr: i32,
    ) -> Result<serde_json::Value> {
        let raw_addr = self.opa_json_dump_fn.call(store.as_context_mut(), addr)?;
        let data = self.read_string(store, memory, raw_addr)?;

        serde_json::from_slice(&data).map_err(|e| {
            anyhow!(
                "Cannot convert data read from memory into utf8 String: {:?}",
                e
            )
        })
    }

    /// Push a JSON data from the host into the Wasm guest
    /// # Arguments
    /// * `store` - the Store associated with the Wasm instance
    /// * `memory` - the Wasm linear memory used by the Wasm Instance
    /// * `value` - the JSON data to push into the Wasm guest
    /// # Returns
    /// * Address inside of the Wasm linear memory where the value has been stored
    pub fn push_json(
        &self,
        mut store: impl AsContextMut,
        memory: &Memory,
        value: &serde_json::Value,
    ) -> Result<i32> {
        let data = serde_json::to_vec(&value)?;
        let data_size: i32 = data
            .len()
            .try_into()
            .map_err(|e| anyhow!("push_json: cannot convert size: {:?}", e))?;

        // allocate memory to fit the value
        let raw_addr = self.opa_malloc_fn.call(store.as_context_mut(), data_size)?;
        memory.write(store.as_context_mut(), raw_addr.try_into().unwrap(), &data)?;

        match self
            .opa_json_parse_fn
            .call(store.as_context_mut(), (raw_addr, data_size))
        {
            Ok(0) => Err(anyhow!("Failed to load json in memory")),
            Ok(addr) => Ok(addr),
            Err(e) => Err(anyhow!("Cannot get memory address: {:?}", e)),
        }
    }
}

#[derive(Copy, Clone)]
pub struct Policy {
    builtins_fn: TypedFunc<(), i32>,
    entrypoints_fn: TypedFunc<(), i32>,
    opa_heap_ptr_get_fn: TypedFunc<(), i32>,
    opa_heap_ptr_set_fn: TypedFunc<i32, ()>,
    opa_eval_ctx_new_fn: TypedFunc<(), i32>,
    opa_eval_ctx_set_input_fn: TypedFunc<(i32, i32), ()>,
    opa_eval_ctx_set_data_fn: TypedFunc<(i32, i32), ()>,
    opa_eval_ctx_set_entrypoint_fn: TypedFunc<(i32, i32), ()>,
    opa_eval_ctx_get_result_fn: TypedFunc<i32, i32>,
    eval_fn: TypedFunc<i32, i32>,

    stack_helper: StackHelper,

    data_addr: i32,
    base_heap_ptr: i32,
    data_heap_ptr: i32,
}

impl Policy {
    pub fn new(
        instance: &Instance,
        mut store: impl AsContextMut,
        memory: &Memory,
        stack_helper: StackHelper,
    ) -> Result<Policy> {
        let mut policy = Policy {
            stack_helper,
            builtins_fn: instance
                .get_typed_func::<(), i32, _>(store.as_context_mut(), "builtins")?,
            entrypoints_fn: instance
                .get_typed_func::<(), i32, _>(store.as_context_mut(), "entrypoints")?,
            opa_heap_ptr_get_fn: instance
                .get_typed_func::<(), i32, _>(store.as_context_mut(), "opa_heap_ptr_get")?,
            opa_heap_ptr_set_fn: instance
                .get_typed_func::<i32, (), _>(store.as_context_mut(), "opa_heap_ptr_set")?,
            opa_eval_ctx_new_fn: instance
                .get_typed_func::<(), i32, _>(store.as_context_mut(), "opa_eval_ctx_new")?,
            opa_eval_ctx_set_input_fn: instance.get_typed_func::<(i32, i32), (), _>(
                store.as_context_mut(),
                "opa_eval_ctx_set_input",
            )?,
            opa_eval_ctx_set_data_fn: instance.get_typed_func::<(i32, i32), (), _>(
                store.as_context_mut(),
                "opa_eval_ctx_set_data",
            )?,
            opa_eval_ctx_set_entrypoint_fn: instance.get_typed_func::<(i32, i32), (), _>(
                store.as_context_mut(),
                "opa_eval_ctx_set_entrypoint",
            )?,
            opa_eval_ctx_get_result_fn: instance
                .get_typed_func::<i32, i32, _>(store.as_context_mut(), "opa_eval_ctx_get_result")?,
            eval_fn: instance.get_typed_func::<i32, i32, _>(store.as_context_mut(), "eval")?,
            data_addr: 0,
            base_heap_ptr: 0,
            data_heap_ptr: 0,
        };

        // init data
        let initial_data = json!({});
        policy.data_addr =
            policy
                .stack_helper
                .push_json(store.as_context_mut(), memory, &initial_data)?;
        policy.base_heap_ptr = policy
            .opa_heap_ptr_get_fn
            .call(store.as_context_mut(), ())?;
        policy.data_heap_ptr = policy.base_heap_ptr;

        Ok(policy)
    }

    pub fn builtins(
        &self,
        mut store: impl AsContextMut,
        memory: &Memory,
    ) -> Result<HashMap<String, i64>> {
        let addr = self.builtins_fn.call(store.as_context_mut(), ())?;
        let builtins: HashMap<String, i64> = self
            .stack_helper
            .pull_json(store.as_context_mut(), memory, addr)?
            .as_object()
            .ok_or_else(|| anyhow!("OPA builtins didn't return a dictionary"))?
            .iter()
            .map(|(k, v)| {
                let id = v.as_i64().unwrap();
                let builtin = String::from(k.as_str());
                (builtin, id)
            })
            .collect();
        Ok(builtins)
    }

    pub fn builtins_lookup(
        &self,
        mut store: impl AsContextMut,
        memory: &Memory,
    ) -> Result<HashMap<i64, String>> {
        Ok(self
            .builtins(store.as_context_mut(), memory)?
            .iter()
            .map(|(k, v)| (*v, k.clone()))
            .collect())
    }

    pub fn entrypoints(
        &self,
        mut store: impl AsContextMut,
        memory: &Memory,
    ) -> Result<HashMap<String, i32>> {
        let addr = self.entrypoints_fn.call(store.as_context_mut(), ())?;
        let res = self
            .stack_helper
            .pull_json(store.as_context_mut(), memory, addr)?
            .as_object()
            .ok_or_else(|| anyhow!("OPA entrypoints didn't return a dictionary"))?
            .iter()
            .map(|(k, v)| {
                let id = v.as_i64().unwrap();
                let entrypoint = String::from(k.as_str());
                (entrypoint, i32::try_from(id).unwrap())
            })
            .collect();
        Ok(res)
    }

    pub fn set_data(
        &mut self,
        mut store: impl AsContextMut,
        memory: &Memory,
        data: &serde_json::Value,
    ) -> Result<()> {
        self.opa_heap_ptr_set_fn
            .call(store.as_context_mut(), self.base_heap_ptr)?;
        self.data_addr = self
            .stack_helper
            .push_json(store.as_context_mut(), memory, data)?;
        self.data_heap_ptr = self.opa_heap_ptr_get_fn.call(store.as_context_mut(), ())?;

        Ok(())
    }

    pub fn evaluate(
        &self,
        entrypoint_id: i32,
        mut store: impl AsContextMut,
        memory: &Memory,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        // Reset the heap pointer before each evaluation
        self.opa_heap_ptr_set_fn
            .call(store.as_context_mut(), self.data_heap_ptr)?;

        // Load the input data
        let input_addr = self
            .stack_helper
            .push_json(store.as_context_mut(), memory, input)?;

        // Setup the evaluation context
        let ctx_addr = self.opa_eval_ctx_new_fn.call(store.as_context_mut(), ())?;
        self.opa_eval_ctx_set_input_fn
            .call(store.as_context_mut(), (ctx_addr, input_addr))?;
        self.opa_eval_ctx_set_data_fn
            .call(store.as_context_mut(), (ctx_addr, self.data_addr))?;
        self.opa_eval_ctx_set_entrypoint_fn
            .call(store.as_context_mut(), (ctx_addr, entrypoint_id))?;

        // Perform evaluation
        self.eval_fn.call(store.as_context_mut(), ctx_addr)?;

        // Retrieve the result
        let res_addr = self
            .opa_eval_ctx_get_result_fn
            .call(store.as_context_mut(), ctx_addr)?;

        self.stack_helper
            .pull_json(store.as_context_mut(), memory, res_addr)
    }
}
