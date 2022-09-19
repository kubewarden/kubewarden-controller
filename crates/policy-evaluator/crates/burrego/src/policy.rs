use crate::stack_helper::StackHelper;
use anyhow::{anyhow, Result};
use serde_json::json;
use std::collections::HashMap;
use std::convert::TryFrom;
use wasmtime::{AsContextMut, Instance, Memory, TypedFunc};

pub(crate) struct Policy {
    builtins_fn: TypedFunc<(), i32>,
    entrypoints_fn: TypedFunc<(), i32>,
    opa_heap_ptr_get_fn: TypedFunc<(), i32>,
    opa_heap_ptr_set_fn: TypedFunc<i32, ()>,
    opa_eval_ctx_new_fn: TypedFunc<(), i32>,
    opa_eval_ctx_set_input_fn: TypedFunc<(i32, i32), ()>,
    opa_eval_ctx_set_data_fn: TypedFunc<(i32, i32), ()>,
    opa_eval_ctx_set_entrypoint_fn: TypedFunc<(i32, i32), ()>,
    opa_eval_ctx_get_result_fn: TypedFunc<i32, i32>,
    opa_json_dump_fn: TypedFunc<i32, i32>,
    opa_malloc_fn: TypedFunc<i32, i32>,
    opa_json_parse_fn: TypedFunc<(i32, i32), i32>,
    eval_fn: TypedFunc<i32, i32>,

    data_addr: i32,
    base_heap_ptr: i32,
    data_heap_ptr: i32,
}

impl Policy {
    pub fn new(
        instance: &Instance,
        mut store: impl AsContextMut,
        memory: &Memory,
    ) -> Result<Policy> {
        let mut policy = Policy {
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
            opa_json_dump_fn: instance
                .get_typed_func::<i32, i32, _>(store.as_context_mut(), "opa_json_dump")
                .map_err(|e| anyhow!("Cannot access opa_json_dump fuction: {:?}", e))?,
            opa_malloc_fn: instance
                .get_typed_func::<i32, i32, _>(store.as_context_mut(), "opa_malloc")
                .map_err(|e| anyhow!("Cannot access opa_malloc fuction: {:?}", e))?,
            opa_json_parse_fn: instance
                .get_typed_func::<(i32, i32), i32, _>(store.as_context_mut(), "opa_json_parse")
                .map_err(|e| anyhow!("Cannot access opa_json_parse fuction: {:?}", e))?,
            eval_fn: instance.get_typed_func::<i32, i32, _>(store.as_context_mut(), "eval")?,
            data_addr: 0,
            base_heap_ptr: 0,
            data_heap_ptr: 0,
        };

        // init data
        let initial_data = json!({});
        policy.data_addr = StackHelper::push_json(
            store.as_context_mut(),
            memory,
            policy.opa_malloc_fn,
            policy.opa_json_parse_fn,
            &initial_data,
        )?;
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
    ) -> Result<HashMap<String, i32>> {
        let addr = self.builtins_fn.call(store.as_context_mut(), ())?;

        let builtins: HashMap<String, i32> =
            StackHelper::pull_json(store, memory, self.opa_json_dump_fn, addr)?
                .as_object()
                .ok_or_else(|| anyhow!("OPA builtins didn't return a dictionary"))?
                .iter()
                .map(|(k, v)| {
                    let id = v.as_i64().unwrap() as i32;
                    let builtin = String::from(k.as_str());
                    (builtin, id)
                })
                .collect();
        Ok(builtins)
    }

    pub fn entrypoints(
        &self,
        mut store: impl AsContextMut,
        memory: &Memory,
    ) -> Result<HashMap<String, i32>> {
        let addr = self.entrypoints_fn.call(store.as_context_mut(), ())?;
        let res =
            StackHelper::pull_json(store.as_context_mut(), memory, self.opa_json_dump_fn, addr)?
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
        self.data_addr = StackHelper::push_json(
            store.as_context_mut(),
            memory,
            self.opa_malloc_fn,
            self.opa_json_parse_fn,
            data,
        )?;
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
        let input_addr = StackHelper::push_json(
            store.as_context_mut(),
            memory,
            self.opa_malloc_fn,
            self.opa_json_parse_fn,
            input,
        )?;

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

        StackHelper::pull_json(
            store.as_context_mut(),
            memory,
            self.opa_json_dump_fn,
            res_addr,
        )
    }
}
