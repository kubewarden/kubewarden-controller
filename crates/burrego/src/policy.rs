use crate::errors::{BurregoError, Result};
use crate::stack_helper::StackHelper;
use serde_json::json;
use std::collections::HashMap;
use std::convert::TryFrom;
use wasmtime::{AsContextMut, Instance, Memory, TypedFunc};

/// Handle errors returned when calling a wasmtime function
/// The macro looks into the error type and, when an epoch interruption
/// happens, maps the error to BurregoError::ExecutionDeadlineExceeded
macro_rules! map_call_error {
    ($err:expr, $msg:expr) => {{
        if let Some(trap) = $err.downcast_ref::<wasmtime::Trap>() {
            if matches!(trap, wasmtime::Trap::Interrupt) {
                BurregoError::ExecutionDeadlineExceeded
            } else {
                BurregoError::WasmEngineError(format!("{}: {:?}", $msg, $err))
            }
        } else {
            BurregoError::WasmEngineError(format!("{}: {:?}", $msg, $err))
        }
    }};
}

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
                .get_typed_func::<(), i32>(store.as_context_mut(), "builtins")
                .map_err(|e| {
                    BurregoError::RegoWasmError(format!("cannot get builtins function: {e:?}"))
                })?,
            entrypoints_fn: instance
                .get_typed_func::<(), i32>(store.as_context_mut(), "entrypoints")
                .map_err(|e| {
                    BurregoError::RegoWasmError(format!("cannot get entrypoints function: {e:?}"))
                })?,
            opa_heap_ptr_get_fn: instance
                .get_typed_func::<(), i32>(store.as_context_mut(), "opa_heap_ptr_get")
                .map_err(|e| {
                    BurregoError::RegoWasmError(format!(
                        "cannot get opa_heap_ptr_get function: {e:?}"
                    ))
                })?,
            opa_heap_ptr_set_fn: instance
                .get_typed_func::<i32, ()>(store.as_context_mut(), "opa_heap_ptr_set")
                .map_err(|e| {
                    BurregoError::RegoWasmError(format!(
                        "cannot get opa_heap_ptr_set function: {e:?}"
                    ))
                })?,
            opa_eval_ctx_new_fn: instance
                .get_typed_func::<(), i32>(store.as_context_mut(), "opa_eval_ctx_new")
                .map_err(|e| {
                    BurregoError::RegoWasmError(format!(
                        "cannot get opa_eval_ctx_new function: {e:?}"
                    ))
                })?,
            opa_eval_ctx_set_input_fn: instance
                .get_typed_func::<(i32, i32), ()>(store.as_context_mut(), "opa_eval_ctx_set_input")
                .map_err(|e| {
                    BurregoError::RegoWasmError(format!(
                        "cannot get opa_eval_ctx_set_input function: {e:?}"
                    ))
                })?,
            opa_eval_ctx_set_data_fn: instance
                .get_typed_func::<(i32, i32), ()>(store.as_context_mut(), "opa_eval_ctx_set_data")
                .map_err(|e| {
                    BurregoError::RegoWasmError(format!(
                        "cannot get opa_eval_ctx_set_data function: {e:?}"
                    ))
                })?,
            opa_eval_ctx_set_entrypoint_fn: instance
                .get_typed_func::<(i32, i32), ()>(
                    store.as_context_mut(),
                    "opa_eval_ctx_set_entrypoint",
                )
                .map_err(|e| {
                    BurregoError::RegoWasmError(format!(
                        "cannot get opa_eval_ctx_set_entrypoint function: {e:?}"
                    ))
                })?,
            opa_eval_ctx_get_result_fn: instance
                .get_typed_func::<i32, i32>(store.as_context_mut(), "opa_eval_ctx_get_result")
                .map_err(|e| {
                    BurregoError::RegoWasmError(format!(
                        "cannot get opa_eval_ctx_get_result function: {e:?}"
                    ))
                })?,
            opa_json_dump_fn: instance
                .get_typed_func::<i32, i32>(store.as_context_mut(), "opa_json_dump")
                .map_err(|e| {
                    BurregoError::RegoWasmError(format!("cannot get opa_json_dump function: {e:?}"))
                })?,
            opa_malloc_fn: instance
                .get_typed_func::<i32, i32>(store.as_context_mut(), "opa_malloc")
                .map_err(|e| {
                    BurregoError::RegoWasmError(format!("cannot get opa_malloc function: {e:?}"))
                })?,
            opa_json_parse_fn: instance
                .get_typed_func::<(i32, i32), i32>(store.as_context_mut(), "opa_json_parse")
                .map_err(|e| {
                    BurregoError::RegoWasmError(format!(
                        "cannot get opa_json_parse function: {e:?}"
                    ))
                })?,
            eval_fn: instance
                .get_typed_func::<i32, i32>(store.as_context_mut(), "eval")
                .map_err(|e| {
                    BurregoError::RegoWasmError(format!("cannot get eval function: {e:?}"))
                })?,
            data_addr: 0,
            base_heap_ptr: 0,
            data_heap_ptr: 0,
        };

        // init data
        let initial_data = json!({});
        policy.data_addr = StackHelper::push_json(
            store.as_context_mut(),
            memory,
            &policy.opa_malloc_fn,
            &policy.opa_json_parse_fn,
            &initial_data,
        )?;

        policy.base_heap_ptr = policy
            .opa_heap_ptr_get_fn
            .call(store.as_context_mut(), ())
            .map_err(|e| map_call_error!(e, "error invoking opa_heap_ptr_get function"))?;
        policy.data_heap_ptr = policy.base_heap_ptr;

        Ok(policy)
    }

    pub fn builtins(
        &self,
        mut store: impl AsContextMut,
        memory: &Memory,
    ) -> Result<HashMap<String, i32>> {
        let addr = self
            .builtins_fn
            .call(store.as_context_mut(), ())
            .map_err(|e| map_call_error!(e, "error invoking builtins function"))?;

        let builtins: HashMap<String, i32> =
            StackHelper::pull_json(store, memory, &self.opa_json_dump_fn, addr)?
                .as_object()
                .ok_or_else(|| {
                    BurregoError::RegoWasmError(
                        "OPA builtins didn't return a dictionary".to_string(),
                    )
                })?
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
        let addr = self
            .entrypoints_fn
            .call(store.as_context_mut(), ())
            .map_err(|e| map_call_error!(e, "error invoking entrypoints function"))?;
        let res =
            StackHelper::pull_json(store.as_context_mut(), memory, &self.opa_json_dump_fn, addr)?
                .as_object()
                .ok_or_else(|| {
                    BurregoError::RegoWasmError(
                        "OPA entrypoints didn't return a dictionary".to_string(),
                    )
                })?
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
        data: &[u8],
    ) -> Result<()> {
        self.opa_heap_ptr_set_fn
            .call(store.as_context_mut(), self.base_heap_ptr)
            .map_err(|e| map_call_error!(e, "error invoking opa_heap_ptr_set function"))?;
        self.data_addr = StackHelper::push_json_raw(
            store.as_context_mut(),
            memory,
            &self.opa_malloc_fn,
            &self.opa_json_parse_fn,
            data,
        )?;
        self.data_heap_ptr = self
            .opa_heap_ptr_get_fn
            .call(store.as_context_mut(), ())
            .map_err(|e| map_call_error!(e, "error invoking opa_heap_ptr_get function"))?;

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
            .call(store.as_context_mut(), self.data_heap_ptr)
            .map_err(|e| map_call_error!(e, "error invoking opa_heap_ptr_set function"))?;

        // Load the input data
        let input_addr = StackHelper::push_json(
            store.as_context_mut(),
            memory,
            &self.opa_malloc_fn,
            &self.opa_json_parse_fn,
            input,
        )?;

        // Setup the evaluation context
        let ctx_addr = self
            .opa_eval_ctx_new_fn
            .call(store.as_context_mut(), ())
            .map_err(|e| map_call_error!(e, "error invoking opa_eval_ctx_new function"))?;
        self.opa_eval_ctx_set_input_fn
            .call(store.as_context_mut(), (ctx_addr, input_addr))
            .map_err(|e| map_call_error!(e, "error invoking opa_eval_ctx_set_input function"))?;
        self.opa_eval_ctx_set_data_fn
            .call(store.as_context_mut(), (ctx_addr, self.data_addr))
            .map_err(|e| map_call_error!(e, "error invoking opa_eval_ctx_set_data function"))?;
        self.opa_eval_ctx_set_entrypoint_fn
            .call(store.as_context_mut(), (ctx_addr, entrypoint_id))
            .map_err(|e| {
                map_call_error!(e, "error invoking opa_eval_ctx_set_entrypoint function")
            })?;

        // Perform evaluation
        self.eval_fn
            .call(store.as_context_mut(), ctx_addr)
            .map_err(|e| map_call_error!(e, "error invoking opa_eval function"))?;

        // Retrieve the result
        let res_addr = self
            .opa_eval_ctx_get_result_fn
            .call(store.as_context_mut(), ctx_addr)
            .map_err(|e| map_call_error!(e, "error invoking opa_eval_ctx_get_result function"))?;

        StackHelper::pull_json(
            store.as_context_mut(),
            memory,
            &self.opa_json_dump_fn,
            res_addr,
        )
    }
}
