use crate::errors::{BurregoError, Result};
use crate::host_callbacks;

use std::collections::HashMap;
use std::convert::TryInto;
use wasmtime::{AsContext, AsContextMut, Instance, Memory, TypedFunc};

/// StackHelper provides a set of helper methods to share data
/// between the host and the Rego Wasm guest
#[derive(Clone)]
pub(crate) struct StackHelper {
    pub(crate) opa_json_dump_fn: TypedFunc<i32, i32>,
    pub(crate) opa_malloc_fn: TypedFunc<i32, i32>,
    pub(crate) opa_json_parse_fn: TypedFunc<(i32, i32), i32>,

    pub(crate) opa_abort_host_callback: host_callbacks::HostCallback,
    pub(crate) opa_println_host_callback: host_callbacks::HostCallback,

    pub(crate) builtins: HashMap<i32, String>,
}

impl StackHelper {
    pub fn new(
        instance: &Instance,
        memory: &Memory,
        mut store: impl AsContextMut,
        opa_abort_host_callback: host_callbacks::HostCallback,
        opa_println_host_callback: host_callbacks::HostCallback,
    ) -> Result<StackHelper> {
        let opa_json_dump_fn = instance
            .get_typed_func::<i32, i32, _>(store.as_context_mut(), "opa_json_dump")
            .map_err(|e| {
                BurregoError::RegoWasmError(format!("cannot access opa_json_dump fuction: {:?}", e))
            })?;
        let opa_malloc_fn = instance
            .get_typed_func::<i32, i32, _>(store.as_context_mut(), "opa_malloc")
            .map_err(|e| {
                BurregoError::RegoWasmError(format!("Cannot access opa_malloc fuction: {:?}", e))
            })?;
        let opa_json_parse_fn = instance
            .get_typed_func::<(i32, i32), i32, _>(store.as_context_mut(), "opa_json_parse")
            .map_err(|e| {
                BurregoError::RegoWasmError(format!(
                    "Cannot access opa_json_parse fuction: {:?}",
                    e
                ))
            })?;

        let builtins_fn = instance
            .get_typed_func::<(), i32, _>(store.as_context_mut(), "builtins")
            .map_err(|e| {
                BurregoError::RegoWasmError(format!("cannot access builtins function: {:?}", e))
            })?;
        let addr = builtins_fn.call(store.as_context_mut(), ()).map_err(|e| {
            BurregoError::WasmEngineError(format!("cannot invoke builtins function: {:?}", e))
        })?;

        let builtins: HashMap<i32, String> =
            StackHelper::pull_json(store, memory, opa_json_dump_fn, addr)?
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
                    (id, builtin)
                })
                .collect();

        Ok(StackHelper {
            opa_json_dump_fn,
            opa_malloc_fn,
            opa_json_parse_fn,
            builtins,
            opa_abort_host_callback,
            opa_println_host_callback,
        })
    }

    /// Read a string from the Wasm guest into the host
    /// # Arguments
    /// * `store` - the Store associated with the Wasm instance
    /// * `memory` - the Wasm linear memory used by the Wasm Instance
    /// * `addr` - address inside of the Wasm linear memory where the value is stored
    /// # Returns
    /// * The data read
    pub fn read_string(store: impl AsContext, memory: &Memory, addr: i32) -> Result<Vec<u8>> {
        let mut buffer: [u8; 1] = [0u8];
        let mut data: Vec<u8> = vec![];
        let mut raw_addr = addr;

        loop {
            memory
                .read(&store, raw_addr.try_into().unwrap(), &mut buffer)
                .map_err(|e| {
                    BurregoError::WasmEngineError(format!("cannot read from memory: {:?}", e))
                })?;
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
    /// * `opa_json_dump_fn` - the `opa_json_dump` function exported by the wasm guest
    /// * `addr` - address inside of the Wasm linear memory where the value is stored
    /// # Returns
    /// * The JSON data read
    pub fn pull_json(
        mut store: impl AsContextMut,
        memory: &Memory,
        opa_json_dump_fn: TypedFunc<i32, i32>,
        addr: i32,
    ) -> Result<serde_json::Value> {
        let raw_addr = opa_json_dump_fn
            .call(store.as_context_mut(), addr)
            .map_err(|e| {
                BurregoError::WasmEngineError(format!(
                    "cannot invoke opa_json_dump function: {:?}",
                    e
                ))
            })?;
        let data = StackHelper::read_string(store, memory, raw_addr)?;

        serde_json::from_slice(&data).map_err(|e| {
            BurregoError::JSONError(format!(
                "cannot convert data read from memory into utf8 String: {:?}",
                e
            ))
        })
    }

    /// Push a JSON data from the host into the Wasm guest
    /// # Arguments
    /// * `store` - the Store associated with the Wasm instance
    /// * `memory` - the Wasm linear memory used by the Wasm Instance
    /// * `opa_malloc_fn` - the `opa_malloc` function exported by the wasm guest
    /// * `opa_json_parse_fn` - the `opa_json_parse` function exported by the wasm guest
    /// * `value` - the JSON data to push into the Wasm guest
    /// # Returns
    /// * Address inside of the Wasm linear memory where the value has been stored
    pub fn push_json(
        mut store: impl AsContextMut,
        memory: &Memory,
        opa_malloc_fn: TypedFunc<i32, i32>,
        opa_json_parse_fn: TypedFunc<(i32, i32), i32>,
        value: &serde_json::Value,
    ) -> Result<i32> {
        let data = serde_json::to_vec(&value).map_err(|e| {
            BurregoError::JSONError(format!("push_json: cannot convert value to json: {:?}", e))
        })?;

        let data_size: i32 = data.len().try_into().map_err(|e| {
            BurregoError::JSONError(format!("push_json: cannot convert size to json: {:?}", e))
        })?;

        // allocate memory to fit the value
        let raw_addr = opa_malloc_fn
            .call(store.as_context_mut(), data_size)
            .map_err(|e| {
                BurregoError::WasmEngineError(format!(
                    "push_json: cannot invoke opa_malloc function: {:?}",
                    e
                ))
            })?;
        memory
            .write(store.as_context_mut(), raw_addr.try_into().unwrap(), &data)
            .map_err(|e| {
                BurregoError::WasmEngineError(format!("push_json: cannot write to memory: {:?}", e))
            })?;

        match opa_json_parse_fn.call(store.as_context_mut(), (raw_addr, data_size)) {
            Ok(0) => Err(BurregoError::RegoWasmError(
                "Failed to load json in memory".to_string(),
            )),
            Ok(addr) => Ok(addr),
            Err(e) => Err(BurregoError::RegoWasmError(format!(
                "Cannot get memory address: {:?}",
                e
            ))),
        }
    }
}
