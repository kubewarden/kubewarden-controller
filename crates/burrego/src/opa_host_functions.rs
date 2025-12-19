use crate::errors::{BurregoError, Result};
use tracing::{debug, error};
use wasmtime::{AsContextMut, Caller, Linker};

use crate::builtins::BUILTINS_HELPER;
use crate::stack_helper::StackHelper;

/// Add OPA host callbacks to the linker.
/// The callbackes are the one listed at https://www.openpolicyagent.org/docs/latest/wasm/#imports
pub(crate) fn add_to_linker(linker: &mut Linker<Option<StackHelper>>) -> Result<()> {
    register_opa_abort_func(linker)?;
    register_opa_println_func(linker)?;
    register_opa_builtin0_func(linker)?;
    register_opa_builtin1_func(linker)?;
    register_opa_builtin2_func(linker)?;
    register_opa_builtin3_func(linker)?;
    register_opa_builtin4_func(linker)?;

    Ok(())
}

fn register_opa_abort_func(
    linker: &mut Linker<Option<StackHelper>>,
) -> Result<&mut Linker<Option<StackHelper>>> {
    linker
        .func_wrap(
            "env",
            "opa_abort",
            |mut caller: Caller<'_, Option<StackHelper>>, addr: i32| {
                let stack_helper = caller.data().as_ref().unwrap();
                let opa_abort_host_callback = stack_helper.opa_abort_host_callback;

                let memory_export = caller.get_export("memory").ok_or_else(|| BurregoError::RegoWasmError("cannot find 'memory' export".to_string()))?;
                let memory = memory_export.into_memory().ok_or_else(|| BurregoError::RegoWasmError("'memory' export cannot be converted into a memory object".to_string()))?;

                let msg = StackHelper::read_string(caller.as_context_mut(), &memory, addr)
                    .map_or_else(
                        |e| format!("cannot decode opa_abort message: {e:?}"),
                        |data| String::from_utf8(data).unwrap_or_else(|e| format!("cannot decode opa_abort message: didn't read a valid string from memory - {e:?}")),
                    );
                opa_abort_host_callback(&msg);

                Ok(())
            },
        ).map_err(|e| BurregoError::BuiltinError{
            name: "opa_abort".to_string(),
            message: e.to_string()
        })
}

fn register_opa_println_func(
    linker: &mut Linker<Option<StackHelper>>,
) -> Result<&mut Linker<Option<StackHelper>>> {
    linker.func_wrap(
        "env",
        "opa_println",
        |mut caller: Caller<'_, Option<StackHelper>>, addr: i32| {
            let stack_helper = caller.data().as_ref().unwrap();
            let opa_println_host_callback = stack_helper.opa_println_host_callback;

            let memory_export = caller.get_export("memory").ok_or_else(|| BurregoError::RegoWasmError("cannot find 'memory' export".to_string()))?;
            let memory = memory_export.into_memory().ok_or_else(|| BurregoError::RegoWasmError("'memory' export cannot be converted into a memory object".to_string()))?;

            let msg = StackHelper::read_string(caller.as_context_mut(), &memory, addr)
                .map_or_else(
                    |e| format!("cannot decode opa_println message: {e:?}"),
                    |data| String::from_utf8(data).unwrap_or_else(|e| format!("cannot decode opa_println message: didn't read a valid string from memory - {e:?}")),
                );
            opa_println_host_callback(&msg);

            Ok(())
        },
    ).map_err(|e| BurregoError::BuiltinError{
        name: "opa_println".to_string(),
        message: e.to_string()
    })
}

/// env.opa_builtin0 (builtin_id, ctx) addr
/// Called to dispatch the built-in function identified by the builtin_id.
/// The ctx parameter reserved for future use. The result addr must refer to a value in the shared-memory buffer. The function accepts 0 arguments.
fn register_opa_builtin0_func(
    linker: &mut Linker<Option<StackHelper>>,
) -> Result<&mut Linker<Option<StackHelper>>> {
    linker.func_wrap(
        "env",
        "opa_builtin0",
        |mut caller: Caller<'_, Option<StackHelper>>, builtin_id: i32, _ctx: i32| {
            debug!(builtin_id, "opa_builtin0");

            let stack_helper = caller.data().as_ref().unwrap();
            let opa_malloc_fn = stack_helper.opa_malloc_fn.clone();
            let opa_json_parse_fn = stack_helper.opa_json_parse_fn.clone();
            let builtin_name = stack_helper
                .builtins
                .get(&builtin_id)
                .ok_or_else(|| {
                    error!(builtin_id, builtins =? stack_helper.builtins, "opa_builtin0: cannot find builtin");
                    BurregoError::BuiltinNotImplementedError(format!("opa_builtin0: cannot find builtin {builtin_id}"))
                })?.clone();
            let args = vec![];

            let memory_export = caller.get_export("memory").ok_or_else(|| BurregoError::RegoWasmError("cannot find 'memory' export".to_string()))?;
            let memory = memory_export.into_memory().ok_or_else(|| BurregoError::RegoWasmError("'memory' export cannot be converted into a memory object".to_string()))?;

            let builtin_helper = BUILTINS_HELPER
                .read()
                .map_err(|e| BurregoError::RegoWasmError(format!("Cannot access global builtin helper: {e:?}")))?;

            let builtin_result = builtin_helper
                .invoke(&builtin_name, &args)?;

            let addr = StackHelper::push_json(
                caller.as_context_mut(),
                &memory,
                &opa_malloc_fn,
                &opa_json_parse_fn,
                &builtin_result,
            )?;

            Ok(addr)
        },
    ).map_err(|e| BurregoError::BuiltinError{
        name: "opa_builtin0".to_string(),
        message: e.to_string()})
}

/// env.opa_builtin1(builtin_id, ctx, _1) addr
/// Same as previous except the function accepts 1 argument.
fn register_opa_builtin1_func(
    linker: &mut Linker<Option<StackHelper>>,
) -> Result<&mut Linker<Option<StackHelper>>> {
    linker.func_wrap(
        "env",
        "opa_builtin1",
            move |mut caller: Caller<'_, Option<StackHelper>>,
                  builtin_id: i32,
                  _ctx: i32,
                  p1: i32| {
            debug!(builtin_id, p1, "opa_builtin1");

            let stack_helper = caller.data().as_ref().unwrap();
            let opa_malloc_fn = stack_helper.opa_malloc_fn.clone();
            let opa_json_parse_fn = stack_helper.opa_json_parse_fn.clone();
            let opa_json_dump_fn = stack_helper.opa_json_dump_fn.clone();
            let builtin_name = stack_helper
                .builtins
                .get(&builtin_id)
                .ok_or_else(|| {
                    error!(builtin_id, builtins =? stack_helper.builtins, "opa_builtin0: cannot find builtin");
                    BurregoError::BuiltinNotImplementedError(
                    format!("opa_bunltin1: cannot find builtin {builtin_id}"))
                })?.clone();

            let memory_export = caller.get_export("memory").ok_or_else(|| BurregoError::RegoWasmError("cannot find 'memory' export".to_string()))?;
            let memory = memory_export.into_memory().ok_or_else(|| BurregoError::RegoWasmError("'memory' export cannot be converted into a memory object".to_string()))?;


            let p1 =
                    StackHelper::pull_json(caller.as_context_mut(), &memory, &opa_json_dump_fn, p1)?;
            let args = vec![p1];

            let builtin_helper = BUILTINS_HELPER
                .read()
                .map_err(|e| BurregoError::RegoWasmError(format!("Cannot access global builtin helper: {e:?}")))?;

            let builtin_result = builtin_helper
                .invoke(&builtin_name, &args)?;

            let addr = StackHelper::push_json(
                caller.as_context_mut(),
                &memory,
                &opa_malloc_fn,
                &opa_json_parse_fn,
                &builtin_result,
            )?;

            Ok(addr)
        },
    ).map_err(|e| BurregoError::BuiltinError{
        name: "opa_bunltin1".to_string(),
        message: e.to_string(),
    })
}

/// env.opa_builtin2 (builtin_id, ctx, _1, _2) addr
/// Same as previous except the function accepts 2 arguments.
fn register_opa_builtin2_func(
    linker: &mut Linker<Option<StackHelper>>,
) -> Result<&mut Linker<Option<StackHelper>>> {
    linker.func_wrap(
        "env",
        "opa_builtin2",
            move |mut caller: Caller<'_, Option<StackHelper>>,
                  builtin_id: i32,
                  _ctx: i32,
                  p1: i32,
                  p2: i32| {
            debug!(builtin_id, p1, p2, "opa_builtin2");

            let stack_helper = caller.data().as_ref().unwrap();
            let opa_malloc_fn = stack_helper.opa_malloc_fn.clone();
            let opa_json_parse_fn = stack_helper.opa_json_parse_fn.clone();
            let opa_json_dump_fn = stack_helper.opa_json_dump_fn.clone();
            let builtin_name = stack_helper
                .builtins
                .get(&builtin_id)
                .ok_or_else(|| {
                    error!(builtin_id, builtins =? stack_helper.builtins, "opa_builtin0: cannot find builtin");
                    BurregoError::BuiltinNotImplementedError(format!("opa_builtin2: cannot find builtin {builtin_id}"))
                })?.clone();

            let memory_export = caller.get_export("memory").ok_or_else(|| BurregoError::RegoWasmError("cannot find 'memory' export".to_string()))?;
            let memory = memory_export.into_memory().ok_or_else(|| BurregoError::RegoWasmError("'memory' export cannot be converted into a memory object".to_string()))?;

            let p1 =
                    StackHelper::pull_json(caller.as_context_mut(), &memory, &opa_json_dump_fn, p1)?;
            let p2 =
                    StackHelper::pull_json(caller.as_context_mut(), &memory, &opa_json_dump_fn, p2)?;

            let args = vec![p1, p2];

            let builtin_helper = BUILTINS_HELPER
                .read()
                .map_err(|e| BurregoError::RegoWasmError(format!("Cannot access global builtin helper: {e:?}")))?;

            let builtin_result = builtin_helper.invoke(&builtin_name, &args)?;

            let addr = StackHelper::push_json(
                caller.as_context_mut(),
                &memory,
                &opa_malloc_fn,
                &opa_json_parse_fn,
                &builtin_result,
            )?;

            Ok(addr)
        },
    ).map_err(|e| BurregoError::BuiltinError{
        name: "opa_builtin2".to_string(),
        message: e.to_string()
    })
}

/// env.opa_builtin3 (builtin_id, ctx, _1, _2, _3) addr
/// Same as previous except the function accepts 3 arguments.
fn register_opa_builtin3_func(
    linker: &mut Linker<Option<StackHelper>>,
) -> Result<&mut Linker<Option<StackHelper>>> {
    linker.func_wrap(
        "env",
        "opa_builtin3",
            move |mut caller: Caller<'_, Option<StackHelper>>,
                  builtin_id: i32,
                  _ctx: i32,
                  p1: i32,
                  p2: i32,
                  p3: i32| {
            debug!(builtin_id, p1, p2, p3, "opa_builtin3");

            let stack_helper = caller.data().as_ref().unwrap();
            let opa_malloc_fn = stack_helper.opa_malloc_fn.clone();
            let opa_json_parse_fn = stack_helper.opa_json_parse_fn.clone();
            let opa_json_dump_fn = stack_helper.opa_json_dump_fn.clone();
            let builtin_name = stack_helper
                .builtins
                .get(&builtin_id)
                .ok_or_else(|| {
                    error!(builtin_id, builtins =? stack_helper.builtins, "opa_builtin0: cannot find builtin");
                    BurregoError::BuiltinNotImplementedError(format!("opa_builtin3: cannot find builtin {builtin_id}"))
                })?.clone();

            let memory_export = caller.get_export("memory").ok_or_else(|| BurregoError::RegoWasmError("cannot find 'memory' export".to_string()))?;
            let memory = memory_export.into_memory().ok_or_else(|| BurregoError::RegoWasmError("'memory' export cannot be converted into a memory object".to_string()))?;

            let p1 =
                    StackHelper::pull_json(caller.as_context_mut(), &memory, &opa_json_dump_fn, p1)?;
            let p2 =
                    StackHelper::pull_json(caller.as_context_mut(), &memory, &opa_json_dump_fn, p2)?;
            let p3 =
                    StackHelper::pull_json(caller.as_context_mut(), &memory, &opa_json_dump_fn, p3)?;

            let args = vec![p1, p2, p3];

            let builtin_helper = BUILTINS_HELPER
                .read()
                .map_err(|e| BurregoError::RegoWasmError(format!("Cannot access global builtin helper: {e:?}")))?;

            let builtin_result = builtin_helper.invoke(&builtin_name, &args)?;

            let addr = StackHelper::push_json(
                caller.as_context_mut(),
                &memory,
                &opa_malloc_fn,
                &opa_json_parse_fn,
                &builtin_result,
            )?;

            Ok(addr)
        },
    ).map_err(|e| BurregoError::BuiltinError{
        name: "opa_builtin3".to_string(),
        message: e.to_string(),
    })
}

/// env.opa_builtin4 (builtin_id, ctx, _1, _2, _3, _4) addr
/// Same as previous except the function accepts 4 arguments.
fn register_opa_builtin4_func(
    linker: &mut Linker<Option<StackHelper>>,
) -> Result<&mut Linker<Option<StackHelper>>> {
    linker.func_wrap(
        "env",
        "opa_builtin4",
            move |mut caller: Caller<'_, Option<StackHelper>>,
                  builtin_id: i32,
                  _ctx: i32,
                  p1: i32,
                  p2: i32,
                  p3: i32,
                  p4: i32| {
            debug!(builtin_id, p1, p2, p3, p4, "opa_builtin4");

            let stack_helper = caller.data().as_ref().unwrap();
            let opa_malloc_fn = stack_helper.opa_malloc_fn.clone();
            let opa_json_parse_fn = stack_helper.opa_json_parse_fn.clone();
            let opa_json_dump_fn = stack_helper.opa_json_dump_fn.clone();
            let builtin_name = stack_helper
                .builtins
                .get(&builtin_id)
                .ok_or_else(|| {
                    error!(builtin_id, builtins =? stack_helper.builtins, "opa_builtin0: cannot find builtin");
                    BurregoError::BuiltinNotImplementedError(format!("opa_builtin4: cannot find builtin {builtin_id}"))
                })?.clone();

            let memory_export = caller.get_export("memory").ok_or_else(|| BurregoError::RegoWasmError("cannot find 'memory' export".to_string()))?;
            let memory = memory_export.into_memory().ok_or_else(|| BurregoError::RegoWasmError("'memory' export cannot be converted into a memory object".to_string()))?;

            let p1 =
                    StackHelper::pull_json(caller.as_context_mut(), &memory, &opa_json_dump_fn, p1)?;
            let p2 =
                    StackHelper::pull_json(caller.as_context_mut(), &memory, &opa_json_dump_fn, p2)?;
            let p3 =
                    StackHelper::pull_json(caller.as_context_mut(), &memory, &opa_json_dump_fn, p3)?;
            let p4 =
                    StackHelper::pull_json(caller.as_context_mut(), &memory, &opa_json_dump_fn, p4)?;

            let args = vec![p1, p2, p3, p4];

            let builtin_helper = BUILTINS_HELPER
                .read()
                .map_err(|e| BurregoError::RegoWasmError(format!("Cannot access global builtin helper: {e:?}")))?;

            let builtin_result = builtin_helper.invoke(&builtin_name, &args)?;

            let addr = StackHelper::push_json(
                caller.as_context_mut(),
                &memory,
                &opa_malloc_fn,
                &opa_json_parse_fn,
                &builtin_result,
            )?;

            Ok(addr)
        },
    ).map_err(|e| BurregoError::BuiltinError{
        name: "opa_builtin4".to_string(),
        message: e.to_string(),
    })
}
