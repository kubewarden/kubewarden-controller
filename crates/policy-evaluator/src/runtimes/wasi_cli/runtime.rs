use kubewarden_policy_sdk::response::ValidationResponse as PolicyValidationResponse;
use kubewarden_policy_sdk::settings::SettingsValidationResponse;
use serde_json::json;
use std::io::Cursor;
use tracing::{error, warn};
use wasi_common::pipe::{ReadPipe, WritePipe};
use wasmtime_wasi::sync::WasiCtxBuilder;

use super::{errors::WasiRuntimeError, stack};
use crate::admission_response::AdmissionResponse;
use crate::policy_evaluator::{PolicySettings, ValidateRequest};

const EXIT_SUCCESS: i32 = 0;

pub(crate) struct Runtime<'a>(pub(crate) &'a mut stack::Stack);

struct ExcutionResult {
    stdout: String,
    stderr: String,
}

impl<'a> Runtime<'a> {
    /// executes the wasi cli program
    fn execute(
        &mut self,
        input: Vec<u8>,
        args: &[String],
    ) -> std::result::Result<ExcutionResult, WasiRuntimeError> {
        let stdout_pipe = WritePipe::new_in_memory();
        let stderr_pipe = WritePipe::new_in_memory();
        let stdin_pipe = ReadPipe::new(Cursor::new(input));

        let wasi_ctx = WasiCtxBuilder::new()
            .args(args)?
            .stdin(Box::new(stdin_pipe))
            .stdout(Box::new(stdout_pipe.clone()))
            .stderr(Box::new(stderr_pipe.clone()))
            .build();
        let ctx = stack::Context { wasi_ctx };

        let mut store = wasmtime::Store::new(&self.0.engine, ctx);
        if let Some(deadline) = self.0.epoch_deadlines {
            store.set_epoch_deadline(deadline.wapc_func);
        }

        let instance = self
            .0
            .instance_pre
            .instantiate(&mut store)
            .map_err(WasiRuntimeError::WasmInstantiate)?;
        let start_fn = instance
            .get_typed_func::<(), ()>(&mut store, "_start")
            .map_err(WasiRuntimeError::WasmMissingStartFn)?;
        let evaluation_result = start_fn.call(&mut store, ());

        // Dropping the store, this is no longer needed, plus it's keeping
        // references to the WritePipe(s) that we need exclusive access to.
        drop(store);

        let stderr = pipe_to_string("stderr", stderr_pipe)?;

        if let Err(err) = evaluation_result {
            if let Some(exit_error) = err.downcast_ref::<wasmtime_wasi::I32Exit>() {
                if exit_error.0 == EXIT_SUCCESS {
                    let stdout = pipe_to_string("stdout", stdout_pipe)?;
                    return Ok(ExcutionResult { stdout, stderr });
                } else {
                    return Err(WasiRuntimeError::WasiEvaluation {
                        code: Some(exit_error.0),
                        stderr,
                        error: err,
                    });
                }
            }
            return Err(WasiRuntimeError::WasiEvaluation {
                code: None,
                stderr,
                error: err,
            });
        }

        let stdout = pipe_to_string("stdout", stdout_pipe)?;
        Ok(ExcutionResult { stdout, stderr })
    }

    pub fn validate(
        &mut self,
        settings: &PolicySettings,
        request: &ValidateRequest,
    ) -> AdmissionResponse {
        let validate_params = json!({
            "request": request,
            "settings": settings,
        });

        let input = match serde_json::to_vec(&validate_params) {
            Ok(s) => s,
            Err(e) => {
                error!(
                    error = e.to_string().as_str(),
                    "cannot serialize validation params"
                );
                return AdmissionResponse::reject_internal_server_error(
                    request.uid().to_string(),
                    e.to_string(),
                );
            }
        };
        let args = vec!["policy.wasm".to_string(), "validate".to_string()];

        match self.execute(input, &args) {
            Ok(ExcutionResult { stdout, stderr }) => {
                if !stderr.is_empty() {
                    warn!(
                        request = request.uid().to_string(),
                        operation = "validate",
                        "stderr: {:?}",
                        stderr
                    )
                }
                match serde_json::from_slice::<PolicyValidationResponse>(stdout.as_bytes()) {
                    Ok(pvr) => {
                        let req_json_value = serde_json::to_value(request)
                            .expect("cannot convert request to json value");
                        let req_obj = match request {
                            ValidateRequest::Raw(_) => Some(&req_json_value),
                            ValidateRequest::AdmissionRequest(_) => req_json_value.get("object"),
                        };

                        AdmissionResponse::from_policy_validation_response(
                            request.uid().to_string(),
                            req_obj,
                            &pvr,
                        )
                    }
                    .unwrap_or_else(|e| {
                        AdmissionResponse::reject_internal_server_error(
                            request.uid().to_string(),
                            format!("Cannot convert policy validation response: {e}"),
                        )
                    }),
                    Err(e) => AdmissionResponse::reject_internal_server_error(
                        request.uid().to_string(),
                        format!("Cannot deserialize policy validation response: {e}"),
                    ),
                }
            }
            Err(e) => AdmissionResponse::reject_internal_server_error(
                request.uid().to_string(),
                e.to_string(),
            ),
        }
    }

    pub fn validate_settings(&mut self, settings: String) -> SettingsValidationResponse {
        let args = vec!["policy.wasm".to_string(), "validate-settings".to_string()];

        match self.execute(settings.as_bytes().to_owned(), &args) {
            Ok(ExcutionResult { stdout, stderr }) => {
                if !stderr.is_empty() {
                    warn!(operation = "validate-settings", "stderr: {:?}", stderr)
                }
                serde_json::from_slice::<SettingsValidationResponse>(stdout.as_bytes())
                    .unwrap_or_else(|e| SettingsValidationResponse {
                        valid: false,
                        message: Some(format!(
                            "Cannot deserialize settings validation response: {e}"
                        )),
                    })
            }
            Err(e) => SettingsValidationResponse {
                valid: false,
                message: Some(e.to_string()),
            },
        }
    }
}

fn pipe_to_string(
    name: &str,
    pipe: WritePipe<Cursor<Vec<u8>>>,
) -> std::result::Result<String, WasiRuntimeError> {
    match pipe.try_into_inner() {
        Ok(cursor) => {
            let buf = cursor.into_inner();
            String::from_utf8(buf).map_err(|e| WasiRuntimeError::PipeConversion {
                name: name.to_string(),
                error: format!("Cannot convert buffer to UTF8 string: {e}"),
            })
        }
        Err(_) => Err(WasiRuntimeError::PipeConversion {
            name: name.to_string(),
            error: "cannot convert pipe into inner".to_string(),
        }),
    }
}
