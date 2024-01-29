use crate::runtimes::wapc::errors::{Result, WapcRuntimeError};
use kubewarden_policy_sdk::metadata::ProtocolVersion;
use kubewarden_policy_sdk::response::ValidationResponse as PolicyValidationResponse;
use kubewarden_policy_sdk::settings::SettingsValidationResponse;
use serde_json::json;
use std::convert::TryFrom;
use tracing::{error, info};

use crate::admission_response::AdmissionResponse;
use crate::policy_evaluator::{PolicySettings, ValidateRequest};
use crate::runtimes::wapc::WapcStack;

pub(crate) struct Runtime<'a>(pub(crate) &'a mut WapcStack);

/// Error message returned by wasmtime_provider when the guest execution
/// is interrupted because of epoch deadline is exceeded.
///
/// Unfortunately, wasmtime_provider doesn't return a typed error, hence we have
/// to look for this text
const WAPC_EPOCH_INTERRUPTION_ERR_MSG: &str = "guest code interrupted, execution deadline exceeded";

impl<'a> Runtime<'a> {
    pub fn validate(
        &mut self,
        settings: &PolicySettings,
        request: &ValidateRequest,
    ) -> AdmissionResponse {
        let uid = request.uid();

        let req_json_value =
            serde_json::to_value(request).expect("cannot convert request to json value");

        //NOTE: object is null for DELETE operations
        let req_obj = match request {
            ValidateRequest::Raw(_) => Some(&req_json_value),
            ValidateRequest::AdmissionRequest(_) => req_json_value.get("object"),
        };

        let validate_params = json!({
            "request": request,
            "settings": settings,
        });

        let validate_str = match serde_json::to_string(&validate_params) {
            Ok(s) => s,
            Err(e) => {
                error!(
                    error = e.to_string().as_str(),
                    "cannot serialize validation params"
                );
                return AdmissionResponse::reject_internal_server_error(
                    uid.to_string(),
                    e.to_string(),
                );
            }
        };

        match self.0.call("validate", validate_str.as_bytes()) {
            Ok(res) => {
                let pol_val_resp: Result<PolicyValidationResponse> = serde_json::from_slice(&res)
                    .map_err(WapcRuntimeError::InvalidResponseWithError);
                pol_val_resp
                    .and_then(|pol_val_resp| {
                        AdmissionResponse::from_policy_validation_response(
                            uid.to_string(),
                            req_obj,
                            &pol_val_resp,
                        )
                        .map_err(|e| -> WapcRuntimeError {
                            WapcRuntimeError::InvalidResponseFormat(e)
                        })
                    })
                    .unwrap_or_else(|e| {
                        error!(
                            error = e.to_string().as_str(),
                            "cannot build validation response from policy result"
                        );
                        AdmissionResponse::reject_internal_server_error(
                            uid.to_string(),
                            e.to_string(),
                        )
                    })
            }
            Err(e) => {
                error!(error = e.to_string().as_str(), "waPC communication error");
                if e.to_string()
                    .as_str()
                    .contains(WAPC_EPOCH_INTERRUPTION_ERR_MSG)
                {
                    // TL;DR: after code execution is interrupted because of an
                    // epoch deadline being reached, we have to reset the waPC host
                    // to ensure further invocations of the policy work as expected.
                    //
                    // The waPC host is using the wasmtime_provider, which internally
                    // uses a wasmtime::Engine and a wasmtime::Store.
                    // The Store keeps track of the stateful data of the policy. When an
                    // epoch deadline is reached, wasmtime::Engine stops the execution of
                    // the wasm guest. There's NO CLEANUP code called inside of the guest.
                    // It's like unplugging the power cord from a turned on computer.
                    //
                    // When the guest function is invoked again, the previous state stored
                    // inside of wasmtime::Store is used.
                    // That can lead to unexpected issues. For example, if the guest makes
                    // uses of a Mutex, something like that can happen (I've witnessed that):
                    //
                    // * Guest code 1st run:
                    //   - Mutex.lock
                    // * Host: interrupt code execution because of epoch deadline
                    // * Guest code 2nd run:
                    //   - The Mutex is still locked, because that's what is stored inside
                    //     of the wasmtime::Store
                    //   - Guest attempts to `lock` the Mutex -> error is raised
                    //
                    // The guest code will stay in this broken state forever. The only
                    // solution to that is to reinitialize the wasmtime::Store.
                    // It's hard to provide a facility for that inside of WapcHost, because
                    // epoch deadline is a feature provided only by the wasmtime backend.
                    // Hence it's easier to just recreate the wapc_host associated with this
                    // policy evaluator
                    if let Err(reset_err) = self.0.reset() {
                        error!(error = reset_err.to_string().as_str(), "cannot reset waPC stack - further calls to this policy can result in errors");
                    } else {
                        info!("wapc_host reset performed after timeout protection was triggered");
                    }
                }
                AdmissionResponse::reject_internal_server_error(uid.to_string(), e.to_string())
            }
        }
    }

    pub fn validate_settings(&mut self, settings: String) -> SettingsValidationResponse {
        match self.0.call("validate_settings", settings.as_bytes()) {
            Ok(res) => {
                let vr: Result<SettingsValidationResponse> = serde_json::from_slice(&res)
                    .map_err(WapcRuntimeError::InvalidResponseWithError);
                vr.unwrap_or_else(|e| SettingsValidationResponse {
                    valid: false,
                    message: Some(format!("error: {e:?}")),
                })
            }
            Err(err) => SettingsValidationResponse {
                valid: false,
                message: Some(format!(
                    "Error invoking settings validation callback: {err:?}"
                )),
            },
        }
    }

    pub fn protocol_version(&self) -> Result<ProtocolVersion> {
        match self.0.call("protocol_version", &[0; 0]) {
            Ok(res) => ProtocolVersion::try_from(res.clone())
                .map_err(|e| WapcRuntimeError::CreateProtocolVersion { res, error: e }),
            Err(e) => Err(WapcRuntimeError::InvokeProtocolVersion(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        evaluation_context::EvaluationContext, runtimes::wapc::callback::new_host_callback,
    };
    use std::{
        sync::{self, Arc},
        thread, time,
    };

    #[test]
    fn wapc_epoch_interrutpion_error_msg() {
        // This unit test makes sure that waPC host error raised when a wasmtime
        // epoch_interruption happens contains the WAPC_EPOCH_INTERRUPTION_ERR_MSG
        // string
        //
        // The unit test is a bit "low-level", meaning the target are the
        // wapc libraries we consume, not the "high" level code we expose
        // as part of policy-evaluator.
        // This is done to make the whole testing process simple:
        // * No need to download a wasm module from a registry/commit a ~3Mb
        //   binary blob to this git repository
        // * Reduce the code being tested to the bare minimum

        let mut engine_conf = wasmtime::Config::default();
        engine_conf.epoch_interruption(true);
        let engine = wasmtime::Engine::new(&engine_conf).expect("cannot create wasmtime engine");

        let wat = include_bytes!("../../../tests/data/endless_wasm/wapc_endless_loop.wat");
        let module = wasmtime::Module::new(&engine, wat).expect("cannot compile WAT to wasm");

        // Create the wapc engine, the code will be interrupted after 10 ticks
        // happen. We produce 1 tick every 10 milliseconds, see below
        let wapc_engine_builder = wasmtime_provider::WasmtimeEngineProviderBuilder::new()
            .engine(engine.clone())
            .module(module)
            .enable_epoch_interruptions(10, 10);

        let eval_ctx = EvaluationContext {
            policy_id: "wapc_endless_loop".to_string(),
            callback_channel: None,
            ctx_aware_resources_allow_list: Default::default(),
        };

        let eval_ctx = Arc::new(eval_ctx);

        let wapc_engine = wapc_engine_builder
            .build()
            .expect("error creating wasmtime engine provider");
        let host = wapc::WapcHost::new(
            Box::new(wapc_engine),
            Some(Box::new(new_host_callback(eval_ctx))),
        )
        .expect("cannot create waPC host");

        // Create a lock to break the endless loop of the ticker thread
        let timer_lock = sync::Arc::new(sync::RwLock::new(false));
        let quit_lock = timer_lock.clone();

        // Start a thread that ticks the epoch timer of the wasmtime
        // engine. 1 tick equals 10 milliseconds
        thread::spawn(move || {
            let interval = time::Duration::from_millis(10);
            loop {
                thread::sleep(interval);
                engine.increment_epoch();
                if *quit_lock.read().unwrap() {
                    break;
                }
            }
        });

        // This triggers an endless loop inside of wasm
        // If the epoch_interruption doesn't work, this unit test
        // will never complete
        let res = host.call("run", "".as_bytes());

        // Tell the ticker thread to quit
        {
            let mut w = timer_lock.write().unwrap();
            *w = true;
        }

        // Ensure we got back an error from waPC, the error must
        // contain the WAPC_EPOCH_INTERRUPTION_ERR_MSG string
        let err = res.unwrap_err();
        assert!(err
            .to_string()
            .as_str()
            .contains(WAPC_EPOCH_INTERRUPTION_ERR_MSG));
    }
}
