use anyhow::{anyhow, Result};

use serde_json::json;

use std::fs::File;
use std::io::prelude::*;

use wapc::WapcHost;
use wasmtime_provider::WasmtimeEngineProvider;

use chimera_kube_policy_sdk::response::ValidationResponse as PolicyValidationResponse;
use chimera_kube_policy_sdk::settings::SettingsValidationResponse;

use crate::utils::convert_yaml_map_to_json;
use crate::validation_response::ValidationResponse;

pub struct PolicyEvaluator {
    wapc_host: WapcHost,
    settings: serde_json::Map<String, serde_json::Value>,
}

impl PolicyEvaluator {
    pub fn new(
        wasm_file: String,
        settings: serde_yaml::Mapping,
        host_callback: impl Fn(
                u64,
                &str,
                &str,
                &str,
                &[u8],
            )
                -> std::result::Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>
            + 'static
            + Sync
            + Send,
    ) -> Result<PolicyEvaluator> {
        let mut f = File::open(&wasm_file)?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;

        let engine = WasmtimeEngineProvider::new(&buf, None);
        let host = WapcHost::new(Box::new(engine), host_callback)?;
        let settings_json = convert_yaml_map_to_json(settings)?;

        Ok(PolicyEvaluator {
            wapc_host: host,
            settings: settings_json,
        })
    }

    pub fn validate(&mut self, request: serde_json::Value) -> ValidationResponse {
        let uid = request
            .get("uid")
            .and_then(|v| v.as_str())
            .or(Some(""))
            .map(|s| s.to_owned())
            .unwrap();

        let req_obj = request.get("object");
        if req_obj.is_none() {
            return ValidationResponse::reject(
                uid,
                String::from("request doesn't have a 'object' value"),
                hyper::StatusCode::BAD_REQUEST.as_u16(),
            );
        }
        let req_obj = req_obj.unwrap();

        let validate_params = json!({
            "request": request,
            "settings": self.settings,
        });
        let validate_str = match serde_json::to_string(&validate_params) {
            Ok(s) => s,
            Err(e) => {
                //TODO: proper logging
                println!("Cannot serialize validation params: {}", e);
                return ValidationResponse::reject_internal_server_error(uid);
            }
        };

        match self.wapc_host.call("validate", validate_str.as_bytes()) {
            Ok(res) => {
                let pol_val_resp: Result<PolicyValidationResponse> = serde_json::from_slice(&res)
                    .map_err(|e| anyhow!("cannot deserialize policy validation response: {:?}", e));

                pol_val_resp
                    .and_then(|pol_val_resp| {
                        ValidationResponse::from_policy_validation_response(
                            uid.clone(),
                            &req_obj,
                            &pol_val_resp,
                        )
                    })
                    .unwrap_or_else(|e| {
                        //TODO: proper logging
                        println!("Cannot build validation response from policy result: {}", e);
                        ValidationResponse::reject_internal_server_error(uid)
                    })
            }
            Err(e) => {
                //TODO: proper logging
                println!("Something went wrong with waPC: {}", e);
                ValidationResponse::reject_internal_server_error(uid)
            }
        }
    }

    pub fn validate_settings(&mut self) -> SettingsValidationResponse {
        let settings_str = match serde_json::to_string(&self.settings) {
            Ok(s) => s,
            Err(e) => {
                return SettingsValidationResponse {
                    valid: false,
                    message: Some(format!("Cannot serialize validation params: {}", e)),
                }
            }
        };

        match self
            .wapc_host
            .call("validate_settings", settings_str.as_bytes())
        {
            Ok(res) => {
                let vr: Result<SettingsValidationResponse> = serde_json::from_slice(&res)
                    .map_err(|e| anyhow!("cannot convert response: {:?}", e));
                vr.unwrap_or_else(|e| SettingsValidationResponse {
                    valid: false,
                    message: Some(format!("error: {:?}", e)),
                })
            }
            Err(err) => {
                if let wapc::errors::ErrorKind::GuestCallFailure(m) = err.kind() {
                    // Unfortunately waPC doesn't define a dedicated error
                    if m.contains("No handler registered") {
                        return SettingsValidationResponse {
                            valid: true,
                            message: Some(String::from(
                                "This policy doesn't have a settings validation capability",
                            )),
                        };
                    }
                };
                SettingsValidationResponse {
                    valid: false,
                    message: Some(format!(
                        "Error invoking settings validation callback: {:?}",
                        err
                    )),
                }
            }
        }
    }
}
