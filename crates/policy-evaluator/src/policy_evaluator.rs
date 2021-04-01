use anyhow::{anyhow, Result};

use serde_json::json;

use std::{fmt, fs::File, io::prelude::*};

use tracing::error;

use wapc::WapcHost;
use wasmtime_provider::WasmtimeEngineProvider;

use kubewarden_policy_sdk::response::ValidationResponse as PolicyValidationResponse;
use kubewarden_policy_sdk::settings::SettingsValidationResponse;

use crate::utils::convert_yaml_map_to_json;
use crate::validation_response::ValidationResponse;

use crate::cluster_context::ClusterContext;

pub(crate) fn host_callback(
    _id: u64,
    binding: &str,
    namespace: &str,
    _operation: &str,
    _payload: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let cluster_context = ClusterContext::get();
    if binding != "kubernetes" {
        return Err(format!("unknown binding: {}", binding).into());
    }
    match namespace {
        "ingresses" => Ok(cluster_context.ingresses().into()),
        "namespaces" => Ok(cluster_context.namespaces().into()),
        "services" => Ok(cluster_context.services().into()),
        _ => Err(format!("unknown namespace name: {}", namespace).into()),
    }
}

pub struct PolicyEvaluator {
    wapc_host: WapcHost,
    settings: serde_json::Map<String, serde_json::Value>,
}

impl fmt::Debug for PolicyEvaluator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PolicyEvaluator")
            .field("settings", &self.settings)
            .finish()
    }
}

impl PolicyEvaluator {
    pub fn new(wasm_file: String, settings: serde_yaml::Mapping) -> Result<PolicyEvaluator> {
        let mut f = File::open(&wasm_file)?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;

        if let Err(error) = ClusterContext::init() {
            println!("non fatal error: could not initialize a cluster context due to error: {}; context sensitive functions will not return any information", error);
        }

        let engine = WasmtimeEngineProvider::new(&buf, None);
        let host = WapcHost::new(Box::new(engine), host_callback)?;
        let settings_json = convert_yaml_map_to_json(settings)?;

        Ok(PolicyEvaluator {
            wapc_host: host,
            settings: settings_json,
        })
    }

    #[tracing::instrument]
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
                error!(
                    error = e.to_string().as_str(),
                    "cannot serialize validation params"
                );
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
                        error!(
                            error = e.to_string().as_str(),
                            "cannot build validation response from policy result"
                        );
                        ValidationResponse::reject_internal_server_error(uid)
                    })
            }
            Err(e) => {
                error!(error = e.to_string().as_str(), "waPC communication error");

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
