use anyhow::{anyhow, Result};
use lazy_static::lazy_static;
use serde::Serialize;
use serde_json::{json, value};
use std::{collections::HashMap, convert::TryFrom, fmt, fs, path::Path, sync::RwLock};
use tracing::{debug, error};

use wapc::WapcHost;
use wasmtime_provider::WasmtimeEngineProvider;

use kubewarden_policy_sdk::metadata::ProtocolVersion;
use kubewarden_policy_sdk::response::ValidationResponse as PolicyValidationResponse;
use kubewarden_policy_sdk::settings::SettingsValidationResponse;

use crate::cluster_context::ClusterContext;
use crate::policy::Policy;
use crate::validation_response::ValidationResponse;

#[derive(Clone, PartialEq, serde::Deserialize, serde::Serialize, Debug)]
pub enum PolicyExecutionMode {
    #[serde(rename = "kubewarden-wapc")]
    KubewardenWapc,
    #[serde(rename = "opa")]
    Opa,
    #[serde(rename = "gatekeeper")]
    OpaGatekeeper,
}

lazy_static! {
    static ref WAPC_POLICY_MAPPING: RwLock<HashMap<u64, Policy>> =
        RwLock::new(HashMap::with_capacity(64));
}

#[derive(Serialize)]
pub struct ValidateRequest(serde_json::Value);

impl ValidateRequest {
    pub fn new(request: serde_json::Value) -> Self {
        ValidateRequest(request)
    }

    fn uid(&self) -> &str {
        if let Some(uid) = self.0.get("uid").and_then(value::Value::as_str) {
            uid
        } else {
            ""
        }
    }
}

pub(crate) fn host_callback(
    policy_id: u64,
    binding: &str,
    namespace: &str,
    operation: &str,
    payload: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    match binding {
        "kubewarden" => match namespace {
            "tracing" => match operation {
                "log" => {
                    let policy_mapping = WAPC_POLICY_MAPPING.read().unwrap();
                    let policy = policy_mapping.get(&policy_id).unwrap();
                    if let Err(e) = policy.log(payload) {
                        let p =
                            String::from_utf8(payload.to_vec()).unwrap_or_else(|e| e.to_string());
                        error!(
                            payload = p.as_str(),
                            error = e.to_string().as_str(),
                            "Cannot log event"
                        );
                    }
                    Ok(Vec::new())
                }
                _ => {
                    error!("unknown operation: {}", operation);
                    Err(format!("unknown operation: {}", operation).into())
                }
            },
            _ => {
                error!("unknown namespace: {}", namespace);
                Err(format!("unknown namespace: {}", namespace).into())
            }
        },
        "kubernetes" => {
            let cluster_context = ClusterContext::get();
            match namespace {
                "ingresses" => Ok(cluster_context.ingresses().into()),
                "namespaces" => Ok(cluster_context.namespaces().into()),
                "services" => Ok(cluster_context.services().into()),
                _ => {
                    error!("unknown namespace: {}", namespace);
                    Err(format!("unknown namespace: {}", namespace).into())
                }
            }
        }
        _ => {
            error!("unknown binding: {}", binding);
            Err(format!("unknown binding: {}", binding).into())
        }
    }
}

pub struct BurregoEvaluator {
    evaluator: burrego::opa::wasm::Evaluator,
    entrypoint_id: i32,
    input: serde_json::Value,
    data: serde_json::Value,
}

pub enum Runtime {
    Wapc(wapc::WapcHost),
    // The `BurregoEvaluator` variant is boxed since it outsizes the
    // other variants of this enum.
    Burrego(Box<BurregoEvaluator>),
}

pub struct PolicyEvaluator {
    runtime: Runtime,
    policy: Policy,
    settings: serde_json::Map<String, serde_json::Value>,
}

impl fmt::Debug for PolicyEvaluator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PolicyEvaluator")
            .field("id", &self.policy.id)
            .field("settings", &self.settings)
            .finish()
    }
}

impl PolicyEvaluator {
    pub fn from_file(
        id: String,
        policy_file: &Path,
        policy_execution_mode: PolicyExecutionMode,
        settings: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> Result<PolicyEvaluator> {
        PolicyEvaluator::from_contents(id, fs::read(policy_file)?, policy_execution_mode, settings)
    }

    pub fn from_contents(
        id: String,
        policy_contents: Vec<u8>,
        policy_execution_mode: PolicyExecutionMode,
        settings: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> Result<PolicyEvaluator> {
        let (policy, runtime) = match policy_execution_mode {
            PolicyExecutionMode::KubewardenWapc => {
                let engine = WasmtimeEngineProvider::new(&policy_contents, None);
                let wapc_host = WapcHost::new(Box::new(engine), host_callback)?;
                let policy = PolicyEvaluator::from_contents_internal(
                    id,
                    |_| Ok(wapc_host.id()),
                    Policy::new,
                    policy_execution_mode,
                )?;
                let policy_runtime = Runtime::Wapc(wapc_host);
                (policy, policy_runtime)
            }
            PolicyExecutionMode::Opa | PolicyExecutionMode::OpaGatekeeper => {
                let policy = PolicyEvaluator::from_contents_internal(
                    id.clone(),
                    |_| Ok(0),
                    Policy::new,
                    policy_execution_mode,
                )?;
                let evaluator = burrego::opa::wasm::Evaluator::new(id, &policy_contents)?;
                let policy_runtime = Runtime::Burrego(Box::new(BurregoEvaluator {
                    evaluator,
                    entrypoint_id: 0, // This is fixed for now to the first entry point
                    input: json!({}), // TODO: let kwctl/policy-server populate this
                    data: json!({}),  // TODO: let kwctl/policy-server populate this
                }));
                (policy, policy_runtime)
            }
        };

        Ok(PolicyEvaluator {
            runtime,
            policy,
            settings: settings.unwrap_or_default(),
        })
    }

    fn from_contents_internal<E, P>(
        id: String,
        engine_initializer: E,
        policy_initializer: P,
        policy_execution_mode: PolicyExecutionMode,
    ) -> Result<Policy>
    where
        E: Fn(PolicyExecutionMode) -> Result<u64>,
        P: Fn(String) -> Result<Policy>,
    {
        let wapc_policy_id = engine_initializer(policy_execution_mode)?;

        let policy = policy_initializer(id)?;
        WAPC_POLICY_MAPPING
            .write()
            .unwrap()
            .insert(wapc_policy_id, policy.clone());

        Ok(policy)
    }

    #[tracing::instrument(skip(request))]
    pub fn validate(&mut self, request: ValidateRequest) -> ValidationResponse {
        let uid = request.uid();

        let req_obj = match request.0.get("object") {
            Some(req_obj) => req_obj,
            None => {
                return ValidationResponse::reject(
                    uid.to_string(),
                    "request doesn't have an 'object' value".to_string(),
                    hyper::StatusCode::BAD_REQUEST.as_u16(),
                );
            }
        };
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
                return ValidationResponse::reject_internal_server_error(
                    uid.to_string(),
                    e.to_string(),
                );
            }
        };
        match &mut self.runtime {
            Runtime::Wapc(wapc_host) => match wapc_host.call("validate", validate_str.as_bytes()) {
                Ok(res) => {
                    let pol_val_resp: Result<PolicyValidationResponse> =
                        serde_json::from_slice(&res).map_err(|e| {
                            anyhow!("cannot deserialize policy validation response: {:?}", e)
                        });
                    pol_val_resp
                        .and_then(|pol_val_resp| {
                            ValidationResponse::from_policy_validation_response(
                                uid.to_string(),
                                req_obj,
                                &pol_val_resp,
                            )
                        })
                        .unwrap_or_else(|e| {
                            error!(
                                error = e.to_string().as_str(),
                                "cannot build validation response from policy result"
                            );
                            ValidationResponse::reject_internal_server_error(
                                uid.to_string(),
                                e.to_string(),
                            )
                        })
                }
                Err(e) => {
                    error!(error = e.to_string().as_str(), "waPC communication error");
                    ValidationResponse::reject_internal_server_error(uid.to_string(), e.to_string())
                }
            },
            Runtime::Burrego(ref mut burrego) => {
                let burrego_evaluation = burrego.evaluator.evaluate(
                    burrego.entrypoint_id,
                    &burrego.input,
                    &burrego.data,
                );
                match burrego_evaluation {
                    Ok(evaluation_result) => {
                        // According to the OPA WASM
                        // documentation/specification, the result of
                        // the evaluation will contain an object of
                        // the form:
                        //
                        // ```
                        // [
                        //   {
                        //     "result": "<the AdmissionReview object -- generated by the policy>"
                        //   }
                        // ]
                        // ```
                        //
                        // Reference: https://www.openpolicyagent.org/docs/v0.31.0/wasm/#compiling-policies
                        let evaluation_result = evaluation_result
                            .get(0)
                            .and_then(|r| r.get("result"))
                            .and_then(|r| r.get("response"));

                        match evaluation_result {
                            Some(evaluation_result) => {
                                match serde_json::from_value(evaluation_result.clone()) {
                                    Ok(evaluation_result) => ValidationResponse {
                                        uid: uid.to_string(),
                                        ..evaluation_result
                                    },
                                    Err(err) => ValidationResponse::reject_internal_server_error(
                                        uid.to_string(),
                                        err.to_string(),
                                    ),
                                }
                            }
                            None => ValidationResponse::reject_internal_server_error(
                                uid.to_string(),
                                "cannot interpret OPA policy result".to_string(),
                            ),
                        }
                    }
                    Err(err) => {
                        error!(
                            error = err.to_string().as_str(),
                            "error evaluating policy with burrego"
                        );
                        ValidationResponse::reject_internal_server_error(
                            uid.to_string(),
                            err.to_string(),
                        )
                    }
                }
            }
        }
    }

    #[tracing::instrument]
    pub fn validate_settings(&self) -> SettingsValidationResponse {
        let settings_str = match serde_json::to_string(&self.settings) {
            Ok(s) => s,
            Err(e) => {
                return SettingsValidationResponse {
                    valid: false,
                    message: Some(format!("Cannot serialize validation params: {}", e)),
                }
            }
        };

        match &self.runtime {
            Runtime::Wapc(wapc_host) => {
                match wapc_host.call("validate_settings", settings_str.as_bytes()) {
                    Ok(res) => {
                        let vr: Result<SettingsValidationResponse> = serde_json::from_slice(&res)
                            .map_err(|e| anyhow!("cannot convert response: {:?}", e));
                        vr.unwrap_or_else(|e| SettingsValidationResponse {
                            valid: false,
                            message: Some(format!("error: {:?}", e)),
                        })
                    }
                    Err(err) => SettingsValidationResponse {
                        valid: false,
                        message: Some(format!(
                            "Error invoking settings validation callback: {:?}",
                            err
                        )),
                    },
                }
            }
            Runtime::Burrego(_) => {
                debug!("settings cannot be evaluated by a burrego runtime");
                SettingsValidationResponse {
                    valid: true,
                    message: None,
                }
            }
        }
    }

    pub fn protocol_version(&self) -> Result<ProtocolVersion> {
        match &self.runtime {
            Runtime::Wapc(wapc_host) => match wapc_host.call("protocol_version", &[0; 0]) {
                Ok(res) => ProtocolVersion::try_from(res.clone()).map_err(|e| {
                    anyhow!(
                        "Cannot create ProtocolVersion object from '{:?}': {:?}",
                        res,
                        e
                    )
                }),
                Err(err) => Err(anyhow!(
                    "Cannot invoke 'protocol_version' waPC function: {:?}",
                    err
                )),
            },
            _ => Err(anyhow!(
                "protocol_version is only applicable to a Kubewarden policy"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_is_registered_in_the_mapping() -> Result<()> {
        let policy = Policy::default();
        let policy_id = 1;

        assert!(!WAPC_POLICY_MAPPING.read().unwrap().contains_key(&policy_id));

        PolicyEvaluator::from_contents_internal(
            "mock_policy".to_string(),
            |_| Ok(policy_id),
            |_| Ok(policy.clone()),
            PolicyExecutionMode::KubewardenWapc,
        )?;

        let policy_mapping = WAPC_POLICY_MAPPING.read().unwrap();

        assert!(policy_mapping.contains_key(&policy_id));
        assert_eq!(policy_mapping[&policy_id], policy);

        Ok(())
    }

    #[test]
    fn serialize_policy_execution_mode() {
        let mut test_data: HashMap<String, PolicyExecutionMode> = HashMap::new();
        test_data.insert(
            serde_json::to_string(&json!("kubewarden-wapc")).unwrap(),
            PolicyExecutionMode::KubewardenWapc,
        );
        test_data.insert(
            serde_json::to_string(&json!("opa")).unwrap(),
            PolicyExecutionMode::Opa,
        );
        test_data.insert(
            serde_json::to_string(&json!("gatekeeper")).unwrap(),
            PolicyExecutionMode::OpaGatekeeper,
        );

        for (expected, mode) in &test_data {
            let actual = serde_json::to_string(&mode);
            assert!(actual.is_ok());
            assert_eq!(expected, &actual.unwrap());
        }
    }

    #[test]
    fn deserialize_policy_execution_mode() {
        let mut test_data: HashMap<String, PolicyExecutionMode> = HashMap::new();
        test_data.insert(
            serde_json::to_string(&json!("kubewarden-wapc")).unwrap(),
            PolicyExecutionMode::KubewardenWapc,
        );
        test_data.insert(
            serde_json::to_string(&json!("opa")).unwrap(),
            PolicyExecutionMode::Opa,
        );
        test_data.insert(
            serde_json::to_string(&json!("gatekeeper")).unwrap(),
            PolicyExecutionMode::OpaGatekeeper,
        );

        for (mode_str, expected) in &test_data {
            let actual: std::result::Result<PolicyExecutionMode, serde_json::Error> =
                serde_json::from_str(&mode_str);
            assert_eq!(expected, &actual.unwrap());
        }

        // an unknown policy mode should not be deserializable
        let actual: std::result::Result<PolicyExecutionMode, serde_json::Error> =
            serde_json::from_str("hello world");
        assert!(actual.is_err());
    }
}
