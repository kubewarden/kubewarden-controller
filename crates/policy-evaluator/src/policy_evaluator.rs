use anyhow::{anyhow, Result};
use lazy_static::lazy_static;
use serde::Serialize;
use serde_json::{json, value};
use std::{collections::HashMap, fmt, fs, path::Path, sync::RwLock};
use tracing::error;

use wapc::WapcHost;
use wasmtime_provider::WasmtimeEngineProvider;

use kubewarden_policy_sdk::metadata::ProtocolVersion;
use kubewarden_policy_sdk::settings::SettingsValidationResponse;

use crate::cluster_context::ClusterContext;
use crate::policy::Policy;
use crate::runtimes::{burrego::Runtime as BurregoRuntime, wapc::Runtime as WapcRuntime};
use crate::validation_response::ValidationResponse;

pub enum PolicyExecutionMode {
    KubewardenWapc,
    Opa,
    OpaGatekeeper,
}

lazy_static! {
    static ref WAPC_POLICY_MAPPING: RwLock<HashMap<u64, Policy>> =
        RwLock::new(HashMap::with_capacity(64));
}

#[derive(Serialize)]
pub struct ValidateRequest(pub(crate) serde_json::Value);

impl ValidateRequest {
    pub fn new(request: serde_json::Value) -> Self {
        ValidateRequest(request)
    }

    pub(crate) fn uid(&self) -> &str {
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

pub(crate) struct BurregoEvaluator {
    pub(crate) evaluator: burrego::opa::wasm::Evaluator,
    pub(crate) entrypoint_id: i32,
    pub(crate) input: serde_json::Value,
    pub(crate) data: serde_json::Value,
}

pub(crate) type PolicySettings = serde_json::Map<String, serde_json::Value>;

enum Runtime {
    Wapc(wapc::WapcHost),
    // The `BurregoEvaluator` variant is boxed since it outsizes the
    // other variants of this enum.
    Burrego(Box<BurregoEvaluator>),
}

pub struct PolicyEvaluator {
    runtime: Runtime,
    policy: Policy,
    settings: PolicySettings,
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
        match self.runtime {
            Runtime::Wapc(ref mut wapc_host) => {
                WapcRuntime(wapc_host).validate(&self.settings, &request)
            }
            Runtime::Burrego(ref mut burrego_evaluator) => {
                BurregoRuntime(burrego_evaluator).validate(&self.settings, &request)
            }
        }
    }

    #[tracing::instrument]
    pub fn validate_settings(&mut self) -> SettingsValidationResponse {
        let settings_str = match serde_json::to_string(&self.settings) {
            Ok(settings) => settings,
            Err(err) => {
                return SettingsValidationResponse {
                    valid: false,
                    message: Some(format!("could not marshal settings: {}", err)),
                }
            }
        };

        match self.runtime {
            Runtime::Wapc(ref mut wapc_host) => {
                WapcRuntime(wapc_host).validate_settings(settings_str)
            }
            Runtime::Burrego(ref mut burrego_evaluator) => {
                BurregoRuntime(burrego_evaluator).validate_settings(settings_str)
            }
        }
    }

    pub fn protocol_version(&mut self) -> Result<ProtocolVersion> {
        match &mut self.runtime {
            Runtime::Wapc(ref mut wapc_host) => WapcRuntime(wapc_host).protocol_version(),
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
}
