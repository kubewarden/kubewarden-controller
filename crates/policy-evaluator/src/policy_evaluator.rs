use anyhow::{anyhow, Result};
use burrego::opa::host_callbacks as opa_callbacks;
use serde::Serialize;
use serde_json::{json, value};
use std::{fmt, fs, path::Path};

use wapc::WapcHost;
use wasmtime_provider::WasmtimeEngineProvider;

use kubewarden_policy_sdk::metadata::ProtocolVersion;
use kubewarden_policy_sdk::settings::SettingsValidationResponse;

use crate::policy::Policy;
use crate::runtimes::burrego::Runtime as BurregoRuntime;
use crate::runtimes::{
    wapc::host_callback as wapc_callback, wapc::Runtime as WapcRuntime, wapc::WAPC_POLICY_MAPPING,
};
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

impl Default for PolicyExecutionMode {
    fn default() -> Self {
        PolicyExecutionMode::KubewardenWapc
    }
}

impl fmt::Display for PolicyExecutionMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let json = serde_json::to_string(self).map_err(|_| fmt::Error {})?;
        write!(f, "{}", json.replace("\"", ""))
    }
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
                let wapc_host = WapcHost::new(Box::new(engine), wapc_callback)?;
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
                let evaluator = burrego::opa::wasm::Evaluator::new(
                    id,
                    &policy_contents,
                    &opa_callbacks::DEFAULT_HOST_CALLBACKS,
                )?;
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

    use std::collections::HashMap;

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
