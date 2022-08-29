use anyhow::{anyhow, Result};
use serde::Serialize;
use serde_json::value;
use std::{
    convert::{TryFrom, TryInto},
    fmt,
};
use tokio::sync::mpsc;

use wapc::WapcHost;
use wasmtime_provider::wasmtime;
use wasmtime_provider::WasmtimeEngineProvider;

use kubewarden_policy_sdk::metadata::ProtocolVersion;
use kubewarden_policy_sdk::settings::SettingsValidationResponse;

use crate::admission_response::AdmissionResponse;
use crate::callback_requests::CallbackRequest;
use crate::policy::Policy;
use crate::runtimes::burrego::Runtime as BurregoRuntime;
use crate::runtimes::{
    wapc::host_callback as wapc_callback, wapc::Runtime as WapcRuntime, wapc::WAPC_POLICY_MAPPING,
};

#[derive(Copy, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize, Debug)]
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
        write!(f, "{}", json.replace('"', ""))
    }
}

#[derive(Debug, Serialize)]
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

pub(crate) enum RegoPolicyExecutionMode {
    Opa,
    Gatekeeper,
}

impl TryFrom<PolicyExecutionMode> for RegoPolicyExecutionMode {
    type Error = anyhow::Error;

    fn try_from(execution_mode: PolicyExecutionMode) -> Result<RegoPolicyExecutionMode> {
        match execution_mode {
            PolicyExecutionMode::Opa => Ok(RegoPolicyExecutionMode::Opa),
            PolicyExecutionMode::OpaGatekeeper => Ok(RegoPolicyExecutionMode::Gatekeeper),
            PolicyExecutionMode::KubewardenWapc => Err(anyhow!(
                "execution mode not convertible to a Rego based executon mode"
            )),
        }
    }
}

pub(crate) struct BurregoEvaluator {
    pub(crate) evaluator: burrego::opa::wasm::Evaluator,
    pub(crate) entrypoint_id: i32,
    pub(crate) policy_execution_mode: RegoPolicyExecutionMode,
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
    pub policy: Policy,
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
    /// This method should not be used directly. Please use
    /// `PolicyEvaluatorBuilder` instead.
    pub(crate) fn new(
        id: String,
        policy_contents: Vec<u8>,
        policy_execution_mode: PolicyExecutionMode,
        settings: Option<serde_json::Map<String, serde_json::Value>>,
        callback_channel: Option<mpsc::Sender<CallbackRequest>>,
        enable_wasmtime_cache: bool,
    ) -> Result<PolicyEvaluator> {
        let (policy, runtime) = match policy_execution_mode {
            PolicyExecutionMode::KubewardenWapc => {
                let mut wasmtime_config = wasmtime::Config::new();
                if enable_wasmtime_cache {
                    wasmtime_config.cache_config_load_default()?;
                }

                let wasmtime_engine = wasmtime::Engine::new(&wasmtime_config)?;

                let engine = WasmtimeEngineProvider::new_with_engine(
                    &policy_contents,
                    wasmtime_engine,
                    None,
                )?;
                let wapc_host = WapcHost::new(Box::new(engine), Some(Box::new(wapc_callback)))?;
                let policy = PolicyEvaluator::from_contents_internal(
                    id,
                    callback_channel,
                    || Some(wapc_host.id()),
                    Policy::new,
                    policy_execution_mode,
                )?;

                let policy_runtime = Runtime::Wapc(wapc_host);
                (policy, policy_runtime)
            }
            PolicyExecutionMode::Opa | PolicyExecutionMode::OpaGatekeeper => {
                let policy = PolicyEvaluator::from_contents_internal(
                    id.clone(),
                    callback_channel,
                    || None,
                    Policy::new,
                    policy_execution_mode,
                )?;
                let evaluator = burrego::opa::wasm::Evaluator::new(
                    id,
                    &policy_contents,
                    &crate::runtimes::burrego::DEFAULT_HOST_CALLBACKS,
                )?;
                let policy_runtime = Runtime::Burrego(Box::new(BurregoEvaluator {
                    evaluator,
                    entrypoint_id: 0, // This is fixed for now to the first entry point
                    policy_execution_mode: policy_execution_mode.try_into()?,
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
        callback_channel: Option<mpsc::Sender<CallbackRequest>>,
        engine_initializer: E,
        policy_initializer: P,
        policy_execution_mode: PolicyExecutionMode,
    ) -> Result<Policy>
    where
        E: Fn() -> Option<u64>,
        P: Fn(String, Option<u64>, Option<mpsc::Sender<CallbackRequest>>) -> Result<Policy>,
    {
        let policy_id = engine_initializer();
        let policy = policy_initializer(id, policy_id, callback_channel)?;
        if policy_execution_mode == PolicyExecutionMode::KubewardenWapc {
            WAPC_POLICY_MAPPING.write().unwrap().insert(
                policy_id.ok_or_else(|| anyhow!("invalid policy id"))?,
                policy.clone(),
            );
        }
        Ok(policy)
    }

    #[tracing::instrument(skip(request))]
    pub fn validate(&mut self, request: ValidateRequest) -> AdmissionResponse {
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

    use serde_json::json;
    use std::collections::HashMap;

    #[test]
    fn policy_is_registered_in_the_mapping() -> Result<()> {
        let policy_name = "policy_is_registered_in_the_mapping";

        // We cannot set policy.id at build time, because some attributes
        // of Policy are private.
        let mut policy = Policy::default();
        policy.id = policy_name.to_string();

        let policy_id = 1;

        PolicyEvaluator::from_contents_internal(
            "mock_policy".to_string(),
            None,
            || Some(policy_id),
            |_, _, _| Ok(policy.clone()),
            PolicyExecutionMode::KubewardenWapc,
        )?;

        let policy_mapping = WAPC_POLICY_MAPPING.read().unwrap();
        let found = policy_mapping
            .iter()
            .find(|(_id, policy)| policy.id == policy_name);

        assert!(found.is_some());

        Ok(())
    }

    #[test]
    fn policy_is_not_registered_in_the_mapping_if_not_wapc() -> Result<()> {
        let policy_name = "policy_is_not_registered_in_the_mapping_if_not_wapc";

        // We cannot set policy.id at build time, because some attributes
        // of Policy are private.
        let mut policy = Policy::default();
        policy.id = policy_name.to_string();

        let policy_id = 1;

        PolicyEvaluator::from_contents_internal(
            policy_name.to_string(),
            None,
            || Some(policy_id),
            |_, _, _| Ok(policy.clone()),
            PolicyExecutionMode::OpaGatekeeper,
        )?;

        let policy_mapping = WAPC_POLICY_MAPPING.read().unwrap();
        let found = policy_mapping
            .iter()
            .find(|(_id, policy)| policy.id == policy_name);

        assert!(found.is_none());
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
