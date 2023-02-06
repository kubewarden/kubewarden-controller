use anyhow::{anyhow, Result};
use kubewarden_policy_sdk::metadata::ProtocolVersion;
use kubewarden_policy_sdk::settings::SettingsValidationResponse;
use serde::Serialize;
use serde_json::value;
use std::{convert::TryFrom, fmt};

use crate::admission_response::AdmissionResponse;
use crate::policy::Policy;
use crate::runtimes::burrego::Runtime as BurregoRuntime;
use crate::runtimes::wapc::Runtime as WapcRuntime;
use crate::runtimes::Runtime;

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

#[derive(Clone)]
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

pub(crate) type PolicySettings = serde_json::Map<String, serde_json::Value>;

pub trait Evaluator {
    fn validate(&mut self, request: ValidateRequest) -> AdmissionResponse;
    fn validate_settings(&mut self) -> SettingsValidationResponse;
    fn protocol_version(&mut self) -> Result<ProtocolVersion>;
    fn policy_id(&self) -> String;
}

pub struct PolicyEvaluator {
    pub(crate) runtime: Runtime,
    pub(crate) settings: PolicySettings,
    pub policy: Policy,
}

impl fmt::Debug for PolicyEvaluator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PolicyEvaluator")
            .field("id", &self.policy.id)
            .field("settings", &self.settings)
            .finish()
    }
}

impl Evaluator for PolicyEvaluator {
    fn policy_id(&self) -> String {
        self.policy.id.clone()
    }

    #[tracing::instrument(skip(request))]
    fn validate(&mut self, request: ValidateRequest) -> AdmissionResponse {
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
    fn validate_settings(&mut self) -> SettingsValidationResponse {
        let settings_str = match serde_json::to_string(&self.settings) {
            Ok(settings) => settings,
            Err(err) => {
                return SettingsValidationResponse {
                    valid: false,
                    message: Some(format!("could not marshal settings: {err}")),
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

    fn protocol_version(&mut self) -> Result<ProtocolVersion> {
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
