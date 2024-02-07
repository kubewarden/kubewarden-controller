pub mod errors;
mod evaluator;
pub mod policy_evaluator_builder;
mod policy_evaluator_pre;
mod stack_pre;

pub use evaluator::PolicyEvaluator;
pub use policy_evaluator_pre::PolicyEvaluatorPre;

use anyhow::{anyhow, Result};
use serde::Serialize;
use serde_json::value;
use std::{convert::TryFrom, fmt};

use crate::admission_request::AdmissionRequest;

#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub enum PolicyExecutionMode {
    #[serde(rename = "kubewarden-wapc")]
    #[default]
    KubewardenWapc,
    #[serde(rename = "opa")]
    Opa,
    #[serde(rename = "gatekeeper")]
    OpaGatekeeper,
    #[serde(rename = "wasi")]
    Wasi,
}

impl fmt::Display for PolicyExecutionMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let json = serde_json::to_string(self).map_err(|_| fmt::Error {})?;
        write!(f, "{}", json.replace('"', ""))
    }
}

/// A validation request that can be sent to a policy evaluator.
/// It can be either a raw JSON object, or a Kubernetes AdmissionRequest.
#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum ValidateRequest {
    Raw(serde_json::Value),
    AdmissionRequest(AdmissionRequest),
}

impl ValidateRequest {
    pub fn uid(&self) -> &str {
        match self {
            ValidateRequest::Raw(raw_req) => raw_req
                .get("uid")
                .and_then(value::Value::as_str)
                .unwrap_or_default(),
            ValidateRequest::AdmissionRequest(adm_req) => &adm_req.uid,
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
            PolicyExecutionMode::KubewardenWapc | PolicyExecutionMode::Wasi => Err(anyhow!(
                "execution mode not convertible to a Rego based executon mode"
            )),
        }
    }
}

/// Settings specified by the user for a given policy.
pub type PolicySettings = serde_json::Map<String, serde_json::Value>;

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
                serde_json::from_str(mode_str);
            assert_eq!(expected, &actual.unwrap());
        }

        // an unknown policy mode should not be deserializable
        let actual: std::result::Result<PolicyExecutionMode, serde_json::Error> =
            serde_json::from_str("hello world");
        assert!(actual.is_err());
    }
}
