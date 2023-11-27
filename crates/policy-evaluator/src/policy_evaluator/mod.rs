pub mod policy_evaluator_builder;

use anyhow::{anyhow, Result};
use kubewarden_policy_sdk::metadata::ProtocolVersion;
use kubewarden_policy_sdk::settings::SettingsValidationResponse;
use serde::Serialize;
use serde_json::value;
use std::{convert::TryFrom, fmt};

use crate::admission_request::AdmissionRequest;
use crate::admission_response::AdmissionResponse;
use crate::evaluation_context::EvaluationContext;
use crate::runtimes::rego::Runtime as BurregoRuntime;
use crate::runtimes::wapc::Runtime as WapcRuntime;
use crate::runtimes::wasi_cli::Runtime as WasiRuntime;
use crate::runtimes::Runtime;

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

pub struct PolicyEvaluator {
    runtime: Runtime,
    worker_id: u64,
    policy_id: String,
}

impl PolicyEvaluator {
    pub(crate) fn new(policy_id: &str, worker_id: u64, runtime: Runtime) -> Self {
        Self {
            runtime,
            worker_id,
            policy_id: policy_id.to_owned(),
        }
    }

    pub fn policy_id(&self) -> String {
        self.policy_id.clone()
    }

    #[tracing::instrument(skip(request, eval_ctx))]
    pub fn validate(
        &mut self,
        request: ValidateRequest,
        settings: &PolicySettings,
        eval_ctx: &EvaluationContext,
    ) -> AdmissionResponse {
        match self.runtime {
            Runtime::Wapc(ref mut wapc_stack) => {
                wapc_stack.set_eval_ctx(eval_ctx);
                WapcRuntime(wapc_stack).validate(settings, &request)
            }
            Runtime::Burrego(ref mut burrego_evaluator) => {
                let kube_ctx = burrego_evaluator.build_kubernetes_context(
                    eval_ctx.callback_channel.as_ref(),
                    &eval_ctx.ctx_aware_resources_allow_list,
                );
                match kube_ctx {
                    Ok(ctx) => BurregoRuntime(burrego_evaluator).validate(settings, &request, &ctx),
                    Err(e) => {
                        AdmissionResponse::reject(request.uid().to_string(), e.to_string(), 500)
                    }
                }
            }
            Runtime::Cli(ref mut cli_stack) => WasiRuntime(cli_stack).validate(settings, &request),
        }
    }

    #[tracing::instrument(skip(eval_ctx))]
    pub fn validate_settings(
        &mut self,
        settings: &PolicySettings,
        eval_ctx: &EvaluationContext,
    ) -> SettingsValidationResponse {
        let settings_str = match serde_json::to_string(settings) {
            Ok(settings) => settings,
            Err(err) => {
                return SettingsValidationResponse {
                    valid: false,
                    message: Some(format!("could not marshal settings: {err}")),
                }
            }
        };

        match self.runtime {
            Runtime::Wapc(ref mut wapc_stack) => {
                wapc_stack.set_eval_ctx(eval_ctx);
                WapcRuntime(wapc_stack).validate_settings(settings_str)
            }
            Runtime::Burrego(ref mut burrego_evaluator) => {
                BurregoRuntime(burrego_evaluator).validate_settings(settings_str)
            }
            Runtime::Cli(ref mut cli_stack) => {
                WasiRuntime(cli_stack).validate_settings(settings_str)
            }
        }
    }

    pub fn protocol_version(&mut self) -> Result<ProtocolVersion> {
        match &mut self.runtime {
            Runtime::Wapc(ref mut wapc_stack) => WapcRuntime(wapc_stack).protocol_version(),
            _ => Err(anyhow!(
                "protocol_version is only applicable to a Kubewarden policy"
            )),
        }
    }
}

impl fmt::Debug for PolicyEvaluator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let runtime = self.runtime.to_string();

        f.debug_struct("PolicyEvaluator")
            .field("policy_id", &self.policy_id)
            .field("worker_id", &self.worker_id)
            .field("runtime", &runtime)
            .finish()
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
                serde_json::from_str(mode_str);
            assert_eq!(expected, &actual.unwrap());
        }

        // an unknown policy mode should not be deserializable
        let actual: std::result::Result<PolicyExecutionMode, serde_json::Error> =
            serde_json::from_str("hello world");
        assert!(actual.is_err());
    }
}
