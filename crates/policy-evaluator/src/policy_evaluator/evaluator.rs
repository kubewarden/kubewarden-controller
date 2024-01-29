use anyhow::{anyhow, Result};
use kubewarden_policy_sdk::metadata::ProtocolVersion;
use kubewarden_policy_sdk::settings::SettingsValidationResponse;
use std::fmt;

use crate::admission_response::AdmissionResponse;
use crate::evaluation_context::EvaluationContext;
use crate::policy_evaluator::{PolicySettings, ValidateRequest};
use crate::runtimes::rego::Runtime as BurregoRuntime;
use crate::runtimes::wapc::Runtime as WapcRuntime;
use crate::runtimes::wasi_cli::Runtime as WasiRuntime;
use crate::runtimes::Runtime;

pub struct PolicyEvaluator {
    runtime: Runtime,
    eval_ctx: EvaluationContext,
}

impl PolicyEvaluator {
    pub(crate) fn new(runtime: Runtime, eval_ctx: &EvaluationContext) -> Self {
        Self {
            runtime,
            eval_ctx: eval_ctx.to_owned(),
        }
    }

    #[tracing::instrument(skip(request))]
    pub fn validate(
        &mut self,
        request: ValidateRequest,
        settings: &PolicySettings,
    ) -> AdmissionResponse {
        match self.runtime {
            Runtime::Wapc(ref mut wapc_stack) => {
                WapcRuntime(wapc_stack).validate(settings, &request)
            }
            Runtime::Rego(ref mut burrego_evaluator) => {
                let kube_ctx = burrego_evaluator.build_kubernetes_context(
                    self.eval_ctx.callback_channel.as_ref(),
                    &self.eval_ctx.ctx_aware_resources_allow_list,
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

    #[tracing::instrument]
    pub fn validate_settings(&mut self, settings: &PolicySettings) -> SettingsValidationResponse {
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
                WapcRuntime(wapc_stack).validate_settings(settings_str)
            }
            Runtime::Rego(ref mut burrego_evaluator) => {
                BurregoRuntime(burrego_evaluator).validate_settings(settings_str)
            }
            Runtime::Cli(ref mut cli_stack) => {
                WasiRuntime(cli_stack).validate_settings(settings_str)
            }
        }
    }

    pub fn protocol_version(&mut self) -> Result<ProtocolVersion> {
        match &mut self.runtime {
            Runtime::Wapc(ref mut wapc_stack) => Ok(WapcRuntime(wapc_stack).protocol_version()?),
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
            .field("runtime", &runtime)
            .finish()
    }
}
