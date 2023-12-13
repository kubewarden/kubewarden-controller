use kubewarden_policy_sdk::response::ValidationResponse as PolicyValidationResponse;
use kubewarden_policy_sdk::settings::SettingsValidationResponse;
use serde_json::json;
use tracing::{error, warn};

use crate::admission_response::AdmissionResponse;
use crate::policy_evaluator::{PolicySettings, ValidateRequest};
use crate::runtimes::wasi_cli::stack::{RunResult, Stack};

pub(crate) struct Runtime<'a>(pub(crate) &'a Stack);

impl<'a> Runtime<'a> {
    pub fn validate(
        &self,
        settings: &PolicySettings,
        request: &ValidateRequest,
    ) -> AdmissionResponse {
        let validate_params = json!({
            "request": request,
            "settings": settings,
        });

        let input = match serde_json::to_vec(&validate_params) {
            Ok(s) => s,
            Err(e) => {
                error!(
                    error = e.to_string().as_str(),
                    "cannot serialize validation params"
                );
                return AdmissionResponse::reject_internal_server_error(
                    request.uid().to_string(),
                    e.to_string(),
                );
            }
        };
        let args = ["policy.wasm", "validate"];

        match self.0.run(&input, &args) {
            Ok(RunResult { stdout, stderr }) => {
                if !stderr.is_empty() {
                    warn!(
                        request = request.uid().to_string(),
                        operation = "validate",
                        "stderr: {:?}",
                        stderr
                    )
                }
                match serde_json::from_slice::<PolicyValidationResponse>(stdout.as_bytes()) {
                    Ok(pvr) => {
                        let req_json_value = serde_json::to_value(request)
                            .expect("cannot convert request to json value");
                        let req_obj = match request {
                            ValidateRequest::Raw(_) => Some(&req_json_value),
                            ValidateRequest::AdmissionRequest(_) => req_json_value.get("object"),
                        };

                        AdmissionResponse::from_policy_validation_response(
                            request.uid().to_string(),
                            req_obj,
                            &pvr,
                        )
                    }
                    .unwrap_or_else(|e| {
                        AdmissionResponse::reject_internal_server_error(
                            request.uid().to_string(),
                            format!("Cannot convert policy validation response: {e}"),
                        )
                    }),
                    Err(e) => AdmissionResponse::reject_internal_server_error(
                        request.uid().to_string(),
                        format!("Cannot deserialize policy validation response: {e}"),
                    ),
                }
            }
            Err(e) => AdmissionResponse::reject_internal_server_error(
                request.uid().to_string(),
                e.to_string(),
            ),
        }
    }

    pub fn validate_settings(&self, settings: String) -> SettingsValidationResponse {
        let args = ["policy.wasm", "validate-settings"];

        match self.0.run(settings.as_bytes(), &args) {
            Ok(RunResult { stdout, stderr }) => {
                if !stderr.is_empty() {
                    warn!(operation = "validate-settings", "stderr: {:?}", stderr)
                }
                serde_json::from_slice::<SettingsValidationResponse>(stdout.as_bytes())
                    .unwrap_or_else(|e| SettingsValidationResponse {
                        valid: false,
                        message: Some(format!(
                            "Cannot deserialize settings validation response: {e}"
                        )),
                    })
            }
            Err(e) => SettingsValidationResponse {
                valid: false,
                message: Some(e.to_string()),
            },
        }
    }
}
