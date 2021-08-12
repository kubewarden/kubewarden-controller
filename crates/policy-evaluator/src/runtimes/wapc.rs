use anyhow::{anyhow, Result};
use serde_json::json;
use std::convert::TryFrom;
use tracing::error;

pub(crate) struct Runtime<'a>(pub(crate) &'a mut wapc::WapcHost);

use crate::policy_evaluator::{PolicySettings, ValidateRequest};
use crate::validation_response::ValidationResponse;

use kubewarden_policy_sdk::metadata::ProtocolVersion;
use kubewarden_policy_sdk::response::ValidationResponse as PolicyValidationResponse;
use kubewarden_policy_sdk::settings::SettingsValidationResponse;

impl<'a> Runtime<'a> {
    pub fn validate(
        &mut self,
        settings: &PolicySettings,
        request: &ValidateRequest,
    ) -> ValidationResponse {
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
            "settings": settings,
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

        match self.0.call("validate", validate_str.as_bytes()) {
            Ok(res) => {
                let pol_val_resp: Result<PolicyValidationResponse> = serde_json::from_slice(&res)
                    .map_err(|e| anyhow!("cannot deserialize policy validation response: {:?}", e));
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
        }
    }

    pub fn validate_settings(&mut self, settings: String) -> SettingsValidationResponse {
        match self.0.call("validate_settings", settings.as_bytes()) {
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

    pub fn protocol_version(&self) -> Result<ProtocolVersion> {
        match self.0.call("protocol_version", &[0; 0]) {
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
        }
    }
}
