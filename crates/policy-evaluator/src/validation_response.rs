use anyhow::{anyhow, Result};
use kubewarden_policy_sdk::response::ValidationResponse as PolicyValidationResponse;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct ValidationResponse {
    pub uid: String,

    pub allowed: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub patch_type: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub patch: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<ValidationResponseStatus>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ValidationResponseStatus {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<u16>,
}

impl ValidationResponse {
    pub fn reject(uid: String, message: String, code: u16) -> ValidationResponse {
        ValidationResponse {
            uid,
            allowed: false,
            status: Some(ValidationResponseStatus {
                message: Some(message),
                code: Some(code),
            }),
            ..Default::default()
        }
    }

    pub fn reject_internal_server_error(uid: String, message: String) -> ValidationResponse {
        ValidationResponse::reject(
            uid,
            format!("internal server error: {}", message),
            hyper::StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
        )
    }

    pub fn from_policy_validation_response(
        uid: String,
        req_obj: &serde_json::Value,
        pol_val_resp: &PolicyValidationResponse,
    ) -> Result<ValidationResponse> {
        let patch = match pol_val_resp.mutated_object.clone() {
            Some(mut_obj) => {
                let diff = json_patch::diff(req_obj, &mut_obj);
                let empty_patch = json_patch::Patch(Vec::<json_patch::PatchOperation>::new());
                if diff == empty_patch {
                    None
                } else {
                    let diff_str = serde_json::to_string(&diff)
                        .map(base64::encode)
                        .map_err(|e| anyhow!("cannot serialize JSONPatch: {:?}", e))?;
                    Some(diff_str)
                }
            }
            None => None,
        };

        let patch_type: Option<String> = if patch.is_some() {
            Some(String::from("JSONPatch"))
        } else {
            None
        };

        let status = if pol_val_resp.message.is_some() || pol_val_resp.code.is_some() {
            Some(ValidationResponseStatus {
                message: pol_val_resp.message.clone(),
                code: pol_val_resp.code,
            })
        } else {
            None
        };

        Ok(ValidationResponse {
            uid,
            allowed: pol_val_resp.accepted,
            patch_type,
            patch,
            status,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn create_reject_response() {
        let uid = String::from("UID");
        let message = String::from("test message");
        let code: u16 = 500;

        let response = ValidationResponse::reject(uid.clone(), message.clone(), code);
        assert_eq!(response.uid, uid);
        assert_eq!(response.allowed, false);
        assert_eq!(response.patch, None);
        assert_eq!(response.patch_type, None);

        let status = response.status.unwrap();
        assert_eq!(status.code, Some(code));
        assert_eq!(status.message, Some(message));
    }

    #[test]
    fn create_from_policy_validation_response_and_mutated_object_is_none() {
        let uid = String::from("UID");
        let message = String::from("test message");
        let code: u16 = 500;

        let pol_val_resp = PolicyValidationResponse {
            accepted: false,
            message: Some(message.clone()),
            code: Some(code),
            mutated_object: None,
        };

        let req_obj = json!({"hello": "world"});

        let response = ValidationResponse::from_policy_validation_response(
            uid.clone(),
            &req_obj,
            &pol_val_resp,
        );
        assert!(response.is_ok());
        let response = response.unwrap();

        assert_eq!(response.uid, uid);
        assert_eq!(response.allowed, false);
        assert_eq!(response.patch, None);
        assert_eq!(response.patch_type, None);

        let status = response.status.unwrap();
        assert_eq!(status.code, Some(code));
        assert_eq!(status.message, Some(message));
    }

    #[test]
    fn create_from_policy_validation_response_and_mutated_object_is_not_different_from_original_one(
    ) {
        // The Mutated Object should be `Some` only when the policy performs an actual
        // mutation. However we have to play safe and ensure we can handle the case
        // where a policy has a bug and by mistake returns a `mutated_object` that is
        // equal to the original one

        let uid = String::from("UID");
        let req_obj = json!({"hello": "world"});

        let pol_val_resp = PolicyValidationResponse {
            accepted: true,
            message: None,
            code: None,
            mutated_object: Some(req_obj.clone()),
        };

        let response = ValidationResponse::from_policy_validation_response(
            uid.clone(),
            &req_obj,
            &pol_val_resp,
        );
        assert!(response.is_ok());
        let response = response.unwrap();

        assert_eq!(response.uid, uid);
        assert!(response.allowed);
        assert!(response.status.is_none());
        assert!(response.patch.is_none());
        assert!(response.patch_type.is_none());
    }

    #[test]
    fn create_from_policy_validation_response_with_mutation() {
        let uid = String::from("UID");
        let req_obj = json!({"hello": "world"});
        let mutated_obj = json!({
            "hello": "world",
            "ciao": "mondo",
        });
        let expected_diff = json_patch::diff(&req_obj, &mutated_obj);

        let pol_val_resp = PolicyValidationResponse {
            accepted: true,
            message: None,
            code: None,
            mutated_object: Some(mutated_obj),
        };

        let response = ValidationResponse::from_policy_validation_response(
            uid.clone(),
            &req_obj,
            &pol_val_resp,
        );
        assert!(response.is_ok());
        let response = response.unwrap();

        assert_eq!(response.uid, uid);
        assert!(response.allowed);
        assert!(response.status.is_none());
        assert_eq!(response.patch_type, Some(String::from("JSONPatch")));

        let patch_decoded_str = base64::decode(response.patch.unwrap()).unwrap();
        let patch: json_patch::Patch =
            serde_json::from_slice(patch_decoded_str.as_slice()).unwrap();
        assert_eq!(patch, expected_diff);
    }
}
