use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use kubewarden_policy_sdk::response::ValidationResponse as PolicyValidationResponse;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// This models the admission/v1/AdmissionResponse object of Kubernetes
#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Eq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionResponse {
    /// UID is an identifier for the individual request/response.
    /// This must be copied over from the corresponding AdmissionRequest.
    pub uid: String,

    /// Allowed indicates whether or not the admission request was permitted.
    pub allowed: bool,

    /// The type of Patch. Currently we only allow "JSONPatch".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patch_type: Option<String>,

    /// The patch body. Currently we only support "JSONPatch" which implements RFC 6902.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patch: Option<String>,

    /// Status contains extra details into why an admission request was denied.
    /// This field IS NOT consulted in any way if "Allowed" is "true".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<AdmissionResponseStatus>,

    /// AuditAnnotations is an unstructured key value map set by remote admission controller (e.g. error=image-blacklisted).
    /// MutatingAdmissionWebhook and ValidatingAdmissionWebhook admission controller will prefix the keys with
    /// admission webhook name (e.g. imagepolicy.example.com/error=image-blacklisted). AuditAnnotations will be provided by
    /// the admission webhook to add additional context to the audit log for this request.
    pub audit_annotations: Option<HashMap<String, String>>,

    /// warnings is a list of warning messages to return to the requesting API client.
    /// Warning messages describe a problem the client making the API request should correct or be aware of.
    /// Limit warnings to 120 characters if possible.
    /// Warnings over 256 characters and large numbers of warnings may be truncated.
    pub warnings: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Eq, Clone)]
pub struct AdmissionResponseStatus {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<u16>,
}

impl AdmissionResponse {
    pub fn reject(uid: String, message: String, code: u16) -> AdmissionResponse {
        AdmissionResponse {
            uid,
            allowed: false,
            status: Some(AdmissionResponseStatus {
                message: Some(message),
                code: Some(code),
            }),
            ..Default::default()
        }
    }

    pub fn reject_internal_server_error(uid: String, message: String) -> AdmissionResponse {
        AdmissionResponse::reject(uid, format!("internal server error: {message}"), 500)
    }

    pub fn from_policy_validation_response(
        uid: String,
        req_obj: Option<&serde_json::Value>,
        pol_val_resp: &PolicyValidationResponse,
    ) -> Result<AdmissionResponse> {
        if pol_val_resp.mutated_object.is_some() && req_obj.is_none() {
            let message = "Incoming object is null, which happens only with DELETE operations, but the policy is attempting a mutation. This is not allowed";

            return Ok(AdmissionResponse {
                uid,
                allowed: false,
                warnings: None,
                audit_annotations: None,
                patch_type: None,
                patch: None,
                status: Some(AdmissionResponseStatus {
                    message: Some(message.to_string()),
                    code: None,
                }),
            });
        }

        let patch = match pol_val_resp.mutated_object.clone() {
            Some(mut_obj) => {
                let diff = json_patch::diff(req_obj.unwrap(), &mut_obj);
                let empty_patch = json_patch::Patch(Vec::<json_patch::PatchOperation>::new());
                if diff == empty_patch {
                    None
                } else {
                    let diff_str = serde_json::to_string(&diff)
                        .map(|s| general_purpose::STANDARD.encode(s))
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
            Some(AdmissionResponseStatus {
                message: pol_val_resp.message.clone(),
                code: pol_val_resp.code,
            })
        } else {
            None
        };

        Ok(AdmissionResponse {
            uid,
            allowed: pol_val_resp.accepted,
            warnings: pol_val_resp.warnings.clone(),
            audit_annotations: pol_val_resp.audit_annotations.clone(),
            patch_type,
            patch,
            status,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use serde_json::json;

    #[test]
    fn create_reject_response() {
        let uid = String::from("UID");
        let message = String::from("test message");
        let code: u16 = 500;

        let response = AdmissionResponse::reject(uid.clone(), message.clone(), code);
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

        let mut audit_annotations: HashMap<String, String> = HashMap::new();
        audit_annotations.insert(String::from("key"), String::from("value"));

        let warnings = vec![String::from("hello"), String::from("world")];

        let pol_val_resp = PolicyValidationResponse {
            accepted: false,
            message: Some(message.clone()),
            code: Some(code),
            mutated_object: None,
            audit_annotations: Some(audit_annotations.clone()),
            warnings: Some(warnings.clone()),
        };

        let req_obj = Some(json!({"hello": "world"}));

        let response = AdmissionResponse::from_policy_validation_response(
            uid.clone(),
            req_obj.as_ref(),
            &pol_val_resp,
        );
        assert!(response.is_ok());
        let response = response.unwrap();

        assert_eq!(response.uid, uid);
        assert_eq!(response.allowed, false);
        assert_eq!(response.patch, None);
        assert_eq!(response.patch_type, None);
        assert_eq!(response.audit_annotations, Some(audit_annotations));
        assert_eq!(response.warnings, Some(warnings));

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
        let req_obj = Some(json!({"hello": "world"}));

        let pol_val_resp = PolicyValidationResponse {
            accepted: true,
            message: None,
            code: None,
            mutated_object: req_obj.clone(),
            warnings: None,
            audit_annotations: None,
        };

        let response = AdmissionResponse::from_policy_validation_response(
            uid.clone(),
            req_obj.as_ref(),
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
    fn mutation_on_delete_operation_is_not_allowed() {
        let uid = String::from("UID");
        // DELETE operation have a null 'object'
        let req_obj = None;

        let pol_val_resp = PolicyValidationResponse {
            accepted: true,
            message: None,
            code: None,
            mutated_object: Some(json!({"hello": "world"})),
            warnings: None,
            audit_annotations: None,
        };

        let response =
            AdmissionResponse::from_policy_validation_response(uid.clone(), req_obj, &pol_val_resp);
        assert!(response.is_ok());
        let response = response.unwrap();

        assert_eq!(response.uid, uid);
        assert!(!response.allowed);
        assert!(response.status.is_some());
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
            audit_annotations: None,
            warnings: None,
        };

        let response = AdmissionResponse::from_policy_validation_response(
            uid.clone(),
            Some(&req_obj),
            &pol_val_resp,
        );
        assert!(response.is_ok());
        let response = response.unwrap();

        assert_eq!(response.uid, uid);
        assert!(response.allowed);
        assert!(response.status.is_none());
        assert_eq!(response.patch_type, Some(String::from("JSONPatch")));

        let patch_decoded_str = general_purpose::STANDARD
            .decode(response.patch.unwrap())
            .unwrap();
        let patch: json_patch::Patch =
            serde_json::from_slice(patch_decoded_str.as_slice()).unwrap();
        assert_eq!(patch, expected_diff);
    }
}
