use crate::errors::ResponseError;

use base64::{engine::general_purpose, Engine as _};
use kubewarden_policy_sdk::response::ValidationResponse as PolicyValidationResponse;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, result::Result};

/// This models the admission/v1/AdmissionResponse object of Kubernetes
/// See https://pkg.go.dev/k8s.io/kubernetes/pkg/apis/admission#AdmissionResponse
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
    pub patch_type: Option<PatchType>,

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

/// PatchType is the type of patch being used to represent the mutated object
#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Eq, Clone)]
pub enum PatchType {
    #[serde(rename = "JSONPatch")]
    #[default]
    JSONPatch,
}

/// Values that Status.Status of an AdmissionResponse can have
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum AdmissionResponseStatusValue {
    Success,
    Failure,
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Eq, Clone)]
pub struct AdmissionResponseStatus {
    /// Status of the operation.
    /// One of: "Success" or "Failure".
    /// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<AdmissionResponseStatusValue>,

    /// A human-readable description of the status of this operation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// A machine-readable description of why this operation is in the
    /// "Failure" status. If this value is empty there
    /// is no information available. A Reason clarifies an HTTP status
    /// code but does not override it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<StatusReason>,

    /// Extended data associated with the reason.  Each reason may define its
    /// own extended details. This field is optional and the data returned
    /// is not guaranteed to conform to any schema except that defined by
    /// the reason type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<StatusDetails>,

    /// Suggested HTTP return code for this status
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
                ..Default::default()
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
    ) -> Result<AdmissionResponse, ResponseError> {
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
                    ..Default::default()
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
                        .map_err(ResponseError::Deserialize)?;
                    Some(diff_str)
                }
            }
            None => None,
        };

        let patch_type: Option<PatchType> = if patch.is_some() {
            Some(PatchType::JSONPatch)
        } else {
            None
        };

        let status = if pol_val_resp.message.is_some() || pol_val_resp.code.is_some() {
            Some(AdmissionResponseStatus {
                message: pol_val_resp.message.clone(),
                code: pol_val_resp.code,
                ..Default::default()
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

/// StatusReason is an enumeration of possible failure causes.
/// Each StatusReason must map to a single HTTP status code, but multiple reasons may map to the same
/// HTTP status code.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum StatusReason {
    /// StatusReasonUnknown means the server has declined to indicate a specific reason.
    /// The details field may contain other information about this error.
    /// Status code 500.
    #[serde(rename = "")]
    Unknown,

    /// StatusReasonUnauthorized means the server can be reached and understood the request,
    /// but requires the user to present appropriate authorization credentials (identified by
    /// the WWW-Authenticate header) in order for the action to be completed.
    /// Status code 401.
    Unauthorized,

    /// StatusReasonForbidden means the server can be reached and understood the request, but
    /// refuses to take any further action. This is the result of the server being configured to
    /// deny access for some reason to the requested resource by the client.
    /// Status code 403.
    Forbidden,

    /// StatusReasonNotFound means one or more resources required for this operation could not
    /// be found.
    /// Status code 404.
    NotFound,

    /// StatusReasonAlreadyExists means the resource you are creating already exists.
    /// Status code 409.
    AlreadyExists,

    /// StatusReasonConflict means the requested operation cannot be completed due to a conflict
    /// in the operation. The client may need to alter the request.
    /// Status code 409.
    Conflict,

    /// StatusReasonGone means the item is no longer available at the server and no forwarding
    /// address is known.
    /// Status code 410.
    Gone,

    /// StatusReasonInvalid means the requested create or update operation cannot be completed
    /// due to invalid data provided as part of the request. The client may need to alter the request.
    /// Status code 422.
    Invalid,

    /// StatusReasonServerTimeout means the server can be reached and understood the request,
    /// but cannot complete the action in a reasonable time. The client should retry the request.
    /// Status code 500.
    ServerTimeout,

    /// StatusReasonTimeout means that the request could not be completed within the given time.
    /// Clients can get this response only when they specified a timeout param in the request.
    /// Status code 504.
    Timeout,

    /// StatusReasonTooManyRequests means the server experienced too many requests within a
    /// given window and that the client must wait to perform the action again.
    /// Status code 429.
    TooManyRequests,

    /// StatusReasonBadRequest means that the request itself was invalid.
    /// Status code 400.
    BadRequest,

    /// StatusReasonMethodNotAllowed means that the action the client attempted to perform on
    /// the resource was not supported by the code.
    /// Status code 405.
    MethodNotAllowed,

    /// StatusReasonNotAcceptable means that the accept types indicated by the client were not
    /// acceptable to the server.
    /// Status code 406.
    NotAcceptable,

    /// StatusReasonRequestEntityTooLarge means that the request entity is too large.
    /// Status code 413.
    RequestEntityTooLarge,

    /// StatusReasonUnsupportedMediaType means that the content type sent by the client is not
    /// acceptable to the server.
    /// Status code 415.
    UnsupportedMediaType,

    /// StatusReasonInternalError indicates that an internal error occurred.
    /// Status code 500.
    InternalError,

    /// StatusReasonExpired indicates that the request is invalid because the content has expired
    /// and is no longer available.
    /// Status code 410.
    Expired,

    /// StatusReasonServiceUnavailable means that the requested service is unavailable at this time.
    /// Retrying the request after some time might succeed.
    /// Status code 503.
    ServiceUnavailable,
}

/// StatusDetails is a set of additional properties that MAY be set by the server to provide
/// additional information about a response.
/// The Reason field of a Status object defines what attributes will be set.
/// Clients must ignore fields that do not match the defined type of each attribute,
/// and should assume that any attribute may be empty, invalid, or under defined.
#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Eq, Clone)]
pub struct StatusDetails {
    /// The name attribute of the resource associated with the status StatusReason
    /// (when there is a single name which can be described).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// The group attribute of the resource associated with the status StatusReason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,

    /// The kind attribute of the resource associated with the status StatusReason.
    /// On some operations may differ from the requested resource Kind.
    /// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,

    /// UID of the resource.
    /// (when there is a single resource which can be described).
    /// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names#uids
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,

    /// The Causes array includes more details associated with the StatusReason
    /// failure. Not all StatusReasons may provide detailed causes.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub causes: Vec<StatusCause>,

    /// If specified, the time in seconds before the operation should be retried. Some errors may indicate
    /// the client must take an alternate action - for those errors this field may indicate how long to wait
    /// before taking the alternate action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_seconds: Option<i32>,
}

///StatusCause provides more information about an api.Status failure, including cases when multiple errors are encountered.
#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Eq, Clone)]
pub struct StatusCause {
    // A machine-readable description of the cause of the error. If this value is
    // empty there is no information available.
    pub reason: Option<CauseType>,

    // A human-readable description of the cause of the error.  This field may be
    // presented as-is to a reader.
    pub message: Option<String>,

    // The field of the resource that has caused this error, as named by its JSON
    // serialization. May include dot and postfix notation for nested attributes.
    // Arrays are zero-indexed.  Fields may appear more than once in an array of
    // causes due to fields having multiple errors.
    //
    // Examples:
    //   "name" - the field "name" on the current resource
    //   "items[0].name" - the field "name" on the first array entry in "items"
    pub field: Option<String>,
}

/// CauseType is a machine readable value providing more detail about what occurred in a
/// status response.
/// An operation may have multiple causes for a status (whether Failure or Success).
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum CauseType {
    /// CauseTypeFieldValueNotFound is used to report failure to find a requested value
    /// (e.g., looking up an ID).
    FieldValueNotFound,

    /// CauseTypeFieldValueRequired is used to report required values that are not
    /// provided (e.g., empty strings, null values, or empty arrays).
    FieldValueRequired,

    /// CauseTypeFieldValueDuplicate is used to report collisions of values that must be
    /// unique (e.g., unique IDs).
    FieldValueDuplicate,

    /// CauseTypeFieldValueInvalid is used to report malformed values (e.g., failed regex
    /// match).
    FieldValueInvalid,

    /// CauseTypeFieldValueNotSupported is used to report valid (as per formatting rules)
    /// values that cannot be handled (e.g., an enumerated string).
    FieldValueNotSupported,

    /// CauseTypeForbidden is used to report valid (as per formatting rules)
    /// values which would be accepted under some conditions, but which are not
    /// permitted by the current conditions (such as security policy).
    FieldValueForbidden,

    /// CauseTypeTooLong is used to report that the given value is too long.
    /// This is similar to ErrorTypeInvalid, but the error will not include the
    /// too-long value.
    FieldValueTooLong,

    /// CauseTypeTooMany is used to report that a given list has too many items.
    /// This is similar to FieldValueTooLong, but the error indicates quantity instead of length.
    FieldValueTooMany,

    /// CauseTypeInternal is used to report other errors that are not related
    /// to user input.
    InternalError,

    /// CauseTypeTypeInvalid is for when the value did not match the schema type for that field.
    FieldValueTypeInvalid,

    /// CauseTypeUnexpectedServerResponse is used to report when the server responded to the client
    /// without the expected return type. The presence of this cause indicates the error may be
    /// due to an intervening proxy or the server software malfunctioning.
    UnexpectedServerResponse,

    /// CauseTypeFieldManagerConflict is used to report when another client claims to manage this field.
    /// It should only be returned for a request using server-side apply.
    FieldManagerConflict,

    /// CauseTypeResourceVersionTooLarge is used to report that the requested resource version
    /// is newer than the data observed by the API server, so the request cannot be served.
    ResourceVersionTooLarge,
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
        assert!(!response.allowed);
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
        assert!(!response.allowed);
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
        assert_eq!(response.patch_type, Some(PatchType::JSONPatch));

        let patch_decoded_str = general_purpose::STANDARD
            .decode(response.patch.unwrap())
            .unwrap();
        let patch: json_patch::Patch =
            serde_json::from_slice(patch_decoded_str.as_slice()).unwrap();
        assert_eq!(patch, expected_diff);
    }
}
