use crate::admission_response::{
    AdmissionResponse, AdmissionResponseStatus, StatusCause, StatusDetails,
};
use tracing::info;

pub mod errors;
pub mod policy_id;
pub mod policy_mode;

use crate::admission_response_handler::{policy_id::PolicyID, policy_mode::PolicyMode};

/// Apply as series of mutation constrains to the admission response.
///
/// Current constraints are:
/// - A policy might have tried to mutate while the policy-server
///   configuration does not allow it to mutate
/// - A policy might be running in "Monitor" mode, that always
///   accepts the request (without mutation), logging the answer
/// - A policy might have a custom rejection message that should be used instead of the error
///   returned by the policy. The original error is added in the warnings list.
pub struct AdmissionResponseHandler<'a> {
    policy_id: &'a PolicyID,
    policy_mode: &'a PolicyMode,
    allowed_to_mutate: bool,
    custom_rejection_message: Option<String>,
}

impl<'a> AdmissionResponseHandler<'a> {
    pub fn new(
        policy_id: &'a PolicyID,
        policy_mode: &'a PolicyMode,
        allowed_to_mutate: bool,
        custom_rejection_message: Option<String>,
    ) -> Self {
        AdmissionResponseHandler {
            policy_id,
            policy_mode,
            allowed_to_mutate,
            custom_rejection_message,
        }
    }

    pub fn process_response(&'a self, admission_response: AdmissionResponse) -> AdmissionResponse {
        let admission_response = self.apply_monitor_mode(admission_response);
        let admission_response = self.apply_mutation_constraint(admission_response);

        // Note: apply the custom rejection message as a last step, so that it can override
        // any previous status message.
        self.apply_custom_rejection_message(admission_response)
    }

    // In monitor mode we always accept the request, but log what would have been the decision of the
    // policy. We also force mutating patches to be none. Status is also overridden, as it's only taken into
    // account when a request is rejected.
    fn apply_monitor_mode(&'a self, admission_response: AdmissionResponse) -> AdmissionResponse {
        if self.policy_mode != &PolicyMode::Monitor {
            return admission_response;
        }

        info!(
            policy_id = self.policy_id.to_string(),
            allowed_to_mutate = self.allowed_to_mutate,
            response = format!("{admission_response:?}").as_str(),
            "policy evaluation (monitor mode)",
        );
        AdmissionResponse {
            allowed: true,
            patch_type: None,
            patch: None,
            status: None,
            ..admission_response
        }
    }

    /// This check is applied only when the policy is in `Protect` mode.
    /// If the policy attempted to mutate the request, but it is currently configured to not allow mutations,
    /// the request is rejected.
    fn apply_mutation_constraint(
        &'a self,
        admission_response: AdmissionResponse,
    ) -> AdmissionResponse {
        if self.policy_mode != &PolicyMode::Protect {
            return admission_response;
        }

        if self.allowed_to_mutate {
            // If the policy is allowed to mutate, we don't need to do anything
            return admission_response;
        }

        if admission_response.patch.is_none() {
            // If the policy did not attempt to mutate, we don't need to do anything
            return admission_response;
        }

        AdmissionResponse {
            allowed: false,
            status: Some(AdmissionResponseStatus {
                message: Some(rejection_message_because_policy_is_not_allowed_to_mutate(
                    self.policy_id,
                )),
                code: None,
                ..Default::default()
            }),
            // if `allowed_to_mutate` is false, we are in a validating webhook.
            // If we send a patch, k8s will fail because validating webhook do not expect this field
            patch: None,
            patch_type: None,
            ..admission_response
        }
    }

    /// This check is applied only when the admission response is not allowed.
    ///
    /// If the policy has a custom rejection message, it is applied to the
    /// admission response status.
    /// The original rejection message is added to the status details causes
    /// to preserve the original error message.
    fn apply_custom_rejection_message(
        &'a self,
        admission_response: AdmissionResponse,
    ) -> AdmissionResponse {
        if admission_response.allowed {
            // If the policy is allowed, we don't need to do anything
            return admission_response;
        }

        if self.custom_rejection_message.is_none() {
            // If the policy does not have a custom rejection message,
            // we don't need to do anything
            return admission_response;
        }

        let status = admission_response.status.unwrap_or_default();
        let original_rejection_message = status.message.unwrap_or_default();

        let mut causes = status.details.clone().unwrap_or_default().causes;
        causes.push(StatusCause {
            message: Some(original_rejection_message),
            ..Default::default()
        });

        AdmissionResponse {
            status: Some(AdmissionResponseStatus {
                message: self.custom_rejection_message.clone(),
                details: Some(StatusDetails {
                    causes,
                    ..status.details.unwrap_or_default()
                }),
                ..status
            }),
            ..admission_response
        }
    }
}

fn rejection_message_because_policy_is_not_allowed_to_mutate(policy_id: &PolicyID) -> String {
    format!(
        "Request rejected by policy {}. The policy attempted to mutate the request, but it is currently configured to not allow mutations.",
        policy_id
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::admission_response::{self, AdmissionResponse};
    use lazy_static::lazy_static;
    use rstest::rstest;

    lazy_static! {
        static ref POLICY_ID: PolicyID = PolicyID::Policy("policy-id".to_string());
    }

    const DEFAULT_REJECTION_MESSAGE: &str = "default rejection message";

    struct RejectionDetails {
        pub message: String,
        pub cause: Option<String>,
    }

    impl Default for RejectionDetails {
        fn default() -> Self {
            RejectionDetails {
                message: DEFAULT_REJECTION_MESSAGE.to_string(),
                cause: None,
            }
        }
    }

    fn rejection_response(rejection_details: RejectionDetails) -> AdmissionResponse {
        let response = AdmissionResponse {
            allowed: false,
            patch: None,
            patch_type: None,
            status: Some(AdmissionResponseStatus {
                message: Some(rejection_details.message.clone()),
                ..Default::default()
            }),
            ..Default::default()
        };

        if rejection_details.cause.is_some() {
            AdmissionResponse {
                status: Some(AdmissionResponseStatus {
                    message: Some(rejection_details.message),
                    details: Some(StatusDetails {
                        causes: vec![StatusCause {
                            message: rejection_details.cause.clone(),
                            ..Default::default()
                        }],
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..response
            }
        } else {
            response
        }
    }

    fn accepted_response() -> AdmissionResponse {
        AdmissionResponse {
            allowed: true,
            ..Default::default()
        }
    }

    fn mutation_response() -> AdmissionResponse {
        AdmissionResponse {
            allowed: true,
            patch: Some("patch".to_string()),
            patch_type: Some(admission_response::PatchType::JSONPatch),
            ..Default::default()
        }
    }

    #[rstest]
    #[case::monitor_mode_allowed_to_mutate_custom_rejection_message(AdmissionResponseHandler::new(
        &POLICY_ID,
        &PolicyMode::Monitor,
        true,
        Some("Custom rejection message".to_string()),
    ) )]
    #[case::monitor_mode_not_allowed_to_mutate_custom_rejection_message(
        AdmissionResponseHandler::new(
            &POLICY_ID,
            &PolicyMode::Monitor,
            false,
            Some("Custom rejection message".to_string()),
        ),
    )]
    #[case::monitor_mode_not_allowed_to_mutate_no_custom_rejection_message(
        AdmissionResponseHandler::new(
            &POLICY_ID,
            &PolicyMode::Monitor,
            false,
            None,
        ),
    )]
    #[case::monitor_mode_allowed_to_mutate_no_custom_rejection_message(
        AdmissionResponseHandler::new(
            &POLICY_ID,
            &PolicyMode::Monitor,
            true,
            None,
        ),
    )]
    #[case::protect_mode_allowed_to_mutate_custom_rejection_message(
        AdmissionResponseHandler::new(
            &POLICY_ID,
            &PolicyMode::Protect,
            true,
            Some("Custom rejection message".to_string()),
        ),
    )]
    #[case::protect_mode_not_allowed_to_mutate_custom_rejection_message(
        AdmissionResponseHandler::new(
            &POLICY_ID,
            &PolicyMode::Protect,
            false,
            Some("Custom rejection message".to_string()),
        ),
    )]
    #[case::protect_mode_not_allowed_to_mutate_no_custom_rejection_message(
        AdmissionResponseHandler::new(
            &POLICY_ID,
            &PolicyMode::Protect,
            false,
            None,
        ),
    )]
    #[case::protect_mode_allowed_to_mutate_no_custom_rejection_message(
        AdmissionResponseHandler::new(
            &POLICY_ID,
            &PolicyMode::Protect,
            true,
            None,
        ),
    )]
    fn process_accepted_response(#[case] handler: AdmissionResponseHandler) {
        let processed_response = handler.process_response(accepted_response());
        assert_eq!(processed_response, accepted_response());
    }

    #[rstest]
    #[case::monitor_mode_allowed_to_mutate_custom_rejection_message(
        AdmissionResponseHandler::new(
            &POLICY_ID,
            &PolicyMode::Monitor,
            true,
            Some("Custom rejection message".to_string()),
        ),
        accepted_response(),
    )]
    #[case::monitor_mode_not_allowed_to_mutate_custom_rejection_message(
        AdmissionResponseHandler::new(
            &POLICY_ID,
            &PolicyMode::Monitor,
            false,
            Some("Custom rejection message".to_string()),
        ),
        accepted_response(),
    )]
    #[case::monitor_mode_not_allowed_to_mutate_no_custom_rejection_message(
        AdmissionResponseHandler::new(
            &POLICY_ID,
            &PolicyMode::Monitor,
            false,
            None,
        ),
        accepted_response(),
    )]
    #[case::monitor_mode_allowed_to_mutate_no_custom_rejection_message(
        AdmissionResponseHandler::new(
            &POLICY_ID,
            &PolicyMode::Monitor,
            true,
            None,
        ),
        accepted_response(),
    )]
    #[case::protect_mode_allowed_to_mutate_custom_rejection_message(
        AdmissionResponseHandler::new(
            &POLICY_ID,
            &PolicyMode::Protect,
            true,
            Some("Custom rejection message".to_string()),
        ),
        rejection_response(RejectionDetails{
            message: "Custom rejection message".to_string(),
            cause: Some(DEFAULT_REJECTION_MESSAGE.to_string()),
        }),
    )]
    #[case::protect_mode_not_allowed_to_mutate_custom_rejection_message(
        AdmissionResponseHandler::new(
            &POLICY_ID,
            &PolicyMode::Protect,
            false,
            Some("Custom rejection message".to_string()),
        ),
        rejection_response(RejectionDetails{
            message: "Custom rejection message".to_string(),
            cause: Some(DEFAULT_REJECTION_MESSAGE.to_string()),
        }),
    )]
    #[case::protect_mode_not_allowed_to_mutate_no_custom_rejection_message(
        AdmissionResponseHandler::new(
            &POLICY_ID,
            &PolicyMode::Protect,
            false,
            None,
        ),
        rejection_response(RejectionDetails::default()),
    )]
    #[case::protect_mode_allowed_to_mutate_no_custom_rejection_message(
        AdmissionResponseHandler::new(
            &POLICY_ID,
            &PolicyMode::Protect,
            true,
            None,
        ),
        rejection_response(RejectionDetails::default()),
    )]
    fn process_rejected_response(
        #[case] handler: AdmissionResponseHandler,
        #[case] expected_response: AdmissionResponse,
    ) {
        let processed_response =
            handler.process_response(rejection_response(RejectionDetails::default()));
        assert_eq!(
            processed_response, expected_response,
            "Got: {:?} - expected: {:?}",
            processed_response, expected_response
        );
    }

    #[rstest]
    #[case::monitor_mode_allowed_to_mutate_custom_rejection_message(
        AdmissionResponseHandler::new(
            &POLICY_ID,
            &PolicyMode::Monitor,
            true,
            Some("Custom rejection message".to_string()),
        ),
        accepted_response(),
    )]
    #[case::monitor_mode_not_allowed_to_mutate_custom_rejection_message(
        AdmissionResponseHandler::new(
            &POLICY_ID,
            &PolicyMode::Monitor,
            false,
            Some("Custom rejection message".to_string()),
        ),
        accepted_response(),
    )]
    #[case::monitor_mode_not_allowed_to_mutate_no_custom_rejection_message(
        AdmissionResponseHandler::new(
            &POLICY_ID,
            &PolicyMode::Monitor,
            false,
            None,
        ),
        accepted_response(),
    )]
    #[case::monitor_mode_allowed_to_mutate_no_custom_rejection_message(
        AdmissionResponseHandler::new(
            &POLICY_ID,
            &PolicyMode::Monitor,
            true,
            None,
        ),
        accepted_response(),
    )]
    #[case::protect_mode_allowed_to_mutate_custom_rejection_message(
        AdmissionResponseHandler::new(
            &POLICY_ID,
            &PolicyMode::Protect,
            true,
            Some("Custom rejection message".to_string()),
        ),
        mutation_response(),
    )]
    #[case::protect_mode_not_allowed_to_mutate_custom_rejection_message(
        AdmissionResponseHandler::new(
            &POLICY_ID,
            &PolicyMode::Protect,
            false,
            Some("Custom rejection message".to_string()),
        ),
        rejection_response(
            RejectionDetails {
                message: "Custom rejection message".to_string(),
                cause: Some(rejection_message_because_policy_is_not_allowed_to_mutate(&POLICY_ID)),
            }
        ),
    )]
    #[case::protect_mode_not_allowed_to_mutate_no_custom_rejection_message(
        AdmissionResponseHandler::new(
            &POLICY_ID,
            &PolicyMode::Protect,
            false,
            None,
        ),
        rejection_response(
            RejectionDetails {
                message: rejection_message_because_policy_is_not_allowed_to_mutate(&POLICY_ID),
                cause: None,
            }
        ),
    )]
    #[case::protect_mode_allowed_to_mutate_no_custom_rejection_message(
        AdmissionResponseHandler::new(
            &POLICY_ID,
            &PolicyMode::Protect,
            true,
            None,
        ),
        mutation_response(),
    )]
    fn process_mutated_response(
        #[case] handler: AdmissionResponseHandler,
        #[case] expected_response: AdmissionResponse,
    ) {
        let processed_response = handler.process_response(mutation_response());
        assert_eq!(
            processed_response, expected_response,
            "Got: {:?} - expected: {:?}",
            processed_response, expected_response
        );
    }
}
