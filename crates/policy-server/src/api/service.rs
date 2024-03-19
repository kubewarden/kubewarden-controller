use std::fmt;

use policy_evaluator::{
    admission_response::{AdmissionResponse, AdmissionResponseStatus},
    policy_evaluator::ValidateRequest,
};
use tokio::time::Instant;
use tracing::info;

use crate::{
    config::PolicyMode,
    evaluation::{errors::EvaluationError, EvaluationEnvironment},
    metrics,
};

pub(crate) enum RequestOrigin {
    Validate,
    Audit,
}

impl fmt::Display for RequestOrigin {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RequestOrigin::Validate => write!(f, "validate"),
            RequestOrigin::Audit => write!(f, "audit"),
        }
    }
}

pub(crate) fn evaluate(
    evaluation_environment: &EvaluationEnvironment,
    policy_id: &str,
    validate_request: &ValidateRequest,
    request_origin: RequestOrigin,
) -> Result<AdmissionResponse, EvaluationError> {
    let start_time = Instant::now();

    let policy_name = policy_id.to_owned();
    let vanilla_validation_response =
        match evaluation_environment.validate(policy_id, validate_request) {
            Ok(validation_response) => validation_response,
            Err(EvaluationError::PolicyInitialization(error)) => {
                return Ok(AdmissionResponse::reject(
                    validate_request.uid().to_owned(),
                    error.to_string(),
                    500,
                ))
            }

            Err(error) => return Err(error),
        };

    let policy_mode = evaluation_environment.get_policy_mode(policy_id)?;
    let allowed_to_mutate = evaluation_environment.get_policy_allowed_to_mutate(policy_id)?;

    let policy_evaluation_duration = start_time.elapsed();
    let accepted = vanilla_validation_response.allowed;
    let mutated = vanilla_validation_response.patch.is_some();
    let error_code = if let Some(status) = &vanilla_validation_response.status {
        status.code
    } else {
        None
    };

    let mut validation_response = match request_origin {
        RequestOrigin::Validate => validation_response_with_constraints(
            policy_id,
            &policy_mode,
            allowed_to_mutate,
            vanilla_validation_response.clone(),
        ),
        RequestOrigin::Audit => vanilla_validation_response.clone(),
    };

    match validate_request {
        ValidateRequest::AdmissionRequest(adm_req) => {
            // TODO: we should check immediately if the request is coming from the "always
            // accepted" namespace ASAP. Right now we do an evaluation and then we discard the
            // result if the namespace is the special one.
            // Moreover, I (flavio) don't like the fact we're using a mutable variable for
            // `validation_response`
            if let Some(ref req_namespace) = adm_req.namespace {
                if evaluation_environment
                    .should_always_accept_requests_made_inside_of_namespace(req_namespace)
                {
                    // given namespace, just set the `allowed`
                    // part of the response to `true` if the
                    // request matches this namespace. Keep
                    // the rest of the behaviors unchanged,
                    // such as checking if the policy is
                    // allowed to mutate.

                    validation_response = AdmissionResponse {
                        allowed: true,
                        status: None,
                        ..validation_response
                    };
                }
            }
            let policy_evaluation = metrics::PolicyEvaluation {
                policy_name,
                policy_mode: policy_mode.into(),
                resource_namespace: adm_req.clone().namespace,
                resource_kind: adm_req.clone().request_kind.unwrap_or_default().kind,
                resource_request_operation: adm_req.clone().operation,
                accepted,
                mutated,
                request_origin: request_origin.to_string(),
                error_code,
            };
            metrics::record_policy_latency(policy_evaluation_duration, &policy_evaluation);
            metrics::add_policy_evaluation(&policy_evaluation);
        }
        ValidateRequest::Raw(_) => {
            let accepted = vanilla_validation_response.allowed;
            let mutated = vanilla_validation_response.patch.is_some();
            let policy_evaluation = metrics::RawPolicyEvaluation {
                policy_name,
                policy_mode: policy_mode.into(),
                accepted,
                mutated,
                error_code,
            };
            metrics::record_policy_latency(policy_evaluation_duration, &policy_evaluation);
            metrics::add_policy_evaluation(&policy_evaluation);
        }
    };
    Ok(validation_response)
}

// Returns a validation response with policy-server specific
// constraints taken into account:
// - A policy might have tried to mutate while the policy-server
//   configuration does not allow it to mutate
// - A policy might be running in "Monitor" mode, that always
//   accepts the request (without mutation), logging the answer
fn validation_response_with_constraints(
    policy_id: &str,
    policy_mode: &PolicyMode,
    allowed_to_mutate: bool,
    validation_response: AdmissionResponse,
) -> AdmissionResponse {
    match policy_mode {
        PolicyMode::Protect => {
            if validation_response.patch.is_some() && !allowed_to_mutate {
                AdmissionResponse {
                        allowed: false,
                        status: Some(AdmissionResponseStatus {
                            message: Some(format!("Request rejected by policy {policy_id}. The policy attempted to mutate the request, but it is currently configured to not allow mutations.")),
                            code: None,
                        }),
                        // if `allowed_to_mutate` is false, we are in a validating webhook. If we send a patch, k8s will fail because validating webhook do not expect this field
                        patch: None,
                        patch_type: None,
                        ..validation_response
                    }
            } else {
                validation_response
            }
        }
        PolicyMode::Monitor => {
            // In monitor mode we always accept
            // the request, but log what would
            // have been the decision of the
            // policy. We also force mutating
            // patches to be none. Status is also
            // overriden, as it's only taken into
            // account when a request is rejected.
            info!(
                policy_id = policy_id,
                allowed_to_mutate = allowed_to_mutate,
                response = format!("{validation_response:?}").as_str(),
                "policy evaluation (monitor mode)",
            );
            AdmissionResponse {
                allowed: true,
                patch_type: None,
                patch: None,
                status: None,
                ..validation_response
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utils::build_admission_review_request;
    use rstest::*;

    use super::*;

    const POLICY_ID: &str = "policy-id";

    fn create_evaluation_environment_that_accepts_request(
        policy_mode: PolicyMode,
    ) -> EvaluationEnvironment {
        let mut mock_evaluation_environment = EvaluationEnvironment::default();
        mock_evaluation_environment
            .expect_validate()
            .returning(|_policy_id, request| {
                Ok(AdmissionResponse {
                    uid: request.uid().to_owned(),
                    allowed: true,
                    ..Default::default()
                })
            });
        mock_evaluation_environment
            .expect_get_policy_mode()
            .returning(move |_policy_id| Ok(policy_mode.clone()));
        mock_evaluation_environment
            .expect_get_policy_allowed_to_mutate()
            .returning(|_policy_id| Ok(false));
        mock_evaluation_environment
            .expect_should_always_accept_requests_made_inside_of_namespace()
            .returning(|_namespace| false);

        mock_evaluation_environment
    }

    #[derive(Clone)]
    struct EvaluationEnvironmentRejectionDetails {
        message: String,
        code: u16,
    }

    fn create_evaluation_environment_that_reject_request(
        policy_mode: PolicyMode,
        rejection_details: EvaluationEnvironmentRejectionDetails,
        allowed_namespace: String,
    ) -> EvaluationEnvironment {
        let mut mock_evaluation_environment = EvaluationEnvironment::default();
        mock_evaluation_environment
            .expect_validate()
            .returning(move |_policy_id, request| {
                Ok(AdmissionResponse::reject(
                    request.uid().to_owned(),
                    rejection_details.message.clone(),
                    rejection_details.code,
                ))
            });
        mock_evaluation_environment
            .expect_get_policy_mode()
            .returning(move |_policy_id| Ok(policy_mode.clone()));
        mock_evaluation_environment
            .expect_get_policy_allowed_to_mutate()
            .returning(|_policy_id| Ok(false));
        mock_evaluation_environment
            .expect_should_always_accept_requests_made_inside_of_namespace()
            .returning(move |namespace| namespace == allowed_namespace);

        mock_evaluation_environment
    }

    #[test]
    fn validation_response_with_constraints_not_allowed_to_mutate() {
        let rejection_response = AdmissionResponse {
            allowed: false,
            patch: None,
            patch_type: None,
            status: Some(AdmissionResponseStatus {
                message: Some("Request rejected by policy policy-id. The policy attempted to mutate the request, but it is currently configured to not allow mutations.".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let accept_response = AdmissionResponse {
            allowed: true,
            ..Default::default()
        };

        assert_eq!(
            validation_response_with_constraints(
                POLICY_ID,
                &PolicyMode::Protect,
                false,
                AdmissionResponse {
                    allowed: true,
                    patch: Some("patch".to_string()),
                    patch_type: Some("application/json-patch+json".to_string()),
                    ..Default::default()
                },
            ),
            rejection_response,
        );

        assert_eq!(
            validation_response_with_constraints(
                POLICY_ID,
                &PolicyMode::Monitor,
                false,
                AdmissionResponse {
                    allowed: true,
                    patch: Some("patch".to_string()),
                    patch_type: Some("application/json-patch+json".to_string()),
                    ..Default::default()
                },
            ),
            accept_response,
        );
    }

    #[test]
    fn validation_response_with_constraints_monitor_mode() {
        let admission_response = AdmissionResponse {
            allowed: true,
            ..Default::default()
        };

        assert_eq!(
            validation_response_with_constraints(
                POLICY_ID,
                &PolicyMode::Monitor,
                true,
                AdmissionResponse {
                    allowed: true,
                    patch: Some("patch".to_string()),
                    patch_type: Some("application/json-patch+json".to_string()),
                    ..Default::default()
                },
            ),
            admission_response,
            "Mutated request from a policy allowed to mutate should be accepted in monitor mode"
        );

        assert_eq!(
            validation_response_with_constraints(
                POLICY_ID,
                &PolicyMode::Monitor,
                false,
                AdmissionResponse {
                    allowed: true,
                    patch: Some("patch".to_string()),
                    patch_type: Some("application/json-patch+json".to_string()),
                    ..Default::default()
                },
            ),
            admission_response, "Mutated request from a policy not allowed to mutate should be accepted in monitor mode"
        );

        assert_eq!(
            validation_response_with_constraints(
                POLICY_ID,
                &PolicyMode::Monitor,
                true,
                AdmissionResponse {
                    allowed: true,
                    ..Default::default()
                },
            ),
            admission_response,
            "Accepted request from a policy allowed to mutate should be accepted in monitor mode"
        );

        assert_eq!(
            validation_response_with_constraints(
                POLICY_ID,
                &PolicyMode::Monitor,
                true,
                AdmissionResponse {
                    allowed: false,
                    status: Some(AdmissionResponseStatus {
                        message: Some("some rejection message".to_string()),
                        code: Some(500),
                    }),
                    ..Default::default()
                },
            ),
            admission_response, "Not accepted request from a policy allowed to mutate should be accepted in monitor mode"
        );

        assert_eq!(
            validation_response_with_constraints(
                POLICY_ID,
                &PolicyMode::Monitor,
                false,
                AdmissionResponse {
                    allowed: true,
                    ..Default::default()
                },
            ),
            admission_response, "Accepted request from a policy not allowed to mutate should be accepted in monitor mode"
        );

        assert_eq!(
            validation_response_with_constraints(
                POLICY_ID,
                &PolicyMode::Monitor,
                false,
                AdmissionResponse {
                    allowed: false,
                    status: Some(AdmissionResponseStatus {
                        message: Some("some rejection message".to_string()),
                        code: Some(500),
                    }),
                    ..Default::default()
                },
            ),
            admission_response, "Not accepted request from a policy not allowed to mutate should be accepted in monitor mode"
        );
    }

    #[test]
    fn validation_response_with_constraints_protect_mode() {
        let admission_response = AdmissionResponse {
            allowed: true,
            ..Default::default()
        };

        assert_eq!(
            validation_response_with_constraints(
                POLICY_ID,
                &PolicyMode::Protect,
                true,
                AdmissionResponse {
                    allowed: true,
                    patch: Some("patch".to_string()),
                    patch_type: Some("application/json-patch+json".to_string()),
                    ..Default::default()
                },
            ),
            AdmissionResponse {
                allowed: true,
                patch: Some("patch".to_string()),
                patch_type: Some("application/json-patch+json".to_string()),
                ..Default::default()
            },
            "Mutated request from a policy allowed to mutate should be accepted in protect mode"
        );

        assert_eq!(
            validation_response_with_constraints(
                POLICY_ID,
                &PolicyMode::Protect,
                false,
                AdmissionResponse {
                    allowed: true,
                    patch: Some("patch".to_string()),
                    patch_type: Some("application/json-patch+json".to_string()),
                    ..Default::default()
                },
            ),
            AdmissionResponse {
            allowed: false,
            patch: None,
            patch_type: None,
            status: Some(AdmissionResponseStatus {
                message: Some("Request rejected by policy policy-id. The policy attempted to mutate the request, but it is currently configured to not allow mutations.".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        },
            "Mutated request from a policy not allowed to mutate should be reject in protect mode"
        );

        assert_eq!(
            validation_response_with_constraints(
                POLICY_ID,
                &PolicyMode::Protect,
                true,
                AdmissionResponse {
                    allowed: true,
                    ..Default::default()
                },
            ),
            admission_response,
            "Accepted request from a policy allowed to mutate should be accepted in protect mode"
        );

        assert_eq!(
            validation_response_with_constraints(
                POLICY_ID,
                &PolicyMode::Protect,
                true,
                AdmissionResponse {
                    allowed: false,
                    status: Some(AdmissionResponseStatus {
                        message: Some("some rejection message".to_string()),
                        code: Some(500),
                    }),
                    ..Default::default()
                },
            ),
            AdmissionResponse {
                    allowed: false,
                    status: Some(AdmissionResponseStatus {
                        message: Some("some rejection message".to_string()),
                        code: Some(500),
                    }),
                    ..Default::default()
                }, "Not accepted request from a policy allowed to mutate should be rejected in protect mode"
        );

        assert_eq!(
            validation_response_with_constraints(
                POLICY_ID,
                &PolicyMode::Protect,
                false,
                AdmissionResponse {
                    allowed: true,
                    ..Default::default()
                },
            ),
            admission_response, "Accepted request from a policy not allowed to mutate should be accepted in protect mode"
        );

        assert_eq!(
            validation_response_with_constraints(
                POLICY_ID,
                &PolicyMode::Protect,
                false,
                AdmissionResponse {
                    allowed: false,
                    status: Some(AdmissionResponseStatus {
                        message: Some("some rejection message".to_string()),
                        code: Some(500),
                    }),
                    ..Default::default()
                },
            ),
            AdmissionResponse {
                    allowed: false,
                    status: Some(AdmissionResponseStatus {
                        message: Some("some rejection message".to_string()),
                        code: Some(500),
                    }),
                    ..Default::default()
                }, "Not accepted request from a policy not allowed to mutate should be rejected in protect mode"
        );
    }

    #[rstest]
    #[test]
    #[case(PolicyMode::Protect, RequestOrigin::Validate)]
    #[case(PolicyMode::Monitor, RequestOrigin::Validate)]
    #[case(PolicyMode::Protect, RequestOrigin::Audit)]
    #[case(PolicyMode::Monitor, RequestOrigin::Audit)]
    fn evaluate_policy_evaluator_accepts_request(
        #[case] policy_mode: PolicyMode,
        #[case] request_origin: RequestOrigin,
    ) {
        let evaluation_environment =
            create_evaluation_environment_that_accepts_request(policy_mode);
        let policy_id = "test_policy1";
        let validate_request =
            ValidateRequest::AdmissionRequest(build_admission_review_request().request);

        let response = evaluate(
            &evaluation_environment,
            policy_id,
            &validate_request,
            request_origin,
        )
        .unwrap();
        assert!(response.allowed);
    }

    #[rstest]
    #[test]
    #[case(PolicyMode::Protect, RequestOrigin::Validate, false)]
    #[case(PolicyMode::Monitor, RequestOrigin::Validate, true)]
    #[case(PolicyMode::Protect, RequestOrigin::Audit, false)]
    #[case(PolicyMode::Monitor, RequestOrigin::Audit, false)]
    fn evaluate_policy_evaluator_rejects_request(
        #[case] policy_mode: PolicyMode,
        #[case] request_origin: RequestOrigin,
        #[case] accept: bool,
    ) {
        let rejection_details = EvaluationEnvironmentRejectionDetails {
            message: "boom".to_string(),
            code: 500,
        };
        let evaluation_environment = create_evaluation_environment_that_reject_request(
            policy_mode,
            rejection_details.clone(),
            "".to_string(),
        );
        let validate_request =
            ValidateRequest::AdmissionRequest(build_admission_review_request().request);
        let policy_id = "test_policy1";

        let response = evaluate(
            &evaluation_environment,
            policy_id,
            &validate_request,
            request_origin,
        )
        .unwrap();

        if accept {
            assert!(response.allowed);
            assert!(response.status.is_none());
        } else {
            assert!(!response.allowed);
            let response_status = response.status.expect("should be set");
            assert_eq!(response_status.message, Some(rejection_details.message));
            assert_eq!(response_status.code, Some(rejection_details.code));
        }
    }

    #[test]
    fn evaluate_policy_evaluator_accepts_request_raw() {
        let evaluation_environment =
            create_evaluation_environment_that_accepts_request(PolicyMode::Protect);
        let request = serde_json::json!(r#"{"foo": "bar"}"#);
        let validate_request = ValidateRequest::Raw(request.clone());
        let policy_id = "test_policy1";

        let response = evaluate(
            &evaluation_environment,
            policy_id,
            &validate_request,
            RequestOrigin::Validate,
        )
        .unwrap();

        assert!(response.allowed);
    }

    #[test]
    fn evaluate_policy_evaluator_rejects_request_raw() {
        let rejection_details = EvaluationEnvironmentRejectionDetails {
            message: "boom".to_string(),
            code: 500,
        };
        let evaluation_environment = create_evaluation_environment_that_reject_request(
            PolicyMode::Protect,
            rejection_details.clone(),
            "".to_string(),
        );
        let request = serde_json::json!(r#"{"foo": "bar"}"#);
        let validate_request = ValidateRequest::Raw(request.clone());
        let policy_id = "test_policy1";

        let response = evaluate(
            &evaluation_environment,
            policy_id,
            &validate_request,
            RequestOrigin::Validate,
        )
        .unwrap();

        assert!(!response.allowed);
        let response_status = response.status.expect("should be set");
        assert_eq!(response_status.message, Some(rejection_details.message));
        assert_eq!(response_status.code, Some(rejection_details.code));
    }

    #[rstest]
    #[test]
    #[case(RequestOrigin::Validate)]
    #[case(RequestOrigin::Audit)]
    fn evaluate_policy_evaluator_rejects_request_but_request_originated_from_allowed_namespace(
        #[case] request_origin: RequestOrigin,
    ) {
        let allowed_namespace = "kubewarden_special".to_string();
        let rejection_details = EvaluationEnvironmentRejectionDetails {
            message: "boom".to_string(),
            code: 500,
        };
        let evaluation_environment = create_evaluation_environment_that_reject_request(
            PolicyMode::Protect,
            rejection_details.clone(),
            allowed_namespace.clone(),
        );
        let mut request = build_admission_review_request().request;
        request.namespace = Some(allowed_namespace.clone());
        let validate_request = ValidateRequest::AdmissionRequest(request);

        let policy_id = "test_policy1";

        let response = evaluate(
            &evaluation_environment,
            policy_id,
            &validate_request,
            request_origin,
        )
        .unwrap();

        assert!(response.allowed);
        assert!(response.status.is_none());
    }
}
