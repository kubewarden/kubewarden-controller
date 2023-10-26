use anyhow::{anyhow, Result};
use itertools::Itertools;
use policy_evaluator::callback_requests::CallbackRequest;
use policy_evaluator::wasmtime;
use policy_evaluator::{
    admission_response::{AdmissionResponse, AdmissionResponseStatus},
    policy_evaluator::{Evaluator, ValidateRequest},
};
use std::{collections::HashMap, fmt, time::Instant};
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{error, info, info_span};

use crate::communication::{EvalRequest, RequestOrigin};
use crate::metrics::{self};
use crate::settings::{Policy, PolicyMode};
use crate::worker_pool::PrecompiledPolicies;

struct PolicyEvaluatorWithSettings {
    policy_evaluator: Box<dyn Evaluator>,
    policy_mode: PolicyMode,
    allowed_to_mutate: bool,
    always_accept_admission_reviews_on_namespace: Option<String>,
}

pub(crate) struct Worker {
    evaluators: HashMap<String, PolicyEvaluatorWithSettings>,
    channel_rx: Receiver<EvalRequest>,
}

pub struct PolicyErrors(HashMap<String, String>);

impl fmt::Display for PolicyErrors {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut errors = self
            .0
            .iter()
            .map(|(policy, error)| format!("[{policy}: {error}]"));
        write!(f, "{}", errors.join(", "))
    }
}

impl Worker {
    #[tracing::instrument(
        name = "worker_new",
        fields(host=crate::cli::HOSTNAME.as_str()),
        skip_all,
    )]
    pub(crate) fn new(
        rx: Receiver<EvalRequest>,
        policies: &HashMap<String, Policy>,
        precompiled_policies: &PrecompiledPolicies,
        engine: wasmtime::Engine,
        callback_handler_tx: Sender<CallbackRequest>,
        always_accept_admission_reviews_on_namespace: Option<String>,
        policy_evaluation_limit_seconds: Option<u64>,
    ) -> Result<Worker, PolicyErrors> {
        let mut evs_errors = HashMap::new();
        let mut evs = HashMap::new();

        for (id, policy) in policies.iter() {
            // It's safe to clone the outer engine. This creates a shallow copy
            let inner_engine = engine.clone();
            let policy_evaluator = match crate::worker_pool::build_policy_evaluator(
                id,
                policy,
                &inner_engine,
                precompiled_policies,
                callback_handler_tx.clone(),
                policy_evaluation_limit_seconds,
            ) {
                Ok(pe) => Box::new(pe),
                Err(e) => {
                    evs_errors.insert(
                        id.clone(),
                        format!("[{id}] could not create PolicyEvaluator: {e:?}"),
                    );
                    continue;
                }
            };

            let policy_evaluator_with_settings = PolicyEvaluatorWithSettings {
                policy_evaluator,
                policy_mode: policy.policy_mode.clone(),
                allowed_to_mutate: policy.allowed_to_mutate.unwrap_or(false),
                always_accept_admission_reviews_on_namespace:
                    always_accept_admission_reviews_on_namespace.clone(),
            };

            evs.insert(id.to_string(), policy_evaluator_with_settings);
        }

        if !evs_errors.is_empty() {
            return Err(PolicyErrors(evs_errors));
        }

        Ok(Worker {
            evaluators: evs,
            channel_rx: rx,
        })
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

    pub(crate) fn run(&mut self) {
        while let Some(req) = self.channel_rx.blocking_recv() {
            let span = info_span!(parent: &req.parent_span, "policy_eval");
            let _enter = span.enter();

            let res = match self.evaluators.get_mut(&req.policy_id) {
                Some(pes) => Self::evaluate(req, pes),
                None => req
                    .resp_chan
                    .send(None)
                    .map_err(|_| anyhow!("cannot send response back")),
            };
            if res.is_err() {
                error!("receiver dropped");
            }
        }
    }

    fn evaluate(req: EvalRequest, pes: &mut PolicyEvaluatorWithSettings) -> anyhow::Result<()> {
        let start_time = Instant::now();

        let policy_name = pes.policy_evaluator.policy_id();
        let policy_mode = pes.policy_mode.clone();
        let allowed_to_mutate = pes.allowed_to_mutate;
        let vanilla_validation_response = pes.policy_evaluator.validate(req.req.clone());
        let policy_evaluation_duration = start_time.elapsed();
        let accepted = vanilla_validation_response.allowed;
        let mutated = vanilla_validation_response.patch.is_some();
        let error_code = if let Some(status) = &vanilla_validation_response.status {
            status.code
        } else {
            None
        };

        let mut validation_response = match req.request_origin {
            RequestOrigin::Validate => Worker::validation_response_with_constraints(
                &req.policy_id,
                &policy_mode,
                allowed_to_mutate,
                vanilla_validation_response.clone(),
            ),
            RequestOrigin::Audit => vanilla_validation_response.clone(),
        };

        match req.req.clone() {
            ValidateRequest::AdmissionRequest(adm_req) => {
                if let Some(namespace) = &pes.always_accept_admission_reviews_on_namespace {
                    // If the policy server is configured to
                    // always accept admission reviews on a
                    // given namespace, just set the `allowed`
                    // part of the response to `true` if the
                    // request matches this namespace. Keep
                    // the rest of the behaviors unchanged,
                    // such as checking if the policy is
                    // allowed to mutate.

                    if adm_req.namespace == Some(namespace.to_string()) {
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

        let res = req.resp_chan.send(Some(validation_response));
        res.map_err(|_| anyhow!("cannot send response back"))
    }
}

#[cfg(test)]
mod tests {
    use crate::admission_review::tests::build_admission_review;
    use crate::communication::RequestOrigin;

    use policy_evaluator::kubewarden_policy_sdk::settings::SettingsValidationResponse;
    use policy_evaluator::ProtocolVersion;
    use rstest::*;
    use tokio::sync::oneshot;

    use super::*;

    const POLICY_ID: &str = "policy-id";

    struct MockPolicyEvaluator {
        pub policy_id: String,
        pub admission_response: AdmissionResponse,
        pub settings_validation_response: SettingsValidationResponse,
        pub protocol_version: Result<ProtocolVersion>,
    }

    impl Default for MockPolicyEvaluator {
        fn default() -> Self {
            Self {
                policy_id: "mock_policy".to_string(),
                admission_response: AdmissionResponse {
                    allowed: false,
                    ..Default::default()
                },
                settings_validation_response: SettingsValidationResponse {
                    valid: true,
                    message: None,
                },
                protocol_version: Ok(ProtocolVersion::V1),
            }
        }
    }

    impl MockPolicyEvaluator {
        fn new_allowed() -> MockPolicyEvaluator {
            MockPolicyEvaluator {
                admission_response: AdmissionResponse {
                    allowed: true,
                    ..Default::default()
                },
                ..Default::default()
            }
        }

        fn new_rejected(message: Option<String>, code: Option<u16>) -> MockPolicyEvaluator {
            MockPolicyEvaluator {
                admission_response: AdmissionResponse {
                    allowed: false,
                    status: Some(AdmissionResponseStatus { message, code }),
                    ..Default::default()
                },
                ..Default::default()
            }
        }
    }

    impl Evaluator for MockPolicyEvaluator {
        fn validate(&mut self, _request: ValidateRequest) -> AdmissionResponse {
            self.admission_response.clone()
        }

        fn validate_settings(&mut self) -> SettingsValidationResponse {
            self.settings_validation_response.clone()
        }

        fn protocol_version(&mut self) -> Result<ProtocolVersion> {
            match &self.protocol_version {
                Ok(pv) => Ok(pv.clone()),
                Err(e) => Err(anyhow::anyhow!("{}", e)),
            }
        }

        fn policy_id(&self) -> String {
            self.policy_id.clone()
        }
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
            Worker::validation_response_with_constraints(
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
            Worker::validation_response_with_constraints(
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
            Worker::validation_response_with_constraints(
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
            Worker::validation_response_with_constraints(
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
            Worker::validation_response_with_constraints(
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
            Worker::validation_response_with_constraints(
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
            Worker::validation_response_with_constraints(
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
            Worker::validation_response_with_constraints(
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
            Worker::validation_response_with_constraints(
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
            Worker::validation_response_with_constraints(
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
            Worker::validation_response_with_constraints(
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
            Worker::validation_response_with_constraints(
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
            Worker::validation_response_with_constraints(
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
            Worker::validation_response_with_constraints(
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
        let (tx, mut rx) = oneshot::channel::<Option<AdmissionResponse>>();
        let req = ValidateRequest::AdmissionRequest(
            build_admission_review().request.expect("no request"),
        );

        let eval_req = EvalRequest {
            policy_id: "test_policy1".to_string(),
            req,
            resp_chan: tx,
            parent_span: tracing::Span::none(),
            request_origin,
        };

        let mock_evaluator = MockPolicyEvaluator::new_allowed();
        let mut pes = PolicyEvaluatorWithSettings {
            policy_evaluator: Box::new(mock_evaluator),
            policy_mode,
            allowed_to_mutate: false,
            always_accept_admission_reviews_on_namespace: None,
        };

        let result = Worker::evaluate(eval_req, &mut pes);
        assert!(result.is_ok());

        let response = rx
            .try_recv()
            .expect("Got an error")
            .expect("expected a AdmissionResponse object");
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
        let (tx, mut rx) = oneshot::channel::<Option<AdmissionResponse>>();
        let req = ValidateRequest::AdmissionRequest(
            build_admission_review().request.expect("no request"),
        );

        let eval_req = EvalRequest {
            policy_id: "test_policy1".to_string(),
            req,
            resp_chan: tx,
            parent_span: tracing::Span::none(),
            request_origin,
        };

        let message = Some("boom".to_string());
        let code = Some(500);
        let mock_evaluator = MockPolicyEvaluator::new_rejected(message.clone(), code);
        let mut pes = PolicyEvaluatorWithSettings {
            policy_evaluator: Box::new(mock_evaluator),
            policy_mode,
            allowed_to_mutate: false,
            always_accept_admission_reviews_on_namespace: None,
        };

        let result = Worker::evaluate(eval_req, &mut pes);
        assert!(result.is_ok());

        let response = rx
            .try_recv()
            .expect("Got an error")
            .expect("expected a AdmissionResponse object");

        if accept {
            assert!(response.allowed);
            assert!(response.status.is_none());
        } else {
            assert!(!response.allowed);
            let response_status = response.status.expect("should be set");
            assert_eq!(response_status.message, message);
            assert_eq!(response_status.code, code);
        }
    }

    #[test]
    fn evaluate_policy_evaluator_accepts_request_raw() {
        let (tx, mut rx) = oneshot::channel::<Option<AdmissionResponse>>();

        let request = serde_json::json!(r#"{"foo": "bar"}"#);
        let req = ValidateRequest::Raw(request.clone());

        let eval_req = EvalRequest {
            policy_id: "test_policy1".to_string(),
            req,
            resp_chan: tx,
            parent_span: tracing::Span::none(),
            request_origin: RequestOrigin::Validate,
        };

        let mock_evaluator = MockPolicyEvaluator::new_allowed();
        let mut pes = PolicyEvaluatorWithSettings {
            policy_evaluator: Box::new(mock_evaluator),
            policy_mode: PolicyMode::Protect,
            allowed_to_mutate: false,
            always_accept_admission_reviews_on_namespace: None,
        };

        let result = Worker::evaluate(eval_req, &mut pes);
        assert!(result.is_ok());

        let response = rx
            .try_recv()
            .expect("Got an error")
            .expect("expected a AdmissionResponse object");
        assert!(response.allowed);
    }

    #[test]
    fn evaluate_policy_evaluator_rejects_request_raw() {
        let (tx, mut rx) = oneshot::channel::<Option<AdmissionResponse>>();

        let request = serde_json::json!(r#"{"foo": "bar"}"#);
        let req = ValidateRequest::Raw(request.clone());

        let eval_req = EvalRequest {
            policy_id: "test_policy1".to_string(),
            req,
            resp_chan: tx,
            parent_span: tracing::Span::none(),
            request_origin: RequestOrigin::Validate,
        };

        let message = Some("boom".to_string());
        let code = Some(500);
        let mock_evaluator = MockPolicyEvaluator::new_rejected(message.clone(), code);
        let mut pes = PolicyEvaluatorWithSettings {
            policy_evaluator: Box::new(mock_evaluator),
            policy_mode: PolicyMode::Protect,
            allowed_to_mutate: false,
            always_accept_admission_reviews_on_namespace: None,
        };

        let result = Worker::evaluate(eval_req, &mut pes);
        assert!(result.is_ok());

        let response = rx
            .try_recv()
            .expect("Got an error")
            .expect("expected a AdmissionResponse object");

        assert!(!response.allowed);
        let response_status = response.status.expect("should be set");
        assert_eq!(response_status.message, message);
        assert_eq!(response_status.code, code);
    }

    #[rstest]
    #[test]
    #[case(RequestOrigin::Validate)]
    #[case(RequestOrigin::Audit)]
    fn evaluate_policy_evaluator_rejects_request_but_request_originated_from_allowed_namespace(
        #[case] request_origin: RequestOrigin,
    ) {
        // PolicyEvaluator rejects the request, but the event took plance inside
        // of a namespace that is ignored by kubewarden -> this leads the
        // request to still be accepted

        let (tx, mut rx) = oneshot::channel::<Option<AdmissionResponse>>();

        let allowed_namespace = "kubewarden_special".to_string();

        let mut request = build_admission_review().request.expect("no request");
        request.namespace = Some(allowed_namespace.clone());
        let req = ValidateRequest::AdmissionRequest(request);

        let eval_req = EvalRequest {
            policy_id: "test_policy1".to_string(),
            req,
            resp_chan: tx,
            parent_span: tracing::Span::none(),
            request_origin,
        };

        let message = Some("boom".to_string());
        let code = Some(500);
        let mock_evaluator = MockPolicyEvaluator::new_rejected(message, code);
        let mut pes = PolicyEvaluatorWithSettings {
            policy_evaluator: Box::new(mock_evaluator),
            policy_mode: PolicyMode::Protect,
            allowed_to_mutate: false,
            always_accept_admission_reviews_on_namespace: Some(allowed_namespace),
        };

        let result = Worker::evaluate(eval_req, &mut pes);
        assert!(result.is_ok());

        let response = rx
            .try_recv()
            .expect("Got an error")
            .expect("expected a AdmissionResponse object");
        assert!(response.allowed);
        assert!(response.status.is_none());
    }
}
