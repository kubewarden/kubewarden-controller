use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex},
};

use kubewarden_policy_sdk::settings::SettingsValidationResponse;
use rhai::EvalAltResult;
use tokio::sync::mpsc;
use tracing::debug;

use crate::admission_response::{self, AdmissionResponse, AdmissionResponseStatus};
use crate::callback_requests::CallbackRequest;
use crate::evaluation_context::EvaluationContext;
use crate::policy_evaluator::{PolicyEvaluatorPre, ValidateRequest};
use crate::policy_group_evaluator::{
    errors::{EvaluationError, Result},
    PolicyGroupMemberEvaluationResult, PolicyGroupMemberSettings,
};

/// PolicyGroupEvaluator is an evaluator that can evaluate a group of policies
///
/// How to use a use a `PolicyGroupEvaluator`:
///
/// ```rust,ignore
/// // Create a new PolicyGroupEvaluator
/// let mut policy_group_evaluator = PolicyGroupEvaluator::new("group_policy", "something went wrong", "happy_policy_1() && happy_policy_2()", None);
///
/// // For each policy that is part of the group, register it
/// policy_group_evaluator.add_policy_member("happy_policy_1", POLICY_ALWAYS_HAPPY.clone(), happy_policy_1_settings);
/// policy_group_evaluator.add_policy_member("happy_policy_2", POLICY_ALWAYS_HAPPY.clone(), happy_policy_2_settings);
///
/// // Ensure the policy group is properly configured. This will make sure:
/// // - the expression is valid
/// // - each policy has valid settings
/// let validation_result = policy_group_evaluator.validate_settings();
/// assert!(validation_result.valid);
///
/// // Validate a request against the group of policies
/// let admission_response = Arc::new(policy_group_evaluator).validate(request);
/// ````
pub struct PolicyGroupEvaluator {
    /// The unique identifier of the policy group
    policy_id: String,

    /// The message to be returned in the AdmissionResponse when the request is denied
    message: String,

    /// The rhai expression that will be evaluated to determine if the request is allowed or not
    expression: String,

    /// A map of the policies that are part of the group
    policy_members: HashMap<String, Arc<PolicyEvaluatorPre>>,

    /// A map of the settings for each policy that is part of the group
    policy_members_settings: HashMap<String, PolicyGroupMemberSettings>,

    /// Channel used by the synchronous world (like the `host_callback` waPC function,
    /// but also Burrego for k8s context aware data),
    /// to request the computation of code that can only be run inside of an
    /// asynchronous block
    callback_channel: Option<mpsc::Sender<CallbackRequest>>,
}

impl fmt::Debug for PolicyGroupEvaluator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"PolicyGroupEvaluator {{ id: "{}", message: "{}", expression: "{}", policies: {:?} }}"#,
            self.policy_id,
            self.message,
            self.expression,
            self.policy_members.keys()
        )
    }
}

impl PolicyGroupEvaluator {
    pub fn new(
        id: &str,
        message: &str,
        expression: &str,
        callback_channel: Option<mpsc::Sender<CallbackRequest>>,
    ) -> Self {
        Self {
            policy_id: id.to_owned(),
            message: message.to_owned(),
            expression: expression.to_owned(),
            policy_members: HashMap::new(),
            policy_members_settings: HashMap::new(),
            callback_channel,
        }
    }

    /// Add a policy to the group
    pub fn add_policy_member(
        &mut self,
        name: &str,
        policy_evaluator_pre: Arc<PolicyEvaluatorPre>,
        settings: PolicyGroupMemberSettings,
    ) {
        self.policy_members_settings
            .insert(name.to_owned(), settings);
        self.policy_members
            .insert(name.to_owned(), policy_evaluator_pre);
    }

    /// Validate the request against the group of policies
    ///
    /// Note, `self` is wrapped inside of `Arc` because this method is called from within a Rhai engine closure that
    /// requires `+send` and `+sync`.
    #[tracing::instrument(skip(request))]
    pub fn validate(self: Arc<Self>, request: &ValidateRequest) -> AdmissionResponse {
        // We create a RAW engine, which has a really limited set of built-ins available
        let mut rhai_engine = rhai::Engine::new_raw();

        // Keep track of all the evaluation results of the member policies
        let policies_evaluation_results: Arc<
            Mutex<HashMap<String, PolicyGroupMemberEvaluationResult>>,
        > = Arc::new(Mutex::new(HashMap::new()));

        let policy_ids = self.policy_members.keys().cloned().collect::<Vec<String>>();
        for sub_policy_name in policy_ids {
            let rhai_eval_env = self.clone();

            let evaluation_results = policies_evaluation_results.clone();

            let validate_request = request.clone();
            rhai_engine.register_fn(
                sub_policy_name.clone().as_str(),
                move || -> std::result::Result<bool, Box<EvalAltResult>> {
                    let response = Self::validate_policy(
                        rhai_eval_env.clone(),
                        &sub_policy_name,
                        &validate_request,
                    )
                    .map_err(|e| {
                        EvalAltResult::ErrorSystem(
                            format!(
                                "error invoking {}/{}",
                                rhai_eval_env.policy_id, sub_policy_name
                            ),
                            Box::new(e),
                        )
                    })?;

                    if response.patch.is_some() {
                        // mutation is not allowed inside of group policies
                        let mut results = evaluation_results.lock().unwrap();
                        results.insert(
                            sub_policy_name.clone(),
                            PolicyGroupMemberEvaluationResult {
                                allowed: false,
                                message: Some(
                                    "mutation is not allowed inside of policy group".to_string(),
                                ),
                            },
                        );
                        return Ok(false);
                    }

                    let allowed = response.allowed;

                    let mut results = evaluation_results.lock().unwrap();
                    results.insert(sub_policy_name.clone(), response.into());

                    Ok(allowed)
                },
            );
        }

        // drop the `mut`
        let rhai_engine = rhai_engine;

        // Note: we use `eval_expression` to limit even further what the user is allowed
        // to define inside of the expression
        let allowed = match rhai_engine.eval_expression::<bool>(self.expression.as_str()) {
            Ok(allowed) => allowed,
            Err(e) => {
                let message = format!("error evaluating policy group expression: {}", e);
                debug!(?e, "error evaluating policy group expression");
                return AdmissionResponse::reject(request.uid().to_string(), message, 500);
            }
        };

        // The details of each policy evaluation are returned as part of the
        // AdmissionResponse.status.details.causes
        let mut status_causes = vec![];

        let evaluation_results = policies_evaluation_results.lock().unwrap();

        for policy_id in self.policy_members.keys() {
            if let Some(result) = evaluation_results.get(policy_id) {
                if !result.allowed {
                    let cause = admission_response::StatusCause {
                        field: Some(format!("spec.policies.{}", policy_id)),
                        message: result.message.clone(),
                        ..Default::default()
                    };
                    status_causes.push(cause);
                }
            }
        }
        debug!(
            ?self.policy_id,
            ?allowed,
            ?status_causes,
            "policy group evaluation result"
        );

        let status = if allowed {
            // The status field is discarded by the Kubernetes API server when the
            // request is allowed.
            None
        } else {
            Some(AdmissionResponseStatus {
                message: Some(self.message.clone()),
                code: None,
                details: Some(admission_response::StatusDetails {
                    causes: status_causes,
                    ..Default::default()
                }),
                ..Default::default()
            })
        };

        AdmissionResponse {
            uid: request.uid().to_string(),
            allowed,
            patch_type: None,
            patch: None,
            status,
            audit_annotations: None,
            warnings: None,
        }
    }

    /// Validate the request against a single policy
    ///
    /// Note, `self` is wrapped inside of `Arc` because this method is called from within a Rhai engine closure that
    /// requires `+send` and `+sync`.
    fn validate_policy(
        self: Arc<Self>,
        policy_id: &str,
        req: &ValidateRequest,
    ) -> Result<AdmissionResponse> {
        debug!(?policy_id, "validate policy");

        let evaluator_pre = self
            .policy_members
            .get(policy_id)
            .ok_or_else(|| EvaluationError::EvaluatorPreNotFound(policy_id.to_owned()))?;
        let settings = self
            .policy_members_settings
            .get(policy_id)
            .ok_or_else(|| EvaluationError::SettingsNotFound(policy_id.to_owned()))?;

        let eval_ctx = EvaluationContext {
            policy_id: policy_id.to_owned(),
            callback_channel: self.callback_channel.clone(),
            ctx_aware_resources_allow_list: settings.ctx_aware_resources_allow_list.clone(),
        };
        let mut evaluator = evaluator_pre.rehydrate(&eval_ctx).map_err(|e| {
            EvaluationError::CannotRehydratePolicyGroupMember(policy_id.to_owned(), e)
        })?;
        Ok(evaluator.validate(req.clone(), &settings.settings))
    }

    /// Validate the settings of the group of policies
    ///
    /// Each policy is validated individually, and the expression is also validated.
    #[tracing::instrument]
    pub fn validate_settings(self) -> SettingsValidationResponse {
        let mut rhai_engine = rhai::Engine::new_raw();

        let mut policy_validation_errors = HashMap::new();

        for sub_policy_name in self.policy_members.keys() {
            if let Err(e) = self.validate_policy_settings(sub_policy_name) {
                policy_validation_errors.insert(
                    format!("{}/{}", self.policy_id, sub_policy_name),
                    e.to_string(),
                );
            }

            rhai_engine.register_fn(sub_policy_name.as_str(), || true);
        }

        // Make sure:
        // - the expression is valid
        // - TODO: make sure the expression returns a boolean, we don't care about the actual result.
        //   Note about that, the expressions are also going to be validated by the
        //   Kubewarden controller when the GroupPolicy is created. Here we will leverage
        //   CEL to perform the validation, which makes that possible.
        if let Err(e) = rhai_engine.eval_expression::<bool>(self.expression.as_str()) {
            policy_validation_errors.insert(self.policy_id.clone(), e.to_string());
        }

        if policy_validation_errors.is_empty() {
            SettingsValidationResponse {
                valid: true,
                message: None,
            }
        } else {
            let message = policy_validation_errors
                .iter()
                .map(|(policy_id, error)| format!("{}: {}", policy_id, error))
                .collect::<Vec<String>>()
                .join(", ");

            SettingsValidationResponse {
                valid: false,
                message: Some(message),
            }
        }
    }

    /// Validate the settings of a single policy
    fn validate_policy_settings(&self, policy_id: &str) -> Result<()> {
        debug!(?policy_id, "validate policy settings");

        let evaluator_pre = self
            .policy_members
            .get(policy_id)
            .ok_or_else(|| EvaluationError::EvaluatorPreNotFound(policy_id.to_owned()))?;
        let settings = self
            .policy_members_settings
            .get(policy_id)
            .ok_or_else(|| EvaluationError::SettingsNotFound(policy_id.to_owned()))?;

        let eval_ctx = EvaluationContext {
            policy_id: policy_id.to_owned(),
            callback_channel: self.callback_channel.clone(),
            ctx_aware_resources_allow_list: settings.ctx_aware_resources_allow_list.clone(),
        };
        let mut evaluator = evaluator_pre.rehydrate(&eval_ctx).map_err(|e| {
            EvaluationError::CannotRehydratePolicyGroupMember(policy_id.to_owned(), e)
        })?;

        match evaluator.validate_settings(&settings.settings) {
            SettingsValidationResponse {
                valid: true,
                message: _,
            } => Ok(()),
            SettingsValidationResponse {
                valid: false,
                message,
            } => {
                let error_message = format!(
                    "Policy settings are invalid: {}",
                    message.unwrap_or("no message".to_owned())
                );

                Err(EvaluationError::SettingsNotValid(error_message))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use lazy_static::lazy_static;
    use rstest::*;
    use wasmtime::Engine;

    use crate::{
        admission_request::AdmissionRequest,
        policy_evaluator::policy_evaluator_builder::PolicyEvaluatorBuilder,
    };

    lazy_static! {
        static ref ENGINE: Engine = Engine::default();
        static ref POLICY_ALWAYS_HAPPY: PolicyEvaluatorPre = build_precompiled_policy(
            include_bytes!("../../tests/data/gatekeeper_always_happy_policy.wasm")
        );
        static ref POLICY_ALWAYS_UNHAPPY: PolicyEvaluatorPre = build_precompiled_policy(
            include_bytes!("../../tests/data/gatekeeper_always_unhappy_policy.wasm")
        );
    }

    fn build_validate_request() -> ValidateRequest {
        let input = r#"
            {
                "uid": "hello",
                "kind": {"group":"autoscaling","version":"v1","kind":"Scale"},
                "resource": {"group":"apps","version":"v1","resource":"deployments"},
                "subResource": "scale",
                "requestKind": {"group":"autoscaling","version":"v1","kind":"Scale"},
                "requestResource": {"group":"apps","version":"v1","resource":"deployments"},
                "requestSubResource": "scale",
                "name": "my-deployment",
                "namespace": "my-namespace",
                "operation": "UPDATE",
                "userInfo": {
                  "username": "admin",
                  "uid": "014fbff9a07c",
                  "groups": ["system:authenticated","my-admin-group"],
                  "extra": {
                    "some-key":["some-value1", "some-value2"]
                  }
                },
                "object": {"apiVersion":"autoscaling/v1","kind":"Scale"},
                "oldObject": {"apiVersion":"autoscaling/v1","kind":"Scale"},
                "options": {"apiVersion":"meta.k8s.io/v1","kind":"UpdateOptions"},
                "dryRun": false
            }
        "#;

        let admission_request: AdmissionRequest =
            serde_json::from_str(input).expect("deserialization should work");

        ValidateRequest::AdmissionRequest(admission_request)
    }

    /// build a precompiled policy of the given wasm module. Assumes this is a OPA Gatekeeper policy
    fn build_precompiled_policy(policy_contents: &[u8]) -> PolicyEvaluatorPre {
        let builder = PolicyEvaluatorBuilder::new()
            .engine(ENGINE.clone())
            .policy_contents(policy_contents)
            .execution_mode(crate::policy_evaluator::PolicyExecutionMode::OpaGatekeeper);
        builder.build_pre().unwrap()
    }

    #[rstest]
    #[case::all_policies_are_evaluated(
        "unhappy_policy_1() || (happy_policy_1() && unhappy_policy_2())",
        vec![
            ("unhappy_policy_1".to_string(), POLICY_ALWAYS_UNHAPPY.clone()),
            ("happy_policy_1".to_string(), POLICY_ALWAYS_HAPPY.clone()),
            ("unhappy_policy_2".to_string(), POLICY_ALWAYS_UNHAPPY.clone())
        ].into_iter().collect(),
        false,
        vec![
            admission_response::StatusCause {
                field: Some("spec.policies.unhappy_policy_1".to_string()),
                message: Some("failing as expected".to_string()),
                ..Default::default()
            },
            admission_response::StatusCause {
                field: Some("spec.policies.unhappy_policy_2".to_string()),
                message: Some("failing as expected".to_string()),
                ..Default::default()
            },
        ]
    )]
    #[case::not_all_policies_are_evaluated(
        "unhappy_policy_1() || happy_policy_1() || unhappy_policy_2()",
        vec![
            ("unhappy_policy_1".to_string(), POLICY_ALWAYS_UNHAPPY.clone()),
            ("happy_policy_1".to_string(), POLICY_ALWAYS_HAPPY.clone()),
            ("unhappy_policy_2".to_string(), POLICY_ALWAYS_UNHAPPY.clone())
        ].into_iter().collect(),
        true,
        Vec::new(), // no expected causes, since the request is accepted
    )]
    fn group_policy_warning_assignments(
        #[case] expression: &str,
        #[case] policies: HashMap<String, PolicyEvaluatorPre>,
        #[case] admission_accepted: bool,
        #[case] expected_status_causes: Vec<admission_response::StatusCause>,
    ) {
        let mut policy_group_evaluator =
            PolicyGroupEvaluator::new("group_policy", "something went wrong", expression, None);
        for (policy_id, policy_pre) in policies {
            policy_group_evaluator.add_policy_member(
                &policy_id,
                Arc::new(policy_pre),
                PolicyGroupMemberSettings {
                    settings: Default::default(),
                    ctx_aware_resources_allow_list: Default::default(),
                },
            );
        }
        let validate_request = build_validate_request();

        let policy_group_evaluator = Arc::new(policy_group_evaluator);

        let response = policy_group_evaluator.validate(&validate_request);
        assert_eq!(response.allowed, admission_accepted);
        assert_eq!(response.warnings, None);

        if admission_accepted {
            assert!(response.status.is_none());
        } else {
            let causes = response
                .status
                .expect("should have status")
                .details
                .expect("should have details")
                .causes;
            for expected in expected_status_causes {
                assert!(
                    causes.iter().any(|c| *c == expected),
                    "could not find cause {:?}",
                    expected
                );
            }
        }
    }

    #[rstest]
    #[case::valid_expression_with_single_policy(
        "true || happy_policy_1()",
        vec![
            ("happy_policy_1".to_string(), POLICY_ALWAYS_HAPPY.clone()),
        ].into_iter().collect(),
        true
    )]
    #[case::valid_expression_with_just_rhai("2 > 1", HashMap::new(), true)]
    #[case::not_valid_expression_because_of_unregistered_function(
        "unknown_policy() || happy_policy_1()",
        vec![
            ("happy_policy_1".to_string(), POLICY_ALWAYS_HAPPY.clone()),
        ].into_iter().collect(),
        false
    )]
    #[case::not_valid_expression_because_of_typos(
        "something that does not make sense",
        HashMap::new(),
        false
    )]
    #[case::not_valid_expression_because_doing_operations_with_booleans_is_wrong(
        "1 + 1",
        HashMap::new(),
        false
    )]
    #[case::not_valid_expression_because_does_not_return_boolean(
        "happy_policy_1() + 1",
        vec![
            ("happy_policy_1".to_string(), POLICY_ALWAYS_HAPPY.clone()),
        ].into_iter().collect(),
        false
    )]
    fn validate_policy_settings_of_policy_group(
        #[case] expression: &str,
        #[case] policies: HashMap<String, PolicyEvaluatorPre>,
        #[case] expression_is_valid: bool,
    ) {
        let mut policy_group_evaluator =
            PolicyGroupEvaluator::new("group_policy", "something went wrong", expression, None);
        for (policy_id, policy_pre) in policies {
            policy_group_evaluator.add_policy_member(
                &policy_id,
                Arc::new(policy_pre),
                PolicyGroupMemberSettings {
                    settings: Default::default(),
                    ctx_aware_resources_allow_list: Default::default(),
                },
            );
        }
        let validation_result = policy_group_evaluator.validate_settings();

        assert_eq!(expression_is_valid, validation_result.valid);
    }
}
