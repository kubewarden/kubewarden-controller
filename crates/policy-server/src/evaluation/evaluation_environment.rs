use std::{
    collections::{BTreeSet, HashMap, HashSet},
    fmt,
    sync::Arc,
};

use policy_evaluator::{
    admission_response::AdmissionResponse,
    admission_response_handler::{
        errors::{EvaluationError, Result},
        policy_id::PolicyID,
        policy_mode::PolicyMode,
    },
    callback_requests::CallbackRequest,
    evaluation_context::EvaluationContext,
    kubewarden_policy_sdk::settings::SettingsValidationResponse,
    policy_evaluator::{PolicyEvaluator, PolicyEvaluatorPre, PolicyExecutionMode, ValidateRequest},
    policy_evaluator_builder::PolicyEvaluatorBuilder,
    policy_group_evaluator::{evaluator::PolicyGroupEvaluator, PolicyGroupMemberSettings},
    policy_metadata::ContextAwareResource,
    wasmtime,
};
use tokio::sync::mpsc;
use tracing::debug;

use crate::{
    config::{PolicyOrPolicyGroup, PolicyOrPolicyGroupSettings},
    evaluation::{
        policy_evaluation_settings::PolicyEvaluationSettings,
        precompiled_policy::{PrecompiledPolicies, PrecompiledPolicy},
    },
};

#[cfg(test)]
use mockall::automock;

/// This holds the a summary of the evaluation results of a policy group member
struct PolicyGroupMemberEvaluationResult {
    /// whether the request is allowed or not
    allowed: bool,
    /// the optional message included inside of the evaluation result of the policy
    message: Option<String>,
}

impl From<AdmissionResponse> for PolicyGroupMemberEvaluationResult {
    fn from(response: AdmissionResponse) -> Self {
        Self {
            allowed: response.allowed,
            message: response.status.and_then(|status| status.message),
        }
    }
}

impl fmt::Display for PolicyGroupMemberEvaluationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.allowed {
            write!(f, "[ALLOWED]")?;
        } else {
            write!(f, "[DENIED]")?;
        }
        if let Some(message) = &self.message {
            write!(f, " - {}", message)?;
        }

        Ok(())
    }
}

/// The digest of a WebAssembly module
type ModuleDigest = String;

/// This structure contains all the policies defined by the user inside of the `policies.yml`.
/// It also provides helper methods to perform the validation of a request and the validation
/// of the settings provided by the user.
///
/// This is an immutable structure that can be safely shared across different threads once wrapped
/// inside of a `Arc`.
///
/// When performing a `validate` or `validate_settings` operation, a new WebAssembly environment is
/// created and used to perform the operation. The environment is then discarded once the
/// evaluation is over.
/// This ensures:
/// - no memory leaks caused by bogus policies affect the Policy Server long running process
/// - no data is shared between evaluations of the same module
///
/// To reduce the creation time, this code makes use of `PolicyEvaluatorPre` which are created
/// only once, during the bootstrap phase.
#[derive(Default)]
pub(crate) struct EvaluationEnvironment {
    /// The name of the Namespace where Policy Server doesn't operate. All the requests
    /// involving this Namespace are going to be accepted. This is usually done to prevent user
    /// policies from messing with the components of the Kubewarden stack (which are all
    /// deployed inside of the same Namespace).
    always_accept_admission_reviews_on_namespace: Option<String>,

    /// A map with the module digest as key, and the associated `PolicyEvaluatorPre`
    /// as value
    ///
    /// Note: the `PolicyEvaluatorPre` is wrapped into an `Arc` to allow cheap cloning
    /// when it's being used inside of a `GroupPolicyEvaluator`.
    /// We have to use an `Arc` instead of a `Rc` because rhai (used by the `PolicyGroupEvaluator`)
    /// requires `+send` and `+sync`.
    module_digest_to_policy_evaluator_pre: HashMap<ModuleDigest, Arc<PolicyEvaluatorPre>>,

    /// A map with the ID of the policy as value, and the list of ContextAwareResource the
    /// policy is allowed to access.
    policy_id_to_ctx_aware_allowed_resources: HashMap<PolicyID, BTreeSet<ContextAwareResource>>,

    /// Map a `policy_id` to the module's digest.
    /// This allows us to deduplicate the Wasm modules defined by the user.
    policy_id_to_module_digest: HashMap<PolicyID, ModuleDigest>,

    /// Map a `policy_id` to the `PolicyEvaluationSettings` instance. This allows us to obtain
    /// the list of settings to be used when evaluating a given policy.
    policy_id_to_settings: HashMap<PolicyID, PolicyEvaluationSettings>,

    /// A map with the policy ID as key, and the error message as value.
    /// This is used to store the errors that occurred during policies initialization.
    /// The errors can occur in the fetching of the policy, or in the validation of the settings.
    policy_initialization_errors: HashMap<PolicyID, String>,

    /// A Set containing the IDs of the policy groups.
    policy_groups: HashSet<PolicyID>,

    /// Channel used by the synchronous world (like the `host_callback` waPC function,
    /// but also Burrego for k8s context aware data),
    /// to request the computation of code that can only be run inside of an
    /// asynchronous block
    callback_handler_tx: Option<mpsc::Sender<CallbackRequest>>,
}

/// This structure is used to build the `EvaluationEnvironment` instance.
pub(crate) struct EvaluationEnvironmentBuilder<'engine, 'precompiled_policies> {
    engine: &'engine wasmtime::Engine,
    precompiled_policies: &'precompiled_policies PrecompiledPolicies,
    callback_handler_tx: mpsc::Sender<CallbackRequest>,
    continue_on_errors: bool,
    policy_evaluation_limit_seconds: Option<u64>,
    always_accept_admission_reviews_on_namespace: Option<String>,
}

impl<'engine, 'precompiled_policies> EvaluationEnvironmentBuilder<'engine, 'precompiled_policies> {
    /// Prepare a new `EvaluationEnvironmentBuilder` instance.
    pub fn new(
        engine: &'engine wasmtime::Engine,
        precompiled_policies: &'precompiled_policies PrecompiledPolicies,
        callback_handler_tx: mpsc::Sender<CallbackRequest>,
    ) -> Self {
        EvaluationEnvironmentBuilder {
            engine,
            precompiled_policies,
            callback_handler_tx,
            continue_on_errors: false,
            policy_evaluation_limit_seconds: None,
            always_accept_admission_reviews_on_namespace: None,
        }
    }

    /// Enable policy evaluatation timeout feature
    pub fn with_policy_evaluation_limit_seconds(
        mut self,
        policy_evaluation_limit_seconds: u64,
    ) -> Self {
        self.policy_evaluation_limit_seconds = Some(policy_evaluation_limit_seconds);
        self
    }

    /// Do not fail when a policy initialization error occurs
    pub fn with_continue_on_errors(mut self, continue_on_errors: bool) -> Self {
        self.continue_on_errors = continue_on_errors;
        self
    }

    /// Set the namespace where all the requests are going to be accepted
    pub fn with_always_accept_admission_reviews_on_namespace(mut self, namespace: String) -> Self {
        self.always_accept_admission_reviews_on_namespace = Some(namespace);
        self
    }

    // Because of automock, we have to provide a tailored build method between test and production
    // code
    #[cfg(test)]
    pub fn build(
        &self,
        _policies: &HashMap<String, PolicyOrPolicyGroup>,
    ) -> Result<MockEvaluationEnvironment> {
        Ok(MockEvaluationEnvironment::new())
    }

    /// Build the `EvaluationEnvironment` instance
    #[cfg(not(test))]
    pub fn build(
        &self,
        policies: &HashMap<String, PolicyOrPolicyGroup>,
    ) -> Result<EvaluationEnvironment> {
        self.build_evaluation_environment(policies)
    }

    /// Internal method to build the `EvaluationEnvironment` instance that is used by production
    /// code. We need this method inside of the unit tests
    fn build_evaluation_environment(
        &self,
        policies: &HashMap<String, PolicyOrPolicyGroup>,
    ) -> Result<EvaluationEnvironment> {
        let mut eval_env = EvaluationEnvironment {
            always_accept_admission_reviews_on_namespace: self
                .always_accept_admission_reviews_on_namespace
                .clone(),
            callback_handler_tx: Some(self.callback_handler_tx.clone()),
            ..Default::default()
        };

        for (policy_name, policy) in policies {
            // there's no way to recover from a parse error, so we just return it
            let id: PolicyID = policy_name.parse()?;

            let settings = match policy.settings() {
                Ok(s) => s,
                Err(e) => {
                    if !self.continue_on_errors {
                        return Err(EvaluationError::BootstrapFailure(format!(
                            "cannot extract settings from policy: {e}"
                        )));
                    }
                    eval_env
                        .policy_initialization_errors
                        .insert(id.to_owned(), e.to_string());
                    continue;
                }
            };

            match policy {
                PolicyOrPolicyGroup::Policy {
                    module: url,
                    policy_mode,
                    message,
                    allowed_to_mutate,
                    context_aware_resources,
                    ..
                } => {
                    let policy_evaluation_settings = PolicyEvaluationSettings {
                        policy_mode: policy_mode.to_owned(),
                        allowed_to_mutate: allowed_to_mutate.unwrap_or(false),
                        settings,
                        custom_rejection_message: message.clone(),
                    };

                    let eval_ctx = EvaluationContext {
                        policy_id: id.to_string(),
                        callback_channel: Some(self.callback_handler_tx.clone()),
                        ctx_aware_resources_allow_list: context_aware_resources.to_owned(),
                    };

                    if let Err(e) = self.bootstrap_policy(
                        &mut eval_env,
                        id.clone(),
                        url,
                        policy_evaluation_settings,
                        eval_ctx,
                    ) {
                        if !self.continue_on_errors {
                            return Err(e);
                        }
                        eval_env
                            .policy_initialization_errors
                            .insert(id.to_owned(), e.to_string());
                        continue;
                    }
                }
                PolicyOrPolicyGroup::PolicyGroup {
                    policy_mode,
                    policies,
                    ..
                } => {
                    let policy_evaluation_settings = PolicyEvaluationSettings {
                        policy_mode: policy_mode.to_owned(),
                        allowed_to_mutate: false, // Group policies are not allowed to mutate
                        custom_rejection_message: None,
                        settings,
                    };
                    eval_env.register_policy_group(&id, policy_evaluation_settings);

                    for (policy_name, policy) in policies {
                        let policy_id = PolicyID::PolicyGroupPolicy {
                            group: id.to_string(),
                            name: policy_name.clone(),
                        };
                        let settings = match policy.settings() {
                            Ok(s) => s,
                            Err(e) => {
                                if !self.continue_on_errors {
                                    return Err(EvaluationError::BootstrapFailure(format!(
                                        "cannot extract settings from policy: {e}"
                                    )));
                                }
                                eval_env
                                    .policy_initialization_errors
                                    .insert(policy_id, e.to_string());
                                continue;
                            }
                        };

                        let policy_evaluation_settings = PolicyEvaluationSettings {
                            policy_mode: PolicyMode::Protect,
                            allowed_to_mutate: false,
                            settings,
                            custom_rejection_message: None,
                        };

                        let eval_ctx = EvaluationContext {
                            policy_id: policy_id.to_string(),
                            callback_channel: Some(self.callback_handler_tx.clone()),
                            ctx_aware_resources_allow_list: policy
                                .context_aware_resources
                                .to_owned(),
                        };

                        if let Err(e) = self.bootstrap_policy(
                            &mut eval_env,
                            policy_id.clone(),
                            &policy.module,
                            policy_evaluation_settings,
                            eval_ctx,
                        ) {
                            if !self.continue_on_errors {
                                return Err(e);
                            }
                            eval_env
                                .policy_initialization_errors
                                .insert(policy_id, e.to_string());
                            continue;
                        }
                    }
                }
            }
        }

        Ok(eval_env)
    }

    /// Internal method used to bootstrap a policy. The policy is either a single policy or a
    /// children of a policy group.
    fn bootstrap_policy(
        &self,
        eval_env: &mut EvaluationEnvironment,
        id: PolicyID,
        url: &str,
        policy_evaluation_settings: PolicyEvaluationSettings,
        eval_ctx: EvaluationContext,
    ) -> Result<()> {
        let precompiled_policy = self
            .precompiled_policies
            .get(url)
            .ok_or_else(|| {
                EvaluationError::BootstrapFailure(format!("cannot find precompiled policy of {id}"))
            })?
            .as_ref()
            .map_err(|e| EvaluationError::BootstrapFailure(format!("{id}: {e}")))?;

        eval_env
            .register(
                self.engine,
                &id,
                policy_evaluation_settings,
                eval_ctx,
                precompiled_policy,
                self.policy_evaluation_limit_seconds,
            )
            .map_err(|e| EvaluationError::BootstrapFailure(e.to_string()))?;

        eval_env.validate_settings(&id)
    }
}

#[cfg_attr(test, automock)]
#[cfg_attr(test, allow(dead_code))]
impl EvaluationEnvironment {
    /// Returns `true` if the given `namespace` is the special Namespace that is ignored by all
    /// the policies
    pub(crate) fn should_always_accept_requests_made_inside_of_namespace(
        &self,
        namespace: &str,
    ) -> bool {
        self.always_accept_admission_reviews_on_namespace.as_deref() == Some(namespace)
    }

    /// Register a new policy. It takes care of creating a new `PolicyEvaluator` (when needed).
    /// This is used to register both individual policies and the ones that are part of a group
    /// policy.
    ///
    /// Params:
    /// - `engine`: the `wasmtime::Engine` to be used when creating the `PolicyEvaluator`
    /// - `policy_id`: the unique identifier of the policy
    /// - `policy_evaluation_settings`: the settings associated with the policy
    /// - `precompiled_policy`: the `PrecompiledPolicy` associated with the Wasm module referenced by the policy
    /// - `callback_handler_tx`: the transmission end of a channel that connects the worker with the asynchronous world
    /// - `policy_evaluation_limit_seconds`: when set, defines after how many seconds the policy evaluation is interrupted
    fn register(
        &mut self,
        engine: &wasmtime::Engine,
        policy_id: &PolicyID,
        policy_evaluation_settings: PolicyEvaluationSettings,
        eval_ctx: EvaluationContext,
        precompiled_policy: &PrecompiledPolicy,
        policy_evaluation_limit_seconds: Option<u64>,
    ) -> Result<()> {
        let module_digest = &precompiled_policy.digest;

        if !self
            .module_digest_to_policy_evaluator_pre
            .contains_key(module_digest)
        {
            debug!(?policy_id, "create wasmtime::Module");
            let module = create_wasmtime_module(policy_id, engine, precompiled_policy)?;
            debug!(?policy_id, "create PolicyEvaluatorPre");
            let pol_eval_pre = create_policy_evaluator_pre(
                engine,
                &module,
                precompiled_policy.execution_mode,
                policy_evaluation_limit_seconds,
            )?;

            self.module_digest_to_policy_evaluator_pre
                .insert(module_digest.to_owned(), Arc::new(pol_eval_pre));
        }
        self.policy_id_to_module_digest
            .insert(policy_id.to_owned(), module_digest.to_owned());

        self.policy_id_to_settings
            .insert(policy_id.to_owned(), policy_evaluation_settings);

        self.policy_id_to_ctx_aware_allowed_resources.insert(
            policy_id.to_owned(),
            eval_ctx.ctx_aware_resources_allow_list,
        );

        Ok(())
    }

    /// Register a policy group
    fn register_policy_group(
        &mut self,
        policy_id: &PolicyID,
        policy_evaluation_settings: PolicyEvaluationSettings,
    ) {
        self.policy_id_to_settings
            .insert(policy_id.to_owned(), policy_evaluation_settings);
        self.policy_groups.insert(policy_id.to_owned());
    }

    /// Given a policy ID, return how the policy operates
    pub(crate) fn get_policy_mode(&self, policy_id: &PolicyID) -> Result<PolicyMode> {
        self.policy_id_to_settings
            .get(policy_id)
            .map(|settings| settings.policy_mode.clone())
            .ok_or(EvaluationError::PolicyNotFound(policy_id.to_string()))
    }

    /// Given a policy ID, return how the policy custom reject message
    pub(crate) fn get_policy_custom_rejection_message(
        &self,
        policy_id: &PolicyID,
    ) -> Result<Option<String>> {
        self.policy_id_to_settings
            .get(policy_id)
            .map(|settings| settings.custom_rejection_message.clone())
            .ok_or(EvaluationError::PolicyNotFound(policy_id.to_string()))
    }

    /// Given a policy ID, returns true if the policy is allowed to mutate
    pub(crate) fn get_policy_allowed_to_mutate(&self, policy_id: &PolicyID) -> Result<bool> {
        self.policy_id_to_settings
            .get(policy_id)
            .map(|settings| settings.allowed_to_mutate)
            .ok_or(EvaluationError::PolicyNotFound(policy_id.to_string()))
    }

    /// Given a policy ID, returns the settings provided by the user inside of `policies.yml`
    fn get_policy_settings(&self, policy_id: &PolicyID) -> Result<PolicyEvaluationSettings> {
        let settings = self
            .policy_id_to_settings
            .get(policy_id)
            .ok_or(EvaluationError::PolicyNotFound(policy_id.to_string()))?
            .clone();

        Ok(settings)
    }

    /// Validate the settings the user provided for the given policy
    fn validate_settings(&mut self, policy_id: &PolicyID) -> Result<()> {
        let settings = self.get_policy_settings(policy_id)?;

        match &settings.settings {
            PolicyOrPolicyGroupSettings::Policy(settings) => {
                let mut evaluator = self.rehydrate(policy_id)?;
                match evaluator.validate_settings(settings) {
                    SettingsValidationResponse {
                        valid: true,
                        message: _,
                    } => {}
                    SettingsValidationResponse {
                        valid: false,
                        message,
                    } => {
                        let error_message = format!(
                            "Policy settings are invalid: {}",
                            message.unwrap_or("no message".to_owned())
                        );

                        return Err(EvaluationError::PolicyInitialization(error_message));
                    }
                };
            }
            PolicyOrPolicyGroupSettings::PolicyGroup { .. } => {
                let group_evaluator = self.build_policy_group_evaluator(policy_id)?;
                let validation_result = group_evaluator.validate_settings();
                if !validation_result.valid {
                    return Err(EvaluationError::PolicyInitialization(
                        validation_result
                            .message
                            .unwrap_or(format!("{} settings are not valid", policy_id)),
                    ));
                }
            }
        }

        Ok(())
    }

    /// Internal method, create a `PolicyEvaluator` by using a pre-initialized instance
    fn rehydrate(&self, policy_id: &PolicyID) -> Result<PolicyEvaluator> {
        if self.policy_groups.contains(policy_id) {
            return Err(EvaluationError::CannotRehydratePolicyGroup(
                policy_id.to_string(),
            ));
        }

        let module_digest = self
            .policy_id_to_module_digest
            .get(policy_id)
            .ok_or(EvaluationError::PolicyNotFound(policy_id.to_string()))?;
        let policy_evaluator_pre = self
            .module_digest_to_policy_evaluator_pre
            .get(module_digest)
            .ok_or(EvaluationError::PolicyNotFound(policy_id.to_string()))?;

        let ctx_aware_resources_allow_list = self
            .policy_id_to_ctx_aware_allowed_resources
            .get(policy_id)
            .ok_or(EvaluationError::PolicyNotFound(policy_id.to_string()))?;

        let eval_ctx = EvaluationContext {
            policy_id: policy_id.to_string(),
            callback_channel: self.callback_handler_tx.clone(),
            ctx_aware_resources_allow_list: ctx_aware_resources_allow_list.clone(),
        };

        policy_evaluator_pre.rehydrate(&eval_ctx).map_err(|e| {
            EvaluationError::WebAssemblyError(format!("cannot rehydrate PolicyEvaluatorPre: {e}"))
        })
    }

    /// Perform a request validation
    pub fn validate(
        &self,
        policy_id: &PolicyID,
        req: &ValidateRequest,
    ) -> Result<AdmissionResponse> {
        if self.policy_groups.contains(policy_id) {
            self.validate_policy_group(policy_id, req)
        } else {
            self.validate_policy(policy_id, req)
        }
    }

    /// Validate a policy.
    ///
    /// Note, `self` is wrapped inside of `Arc` because this method is called from within a Rhai engine closure that
    /// requires `+send` and `+sync`.
    fn validate_policy(
        &self,
        policy_id: &PolicyID,
        req: &ValidateRequest,
    ) -> Result<AdmissionResponse> {
        debug!(?policy_id, "validate individual policy");

        if let Some(error) = self.policy_initialization_errors.get(policy_id) {
            return Err(EvaluationError::PolicyInitialization(error.to_string()));
        }

        let settings = match self.get_policy_settings(policy_id)?.settings {
            PolicyOrPolicyGroupSettings::Policy(settings) => settings,
            _ => unreachable!(),
        };
        let mut evaluator = self.rehydrate(policy_id)?;

        Ok(evaluator.validate(req.clone(), &settings))
    }

    /// Validate a policy group
    ///
    /// Note, `self` is wrapped inside of `Arc` because the Rhai engine closure requires
    /// `+send` and `+sync`.
    fn validate_policy_group(
        &self,
        policy_id: &PolicyID,
        req: &ValidateRequest,
    ) -> Result<AdmissionResponse> {
        let group_evaluator = Arc::new(self.build_policy_group_evaluator(policy_id)?);
        Ok(group_evaluator.validate(req))
    }

    fn build_policy_group_evaluator(&self, policy_id: &PolicyID) -> Result<PolicyGroupEvaluator> {
        let (expression, message, policies) = match self.get_policy_settings(policy_id)?.settings {
            PolicyOrPolicyGroupSettings::PolicyGroup {
                expression,
                message,
                policies,
            } => (expression, message, policies),
            _ => unreachable!(),
        };

        let mut evaluator = PolicyGroupEvaluator::new(
            &policy_id.to_string(),
            &message,
            &expression,
            self.callback_handler_tx.clone(),
        );

        for sub_policy_name in policies {
            let policy_id = PolicyID::PolicyGroupPolicy {
                group: policy_id.to_string(),
                name: sub_policy_name.clone(),
            };
            let module_digest = self
                .policy_id_to_module_digest
                .get(&policy_id)
                .ok_or(EvaluationError::PolicyNotFound(policy_id.to_string()))?;
            let policy_evaluator_pre = self
                .module_digest_to_policy_evaluator_pre
                .get(module_digest)
                .ok_or(EvaluationError::PolicyNotFound(policy_id.to_string()))?;

            let ctx_aware_resources_allow_list = self
                .policy_id_to_ctx_aware_allowed_resources
                .get(&policy_id)
                .ok_or(EvaluationError::PolicyNotFound(policy_id.to_string()))?;

            let settings = match self.get_policy_settings(&policy_id)?.settings {
                PolicyOrPolicyGroupSettings::Policy(settings) => settings,
                _ => unreachable!(),
            };

            let policy_group_member_settings = PolicyGroupMemberSettings {
                settings,
                ctx_aware_resources_allow_list: ctx_aware_resources_allow_list.clone(),
            };

            evaluator.add_policy_member(
                &sub_policy_name,
                policy_evaluator_pre.clone(),
                policy_group_member_settings,
            );
        }

        Ok(evaluator)
    }
}

fn create_wasmtime_module(
    policy_id: &PolicyID,
    engine: &wasmtime::Engine,
    precompiled_policy: &PrecompiledPolicy,
) -> Result<wasmtime::Module> {
    // See `wasmtime::Module::deserialize` to know why this method is `unsafe`.
    // However, in our context, nothing bad will happen because we have
    // full control of the precompiled module. This is generated by the
    // WorkerPool thread
    unsafe { wasmtime::Module::deserialize(engine, &precompiled_policy.precompiled_module) }
        .map_err(|e| {
            EvaluationError::WebAssemblyError(format!(
                "could not rehydrate wasmtime::Module {policy_id}: {e:?}"
            ))
        })
}

/// Internal function, takes care of creating the `PolicyEvaluator` instance for the given policy
fn create_policy_evaluator_pre(
    engine: &wasmtime::Engine,
    module: &wasmtime::Module,
    mode: PolicyExecutionMode,
    policy_evaluation_limit_seconds: Option<u64>,
) -> Result<PolicyEvaluatorPre> {
    let mut policy_evaluator_builder = PolicyEvaluatorBuilder::new()
        .engine(engine.to_owned())
        .policy_module(module.to_owned())
        .execution_mode(mode);

    if let Some(limit) = policy_evaluation_limit_seconds {
        policy_evaluator_builder =
            policy_evaluator_builder.enable_epoch_interruptions(limit, limit);
    }

    policy_evaluator_builder.build_pre().map_err(|e| {
        EvaluationError::WebAssemblyError(format!("cannot build PolicyEvaluatorPre {e}"))
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use policy_evaluator::{admission_response, policy_evaluator::ValidateRequest};
    use rstest::*;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::config::{PolicyGroupMember, PolicyOrPolicyGroup};
    use crate::test_utils::build_admission_review_request;

    /// build a precompiled policy of the given wasm module. Assumes this is a OPA Gatekeeper policy
    fn build_precompiled_policy(
        engine: &wasmtime::Engine,
        module_bytes: &[u8],
    ) -> PrecompiledPolicy {
        let module = wasmtime::Module::new(engine, module_bytes)
            .expect("should be able to build the smallest wasm module ever");

        // calculate the digest of the module using sha256
        let mut hasher = Sha256::new();
        hasher.update(module_bytes);
        let digest = hasher.finalize();

        PrecompiledPolicy {
            precompiled_module: module.serialize().unwrap(),
            execution_mode: policy_evaluator::policy_evaluator::PolicyExecutionMode::OpaGatekeeper,
            digest: format!("{digest:x}"),
        }
    }

    fn build_evaluation_environment() -> EvaluationEnvironment {
        let engine = wasmtime::Engine::default();
        let module_bytes_always_happy =
            include_bytes!("../../tests/data/gatekeeper_always_happy_policy.wasm");
        let module_bytes_always_unhappy =
            include_bytes!("../../tests/data/gatekeeper_always_unhappy_policy.wasm");

        let (callback_handler_tx, _) = mpsc::channel(10);

        let precompiled_policy_happy = build_precompiled_policy(&engine, module_bytes_always_happy);
        let precompiled_policy_unhappy =
            build_precompiled_policy(&engine, module_bytes_always_unhappy);

        let test_policies: HashMap<String, PrecompiledPolicy> = vec![
            (
                "happy_policy_1".to_string(),
                precompiled_policy_happy.clone(),
            ),
            (
                "happy_policy_2".to_string(),
                precompiled_policy_happy.clone(),
            ),
            (
                "unhappy_policy_1".to_string(),
                precompiled_policy_unhappy.clone(),
            ),
        ]
        .into_iter()
        .collect();

        let mut policies: HashMap<String, crate::config::PolicyOrPolicyGroup> = HashMap::new();
        let mut precompiled_policies: PrecompiledPolicies = PrecompiledPolicies::new();

        for (policy_id, precompiled_policy) in &test_policies {
            let policy_url = format!("file:///tmp/{policy_id}.wasm");
            policies.insert(
                policy_id.to_string(),
                PolicyOrPolicyGroup::Policy {
                    module: policy_url.clone(),
                    policy_mode: PolicyMode::Protect,
                    allowed_to_mutate: None,
                    settings: None,
                    context_aware_resources: BTreeSet::new(),
                    message: None,
                },
            );
            precompiled_policies.insert(policy_url, Ok(precompiled_policy.clone()));
        }

        // add policy group policies
        policies.insert(
            "group_policy_valid_expression_with_single_member".to_string(),
            PolicyOrPolicyGroup::PolicyGroup {
                policy_mode: PolicyMode::Protect,
                policies: vec![(
                    "happy_policy_1".to_string(),
                    PolicyGroupMember {
                        module: "file:///tmp/happy_policy_1.wasm".to_string(),
                        settings: None,
                        context_aware_resources: BTreeSet::new(),
                    },
                )]
                .into_iter()
                .collect(),
                expression: "true || happy_policy_1()".to_string(),
                message: "something went wrong".to_string(),
            },
        );
        policies.insert(
            "group_policy_valid_expression_just_rhai".to_string(),
            PolicyOrPolicyGroup::PolicyGroup {
                policy_mode: PolicyMode::Protect,
                expression: "2 > 1".to_string(),
                message: "something went wrong".to_string(),
                policies: HashMap::new(),
            },
        );
        policies.insert(
            "group_policy_not_valid_expression_because_of_unregistered_function".to_string(),
            PolicyOrPolicyGroup::PolicyGroup {
                policy_mode: PolicyMode::Protect,
                policies: vec![(
                    "happy_policy_1".to_string(),
                    PolicyGroupMember {
                        module: "file:///tmp/happy_policy_1.wasm".to_string(),
                        settings: None,
                        context_aware_resources: BTreeSet::new(),
                    },
                )]
                .into_iter()
                .collect(),
                expression: "unknown_policy() || happy_policy_1()".to_string(),
                message: "something went wrong".to_string(),
            },
        );
        policies.insert(
            "group_policy_not_valid_expression_because_of_typos".to_string(),
            PolicyOrPolicyGroup::PolicyGroup {
                policy_mode: PolicyMode::Protect,
                expression: "something that doesn't make sense".to_string(),
                message: "something went wrong".to_string(),
                policies: HashMap::new(),
            },
        );
        policies.insert(
            "group_policy_not_valid_expression_because_of_does_not_return_boolean".to_string(),
            PolicyOrPolicyGroup::PolicyGroup {
                policy_mode: PolicyMode::Protect,
                expression: "1 + 1".to_string(),
                message: "something went wrong".to_string(),
                policies: HashMap::new(),
            },
        );
        policies.insert(
            "group_policy_not_valid_expression_because_doing_operations_with_booleans_is_wrong"
                .to_string(),
            PolicyOrPolicyGroup::PolicyGroup {
                policy_mode: PolicyMode::Protect,
                policies: vec![(
                    "happy_policy_1".to_string(),
                    PolicyGroupMember {
                        module: "file:///tmp/happy_policy_1.wasm".to_string(),
                        settings: None,
                        context_aware_resources: BTreeSet::new(),
                    },
                )]
                .into_iter()
                .collect(),
                expression: "happy_policy_1() + 1".to_string(),
                message: "something went wrong".to_string(),
            },
        );
        policies.insert(
            "group_policy_with_unhappy_or_bracket_happy_and_unhappy_bracket".to_string(),
            PolicyOrPolicyGroup::PolicyGroup {
                policy_mode: PolicyMode::Protect,
                policies: vec![
                    (
                        "happy_policy_1".to_string(),
                        PolicyGroupMember {
                            module: "file:///tmp/happy_policy_1.wasm".to_string(),
                            settings: None,
                            context_aware_resources: BTreeSet::new(),
                        },
                    ),
                    (
                        "unhappy_policy_1".to_string(),
                        PolicyGroupMember {
                            module: "file:///tmp/unhappy_policy_1.wasm".to_string(),
                            settings: None,
                            context_aware_resources: BTreeSet::new(),
                        },
                    ),
                    (
                        "unhappy_policy_2".to_string(),
                        PolicyGroupMember {
                            module: "file:///tmp/unhappy_policy_1.wasm".to_string(),
                            settings: None,
                            context_aware_resources: BTreeSet::new(),
                        },
                    ),
                ]
                .into_iter()
                .collect(),
                expression: "unhappy_policy_1() || (happy_policy_1() && unhappy_policy_2())"
                    .to_string(),
                message: "something went wrong".to_string(),
            },
        );

        policies.insert(
            "group_policy_with_unhappy_or_happy_or_unhappy".to_string(),
            PolicyOrPolicyGroup::PolicyGroup {
                policy_mode: PolicyMode::Protect,
                policies: vec![
                    (
                        "happy_policy_1".to_string(),
                        PolicyGroupMember {
                            module: "file:///tmp/happy_policy_1.wasm".to_string(),
                            settings: None,
                            context_aware_resources: BTreeSet::new(),
                        },
                    ),
                    (
                        "unhappy_policy_1".to_string(),
                        PolicyGroupMember {
                            module: "file:///tmp/unhappy_policy_1.wasm".to_string(),
                            settings: None,
                            context_aware_resources: BTreeSet::new(),
                        },
                    ),
                    (
                        "unhappy_policy_2".to_string(),
                        PolicyGroupMember {
                            module: "file:///tmp/unhappy_policy_1.wasm".to_string(),
                            settings: None,
                            context_aware_resources: BTreeSet::new(),
                        },
                    ),
                ]
                .into_iter()
                .collect(),
                expression: "unhappy_policy_1() || happy_policy_1() || unhappy_policy_2()"
                    .to_string(),
                message: "something went wrong".to_string(),
            },
        );

        let eval_env_builder =
            EvaluationEnvironmentBuilder::new(&engine, &precompiled_policies, callback_handler_tx);
        eval_env_builder
            .build_evaluation_environment(&policies)
            .unwrap()
    }

    #[rstest]
    #[case::policy_not_defined("policy_not_defined", true)]
    #[case::policy_known("happy_policy_1", false)]
    fn lookup_policy(#[case] policy_id: &str, #[case] expect_error: bool) {
        let policy_id = PolicyID::Policy(policy_id.to_string());
        let evaluation_environment = Arc::new(build_evaluation_environment());
        let validate_request =
            ValidateRequest::AdmissionRequest(Box::new(build_admission_review_request().request));

        if expect_error {
            assert!(matches!(
                evaluation_environment.get_policy_mode(&policy_id),
                Err(EvaluationError::PolicyNotFound(_))
            ));
            assert!(matches!(
                evaluation_environment.get_policy_allowed_to_mutate(&policy_id),
                Err(EvaluationError::PolicyNotFound(_))
            ));
            assert!(matches!(
                evaluation_environment.get_policy_settings(&policy_id),
                Err(EvaluationError::PolicyNotFound(_))
            ));
            assert!(matches!(
                evaluation_environment.validate(&policy_id, &validate_request),
                Err(EvaluationError::PolicyNotFound(_))
            ));
        } else {
            assert!(evaluation_environment.get_policy_mode(&policy_id).is_ok());
            assert!(evaluation_environment
                .get_policy_allowed_to_mutate(&policy_id)
                .is_ok());
            assert!(evaluation_environment
                .get_policy_settings(&policy_id)
                .is_ok());
            assert!(evaluation_environment
                .validate(&policy_id, &validate_request)
                .is_ok());
        }
    }

    #[rstest]
    #[case::all_policies_are_evaluated(
        "group_policy_with_unhappy_or_bracket_happy_and_unhappy_bracket",
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
        "group_policy_with_unhappy_or_happy_or_unhappy",
        true,
        Vec::new(), // no expected causes, since the request is accepted
    )]
    fn group_policy_warning_assignments(
        #[case] policy_id: &str,
        #[case] admission_accepted: bool,
        #[case] expected_status_causes: Vec<admission_response::StatusCause>,
    ) {
        let policy_id = PolicyID::Policy(policy_id.to_string());
        let evaluation_environment = Arc::new(build_evaluation_environment());
        let validate_request =
            ValidateRequest::AdmissionRequest(Box::new(build_admission_review_request().request));

        assert!(evaluation_environment.get_policy_mode(&policy_id).is_ok());
        assert!(evaluation_environment
            .get_policy_allowed_to_mutate(&policy_id)
            .is_ok());
        assert!(evaluation_environment
            .get_policy_settings(&policy_id)
            .is_ok());

        let response = evaluation_environment
            .validate(&policy_id, &validate_request)
            .expect("should not have errored");
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
                    causes.contains(&expected),
                    "could not find cause {:?}",
                    expected
                );
            }
        }
    }

    /// Given to identical wasm modules, only one instance of PolicyEvaluator is going to be
    /// created
    #[test]
    fn avoid_duplicated_instances_of_policy_evaluator() {
        let evaluation_environment = build_evaluation_environment();

        assert_eq!(
            evaluation_environment
                .module_digest_to_policy_evaluator_pre
                .len(),
            2
        );
    }

    #[test]
    fn validate_policy_with_initialization_error() {
        let mut evaluation_environment = build_evaluation_environment();
        let policy_id = PolicyID::Policy("policy_3".to_string());
        evaluation_environment
            .policy_initialization_errors
            .insert(policy_id.clone(), "error".to_string());
        let evaluation_environment = Arc::new(evaluation_environment);

        let validate_request =
            ValidateRequest::AdmissionRequest(Box::new(build_admission_review_request().request));
        assert!(matches!(
            evaluation_environment.validate(&policy_id, &validate_request).unwrap_err(),
            EvaluationError::PolicyInitialization(error) if error == "error"
        ));
    }

    #[rstest]
    #[case::valid_expression_with_single_policy(
        "group_policy_valid_expression_with_single_member",
        true
    )]
    #[case::valid_expression_with_just_rhai("group_policy_valid_expression_just_rhai", true)]
    #[case::not_valid_expression_because_of_unregistered_function(
        "group_policy_not_valid_expression_because_of_unregistered_function",
        false
    )]
    #[case::not_valid_expression_because_of_typos(
        "group_policy_not_valid_expression_because_of_typos",
        false
    )]
    #[case::not_valid_expression_because_doing_operations_with_booleans_is_wrong(
        "group_policy_not_valid_expression_because_doing_operations_with_booleans_is_wrong",
        false
    )]
    // This doesn't test doesn't pass: the int is automatically converted to boolean
    // #[case::not_valid_expression_because_does_not_return_boolean(
    //     "group_policy_not_valid_expression_because_does_not_return_boolean",
    //     false
    // )]
    fn validate_policy_settings_of_policy_group(
        #[case] policy_id: &str,
        #[case] expression_is_valid: bool,
    ) {
        let policy_id = PolicyID::Policy(policy_id.to_string());
        // Note, the validations of the other non-group policies, and the members of the group
        // policies, are going to fail because we are not running a proper wasm module.
        // However we ignore these errors because we are only interested in the validation of the
        // expression of the group policy

        let mut evaluation_environment = build_evaluation_environment();
        let validation_result = evaluation_environment.validate_settings(&policy_id);

        assert_eq!(expression_is_valid, validation_result.is_ok());
    }
}
