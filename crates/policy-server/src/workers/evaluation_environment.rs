use policy_evaluator::{
    admission_response::AdmissionResponse,
    callback_requests::CallbackRequest,
    evaluation_context::EvaluationContext,
    kubewarden_policy_sdk::settings::SettingsValidationResponse,
    policy_evaluator::{PolicyEvaluator, PolicyEvaluatorPre, PolicyExecutionMode},
    policy_evaluator_builder::PolicyEvaluatorBuilder,
    wasmtime,
};
use std::collections::HashMap;
use tokio::sync::mpsc;
use tracing::debug;

use crate::communication::EvalRequest;
use crate::config::PolicyMode;
use crate::workers::error::{EvaluationError, Result};
use crate::workers::{
    policy_evaluation_settings::PolicyEvaluationSettings,
    precompiled_policy::{PrecompiledPolicies, PrecompiledPolicy},
};

#[cfg(test)]
use mockall::automock;

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
#[cfg_attr(test, allow(dead_code))]
pub(crate) struct EvaluationEnvironment {
    /// The name of the Namespace where Policy Server doesn't operate. All the requests
    /// involving this Namespace are going to be accepted. This is usually done to prevent user
    /// policies from messing with the components of the Kubewarden stack (which are all
    /// deployed inside of the same Namespace).
    always_accept_admission_reviews_on_namespace: Option<String>,

    /// A map with the module digest as key, and the associated `PolicyEvaluatorPre`
    /// as value
    module_digest_to_policy_evaluator_pre: HashMap<String, PolicyEvaluatorPre>,

    /// A map with the ID of the policy as value, and the associated `EvaluationContext` as
    /// value.
    /// In this case, `policy_id` is the name of the policy as  declared inside of the
    /// `policies.yml` file. These names are guaranteed to be unique.
    policy_id_to_eval_ctx: HashMap<String, EvaluationContext>,

    /// Map a `policy_id` (the name given by the user inside of `policies.yml`) to the
    /// module's digest. This allows us to deduplicate the Wasm modules defined by the user.
    policy_id_to_module_digest: HashMap<String, String>,

    /// Map a `policy_id` to the `PolicyEvaluationSettings` instance. This allows us to obtain
    /// the list of settings to be used when evaluating a given policy.
    policy_id_to_settings: HashMap<String, PolicyEvaluationSettings>,
}

#[cfg_attr(test, automock)]
#[cfg_attr(test, allow(dead_code))]
impl EvaluationEnvironment {
    /// Creates a new `EvaluationEnvironment`
    pub(crate) fn new(
        engine: &wasmtime::Engine,
        policies: &HashMap<String, crate::config::Policy>,
        precompiled_policies: &PrecompiledPolicies,
        always_accept_admission_reviews_on_namespace: Option<String>,
        policy_evaluation_limit_seconds: Option<u64>,
        callback_handler_tx: mpsc::Sender<CallbackRequest>,
    ) -> Result<Self> {
        let mut eval_env = Self {
            always_accept_admission_reviews_on_namespace,
            ..Default::default()
        };

        for (policy_id, policy) in policies {
            let precompiled_policy = precompiled_policies.get(&policy.url).ok_or_else(|| {
                EvaluationError::BootstrapFailure(format!(
                    "cannot find policy settings of {}",
                    policy_id
                ))
            })?;

            eval_env
                .register(
                    engine,
                    policy_id,
                    precompiled_policy,
                    policy,
                    callback_handler_tx.clone(),
                    policy_evaluation_limit_seconds,
                )
                .map_err(|e| EvaluationError::BootstrapFailure(e.to_string()))?;
        }

        Ok(eval_env)
    }

    /// Returns `true` if the given `namespace` is the special Namespace that is ignored by all
    /// the policies
    pub(crate) fn should_always_accept_requests_made_inside_of_namespace(
        &self,
        namespace: &str,
    ) -> bool {
        self.always_accept_admission_reviews_on_namespace.as_deref() == Some(namespace)
    }

    /// Register a new policy. It takes care of creating a new `PolicyEvaluator` (when needed).
    ///
    /// Params:
    /// - `engine`: the `wasmtime::Engine` to be used when creating the `PolicyEvaluator`
    /// - `policy_id`: the ID of the policy, as specified inside of the `policies.yml` by the
    ///    user
    /// - `precompiled_policy`: the `PrecompiledPolicy` associated with the Wasm module referenced
    ///    by the policy
    /// - `policy`: a data structure that maps all the information defined inside of
    ///    `policies.yml` for the given policy
    /// - `callback_handler_tx`: the transmission end of a channel that connects the worker
    ///   with the asynchronous world
    /// - `policy_evaluation_limit_seconds`: when set, defines after how many seconds the
    ///   policy evaluation is interrupted
    fn register(
        &mut self,
        engine: &wasmtime::Engine,
        policy_id: &str,
        precompiled_policy: &PrecompiledPolicy,
        policy: &crate::config::Policy,
        callback_handler_tx: mpsc::Sender<CallbackRequest>,
        policy_evaluation_limit_seconds: Option<u64>,
    ) -> Result<()> {
        let module_digest = &precompiled_policy.digest;

        if !self
            .module_digest_to_policy_evaluator_pre
            .contains_key(module_digest)
        {
            debug!(policy_id = policy.url, "create wasmtime::Module");
            let module = create_wasmtime_module(&policy.url, engine, precompiled_policy)?;
            debug!(policy_id = policy.url, "create PolicyEvaluatorPre");
            let pol_eval_pre = create_policy_evaluator_pre(
                engine,
                &module,
                precompiled_policy.execution_mode,
                policy_evaluation_limit_seconds,
            )?;

            self.module_digest_to_policy_evaluator_pre
                .insert(module_digest.to_owned(), pol_eval_pre);
        }
        self.policy_id_to_module_digest
            .insert(policy_id.to_owned(), module_digest.to_owned());

        let policy_eval_settings = PolicyEvaluationSettings {
            policy_mode: policy.policy_mode.clone(),
            allowed_to_mutate: policy.allowed_to_mutate.unwrap_or(false),
            settings: policy
                .settings_to_json()
                .map_err(|e| EvaluationError::InternalError(e.to_string()))?
                .unwrap_or_default(),
        };
        self.policy_id_to_settings
            .insert(policy_id.to_owned(), policy_eval_settings);

        let eval_ctx = EvaluationContext {
            policy_id: policy_id.to_owned(),
            callback_channel: Some(callback_handler_tx.clone()),
            ctx_aware_resources_allow_list: policy.context_aware_resources.clone(),
        };
        self.policy_id_to_eval_ctx
            .insert(policy_id.to_owned(), eval_ctx);

        Ok(())
    }

    /// Given a policy ID, return how the policy operates
    pub fn get_policy_mode(&self, policy_id: &str) -> Result<PolicyMode> {
        self.policy_id_to_settings
            .get(policy_id)
            .map(|settings| settings.policy_mode.clone())
            .ok_or(EvaluationError::PolicyNotFound(policy_id.to_string()))
    }

    /// Given a policy ID, returns true if the policy is allowed to mutate
    pub fn get_policy_allowed_to_mutate(&self, policy_id: &str) -> Result<bool> {
        self.policy_id_to_settings
            .get(policy_id)
            .map(|settings| settings.allowed_to_mutate)
            .ok_or(EvaluationError::PolicyNotFound(policy_id.to_string()))
    }

    /// Given a policy ID, returns the settings provided by the user inside of `policies.yml`
    fn get_policy_settings(&self, policy_id: &str) -> Result<PolicyEvaluationSettings> {
        let settings = self
            .policy_id_to_settings
            .get(policy_id)
            .ok_or(EvaluationError::PolicyNotFound(policy_id.to_string()))?
            .clone();

        Ok(settings)
    }

    /// Perform a request validation
    pub fn validate(&self, policy_id: &str, req: &EvalRequest) -> Result<AdmissionResponse> {
        let settings = self.get_policy_settings(policy_id)?;
        let mut evaluator = self.rehydrate(policy_id)?;

        Ok(evaluator.validate(req.req.clone(), &settings.settings))
    }

    /// Validate the settings the user provided for the given policy
    pub fn validate_settings(&self, policy_id: &str) -> Result<SettingsValidationResponse> {
        let settings = self.get_policy_settings(policy_id)?;
        let mut evaluator = self.rehydrate(policy_id)?;

        Ok(evaluator.validate_settings(&settings.settings))
    }

    /// Internal method, create a `PolicyEvaluator` by using a pre-initialized instance
    fn rehydrate(&self, policy_id: &str) -> Result<PolicyEvaluator> {
        let module_digest = self
            .policy_id_to_module_digest
            .get(policy_id)
            .ok_or(EvaluationError::PolicyNotFound(policy_id.to_string()))?;
        let policy_evaluator_pre = self
            .module_digest_to_policy_evaluator_pre
            .get(module_digest)
            .ok_or(EvaluationError::PolicyNotFound(policy_id.to_string()))?;

        let eval_ctx = self
            .policy_id_to_eval_ctx
            .get(policy_id)
            .ok_or(EvaluationError::PolicyNotFound(policy_id.to_string()))?;

        policy_evaluator_pre.rehydrate(eval_ctx).map_err(|e| {
            EvaluationError::WebAssemblyError(format!("cannot rehydrate PolicyEvaluatorPre: {e}"))
        })
    }
}

fn create_wasmtime_module(
    policy_url: &str,
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
                "could not rehydrate wasmtime::Module {policy_url}: {e:?}"
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
    use policy_evaluator::{
        admission_response::AdmissionResponse, policy_evaluator::ValidateRequest,
    };
    use rstest::*;
    use std::collections::BTreeSet;

    use super::*;
    use crate::admission_review::tests::build_admission_review;
    use crate::config::Policy;

    fn build_evaluation_environment() -> Result<EvaluationEnvironment> {
        let engine = wasmtime::Engine::default();
        let policy_ids = vec!["policy_1", "policy_2"];
        let module = wasmtime::Module::new(&engine, "(module (func))")
            .expect("should be able to build the smallest wasm module ever");
        let (callback_handler_tx, _) = mpsc::channel(10);

        let precompiled_policy = PrecompiledPolicy {
            precompiled_module: module.serialize().unwrap(),
            execution_mode: policy_evaluator::policy_evaluator::PolicyExecutionMode::Wasi,
            digest: "unique-digest".to_string(),
        };

        let mut policies: HashMap<String, crate::config::Policy> = HashMap::new();
        let mut precompiled_policies: PrecompiledPolicies = PrecompiledPolicies::new();

        for policy_id in &policy_ids {
            let policy_url = format!("file:///tmp/{policy_id}.wasm");
            policies.insert(
                policy_id.to_string(),
                Policy {
                    url: policy_url.clone(),
                    policy_mode: PolicyMode::Protect,
                    allowed_to_mutate: None,
                    settings: None,
                    context_aware_resources: BTreeSet::new(),
                },
            );
            precompiled_policies.insert(policy_url, precompiled_policy.clone());
        }

        EvaluationEnvironment::new(
            &engine,
            &policies,
            &precompiled_policies,
            None,
            None,
            callback_handler_tx,
        )
    }

    #[rstest]
    #[case("policy_not_defined", true)]
    #[case("policy_1", false)]
    fn return_policy_not_found_error(#[case] policy_id: &str, #[case] expect_error: bool) {
        let eval_env = build_evaluation_environment().unwrap();
        let req = ValidateRequest::AdmissionRequest(
            build_admission_review().request.expect("no request"),
        );

        let (tx, _) = tokio::sync::oneshot::channel::<Option<AdmissionResponse>>();
        let eval_req = EvalRequest {
            policy_id: policy_id.to_string(),
            req,
            resp_chan: tx,
            parent_span: tracing::Span::none(),
            request_origin: crate::communication::RequestOrigin::Validate,
        };

        if expect_error {
            assert!(matches!(
                eval_env.get_policy_mode(policy_id),
                Err(EvaluationError::PolicyNotFound(_))
            ));
            assert!(matches!(
                eval_env.get_policy_allowed_to_mutate(policy_id),
                Err(EvaluationError::PolicyNotFound(_))
            ));
            assert!(matches!(
                eval_env.get_policy_settings(policy_id),
                Err(EvaluationError::PolicyNotFound(_))
            ));
            assert!(matches!(
                eval_env.validate(policy_id, &eval_req),
                Err(EvaluationError::PolicyNotFound(_))
            ));
        } else {
            assert!(eval_env.get_policy_mode(policy_id).is_ok());
            assert!(eval_env.get_policy_allowed_to_mutate(policy_id).is_ok());
            assert!(eval_env.get_policy_settings(policy_id).is_ok());
            // note: we do not test `validate` with a known policy because this would
            // cause another error. The test policy we're using is just an empty Wasm
            // module
        }
    }

    /// Given to identical wasm modules, only one instance of PolicyEvaluator is going to be
    /// created
    #[test]
    fn avoid_duplicated_instaces_of_policy_evaluator() {
        let evaluation_environment = build_evaluation_environment().unwrap();

        assert_eq!(
            evaluation_environment
                .module_digest_to_policy_evaluator_pre
                .len(),
            1
        );
    }
}
