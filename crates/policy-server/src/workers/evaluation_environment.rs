use anyhow::{anyhow, Result};
use policy_evaluator::{
    admission_response::AdmissionResponse, callback_requests::CallbackRequest,
    evaluation_context::EvaluationContext, policy_evaluator::PolicyEvaluator,
    policy_evaluator_builder::PolicyEvaluatorBuilder, wasmtime,
};
use std::collections::HashMap;
use tokio::sync::mpsc;

use crate::communication::EvalRequest;
use crate::config::PolicyMode;
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
/// Each worker has its own dedicated instance of this structure.
/// At the worker level, the ultimate goal is to avoid duplicated instances of `PolicyEvaluator`.
/// That means that, given two or more identical Wasm modules, only one `PolicyEvaluator`
/// should be created. This is required to avoid a waste of memory by the Policy Server
/// process.
///
/// Note: the `PolicyEvaluator` instances will still be duplicated across each worker. This is
/// something we have to deal with.
#[derive(Default)]
#[cfg_attr(test, allow(dead_code))]
pub(crate) struct EvaluationEnvironment {
    /// Unique ID of the worker
    worker_id: u64,

    /// The name of the Namespace where Policy Server doesn't operate. All the requests
    /// involving this Namespace are going to be accepted. This is usually done to prevent user
    /// policies from messing with the components of the Kubewarden stack (which are all
    /// deployed inside of the same Namespace).
    always_accept_admission_reviews_on_namespace: Option<String>,

    /// A map with the unique ID of a Wasm module as key, and the associated `PolicyEvaluator`
    /// instance as value.
    /// Currently we the `module_id` is obtained by computing the sha255 digest of the
    /// optimized Wasm module.
    /// This dictionary allows us to reduce by amount of memory consumed by Policy Server.
    module_id_to_evaluator: HashMap<String, PolicyEvaluator>,

    /// A map with the ID of the policy as value, and the associated `EvaluationContext` as
    /// value.
    /// In this case, `policy_id` is the name of the policy as  declared inside of the
    /// `policies.yml` file. These names are guaranteed to be unique.
    policy_id_to_eval_ctx: HashMap<String, EvaluationContext>,

    /// Map a `policy_id` (the name given by the user inside of `policies.yml`) to the
    /// `module_id`. This allows us to deduplicate the Wasm modules defined by the user.
    policy_id_to_module_id: HashMap<String, String>,

    /// Map a `policy_id` to the `PolicyEvaluationSettings` instance. This allows us to obtain
    /// the list of settings to be used when evaluating a given policy.
    policy_id_to_settings: HashMap<String, PolicyEvaluationSettings>,
}

#[cfg_attr(test, automock)]
#[cfg_attr(test, allow(dead_code))]
impl EvaluationEnvironment {
    /// Creates a new `EvaluationEnvironment`
    pub(crate) fn new(
        worker_id: u64,
        always_accept_admission_reviews_on_namespace: Option<String>,
    ) -> Self {
        Self {
            worker_id,
            always_accept_admission_reviews_on_namespace,
            ..Default::default()
        }
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
    /// - `policy_id`: the ID of the policy, as specified inside of the `policies.yml` by the
    ///    user
    /// - `policy`: a data structure that maps all the information defined inside of
    ///    `policies.yml` for the given policy
    /// - `engine`: the `wasmtime::Engine` to be used when creating the `PolicyEvaluator`
    /// - `policy_modules`: all the `wasmtime::Module` precompiled for the current
    ///    OS/architecture
    /// - `callback_handler_tx`: the transmission end of a channel that connects the worker
    ///   with the asynchronous world
    /// - `policy_evaluation_limit_seconds`: when set, defines after how many seconds the
    ///   policy evaluation is interrupted
    pub(crate) fn register(
        &mut self,
        policy_id: &str,
        policy: &crate::config::Policy,
        engine: &wasmtime::Engine,
        policy_modules: &PrecompiledPolicies,
        callback_handler_tx: mpsc::Sender<CallbackRequest>,
        policy_evaluation_limit_seconds: Option<u64>,
    ) -> Result<()> {
        let precompiled_policy = policy_modules.get(policy.url.as_str()).ok_or_else(|| {
            anyhow!(
                "could not find preoptimized module for policy: {:?}",
                policy.url
            )
        })?;
        let module_id = precompiled_policy.digest.clone();

        if !self.module_id_to_evaluator.contains_key(&module_id) {
            let evaluator = create_policy_evaluator(
                policy_id,
                self.worker_id,
                policy,
                engine,
                precompiled_policy,
                callback_handler_tx.clone(),
                policy_evaluation_limit_seconds,
            )?;
            self.module_id_to_evaluator
                .insert(module_id.clone(), evaluator);
        }
        self.policy_id_to_module_id
            .insert(policy_id.to_owned(), module_id);

        let policy_eval_settings = PolicyEvaluationSettings {
            policy_mode: policy.policy_mode.clone(),
            allowed_to_mutate: policy.allowed_to_mutate.unwrap_or(false),
            settings: policy.settings_to_json()?.unwrap_or_default(),
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
            .ok_or(anyhow!("cannot find policy with ID {policy_id}"))
    }

    /// Given a policy ID, returns true if the policy is allowed to mutate
    pub fn get_policy_allowed_to_mutate(&self, policy_id: &str) -> Result<bool> {
        self.policy_id_to_settings
            .get(policy_id)
            .map(|settings| settings.allowed_to_mutate)
            .ok_or(anyhow!("cannot find policy with ID {policy_id}"))
    }

    /// Given a policy ID and a request to be processed, uses the `PolicyEvaluator` to perform
    /// a validation operation.
    pub fn validate(&mut self, policy_id: &str, req: &EvalRequest) -> Result<AdmissionResponse> {
        let settings = self.policy_id_to_settings.get(policy_id).ok_or(anyhow!(
            "cannot find settings for policy with ID {policy_id}"
        ))?;

        let module_id = self.policy_id_to_module_id.get(policy_id).ok_or(anyhow!(
            "cannot find module_id for policy with ID {policy_id}"
        ))?;
        let evaluator = self
            .module_id_to_evaluator
            .get_mut(module_id)
            .ok_or(anyhow!(
                "cannot find evaluator for policy with ID {policy_id}"
            ))?;

        let eval_ctx = self.policy_id_to_eval_ctx.get(policy_id).ok_or(anyhow!(
            "cannot find evaluation context for policy with ID {policy_id}"
        ))?;

        Ok(evaluator.validate(req.req.clone(), &settings.settings, eval_ctx))
    }
}

/// Internal function, takes care of creating the `PolicyEvaluator` instance for the given policy
fn create_policy_evaluator(
    policy_id: &str,
    worker_id: u64,
    policy: &crate::config::Policy,
    engine: &wasmtime::Engine,
    precompiled_policy: &PrecompiledPolicy,
    callback_handler_tx: mpsc::Sender<CallbackRequest>,
    policy_evaluation_limit_seconds: Option<u64>,
) -> Result<PolicyEvaluator> {
    // See `wasmtime::Module::deserialize` to know why this method is `unsafe`.
    // However, in our context, nothing bad will happen because we have
    // full control of the precompiled module. This is generated by the
    // WorkerPool thread
    let module =
        unsafe { wasmtime::Module::deserialize(engine, &precompiled_policy.precompiled_module) }
            .map_err(|e| {
                anyhow!(
                    "could not rehydrate wasmtime::Module {}: {:?}",
                    policy.url,
                    e
                )
            })?;

    let mut policy_evaluator_builder =
        PolicyEvaluatorBuilder::new(policy_id.to_string(), worker_id)
            .engine(engine.clone())
            .policy_module(module)
            .context_aware_resources_allowed(policy.context_aware_resources.clone())
            .callback_channel(callback_handler_tx)
            .execution_mode(precompiled_policy.execution_mode);

    if let Some(limit) = policy_evaluation_limit_seconds {
        policy_evaluator_builder =
            policy_evaluator_builder.enable_epoch_interruptions(limit, limit);
    }

    policy_evaluator_builder.build()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::config::Policy;

    /// Given to identical wasm modules, only one instance of PolicyEvaluator is going to be
    /// created
    #[test]
    fn avoid_duplicated_instaces_of_policy_evaluator() {
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

        let mut policies = HashMap::new();
        let mut policy_modules = HashMap::new();

        for policy_id in &policy_ids {
            policies.insert(
                policy_id.to_owned(),
                Policy {
                    url: policy_id.to_string(),
                    policy_mode: PolicyMode::Protect,
                    allowed_to_mutate: None,
                    settings: None,
                    context_aware_resources: BTreeSet::new(),
                },
            );
            policy_modules.insert(policy_id.to_string(), precompiled_policy.clone());
        }

        let mut evaluation_environment = EvaluationEnvironment::new(0, None);
        for policy_id in policy_ids {
            evaluation_environment
                .register(
                    policy_id,
                    &policies[policy_id],
                    &engine,
                    &policy_modules,
                    callback_handler_tx.clone(),
                    None,
                )
                .unwrap();
        }

        assert_eq!(evaluation_environment.module_id_to_evaluator.len(), 1);
    }
}
