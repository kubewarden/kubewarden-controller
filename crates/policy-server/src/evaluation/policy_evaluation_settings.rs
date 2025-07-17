use crate::config::PolicyOrPolicyGroupSettings;
use policy_evaluator::admission_response_handler::policy_mode::PolicyMode;

/// Holds the evaluation settings of loaded Policy. These settings are taken straight from the
/// `policies.yml` file provided by the user
#[cfg_attr(test, allow(dead_code))]
#[derive(Clone)]
pub(crate) struct PolicyEvaluationSettings {
    /// Whether the policy is operating in `protect` or `monitor` mode
    pub(crate) policy_mode: PolicyMode,
    /// Determines if a mutating policy is actually allowed to mutate
    pub(crate) allowed_to_mutate: bool,
    /// The policy-specific settings provided by the user
    pub(crate) settings: PolicyOrPolicyGroupSettings,
    /// Determines a custom rejection message for the policy
    pub(crate) custom_rejection_message: Option<String>,
}
