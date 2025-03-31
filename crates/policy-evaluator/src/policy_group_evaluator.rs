use std::{collections::BTreeSet, fmt};

pub mod errors;
pub mod evaluator;

use crate::admission_response::AdmissionResponse;
use crate::policy_evaluator::PolicySettings;
use crate::policy_metadata::ContextAwareResource;

/// The settings of a policy group member
pub struct PolicyGroupMemberSettings {
    /// The policy settings
    pub settings: PolicySettings,
    /// The list of kubernetes resources that are allowed to be accessed by the policy member
    pub ctx_aware_resources_allow_list: BTreeSet<ContextAwareResource>,
}

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
