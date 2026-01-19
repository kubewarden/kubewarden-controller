use std::{collections::BTreeSet, fmt};

use kubewarden_policy_sdk::crd::policies::{
    admission_policy_group::PolicyGroupMember,
    cluster_admission_policy_group::PolicyGroupMemberWithContext,
};

pub mod errors;
pub mod evaluator;

use crate::{
    admission_response::AdmissionResponse, policy_evaluator::PolicySettings,
    policy_metadata::ContextAwareResource,
};

/// The settings of a policy group member
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyGroupMemberSettings {
    /// The policy settings
    pub settings: PolicySettings,
    /// The list of kubernetes resources that are allowed to be accessed by the policy member
    pub ctx_aware_resources_allow_list: BTreeSet<ContextAwareResource>,
    /// The epoch deadlines to be used when executing this policy member
    pub epoch_deadline: Option<u64>,
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

impl TryFrom<&PolicyGroupMemberWithContext> for PolicyGroupMemberSettings {
    type Error = &'static str;

    fn try_from(member: &PolicyGroupMemberWithContext) -> Result<Self, Self::Error> {
        let settings = PolicySettings::try_from(&member.settings)?;
        let ctx_aware_resources_allow_list = member
            .context_aware_resources
            .iter()
            .map(|car| car.into())
            .collect();

        Ok(Self {
            settings,
            ctx_aware_resources_allow_list,
            epoch_deadline: member
                .timeout_eval_seconds
                .as_ref()
                .map(|t| Into::<i32>::into(t) as u64),
        })
    }
}

impl TryFrom<&PolicyGroupMember> for PolicyGroupMemberSettings {
    type Error = &'static str;

    fn try_from(member: &PolicyGroupMember) -> Result<Self, Self::Error> {
        let settings = PolicySettings::try_from(&member.settings)?;

        Ok(Self {
            settings,
            ctx_aware_resources_allow_list: BTreeSet::new(),
            epoch_deadline: member
                .timeout_eval_seconds
                .as_ref()
                .map(|t| Into::<i32>::into(t) as u64),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use assert_json_diff::assert_json_eq;
    use k8s_openapi::apimachinery::pkg::runtime::RawExtension;
    use kubewarden_policy_sdk::crd::policies::common::ContextAwareResource as ContextAwareResourceSdk;
    use serde_json::json;

    #[test]
    fn test_convert_policy_group_member_with_context_into_policy_group_member() {
        let settings = json!({
            "key1": "value1",
            "key2": "value2"
        });

        let context_aware_resources_sdk = vec![
            ContextAwareResourceSdk {
                api_version: "v1".to_string(),
                kind: "Pod".to_string(),
            },
            ContextAwareResourceSdk {
                api_version: "v1".to_string(),
                kind: "Service".to_string(),
            },
        ];

        let expected_context_aware_resources: BTreeSet<ContextAwareResource> = BTreeSet::from([
            ContextAwareResource {
                api_version: "v1".to_string(),
                kind: "Pod".to_string(),
            },
            ContextAwareResource {
                api_version: "v1".to_string(),
                kind: "Service".to_string(),
            },
        ]);

        let pgmc = PolicyGroupMemberWithContext {
            module: "test-module.wasm".to_string(),
            settings: RawExtension(settings.clone()),
            context_aware_resources: context_aware_resources_sdk,
            timeout_eval_seconds: None,
        };

        let policy_group_member_settings: PolicyGroupMemberSettings =
            PolicyGroupMemberSettings::try_from(&pgmc).expect("Failed to convert");

        assert_json_eq!(policy_group_member_settings.settings, settings);
        assert_eq!(
            expected_context_aware_resources,
            policy_group_member_settings.ctx_aware_resources_allow_list
        );
    }

    #[test]
    fn test_convert_policy_group_member_into_policy_group_member() {
        let settings = json!({
            "key1": "value1",
            "key2": "value2"
        });

        let pgm = PolicyGroupMember {
            module: "test-module.wasm".to_string(),
            settings: RawExtension(settings.clone()),
            timeout_eval_seconds: Some(15i32.into()),
        };

        let policy_group_member_settings: PolicyGroupMemberSettings =
            PolicyGroupMemberSettings::try_from(&pgm).expect("Failed to convert");

        assert_json_eq!(policy_group_member_settings.settings, settings);
        assert!(
            policy_group_member_settings
                .ctx_aware_resources_allow_list
                .is_empty(),
        );
        assert_eq!(policy_group_member_settings.epoch_deadline, Some(15));
    }
}
