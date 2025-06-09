use std::{collections::BTreeSet, fmt};

use k8s_openapi::apimachinery::pkg::runtime::RawExtension;
use kubewarden_policy_sdk::crd::policies::{
    admission_policy_group::PolicyGroupMember,
    cluster_admission_policy_group::PolicyGroupMemberWithContext,
};

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

/// Converts a `kubewarden_policy_sdk::crd::RawExtension` to `PolicySettings`.
/// If the `RawExtension` is `null`, it returns default settings.
/// If the `RawExtension` is an object, it converts it to `PolicySettings`.
/// If the `RawExtension` is not an object or null, it returns an error.
fn convert_raw_extension_to_settings(
    raw_extension: &RawExtension,
) -> Result<PolicySettings, &'static str> {
    match &raw_extension.0 {
        serde_json::Value::Null => Ok(PolicySettings::default()),
        serde_json::Value::Object(obj) => Ok(obj.to_owned()),
        _ => Err("Invalid settings in CRD, not an object"),
    }
}

impl TryFrom<&PolicyGroupMemberWithContext> for PolicyGroupMemberSettings {
    type Error = &'static str;

    fn try_from(member: &PolicyGroupMemberWithContext) -> Result<Self, Self::Error> {
        let settings = convert_raw_extension_to_settings(&member.settings)?;
        let ctx_aware_resources_allow_list = member
            .context_aware_resources
            .iter()
            .map(|car| car.into())
            .collect();

        Ok(Self {
            settings,
            ctx_aware_resources_allow_list,
        })
    }
}

impl TryFrom<&PolicyGroupMember> for PolicyGroupMemberSettings {
    type Error = &'static str;

    fn try_from(member: &PolicyGroupMember) -> Result<Self, Self::Error> {
        let settings = convert_raw_extension_to_settings(&member.settings)?;

        Ok(Self {
            settings,
            ctx_aware_resources_allow_list: BTreeSet::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use assert_json_diff::assert_json_eq;
    use kubewarden_policy_sdk::crd::policies::common::ContextAwareResource as ContextAwareResourceSdk;
    use rstest::rstest;
    use serde_json::json;

    #[rstest]
    #[case::dictionrary(json!({"key1": "value1", "key2": "value2"}), true)]
    #[case::empty_dictionrary(json!({}), true)]
    #[case::nil(serde_json::Value::Null, true)]
    #[case::string(json!("boom"), false)]
    #[case::number(json!(123), false)]
    #[case::bool(json!(true), false)]
    fn convert_raw_extension_to_settings_conversion(
        #[case] settings: serde_json::Value,
        #[case] is_ok: bool,
    ) {
        let conversion_result = convert_raw_extension_to_settings(&RawExtension(settings.clone()));
        assert_eq!(
            conversion_result.is_ok(),
            is_ok,
            "Conversion should {}",
            if is_ok { "succeed" } else { "fail" }
        );
    }

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
        };

        let policy_group_member_settings: PolicyGroupMemberSettings =
            PolicyGroupMemberSettings::try_from(&pgm).expect("Failed to convert");

        assert_json_eq!(policy_group_member_settings.settings, settings);
        assert!(policy_group_member_settings
            .ctx_aware_resources_allow_list
            .is_empty(),);
    }
}
