use std::collections::BTreeSet;
use std::fmt;
use tokio::sync::mpsc;

use crate::callback_requests::CallbackRequest;
use crate::policy_metadata::ContextAwareResource;

/// A struct that holds metadata and other data that are needed when a policy
/// is being evaluated
#[derive(Clone)]
pub struct EvaluationContext {
    /// The policy identifier. This is mostly relevant for Policy Server,
    /// which uses the identifier provided by the user inside of the `policy.yml`
    /// file
    pub policy_id: String,

    /// Channel used by the synchronous world (like the `host_callback` waPC function,
    /// but also Burrego for k8s context aware data),
    /// to request the computation of code that can only be run inside of an
    /// asynchronous block
    pub callback_channel: Option<mpsc::Sender<CallbackRequest>>,

    /// List of ContextAwareResource the policy is granted access to.
    pub ctx_aware_resources_allow_list: BTreeSet<ContextAwareResource>,
}

impl EvaluationContext {
    /// Checks if a policy has access to a Kubernetes resource, based on the privileges
    /// that have been granted by the user
    pub(crate) fn can_access_kubernetes_resource(&self, api_version: &str, kind: &str) -> bool {
        let wanted_resource = ContextAwareResource {
            api_version: api_version.to_string(),
            kind: kind.to_string(),
        };

        self.ctx_aware_resources_allow_list
            .contains(&wanted_resource)
    }
}

impl fmt::Debug for EvaluationContext {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let callback_channel = match self.callback_channel {
            Some(_) => "Some(...)",
            None => "None",
        };

        write!(
            f,
            r#"EvaluationContext {{ policy_id: "{}", callback_channel: {}, allowed_kubernetes_resources: {:?} }}"#,
            self.policy_id, callback_channel, self.ctx_aware_resources_allow_list,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("nothing allowed", BTreeSet::new(), "v1", "Secret", false)]
    #[case(
        "try to access denied resource",
        BTreeSet::from([
            ContextAwareResource{
                api_version: "v1".to_string(),
                kind: "ConfigMap".to_string(),
            }]),
        "v1",
        "Secret",
        false,
    )]
    #[case(
        "access allowed resource",
        BTreeSet::from([
            ContextAwareResource{
                api_version: "v1".to_string(),
                kind: "ConfigMap".to_string(),
            }]),
        "v1",
        "ConfigMap",
        true,
    )]

    fn can_access_kubernetes_resource(
        #[case] name: &str,
        #[case] allowed_resources: BTreeSet<ContextAwareResource>,
        #[case] api_version: &str,
        #[case] kind: &str,
        #[case] allowed: bool,
    ) {
        let ctx = EvaluationContext {
            policy_id: name.to_string(),
            callback_channel: None,
            ctx_aware_resources_allow_list: allowed_resources,
        };

        let requested_resource = ContextAwareResource {
            api_version: api_version.to_string(),
            kind: kind.to_string(),
        };

        assert_eq!(
            allowed,
            ctx.can_access_kubernetes_resource(
                &requested_resource.api_version,
                &requested_resource.kind
            )
        );
    }
}
