use std::collections::BTreeSet;
use std::fmt;
use tokio::sync::mpsc;

use crate::callback_requests::CallbackRequest;
use crate::host_capabilities_allow_list::HostCapabilitiesAllowList;
use crate::policy_metadata::ContextAwareResource;

/// A struct that holds metadata and other data that are needed when a policy
/// is being evaluated
#[derive(Clone, Default)]
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

    /// Optional epoch deadline to set on the wasmtime store. This is used to
    /// interrupt long running executions
    ///
    /// This could either be the global epoch deadline, or the one
    /// specific to the policy
    pub epoch_deadline: Option<u64>,

    /// The set of host capabilities this policy is allowed to invoke.
    /// An empty list means no host capabilities are allowed (deny by default).
    /// A list containing `*` means all capabilities are allowed.
    pub host_capabilities_allow_list: HostCapabilitiesAllowList,
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

    /// Checks if a policy has access to a host capability, based on the
    /// `host_capabilities` allow list configured for this policy.
    ///
    /// The capability path is constructed as `{namespace}/{operation}`,
    /// matching the waPC host callback namespace and operation parameters.
    pub(crate) fn can_access_host_capability(&self, capability_path: &str) -> bool {
        self.host_capabilities_allow_list
            .is_capability_allowed(capability_path)
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
            r#"EvaluationContext {{ policy_id: "{}", callback_channel: {}, allowed_kubernetes_resources: {:?}, host_capabilities: {} }}"#,
            self.policy_id,
            callback_channel,
            self.ctx_aware_resources_allow_list,
            self.host_capabilities_allow_list,
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
            epoch_deadline: None,
            host_capabilities_allow_list: HostCapabilitiesAllowList::allow_all(),
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

    #[rstest]
    #[case("deny all", vec![], "oci/v1/verify", false)]
    #[case("allow all", vec!["*"], "oci/v1/verify", true)]
    #[case("exact match", vec!["oci/v1/verify"], "oci/v1/verify", true)]
    #[case("prefix match", vec!["oci/*"], "oci/v2/verify", true)]
    #[case("no match", vec!["net/v1/dns_lookup_host"], "oci/v1/verify", false)]
    fn can_access_host_capability(
        #[case] name: &str,
        #[case] patterns: Vec<&str>,
        #[case] capability: &str,
        #[case] allowed: bool,
    ) {
        let ctx = EvaluationContext {
            policy_id: name.to_string(),
            callback_channel: None,
            ctx_aware_resources_allow_list: BTreeSet::new(),
            epoch_deadline: None,
            host_capabilities_allow_list: HostCapabilitiesAllowList::try_from(patterns)
                .expect("valid patterns"),
        };
        assert_eq!(ctx.can_access_host_capability(capability), allowed);
    }
}
