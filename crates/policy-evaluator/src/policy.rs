use anyhow::Result;
use std::clone::Clone;
use std::collections::HashSet;
use std::fmt;
use tokio::sync::mpsc;

use crate::callback_requests::CallbackRequest;
use crate::policy_metadata::ContextAwareResource;

/// Minimal amount of information about a policy that need to
/// be always accessible at runtime.
///
/// This struct is used extensively inside of the `host_callback`
/// function to obtain information about the policy that is invoking
/// a host waPC function, and handle the request.
#[derive(Clone)]
pub struct Policy {
    /// The policy identifier. This is mostly relevant for Policy Server,
    /// which uses the identifier provided by the user inside of the `policy.yml`
    /// file
    pub id: String,

    /// This is relevant only for waPC-based policies. This is the unique ID
    /// associated to the waPC policy.
    /// Burrego policies have this field set to `None`
    instance_id: Option<u64>,

    /// Channel used by the synchronous world (the `host_callback` waPC function),
    /// to request the computation of code that can only be run inside of an
    /// asynchronous block
    pub callback_channel: Option<mpsc::Sender<CallbackRequest>>,

    /// List of ContextAwareResource the policy is granted access to.
    /// Currently, this is relevant only for waPC based policies
    pub ctx_aware_resources_allow_list: HashSet<ContextAwareResource>,
}

impl fmt::Debug for Policy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let callback_channel = match self.callback_channel {
            Some(_) => "Some(...)",
            None => "None",
        };

        write!(
            f,
            r#"Policy {{ id: "{}", instance_id: {:?}, callback_channel: {} }}"#,
            self.id, self.instance_id, callback_channel,
        )
    }
}

impl PartialEq for Policy {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.instance_id == other.instance_id
    }
}

#[cfg(test)]
impl Default for Policy {
    fn default() -> Self {
        Policy {
            id: String::default(),
            instance_id: None,
            callback_channel: None,
            ctx_aware_resources_allow_list: HashSet::new(),
        }
    }
}

impl Policy {
    pub(crate) fn new(
        id: String,
        policy_id: Option<u64>,
        callback_channel: Option<mpsc::Sender<CallbackRequest>>,
        ctx_aware_resources_allow_list: Option<HashSet<ContextAwareResource>>,
    ) -> Result<Policy> {
        Ok(Policy {
            id,
            instance_id: policy_id,
            callback_channel,
            ctx_aware_resources_allow_list: ctx_aware_resources_allow_list.unwrap_or_default(),
        })
    }

    pub(crate) fn can_access_kubernetes_resource(&self, api_version: &str, kind: &str) -> bool {
        let wanted_resource = ContextAwareResource {
            api_version: api_version.to_string(),
            kind: kind.to_string(),
        };

        self.ctx_aware_resources_allow_list
            .contains(&wanted_resource)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_access_kubernetes_resource_empty_allow_list() {
        let policy =
            Policy::new("test".to_string(), None, None, None).expect("cannot create policy");

        let requested_resource = ContextAwareResource {
            api_version: "v1".to_string(),
            kind: "Secret".to_string(),
        };

        assert!(!policy.can_access_kubernetes_resource(
            &requested_resource.api_version,
            &requested_resource.kind
        ));
    }

    #[test]
    fn can_access_kubernetes_resource_denied() {
        let requested_resource = ContextAwareResource {
            api_version: "v1".to_string(),
            kind: "Secret".to_string(),
        };

        let mut allowed_resources = HashSet::new();
        allowed_resources.insert(ContextAwareResource {
            api_version: "v1".to_string(),
            kind: "Pod".to_string(),
        });

        let policy = Policy::new("test".to_string(), None, None, Some(allowed_resources))
            .expect("cannot create policy");

        assert!(!policy.can_access_kubernetes_resource(
            &requested_resource.api_version,
            &requested_resource.kind
        ));
    }

    #[test]
    fn can_access_kubernetes_resource_allowed() {
        let requested_resource = ContextAwareResource {
            api_version: "v1".to_string(),
            kind: "Secret".to_string(),
        };

        let mut allowed_resources = HashSet::new();
        allowed_resources.insert(ContextAwareResource {
            api_version: "v1".to_string(),
            kind: "Pod".to_string(),
        });
        allowed_resources.insert(ContextAwareResource {
            api_version: "v1".to_string(),
            kind: "Secret".to_string(),
        });

        let policy = Policy::new("test".to_string(), None, None, Some(allowed_resources))
            .expect("cannot create policy");

        assert!(policy.can_access_kubernetes_resource(
            &requested_resource.api_version,
            &requested_resource.kind
        ));
    }
}
