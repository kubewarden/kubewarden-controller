/// This file builds a the context data required by OPA polices.
/// ## Docs references
///
/// We define OPA policies as the ones deployed via [kube-mgmt](https://github.com/open-policy-agent/kube-mgmt), which is an alternative to gatekeeper.
///
/// kube-mgmt can be configured to expose Kubernetes resources to the policies. This is described in detail [here](https://github.com/open-policy-agent/kube-mgmt#caching).
///
/// By default, the Kubernetes information is made available to the policies inside of `data.kubernetes`.
/// The `kubernetes` key can be changed by the user via a configuration flag, but we decided to conform to the default behavior.
///
/// ## Incoming JSON structure
///
/// Kubernetes resources are exposed using this format:
///
/// * namespaced resources: `kubernetes.<resource>.<namespace>.<name>`
/// * cluster wide resources: `kubernetes.<resource>.<name>`
///
/// It's important to point out that `<resource>` is the Kubernetes plural name of the resource obtained when doing:
///
/// ```console
/// kubectl api-resources
/// ```
///
/// For example, the name of `v1/Service` is `services`.
///
/// This is problematic, because the name of a resource isn't unique. For example:
///
/// ```console
/// kubectl api-resources | grep events
/// events                            ev           v1                                     true         Event
/// events                            ev           events.k8s.io/v1                       true         Event
/// ```
///
/// The problem might become even more evident when multiple CRDs are installed.
///
/// However, this is is not our problem... Moreover, the admin decides what has to be shared with the policies. Hence he can pick, among the duplicates, which resource to share with the policies.
///
/// ### Examples
///
/// This is how the `data` payload would look like when Kubernetes Service and Namespace resources are shared with policies:
///
/// ```hcl
/// {
///   "kubernetes": { # the default key
///     "services": { # the name of the resource
///       "default": { # the namespace inside of which the resources are defined
///         "example-service": { # the name of the Service
///           # the contents of `kubectl get svc -n default -o json example-service`
///         },
///         "another-service": {
///           # the contents of `kubectl get svc -n default -o json another-service`
///         }
///       }
///     },
///     "namespaces": { # the name of the resource - note: this is a cluster-wide resource
///        "default": {
///           # contents of `kubectl get ns default -o json`
///        },
///        "kube-system": {
///          # contents of `kubectl get ns kube-system -o json`
///        }
///     }
///   }
/// }
/// ```
///
use kube::api::ObjectList;
use serde::Serialize;
use std::collections::BTreeMap;

use crate::policy_metadata::ContextAwareResource;
use crate::runtimes::rego::errors::{RegoRuntimeError, Result};

/// A wrapper around a dictionary that has the resource Name as key,
/// and a DynamicObject as value
#[derive(Serialize, Default)]
pub(crate) struct ResourcesByName(BTreeMap<String, kube::core::DynamicObject>);

impl ResourcesByName {
    fn register(&mut self, obj: &kube::core::DynamicObject) -> Result<()> {
        let name = obj
            .metadata
            .name
            .clone()
            .ok_or(RegoRuntimeError::OpaInventoryMissingName())?;
        self.0.insert(name, obj.to_owned());
        Ok(())
    }
}

/// A wrapper around a dictionary that has the name of the namespace as key and the list of
/// ResourcesByName as value
#[derive(Serialize, Default)]
pub(crate) struct ResourcesByNamespace(BTreeMap<String, ResourcesByName>);

impl ResourcesByNamespace {
    fn register(&mut self, obj: &kube::core::DynamicObject) -> Result<()> {
        let namespace = obj
            .metadata
            .namespace
            .clone()
            .ok_or(RegoRuntimeError::OpaInventoryMissingNamespace())?;
        self.0.entry(namespace).or_default().register(obj)
    }
}

#[derive(Serialize)]
#[serde(untagged)]
pub(crate) enum ResourcesByScope {
    Cluster(ResourcesByName),
    Namespace(ResourcesByNamespace),
}

impl ResourcesByScope {
    fn register(&mut self, obj: &kube::core::DynamicObject) -> Result<()> {
        match self {
            ResourcesByScope::Cluster(cluster_resources) => cluster_resources.register(obj),
            ResourcesByScope::Namespace(namespace_resources) => namespace_resources.register(obj),
        }
    }
}

/// A wrapper around a dictionary that has
/// the plural name of a Kubernetes resource (e.g. `services`) as key,
/// and a ResourcesByScope as value
#[derive(Serialize, Default)]
pub(crate) struct ResourcesByPluralName(BTreeMap<String, ResourcesByScope>);

impl ResourcesByPluralName {
    fn register(&mut self, obj: &kube::core::DynamicObject, plural_name: &str) -> Result<()> {
        let obj_namespaced = obj.metadata.namespace.is_some();

        match self.0.get_mut(plural_name) {
            Some(ref mut resources_by_scope) => {
                match resources_by_scope {
                    ResourcesByScope::Cluster(_) => {
                        if obj_namespaced {
                            return Err(RegoRuntimeError::OpaInventoryAddNamespacedRes());
                        }
                    }
                    ResourcesByScope::Namespace(_) => {
                        if !obj_namespaced {
                            return Err(RegoRuntimeError::OpaInventoryAddClusterwideRes());
                        }
                    }
                }
                resources_by_scope.register(obj)
            }
            None => {
                let mut resources_by_scope = if obj_namespaced {
                    ResourcesByScope::Namespace(ResourcesByNamespace::default())
                } else {
                    ResourcesByScope::Cluster(ResourcesByName::default())
                };
                resources_by_scope.register(obj)?;
                self.0.insert(plural_name.to_owned(), resources_by_scope);
                Ok(())
            }
        }
    }
}

#[derive(Serialize, Default)]
pub(crate) struct OpaInventory(ResourcesByPluralName);

impl OpaInventory {
    /// Creates a GatekeeperInventory by querying a Kubernetes cluster
    /// for all the resources specified
    pub(crate) fn new(
        kube_resources: &BTreeMap<ContextAwareResource, ObjectList<kube::core::DynamicObject>>,
        plural_names: &BTreeMap<ContextAwareResource, String>,
    ) -> Result<Self> {
        let mut inventory = OpaInventory::default();

        for (resource, resources_list) in kube_resources {
            let plural_name = plural_names.get(resource).ok_or_else(|| {
                RegoRuntimeError::OpaInventoryMissingPluralName(format!("{:?}", resource))
            })?;

            for obj in resources_list {
                inventory.register(obj, plural_name)?
            }
        }

        Ok(inventory)
    }

    fn register(&mut self, obj: &kube::core::DynamicObject, plural_name: &str) -> Result<()> {
        self.0.register(obj, plural_name)
    }
}

#[cfg(test)]
mod tests {
    use crate::runtimes::rego::context_aware::tests::{
        dynamic_object_from_fixture, object_list_from_dynamic_objects,
    };

    use super::*;
    use assert_json_diff::assert_json_eq;

    #[test]
    fn create() {
        let mut kube_resources: BTreeMap<
            ContextAwareResource,
            ObjectList<kube::core::DynamicObject>,
        > = BTreeMap::new();
        let mut plural_names: BTreeMap<ContextAwareResource, String> = BTreeMap::new();

        let services = [
            dynamic_object_from_fixture("services", Some("kube-system"), "kube-dns").unwrap(),
            dynamic_object_from_fixture("services", Some("kube-system"), "metrics-server").unwrap(),
        ];
        let services_list = object_list_from_dynamic_objects(&services).unwrap();
        let ctx_aware_resource = ContextAwareResource {
            api_version: "v1".to_string(),
            kind: "Service".to_string(),
        };
        plural_names.insert(ctx_aware_resource.clone(), "services".to_string());
        kube_resources.insert(ctx_aware_resource, services_list);

        let deployments = [
            dynamic_object_from_fixture("deployments", Some("ingress"), "ingress-nginx").unwrap(),
            dynamic_object_from_fixture("deployments", Some("kube-system"), "coredns").unwrap(),
            dynamic_object_from_fixture(
                "deployments",
                Some("kube-system"),
                "local-path-provisioner",
            )
            .unwrap(),
        ];
        let deployments_list = object_list_from_dynamic_objects(&deployments).unwrap();
        let ctx_aware_resource = ContextAwareResource {
            api_version: "apps/v1".to_string(),
            kind: "Deployment".to_string(),
        };
        plural_names.insert(ctx_aware_resource.clone(), "deployments".to_string());
        kube_resources.insert(ctx_aware_resource, deployments_list);

        let namespaces = [
            dynamic_object_from_fixture("namespaces", None, "cert-manager").unwrap(),
            dynamic_object_from_fixture("namespaces", None, "kube-system").unwrap(),
        ];
        let namespaces_list = object_list_from_dynamic_objects(&namespaces).unwrap();
        let ctx_aware_resource = ContextAwareResource {
            api_version: "v1".to_string(),
            kind: "Namespace".to_string(),
        };
        plural_names.insert(ctx_aware_resource.clone(), "namespaces".to_string());
        kube_resources.insert(ctx_aware_resource, namespaces_list);

        let expected = serde_json::json!({
            "namespaces": {
                "kube-system": dynamic_object_from_fixture("namespaces", None, "kube-system").unwrap(),
                "cert-manager": dynamic_object_from_fixture("namespaces", None, "cert-manager").unwrap(),
            },
            "services": {
                "kube-system": {
                   "kube-dns": dynamic_object_from_fixture("services", Some("kube-system"), "kube-dns").unwrap(),
                   "metrics-server": dynamic_object_from_fixture("services", Some("kube-system"), "metrics-server").unwrap(),
               },
            },
            "deployments": {
                "kube-system": {
                    "coredns": dynamic_object_from_fixture("deployments", Some("kube-system"), "coredns").unwrap(),
                    "local-path-provisioner": dynamic_object_from_fixture("deployments", Some("kube-system"), "local-path-provisioner").unwrap(),
                },
                "ingress": {
                    "ingress-nginx": dynamic_object_from_fixture("deployments", Some("ingress"), "ingress-nginx").unwrap(),
                }
            }
        });

        let inventory = OpaInventory::new(&kube_resources, &plural_names).unwrap();
        let inventory_json = serde_json::to_value(&inventory).unwrap();
        assert_json_eq!(inventory_json, expected);
    }
}
