/// This file defines structs that contain the kubernetes context aware data in a format that is
/// compatible with what Gatekeeper expects.
///
/// If you don't care about the process, jump straight to the section about the inventory.
///
/// ## The `inventory` object
///
/// As documented [here](https://open-policy-agent.github.io/gatekeeper/website/docs/sync/), the
/// Kubernetes details are made available to all the policies via the `data.inventory` object.
///
/// Inventory is a JSON dictionary built using the rules mentioned by the doc:
/// - For cluster-scoped objects: `data.inventory.cluster[<groupVersion>][<kind>][<name>]`
/// - For namespace-scoped objects: `data.inventory.namespace[<namespace>][groupVersion][<kind>][<name>]`
///
/// For example, all the `Namespace` objects are exposed this way:
///
/// ```hcl
///   "cluster": { # that's because Namespace is a cluster wide resournce
///     "v1": { # this is the group version of the `Namespace` resource
///       "Namespace": { # this is the kind used by `Namespace`
///            "default": { # this is the name of the Namespace resource being "dumped"
///                # contents of `kubectl get ns default -o json`
///            },
///            "kube-system": { # name of the namespace
///               # contents of the namespace object
///            }
///            # more entries...
///        }
///     }
///   }
/// ```
///
/// While all the Pods are exposed in this way:
///
/// ```hcl
///   "namespace": { # this is used for namespaced resources, like `cluster` was used before for cluster-wide ones
///     "gatekeeper-system": { # name of the namespace that contains the Pod
///       "v1": { # the group version of the Pod resource
///         "Pod": { # the kind of the Pod resource
///           "gatekeeper-audit-fd9c6d89d-lrr9d": { # the name of the Pod
///                # contents of `kubectl get pod -n gatekeeper-system -o json gatekeeper-audit-fd9c6d89d-lrr9d`
///           }
///           # the other pods defined inside of the `gatekeeper-system` namespace are shown here
///         }
///       },
///       "default": { # all the pods defined under the `default` namespace
///          "v1": {
///            "Pod": {
///               "foo": {
///                  # definition of the `foo` pod, defined under the `default` namespace
///               }
///            }
///         }
///       }
///    }
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
            .ok_or(RegoRuntimeError::GatekeeperInventoryMissingName)?;
        self.0.insert(name, obj.to_owned());
        Ok(())
    }
}

/// A wrapper around a dictionary that has a Kubernetes Kind (e.g. `Pod`)
/// as key, and a ResourcesByName as value
#[derive(Serialize, Default)]
pub(crate) struct ResourcesByKind(BTreeMap<String, ResourcesByName>);

impl ResourcesByKind {
    fn register(
        &mut self,
        obj: &kube::core::DynamicObject,
        resource: &ContextAwareResource,
    ) -> Result<()> {
        self.0
            .entry(resource.kind.clone())
            .or_default()
            .register(obj)
    }
}

/// A wrapper around a dictionary that has a Kubernetes GroupVersion (e.g. `apps/v1`)
/// as key, and a ResourcesByKind as value
#[derive(Serialize, Default)]
pub(crate) struct ResourcesByGroupVersion(BTreeMap<String, ResourcesByKind>);

impl ResourcesByGroupVersion {
    fn register(
        &mut self,
        obj: &kube::core::DynamicObject,
        resource: &ContextAwareResource,
    ) -> Result<()> {
        self.0
            .entry(resource.api_version.clone())
            .or_default()
            .register(obj, resource)
    }
}

/// A wrapper around a dictionary that has
/// the name of a Kubernetes Namespace (e.g. `kube-system`) as key,
/// and a ResourcesByGroupVersion as value
#[derive(Serialize, Default)]
pub(crate) struct ResourcesByNamespace(BTreeMap<String, ResourcesByGroupVersion>);

impl ResourcesByNamespace {
    fn register(
        &mut self,
        obj: &kube::core::DynamicObject,
        resource: &ContextAwareResource,
    ) -> Result<()> {
        let namespace = obj
            .metadata
            .namespace
            .clone()
            .ok_or(RegoRuntimeError::GatekeeperInventoryMissingNamespace)?;
        self.0.entry(namespace).or_default().register(obj, resource)
    }
}

/// A struct holding the Kubernetes context aware data in a format that is compabible with what
/// Gatekeeper expects
#[derive(Serialize, Default)]
pub(crate) struct GatekeeperInventory {
    #[serde(rename = "cluster")]
    cluster_resources: ResourcesByGroupVersion,
    #[serde(rename = "namespace")]
    namespaced_resources: ResourcesByNamespace,
}

impl GatekeeperInventory {
    /// Creates a GatekeeperInventory by querying a Kubernetes cluster
    /// for all the resources specified
    pub(crate) fn new(
        kube_resources: &BTreeMap<ContextAwareResource, ObjectList<kube::core::DynamicObject>>,
    ) -> Result<Self> {
        let mut inventory = GatekeeperInventory::default();

        for (resource, resources_list) in kube_resources {
            for obj in resources_list {
                inventory.register(obj, resource)?
            }
        }

        Ok(inventory)
    }

    fn register(
        &mut self,
        obj: &kube::core::DynamicObject,
        resource: &ContextAwareResource,
    ) -> Result<()> {
        match &obj.metadata.namespace {
            Some(_) => {
                // namespaced resource
                self.namespaced_resources.register(obj, resource)
            }
            None => {
                // cluster-wide resource
                self.cluster_resources.register(obj, resource)
            }
        }
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

        let services = [
            dynamic_object_from_fixture("services", Some("kube-system"), "kube-dns").unwrap(),
            dynamic_object_from_fixture("services", Some("kube-system"), "metrics-server").unwrap(),
        ];
        let services_list = object_list_from_dynamic_objects(&services).unwrap();
        kube_resources.insert(
            ContextAwareResource {
                api_version: "v1".to_string(),
                kind: "Service".to_string(),
            },
            services_list,
        );

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
        kube_resources.insert(
            ContextAwareResource {
                api_version: "apps/v1".to_string(),
                kind: "Deployment".to_string(),
            },
            deployments_list,
        );

        let namespaces = [
            dynamic_object_from_fixture("namespaces", None, "cert-manager").unwrap(),
            dynamic_object_from_fixture("namespaces", None, "kube-system").unwrap(),
        ];
        let namespaces_list = object_list_from_dynamic_objects(&namespaces).unwrap();
        kube_resources.insert(
            ContextAwareResource {
                api_version: "v1".to_string(),
                kind: "Namespace".to_string(),
            },
            namespaces_list,
        );

        let expected = serde_json::json!({
            "cluster": {
                "v1": {
                    "Namespace": {
                        "kube-system": dynamic_object_from_fixture("namespaces", None, "kube-system").unwrap(),
                        "cert-manager": dynamic_object_from_fixture("namespaces", None, "cert-manager").unwrap(),
                    }
                }
            },
            "namespace": {
                "kube-system": {
                    "v1": {
                        "Service": {
                            "kube-dns": dynamic_object_from_fixture("services", Some("kube-system"), "kube-dns").unwrap(),
                            "metrics-server": dynamic_object_from_fixture("services", Some("kube-system"), "metrics-server").unwrap(),
                        }
                    },
                    "apps/v1": {
                        "Deployment": {
                            "coredns": dynamic_object_from_fixture("deployments", Some("kube-system"), "coredns").unwrap(),
                            "local-path-provisioner": dynamic_object_from_fixture("deployments", Some("kube-system"), "local-path-provisioner").unwrap(),
                        }
                    }
                },
                "ingress": {
                    "apps/v1": {
                        "Deployment": {
                            "ingress-nginx": dynamic_object_from_fixture("deployments", Some("ingress"), "ingress-nginx").unwrap(),
                        }
                    }
                }
            }
        });

        let inventory = GatekeeperInventory::new(&kube_resources).unwrap();
        let inventory_json = serde_json::to_value(inventory).unwrap();
        assert_json_eq!(inventory_json, expected);
    }
}
