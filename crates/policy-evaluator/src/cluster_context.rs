use kube::api::{ListParams, Resource};
use kube::Client;
use std::sync::RwLock;

use k8s_openapi::api::core::v1::{Namespace, Service};
use k8s_openapi::api::networking::v1::Ingress;

use lazy_static::lazy_static;

lazy_static! {
    static ref CLUSTER_CONTEXT: ClusterContext = ClusterContext::default();
}

// ClusterContext represents a structure that can be used to retrieve
// information about a running Kubernetes cluster.
#[derive(Default)]
pub struct ClusterContext {
    ingresses: RwLock<String>,
    namespaces: RwLock<String>,
    services: RwLock<String>,
}

impl ClusterContext {
    pub fn get<'a>() -> &'a ClusterContext {
        &CLUSTER_CONTEXT
    }

    pub fn ingresses(&self) -> String {
        (*self.ingresses.read().unwrap()).clone()
    }

    pub fn namespaces(&self) -> String {
        (*self.namespaces.read().unwrap()).clone()
    }

    pub fn services(&self) -> String {
        (*self.services.read().unwrap()).clone()
    }

    pub async fn refresh(&self, kubernetes_client: &Client) -> kube::Result<()> {
        // TODO (ereslibre): use macros to remove duplication and then
        // generalize
        {
            let ingress_list_req = Resource::all::<Ingress>().list(&ListParams::default())?;
            let ingress_list = kubernetes_client.request_text(ingress_list_req).await?;
            if let Ok(mut ingresses) = self.ingresses.write() {
                *ingresses = ingress_list
            };
        };
        {
            let namespace_list_req = Resource::all::<Namespace>().list(&ListParams::default())?;
            let namespace_list = kubernetes_client.request_text(namespace_list_req).await?;
            if let Ok(mut namespaces) = self.namespaces.write() {
                *namespaces = namespace_list
            };
        };
        {
            let service_list_req = Resource::all::<Service>().list(&ListParams::default())?;
            let service_list = kubernetes_client.request_text(service_list_req).await?;
            if let Ok(mut services) = self.services.write() {
                *services = service_list
            };
        };
        Ok(())
    }
}
