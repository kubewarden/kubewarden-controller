use anyhow::{anyhow, Result};
use kube::{
    api::{ListParams, Request},
    Client,
};
use std::sync::RwLock;

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

    pub async fn refresh(&self, kubernetes_client: &Client) -> Result<()> {
        {
            let namespace_list = kubernetes_client
                .request_text(
                    Request::new("/api/v1/namespaces")
                        .list(&ListParams::default())
                        .map_err(|err| anyhow!("could not list namespaces: {:?}", err))?,
                )
                .await?;

            if let Ok(mut namespaces) = self.namespaces.write() {
                *namespaces = namespace_list
            };
        }
        {
            let service_list = kubernetes_client
                .request_text(
                    Request::new("/api/v1/services")
                        .list(&ListParams::default())
                        .map_err(|err| anyhow!("could not list services: {:?}", err))?,
                )
                .await?;

            if let Ok(mut services) = self.services.write() {
                *services = service_list
            };
        }
        {
            let ingress_list = kubernetes_client
                .request_text(
                    Request::new("/apis/networking.k8s.io/v1/ingresses")
                        .list(&ListParams::default())
                        .map_err(|err| anyhow!("could not list ingresses: {:?}", err))?,
                )
                .await?;

            if let Ok(mut ingresses) = self.ingresses.write() {
                *ingresses = ingress_list
            };
        }

        Ok(())
    }
}
