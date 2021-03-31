#![allow(clippy::mutex_atomic)]

use anyhow::Result;
use kube::api::{ListParams, Resource};
use kube::Client;
use std::sync::{Mutex, RwLock};
use tokio::runtime::Builder;

use k8s_openapi::api::core::v1::{Namespace, Service};
use k8s_openapi::api::networking::v1::Ingress;

use lazy_static::lazy_static;
use std::thread;

lazy_static! {
    static ref CLUSTER_CONTEXT_INITIALIZED: Mutex<bool> = Mutex::new(false);
    static ref CLUSTER_CONTEXT: ClusterContext = ClusterContext::default();
}

// ClusterContext represents a structure that can be used to retrieve
// information about a running Kubernetes cluster.
//
// In the current implementation, the `ClusterContext` contains a set
// of well known resources. This resources get exposed through the
// waPC host callback and are readable by waPC guests as JSON encoded
// raw strings.
//
// The current implementation performs a list of this well known
// resources every 5 seconds. Two things need to be improved at least
// in the current implementation:
//
// 1. Do not limit to a reduced number of well-known types. Generalize
// the supported types, and by generalizing support custom resource
// definitions too. This allows guest waPC policies to take contextual
// decisions based on custom resources defined by the user.
//
// 2. Do not use polling. Perform an initial list request of resources
// when the first request is performed by a guest. Then, cache and
// watch in order to maintain an updated list: this significantly
// reduces the data that needs to be pulled in a scheduled basis.
//
// Synchronization of the ClusterContext data structure happens by
// protecting all inner shared resources with a RwLock. This enables
// us to differentiate between reader locks and writer lock. Only one
// writer exists, that will currently perform an active poll and
// request information to the API server. Many readers may exist (many
// policies reading the latest information from the cluster context).
#[derive(Default)]
pub struct ClusterContext {
    ingresses: RwLock<String>,
    namespaces: RwLock<String>,
    services: RwLock<String>,
}

impl ClusterContext {
    // Initialize a ClusterContext. With the current implementation
    // this will start an active polling loop.
    #[allow(unused_must_use)]
    pub fn init() -> Result<()> {
        let mut context_initialized = CLUSTER_CONTEXT_INITIALIZED.lock().unwrap();
        if *context_initialized {
            return Ok(());
        }
        *context_initialized = true;
        thread::spawn(|| {
            let rt = match Builder::new_current_thread().enable_all().build() {
                Ok(r) => r,
                Err(error) => {
                    panic!("error initializing tokio runtime: {}", error);
                }
            };
            let client = match rt.block_on(Client::try_default()) {
                Ok(client) => client,
                Err(error) => panic!("could not initialize Kubernetes client: {}", error),
            };
            loop {
                rt.block_on(ClusterContext::get().refresh(&client));
                thread::sleep(std::time::Duration::from_secs(5));
            }
        });
        Ok(())
    }

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

    pub async fn refresh(&self, client: &Client) -> kube::Result<()> {
        // TODO (ereslibre): use macros to remove duplication and then
        // generalize
        {
            let ingress_list_req = Resource::all::<Ingress>().list(&ListParams::default())?;
            let ingress_list = client.request_text(ingress_list_req).await?;
            if let Ok(mut ingresses) = self.ingresses.write() {
                *ingresses = ingress_list
            };
        };
        {
            let namespace_list_req = Resource::all::<Namespace>().list(&ListParams::default())?;
            let namespace_list = client.request_text(namespace_list_req).await?;
            if let Ok(mut namespaces) = self.namespaces.write() {
                *namespaces = namespace_list
            };
        };
        {
            let service_list_req = Resource::all::<Service>().list(&ListParams::default())?;
            let service_list = client.request_text(service_list_req).await?;
            if let Ok(mut services) = self.services.write() {
                *services = service_list
            };
        };
        Ok(())
    }
}
