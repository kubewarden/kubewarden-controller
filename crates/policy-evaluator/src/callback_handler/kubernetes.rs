use anyhow::{anyhow, Result};
use cached::proc_macro::cached;
use kube::api::ListParams;
use serde::Serialize;
use std::collections::HashMap;
use tokio::sync::RwLock;

#[derive(Eq, Hash, PartialEq)]
struct ApiVersionKind {
    api_version: String,
    kind: String,
}

#[derive(Debug, Clone, Serialize)]
struct KubeResource {
    pub resource: kube::api::ApiResource,
    pub namespaced: bool,
}

pub(crate) struct Client {
    kube_client: kube::Client,
    kube_resources: RwLock<HashMap<ApiVersionKind, KubeResource>>,
}

/// This is a specialized `kube::api::ObjectList` object which
/// implements the `Clone` trait. This trait is required by
/// `cached::Return<>`
#[derive(Clone, Serialize)]
pub(crate) struct ObjectList {
    pub metadata: kube::core::ListMeta,
    pub items: Vec<kube::core::DynamicObject>,
}

impl Client {
    pub fn new(client: kube::Client) -> Self {
        Self {
            kube_client: client,
            kube_resources: RwLock::new(HashMap::new()),
        }
    }

    /// Build a KubeResource using the apiVersion and Kind "coordinates" provided.
    /// The result is then cached locally to avoid further interactions with
    /// the Kubernetes API Server
    async fn build_kube_resource(&mut self, api_version: &str, kind: &str) -> Result<KubeResource> {
        let avk = ApiVersionKind {
            api_version: api_version.to_string(),
            kind: kind.to_string(),
        };

        // take a reader lock and search for the resource inside of the
        // known resources
        let kube_resource = {
            let known_resources = self.kube_resources.read().await;
            known_resources.get(&avk).map(|r| r.to_owned())
        };
        if let Some(kr) = kube_resource {
            return Ok(kr);
        }

        // the resource is not known yet, we have to search it
        let resources_list = match api_version {
            "v1" => {
                self.kube_client
                    .list_core_api_resources(api_version)
                    .await?
            }
            _ => {
                self.kube_client
                    .list_api_group_resources(api_version)
                    .await?
            }
        };

        let resource = resources_list
            .resources
            .iter()
            .find(|r| r.kind == kind)
            .ok_or_else(|| anyhow!("Cannot find resource {api_version}/{kind}"))?
            .to_owned();

        let kube_resource = KubeResource {
            resource: kube::api::ApiResource {
                group: resource.group.unwrap_or_default(),
                version: resource.version.unwrap_or_default(),
                api_version: api_version.to_string(),
                kind: kind.to_string(),
                plural: resource.name,
            },
            namespaced: resource.namespaced,
        };

        // Take a writer lock and cache the resource we just found
        let mut known_resources = self.kube_resources.write().await;
        known_resources.insert(avk, kube_resource.clone());

        Ok(kube_resource)
    }

    async fn list_resources_by_namespace(
        &mut self,
        api_version: &str,
        kind: &str,
        namespace: &str,
        list_params: &ListParams,
    ) -> Result<ObjectList> {
        let resource = self.build_kube_resource(api_version, kind).await?;

        if !resource.namespaced {
            return Err(anyhow!("resource {api_version}/{kind} is cluster wide. Cannot search for it inside of a namespace"));
        }

        let api = kube::api::Api::<kube::core::DynamicObject>::namespaced_with(
            self.kube_client.clone(),
            namespace,
            &resource.resource,
        );

        let resource_list = api.list(list_params).await?;
        Ok(ObjectList {
            metadata: resource_list.metadata,
            items: resource_list.items,
        })
    }

    async fn list_resources_all(
        &mut self,
        api_version: &str,
        kind: &str,
        list_params: &ListParams,
    ) -> Result<ObjectList> {
        let resource = self.build_kube_resource(api_version, kind).await?;

        let api = kube::api::Api::<kube::core::DynamicObject>::all_with(
            self.kube_client.clone(),
            &resource.resource,
        );

        let resource_list = api.list(list_params).await?;
        Ok(ObjectList {
            metadata: resource_list.metadata,
            items: resource_list.items,
        })
    }
}

#[cached(
    time = 60,
    result = true,
    sync_writes = true,
    key = "String",
    convert = r#"{ format!("list_resources_by_namespace({},{},{},{:?},{:?})", api_version, kind, namespace, label_selector, field_selector) }"#,
    with_cached_flag = true
)]
pub(crate) async fn list_resources_by_namespace(
    client: Option<&mut Client>,
    api_version: &str,
    kind: &str,
    namespace: &str,
    label_selector: Option<String>,
    field_selector: Option<String>,
) -> Result<cached::Return<ObjectList>> {
    if client.is_none() {
        return Err(anyhow!("kube::Client was not initialized properly")).map(cached::Return::new);
    }

    let list_params = kube::core::params::ListParams {
        label_selector,
        field_selector,
        ..Default::default()
    };

    client
        .unwrap()
        .list_resources_by_namespace(api_version, kind, namespace, &list_params)
        .await
        .map(cached::Return::new)
}

#[cached(
    time = 60,
    result = true,
    sync_writes = true,
    key = "String",
    convert = r#"{ format!("list_resources_all({},{}),{:?},{:?}", api_version, kind,label_selector,field_selector) }"#,
    with_cached_flag = true
)]
pub(crate) async fn list_resources_all(
    client: Option<&mut Client>,
    api_version: &str,
    kind: &str,
    label_selector: Option<String>,
    field_selector: Option<String>,
) -> Result<cached::Return<ObjectList>> {
    if client.is_none() {
        return Err(anyhow!("kube::Client was not initialized properly")).map(cached::Return::new);
    }

    let list_params = kube::core::params::ListParams {
        label_selector,
        field_selector,
        ..Default::default()
    };

    client
        .unwrap()
        .list_resources_all(api_version, kind, &list_params)
        .await
        .map(cached::Return::new)
}
