use anyhow::{anyhow, Result};
use kube::core::{DynamicObject, ObjectList};
use std::collections::HashMap;
use tokio::sync::RwLock;

use crate::callback_handler::kubernetes::{reflector::Reflector, ApiVersionKind, KubeResource};

pub(crate) struct Client {
    kube_client: kube::Client,
    kube_resources: RwLock<HashMap<ApiVersionKind, KubeResource>>,
    reflectors: RwLock<HashMap<String, Reflector>>,
}

impl Client {
    pub fn new(client: kube::Client) -> Self {
        Self {
            kube_client: client,
            kube_resources: RwLock::new(HashMap::new()),
            reflectors: RwLock::new(HashMap::new()),
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
            _ => self
                .kube_client
                .list_api_group_resources(api_version)
                .await
                .map_err(|e| anyhow!("error finding resource {api_version} / {kind}: {e}"))?,
        };

        let resource = resources_list
            .resources
            .iter()
            .find(|r| r.kind == kind)
            .ok_or_else(|| anyhow!("Cannot find resource {api_version}/{kind}"))?
            .to_owned();

        let (group, version) = match api_version {
            "v1" => ("", "v1"),
            _ => api_version
                .split_once('/')
                .ok_or_else(|| anyhow!("cannot determine group and version for {api_version}"))?,
        };

        let kube_resource = KubeResource {
            resource: kube::api::ApiResource {
                group: group.to_string(),
                version: version.to_string(),
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

    async fn get_reflector_reader(
        &mut self,
        reflector_id: &str,
        resource: KubeResource,
        namespace: Option<String>,
        label_selector: Option<String>,
        field_selector: Option<String>,
    ) -> Result<kube::runtime::reflector::Store<kube::core::DynamicObject>> {
        let reader = {
            let reflectors = self.reflectors.read().await;
            reflectors
                .get(reflector_id)
                .map(|reflector| reflector.reader.clone())
        };
        if let Some(reader) = reader {
            return Ok(reader);
        }

        let reflector = Reflector::create_and_run(
            self.kube_client.clone(),
            resource,
            namespace,
            label_selector,
            field_selector,
        )
        .await?;
        let reader = reflector.reader.clone();

        {
            let mut reflectors = self.reflectors.write().await;
            reflectors.insert(reflector_id.to_string(), reflector);
        }

        Ok(reader)
    }

    pub async fn list_resources_by_namespace(
        &mut self,
        api_version: &str,
        kind: &str,
        namespace: &str,
        label_selector: Option<String>,
        field_selector: Option<String>,
    ) -> Result<ObjectList<kube::core::DynamicObject>> {
        let resource = self.build_kube_resource(api_version, kind).await?;
        if !resource.namespaced {
            return Err(anyhow!("resource {api_version}/{kind} is cluster wide. Cannot search for it inside of a namespace"));
        }

        self.list_resources_from_reflector(
            resource,
            Some(namespace.to_owned()),
            label_selector,
            field_selector,
        )
        .await
    }

    pub async fn list_resources_all(
        &mut self,
        api_version: &str,
        kind: &str,
        label_selector: Option<String>,
        field_selector: Option<String>,
    ) -> Result<ObjectList<kube::core::DynamicObject>> {
        let resource = self.build_kube_resource(api_version, kind).await?;

        self.list_resources_from_reflector(resource, None, label_selector, field_selector)
            .await
    }

    async fn list_resources_from_reflector(
        &mut self,
        resource: KubeResource,
        namespace: Option<String>,
        label_selector: Option<String>,
        field_selector: Option<String>,
    ) -> Result<ObjectList<kube::core::DynamicObject>> {
        let api_version = resource.resource.api_version.clone();
        let kind = resource.resource.kind.clone();

        let reflector_id = Reflector::compute_id(
            &resource,
            namespace.as_deref(),
            label_selector.as_deref(),
            field_selector.as_deref(),
        );

        let reader = self
            .get_reflector_reader(
                &reflector_id,
                resource,
                namespace,
                label_selector,
                field_selector,
            )
            .await?;

        Ok(ObjectList {
            types: kube::core::TypeMeta {
                api_version,
                kind: format!("{kind}List"),
            },
            metadata: Default::default(),
            items: reader
                .state()
                .iter()
                .map(|v| DynamicObject::clone(v))
                .collect(),
        })
    }

    pub async fn get_resource(
        &mut self,
        api_version: &str,
        kind: &str,
        name: &str,
        namespace: Option<&str>,
    ) -> Result<kube::core::DynamicObject> {
        let resource = self.build_kube_resource(api_version, kind).await?;

        let api = match resource.namespaced {
            true => kube::api::Api::<kube::core::DynamicObject>::namespaced_with(
                self.kube_client.clone(),
                namespace.ok_or_else(|| {
                    anyhow!(
                        "Resource {}/{} is namespaced, but no namespace was provided",
                        api_version,
                        kind
                    )
                })?,
                &resource.resource,
            ),
            false => kube::api::Api::<kube::core::DynamicObject>::all_with(
                self.kube_client.clone(),
                &resource.resource,
            ),
        };

        api.get_opt(name)
            .await
            .map_err(anyhow::Error::new)?
            .ok_or_else(|| anyhow!("Cannot find {api_version}/{kind} named '{name}' inside of namespace '{namespace:?}'"))
    }

    pub async fn get_resource_plural_name(
        &mut self,
        api_version: &str,
        kind: &str,
    ) -> Result<String> {
        let resource = self.build_kube_resource(api_version, kind).await?;
        Ok(resource.resource.plural)
    }
}
