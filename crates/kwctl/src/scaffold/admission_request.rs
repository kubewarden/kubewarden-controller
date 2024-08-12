use std::{
    collections::HashMap,
    fmt::{self, Display, Formatter},
    fs::File,
    future::Future,
    path::PathBuf,
    str::FromStr,
};

use anyhow::{anyhow, Result};
use directories::ProjectDirs;
use k8s_openapi::{
    api::authentication::v1::UserInfo,
    apimachinery::pkg::{apis::meta::v1::APIResource, runtime::RawExtension},
};
use kube::api::DynamicObject;
use lazy_static::lazy_static;
use policy_evaluator::admission_request::{
    AdmissionRequest, GroupVersionKind, GroupVersionResource,
};
use policy_evaluator::kube;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

lazy_static! {
    pub static ref DEFAULT_ROOT: ProjectDirs =
        ProjectDirs::from("io.kubewarden", "", "kubewarden").unwrap();
    pub static ref DEFAULT_KWCTL_CACHE: PathBuf = DEFAULT_ROOT.cache_dir().join("kwctl");
    pub static ref RESOURCE_CATALOG_FILE: PathBuf =
        DEFAULT_KWCTL_CACHE.join("resource_catalog.json");
}

const FALLBACK_API_RESOURCE_PLURAL_NAME: &str = "this-is-the-plural-name-of-the-resource-this-information-is-not-used-by-policies-and-requires-a-connection-to-an-api-server-to-be-obtained";

/// Types of AdmissionRequest operation we can scaffold
pub(crate) enum Operation {
    Create,
    Update,
    Delete,
}

impl FromStr for Operation {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "CREATE" => Ok(Operation::Create),
            "UPDATE" => Ok(Operation::Update),
            "DELETE" => Ok(Operation::Delete),
            _ => Err(format!("Invalid operation: {}", s)),
        }
    }
}

impl Display for Operation {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Operation::Create => write!(f, "CREATE"),
            Operation::Update => write!(f, "UPDATE"),
            Operation::Delete => write!(f, "DELETE"),
        }
    }
}

#[derive(Debug, Default)]
enum ApiResourceCatalogRestoredFrom {
    #[default]
    Cache,
    ApiServer,
    Empty,
}

/// A catalog of Kubernetes resources. The catalog is built once by querying a Kubernetes API server.
///
/// This is required because some information about the resource being scaffolded cannot be
/// inferred from the object itself. For example: knowning if a resource is namespaced or not, or
/// the plural name of the resource.
#[derive(Serialize, Deserialize, Debug)]
struct ApiResourceCatalog {
    resources: HashMap<String, APIResource>,
    #[serde(skip)]
    restored_from: ApiResourceCatalogRestoredFrom,
}

impl ApiResourceCatalog {
    /// Create a new catalog. The function will try to load the catalog from disk, if it fails
    /// it will build it by querying the Kubernetes API server.
    /// If querying the API server fails, the function will return an empty catalog.
    ///
    /// The creation of the `kube::Client` is deferred. The catalog creates it only when the
    /// local cache is not available and it needs to query the API server.
    /// Creating the client can take some time, so it's better to defer it.
    pub async fn new<F, Fut>(resource_catalog_file: PathBuf, build_kubeclient_fn: F) -> Self
    where
        F: FnOnce() -> Fut + Clone,
        Fut: Future<Output = Result<kube::Client>>,
    {
        match Self::init(resource_catalog_file, build_kubeclient_fn).await {
            Ok(catalog) => catalog,
            Err(err) => {
                warn!(?err, "Failed to load resource catalog");
                Self {
                    resources: HashMap::new(),
                    restored_from: ApiResourceCatalogRestoredFrom::Empty,
                }
            }
        }
    }

    async fn init<F, Fut>(catalog_path: PathBuf, build_kubeclient_fn: F) -> Result<Self>
    where
        F: FnOnce() -> Fut + Clone,
        Fut: Future<Output = Result<kube::Client>>,
    {
        if catalog_path.exists() {
            debug!("Resource catalog found, loading it");
            let file = File::open(catalog_path.clone())?;
            let catalog: Self = serde_json::from_reader(file)?;
            Ok(catalog)
        } else {
            info!("Resource catalog not found, building it");
            let client = build_kubeclient_fn().await?;
            let catalog = Self::build(client).await?;
            if let Err(err) = catalog.save(catalog_path) {
                warn!(?err, "Failed to save resource catalog");
            }
            Ok(catalog)
        }
    }

    async fn build(client: kube::Client) -> Result<Self> {
        let mut resources: HashMap<String, APIResource> = HashMap::new();

        // Build knowledge about core resources
        let core_resources = client.list_core_api_resources("v1").await?;
        for resource in &core_resources.resources {
            if resource.name.contains("/") {
                // skip sub-resources
                continue;
            }
            let gvk = kube::api::GroupVersionKind {
                group: "".to_string(),
                version: "v1".to_string(),
                kind: resource.kind.clone(),
            };
            resources.insert(Self::gvk_to_string(&gvk), resource.to_owned());
        }

        // Build knowledge about all the non-core resources
        let api_groups = client.list_api_groups().await?;
        for group in &api_groups.groups {
            let version = group
                .preferred_version
                .as_ref()
                .or_else(|| group.versions.first())
                .ok_or(anyhow!(
                    "cannot find preferred version or version for group {}",
                    group.name
                ))?;

            let group_resources = client
                .list_api_group_resources(&version.group_version)
                .await?;

            for resource in &group_resources.resources {
                if resource.name.contains("/") {
                    // skip sub-resources
                    continue;
                }

                let gvk = kube::api::GroupVersionKind {
                    group: group.name.clone(),
                    version: version.version.clone(),
                    kind: resource.kind.clone(),
                };
                resources.insert(Self::gvk_to_string(&gvk), resource.to_owned());
            }
        }

        Ok(Self {
            resources,
            restored_from: ApiResourceCatalogRestoredFrom::ApiServer,
        })
    }

    pub fn save(&self, catalog_path: PathBuf) -> Result<()> {
        let catalog_dir = catalog_path
            .parent()
            .ok_or(anyhow!("catalog path has no parent"))?;
        if !catalog_dir.exists() {
            std::fs::create_dir_all(catalog_dir)
                .map_err(|err| anyhow!("failed to create cache directory: {err:?}"))?;
        }

        let file = File::create(catalog_path)
            .map_err(|err| anyhow!("failed to create resource catalog file: {err:?}"))?;
        serde_json::to_writer(&file, self)
            .map_err(|err| anyhow!("failed to write resource catalog: {err:?}"))?;

        Ok(())
    }

    pub fn lookup(
        &self,
        gvk: &kube::api::GroupVersionKind,
    ) -> Option<&k8s_openapi::apimachinery::pkg::apis::meta::v1::APIResource> {
        self.resources.get(&Self::gvk_to_string(gvk))
    }

    /// Refresh the catalog by querying the Kubernetes API server.
    /// This applies only if the catalog was built from the cache.
    pub async fn refresh<F, Fut>(&mut self, build_kubeclient_fn: F) -> Result<()>
    where
        F: FnOnce() -> Fut + Clone,
        Fut: Future<Output = Result<kube::Client>>,
    {
        match self.restored_from {
            ApiResourceCatalogRestoredFrom::Cache => {
                let client = build_kubeclient_fn().await?;
                let fresh_catalog = Self::build(client).await?;

                self.resources.clear();
                self.resources.extend(fresh_catalog.resources);
                self.restored_from = ApiResourceCatalogRestoredFrom::ApiServer;
            }
            _ => {
                // Nothing to do
            }
        }
        Ok(())
    }

    /// Convert a GroupVersionKind to a string. This is used as a key in the catalog.
    /// This proves to be faster to implement than doing a custom serialization/deserialization
    /// for the GroupVersionKind struct.
    ///
    /// All the fields of GroupVersionKind are joined by a pipe character, which is a symbol
    /// not accepted by Kubernetes.
    fn gvk_to_string(gvk: &kube::api::GroupVersionKind) -> String {
        format!("{}|{}|{}", gvk.group, gvk.version, gvk.kind)
    }
}

// Build a client to interact with the Kubernetes API server.
// The scaffold command must be snappy, we don't want it to get stuck
// waiting for the connection to Kubernetes to be established.
// Because of that we set a connection timeout of 1 second.
async fn build_kube_client() -> Result<kube::Client> {
    let mut config = kube::Config::infer().await?;
    config.connect_timeout = Some(std::time::Duration::from_secs(1));
    let client = kube::Client::try_from(config)?;
    Ok(client)
}

pub(crate) async fn admission_request(
    operation: Operation,
    object: Option<PathBuf>,
    old_object: Option<PathBuf>,
) -> Result<()> {
    validate_params(&operation, object.as_ref(), old_object.as_ref())?;

    let output = match operation {
        Operation::Create => {
            scaffold_create(
                RESOURCE_CATALOG_FILE.to_path_buf(),
                build_kube_client,
                object.unwrap(),
            )
            .await?
        }
        Operation::Update => todo!(),
        Operation::Delete => todo!(),
    };

    println!("{}", output);
    Ok(())
}

fn validate_params(
    operation: &Operation,
    object_path: Option<&PathBuf>,
    old_object_path: Option<&PathBuf>,
) -> Result<()> {
    match operation {
        Operation::Create => {
            if object_path.is_none() {
                anyhow::bail!("CREATE operation requires an object");
            }
            if old_object_path.is_some() {
                anyhow::bail!("CREATE operation does not require an old_object");
            }
        }
        Operation::Update => {
            if object_path.is_none() {
                anyhow::bail!("UPDATE operation requires an object");
            }
            if old_object_path.is_none() {
                anyhow::bail!("UPDATE operation requires an old_object");
            }
        }
        Operation::Delete => {
            if object_path.is_some() {
                anyhow::bail!("DELETE operation does not require an object");
            }
            if old_object_path.is_none() {
                anyhow::bail!("DELETE operation requires an old_object");
            }
        }
    }

    Ok(())
}

async fn scaffold_create<F, Fut>(
    resource_catalog_file: PathBuf,
    kube_client: F,
    object_path: PathBuf,
) -> Result<String>
where
    F: FnOnce() -> Fut + Clone,
    Fut: Future<Output = Result<kube::Client>>,
{
    let mut resource_catalog =
        ApiResourceCatalog::new(resource_catalog_file, kube_client.clone()).await;

    let file = File::open(object_path.clone()).map_err(|err| {
        anyhow!(
            "failed to open object file {}: {}",
            object_path.to_string_lossy(),
            err
        )
    })?;
    let object: DynamicObject = serde_yaml::from_reader(file).map_err(|err| {
        anyhow!(
            "failed to parse object file {}: {}",
            object_path.to_string_lossy(),
            err
        )
    })?;

    let object_type_meta = object.clone().types.ok_or(anyhow!(
        "object defined inside of {} is missing types",
        object_path.to_string_lossy()
    ))?;

    let kube_gvk: kube::api::GroupVersionKind = object_type_meta.try_into()?;
    let api_resource = match resource_catalog.lookup(&kube_gvk) {
        Some(ar) => Some(ar),
        None => {
            // Try to refresh the catalog and lookup again
            if resource_catalog.refresh(kube_client).await.is_ok() {
                if let Err(err) = resource_catalog.save(object_path) {
                    warn!(?err, "Failed to save resource catalog");
                }
                resource_catalog.lookup(&kube_gvk)
            } else {
                None
            }
        }
    };
    if api_resource.is_none() {
        warn!(
            "Could not find information for {:?}, some scaffolded data is not going to be accurate.",
            kube_gvk
        );
    }

    let resource = match api_resource {
        Some(ar) => ar.name.clone(),
        None => FALLBACK_API_RESOURCE_PLURAL_NAME.to_string(),
    };

    let namespace = if object.metadata.namespace.is_some() {
        object.metadata.namespace.clone()
    } else if let Some(ar) = api_resource {
        if ar.namespaced {
            Some("default".to_string())
        } else {
            None
        }
    } else {
        None
    };

    let object_kind = GroupVersionKind {
        group: kube_gvk.group.clone(),
        version: kube_gvk.version.clone(),
        kind: kube_gvk.kind.clone(),
    };
    let object_gvr = GroupVersionResource {
        group: kube_gvk.group.clone(),
        version: kube_gvk.version.clone(),
        resource,
    };

    let object_json = serde_json::to_value(object.clone())?;

    let request = AdmissionRequest {
        // hard-coded UID
        uid: "705ab4f5-6393-11e8-b7cc-42010a800002".to_string(),
        kind: object_kind.clone(),
        request_kind: Some(object_kind),
        resource: object_gvr.clone(),
        request_resource: Some(object_gvr),
        sub_resource: None,
        request_sub_resource: None,
        name: object.metadata.name,
        namespace,
        operation: Operation::Create.to_string(),
        user_info: UserInfo {
            username: Some("test-user".to_string()),
            groups: Some(vec!["system:masters".to_string()]),
            ..Default::default()
        },
        object: Some(RawExtension(object_json)),
        old_object: None,
        dry_run: None,
        options: None,
    };

    let output = serde_json::to_string_pretty(&request)?;

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::File;
    use std::io::Write;

    use hyper::{http, Request, Response};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{
        APIGroup, APIGroupList, APIResource, APIResourceList, GroupVersionForDiscovery,
    };
    use kube::client::Body;
    use rstest::*;
    use tower_test::mock::{Handle, SendResponse};

    #[rstest]
    #[case::create_with_right_params(Operation::Create, Some(PathBuf::from_str("new").unwrap()), None, true)]
    #[case::create_with_old_object(Operation::Create, Some(PathBuf::from_str("new").unwrap()), Some(PathBuf::from_str("old").unwrap()), false)]
    #[case::update_with_right_params(Operation::Update, Some(PathBuf::from_str("new").unwrap()), Some(PathBuf::from_str("old").unwrap()), true)]
    #[case::update_without_object(Operation::Update, None, Some(PathBuf::from_str("old").unwrap()), false)]
    #[case::update_without_old_object(Operation::Update, Some(PathBuf::from_str("new").unwrap()), None, false)]
    #[case::update_without_object_and_old_object(Operation::Update, None, None, false)]
    #[case::delete_with_right_params(Operation::Delete, None, Some(PathBuf::from_str("old").unwrap()), true)]
    #[case::delete_with_object(Operation::Delete, Some(PathBuf::from_str("not expected").unwrap()), Some(PathBuf::from_str("old").unwrap()), false)]
    #[case::delete_without_old_object(Operation::Delete, None, None, false)]
    #[case::delete_without_object_and_old_object(Operation::Delete, None, None, false)]
    fn test_validate_params(
        #[case] operation: Operation,
        #[case] object_path: Option<PathBuf>,
        #[case] old_object_path: Option<PathBuf>,
        #[case] valid: bool,
    ) {
        assert_eq!(
            valid,
            validate_params(&operation, object_path.as_ref(), old_object_path.as_ref()).is_ok()
        );
    }

    fn apis_list() -> APIGroupList {
        APIGroupList {
            groups: vec![APIGroup {
                name: "apps".to_owned(),
                versions: vec![GroupVersionForDiscovery {
                    group_version: "apps/v1".to_owned(),
                    version: "v1".to_owned(),
                }],
                preferred_version: Some(GroupVersionForDiscovery {
                    group_version: "apps/v1".to_owned(),
                    version: "v1".to_owned(),
                }),
                ..Default::default()
            }],
        }
    }

    fn v1_resource_list() -> APIResourceList {
        APIResourceList {
            group_version: "v1".to_owned(),
            resources: vec![
                APIResource {
                    name: "namespaces".to_owned(),
                    singular_name: "namespace".to_owned(),
                    namespaced: false,
                    kind: "Namespace".to_owned(),
                    ..Default::default()
                },
                APIResource {
                    name: "services".to_owned(),
                    singular_name: "service".to_owned(),
                    namespaced: true,
                    kind: "Service".to_owned(),
                    ..Default::default()
                },
            ],
        }
    }

    fn apps_v1_resource_list() -> APIResourceList {
        APIResourceList {
            group_version: "apps/v1".to_owned(),
            resources: vec![APIResource {
                name: "deployments".to_owned(),
                singular_name: "deployment".to_owned(),
                namespaced: true,
                kind: "Deployment".to_owned(),
                ..Default::default()
            }],
        }
    }

    async fn handle_discovery(handle: Handle<Request<Body>, Response<Body>>) {
        tokio::spawn(async move {
            let mut handle = handle;

            loop {
                let (request, send) = handle.next_request().await.expect("service not called");

                match (request.method(), request.uri().path()) {
                    (&http::Method::GET, "/apis") => {
                        send_response(send, apis_list());
                    }
                    (&http::Method::GET, "/api/v1") => {
                        send_response(send, v1_resource_list());
                    }
                    (&http::Method::GET, "/apis/apps/v1") => {
                        send_response(send, apps_v1_resource_list());
                    }
                    _ => {
                        panic!("unexpected request: {:?}", request);
                    }
                }
            }
        });
    }

    async fn expect_no_request(handle: Handle<Request<Body>, Response<Body>>) {
        tokio::spawn(async move {
            let mut handle = handle;

            let (request, _) = handle.next_request().await.expect("service not called");
            panic!("unexpected request: {:?}", request);
        });
    }

    fn send_response<T: Serialize>(send: SendResponse<Response<Body>>, response: T) {
        let response = serde_json::to_vec(&response).unwrap();
        send.send_response(Response::builder().body(Body::from(response)).unwrap());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn create_catalog_by_querying_api_server() {
        let tempdir = tempfile::tempdir().unwrap();
        let catalog_file = tempdir.path().join("resource_catalog.json");

        let (mocksvc, handle) = tower_test::mock::pair::<Request<Body>, Response<Body>>();
        handle_discovery(handle).await;

        let build_mock_kube_client = || async { Ok(kube::Client::new(mocksvc, "default")) };

        let catalog = ApiResourceCatalog::init(catalog_file.clone(), build_mock_kube_client)
            .await
            .expect("catalog creation failed");

        assert!(catalog
            .lookup(&kube::api::GroupVersionKind {
                group: "".to_string(),
                version: "v1".to_string(),
                kind: "Namespace".to_string()
            })
            .is_some());
        assert!(catalog
            .lookup(&kube::api::GroupVersionKind {
                group: "".to_string(),
                version: "v1".to_string(),
                kind: "Service".to_string()
            })
            .is_some());
        assert!(catalog
            .lookup(&kube::api::GroupVersionKind {
                group: "apps".to_string(),
                version: "v1".to_string(),
                kind: "Deployment".to_string()
            })
            .is_some());
        assert!(catalog_file.exists());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn create_catalog_by_reusing_cache_file() {
        let tempdir = tempfile::tempdir().unwrap();
        let catalog_file = tempdir.path().join("resource_catalog.json");

        let catalog = ApiResourceCatalog {
            resources: vec![(
                "|v1|Namespace".to_string(),
                APIResource {
                    name: "namespaces".to_owned(),
                    singular_name: "namespace".to_owned(),
                    namespaced: false,
                    kind: "Namespace".to_owned(),
                    ..Default::default()
                },
            )]
            .into_iter()
            .collect(),
            restored_from: ApiResourceCatalogRestoredFrom::Cache,
        };
        catalog
            .save(catalog_file.clone())
            .expect("failed to save catalog");

        let (mocksvc, handle) = tower_test::mock::pair::<Request<Body>, Response<Body>>();
        expect_no_request(handle).await;

        let build_mock_kube_client = || async { Ok(kube::Client::new(mocksvc, "default")) };

        let catalog = ApiResourceCatalog::init(catalog_file.clone(), build_mock_kube_client)
            .await
            .expect("catalog creation failed");

        assert!(catalog
            .lookup(&kube::api::GroupVersionKind {
                group: "".to_string(),
                version: "v1".to_string(),
                kind: "Namespace".to_string()
            })
            .is_some());
        assert!(catalog
            .lookup(&kube::api::GroupVersionKind {
                group: "apps".to_string(),
                version: "v1".to_string(),
                kind: "Deployment".to_string()
            })
            .is_none());
        assert!(catalog_file.exists());
    }

    const NAMESPACE_YAML: &str = r#"
        apiVersion: v1
        kind: Namespace
        metadata:
          name: my-namespace"#;

    const SERVICE_YAML: &str = r#"
        apiVersion: v1
        kind: Service
        metadata:
          name: my-service
          namespace: my-namespace
        spec:
          selector:
            app: my-app
          ports:
            - protocol: TCP
              port: 80
              targetPort: 9376"#;

    const PERSISTENT_VOLUME_CLAIM_YAML: &str = r#"
        apiVersion: v1
        kind: PersistentVolumeClaim
        metadata:
          name: my-pvc
          namespace: my-namespace
        spec:
          accessModes:
            - ReadWriteOnce
          resources:
            requests:
              storage: 1Gi"#;

    // creates a ApiResourceCatalog with a single resource(Namespace)
    // that has been restored from cache
    fn build_basic_catalog() -> ApiResourceCatalog {
        ApiResourceCatalog {
            resources: vec![(
                "|v1|Namespace".to_string(),
                APIResource {
                    name: "namespaces".to_owned(),
                    singular_name: "namespace".to_owned(),
                    namespaced: false,
                    kind: "Namespace".to_owned(),
                    ..Default::default()
                },
            )]
            .into_iter()
            .collect(),
            restored_from: ApiResourceCatalogRestoredFrom::Cache,
        }
    }

    #[rstest]
    #[case::use_local_cache(
        NAMESPACE_YAML,
        build_basic_catalog(),
        true,
        expect_no_request,
        GroupVersionKind {
            group: "".to_string(),
            version: "v1".to_string(),
            kind: "Namespace".to_string(),
        },
        GroupVersionResource {
            group: "".to_string(),
            version: "v1".to_string(),
            resource: "namespaces".to_string(),
        },
    )]
    #[case::find_unknown_resource_by_querying_api_server(
        SERVICE_YAML,
        build_basic_catalog(),
        false,
        handle_discovery,
        GroupVersionKind {
            group: "".to_string(),
            version: "v1".to_string(),
            kind: "Service".to_string(),
        },
        GroupVersionResource {
            group: "".to_string(),
            version: "v1".to_string(),
            resource: "services".to_string(),
        },
    )]
    #[case::totally_unknown_resource(
        PERSISTENT_VOLUME_CLAIM_YAML,
        build_basic_catalog(),
        false,
        handle_discovery,
        GroupVersionKind {
            group: "".to_string(),
            version: "v1".to_string(),
            kind: "PersistentVolumeClaim".to_string(),
        },
        GroupVersionResource {
            group: "".to_string(),
            version: "v1".to_string(),
            resource: FALLBACK_API_RESOURCE_PLURAL_NAME.to_string(),
        },
    )]
    #[tokio::test(flavor = "multi_thread")]
    async fn scaffold_create_operation<F, Fut>(
        #[case] raw_object: &str,
        #[case] catalog: ApiResourceCatalog,
        #[case] already_knew_resource: bool,
        #[case] scenario: F,
        #[case] expected_group_version_kind: GroupVersionKind,
        #[case] expected_group_resource: GroupVersionResource,
    ) where
        F: FnOnce(Handle<Request<Body>, Response<Body>>) -> Fut,
        Fut: Future<Output = ()>,
    {
        let tempdir = tempfile::tempdir().unwrap();
        let catalog_filepath = tempdir.path().join("resource_catalog.json");

        let object_filepath = tempdir.path().join("namespace.yaml");
        let mut object_file = File::create(&object_filepath).expect("failed to create object file");
        object_file
            .write_all(raw_object.as_bytes())
            .expect("failed to write object file");

        let object_value: serde_json::Value = serde_yaml::from_str(raw_object)
            .expect("failed to convert raw object into serde value");

        catalog
            .save(catalog_filepath.clone())
            .expect("failed to save catalog");

        let (mocksvc, handle) = tower_test::mock::pair::<Request<Body>, Response<Body>>();
        scenario(handle).await;

        let build_mock_kube_client = || async { Ok(kube::Client::new(mocksvc, "default")) };
        let output = scaffold_create(
            catalog_filepath.clone(),
            build_mock_kube_client,
            object_filepath.clone(),
        )
        .await
        .expect("scaffold failed");

        let admission_request: AdmissionRequest =
            serde_json::from_str(&output).expect("failed to parse output");
        assert_eq!(admission_request.operation, "CREATE");
        assert_eq!(admission_request.kind, expected_group_version_kind);
        assert_eq!(admission_request.resource, expected_group_resource,);
        assert_eq!(admission_request.object, Some(RawExtension(object_value)));

        if already_knew_resource {
            let catalog: ApiResourceCatalog = serde_json::from_reader(
                File::open(catalog_filepath).expect("failed to open catalog file"),
            )
            .expect("failed to parse catalog");
            let gvk = kube::api::GroupVersionKind {
                group: expected_group_version_kind.group.clone(),
                version: expected_group_version_kind.version.clone(),
                kind: expected_group_version_kind.kind.clone(),
            };
            assert!(catalog.lookup(&gvk).is_some());
        }
    }
}
