use anyhow::Result;
use futures::{future::ready, StreamExt, TryStreamExt};
use kube::{
    runtime::{reflector::store::Writer, watcher, WatchStreamExt},
    ResourceExt,
};
use tracing::{debug, info, warn};

use crate::callback_handler::kubernetes::KubeResource;

/// A reflector fetches kubernetes objects based on filtering criteria.
/// When created, the list is populated slowly, to prevent hammering the Kubernetes API server.
/// The items are stored in-memory. The `managedFields` attribute is stripped from all the objects
/// to reduce memory consumption. All the other fields are retained.
/// A Kubernetes Watch is then created to keep the contents of the list updated.
///
/// This is code relies heavily on the `kube::runtime::reflector` module.
///
/// ## Stale date
///
/// There's always some delay involved with Kubernetes notifications. That depends on
/// different factors like: the load on the Kubernetes API server, the number of watchers to be
/// notifies,... That means, changes are not propagated immediately, hence the cache can have stale
/// data.
///
/// Finally, when started, the Reflector takes some time to make the loaded data available to
/// consumers.
pub(crate) struct Reflector {
    /// Read-only access to the data cached by the Reflector
    pub reader: kube::runtime::reflector::Store<kube::core::DynamicObject>,
}

impl Reflector {
    /// Compute a unique identifier for the Reflector. This is used to prevent the creation of two
    /// Reflectors watching the same set of resources.
    pub fn compute_id(
        resource: &KubeResource,
        namespace: Option<&str>,
        label_selector: Option<&str>,
        field_selector: Option<&str>,
    ) -> String {
        format!(
            "{}|{}|{namespace:?}|{label_selector:?}|{field_selector:?}",
            resource.resource.api_version, resource.resource.kind
        )
    }

    /// Create the reflector and start a tokio task in the background that keeps
    /// the contents of the Reflector updated
    pub async fn create_and_run(
        kube_client: kube::Client,
        resource: KubeResource,
        namespace: Option<String>,
        label_selector: Option<String>,
        field_selector: Option<String>,
    ) -> Result<Self> {
        let group = resource.resource.group.clone();
        let version = resource.resource.version.clone();
        let kind = resource.resource.kind.clone();

        info!(
            group,
            version,
            kind,
            ?namespace,
            ?label_selector,
            ?field_selector,
            "creating new reflector"
        );

        let api = match namespace {
            Some(ref ns) => kube::api::Api::<kube::core::DynamicObject>::namespaced_with(
                kube_client,
                ns,
                &resource.resource,
            ),
            None => kube::api::Api::<kube::core::DynamicObject>::all_with(
                kube_client,
                &resource.resource,
            ),
        };

        let writer = Writer::new(resource.resource);
        let reader = writer.as_reader();

        let filter = watcher::Config {
            label_selector: label_selector.clone(),
            field_selector: field_selector.clone(),
            ..Default::default()
        };
        let stream = watcher(api, filter).map_ok(|ev| {
            ev.modify(|obj| {
                // clear managed fields to reduce memory usage
                obj.managed_fields_mut().clear();
            })
        });

        let rf = kube::runtime::reflector(writer, stream);

        tokio::spawn(async move {
            let infinite_watch = rf.default_backoff().touched_objects().for_each(|obj| {
                match obj {
                    Ok(o) => debug!(
                        group,
                        version,
                        kind,
                        ?namespace,
                        ?label_selector,
                        ?field_selector,
                        object=?o,
                        "watcher saw object"
                    ),
                    Err(e) => warn!(
                        group,
                        version,
                        kind,
                        ?namespace,
                        ?label_selector,
                        ?field_selector,
                        error=?e,
                        "watcher error"
                    ),
                };
                ready(())
            });
            infinite_watch.await
        });

        reader.wait_until_ready().await?;

        Ok(Reflector { reader })
    }
}
