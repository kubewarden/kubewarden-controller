use k8s_openapi::{
    api::{
        apps::v1::Deployment,
        core::v1::{Namespace, Service},
    },
    apimachinery::pkg::apis::meta::v1::{APIResource, APIResourceList},
};
use kube::core::{
    watch::{Bookmark, BookmarkMeta},
    ListMeta, ObjectList, ObjectMeta, TypeMeta, WatchEvent,
};
use std::collections::BTreeMap;

pub(crate) fn v1_resource_list() -> APIResourceList {
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

pub(crate) fn apps_v1_resource_list() -> APIResourceList {
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

pub(crate) fn namespaces() -> ObjectList<Namespace> {
    ObjectList {
        types: TypeMeta::list::<Namespace>(),
        metadata: ListMeta {
            resource_version: Some("1".to_owned()),
            ..Default::default()
        },
        items: vec![Namespace {
            metadata: ObjectMeta {
                name: Some("customer-1".to_owned()),
                labels: Some(BTreeMap::from([("customer-id".to_owned(), "1".to_owned())])),
                resource_version: Some("1".to_owned()),
                ..Default::default()
            },
            ..Default::default()
        }],
    }
}

pub(crate) fn namespaces_watch_bookmark(resource_version: &str) -> WatchEvent<Namespace> {
    WatchEvent::Bookmark(Bookmark {
        types: TypeMeta::list::<Namespace>(),
        metadata: BookmarkMeta {
            annotations: BTreeMap::new(),
            resource_version: resource_version.to_owned(),
        },
    })
}

pub(crate) fn deployments() -> ObjectList<Deployment> {
    ObjectList {
        metadata: ListMeta {
            resource_version: Some("1".to_owned()),
            ..Default::default()
        },
        types: TypeMeta::list::<Deployment>(),
        items: vec![
            Deployment {
                metadata: ObjectMeta {
                    name: Some("postgres".to_owned()),
                    namespace: Some("customer-1".to_owned()),
                    labels: Some(BTreeMap::from([(
                        "app.kubernetes.io/component".to_owned(),
                        "database".to_owned(),
                    )])),
                    resource_version: Some("1".to_owned()),
                    ..Default::default()
                },
                ..Default::default()
            },
            Deployment {
                metadata: ObjectMeta {
                    name: Some("single-page-app".to_owned()),
                    namespace: Some("customer-1".to_owned()),
                    labels: Some(BTreeMap::from([(
                        "app.kubernetes.io/component".to_owned(),
                        "frontend".to_owned(),
                    )])),
                    resource_version: Some("1".to_owned()),
                    ..Default::default()
                },
                ..Default::default()
            },
        ],
    }
}

pub(crate) fn deployments_watch_bookmark(resource_version: &str) -> WatchEvent<Deployment> {
    WatchEvent::Bookmark(Bookmark {
        types: TypeMeta::list::<Deployment>(),
        metadata: BookmarkMeta {
            annotations: BTreeMap::new(),
            resource_version: resource_version.to_owned(),
        },
    })
}

pub(crate) fn services() -> ObjectList<Service> {
    ObjectList {
        metadata: ListMeta {
            resource_version: Some("1".to_owned()),
            ..Default::default()
        },
        types: TypeMeta::list::<Service>(),
        items: vec![api_auth_service()],
    }
}

pub(crate) fn services_watch_bookmark(resource_version: &str) -> WatchEvent<Service> {
    WatchEvent::Bookmark(Bookmark {
        types: TypeMeta::list::<Service>(),
        metadata: BookmarkMeta {
            annotations: BTreeMap::new(),
            resource_version: resource_version.to_owned(),
        },
    })
}

pub(crate) fn api_auth_service() -> Service {
    Service {
        metadata: ObjectMeta {
            name: Some("api-auth-service".to_owned()),
            namespace: Some("customer-1".to_owned()),
            labels: Some(BTreeMap::from([(
                "app.kubernetes.io/part-of".to_owned(),
                "api".to_owned(),
            )])),
            resource_version: Some("1".to_owned()),
            ..Default::default()
        },
        ..Default::default()
    }
}
