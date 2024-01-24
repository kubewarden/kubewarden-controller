use k8s_openapi::{
    api::{
        apps::v1::Deployment,
        core::v1::{Namespace, Service},
    },
    apimachinery::pkg::apis::meta::v1::{APIResource, APIResourceList},
};
use kube::core::{ObjectList, ObjectMeta, TypeMeta};
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
        metadata: Default::default(),
        items: vec![Namespace {
            metadata: ObjectMeta {
                name: Some("customer-1".to_owned()),
                labels: Some(BTreeMap::from([("customer-id".to_owned(), "1".to_owned())])),
                ..Default::default()
            },
            ..Default::default()
        }],
    }
}

pub(crate) fn deployments() -> ObjectList<Deployment> {
    ObjectList {
        metadata: Default::default(),
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
                    ..Default::default()
                },
                ..Default::default()
            },
        ],
    }
}

pub(crate) fn services() -> ObjectList<Service> {
    ObjectList {
        metadata: Default::default(),
        types: TypeMeta::list::<Service>(),
        items: vec![api_auth_service()],
    }
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
            ..Default::default()
        },
        ..Default::default()
    }
}
