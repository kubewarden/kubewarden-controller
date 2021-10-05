use anyhow::{anyhow, Result};

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct GroupVersionKind {
    pub group: String,
    pub version: String,
    pub kind: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct GroupVersionResource {
    pub group: String,
    pub version: String,
    pub resource: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AdmissionReview {
    pub uid: String,
    pub kind: GroupVersionKind,
    pub resource: GroupVersionResource,
    pub sub_resource: Option<String>,
    pub request_kind: Option<GroupVersionKind>,
    pub request_resource: Option<GroupVersionResource>,
    pub request_sub_resource: Option<String>,
    pub name: Option<String>,
    pub namespace: Option<String>,
    pub operation: String,
    pub user_info: k8s_openapi::api::authentication::v1::UserInfo,
    pub object: Option<k8s_openapi::apimachinery::pkg::runtime::RawExtension>,
    pub old_object: Option<k8s_openapi::apimachinery::pkg::runtime::RawExtension>,
    pub dry_run: Option<bool>,
    pub options: Option<k8s_openapi::apimachinery::pkg::runtime::RawExtension>,
}

impl AdmissionReview {
    pub(crate) fn new(raw: hyper::body::Bytes) -> Result<AdmissionReview> {
        let obj: serde_json::Value = match serde_json::from_slice(&raw) {
            Ok(obj) => obj,
            Err(e) => return Err(anyhow!("Error parsing request: {:?}", e)),
        };

        let req = match obj.get("request") {
            Some(req) => req,
            None => return Err(anyhow!("Cannot parse AdmissionReview: 'request' not found")),
        };
        let admission_review: AdmissionReview = serde_json::from_value(req.clone())?;
        Ok(admission_review)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::body::Bytes;
    use std::collections::BTreeMap;

    #[test]
    fn invalid_input() {
        let input = Bytes::from("this is not the JSON you're looking for");

        let res = AdmissionReview::new(input);
        assert!(res.is_err());
    }

    #[test]
    fn missing_request() {
        let input = Bytes::from(
            r#"
            { "foo": "bar" }
        "#,
        );

        let res = AdmissionReview::new(input);
        assert!(res.is_err());
    }

    #[test]
    fn missing_uid() {
        let input = Bytes::from(
            r#"
            { 
                "request": {
                    "foo": "bar"
                }
            }
        "#,
        );

        let res = AdmissionReview::new(input);
        assert!(res.is_err());
    }

    #[test]
    fn good_input() {
        let input = Bytes::from(
            r#"
            { 
                "request": {
                    "uid": "hello",
                    "foo": "bar",

                    "kind": {"group":"autoscaling","version":"v1","kind":"Scale"},
                    "resource": {"group":"apps","version":"v1","resource":"deployments"},
                    "subResource": "scale",
                    "requestKind": {"group":"autoscaling","version":"v1","kind":"Scale"},
                    "requestResource": {"group":"apps","version":"v1","resource":"deployments"},
                    "requestSubResource": "scale",
                    "name": "my-deployment",
                    "namespace": "my-namespace",
                    "operation": "UPDATE",
                    "userInfo": {
                      "username": "admin",
                      "uid": "014fbff9a07c",
                      "groups": ["system:authenticated","my-admin-group"],
                      "extra": {
                        "some-key":["some-value1", "some-value2"]
                      }
                    },
                    "object": {"apiVersion":"autoscaling/v1","kind":"Scale"},
                    "oldObject": {"apiVersion":"autoscaling/v1","kind":"Scale"},
                    "options": {"apiVersion":"meta.k8s.io/v1","kind":"UpdateOptions"},
                    "dryRun": false
                }
            }
        "#,
        );

        let res = AdmissionReview::new(input);
        assert!(!res.is_err());

        let ar = res.unwrap();
        assert_eq!(ar.uid, "hello");
        assert_eq!(ar.name.unwrap(), "my-deployment");
        assert_eq!(ar.namespace.unwrap(), "my-namespace");
        assert_eq!(ar.operation, "UPDATE");
        assert_eq!(ar.sub_resource.unwrap(), "scale");
        assert_eq!(ar.kind.group, "autoscaling");
        assert_eq!(ar.kind.version, "v1");
        assert_eq!(ar.kind.kind, "Scale");
        assert_eq!(ar.resource.resource, "deployments");
        assert_eq!(ar.resource.group, "apps");
        assert_eq!(ar.resource.version, "v1");
        assert_eq!(ar.resource.version, "v1");

        assert!(!ar.dry_run.unwrap());
        assert_eq!(ar.request_sub_resource.unwrap(), "scale");
        assert!(ar.request_kind.is_some());
        let request_kind = ar.request_kind.unwrap();
        assert_eq!(request_kind.group, "autoscaling");
        assert_eq!(request_kind.version, "v1");
        assert_eq!(request_kind.kind, "Scale");
        assert!(ar.request_resource.is_some());
        let request_resource = ar.request_resource.unwrap();
        assert_eq!(request_resource.group, "apps");
        assert_eq!(request_resource.version, "v1");
        assert_eq!(request_resource.resource, "deployments");

        assert_eq!(ar.user_info.username.unwrap(), "admin");
        assert_eq!(ar.user_info.uid.unwrap(), "014fbff9a07c");
        assert_eq!(
            ar.user_info.groups.unwrap(),
            vec!["system:authenticated", "my-admin-group"]
        );
        let mut expected_extra_values = BTreeMap::new();
        expected_extra_values.insert(
            String::from("some-key"),
            vec![String::from("some-value1"), String::from("some-value2")],
        );
        assert_eq!(ar.user_info.extra.unwrap(), expected_extra_values);

        assert!(ar.object.is_some());
        let object = ar.object.unwrap();
        assert_eq!(
            object.0.get("apiVersion").unwrap().as_str().unwrap(),
            "autoscaling/v1"
        );
        assert_eq!(object.0.get("kind").unwrap().as_str().unwrap(), "Scale");

        assert!(ar.old_object.is_some());
        let old_object = ar.old_object.unwrap();
        assert_eq!(
            old_object.0.get("apiVersion").unwrap().as_str().unwrap(),
            "autoscaling/v1"
        );
        assert_eq!(old_object.0.get("kind").unwrap().as_str().unwrap(), "Scale");

        assert!(ar.options.is_some());
        let options = ar.options.unwrap();
        assert_eq!(
            options.0.get("apiVersion").unwrap().as_str().unwrap(),
            "meta.k8s.io/v1"
        );
        assert_eq!(
            options.0.get("kind").unwrap().as_str().unwrap(),
            "UpdateOptions"
        );
    }
}
