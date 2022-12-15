use policy_evaluator::admission_response::AdmissionResponse;

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub(crate) struct GroupVersionKind {
    pub group: String,
    pub version: String,
    pub kind: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct GroupVersionResource {
    pub group: String,
    pub version: String,
    pub resource: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AdmissionReview {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_version: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<AdmissionRequest>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<AdmissionResponse>,
}

impl AdmissionReview {
    pub fn new_with_response(response: AdmissionResponse) -> Self {
        AdmissionReview {
            response: Some(response),
            ..Default::default()
        }
    }
}

impl Default for AdmissionReview {
    fn default() -> Self {
        AdmissionReview {
            api_version: Some(String::from("admission.k8s.io/v1")),
            kind: Some(String::from("AdmissionReview")),
            request: None,
            response: None,
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AdmissionRequest {
    pub uid: String,
    pub kind: GroupVersionKind,
    pub resource: GroupVersionResource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_resource: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_kind: Option<GroupVersionKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_resource: Option<GroupVersionResource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_sub_resource: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    pub operation: String,
    pub user_info: k8s_openapi::api::authentication::v1::UserInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object: Option<k8s_openapi::apimachinery::pkg::runtime::RawExtension>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_object: Option<k8s_openapi::apimachinery::pkg::runtime::RawExtension>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dry_run: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<k8s_openapi::apimachinery::pkg::runtime::RawExtension>,
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::BTreeMap;

    pub(crate) fn build_admission_review() -> AdmissionReview {
        let input = r#"
            { 
                "request": {
                    "uid": "hello",
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
        "#;

        let ar: AdmissionReview = serde_json::from_str(input).expect("deserialization should work");
        ar
    }

    #[test]
    fn good_input() {
        let ar = build_admission_review();
        let request = ar.request.expect("request should be set");

        assert_eq!(request.uid, "hello");
        assert_eq!(request.name.unwrap(), "my-deployment");
        assert_eq!(request.namespace.unwrap(), "my-namespace");
        assert_eq!(request.operation, "UPDATE");
        assert_eq!(request.sub_resource.unwrap(), "scale");
        assert_eq!(request.kind.group, "autoscaling");
        assert_eq!(request.kind.version, "v1");
        assert_eq!(request.kind.kind, "Scale");
        assert_eq!(request.resource.resource, "deployments");
        assert_eq!(request.resource.group, "apps");
        assert_eq!(request.resource.version, "v1");
        assert_eq!(request.resource.version, "v1");

        assert!(!request.dry_run.unwrap());
        assert_eq!(request.request_sub_resource.unwrap(), "scale");
        assert!(request.request_kind.is_some());
        let request_kind = request.request_kind.unwrap();
        assert_eq!(request_kind.group, "autoscaling");
        assert_eq!(request_kind.version, "v1");
        assert_eq!(request_kind.kind, "Scale");
        assert!(request.request_resource.is_some());
        let request_resource = request.request_resource.unwrap();
        assert_eq!(request_resource.group, "apps");
        assert_eq!(request_resource.version, "v1");
        assert_eq!(request_resource.resource, "deployments");

        assert_eq!(request.user_info.username.unwrap(), "admin");
        assert_eq!(request.user_info.uid.unwrap(), "014fbff9a07c");
        assert_eq!(
            request.user_info.groups.unwrap(),
            vec!["system:authenticated", "my-admin-group"]
        );
        let mut expected_extra_values = BTreeMap::new();
        expected_extra_values.insert(
            String::from("some-key"),
            vec![String::from("some-value1"), String::from("some-value2")],
        );
        assert_eq!(request.user_info.extra.unwrap(), expected_extra_values);

        assert!(request.object.is_some());
        let object = request.object.unwrap();
        assert_eq!(
            object.0.get("apiVersion").unwrap().as_str().unwrap(),
            "autoscaling/v1"
        );
        assert_eq!(object.0.get("kind").unwrap().as_str().unwrap(), "Scale");

        assert!(request.old_object.is_some());
        let old_object = request.old_object.unwrap();
        assert_eq!(
            old_object.0.get("apiVersion").unwrap().as_str().unwrap(),
            "autoscaling/v1"
        );
        assert_eq!(old_object.0.get("kind").unwrap().as_str().unwrap(), "Scale");

        assert!(request.options.is_some());
        let options = request.options.unwrap();
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
