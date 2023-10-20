#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionRequest {
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

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct GroupVersionKind {
    pub group: String,
    pub version: String,
    pub kind: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct GroupVersionResource {
    pub group: String,
    pub version: String,
    pub resource: String,
}
