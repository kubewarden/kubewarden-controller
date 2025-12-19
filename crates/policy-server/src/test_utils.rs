use crate::api::admission_review::AdmissionReviewRequest;

pub(crate) fn build_admission_review_request() -> AdmissionReviewRequest {
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

    let admission_review_request: AdmissionReviewRequest =
        serde_json::from_str(input).expect("deserialization should work");

    admission_review_request
}
