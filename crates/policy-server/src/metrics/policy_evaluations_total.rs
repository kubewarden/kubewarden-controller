use lazy_static::lazy_static;
use opentelemetry::{metrics::Counter, KeyValue};

lazy_static! {
    static ref POLICY_EVALUATIONS_TOTAL: Counter<u64> =
        opentelemetry::global::meter(super::METER_NAME)
            .u64_counter("kubewarden_policy_evaluations_total")
            .init();
}

pub struct PolicyEvaluation {
    pub(crate) policy_name: String,
    pub(crate) resource_name: String,
    pub(crate) resource_kind: String,
    pub(crate) resource_namespace: Option<String>,
    pub(crate) resource_request_operation: String,
    pub(crate) accepted: bool,
    pub(crate) mutated: bool,
    pub(crate) error_code: Option<u16>,
}

#[allow(clippy::from_over_into)]
impl Into<Vec<KeyValue>> for PolicyEvaluation {
    fn into(self) -> Vec<KeyValue> {
        let mut baggage = vec![
            KeyValue::new("policy_name", self.policy_name),
            KeyValue::new("resource_name", self.resource_name),
            KeyValue::new("resource_kind", self.resource_kind),
            KeyValue::new(
                "resource_request_operation",
                self.resource_request_operation,
            ),
            KeyValue::new("accepted", self.accepted),
            KeyValue::new("mutated", self.mutated),
        ];
        if let Some(resource_namespace) = self.resource_namespace {
            baggage.append(&mut vec![KeyValue::new(
                "resource_namespace",
                resource_namespace,
            )]);
        }
        if let Some(error_code) = self.error_code {
            baggage.append(&mut vec![KeyValue::new("error_code", error_code as i64)]);
        }
        baggage
    }
}

pub fn add_policy_evaluation(policy_evaluation: PolicyEvaluation) {
    POLICY_EVALUATIONS_TOTAL.add(1, &Into::<Vec<KeyValue>>::into(policy_evaluation));
}
