use crate::metrics::PolicyEvaluation;
use lazy_static::lazy_static;
use opentelemetry::{metrics::Counter, KeyValue};

lazy_static! {
    static ref POLICY_EVALUATIONS_TOTAL: Counter<u64> =
        opentelemetry::global::meter(super::METER_NAME)
            .u64_counter("kubewarden_policy_evaluations_total")
            .init();
}

pub fn add_policy_evaluation(policy_evaluation: &PolicyEvaluation) {
    POLICY_EVALUATIONS_TOTAL.add(1, &Into::<Vec<KeyValue>>::into(policy_evaluation));
}
