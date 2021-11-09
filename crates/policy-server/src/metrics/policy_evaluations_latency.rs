use crate::metrics::PolicyEvaluation;
use lazy_static::lazy_static;
use opentelemetry::{metrics::ValueRecorder, KeyValue};
use std::convert::TryFrom;
use std::time::Duration;

lazy_static! {
    static ref POLICY_EVALUATION_LATENCY: ValueRecorder<u64> =
        opentelemetry::global::meter(super::METER_NAME)
            .u64_value_recorder("kubewarden_policy_evaluation_latency_milliseconds")
            .init();
}

pub fn record_policy_latency(latency: Duration, policy_evaluation: &PolicyEvaluation) {
    let millis_latency = u64::try_from(latency.as_millis()).unwrap_or(u64::MAX);
    POLICY_EVALUATION_LATENCY.record(
        millis_latency,
        &Into::<Vec<KeyValue>>::into(policy_evaluation),
    );
}
