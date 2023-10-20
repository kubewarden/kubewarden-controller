use lazy_static::lazy_static;
use opentelemetry::{metrics::Histogram, KeyValue};
use std::convert::TryFrom;
use std::time::Duration;

use super::PolicyEvaluationMetric;

lazy_static! {
    static ref POLICY_EVALUATION_LATENCY: Histogram<u64> =
        opentelemetry::global::meter(super::METER_NAME)
            .u64_histogram("kubewarden_policy_evaluation_latency_milliseconds")
            .init();
}

pub fn record_policy_latency(latency: Duration, policy_evaluation: impl PolicyEvaluationMetric) {
    let millis_latency = u64::try_from(latency.as_millis()).unwrap_or(u64::MAX);
    POLICY_EVALUATION_LATENCY.record(
        millis_latency,
        &Into::<Vec<KeyValue>>::into(policy_evaluation),
    );
}
