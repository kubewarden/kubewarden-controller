use anyhow::Result;
use opentelemetry::{global, KeyValue};
use opentelemetry_otlp::{ExportConfig, WithExportConfig, WithTonicConfig};

mod policy_evaluations_total;
pub use policy_evaluations_total::add_policy_evaluation;
mod policy_evaluations_latency;
pub use policy_evaluations_latency::record_policy_latency;

use crate::config::build_client_tls_config_from_env;

const METER_NAME: &str = "kubewarden";

pub fn setup_metrics() -> Result<()> {
    let metric_exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_tonic()
        .with_tls_config(build_client_tls_config_from_env("METRICS")?)
        .with_export_config(ExportConfig::default())
        .build()?;

    let periodic_reader =
        opentelemetry_sdk::metrics::PeriodicReader::builder(metric_exporter).build();
    let meter_provider = opentelemetry_sdk::metrics::SdkMeterProvider::builder()
        .with_reader(periodic_reader)
        .build();

    global::set_meter_provider(meter_provider);
    Ok(())
}

pub trait PolicyEvaluationMetric: Into<Vec<KeyValue>> {}

#[derive(Clone)]
pub(crate) struct PolicyEvaluation {
    pub(crate) policy_name: String,
    pub(crate) policy_mode: String,
    pub(crate) resource_kind: String,
    pub(crate) resource_namespace: Option<String>,
    pub(crate) resource_request_operation: String,
    pub(crate) accepted: bool,
    pub(crate) mutated: bool,
    pub(crate) request_origin: String,
    pub(crate) error_code: Option<u16>,
}

impl PolicyEvaluationMetric for &PolicyEvaluation {}

#[allow(clippy::from_over_into)]
impl Into<Vec<KeyValue>> for &PolicyEvaluation {
    fn into(self) -> Vec<KeyValue> {
        let mut baggage = vec![
            KeyValue::new("policy_name", self.policy_name.clone()),
            KeyValue::new("policy_mode", self.policy_mode.clone()),
            KeyValue::new("resource_kind", self.resource_kind.clone()),
            KeyValue::new(
                "resource_request_operation",
                self.resource_request_operation.clone(),
            ),
            KeyValue::new("accepted", self.accepted),
            KeyValue::new("mutated", self.mutated),
            KeyValue::new("request_origin", self.request_origin.clone()),
        ];
        if let Some(resource_namespace) = &self.resource_namespace {
            baggage.append(&mut vec![KeyValue::new(
                "resource_namespace",
                resource_namespace.clone(),
            )]);
        }
        if let Some(error_code) = self.error_code {
            baggage.append(&mut vec![KeyValue::new("error_code", error_code as i64)]);
        }
        baggage
    }
}

#[derive(Clone)]
pub(crate) struct RawPolicyEvaluation {
    pub(crate) policy_name: String,
    pub(crate) policy_mode: String,
    pub(crate) accepted: bool,
    pub(crate) mutated: bool,
    pub(crate) error_code: Option<u16>,
}

impl PolicyEvaluationMetric for &RawPolicyEvaluation {}

#[allow(clippy::from_over_into)]
impl Into<Vec<KeyValue>> for &RawPolicyEvaluation {
    fn into(self) -> Vec<KeyValue> {
        let mut baggage = vec![
            KeyValue::new("policy_name", self.policy_name.clone()),
            KeyValue::new("policy_mode", self.policy_mode.clone()),
            KeyValue::new("accepted", self.accepted),
            KeyValue::new("mutated", self.mutated),
        ];

        if let Some(error_code) = self.error_code {
            baggage.append(&mut vec![KeyValue::new("error_code", error_code as i64)]);
        }
        baggage
    }
}

#[derive(Clone)]
pub(crate) struct PolicyInitializationError {
    pub(crate) policy_name: String,
    pub(crate) initialization_error: String,
}

impl PolicyEvaluationMetric for &PolicyInitializationError {}

#[allow(clippy::from_over_into)]
impl Into<Vec<KeyValue>> for &PolicyInitializationError {
    fn into(self) -> Vec<KeyValue> {
        vec![
            KeyValue::new("policy_name", self.policy_name.clone()),
            KeyValue::new("initialization_error", self.initialization_error.clone()),
        ]
    }
}
