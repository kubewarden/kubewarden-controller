use opentelemetry::metrics;
use opentelemetry::sdk::metrics::PushController;
use opentelemetry::KeyValue;
use opentelemetry_otlp::{ExportConfig, WithExportConfig};

mod policy_evaluations_total;
pub use policy_evaluations_total::add_policy_evaluation;
mod policy_evaluations_latency;
pub use policy_evaluations_latency::record_policy_latency;

const METER_NAME: &str = "kubewarden";

pub(crate) fn init_meter() -> metrics::Result<PushController> {
    opentelemetry_otlp::new_pipeline()
        .metrics(tokio::spawn, opentelemetry::util::tokio_interval_stream)
        .with_exporter(
            opentelemetry_otlp::new_exporter()
                .tonic()
                .with_export_config(ExportConfig::default()),
        )
        .build()
}

#[derive(Clone)]
pub struct PolicyEvaluation {
    pub(crate) policy_name: String,
    pub(crate) policy_mode: String,
    pub(crate) resource_name: String,
    pub(crate) resource_kind: String,
    pub(crate) resource_namespace: Option<String>,
    pub(crate) resource_request_operation: String,
    pub(crate) accepted: bool,
    pub(crate) mutated: bool,
    pub(crate) error_code: Option<u16>,
}

#[allow(clippy::from_over_into)]
impl Into<Vec<KeyValue>> for &PolicyEvaluation {
    fn into(self) -> Vec<KeyValue> {
        let mut baggage = vec![
            KeyValue::new("policy_name", self.policy_name.clone()),
            KeyValue::new("policy_mode", self.policy_mode.clone()),
            KeyValue::new("resource_name", self.resource_name.clone()),
            KeyValue::new("resource_kind", self.resource_kind.clone()),
            KeyValue::new(
                "resource_request_operation",
                self.resource_request_operation.clone(),
            ),
            KeyValue::new("accepted", self.accepted),
            KeyValue::new("mutated", self.mutated),
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
