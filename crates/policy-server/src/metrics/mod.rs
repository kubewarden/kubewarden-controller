use opentelemetry::metrics;
use opentelemetry::sdk::metrics::PushController;
use opentelemetry_otlp::{ExportConfig, WithExportConfig};

mod policy_evaluations_total;
pub use policy_evaluations_total::{add_policy_evaluation, PolicyEvaluation};

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
