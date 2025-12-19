use std::sync::Arc;

use anyhow::Result;
use tracing::debug;

use crate::evaluation_context::EvaluationContext;

/// A host callback function that can be used by the waPC runtime.
type HostCallback = Box<
    dyn Fn(
            u64,
            &str,
            &str,
            &str,
            &[u8],
        ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>
        + Send
        + Sync,
>;

/// Returns a host callback function that can be used by the waPC runtime.
/// The callback function will be able to access the `EvaluationContext` instance.
pub(crate) fn new_host_callback(eval_ctx: Arc<EvaluationContext>) -> HostCallback {
    Box::new({
        move |wapc_id, binding, namespace, operation, payload| {
            debug!(wapc_id, "invoking host_callback");
            crate::runtimes::callback::host_callback(
                binding, namespace, operation, payload, &eval_ctx,
            )
        }
    })
}
