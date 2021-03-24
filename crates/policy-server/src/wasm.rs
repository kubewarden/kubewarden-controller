use anyhow::{anyhow, Result};
use policy_evaluator::validation_response::ValidationResponse;
use tokio::sync::oneshot;

#[allow(clippy::unnecessary_wraps)]
pub(crate) fn host_callback(
    id: u64,
    bd: &str,
    ns: &str,
    op: &str,
    payload: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let payload = ::std::str::from_utf8(payload)
        .map_err(|e| anyhow!("Error converting payload to UTF8: {:?}", e))?;
    println!(
        "Guest {} invoked '{}->{}:{}' with payload of {}",
        id, bd, ns, op, payload
    );
    Ok(b"Host result".to_vec())
}

#[derive(Debug)]
pub(crate) struct EvalRequest {
    pub policy_id: String,
    pub req: serde_json::Value,
    pub resp_chan: oneshot::Sender<Option<ValidationResponse>>,
}
