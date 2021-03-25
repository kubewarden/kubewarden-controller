use policy_evaluator::validation_response::ValidationResponse;
use tokio::sync::oneshot;

#[derive(Debug)]
pub(crate) struct EvalRequest {
    pub policy_id: String,
    pub req: serde_json::Value,
    pub resp_chan: oneshot::Sender<Option<ValidationResponse>>,
}
