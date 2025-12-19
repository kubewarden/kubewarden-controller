use std::path::PathBuf;

use policy_evaluator::{
    evaluation_context::EvaluationContext, policy_evaluator::PolicyEvaluator,
    policy_evaluator::PolicyExecutionMode, policy_evaluator_builder::PolicyEvaluatorBuilder,
};
use policy_fetcher::{PullDestination, policy::Policy};

use lazy_static::lazy_static;

lazy_static! {
    pub(crate) static ref CONTEXT_AWARE_POLICY_FILE: String = format!(
        "file://{}",
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("annotated-policy.wasm")
            .to_str()
            .expect("failed to convert path into str")
    );
}

pub(crate) async fn fetch_policy(policy_uri: &str, tempdir: PathBuf) -> Policy {
    policy_evaluator::policy_fetcher::fetch_policy(
        policy_uri,
        PullDestination::LocalFile(tempdir),
        None,
    )
    .await
    .expect("cannot fetch policy")
}

pub(crate) fn build_policy_evaluator(
    execution_mode: PolicyExecutionMode,
    policy: &Policy,
    eval_ctx: &EvaluationContext,
) -> PolicyEvaluator {
    let mut policy_evaluator_builder = PolicyEvaluatorBuilder::new()
        .execution_mode(execution_mode)
        .policy_file(&policy.local_path)
        .expect("cannot read policy file")
        .enable_wasmtime_cache();

    if let Some(deadline) = eval_ctx.epoch_deadline {
        policy_evaluator_builder =
            policy_evaluator_builder.enable_epoch_interruptions(deadline, deadline);
    }

    let policy_evaluator_pre = policy_evaluator_builder
        .build_pre()
        .expect("cannot build policy evaluator pre");

    policy_evaluator_pre
        .rehydrate(eval_ctx)
        .expect("cannot rehydrate policy evaluator")
}

pub(crate) fn load_request_data(request_file_name: &str) -> Vec<u8> {
    let request_file_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(request_file_name);
    std::fs::read(request_file_path).expect("cannot read request file")
}
