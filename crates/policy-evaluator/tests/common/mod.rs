use tempfile::TempDir;

use policy_evaluator::{
    evaluation_context::EvaluationContext, policy_evaluator::PolicyEvaluator,
    policy_evaluator::PolicyExecutionMode, policy_evaluator_builder::PolicyEvaluatorBuilder,
};
use policy_fetcher::{policy::Policy, PullDestination};

pub(crate) async fn fetch_policy(policy_uri: &str, tempdir: TempDir) -> Policy {
    policy_evaluator::policy_fetcher::fetch_policy(
        policy_uri,
        PullDestination::LocalFile(tempdir.into_path()),
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
    let policy_evaluator_builder = PolicyEvaluatorBuilder::new()
        .execution_mode(execution_mode)
        .policy_file(&policy.local_path)
        .expect("cannot read policy file")
        .enable_wasmtime_cache()
        .enable_epoch_interruptions(1, 2);

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
