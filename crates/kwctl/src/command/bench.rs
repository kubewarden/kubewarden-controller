use anyhow::{anyhow, Result};
use tiny_bench::{bench_with_configuration_labeled, BenchmarkConfig};
use tracing::{debug, error};

use crate::{
    command::run::{evaluator::Evaluator, local_data::LocalData},
    config::{policy_definition::PolicyDefinition, pull_and_run::PullAndRunSettings},
};

pub(crate) async fn exec(
    policy_definitions: &[PolicyDefinition],
    pull_and_run_settings: &PullAndRunSettings,
    benchmark_config: &BenchmarkConfig,
) -> Result<()> {
    let local_data = LocalData::new(policy_definitions, pull_and_run_settings).await?;

    for policy_definition in policy_definitions {
        pull_and_bench(
            policy_definition,
            pull_and_run_settings,
            &local_data,
            benchmark_config,
        )
        .await
        .map_err(|e| anyhow!("[{}] - {}", policy_definition, e))?;
    }

    Ok(())
}

pub(crate) async fn pull_and_bench(
    policy_definition: &PolicyDefinition,
    pull_and_run_settings: &PullAndRunSettings,
    local_data: &LocalData,
    benchmark_config: &BenchmarkConfig,
) -> Result<()> {
    let (mut evaluator, callback_handler, shutdown_channel_tx) =
        Evaluator::new(policy_definition, pull_and_run_settings, local_data).await?;

    // start the callback handler
    let handler = tokio::spawn(async { callback_handler.loop_eval().await });

    // validate the settings given by the user
    let settings_validation_response = evaluator.validate_settings();
    if !settings_validation_response.valid {
        debug!(
            response = serde_json::to_string(&settings_validation_response)
                .expect("Failed to serialize response"),
            "Settings validation response"
        );
        return Err(anyhow!(
            "[{}] - provided settings are not valid: {:?}",
            policy_definition,
            settings_validation_response.message
        ));
    }

    // We have to wrap the settings validation in a `tokio::task::block_in_place` context
    // because if the policy uses context aware functions, this would lead to blocking the
    // tokio runtime. Remember, we're running inside of an async context.
    tokio::task::block_in_place(|| {
        bench_with_configuration_labeled("validate_settings", benchmark_config, || {
            let _settings_validation_response = evaluator.validate_settings();
        });
    });

    // We have to wrap the evaluation code inside of a `tokio::task::block_in_place` context
    // because if the policy uses context aware functions, this would lead to blocking the
    // tokio runtime. Remember, we're running inside of an async context.
    tokio::task::block_in_place(|| {
        bench_with_configuration_labeled("validate", benchmark_config, || {
            let _evaluation_result = evaluator.evaluate();
        });
    });

    if shutdown_channel_tx.send(()).is_err() {
        error!("Cannot shut down the CallbackHandler task");
    } else if let Err(e) = handler.await {
        error!(
            error = e.to_string().as_str(),
            "Error waiting for the CallbackHandler task"
        );
    }

    Ok(())
}
