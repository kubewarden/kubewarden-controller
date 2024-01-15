use anyhow::{anyhow, Result};
use tiny_bench::{bench_with_configuration_labeled, BenchmarkConfig};
use tracing::error;

use crate::run;

pub(crate) struct PullAndBenchSettings {
    pub pull_and_run_settings: run::PullAndRunSettings,
    pub benchmark_cfg: BenchmarkConfig,
}

pub(crate) async fn pull_and_bench(cfg: &PullAndBenchSettings) -> Result<()> {
    let run_env = run::prepare_run_env(&cfg.pull_and_run_settings).await?;
    let mut policy_evaluator = run_env.policy_evaluator;
    let mut callback_handler = run_env.callback_handler;
    let callback_handler_shutdown_channel_tx = run_env.callback_handler_shutdown_channel_tx;
    let request = run_env.request;

    // validate the settings given by the user
    let settings_validation_response = policy_evaluator.validate_settings(&run_env.policy_settings);
    if !settings_validation_response.valid {
        println!("{}", serde_json::to_string(&settings_validation_response)?);
        return Err(anyhow!(
            "Provided settings are not valid: {:?}",
            settings_validation_response.message
        ));
    }

    // Spawn the tokio task used by the CallbackHandler
    let callback_handle = tokio::spawn(async move {
        callback_handler.loop_eval().await;
    });

    // validate the settings given by the user
    let settings_validation_response = policy_evaluator.validate_settings(&run_env.policy_settings);
    if !settings_validation_response.valid {
        println!("{}", serde_json::to_string(&settings_validation_response)?);
        return Err(anyhow!(
            "Provided settings are not valid: {:?}",
            settings_validation_response.message
        ));
    }
    bench_with_configuration_labeled("validate_settings", &cfg.benchmark_cfg, || {
        let _settings_validation_response =
            policy_evaluator.validate_settings(&run_env.policy_settings);
    });

    bench_with_configuration_labeled("validate", &cfg.benchmark_cfg, || {
        let _response = policy_evaluator.validate(request.clone(), &run_env.policy_settings);
    });

    // The evaluation is done, we can shutdown the tokio task that is running
    // the CallbackHandler
    if callback_handler_shutdown_channel_tx.send(()).is_err() {
        error!("Cannot shut down the CallbackHandler task");
    } else if let Err(e) = callback_handle.await {
        error!(
            error = e.to_string().as_str(),
            "Error waiting for the CallbackHandler task"
        );
    }

    Ok(())
}
