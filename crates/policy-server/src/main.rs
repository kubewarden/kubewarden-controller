mod cli;

use std::fs;

use ::tracing::info;
use anyhow::anyhow;
use anyhow::Result;
use opentelemetry::global::shutdown_tracer_provider;
use policy_server::metrics::setup_metrics;
use policy_server::tracing::setup_tracing;
use policy_server::PolicyServer;

#[tokio::main]
async fn main() -> Result<()> {
    let matches = cli::build_cli().get_matches();
    let config = policy_server::config::Config::from_args(&matches)?;

    setup_tracing(&config.log_level, &config.log_fmt, config.log_no_color)?;

    if config.metrics_enabled {
        setup_metrics()?;
    };

    if config.daemon {
        info!("Running instance as a daemon");

        let mut daemonize = daemonize::Daemonize::new().pid_file(&config.daemon_pid_file);
        if let Some(stdout_file) = config.daemon_stdout_file.clone() {
            let file = fs::File::create(stdout_file)
                .map_err(|e| anyhow!("Cannot create file for daemon stdout: {}", e))?;
            daemonize = daemonize.stdout(file);
        }
        if let Some(stderr_file) = config.daemon_stderr_file.clone() {
            let file = fs::File::create(stderr_file)
                .map_err(|e| anyhow!("Cannot create file for daemon stderr: {}", e))?;
            daemonize = daemonize.stderr(file);
        }

        daemonize
            .start()
            .map_err(|e| anyhow!("Cannot daemonize: {}", e))?;

        info!("Detached from shell, now running in background.");
    }

    let api_server = PolicyServer::new_from_config(config).await?;
    api_server.run().await?;

    shutdown_tracer_provider();

    Ok(())
}
