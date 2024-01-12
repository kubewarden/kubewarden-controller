mod evaluation;
mod metrics;
mod policy_downloader;

#[cfg(test)]
mod test_utils;

pub mod api;
pub mod config;

use anyhow::{anyhow, Result};
use axum::routing::{get, post};
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use opentelemetry::global::shutdown_tracer_provider;
use policy_evaluator::callback_handler::CallbackHandler;
use policy_evaluator::policy_fetcher::sigstore;
use policy_evaluator::policy_fetcher::verify::FulcioAndRekorData;
use policy_evaluator::wasmtime;
use policy_evaluator::{callback_handler::CallbackHandlerBuilder, kube};
use rayon::prelude::*;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::oneshot;
use tokio::sync::Semaphore;
use tokio::time;
use tower_http::trace::{self, TraceLayer};
use tracing::{debug, info, Level};

use crate::api::handlers::{
    audit_handler, readiness_handler, validate_handler, validate_raw_handler,
};
use crate::api::state::ApiServerState;
use crate::evaluation::{
    precompiled_policy::{PrecompiledPolicies, PrecompiledPolicy},
    EvaluationEnvironment,
};
use crate::metrics::init_meter;
use crate::policy_downloader::{Downloader, FetchedPolicies};
use config::{Config, Policy};

pub struct PolicyServer {
    router: Router,
    callback_handler: CallbackHandler,
    callback_handler_shutdown_channel_tx: oneshot::Sender<()>,
    addr: SocketAddr,
    tls_config: Option<RustlsConfig>,
}

impl PolicyServer {
    pub async fn new_from_config(config: Config) -> Result<Self> {
        // This is a channel used to stop the tokio task that is run
        // inside of the CallbackHandler
        let (callback_handler_shutdown_channel_tx, callback_handler_shutdown_channel_rx) =
            oneshot::channel();

        let fulcio_and_rekor_data = match tokio::task::spawn_blocking(|| {
            sigstore::tuf::SigstoreRepository::fetch(None)
        })
        .await
        .unwrap()
        {
            Ok(repo) => Some(FulcioAndRekorData::FromTufRepository { repo }),
            Err(e) => {
                // We cannot rely on `tracing` yet, because the tracing system has not
                // been initialized, this has to be done inside of an async block, which
                // we cannot use yet
                eprintln!("Cannot fetch TUF repository: {e:?}");
                eprintln!("Sigstore Verifier created without Fulcio data: keyless signatures are going to be discarded because they cannot be verified");
                eprintln!(
                "Sigstore Verifier created without Rekor data: transparency log data won't be used"
            );
                eprintln!("Sigstore capabilities are going to be limited");
                None
            }
        };

        let mut callback_handler_builder =
            CallbackHandlerBuilder::new(callback_handler_shutdown_channel_rx)
                .registry_config(config.sources.clone())
                .fulcio_and_rekor_data(fulcio_and_rekor_data.as_ref());

        let kube_client: Option<kube::Client> = match kube::Client::try_default().await {
            Ok(client) => Some(client),
            Err(e) => {
                // We cannot rely on `tracing` yet, because the tracing system has not
                // been initialized yet
                eprintln!("Cannot connect to Kubernetes cluster: {e}");
                None
            }
        };

        match kube_client {
            Some(client) => {
                callback_handler_builder = callback_handler_builder.kube_client(client);
            }
            None => {
                if config.ignore_kubernetes_connection_failure {
                    // We cannot rely on `tracing` yet, because the tracing system has not
                    // been initialized yet
                    eprintln!(
                    "Cannot connect to Kubernetes, context aware policies will not work properly"
                );
                } else {
                    return Err(anyhow!(
                    "Cannot connect to Kubernetes, context aware policies would not work properly"
                ));
                }
            }
        };

        let callback_handler = callback_handler_builder.build()?;
        let callback_sender_channel = callback_handler.sender_channel();

        // The unused variable is required so the meter is not dropped early and
        // lives for the whole block lifetime, exporting metrics
        let _meter = if config.metrics_enabled {
            Some(init_meter())
        } else {
            None
        };

        // Download policies
        let mut downloader = Downloader::new(
            config.sources.clone(),
            config.verification_config.is_some(),
            Some(config.sigstore_cache_dir.clone()),
        )
        .await?;

        let fetched_policies = downloader
            .download_policies(
                &config.policies,
                &config.policies_download_dir,
                config.verification_config.as_ref(),
            )
            .await?;

        let mut wasmtime_config = wasmtime::Config::new();
        if config.policy_evaluation_limit_seconds.is_some() {
            wasmtime_config.epoch_interruption(true);
        }
        let engine = wasmtime::Engine::new(&wasmtime_config)?;
        let precompiled_policies = precompile_policies(&engine, &fetched_policies)?;

        let evaluation_environment = EvaluationEnvironment::new(
            &engine,
            &config.policies,
            &precompiled_policies,
            config.always_accept_admission_reviews_on_namespace,
            config.policy_evaluation_limit_seconds,
            callback_sender_channel.clone(),
        )?;

        if let Some(limit) = config.policy_evaluation_limit_seconds {
            info!(
                execution_limit_seconds = limit,
                "policy timeout protection is enabled"
            );

            let engine = engine.clone();
            tokio::spawn(async move {
                let mut interval = time::interval(time::Duration::from_secs(1));
                loop {
                    interval.tick().await;
                    engine.increment_epoch();
                }
            });
        } else {
            info!("policy timeout protection is disabled");
        }

        verify_policy_settings(&config.policies, &evaluation_environment).await?;

        let state = Arc::new(ApiServerState {
            semaphore: Semaphore::new(config.pool_size),
            evaluation_environment,
        });

        let tls_config = if let Some(tls_config) = config.tls_config {
            let rustls_config =
                RustlsConfig::from_pem_file(tls_config.cert_file, tls_config.key_file).await?;
            Some(rustls_config)
        } else {
            None
        };

        let router = Router::new()
            .route("/audit/:policy_id", post(audit_handler))
            .route("/validate/:policy_id", post(validate_handler))
            .route("/validate_raw/:policy_id", post(validate_raw_handler))
            .route("/readiness", get(readiness_handler))
            .with_state(state.clone())
            .layer(
                TraceLayer::new_for_http()
                    .make_span_with(trace::DefaultMakeSpan::new().level(Level::INFO))
                    .on_response(trace::DefaultOnResponse::new().level(Level::INFO)),
            );

        Ok(Self {
            router,
            callback_handler,
            callback_handler_shutdown_channel_tx,
            addr: config.addr,
            tls_config,
        })
    }

    pub async fn run(self) -> Result<()> {
        // Start the CallbackHandler
        let mut callback_handler = self.callback_handler;
        let callback_handler = tokio::spawn(async move {
            info!(status = "init", "CallbackHandler task");
            callback_handler.loop_eval().await;
            info!(status = "exit", "CallbackHandler task");
        });

        if let Some(tls_config) = self.tls_config {
            axum_server::bind_rustls(self.addr, tls_config)
                .serve(self.router.into_make_service())
                .await?;
        } else {
            axum_server::bind(self.addr)
                .serve(self.router.into_make_service())
                .await?;
        };

        // Stop the CallbackHandler
        self.callback_handler_shutdown_channel_tx
            .send(())
            .expect("Cannot send shutdown signal to CallbackHandler");

        // Wait for the CallbackHandler to exit
        callback_handler
            .await
            .expect("Cannot wait for CallbackHandler to exit");

        shutdown_tracer_provider();

        Ok(())
    }

    pub fn router(&self) -> Router {
        self.router.clone()
    }
}

fn precompile_policies(
    engine: &wasmtime::Engine,
    fetched_policies: &FetchedPolicies,
) -> Result<PrecompiledPolicies> {
    debug!(
        wasm_modules_count = fetched_policies.len(),
        "instantiating wasmtime::Module objects"
    );

    let precompiled_policies: HashMap<String, Result<PrecompiledPolicy>> = fetched_policies
        .par_iter()
        .map(|(policy_url, wasm_module_path)| {
            let precompiled_policy = PrecompiledPolicy::new(engine, wasm_module_path);
            debug!(?policy_url, "module compiled");
            (policy_url.clone(), precompiled_policy)
        })
        .collect();

    let errors: Vec<String> = precompiled_policies
        .iter()
        .filter_map(|(url, result)| match result {
            Ok(_) => None,
            Err(e) => Some(format!(
                "[{url}] policy cannot be compiled to WebAssembly module: {e:?}"
            )),
        })
        .collect();
    if !errors.is_empty() {
        return Err(anyhow!(
            "workers pool bootstrap: cannot instantiate `wasmtime::Module` objects: {:?}",
            errors.join(", ")
        ));
    }

    Ok(precompiled_policies
        .iter()
        .filter_map(|(url, result)| match result {
            Ok(p) => Some((url.clone(), p.clone())),
            Err(_) => None,
        })
        .collect())
}

/// Ensure the user provided valid settings for all the policies
async fn verify_policy_settings(
    policies: &HashMap<String, Policy>,
    evaluation_environment: &EvaluationEnvironment,
) -> Result<()> {
    let mut errors = vec![];
    for (policy_id, _policy) in policies.iter() {
        let set_val_rep = evaluation_environment.validate_settings(policy_id)?;
        if !set_val_rep.valid {
            errors.push(format!(
                "[{}] settings are not valid: {:?}",
                policy_id, set_val_rep.message
            ));
            continue;
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(anyhow!("{}", errors.join(", ")))
    }
}
