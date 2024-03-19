mod evaluation;
mod policy_downloader;

#[cfg(test)]
mod test_utils;

#[cfg(test)]
mod cli;

pub mod api;
pub mod config;
pub mod metrics;
pub mod profiling;
pub mod tracing;

use ::tracing::{debug, error, info, Level};
use anyhow::{anyhow, Result};
use axum::routing::{get, post};
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use policy_evaluator::callback_handler::CallbackHandler;
use policy_evaluator::policy_fetcher::sigstore;
use policy_evaluator::policy_fetcher::verify::FulcioAndRekorData;
use policy_evaluator::wasmtime;
use policy_evaluator::{callback_handler::CallbackHandlerBuilder, kube};
use rayon::prelude::*;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::oneshot;
use tokio::sync::Semaphore;
use tokio::time;
use tower_http::trace::{self, TraceLayer};

use crate::api::handlers::{
    audit_handler, pprof_get_cpu, readiness_handler, validate_handler, validate_raw_handler,
};
use crate::api::state::ApiServerState;
use crate::evaluation::{
    precompiled_policy::{PrecompiledPolicies, PrecompiledPolicy},
    EvaluationEnvironment,
};
use crate::policy_downloader::{Downloader, FetchedPolicies};
use config::Config;

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

        // TODO: remove the spawn blocking once the Sigstore client is async
        // see: https://github.com/sigstore/sigstore-rs/pull/320
        let fulcio_and_rekor_data = match tokio::task::spawn_blocking(|| {
            sigstore::tuf::SigstoreRepository::fetch(None)
        })
        .await
        .unwrap()
        {
            Ok(repo) => Some(FulcioAndRekorData::FromTufRepository { repo }),
            Err(e) => {
                error!("Cannot fetch TUF repository: {e:?}");
                error!("Sigstore Verifier created without Fulcio data: keyless signatures are going to be discarded because they cannot be verified");
                error!(
                "Sigstore Verifier created without Rekor data: transparency log data won't be used"
            );
                error!("Sigstore capabilities are going to be limited");
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
            .await;

        let mut wasmtime_config = wasmtime::Config::new();
        if config.policy_evaluation_limit_seconds.is_some() {
            wasmtime_config.epoch_interruption(true);
        }
        let engine = wasmtime::Engine::new(&wasmtime_config)?;
        let precompiled_policies = precompile_policies(&engine, &fetched_policies);

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

        let mut router = Router::new()
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
        if config.enable_pprof {
            let pprof_router = Router::new().route("/debug/pprof/cpu", get(pprof_get_cpu));
            router = Router::new().merge(router).merge(pprof_router);
        }

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

        Ok(())
    }

    pub fn router(&self) -> Router {
        self.router.clone()
    }
}

fn precompile_policies(
    engine: &wasmtime::Engine,
    fetched_policies: &FetchedPolicies,
) -> PrecompiledPolicies {
    debug!(
        wasm_modules_count = fetched_policies.len(),
        "instantiating wasmtime::Module objects"
    );

    fetched_policies
        .par_iter()
        .map(|(policy_url, fetched_policy)| match fetched_policy {
            Ok(policy) => {
                let precompiled_policy = PrecompiledPolicy::new(engine, policy);
                debug!(?policy_url, "module compiled");
                (policy_url.clone(), precompiled_policy)
            }
            Err(error) => (policy_url.clone(), Err(anyhow!(error.to_string()))),
        })
        .collect()
}
