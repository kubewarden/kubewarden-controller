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

use ::tracing::{debug, info, warn, Level};
use anyhow::{anyhow, Result};
use axum::{
    routing::{get, post},
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use evaluation::EvaluationEnvironmentBuilder;
use policy_evaluator::{
    callback_handler::{CallbackHandler, CallbackHandlerBuilder},
    kube,
    policy_fetcher::sigstore::trust::{
        sigstore::{ManualTrustRoot, SigstoreTrustRoot},
        TrustRoot,
    },
    wasmtime,
};
use profiling::activate_memory_profiling;
use rayon::prelude::*;
use std::{fs, net::SocketAddr, sync::Arc};
use tokio::{
    sync::{oneshot, Semaphore},
    time,
};
use tower_http::trace::{self, TraceLayer};

// This is required by certificate hot reload when using inotify, which is available only on linux
#[cfg(target_os = "linux")]
use tokio_stream::StreamExt;

use crate::api::handlers::{
    audit_handler, pprof_get_cpu, pprof_get_heap, readiness_handler, validate_handler,
    validate_raw_handler,
};
use crate::api::state::ApiServerState;
use crate::evaluation::precompiled_policy::{PrecompiledPolicies, PrecompiledPolicy};
use crate::policy_downloader::{Downloader, FetchedPolicies};
use config::{Config, TlsConfig};

use tikv_jemallocator::Jemalloc;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[allow(non_upper_case_globals)]
#[export_name = "malloc_conf"]
/// Prioritize memory usage, then enable features request by pprof but do not activate them by
/// default. When pprof is activate there's a CPU overhead.
pub static malloc_conf: &[u8] = b"background_thread:true,tcache_max:4096,dirty_decay_ms:5000,muzzy_decay_ms:5000,abort_conf:true,prof:true,prof_active:false,lg_prof_sample:19\0";

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

        let sigstore_trust_root = match create_sigstore_trustroot(&config).await {
            Ok(trust_root) => Some(trust_root),
            Err(e) => {
                // Do not exit, only policies making use of sigstore's keyless/certificate based signatures will fail
                // There are good chances everything is going to work fine in the majority of cases
                warn!(?e, "Cannot create Sigstore trust root, verification relying on Rekor and Fulcio will fail");
                None
            }
        };

        let mut callback_handler_builder =
            CallbackHandlerBuilder::new(callback_handler_shutdown_channel_rx)
                .registry_config(config.sources.clone())
                .trust_root(sigstore_trust_root.clone());

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

        let callback_handler = callback_handler_builder.build().await?;
        let callback_sender_channel = callback_handler.sender_channel();

        // Download policies
        let downloader_sigstore_trust_root = if config.verification_config.is_some() {
            sigstore_trust_root.clone()
        } else {
            None
        };
        let mut downloader =
            Downloader::new(config.sources.clone(), downloader_sigstore_trust_root).await?;

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

        if !config.continue_on_errors {
            for result in precompiled_policies.values() {
                if let Err(error) = result {
                    return Err(anyhow!(error.to_string()));
                }
            }
        }

        let mut evaluation_environment_builder = EvaluationEnvironmentBuilder::new(
            &engine,
            &precompiled_policies,
            callback_sender_channel.clone(),
        )
        .with_continue_on_errors(config.continue_on_errors);
        if let Some(namespace) = config.always_accept_admission_reviews_on_namespace {
            evaluation_environment_builder = evaluation_environment_builder
                .with_always_accept_admission_reviews_on_namespace(namespace);
        }
        if let Some(limit) = config.policy_evaluation_limit_seconds {
            evaluation_environment_builder =
                evaluation_environment_builder.with_policy_evaluation_limit_seconds(limit);
        }
        let evaluation_environment = evaluation_environment_builder.build(&config.policies)?;

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
            evaluation_environment: Arc::new(evaluation_environment),
        });

        let tls_config = if let Some(tls_config) = config.tls_config {
            Some(create_tls_config_and_watch_certificate_changes(tls_config).await?)
        } else {
            None
        };

        let mut router = Router::new()
            .route("/audit/{policy_id}", post(audit_handler))
            .route("/validate/{policy_id}", post(validate_handler))
            .route("/validate_raw/{policy_id}", post(validate_raw_handler))
            .with_state(state.clone())
            .layer(
                TraceLayer::new_for_http()
                    .make_span_with(trace::DefaultMakeSpan::new().level(Level::INFO))
                    .on_response(trace::DefaultOnResponse::new().level(Level::INFO)),
            )
            // Adding the readiness probe handler after the tracing layer to avoid logging
            // See: https://github.com/tokio-rs/axum/discussions/355
            .route("/readiness", get(readiness_handler));

        if config.enable_pprof {
            activate_memory_profiling().await?;

            let pprof_router = Router::new()
                .route("/debug/pprof/cpu", get(pprof_get_cpu))
                .route("/debug/pprof/heap", get(pprof_get_heap));
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

/// There's no watching of the certificate files on non-linux platforms
/// since we rely on inotify to watch for changes
#[cfg(not(target_os = "linux"))]
async fn create_tls_config_and_watch_certificate_changes(
    tls_config: TlsConfig,
) -> Result<RustlsConfig> {
    let cfg = RustlsConfig::from_pem_file(tls_config.cert_file, tls_config.key_file).await?;
    Ok(cfg)
}

/// Return the RustlsConfig and watch for changes in the certificate files
/// using inotify.
/// When a both the certificate and its key are changed, the RustlsConfig is reloaded,
/// causing the https server to use the new certificate.
///
/// Relying on inotify is only available on linux
#[cfg(target_os = "linux")]
async fn create_tls_config_and_watch_certificate_changes(
    tls_config: TlsConfig,
) -> Result<RustlsConfig> {
    use ::tracing::error;

    let cert_file = tls_config.cert_file.clone();
    let key_file = tls_config.key_file.clone();

    let rust_config =
        RustlsConfig::from_pem_file(tls_config.cert_file, tls_config.key_file).await?;
    let reloadable_rust_config = rust_config.clone();

    let inotify =
        inotify::Inotify::init().map_err(|e| anyhow!("Cannot initialize inotify: {e}"))?;
    let cert_watch = inotify
        .watches()
        .add(cert_file.clone(), inotify::WatchMask::CLOSE_WRITE)
        .map_err(|e| anyhow!("Cannot watch certificate file: {e}"))?;
    let key_watch = inotify
        .watches()
        .add(key_file.clone(), inotify::WatchMask::CLOSE_WRITE)
        .map_err(|e| anyhow!("Cannot watch key file: {e}"))?;

    let buffer = [0; 1024];
    let stream = inotify
        .into_event_stream(buffer)
        .map_err(|e| anyhow!("Cannot create inotify event stream: {e}"))?;

    tokio::spawn(async move {
        tokio::pin!(stream);
        let mut cert_changed = false;
        let mut key_changed = false;

        while let Some(event) = stream.next().await {
            let event = match event {
                Ok(event) => event,
                Err(e) => {
                    warn!("Cannot read inotify event: {e}");
                    continue;
                }
            };

            if event.wd == cert_watch {
                info!("TLS certificate file has been modified");
                cert_changed = true;
            }
            if event.wd == key_watch {
                info!("TLS key file has been modified");
                key_changed = true;
            }

            if key_changed && cert_changed {
                info!("reloading TLS certificate");

                cert_changed = false;
                key_changed = false;
                if let Err(e) = reloadable_rust_config
                    .reload_from_pem_file(cert_file.clone(), key_file.clone())
                    .await
                {
                    error!("Failed to reload TLS certificate: {}", e);
                }
            }
        }
    });

    Ok(rust_config)
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

async fn create_sigstore_trustroot(config: &Config) -> Result<Arc<ManualTrustRoot<'static>>> {
    if !config.sigstore_cache_dir.exists() {
        fs::create_dir_all(&config.sigstore_cache_dir)
            .map_err(|e| anyhow!("Cannot create directory to cache sigstore data: {}", e))?;
    }

    let repo = SigstoreTrustRoot::new(Some(config.sigstore_cache_dir.as_path())).await?;

    let fulcio_certs: Vec<rustls_pki_types::CertificateDer> = repo
        .fulcio_certs()
        .expect("Cannot fetch Fulcio certificates from TUF repository")
        .into_iter()
        .map(|c| c.into_owned())
        .collect();

    let manual_root = ManualTrustRoot {
        fulcio_certs,
        rekor_keys: repo
            .rekor_keys()
            .expect("Cannot fetch Rekor keys from TUF repository")
            .iter()
            .map(|k| k.to_vec())
            .collect(),
        ..Default::default()
    };

    Ok(Arc::new(manual_root))
}
