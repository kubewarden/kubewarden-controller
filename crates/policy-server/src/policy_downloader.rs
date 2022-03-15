use anyhow::{anyhow, Result};
use policy_evaluator::policy_metadata::Metadata;
use policy_fetcher::{
    registry::config::DockerConfig,
    sigstore,
    sources::Sources,
    verify::{config::LatestVerificationConfig, FulcioAndRekorData, Verifier},
};
use std::{collections::HashMap, fs, path::PathBuf};
use tokio::task::spawn_blocking;
use tracing::{debug, info};

use crate::settings::Policy;

/// Handles download and verification of policies
pub(crate) struct Downloader {
    verifier: Option<Verifier>,
    verification_config: LatestVerificationConfig,
    docker_config: Option<DockerConfig>,
    sources: Option<Sources>,
}

impl Downloader {
    /// Create a new instance of Downloader
    ///
    /// **Warning:** this needs network connectivity because the constructor
    /// fetches Fulcio and Rekor data from the official TUF repository of
    /// sigstore. This network operations are going to be blocking, that's
    /// caused by the libraries used by sigstore-rs to interact with TUF.
    ///
    /// Being a blocking operation, the other tokio operations are going to be
    /// put on hold until this method is done. This should not be done too often,
    /// otherwise there will be performance consequences.
    pub async fn new(
        sources: Option<Sources>,
        docker_config: Option<DockerConfig>,
        enable_verification: bool,
        verification_config: LatestVerificationConfig,
        sigstore_cache_dir: PathBuf,
    ) -> Result<Self> {
        let verifier = if enable_verification {
            info!("Fetching sigstore data from remote TUF repository");
            Some(create_verifier(sources.clone(), sigstore_cache_dir).await?)
        } else {
            None
        };

        Ok(Downloader {
            verifier,
            verification_config,
            docker_config,
            sources,
        })
    }

    /// Download all the policies to the given destination
    pub async fn download_policies(
        &mut self,
        policies: &mut HashMap<String, Policy>,
        destination: &str,
    ) -> Result<()> {
        let policies_total = policies.len();
        info!(
            download_dir = destination,
            policies_count = policies_total,
            status = "init",
            "policies download",
        );

        let mut policy_verification_errors = vec![];

        for (name, policy) in policies.iter_mut() {
            debug!(policy = name.as_str(), "download");

            let mut verified_manifest_digest: Option<String> = None;

            if let Some(ver) = self.verifier.as_mut() {
                info!(
                    policy = name.as_str(),
                    "verifying policy authenticity and integrity using sigstore"
                );
                verified_manifest_digest = match ver
                    .verify(
                        &policy.url,
                        self.docker_config.as_ref(),
                        &self.verification_config,
                    )
                    .await
                {
                    Ok(d) => Some(d),
                    Err(e) => {
                        info!(policy = name.as_str(), error =?e, "policy cannot be verified");
                        policy_verification_errors
                            .push(format!("Policy '{}' cannot be verified: {:?}", name, e));
                        continue;
                    }
                };
                info!(
                    name = name.as_str(),
                    sha256sum = verified_manifest_digest
                        .as_ref()
                        .unwrap_or(&"unknown".to_string())
                        .as_str(),
                    status = "verified-signatures",
                    "policy download",
                );
            }

            let fetched_policy = policy_fetcher::fetch_policy(
                &policy.url,
                policy_fetcher::PullDestination::Store(PathBuf::from(destination)),
                self.docker_config.as_ref(),
                self.sources.as_ref(),
            )
            .await
            .map_err(|e| {
                anyhow!(
                    "error while downloading policy {} from {}: {}",
                    name,
                    policy.url,
                    e
                )
            })?;

            if let Some(ver) = self.verifier.as_mut() {
                if verified_manifest_digest.is_none() {
                    // when deserializing keys we check that have keys to
                    // verify. We will always have a digest manifest
                    info!(
                        policy = name.as_str(),
                        "cannot verify policy, missing verified manifest digest"
                    );
                    policy_verification_errors
                            .push(format!("verification of policy {} cannot be done, missing verified manifest digest", name));
                    continue;
                }

                if let Err(e) = ver
                    .verify_local_file_checksum(
                        &fetched_policy,
                        self.docker_config.as_ref(),
                        verified_manifest_digest.as_ref().unwrap(),
                    )
                    .await
                {
                    info!(
                        policy = name.as_str(),
                        error =? e,
                        "verification failed"
                    );
                    policy_verification_errors
                        .push(format!("verification of policy {} failed: {}", name, e));

                    continue;
                }

                info!(
                    name = name.as_str(),
                    sha256sum = verified_manifest_digest
                        .as_ref()
                        .unwrap_or(&"unknown".to_string())
                        .as_str(),
                    status = "verified-local-checksum",
                    "policy download",
                );
            }

            if let Ok(Some(policy_metadata)) = Metadata::from_path(&fetched_policy.local_path) {
                info!(
                    name = name.as_str(),
                    path = fetched_policy.local_path.clone().into_os_string().to_str(),
                    sha256sum = fetched_policy
                        .digest()
                        .unwrap_or_else(|_| "unknown".to_string())
                        .as_str(),
                    mutating = policy_metadata.mutating,
                    "policy download",
                );
            } else {
                info!(
                    name = name.as_str(),
                    path = fetched_policy.local_path.clone().into_os_string().to_str(),
                    sha256sum = fetched_policy
                        .digest()
                        .unwrap_or_else(|_| "unknown".to_string())
                        .as_str(),
                    "policy download",
                );
            }
            policy.wasm_module_path = fetched_policy.local_path;
        }

        if policy_verification_errors.is_empty() {
            info!(status = "done", "policies download");
            Ok(())
        } else {
            Err(anyhow!(
                "Failed to verify the following policies: {}",
                policy_verification_errors.join(", ")
            ))
        }
    }
}

/// Creates a new Verifier that fetches Fulcio and Rekor data from the official
/// TUF repository of the sigstore project
async fn create_verifier(
    sources: Option<Sources>,
    sigstore_cache_dir: PathBuf,
) -> Result<Verifier> {
    if !sigstore_cache_dir.exists() {
        fs::create_dir_all(sigstore_cache_dir.clone())
            .map_err(|e| anyhow!("Cannot create directory to cache sigstore data: {}", e))?;
    }

    let repo = spawn_blocking(move || {
        sigstore::tuf::SigstoreRepository::fetch(Some(sigstore_cache_dir.as_path()))
    })
    .await
    .map_err(|e| anyhow!("Cannot spawn blocking task: {}", e))?
    .map_err(|e| anyhow!("Cannot create TUF repository: {}", e))?;

    let fulcio_and_rekor_data = FulcioAndRekorData::FromTufRepository { repo };
    Verifier::new(sources, &fulcio_and_rekor_data)
}
