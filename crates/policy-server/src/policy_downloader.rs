use anyhow::{anyhow, Result};
use policy_evaluator::policy_metadata::Metadata;
use policy_evaluator::{
    policy_fetcher,
    policy_fetcher::{
        sigstore,
        sources::Sources,
        verify::{config::LatestVerificationConfig, FulcioAndRekorData, Verifier},
    },
};
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::PathBuf,
};
use tokio::task::spawn_blocking;
use tracing::{debug, info};

use crate::settings::Policy;

/// A Map with the `policy.url` as key,
/// and a `PathBuf` as value. The `PathBuf` points to the location where
/// the WebAssembly module has been downloaded.
pub(crate) type FetchedPolicies = HashMap<String, PathBuf>;

/// Handles download and verification of policies
pub(crate) struct Downloader {
    verifier: Option<Verifier>,
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
        enable_verification: bool,
        sigstore_cache_dir: Option<PathBuf>,
    ) -> Result<Self> {
        let verifier = if enable_verification {
            info!("Fetching sigstore data from remote TUF repository");
            Some(create_verifier(sources.clone(), sigstore_cache_dir).await?)
        } else {
            None
        };

        Ok(Downloader { verifier, sources })
    }

    /// Download all the policies to the given destination
    pub async fn download_policies(
        &mut self,
        policies: &HashMap<String, Policy>,
        destination: &str,
        verification_config: Option<&LatestVerificationConfig>,
    ) -> Result<FetchedPolicies> {
        let policies_total = policies.len();
        info!(
            download_dir = destination,
            policies_count = policies_total,
            status = "init",
            "policies download",
        );

        let mut policy_verification_errors = vec![];
        let verification_config = verification_config.unwrap_or(&LatestVerificationConfig {
            all_of: None,
            any_of: None,
        });

        // The same WebAssembly module can be referenced by multiple policies,
        // there's no need to keep downloading and verifying it

        // List of policies that we have already tried to download & verify.
        // Note: this Set includes both successful downloads and ones that
        // failed.
        let mut processed_policies: HashSet<&str> = HashSet::new();

        // List of policies that have been successfully fetched.
        // This can be a subset of `processed_policies`
        let mut fetched_policies: FetchedPolicies = HashMap::new();

        for (name, policy) in policies.iter() {
            debug!(policy = name.as_str(), "download");
            if !processed_policies.insert(policy.url.as_str()) {
                debug!(
                    policy = name.as_str(),
                    "skipping, wasm module alredy processed"
                );
                continue;
            }

            let mut verified_manifest_digest: Option<String> = None;

            if let Some(ver) = self.verifier.as_mut() {
                info!(
                    policy = name.as_str(),
                    "verifying policy authenticity and integrity using sigstore"
                );
                verified_manifest_digest = match ver.verify(&policy.url, verification_config).await
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

            fetched_policies.insert(policy.url.clone(), fetched_policy.local_path);
        }

        if policy_verification_errors.is_empty() {
            info!(status = "done", "policies download");
            Ok(fetched_policies)
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
    sigstore_cache_dir: Option<PathBuf>,
) -> Result<Verifier> {
    if let Some(cache_dir) = sigstore_cache_dir.clone() {
        if !cache_dir.exists() {
            fs::create_dir_all(cache_dir)
                .map_err(|e| anyhow!("Cannot create directory to cache sigstore data: {}", e))?;
        }
    }

    let repo = spawn_blocking(move || match sigstore_cache_dir {
        Some(d) => sigstore::tuf::SigstoreRepository::fetch(Some(d.as_path())),
        None => sigstore::tuf::SigstoreRepository::fetch(None),
    })
    .await
    .map_err(|e| anyhow!("Cannot spawn blocking task: {}", e))?;

    let fulcio_and_rekor_data = match repo {
        Ok(repo) => Some(FulcioAndRekorData::FromTufRepository { repo }),
        Err(e) => {
            // We cannot rely on `tracing` yet, because the tracing system has not
            // been initialized, this has to be done inside of an async block, which
            // we cannot use yet
            eprintln!("Cannot fetch TUF repository: {:?}", e);
            eprintln!("Sigstore Verifier created without Fulcio data: keyless signatures are going to be discarded because they cannot be verified");
            eprintln!(
                "Sigstore Verifier created without Rekor data: transparency log data won't be used"
            );
            eprintln!("Sigstore capabilities are going to be limited");
            None
        }
    };
    Verifier::new(sources, fulcio_and_rekor_data.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lazy_static::lazy_static;
    use std::sync::Mutex;
    use tempfile::TempDir;
    use tokio::runtime::Runtime;

    lazy_static! {
        // Allocate the DOWNLOADER once, this is needed to reduce the execution time
        // of the unit tests
        static ref DOWNLOADER: Mutex<Downloader> = Mutex::new({
            let rt = Runtime::new().unwrap();
            rt.block_on(async { Downloader::new(None, true, None).await.unwrap() })
        });
    }

    #[test]
    fn download_and_verify_success() {
        let verification_cfg_yml = r#"---
    allOf:
      - kind: pubKey
        owner: pubkey1.pub
        key: |
              -----BEGIN PUBLIC KEY-----
              MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQiTy5S+2JFvVlhUwWPLziM7iTM2j
              byLgh2IjpNQN0Uio/9pZOTP/CsJmXoUNshfpTUHd3OxgHgz/6adtf2nBwQ==
              -----END PUBLIC KEY-----
        annotations:
          env: prod
          stable: "true"
      - kind: pubKey
        owner: pubkey2.pub
        key: |
              -----BEGIN PUBLIC KEY-----
              MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEx0HuqSss8DUIIUg3I006b1EQjj3Q
              igsTrvZ/Q3+h+81DkNJg4LzID1rz0UJFUcdzI5NqlFLSTDIQw0gVKOiK7g==
              -----END PUBLIC KEY-----
        annotations:
          env: prod
        "#;
        let verification_config =
            serde_yaml::from_str::<LatestVerificationConfig>(verification_cfg_yml)
                .expect("Cannot convert verification config");

        let policies_cfg = r#"
    pod-privileged:
      url: registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    another-pod-privileged:
      url: registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    "#;

        let mut policies: HashMap<String, Policy> =
            serde_yaml::from_str(policies_cfg).expect("Cannot parse policy cfg");

        let policy_download_dir = TempDir::new().expect("Cannot create temp dir");

        // This is required to have lazy_static create the object right now,
        // outside of the tokio runtime. Creating the object inside of the tokio
        // rutime causes a panic because sigstore-rs' code invokes a `block_on` too
        let downloader = DOWNLOADER.lock().unwrap();
        drop(downloader);

        let rt = Runtime::new().unwrap();
        let fetched_policies = rt.block_on(async {
            DOWNLOADER
                .lock()
                .unwrap()
                .download_policies(
                    &mut policies,
                    policy_download_dir.path().to_str().unwrap(),
                    Some(&verification_config),
                )
                .await
                .expect("Cannot download policy")
        });

        // There are 2 policies defined, but they both reference the same
        // WebAssembly module. Hence, just one `.wasm` file is going to be
        // be downloaded
        assert_eq!(fetched_policies.len(), 1);
    }

    #[test]
    fn download_and_verify_error() {
        let verification_cfg_yml = r#"---
    allOf:
      - kind: githubAction
        owner: kubewarden
       "#;
        let verification_config =
            serde_yaml::from_str::<LatestVerificationConfig>(verification_cfg_yml)
                .expect("Cannot convert verification config");

        let policies_cfg = r#"
    pod-privileged:
      url: registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    "#;

        let mut policies: HashMap<String, Policy> =
            serde_yaml::from_str(policies_cfg).expect("Cannot parse policy cfg");

        let policy_download_dir = TempDir::new().expect("Cannot create temp dir");

        // This is required to have lazy_static create the object right now,
        // outside of the tokio runtime. Creating the object inside of the tokio
        // rutime causes a panic because sigstore-rs' code invokes a `block_on` too
        let downloader = DOWNLOADER.lock().unwrap();
        drop(downloader);

        let rt = Runtime::new().unwrap();
        let err = rt.block_on(async {
            DOWNLOADER
                .lock()
                .unwrap()
                .download_policies(
                    &mut policies,
                    policy_download_dir.path().to_str().unwrap(),
                    Some(&verification_config),
                )
                .await
                .expect_err("an error was expected")
        });
        assert!(err
            .to_string()
            .contains("Image verification failed: missing signatures"));
    }
}
