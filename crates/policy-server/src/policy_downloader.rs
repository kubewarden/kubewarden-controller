use anyhow::{anyhow, Result};
use policy_evaluator::{
    policy_fetcher,
    policy_fetcher::{
        sigstore,
        sources::Sources,
        verify::{config::LatestVerificationConfig, Verifier},
    },
    policy_metadata::Metadata,
};
use sigstore::trust::ManualTrustRoot;
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::Arc,
};
use tracing::{debug, error, info};

use crate::config::Policy;

/// A Map with the `policy.url` as key,
/// and a `PathBuf` as value. The `PathBuf` points to the location where
/// the WebAssembly module has been downloaded.
pub(crate) type FetchedPolicies = HashMap<String, Result<PathBuf>>;

/// Handles download and verification of policies
pub(crate) struct Downloader<'v> {
    verifier: Option<Verifier<'v>>,
    sources: Option<Sources>,
}

impl<'v> Downloader<'v> {
    /// Create a new instance of Downloader
    ///
    /// **Warning:** this needs network connectivity because the constructor
    /// fetches Fulcio and Rekor data from the official TUF repository of
    /// sigstore.
    pub async fn new(
        sources: Option<Sources>,
        manual_root: Option<Arc<ManualTrustRoot<'static>>>,
    ) -> Result<Self> {
        let verifier = if let Some(manual_root) = manual_root {
            info!("Fetching sigstore data from remote TUF repository");
            Some(create_verifier(sources.clone(), manual_root).await?)
        } else {
            None
        };

        Ok(Downloader { verifier, sources })
    }

    /// Download all the policies to the given destination
    pub async fn download_policies(
        &mut self,
        policies: &HashMap<String, Policy>,
        destination: impl AsRef<Path>,
        verification_config: Option<&LatestVerificationConfig>,
    ) -> FetchedPolicies {
        let policies_total = policies.len();
        info!(
            download_dir = destination
                .as_ref()
                .to_str()
                .expect("cannot convert path to string"),
            policies_count = policies_total,
            status = "init",
            "policies download",
        );

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
                        error!(policy = name.as_str(), error =?e, "policy cannot be verified");
                        fetched_policies.insert(
                            policy.url.clone(),
                            Err(anyhow!("Policy '{}' cannot be verified: {}", name, e)),
                        );

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

            let fetched_policy = match policy_fetcher::fetch_policy(
                &policy.url,
                policy_fetcher::PullDestination::Store(destination.as_ref().to_path_buf()),
                self.sources.as_ref(),
            )
            .await
            {
                Ok(fetched_policy) => fetched_policy,
                Err(e) => {
                    error!(
                        policy = name.as_str(),
                        error =? e,
                        "policy download failed"
                    );
                    fetched_policies.insert(
                        policy.url.clone(),
                        Err(anyhow!(
                            "Error while downloading policy '{}' from {}: {}",
                            name,
                            policy.url,
                            e
                        )),
                    );

                    continue;
                }
            };

            if let Some(ver) = self.verifier.as_mut() {
                if let Err(e) = ver
                    .verify_local_file_checksum(
                        &fetched_policy,
                        verified_manifest_digest.as_ref().unwrap(),
                    )
                    .await
                {
                    error!(
                        policy = name.as_str(),
                        error =? e,
                        "verification failed"
                    );

                    fetched_policies.insert(
                        policy.url.clone(),
                        Err(anyhow!("Verification of policy {} failed: {}", name, e)),
                    );
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

            fetched_policies.insert(policy.url.clone(), Ok(fetched_policy.local_path));
        }

        fetched_policies
    }
}

/// Creates a new Verifier that fetches Fulcio and Rekor data from the official
/// TUF repository of the sigstore project
async fn create_verifier<'v>(
    sources: Option<Sources>,
    manual_root: Arc<ManualTrustRoot<'static>>,
) -> Result<Verifier<'v>> {
    let verifier = Verifier::new(sources, Some(manual_root)).await?;

    Ok(verifier)
}

#[cfg(test)]
mod tests {
    use super::*;
    use policy_evaluator::policy_fetcher::sigstore::trust::TrustRoot;
    use tempfile::TempDir;

    #[tokio::test]
    async fn verify_success() {
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

        let policies: HashMap<String, Policy> =
            serde_yaml::from_str(policies_cfg).expect("Cannot parse policy cfg");

        let policy_download_dir = TempDir::new().expect("Cannot create temp dir");

        let mut downloader = Downloader::new(None, None).await.unwrap();

        let fetched_policies = downloader
            .download_policies(
                &policies,
                policy_download_dir.path().to_str().unwrap(),
                Some(&verification_config),
            )
            .await;

        // There are 2 policies defined, but they both reference the same
        // WebAssembly module. Hence, just one `.wasm` file is going to be
        // be downloaded
        assert_eq!(fetched_policies.len(), 1);

        assert!(fetched_policies
            .get("registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9")
            .unwrap()
            .is_ok());
    }

    #[tokio::test]
    async fn verify_error() {
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

        let policies: HashMap<String, Policy> =
            serde_yaml::from_str(policies_cfg).expect("Cannot parse policy cfg");

        let policy_download_dir = TempDir::new().expect("Cannot create temp dir");
        let repo = sigstore::trust::sigstore::SigstoreTrustRoot::new(None)
            .await
            .unwrap();

        let fulcio_certs: Vec<rustls_pki_types::CertificateDer> = repo
            .fulcio_certs()
            .expect("Cannot fetch Fulcio certificates from TUF repository")
            .into_iter()
            .map(|c| c.into_owned())
            .collect();

        let manual_root = ManualTrustRoot {
            fulcio_certs: Some(fulcio_certs),
            rekor_keys: Some(
                repo.rekor_keys()
                    .expect("Cannot fetch Rekor keys from TUF repository")
                    .iter()
                    .map(|k| k.to_vec())
                    .collect(),
            ),
        };

        let mut downloader = Downloader::new(None, Some(Arc::new(manual_root)))
            .await
            .unwrap();

        let fetched_policies = downloader
            .download_policies(
                &policies,
                policy_download_dir.path().to_str().unwrap(),
                Some(&verification_config),
            )
            .await;

        // There are 2 policies defined, but they both reference the same
        // WebAssembly module. Hence, just one `.wasm` file is going to be
        // be downloaded
        assert_eq!(fetched_policies.len(), 1);

        assert!(matches!(
            fetched_policies
                .get("registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9")
                .unwrap(),
            Err(error) if error.to_string().contains("Policy 'pod-privileged' cannot be verified: Image verification failed: missing signatures")
        ));
    }
}
