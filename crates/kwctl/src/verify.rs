use anyhow::Result;
use policy_fetcher::sources::Sources;
use policy_fetcher::verify::config::LatestVerificationConfig;
use policy_fetcher::verify::Verifier;
use policy_fetcher::{policy::Policy, registry::config::DockerConfig};
use std::collections::HashMap;
use tracing::{debug, info};

use crate::sigstore::SigstoreOpts;

pub(crate) type VerificationAnnotations = HashMap<String, String>;

pub(crate) async fn verify(
    url: &str,
    docker_config: Option<&DockerConfig>,
    sources: Option<&Sources>,
    verification_config: &LatestVerificationConfig,
    sigstore_opts: &SigstoreOpts,
) -> Result<String> {
    debug!(policy = url, "Verifying policy");
    let mut verifier = Verifier::new(
        sources.cloned(),
        &sigstore_opts.fulcio_cert,
        &sigstore_opts.rekor_public_key,
    )?;
    let verified_manifest_digest = verifier
        .verify(url, docker_config.cloned(), verification_config.clone())
        .await?;

    info!("Policy successfully verified");
    Ok(verified_manifest_digest)
}

pub(crate) async fn verify_local_checksum(
    policy: &Policy,
    docker_config: Option<&DockerConfig>,
    sources: Option<&Sources>,
    verified_manifest_digest: &str,
    sigstore_opts: &SigstoreOpts,
) -> Result<()> {
    let mut verifier = Verifier::new(
        sources.cloned(),
        &sigstore_opts.fulcio_cert,
        &sigstore_opts.rekor_public_key,
    )?;
    verifier
        .verify_local_file_checksum(policy, docker_config.cloned(), verified_manifest_digest)
        .await?;

    info!("Local checksum successfully verified");
    Ok(())
}
