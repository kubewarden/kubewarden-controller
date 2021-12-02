use anyhow::{anyhow, Result};
use policy_fetcher::registry::config::DockerConfig;
use policy_fetcher::sources::Sources;
use policy_fetcher::verify::Verifier;
use std::{collections::HashMap, fs};
use tracing::{debug, info};

use crate::sigstore::SigstoreOpts;

pub(crate) type VerificationAnnotations = HashMap<String, String>;

pub(crate) async fn verify(
    url: &str,
    docker_config: Option<&DockerConfig>,
    sources: Option<&Sources>,
    annotations: Option<&VerificationAnnotations>,
    key_file: &str,
    sigstore_opts: &SigstoreOpts,
) -> Result<String> {
    debug!(policy = url, ?annotations, ?key_file, "Verifying policy");
    let mut verifier = Verifier::new(
        sources.cloned(),
        &sigstore_opts.fulcio_cert,
        &sigstore_opts.rekor_public_key,
    )?;
    let verified_manifest_digest = verifier
        .verify(
            url,
            docker_config.cloned(),
            annotations.cloned(),
            &read_key_file(key_file)?,
        )
        .await?;

    info!("Policy successfully verified");
    Ok(verified_manifest_digest)
}

pub(crate) async fn verify_local_checksum(
    url: &str,
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
        .verify_local_file_checksum(url, docker_config.cloned(), verified_manifest_digest)
        .await?;

    info!("Local checksum successfully verified");
    Ok(())
}

fn read_key_file(path: &str) -> Result<String> {
    fs::read_to_string(path).map_err(|e| anyhow!("could not read file {}: {:?}", path, e))
}
