use anyhow::Result;
use policy_evaluator::policy_fetcher::{
    policy::Policy,
    sources::Sources,
    verify::{config::LatestVerificationConfig, FulcioAndRekorData, Verifier},
};
use std::collections::HashMap;
use tracing::{debug, info};

pub(crate) type VerificationAnnotations = HashMap<String, String>;

pub(crate) async fn verify(
    url: &str,
    sources: Option<&Sources>,
    verification_config: &LatestVerificationConfig,
    fulcio_and_rekor_data: Option<&FulcioAndRekorData>,
) -> Result<String> {
    debug!(policy = url, "Verifying policy");
    let mut verifier = Verifier::new(sources.cloned(), fulcio_and_rekor_data)?;
    let verified_manifest_digest = verifier.verify(url, verification_config).await?;

    info!("Policy successfully verified");
    Ok(verified_manifest_digest)
}

pub(crate) async fn verify_local_checksum(
    policy: &Policy,
    sources: Option<&Sources>,
    verified_manifest_digest: &str,
    fulcio_and_rekor_data: Option<&FulcioAndRekorData>,
) -> Result<()> {
    let mut verifier = Verifier::new(sources.cloned(), fulcio_and_rekor_data)?;
    verifier
        .verify_local_file_checksum(policy, verified_manifest_digest)
        .await?;

    info!("Local checksum successfully verified");
    Ok(())
}
