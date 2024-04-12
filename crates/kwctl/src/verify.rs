use anyhow::Result;
use policy_evaluator::policy_fetcher::{
    policy::Policy,
    sigstore::trust::ManualTrustRoot,
    sources::Sources,
    verify::{config::LatestVerificationConfig, Verifier},
};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info};

pub(crate) type VerificationAnnotations = HashMap<String, String>;

pub(crate) async fn verify(
    url: &str,
    sources: Option<&Sources>,
    verification_config: &LatestVerificationConfig,
    sigstore_trust_root: Option<Arc<ManualTrustRoot<'static>>>,
) -> Result<String> {
    debug!(
        policy = url,
        ?sources,
        ?verification_config,
        "Verifying policy"
    );
    let mut verifier = Verifier::new(sources.cloned(), sigstore_trust_root).await?;
    let verified_manifest_digest = verifier.verify(url, verification_config).await?;

    info!("Policy successfully verified");
    Ok(verified_manifest_digest)
}

pub(crate) async fn verify_local_checksum(
    policy: &Policy,
    sources: Option<&Sources>,
    verified_manifest_digest: &str,
    sigstore_trust_root: Option<Arc<ManualTrustRoot<'static>>>,
) -> Result<()> {
    let mut verifier = Verifier::new(sources.cloned(), sigstore_trust_root).await?;
    verifier
        .verify_local_file_checksum(policy, verified_manifest_digest)
        .await?;

    info!("Local checksum successfully verified");
    Ok(())
}
