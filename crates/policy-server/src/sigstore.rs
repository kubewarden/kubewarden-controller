use anyhow::{anyhow, Result};
use policy_fetcher::{
    sigstore,
    sources::Sources,
    verify::{FulcioAndRekorData, Verifier},
};
use tokio::task::spawn_blocking;

pub(crate) async fn create_verifier(sources: Option<Sources>) -> Result<Verifier> {
    let repo = spawn_blocking(|| sigstore::tuf::SigstoreRepository::fetch(None))
        .await
        .map_err(|e| anyhow!("Cannot spawn blocking task: {}", e))?
        .map_err(|e| anyhow!("Cannot create TUF repository: {}", e))?;

    let fulcio_and_rekor_data = FulcioAndRekorData::FromTufRepository { repo };
    Verifier::new(sources, &fulcio_and_rekor_data)
}
