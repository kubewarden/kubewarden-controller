use anyhow::{anyhow, Result};
use policy_evaluator::{policy_artifacthub::ArtifactHubPkg, policy_metadata::Metadata};
use std::{
    fs::{self, File},
    path::PathBuf,
};
use time::OffsetDateTime;

pub(crate) fn artifacthub(
    metadata_path: PathBuf,
    questions_path: Option<PathBuf>,
) -> Result<String> {
    let comment_header = r#"# Kubewarden Artifacthub Package config
#
# Use this config to submit the policy to https://artifacthub.io.
#
# This config can be saved to its default location with:
#   kwctl scaffold artifacthub > artifacthub-pkg.yml "#;

    let metadata_file =
        File::open(metadata_path).map_err(|e| anyhow!("Error opening metadata file: {}", e))?;
    let metadata: Metadata = serde_yaml::from_reader(&metadata_file)
        .map_err(|e| anyhow!("Error unmarshalling metadata {}", e))?;
    let questions = questions_path
        .map(|path| {
            fs::read_to_string(path).map_err(|e| anyhow!("Error reading questions file: {}", e))
        })
        .transpose()?;

    let kubewarden_artifacthub_pkg =
        ArtifactHubPkg::from_metadata(&metadata, OffsetDateTime::now_utc(), questions.as_deref())?;

    Ok(format!(
        "{}\n{}",
        comment_header,
        serde_yaml::to_string(&kubewarden_artifacthub_pkg)?
    ))
}
