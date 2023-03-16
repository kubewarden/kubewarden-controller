use anyhow::{anyhow, Result};
use policy_evaluator::{
    policy_fetcher::{policy::Policy, store::Store},
    policy_metadata::Metadata as PolicyMetadata,
};
use pretty_bytes::converter::convert;
use prettytable::{format, Table};

pub(crate) fn list() -> Result<()> {
    if policy_list()?.is_empty() {
        return Ok(());
    }
    let mut table = Table::new();
    table.set_format(*format::consts::FORMAT_NO_LINESEP_WITH_TITLE);
    table.set_titles(row![
        "Policy",
        "Mutating",
        "Context aware",
        "SHA-256",
        "Size"
    ]);
    for policy in policy_list()? {
        let (mutating, context_aware) = if let Some(policy_metadata) =
            PolicyMetadata::from_path(&policy.local_path)
                .map_err(|e| anyhow!("error processing metadata of policy {}: {:?}", policy, e))?
        {
            let mutating = if policy_metadata.mutating {
                "yes"
            } else {
                "no"
            };

            let context_aware = if policy_metadata.context_aware_resources.is_empty() {
                "no"
            } else {
                "yes"
            };

            (mutating, context_aware)
        } else {
            ("unknown", "no")
        };

        let mut sha256sum = policy.digest()?;
        sha256sum.truncate(12);

        let policy_filesystem_metadata = std::fs::metadata(&policy.local_path)?;

        table.add_row(row![
            format!("{policy}"),
            mutating,
            context_aware,
            sha256sum,
            convert(policy_filesystem_metadata.len() as f64),
        ]);
    }
    table.printstd();
    Ok(())
}

fn policy_list() -> Result<Vec<Policy>> {
    Store::default().list()
}
