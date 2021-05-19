use anyhow::{anyhow, Result};
use policy_evaluator::policy_metadata::Metadata as PolicyMetadata;
use policy_fetcher::policy::Policy;
use policy_fetcher::store::Store;
use prettytable::{format, Table};
use sha2::{Digest, Sha256};

pub(crate) fn list() -> Result<()> {
    if policy_list()?.is_empty() {
        return Ok(());
    }
    let mut table = Table::new();
    table.set_format(*format::consts::FORMAT_NO_LINESEP_WITH_TITLE);
    table.set_titles(row!["Policy", "Mutating", "SHA-256", "Size"]);
    for policy in policy_list()? {
        let mutating = if let Some(policy_metadata) = PolicyMetadata::from_path(&policy.local_path)?
        {
            if policy_metadata.mutating {
                "yes"
            } else {
                "no"
            }
        } else {
            "unknown"
        };

        let sha256sum = format!(
            "{:.12x}",
            Sha256::digest(&std::fs::read(&policy.local_path)?)
        );

        let policy_filesystem_metadata = std::fs::metadata(&policy.local_path)?;

        table.add_row(row![
            format!("{}", policy),
            mutating,
            sha256sum,
            policy_filesystem_metadata.len()
        ]);
    }
    table.printstd();
    Ok(())
}

fn policy_list() -> Result<Vec<Policy>> {
    match Store::default().list() {
        Ok(policies) => Ok(policies),
        Err(err) => {
            if err.kind() == std::io::ErrorKind::NotFound {
                Ok(Vec::new())
            } else {
                Err(anyhow!("error listing policies: {}", err))
            }
        }
    }
}
