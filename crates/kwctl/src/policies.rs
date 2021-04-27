use anyhow::{anyhow, Result};
use policy_fetcher::policy::Policy;
use policy_fetcher::store::Store;

pub(crate) fn list() -> Result<Vec<Policy>> {
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
