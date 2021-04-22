use policy_fetcher::policy::Policy;
use policy_fetcher::storage::Storage;

pub(crate) fn list() -> Vec<Policy> {
    Storage::default().list().unwrap_or_default()
}
