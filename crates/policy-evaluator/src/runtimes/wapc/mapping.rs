use anyhow::{anyhow, Result};
use lazy_static::lazy_static;
use std::{collections::HashMap, sync::RwLock};

use crate::policy::Policy;

lazy_static! {
    pub(crate) static ref WAPC_POLICY_MAPPING: RwLock<HashMap<u64, Policy>> =
        RwLock::new(HashMap::with_capacity(64));
}

pub(crate) fn get_policy(policy_id: u64) -> Result<Policy> {
    let policy_mapping = WAPC_POLICY_MAPPING.read().map_err(|e| {
        anyhow!(
            "Cannot obtain read lock access to WAPC_POLICY_MAPPING: {}",
            e
        )
    })?;
    policy_mapping
        .get(&policy_id)
        .ok_or_else(|| anyhow!("Cannot find policy with ID {}", policy_id))
        .cloned()
}
