use anyhow::Result;
use std::clone::Clone;

#[derive(Clone, Debug, PartialEq)]
pub struct Policy {
    pub id: String,
    policy_id: Option<u64>,
}

#[cfg(test)]
impl Default for Policy {
    fn default() -> Self {
        Policy {
            id: String::default(),
            policy_id: None,
        }
    }
}

impl Policy {
    pub(crate) fn new(id: String, policy_id: Option<u64>) -> Result<Policy> {
        Ok(Policy { id, policy_id })
    }
}
