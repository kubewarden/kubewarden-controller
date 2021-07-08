use anyhow::Result;
use std::clone::Clone;

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Policy {
    pub id: String,
    pub wapc_id: u64,
}

#[cfg(test)]
impl Default for Policy {
    fn default() -> Self {
        Policy {
            id: String::default(),
            wapc_id: 1,
        }
    }
}

impl Policy {
    pub(crate) fn from_contents(id: String, wapc_id: u64) -> Result<Policy> {
        Ok(Policy { id, wapc_id })
    }
}
