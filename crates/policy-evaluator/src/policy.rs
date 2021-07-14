use anyhow::Result;
use std::clone::Clone;

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Policy {
    pub id: String,
}

#[cfg(test)]
impl Default for Policy {
    fn default() -> Self {
        Policy {
            id: String::default(),
        }
    }
}

impl Policy {
    pub(crate) fn new(id: String) -> Result<Policy> {
        Ok(Policy { id })
    }
}
