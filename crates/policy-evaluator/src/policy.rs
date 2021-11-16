use anyhow::Result;
use std::clone::Clone;
use tokio::sync::mpsc;

use crate::callback_requests::CallbackRequest;

/// Minimal amount of information about a policy that need to
/// be always accessible at runtime.
///
/// This struct is used extensively inside of the `host_callback`
/// function to obtain information about the policy that is invoking
/// a host waPC function, and handle the request.
#[derive(Clone, Debug)]
pub struct Policy {
    pub id: String,
    policy_id: Option<u64>,
    /// Channel used by the synchronous world (the `host_callback` waPC function),
    /// to request the computation of code that can only be run inside of an
    /// asynchronous block
    pub callback_channel: Option<mpsc::Sender<CallbackRequest>>,
}

impl PartialEq for Policy {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.policy_id == other.policy_id
    }
}

#[cfg(test)]
impl Default for Policy {
    fn default() -> Self {
        Policy {
            id: String::default(),
            policy_id: None,
            callback_channel: None,
        }
    }
}

impl Policy {
    pub(crate) fn new(
        id: String,
        policy_id: Option<u64>,
        callback_channel: Option<mpsc::Sender<CallbackRequest>>,
    ) -> Result<Policy> {
        Ok(Policy {
            id,
            policy_id,
            callback_channel,
        })
    }
}
