use anyhow::{anyhow, Result};
use std::{fs, path::Path};
use tokio::sync::mpsc::Sender;

use crate::callback_requests::CallbackRequest;
use crate::policy_evaluator::{PolicyEvaluator, PolicyExecutionMode};

/// Helper Struct that creates a `PolicyEvaluator` object
#[derive(Default)]
pub struct PolicyEvaluatorBuilder {
    policy_id: String,
    policy_file: Option<String>,
    policy_contents: Option<Vec<u8>>,
    execution_mode: Option<PolicyExecutionMode>,
    settings: Option<serde_json::Map<String, serde_json::Value>>,
    callback_channel: Option<Sender<CallbackRequest>>,
}

impl PolicyEvaluatorBuilder {
    /// Create a new PolicyEvaluatorBuilder object. The `policy_id` must be
    /// specified.
    pub fn new(policy_id: String) -> PolicyEvaluatorBuilder {
        PolicyEvaluatorBuilder {
            policy_id,
            ..Default::default()
        }
    }

    /// Build the policy by reading the Wasm file from disk.
    /// Cannot be used at the same time as `policy_contents`
    pub fn policy_file(mut self, path: &Path) -> Result<PolicyEvaluatorBuilder> {
        let filename = path
            .to_str()
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("Cannot convert given path to String"))?;
        self.policy_file = Some(filename);
        Ok(self)
    }

    /// Build the policy by using the Wasm object given via the `data` array.
    /// Cannot be used at the same time as `policy_file`
    pub fn policy_contents(mut self, data: &[u8]) -> PolicyEvaluatorBuilder {
        self.policy_contents = Some(data.to_owned());
        self
    }

    /// Sets the policy execution mode
    pub fn execution_mode(mut self, mode: PolicyExecutionMode) -> PolicyEvaluatorBuilder {
        self.execution_mode = Some(mode);
        self
    }

    /// Set the settings the policy will use at evaluation time
    pub fn settings(
        mut self,
        s: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> PolicyEvaluatorBuilder {
        self.settings = s;
        self
    }

    /// Specify the channel that is used by the synchronous world (the waPC `host_callback`
    /// function) to obtain information that can be computed only from within a
    /// tokio runtime.
    ///
    /// Note well: if no channel is given, the policy will still be created, but
    /// some waPC functions exposed by the host will not be available at runtime.
    /// The policy evaluation will not fail because of that, but the guest will
    /// get an error instead of the expected result.
    pub fn callback_channel(mut self, channel: Sender<CallbackRequest>) -> PolicyEvaluatorBuilder {
        self.callback_channel = Some(channel);
        self
    }

    /// Create the instance of `PolicyEvaluator` to be used
    pub fn build(self) -> Result<PolicyEvaluator> {
        if self.policy_file.is_some() && self.policy_contents.is_some() {
            return Err(anyhow!(
                "Cannot specify 'policy_file' and 'policy_contents' at the same time"
            ));
        }
        if self.policy_file.is_none() && self.policy_contents.is_none() {
            return Err(anyhow!(
                "Must specify either 'policy_file' or 'policy_contents'"
            ));
        }
        let contents: Vec<u8> = if let Some(file) = self.policy_file {
            fs::read(file.clone())
                .map_err(|e| anyhow!("Cannot read policy from file {}: {:?}", file, e))?
        } else {
            self.policy_contents.unwrap()
        };

        let mode = self
            .execution_mode
            .ok_or_else(|| anyhow!("Must specify execution mode"))?;

        PolicyEvaluator::new(
            self.policy_id,
            contents,
            mode,
            self.settings,
            self.callback_channel,
        )
    }
}
