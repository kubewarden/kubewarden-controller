use anyhow::Result;
use std::clone::Clone;
use tracing::span;

#[cfg(test)]
use tracing::Level;

use crate::constants::*;
use crate::policy_metadata::Metadata;

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Policy {
    pub name: Option<String>,
    pub settings: Option<serde_json::Map<String, serde_json::Value>>,
    pub wapc_policy_id: u64,
    pub span: span::Span,
    pub request_uid: Option<String>,
}

#[cfg(test)]
impl Default for Policy {
    fn default() -> Self {
        Policy {
            name: None,
            settings: None,
            // This is going to be changed at creation time
            wapc_policy_id: 1,
            //This is going to be changed at creation time
            span: span!(Level::INFO, "kubewarden testing"),
            request_uid: None,
        }
    }
}

impl Policy {
    pub(crate) fn from_contents(
        policy_contents: Vec<u8>,
        wapc_policy_id: u64,
        span: tracing::Span,
        settings: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> Result<Policy> {
        let metadata = Metadata::from_contents(policy_contents)?;
        let policy_name: Option<String> = match metadata {
            Some(ref metadata) => match metadata.annotations {
                Some(ref annotations) => annotations
                    .get(KUBEWARDEN_ANNOTATION_POLICY_TITLE)
                    .map(Clone::clone),
                None => None,
            },
            None => None,
        };

        let policy = Policy {
            name: policy_name,
            settings,
            span,
            request_uid: None,
            wapc_policy_id,
        };

        policy.span.record("policy_name", &policy.name().as_str());

        Ok(policy)
    }

    fn name(&self) -> String {
        self.name
            .as_ref()
            .unwrap_or(&"unknown".to_string())
            .to_string()
    }
}
