use std::{fmt, str::FromStr};

use crate::admission_response_handler::errors::{EvaluationError, Result};

/// A unique identifier for a policy.
#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub enum PolicyID {
    /// This is the identifier for "individual" policies and for "parent group" policies.
    /// In both cases, this is the name of the policy as seen inside of the `policy.yml` file.
    Policy(String),
    /// This is the identifier of a member of a group policy
    PolicyGroupPolicy {
        /// The name of the group policy, which is also the ID of the parent policy
        group: String,
        /// The name of the policy inside of the group. This is guaranteed to be unique
        name: String,
    },
}

impl fmt::Display for PolicyID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyID::Policy(name) => write!(f, "{}", name),
            PolicyID::PolicyGroupPolicy { group, name } => write!(f, "{}/{}", group, name),
        }
    }
}

impl FromStr for PolicyID {
    type Err = EvaluationError;

    fn from_str(s: &str) -> Result<Self> {
        if s.is_empty() {
            return Err(EvaluationError::InvalidPolicyId(s.to_string()));
        }

        let parts: Vec<&str> = s.split('/').collect();
        match parts.len() {
            1 => Ok(PolicyID::Policy(s.to_string())),
            2 => Ok(PolicyID::PolicyGroupPolicy {
                group: parts[0].to_string(),
                name: parts[1].to_string(),
            }),
            _ => Err(EvaluationError::InvalidPolicyId(s.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use rstest::*;

    use super::*;

    #[rstest]
    #[case::valid_policy("policy1", Ok(PolicyID::Policy("policy1".to_string())))]
    #[case::valid_member_of_policy_group("group1/policy1",
        Ok(
            PolicyID::PolicyGroupPolicy{
                group: "group1".to_string(),
                name: "policy1".to_string(),
            }
        ))]
    #[case::empty_policy("", Err(EvaluationError::InvalidPolicyId("".to_string())))]
    #[case::too_many_separators("a/b/c", Err(EvaluationError::InvalidPolicyId("a/b/c".to_string())))]
    fn create_policy_id_by_parsing_string(#[case] input: &str, #[case] expected: Result<PolicyID>) {
        let actual = input.parse::<PolicyID>();

        match actual {
            Ok(id) => assert_eq!(id, expected.unwrap()),
            Err(e) => assert_eq!(e.to_string(), expected.unwrap_err().to_string()),
        }
    }
}
