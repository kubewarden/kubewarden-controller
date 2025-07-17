use serde::Deserialize;

#[derive(Deserialize, Debug, Clone, Default, PartialEq)]
pub enum PolicyMode {
    #[serde(rename = "monitor")]
    Monitor,
    #[serde(rename = "protect")]
    #[default]
    Protect,
}

impl From<PolicyMode> for String {
    fn from(policy_mode: PolicyMode) -> String {
        match policy_mode {
            PolicyMode::Monitor => String::from("monitor"),
            PolicyMode::Protect => String::from("protect"),
        }
    }
}
