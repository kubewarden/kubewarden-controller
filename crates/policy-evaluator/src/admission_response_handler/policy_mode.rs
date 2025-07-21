use serde::Deserialize;

#[derive(Deserialize, Debug, Clone, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PolicyMode {
    Monitor,
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
