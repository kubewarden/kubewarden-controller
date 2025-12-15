use kubewarden_policy_sdk::crd::policies::common::PolicyMode as PolicyModeSdk;
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

impl From<PolicyModeSdk> for PolicyMode {
    fn from(mode: PolicyModeSdk) -> Self {
        match mode {
            PolicyModeSdk::Protect => PolicyMode::Protect,
            PolicyModeSdk::Monitor => PolicyMode::Monitor,
        }
    }
}
