use anyhow::{anyhow, Result};
use clap::ArgMatches;
use lazy_static::lazy_static;
use policy_evaluator::{
    policy_fetcher::{
        sources::{read_sources_file, Sources},
        verify::config::{read_verification_file, LatestVerificationConfig, VerificationConfigV1},
    },
    policy_metadata::ContextAwareResource,
};
use serde::Deserialize;
use std::{
    collections::{BTreeSet, HashMap},
    env,
    fs::File,
    net::SocketAddr,
    path::{Path, PathBuf},
};

pub static SERVICE_NAME: &str = "kubewarden-policy-server";
const DOCKER_CONFIG_ENV_VAR: &str = "DOCKER_CONFIG";

lazy_static! {
    pub(crate) static ref HOSTNAME: String =
        std::env::var("HOSTNAME").unwrap_or_else(|_| String::from("unknown"));
}

pub struct Config {
    pub addr: SocketAddr,
    pub sources: Option<Sources>,
    pub policies: HashMap<String, PolicyOrPolicyGroup>,
    pub policies_download_dir: PathBuf,
    pub ignore_kubernetes_connection_failure: bool,
    pub always_accept_admission_reviews_on_namespace: Option<String>,
    pub policy_evaluation_limit_seconds: Option<u64>,
    pub tls_config: Option<TlsConfig>,
    pub pool_size: usize,
    pub metrics_enabled: bool,
    pub sigstore_cache_dir: PathBuf,
    pub verification_config: Option<VerificationConfigV1>,
    pub log_level: String,
    pub log_fmt: String,
    pub log_no_color: bool,
    pub daemon: bool,
    pub enable_pprof: bool,
    pub daemon_pid_file: String,
    pub daemon_stdout_file: Option<String>,
    pub daemon_stderr_file: Option<String>,
    pub continue_on_errors: bool,
}

pub struct TlsConfig {
    pub cert_file: String,
    pub key_file: String,
}

impl Config {
    pub fn from_args(matches: &ArgMatches) -> Result<Self> {
        // init some variables based on the cli parameters
        let addr = api_bind_address(matches)?;

        let policies = policies(matches)?;
        let policies_download_dir = matches
            .get_one::<String>("policies-download-dir")
            .map(PathBuf::from)
            .expect("This should not happen, there's a default value for policies-download-dir");
        let policy_evaluation_limit_seconds = if *matches
            .get_one::<bool>("disable-timeout-protection")
            .expect("clap should have set a default value")
        {
            None
        } else {
            Some(
                matches
                    .get_one::<String>("policy-timeout")
                    .expect("policy-timeout should always be set")
                    .parse::<u64>()?,
            )
        };
        let sources = remote_server_options(matches)?;
        let pool_size = matches
            .get_one::<String>("workers")
            .map_or_else(num_cpus::get, |v| {
                v.parse::<usize>()
                    .expect("error parsing the number of workers")
            });
        let always_accept_admission_reviews_on_namespace = matches
            .get_one::<String>("always-accept-admission-reviews-on-namespace")
            .map(|s| s.to_owned());

        let metrics_enabled = matches
            .get_one::<bool>("enable-metrics")
            .expect("clap should have set a default value")
            .to_owned();
        let ignore_kubernetes_connection_failure = matches
            .get_one::<bool>("ignore-kubernetes-connection-failure")
            .expect("clap should have set a default value")
            .to_owned();
        let verification_config = verification_config(matches)?;
        let sigstore_cache_dir = matches
            .get_one::<String>("sigstore-cache-dir")
            .map(PathBuf::from)
            .expect("This should not happen, there's a default value for sigstore-cache-dir");

        let daemon = matches
            .get_one::<bool>("daemon")
            .expect("clap should have set a default value")
            .to_owned();
        let daemon_pid_file = matches
            .get_one::<String>("daemon-pid-file")
            .expect("This should not happen, there's a default value for daemon-pid-file")
            .to_owned();
        let daemon_stdout_file = matches.get_one::<String>("daemon-stdout-file").cloned();
        let daemon_stderr_file = matches.get_one::<String>("daemon-stderr-file").cloned();

        let log_level = matches
            .get_one::<String>("log-level")
            .expect("This should not happen, there's a default value for log-level")
            .to_owned();
        let log_fmt = matches
            .get_one::<String>("log-fmt")
            .expect("This should not happen, there's a default value for log-fmt")
            .to_owned();
        let log_no_color = matches
            .get_one::<bool>("log-no-color")
            .expect("clap should have assigned a default value")
            .to_owned();
        let (cert_file, key_file) = tls_files(matches)?;
        let tls_config = if cert_file.is_empty() {
            None
        } else {
            Some(TlsConfig {
                cert_file,
                key_file,
            })
        };
        let enable_pprof = matches
            .get_one::<bool>("enable-pprof")
            .expect("clap should have assigned a default value")
            .to_owned();

        let continue_on_errors = matches
            .get_one::<bool>("continue-on-errors")
            .expect("clap should have assigned a default value")
            .to_owned();

        Ok(Self {
            addr,
            sources,
            policies,
            policies_download_dir,
            ignore_kubernetes_connection_failure,
            tls_config,
            always_accept_admission_reviews_on_namespace,
            policy_evaluation_limit_seconds,
            pool_size,
            metrics_enabled,
            sigstore_cache_dir,
            verification_config,
            log_level,
            log_fmt,
            log_no_color,
            daemon,
            daemon_pid_file,
            daemon_stdout_file,
            daemon_stderr_file,
            enable_pprof,
            continue_on_errors,
        })
    }
}

fn api_bind_address(matches: &clap::ArgMatches) -> Result<SocketAddr> {
    format!(
        "{}:{}",
        matches.get_one::<String>("address").unwrap(),
        matches.get_one::<String>("port").unwrap()
    )
    .parse()
    .map_err(|e| anyhow!("error parsing arguments: {}", e))
}

fn tls_files(matches: &clap::ArgMatches) -> Result<(String, String)> {
    let cert_file = matches.get_one::<String>("cert-file").unwrap().to_owned();
    let key_file = matches.get_one::<String>("key-file").unwrap().to_owned();
    if cert_file.is_empty() != key_file.is_empty() {
        Err(anyhow!("error parsing arguments: either both --cert-file and --key-file must be provided, or neither"))
    } else {
        Ok((cert_file, key_file))
    }
}

fn policies(matches: &clap::ArgMatches) -> Result<HashMap<String, PolicyOrPolicyGroup>> {
    let policies_file = Path::new(matches.get_one::<String>("policies").unwrap());
    let policies = read_policies_file(policies_file).map_err(|e| {
        anyhow!(
            "error while loading policies from {:?}: {}",
            policies_file,
            e
        )
    })?;

    validate_policies(&policies)?;

    Ok(policies)
}

// Validate the policies and policy groups:
//  - ensure policy names do not contain a '/' character
//  - ensure names of policy group's policies do not contain a '/' character
fn validate_policies(policies: &HashMap<String, PolicyOrPolicyGroup>) -> Result<()> {
    for (name, policy) in policies.iter() {
        if name.contains('/') {
            return Err(anyhow!("policy name '{}' contains a '/' character", name));
        }
        if let PolicyOrPolicyGroup::PolicyGroup { policies, .. } = policy {
            let policies_with_invalid_name: Vec<String> = policies
                .iter()
                .filter_map(|(id, _)| if id.contains('/') { Some(id) } else { None })
                .cloned()
                .collect();
            if !policies_with_invalid_name.is_empty() {
                return Err(anyhow!(
                    "policy group '{}' contains policies with invalid names: {:?}",
                    name,
                    policies_with_invalid_name
                ));
            }
        }
    }
    Ok(())
}

fn verification_config(matches: &clap::ArgMatches) -> Result<Option<LatestVerificationConfig>> {
    match matches.get_one::<String>("verification-path") {
        None => Ok(None),
        Some(path) => {
            let verification_file = Path::new(path);
            Ok(Some(read_verification_file(verification_file)?))
        }
    }
}

fn remote_server_options(matches: &clap::ArgMatches) -> Result<Option<Sources>> {
    let sources = match matches.get_one::<String>("sources-path") {
        Some(sources_file) => Some(
            read_sources_file(Path::new(sources_file))
                .map_err(|e| anyhow!("error while loading sources from {}: {}", sources_file, e))?,
        ),
        None => None,
    };

    if let Some(docker_config_json_path) = matches.get_one::<String>("docker-config-json-path") {
        // docker_credential crate expects the config path in the $DOCKER_CONFIG. Keep docker-config-json-path parameter for backwards compatibility
        env::set_var(DOCKER_CONFIG_ENV_VAR, docker_config_json_path);
    }

    Ok(sources)
}

#[derive(Deserialize, Debug, Clone, Default)]
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

/// Settings specified by the user for a given policy.
#[derive(Debug, Clone, Default)]
pub struct SettingsJSON(serde_json::Map<String, serde_json::Value>);

impl From<SettingsJSON> for serde_json::Map<String, serde_json::Value> {
    fn from(val: SettingsJSON) -> Self {
        val.0
    }
}

impl TryFrom<HashMap<String, serde_yaml::Value>> for SettingsJSON {
    type Error = anyhow::Error;

    fn try_from(settings: HashMap<String, serde_yaml::Value>) -> Result<Self> {
        let settings_yaml = serde_yaml::Mapping::from_iter(
            settings
                .iter()
                .map(|(key, value)| (serde_yaml::Value::String(key.to_string()), value.clone())),
        );
        let settings_json = convert_yaml_map_to_json(settings_yaml)
            .map_err(|e| anyhow!("cannot convert YAML settings to JSON: {:?}", e))?;
        Ok(SettingsJSON(settings_json))
    }
}

#[derive(Debug, Clone)]
pub enum PolicyOrPolicyGroupSettings {
    Policy(SettingsJSON),
    PolicyGroup {
        expression: String,
        message: String,
        policies: Vec<String>,
    },
}

/// `PolicyGroupMember` represents a single policy that is part of a policy group.
#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PolicyGroupMember {
    /// Thge URL where the policy is located
    pub url: String,
    /// The settings for the policy
    pub settings: Option<HashMap<String, serde_yaml::Value>>,
    /// The list of Kubernetes resources the policy is allowed to access
    #[serde(default)]
    pub context_aware_resources: BTreeSet<ContextAwareResource>,
}

impl PolicyGroupMember {
    pub fn settings(&self) -> Result<PolicyOrPolicyGroupSettings> {
        let settings = SettingsJSON::try_from(self.settings.clone().unwrap_or_default())?;
        Ok(PolicyOrPolicyGroupSettings::Policy(settings))
    }
}

/// Describes a policy that can be either an individual policy or a group policy.
#[derive(Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum PolicyOrPolicyGroup {
    /// An individual policy
    #[serde(rename_all = "camelCase")]
    Policy {
        /// The URL where the policy is located
        url: String,
        #[serde(default)]
        /// The mode of the policy
        policy_mode: PolicyMode,
        /// Whether the policy is allowed to mutate the request
        allowed_to_mutate: Option<bool>,
        /// The settings for the policy, as provided by the user
        settings: Option<HashMap<String, serde_yaml::Value>>,
        #[serde(default)]
        /// The list of Kubernetes resources the policy is allowed to access
        context_aware_resources: BTreeSet<ContextAwareResource>,
    },
    /// A group of policies that are evaluated together using a given expression
    #[serde(rename_all = "camelCase")]
    PolicyGroup {
        /// The mode of the policy
        #[serde(default)]
        policy_mode: PolicyMode,
        /// The policies that make up for this group
        /// Key is a unique identifier
        policies: HashMap<String, PolicyGroupMember>,
        /// The expression that is used to evaluate the group of policies
        expression: String,
        /// The message that is returned when the group of policies evaluates to false
        message: String,
    },
}

impl PolicyOrPolicyGroup {
    pub fn settings(&self) -> Result<PolicyOrPolicyGroupSettings> {
        match self {
            PolicyOrPolicyGroup::Policy { settings, .. } => {
                let settings = SettingsJSON::try_from(settings.clone().unwrap_or_default())?;
                Ok(PolicyOrPolicyGroupSettings::Policy(settings))
            }
            PolicyOrPolicyGroup::PolicyGroup {
                expression,
                message,
                policies,
                ..
            } => Ok(PolicyOrPolicyGroupSettings::PolicyGroup {
                expression: expression.clone(),
                message: message.clone(),
                policies: policies.keys().cloned().collect(),
            }),
        }
    }
}

/// Helper function that takes a YAML map and returns a
/// JSON object.
fn convert_yaml_map_to_json(
    yml_map: serde_yaml::Mapping,
) -> Result<serde_json::Map<String, serde_json::Value>> {
    // convert the policy settings from yaml format to json
    let yml_string = serde_yaml::to_string(&yml_map).map_err(|e| {
        anyhow!(
            "error while converting {:?} from yaml to string: {}",
            yml_map,
            e
        )
    })?;

    let v: serde_json::Value = serde_yaml::from_str(&yml_string).map_err(|e| {
        anyhow!(
            "error while converting {:?} from yaml string to json: {}",
            yml_map,
            e
        )
    })?;

    Ok(v.as_object()
        .map_or_else(serde_json::Map::<String, serde_json::Value>::new, |m| {
            m.clone()
        }))
}

/// Reads the policies configuration file, returns a HashMap with String as value
/// and Policy as values. The key is the name of the policy as provided by the user
/// inside of the configuration file. This name is used to build the API path
/// exposing the policy.
fn read_policies_file(path: &Path) -> Result<HashMap<String, PolicyOrPolicyGroup>> {
    let settings_file = File::open(path)?;
    let ps: HashMap<String, PolicyOrPolicyGroup> = serde_yaml::from_reader(&settings_file)?;
    Ok(ps)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli;
    use rstest::*;
    use serde_json::json;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[rstest]
    #[case::settings_empty(
        r#"
---
example:
  url: file:///tmp/namespace-validate-policy.wasm
  settings: {}
"#, json!({})
    )]
    #[case::settings_missing(
        r#"
---
example:
  url: file:///tmp/namespace-validate-policy.wasm
"#, json!({})
    )]
    #[case::settings_null(
        r#"
---
example:
  url: file:///tmp/namespace-validate-policy.wasm
  settings: null
"#, json!({})
    )]
    #[case::settings_provided(
        r#"
---
example:
  url: file:///tmp/namespace-validate-policy.wasm
  settings:
    "counter": 1
    "items": ["a", "b"]
    "nested": {"key": "value"}
"#, json!({"counter": 1, "items": ["a", "b"], "nested": {"key": "value"}})
    )]
    fn handle_settings_conversion(#[case] input: &str, #[case] expected: serde_json::Value) {
        let policies: HashMap<String, PolicyOrPolicyGroup> = serde_yaml::from_str(input).unwrap();
        assert!(!policies.is_empty());

        let policy = policies.get("example").unwrap();
        let settings = policy.settings().unwrap();
        match settings {
            PolicyOrPolicyGroupSettings::Policy(settings) => {
                assert_eq!(serde_json::Value::Object(settings.0), expected);
            }
            _ => panic!("Expected an Individual policy"),
        }
    }

    #[test]
    fn boolean_flags() {
        let policies_yaml = r#"
---
example:
  url: file:///tmp/namespace-validate-policy.wasm
  settings: {}
"#;
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(policies_yaml.as_bytes()).unwrap();
        let file_path = temp_file.into_temp_path();
        let policies_flag = format!("--policies={}", file_path.to_str().unwrap());

        let boolean_flags = [
            "--enable-pprof",
            "--log-no-color",
            "--daemon",
            "--enable-metrics",
        ];

        for provide_flag in [true, false] {
            let cli = cli::build_cli();

            let mut flags = vec!["policy-server", &policies_flag];
            if provide_flag {
                flags.extend(boolean_flags);
            }

            let matches = cli.clone().try_get_matches_from(flags).unwrap();
            let config = Config::from_args(&matches).unwrap();
            assert_eq!(provide_flag, config.enable_pprof);
            assert_eq!(provide_flag, config.log_no_color);
            assert_eq!(provide_flag, config.daemon);
            assert_eq!(provide_flag, config.metrics_enabled);
        }
    }

    #[rstest]
    #[case::all_good(
        r#"
---
example:
  url: file:///tmp/namespace-validate-policy.wasm
  settings: {}
group_policy:
  expression: "true"
  message: "group policy message"
  policies:
    policy1:
      url: file:///tmp/namespace-validate-policy.wasm
      settings: {}
    policy2:
      url: file:///tmp/namespace-validate-policy.wasm
      settings: {}
"#,
        true
    )]
    #[case::policy_with_invalid_name(
        r#"
---
example/invalid:
  url: file:///tmp/namespace-validate-policy.wasm
  settings: {}
"#,
        false
    )]
    #[case::policy_group_member_with_invalid_name(
        r#"
---
example:
  url: file:///tmp/namespace-validate-policy.wasm
  settings: {}
group_policy:
  expression: "true"
  message: "group policy message"
  policies:
    policy1/a:
      url: file:///tmp/namespace-validate-policy.wasm
      settings: {}
    policy2:
      url: file:///tmp/namespace-validate-policy.wasm
      settings: {}
"#,
        false
    )]
    fn policy_validation(#[case] policies_yaml: &str, #[case] is_valid: bool) {
        let policies: HashMap<String, PolicyOrPolicyGroup> =
            serde_yaml::from_str(policies_yaml).unwrap();

        let validation_result = validate_policies(&policies);
        assert_eq!(is_valid, validation_result.is_ok());
    }
}
