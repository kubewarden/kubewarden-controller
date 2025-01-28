use std::{
    collections::{HashMap, HashSet},
    fs,
    io::{self, Read},
    path::PathBuf,
    str::FromStr,
    sync::Arc,
};

use anyhow::{anyhow, Result};
use clap::ArgMatches;
use policy_evaluator::policy_fetcher::{
    sigstore::trust::ManualTrustRoot, sources::Sources, verify::config::LatestVerificationConfig,
};
use tracing::info;

use crate::{
    callback_handler,
    config::{
        policy_definition::PolicyDefinition,
        sources::remote_server_options,
        verification::{build_sigstore_trust_root, build_verification_options},
        HostCapabilitiesMode,
    },
    verify,
};

#[derive(Default)]
pub(crate) struct PullAndRunSettings {
    pub sources: Option<Sources>,
    pub request: serde_json::Value,
    /// When verification is enabled, the map is populated with:
    /// - key: the policy URI
    /// - value: the digest of the verified manifest
    pub verified_manifest_digests: Option<HashMap<String, String>>,
    pub sigstore_trust_root: Option<Arc<ManualTrustRoot<'static>>>,
    pub enable_wasmtime_cache: bool,
    pub host_capabilities_mode: HostCapabilitiesMode,
}

pub(crate) fn parse_policy_definitions(matches: &ArgMatches) -> Result<Vec<PolicyDefinition>> {
    let uri = matches
        .get_one::<String>("uri_or_sha_prefix_or_yaml_file")
        .expect("uri_or_sha_prefix is guaranteed to be Some here");

    if uri.ends_with(".yaml") || uri.ends_with(".yml") {
        let raw = matches.get_one::<bool>("raw").unwrap_or(&false);
        if *raw {
            return Err(anyhow!(
                "The --raw option cannot be used with a YAML file: {}",
                uri
            ));
        }
        if matches.contains_id("settings-json") || matches.contains_id("settings-path") {
            info!("The --settings-json and --settings-path options are ignored when using a YAML file");
        }

        // If the URI is a YAML file, parse it as a policy definition
        return PolicyDefinition::from_yaml_file(uri);
    }

    Ok(vec![PolicyDefinition::from_cli(matches)?])
}

pub(crate) async fn parse_pull_and_run_settings(
    matches: &ArgMatches,
    policy_definitions: &[PolicyDefinition],
) -> Result<PullAndRunSettings> {
    let request_raw = match matches
        .get_one::<String>("request-path")
        .map(|s| s.as_str())
        .unwrap()
    {
        "-" => {
            let mut buffer = String::new();
            io::stdin()
                .read_to_string(&mut buffer)
                .map_err(|e| anyhow!("Error reading request from stdin: {}", e))?;
            buffer
        }
        request_path => fs::read_to_string(request_path).map_err(|e| {
            anyhow!(
                "Error opening request file {}; {}",
                matches.get_one::<String>("request-path").unwrap(),
                e
            )
        })?,
    };
    let request = serde_json::from_str::<serde_json::Value>(&request_raw)?;

    let sources = remote_server_options(matches)
        .map_err(|e| anyhow!("Error getting remote server options: {}", e))?;
    let sigstore_trust_root = build_sigstore_trust_root(matches.to_owned()).await?;

    let verified_manifest_digests =
        if let Some(verification_options) = build_verification_options(matches)? {
            Some(
                build_verified_manifest_digests(
                    policy_definitions,
                    &verification_options,
                    &sources,
                    sigstore_trust_root.clone(),
                )
                .await?,
            )
        } else {
            None
        };

    let enable_wasmtime_cache = !matches
        .get_one::<bool>("disable-wasmtime-cache")
        .unwrap_or(&false)
        .to_owned();

    let mut host_capabilities_mode = HostCapabilitiesMode::Direct;
    if matches.contains_id("record-host-capabilities-interactions") {
        let destination = matches
            .get_one::<String>("record-host-capabilities-interactions")
            .map(|destination| PathBuf::from_str(destination).unwrap())
            .ok_or_else(|| anyhow!("Cannot parse 'record-host-capabilities-interactions' file"))?;

        info!(session_file = ?destination, "host capabilities proxy enabled with record mode");
        host_capabilities_mode =
            HostCapabilitiesMode::Proxy(callback_handler::ProxyMode::Record { destination });
    }
    if matches.contains_id("replay-host-capabilities-interactions") {
        let source = matches
            .get_one::<String>("replay-host-capabilities-interactions")
            .map(|source| PathBuf::from_str(source).unwrap())
            .ok_or_else(|| anyhow!("Cannot parse 'replay-host-capabilities-interaction' file"))?;

        info!(session_file = ?source, "host capabilities proxy enabled with replay mode");
        host_capabilities_mode =
            HostCapabilitiesMode::Proxy(callback_handler::ProxyMode::Replay { source });
    }

    Ok(PullAndRunSettings {
        sources,
        request,
        verified_manifest_digests,
        sigstore_trust_root,
        enable_wasmtime_cache,
        host_capabilities_mode,
    })
}

async fn build_verified_manifest_digests(
    policy_definitions: &[PolicyDefinition],
    verification_options: &LatestVerificationConfig,
    sources: &Option<Sources>,
    sigstore_trust_root: Option<Arc<ManualTrustRoot<'static>>>,
) -> Result<HashMap<String, String>> {
    let mut uris: HashSet<String> = HashSet::new();
    for policy_definition in policy_definitions {
        uris = uris.union(&policy_definition.uris()).cloned().collect();
    }

    let mut verified_manifest_digests = HashMap::new();

    for uri in &uris {
        // verify policy prior to pulling if keys listed, and keep the
        // verified manifest digest:
        let verified_manifest_digest = verify::verify(
            uri.as_str(),
            sources.as_ref(),
            verification_options,
            sigstore_trust_root.clone(),
        )
        .await
        .map_err(|e| anyhow!("Policy {} cannot be validated\n{:?}", uri, e))?;
        verified_manifest_digests.insert(uri.clone(), verified_manifest_digest);
    }

    Ok(verified_manifest_digests)
}
