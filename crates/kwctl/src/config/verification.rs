use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Result, anyhow};
use clap::ArgMatches;
use policy_evaluator::policy_fetcher::{
    sigstore::{self, trust::sigstore::SigstoreTrustRoot},
    store::DEFAULT_ROOT,
    verify::config::{LatestVerificationConfig, Signature, Subject, read_verification_file},
};
use sigstore_protobuf_specs::dev::sigstore::trustroot::v1::ClientTrustConfig;
use tracing::{debug, info};

use crate::{KWCTL_VERIFICATION_CONFIG, verify::VerificationAnnotations};

pub(crate) fn build_verification_options(
    matches: &ArgMatches,
) -> Result<Option<LatestVerificationConfig>> {
    if let Some(verification_config) = build_verification_options_from_flags(matches)? {
        // flags present, built configmap from them:
        if matches.contains_id("verification-config-path") {
            return Err(anyhow!(
                "verification-config-path cannot be used in conjunction with other verification flags"
            ));
        }
        return Ok(Some(verification_config));
    }
    if let Some(verification_config_path) = matches.get_one::<String>("verification-config-path") {
        // config flag present, read it:
        Ok(Some(read_verification_file(Path::new(
            &verification_config_path,
        ))?))
    } else {
        let verification_config_path = DEFAULT_ROOT.config_dir().join(KWCTL_VERIFICATION_CONFIG);
        if Path::exists(&verification_config_path) {
            // default config flag present, read it:
            info!(path = ?verification_config_path, "Default verification config present, using it");
            Ok(Some(read_verification_file(&verification_config_path)?))
        } else {
            Ok(None)
        }
    }
}

/// Takes clap flags and builds a Some(LatestVerificationConfig) containing all
/// passed pub keys and annotations in LatestVerificationConfig.AllOf.
/// If no verification flags where used, it returns a None.
fn build_verification_options_from_flags(
    matches: &ArgMatches,
) -> Result<Option<LatestVerificationConfig>> {
    let key_files: Option<Vec<String>> = matches
        .get_many::<String>("verification-key")
        .map(|items| items.into_iter().map(|i| i.to_string()).collect());

    let annotations: Option<VerificationAnnotations> =
        match matches.get_many::<String>("verification-annotation") {
            None => None,
            Some(items) => {
                let mut values: BTreeMap<String, String> = BTreeMap::new();
                for item in items {
                    let tmp: Vec<_> = item.splitn(2, '=').collect();
                    if tmp.len() == 2 {
                        values.insert(String::from(tmp[0]), String::from(tmp[1]));
                    }
                }
                if values.is_empty() {
                    None
                } else {
                    Some(values)
                }
            }
        };

    let cert_email: Option<String> = matches
        .get_many::<String>("cert-email")
        .map(|items| items.into_iter().map(|i| i.to_string()).collect());
    let cert_oidc_issuer: Option<String> = matches
        .get_many::<String>("cert-oidc-issuer")
        .map(|items| items.into_iter().map(|i| i.to_string()).collect());

    let github_owner: Option<String> = matches
        .get_many::<String>("github-owner")
        .map(|items| items.into_iter().map(|i| i.to_string()).collect());
    let github_repo: Option<String> = matches
        .get_many::<String>("github-repo")
        .map(|items| items.into_iter().map(|i| i.to_string()).collect());

    if key_files.is_none()
        && annotations.is_none()
        && cert_email.is_none()
        && cert_oidc_issuer.is_none()
        && github_owner.is_none()
        && github_repo.is_none()
    {
        // no verification flags were used, don't create a LatestVerificationConfig
        return Ok(None);
    }

    if key_files.is_none()
        && cert_email.is_none()
        && cert_oidc_issuer.is_none()
        && github_owner.is_none()
        && annotations.is_some()
    {
        return Err(anyhow!(
            "Intending to verify annotations, but no verification keys, OIDC issuer or GitHub owner were passed"
        ));
    }

    if github_repo.is_some() && github_owner.is_none() {
        return Err(anyhow!(
            "Intending to verify GitHub actions signature, but the repository owner is missing."
        ));
    }

    let mut signatures: Vec<Signature> = Vec::new();

    if (cert_email.is_some() && cert_oidc_issuer.is_none())
        || (cert_email.is_none() && cert_oidc_issuer.is_some())
    {
        return Err(anyhow!(
            "Intending to verify OIDC issuer, but no email or issuer were provided. You must pass the email and OIDC issuer to be validated together "
        ));
    } else if cert_email.is_some() && cert_oidc_issuer.is_some() {
        let sig = Signature::GenericIssuer {
            issuer: cert_oidc_issuer.unwrap(),
            subject: Subject::Equal(cert_email.unwrap()),
            annotations: annotations.clone(),
        };
        signatures.push(sig)
    }

    if let Some(repo_owner) = github_owner {
        let sig = Signature::GithubAction {
            owner: repo_owner,
            repo: github_repo,
            annotations: annotations.clone(),
        };
        signatures.push(sig)
    }

    for key_path in key_files.iter().flatten() {
        let sig = Signature::PubKey {
            owner: None,
            key: fs::read_to_string(key_path)
                .map_err(|e| anyhow!("could not read file {}: {:?}", key_path, e))?
                .to_string(),
            annotations: annotations.clone(),
        };
        signatures.push(sig);
    }
    let signatures_all_of: Option<Vec<Signature>> = if signatures.is_empty() {
        None
    } else {
        Some(signatures)
    };
    let verification_config = LatestVerificationConfig {
        all_of: signatures_all_of,
        any_of: None,
    };
    Ok(Some(verification_config))
}

/// Function that builds the Sigstore trust root used for verification. If a trust-config flag is
/// provided, it uses that file to load the trust root. Otherwise, it builds the trust root from
/// Sigstore's TUF repository.
pub(crate) async fn build_sigstore_trust_root(
    sigstore_trust_config: Option<&PathBuf>,
) -> Result<Option<Arc<SigstoreTrustRoot>>> {
    if let Some(pki_file) = sigstore_trust_config {
        return build_sigstore_trust_root_from_config(pki_file);
    }
    debug!("building Sigstore trust root from Sigstore's TUF repository");
    let checkout_path = DEFAULT_ROOT.config_dir().join("fulcio_and_rekor_data");
    if !Path::exists(&checkout_path) {
        fs::create_dir_all(checkout_path.clone())?
    }

    let trust_root =
        sigstore::trust::sigstore::SigstoreTrustRoot::new(Some(checkout_path.as_path())).await?;
    Ok(Some(Arc::new(trust_root)))
}

fn build_sigstore_trust_root_from_config(
    pki_file: &PathBuf,
) -> Result<Option<Arc<SigstoreTrustRoot>>> {
    debug!(
        "Using user specified Sigstore trust root location: {}",
        pki_file.display()
    );
    let json_bytes = fs::read(pki_file).map_err(|e| {
        anyhow!(
            "could not read Sigstore PKI file {}: {:?}",
            pki_file.display(),
            e
        )
    })?;
    // Sigstore.rs does not have a direct way to read from file, so we parse the
    // protobuf spec first, then re-serialize the trusted_root field to JSON bytes
    let client_trust_config: ClientTrustConfig = serde_json::from_slice(json_bytes.as_slice())
        .map_err(|e| {
            anyhow!(
                "could not parse Sigstore trust config file {}: {:?}",
                pki_file.display(),
                e
            )
        })?;
    let trust_root = client_trust_config.trusted_root.ok_or_else(|| {
        anyhow!(
            "Sigstore PKI file {} missing trusted_root field",
            pki_file.display()
        )
    })?;
    let trust_root_bytes = serde_json::to_vec(&trust_root)?;
    let trust_root =
        sigstore::trust::sigstore::SigstoreTrustRoot::from_trusted_root_json_unchecked(
            trust_root_bytes.as_slice(),
        )?;
    Ok(Some(Arc::new(trust_root)))
}
