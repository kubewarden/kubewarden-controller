use std::{collections::BTreeMap, convert::TryInto, fs, path::Path, sync::Arc};

use anyhow::{anyhow, Result};
use clap::ArgMatches;
use policy_evaluator::policy_fetcher::{
    sigstore::{
        self,
        trust::{ManualTrustRoot, TrustRoot},
    },
    store::DEFAULT_ROOT,
    verify::config::{read_verification_file, LatestVerificationConfig, Signature, Subject},
};
use tracing::{debug, info};

use crate::{verify::VerificationAnnotations, KWCTL_VERIFICATION_CONFIG};

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

pub(crate) async fn build_sigstore_trust_root(
    matches: ArgMatches,
) -> Result<Option<Arc<ManualTrustRoot<'static>>>> {
    use sigstore::registry::Certificate;

    if matches.contains_id("fulcio-cert-path") || matches.contains_id("rekor-public-key-path") {
        let mut fulcio_certs: Vec<Certificate> = vec![];
        if let Some(items) = matches.get_many::<String>("fulcio-cert-path") {
            for item in items {
                let data = fs::read(item)?;
                let cert = Certificate {
                    data,
                    encoding: sigstore::registry::CertificateEncoding::Pem,
                };
                fulcio_certs.push(cert);
            }
        };

        let mut rekor_public_keys: Vec<Vec<u8>> = vec![];
        if let Some(items) = matches.get_many::<String>("rekor-public-key-path") {
            for item in items {
                let data = fs::read(item)?;
                let pem_data = pem::parse(&data)?;
                rekor_public_keys.push(pem_data.contents().to_owned());
            }
        };

        if fulcio_certs.is_empty() || rekor_public_keys.is_empty() {
            return Err(anyhow!(
                "both a fulcio certificate and a rekor public key are required"
            ));
        }
        debug!("building Sigstore trust root from flags");
        Ok(Some(Arc::new(ManualTrustRoot {
            fulcio_certs: fulcio_certs
                .iter()
                .map(|c| {
                    let cert: sigstore::registry::Certificate = c.to_owned();
                    cert.try_into()
                        .expect("could not convert certificate to CertificateDer")
                })
                .collect(),
            rekor_keys: rekor_public_keys,
            ..Default::default()
        })))
    } else {
        debug!("building Sigstore trust root from Sigstore's TUF repository");
        let checkout_path = DEFAULT_ROOT.config_dir().join("fulcio_and_rekor_data");
        if !Path::exists(&checkout_path) {
            fs::create_dir_all(checkout_path.clone())?
        }

        let repo = sigstore::trust::sigstore::SigstoreTrustRoot::new(Some(checkout_path.as_path()))
            .await?;
        let fulcio_certs: Vec<rustls_pki_types::CertificateDer> = repo
            .fulcio_certs()
            .expect("no fulcio certs found inside of TUF repository")
            .into_iter()
            .map(|c| c.into_owned())
            .collect();
        let manual_root = ManualTrustRoot {
            fulcio_certs,
            rekor_keys: repo
                .rekor_keys()
                .expect("no rekor keys found inside of TUF repository")
                .iter()
                .map(|k| k.to_vec())
                .collect(),
            ..Default::default()
        };
        Ok(Some(Arc::new(manual_root)))
    }
}
