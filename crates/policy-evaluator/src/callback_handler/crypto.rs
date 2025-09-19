use anyhow::{anyhow, Result};
use kubewarden_policy_sdk::host_capabilities::{
    crypto::{Certificate, CertificateEncoding},
    crypto_v1::{CertificateVerificationRequest, CertificateVerificationResponse},
};
use pki_types::{pem::PemObject, CertificateDer, TrustAnchor, UnixTime};
use webpki::{EndEntityCert, Error};

const CERTIFICATE_USED_AFTER_EXPIRATION: &str =
    "Certificate is being used after its expiration date";
const CERTIFICATE_USED_BEFORE_VALIDITY: &str = "Certificate is being used before its validity date";
const CERTIFICATE_NOT_TRUSTED_BY_CHAIN: &str =
    "Certificate is not trusted by the provided cert chain";

// Helper function to convert a KW Certificate to a webpki CertificateDer
fn get_certificate_der<'a>(cert: &'a Certificate) -> Result<CertificateDer<'a>> {
    match cert.encoding {
        CertificateEncoding::Pem => CertificateDer::from_pem_slice(&cert.data)
            .map_err(|e| anyhow!("Certificate PEM data is not valid: {}", e)),
        CertificateEncoding::Der => Ok(CertificateDer::from_slice(&cert.data)),
    }
}

/// Verify a certificate against an optional chain of trust.
/// The certificate is checked for validation time, and if a cert chain is provided,
/// the certificate is checked against the chain of trust.
///
/// Not providing a cert chain will verify the certificate using Mozilla's CA root certificates.
///
/// Note: we use webpki for certificate verification, which does not check the expiration
/// of the root CA. Intermediate CAs are checked for expiration.
pub fn verify_certificate(
    req: CertificateVerificationRequest,
) -> Result<cached::Return<CertificateVerificationResponse>> {
    let cert_der = get_certificate_der(&req.cert)?;
    let end_entity_certificate = EndEntityCert::try_from(&cert_der)
        .map_err(|e| anyhow!("Certificate is not a valid end-entity certificate: {}", e))?;

    // verify validity
    let verification_time = match &req.not_after {
        Some(not_after_str) => {
            // picky - the library we used earlier - deals with UTCTime as defined in:
            //   https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5.1
            //
            // Convert RFC 3339 not_after string from the request to chrono's
            // DateTime<Utc>, to ensure Zulu:
            let not_after_utc = chrono::DateTime::parse_from_rfc3339(not_after_str)
                .map_err(|_| anyhow!("Timestamp not_after is not in RFC3339 format"))?
                .to_utc();
            UnixTime::since_unix_epoch(std::time::Duration::from_secs(
                not_after_utc.timestamp() as u64
            ))
        }
        None => {
            let now = std::time::Duration::from_secs(chrono::Utc::now().timestamp() as u64);
            UnixTime::since_unix_epoch(now)
        }
    };

    verify_cert_chain(req.cert_chain, end_entity_certificate, verification_time)
}

fn verify_cert_chain(
    cert_chain: Option<Vec<Certificate>>,
    end_entity_certificate: EndEntityCert,
    verification_time: UnixTime,
) -> Result<cached::Return<CertificateVerificationResponse>> {
    let cert_pool = match &cert_chain {
        None => CertificatePool::from_webpki_roots(),
        Some(chain) => CertificatePool::from_certificates(chain),
    }?;

    let signing_algs = webpki::ALL_VERIFICATION_ALGS;

    let verification_result = end_entity_certificate.verify_for_usage(
        signing_algs,
        &cert_pool.trusted_roots,
        &cert_pool.intermediates,
        verification_time,
        KeyUsageAlwaysValid::accept_any(),
        None,
        None,
    );

    match verification_result {
        Ok(_) => Ok(cached::Return {
            value: CertificateVerificationResponse {
                trusted: true,
                reason: "".to_string(),
            },
            was_cached: false,
        }),
        Err(Error::InvalidSignatureForPublicKey) => Ok(cached::Return {
            value: CertificateVerificationResponse {
                trusted: false,
                reason: CERTIFICATE_NOT_TRUSTED_BY_CHAIN.to_string(),
            },
            was_cached: false,
        }),
        Err(Error::CertExpired {
            time: _,
            not_after: _,
        }) => Ok(cached::Return {
            value: CertificateVerificationResponse {
                trusted: false,
                reason: CERTIFICATE_USED_AFTER_EXPIRATION.to_string(),
            },
            was_cached: false,
        }),
        Err(Error::CertNotValidYet {
            time: _,
            not_before: _,
        }) => Ok(cached::Return {
            value: CertificateVerificationResponse {
                trusted: false,
                reason: CERTIFICATE_USED_BEFORE_VALIDITY.to_string(),
            },
            was_cached: false,
        }),
        Err(Error::UnknownIssuer) => Ok(cached::Return {
            value: CertificateVerificationResponse {
                trusted: false,
                reason: CERTIFICATE_NOT_TRUSTED_BY_CHAIN.to_string(),
            },
            was_cached: false,
        }),
        Err(e) => Ok(cached::Return {
            value: CertificateVerificationResponse {
                trusted: false,
                reason: format!("Certificate not trusted: {}", e),
            },
            was_cached: false,
        }),
    }
}

/// A collection of trusted certificates, both root, and intermediate ones.
#[derive(Default, Debug)]
struct CertificatePool<'a> {
    trusted_roots: Vec<TrustAnchor<'a>>,
    intermediates: Vec<CertificateDer<'a>>,
}

impl<'a> CertificatePool<'a> {
    /// Build a `CertificatePool` instance using the provided list of [`Certificate`]
    fn from_certificates(certs: &'a [Certificate]) -> Result<Self> {
        let mut trusted_roots = vec![];
        let mut intermediates = vec![];

        let mut certs_der = certs
            .iter()
            .map(get_certificate_der)
            .collect::<Result<Vec<CertificateDer>>>()?;

        // The API expects the last certificate in the chain to be the root ca
        if let Some(root_cert) = certs_der.pop() {
            trusted_roots.push(webpki::anchor_from_trusted_cert(&root_cert)?.to_owned());
        }
        while let Some(intermediate_cert_der) = certs_der.pop() {
            intermediates.push(intermediate_cert_der);
        }

        Ok(CertificatePool {
            trusted_roots,
            intermediates,
        })
    }

    fn from_webpki_roots() -> Result<Self> {
        Ok(CertificatePool {
            trusted_roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            intermediates: vec![],
        })
    }
}

/// A validator for webpki `verify_for_usage` function that accepts any EKU
struct KeyUsageAlwaysValid;

impl webpki::ExtendedKeyUsageValidator for KeyUsageAlwaysValid {
    fn validate(&self, _: webpki::KeyPurposeIdIter<'_, '_>) -> Result<(), Error> {
        Ok(())
    }
}

impl KeyUsageAlwaysValid {
    const fn accept_any() -> Self {
        KeyUsageAlwaysValid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::Utc;
    use kubewarden_policy_sdk::host_capabilities::crypto::{Certificate, CertificateEncoding};
    use kubewarden_policy_sdk::host_capabilities::crypto_v1::CertificateVerificationRequest;
    use lazy_static::lazy_static;
    use rcgen::{
        CertificateParams, CertifiedKey, ExtendedKeyUsagePurpose, Issuer, KeyPair, KeyUsagePurpose,
    };
    use rstest::rstest;
    use time::{Duration, OffsetDateTime};

    lazy_static! {
        static ref ONE_YEAR_AGO: OffsetDateTime = OffsetDateTime::now_utc()
            .checked_sub(Duration::days(365))
            .unwrap();
        static ref TWO_YEARS_AGO: OffsetDateTime = OffsetDateTime::now_utc()
            .checked_sub(Duration::days(365 * 2))
            .unwrap();
        static ref ONE_YEAR_IN_FUTURE: OffsetDateTime = OffsetDateTime::now_utc()
            .checked_add(Duration::days(365))
            .unwrap();
        static ref TWO_YEARS_IN_FUTURE: OffsetDateTime = OffsetDateTime::now_utc()
            .checked_add(Duration::days(365 * 2))
            .unwrap();
        static ref TEN_DAYS_AGO: OffsetDateTime = OffsetDateTime::now_utc()
            .checked_sub(Duration::days(10))
            .unwrap();
        static ref TEN_DAYS_IN_FUTURE: OffsetDateTime = OffsetDateTime::now_utc()
            .checked_add(Duration::days(10))
            .unwrap();
    }

    #[derive(Clone)]
    struct CertificateGenerationSpec<'a> {
        pub subject_alt_names: &'a [&'a str],
        pub not_before: OffsetDateTime,
        pub not_after: OffsetDateTime,
    }

    fn build_cert_params(spec: CertificateGenerationSpec, is_ca: bool) -> CertificateParams {
        let is_ca_param = if is_ca {
            rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained)
        } else {
            rcgen::IsCa::NoCa
        };

        let key_usages = if is_ca {
            vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign]
        } else {
            vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyEncipherment,
            ]
        };

        let extended_key_usages = if is_ca {
            vec![]
        } else {
            vec![ExtendedKeyUsagePurpose::ServerAuth]
        };

        let mut cert_param = CertificateParams::new(
            spec.subject_alt_names
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<String>>(),
        )
        .expect("Failed to create CertificateParams");

        cert_param.not_before = spec.not_before;
        cert_param.not_after = spec.not_after;
        cert_param.is_ca = is_ca_param;
        cert_param.key_usages = key_usages;
        cert_param.extended_key_usages = extended_key_usages;

        cert_param
    }

    fn generate_certificate(
        spec: CertificateGenerationSpec,
        is_ca: bool,
        issuer: Option<CertifiedKey<KeyPair>>,
    ) -> Result<CertifiedKey<KeyPair>> {
        let cert_param = build_cert_params(spec, is_ca);

        // The public and private key used by the certificate
        let cert_keypair = KeyPair::generate()
            .map_err(|e| anyhow!("Failed to generate certificate key pair: {}", e))?;

        let cert = match (is_ca, issuer) {
            (true, None) => {
                // Generate the root CA
                cert_param.self_signed(&cert_keypair)
            }
            (_, Some(certified_key)) => {
                // Generate intermediate CA or end entity certificate
                let issuer =
                    Issuer::from_ca_cert_der(certified_key.cert.der(), certified_key.signing_key)
                        .map_err(|e| anyhow!("Failed to create issuer from cert: {}", e))?;
                cert_param.signed_by(&cert_keypair, &issuer)
            }
            (is_ca, issuer) => {
                return Err(anyhow!(
                    "Invalid parameters: is_ca={}, issuer.is_none()={}",
                    is_ca,
                    issuer.is_none()
                ));
            }
        }
        .map_err(|e| anyhow!("Failed to create certificate: {}", e))?;

        Ok(CertifiedKey {
            cert,
            signing_key: cert_keypair,
        })
    }

    // Generates a certificate chain with a root CA, an intermediate CA, and an end-entity certificate.
    fn generate_certificate_chain(
        root_ca_spec: CertificateGenerationSpec,
        intermediate_ca_spec: Option<CertificateGenerationSpec>,
        end_entity_spec: CertificateGenerationSpec,
    ) -> (Certificate, Vec<Certificate>) {
        let root_ca =
            generate_certificate(root_ca_spec, true, None).expect("Failed to create root CA");
        let root_ca_cert = Certificate {
            encoding: CertificateEncoding::Pem,
            data: root_ca.cert.pem().as_bytes().to_vec(),
        };

        let intermediate_ca = intermediate_ca_spec.map(|spec| {
            generate_certificate(
                spec,
                true,
                Some(CertifiedKey {
                    // We have to manually clone the root CA to avoid the borrow checker complaining
                    cert: root_ca.cert.clone(),
                    signing_key: KeyPair::from_pem(root_ca.signing_key.serialize_pem().as_str())
                        .unwrap(),
                }),
            )
            .expect("Failed to create intermediate CA")
        });

        let end_entity_signer = if let Some(ca) = &intermediate_ca {
            Some(CertifiedKey {
                // We have to manually implement a to_owned because we have to use a reference of
                // intermediate_ca to avoid the borrow checker complaining
                cert: ca.cert.clone(),
                signing_key: KeyPair::from_pem(ca.signing_key.serialize_pem().as_str()).unwrap(),
            })
        } else {
            Some(root_ca)
        };

        let end_entity_certificate =
            generate_certificate(end_entity_spec, false, end_entity_signer)
                .expect("Failed to create end entity cert");
        let end_entity_cert = Certificate {
            encoding: CertificateEncoding::Pem,
            data: end_entity_certificate.cert.pem().as_bytes().to_vec(),
        };

        let cert_chain = if let Some(ca) = intermediate_ca {
            let intermediate_ca_cert = Certificate {
                encoding: CertificateEncoding::Pem,
                data: ca.cert.pem().as_bytes().to_vec(),
            };
            vec![intermediate_ca_cert, root_ca_cert]
        } else {
            vec![root_ca_cert]
        };

        (end_entity_cert, cert_chain)
    }

    #[rstest]
    #[case::with_intermediate(
        CertificateGenerationSpec {
            subject_alt_names: &["root.kubewarden.io"],
            not_before: *TWO_YEARS_AGO,
            not_after: *TWO_YEARS_IN_FUTURE,
        },
        Some(CertificateGenerationSpec {
            subject_alt_names: &["intermediate.kubewarden.io"],
            not_before: *ONE_YEAR_AGO,
            not_after: *TWO_YEARS_IN_FUTURE,
        }),
        CertificateGenerationSpec {
            subject_alt_names: &["endentity.kubewarden.io"],
            not_before: *TEN_DAYS_AGO,
            not_after: *TEN_DAYS_IN_FUTURE,
        }
    )]
    #[case::without_intermediate(
        CertificateGenerationSpec {
            subject_alt_names: &["root.kubewarden.io"],
            not_before: *TWO_YEARS_AGO,
            not_after: *TWO_YEARS_IN_FUTURE,
        },
        None,
        CertificateGenerationSpec {
            subject_alt_names: &["endentity.kubewarden.io"],
            not_before: *TEN_DAYS_AGO,
            not_after: *TEN_DAYS_IN_FUTURE,
        }
    )]
    fn certificate_is_trusted(
        #[case] root_ca_spec: CertificateGenerationSpec,
        #[case] intermediate_ca_spec: Option<CertificateGenerationSpec>,
        #[case] end_entity_spec: CertificateGenerationSpec,
    ) {
        let (end_entity_cert, cert_chain) =
            generate_certificate_chain(root_ca_spec, intermediate_ca_spec, end_entity_spec);

        let req = CertificateVerificationRequest {
            cert: end_entity_cert,
            cert_chain: Some(cert_chain),
            not_after: None,
        };
        assert_eq!(
            verify_certificate(req).unwrap().value,
            CertificateVerificationResponse {
                trusted: true,
                reason: "".to_string(),
            }
        );
    }

    #[rstest]
    #[case::used_after_expiration_and_no_intermediate(
        CertificateGenerationSpec {
            subject_alt_names: &["root.kubewarden.io"],
            not_before: *TWO_YEARS_AGO,
            not_after: *TWO_YEARS_IN_FUTURE,
        },
        None,
        CertificateGenerationSpec {
            subject_alt_names: &["endentity.kubewarden.io"],
            not_before: *ONE_YEAR_AGO,
            not_after: *TEN_DAYS_AGO,
        },
        CERTIFICATE_USED_AFTER_EXPIRATION
    )]
    #[case::used_before_notbefore_and_no_intermediate(
        CertificateGenerationSpec {
            subject_alt_names: &["root.kubewarden.io"],
            not_before: *TWO_YEARS_AGO,
            not_after: *TWO_YEARS_IN_FUTURE,
        },
        None,
        CertificateGenerationSpec {
            subject_alt_names: &["endentity.kubewarden.io"],
            not_before: *TEN_DAYS_IN_FUTURE,
            not_after: *ONE_YEAR_IN_FUTURE,
        },
        CERTIFICATE_USED_BEFORE_VALIDITY
    )]
    #[case::intermediate_used_after_expiration_valid_intermediate_ca(
        CertificateGenerationSpec {
            subject_alt_names: &["root.kubewarden.io"],
            not_before: *TWO_YEARS_AGO,
            not_after: *TWO_YEARS_IN_FUTURE,
        },
        Some(CertificateGenerationSpec {
            subject_alt_names: &["intermediate.kubewarden.io"],
            not_before: *ONE_YEAR_AGO,
            not_after: *TWO_YEARS_IN_FUTURE,
        }),
        CertificateGenerationSpec {
            subject_alt_names: &["endentity.kubewarden.io"],
            not_before: *ONE_YEAR_AGO,
            not_after: *TEN_DAYS_AGO,
        },
        CERTIFICATE_USED_AFTER_EXPIRATION
    )]
    #[case::used_before_notbefore_valid_intermediate_ca(
        CertificateGenerationSpec {
            subject_alt_names: &["root.kubewarden.io"],
            not_before: *TWO_YEARS_AGO,
            not_after: *TWO_YEARS_IN_FUTURE,
        },
        Some(CertificateGenerationSpec {
            subject_alt_names: &["intermediate.kubewarden.io"],
            not_before: *ONE_YEAR_AGO,
            not_after: *TWO_YEARS_IN_FUTURE,
        }),
        CertificateGenerationSpec {
            subject_alt_names: &["endentity.kubewarden.io"],
            not_before: *TEN_DAYS_IN_FUTURE,
            not_after: *ONE_YEAR_IN_FUTURE,
        },
        CERTIFICATE_USED_BEFORE_VALIDITY
    )]
    fn certificate_expired_no_chain(
        #[case] root_ca_spec: CertificateGenerationSpec,
        #[case] intermediate_ca_spec: Option<CertificateGenerationSpec>,
        #[case] end_entity_spec: CertificateGenerationSpec,
        #[case] error_msg: &str,
    ) {
        let (end_entity_cert, _) =
            generate_certificate_chain(root_ca_spec, intermediate_ca_spec, end_entity_spec);

        let req = CertificateVerificationRequest {
            cert: end_entity_cert,
            cert_chain: None,
            not_after: None,
        };
        assert_eq!(
            verify_certificate(req).unwrap().value,
            CertificateVerificationResponse {
                trusted: false,
                reason: error_msg.to_string(),
            }
        );
    }

    #[test]
    fn certificate_is_not_trusted() {
        // Build two different certificate chains, both valid in terms of expiration dates.
        // Generate a certificate from the first chain, but provide the second chain for verification.

        let root_ca_spec = CertificateGenerationSpec {
            subject_alt_names: &["root.kubewarden.io"],
            not_before: *TWO_YEARS_AGO,
            not_after: *TWO_YEARS_IN_FUTURE,
        };
        let intermediate_ca_spec = CertificateGenerationSpec {
            subject_alt_names: &["intermediate.kubewarden.io"],
            not_before: *ONE_YEAR_AGO,
            not_after: *TWO_YEARS_IN_FUTURE,
        };
        let end_entity_spec = CertificateGenerationSpec {
            subject_alt_names: &["endentity.kubewarden.io"],
            not_before: *TEN_DAYS_AGO,
            not_after: *TEN_DAYS_IN_FUTURE,
        };

        let root_ca2_spec = CertificateGenerationSpec {
            subject_alt_names: &["root2.kubewarden.io"],
            not_before: *TWO_YEARS_AGO,
            not_after: *TWO_YEARS_IN_FUTURE,
        };

        let (end_entity_cert, _) = generate_certificate_chain(
            root_ca_spec,
            Some(intermediate_ca_spec),
            end_entity_spec.clone(),
        );
        let (_, cert_chain2) = generate_certificate_chain(root_ca2_spec, None, end_entity_spec);
        let req = CertificateVerificationRequest {
            cert: end_entity_cert,
            cert_chain: Some(cert_chain2),
            not_after: None,
        };

        assert_eq!(
            verify_certificate(req).unwrap().value,
            CertificateVerificationResponse {
                trusted: false,
                reason: CERTIFICATE_NOT_TRUSTED_BY_CHAIN.to_string(),
            }
        );
    }

    #[test]
    fn certificate_is_not_trusted_no_chain_provided_by_user() {
        let root_ca_spec = CertificateGenerationSpec {
            subject_alt_names: &["root.kubewarden.io"],
            not_before: *TWO_YEARS_AGO,
            not_after: *TWO_YEARS_IN_FUTURE,
        };
        let intermediate_ca_spec = CertificateGenerationSpec {
            subject_alt_names: &["intermediate.kubewarden.io"],
            not_before: *ONE_YEAR_AGO,
            not_after: *TWO_YEARS_IN_FUTURE,
        };
        let end_entity_spec = CertificateGenerationSpec {
            subject_alt_names: &["endentity.kubewarden.io"],
            not_before: *TEN_DAYS_AGO,
            not_after: *TEN_DAYS_IN_FUTURE,
        };

        let (end_entity_cert, _) =
            generate_certificate_chain(root_ca_spec, Some(intermediate_ca_spec), end_entity_spec);
        let req = CertificateVerificationRequest {
            cert: end_entity_cert,
            cert_chain: None,
            not_after: None,
        };
        assert_eq!(
            verify_certificate(req).unwrap().value,
            CertificateVerificationResponse {
                trusted: false,
                reason: CERTIFICATE_NOT_TRUSTED_BY_CHAIN.to_string(),
            }
        );
    }

    #[test]
    fn certificate_malformed_not_after() {
        let root_ca_spec = CertificateGenerationSpec {
            subject_alt_names: &["root.kubewarden.io"],
            not_before: *TWO_YEARS_AGO,
            not_after: *TWO_YEARS_IN_FUTURE,
        };
        let intermediate_ca_spec = CertificateGenerationSpec {
            subject_alt_names: &["intermediate.kubewarden.io"],
            not_before: *ONE_YEAR_AGO,
            not_after: *TWO_YEARS_IN_FUTURE,
        };
        let end_entity_spec = CertificateGenerationSpec {
            subject_alt_names: &["endentity.kubewarden.io"],
            not_before: *TEN_DAYS_AGO,
            not_after: *TEN_DAYS_IN_FUTURE,
        };

        let (end_entity_cert, cert_chain) =
            generate_certificate_chain(root_ca_spec, Some(intermediate_ca_spec), end_entity_spec);
        let req = CertificateVerificationRequest {
            cert: end_entity_cert,
            cert_chain: Some(cert_chain),
            not_after: Some("malformed".to_string()),
        };

        assert_eq!(
            verify_certificate(req).err().unwrap().to_string(),
            "Timestamp not_after is not in RFC3339 format"
        );
    }

    #[rstest]
    #[case::root_ca_expired_intermediate_ca_not(
        CertificateGenerationSpec {
            subject_alt_names: &["root.kubewarden.io"],
            not_before: *ONE_YEAR_AGO,
            not_after: *TEN_DAYS_AGO,
        },
        Some(CertificateGenerationSpec {
            subject_alt_names: &["intermediate.kubewarden.io"],
            not_before: *ONE_YEAR_AGO,
            not_after: *ONE_YEAR_IN_FUTURE,
        }),
        CertificateGenerationSpec {
            subject_alt_names: &["endentity.kubewarden.io"],
            not_before: *ONE_YEAR_AGO,
            not_after: *ONE_YEAR_IN_FUTURE,
        },
        None // webpki does not check the expiration of the root CA
    )]
    #[case::root_ca_expired_no_intermediate_ca(
        CertificateGenerationSpec {
            subject_alt_names: &["root.kubewarden.io"],
            not_before: *ONE_YEAR_AGO,
            not_after: *TEN_DAYS_AGO,
        },
        None,
        CertificateGenerationSpec {
            subject_alt_names: &["endentity.kubewarden.io"],
            not_before: *ONE_YEAR_AGO,
            not_after: *ONE_YEAR_IN_FUTURE,
        },
        None // webpki does not check the expiration of the root CA
    )]
    #[case::intermediate_ca_expired(
        CertificateGenerationSpec {
            subject_alt_names: &["root.kubewarden.io"],
            not_before: *ONE_YEAR_AGO,
            not_after: *TWO_YEARS_IN_FUTURE,
        },
        Some(CertificateGenerationSpec {
            subject_alt_names: &["intermediate.kubewarden.io"],
            not_before: *ONE_YEAR_AGO,
            not_after: *TEN_DAYS_AGO,
        }),
        CertificateGenerationSpec {
            subject_alt_names: &["endentity.kubewarden.io"],
            not_before: *ONE_YEAR_AGO,
            not_after: *ONE_YEAR_IN_FUTURE,
        },
        Some(CERTIFICATE_USED_AFTER_EXPIRATION) // Because the intermediate CA is expired
    )]
    #[case::certificate_expired(
        CertificateGenerationSpec {
            subject_alt_names: &["root.kubewarden.io"],
            not_before: *TWO_YEARS_AGO,
            not_after: *TWO_YEARS_IN_FUTURE,
        },
        Some(CertificateGenerationSpec {
            subject_alt_names: &["intermediate.kubewarden.io"],
            not_before: *ONE_YEAR_AGO,
            not_after: *ONE_YEAR_IN_FUTURE,
        }),
        CertificateGenerationSpec {
            subject_alt_names: &["endentity.kubewarden.io"],
            not_before: *ONE_YEAR_AGO,
            not_after: *TEN_DAYS_AGO,
        },
        Some(CERTIFICATE_USED_AFTER_EXPIRATION)
    )]
    fn certificate_used_after_expiration(
        #[case] root_ca_spec: CertificateGenerationSpec,
        #[case] intermediate_ca_spec: Option<CertificateGenerationSpec>,
        #[case] end_entity_spec: CertificateGenerationSpec,
        #[case] error_msg: Option<&str>,
    ) {
        let (end_entity_cert, cert_chain) =
            generate_certificate_chain(root_ca_spec, intermediate_ca_spec, end_entity_spec);
        let req = CertificateVerificationRequest {
            cert: end_entity_cert,
            cert_chain: Some(cert_chain),
            not_after: Some(Utc::now().to_rfc3339()),
        };

        match error_msg {
            None => {
                assert_eq!(
                    verify_certificate(req).unwrap().value,
                    CertificateVerificationResponse {
                        trusted: true,
                        reason: "".to_string(),
                    }
                )
            }
            Some(msg) => {
                assert_eq!(
                    verify_certificate(req).unwrap().value,
                    CertificateVerificationResponse {
                        trusted: false,
                        reason: msg.to_string(),
                    }
                )
            }
        }
    }
}
