use anyhow::{anyhow, Result};
use chrono::{DateTime, FixedOffset, Utc};
use kubewarden_policy_sdk::host_capabilities::{
    crypto::{Certificate, CertificateEncoding},
    crypto_v1::{CertificateVerificationRequest, CertificateVerificationResponse},
};
use pki_types::{CertificateDer, TrustAnchor, UnixTime};
use sha2::digest::const_oid::db::rfc5280::ID_KP_CODE_SIGNING;
use tracing::debug;
use webpki::{EndEntityCert, Error, KeyUsage};
use x509_cert::der::Decode;

/// A collection of trusted root certificates
#[derive(Default, Debug)]
struct CertificatePool {
    trusted_roots: Vec<TrustAnchor<'static>>,
    intermediates: Vec<CertificateDer<'static>>,
}

fn get_certificate_der<'a>(cert: Certificate) -> Result<CertificateDer<'a>> {
    let der_bytes: Vec<u8> = match cert.encoding {
        CertificateEncoding::Pem => {
            let cert_pem = pem::parse(cert.data)?;
            if cert_pem.tag() != "CERTIFICATE" {
                return Err(anyhow!("Certificate PEM data is not valid"));
            }
            cert_pem.contents().to_owned()
        }
        CertificateEncoding::Der => cert.data,
    };
    Ok(CertificateDer::from(der_bytes.as_slice().to_owned()))
}

/// verify_certificate verifies the validity of the certificate, and if it is
/// trusted with the provided certificate chain.
/// If the provided certificate chain is empty, it is treated as trusted.
pub fn verify_certificate(
    req: CertificateVerificationRequest,
) -> Result<cached::Return<CertificateVerificationResponse>> {
    let der = get_certificate_der(req.cert)
        .map_err(|_| anyhow!("Certificate is not a valid DER or PEM encoded certificate"))?;
    let end_entity_certificate = EndEntityCert::try_from(&der)
        .map_err(|_| anyhow!("Certificate is not a valid end-entity certificate"))?;
    let cert = x509_cert::certificate::Certificate::from_der(der.trim_ascii())?;
    let now = std::time::Duration::from_secs(chrono::Utc::now().timestamp() as u64);

    // verify validity
    let verification_time = match req.not_after {
        Some(ref not_after_string) => {
            // picky deals with UTCTime as defined in:
            //   https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5.1

            // Convert RFC 3339 not_after string from the request to chrono's
            // DateTime<Utc>, to ensure Zulu:
            let dt_not_after: DateTime<FixedOffset> =
                DateTime::parse_from_rfc3339(not_after_string.as_str())
                    .map_err(|_| anyhow!("Timestamp not_after is not in RFC3339 format"))?;
            let zulu_not_after: DateTime<Utc> = dt_not_after.with_timezone(&Utc);

            if cert
                .tbs_certificate
                .validity
                .not_after
                .to_unix_duration()
                .as_secs()
                < zulu_not_after.timestamp() as u64
            {
                return Ok(cached::Return {
                    value: CertificateVerificationResponse {
                        trusted: false,
                        reason: "Certificate is being used after its expiration date".to_string(),
                    },
                    was_cached: false,
                });
            }
            UnixTime::since_unix_epoch(std::time::Duration::from_secs(
                zulu_not_after.timestamp() as u64
            ))
        }
        None => UnixTime::since_unix_epoch(now),
    };

    if cert
        .tbs_certificate
        .validity
        .not_before
        .to_unix_duration()
        .as_secs()
        > now.as_secs()
    {
        return Ok(cached::Return {
            value: CertificateVerificationResponse {
                trusted: false,
                reason: "Certificate is being used before its validity date".to_string(),
            },
            was_cached: false,
        });
    }

    verify_cert_chain(req.cert_chain, end_entity_certificate, verification_time)
}

fn verify_cert_chain(
    cert_chain: Option<Vec<Certificate>>,
    end_entity_certificate: EndEntityCert,
    verification_time: UnixTime,
) -> Result<cached::Return<CertificateVerificationResponse>> {
    match cert_chain {
        None => {
            debug!("No certificate chain provided, treating certificate as trusted");
            Ok(cached::Return {
                value: CertificateVerificationResponse {
                    trusted: true,
                    reason: "".to_string(),
                },
                was_cached: false,
            })
        }
        Some(cert_chain) => {
            let cert_pool = CertificatePool::from_certificates(&cert_chain)?;

            let signing_algs = webpki::ALL_VERIFICATION_ALGS;
            let eku_code_signing = ID_KP_CODE_SIGNING.as_bytes();

            let result = end_entity_certificate
                .verify_for_usage(
                    signing_algs,
                    &cert_pool.trusted_roots,
                    cert_pool.intermediates.as_slice(),
                    verification_time,
                    KeyUsage::required(eku_code_signing),
                    None,
                    None,
                )
                .map_or_else(
                    |e| match e {
                        Error::InvalidSignatureForPublicKey => cached::Return {
                            value: CertificateVerificationResponse {
                                trusted: false,
                                reason: "Certificate is not trusted by the provided cert chain"
                                    .to_string(),
                            },
                            was_cached: false,
                        },
                        _ => cached::Return {
                            value: CertificateVerificationResponse {
                                trusted: false,
                                reason: format!("Certificate not trusted: {}", e),
                            },
                            was_cached: false,
                        },
                    },
                    |_| cached::Return {
                        value: CertificateVerificationResponse {
                            trusted: true,
                            reason: "".to_string(),
                        },
                        was_cached: false,
                    },
                );
            Ok(result)
        }
    }
}

impl CertificatePool {
    /// Build a `CertificatePool` instance using the provided list of [`Certificate`]
    fn from_certificates(certs: &[Certificate]) -> Result<Self> {
        let mut trusted_roots = vec![];
        let mut intermediates = vec![];

        let mut certs_der = certs
            .iter()
            .map(|c| get_certificate_der(c.clone()))
            .collect::<Result<Vec<CertificateDer>>>()?;

        // the api expects the last certificate in the chain to be the root ca
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
}

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::Utc;
    use kubewarden_policy_sdk::host_capabilities::crypto::{Certificate, CertificateEncoding};
    use kubewarden_policy_sdk::host_capabilities::crypto_v1::CertificateVerificationRequest;
    use rcgen::{
        CertificateParams, CertifiedKey, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
        Issuer, KeyPair, KeyUsagePurpose,
    };
    use time::{Duration, OffsetDateTime};

    fn get_cert_params(
        is_ca: rcgen::IsCa,
        not_before: Option<OffsetDateTime>,
        not_after: Option<OffsetDateTime>,
    ) -> CertificateParams {
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CountryName, "DE");
        distinguished_name.push(DnType::StateOrProvinceName, "Bavaria");
        distinguished_name.push(DnType::LocalityName, "Nuremberg");
        distinguished_name.push(DnType::OrganizationalUnitName, "Kubewarden Root CA");
        distinguished_name.push(DnType::CommonName, "Kubewarden Root CA");
        let mut root_ca_cert_param = CertificateParams::default();
        root_ca_cert_param.not_before = not_before
            .or_else(|| OffsetDateTime::now_utc().checked_sub(Duration::days(365)))
            .expect("Failed to set not_before");
        root_ca_cert_param.not_after = not_after
            .or_else(|| OffsetDateTime::now_utc().checked_add(Duration::days(365)))
            .expect("Failed to set not_after");
        root_ca_cert_param.is_ca = is_ca;
        root_ca_cert_param.distinguished_name = distinguished_name;
        root_ca_cert_param.key_usages =
            vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        root_ca_cert_param.use_authority_key_identifier_extension = false;
        root_ca_cert_param.key_identifier_method = rcgen::KeyIdMethod::Sha256;
        root_ca_cert_param.extended_key_usages = [ExtendedKeyUsagePurpose::CodeSigning].to_vec();
        root_ca_cert_param
    }

    fn generate_certificate(
        is_ca: bool,
        ca: Option<CertifiedKey<KeyPair>>,
        not_before: Option<OffsetDateTime>,
        not_after: Option<OffsetDateTime>,
    ) -> Result<CertifiedKey<KeyPair>> {
        let is_ca_param = if is_ca {
            rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained)
        } else {
            rcgen::IsCa::NoCa
        };
        let cert_param = get_cert_params(is_ca_param, not_before, not_after);
        let signing_key = KeyPair::generate().expect("Failed to generate certificate key pair");

        let cert = match (is_ca, ca) {
            // root ca
            (true, None) => cert_param.self_signed(&signing_key),
            // intermediate ca or end entity certificate
            (_, Some(certified_key)) => {
                let issuer =
                    Issuer::from_ca_cert_der(certified_key.cert.der(), certified_key.signing_key)
                        .expect("Failed to generate issuer");
                cert_param.signed_by(&signing_key, &issuer)
            }
            _ => {
                unimplemented!();
            }
        }
        .expect("Failed to create certificate");
        Ok(CertifiedKey { cert, signing_key })
    }

    fn generate_certificate_chain(
        not_before: Option<OffsetDateTime>,
        not_after: Option<OffsetDateTime>,
    ) -> (Certificate, Vec<Certificate>) {
        let root_ca =
            generate_certificate(true, None, None, None).expect("Failed to create root CA");
        let root_ca_cert = Certificate {
            encoding: CertificateEncoding::Pem,
            data: root_ca.cert.pem().as_bytes().to_vec(),
        };

        let intermediate_ca = generate_certificate(true, Some(root_ca), None, None)
            .expect("Failed to create intermediate CA");
        let ca_cert = Certificate {
            encoding: CertificateEncoding::Pem,
            data: intermediate_ca.cert.pem().as_bytes().to_vec(),
        };

        let end_entity_certificate =
            generate_certificate(false, Some(intermediate_ca), not_before, not_after)
                .expect("Failed to create end entity cert");
        let end_entity_cert = Certificate {
            encoding: CertificateEncoding::Pem,
            data: end_entity_certificate.cert.pem().as_bytes().to_vec(),
        };

        // use the correct CA chain
        let cert_chain = vec![ca_cert, root_ca_cert];
        (end_entity_cert, cert_chain)
    }

    #[test]
    fn certificate_is_trusted() {
        let (end_entity_cert, cert_chain) = generate_certificate_chain(None, None);
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

    #[test]
    fn certificate_is_not_trusted() {
        let (end_entity_cert, _) = generate_certificate_chain(None, None);
        let (_, cert_chain2) = generate_certificate_chain(None, None);
        let req = CertificateVerificationRequest {
            cert: end_entity_cert,
            cert_chain: Some(cert_chain2),
            not_after: None,
        };

        // compiler thinks 'reason' is unused, doesn't detect it's used in 'matches!()'
        assert_eq!(
            verify_certificate(req).unwrap().value,
            CertificateVerificationResponse {
                trusted: false,
                reason: "Certificate is not trusted by the provided cert chain".to_string(),
            }
        );
    }

    #[test]
    fn certificate_is_trusted_no_chain() {
        let (end_entity_cert, _) = generate_certificate_chain(None, None);
        let req = CertificateVerificationRequest {
            cert: end_entity_cert,
            cert_chain: None,
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

    #[test]
    fn certificate_is_expired_but_we_dont_check() {
        let (end_entity_cert, _) = generate_certificate_chain(
            OffsetDateTime::now_utc().checked_sub(Duration::days(30)),
            OffsetDateTime::now_utc().checked_sub(Duration::days(2)),
        );
        let req = CertificateVerificationRequest {
            cert: end_entity_cert,
            cert_chain: None,
            not_after: None, // not checking expiration
        };
        assert_eq!(
            verify_certificate(req).unwrap().value,
            CertificateVerificationResponse {
                trusted: true,
                reason: "".to_string(),
            }
        );
    }

    #[test]
    fn certificate_malformed_not_after() {
        let (end_entity_cert, cert_chain) = generate_certificate_chain(None, None);
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

    #[test]
    fn certificate_is_expired() {
        let (end_entity_cert, cert_chain) = generate_certificate_chain(
            OffsetDateTime::now_utc().checked_sub(Duration::days(30)),
            OffsetDateTime::now_utc().checked_sub(Duration::days(1)),
        );
        let req = CertificateVerificationRequest {
            cert: end_entity_cert,
            cert_chain: Some(cert_chain),
            not_after: Some(Utc::now().to_rfc3339()), // not checking expiration
        };

        // compiler thinks 'reason' is unused, doesn't detect it's used in 'matches!()'
        assert_eq!(
            verify_certificate(req).unwrap().value,
            CertificateVerificationResponse {
                trusted: false,
                reason: "Certificate is being used after its expiration date".to_string(),
            }
        );
    }

    #[test]
    fn certificate_is_used_before_notbefore_date() {
        let (end_entity_cert, cert_chain) = generate_certificate_chain(
            OffsetDateTime::now_utc().checked_add(Duration::days(30)),
            OffsetDateTime::now_utc().checked_add(Duration::days(60)),
        );
        let req = CertificateVerificationRequest {
            cert: end_entity_cert,
            cert_chain: Some(cert_chain),
            not_after: None,
        };

        // compiler thinks 'reason' is unused, doesn't detect it's used in 'matches!()'
        assert_eq!(
            verify_certificate(req).unwrap().value,
            CertificateVerificationResponse {
                trusted: false,
                reason: "Certificate is being used before its validity date".to_string()
            }
        );
    }
}
