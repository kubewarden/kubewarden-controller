use anyhow::{anyhow, Result};
use chrono::{DateTime, FixedOffset, Utc};
use kubewarden_policy_sdk::host_capabilities::crypto::{Certificate, CertificateEncoding};
use kubewarden_policy_sdk::host_capabilities::crypto_v1::CertificateVerificationRequest;
use tracing::debug;

/// A collection of trusted root certificates
#[derive(Default, Debug)]
struct CertificatePool {
    trusted_roots: Vec<picky::x509::Cert>,
    intermediates: Vec<picky::x509::Cert>,
}

/// verify_certificate verifies the validity of the certificate, and if it is
/// trusted with the provided certificate chain.
/// If the provided certificate chain is empty, it is treated as trusted.
pub fn verify_certificate(req: CertificateVerificationRequest) -> Result<bool> {
    // verify validity:
    let pc = match req.cert.encoding {
        CertificateEncoding::Pem => {
            let pem_str = String::from_utf8(req.cert.data.clone())
                .map_err(|_| anyhow!("Certificate is not PEM encoded"))?;
            picky::x509::Cert::from_pem_str(&pem_str)
        }
        CertificateEncoding::Der => picky::x509::Cert::from_der(&req.cert.data),
    }?;
    match req.not_after {
        Some(not_after_string) => {
            // picky deals with UTCTime as defined in:
            //   https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5.1

            // Convert RFC 3339 not_after string from the request to chrono's
            // DateTime<Utc>, to ensure Zulu:
            let dt_not_after: DateTime<FixedOffset> =
                DateTime::parse_from_rfc3339(not_after_string.as_str())
                    .map_err(|_| anyhow!("Timestamp not_after is not in RFC3339 format"))?;
            let zulu_not_after: DateTime<Utc> = dt_not_after.with_timezone(&Utc);

            // Convert from chrono's DateTime<Utc> to picky's UtcDate to perform
            // check:
            let p_not_after: picky::x509::date::UtcDate =
                picky::x509::date::UtcDate::from(zulu_not_after);

            if pc.valid_not_after().lt(&p_not_after) {
                return Err(anyhow!(
                    "Certificate is being used after its expiration date"
                ));
            }
        }
        None => debug!(
            "No current time provided to check expiration; certificate is assumed never expired"
        ),
    }

    let now = picky::x509::date::UtcDate::now();
    if pc.valid_not_before().gt(&now) {
        return Err(anyhow!(
            "Certificate is being used before its validity date"
        ));
    }

    // verify trust with cert chain:
    if let Some(mut certch) = req.cert_chain {
        let mut certs = vec![];
        certs.append(&mut certch);
        let cert_pool = CertificatePool::from_certificates(&certs)?;
        match req.cert.encoding {
            CertificateEncoding::Der => cert_pool.verify_der_cert(&req.cert.data)?,
            CertificateEncoding::Pem => cert_pool.verify_pem_cert(&req.cert.data)?,
        }
    }

    Ok(true)
}

impl CertificatePool {
    /// Build a `CertificatePool` instance using the provided list of [`Certificate`]
    fn from_certificates(certs: &[Certificate]) -> Result<Self> {
        let mut trusted_roots = vec![];
        let mut intermediates = vec![];

        for c in certs {
            let pc = match c.encoding {
                CertificateEncoding::Pem => {
                    let pem_str = String::from_utf8(c.data.clone())
                        .map_err(|_| anyhow!("Certificate is not PEM encoded"))?;
                    picky::x509::Cert::from_pem_str(&pem_str)
                }
                CertificateEncoding::Der => picky::x509::Cert::from_der(&c.data),
            }?;

            match pc.ty() {
                picky::x509::certificate::CertType::Root => {
                    trusted_roots.push(pc);
                }
                picky::x509::certificate::CertType::Intermediate => {
                    intermediates.push(pc);
                }
                _ => {
                    return Err(anyhow!(
                        "Cannot add a certificate that is not root nor intermediate"
                    ));
                }
            }
        }

        Ok(CertificatePool {
            trusted_roots,
            intermediates,
        })
    }

    /// Ensures the given certificate has been issued by one of the trusted root certificates
    /// An `Err` is returned when the verification fails.
    fn verify_pem_cert(&self, cert_pem: &[u8]) -> Result<()> {
        let cert_pem_str = std::str::from_utf8(cert_pem)
            .map_err(|_| anyhow!("Cannot convert cert back to string"))?;
        let cert = picky::x509::Cert::from_pem_str(cert_pem_str)?;
        self.verify(&cert)
    }

    /// Ensures the given certificate has been issued by one of the trusted root certificates
    /// An `Err` is returned when the verification fails.
    fn verify_der_cert(&self, bytes: &[u8]) -> Result<()> {
        let cert = picky::x509::Cert::from_der(bytes)?;
        self.verify(&cert)
    }

    fn verify(&self, cert: &picky::x509::Cert) -> Result<()> {
        let verified = self
            .create_chains_for_all_certificates()
            .iter()
            .any(|chain| {
                cert.verifier()
                    .chain(chain.iter().copied())
                    .exact_date(&cert.valid_not_before())
                    .verify()
                    .is_ok()
            });

        if verified {
            Ok(())
        } else {
            Err(anyhow!("Certificate not issued by a trusted root"))
        }
    }

    fn create_chains_for_all_certificates(&self) -> Vec<Vec<&picky::x509::Cert>> {
        let mut chains: Vec<Vec<&picky::x509::Cert>> = vec![];
        self.trusted_roots.iter().for_each(|trusted_root| {
            chains.push([trusted_root].to_vec());
        });
        self.intermediates.iter().for_each(|intermediate| {
            for root in self.trusted_roots.iter() {
                if root.is_parent_of(intermediate).is_ok() {
                    chains.push([intermediate, root].to_vec());
                }
            }
        });

        chains
    }
}
