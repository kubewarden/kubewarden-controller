use anyhow::{anyhow, Result};
use chrono::{DateTime, FixedOffset, Utc};
use kubewarden_policy_sdk::host_capabilities::crypto::{
    BoolWithReason, Certificate, CertificateEncoding,
};
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
pub fn verify_certificate(req: CertificateVerificationRequest) -> Result<BoolWithReason> {
    // verify validity:
    let pc = match req.cert.encoding {
        CertificateEncoding::Pem => {
            let pem_str = String::from_utf8(req.cert.data)
                .map_err(|_| anyhow!("Certificate PEM data is not UTF8 encoded"))?;
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
                return Ok(BoolWithReason::False(
                    "Certificate is being used after its expiration date".to_string(),
                ));
            }
        }
        None => debug!(
            "No current time provided to check expiration; certificate is assumed never expired"
        ),
    }

    let now = picky::x509::date::UtcDate::now();
    if pc.valid_not_before().gt(&now) {
        return Ok(BoolWithReason::False(
            "Certificate is being used before its validity date".to_string(),
        ));
    }

    // verify trust with cert chain:
    if let Some(mut certch) = req.cert_chain {
        let mut certs = vec![];
        certs.append(&mut certch);
        let cert_pool = CertificatePool::from_certificates(&certs)?;
        if !cert_pool.verify(&pc) {
            return Ok(BoolWithReason::False(
                "Certificate is not trusted by the provided cert chain".to_string(),
            ));
        }
    }

    Ok(BoolWithReason::True)
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
                        .map_err(|_| anyhow!("Certificate PEM data is not UTF8 encoded"))?;
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

    fn verify(&self, cert: &picky::x509::Cert) -> bool {
        self.create_chains_for_all_certificates()
            .iter()
            .any(|chain| {
                cert.verifier()
                    .chain(chain.iter().copied())
                    .exact_date(&cert.valid_not_before())
                    .verify()
                    .is_ok()
            })
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

#[cfg(test)]
mod tests {
    use crate::callback_handler::verify_certificate;
    use chrono::Utc;
    use kubewarden_policy_sdk::host_capabilities::crypto::{
        BoolWithReason, Certificate, CertificateEncoding,
    };
    use kubewarden_policy_sdk::host_capabilities::crypto_v1::CertificateVerificationRequest;

    const ROOT_CA1_PEM: &str = "-----BEGIN CERTIFICATE-----
MIICSTCCAfCgAwIBAgIUQS1sQWI6HCOK5vsO2DDHqWZER7swCgYIKoZIzj0EAwIw
gYIxCzAJBgNVBAYTAkRFMRAwDgYDVQQIEwdCYXZhcmlhMRIwEAYDVQQHEwlOdXJl
bWJlcmcxEzARBgNVBAoTCkt1YmV3YXJkZW4xGzAZBgNVBAsTEkt1YmV3YXJkZW4g
Um9vdCBDQTEbMBkGA1UEAxMSS3ViZXdhcmRlbiBSb290IENBMB4XDTIyMTEyNTE2
MTcwMFoXDTI3MTEyNDE2MTcwMFowgYIxCzAJBgNVBAYTAkRFMRAwDgYDVQQIEwdC
YXZhcmlhMRIwEAYDVQQHEwlOdXJlbWJlcmcxEzARBgNVBAoTCkt1YmV3YXJkZW4x
GzAZBgNVBAsTEkt1YmV3YXJkZW4gUm9vdCBDQTEbMBkGA1UEAxMSS3ViZXdhcmRl
biBSb290IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaCb4QEa4/4rTYBoK
Bqfjiuc7bzGbOPox4WIA9UJaTRbdD9vEaxCKDztvAZfv8txr6rJJE/mkFqkXJZoP
NADD2aNCMEAwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0O
BBYEFPuoSG9XuAy5MN3cpZmptH8pfu0PMAoGCCqGSM49BAMCA0cAMEQCIH6foAtH
M1glopoEWuk7LbCR5Zsg7Yhv+otAWbP8uQunAiB7bXV4HbW9Y5dDVn4uHvJ3j9Jc
6gBcoi4XVyawLUiZkQ==
-----END CERTIFICATE-----";

    // this intermediate certificate was built using ROOT_CA1_PEM
    const INTERMEDIATE_CA1_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIClDCCAjmgAwIBAgIUAzsJl3TEWqsFlWPNbJgt0X5heawwCgYIKoZIzj0EAwIw
gYIxCzAJBgNVBAYTAkRFMRAwDgYDVQQIEwdCYXZhcmlhMRIwEAYDVQQHEwlOdXJl
bWJlcmcxEzARBgNVBAoTCkt1YmV3YXJkZW4xGzAZBgNVBAsTEkt1YmV3YXJkZW4g
Um9vdCBDQTEbMBkGA1UEAxMSS3ViZXdhcmRlbiBSb290IENBMB4XDTIyMTEyNTE2
MTcwMFoXDTMyMTEyMjE2MTcwMFowgZIxCzAJBgNVBAYTAkRFMRAwDgYDVQQIEwdC
YXZhcmlhMRIwEAYDVQQHEwlOdXJlbWJlcmcxEzARBgNVBAoTCkt1YmV3YXJkZW4x
IzAhBgNVBAsTGkt1YmV3YXJkZW4gSW50ZXJtZWRpYXRlIENBMSMwIQYDVQQDExpL
dWJld2FyZGVuIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABO9YOVQTb1GgIgYprNIfqDNwGHfXc0PJ7Nmf/+zypBGOoGeldLA44aVWQyAj
VXbEHR27G4LdtYhwMmLUyk1iqrqjezB5MA4GA1UdDwEB/wQEAwIBBjATBgNVHSUE
DDAKBggrBgEFBQcDAzASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBRxoNzy
5uxNFY0wnkUe73yehMn5kzAfBgNVHSMEGDAWgBT7qEhvV7gMuTDd3KWZqbR/KX7t
DzAKBggqhkjOPQQDAgNJADBGAiEAk2kTo4YrCNuUhCsV/3ziu8PHX+b6Rf8G6Nkz
3jKQjYsCIQDpKd/2J7gKujk2mtWZkNiEvmP1JspVjR+OumHpWBLV+Q==
-----END CERTIFICATE-----";

    const ROOT_CA2_PEM: &str = "-----BEGIN CERTIFICATE-----
MIICSzCCAfCgAwIBAgIUOZnBI4X6K3lySVpSwViYgIQwii0wCgYIKoZIzj0EAwIw
gYIxCzAJBgNVBAYTAkRFMRAwDgYDVQQIEwdCYXZhcmlhMRIwEAYDVQQHEwlOdXJl
bWJlcmcxEzARBgNVBAoTCkt1YmV3YXJkZW4xGzAZBgNVBAsTEkt1YmV3YXJkZW4g
Um9vdCBDQTEbMBkGA1UEAxMSS3ViZXdhcmRlbiBSb290IENBMB4XDTIyMTEyNTE2
MTgwMFoXDTI3MTEyNDE2MTgwMFowgYIxCzAJBgNVBAYTAkRFMRAwDgYDVQQIEwdC
YXZhcmlhMRIwEAYDVQQHEwlOdXJlbWJlcmcxEzARBgNVBAoTCkt1YmV3YXJkZW4x
GzAZBgNVBAsTEkt1YmV3YXJkZW4gUm9vdCBDQTEbMBkGA1UEAxMSS3ViZXdhcmRl
biBSb290IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0+9UZU48ZVwDyJel
ti1DseAdbHngQwcouX9eSb9yDe1JCcDWA3VttgoHA3D85lZ4x6eIgNiiId1x3Qcm
8etlpqNCMEAwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0O
BBYEFGiLnKXIbexCZ6hgSfI78yti0XBeMAoGCCqGSM49BAMCA0kAMEYCIQCUT5FU
Ig4B8SE3NuUhOTpsO6NUJBSuj73tHU7o6BQrIwIhAJzPeTZWJK10gO7aG6jjI4io
rwDBTtan3a2vXpmAbOmg
-----END CERTIFICATE-----";

    // cert with notAfter=Nov 25 16:19:00 2022 GMT
    const INTERMEDIATE_CA2_EXPIRED_PEM: &str = "-----BEGIN CERTIFICATE-----
MIICkzCCAjmgAwIBAgIUNVpbvakL2qlht3uMDUg2iHnV50cwCgYIKoZIzj0EAwIw
gYIxCzAJBgNVBAYTAkRFMRAwDgYDVQQIEwdCYXZhcmlhMRIwEAYDVQQHEwlOdXJl
bWJlcmcxEzARBgNVBAoTCkt1YmV3YXJkZW4xGzAZBgNVBAsTEkt1YmV3YXJkZW4g
Um9vdCBDQTEbMBkGA1UEAxMSS3ViZXdhcmRlbiBSb290IENBMB4XDTIyMTEyNTE3
MDQwMFoXDTIyMTEyNTE3MDUwMFowgZIxCzAJBgNVBAYTAkRFMRAwDgYDVQQIEwdC
YXZhcmlhMRIwEAYDVQQHEwlOdXJlbWJlcmcxEzARBgNVBAoTCkt1YmV3YXJkZW4x
IzAhBgNVBAsTGkt1YmV3YXJkZW4gSW50ZXJtZWRpYXRlIENBMSMwIQYDVQQDExpL
dWJld2FyZGVuIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABMrPXVqh2LOLdE/J2fZIcDWZe6xaLGb61AOykiyN3yd1hwL2PSYL6vFGhrZ4
oMFvodJKdC2tXFjyrRQeI5tJdPujezB5MA4GA1UdDwEB/wQEAwIBBjATBgNVHSUE
DDAKBggrBgEFBQcDAzASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBT0OaT5
auXyLvYjL9T9tJejtfAYMTAfBgNVHSMEGDAWgBRoi5ylyG3sQmeoYEnyO/MrYtFw
XjAKBggqhkjOPQQDAgNIADBFAiEAvs57i6LNa44NntViOfyPIDEPtjzuGR1tWThL
1Hs3KgYCIFDHSvzZkIk1LtW+oHdiWzd7nWrcZcdfsTbMK5NIR2B4
-----END CERTIFICATE-----";

    // cert with not_before=2035-01-05T00:00:00Z
    const INTERMEDIATE_CA_NOT_BEFORE_PEM: &str = "-----BEGIN CERTIFICATE-----
MIICkzCCAjmgAwIBAgIUWzgNojMNxpg7g23KELyQzv4vE1MwCgYIKoZIzj0EAwIw
gYIxCzAJBgNVBAYTAkRFMRAwDgYDVQQIEwdCYXZhcmlhMRIwEAYDVQQHEwlOdXJl
bWJlcmcxEzARBgNVBAoTCkt1YmV3YXJkZW4xGzAZBgNVBAsTEkt1YmV3YXJkZW4g
Um9vdCBDQTEbMBkGA1UEAxMSS3ViZXdhcmRlbiBSb290IENBMB4XDTM1MDEwNTAw
MDAwMFoXDTM2MDEwNTAwMDAwMFowgZIxCzAJBgNVBAYTAkRFMRAwDgYDVQQIEwdC
YXZhcmlhMRIwEAYDVQQHEwlOdXJlbWJlcmcxEzARBgNVBAoTCkt1YmV3YXJkZW4x
IzAhBgNVBAsTGkt1YmV3YXJkZW4gSW50ZXJtZWRpYXRlIENBMSMwIQYDVQQDExpL
dWJld2FyZGVuIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABOU504/MZROTH4Ybl8pmQV8TYymk/c51bQS9kqyWyeI19s2G12UvXvb0yfjn
gvLZaM/S3k4rv2HA8uBsu7dfvu6jezB5MA4GA1UdDwEB/wQEAwIBBjATBgNVHSUE
DDAKBggrBgEFBQcDAzASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBReXEAv
EHuCFAQE5thiOSoEqilZAzAfBgNVHSMEGDAWgBR1uDPhKH7EjlGO2axbPKlTgy8j
iDAKBggqhkjOPQQDAgNIADBFAiEArSsdE5dDXqAU2vM3ThT8GvTnjkWhER3l9v1j
3ka2eiMCIBIMXVLY+XGEHNdarxDj8XKQurNf6Nngs0nU+5ggyF4F
-----END CERTIFICATE-----";

    #[test]
    fn certificate_is_trusted() {
        // use the correct CA chain
        let ca_cert = Certificate {
            encoding: CertificateEncoding::Pem,
            data: ROOT_CA1_PEM.as_bytes().to_vec(),
        };
        let cert_chain = vec![ca_cert];
        let cert = Certificate {
            encoding: CertificateEncoding::Pem,
            data: INTERMEDIATE_CA1_PEM.as_bytes().to_vec(),
        };
        let req = CertificateVerificationRequest {
            cert,
            cert_chain: Some(cert_chain),
            not_after: None,
        };
        assert!(matches!(verify_certificate(req), Ok(BoolWithReason::True)));
    }

    #[test]
    fn certificate_is_not_trusted() {
        // Use a CA chain unrelated to the cert
        let ca_cert = Certificate {
            encoding: CertificateEncoding::Pem,
            data: ROOT_CA2_PEM.as_bytes().to_vec(),
        };
        let cert_chain = vec![ca_cert];
        let cert = Certificate {
            encoding: CertificateEncoding::Pem,
            data: INTERMEDIATE_CA1_PEM.as_bytes().to_vec(),
        };
        let req = CertificateVerificationRequest {
            cert,
            cert_chain: Some(cert_chain),
            not_after: None,
        };

        // compiler thinks 'reason' is unused, doesn't detect it's used in 'matches!()'
        let _reason = "Certificate is not trusted by the provided cert chain".to_string();
        assert!(matches!(
            verify_certificate(req),
            Ok(BoolWithReason::False(_reason))
        ));
    }

    #[test]
    fn certificate_is_trusted_no_chain() {
        let cert = Certificate {
            encoding: CertificateEncoding::Pem,
            data: INTERMEDIATE_CA1_PEM.as_bytes().to_vec(),
        };
        let req = CertificateVerificationRequest {
            cert,
            cert_chain: None,
            not_after: None,
        };
        assert!(matches!(verify_certificate(req), Ok(BoolWithReason::True)));
    }

    #[test]
    fn certificate_is_expired_but_we_dont_check() {
        let ca_cert = Certificate {
            encoding: CertificateEncoding::Pem,
            data: ROOT_CA2_PEM.as_bytes().to_vec(),
        };
        let cert_chain = vec![ca_cert];
        let cert = Certificate {
            encoding: CertificateEncoding::Pem,
            data: INTERMEDIATE_CA2_EXPIRED_PEM.as_bytes().to_vec(),
        };
        let req = CertificateVerificationRequest {
            cert,
            cert_chain: Some(cert_chain),
            not_after: None, // not checking expiration
        };
        assert!(matches!(verify_certificate(req), Ok(BoolWithReason::True)));
    }

    #[test]
    fn certificate_malformed_not_after() {
        let cert = Certificate {
            encoding: CertificateEncoding::Pem,
            data: INTERMEDIATE_CA2_EXPIRED_PEM.as_bytes().to_vec(),
        };
        let req = CertificateVerificationRequest {
            cert,
            cert_chain: None,
            not_after: Some("malformed".to_string()),
        };
        assert_eq!(
            verify_certificate(req).unwrap_err().to_string(),
            "Timestamp not_after is not in RFC3339 format"
        );
    }

    #[test]
    fn certificate_is_expired() {
        let cert = Certificate {
            encoding: CertificateEncoding::Pem,
            data: INTERMEDIATE_CA2_EXPIRED_PEM.as_bytes().to_vec(),
        };
        let req = CertificateVerificationRequest {
            cert,
            cert_chain: None,
            not_after: Some(Utc::now().to_rfc3339()),
        };

        // compiler thinks 'reason' is unused, doesn't detect it's used in 'matches!()'
        let _reason = "Certificate is being used after its expiration date".to_string();
        assert!(matches!(
            verify_certificate(req),
            Ok(BoolWithReason::False(_reason))
        ));
    }

    #[test]
    fn certificate_is_used_before_notbefore_date() {
        let cert = Certificate {
            encoding: CertificateEncoding::Pem,
            data: INTERMEDIATE_CA_NOT_BEFORE_PEM.as_bytes().to_vec(),
        };
        let req = CertificateVerificationRequest {
            cert,
            cert_chain: None,
            not_after: None,
        };

        // compiler thinks 'reason' is unused, doesn't detect it's used in 'matches!()'
        let _reason = "Certificate is being used before its validity date".to_string();
        assert!(matches!(
            verify_certificate(req),
            Ok(BoolWithReason::False(_reason))
        ));
    }
}
