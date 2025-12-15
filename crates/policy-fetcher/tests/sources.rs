use policy_fetcher::sources::SourceResult;
use policy_fetcher::sources::{read_sources_file, Certificate, Sources};
use std::io::Write;
use std::path::Path;
use tempfile::NamedTempFile;
use textwrap::indent;

// spellchecker:off
const CERT_DATA: &str = r#"-----BEGIN CERTIFICATE-----
MIICUTCCAfugAwIBAgIBADANBgkqhkiG9w0BAQQFADBXMQswCQYDVQQGEwJDTjEL
MAkGA1UECBMCUE4xCzAJBgNVBAcTAkNOMQswCQYDVQQKEwJPTjELMAkGA1UECxMC
VU4xFDASBgNVBAMTC0hlcm9uZyBZYW5nMB4XDTA1MDcxNTIxMTk0N1oXDTA1MDgx
NDIxMTk0N1owVzELMAkGA1UEBhMCQ04xCzAJBgNVBAgTAlBOMQswCQYDVQQHEwJD
TjELMAkGA1UEChMCT04xCzAJBgNVBAsTAlVOMRQwEgYDVQQDEwtIZXJvbmcgWWFu
ZzBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQCp5hnG7ogBhtlynpOS21cBewKE/B7j
V14qeyslnr26xZUsSVko36ZnhiaO/zbMOoRcKK9vEcgMtcLFuQTWDl3RAgMBAAGj
gbEwga4wHQYDVR0OBBYEFFXI70krXeQDxZgbaCQoR4jUDncEMH8GA1UdIwR4MHaA
FFXI70krXeQDxZgbaCQoR4jUDncEoVukWTBXMQswCQYDVQQGEwJDTjELMAkGA1UE
CBMCUE4xCzAJBgNVBAcTAkNOMQswCQYDVQQKEwJPTjELMAkGA1UECxMCVU4xFDAS
BgNVBAMTC0hlcm9uZyBZYW5nggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEE
BQADQQA/ugzBrjjK9jcWnDVfGHlk3icNRq0oV7Ri32z/+HQX67aRfgZu7KWdI+Ju
Wm7DCfrPNGVwFWUQOmsPue9rZBgO
-----END CERTIFICATE-----
"#;
// spellchecker:on

#[test]
fn test_read_sources_file_with_data() {
    let mut sources_file = NamedTempFile::new().unwrap();

    let expected_contents = r#"
insecure_sources:
  - "localhost:5000"
source_authorities:
  "example.com:5000":
    - type: Data
      data: |
"#;
    write!(sources_file, "{}", expected_contents).unwrap();
    write!(sources_file, "{}", indent(CERT_DATA, "            ")).unwrap();

    let expected_cert = Certificate::Pem(CERT_DATA.into());
    let path = sources_file.path();
    let actual: SourceResult<Sources> = read_sources_file(path);

    match actual {
        Ok(_) => {
            assert_eq!(
                actual
                    .as_ref()
                    .unwrap()
                    .source_authority("example.com:5000")
                    .as_ref()
                    .unwrap()[0],
                expected_cert
            );
            assert!(actual.unwrap().is_insecure_source("localhost:5000"));
        }
        unexpected => {
            panic!("Didn't get what I was expecting: {:?}", unexpected);
        }
    }
}

#[test]
fn test_read_sources_file_with_file_path() {
    let mut sources_file = NamedTempFile::new().unwrap();

    let cert_file = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("test_data")
        .join("cert.der");

    #[cfg(not(windows))]
    let path = cert_file.to_str().unwrap();

    #[cfg(windows)]
    let path = cert_file.to_str().unwrap().escape_default();

    let expected_contents = format!(
        r#"
insecure_sources:
  - "localhost:5000"
source_authorities:
  "example.com:5000":
    - type: Path
      path: "{}"
"#,
        path
    );

    write!(sources_file, "{}", expected_contents).unwrap();

    let expected_cert = Certificate::Der(std::fs::read(cert_file).unwrap());

    let path = sources_file.path();
    let actual: SourceResult<Sources> = read_sources_file(path);

    match actual {
        Ok(_) => {
            assert_eq!(
                actual
                    .as_ref()
                    .unwrap()
                    .source_authority("example.com:5000")
                    .as_ref()
                    .unwrap()[0],
                expected_cert
            );
            assert!(actual.unwrap().is_insecure_source("localhost:5000"));
        }
        unexpected => {
            panic!("Didn't get what I was expecting: {:?}", unexpected);
        }
    }
}
