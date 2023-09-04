mod common;

use anyhow::Error;
use policy_fetcher::sources::{read_sources_file, Certificate, Sources};
use std::io::Write;
use tempfile::NamedTempFile;
use textwrap::indent;

#[test]
fn test_read_sources_file() {
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
    write!(
        sources_file,
        "{}",
        indent(common::CERT_DATA, "            ")
    )
    .unwrap();

    let expected_cert = Certificate::Pem(common::CERT_DATA.into());
    let path = sources_file.path();
    let actual: Result<Sources, Error> = read_sources_file(path);

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
