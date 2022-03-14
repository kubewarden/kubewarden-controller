use anyhow::{anyhow, Result};
use olpc_cjson::CanonicalFormatter;
use policy_fetcher::sources::Sources;
use policy_fetcher::verify::config::{AnyOf, Signature};
use policy_fetcher::verify::Verifier;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tracing::error;

pub(crate) struct Client {
    verifier: Verifier,
}

impl Client {
    pub fn new(
        sources: Option<Sources>,
        fulcio_cert: &[u8],
        rekor_public_key: &str,
    ) -> Result<Self> {
        let verifier = Verifier::new(sources, fulcio_cert, rekor_public_key)?;
        Ok(Client { verifier })
    }

    pub fn is_trusted(&self, settings: &IsTrustedSettings) -> Result<bool> {
        if !settings.has_constraints() {
            return Err(anyhow!("Must provide value for at least all_of or any_of"));
        }
        Err(anyhow::anyhow!("boom"))
    }
}

#[derive(Serialize, Debug)]
pub(crate) struct IsTrustedSettings {
    image: String,
    all_of: Option<Vec<Signature>>,
    any_of: Option<Signature>,
}

impl IsTrustedSettings {
    pub fn has_constraints(&self) -> bool {
        self.all_of.is_some() || self.any_of.is_some()
    }

    // This function returns a hash of the IsTrustedSettings struct.
    // The has is computed by doing a canonical JSON representation of
    // the struct.
    //
    // This method cannot error, because its value is used by the `cached`
    // macro, which doesn't allow error handling.
    // Because of that the method will return the '0' value when something goes
    // wrong during the serialization operation. This is very unlikely to happen
    pub fn hash(&self) -> String {
        let mut buf = Vec::new();
        let mut ser = serde_json::Serializer::with_formatter(&mut buf, CanonicalFormatter::new());
        if let Err(e) = self.serialize(&mut ser) {
            error!(err=?e, settings=?self, "Cannot perform canonical serialization");
            return "0".to_string();
        }

        let mut hasher = Sha256::new();
        hasher.update(&buf);
        let result = hasher.finalize();
        result
            .iter()
            .map(|v| format!("{:x}", v))
            .collect::<Vec<String>>()
            .join("")
    }
}
