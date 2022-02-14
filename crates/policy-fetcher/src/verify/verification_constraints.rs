use sigstore::cosign::verification_constraint::VerificationConstraint;
use sigstore::cosign::verification_constraint::{AnnotationVerifier, PublicKeyVerifier};
use sigstore::cosign::SignatureLayer;
use sigstore::errors::Result;
use std::collections::HashMap;

/// Verification Constraint for public keys and annotations
///
/// This constraint ensures that the SignatureLayer contains both a signature
/// matching the provided Public key, and  all the annotations specified.
#[derive(Debug)]
pub struct PublicKeyAndAnnotationsVerifier {
    pub_key_verifier: PublicKeyVerifier,
    annotation_verifier: AnnotationVerifier,
}

impl PublicKeyAndAnnotationsVerifier {
    pub fn new(key: &str, annotations: Option<HashMap<String, String>>) -> Result<Self> {
        let pub_key_verifier = PublicKeyVerifier::new(key)?;
        let annot: HashMap<String, String> = if let Some(annotations) = annotations {
            annotations
        } else {
            HashMap::default()
        };

        let annotation_verifier = AnnotationVerifier { annotations: annot };
        Ok(Self {
            pub_key_verifier,
            annotation_verifier,
        })
    }
}

impl VerificationConstraint for PublicKeyAndAnnotationsVerifier {
    fn verify(&self, sl: &SignatureLayer) -> Result<bool> {
        let outcome = self.annotation_verifier.verify(sl)? && self.pub_key_verifier.verify(sl)?;
        Ok(outcome)
    }
}
