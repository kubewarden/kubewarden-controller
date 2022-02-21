use anyhow::anyhow;
use sigstore::cosign::signature_layers::CertificateSignature;
use sigstore::cosign::verification_constraint::{
    AnnotationVerifier, PublicKeyVerifier, VerificationConstraint,
};
use sigstore::cosign::{signature_layers::CertificateSubject, SignatureLayer};
use sigstore::crypto::SignatureDigestAlgorithm;
use sigstore::errors::{Result, SigstoreError};
use std::collections::HashMap;
use std::convert::TryFrom;

use super::config::Subject;

/// Verification Constraint for public keys and annotations
///
/// This constraint ensures that the SignatureLayer contains both a signature
/// matching the provided Public key, and  all the annotations specified.
#[derive(Debug)]
pub struct PublicKeyAndAnnotationsVerifier {
    pub_key_verifier: PublicKeyVerifier,
    annotation_verifier: Option<AnnotationVerifier>,
}

impl PublicKeyAndAnnotationsVerifier {
    pub fn new(
        key: &str,
        signature_digest_algorithm: SignatureDigestAlgorithm,
        annotations: Option<&HashMap<String, String>>,
    ) -> Result<Self> {
        let pub_key_verifier = PublicKeyVerifier::new(key.as_bytes(), signature_digest_algorithm)?;
        let annotation_verifier = annotations.map(|a| AnnotationVerifier {
            annotations: a.to_owned(),
        });

        Ok(Self {
            pub_key_verifier,
            annotation_verifier,
        })
    }
}

impl VerificationConstraint for PublicKeyAndAnnotationsVerifier {
    fn verify(&self, sl: &SignatureLayer) -> Result<bool> {
        let outcome = if let Some(av) = &self.annotation_verifier {
            self.pub_key_verifier.verify(sl)? && av.verify(sl)?
        } else {
            self.pub_key_verifier.verify(sl)?
        };
        Ok(outcome)
    }
}
