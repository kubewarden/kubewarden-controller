use anyhow::Result;
use kubewarden_policy_sdk::host_capabilities::verification::{KeylessInfo, KeylessPrefixInfo};
use kubewarden_policy_sdk::host_capabilities::{
    SigstoreVerificationInputV1, SigstoreVerificationInputV2,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::oneshot;

/// Holds the response to a waPC evaluation request
#[derive(Debug)]
pub struct CallbackResponse {
    /// The data to be given back to the waPC guest
    pub payload: Vec<u8>,
}

/// A request sent by some synchronous code (usually waPC's host_callback)
/// that can be evaluated only inside of asynchronous code.
#[derive(Debug)]
pub struct CallbackRequest {
    /// The actual request to be evaluated
    pub request: CallbackRequestType,
    /// A tokio oneshot channel over which the evaluation response has to be sent
    pub response_channel: oneshot::Sender<Result<CallbackResponse>>,
}

/// Describes the different kinds of request a waPC guest can make to
/// our host.
#[derive(Serialize, Deserialize, Debug)]
pub enum CallbackRequestType {
    /// Require the computation of the manifest digest of an OCI object (be
    /// it an image or anything else that can be stored into an OCI registry)
    OciManifestDigest {
        /// String pointing to the object (e.g.: `registry.testing.lan/busybox:1.0.0`)
        image: String,
    },

    /// Require the verification of the manifest digest of an OCI object (be
    /// it an image or anything else that can be stored into an OCI registry)
    /// to be signed by Sigstore, using public keys mode
    SigstorePubKeyVerify {
        /// String pointing to the object (e.g.: `registry.testing.lan/busybox:1.0.0`)
        image: String,
        /// List of PEM encoded keys that must have been used to sign the OCI object
        pub_keys: Vec<String>,
        /// Optional - Annotations that must have been provided by all signers when they signed the OCI artifact
        annotations: Option<HashMap<String, String>>,
    },

    /// Require the verification of the manifest digest of an OCI object to be
    /// signed by Sigstore, using keyless mode
    SigstoreKeylessVerify {
        /// String pointing to the object (e.g.: `registry.testing.lan/busybox:1.0.0`)
        image: String,
        /// List of keyless signatures that must be found
        keyless: Vec<KeylessInfo>,
        /// Optional - Annotations that must have been provided by all signers when they signed the OCI artifact
        annotations: Option<HashMap<String, String>>,
    },

    /// Require the verification of the manifest digest of an OCI object to be
    /// signed by Sigstore using keyless mode, where the passed subject is a URL
    /// prefix of the subject to match
    SigstoreKeylessPrefixVerify {
        /// String pointing to the object (e.g.: `registry.testing.lan/busybox:1.0.0`)
        image: String,
        /// List of keyless signatures that must be found
        keyless_prefix: Vec<KeylessPrefixInfo>,
        /// Optional - Annotations that must have been provided by all signers when they signed the OCI artifact
        annotations: Option<HashMap<String, String>>,
    },

    /// Require the verification of the manifest digest of an OCI object to be
    /// signed by Sigstore using keyless mode and performed in GitHub Actions
    SigstoreGithubActionsVerify {
        /// String pointing to the object (e.g.: `registry.testing.lan/busybox:1.0.0`)
        image: String,
        /// owner of the repository. E.g: octocat
        owner: String,
        /// Optional - Repo of the GH Action workflow that signed the artifact. E.g: example-repo
        repo: Option<String>,
        /// Optional - Annotations that must have been provided by all signers when they signed the OCI artifact
        annotations: Option<HashMap<String, String>>,
    },

    /// Require the verification of the manifest digest of an OCI object
    /// using the user provided certificate
    SigstoreCertificateVerify {
        /// String pointing to the object (e.g.: `registry.testing.lan/busybox:1.0.0`)
        image: String,
        /// PEM encoded certificate used to verify the signature
        certificate: Vec<u8>,
        /// Optional - the certificate chain that is used to verify the provided
        /// certificate. When not specified, the certificate is assumed to be trusted
        certificate_chain: Option<Vec<Vec<u8>>>,
        /// Require the  signature layer to have a Rekor bundle.
        /// Having a Rekor bundle allows further checks to be performed,
        /// like ensuring the signature has been produced during the validity
        /// time frame of the certificate.
        ///
        /// It is recommended to set this value to `true` to have a more secure
        /// verification process.
        require_rekor_bundle: bool,
        /// Optional - Annotations that must have been provided by all signers when they signed the OCI artifact
        annotations: Option<HashMap<String, String>>,
    },

    /// Lookup the addresses for a given hostname via DNS
    DNSLookupHost { host: String },
}

impl From<SigstoreVerificationInputV2> for CallbackRequestType {
    fn from(val: SigstoreVerificationInputV2) -> Self {
        match val {
            SigstoreVerificationInputV2::SigstorePubKeyVerify {
                image,
                pub_keys,
                annotations,
            } => CallbackRequestType::SigstorePubKeyVerify {
                image,
                pub_keys,
                annotations,
            },
            SigstoreVerificationInputV2::SigstoreKeylessVerify {
                image,
                keyless,
                annotations,
            } => CallbackRequestType::SigstoreKeylessVerify {
                image,
                keyless,
                annotations,
            },
            SigstoreVerificationInputV2::SigstoreKeylessPrefixVerify {
                image,
                keyless_prefix,
                annotations,
            } => CallbackRequestType::SigstoreKeylessPrefixVerify {
                image,
                keyless_prefix,
                annotations,
            },
            SigstoreVerificationInputV2::SigstoreGithubActionsVerify {
                image,
                owner,
                repo,
                annotations,
            } => CallbackRequestType::SigstoreGithubActionsVerify {
                image,
                owner,
                repo,
                annotations,
            },
            SigstoreVerificationInputV2::SigstoreCertificateVerify {
                image,
                certificate,
                certificate_chain,
                require_rekor_bundle,
                annotations,
            } => CallbackRequestType::SigstoreCertificateVerify {
                image,
                certificate,
                certificate_chain,
                require_rekor_bundle,
                annotations,
            },
        }
    }
}

impl From<SigstoreVerificationInputV1> for CallbackRequestType {
    fn from(val: SigstoreVerificationInputV1) -> Self {
        match val {
            SigstoreVerificationInputV1::SigstorePubKeyVerify {
                image,
                pub_keys,
                annotations,
            } => CallbackRequestType::SigstorePubKeyVerify {
                image,
                pub_keys,
                annotations,
            },
            SigstoreVerificationInputV1::SigstoreKeylessVerify {
                image,
                keyless,
                annotations,
            } => CallbackRequestType::SigstoreKeylessVerify {
                image,
                keyless,
                annotations,
            },
        }
    }
}
