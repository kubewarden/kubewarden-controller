use anyhow::Result;
use policy_fetcher::verify::config::{AnyOf, Signature};
use tokio::sync::oneshot;

/// Holds the response to a waPC evaluation request
#[derive(Debug)]
pub struct CallbackResponse {
    /// The data to be given back to the waPC guest
    pub payload: Vec<u8>,
}

/// Describes the different kinds of request a waPC guest can make to
/// our host.
#[derive(Debug)]
pub enum CallbackRequestType {
    /// Require the computation of the manifest digest of an OCI object (be
    /// it an image or anything else that can be stored into an OCI registry)
    OciManifestDigest {
        /// String pointing to the object (e.g.: `registry.testing.lan/busybox:1.0.0`)
        image: String,
    },
    /// Require the verification of the manifest digest of an OCI object (be
    /// it an image or anything else that can be stored into an OCI registry)
    /// to be signed by Sigstore
    SigstoreVerify {
        /// String pointing to the object (e.g.: `registry.testing.lan/busybox:1.0.0`)
        image: String,
        /// All these signatures must be present
        all_of: Option<Vec<Signature>>,
        /// A user-defined number of these signatures must be present
        any_of: Option<AnyOf>,
    },
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
