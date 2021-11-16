use anyhow::Result;
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
pub enum CallbackRequest {
    /// Require the computation of the manifest digest of an OCI object (be
    /// it an image or anything else that can be stored into an OCI registry)
    OciManifestDigest {
        /// String pointing to the object (e.g.: `resitry.testing.lan/busybox:1.0.0`)
        image: String,
        /// A tokio oneshot channel over which the evaluation response has to be sent
        response_channel: oneshot::Sender<Result<CallbackResponse>>,
    },
}
