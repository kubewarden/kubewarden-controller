use anyhow::anyhow;
use kubewarden_policy_sdk::host_capabilities::net::LookupResponse;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, warn};

use crate::callback_requests::{CallbackRequest, CallbackRequestType, CallbackResponse};

mod builder;
mod crypto;
mod kubernetes;
mod oci;
mod sigstore_verification;

pub use builder::CallbackHandlerBuilder;
pub use crypto::verify_certificate;

use sigstore_verification::{
    get_sigstore_certificate_verification_cached, get_sigstore_github_actions_verification_cached,
    get_sigstore_keyless_prefix_verification_cached, get_sigstore_keyless_verification_cached,
    get_sigstore_pub_key_verification_cached,
};

/// Struct that computes request coming from a Wasm guest.
/// This should be used only to handle the requests that need some async
/// code in order to be fulfilled.
pub struct CallbackHandler {
    oci_client: oci::Client,
    sigstore_client: sigstore_verification::Client,
    kubernetes_client: Option<kubernetes::Client>,
    rx: mpsc::Receiver<CallbackRequest>,
    tx: mpsc::Sender<CallbackRequest>,
    shutdown_channel: oneshot::Receiver<()>,
}

macro_rules! handle_callback {
    ($req:expr, $log_value: expr, $log_msg: expr, $code:block) => {{
        let response = { $code }
            .await
            .map(|response| {
                debug!(
                    value = ?$log_value,
                    cached = response.was_cached,
                    $log_msg,
                );
                let payload = serde_json::to_vec(&response.value)
                    .map_err(|e| anyhow!("error serializing payload: {e:?}"))?;
                Ok(CallbackResponse { payload })
            })
            .and_then(|r| r);

        if let Err(e) = $req.response_channel.send(response) {
            warn!("callback handler: cannot send response back: {:?}", e);
        }
    }};
}

impl CallbackHandler {
    /// Returns the sender side of the channel that can be used by the sync code
    /// (like the `host_callback` function of PolicyEvaluator)
    /// to request the computation of async code.
    ///
    /// Can be invoked as many times as wanted.
    pub fn sender_channel(&self) -> mpsc::Sender<CallbackRequest> {
        self.tx.clone()
    }

    /// Enter an endless loop that:
    ///    1. Waits for requests to be evaluated
    ///    2. Evaluate the request
    ///    3. Send back the result of the evaluation
    ///
    /// The loop is interrupted only when a message is sent over the
    /// `shutdown_channel`.
    pub async fn loop_eval(&mut self) {
        loop {
            tokio::select! {
                // place the shutdown check before the message evaluation,
                // as recommended by tokio's documentation about select!
                _ = &mut self.shutdown_channel => {
                    return;
                },
                maybe_req = self.rx.recv() => {
                    if let Some(req) = maybe_req {
                        match req.request {
                            CallbackRequestType::OciManifestDigest {
                                image,
                            } => {
                                handle_callback!(
                                    req,
                                    image,
                                    "Image digest computed",
                                    {
                                        oci::get_oci_digest_cached(
                                            &self.oci_client,
                                            &image,
                                        )
                                    }
                                );
                            },
                            CallbackRequestType::SigstorePubKeyVerify {
                                image,
                                pub_keys,
                                annotations,
                            } => {
                                handle_callback!(
                                    req,
                                    image,
                                    "Sigstore pub key verification done",
                                    {
                                        get_sigstore_pub_key_verification_cached(
                                            &mut self.sigstore_client,
                                            image.clone(),
                                            pub_keys,
                                            annotations,
                                        )
                                    }
                                );
                            },
                            CallbackRequestType::SigstoreKeylessVerify {
                                image,
                                keyless,
                                annotations,
                            } => {
                                handle_callback!(
                                    req,
                                    image,
                                    "Sigstore keyless verification done",
                                    {
                                        get_sigstore_keyless_verification_cached(
                                            &mut self.sigstore_client,
                                            image.clone(),
                                            keyless,
                                            annotations,
                                        )
                                    }
                                );
                            },
                            CallbackRequestType::SigstoreKeylessPrefixVerify {
                                image,
                                keyless_prefix,
                                annotations,
                            } => {
                                handle_callback!(
                                    req,
                                    image,
                                    "Sigstore keyless prefix verification done",
                                    {
                                        get_sigstore_keyless_prefix_verification_cached(
                                            &mut self.sigstore_client,
                                            image.clone(),
                                            keyless_prefix,
                                            annotations,
                                        )
                                    }
                                );
                            },
                            CallbackRequestType::SigstoreGithubActionsVerify {
                                image,
                                owner,
                                repo,
                                annotations,
                            } => {
                                handle_callback!(
                                    req,
                                    image,
                                    "Sigstore GitHub Action verification done",
                                    {
                                        get_sigstore_github_actions_verification_cached(
                                            &mut self.sigstore_client,
                                            image.clone(),
                                            owner,
                                            repo,
                                            annotations,
                                        )
                                    }
                                );
                            },
                            CallbackRequestType::SigstoreCertificateVerify {
                                image,
                                certificate,
                                certificate_chain,
                                require_rekor_bundle,
                                annotations
                            } => {
                                handle_callback!(
                                    req,
                                    image,
                                    "Sigstore GitHub Action verification done",
                                    {
                                        get_sigstore_certificate_verification_cached(
                                            &mut self.sigstore_client,
                                            &image,
                                            &certificate,
                                            certificate_chain.as_deref(),
                                            require_rekor_bundle, annotations
                                        )
                                    }
                                )
                            },
                            CallbackRequestType::DNSLookupHost {
                                host,
                            } => {
                                let response = dns_lookup::lookup_host(&host).map(|ips| {
                                        let res = LookupResponse {
                                            ips: ips
                                                .iter()
                                                .map(|ip| ip.to_string())
                                                .collect(),
                                        };
                                        CallbackResponse {
                                            payload: serde_json::to_vec(&res).unwrap()
                                        }
                                    }
                                ).map_err(anyhow::Error::new);

                                if let Err(e) = req.response_channel.send(response) {
                                    warn!("callback handler: cannot send response back: {:?}", e);
                                }
                            },
                            CallbackRequestType::KubernetesListResourceNamespace{
                                api_version,
                                kind,
                                namespace,
                                label_selector,
                                field_selector,
                            } => {
                                handle_callback!(
                                    req,
                                    format!("[{namespace}] {api_version}/{kind}"),
                                    "List namespaced Kubernetes resource",
                                    {
                                        kubernetes::list_resources_by_namespace(
                                            self.kubernetes_client.as_mut(),
                                            &api_version,
                                            &kind,
                                            &namespace,
                                            label_selector,
                                            field_selector,
                                        )
                                    }
                                )
                            },
                            CallbackRequestType::KubernetesListResourceAll {
                                api_version,
                                kind,
                                label_selector,
                                field_selector,
                            } => {
                                handle_callback!(
                                    req,
                                    format!("{api_version}/{kind}"),
                                    "List Kubernetes resource",
                                    {
                                        kubernetes::list_resources_all(
                                            self.kubernetes_client.as_mut(),
                                            &api_version,
                                            &kind,
                                            label_selector,
                                            field_selector,
                                        )
                                    }
                                )
                            }
                        }
                    }
                },
            }
        }
    }
}
