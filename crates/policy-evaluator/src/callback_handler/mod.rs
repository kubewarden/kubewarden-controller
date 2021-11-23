use anyhow::{anyhow, Result};
use policy_fetcher::{registry::config::DockerConfig, sources::Sources};
use tokio::sync::{mpsc, oneshot};
use tracing::warn;

use crate::callback_requests::{CallbackRequest, CallbackRequestType, CallbackResponse};

mod oci;

const DEFAULT_CHANNEL_BUFF_SIZE: usize = 100;

/// Helper struct that creates CallbackHandler objects
pub struct CallbackHandlerBuilder {
    oci_sources: Option<Sources>,
    docker_config: Option<DockerConfig>,
    channel_buffer_size: usize,
    shutdown_channel: Option<oneshot::Receiver<()>>,
}

impl Default for CallbackHandlerBuilder {
    fn default() -> Self {
        CallbackHandlerBuilder {
            oci_sources: None,
            docker_config: None,
            shutdown_channel: None,
            channel_buffer_size: DEFAULT_CHANNEL_BUFF_SIZE,
        }
    }
}

impl CallbackHandlerBuilder {
    #![allow(dead_code)]

    /// Provide all the information needed to access OCI registries. Optional
    pub fn registry_config(
        mut self,
        sources: Option<Sources>,
        docker_config: Option<DockerConfig>,
    ) -> Self {
        self.oci_sources = sources;
        self.docker_config = docker_config;
        self
    }

    /// Set the size of the channel used by the sync world to communicate with
    /// the CallbackHandler. Optional
    pub fn channel_buffer_size(mut self, size: usize) -> Self {
        self.channel_buffer_size = size;
        self
    }

    /// Set the onetime channel used to stop the endless loop of
    /// CallbackHandler. Mandatory
    pub fn shutdown_channel(mut self, shutdown_channel: oneshot::Receiver<()>) -> Self {
        self.shutdown_channel = Some(shutdown_channel);
        self
    }

    /// Create a CallbackHandler object
    pub fn build(self) -> Result<CallbackHandler> {
        let (tx, rx) = mpsc::channel::<CallbackRequest>(self.channel_buffer_size);
        if self.shutdown_channel.is_none() {
            return Err(anyhow!("shutdown_channel_rx not provided"));
        }

        let oci_client = oci::Client::new(self.oci_sources, self.docker_config);
        Ok(CallbackHandler {
            oci_client,
            tx,
            rx,
            shutdown_channel: self.shutdown_channel.unwrap(),
        })
    }
}

/// Struct that computes request coming from a Wasm guest.
/// This should be used only to handle the requests that need some async
/// code in order to be fulfilled.
pub struct CallbackHandler {
    oci_client: oci::Client,
    rx: mpsc::Receiver<CallbackRequest>,
    tx: mpsc::Sender<CallbackRequest>,
    shutdown_channel: oneshot::Receiver<()>,
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
                maybe_req = self.rx.recv() => {
                    if let Some(req) = maybe_req {
                        match req.request {
                            CallbackRequestType::OciManifestDigest {
                                image,
                            } => {
                                let response =
                                    self.oci_client
                                        .digest(&image)
                                        .await
                                        .map(|digest| CallbackResponse {
                                            payload: digest.as_bytes().to_vec(),
                                        });

                                if let Err(e) = req.response_channel.send(response) {
                                    warn!("callback handler: cannot send response back: {:?}", e);
                                }
                            }
                        }
                    }
                },
                _ = &mut self.shutdown_channel => {
                    return;
                }
            }
        }
    }
}
