use anyhow::Result;
use policy_fetcher::sources::Sources;
use policy_fetcher::verify::FulcioAndRekorData;
use tokio::sync::{mpsc, oneshot};

use super::CallbackHandler;
use super::{oci, sigstore_verification};
use crate::callback_requests::CallbackRequest;

const DEFAULT_CHANNEL_BUFF_SIZE: usize = 100;

/// Helper struct that creates CallbackHandler objects
pub struct CallbackHandlerBuilder<'a> {
    oci_sources: Option<Sources>,
    channel_buffer_size: usize,
    shutdown_channel: oneshot::Receiver<()>,
    fulcio_and_rekor_data: Option<&'a FulcioAndRekorData>,
    kube_client: Option<kube::Client>,
}

impl<'a> CallbackHandlerBuilder<'a> {
    pub fn new(shutdown_channel: oneshot::Receiver<()>) -> Self {
        CallbackHandlerBuilder {
            oci_sources: None,
            shutdown_channel,
            channel_buffer_size: DEFAULT_CHANNEL_BUFF_SIZE,
            fulcio_and_rekor_data: None,
            kube_client: None,
        }
    }

    /// Provide all the information needed to access OCI registries. Optional
    pub fn registry_config(mut self, sources: Option<Sources>) -> Self {
        self.oci_sources = sources;
        self
    }

    pub fn fulcio_and_rekor_data(
        mut self,
        fulcio_and_rekor_data: Option<&'a FulcioAndRekorData>,
    ) -> Self {
        self.fulcio_and_rekor_data = fulcio_and_rekor_data;
        self
    }

    /// Set the size of the channel used by the sync world to communicate with
    /// the CallbackHandler. Optional
    pub fn channel_buffer_size(mut self, size: usize) -> Self {
        self.channel_buffer_size = size;
        self
    }

    /// Set the `kube::Client` to be used by context aware policies.
    /// Optional, but strongly recommended to have context aware policies
    /// work as expected
    pub fn kube_client(mut self, client: kube::Client) -> Self {
        self.kube_client = Some(client);
        self
    }

    /// Create a CallbackHandler object
    pub fn build(self) -> Result<CallbackHandler> {
        let (tx, rx) = mpsc::channel::<CallbackRequest>(self.channel_buffer_size);
        let oci_client = oci::Client::new(self.oci_sources.clone());
        let sigstore_client = sigstore_verification::Client::new(
            self.oci_sources.clone(),
            self.fulcio_and_rekor_data,
        )?;

        let kubernetes_client = self.kube_client.map(super::kubernetes::Client::new);

        Ok(CallbackHandler {
            oci_client,
            sigstore_client,
            kubernetes_client,
            tx,
            rx,
            shutdown_channel: self.shutdown_channel,
        })
    }
}
