use anyhow::{anyhow, Result};
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
    shutdown_channel: Option<oneshot::Receiver<()>>,
    fulcio_and_rekor_data: Option<&'a FulcioAndRekorData>,
}

impl<'a> Default for CallbackHandlerBuilder<'a> {
    fn default() -> Self {
        CallbackHandlerBuilder {
            oci_sources: None,
            shutdown_channel: None,
            channel_buffer_size: DEFAULT_CHANNEL_BUFF_SIZE,
            fulcio_and_rekor_data: None,
        }
    }
}

impl<'a> CallbackHandlerBuilder<'a> {
    #![allow(dead_code)]

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

    /// Set the onetime channel used to stop the endless loop of
    /// CallbackHandler. Mandatory
    pub fn shutdown_channel(mut self, shutdown_channel: oneshot::Receiver<()>) -> Self {
        self.shutdown_channel = Some(shutdown_channel);
        self
    }

    /// Create a CallbackHandler object
    pub fn build(self) -> Result<CallbackHandler> {
        let (tx, rx) = mpsc::channel::<CallbackRequest>(self.channel_buffer_size);
        let shutdown_channel = self
            .shutdown_channel
            .ok_or_else(|| anyhow!("shutdown_channel_rx not provided"))?;

        let oci_client = oci::Client::new(self.oci_sources.clone());
        let sigstore_client = sigstore_verification::Client::new(
            self.oci_sources.clone(),
            self.fulcio_and_rekor_data,
        )?;

        Ok(CallbackHandler {
            oci_client,
            sigstore_client,
            tx,
            rx,
            shutdown_channel,
        })
    }
}
