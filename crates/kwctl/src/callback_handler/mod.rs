use crate::run::{HostCapabilitiesMode, PullAndRunSettings};
use anyhow::Result;
use policy_evaluator::{callback_requests::CallbackRequest, kube};
use std::path::PathBuf;
use tokio::sync::{mpsc, oneshot};

use self::proxy::CallbackHandlerProxy;

mod proxy;

#[derive(Clone)]
pub(crate) enum ProxyMode {
    Record { destination: PathBuf },
    Replay { source: PathBuf },
}

/// This is an abstraction over the callback_handler provided by the
/// policy_evaluator crate.
/// The goal is to allow kwctl to have a proxy handler, that can
/// record and reply any kind of policy <-> host capability exchange
pub(crate) enum CallbackHandler {
    Direct(policy_evaluator::callback_handler::CallbackHandler),
    Proxy(proxy::CallbackHandlerProxy),
}

impl CallbackHandler {
    pub async fn new(
        cfg: &PullAndRunSettings,
        kube_client: Option<kube::Client>,
        shutdown_channel: oneshot::Receiver<()>,
    ) -> Result<CallbackHandler> {
        match &cfg.host_capabilities_mode {
            HostCapabilitiesMode::Proxy(proxy_mode) => {
                new_proxy(proxy_mode, cfg, kube_client, shutdown_channel).await
            }
            HostCapabilitiesMode::Direct => {
                new_transparent(cfg, kube_client, shutdown_channel).await
            }
        }
    }

    pub async fn loop_eval(&mut self) {
        match self {
            CallbackHandler::Direct(direct) => direct.loop_eval().await,
            CallbackHandler::Proxy(proxy) => proxy.loop_eval().await,
        }
    }

    pub fn sender_channel(&self) -> mpsc::Sender<CallbackRequest> {
        match self {
            CallbackHandler::Direct(direct) => direct.sender_channel(),
            CallbackHandler::Proxy(proxy) => proxy.sender_channel(),
        }
    }
}

async fn new_proxy(
    mode: &ProxyMode,
    cfg: &PullAndRunSettings,
    kube_client: Option<kube::Client>,
    shutdown_channel: oneshot::Receiver<()>,
) -> Result<CallbackHandler> {
    let proxy = CallbackHandlerProxy::new(
        mode,
        shutdown_channel,
        cfg.sources.clone(),
        cfg.fulcio_and_rekor_data.clone(),
        kube_client,
    )
    .await?;

    Ok(CallbackHandler::Proxy(proxy))
}

async fn new_transparent(
    cfg: &PullAndRunSettings,
    kube_client: Option<kube::Client>,
    shutdown_channel: oneshot::Receiver<()>,
) -> Result<CallbackHandler> {
    let mut callback_handler_builder =
        policy_evaluator::callback_handler::CallbackHandlerBuilder::new(shutdown_channel)
            .registry_config(cfg.sources.clone())
            .fulcio_and_rekor_data(cfg.fulcio_and_rekor_data.as_ref());
    if let Some(kc) = kube_client {
        callback_handler_builder = callback_handler_builder.kube_client(kc);
    }

    let real_callback_handler = callback_handler_builder.build()?;

    Ok(CallbackHandler::Direct(real_callback_handler))
}
