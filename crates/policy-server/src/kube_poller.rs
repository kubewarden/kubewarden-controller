use crate::communication::KubePollerBootRequest;
use anyhow::{anyhow, Result};
use policy_evaluator::cluster_context::ClusterContext;
use policy_evaluator::kube::Client;
use tokio::{
    sync::oneshot,
    time::{sleep, Duration},
};
use tracing::{error, info, warn};

pub(crate) struct Poller {
    bootstrap_rx: oneshot::Receiver<KubePollerBootRequest>,
    runtime: tokio::runtime::Runtime,
}

impl Poller {
    pub(crate) fn new(bootstrap_rx: oneshot::Receiver<KubePollerBootRequest>) -> Result<Poller> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        Ok(Poller {
            bootstrap_rx,
            runtime,
        })
    }

    pub(crate) fn run(mut self) {
        loop {
            match self.bootstrap_rx.try_recv() {
                Ok(data) => {
                    if data.resp_chan.send(Ok(())).is_err() {
                        eprint!(
                            "kubernetes poller bootstrap: cannot send back success message through channel"
                        );
                        std::process::exit(1);
                    }
                    break;
                }
                Err(oneshot::error::TryRecvError::Empty) => {
                    // the channel is empty, keep waiting
                }
                _ => {
                    error!("Cannot receive bootstrap data");
                    return;
                }
            }
        }

        self.runtime.block_on(async {

            info!("spawning cluster context refresh loop");
            loop {
                let kubernetes_client = Client::try_default()
                    .await
                    .map_err(|e| anyhow!("could not initialize a cluster context because a Kubernetes client could not be created: {}", e));

                match kubernetes_client {
                    Ok(kubernetes_client) => loop {
                        let refresh = ClusterContext::get().refresh(&kubernetes_client).await;

                        if let Err(err) = refresh {
                            warn!("error when refreshing the cluster context: {}", err);
                        }
                        sleep(Duration::from_secs(5)).await;
                    },
                    Err(err) => {
                        warn!(
                            "error when initializing the cluster context client: {}",
                            err
                        );
                        sleep(Duration::from_secs(5)).await;
                        continue;
                    }
                }
            }
    });
    }
}
