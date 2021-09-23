use crate::communication::{EvalRequest, WorkerPoolBootRequest};
use anyhow::{anyhow, Result};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Barrier,
    },
    thread,
    thread::JoinHandle,
    vec::Vec,
};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info};

use crate::worker::Worker;

pub(crate) struct WorkerPool {
    api_rx: mpsc::Receiver<EvalRequest>,
    bootstrap_rx: oneshot::Receiver<WorkerPoolBootRequest>,
}

impl WorkerPool {
    pub(crate) fn new(
        bootstrap_rx: oneshot::Receiver<WorkerPoolBootRequest>,
        api_rx: mpsc::Receiver<EvalRequest>,
    ) -> WorkerPool {
        WorkerPool {
            api_rx,
            bootstrap_rx,
        }
    }

    pub(crate) fn run(mut self) {
        let mut worker_tx_chans = Vec::<mpsc::Sender<EvalRequest>>::new();
        let mut join_handles = Vec::<JoinHandle<Result<()>>>::new();
        let pool_size: usize;

        // Phase 1: wait for bootstrap data to be received by the main
        // code running in the async block. Once the data is received
        // populate the worker pool
        loop {
            match self.bootstrap_rx.try_recv() {
                Ok(data) => {
                    pool_size = data.pool_size;
                    let barrier = Arc::new(Barrier::new(pool_size + 1));
                    let boot_canary = Arc::new(AtomicBool::new(true));

                    for n in 1..=pool_size {
                        let (tx, rx) = mpsc::channel::<EvalRequest>(32);
                        worker_tx_chans.push(tx);
                        let ps = data.policies.clone();
                        let b = barrier.clone();
                        let canary = boot_canary.clone();

                        let join = thread::spawn(move || -> Result<()> {
                            info!(spawned = n, total = pool_size, "spawning worker");
                            let worker = match Worker::new(rx, ps) {
                                Ok(w) => w,
                                Err(e) => {
                                    error!(error = e.to_string().as_str(), "cannot spawn worker");
                                    canary.store(false, Ordering::SeqCst);
                                    b.wait();
                                    return Err(anyhow!("Worker {} couldn't start: {}", n, e));
                                }
                            };
                            b.wait();

                            debug!(id = n, "worker loop start");
                            worker.run();
                            debug!(id = n, "worker loop exit");

                            Ok(())
                        });
                        join_handles.push(join);
                    }
                    barrier.wait();

                    if !boot_canary.load(Ordering::SeqCst) {
                        match data
                            .resp_chan
                            .send(Err(anyhow!("could not init one of the workers")))
                        {
                            Ok(_) => return,
                            Err(_) => {
                                eprint!(
                                    "worker bootstrap: cannot send back failure through channel"
                                );
                                std::process::exit(1);
                            }
                        };
                    }

                    // bootstrap went smoothly
                    if data.resp_chan.send(Ok(())).is_err() {
                        eprint!(
                            "worker bootstrap: cannot send back success message through channel"
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

        // Phase 2: the worker pool has been successfully bootstraped.
        // We can start waiting for admission review requests to be evaluated
        let mut next_worker_id = 0;

        while let Some(req) = self.api_rx.blocking_recv() {
            let _ = worker_tx_chans[next_worker_id].blocking_send(req);
            next_worker_id += 1;
            if next_worker_id >= pool_size {
                next_worker_id = 0;
            }
        }

        for handle in join_handles {
            handle.join().unwrap().unwrap();
        }
    }
}
