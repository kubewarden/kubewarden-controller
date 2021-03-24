use crate::wasm::EvalRequest;
use anyhow::{anyhow, Result};
use policy_evaluator::{policy::Policy, policy_evaluator::PolicyEvaluator};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Barrier,
    },
    thread,
    thread::JoinHandle,
    vec::Vec,
};
use tokio::sync::mpsc::{channel, Receiver, Sender};

pub(crate) struct Worker {
    evaluators: HashMap<String, PolicyEvaluator>,
    channel_rx: Receiver<EvalRequest>,
}

impl Worker {
    pub(crate) fn new(
        rx: Receiver<EvalRequest>,
        policies: HashMap<String, Policy>,
    ) -> Result<Worker> {
        let mut evs: HashMap<String, PolicyEvaluator> = HashMap::new();

        for (id, policy) in policies.iter() {
            let settings = policy.settings();

            let policy_evaluator = PolicyEvaluator::new(
                policy.wasm_module_path.clone(),
                settings,
                crate::wasm::host_callback,
            )?;
            evs.insert(id.to_string(), policy_evaluator);
        }

        Ok(Worker {
            evaluators: evs,
            channel_rx: rx,
        })
    }

    pub(crate) fn run(mut self) {
        while let Some(req) = self.channel_rx.blocking_recv() {
            //TODO: handle error
            match self.evaluators.get_mut(&req.policy_id) {
                Some(policy_evaluator) => {
                    let resp = policy_evaluator.validate(req.req);
                    let _ = req.resp_chan.send(Some(resp));
                }
                None => {
                    let _ = req.resp_chan.send(None);
                }
            }
        }
    }
}

pub(crate) struct WorkerPool {
    pool_size: usize,
    worker_tx_chans: Vec<Sender<EvalRequest>>,
    api_rx: Receiver<EvalRequest>,
    join_handles: Vec<JoinHandle<Result<()>>>,
}

impl WorkerPool {
    pub(crate) fn new(
        size: usize,
        policies: HashMap<String, Policy>,
        rx: Receiver<EvalRequest>,
        barrier: Arc<Barrier>,
        boot_canary: Arc<AtomicBool>,
    ) -> WorkerPool {
        let mut tx_chans = Vec::<Sender<EvalRequest>>::new();
        let mut handles = Vec::<JoinHandle<Result<()>>>::new();

        for n in 1..=size {
            let (tx, rx) = channel::<EvalRequest>(32);
            tx_chans.push(tx);
            let ps = policies.clone();
            let b = barrier.clone();
            let canary = boot_canary.clone();

            let join = thread::spawn(move || -> Result<()> {
                println!("spawning worker {}", n);
                let worker = match Worker::new(rx, ps) {
                    Ok(w) => w,
                    Err(e) => {
                        let msg = format!("Worker {} couldn't start: {:?}", n, e);
                        //TODO: better logging
                        println!("{}", msg);
                        canary.store(false, Ordering::SeqCst);
                        b.wait();
                        return Err(anyhow!(msg));
                    }
                };
                b.wait();

                //TODO: better logging
                println!("worker {} loop start", n);
                worker.run();
                println!("worker {} loop exit", n);

                Ok(())
            });
            handles.push(join);
        }

        WorkerPool {
            pool_size: size,
            worker_tx_chans: tx_chans,
            api_rx: rx,
            join_handles: handles,
        }
    }

    pub(crate) fn run(mut self) {
        let mut next_worker_id = 0;

        while let Some(req) = self.api_rx.blocking_recv() {
            let _ = self.worker_tx_chans[next_worker_id].blocking_send(req);
            next_worker_id += 1;
            if next_worker_id >= self.pool_size {
                next_worker_id = 0;
            }
        }

        for handle in self.join_handles {
            handle.join().unwrap().unwrap();
        }
    }
}
