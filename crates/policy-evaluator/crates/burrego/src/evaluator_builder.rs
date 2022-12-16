use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};
use wasmtime::{Engine, Module};

use crate::{host_callbacks::HostCallbacks, Evaluator};

#[derive(Default)]
pub struct EvaluatorBuilder {
    policy_path: Option<PathBuf>,
    module: Option<Module>,
    engine: Option<Engine>,
    epoch_deadline: Option<u64>,
    host_callbacks: Option<HostCallbacks>,
}

impl EvaluatorBuilder {
    #[must_use]
    pub fn policy_path(mut self, path: &Path) -> Self {
        self.policy_path = Some(path.into());
        self
    }

    #[must_use]
    pub fn module(mut self, module: Module) -> Self {
        self.module = Some(module);
        self
    }

    #[must_use]
    pub fn engine(mut self, engine: &Engine) -> Self {
        self.engine = Some(engine.clone());
        self
    }

    #[must_use]
    pub fn enable_epoch_interruptions(mut self, deadline: u64) -> Self {
        self.epoch_deadline = Some(deadline);
        self
    }

    #[must_use]
    pub fn host_callbacks(mut self, host_callbacks: HostCallbacks) -> Self {
        self.host_callbacks = Some(host_callbacks);
        self
    }

    fn validate(&self) -> Result<()> {
        if self.policy_path.is_some() && self.module.is_some() {
            return Err(anyhow!(
                "policy_path and module cannot be set at the same time"
            ));
        }
        if self.policy_path.is_none() && self.module.is_none() {
            return Err(anyhow!("Either policy_path or module must be set"));
        }

        if self.host_callbacks.is_none() {
            return Err(anyhow!("host_callbacks must be set"));
        }

        Ok(())
    }

    pub fn build(&self) -> Result<Evaluator> {
        self.validate()?;

        let engine = match &self.engine {
            Some(e) => e.clone(),
            None => {
                let mut config = wasmtime::Config::default();
                if self.epoch_deadline.is_some() {
                    config.epoch_interruption(true);
                }
                Engine::new(&config)?
            }
        };

        let module = match &self.module {
            Some(m) => m.clone(),
            None => Module::from_file(
                &engine,
                self.policy_path.clone().expect("policy_path should be set"),
            )?,
        };

        let host_callbacks = self
            .host_callbacks
            .clone()
            .expect("host callbacks should be set");

        Evaluator::from_engine_and_module(engine, module, host_callbacks, self.epoch_deadline)
    }
}
