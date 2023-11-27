use std::fmt::Display;

use crate::policy_evaluator::RegoPolicyExecutionMode;

pub(crate) mod rego;
pub(crate) mod wapc;
pub(crate) mod wasi_cli;

pub(crate) enum Runtime {
    Wapc(wapc::WapcStack),
    Burrego(rego::BurregoStack),
    Cli(wasi_cli::Stack),
}

impl Display for Runtime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Runtime::Cli(_) => write!(f, "wasi"),
            Runtime::Wapc(_) => write!(f, "wapc"),
            Runtime::Burrego(stack) => match stack.policy_execution_mode {
                RegoPolicyExecutionMode::Opa => {
                    write!(f, "OPA")
                }
                RegoPolicyExecutionMode::Gatekeeper => {
                    write!(f, "Gatekeeper")
                }
            },
        }
    }
}
