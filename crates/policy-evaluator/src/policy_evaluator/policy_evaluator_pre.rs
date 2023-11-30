use anyhow::Result;

use crate::evaluation_context::EvaluationContext;
use crate::policy_evaluator::PolicyEvaluator;
use crate::runtimes::{rego, wapc, wasi_cli, Runtime};

/// Holds pre-initialized stacks for all the types of policies we run
///
/// Pre-initialized instances are key to reduce the evaluation time when
/// using on-demand PolicyEvaluator instances; where on-demand means that
/// each validation request has a brand new PolicyEvaluator that is discarded
/// once  the evaluation is done.
pub(crate) enum StackPre {
    Wapc(crate::runtimes::wapc::StackPre),
    Wasi(crate::runtimes::wasi_cli::StackPre),
    Rego(crate::runtimes::rego::StackPre),
}

impl From<wapc::StackPre> for StackPre {
    fn from(wapc_stack_pre: wapc::StackPre) -> Self {
        StackPre::Wapc(wapc_stack_pre)
    }
}

impl From<wasi_cli::StackPre> for StackPre {
    fn from(wasi_stack_pre: wasi_cli::StackPre) -> Self {
        StackPre::Wasi(wasi_stack_pre)
    }
}

impl From<rego::StackPre> for StackPre {
    fn from(rego_stack_pre: rego::StackPre) -> Self {
        StackPre::Rego(rego_stack_pre)
    }
}

/// This struct provides a way to quickly allocate a `PolicyEvaluator`
/// object.
///
/// See the [`rehydrate`](PolicyEvaluatorPre::rehydrate) method.
pub struct PolicyEvaluatorPre {
    pub(crate) stack_pre: StackPre,
}

impl PolicyEvaluatorPre {
    /// Create a `PolicyEvaluator` instance. The creation of the instance is achieved by
    /// using wasmtime low level primitives (like `wasmtime::InstancePre`) to make the operation
    /// as fast as possible.
    ///
    /// Warning: the Rego stack cannot make use of these low level primitives, but its
    /// instantiation times are negligible. More details inside of the
    /// documentation of [`rego::StackPre`](crate::rego::stack_pre::StackPre).
    pub fn rehydrate(&self, eval_ctx: &EvaluationContext) -> Result<PolicyEvaluator> {
        let runtime = match &self.stack_pre {
            StackPre::Wapc(stack_pre) => {
                let wapc_stack = wapc::WapcStack::new_from_pre(stack_pre, eval_ctx)?;
                Runtime::Wapc(wapc_stack)
            }
            StackPre::Wasi(stack_pre) => {
                let wasi_stack = wasi_cli::Stack::new_from_pre(stack_pre);
                Runtime::Cli(wasi_stack)
            }
            StackPre::Rego(stack_pre) => {
                let rego_stack = rego::Stack::new_from_pre(stack_pre)?;
                Runtime::Rego(rego_stack)
            }
        };

        Ok(PolicyEvaluator::new(runtime))
    }
}
