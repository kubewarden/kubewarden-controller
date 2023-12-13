use crate::runtimes::{rego, wapc, wasi_cli};

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
