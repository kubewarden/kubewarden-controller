mod context_aware;
mod gatekeeper_inventory;
mod opa_inventory;
mod runtime;
mod stack;

use burrego::host_callbacks::HostCallbacks;
pub(crate) use runtime::Runtime;
pub(crate) use stack::BurregoStack;

#[tracing::instrument(level = "error")]
fn opa_abort(msg: &str) {}

#[tracing::instrument(level = "info")]
fn opa_println(msg: &str) {}

pub(crate) fn new_host_callbacks() -> HostCallbacks {
    HostCallbacks {
        opa_abort,
        opa_println,
    }
}
