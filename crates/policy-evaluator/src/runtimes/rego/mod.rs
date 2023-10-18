mod runtime;

use burrego::host_callbacks::HostCallbacks;
pub(crate) use runtime::BurregoStack;
pub(crate) use runtime::Runtime;

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
