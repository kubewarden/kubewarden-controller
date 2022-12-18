pub mod burrego;
pub(crate) mod wapc;

pub(crate) enum Runtime {
    Wapc(wapc::WapcStack),
    Burrego(burrego::BurregoStack),
}
