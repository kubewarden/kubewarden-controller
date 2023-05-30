pub mod burrego;
pub(crate) mod wapc;
pub(crate) mod wasi_cli;

pub(crate) enum Runtime {
    Wapc(wapc::WapcStack),
    Burrego(burrego::BurregoStack),
    Cli(wasi_cli::Stack),
}
