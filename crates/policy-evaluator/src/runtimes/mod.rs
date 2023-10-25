pub(crate) mod rego;
pub(crate) mod wapc;
pub(crate) mod wasi_cli;

pub(crate) enum Runtime {
    Wapc(wapc::WapcStack),
    Burrego(rego::BurregoStack),
    Cli(wasi_cli::Stack),
}
