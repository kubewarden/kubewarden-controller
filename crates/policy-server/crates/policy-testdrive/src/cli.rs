use clap::{App, Arg};

pub(crate) fn app() -> App<'static, 'static> {
    App::new("chimera-policy-testdrive")
        .version("0.0.1")
        .about("Quickly test chimera policies")
        .arg(
            Arg::with_name("policy")
                .short("p")
                .long("policy")
                .value_name("POLICY.wasm")
                .required(true)
                .help("Chimera WASM policy file"),
        )
        .arg(
            Arg::with_name("request-file")
                .short("r")
                .long("request-file")
                .value_name("REQUEST.json")
                .required(true)
                .help("File containing the Kubernetes Admission Request object (JSON format)"),
        )
        .arg(
            Arg::with_name("settings")
                .short("s")
                .long("settings")
                .value_name("JSON_OBJECT_STRING")
                .default_value("{}")
                .help("Policy settings, written as a JSON dict"),
        )
}
