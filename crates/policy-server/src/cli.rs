use clap::{crate_authors, crate_description, crate_name, crate_version, App, Arg};

pub fn build_cli() -> App<'static, 'static> {
    App::new(crate_name!())
        .author(crate_authors!())
        .version(crate_version!())
        .about(crate_description!())
        .arg(
            Arg::with_name("log-level")
                .long("log-level")
                .env("KUBEWARDEN_LOG_LEVEL")
                .default_value("info")
                .possible_values(&["trace", "debug", "info", "warn", "error"])
                .help("Log level"),
        )
        .arg(
            Arg::with_name("log-fmt")
                .long("log-fmt")
                .env("KUBEWARDEN_LOG_FMT")
                .default_value("text")
                .possible_values(&["text", "json", "jaeger", "otlp"])
                .help("Log output format"),
        )
        .arg(
            Arg::with_name("address")
                .long("addr")
                .default_value("0.0.0.0")
                .env("KUBEWARDEN_BIND_ADDRESS")
                .help("Bind against ADDRESS"),
        )
        .arg(
            Arg::with_name("port")
                .long("port")
                .default_value("3000")
                .env("KUBEWARDEN_PORT")
                .help("Listen on PORT"),
        )
        .arg(
            Arg::with_name("workers")
                .long("workers")
                .env("KUBEWARDEN_WORKERS")
                .help("Number of workers thread to create"),
        )
        .arg(
            Arg::with_name("cert-file")
                .long("cert-file")
                .default_value("")
                .env("KUBEWARDEN_CERT_FILE")
                .help("Path to an X.509 certificate file for HTTPS"),
        )
        .arg(
            Arg::with_name("key-file")
                .long("key-file")
                .default_value("")
                .env("KUBEWARDEN_KEY_FILE")
                .help("Path to an X.509 private key file for HTTPS"),
        )
        .arg(
            Arg::with_name("policies")
                .long("policies")
                .env("KUBEWARDEN_POLICIES")
                .default_value("policies.yml")
                .help(
                    "YAML file holding the policies to be loaded and
                    their settings",
                ),
        )
        .arg(
            Arg::with_name("policies-download-dir")
                .long("policies-download-dir")
                .default_value(".")
                .env("KUBEWARDEN_POLICIES_DOWNLOAD_DIR")
                .help("Download path for the policies"),
        )
        .arg(
            Arg::with_name("sources-path")
                .takes_value(true)
                .long("sources-path")
                .env("KUBEWARDEN_SOURCES_PATH")
                .help("YAML file holding source information (https, registry insecure hosts, custom CA's...)"),
        )
        .arg(
            Arg::with_name("docker-config-json-path")
                .env("KUBEWARDEN_DOCKER_CONFIG_JSON_PATH")
                .long("docker-config-json-path")
                .takes_value(true)
                .help("Path to a Docker config.json-like path. Can be used to indicate registry authentication details"),
        )
}
