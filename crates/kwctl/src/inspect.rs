use anyhow::{anyhow, Result};
use kubewarden_policy_sdk::metadata::ProtocolVersion;
use mdcat::{ResourceAccess, TerminalCapabilities, TerminalSize};
use policy_evaluator::policy_metadata::Metadata;
use prettytable::{format::FormatBuilder, Table};
use pulldown_cmark::{Options, Parser};
use std::convert::TryFrom;
use syntect::parsing::SyntaxSet;

use crate::constants::*;

pub(crate) fn inspect(uri: &str, output: OutputType) -> Result<()> {
    let uri = crate::utils::map_path_to_uri(uri)?;
    let wasm_path = crate::utils::wasm_path(uri.as_str())?;
    let printer = get_printer(output);

    match Metadata::from_path(&wasm_path)? {
        Some(metadata) => printer.print(&metadata),
        None => Err(anyhow!(
            "No Kubewarden metadata found inside of '{}'.\nPolicies can be annotated with the `kwctl annotate` command.",
            uri
        )),
    }
}

pub(crate) enum OutputType {
    Yaml,
    Pretty,
}

impl TryFrom<Option<&str>> for OutputType {
    type Error = anyhow::Error;

    fn try_from(value: Option<&str>) -> Result<Self, Self::Error> {
        match value {
            Some("yaml") => Ok(Self::Yaml),
            None => Ok(Self::Pretty),
            Some(unknown) => Err(anyhow!("Invalid output format '{}'", unknown)),
        }
    }
}

fn get_printer(output_type: OutputType) -> Box<dyn MetadataPrinter> {
    match output_type {
        OutputType::Yaml => Box::new(MetadataYamlPrinter {}),
        OutputType::Pretty => Box::new(MetadataPrettyPrinter {}),
    }
}

trait MetadataPrinter {
    fn print(&self, metadata: &Metadata) -> Result<()>;
}

struct MetadataYamlPrinter {}

impl MetadataPrinter for MetadataYamlPrinter {
    fn print(&self, metadata: &Metadata) -> Result<()> {
        let metadata_yaml = serde_yaml::to_string(&metadata)?;
        println!("{}", metadata_yaml);
        Ok(())
    }
}

struct MetadataPrettyPrinter {}

impl MetadataPrettyPrinter {
    fn annotation_to_row_key(&self, text: &str) -> String {
        let mut out = String::from(text);
        out.push(':');
        String::from(out.trim_start_matches("io.kubewarden.policy."))
    }

    fn print_metadata_generic_info(&self, metadata: &Metadata) -> Result<()> {
        let protocol_version = metadata
            .protocol_version
            .clone()
            .ok_or_else(|| anyhow!("Invalid policy: protocol_version not defined"))?;
        if protocol_version == ProtocolVersion::Unknown {
            return Err(anyhow!("Invalid policy: protocol_version not defined"));
        }

        let pretty_annotations = vec![
            ANNOTATION_POLICY_TITLE,
            ANNOTATION_POLICY_DESCRIPTION,
            ANNOTATION_POLICY_AUTHOR,
            ANNOTATION_POLICY_URL,
            ANNOTATION_POLICY_SOURCE,
            ANNOTATION_POLICY_LICENSE,
        ];
        let mut annotations = metadata.annotations.clone().unwrap_or_default();

        let mut table = Table::new();
        table.set_format(FormatBuilder::new().padding(0, 1).build());

        table.add_row(row![Fmbl -> "Details"]);
        for annotation in pretty_annotations.iter() {
            if let Some(value) = annotations.get(&String::from(*annotation)) {
                table.add_row(row![Fgbl -> self.annotation_to_row_key(annotation), d -> value]);
                annotations.remove(&String::from(*annotation));
            }
        }
        table.add_row(row![Fgbl -> "mutating:", metadata.mutating]);
        table.add_row(row![Fgbl -> "protocol version:", protocol_version]);

        let _usage = annotations.remove(ANNOTATION_POLICY_USAGE);
        if !annotations.is_empty() {
            table.add_row(row![]);
            table.add_row(row![Fmbl -> "Annotations"]);
            for (annotation, value) in annotations.iter() {
                table.add_row(row![Fgbl -> annotation, d -> value]);
            }
        }
        table.printstd();

        Ok(())
    }

    fn print_metadata_rules(&self, metadata: &Metadata) -> Result<()> {
        let rules_yaml = serde_yaml::to_string(&metadata.rules)?;

        // Quick hack to print a colorized "Rules" section, with the same
        // style as the other sections we print
        let mut table = Table::new();
        table.set_format(FormatBuilder::new().padding(0, 1).build());
        table.add_row(row![Fmbl -> "Rules"]);
        table.printstd();

        let text = format!("```yaml\n{}```", rules_yaml);
        self.render_markdown(&text)
    }

    fn print_metadata_usage(&self, metadata: &Metadata) -> Result<()> {
        let usage = match metadata.annotations.clone() {
            None => None,
            Some(annotations) => annotations.get(ANNOTATION_POLICY_USAGE).map(String::from),
        };

        if usage.is_none() {
            return Ok(());
        }

        // Quick hack to print a colorized "Rules" section, with the same
        // style as the other sections we print
        let mut table = Table::new();
        table.set_format(FormatBuilder::new().padding(0, 1).build());
        table.add_row(row![Fmbl -> "Usage"]);
        table.printstd();

        self.render_markdown(&usage.unwrap())
    }

    fn render_markdown(&self, text: &str) -> Result<()> {
        let size = TerminalSize::detect().unwrap_or_default();
        let columns = size.columns;
        let settings = mdcat::Settings {
            terminal_capabilities: TerminalCapabilities::detect(),
            terminal_size: TerminalSize { columns, ..size },
            resource_access: ResourceAccess::LocalOnly,
            syntax_set: SyntaxSet::load_defaults_newlines(),
        };
        let parser = Parser::new_ext(
            text,
            Options::ENABLE_TASKLISTS | Options::ENABLE_STRIKETHROUGH,
        );
        let env = mdcat::Environment::for_local_directory(&std::env::current_dir()?)?;

        let stdout = std::io::stdout();
        let mut output = stdout.lock();
        mdcat::push_tty(&settings, &env, &mut output, parser).or_else(|error| {
            if error.kind() == std::io::ErrorKind::BrokenPipe {
                Ok(())
            } else {
                Err(anyhow!("Cannot render markdown to stdout: {:?}", error))
            }
        })
    }
}

impl MetadataPrinter for MetadataPrettyPrinter {
    fn print(&self, metadata: &Metadata) -> Result<()> {
        self.print_metadata_generic_info(metadata)?;
        println!();
        self.print_metadata_rules(metadata)?;
        println!();
        self.print_metadata_usage(metadata)
    }
}
