use thiserror::Error;

#[derive(Error, Debug)]
pub enum InvalidUserInputError {
    #[error("cannot specify 'policy_file' and 'policy_contents' at the same time")]
    FileAndContents,

    #[error("cannot specify 'policy_file' and 'policy_module' at the same time")]
    FileAndModule,

    #[error("cannot specify 'policy_contents' and 'policy_module' at the same time")]
    ContentsAndModule,

    #[error("must specify one among: `policy_file`, `policy_contents` and `policy_module`")]
    OneOfFileContentsModule,

    #[error(
        "you must provide the `engine` that was used to instantiate the given `policy_module`"
    )]
    EngineForModule,

    #[error("must specify execution mode")]
    ExecutionMode,
}
