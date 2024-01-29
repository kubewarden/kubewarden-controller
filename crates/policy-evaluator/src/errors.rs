use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum ArtifactHubError {
    #[error("no annotations in policy metadata. policy metadata must specify annotations")]
    NoAnnotations,

    #[error("policy version must be in semver: {0}")]
    NoSemverVersion(String),

    #[error("questions-ui content cannot be empty")]
    EmptyQuestionsUI,

    #[error("policy metadata must specify \"{0}\" in annotations")]
    MissingAnnotation(String),

    #[error("annotation \"{annot:?}\" in policy metadata must be a well formed URL: {error:?}")]
    MalformedURL { annot: String, error: String },

    #[error("annotation \"{0}\" in policy metadata is malformed, must be csv values")]
    MalformedCSV(String),

    #[error("annotation \"{0}\" in policy metadata is malformed, must be csv values of \"name <email>\"")]
    MalformedCSVEmail(String),

    #[error("annotation \"{annot:?}\" in policy metadata must be a well formed email: {error:?}")]
    MalformedEmail { annot: String, error: String },

    #[error("annotation \"{0}\" in policy metadata is malformed, must be a string \"true\" or \"false\"")]
    MalformedBoolString(String),
}

#[derive(Error, Debug)]
pub enum PolicyEvaluatorError {
    #[error("protocol_version is only applicable to a Kubewarden policy")]
    InvalidProtocolVersion(),

    #[error("protocol_version is only applicable to a Kubewarden policy")]
    InvokeWapcProtocolVersion(#[source] crate::runtimes::wapc::errors::WapcRuntimeError),
}
