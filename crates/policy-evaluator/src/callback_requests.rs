use anyhow::Result;
use k8s_openapi::api::authorization::v1::SubjectAccessReview;
use kubewarden_policy_sdk::host_capabilities::{
    kubernetes::SubjectAccessReviewRequest,
    verification::{KeylessInfo, KeylessPrefixInfo},
    SigstoreVerificationInputV1, SigstoreVerificationInputV2,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    hash::{DefaultHasher, Hasher},
};
use std::{fmt::Display, hash::Hash};
use tokio::{sync::oneshot, time::Instant};

/// Holds the response to a waPC evaluation request
#[derive(Debug, Clone)]
pub struct CallbackResponse {
    /// The data to be given back to the waPC guest
    pub payload: Vec<u8>,
}

/// A request sent by some synchronous code (usually waPC's host_callback)
/// that can be evaluated only inside of asynchronous code.
#[derive(Debug)]
pub struct CallbackRequest {
    /// The actual request to be evaluated
    pub request: CallbackRequestType,
    /// A tokio oneshot channel over which the evaluation response has to be sent
    pub response_channel: oneshot::Sender<Result<CallbackResponse>>,
}

/// Describes the different kinds of request a waPC guest can make to
/// our host.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CallbackRequestType {
    /// Require the computation of the manifest digest of an OCI object (be
    /// it an image or anything else that can be stored into an OCI registry)
    OciManifestDigest {
        /// String pointing to the object (e.g.: `registry.testing.lan/busybox:1.0.0`)
        image: String,
    },

    /// Require the OCI object manifest returned by the registry (be it an image or anything else
    /// that can be stored into an OCI registry)
    OciManifest {
        /// String pointing to the object (e.g.: `registry.testing.lan/busybox:1.0.0`)
        image: String,
    },

    /// Require the OCI object manifest and digest returned by the registry (be it an image or anything else
    /// that can be stored into an OCI registry) and the config used to run the container
    OciManifestAndConfig {
        /// String pointing to the object (e.g.: `registry.testing.lan/busybox:1.0.0`)
        image: String,
    },

    /// Require the verification of the manifest digest of an OCI object (be
    /// it an image or anything else that can be stored into an OCI registry)
    /// to be signed by Sigstore, using public keys mode
    SigstorePubKeyVerify {
        /// String pointing to the object (e.g.: `registry.testing.lan/busybox:1.0.0`)
        image: String,
        /// List of PEM encoded keys that must have been used to sign the OCI object
        pub_keys: Vec<String>,
        /// Optional - Annotations that must have been provided by all signers when they signed the OCI artifact
        annotations: Option<BTreeMap<String, String>>,
    },

    /// Require the verification of the manifest digest of an OCI object to be
    /// signed by Sigstore, using keyless mode
    SigstoreKeylessVerify {
        /// String pointing to the object (e.g.: `registry.testing.lan/busybox:1.0.0`)
        image: String,
        /// List of keyless signatures that must be found
        keyless: Vec<KeylessInfo>,
        /// Optional - Annotations that must have been provided by all signers when they signed the OCI artifact
        annotations: Option<BTreeMap<String, String>>,
    },

    /// Require the verification of the manifest digest of an OCI object to be
    /// signed by Sigstore using keyless mode, where the passed subject is a URL
    /// prefix of the subject to match
    SigstoreKeylessPrefixVerify {
        /// String pointing to the object (e.g.: `registry.testing.lan/busybox:1.0.0`)
        image: String,
        /// List of keyless signatures that must be found
        keyless_prefix: Vec<KeylessPrefixInfo>,
        /// Optional - Annotations that must have been provided by all signers when they signed the OCI artifact
        annotations: Option<BTreeMap<String, String>>,
    },

    /// Require the verification of the manifest digest of an OCI object to be
    /// signed by Sigstore using keyless mode and performed in GitHub Actions
    SigstoreGithubActionsVerify {
        /// String pointing to the object (e.g.: `registry.testing.lan/busybox:1.0.0`)
        image: String,
        /// owner of the repository. E.g: octocat
        owner: String,
        /// Optional - Repo of the GH Action workflow that signed the artifact. E.g: example-repo
        repo: Option<String>,
        /// Optional - Annotations that must have been provided by all signers when they signed the OCI artifact
        annotations: Option<BTreeMap<String, String>>,
    },

    /// Require the verification of the manifest digest of an OCI object
    /// using the user provided certificate
    SigstoreCertificateVerify {
        /// String pointing to the object (e.g.: `registry.testing.lan/busybox:1.0.0`)
        image: String,
        /// PEM encoded certificate used to verify the signature
        certificate: Vec<u8>,
        /// Optional - the certificate chain that is used to verify the provided
        /// certificate. When not specified, the certificate is assumed to be trusted
        certificate_chain: Option<Vec<Vec<u8>>>,
        /// Require the  signature layer to have a Rekor bundle.
        /// Having a Rekor bundle allows further checks to be performed,
        /// like ensuring the signature has been produced during the validity
        /// time frame of the certificate.
        ///
        /// It is recommended to set this value to `true` to have a more secure
        /// verification process.
        require_rekor_bundle: bool,
        /// Optional - Annotations that must have been provided by all signers when they signed the OCI artifact
        annotations: Option<BTreeMap<String, String>>,
    },

    /// Lookup the addresses for a given hostname via DNS
    DNSLookupHost { host: String },

    /// Get all the Kubernetes resources defined inside of the given
    /// namespace
    /// Note: cannot be used with cluster-wide resources
    KubernetesListResourceNamespace {
        /// apiVersion of the resource (v1 for core group, groupName/groupVersions for other).
        api_version: String,
        /// Singular PascalCase name of the resource
        kind: String,
        /// Namespace scoping the search
        namespace: String,
        /// A selector to restrict the list of returned objects by their labels.
        /// Defaults to everything if `None`
        label_selector: Option<String>,
        /// A selector to restrict the list of returned objects by their fields.
        /// Defaults to everything if `None`
        field_selector: Option<String>,
    },

    /// Get all the Kubernetes resources defined inside of the given
    /// cluster
    /// Cluster level resources, or resources viewed across all namespaces.
    KubernetesListResourceAll {
        /// apiVersion of the resource (v1 for core group, groupName/groupVersions for other).
        api_version: String,
        /// Singular PascalCase name of the resource
        kind: String,
        /// A selector to restrict the list of returned objects by their labels.
        /// Defaults to everything if `None`
        label_selector: Option<String>,
        /// A selector to restrict the list of returned objects by their fields.
        /// Defaults to everything if `None`
        field_selector: Option<String>,
    },

    /// Get a Kubernetes resource with the specified `name`.
    /// Namespaced resources must provide a `namespace` name to scope the search.
    KubernetesGetResource {
        /// apiVersion of the resource (v1 for core group, groupName/groupVersions for other).
        api_version: String,
        /// Singular PascalCase name of the resource
        kind: String,
        /// The name of the resource
        name: String,
        /// The namespace used to search namespaced resources. Cluster level resources
        /// must set this parameter to `None`
        namespace: Option<String>,

        /// Disable caching of results obtained from Kubernetes API Server
        /// By default query results are cached for 5 seconds, that might cause
        /// stale data to be returned.
        /// However, making too many requests against the Kubernetes API Server
        /// might cause issues to the cluster
        disable_cache: bool,
    },

    /// Get the plural name of a Kubernetes resource. E.g. `v1/Service` -> `services`
    KubernetesGetResourcePluralName {
        /// apiVersion of the resource (v1 for core group, groupName/groupVersions for other).
        api_version: String,
        /// Singular PascalCase name of the resource
        kind: String,
    },

    /// Checks if the data of the reflector tracking this query changed since the given instant
    HasKubernetesListResourceAllResultChangedSinceInstant {
        /// apiVersion of the resource (v1 for core group, groupName/groupVersions for other).
        api_version: String,
        /// Singular PascalCase name of the resource
        kind: String,
        /// A selector to restrict the list of returned objects by their labels.
        /// Defaults to everything if `None`
        label_selector: Option<String>,
        /// A selector to restrict the list of returned objects by their fields.
        /// Defaults to everything if `None`
        field_selector: Option<String>,
        /// The instant in time to compare the last change of the resources
        #[serde(with = "tokio_instant_serializer")]
        since: Instant,
    },

    KubernetesCanI {
        subject_access_review: Box<SubjectAccessReviewWrapper>,
        disable_cache: bool,
    },
}
mod tokio_instant_serializer {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;
    use tokio::time::Instant;

    pub fn serialize<S>(instant: &Instant, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let duration = instant.elapsed();
        duration.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Instant, D::Error>
    where
        D: Deserializer<'de>,
    {
        let duration = Duration::deserialize(deserializer)?;
        let now = Instant::now();
        let instant = now
            .checked_sub(duration)
            .ok_or_else(|| Error::custom("Error checked_sub"))?;
        Ok(instant)
    }
}

impl From<SigstoreVerificationInputV2> for CallbackRequestType {
    fn from(val: SigstoreVerificationInputV2) -> Self {
        match val {
            SigstoreVerificationInputV2::SigstorePubKeyVerify {
                image,
                pub_keys,
                annotations,
            } => CallbackRequestType::SigstorePubKeyVerify {
                image,
                pub_keys,
                annotations,
            },
            SigstoreVerificationInputV2::SigstoreKeylessVerify {
                image,
                keyless,
                annotations,
            } => CallbackRequestType::SigstoreKeylessVerify {
                image,
                keyless,
                annotations,
            },
            SigstoreVerificationInputV2::SigstoreKeylessPrefixVerify {
                image,
                keyless_prefix,
                annotations,
            } => CallbackRequestType::SigstoreKeylessPrefixVerify {
                image,
                keyless_prefix,
                annotations,
            },
            SigstoreVerificationInputV2::SigstoreGithubActionsVerify {
                image,
                owner,
                repo,
                annotations,
            } => CallbackRequestType::SigstoreGithubActionsVerify {
                image,
                owner,
                repo,
                annotations,
            },
            SigstoreVerificationInputV2::SigstoreCertificateVerify {
                image,
                certificate,
                certificate_chain,
                require_rekor_bundle,
                annotations,
            } => CallbackRequestType::SigstoreCertificateVerify {
                image,
                certificate,
                certificate_chain,
                require_rekor_bundle,
                annotations,
            },
        }
    }
}

impl From<SigstoreVerificationInputV1> for CallbackRequestType {
    fn from(val: SigstoreVerificationInputV1) -> Self {
        match val {
            SigstoreVerificationInputV1::SigstorePubKeyVerify {
                image,
                pub_keys,
                annotations,
            } => CallbackRequestType::SigstorePubKeyVerify {
                image,
                pub_keys,
                annotations,
            },
            SigstoreVerificationInputV1::SigstoreKeylessVerify {
                image,
                keyless,
                annotations,
            } => CallbackRequestType::SigstoreKeylessVerify {
                image,
                keyless,
                annotations,
            },
        }
    }
}

impl From<kubewarden_policy_sdk::host_capabilities::kubernetes::ListResourcesByNamespaceRequest>
    for CallbackRequestType
{
    fn from(
        req: kubewarden_policy_sdk::host_capabilities::kubernetes::ListResourcesByNamespaceRequest,
    ) -> Self {
        CallbackRequestType::KubernetesListResourceNamespace {
            api_version: req.api_version,
            kind: req.kind,
            namespace: req.namespace,
            label_selector: req.label_selector,
            field_selector: req.field_selector,
        }
    }
}

impl From<kubewarden_policy_sdk::host_capabilities::kubernetes::ListAllResourcesRequest>
    for CallbackRequestType
{
    fn from(
        req: kubewarden_policy_sdk::host_capabilities::kubernetes::ListAllResourcesRequest,
    ) -> Self {
        CallbackRequestType::KubernetesListResourceAll {
            api_version: req.api_version,
            kind: req.kind,
            label_selector: req.label_selector,
            field_selector: req.field_selector,
        }
    }
}

impl From<kubewarden_policy_sdk::host_capabilities::kubernetes::GetResourceRequest>
    for CallbackRequestType
{
    fn from(req: kubewarden_policy_sdk::host_capabilities::kubernetes::GetResourceRequest) -> Self {
        CallbackRequestType::KubernetesGetResource {
            api_version: req.api_version,
            kind: req.kind,
            name: req.name,
            namespace: req.namespace,
            disable_cache: req.disable_cache,
        }
    }
}

impl From<SubjectAccessReviewRequest> for CallbackRequestType {
    fn from(req: SubjectAccessReviewRequest) -> Self {
        CallbackRequestType::KubernetesCanI {
            subject_access_review: Box::new(SubjectAccessReviewWrapper(req.subject_access_review)),
            disable_cache: req.disable_cache,
        }
    }
}

/// Wrapper type to allow users to pass a `SubjectAccessReview` to the
/// `KubernetesCanI` request. The original types does not implement the Eq trait.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct SubjectAccessReviewWrapper(pub SubjectAccessReview);

impl Eq for SubjectAccessReviewWrapper {}

/// Implementing the AsRef trait for SubjectAccessReviewWrapper to allow
/// easy access to the inner SubjectAccessReview type.
impl AsRef<SubjectAccessReview> for SubjectAccessReviewWrapper {
    fn as_ref(&self) -> &SubjectAccessReview {
        &self.0
    }
}

/// Implementing the Display trait for SubjectAccessReviewWrapper to simplify the
/// cache key generation. This implementation uses a hasher to generate a unique
/// identifier for the SubjectAccessReviewWrapper instance.
impl Display for SubjectAccessReviewWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        write!(f, "SubjectAccessReviewWrapper({})", hasher.finish())
    }
}

/// Implementing the Hash trait for SubjectAccessReviewWrapper to be used in cache key
impl Hash for SubjectAccessReviewWrapper {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.spec.user.hash(state);
        if let Some(ref resource_attributes) = self.0.spec.resource_attributes {
            resource_attributes.namespace.hash(state);
            resource_attributes.verb.hash(state);
            resource_attributes.resource.hash(state);
        }
        if let Some(ref non_resource_attributes) = self.0.spec.non_resource_attributes {
            non_resource_attributes.path.hash(state);
            non_resource_attributes.verb.hash(state);
        }
        self.0.spec.groups.hash(state);
        self.0.spec.extra.hash(state);
        self.0.spec.uid.hash(state);
    }
}
