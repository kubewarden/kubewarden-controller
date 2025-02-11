// The test is disabled on macOS because the GitHub Actions runner image
// does not have the docker installed to run the test.
// We encapsulate the test inside the e2e module to avoid warnings when building
// the tests on macOS.
#[cfg(not(target_os = "macos"))]
mod e2e {
    use std::{
        collections::{HashMap, HashSet},
        fs, path,
        str::FromStr,
        sync::Arc,
    };

    use base64::prelude::{Engine as _, BASE64_STANDARD_NO_PAD};
    use oci_client::{client::ImageData, manifest, secrets::RegistryAuth, Client, Reference};
    use policy_fetcher::{
        registry::Registry,
        sources::{Certificate, SourceAuthorities, Sources},
        verify::fetch_sigstore_remote_data,
    };
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use sigstore::{
        cosign::{
            self,
            constraint::PrivateKeySigner,
            verification_constraint::{PublicKeyVerifier, VerificationConstraint},
            ClientBuilder, Constraint, CosignCapabilities, SignatureLayer,
        },
        crypto::SigningScheme,
        registry::{Auth, ClientConfig, ClientProtocol, OciReference},
    };
    use tempfile::TempDir;
    use testcontainers::{
        core::Mount, core::WaitFor, runners::AsyncRunner, ContainerRequest, GenericImage, ImageExt,
    };
    use tokio::sync::Mutex;

    const REGISTRY_USER: &str = "user";
    const REGISTRY_PASSWORD: &str = "password";
    const REGISTRY_CREDENTIALS_BCRYPT: &str =
        "user:$2y$05$WRQnMYgFDnzA/wViFUOw6uNgJpjaYemWXRD2pQTrBgfU4abxv1KdO";
    const POLICY_IMAGE_TAG: &str = "ghcr.io/kubewarden/tests/pod-privileged:v0.2.5";
    const REGISTRY_PORT: u16 = 5000;

    /// Signs the given image reference and pushes the signature to the registry on the given port
    async fn sign_image(port: u16, image_reference: &Reference) -> Box<dyn VerificationConstraint> {
        let auth = Auth::Basic(REGISTRY_USER.to_string(), REGISTRY_PASSWORD.to_string());
        let mut client = ClientBuilder::default()
            .with_oci_client_config(ClientConfig {
                protocol: ClientProtocol::HttpsExcept(vec![format!("localhost:{}", port)]),
                ..Default::default()
            })
            .build()
            .expect("failed to build cosign client");
        let image = OciReference::from_str(&image_reference.whole())
            .expect("failed to create oci reference");

        let (cosign_signature_image, source_image_digest) = client
            .triangulate(&image, &auth)
            .await
            .expect("failed to triangulate image");
        let mut signature_layer = SignatureLayer::new_unsigned(&image, &source_image_digest)
            .expect("fail to create signature layer");
        let signer = SigningScheme::ECDSA_P256_SHA256_ASN1
            .create_signer()
            .expect("failed to create signer");
        let keys = signer
            .to_sigstore_keypair()
            .expect("failed to create sigstore keypair");
        let public_key = keys.public_key_to_pem().expect("failed to get public key");
        let pk_signer = PrivateKeySigner::new_with_signer(signer);
        pk_signer
            .add_constraint(&mut signature_layer)
            .expect("failed to add constraint");
        client
            .push_signature(
                None,
                &auth,
                &cosign_signature_image,
                vec![signature_layer.clone()],
            )
            .await
            .expect("failed to push signature");
        Box::new(
            PublicKeyVerifier::new(
                public_key.as_bytes(),
                &SigningScheme::ECDSA_P256_SHA256_ASN1,
            )
            .expect("failed to create public key verifier"),
        )
    }

    #[derive(Default)]
    struct RegistryConfiguration {
        enable_auth: bool,
        enable_tls: bool,
    }

    struct RegistryDetails {
        container_request: ContainerRequest<GenericImage>,
        config_dir: Option<TempDir>,
        certificate: Option<Vec<u8>>,
    }

    fn setup_registry_image(config: RegistryConfiguration) -> RegistryDetails {
        let mut env_vars = HashMap::new();

        let config_dir = if config.enable_tls || config.enable_auth {
            Some(TempDir::new().expect("cannot create temp dir"))
        } else {
            None
        };

        // create the directory, regardless of the auth configuration
        if config.enable_auth {
            let auth_dir = config_dir.as_ref().unwrap();
            let htpasswd_path = path::Path::join(auth_dir.path(), "htpasswd");
            fs::write(htpasswd_path, REGISTRY_CREDENTIALS_BCRYPT)
                .expect("cannot write htpasswd file");

            env_vars.insert("REGISTRY_AUTH", "htpasswd");
            env_vars.insert("REGISTRY_AUTH_HTPASSWD_REALM", "Registry Realm");
            env_vars.insert("REGISTRY_AUTH_HTPASSWD_PATH", "/config/htpasswd");
        };

        let certificate = if config.enable_tls {
            let config_dir = config_dir.as_ref().unwrap();
            let subject_alt_names = vec!["localhost".to_string()];

            let CertifiedKey { cert, key_pair } =
                generate_simple_self_signed(subject_alt_names).unwrap();

            fs::write(config_dir.path().join("key.pem"), key_pair.serialize_pem())
                .expect("cannot write key.pem");
            fs::write(config_dir.path().join("cert.pem"), cert.pem())
                .expect("cannot write cert.pem");

            env_vars.insert("REGISTRY_HTTP_TLS_CERTIFICATE", "/config/cert.pem");
            env_vars.insert("REGISTRY_HTTP_TLS_KEY", "/config/key.pem");

            Some(cert.pem().as_bytes().to_vec())
        } else {
            None
        };

        let mut container_request = GenericImage::new("docker.io/library/registry", "2")
            .with_wait_for(WaitFor::message_on_stderr("listening on "))
            .with_env_var("REGISTRY_LOG_LEVEL", "debug");

        if let Some(config_dir) = &config_dir {
            let mount =
                Mount::bind_mount(config_dir.path().to_string_lossy().to_string(), "/config");
            container_request = container_request.with_mount(mount);
        }

        for (key, value) in env_vars {
            container_request = container_request.with_env_var(key, value);
        }

        RegistryDetails {
            container_request,
            config_dir,
            certificate,
        }
    }

    async fn pull_image_from_internet(client: Client) -> ImageData {
        // pulling policy image.
        let image: Reference = POLICY_IMAGE_TAG.parse().unwrap();
        let anonymous_auth = &RegistryAuth::Anonymous;

        client
            .pull(
                &image,
                anonymous_auth,
                vec![manifest::WASM_LAYER_MEDIA_TYPE],
            )
            .await
            .expect("failed to pull manifest")
    }

    async fn push_image_to_test_registry(client: Client, port: u16, image: ImageData) -> Reference {
        let push_image: Reference = format!("localhost:{}/test-policy:v1", port)
            .parse()
            .unwrap();
        let registry_auth =
            &RegistryAuth::Basic(REGISTRY_USER.to_string(), REGISTRY_PASSWORD.to_string());
        client
            .push(
                &push_image,
                &image.layers,
                image.config.clone(),
                registry_auth,
                image.manifest.clone(),
            )
            .await
            .expect("failed to push image");
        push_image
    }

    /// Loads a policy image into the registry running in the given port and signs it
    async fn push_container_image(port: u16) -> (Reference, Box<dyn VerificationConstraint>) {
        let client = Client::new(oci_client::client::ClientConfig {
            protocol: oci_client::client::ClientProtocol::HttpsExcept(vec![format!(
                "localhost:{}",
                port
            )]),
            ..Default::default()
        });
        let image = pull_image_from_internet(client.clone()).await;
        let push_image = push_image_to_test_registry(client, port, image).await;
        let signature_verifier = sign_image(port, &push_image).await;

        (push_image, signature_verifier)
    }

    /// Creates the docker config.json file with the credentials to be
    /// used to pull the image from the registry
    fn create_docker_config_file(auth_dir: &TempDir, port: u16) {
        let auth_string =
            BASE64_STANDARD_NO_PAD.encode(format!("{}:{}", REGISTRY_USER, REGISTRY_PASSWORD));
        let docker_auth_config = format!(
            r#"
    {{
        "auths": {{
            "localhost:{}": {{
                "auth": "{}"
            }}
        }}
    }}"#,
            port, auth_string,
        )
        .to_owned();
        let docker_config_path = path::Path::join(auth_dir.path(), "config.json");
        fs::write(docker_config_path, docker_auth_config).expect("cannot write docker config file");

        // test should not be run with custom docker config
        // because if this test fails, the docker config will be
        // used by other tests and they will fail too
        if std::env::var("DOCKER_CONFIG").is_ok() {
            panic!("DOCKER_CONFIG is already set");
        }

        // add the DOCKER_CONFIG environment variable to the client
        // so it knows where to find the credentials
        std::env::set_var("DOCKER_CONFIG", auth_dir.path());
    }

    #[cfg(not(target_os = "windows"))]
    #[tokio::test]
    async fn test_fetch_sigstore_data_from_registry_with_authentication() {
        let registry_details = setup_registry_image(RegistryConfiguration {
            enable_auth: true,
            enable_tls: false,
        });
        let container = registry_details
            .container_request
            .start()
            .await
            .expect("failed to start registry container");
        let auth_dir = registry_details.config_dir.expect("auth dir not found");

        let port = container
            .get_host_port_ipv4(REGISTRY_PORT)
            .await
            .expect("failed to get port");
        let (push_image, signature_verifier) = push_container_image(port).await;

        // prepare the cosign client to fetch the signature
        let cosign_client = ClientBuilder::default()
            .with_oci_client_config(ClientConfig {
                protocol: ClientProtocol::HttpsExcept(vec![format!("localhost:{}", port)]),
                ..Default::default()
            })
            .build()
            .expect("failed to build cosign client");

        create_docker_config_file(&auth_dir, port);

        let client_arc = Arc::new(Mutex::new(cosign_client));
        let (_, trusted_layers) =
            fetch_sigstore_remote_data(&client_arc, &format!("registry://{}", push_image.whole()))
                .await
                .expect("failed to fetch sigstore remote data");

        cosign::verify_constraints(&trusted_layers, [signature_verifier].iter())
            .expect("failed to verify constraints");

        std::env::remove_var("DOCKER_CONFIG");
    }

    #[tokio::test]
    async fn test_fetch_image_config() {
        let url = "ghcr.io/kubewarden/tests/policy-server:v1.13.0";
        let expected_config = serde_json::json!({
    "User": "65533:65533",
    "ExposedPorts": {
      "3000/tcp": {}
    },
    "Env": [
      "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    ],
    "Entrypoint": [
      "/policy-server"
    ],
    "WorkingDir": "/"});
        let registry = Registry::new();
        let (manifest, _digest, config) = registry.manifest_and_config(url, None).await.unwrap();
        assert_eq!(config.get("config").unwrap(), &expected_config);
        assert_eq!(
            manifest.media_type.unwrap(),
            "application/vnd.docker.distribution.manifest.v2+json"
        );
        assert_eq!(manifest.schema_version, 2);
        assert_eq!(
            manifest.config.digest,
            "sha256:bc3511804cb29da6333f0187a333eba13a43a3a0a1737e9b50227a5cf057af74"
        );
    }

    #[cfg(not(target_os = "windows"))]
    #[tokio::test]
    async fn test_operations_against_http_registry() {
        use std::collections::HashSet;

        let registry_details = setup_registry_image(RegistryConfiguration {
            enable_auth: false,
            enable_tls: false,
        });
        let container = registry_details
            .container_request
            .start()
            .await
            .expect("failed to start registry container");

        let registry_fqdn = format!(
            "localhost:{}",
            container.get_host_port_ipv4(REGISTRY_PORT).await.unwrap()
        );
        let destination = format!("registry://{}/test-policy:v1", registry_fqdn,);

        let policy = b"\xCA\xFE";
        let registry = Registry::new();

        // By default we enforce https
        let sources = Sources::default();

        let result = registry
            .push(policy, &destination, Some(&sources), None)
            .await;
        assert!(result.is_err());

        // configure the registry to be insecure
        let sources = Sources {
            insecure_sources: HashSet::from([registry_fqdn]),
            ..Default::default()
        };

        push_to_registry_and_perform_common_operations(policy, &registry, &destination, &sources)
            .await;
    }

    #[cfg(not(target_os = "windows"))]
    #[tokio::test]
    async fn test_operations_against_https_registry() {
        let registry_details = setup_registry_image(RegistryConfiguration {
            enable_auth: false,
            enable_tls: true,
        });
        let container = registry_details
            .container_request
            .start()
            .await
            .expect("failed to start registry container");

        let registry_fqdn = format!(
            "localhost:{}",
            container.get_host_port_ipv4(REGISTRY_PORT).await.unwrap()
        );
        let destination = format!("registry://{}/test-policy:v1", registry_fqdn,);

        // registry is using self-signed certificate, pushing without having trusted the CA
        // should fail
        let policy = b"\xCA\xFE";

        let registry = Registry::new();
        let sources = Sources::default();

        let result = registry
            .push(policy, &destination, Some(&sources), None)
            .await;

        assert!(result.is_err());

        // add the self-signed certificate to the trusted certificates
        let source_authorities = SourceAuthorities(
            [(
                registry_fqdn.clone(),
                vec![Certificate::Pem(
                    registry_details.certificate.as_ref().unwrap().clone(),
                )],
            )]
            .iter()
            .cloned()
            .collect(),
        );
        let sources = Sources {
            source_authorities,
            ..Default::default()
        };

        push_to_registry_and_perform_common_operations(policy, &registry, &destination, &sources)
            .await;

        // configure the client to ignore certificate errors for the registry
        let sources = Sources {
            insecure_sources: HashSet::from([registry_fqdn]),
            ..Default::default()
        };

        let result = registry
            .push(policy, &destination, Some(&sources), None)
            .await;
        assert!(result.is_ok(), "did not expect this error: {:?}", result);

        push_to_registry_and_perform_common_operations(policy, &registry, &destination, &sources)
            .await;
    }

    async fn push_to_registry_and_perform_common_operations(
        policy: &[u8],
        registry: &Registry,
        destination: &str,
        sources: &Sources,
    ) {
        let result = registry
            .push(policy, destination, Some(sources), None)
            .await;
        assert!(result.is_ok(), "did not expect this error: {:?}", result);

        let result = registry.manifest(destination, Some(sources)).await;
        assert!(result.is_ok(), "did not expect this error: {:?}", result);

        let result = registry.manifest_digest(destination, Some(sources)).await;
        assert!(result.is_ok(), "did not expect this error: {:?}", result);

        let result = registry
            .manifest_and_config(destination, Some(sources))
            .await;
        assert!(result.is_ok(), "did not expect this error: {:?}", result);
    }
}
