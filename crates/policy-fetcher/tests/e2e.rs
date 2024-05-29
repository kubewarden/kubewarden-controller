// The test is disabled on macOS because the GitHub Actions runner image
// does not have the docker installed to run the test.
// We encapsulate the test inside the e2e module to avoid warnings when building
// the tests on macOS.
#[cfg(not(target_os = "macos"))]
mod e2e {

    use base64::prelude::{Engine as _, BASE64_STANDARD_NO_PAD};
    use oci_distribution::{client::ImageData, manifest, secrets::RegistryAuth, Client, Reference};
    use policy_fetcher::verify::fetch_sigstore_remote_data;
    use sigstore::cosign::{
        constraint::PrivateKeySigner,
        verification_constraint::{PublicKeyVerifier, VerificationConstraint},
        {self, ClientBuilder, Constraint, CosignCapabilities, SignatureLayer},
    };
    use sigstore::crypto::SigningScheme;
    use sigstore::registry::{Auth, ClientConfig, ClientProtocol, OciReference};
    use std::{fs, path, str::FromStr, sync::Arc};
    use tempfile::TempDir;
    use testcontainers::{core::Mount, core::WaitFor, runners::AsyncRunner, GenericImage};
    use tokio::sync::Mutex;

    const REGISTRY_USER: &str = "user";
    const REGISTRY_PASSWORD: &str = "password";
    const REGISTRY_CREDENTIALS_BCRYPT: &str =
        "user:$2y$05$WRQnMYgFDnzA/wViFUOw6uNgJpjaYemWXRD2pQTrBgfU4abxv1KdO";
    const POLICY_IMAGE_TAG: &str = "ghcr.io/kubewarden/tests/pod-privileged:v0.2.5";
    const REGISTRY_PORT: u16 = 5000;

    /// Signs the given image reference and pushes the signature to the registry on the given port
    async fn sign_image<'a>(
        port: u16,
        image_reference: &Reference,
    ) -> Box<dyn VerificationConstraint> {
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

    fn setup_registry_image() -> (GenericImage, TempDir) {
        let auth_dir = TempDir::new().expect("cannot create tmp directory");
        let htpasswd_path = path::Path::join(auth_dir.path(), "htpasswd");
        fs::write(htpasswd_path, REGISTRY_CREDENTIALS_BCRYPT).expect("cannot write htpasswd file");

        let mount = Mount::bind_mount(auth_dir.path().to_string_lossy().to_string(), "/auth");
        (
            GenericImage::new("docker.io/library/registry", "2")
                .with_wait_for(WaitFor::message_on_stderr("listening on "))
                .with_env_var("REGISTRY_AUTH", "htpasswd")
                .with_env_var("REGISTRY_AUTH_HTPASSWD_REALM", "Registry Realm")
                .with_env_var("REGISTRY_AUTH_HTPASSWD_PATH", "/auth/htpasswd")
                .with_mount(mount),
            auth_dir,
        )
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
        let client = Client::new(oci_distribution::client::ClientConfig {
            protocol: oci_distribution::client::ClientProtocol::HttpsExcept(vec![format!(
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

    #[tokio::test]
    async fn test_fetch_sigstore_data_from_registry_with_authentication() {
        let (registry_image, auth_dir) = setup_registry_image();
        let container = registry_image
            .start()
            .await
            .expect("failed to start registry container");

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
}
