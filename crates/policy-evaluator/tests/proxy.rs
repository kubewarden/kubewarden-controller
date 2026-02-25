mod common;

// Proxy integration tests are disabled on macOS because the GitHub Actions runner image does not
// have Docker installed.
#[cfg(not(target_os = "macos"))]
mod proxy_tests {
    use crate::common::setup_callback_handler;
    use policy_evaluator::callback_requests::{CallbackRequest, CallbackRequestType};
    use policy_fetcher::{proxy::ProxyConfig, sources::Sources};
    use testcontainers::{
        ContainerAsync, GenericImage,
        core::{IntoContainerPort, WaitFor},
        runners::AsyncRunner,
    };
    use tokio::sync::oneshot;

    async fn start_proxy() -> (ContainerAsync<GenericImage>, u16) {
        let container = GenericImage::new("kalaksi/tinyproxy", "1.7")
            .with_wait_for(WaitFor::message_on_stdout("Starting main loop"))
            .with_exposed_port(8888.tcp())
            .start()
            .await
            .expect("Failed to start proxy container");
        let port = container
            .get_host_port_ipv4(8888)
            .await
            .expect("Failed to get proxy port");
        (container, port)
    }

    async fn proxy_log_contains(container: &ContainerAsync<GenericImage>, needle: &str) -> bool {
        let stdout = String::from_utf8(container.stdout_to_vec().await.unwrap_or_default())
            .unwrap_or_default();
        let stderr = String::from_utf8(container.stderr_to_vec().await.unwrap_or_default())
            .unwrap_or_default();
        stdout.contains(needle) || stderr.contains(needle)
    }

    /// Tests that OCI manifest context-aware calls are routed through the proxy when
    /// `Sources.proxies` carries an `https_proxy` URL. Verifies by inspecting proxy logs.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_oci_manifest_callback_with_https_proxy() {
        let (proxy_container, proxy_port) = start_proxy().await;
        let proxy_url = format!("http://127.0.0.1:{proxy_port}");

        let sources = Sources {
            proxies: Some(ProxyConfig {
                https_proxy: Some(proxy_url),
                ..Default::default()
            }),
            ..Default::default()
        };

        let (shutdown_tx, cb_channel) = setup_callback_handler(None, Some(sources)).await;

        let (resp_tx, resp_rx) = oneshot::channel();
        cb_channel
            .try_send(CallbackRequest {
                request: CallbackRequestType::OciManifest {
                    image: "ghcr.io/kubewarden/tests/pod-privileged:v0.2.5".to_owned(),
                },
                response_channel: resp_tx,
            })
            .expect("cannot send callback request");

        resp_rx
            .await
            .expect("cannot receive response")
            .expect("OCI manifest callback should succeed via HTTPS proxy");

        shutdown_tx.send(()).expect("cannot send shutdown signal");

        assert!(
            proxy_log_contains(&proxy_container, "ghcr.io").await,
            "Expected 'ghcr.io' in proxy logs, indicating the OCI manifest call was routed through the proxy"
        );
    }

    /// Tests that `NO_PROXY` in `Sources.proxies` bypasses the proxy for matching hosts.
    /// The OCI manifest call for ghcr.io must succeed and the proxy logs must not mention ghcr.io.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_oci_manifest_callback_with_no_proxy() {
        let (proxy_container, proxy_port) = start_proxy().await;
        let proxy_url = format!("http://127.0.0.1:{proxy_port}");

        let sources = Sources {
            proxies: Some(ProxyConfig {
                https_proxy: Some(proxy_url),
                no_proxy: Some("ghcr.io".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let (shutdown_tx, cb_channel) = setup_callback_handler(None, Some(sources)).await;

        let (resp_tx, resp_rx) = oneshot::channel();
        cb_channel
            .try_send(CallbackRequest {
                request: CallbackRequestType::OciManifest {
                    image: "ghcr.io/kubewarden/tests/pod-privileged:v0.2.5".to_owned(),
                },
                response_channel: resp_tx,
            })
            .expect("cannot send callback request");

        resp_rx
            .await
            .expect("cannot receive response")
            .expect("OCI manifest callback should succeed when ghcr.io bypasses the proxy");

        shutdown_tx.send(()).expect("cannot send shutdown signal");

        assert!(
            !proxy_log_contains(&proxy_container, "ghcr.io").await,
            "Expected 'ghcr.io' to be absent from proxy logs, \
             indicating the OCI manifest call bypassed the proxy via NO_PROXY"
        );
    }
}
