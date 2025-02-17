use ::tracing::{info, warn};
use anyhow::{anyhow, Result};
use rustls::{server::WebPkiClientVerifier, RootCertStore, ServerConfig};
use rustls_pemfile::Item;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::{io::BufReader, path::Path, sync::Arc};

// This is required by certificate hot reload when using inotify, which is available only on linux
#[cfg(target_os = "linux")]
use tokio_stream::StreamExt;

use crate::config::TlsConfig;

/// There's no watching of the certificate files on non-linux platforms
/// since we rely on inotify to watch for changes
#[cfg(not(target_os = "linux"))]
async fn create_tls_config_and_watch_certificate_changes(
    tls_config: TlsConfig,
) -> Result<RustlsConfig> {
    let cfg = RustlsConfig::from_pem_file(tls_config.cert_file, tls_config.key_file).await?;
    Ok(cfg)
}

/// Return the RustlsConfig and watch for changes in the certificate files
/// using inotify.
/// When both the certificate and its key are changed, the RustlsConfig is reloaded,
/// causing the https server to use the new certificate.
///
/// Relying on inotify is only available on linux
#[cfg(target_os = "linux")]
pub(crate) async fn create_tls_config_and_watch_certificate_changes(
    tls_config: TlsConfig,
) -> Result<axum_server::tls_rustls::RustlsConfig> {
    use ::tracing::error;
    use axum_server::tls_rustls::RustlsConfig;
    use inotify::WatchDescriptor;

    // Build initial TLS configuration
    let (mut cert, mut key) =
        load_server_cert_and_key(&tls_config.cert_file, &tls_config.key_file).await?;
    let mut client_verifier = if tls_config.client_ca_file.is_empty() {
        None
    } else {
        Some(load_client_ca_certs(tls_config.client_ca_file.clone()).await?)
    };
    let initial_config =
        build_tls_server_config(cert.clone(), key.clone_key(), client_verifier.clone())?;

    let rust_config = RustlsConfig::from_config(Arc::new(initial_config));
    let reloadable_rust_config = rust_config.clone();

    // Init inotify to watch for changes in the certificate files
    let inotify =
        inotify::Inotify::init().map_err(|e| anyhow!("Cannot initialize inotify: {e}"))?;
    let cert_watch = inotify
        .watches()
        .add(
            tls_config.cert_file.clone(),
            inotify::WatchMask::CLOSE_WRITE,
        )
        .map_err(|e| anyhow!("Cannot watch certificate file: {e}"))?;
    let key_watch = inotify
        .watches()
        .add(tls_config.key_file.clone(), inotify::WatchMask::CLOSE_WRITE)
        .map_err(|e| anyhow!("Cannot watch key file: {e}"))?;

    let client_ca_watches: Result<Vec<WatchDescriptor>, anyhow::Error> = tls_config
        .client_ca_file
        .clone()
        .into_iter()
        .map(|path| {
            inotify
                .watches()
                .add(path, inotify::WatchMask::CLOSE_WRITE)
                .map_err(|e| anyhow!("Cannot watch client CA file: {e}"))
        })
        .collect();

    let client_ca_watches = client_ca_watches?;

    let buffer = [0; 1024];
    let stream = inotify
        .into_event_stream(buffer)
        .map_err(|e| anyhow!("Cannot create inotify event stream: {e}"))?;

    tokio::spawn(async move {
        tokio::pin!(stream);
        let mut cert_changed = false;
        let mut key_changed = false;
        let mut client_ca_changed = false;

        while let Some(event) = stream.next().await {
            let event = match event {
                Ok(event) => event,
                Err(e) => {
                    warn!("Cannot read inotify event: {e}");
                    continue;
                }
            };

            if event.wd == cert_watch {
                info!("TLS certificate file has been modified");
                cert_changed = true;
            }
            if event.wd == key_watch {
                info!("TLS key file has been modified");
                key_changed = true;
            }

            for client_ca_watch in client_ca_watches.iter() {
                if event.wd == *client_ca_watch {
                    info!("TLS client CA file has been modified");
                    client_ca_changed = true;
                }
            }

            // Reload the client CA certificates if they have changed, keeping the current server certificates unchanged
            if client_ca_changed {
                info!("Reloading client CA certificates");

                client_ca_changed = false;

                match load_client_ca_certs(tls_config.client_ca_file.clone()).await {
                    Ok(cv) => {
                        client_verifier = Some(cv);
                    }
                    Err(e) => {
                        error!("Failed to reload TLS certificates: {e}");
                        continue;
                    }
                }
            }

            // Reload the server certificates if they have changed keeping the current client CA certificates unchanged
            if key_changed && cert_changed {
                info!("Reloading Server TLS certificates");

                cert_changed = false;
                key_changed = false;

                match load_server_cert_and_key(&tls_config.cert_file, &tls_config.key_file).await {
                    Ok(ck) => {
                        (cert, key) = ck;
                    }
                    Err(e) => {
                        error!("Failed to reload TLS certificates: {e}");
                        continue;
                    }
                }
            }

            match build_tls_server_config(cert.clone(), key.clone_key(), client_verifier.clone()) {
                Ok(server_config) => {
                    reloadable_rust_config.reload_from_config(Arc::new(server_config));
                }
                Err(e) => {
                    error!("Failed to reload TLS certificate: {e}");
                }
            }
        }
    });

    Ok(rust_config)
}

// Build the TLS server
fn build_tls_server_config(
    cert: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    client_verifier: Option<Arc<dyn rustls::server::danger::ClientCertVerifier>>,
) -> Result<rustls::ServerConfig> {
    if let Some(client_verifier) = client_verifier {
        return Ok(ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(cert, key)?);
    }

    Ok(ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert, key)?)
}

// Load the server certificate and key
async fn load_server_cert_and_key(
    cert_file: &Path,
    key_file: &Path,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert_contents = tokio::fs::read(cert_file).await?;
    let key_contents = tokio::fs::read(key_file).await?;

    let cert_reader = &mut BufReader::new(&cert_contents[..]);
    let key_reader = &mut BufReader::new(&key_contents[..]);

    let cert: Vec<CertificateDer> = rustls_pemfile::certs(cert_reader)
        .filter_map(|it| {
            if let Err(ref e) = it {
                warn!("Cannot parse certificate: {e}");
                return None;
            }
            it.ok()
        })
        .collect();
    if cert.len() > 1 {
        return Err(anyhow!("Multiple certificates provided in cert file"));
    }

    let mut key_vec: Vec<Vec<u8>> = rustls_pemfile::read_all(key_reader)
        .filter_map(|i| match i.ok()? {
            Item::Sec1Key(key) => Some(key.secret_sec1_der().to_vec()),
            Item::Pkcs1Key(key) => Some(key.secret_pkcs1_der().to_vec()),
            Item::Pkcs8Key(key) => Some(key.secret_pkcs8_der().to_vec()),
            _ => {
                info!("Ignoring non-key item in key file");
                None
            }
        })
        .collect();
    if key_vec.is_empty() {
        return Err(anyhow!("No key provided in key file"));
    }
    if key_vec.len() > 1 {
        return Err(anyhow!("Multiple keys provided in key file"));
    }
    let key = PrivateKeyDer::try_from(key_vec.pop().unwrap())
        .map_err(|e| anyhow!("Cannot parse server key: {e}"))?;

    Ok((cert, key))
}

// Load the client CA certificates and build the client verifier
async fn load_client_ca_certs(
    client_cas: Vec<std::path::PathBuf>,
) -> Result<Arc<dyn rustls::server::danger::ClientCertVerifier>> {
    let mut store = RootCertStore::empty();
    for client_ca_file in client_cas {
        let client_ca_contents = tokio::fs::read(&client_ca_file).await?;
        let client_ca_reader = &mut BufReader::new(&client_ca_contents[..]);

        let client_ca_certs: Vec<_> = rustls_pemfile::certs(client_ca_reader)
            .filter_map(|it| {
                if let Err(ref e) = it {
                    warn!("Cannot parse client CA certificate: {e}");
                }
                it.ok()
            })
            .collect();
        let (cert_added, cert_ignored) = store.add_parsable_certificates(client_ca_certs);
        info!(
            client_ca_certs_added = cert_added,
            client_ca_certs_ignored = cert_ignored,
            "Loaded client CA certificates"
        );
    }

    WebPkiClientVerifier::builder(Arc::new(store))
        .build()
        .map_err(|e| anyhow!("Cannot build client verifier: {e}"))
}
