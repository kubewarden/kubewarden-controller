use serde::{Deserialize, Serialize};

/// Proxy configuration for outbound HTTP/HTTPS connections.
///
/// Mirrors the conventional `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY`
/// environment variables. All three fields are optional; an absent value means
/// "no proxy" for that protocol.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct ProxyConfig {
    /// Proxy URL for plain HTTP requests (e.g. `http://proxy.corp:3128`).
    pub http_proxy: Option<String>,
    /// Proxy URL for HTTPS requests.
    pub https_proxy: Option<String>,
    /// Comma-separated list of hosts / IP ranges that must bypass the proxy
    /// (e.g. `localhost,127.0.0.1,.corp`).
    pub no_proxy: Option<String>,
}

impl ProxyConfig {
    /// Populate a `ProxyConfig` from the standard environment variables.
    ///
    /// Both the upper-case (`HTTP_PROXY`) and lower-case (`http_proxy`) forms
    /// are checked; the upper-case variant takes precedence when both are set.
    pub fn from_env() -> Self {
        let (http_proxy, https_proxy, no_proxy) = get_proxy_env_vars();
        ProxyConfig {
            http_proxy,
            https_proxy,
            no_proxy,
        }
    }
}

/// Helper function, reads proxy configuration from environment variables.
/// Checks both uppercase and lowercase variants (HTTP_PROXY/http_proxy, etc.)
///
/// We have elected to implement all proxy features for all clients explicitly.
/// Some clients like reqwest already support proxy env vars via their system-proxy crate
/// feature, while others such as oci-client or sigstore don't.
fn get_proxy_env_vars() -> (Option<String>, Option<String>, Option<String>) {
    let http_proxy = std::env::var("HTTP_PROXY")
        .or_else(|_| std::env::var("http_proxy"))
        .ok();
    let https_proxy = std::env::var("HTTPS_PROXY")
        .or_else(|_| std::env::var("https_proxy"))
        .ok();
    let no_proxy = std::env::var("NO_PROXY")
        .or_else(|_| std::env::var("no_proxy"))
        .ok();

    (http_proxy, https_proxy, no_proxy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_proxy_env_vars_case_insensitivity() {
        temp_env::with_vars(
            [
                ("http_proxy", Some("http://lowercase-http")),
                ("https_proxy", Some("http://lowercase-https")),
                ("no_proxy", Some("localhost,127.0.0.1")),
            ],
            || {
                let (http, https, no) = get_proxy_env_vars();
                assert_eq!(http, Some("http://lowercase-http".to_string()));
                assert_eq!(https, Some("http://lowercase-https".to_string()));
                assert_eq!(no, Some("localhost,127.0.0.1".to_string()));
            },
        );
        temp_env::with_vars(
            [
                ("HTTP_PROXY", Some("http://uppercase-http")),
                ("HTTPS_PROXY", Some("http://uppercase-https")),
                ("NO_PROXY", Some("our.example")),
            ],
            || {
                let (http, https, no) = get_proxy_env_vars();
                assert_eq!(http, Some("http://uppercase-http".to_string()));
                assert_eq!(https, Some("http://uppercase-https".to_string()));
                assert_eq!(no, Some("our.example".to_string()));
            },
        );
    }
}
