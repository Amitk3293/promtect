//! Network-address helpers for deciding how Promtect may bind.

/// True if `bind` is a loopback address that is safe to listen on directly
/// (only the local host can reach it). Anything else (e.g. `0.0.0.0`) is only
/// safe inside a container whose port is published to `127.0.0.1`.
pub fn is_loopback(bind: &str) -> bool {
    bind == "127.0.0.1" || bind == "::1" || bind == "localhost"
}

/// The upstream HTTP client Promtect forwards through.
///
/// Sets a connect timeout so a black-hole upstream (a host that silently drops
/// the SYN, rather than refusing it) surfaces as a prompt 502 instead of hanging
/// until the OS TCP stack gives up minutes later. No request/response *body*
/// timeout is set: responses stream and may legitimately be long-lived.
///
/// Falls back to the default client if the builder fails (only possible on TLS
/// backend init, at startup — never on the request path), so construction is
/// infallible for callers.
pub fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_addresses_are_recognised() {
        // The three forms Promtect treats as host-only.
        for b in ["127.0.0.1", "::1", "localhost"] {
            assert!(is_loopback(b), "{b} should be loopback");
        }
    }

    #[test]
    fn non_loopback_addresses_are_rejected() {
        // 0.0.0.0 (the container bind) and any routable IP must NOT be loopback.
        for b in ["0.0.0.0", "::", "10.0.0.5", "192.168.1.1", ""] {
            assert!(!is_loopback(b), "{b} should not be loopback");
        }
    }
}
