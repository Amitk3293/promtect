//! Network-address helpers for deciding how Promtect may bind.

/// True if `bind` is a loopback address that is safe to listen on directly
/// (only the local host can reach it). Anything else (e.g. `0.0.0.0`) is only
/// safe inside a container whose port is published to `127.0.0.1`.
pub fn is_loopback(bind: &str) -> bool {
    bind == "127.0.0.1" || bind == "::1" || bind == "localhost"
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
