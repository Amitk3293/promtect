// SPDX-License-Identifier: LicenseRef-SUL-1.0
// Copyright (c) 2026 AK DevOps Solutions SL

//! Network-address helpers for deciding how Promtect may bind, plus the
//! upstream HTTP client construction.

use std::time::Duration;

/// Default inter-chunk read timeout (seconds) for the upstream client. Bounds
/// how long a single read may stall before the request is abandoned; it resets
/// on every successful read, so a healthy long-lived SSE stream is unaffected.
const DEFAULT_READ_TIMEOUT_SECS: u64 = 120;

/// True if `bind` is a loopback address that is safe to listen on directly
/// (only the local host can reach it). Anything else (e.g. `0.0.0.0`) is only
/// safe inside a container whose port is published to `127.0.0.1`.
pub fn is_loopback(bind: &str) -> bool {
    bind == "127.0.0.1" || bind == "::1" || bind == "localhost"
}

/// Resolve the upstream read timeout (seconds) from `PROMTECT_READ_TIMEOUT`.
///
/// Fail-SAFE on parse: unset, empty, non-numeric, or `0` all fall back to
/// [`DEFAULT_READ_TIMEOUT_SECS`]. A read timeout is a liveness safety net, not a
/// security control, so a bad value should degrade to the safe default rather
/// than abort startup (unlike fail-CLOSED config such as the body cap).
pub fn parse_read_timeout_secs(value: Option<&str>) -> u64 {
    match value.map(str::trim) {
        Some(s) if !s.is_empty() => match s.parse::<u64>() {
            Ok(n) if n > 0 => n,
            _ => DEFAULT_READ_TIMEOUT_SECS,
        },
        _ => DEFAULT_READ_TIMEOUT_SECS,
    }
}

/// The upstream HTTP client Promtect forwards through.
///
/// - **Connect timeout (30s):** a black-hole upstream (a host that silently
///   drops the SYN, rather than refusing it) surfaces as a prompt 502 instead
///   of hanging until the OS TCP stack gives up minutes later.
/// - **Read timeout (`PROMTECT_READ_TIMEOUT`, default 120s):** bounds an
///   inter-chunk stall. It resets per read, so legitimately long-lived SSE
///   streams keep working as long as bytes keep arriving; only a hung peer that
///   stops sending mid-response is cut off. No overall *request* timeout is set
///   for the same reason — a slow-but-progressing stream must not be killed.
/// - **No redirect following:** reqwest follows up to 10 redirects by default.
///   Promtect forwards the client's auth (e.g. `x-api-key`) to the configured
///   upstream only; following a 3xx could replay that secret to an
///   attacker-chosen target, so we hand the 3xx back to the client untouched.
/// - **No implicit system proxy:** reqwest honors `HTTP_PROXY`/`HTTPS_PROXY` by
///   default. A stale or hostile inherited proxy could silently receive the
///   auth-bearing upstream request. Promtect requires proxies/gateways to be
///   selected explicitly as the configured upstream instead.
///
/// Falls back to a minimal client if the builder fails (only possible on TLS
/// backend init, at startup — never on the request path), so construction is
/// infallible for callers. The fallback keeps redirects disabled; its config is
/// trivially infallible, so the `expect` cannot fire at runtime.
pub fn http_client() -> reqwest::Client {
    let read_timeout =
        parse_read_timeout_secs(std::env::var("PROMTECT_READ_TIMEOUT").ok().as_deref());
    reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_secs(30))
        .read_timeout(Duration::from_secs(read_timeout))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_else(|_| {
            reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("minimal reqwest client with redirects disabled is infallible")
        })
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

    #[test]
    fn read_timeout_uses_default_when_unset_or_invalid() {
        // Unset, empty, non-numeric, and 0 must all degrade to the safe default,
        // never abort. (Distinguishes this fail-SAFE knob from fail-CLOSED config.)
        for v in [
            None,
            Some(""),
            Some("   "),
            Some("abc"),
            Some("0"),
            Some("-5"),
        ] {
            assert_eq!(
                parse_read_timeout_secs(v),
                DEFAULT_READ_TIMEOUT_SECS,
                "{v:?} should fall back to the default"
            );
        }
    }

    #[test]
    fn read_timeout_parses_a_valid_value() {
        assert_eq!(parse_read_timeout_secs(Some("300")), 300);
        // Surrounding whitespace is tolerated.
        assert_eq!(parse_read_timeout_secs(Some(" 45 ")), 45);
    }

    #[test]
    fn http_client_builds() {
        // The client must construct successfully with the hardened config
        // (connect + read timeouts, redirects disabled). This is the unit-level
        // guarantee that the redirect/timeout settings did not break the build;
        // an end-to-end "does not follow 302" check would require a mock server
        // (extra dev-dep), so the no-redirect behaviour is documented on
        // http_client and asserted here only via successful construction.
        let _client = http_client();
    }
}
