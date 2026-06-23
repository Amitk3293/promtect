//! Egress-hardening integration tests (issues #37, #38, #39, #40).
//!
//! These cover the public surface of the hardened upstream client and the
//! off-loopback bind policy. The `public_bind_allowed` decision itself lives in
//! the binary crate (`src/main.rs`) and is unit-tested there; here we assert the
//! building blocks it composes from (`net::is_loopback` + `proxy::parse_truthy`)
//! agree with that policy, plus the client construction and read-timeout parsing.

use promtect::net::{http_client, is_loopback, parse_read_timeout_secs};
use promtect::proxy::parse_truthy;

/// #37: the hardened client must construct with redirects disabled and the
/// connect/read timeouts applied. A build failure here would be a regression in
/// the TLS/redirect config wiring.
#[test]
fn hardened_client_builds() {
    let _client = http_client();
}

/// #39: `PROMTECT_READ_TIMEOUT` parsing is fail-safe — only a positive integer
/// is honoured; everything else falls back to the built-in default.
#[test]
fn read_timeout_parsing_is_fail_safe() {
    let default = parse_read_timeout_secs(None);
    assert!(default > 0, "default read timeout must be positive");

    // A valid override is honoured.
    assert_eq!(parse_read_timeout_secs(Some("300")), 300);
    assert_eq!(parse_read_timeout_secs(Some(" 45 ")), 45);

    // Invalid / zero / empty all degrade to the default rather than aborting.
    for bad in ["", "   ", "abc", "0", "-1", "1.5"] {
        assert_eq!(
            parse_read_timeout_secs(Some(bad)),
            default,
            "{bad:?} should fall back to the default read timeout"
        );
    }
}

/// #38: the off-loopback bind policy is `is_loopback OR truthy(opt-in)`.
/// Mirror that composition here so the public building blocks stay in agreement
/// with the private `public_bind_allowed` helper in `main.rs`.
#[test]
fn off_loopback_bind_requires_explicit_optin() {
    let allowed = |bind: &str, env: Option<&str>| is_loopback(bind) || parse_truthy(env);

    // Loopback is always allowed, regardless of the flag.
    assert!(allowed("127.0.0.1", None));
    assert!(allowed("::1", Some("0")));
    assert!(allowed("localhost", None));

    // Off-loopback is refused without an explicit truthy opt-in.
    for env in [None, Some(""), Some("0"), Some("false"), Some("no")] {
        assert!(!allowed("0.0.0.0", env), "0.0.0.0 with {env:?} must refuse");
    }

    // Off-loopback is allowed only with an explicit truthy opt-in.
    for env in [Some("1"), Some("true"), Some("yes"), Some("on")] {
        assert!(allowed("0.0.0.0", env), "0.0.0.0 with {env:?} must allow");
    }
}
