// SPDX-License-Identifier: LicenseRef-SUL-1.0
// Copyright (c) 2026 AK DevOps Solutions SL

//! Reusable default-proxy startup.
//!
//! This module hosts the proxy bring-up that used to be inlined at the end of
//! `main.rs`: parse the `PROMTECT_*` env, resolve and risk-classify the upstream,
//! build the request-pipeline [`Ctx`](crate::proxy::Ctx), fail-closed on an
//! off-loopback bind, bind the listener, auto-start the dashboard, and run
//! `axum::serve` with graceful shutdown.
//!
//! It is exposed so a downstream closed build can run the exact same
//! proxy while injecting an extra detection pass. The public core calls it with
//! `extra_detect = None`, which is byte-for-behavior identical to the previous
//! inlined startup.

use std::sync::Arc;

use crate::{
    audit, dashboard,
    proxy::{self, Ctx, ExtraDetector, shutdown_signal},
};

/// Run the default Promtect proxy (the no-subcommand path) and return its
/// process exit code.
///
/// This is the reusable form of the startup that previously lived inline in
/// `main()`. Behavior is identical to that startup; the only seam is
/// `extra_detect`, which is threaded into [`Ctx::extra_detect`] so a downstream
/// build can compose its own detectors into the SAME mask / restore /
/// value-free-audit path. Passing `None` (the public core) is byte-for-behavior
/// identical to the previous hardcoded `None`.
///
/// # Parameters
/// - `extra_detect`: optional extra detection pass merged on top of the core
///   detectors at mask time. `None` in the public core.
/// - `no_dashboard`: when `true`, the metrics dashboard is not auto-started
///   (the `--no-dashboard` flag). The caller computes this from its own argv.
///
/// # Return value
/// The process exit code: `0` on a clean graceful shutdown, `1` on any
/// fail-closed configuration error (bad port/body cap, unknown mode, blocked
/// high-risk upstream, refused off-loopback bind, port already in use) or an
/// `axum::serve` error. The function never calls `std::process::exit` itself, so
/// the caller decides how to terminate.
pub async fn run_proxy(
    extra_detect: Option<ExtraDetector>,
    output_scan: Option<crate::stream::ResponseScanner>,
    no_dashboard: bool,
) -> u8 {
    let port = match proxy::parse_port(
        "PROMTECT_PORT",
        std::env::var("PROMTECT_PORT").ok().as_deref(),
        8790,
    ) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("promtect: {e}");
            return 1;
        }
    };
    // Upstream selection: PROMTECT_UPSTREAM (explicit override / chaining knob)
    // wins; otherwise PROMTECT_MODE picks a known provider; default Anthropic.
    let mode = std::env::var("PROMTECT_MODE").ok();
    let upstream_override = std::env::var("PROMTECT_UPSTREAM").ok();
    let upstream = match proxy::resolve_upstream(mode.as_deref(), upstream_override.as_deref()) {
        Ok(u) => u,
        Err(e) => {
            eprintln!("promtect: {e}");
            return 1;
        }
    };
    // Where does this upstream send data, and is it rotate-worthy? Classify it for the
    // startup banner, and honor PROMTECT_BLOCK_RISKY (fail-closed: refuse high-risk
    // upstreams like DeepSeek or an unverified unknown host).
    let risk = crate::provider::classify(&upstream);
    let block_risky = proxy::parse_truthy(std::env::var("PROMTECT_BLOCK_RISKY").ok().as_deref());
    if crate::provider::is_blocked(&risk, block_risky) {
        eprintln!(
            "promtect: refusing to proxy to a high-risk upstream — {note}\n  \
             ({upstream}). Unset PROMTECT_BLOCK_RISKY to allow it.",
            note = risk.note,
        );
        return 1;
    }

    let audit_path =
        std::env::var("PROMTECT_AUDIT").unwrap_or_else(|_| "promtect-audit.jsonl".into());

    // Operator-tunable body cap (default 32 MiB); fail closed on an invalid value.
    let max_body_bytes =
        match proxy::parse_max_body_bytes(std::env::var("PROMTECT_MAX_BODY_BYTES").ok().as_deref())
        {
            Ok(n) => n,
            Err(e) => {
                eprintln!("promtect: {e}");
                return 1;
            }
        };

    // Restore secrets in the response (transparent mode) by default; PROMTECT_RESTORE
    // falsey → strict mode (secrets never re-enter the response).
    let restore = proxy::parse_restore(std::env::var("PROMTECT_RESTORE").ok().as_deref());

    // The output scan runs whenever a scanner is supplied, unless
    // the operator disables it. PROMTECT_OUTPUT_SCAN shares the default-on /
    // explicit-falsey convention of PROMTECT_RESTORE. The public core supplies no
    // scanner, so this is a no-op there regardless of the variable.
    let output_scan = if proxy::parse_restore(std::env::var("PROMTECT_OUTPUT_SCAN").ok().as_deref())
    {
        output_scan
    } else {
        None
    };

    let audit_path_for_dash = audit_path.clone();
    let upstream_for_log = upstream.clone();
    let ctx = Ctx {
        upstream,
        audit: Arc::new(audit::Audit::to_file(audit_path)),
        client: crate::net::http_client(),
        max_body_bytes,
        restore,
        requests: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        extra_detect,
        output_scan,
    };

    let app = proxy::app(ctx);
    let bind = std::env::var("PROMTECT_BIND").unwrap_or_else(|_| "127.0.0.1".into());
    let addr = format!("{bind}:{port}");
    // Delegate to net::is_loopback so the safety decision is unit-tested in isolation.
    let is_loopback = crate::net::is_loopback(&bind);
    // Refuse an off-loopback bind unless the operator has explicitly opted in via
    // PROMTECT_ALLOW_PUBLIC_BIND. Binding the secrets proxy to a host network is a
    // serious exposure, so fail-closed rather than warn-then-bind.
    if !public_bind_allowed(
        is_loopback,
        std::env::var("PROMTECT_ALLOW_PUBLIC_BIND").ok().as_deref(),
    ) {
        eprintln!(
            "promtect: refusing to bind non-loopback address ({bind}). This would expose your \
             secrets proxy to other machines.\n  Set PROMTECT_ALLOW_PUBLIC_BIND=1 to allow this \
             (only inside a container whose port is published to 127.0.0.1, or behind trusted \
             network controls), or set PROMTECT_BIND=127.0.0.1."
        );
        return 1;
    }
    // Graceful exit (not a panic/backtrace) when the port is taken.
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "promtect: cannot bind {addr} ({e}).\n\
                 That port is already in use — set PROMTECT_PORT to a free port and retry."
            );
            return 1;
        }
    };
    let hint = if is_loopback {
        format!("http://{addr}")
    } else {
        format!("http://127.0.0.1:{port}")
    };

    // Auto-start the dashboard on a background task so users don't need a
    // second process. Pass --no-dashboard to skip. Non-fatal if port taken.
    let dash_hint = if no_dashboard {
        None
    } else {
        match proxy::parse_port(
            "PROMTECT_DASHBOARD_PORT",
            std::env::var("PROMTECT_DASHBOARD_PORT").ok().as_deref(),
            8799,
        ) {
            Err(e) => {
                eprintln!("promtect: dashboard port config error — {e}; running without dashboard");
                None
            }
            Ok(dash_port) => {
                let dash_addr = format!("{bind}:{dash_port}");
                match tokio::net::TcpListener::bind(&dash_addr).await {
                    Err(e) => {
                        eprintln!(
                            "promtect: dashboard could not bind {dash_addr} ({e}); running without dashboard"
                        );
                        None
                    }
                    Ok(dash_listener) => {
                        let dash_app = dashboard::app(dashboard::DashCtx {
                            audit_path: Arc::new(audit_path_for_dash.as_str().into()),
                            restore_enabled: restore,
                        });
                        tokio::task::spawn(async move {
                            // Graceful drain: stop accepting new dashboard
                            // connections on signal before the main proxy
                            // shuts down, so metrics pages aren't cut mid-stream.
                            if let Err(e) = axum::serve(dash_listener, dash_app)
                                .with_graceful_shutdown(shutdown_signal())
                                .await
                            {
                                eprintln!("promtect: dashboard error: {e}");
                            }
                        });
                        Some(format!("http://127.0.0.1:{dash_port}"))
                    }
                }
            }
        }
    };

    let restore_note = if restore {
        ""
    } else {
        "  [strict: restore off]"
    };
    let dash_note = dash_hint
        .as_deref()
        .map(|u| format!("\n  dashboard: {u}"))
        .unwrap_or_default();
    println!(
        "promtect listening on {addr} (upstream: {upstream_for_log}){restore_note}\n  point your tool's base URL at {hint}{dash_note}\n  upstream risk: {risk_note}",
        risk_note = risk.note,
    );
    // Graceful shutdown on SIGINT / SIGTERM: stop accepting new connections
    // and let in-flight requests drain rather than dropping mid-stream restores.
    if let Err(e) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
    {
        eprintln!("promtect: server error: {e}");
        return 1;
    }
    0
}

/// Decide whether an off-loopback bind is permitted.
///
/// Loopback binds are always allowed. A non-loopback bind is only allowed when
/// the operator has explicitly opted in via a truthy `PROMTECT_ALLOW_PUBLIC_BIND`
/// (reusing [`proxy::parse_truthy`] so the truthiness grammar matches the rest of
/// the config surface). Extracted as a pure function so the fail-closed decision
/// is unit-tested without spawning a server.
fn public_bind_allowed(is_loopback: bool, allow_env: Option<&str>) -> bool {
    is_loopback || proxy::parse_truthy(allow_env)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_bind_is_always_allowed() {
        // Loopback is safe regardless of the opt-in flag.
        assert!(public_bind_allowed(true, None));
        assert!(public_bind_allowed(true, Some("0")));
        assert!(public_bind_allowed(true, Some("1")));
    }

    #[test]
    fn off_loopback_bind_refused_without_optin() {
        // The default and any falsey/garbage flag must refuse a public bind.
        for env in [
            None,
            Some(""),
            Some("0"),
            Some("false"),
            Some("no"),
            Some("nope"),
        ] {
            assert!(
                !public_bind_allowed(false, env),
                "off-loopback with {env:?} must be refused"
            );
        }
    }

    #[test]
    fn off_loopback_bind_allowed_with_truthy_optin() {
        // Explicit opt-in (matching parse_truthy's grammar) permits a public bind.
        for env in [
            Some("1"),
            Some("true"),
            Some("yes"),
            Some("on"),
            Some("TRUE"),
        ] {
            assert!(
                public_bind_allowed(false, env),
                "off-loopback with {env:?} must be allowed"
            );
        }
    }
}
