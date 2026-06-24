// SPDX-License-Identifier: LicenseRef-SUL-1.0
// Copyright (c) 2026 AK DevOps Solutions SL

use std::sync::Arc;

use promtect::{
    audit, dashboard,
    proxy::{self, Ctx},
};

// Re-export shutdown_signal from the library so the binary uses a single
// implementation.  The function is defined in promtect::proxy where it is
// also callable from guard.rs and test code.
use promtect::proxy::shutdown_signal;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Help must print before any port binding attempt.
    if args.get(1).map(|s| s.as_str()) == Some("--help")
        || args.get(1).map(|s| s.as_str()) == Some("-h")
    {
        print!(concat!(
            "promtect ",
            env!("CARGO_PKG_VERSION"),
            "\n",
            "\n",
            "USAGE:\n",
            "    promtect [OPTIONS] [SUBCOMMAND]\n",
            "\n",
            "OPTIONS:\n",
            "    --no-dashboard   Start proxy without the metrics dashboard\n",
            "\n",
            "SUBCOMMANDS:\n",
            "    (none)       Start the proxy + dashboard (default)\n",
            "    selftest     Detector canary check — no network\n",
            "    mask         Mask stdin, write masked text to stdout\n",
            "    playground   Offline mask+restore demo\n",
            "    guard <cmd>  Wrap a command with an ephemeral proxy\n",
            "    dashboard    Dashboard-only (no proxy) on PROMTECT_DASHBOARD_PORT\n",
            "\n",
            "ENV VARS:\n",
            "    PROMTECT_PORT              Proxy bind port (default 8790)\n",
            "    PROMTECT_BIND              Proxy bind address (default 127.0.0.1)\n",
            "    PROMTECT_ALLOW_PUBLIC_BIND Allow non-loopback bind (default false)\n",
            "    PROMTECT_MODE              anthropic|openai|ollama|ollama-cloud|openrouter (default anthropic)\n",
            "    PROMTECT_UPSTREAM          Explicit upstream URL (overrides mode)\n",
            "    PROMTECT_RESTORE           Restore sentinels in response (default true)\n",
            "    PROMTECT_BLOCK_RISKY       Block high-risk upstreams (default false)\n",
            "    PROMTECT_AUDIT             Audit log path (default promtect-audit.jsonl)\n",
            "    PROMTECT_MAX_BODY_BYTES    Request body size cap (default 33554432)\n",
            "    PROMTECT_READ_TIMEOUT      Per-chunk read timeout seconds (default 120)\n",
            "    PROMTECT_DASHBOARD_PORT    Dashboard port (default 8799)\n",
        ));
        return;
    }

    if args.get(1).map(|s| s.as_str()) == Some("selftest") {
        let ok = promtect::mask::selftest();
        println!(
            "promtect selftest: {}",
            if ok {
                "PASS — no leak"
            } else {
                "FAIL — leak detected"
            }
        );
        std::process::exit(if ok { 0 } else { 1 });
    }

    // ── mask subcommand ─────────────────────────────────────────────────────
    // Pipe any text in, see exactly what Promtect would hide before it reaches
    // the model. Reads stdin, replaces every detected secret with its sentinel,
    // and writes the masked text to stdout. Pure local — no network, no audit
    // file, no restore. Handy for "what would this leak?" checks:
    //   echo 'deploy with AKIA...' | promtect mask
    //   cat .env | promtect mask
    if args.get(1).map(|s| s.as_str()) == Some("mask") {
        use std::io::{Read, Write};
        let mut input = String::new();
        if let Err(e) = std::io::stdin().read_to_string(&mut input) {
            eprintln!("promtect mask: cannot read stdin ({e})");
            std::process::exit(1);
        }
        // Throwaway vault/audit: masking is one-way here, so neither the sentinel
        // map nor an audit trail needs to outlive the call.
        let vault = promtect::vault::Vault::new();
        let masked =
            promtect::mask::mask_text(&input, &vault, &promtect::audit::Audit::null(), "mask");
        print!("{masked}");
        std::io::stdout().flush().ok();
        return;
    }

    // ── playground subcommand ───────────────────────────────────────────────
    // A narrated, offline demo of the full mask → forward → restore round-trip
    // against an in-process mock upstream. Every secret is fake; nothing leaves
    // the machine. The fastest way to watch Promtect actually work:
    //   promtect playground
    if args.get(1).map(|s| s.as_str()) == Some("playground") {
        promtect::playground::run().await;
        return;
    }

    // ── guard subcommand ────────────────────────────────────────────────────
    // One-command protected session: start an ephemeral proxy, point the tool at
    // it, run the tool with the user's args, tear down on exit.
    //   promtect guard claude
    //   promtect guard codex
    //   promtect guard ollama run deepseek-r1
    //   promtect guard ollama --cloud run gpt-oss:120b-cloud
    //   promtect guard aider --model openai/gpt-5.5
    //   promtect guard claude --headroom
    if args.get(1).map(|s| s.as_str()) == Some("guard") {
        match promtect::guard::plan_guard(&args[2..]) {
            Ok(plan) => std::process::exit(promtect::guard::guard(plan).await),
            Err(e) => {
                eprintln!(
                    "promtect guard: {e}\n\
                     usage: promtect guard <claude|codex|ollama|aider|--exec CMD> \
                     [--cloud] [--headroom[=URL]] [--openrouter] [--upstream URL] [--strict] \
                     [--port N] [-- TOOL_ARGS...]"
                );
                std::process::exit(2);
            }
        }
    }

    // ── dashboard subcommand ────────────────────────────────────────────────
    // Starts a local, offline HTTP server that exposes the aggregated audit-log
    // metrics three ways: a browser UI at `/`, JSON at `/api/metrics`, and
    // Prometheus text exposition at `/metrics`. The server never receives proxy
    // traffic — it only reads the audit JSONL that the proxy writes.
    if args.get(1).map(|s| s.as_str()) == Some("dashboard") {
        let port = match proxy::parse_port(
            "PROMTECT_DASHBOARD_PORT",
            std::env::var("PROMTECT_DASHBOARD_PORT").ok().as_deref(),
            8799,
        ) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("promtect: {e}");
                std::process::exit(1);
            }
        };
        let bind = std::env::var("PROMTECT_BIND").unwrap_or_else(|_| "127.0.0.1".into());
        // Refuse an off-loopback bind unless the operator has explicitly opted in
        // via PROMTECT_ALLOW_PUBLIC_BIND. A warn-then-bind default silently exposed
        // the metrics endpoint off-host; fail-closed instead.
        if !public_bind_allowed(
            promtect::net::is_loopback(&bind),
            std::env::var("PROMTECT_ALLOW_PUBLIC_BIND").ok().as_deref(),
        ) {
            eprintln!(
                "promtect dashboard: refusing to bind non-loopback address ({bind}). The metrics \
                 endpoint would be reachable off-host.\n  Set PROMTECT_ALLOW_PUBLIC_BIND=1 to allow \
                 this (only behind trusted network controls), or set PROMTECT_BIND=127.0.0.1."
            );
            std::process::exit(1);
        }
        let audit_path =
            std::env::var("PROMTECT_AUDIT").unwrap_or_else(|_| "promtect-audit.jsonl".into());
        let app = promtect::dashboard::app(promtect::dashboard::DashCtx {
            audit_path: std::sync::Arc::new(audit_path.into()),
        });
        let addr = format!("{bind}:{port}");
        // Graceful exit (not a panic/backtrace) when the port is taken — a common,
        // recoverable misconfiguration deserves a clear message, not a crash.
        let listener = match tokio::net::TcpListener::bind(&addr).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!(
                    "promtect dashboard: cannot bind {addr} ({e}).\n\
                     That port is already in use — set PROMTECT_DASHBOARD_PORT to a free port and retry."
                );
                std::process::exit(1);
            }
        };
        println!(
            "promtect dashboard on http://{}:{port}  (UI: /, JSON: /api/metrics, Prometheus: /metrics)",
            if promtect::net::is_loopback(&bind) {
                "127.0.0.1"
            } else {
                bind.as_str()
            }
        );
        // Drain in-flight dashboard requests on Ctrl-C / SIGTERM before
        // exiting, so partial metric responses aren't silently cut off.
        if let Err(e) = axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await
        {
            eprintln!("promtect dashboard: server error: {e}");
            std::process::exit(1);
        }
        return;
    }

    let no_dashboard = args.iter().any(|a| a == "--no-dashboard");

    let port = match proxy::parse_port(
        "PROMTECT_PORT",
        std::env::var("PROMTECT_PORT").ok().as_deref(),
        8790,
    ) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("promtect: {e}");
            std::process::exit(1);
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
            std::process::exit(1);
        }
    };
    // Where does this upstream send data, and is it rotate-worthy? Classify it for the
    // startup banner, and honor PROMTECT_BLOCK_RISKY (fail-closed: refuse high-risk
    // upstreams like DeepSeek or an unverified unknown host).
    let risk = promtect::provider::classify(&upstream);
    let block_risky = proxy::parse_truthy(std::env::var("PROMTECT_BLOCK_RISKY").ok().as_deref());
    if promtect::provider::is_blocked(&risk, block_risky) {
        eprintln!(
            "promtect: refusing to proxy to a high-risk upstream — {note}\n  \
             ({upstream}). Unset PROMTECT_BLOCK_RISKY to allow it.",
            note = risk.note,
        );
        std::process::exit(1);
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
                std::process::exit(1);
            }
        };

    // Restore secrets in the response (transparent mode) by default; PROMTECT_RESTORE
    // falsey → strict mode (secrets never re-enter the response).
    let restore = proxy::parse_restore(std::env::var("PROMTECT_RESTORE").ok().as_deref());

    let audit_path_for_dash = audit_path.clone();
    let upstream_for_log = upstream.clone();
    let ctx = Ctx {
        upstream,
        audit: Arc::new(audit::Audit::to_file(audit_path)),
        client: promtect::net::http_client(),
        max_body_bytes,
        restore,
        requests: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        extra_detect: None,
    };

    let app = proxy::app(ctx);
    let bind = std::env::var("PROMTECT_BIND").unwrap_or_else(|_| "127.0.0.1".into());
    let addr = format!("{bind}:{port}");
    // Delegate to net::is_loopback so the safety decision is unit-tested in isolation.
    let is_loopback = promtect::net::is_loopback(&bind);
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
        std::process::exit(1);
    }
    // Graceful exit (not a panic/backtrace) when the port is taken.
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "promtect: cannot bind {addr} ({e}).\n\
                 That port is already in use — set PROMTECT_PORT to a free port and retry."
            );
            std::process::exit(1);
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
        std::process::exit(1);
    }
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
