// SPDX-License-Identifier: LicenseRef-SUL-1.0
// Copyright (c) 2026 AK DevOps Solutions SL

use promtect::proxy;

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
        // the metrics endpoint off-host; fail-closed instead. The bind decision is
        // `loopback OR truthy(opt-in)` — the same policy run::run_proxy uses.
        if !(promtect::net::is_loopback(&bind)
            || proxy::parse_truthy(std::env::var("PROMTECT_ALLOW_PUBLIC_BIND").ok().as_deref()))
        {
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

    // ── default: the proxy + dashboard ──────────────────────────────────────
    // The startup itself lives in promtect::run::run_proxy so a downstream binary
    // (promtect-pro) can run the exact same proxy with an injected extra detector.
    // The public core passes `None`, which is behavior-identical to the previous
    // inlined startup. run_proxy returns the exit code rather than exiting itself.
    let no_dashboard = args.iter().any(|a| a == "--no-dashboard");
    std::process::exit(i32::from(
        promtect::run::run_proxy(None, no_dashboard).await,
    ));
}
